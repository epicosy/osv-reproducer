import json
import shutil

import yaml

from pathlib import Path
from typing import Dict, Optional, Tuple, Any

from gitlib.parsers.url.base import GithubUrlParser
from github.GithubException import UnknownObjectException

from osv_reproducer.core.models.project import ProjectInfo
from osv_reproducer.handlers.github import GithubHandler


class ProjectHandler(GithubHandler):
    """
    Project handler abstraction for managing OSS-Fuzz projects
    """

    class Meta:
        label = 'project'

    def _setup(self, app):
        super()._setup(app)
        self.config = self.app.config.get("handlers", "project")

        if not "oss_fuzz_repo_sha" in self.config:
            self.app.log.warning(f"'oss_fuzz_repo_sha' key not found in config file, using 'main'")
            self.config["oss_fuzz_repo_sha"] = "main"

    def _load_existing_project_info(self, project_info_path: Path) -> Optional[ProjectInfo]:
        """Load existing project info from a JSON file."""
        if not project_info_path.exists():
            return None

        try:
            with project_info_path.open(mode="r") as f:
                project_info_dict = json.load(f)
                return ProjectInfo(**project_info_dict)
        except Exception as e:
            self.app.log.error(f"Error loading project info: {e}")
            return None

    def _fetch_project_yaml(self, oss_fuzz_repo: Any, project_git_path: str, oss_fuzz_ref: str) -> Optional[Dict[str, Any]]:
        """Fetch and parse project YAML file."""
        try:
            project_yaml = oss_fuzz_repo.repo.get_contents(f"{project_git_path}/project.yaml", oss_fuzz_ref)
            project_info_dict = yaml.safe_load(project_yaml.decoded_content)
            return project_info_dict
        except UnknownObjectException as uoe:
            self.app.log.error(f"{uoe}")
            return None
        except yaml.YAMLError as yaml_error:
            self.app.log.error(f"{yaml_error}")
            return None
        except Exception as exception:
            self.app.log.error(f"{exception}")
            return None

    def _process_github_repo(self, project_info_dict: Dict[str, Any]) -> Tuple[Optional[Any], Optional[str]]:
        """Process GitHub repository information."""
        if not project_info_dict["main_repo"].startswith("https://github.com/"):
            return None, None

        try:
            clean_repo_url = project_info_dict["main_repo"].replace(".git", "")
            git_url_parser = GithubUrlParser(clean_repo_url)
            git_repo_url = git_url_parser()

            if not git_repo_url:
                return None, None

            project_repo = self.client.get_repo(owner=git_repo_url.owner, project=git_repo_url.repo)
            repo_path = str(git_repo_url)

            return project_repo, repo_path
        except Exception as e:
            self.app.log.error(f"Error processing GitHub repo: {e}")
            return None, None

    def _save_project_info(self, project_info_dict: Dict[str, Any], project_info_path: Path) -> None:
        """Save project info to a JSON file."""
        try:
            with project_info_path.open(mode="w") as f:
                json.dump(project_info_dict, f, indent=4)
        except Exception as e:
            self.app.log.error(f"Error saving project info: {e}")

    def _save_project_files(self, oss_fuzz_repo: Any, project_git_path: str, project_dir: Path, oss_fuzz_ref: str) -> bool:
        """Save project files (build script and Dockerfile)."""
        try:
            project_content_files = oss_fuzz_repo.repo.get_contents(project_git_path, oss_fuzz_ref)

            for project_file in project_content_files:
                if project_file.path.endswith("project.yaml"):
                    continue

                project_file_path = project_dir / project_file.name

                with project_file_path.open(mode="w") as f:
                    f.write(project_file.decoded_content.decode("utf-8"))

            return True
        except UnknownObjectException as uoe:
            self.app.log.error(f"{uoe}")
            return False
        except Exception as e:
            self.app.log.error(f"Error saving project files: {e}")
            return False

    def init(self, project_info: ProjectInfo, snapshot: Dict[str, dict], output_dir: Path, artifacts: dict = None):
        for path, v in snapshot.items():
            if v["type"] == "git":
                target_dir = output_dir / Path(path).relative_to("/")
                local_repo_sha = self.get_local_repo_head_commit(target_dir)

                if local_repo_sha and v["rev"] == local_repo_sha:
                    self.app.log.info(
                        f"Using cached repository at {local_repo_sha} for {self.app.pargs.osv_id} in {target_dir}")
                    continue

                self.clone_repository(
                    repo_url=v["url"], commit=v["rev"], target_dir=target_dir,
                )
            else:
                self.app.log.warning(f"Unsupported host type: {v['type']} for {path}")

        if artifacts:
            src_dir = output_dir / "src"

            for file_path, dest in artifacts.items():
                file_path_obj = Path(file_path)

                if not file_path_obj.exists():
                    self.app.log.warning(f"File {file_path} not in {project_info.name}")
                    continue

                dest_file = Path(dest.replace("/src", str(src_dir)))
                dest_path = Path(str(dest_file).replace(file_path_obj.name, ""))

                if not dest_path.exists():
                    self.app.log.warning(f"Destination path {dest_path} not in {project_info.name}")
                    continue

                # copy the file to the src_dir
                shutil.copy(file_path, dest_path)

    def fetch_oss_fuzz_project(self, oss_fuzz_repo: Any, project_git_path: str) -> Optional[ProjectInfo]:
        """
        Process a single OSS-Fuzz project.

        Args:
            oss_fuzz_repo: The OSS-Fuzz repository object.
            project_git_path: The path to the project in the GitHub repository.

        Returns:
            A ProjectInfo object if successful, None otherwise.
        """
        project_name = project_git_path.split("/")[-1]
        project_dir = self.app.projects_dir / project_name
        project_info_path = project_dir / "project.json"

        # Check if project info already exists
        existing_project_info = self._load_existing_project_info(project_info_path)

        if existing_project_info:
            self.app.log.info(f"Loading project {project_name}")
            return existing_project_info

        # Create project directory
        project_dir.mkdir(exist_ok=True, parents=True)

        self.app.log.info(f"Fetching {project_name}...")

        # Fetch and parse project YAML
        project_info_dict = self._fetch_project_yaml(oss_fuzz_repo, project_git_path, self.config["oss_fuzz_repo_sha"])

        if not project_info_dict:
            return None

        if "main_repo" not in project_info_dict:
            self.app.log.error(f"Project {project_name} has no main repo url")
            return None

        project_info_dict["name"] = project_name

        # Process GitHub repository
        project_repo, repo_path = self._process_github_repo(project_info_dict)
        if not project_repo or not repo_path:
            self.app.log.warning(f"Skipping {project_name}; not a repository hosted on GitHub")
            return None

        if "language" not in project_info_dict:
            if project_repo.language:
                project_info_dict["language"] = project_repo.language
            else:
                self.app.log.error(f"Could not determine language for {project_name}")
                return None

        # Update project info with repository details
        project_info_dict["repo_path"] = repo_path
        project_info_dict["main_repo_id"] = project_repo.id

        # Save project info
        self._save_project_info(project_info_dict, project_info_path)

        # Save project files
        if self._save_project_files(oss_fuzz_repo, project_git_path, project_dir, self.config["oss_fuzz_repo_sha"]):
            # Create ProjectInfo object
            return ProjectInfo(**project_info_dict)

        return None

    def get_project_info_by_id(self, repo_id: int) -> Optional[ProjectInfo]:
        # TODO: check also if the project is in the oss-fuzz repo and fetch
        self.app.log.info(f"Looking up for project with {repo_id} repo_id...")
        for project_path in self.app.projects_dir.iterdir():
            project_info = self._load_existing_project_info(project_path / "project.json")

            if project_info and project_info.main_repo_id == repo_id:
                return project_info

        return None

    def get_project_info_by_name(self, name: str) -> Optional[ProjectInfo]:
        project_info = self._load_existing_project_info(self.app.projects_dir / name / "project.json")

        if project_info:
            return project_info

        self.app.log.info(f"Fetching from GitHub the project info for {name}")
        oss_fuzz_repo = self.client.get_repo(owner="google", project="oss-fuzz")

        project_info = self.fetch_oss_fuzz_project(oss_fuzz_repo, f"projects/{name}")

        return project_info
