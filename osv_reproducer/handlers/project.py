import json
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

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

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
                if project_file.path.endswith("build.sh"):
                    # Save build script
                    project_build_script_path = project_dir / "build.sh"

                    with project_build_script_path.open(mode="w") as f:
                        f.write(project_file.decoded_content.decode("utf-8"))

                if project_file.path.endswith("Dockerfile"):
                    # Save Dockerfile
                    project_docker_file_path = project_dir / "Dockerfile"

                    with project_docker_file_path.open(mode="w") as f:
                        f.write(project_file.decoded_content.decode("utf-8"))

            return True
        except UnknownObjectException as uoe:
            self.app.log.error(f"{uoe}")
            return False
        except Exception as e:
            self.app.log.error(f"Error saving project files: {e}")
            return False

    def get_oss_fuzz_project(self, oss_fuzz_repo: Any, project_content_file: Any, oss_fuzz_ref: str) -> Optional[ProjectInfo]:
        """
        Process a single OSS-Fuzz project.

        Args:
            oss_fuzz_repo: The OSS-Fuzz repository object.
            project_content_file: The project content file object.
            oss_fuzz_ref: The OSS-Fuzz reference (branch, tag, or commit).

        Returns:
            A ProjectInfo object if successful, None otherwise.
        """
        project_git_path = project_content_file.path
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
        project_info_dict = self._fetch_project_yaml(oss_fuzz_repo, project_git_path, oss_fuzz_ref)
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

        if "language" not in project_info_dict and project_repo.language:
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
        if self._save_project_files(oss_fuzz_repo, project_git_path, project_dir, oss_fuzz_ref):
            # Create ProjectInfo object
            return ProjectInfo(**project_info_dict)

        return None
