import yaml
import json

from tqdm import tqdm
from typing import Dict
from pathlib import Path
from cement import Handler

from gitlib import GitClient
from gitlib.parsers.url.base import GithubUrlParser
from github.GithubException import UnknownObjectException

from osv_reproducer.core.interfaces import HandlersInterface
from osv_reproducer.core.models.project import ProjectInfo


class GithubHandler(HandlersInterface, Handler):
    """
        GitHub handler abstraction
    """

    class Meta:
        label = 'github'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._client = None

    @property
    def client(self):
        if not self._client:
            tokens_section = self.app.config.get_section_dict("tokens")
            github_token = tokens_section.get("github")
            self._client = GitClient(github_token)

        return self._client

    def get_oss_fuzz_projects(
            self, oss_fuzz_ref: str = "20a387d78148c14dd5243ea1b16164fe08b73884"
    ) -> Dict[str, ProjectInfo]:
        projects_dir = Path.home() / ".osv_reproducer" / "projects"
        projects_dir.mkdir(exist_ok=True, parents=True)

        oss_fuzz_repo = self.client.get_repo(owner="google", project="oss-fuzz", raise_err=True)
        projects_folder = oss_fuzz_repo.repo.get_contents("projects", oss_fuzz_ref)

        projects = {}

        for project_content_file in tqdm(projects_folder, total=len(projects_folder)):
            project_git_path = project_content_file.path
            project_name = project_git_path.split("/")[-1]
            project_dir = projects_dir / project_name
            project_info_path = project_dir / "project.json"

            if project_info_path.exists():
                self.app.log.info(f"Loading project {project_name}")

                with project_info_path.open(mode="r") as f:
                    project_info_dict = json.load(f)
                    project_info = ProjectInfo(**project_info_dict)
                    projects[project_info.repo_path] = project_info
                continue

            project_dir.mkdir(exist_ok=True, parents=True)

            self.app.log.info(f"Analyzing {project_name}...")

            try:
                project_yaml = oss_fuzz_repo.repo.get_contents(f"{project_git_path}/project.yaml", oss_fuzz_ref)
                project_info_dict = yaml.safe_load(project_yaml.decoded_content)
                project_info_dict["name"] = project_name

                if not project_info_dict["main_repo"].startswith("https://github.com/"):
                    print(f"Skipping {project_name}; not a repository hosted on GitHub")
                    continue

                clean_repo_url = project_info_dict["main_repo"].replace(".git", "")
                git_url_parser = GithubUrlParser(clean_repo_url)
                git_repo_url = git_url_parser()

                if git_repo_url:
                    project_repo = self.client.get_repo(owner=git_repo_url.owner, project=git_repo_url.repo)
                    project_info_dict["repo_path"] = str(git_repo_url)

                    if project_repo:
                        project_info_dict["main_repo_id"] = project_repo.id

                        with project_info_path.open(mode="w") as f:
                            json.dump(project_info_dict, f, indent=4)

                        build_script = oss_fuzz_repo.repo.get_contents(f"{project_git_path}/build.sh", oss_fuzz_ref)
                        project_build_script_path = project_dir / "build.sh"

                        with project_build_script_path.open(mode="w") as f:
                            f.write(build_script.decoded_content.decode("utf-8"))

                        dockerfile = oss_fuzz_repo.repo.get_contents(f"{project_git_path}/Dockerfile", oss_fuzz_ref)
                        project_docker_file_path = project_dir / "Dockerfile"

                        with project_docker_file_path.open(mode="w") as f:
                            f.write(dockerfile.decoded_content.decode("utf-8"))

                        project_info = ProjectInfo(**project_info_dict)
                        projects[project_info.repo_path] = project_info
            except UnknownObjectException as uoe:
                self.app.log.error(f"{uoe}")
                continue
            except yaml.YAMLError as yaml_error:
                self.app.log.error(f"{yaml_error}")
                continue
            except Exception as exception:
                self.app.log.error(f"{exception}")
                continue

        return projects
