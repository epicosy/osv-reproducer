import git
import yaml

from pathlib import Path
from cement import Handler
from datetime import datetime
from typing import Dict, Optional, Any, Tuple, List
from github.GithubException import UnknownObjectException
from github.GithubException import BadCredentialsException

from gitlib import GitClient
from git import GitCommandError

from gitlib.github.commit import GitCommit
from gitlib.github.repository import GitRepo
from gitlib.parsers.url.base import GithubUrlParser

from ..core.exc import GitHubError
from ..handlers import HandlersInterface
from ..core.interfaces import GithubInterface
from ..core.models import ProjectInfo, ProjectRange


class GithubHandler(GithubInterface, HandlersInterface, Handler):
    """
        GitHub handler abstraction
    """

    class Meta:
        label = 'github'

    def _setup(self, app):
        super()._setup(app)

        self.config = self.app.config.get("handlers", "github")
        self.project_repo_mappings = self.config.get("project_repo_mappings", {})

        if not self.project_repo_mappings:
            self.app.log.warning("No project repo mappings found in config.")

        token = self.config.get("token", None)
        self.client = GitClient(token)

        try:
            remaining = self.client.remaining
        except BadCredentialsException:
            raise GitHubError("Failed to initialize GitHub client. Check your token and try again.")

        self._repo_cache: Dict[str, GitRepo] = {}
        self._commit_cache: Dict[str, GitCommit] = {}
        self._not_found = set()

    def get_fix_date_range(self, project_ranges: List[ProjectRange]) -> Tuple[Optional[datetime], Optional[datetime]]:
        dates: List[datetime] = []

        for project_range in project_ranges:
            repo_path = str(project_range)

            if repo_path in self._not_found:
                continue

            if repo_path not in self._repo_cache:
                repo = self.client.get_repo(project_range.owner, project_range.name)
                if repo is None:
                    # remember as not found so we skip next time
                    self._not_found.add(repo_path)
                    continue
                self._repo_cache[repo_path] = repo

            # resolve the fix commit date
            fix_date = self.get_commit_date(
                owner=project_range.owner,
                project=project_range.name,
                version=project_range.fix_sha,
            )
            if fix_date is not None:
                dates.append(fix_date)

        if not dates:
            return None, None

        start = min(dates)
        end = max(dates)

        return start, end

    def get_commit_date(self, owner: str, project: str, version: str) -> Optional[datetime]:
        repo_path = f"{owner}/{project}"

        if repo_path in self._not_found:
            return None

        if repo_path not in self._repo_cache:
            repo = self.client.get_repo(owner, project)

            if repo is None:
                self.app.log.error(f"Repository {repo_path} not found.")
                self._not_found.add(repo_path)
                return None

            self._repo_cache[repo_path] = repo

        self.app.log.info(f"Getting date for {repo_path}@{version}")
        commit_id = f"{repo_path}@{version}"

        if commit_id in self._not_found:
            return None

        if commit_id not in self._commit_cache:
            commit = self._repo_cache[repo_path].get_commit(version)

            if commit is None:
                self.app.log.error(f"{repo_path}@{version} not found.")
                self._not_found.add(commit_id)
                return None

            self._commit_cache[commit_id] = commit

        return self._commit_cache[commit_id].commit.commit.committer.date

    def check_repo_url(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        git_url_parser = GithubUrlParser(url.replace(".git", ""))
        git_repo_url = git_url_parser()

        if not git_repo_url:
            self.app.log.error(f"Could not parse GitHub repo URL: {url}")
            return None, None

        repo_path = str(git_repo_url)

        if repo_path in self._not_found:
            return None, None

        if repo_path not in self._repo_cache:
            repo = self.client.get_repo(git_repo_url.owner, git_repo_url.repo)

            if repo is None:
                # remember as not found so we skip next time
                self._not_found.add(repo_path)
                return None, None

            self._repo_cache[repo_path] = repo

        return git_repo_url.owner, git_repo_url.repo

    def clone_repository(self, repo_url: str, commit: str, to_path: Path, shallow: bool = True) -> Optional[Path]:
        try:
            repo = git.Repo(to_path)
            return to_path
        except git.exc.NoSuchPathError:
            # self.app.log.warning(f"Repo not found under directory {to_path}, cloning it")
            to_path.mkdir(parents=True, exist_ok=True)
        except git.exc.InvalidGitRepositoryError as e:
            self.app.log.error(f"Invalid git repository at {to_path}: {str(e)}")
            return None

        try:
            self.app.log.info(f"Cloning repository {repo_url} at commit {commit} to {to_path}")

            if shallow:
                repo = git.Repo.clone_from(repo_url, to_path, no_checkout=True)

                try:
                    # Try shallow
                    repo.git.fetch("origin", commit, depth=1)
                except GitCommandError as e:
                    msg = e.stderr or str(e)
                    self.app.log.warning(f"Shallow clone failed: {msg}")
                    # Fallback on dumb HTTP / no shallow support
                    if "dumb http transport does not support shallow capabilities" in msg \
                            or "does not support --depth" in msg:
                        repo.git.fetch("origin")  # full fetch
                    else:
                        raise

                repo.git.checkout(commit)
            else:
                repo = git.Repo.clone_from(repo_url, to_path)
                repo.git.checkout(commit)

                # Initialize submodules (optional: recursive)
                repo.git.submodule("update", "--init", "--recursive")

            self.app.log.info(f"Successfully cloned repository {repo_url} at commit {commit}")
            return to_path
        except GitCommandError as e:
            self.app.log.error(f"Git command error while cloning {repo_url} at commit {commit}: {str(e)}")
        except Exception as e:
            self.app.log.error(f"Error while cloning {repo_url} at commit {commit}: {str(e)}")

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

    def _parse_project_info(self, project_name: str, project_info: dict, oss_fuzz_repo_sha: str) -> Optional[ProjectInfo]:
        if "main_repo" not in project_info:
            if "github.com" in project_info.get("homepage", ""):
                project_info["main_repo"] = project_info["homepage"]
            elif project_name in self.project_repo_mappings:
                project_info["main_repo"] = self.project_repo_mappings[project_name]
            else:
                self.app.log.error(f"Project {project_name} has no main repo url")
                return None

        project_info["name"] = project_name
        project_info["oss_fuzz_repo_sha"] = oss_fuzz_repo_sha

        # Process GitHub repository
        project_repo, repo_path = self._process_github_repo(project_info)

        if not project_repo or not repo_path:
            self.app.log.warning(f"Skipping {project_name}; not a repository hosted on GitHub")
            return None

        if "language" not in project_info:
            if project_repo.language:
                project_info["language"] = project_repo.language
            else:
                self.app.log.error(f"Could not determine language for {project_name}")
                return None

        # Update project info with repository details
        project_info["repo_path"] = repo_path
        project_info["main_repo_id"] = project_repo.id

        return ProjectInfo(**project_info)

    def find_oss_fuzz_repo_commit(self, until: datetime) -> Optional[str]:
        oss_fuzz_repo = self.client.get_repo(owner="google", project="oss-fuzz")

        self.app.log.info(f"Fetching commits before {until}")
        commits = oss_fuzz_repo.repo.get_commits(until=until)

        if not commits:
            return None

        commit = commits[0]
        self.app.log.info(f"Using commit {commit.sha} at {commit.commit.committer.date}")

        return commit.sha

    def fetch_project_info(self, name: str, oss_fuzz_repo_sha: str = "main") -> Optional[ProjectInfo]:
        """
        Process a single OSS-Fuzz project.

        Args:
            name: The name of the project to process.
            oss_fuzz_repo_sha: The SHA of the OSS-Fuzz repository to use.

        Returns:
            A ProjectInfo object if successful, None otherwise.
        """

        self.app.log.info(f"Fetching from GitHub the project info for {name}")
        oss_fuzz_repo = self.client.get_repo(owner="google", project="oss-fuzz")

        # Fetch project YAML
        try:
            project_yaml = oss_fuzz_repo.repo.get_contents(f"projects/{name}/project.yaml", oss_fuzz_repo_sha)
            project_info_dict = yaml.safe_load(project_yaml.decoded_content)
        except UnknownObjectException as uoe:
            self.app.log.error(f"{uoe}")
            return None
        except yaml.YAMLError as yaml_error:
            self.app.log.error(f"{yaml_error}")
            return None
        except Exception as exception:
            self.app.log.error(f"{exception}")
            return None

        project_info = self._parse_project_info(name, project_info_dict, oss_fuzz_repo_sha)

        return project_info

    def fetch_project_files(self, name: str, oss_fuzz_ref: str) -> Optional[Dict[str, bytes]]:
        """Save project files (build script and Dockerfile)."""
        oss_fuzz_repo = self.client.get_repo(owner="google", project="oss-fuzz")
        project_files = {}

        try:
            for project_file in oss_fuzz_repo.repo.get_contents(f"projects/{name}", oss_fuzz_ref):
                if project_file.path.endswith("project.yaml"):
                    continue

                project_files[project_file.name] = project_file.decoded_content

            return project_files
        except UnknownObjectException as uoe:
            self.app.log.error(f"{uoe}")

        return None
