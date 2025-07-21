import git
import tempfile

from pathlib import Path
from cement import Handler
from datetime import datetime
from typing import Dict, Optional

from gitlib import GitClient
from git import GitCommandError
from gitlib.github.commit import GitCommit
from gitlib.github.repository import GitRepo

from ..core.exc import GitHubError
from ..core.interfaces import HandlersInterface


class GithubHandler(HandlersInterface, Handler):
    """
        GitHub handler abstraction
    """

    class Meta:
        label = 'github'

    def _setup(self, app):
        super()._setup(app)

        self.config = self.app.config.get("handlers", "github")
        token = self.config.get("token", None)
        self.client = GitClient(token)
        self._cache: Dict[str, GitRepo] = {}

    def get_repo_id(self, owner: str, project: str) -> int:
        repo_path = f"{owner}/{project}"

        if repo_path not in self._cache:
            repo = self.client.get_repo(owner, project)

            if repo is None:
                raise GitHubError(f"Repository {repo_path} not found.")

            self._cache[repo_path] = repo

        return self._cache[repo_path].id

    def get_commit(self, owner: str, project: str, version: str) -> GitCommit:
        repo_path = f"{owner}/{project}"

        if repo_path not in self._cache:
            repo = self.client.get_repo(owner, project)

            if repo is None:
                raise GitHubError(f"Repository {repo_path} not found.")

            self._cache[repo_path] = repo

        self.app.log.info(f"Getting timestamp for {repo_path}@{version}")
        git_commit = self._cache[repo_path].get_commit(version)

        if git_commit is None:
            raise GitHubError(f"{repo_path}@{version} not found.")

        return git_commit

    def get_local_repo_head_commit(self, repo_path: Path) -> Optional[str]:
        if not repo_path.exists():
            return None

        repo = git.Repo(repo_path)

        if repo_path.exists():
            return repo.head.commit.hexsha

        self.app.log.warning(f"Repository {repo_path} not found.")

        return None

    def get_commit_build_state(self, owner: str, project: str, version: str) -> str:
        """
            Validate build status of a GitHub repository at a given version.

        :param owner: GitHub owner.
        :param project: GitHub project.
        :param version:
        :return:
        """
        repo_path = f"{owner}/{project}"

        if repo_path not in self._cache:
            repo = self.client.get_repo(owner, project)

            if repo is None:
                raise GitHubError(f"Repository {repo_path} not found.")

            self._cache[repo_path] = repo

        self.app.log.info(f"Getting build status for {repo_path}@{version}")
        git_commit = self._cache[repo_path].get_commit(version)

        if git_commit is None:
            raise GitHubError(f"{repo_path}@{version} not found.")

        return git_commit.commit.get_combined_status().state

    def clone_repository(
            self, repo_url: str, commit: str, target_dir: Optional[Path] = None, shallow: bool = True,
    ) -> str:
        """
        Clone a GitHub repository at a specific commit.

        Args:
            repo_url: URL of the repository.
            commit: Commit hash to checkout.
            target_dir: Directory to clone the repository to. If None, creates a temporary directory.
            shallow: Whether to perform a shallow clone.

        Returns:
            str: Path to the cloned repository.

        Raises:
            GitHubError: If cloning the repository fails.
        """
        to_clone = True

        try:
            # Create target directory if it doesn't exist
            if target_dir is None:
                target_dir = tempfile.mkdtemp(prefix="osv-repo-")
            elif not target_dir.exists():
                target_dir.mkdir(parents=True, exist_ok=True)
            else:
                to_clone = False

            self.app.log.info(f"Cloning repository {repo_url} at commit {commit} to {target_dir}")

            # Clone the repository
            if shallow:
                # Shallow clone with depth 1 and specific commit
                if to_clone:
                    repo = git.Repo.clone_from(
                        repo_url,
                        target_dir,
                        no_checkout=True,
                    )
                else:
                    repo = git.Repo(target_dir)
                repo.git.fetch("origin", commit, depth=1)
                repo.git.checkout(commit)
            else:
                # Full clone
                repo = git.Repo.clone_from(repo_url, target_dir)
                repo.git.checkout(commit)

            self.app.log.info(f"Successfully cloned repository {repo_url} at commit {commit}")
            return target_dir
        except GitCommandError as e:
            self.app.log.error(f"Git command error while cloning {repo_url} at commit {commit}: {str(e)}")
            raise GitHubError(f"Failed to clone repository {repo_url} at commit {commit}: {str(e)}")
        except Exception as e:
            self.app.log.error(f"Error while cloning {repo_url} at commit {commit}: {str(e)}")
            raise GitHubError(f"Failed to clone repository {repo_url} at commit {commit}: {str(e)}")
