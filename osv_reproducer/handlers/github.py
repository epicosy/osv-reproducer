from typing import Dict
from cement import Handler

from gitlib import GitClient
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

        tokens_section = self.app.config.get_section_dict("tokens")
        github_token = tokens_section.get("github")

        self._cache: Dict[str, GitRepo] = {}
        self.client = GitClient(github_token)

    def get_repo_id(self, owner: str, project: str) -> int:
        repo_path = f"{owner}/{project}"

        if repo_path not in self._cache:
            repo = self.client.get_repo(owner, project)

            if repo is None:
                raise GitHubError(f"Repository {repo_path} not found.")

            self._cache[repo_path] = repo

        return self._cache[repo_path].id

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
