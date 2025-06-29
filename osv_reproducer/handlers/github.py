from cement import Handler
from gitlib import GitClient

from osv_reproducer.core.interfaces import HandlersInterface


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
