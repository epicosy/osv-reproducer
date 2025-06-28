from cement import Controller, ex
from cement.utils.version import get_version_banner
from ..core.version import get_version

VERSION_BANNER = """
Tooling for reproducing OSS-Fuzz bugs from OSV database %s
%s
""" % (get_version(), get_version_banner())


class Base(Controller):
    class Meta:
        label = 'base'

        # text displayed at the top of --help output
        description = 'A reproducer component that can compile OSS-Fuzz projects at specific versions and run test cases'

        # text displayed at the bottom of --help output
        epilog = 'Usage: osv_reproducer'

        # controller level arguments. ex: 'osv_reproducer --version'
        arguments = [
            ### add a version banner
            ( [ '-v', '--version' ],
              { 'action'  : 'version',
                'version' : VERSION_BANNER } ),
        ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._github_handler = None

    @property
    def github_handler(self):
        if self._github_handler is None:
            self._github_handler = self.app.handler.get("handlers", "github", setup=True)

        return self._github_handler

    def _default(self):
        """Default action if no sub-command is passed."""
        self.app.args.print_help()

    @ex(
        help='Initialize OSV Reproducer by fetching OSS-Fuzz project data',
        arguments=[
        ]
    )
    def init(self):
        """
            This command fetches information for each OSS-Fuzz project and saves it under ~/.osv-reproducer.
            It also fetches and saves the build.sh and Dockerfile for each project.
        """
        #try:
        self.app.log.info("Fetching OSS-Fuzz project data...")

        # Fetch OSS-Fuzz projects data
        projects = self.github_handler.get_oss_fuzz_projects()
        print(projects)
