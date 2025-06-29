from tqdm import tqdm
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
        self._project_handler = None

    @property
    def github_handler(self):
        if self._github_handler is None:
            self._github_handler = self.app.handler.get("handlers", "github", setup=True)

        return self._github_handler

    @property
    def project_handler(self):
        if self._project_handler is None:
            self._project_handler = self.app.handler.get("handlers", "project", setup=True)

        return self._project_handler

    def _default(self):
        """Default action if no sub-command is passed."""
        self.app.args.print_help()

    @ex(
        help='Initialize OSV Reproducer by fetching OSS-Fuzz project data',
        arguments=[
            (['-s', '--sha'], {
                'help': 'Version of the OSS-Fuzz project', 'type': str, 'required': False,
                'default': "20a387d78148c14dd5243ea1b16164fe08b73884"
            }),
        ]
    )
    def init(self):
        """
            This command fetches information for each OSS-Fuzz project and saves it under ~/.osv-reproducer.
            It also fetches and saves the build.sh and Dockerfile for each project.
        """
        self.app.log.info("Fetching OSS-Fuzz project data...")

        # Get OSS-Fuzz repository
        oss_fuzz_ref = self.app.pargs.sha
        assert oss_fuzz_ref is not None, f"oss_fuzz_ref needs to be specified"

        oss_fuzz_repo = self.github_handler.client.get_repo(owner="google", project="oss-fuzz")

        if not oss_fuzz_repo:
            self.app.log.error("No repo found for OSS-Fuzz project")
            exit(1)

        projects_folder = oss_fuzz_repo.repo.get_contents("projects", oss_fuzz_ref)
        projects = {}

        # Process each project
        for project_content_file in tqdm(projects_folder, total=len(projects_folder)):
            project_info = self.project_handler.get_oss_fuzz_project(oss_fuzz_repo, project_content_file, oss_fuzz_ref)
            if project_info:
                projects[project_info.repo_path] = project_info

        self.app.log.info(f"Fetched {len(projects)} projects...")
