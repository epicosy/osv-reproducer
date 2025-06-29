from tqdm import tqdm
from pathlib import Path
from cement import Controller, ex
from cement.utils.version import get_version_banner

from ..core.version import get_version
from ..core.exc import OSVReproducerError
from ..core.models.result import ReproductionResult, ReproductionStatus


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
            (['-v', '--version'], {'action': 'version', 'version': VERSION_BANNER}),
            (['-vb', '--verbose'], {'help': "Verbose mode.", 'action': 'store_true', 'default': False})
        ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._osv_handler = None
        self._github_handler = None
        self._project_handler = None
        self._build_handler = None

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

    @property
    def osv_handler(self):
        if self._osv_handler is None:
            self._osv_handler = self.app.handler.get("handlers", "osv", setup=True)

        return self._osv_handler

    @property
    def build_handler(self):
        if self._build_handler is None:
            self._build_handler = self.app.handler.get("handlers", "build", setup=True)

        return self._build_handler

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

        # TODO: make it load beyond 1000 entries
        projects_folder = oss_fuzz_repo.repo.get_contents("projects", oss_fuzz_ref)
        projects = {}

        # Process each project
        for project_content_file in tqdm(projects_folder, total=len(projects_folder)):
            project_info = self.project_handler.get_oss_fuzz_project(oss_fuzz_repo, project_content_file, oss_fuzz_ref)
            if project_info:
                projects[project_info.repo_path] = project_info

        self.app.log.info(f"Fetched {len(projects)} projects...")

    @ex(
        help='Reproduce a given OSS-Fuzz vulnerability in the OSV database.',
        arguments=[
            (['-oid', '--osv_id'], {
                'help': 'Identifier of the vulnerability in the OSV database (e.g., OSV-2023-XXXX)', 'type': str,
                'required': True
            }),
            (['-o', '--output-dir'], {
                'help': 'Directory to store output artifacts', 'type': str, 'default': "./osv-results"
            }),
            (['--rm-containers', '--remove-containers'], {
                'help': "Remove Docker containers after reproduction (default is to keep them).",
                'action': 'store_true', 'default': False,
            }),
            (['-nc', '--no-cache'], {
                'help': "Don't use cached OSS-Fuzz project data.", 'action': 'store_true', 'default': False
            })
        ]
    )
    def reproduce(self):
        output_dir = Path(self.app.pargs.output_dir).expanduser()

        try:
            # reproducer = Reproducer(
            #     osv_id=osv_id,
            #     github_token=github_token,
            #     output_dir=output_dir,
            #     keep_containers=keep_containers,
            #     verbose=verbose,
            #     cache_dir=None if no_cache else str(cache_dir),
            # )

            self.app.log.info(f"Starting reproduction of vulnerability {self.app.pargs.osv_id}")

            result = ReproductionResult(
                osv_id=self.app.pargs.osv_id, status=ReproductionStatus.NOT_STARTED, output_dir=output_dir,
            )

            # Update status
            result.status = ReproductionStatus.IN_PROGRESS

            # Create output directory
            output_dir.mkdir(exist_ok=True, parents=True)

            # Step 1: Fetch OSV record
            self.app.log.info(f"Fetching OSV record for {self.app.pargs.osv_id}")
            osv_record = self.osv_handler.fetch_vulnerability(self.app.pargs.osv_id)

            # Step 2: Validate OSV record
            self.app.log.info(f"Validating OSV record for {self.app.pargs.osv_id}")
            git_range, introduced_version, fixed_version = self.osv_handler.get_git_range(osv_record)

            # Get the project info
            repo_id = self.github_handler.get_repo_id(git_range.repo.owner, git_range.repo.name)
            project_info = self.project_handler.get_project_info_by_id(repo_id)

            if not project_info:
                raise OSVReproducerError(f"Could not find project info for {git_range.repo}")

            state = self.github_handler.get_commit_build_state(
                git_range.repo.owner, git_range.repo.name, introduced_version
            )

            if state in ['error', 'failure']:
                raise OSVReproducerError(f"Commit {introduced_version} with {state} state not valid for reproduction")

            state = self.github_handler.get_commit_build_state(
                git_range.repo.owner, git_range.repo.name, fixed_version
            )

            if state in ['error', 'failure']:
                raise OSVReproducerError(f"Commit {introduced_version} with {state} state not valid for reproduction")

            # Step 3: Get build information for vulnerable and fixed versions
            # Note: We don't need to clone the OSS-Fuzz repository here anymore
            # as the BuildManager will use cached data if available

            self.app.log.info(f"Getting build information for project {git_range.repo.name} at commit {introduced_version} (vuln)")
            vulnerable_build_info = self.build_handler.get_build_info(project_info, introduced_version)

            self.app.log.info(f"Getting build information for project {git_range.repo.name} at commit {introduced_version} (fix)")
            fixed_build_info = self.build_handler.get_build_info(project_info, fixed_version)

            # Update result with build information
            result.vulnerable_build = vulnerable_build_info
            result.fixed_build = fixed_build_info
            #
            # # Step 4: Build vulnerable version
            # vulnerable_image = self._build_project(
            #     vulnerable_build_info,
            #     os.path.join(self.output_dir, "vulnerable"),
            # )
            #
            # # Step 5: Build fixed version
            # fixed_image = self._build_project(
            #     fixed_build_info,
            #     os.path.join(self.output_dir, "fixed"),
            # )
            result.status = ReproductionStatus.SUCCESS

            if result.success:
                self.app.log.info(f"Successfully reproduced vulnerability {self.app.pargs.osv_id}")
                self.app.log.info(f"Results saved to {output_dir}")
                exit(0)
            else:
                self.app.log.error(f"Failed to reproduce vulnerability {self.app.pargs.osv_id}: {result.error}")
        except OSVReproducerError as e:
            self.app.log.error(f"Error: {str(e)}")
        except Exception as e:
            self.app.log.error(f"Unexpected error: {str(e)}")
            if self.app.pargs.verbose:
                import traceback
                self.app.log.error(traceback.format_exc())
        exit(1)
