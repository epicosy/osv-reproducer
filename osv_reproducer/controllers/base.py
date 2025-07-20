import json

from tqdm import tqdm
from pathlib import Path
from cement import Controller, ex
from cement.utils.version import get_version_banner

from ..core.models.report import OSSFuzzIssueReport
from ..core.version import get_version
from ..core.exc import OSVReproducerError
from ..core.models.result import ReproductionResult, ReproductionStatus
from ..utils.parse.arguments import parse_key_value_string


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

    def _setup(self, app):
        super()._setup(app)
        self.osv_handler = self.app.handler.get("handlers", "osv", setup=True)
        self.oss_fuzz_handler = self.app.handler.get("handlers", "oss_fuzz", setup=True)
        self.github_handler = self.app.handler.get("handlers", "github", setup=True)
        self.project_handler = self.app.handler.get("handlers", "project", setup=True)
        self.build_handler = self.app.handler.get("handlers", "build", setup=True)
        self.runner_handler = self.app.handler.get("handlers", "runner", setup=True)
        self.gcs_handler = self.app.handler.get("handlers", "gcs", setup=True)

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
            project_info = self.project_handler.get_oss_fuzz_project(oss_fuzz_repo, project_content_file.path, oss_fuzz_ref)

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
            (['-cs', '--cache-src'], {
                'help': "Cache project related source code.", 'action': 'store_true', 'default': False
            }),
            (['--build-extra-args'], {
                'help': "Additional build arguments to pass to the fuzzer container as environment variables. "
                       "Format: 'KEY1:VALUE1|KEY2:VALUE2'",
                'type': str, 'default': ""
            })
        ]
    )
    def reproduce(self):
        output_dir = Path(self.app.pargs.output_dir).expanduser()

        try:
            # Parse the build-extra-args parameter
            extra_args = parse_key_value_string(self.app.pargs.build_extra_args)
            self.app.log.info(f"Starting reproduction of vulnerability {self.app.pargs.osv_id}")

            result = ReproductionResult(osv_id=self.app.pargs.osv_id, output_dir=output_dir)

            # Create output directory
            output_dir.mkdir(exist_ok=True, parents=True)

            # Step 1: Fetch OSV record
            self.app.log.info(f"Fetching OSV record for {self.app.pargs.osv_id}")
            osv_record = self.osv_handler.fetch_vulnerability(self.app.pargs.osv_id)

            if not osv_record.get_git_fixes():
                raise OSVReproducerError(f"No fixes found for {self.app.pargs.osv_id}")

            # check if the oss_fuzz_issue_report exists
            oss_fuzz_issue_report_path = output_dir / f"{osv_record.id}_issue_report.json"
            issue_report = None

            if not oss_fuzz_issue_report_path.exists():
                # get the oss_fuzz_info (srcmap and reproducer testcase)
                for ref in osv_record.references:
                    issue_report = self.oss_fuzz_handler.get_issue_report(ref.url)

                    if issue_report:
                        break
                else:
                    raise OSVReproducerError(f"Could not find an OSS-Fuzz Issue Report for {osv_record.id}")

                with oss_fuzz_issue_report_path.open(mode="w") as f:
                    oss_fuzz_issue_report_json = issue_report.model_dump_json(indent=4)
                    f.write(oss_fuzz_issue_report_json)
            else:
                self.app.log.info(f"Using cached issue report for {self.app.pargs.osv_id}")
                with oss_fuzz_issue_report_path.open(mode="r") as f:
                    oss_fuzz_issue_report_dict = json.load(f)
                    issue_report = OSSFuzzIssueReport(**oss_fuzz_issue_report_dict)

            test_case_path = self.oss_fuzz_handler.get_test_case(issue_report, output_dir)

            # Get the project info
            project_info = self.project_handler.get_project_info_by_name(issue_report.project)

            if not project_info:
                self.app.log.info(f"Fetching from GitHub the project info for {issue_report.project}")
                oss_fuzz_repo = self.github_handler.client.get_repo(owner="google", project="oss-fuzz")
                project_info = self.project_handler.get_oss_fuzz_project(
                    oss_fuzz_repo, f"projects/{issue_report.project}", "20a387d78148c14dd5243ea1b16164fe08b73884"
                )
                if not project_info:
                    raise OSVReproducerError(f"Could not find project info for {issue_report.project}")

            for param, value in issue_report.regressed_url.query_params():
                if param == "range":
                    timestamp = value.split(":")[-1]
                    break
            else:
                raise Exception("No range found in query params")

            if self.app.pargs.cache_src:
                base_src_dir = self.app.projects_dir / project_info.name
            else:
                base_src_dir = output_dir

            # Step 4: Build the base image of the project
            base_image_tag = self.build_handler.get_project_base_image(project_info.name)

            fuzzer_container_name = f"{issue_report.project}_{timestamp}"

            if not self.build_handler.check_container_exists(fuzzer_container_name):
                # If there is no existing container for the given issue, then get the src
                sanitizer = issue_report.sanitizer.split(" ")[0]
                srcmap_file_path = output_dir / f"{issue_report.project}_{timestamp}_srcmap.json"

                if not srcmap_file_path.exists():
                    # Get srcmap.json
                    srcmap = self.gcs_handler.get_srcmap(issue_report.project, sanitizer, timestamp, srcmap_file_path)
                else:
                    self.app.log.info(f"Using cached srcmap for {self.app.pargs.osv_id}")
                    with srcmap_file_path.open(mode="r") as f:
                        srcmap = json.load(f)

                self.project_handler.init(project_info, srcmap, base_src_dir)

            out_dir = output_dir / "out"
            fuzzer_container = self.build_handler.get_project_fuzzer_container(
                fuzzer_container_name, project_info.language, image_name=base_image_tag, issue_report=issue_report,
                src_dir=base_src_dir / "src", out_dir=out_dir, work_dir=output_dir / "work", extra_args=extra_args
            )

            if self.build_handler.check_container_exit_code(fuzzer_container) != 0:
                raise OSVReproducerError(f"Fuzzer container for {self.app.pargs.osv_id} exited with non-zero exit code")

            crash_info = self.runner_handler.reproduce(test_case_path, issue_report, out_dir=out_dir)

            if crash_info:
                result.verification = self.runner_handler.verify_crash(issue_report, crash_info)

            if result.verification and result.verification.success:
                self.app.log.info(f"Successfully reproduced vulnerability {self.app.pargs.osv_id}")
                self.app.log.info(f"Results saved to {output_dir}")
                exit(0)
            else:
                self.app.log.error(
                    f"{self.app.pargs.osv_id} reproduction did not yield expected values:\n{result.verification.error_messages}"
                )
        except OSVReproducerError as e:
            self.app.log.error(f"Error: {str(e)}")
        except Exception as e:
            self.app.log.error(f"Unexpected error: {str(e)}")
            if self.app.pargs.verbose:
                import traceback
                self.app.log.error(traceback.format_exc())
        exit(1)
