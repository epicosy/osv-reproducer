import json

from pathlib import Path
from cement import Controller, ex
from cement.utils.version import get_version_banner

from ..core.version import get_version
from ..core.exc import OSVReproducerError
from ..core.models.result import ReproductionResult
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
            issue_report = self.oss_fuzz_handler.get_issue_report(osv_record)

            if not issue_report:
                raise OSVReproducerError(f"Could not find an OSS-Fuzz Issue Report for {osv_record.id}")

            test_case_path = self.oss_fuzz_handler.get_test_case(issue_report.testcase_url)

            if not test_case_path:
                raise OSVReproducerError(f"Could not get the testcase for {issue_report.id} OSS-Fuzz Issue Report")

            # Get the project info
            project_info = self.project_handler.get_project_info_by_name(issue_report.project)

            if not project_info:
                raise OSVReproducerError(f"Could not find project info for {issue_report.project}")

            # TODO: should be part of the object
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
                # TODO: saving/loading should be done in the handler
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
