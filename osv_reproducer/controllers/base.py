from pathlib import Path
from cement import Controller, ex
from cement.utils.version import get_version_banner

from ..core.version import get_version
from ..core.exc import OSVReproducerError
from ..core.models import ReproductionResult, ReproductionContext, PathsLayout
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

    def _get_context(self, osv_id: str) -> ReproductionContext:
        self.app.log.info(f"Fetching OSV record for {osv_id}")
        osv_record = self.osv_handler.fetch_vulnerability(osv_id)

        if not osv_record.get_git_fixes():
            raise OSVReproducerError(f"No fixes found for {osv_id}")

        issue_report = self.oss_fuzz_handler.get_issue_report(osv_record)

        if not issue_report:
            raise OSVReproducerError(f"Could not find an OSS-Fuzz Issue Report for {osv_record.id}")

        test_case_path = self.oss_fuzz_handler.get_test_case(issue_report.testcase_url)

        if not test_case_path:
            raise OSVReproducerError(f"Could not get the testcase for {issue_report.id} OSS-Fuzz Issue Report")

        project_info = self.project_handler.get_project_info_by_name(issue_report.project)

        if not project_info:
            raise OSVReproducerError(f"Could not find project info for {issue_report.project}")

        timestamp = issue_report.range[-1]
        sanitizer = issue_report.sanitizer.split(" ")[0]
        snapshot = self.gcs_handler.get_snapshot(issue_report.project, sanitizer, timestamp)

        if not snapshot:
            raise OSVReproducerError(f"Could not get snapshot for {issue_report.project}@{timestamp}")

        return ReproductionContext(
            project_info=project_info,
            issue_report=issue_report,
            test_case_path=test_case_path,
            timestamp=timestamp,
            snapshot=snapshot
        )

    def _get_paths_layout(self, path: str, project_name: str) -> PathsLayout:
        paths_layout = PathsLayout(
            base_path=Path(path).expanduser(), project_path=self.app.projects_dir / project_name
        )
        paths_layout.base_path.mkdir(exist_ok=True, parents=True)

        return paths_layout

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
            (['--build-extra-args'], {
                'help': "Additional build arguments to pass to the fuzzer container as environment variables. "
                       "Format: 'KEY1:VALUE1|KEY2:VALUE2'",
                'type': str, 'default': ""
            })
        ]
    )
    def reproduce(self):
        try:
            # Parse the build-extra-args parameter
            extra_args = parse_key_value_string(self.app.pargs.build_extra_args)
            self.app.log.info(f"Starting reproduction of vulnerability {self.app.pargs.osv_id}")
            context = self._get_context(self.app.pargs.osv_id)
            paths_layout = self._get_paths_layout(self.app.pargs.output_dir, context.project_info.name)
            base_image_tag = self.build_handler.get_project_base_image(context.project_info.name)

            if not self.build_handler.check_container_exists(context.fuzzer_container_name):
                # If there is no existing container for the given issue, then get the src
                self.project_handler.init(context.project_info, context.snapshot, paths_layout.project_path)

            fuzzer_container = self.build_handler.get_project_fuzzer_container(
                context.fuzzer_container_name, context.project_info.language, image_name=base_image_tag,
                issue_report=context.issue_report, src_dir=paths_layout.src, out_dir=paths_layout.out,
                work_dir=paths_layout.work, extra_args=extra_args
            )

            if self.build_handler.check_container_exit_code(fuzzer_container) != 0:
                raise OSVReproducerError(f"Fuzzer container for {self.app.pargs.osv_id} exited with non-zero exit code")

            crash_info = self.runner_handler.reproduce(
                context.test_case_path, context.issue_report, out_dir=paths_layout.out
            )
            result = ReproductionResult(osv_id=self.app.pargs.osv_id, output_dir=paths_layout.base_path)

            if crash_info:
                result.verification = self.runner_handler.verify_crash(context.issue_report, crash_info)

            if result.verification and result.verification.success:
                self.app.log.info(f"Successfully reproduced vulnerability {self.app.pargs.osv_id}")
                self.app.log.info(f"Results saved to {paths_layout.base_path}")
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
