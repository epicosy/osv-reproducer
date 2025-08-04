from pathlib import Path
from cement import Controller, ex
from datetime import timedelta, datetime
from cement.utils.version import get_version_banner

from ..core.version import get_version
from ..core.exc import OSVReproducerError
from ..core.common.enums import ReproductionMode
from ..core.models import ReproductionContext, PathsLayout
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
            (['-vb', '--verbose'], {'help': "Verbose mode.", 'action': 'store_true', 'default': False}),
            (['-oid', '--osv_id'], {
                'help': 'Identifier of the vulnerability in the OSV database (e.g., OSV-2023-XXXX)', 'type': str,
                'required': True
            }),
            (['-o', '--output-dir'], {
                'help': 'Directory to store output artifacts', 'type': str, 'default': "./osv-results"
            }),
            (['--build-extra-args'], {
                'help': "Additional build arguments to pass to the fuzzer container as environment variables. Format: 'KEY1:VALUE1|KEY2:VALUE2'",
                'type': str, 'default': ""
            })
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

    def _get_snapshot_for_crash_mode(self, issue_report, sanitizer):
        """
        Get snapshot for CRASH reproduction mode.

        Args:
            issue_report: The OSS-Fuzz issue report.
            sanitizer: The sanitizer to use.

        Returns:
            tuple: A tuple containing (timestamp, snapshot).
        """
        timestamp = issue_report.range[-1]
        self.app.log.info(f"Getting snapshot for CRASH mode at timestamp {timestamp}")
        snapshot = self.gcs_handler.get_snapshot(issue_report.project, sanitizer, timestamp)
        return timestamp, snapshot

    def _get_snapshot_for_fix_mode(self, osv_record, issue_report, project_info, sanitizer):
        """
        Get snapshot for FIX reproduction mode.

        Args:
            osv_record: The OSV vulnerability record.
            issue_report: The OSS-Fuzz issue report.
            project_info: The project information.
            sanitizer: The sanitizer to use.

        Returns:
            tuple: A tuple containing (timestamp, snapshot, visited_commits).
        """
        timestamp = None
        snapshot = None
        visited_commits = []

        self.app.log.info(f"Getting snapshot for FIX mode for project {issue_report.project}")

        for affected in osv_record.affected:
            for git_range in affected.get_git_ranges():
                repo_id = self.github_handler.get_repo_id(owner=git_range.repo.owner, project=git_range.repo.name)

                if project_info.main_repo_id == repo_id:
                    for fix in git_range.get_fixed_events():
                        visited_commits.append(fix.version)
                        self.app.log.info(f"Checking fix version: {fix.version}")
                        commit = self.github_handler.get_commit(
                            owner=git_range.repo.owner, project=git_range.repo.name, version=fix.version
                        )

                        # TODO: Understand why there is an offset of 4 minutes
                        date_offset = commit.commit.commit.committer.date - timedelta(minutes=4)
                        timestamp = date_offset.strftime("%Y%m%d%H%M")
                        self.app.log.info(f"Getting snapshot for timestamp {timestamp} and commit {commit.sha}")
                        snapshot = self.gcs_handler.get_snapshot(issue_report.project, sanitizer, timestamp, commit.sha)
                        if snapshot:
                            return timestamp, snapshot, visited_commits

        return timestamp, snapshot, visited_commits

    def _get_context(self, osv_id: str, mode: ReproductionMode) -> ReproductionContext:
        self.app.log.info(f"Fetching OSV record for {osv_id}")
        osv_record = self.osv_handler.get_record(osv_id)

        if mode == ReproductionMode.FIX and not osv_record.get_git_fixes():
            raise OSVReproducerError(f"No fixes found for {osv_id}")

        issue_report = self.oss_fuzz_handler.get_issue_report(osv_record)

        if not issue_report:
            raise OSVReproducerError(f"Could not find an OSS-Fuzz Issue Report for {osv_record.id}")

        test_case_path = self.oss_fuzz_handler.get_test_case(issue_report.testcase_url)

        if not test_case_path:
            raise OSVReproducerError(f"Could not get the testcase for {issue_report.id} OSS-Fuzz Issue Report")

        report_date = datetime.strptime(issue_report.range[-1], "%Y%m%d%H%M")
        project_info = self.project_handler.get_project_info_by_name(issue_report.project, report_date)

        if not project_info:
            raise OSVReproducerError(f"Could not find project info for {issue_report.project}")

        # TODO: should be handled during parsing
        sanitizer = issue_report.sanitizer.split(" ")[0]

        # Get snapshot based on reproduction mode
        if mode == ReproductionMode.CRASH:
            timestamp, snapshot = self._get_snapshot_for_crash_mode(issue_report, sanitizer)
        else:
            timestamp, snapshot, _ = self._get_snapshot_for_fix_mode(osv_record, issue_report, project_info, sanitizer)

        if not snapshot:
            raise OSVReproducerError(f"Could not get snapshot for {issue_report.project}@{timestamp}")

        return ReproductionContext(
            mode=mode,
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

    def _setup_fuzzer_container(self, context, paths_layout, extra_args):
        """
        Set up and build the fuzzer container for reproduction or verification.

        Args:
            context: The reproduction context
            paths_layout: The paths layout
            extra_args: Additional build arguments

        Returns:
            The fuzzer container

        Raises:
            OSVReproducerError: If the fuzzer container exits with non-zero code
        """
        base_image_tag = self.build_handler.get_project_base_image(context.project_info.name)

        if not self.build_handler.check_container_exists(context.fuzzer_container_name):
            # If there is no existing container for the given issue, then get the src
            # TODO: should check the snapshot against a dependency dict to make sure it includes all dependencies
            artifacts = self.build_handler.get_artifacts(context.project_info.name)
            self.project_handler.init(context.project_info, context.snapshot, paths_layout.project_path, artifacts)

        fuzzer_container = self.build_handler.get_project_fuzzer_container(
            context.fuzzer_container_name, context.project_info.language, image_name=base_image_tag,
            issue_report=context.issue_report, src_dir=paths_layout.src, out_dir=paths_layout.out,
            work_dir=paths_layout.work, snapshot=context.snapshot, extra_args=extra_args
        )

        if self.build_handler.check_container_exit_code(fuzzer_container) != 0:
            raise OSVReproducerError(f"Fuzzer container for {context.issue_report.id} exited with non-zero exit code")

        return fuzzer_container

    def _run_reproduction(self, context, paths_layout):
        """
        Run the reproduction of a crash using the runner handler.

        Args:
            context: The reproduction context
            paths_layout: The paths layout

        Returns:
            The crash information if the crash was reproduced, None otherwise
        """
        return self.runner_handler.reproduce(
            context.runner_container_name, context.test_case_path, context.issue_report, out_dir=paths_layout.out
        )

    def _handle_crash_check(self, context, paths_layout, crash_info):
        """
        Handle the crash check result based on the reproduction mode.

        Args:
            context: The reproduction context
            paths_layout: The paths layout
            crash_info: The crash information from reproduction

        Returns:
            int: Exit code (0 for success, 1 for failure)
        """
        if context.mode == ReproductionMode.CRASH:
            if crash_info:
                verification = self.runner_handler.verify_crash(context.issue_report, crash_info)

                if verification and verification.success:
                    self.app.log.info(f"Successfully reproduced vulnerability {self.app.pargs.osv_id}")
                    self.app.log.info(f"Results saved to {paths_layout.base_path}")
                    return 0
                else:
                    self.app.log.error(
                        f"{self.app.pargs.osv_id} reproduction did not yield expected values:\n{verification.error_messages}"
                    )
            else:
                self.app.log.error(f"Could not reproduce {self.app.pargs.osv_id} vulnerability")
        elif context.mode == ReproductionMode.FIX:
            if crash_info:
                self.app.log.error(
                    f"{self.app.pargs.osv_id} patch did not address the crash:\n{crash_info}"
                )
            else:
                self.app.log.info(f"Patch addressed the crash for {self.app.pargs.osv_id} vulnerability")
                # self.app.log.info(f"Results saved to {paths_layout.base_path}")
                return 0

        return 1

    def _run_and_handle(self, osv_id: str, mode: ReproductionMode, build_extra_args: str, output_dir: str):
        action_desc = "reproduction of crash" if mode.CRASH else "verification of patch"
        try:
            extra_args = parse_key_value_string(build_extra_args)
            self.app.log.info(f"Starting {action_desc} for {osv_id}")

            context = self._get_context(osv_id, mode=mode)
            paths_layout = self._get_paths_layout(output_dir, context.project_info.name)

            self._setup_fuzzer_container(context, paths_layout, extra_args)
            crash_info = self._run_reproduction(context, paths_layout)
            exit_code = self._handle_crash_check(context, paths_layout, crash_info)
            exit(exit_code)

        except OSVReproducerError as e:
            self.app.log.error(f"Error: {str(e)}")
        except Exception as e:
            self.app.log.error(f"Unexpected error: {str(e)}")
            if getattr(self.app.pargs, "verbose", False):
                import traceback
                self.app.log.error(traceback.format_exc())
        exit(1)

    @ex(help='Reproduce a given OSS-Fuzz vulnerability in the OSV database.')
    def reproduce(self):
        self._run_and_handle(
            self.app.pargs.osv_id, mode=ReproductionMode.CRASH, build_extra_args=self.app.pargs.build_extra_args,
            output_dir=self.app.pargs.output_dir
        )

    @ex(help='Verify if the patched version addresses the issue for a given OSS-Fuzz Issue in the OSV database.')
    def verify(self):
        self._run_and_handle(
            self.app.pargs.osv_id, mode=ReproductionMode.FIX, build_extra_args=self.app.pargs.build_extra_args,
            output_dir=self.app.pargs.output_dir
        )

    @ex(help='Checkout (at crash commit) the project for a given OSV vulnerability (useful for downstream tasks).')
    def checkout(self):
        self.app.log.info(f"Starting checkout for {self.app.pargs.osv_id}")

        if not self.app.pargs.output_dir:
            raise OSVReproducerError("Output directory is required for checkout")

        context = self._get_context(self.app.pargs.osv_id, mode=ReproductionMode.CRASH)

        output_dir = Path(self.app.pargs.output_dir).expanduser()
        target_key = f"/src/{context.project_info.name}"

        if target_key not in context.snapshot:
            raise OSVReproducerError(f"Could not find {target_key} in snapshot")

        snapshot = {
            f"/{context.project_info.name}": context.snapshot[target_key]
        }

        self.project_handler.init(context.project_info, snapshot, output_dir)

        project_path = output_dir / context.project_info.name

        if not project_path.exists():
            raise OSVReproducerError(f"Could not checkout project {context.project_info.name} for {self.app.pargs.osv_id}")

        self.app.log.info(f"Successfully checked out project {context.project_info.name} for {self.app.pargs.osv_id}")
