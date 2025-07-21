import json

from pathlib import Path
from typing import Optional

from ..handlers.docker import DockerHandler
from ..core.exc import DockerError
from ..utils.parse.log import parse_reproduce_logs_to_dict
from ..core.models import CrashInfo, OSSFuzzIssueReport
from ..core.models.result import VerificationResult


class RunnerHandler(DockerHandler):
    """
        Build handler
    """

    class Meta:
        label = 'runner'

    def _setup(self, app):
        super()._setup(app)

    def reproduce(
            self, container_name: str, test_case_path: Path, issue_report: OSSFuzzIssueReport, out_dir: Path
    ) -> Optional[CrashInfo]:
        """
        Run a Docker container to reproduce a crash using a test case.

        Args:
            container_name: Container name.
            test_case_path: Path to the test case file.
            issue_report: OSS-Fuzz issue report.
            out_dir: Directory for output files.

        Returns:
            CrashInfo:

        Raises:
            DockerError: If running the container fails.
        """
        try:
            platform = 'linux/arm64' if issue_report.architecture == 'aarch64' else 'linux/amd64'
            out_dir.mkdir(exist_ok=True)
            crash_info_file = out_dir / "crash_info.json"

            # TODO: check if the issue_report.fuzz_target exists under the out_dir

            if crash_info_file.exists():
                with crash_info_file.open(mode="r") as f:
                    crash_info_dict = json.load(f)

                    return CrashInfo(**crash_info_dict)

            container = self.check_container_exists(container_name)

            if container:
                # Delete it if already exists
                self.app.log.info(f"Removing existing container {container_name}")
                container.remove(force=True)

            # Environment variables for the container
            environment = {
                'HELPER': 'True',
                'ARCHITECTURE': issue_report.architecture,
                'RUN_FUZZER_MODE': 'interactive'  # to store the output from the fuzzer
            }

            # Volumes to mount
            volumes = {
                str(out_dir): {'bind': '/out', 'mode': 'rw'},
                str(test_case_path): {'bind': '/testcase', 'mode': 'ro'}
            }

            self.app.log.info(f"Running container {container_name} to reproduce crash")

            # Run the container
            container = self.run_container(
                image='gcr.io/oss-fuzz-base/base-runner:latest',
                container_name=container_name,
                command=['reproduce', issue_report.fuzz_target, '-runs=100'],
                platform=platform,
                environment=environment,
                volumes=volumes,
                tty=False,
                stdin_open=True
            )

            # Stream and display logs in real-time
            logs = self.stream_container_logs(container)

            # Check container exit code
            exit_code = self.check_container_exit_code(container)

            if exit_code == 1:
                crash_info_dict = parse_reproduce_logs_to_dict(logs)

                with crash_info_file.open(mode="w") as f:
                    json.dump(crash_info_dict, f, indent=4)

                return CrashInfo(**crash_info_dict)

            return None
        except Exception as e:
            self.app.log.error(f"Failed to run container {container_name}: {str(e)}")
            raise DockerError(f"Failed to run container {container_name}: {str(e)}")

    def verify_crash(self, issue_report: OSSFuzzIssueReport, crash_info: CrashInfo) -> VerificationResult:
        """
        Verify if the given crash_info matches the crash_info in the OSSFuzzIssueReport.

        Args:
            issue_report: The OSS-Fuzz issue report containing the reference crash_info.
            crash_info: The crash_info to verify against the reference.

        Returns:
            VerificationResult: The result of the verification.
        """
        verification_result = VerificationResult(success=True)

        # Check impact
        if crash_info.impact != issue_report.crash_info.impact:
            verification_result.error_messages.append(
                f"Impact mismatch: {crash_info.impact} != {issue_report.crash_info.impact}"
            )

        # Check operation
        if crash_info.operation != issue_report.crash_info.operation:
            verification_result.error_messages.append(
                f"Operation mismatch: {crash_info.operation} != {issue_report.crash_info.operation}"
            )

        # Check size
        if crash_info.size != issue_report.crash_info.size:
            verification_result.error_messages.append(
                f"Size mismatch: {crash_info.size} != {issue_report.crash_info.size}"
            )

        # Check address
        if crash_info.address != issue_report.crash_info.address:
            self.app.log.warning(f"Address mismatch: {crash_info.address} != {issue_report.crash_info.address}")

        # Check stack frames
        report_frames_count = len(issue_report.crash_info.stack.frames)

        # Check if we have at least one frame to compare
        if report_frames_count == 0 or len(crash_info.stack.frames) == 0:
            verification_result.error_messages.append("No stack frames to compare")

        # Compare stack frames (only as many as in the OSSFuzzIssueReport)
        for i in range(min(report_frames_count, len(crash_info.stack.frames))):
            report_frame_name = issue_report.crash_info.stack.frames[i].location.logical_locations[0].name
            crash_frame_name = crash_info.stack.frames[i].location.logical_locations[0].name

            if report_frame_name != crash_frame_name:
                message = f"Stack frame {i} mismatch: {crash_frame_name} != {report_frame_name}"
                self.app.log.warning(message)

                # If it's the first frame and it doesn't match, return failure
                if i == 0:
                    verification_result.error_messages.append(message)

        if len(verification_result.error_messages) > 0:
            verification_result.success = False

        # Success condition: impact, operation, size, and first stack frame match
        return verification_result
