from typing import Optional

from ..core.exc import RunnerError
from ..core.common.enums import ReproductionMode
from ..utils.parse.log import parse_reproduce_logs_to_dict
from ..core.interfaces import DockerInterface, FileProvisionInterface
from ..core.models import ReproductionContext, VerificationResult, OSSFuzzIssueReport, CrashInfo


class RunnerService:
    def __init__(self, file_provision_handler: FileProvisionInterface, docker_handler: DockerInterface):
        self.docker_handler = docker_handler
        self.file_provision_handler = file_provision_handler

    def reproduce(self, context: ReproductionContext) -> Optional[CrashInfo]:
        """
        Run a Docker container to reproduce a crash using a test case.

        Args:
            context: The reproduction context.

        Returns:
            CrashInfo:

        Raises:
            RunnerError: If running the container fails.
        """
        try:
            fuzzer_path = self.file_provision_handler.get_output_path(
                context.id, context.mode.value, context.issue_report.fuzz_target
            )

            if not fuzzer_path.exists():
                raise RunnerError(f"Fuzzer does not exist at {fuzzer_path}")

            test_case_path = self.file_provision_handler.get_testcase_path(context.issue_report.testcase_id)

            if not test_case_path:
                raise RunnerError(f"Test case {context.issue_report.testcase_id} not found in the file provisioner")

            # TODO: this should return the string and not the raw Docker container object
            container = self.docker_handler.check_container_exists(context.runner_container_name)

            if container:
                # Delete it if already exists
                print(f"Removing existing container {context.runner_container_name}")
                # TODO: this should be done by the docker handler
                container.remove(force=True)

            # Environment variables for the container
            environment = {
                'HELPER': 'True',
                'ARCHITECTURE': context.issue_report.architecture,
                'RUN_FUZZER_MODE': 'interactive',  # to store the output from the fuzzer
                'SANITIZER': context.issue_report.sanitizer
            }

            # Volumes to mount
            volumes = {
                str(fuzzer_path): {'bind': f'/out/{context.issue_report.fuzz_target}', 'mode': 'rw'},
                str(test_case_path): {'bind': '/testcase', 'mode': 'ro'}
            }

            print(f"Running container {context.runner_container_name} to reproduce crash")

            # Run the container
            container = self.docker_handler.run_container(
                image='gcr.io/oss-fuzz-base/base-runner:latest',
                container_name=context.runner_container_name,
                command=['reproduce', context.issue_report.fuzz_target, '-runs=100'],
                platform='linux/arm64' if context.issue_report.architecture == 'aarch64' else 'linux/amd64',
                environment=environment,
                volumes=volumes,
                tty=False,
                stdin_open=True
            )

            # Stream and display logs in real-time
            logs = self.docker_handler.stream_container_logs(container)

            # Check container exit code
            exit_code = self.docker_handler.check_container_exit_code(container)

            if exit_code == 1:
                crash_info_dict = parse_reproduce_logs_to_dict(logs)

                if crash_info_dict:
                    return CrashInfo(**crash_info_dict)

            return None
        except Exception as e:
            raise RunnerError(f"Failed to run container {context.runner_container_name}: {str(e)}")

    # TODO: can be refactored into smaller static methods
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
        if issue_report.crash_info.size and crash_info.size != issue_report.crash_info.size:
            verification_result.error_messages.append(
                f"Size mismatch: {crash_info.size} != {issue_report.crash_info.size}"
            )

        # Check address
        if crash_info.address != issue_report.crash_info.address:
            print(f"Address mismatch: {crash_info.address} != {issue_report.crash_info.address}")

        # Check stack frames
        report_frames_count = len(issue_report.crash_info.stack.frames)

        # Check if we have at least one frame to compare
        if report_frames_count == 0 or len(crash_info.stack.frames) == 0:
            verification_result.error_messages.append("No stack frames to compare")
            return verification_result

        # Check if we need to shift the crash_info stack frames
        # This handles cases where the first frame could be a sanitizer function (like __asan_memcpy)
        shift = 0
        if len(crash_info.stack.frames) > 1:
            report_first_frame = issue_report.crash_info.stack.frames[0].location.logical_locations[0].name
            crash_first_frame = crash_info.stack.frames[0].location.logical_locations[0].name

            if report_first_frame != crash_first_frame:
                # Try to find a matching frame by shifting through the crash frames
                match_found = False
                for potential_shift in range(1, len(crash_info.stack.frames)):
                    crash_frame = crash_info.stack.frames[potential_shift].location.logical_locations[0].name
                    if report_first_frame == crash_frame:
                        verification_result.matched_frame = crash_frame
                        print(f"First frame did not match, shifting stack frames by {potential_shift}")
                        shift = potential_shift
                        match_found = True
                        break

                if not match_found:
                    verification_result.error_messages.append(
                        "No matching stack frames found after shifting through all frames"
                    )

        # Compare stack frames (only as many as in the OSSFuzzIssueReport)
        for i in range(min(report_frames_count, len(crash_info.stack.frames) - shift)):
            report_frame_name = issue_report.crash_info.stack.frames[i].location.logical_locations[0].name
            crash_frame_name = crash_info.stack.frames[i + shift].location.logical_locations[0].name

            if report_frame_name != crash_frame_name:
                message = f"Stack frame {i} mismatch: {crash_frame_name} != {report_frame_name}"
                print(message)

                # If it's the first frame and it doesn't match, add an error message
                if i == 0:
                    verification_result.error_messages.append(message)

        if len(verification_result.error_messages) > 0:
            verification_result.success = False

        # Success condition: impact, operation, size, and first stack frame match
        return verification_result

    def get_crash_info(self, context: ReproductionContext) -> Optional[CrashInfo]:
        crash_info = self.file_provision_handler.load_crash_info(context.id, context.mode.value)

        if not crash_info:
            crash_info = self.reproduce(context)

            if crash_info:
                self.file_provision_handler.save_crash_info(context.id, context.mode.value, crash_info)
                return crash_info

        return None

    def __call__(self, context: ReproductionContext) -> VerificationResult:
        crash_info = self.get_crash_info(context)

        # TODO: should return the string and not the raw Docker container object
        fuzzer_container = self.docker_handler.check_container_exists(context.runner_container_name)

        if not fuzzer_container:
            raise RunnerError(f"Container {context.runner_container_name} not found")

        if not self.docker_handler.container_ran(
            fuzzer_container, expected_exit_code=0 if context.mode == ReproductionMode.FIX else 1,
            require_logs=True, require_no_error=True,
        ):
            raise RunnerError(f"Container {context.runner_container_name} did not run successfully")

        if context.mode == ReproductionMode.FIX:
            verification = VerificationResult(success=crash_info is None)

            if verification.success:
                print(f"Patch addressed the crash for {context.id} vulnerability")
            else:
                print(f"{context.id} patch did not address the crash:\n{crash_info}")
        else:
            if crash_info:
                verification = self.verify_crash(context.issue_report, crash_info)

                if verification.success:
                    print(f"Successfully reproduced vulnerability {context.id}")
                else:
                    print(f"{context.id} reproduction did not yield expected values:\n{verification.error_messages}")
            else:
                verification = VerificationResult(success=False)
                print(f"Could not reproduce {context.id} vulnerability")

        return verification
