from typing import Optional

from ..core.exc import RunnerError
from ..core.common.enums import ReproductionMode
from ..core.models import ReproductionContext, CrashInfo
from ..utils.parse.log import parse_reproduce_logs_to_dict
from ..core.interfaces import DockerInterface, FileProvisionInterface


class RunnerService:
    def __init__(self, file_provision_handler: FileProvisionInterface, docker_handler: DockerInterface):
        self.docker_handler = docker_handler
        self.file_provision_handler = file_provision_handler

    def _reproduce(self, context: ReproductionContext) -> Optional[CrashInfo]:
        """
        Run a Docker container to reproduce a crash using a test case.

        Args:
            context: The reproduction context.

        Returns:
            CrashInfo:

        Raises:
            RunnerError: If running the container fails.
        """
        fuzzer_path = self.file_provision_handler.get_output_path(
            context.id, context.mode.value, context.issue_report.fuzz_target
        )

        if not fuzzer_path.exists():
            raise RunnerError(f"Fuzzer does not exist at {fuzzer_path}")

        test_case_path = self.file_provision_handler.get_testcase_path(context.issue_report.testcase_id)

        if not test_case_path:
            raise RunnerError(f"Test case {context.issue_report.testcase_id} not found in the file provisioner")

        if self.docker_handler.check_container_exists(context.runner_container_name):
            self.docker_handler.remove_container(context.runner_container_name)

        # Environment variables for the container
        environment = {
            'HELPER': 'True',
            'ARCHITECTURE': context.issue_report.architecture,
            'RUN_FUZZER_MODE': 'interactive',  # to store the output from the fuzzer
            'SANITIZER': context.issue_report.sanitizer,
        }

        # Volumes to mount
        volumes = {
            str(fuzzer_path): {'bind': f'/out/{context.issue_report.fuzz_target}', 'mode': 'rw'},
            str(test_case_path): {'bind': '/testcase', 'mode': 'ro'}
        }

        # Run the container
        if not self.docker_handler.run_container(
            image='gcr.io/oss-fuzz-base/base-runner:latest',
            container_name=context.runner_container_name,
            command=['reproduce', context.issue_report.fuzz_target, '-runs=1'],
            platform='linux/arm64' if context.issue_report.architecture == 'aarch64' else 'linux/amd64',
            environment=environment,
            volumes=volumes,
            tty=False,
            stdin_open=True
        ):
            raise RunnerError(f"Failed to run container {context.runner_container_name}: empty container ID returned")

        # Stream and display logs in real-time
        logs = self.docker_handler.stream_container_logs(context.runner_container_name)

        if not self.docker_handler.container_ran(
                context.runner_container_name, require_logs=True, require_no_error=True,
                expected_exit_code=0 if context.mode == ReproductionMode.FIX else 1
        ):
            raise RunnerError(f"Container {context.runner_container_name} did not run successfully")

        self.file_provision_handler.save_runner_logs(
            osv_id=context.id, mode=context.mode.value, logs=[l + '\n' for l in logs]
        )

        # Check container exit code
        exit_code = self.docker_handler.check_container_exit_code(context.runner_container_name)

        if exit_code == 1:
            crash_info_dict = parse_reproduce_logs_to_dict(logs)

            if crash_info_dict:
                return CrashInfo(**crash_info_dict)

        return None

    def __call__(self, osv_id: str, mode: ReproductionMode) -> bool:
        context = self.file_provision_handler.load_context(osv_id, mode)

        if not context:
            raise RunnerError(f"Context for OSV {osv_id} in mode {mode.value} not found")

        if not self.file_provision_handler.load_crash_info(context.id, context.mode.value):
            container_ran = self.docker_handler.container_ran(
                context.runner_container_name, expected_exit_code=0 if context.mode == ReproductionMode.FIX else 1,
                require_logs=True, require_no_error=True,
            )
            container_exists = self.docker_handler.check_container_exists(context.runner_container_name)

            if not container_exists or not container_ran:
                crash_info = self._reproduce(context)

                if crash_info:
                    self.file_provision_handler.save_crash_info(context.id, context.mode.value, crash_info)

        return True
