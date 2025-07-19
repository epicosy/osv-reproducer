import json

from pathlib import Path
from typing import Optional

from ..handlers.docker import DockerHandler
from ..core.exc import RunnerError, DockerError
from ..utils.parse.log import parse_reproduce_logs_to_dict
from ..core.models import CrashInfo, OSSFuzzIssueReport


class RunnerHandler(DockerHandler):
    """
        Build handler
    """

    class Meta:
        label = 'runner'

    def _setup(self, app):
        super()._setup(app)

    def reproduce(self, test_case_path: Path, issue_report: OSSFuzzIssueReport, out_dir: Path) -> Optional[CrashInfo]:
        """
        Run a Docker container to reproduce a crash using a test case.

        Args:
            test_case_path: Path to the test case file.
            issue_report: OSS-Fuzz issue report.
            out_dir: Directory for output files.

        Returns:
            CrashInfo:

        Raises:
            DockerError: If running the container fails.
        """
        try:
            container_name = f"{issue_report.project}_{issue_report.id}_crash"
            platform = 'linux/arm64' if issue_report.architecture == 'aarch64' else 'linux/amd64'
            out_dir.mkdir(exist_ok=True)
            crash_info_file = out_dir / "crash_info.json"

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
