from pathlib import Path

from ..core.exc import BuildError, DockerError
from ..core.models.project import ProjectInfo
from ..core.models.report import OSSFuzzIssueReport
from ..handlers.docker import DockerHandler


# TODO: probably belongs in the config
LANGUAGE_IMAGE_MAP = {
    "c++": "gcr.io/oss-fuzz-base/base-builder",
    "c": "gcr.io/oss-fuzz-base/base-builder",
    "go": "gcr.io/oss-fuzz-base/base-builder-go",
    "rust": "gcr.io/oss-fuzz-base/base-builder-rust",
    "python": "gcr.io/oss-fuzz-base/base-builder-python",
    "java": "gcr.io/oss-fuzz-base/base-builder-jvm",
    "javascript": "gcr.io/oss-fuzz-base/base-builder-javascript",
}


class BuildHandler(DockerHandler):
    """
        Build handler
    """

    class Meta:
        label = 'build'

    def _setup(self, app):
        super()._setup(app)

    def get_project_base_image(self, project_name: str) -> str:
        """
        Build the base image of a project.

        Args:
            project_name: Project name.

        Returns:
            str: ID of the built Docker image.

        Raises:
            BuildError: If building the project fails.
        """
        try:
            image_tag = f"osv-reproducer/{project_name}:latest"

            # if image exists, return tag

            if self.client.images.list(name=image_tag):
                self.app.log.info(f"Image {image_tag} already exists")
                return image_tag

            self.app.log.info(f"Building project {project_name}")
            project_info_path = self.app.projects_dir / project_name

            # Build Docker image
            self.build_image(dockerfile_path=project_info_path / "Dockerfile", tag=image_tag, remove_containers=False)
            self.app.log.info(f"Successfully built project {project_name}")

            return image_tag
        except Exception as e:
            self.app.log.error(f"Error while building project {project_name}: {str(e)}")
            raise BuildError(f"Failed to build project {project_name}: {str(e)}")

    def get_project_fuzzer_container(
            self, project_info: ProjectInfo, project_image: str, issue_report: OSSFuzzIssueReport, src_dir: Path,
            out_dir: Path, work_dir: Path, extra_args: dict = None,
    ) -> str:
        """
        Run a Docker container for fuzzing a project and display its logs.

        Args:
            project_info: Project information.
            project_image: Docker image to use.
            issue_report: OSS-Fuzz issue report.
            src_dir: Working directory for the fuzzer.
            out_dir: Directory for output files.
            work_dir: Directory for temporary files.
            extra_args: Additional arguments to pass to the fuzzer. If None, uses the default arguments.

        Returns:
            str: ID of the created or existing container.

        Raises:
            DockerError: If running the container fails.
        """
        try:
            container_name = f"{issue_report.project}_{issue_report.id}"

            # Check if container with this name already exists
            container = self.check_container_exists(container_name)
            if container:
                # Check if the container can be reused
                if self.check_container_status(container):
                    return container.id

            sanitizer = issue_report.sanitizer.split(" ")[0]
            platform = 'linux/arm64' if issue_report.architecture == 'aarch64' else 'linux/amd64'

            out_dir.mkdir(exist_ok=True)
            work_dir.mkdir(exist_ok=True)
            src_dir.mkdir(exist_ok=True)

            # Environment variables for the container
            environment = {
                'FUZZING_ENGINE': issue_report.fuzzing_engine.lower(),
                'FUZZING_LANGUAGE': project_info.language,
                'SANITIZER': sanitizer,
                'ARCHITECTURE': issue_report.architecture,
                'PROJECT_NAME': issue_report.project,
                'HELPER': 'True'
            }

            if extra_args:
                environment.update(extra_args)

            # Volumes to mount
            volumes = {
                str(out_dir): {'bind': '/out', 'mode': 'rw'},
                str(work_dir): {'bind': '/work', 'mode': 'rw'},
                str(src_dir): {'bind': '/src', 'mode': 'rw'}
            }

            # Run the container
            container = self.run_container(
                image=project_image,
                container_name=container_name,
                platform=platform,
                environment=environment,
                volumes=volumes,
                tty=False,
                stdin_open=True
            )

            # Stream and display logs in real-time
            self.stream_container_logs(container)

            # Check container exit code
            self.check_container_exit_code(container)

            return container.id
        except Exception as e:
            self.app.log.error(f"Failed to run container {container_name}: {str(e)}")
            raise DockerError(f"Failed to run container {container_name}: {str(e)}")

    def reproduce(self, test_case_path: Path, issue_report: OSSFuzzIssueReport, out_dir: Path) -> str:
        """
        Run a Docker container to reproduce a crash using a test case.

        Args:
            test_case_path: Path to the test case file.
            issue_report: OSS-Fuzz issue report.
            out_dir: Directory for output files.

        Returns:
            str: ID of the created container.

        Raises:
            DockerError: If running the container fails.
        """
        try:
            container_name = f"{issue_report.project}_{issue_report.id}_crash"
            platform = 'linux/arm64' if issue_report.architecture == 'aarch64' else 'linux/amd64'
            out_dir.mkdir(exist_ok=True)

            # Check if container with this name already exists
            container = self.check_container_exists(container_name)
            if container:
                # Check if the container can be reused
                if self.check_container_status(container):
                    return container.id

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
            self.stream_container_logs(container)

            # Check container exit code
            self.check_container_exit_code(container)

            return container.id
        except Exception as e:
            self.app.log.error(f"Failed to run container {container_name}: {str(e)}")
            raise DockerError(f"Failed to run container {container_name}: {str(e)}")
