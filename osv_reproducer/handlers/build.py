from pathlib import Path
from docker.models.containers import Container

from ..handlers.docker import DockerHandler
from ..core.exc import BuildError, DockerError
from ..core.models import ProjectInfo, OSSFuzzIssueReport


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
    ) -> Container:
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
            str: name of the created or existing container.

        Raises:
            DockerError: If running the container fails.
        """
        try:
            container_name = f"{issue_report.project}_{issue_report.id}"

            # Check if container with this name already exists
            container = self.check_container_exists(container_name)

            if container:
                # Check if the container can be reused
                if self.check_container_exit_status(container):
                    return container

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

            return container
        except Exception as e:
            self.app.log.error(f"Failed to run container {container_name}: {str(e)}")
            raise DockerError(f"Failed to run container {container_name}: {str(e)}")
