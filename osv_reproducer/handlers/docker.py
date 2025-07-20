"""
Module for interacting with Docker.
"""
import docker

from ast import literal_eval
from pathlib import Path
from cement import Handler
from typing import Dict, Optional, Any, List
from docker.errors import DockerException, APIError
from docker.models.containers import Container

from ..core.exc import DockerError
from ..core.interfaces import HandlersInterface


class DockerHandler(HandlersInterface, Handler):
    """Handler for interacting with Docker."""
    class Meta:
        label = 'docker'

    def _setup(self, app):
        super()._setup(app)
        """Initialize the Docker client."""
        try:
            self.client = docker.from_env(timeout=10)
            # Test connection
            self.client.ping()
            self.app.log.info("Docker client initialized successfully")
        except DockerException as e:
            self.app.log.error(f"Failed to initialize Docker client: {str(e)}")
            raise DockerError(f"Failed to initialize Docker client: {str(e)}")

    def build_image(
            self, dockerfile_path: Path, tag: str, build_args: Optional[Dict[str, str]] = None,
            context_path: Optional[Path] = None, remove_containers: bool = True,
    ) -> str:
        """
        Build a Docker image.

        Args:
            dockerfile_path: Path to the Dockerfile.
            tag: Tag for the image.
            build_args: Build arguments.
            context_path: Path to the build context. If None, uses the directory containing the Dockerfile.
            remove_containers: Whether to remove intermediate containers.

        Returns:
            str: ID of the built image.

        Raises:
            DockerError: If building the image fails.
        """
        try:
            if not dockerfile_path.exists():
                raise DockerError(f"Dockerfile not found at {dockerfile_path}")

            if context_path is None:
                context_path = dockerfile_path.parent.expanduser()

            self.app.log.info(f"Building Docker image {tag} from {dockerfile_path}")

            # Build the image
            logs = self.client.api.build(
                path=str(context_path),
                dockerfile=dockerfile_path.name,
                tag=tag,
                buildargs=build_args,
                rm=remove_containers
            )

            # Log build output
            for line in logs:
                decoded = literal_eval(line.decode('utf-8'))

                if 'stream' in decoded:
                    self.app.log.info(decoded['stream'].strip())
                else:
                    self.app.log.info(decoded)

            image = self.client.images.get(tag)
            self.app.log.info(f"Successfully built Docker image {tag} with ID {image.id}")

            return image.id
        except (DockerException, APIError) as e:
            self.app.log.error(f"Failed to build Docker image {tag}: {str(e)}")
            raise DockerError(f"Failed to build Docker image {tag}: {str(e)}")

    def check_container_exists(self, container_name: str) -> Optional[Container]:
        """
        Check if a container with the given name already exists.

        Args:
            container_name: Name of the container to check.

        Returns:
            Container object if found, None otherwise.
        """
        existing_containers = self.client.containers.list(all=True, filters={"name": container_name})

        for container in existing_containers:
            if container.name == container_name:
                self.app.log.info(f"Container {container_name} already exists with ID {container.id}")
                return container

        self.app.log.warning(f"Container {container_name} not found")

        return None

    def check_container_exit_status(self, container: Container, exit_code: int = 0) -> bool:
        """
        Check the status of a container and determine if it needs to be recreated.

        Args:
            container: Container object to check.
            exit_code: Expected exit code of the container.

        Returns:
            bool: True if the container can be reused, False if it should be recreated.
        """
        container.reload()  # Refresh container data

        if container.attrs['State']['Status'] == 'exited':
            if exit_code != container.attrs['State']['ExitCode']:
                self.app.log.warning(f"Container {container.name} exited with code {exit_code}. Removing and recreating.")
                container.remove(force=True)
                self.app.log.info(f"Container {container.name} removed.")
                return False
            else:
                self.app.log.info(f"Container {container.name} exited with code {exit_code}.")
                return True
        else:
            self.app.log.info(f"Container {container.name} is in state: {container.attrs['State']['Status']}.")
            return True

    def run_container(
            self, image: str, container_name: str, command: Optional[List[str]] = None,
            environment: Optional[Dict[str, str]] = None, volumes: Optional[Dict[str, Dict[str, str]]] = None,
            platform: str = 'linux/amd64', privileged: bool = True, shm_size: str = '2g',
            detach: bool = True, tty: bool = False, stdin_open: bool = True
    ) -> Container:
        """
        Run a Docker container with the given parameters.

        Args:
            image: Docker image to use.
            container_name: Name for the container.
            command: Command to run in the container.
            environment: Environment variables for the container.
            volumes: Volumes to mount in the container.
            platform: Platform for the container (e.g., 'linux/amd64', 'linux/arm64').
            privileged: Whether to run the container in privileged mode.
            shm_size: Size of /dev/shm in the container.
            detach: Whether to run the container in detached mode.
            tty: Whether to allocate a pseudo-TTY.
            stdin_open: Whether to keep STDIN open.

        Returns:
            Container object.

        Raises:
            DockerError: If running the container fails.
        """
        try:
            self.app.log.info(f"Running container {container_name} with image {image}")

            # Run the container
            container = self.client.containers.run(
                image=image,
                name=container_name,
                command=command,
                detach=detach,
                privileged=privileged,
                shm_size=shm_size,
                platform=platform,
                environment=environment,
                volumes=volumes,
                tty=tty,
                stdin_open=stdin_open
            )

            self.app.log.info(f"Successfully started container {container_name} with ID {container.id}")

            return container
        except Exception as e:
            self.app.log.error(f"Failed to run container {container_name}: {str(e)}")
            raise DockerError(f"Failed to run container {container_name}: {str(e)}")

    def stream_container_logs(self, container: Container) -> List[str]:
        """
        Stream and display logs from a container.

        Args:
            container: Container object to stream logs from.
        """
        self.app.log.info(f"Streaming logs for container {container.name}:")

        logs = []

        # Stream logs line by line and manually decode bytes to strings
        for log_bytes in container.logs(stream=True, follow=True):
            line = log_bytes.decode('utf-8').strip()
            if line:  # Only log non-empty lines
                logs.append(line)
                self.app.log.info(line)

        return logs

    def check_container_exit_code(self, container: Container) -> int:
        """
        Check the exit code of a container.

        Args:
            container: Container object to check.

        Returns:
            int: Exit code of the container.
        """
        container.reload()  # Refresh container data
        exit_code = container.attrs['State']['ExitCode']

        if exit_code != 0:
            self.app.log.warning(f"Container {container.name} exited with code {exit_code}")
        else:
            self.app.log.info(f"Container {container.name} completed successfully")

        return exit_code
