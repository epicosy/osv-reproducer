"""
Module for interacting with Docker.
"""
import docker

from pathlib import Path
from cement import Handler
from ast import literal_eval
from typing import Dict, Optional, List

from docker.models.containers import Container
from docker.errors import DockerException, APIError

from ..core.exc import DockerError
from ..handlers import HandlersInterface
from ..core.interfaces import DockerInterface


class DockerHandler(DockerInterface, HandlersInterface, Handler):
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
            self, context_path: Path, tag: str, build_args: Optional[Dict[str, str]] = None,
            remove_containers: bool = True, **kwargs
    ) -> str:
        """
        Build a Docker image.

        Args:
            context_path: Path to the directory containing the Dockerfile and build context files.
            tag: Tag for the image.
            build_args: Build arguments.
            remove_containers: Whether to remove intermediate containers.
            kwargs: Additional keyword arguments to pass to docker.api.build().

        Returns:
            str: ID of the built image.

        Raises:
            DockerError: If building the image fails.
        """
        try:
            self.app.log.info(f"Building Docker image {tag}")

            # Build the image
            logs = self.client.api.build(
                path=str(context_path),
                dockerfile="Dockerfile",
                tag=tag,
                buildargs=build_args,
                rm=remove_containers,
                **kwargs
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

    def check_image_exists(self, image_name: str) -> Optional[str]:
        if self.client.images.list(name=image_name):
            self.app.log.info(f"Image {image_name} already exists")

            return image_name

        return None

    def check_container_exists(self, container_name: str) -> Optional[Container]:
        existing_containers = self.client.containers.list(all=True, filters={"name": container_name})

        for container in existing_containers:
            if container.name == container_name:
                self.app.log.info(f"Container {container_name} already exists with ID {container.id}")
                return container

        self.app.log.warning(f"Container {container_name} not found")

        return None

    def check_container_exit_status(self, container: Container, exit_code: int = 0) -> bool:
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
            platform: str = 'linux/amd64', privileged: bool = True, shm_size: str = '2g', detach: bool = True,
            tty: bool = False, stdin_open: bool = True, remove: bool = False,
    ) -> Container:
        try:
            self.app.log.info(f"Running container {container_name} with image {image} on command {command}")

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
                stdin_open=stdin_open,
                remove=remove
            )

            if not container:
                raise ValueError(f"Container {container_name} failed")

            self.app.log.info(f"Successfully started container {container_name} with ID {container.id}")

            return container
        except Exception as e:
            self.app.log.error(f"Failed to run container {container_name}: {str(e)}")
            raise DockerError(f"Failed to run container {container_name}: {str(e)}")

    def stream_container_logs(self, container: Container) -> List[str]:
        self.app.log.info(f"Streaming logs for container {container.name}:")

        logs = []

        # Stream logs line by line and manually decode bytes to strings
        for log_bytes in container.logs(stream=True, follow=True):
            line = log_bytes.decode('utf-8').strip()
            if line:  # Only log non-empty lines
                logs.append(line)
                self.app.log.info(line)

        return logs

    def check_container_exit_code(self, container: Container) -> Optional[int]:
        if not container:
            return None

        container.reload()  # Refresh container data
        exit_code = container.attrs['State']['ExitCode']

        if exit_code != 0:
            self.app.log.warning(f"Container {container.name} exited with code {exit_code}")
        else:
            self.app.log.info(f"Container {container.name} completed successfully")

        return exit_code

    def container_ran(
            self, container: Container, expected_exit_code: Optional[int] = None, require_logs: bool = False,
            require_no_error: bool = False
    ) -> bool:
        if not container:
            return False

        state = container.attrs.get("State", {})

        # --- 1. Did it ever start? ---
        started_at = state.get("StartedAt", "")
        if not started_at or started_at.startswith("0001"):
            self.app.log.warning(f"Container {container.name} never started")
            return False

        # --- 2. Check status ---
        status = state.get("Status", "")
        if status in ("created", ""):
            self.app.log.warning(f"Container {container.name} was created but never started")
            return False

        # --- 3. Check logs (optional) ---
        if require_logs:
            logs = container.logs(stdout=True, stderr=True).strip()

            if not logs:
                self.app.log.warning(f"Container {container.name} did not produce any logs")
                return False

        # --- 4. Check error (optional) ---
        error = state.get("Error") or state.get("OOMKilled") or None
        # Docker may report "Error" directly in State, no need for wait()
        if require_no_error and error:
            self.app.log.warning(f"Container {container.name} encountered an error: {error}")
            return False

        # --- 5. Check exit code (optional) ---
        exit_code = state.get("ExitCode")
        if expected_exit_code is not None:
            return exit_code == expected_exit_code

        # If we get here, the container ran at least once
        return True
