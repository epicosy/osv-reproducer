from pathlib import Path
from abc import ABC, abstractmethod
from typing import Optional, List, Dict

#TODO: replace external dependency with internal model
from docker.models.containers import Container


class DockerInterface(ABC):
    @abstractmethod
    def build_image(
            self, context_path: Path, tag: str, build_args: Optional[Dict[str, str]] = None,
            remove_containers: bool = True, **kwargs
    ) -> str:
        """
        An abstract method that defines the interface for building a container image. This method
        must be implemented by subclasses to provide the functionality for building a Docker or
        similar container image using the provided arguments.

        Args:
            context_path (Path): The path to the directory containing the build context.
            tag (str): The image tag to apply to the built container image.
            build_args (Optional[Dict[str, str]]): Optional build-time arguments for
                customizing the image build process.
            remove_containers (bool): Indicates whether intermediate containers created
                during the build process should be removed.
            **kwargs: Additional keyword arguments for extended functionality.

        Raises:
            NotImplementedError: If the implementing subclass does not provide the
                method implementation.

        Returns:
            str: The identifier or tag of the built container image.
        """
        raise NotImplementedError()

    @abstractmethod
    def check_image_exists(self, image_name: str) -> Optional[str]:
        """
        Check if an image exists in the image list.

        This method verifies the existence of an image identified by its name in the
        client's image list. If the image is found, it logs the information and returns
        the name of the image. If not found, it returns None.

        Parameters:
        image_name: str
            The name of the image to check for existence.

        Returns:
        Optional[str]
            The name of the image if it exists, otherwise None.
        """
        raise NotImplementedError()

    @abstractmethod
    def check_container_exists(self, container_name: str) -> Optional[Container]:
        """
        Checks if a container with the specified name exists in the Docker environment and returns it if found.

        This method searches for a container by its name among the available containers
        managed by the Docker client. If a matching container is found, it logs the
        information and returns the container object. If no match is found, it logs a
        warning and returns None.

        Parameters:
            container_name: str
                The name of the container to check for existence.

        Returns:
            Optional[Container]
                The container object if it exists, or None if no container is found.
        """
        raise NotImplementedError()

    @abstractmethod
    def check_container_exit_status(self, container: Container, exit_code: int = 0) -> bool:
        """
        Check the status of a container and determine if it needs to be recreated.

        Args:
            container: Container object to check.
            exit_code: Expected exit code of the container.

        Returns:
            bool: True if the container can be reused, False if it should be recreated.
        """
        raise NotImplementedError()

    @abstractmethod
    def run_container(
            self, image: str, container_name: str, command: Optional[List[str]] = None,
            environment: Optional[Dict[str, str]] = None, volumes: Optional[Dict[str, Dict[str, str]]] = None,
            platform: str = 'linux/amd64', privileged: bool = True, shm_size: str = '2g', detach: bool = True,
            tty: bool = False, stdin_open: bool = True, remove: bool = False,
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
            remove: Whether to remove the container when it exits.

        Returns:
            Container object.

        Raises:
            DockerError: If running the container fails.
        """
        raise NotImplementedError()

    @abstractmethod
    def stream_container_logs(self, container: Container) -> List[str]:
        """
        Stream and display logs from a container.

        Args:
            container: Container object to stream logs from.
        """
        raise NotImplementedError()

    @abstractmethod
    def check_container_exit_code(self, container: Container) -> Optional[int]:
        """
        Check the exit code of a container.

        Args:
            container: Container object to check.

        Returns:
            int: Exit code of the container.
        """
        raise NotImplementedError()

    @abstractmethod
    def container_ran(
            self, container: Container, expected_exit_code: Optional[int] = None, require_logs: bool = False,
            require_no_error: bool = False
    ) -> bool:
        """
        Checks if a Docker container ran successfully based on various criteria.

        This method inspects the state of a given Docker container and checks whether
        it ran successfully according to the specified parameters. It can verify if
        the container started, its state, logs output, errors, and exit code. The method
        returns a boolean indicating whether the container met the criteria.

        Parameters:
            container (Container): The Docker container to be inspected.
            expected_exit_code (Optional[int]): The exit code to verify against the
                container's exit state. Defaults to None, implying no exit code check.
            require_logs (bool): Whether to require the container to have produced logs.
                Defaults to False.
            require_no_error (bool): Whether to ensure the container did not encounter
                any errors. Defaults to False.

        Returns:
            bool: True if the container ran successfully based on the specified criteria,
            otherwise False.
        """
        raise NotImplementedError()
