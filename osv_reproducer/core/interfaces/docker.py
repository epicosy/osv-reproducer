from pathlib import Path
from abc import ABC, abstractmethod
from typing import Optional, List, Dict


class DockerInterface(ABC):
    @abstractmethod
    def build_image(
            self, context_path: Path, tag: str, build_args: Optional[Dict[str, str]] = None,
            remove_containers: bool = True, **kwargs
    ) -> Optional[str]:
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
            Optional[str]: The identifier or tag of the built container image if successful, otherwise None.
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
    def remove_container(self, container_name: str) -> bool:
        """
        An abstract method to remove a container by its name. This method must be
        implemented in the child class. It is used to locate and remove the
        specified container. The method will return a boolean indicating whether
        the removal was successful or not. Implementers should handle the necessary
        logic for finding and removing the container.

        Parameters:
            container_name (str): The name of the container to be removed.

        Returns:
            bool: True if the container is successfully removed, otherwise False.

        Raises:
            NotImplementedError: If the method is not implemented in the subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def check_container_exists(self, container_name: str) -> Optional[str]:
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
            Optional[str]
                The container name if it exists, or None if no container is found.
        """
        raise NotImplementedError()

    @abstractmethod
    def check_container_exit_status(self, container_name: str, exit_code: int = 0) -> bool:
        """
        Check the exit status of a container against the expected value.

        This abstract method is intended to verify whether the exit status of a specified
        container matches the provided expected exit code. The method must be implemented
        by any subclass deriving from the base class.

        Args:
            container_name (str): The identifier or name of the container whose exit status will
                be verified.
            exit_code (int, optional): The expected exit code to check against the container's
                actual exit status. Defaults to 0.

        Raises:
            NotImplementedError: Raised when the method is not implemented in the subclass.

        Returns:
            bool: True if the container's exit status matches the expected `exit_code`,
            otherwise False.
        """
        raise NotImplementedError()

    @abstractmethod
    def run_container(
            self, image: str, container_name: str, command: Optional[List[str]] = None,
            environment: Optional[Dict[str, str]] = None, volumes: Optional[Dict[str, Dict[str, str]]] = None,
            platform: str = 'linux/amd64', privileged: bool = True, shm_size: str = '2g', detach: bool = True,
            tty: bool = False, stdin_open: bool = True, remove: bool = False,
    ) -> Optional[str]:
        """
        An abstract method for running containers based on a given image. This method is expected
        to be implemented by subclasses to handle the logic of container execution with configurable
        options such as environment variables, volume bindings, platform specification, and execution
        flags. The method handles parameters for advanced configurations, including privilege levels
        and memory allocation, and returns the identifier of the started container.

        Args:
            image (str): The name of the container image to run.
            container_name (str): The desired name for the container.
            command (Optional[List[str]]): The command to execute within the container. Defaults to None.
            environment (Optional[Dict[str, str]]): A dictionary of environment variables to set within
                the container. Defaults to None.
            volumes (Optional[Dict[str, Dict[str, str]]]): A mapping of volume bindings for the container.
                Defaults to None.
            platform (str): The target platform to use when running the container. Defaults to 'linux/amd64'.
            privileged (bool): Whether to run the container in privileged mode. Defaults to True.
            shm_size (str): The size of the shared memory to allocate, e.g., '2g'. Defaults to '2g'.
            detach (bool): Whether to run the container in detached mode. Defaults to True.
            tty (bool): Whether to allocate a TTY for the container. Defaults to False.
            stdin_open (bool): Whether to keep STDIN open even if not attached. Defaults to True.
            remove (bool): Whether to automatically remove the container when it exits. Defaults to False.

        Returns:
            Optional[str]: The identifier of the started container if successful, otherwise None.

        Raises:
            NotImplementedError: This is an abstract method and must be implemented by any subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def stream_container_logs(self, container_name: str) -> List[str]:
        """
        Abstract method to stream logs from a container.

        This method must be implemented by subclasses to provide functionality
        for fetching and streaming logs from a running container. The implementation
        should return the logs as a list of strings.

        Parameters:
        container_name : str
            The identifier or name of the container whose logs are to be streamed.

        Returns:
        List[str]
            A list of strings where each string represents a line of the container's
            log output.
        """
        raise NotImplementedError()

    @abstractmethod
    def check_container_exit_code(self, container_name: str) -> Optional[int]:
        """
        Represents an abstract method to check the exit code of a specific container.

        This method is intended to be implemented by subclasses to provide logic
        for retrieving the exit code of a container. It should return the exit code
        if available or None if the information cannot be retrieved.

        Parameters:
        container_name: str
            The name or identifier of the container whose exit code should be checked.

        Returns:
        Optional[int]
            The exit code of the container if available, or None if the exit code
            cannot be determined.

        Raises:
        NotImplementedError
            If the method is not implemented in a subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def container_ran(
            self, container_name: str, expected_exit_code: Optional[int] = None, require_logs: bool = False,
            require_no_error: bool = False
    ) -> bool:
        """
        Checks if a container ran successfully based on provided requirements.

        This abstract method is intended to verify the execution of a container by
        checking its name, expected exit code, whether logs are required, and whether
        errors should be absent.

        Parameters:
        container_name (str): The name of the container to verify.
        expected_exit_code (Optional[int]): The expected exit code of the container. Default is None.
        require_logs (bool): A flag indicating if logs are required. Default is False.
        require_no_error (bool): A flag indicating if no error is expected. Default is False.

        Returns:
        bool: True if the container meets the specified requirements, otherwise False.

        Raises:
        NotImplementedError: This is an abstract method and should be implemented in
        a subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def find_log_error_code(self, container_name: str, last_n_log_lines: int = 10) -> Optional[int]:
        """
        Finds the most relevant error code from the logs of the specified container. This is an
        abstract method and must be implemented by subclasses. The method retrieves the last specified
        number of log lines from the container to analyze and identify the error code.

        :param container_name: Name of the container for which logs should be accessed.
        :type container_name: str
        :param last_n_log_lines: Number of log lines to retrieve from the container's log output,
            defaulting to 10.
        :type last_n_log_lines: int
        :raises NotImplementedError: Indicates that this method is abstract and needs to be
            implemented in a subclass.
        :return: An optional integer representing the error code found in the logs, or None if
            no error code is detected.
        :rtype: Optional[int]
        """
        raise NotImplementedError()
