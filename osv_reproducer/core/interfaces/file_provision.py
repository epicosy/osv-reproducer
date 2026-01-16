from pathlib import Path
from abc import ABC, abstractmethod
from typing import Optional, Dict, List

from osvutils.types.osv import OSV
from ..common.enums import ReproductionMode
from ..models import ReproductionContext, OSSFuzzIssueReport, ProjectInfo, CrashInfo


class FileProvisionInterface(ABC):
    @abstractmethod
    def get_osv_record(self, osv_id: str) -> Optional[OSV]:
        """
        An abstract method that retrieves an OSV record given its unique identifier. This method must be
        implemented by any subclass to define how to retrieve OSV records.

        Parameters:
            osv_id (str): The unique identifier of the OSV record to retrieve.

        Returns:
            Optional[OSV]: The OSV record corresponding to the provided identifier, or None if no such
            record exists.

        Raises:
            NotImplementedError: Indicates the method must be implemented in a subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def save_osv_record(self, osv: OSV) -> Optional[Path]:
        """
        An abstract method to save an OSV record. This function is meant to be
        overridden in subclasses, enabling implementation-specific logic
        to persist an OSV (Open Software Vulnerability) record and, if successful,
        return the path where the record has been saved. If saving fails or is
        unsupported, the method may return None.

        Args:
            osv (OSV): An instance of the OSV class representing an
                Open Software Vulnerability record that needs to be saved.

        Returns:
            Optional[Path]: Returns the file path to the saved OSV record
                as a Path object if the operation is successful, or None if
                the save operation fails or is not implemented.

        Raises:
            NotImplementedError: Raised if the method is called
                and has not been implemented in a derived subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_testcase_path(self, testcase_id: int) -> Optional[Path]:
        """
        Provides the interface definition for obtaining the file path of a
        test case based on its identifier. This method must be implemented
        by any subclass, as it provides application-specific logic to
        determine the file paths for storing or retrieving test cases.

        @param testcase_id: Identifier of the test case for which the file
        path is required. It should be a unique integer that allows locating
        the test case within the system.
        @type testcase_id: int

        @return: The file path of the test case if it exists, or None if the
        path cannot be determined.
        @rtype: Optional[Path]
        """
        raise NotImplementedError()

    @abstractmethod
    def get_output_path(self, osv_id: str, mode: str, file_name: str = None, mkdir: bool = False) -> Optional[Path]:
        """
        Gets the output path based on the provided ID, operational mode, and optional file name.

        This abstract method constructs the file path based on the given inputs. The exact behavior
        and implementation details depend on the subclass. This method must be implemented in any
        concrete subclass.

        Parameters:
            osv_id (str): The unique identifier for the resource.
            mode (str): The operational mode which influences the directory or file structure.
            file_name (Optional[str]): An optional name for the file to be included in the path.
            mkdir (bool): A flag indicating whether to create the directory if it doesn't exist.

        Returns:
            Optional[Path]: The constructed file path if applicable, otherwise None.
        """
        raise NotImplementedError()

    @abstractmethod
    def save_testcase(self, testcase_id: int, content: bytes) -> Optional[Path]:
        """
        Abstract method for saving a test case.

        This method is intended to be implemented by subclasses to handle the storage
        of test case content identified by a unique ID. The implementation can vary
        depending on the storage mechanism used (e.g., filesystem, database, etc.).

        Parameters:
        - testcase_id: int
            The unique identifier for the test case that needs to be saved.
        - content: bytes
            The binary data representing the content of the test case to be saved.

        Returns:
        Optional[Path]: The path to the saved test case, or None if the operation
        was not successful or not applicable.
        """
        raise NotImplementedError()

    @abstractmethod
    def load_issue_report(self, issue_id: int) -> Optional[OSSFuzzIssueReport]:
        """
        An abstract method for loading an issue report based on the given issue ID. This
        method is expected to be implemented in a subclass to provide project-specific
        logic for retrieving an OSSFuzz issue report.

        @param issue_id: The identifier of the issue report to load.
        @type issue_id: int

        @return: The loaded issue report object if found, or None if no report is
            associated with the given issue ID.
        @rtype: Optional[OSSFuzzIssueReport]

        @raises NotImplementedError: Always raised in the abstract base class, indicating
            that the method must be implemented in a subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def save_issue_report(self, issue_report: OSSFuzzIssueReport) -> Path:
        """
        An abstract method to save an issue report to a specified location. The method
        is intended to be implemented in any subclass and must handle the logic of saving
        the provided issue report appropriately.

        This method requires an issue report of type OSSFuzzIssueReport and should return
        a Path object indicating the location where the report has been saved.

        Args:
            issue_report (OSSFuzzIssueReport): The issue report that needs to be saved.

        Returns:
            Path: The file path where the issue report has been saved.

        Raises:
            NotImplementedError: Always raised by the base class to enforce implementation
            in derived classes.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_issue_id(self, osv_id: str) -> Optional[int]:
        """
        Represents an abstract method for retrieving the issue ID corresponding to a specific OSV ID.

        This method should be implemented by subclasses to fetch the issue ID based
        on the given OSV ID. Subclasses are expected to determine how the mapping between
        OSV IDs and issue IDs is defined and how the issue ID is retrieved.

        Parameters:
            osv_id (str): The identifier of the OSV issue for which the corresponding
            issue ID needs to be retrieved.

        Returns:
            Optional[int]: The issue ID corresponding to the provided OSV ID, or None
            if no matching issue ID is found.

        Raises:
            NotImplementedError: This exception is raised if the method is not implemented
            in a subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_osv_timestamp(self, osv_id: str) -> Optional[str]:
        """
        Defines an abstract method to retrieve a timestamp associated with a given Open Source Vulnerability (OSV) ID.

        This method must be implemented by a subclass. It should return the timestamp for a specified OSV ID, where the
        timestamp represents the specific moment associated with the OSV record in question. The returned value should be
        a string representing the timestamp, if it exists, or None if no timestamp is associated with the given ID.

        Parameters:
            osv_id (str): The identifier of the OSV for which the timestamp needs to be retrieved. This must be a unique
            identifier corresponding to a specific OSV record or entry.

        Returns:
            Optional[str]: A string representing the timestamp associated with the given OSV ID, or None if no timestamp is
            available.

        Raises:
            NotImplementedError: If the subclass does not implement this method.
        """
        raise NotImplementedError()

    @abstractmethod
    def set_issue_id(self, osv_id: str, issue_id: int) -> None:
        """
        Abstract method definition for setting issue ID with details.

        This method is meant to be implemented in subclasses to handle assignment of
        issue IDs to objects, taking both OSV ID and issue ID as input parameters. Its
        implementation is mandatory and specific to the subclass's requirements.

        Parameters:
            osv_id: str
                The identifier for the Open Source Vulnerability (OSV).
            issue_id: int
                The unique identifier for an issue.

        Returns:
            None

        Raises:
            NotImplementedError
                If the method is not implemented in the subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_oss_fuzz_repo_sha(self, timestamp: str) -> Optional[str]:
        """
        Retrieve the repository SHA for a specific timestamp in OSS-Fuzz.

        This abstract method should be implemented in subclasses to fetch the
        SHA hash of the repository state in an OSS-Fuzz project at the given
        timestamp. It provides a means to retrieve the identifier representing
        a specific state of the repository in time.

        Parameters:
            timestamp (str): A string representing the target timestamp for
                which the repository SHA should be retrieved. The expected
                format of the timestamp should align with the implementation's
                requirements.

        Returns:
            Optional[str]: The SHA hash as a string corresponding to the
                repository state at the specified timestamp. Returns None
                if no repository state is found for the given timestamp.
        """
        raise NotImplementedError()

    @abstractmethod
    def set_oss_fuzz_repo_sha(self, timestamp: str, oss_fuzz_repo_sha: str) -> bool:
        """
        Sets the OSS-Fuzz repository SHA for a given timestamp.

        This method is an abstract method that must be implemented in a
        subclass. It should set the specific SHA for the OSS-Fuzz repository
        corresponding to the provided timestamp.

        Arguments:
            timestamp: str
                The timestamp for which the OSS-Fuzz repository SHA needs to be
                set.
            oss_fuzz_repo_sha: str
                The specific commit SHA of the OSS-Fuzz repository to be set for
                the given timestamp.

        Returns:
            bool
                Returns True if the operation is successful, otherwise False.
        """
        raise NotImplementedError()

    @abstractmethod
    def set_osv_timestamp(self, osv_id: str, timestamp: str) -> bool:
        """
        An abstract method that is required to be implemented in subclasses. It is used to
        set the timestamp for a given OSV (Open Source Vulnerability) identifier. This
        method is abstract, so it requires explicit definition by any subclass that
        inherits it.

        Arguments:
            osv_id: The unique identifier of the OSV for which the timestamp is to be
                set.
            timestamp: The timestamp string representing the time to be set for the
                specified OSV.

        Returns:
            A boolean indicating the success or failure of the operation.

        Raises:
            NotImplementedError: Raised if the subclass does not implement this abstract
                method and it remains unimplemented at runtime.
        """
        raise NotImplementedError()

    @abstractmethod
    def load_context(self, osv_id: str, mode: ReproductionMode) -> Optional[ReproductionContext]:
        """
        Abstract method to load a reproduction context.

        This method is used to fetch and initialize a reproduction context identified
        by the provided OSV (Open Source Vulnerability) identifier. Depending on the
        specified mode, it allows for different reproduction strategies. The exact
        implementation details are to be defined in a subclass.

        Arguments:
            osv_id: str
                The unique identifier of the vulnerability to load the context for.
            mode: ReproductionMode
                The mode specifying how the context should be loaded.

        Returns:
            Optional[ReproductionContext]
                An instance of ReproductionContext if the context loading is successful,
                or None if no context can be loaded.

        Raises:
            NotImplementedError: Always raised since this is an abstract method.
        """
        raise NotImplementedError()

    @abstractmethod
    def save_context(self, context: ReproductionContext) -> Path:
        """
        An abstract method that must be implemented in subclasses to save a given reproduction context
        and return the path to the saved context.

        Raises:
            NotImplementedError: Must be implemented in subclasses to fulfill the contract of this
            abstract method.

        Args:
            context (ReproductionContext): The reproduction context to be saved.

        Returns:
            Path: The file path where the context is saved.
        """
        raise NotImplementedError()

    @abstractmethod
    def load_snapshot(self, project_name: str, sanitizer: str, timestamp: str) -> Optional[dict]:
        """
        Check if a timestamp.srcmap.json snapshot for a given project is cached and load it if it exists.

        Args:
            project_name: Name of the OSS-Fuzz project.
            sanitizer: Name of the sanitizer.
            timestamp: Timestamp of the build.

        Returns:
            Optional[dict]: The srcmap as a dictionary, or None if the file doesn't exist.
        """
        raise NotImplementedError()

    @abstractmethod
    def save_snapshot(self, srcmap: dict, project_name: str, sanitizer: str, timestamp: str) -> Path:
        """
        Save the snapshot to a file.

        Args:
            srcmap: The srcmap to save.
            project_name: Name of the OSS-Fuzz project.
            sanitizer: Name of the sanitizer.
            timestamp: Timestamp to use in the filename.

        Returns:
            Path: Path to the saved snapshot file.
        """
        raise NotImplementedError()

    @abstractmethod
    def load_project_info(self, project_name: str, oss_fuzz_repo_sha: str) -> Optional[ProjectInfo]:
        """
        Abstract method to load project information.

        This method must be implemented in a subclass to load specific project information
        such as name and repository state.

        Args:
            project_name: The name of the project whose information is to be loaded.
            oss_fuzz_repo_sha: The SHA of the OSS-Fuzz repository to retrieve information from.

        Returns:
            An instance of ProjectInfo if the project information is successfully loaded,
            or None if the information cannot be found.

        Raises:
            NotImplementedError: This method is abstract and must be overridden in a subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def save_project_info(self, project_info: ProjectInfo) -> Optional[Path]:
        """
        An abstract method for saving project information.

        This method is responsible for saving the details of a given project.
        It requires implementation in a subclass and does not contain a default
        implementation itself. The method is expected to handle the `ProjectInfo`
        object to save it and optionally return the path where the information
        was saved. If saving fails or is not handled, the method may return None.

        Parameters:
        project_info: ProjectInfo
            The project information to be saved. It encapsulates all necessary
            details about the project.

        Returns:
        Optional[Path]
            The file path where the project information was saved, or None if
            the operation fails or is not applicable.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_project_files(self, name: str, oss_fuzz_repo_sha: str) -> Optional[Dict[str, bytes]]:
        """
        An abstract method for retrieving project files from a repository given the
        project name and the specific repository commit SHA. Returns a dictionary
        mapping file names to their byte content if successful, or None if no files
        are found.

        Args:
            name (str): The name of the project for which the files need to be
                retrieved.
            oss_fuzz_repo_sha (str): The commit SHA of the OSS-Fuzz repository to
                fetch files from.

        Returns:
            Optional[Dict[str, bytes]]: A dictionary where the keys are file names and
            the values are their corresponding content in bytes, or None if no files
            could be retrieved.

        Raises:
            NotImplementedError: If the method is not implemented by the subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_project_path(self, project_name: str, oss_fuzz_repo_sha: str) -> Optional[Path]:
        """
        Abstract method to retrieve the project path given the project name and repository SHA.

        This method must be implemented by any subclass and is used to determine
        the file path associated with a specific project.

        Args:
            project_name: Name of the project as a string.
            oss_fuzz_repo_sha: OSS-Fuzz repository SHA as a string.

        Returns:
            Optional[Path]: The Path object representing the project path,
            or None if the path cannot be determined.

        Raises:
            NotImplementedError: This method must be implemented in a subclass and
            will raise this error if not overridden.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_project_file_path(self, project_name: str, oss_fuzz_repo_sha: str, file_name: str) -> Optional[Path]:
        """
        Provides an abstract method definition for retrieving the file path of a project file.

        This method is designed to be overridden by subclasses which implement the logic to construct and return
        the path to a project-specific file based on the given parameters. The method raises a NotImplementedError
        in the base class and does not contain functionality by itself.

        Arguments:
            project_name: str
                The name of the project for which the file path is being retrieved.
            oss_fuzz_repo_sha: str
                The OSS-Fuzz repository SHA corresponding to the desired revision of the file.
            file_name: str
                The name of the file within the project's directory.

        Returns:
            Path
                A `Path` object representing the file path for the given project, repository SHA, and file name.

        Raises:
            NotImplementedError
                Always raised when called from the base class, signaling that the method must be
                implemented in a subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def save_project_files(self, name: str, oss_fuzz_repo_sha: str, project_files: Dict[str, bytes]) -> bool:
        """
        An abstract method intended to save project-related files in a persistent storage
        medium after associating them with a project name and a repository commit SHA. This
        method supports writing multiple files in a single operation.

        Arguments:
            name (str): The name of the project to be associated with the saved files.
            oss_fuzz_repo_sha (str): The OSS-Fuzz repository commit SHA that identifies the
                version of the project files.
            project_files (Dict[str, bytes]): A dictionary mapping file names to their
                corresponding content in binary format, which represents the project files
                to save.

        Returns:
            bool: A boolean indicating whether the operation was successful or not.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_repository_path(self, owner: str, repository: str, version: str, check: bool = True) -> Optional[Path]:
        """
        Represents an abstract method to retrieve the path of a specific repository. This method
        requires the owner, repository name, and version as mandatory inputs. The function returns
        the file path of the repository if found or None if there is no corresponding repository path.

        Arguments:
            owner: str
                The username or organization name owning the repository.
            repository: str
                The name of the repository whose path is being retrieved.
            version: str
                The version of the repository (e.g., a specific branch, tag, or commit).
            check: bool, optional
                This parameter is used to determine whether the function should raise an exception

        Returns:
            Path:
                A Path object pointing to the location of the repository;

        Raises:
            NotImplementedError:
                This method must be implemented by a concrete subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def load_crash_info(self, osv_id: str, mode: str) -> Optional[CrashInfo]:
        """
        An abstract method that retrieves crash information based on the Open Source Vulnerability
        ID (osv_id) and the mode of operation. It is expected to be implemented by subclasses
        to provide specific behavior for fetching crash details.

        Parameters:
            osv_id (str): The identifier of the operating system vulnerability for which crash information
                is being retrieved.
            mode (str): The mode in which the crash information should be fetched. This may dictate
                the format or specific details included in the returned crash information.

        Raises:
            NotImplementedError: Always raised if the method is not implemented in a subclass.

        Returns:
            Optional[CrashInfo]: An object containing crash information, or None if no crash information
                is available for the given inputs.
        """
        raise NotImplementedError()

    @abstractmethod
    def save_crash_info(self, osv_id: str, mode: str, crash_info: CrashInfo) -> Optional[Path]:
        """
        Abstract method to save crash information for a given Open Source Vulnerability (OSV) ID.

        This method is intended to handle and store crash information in a specified
        manner depending on the mode provided. It serves as a template to be implemented
        by subclasses.

        Arguments:
            osv_id: A string representing the identifier of the Open Source Vulnerability (OSV).
            mode: A string that specifies the mode of saving the crash information.
            crash_info: An instance of CrashInfo containing detailed information about the crash.

        Returns:
            An optional Path object representing the file path where crash information
            is saved, or None if saving was not successful.
        """
        raise NotImplementedError()

    @abstractmethod
    def load_runner_logs(self, osv_id: str, mode: str) -> Optional[List[str]]:
        """
        This method is an abstract method that must be overridden in subclasses to load
        runner logs based on the provided osv_id and mode. It is designed as part of an
        interface or abstract base class for handling runner log retrieval logic. If not
        overridden, it will raise a `NotImplementedError`.

        Args:
            osv_id (str): The unique identifier for the operational service view (OSV).
            mode (str): The mode in which the logs are to be retrieved. Possible mode
                values depend on the implementation of subclasses.

        Returns:
            Optional[List[str]]: A list of runner log entries if found, otherwise None.

        Raises:
            NotImplementedError: If this method is called on the base class without an
                appropriate override in a subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def save_runner_logs(self, osv_id: str, mode: str, logs: List[str]):
        """
        Abstract method for saving runner logs associated with a specific operation or
        process. This method must be implemented by subclasses, ensuring that the logs
        are saved for a particular osv_id and mode.

        Args:
            osv_id: The identifier of the operation or process for which logs are being
                saved.
            mode: The operational mode or context in which the logs are being saved.
            logs: A list of log messages or entries associated with the specified
                operation and mode.

        Raises:
            NotImplementedError: If the subclass does not implement this method.

        """
        raise NotImplementedError()
