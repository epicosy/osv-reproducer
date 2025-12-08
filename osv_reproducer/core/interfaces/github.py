from pathlib import Path

from datetime import datetime
from abc import abstractmethod, ABC
from typing import Optional, Dict, List, Tuple

from ..models import ProjectInfo, ProjectRange


class GithubInterface(ABC):
    @abstractmethod
    def check_repo_url(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        An abstract method for validating and extracting GitHub repository information.

        This method validates whether the provided URL is a valid GitHub repository URL
        and extracts the owner and repository name. The URL can be either HTTPS or SSH format.

        Parameters
        ----------
        url : str
            The GitHub repository URL to validate and parse. Can be in HTTPS format
            (https://github.com/owner/repo) or SSH format (git@github.com:owner/repo).

        Returns
        -------
        tuple of (Optional[str], Optional[str])
            A tuple where the first element is the repository owner/organization name,
            and the second element is the repository name. If the URL is not a valid
            GitHub repository URL, both elements will be None.

        Raises
        ------
        NotImplementedError
            Always raised in the abstract definition. Subclasses implementing this
            method must override it with proper functionality.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_fix_date_range(self, project_ranges: List[ProjectRange]) -> Tuple[Optional[datetime], Optional[datetime]]:
        """
        An abstract method to calculate a fixed date range based on the specified project ranges.

        This method is expected to be implemented in subclasses. It determines an optimal date range
        based on the given list of project ranges.

        Args:
            project_ranges (List[ProjectRange]): A list of ProjectRange objects representing
            the ranges to consider.

        Returns:
            Optional[Tuple[datetime, datetime]]: A tuple containing the start and end dates if a
            fixed date range is determined, or None if no such range can be deduced.

        Raises:
            NotImplementedError: If the method is called on a class where it is not implemented.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_commit_date(self, owner: str, project: str, version: str) -> Optional[datetime]:
        """
        Abstract method to retrieve the commit date of a specific version in a project.

        This method should be implemented to fetch the date of a specified commit
        associated with the provided project, owner, and version. It is intended to be
        overridden in a subclass to provide custom functionality for retrieving the
        information from a version control system or similar service. Returns the
        date of the commit if available, or None if no such commit exists.

        Parameters:
           owner: str
               The owner of the repository containing the project.
           project: str
               The name of the project being queried.
           version: str
               The specific version or tag of the project to retrieve the commit
               date for.

        Returns:
           Optional[datetime]
               The datetime object representing the commit's date, or None if the
               commit does not exist.
        """
        raise NotImplementedError()

    @abstractmethod
    def clone_repository(self, repo_url: str, commit: str, to_path: Path, shallow: bool = True) -> Optional[Path]:
        """
        Clones a git repository to a specified target directory. This is an abstract method that needs
        to be implemented in a subclass. It provides the ability to clone a repository, check out a
        specific commit, and optionally perform a shallow clone if specified.

        Arguments:
            repo_url (str): The URL of the repository to be cloned. Should be a valid repository link.
            commit (str): The specific commit hash to check out after cloning. Required for determining
                the state of the repository.
            to_path (Path): The directory where the repository will be cloned. Must be an absolute path.
            shallow (bool): Indicates whether the clone operation should be performed as a shallow clone.
                Defaults to True if not specified.

        Returns:
            Optional[Path]: The path to the cloned repository if successful, or None if the cloning failed.
        """
        raise NotImplementedError()

    @abstractmethod
    def find_oss_fuzz_repo_commit(self, until: datetime) -> Optional[str]:
        """
        Defines an abstract method to find a specific OSS-Fuzz repository commit
        that meets certain criteria up to a specified datetime. This method is
        expected to be implemented by subclasses.

        Parameters:
            until: datetime
                The cutoff datetime. Commit search is constrained to commits made
                up to this point in time.

        Returns:
            Optional[str]: The identifier of the repository commit if found, or
            None if no commit meeting the criteria is available.

        Raises:
            NotImplementedError: Raised when the method is not implemented by a
            subclass.
        """
        raise NotImplementedError()

    def fetch_project_info(self, name: str, oss_fuzz_repo_sha: str = None) -> Optional[ProjectInfo]:
        """
        Fetches detailed information about a given project.

        This method retrieves project-related data by its name, potentially filtered
        by the specific state of an OSS-Fuzz repository. If no filters are applied, it
        will return the most relevant or recent information.

        Args:
            name (str): The unique identifier of the project whose information needs
                to be fetched.
            oss_fuzz_repo_sha (str, optional): The specific commit hash of the
                OSS-Fuzz repository to filter relevant project state. Defaults to None.

        Returns:
            Optional[ProjectInfo]: The detailed information about the project, or None
                if the project does not match the given parameters or does not exist.

        Raises:
            NotImplementedError: This method has not yet been implemented.
        """
        raise NotImplementedError()

    @abstractmethod
    def fetch_project_files(self, name: str, oss_fuzz_ref: str) -> Optional[Dict[str, bytes]]:
        """
        Fetches project files from a specified project and reference.

        This method is an abstract method and must be implemented by
        subclasses. It fetches files associated with a specified project
        name and reference within the OSS-Fuzz infrastructure. The method
        returns a mapping of file names to their corresponding contents as
        byte strings, or None if the files cannot be fetched.

        Parameters:
            name (str): The name of the project to fetch files from.
            oss_fuzz_ref (str): The reference identifier within OSS-Fuzz
                for the project, which may indicate a specific branch,
                tag, or commit.

        Returns:
            Optional[Dict[str, bytes]]: A mapping where keys are file names
                and values are the file contents in bytes if successful,
                otherwise None.

        Raises:
            NotImplementedError: Raised if the method is called directly
                before being implemented by a subclass.
        """
        raise NotImplementedError()
