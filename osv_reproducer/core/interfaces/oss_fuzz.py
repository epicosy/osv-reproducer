from abc import abstractmethod
from pydantic import AnyHttpUrl
from typing import Tuple, Optional

from ...core.models import OSSFuzzIssueReport


class OSSFuzzInterface:
    @abstractmethod
    def fetch_test_case_content(self, url: AnyHttpUrl) -> Optional[bytes]:
        """
        Retrieves the content of a test case from a URL without saving it.

        Args:
            url (AnyHttpUrl): The URL to download the test case from.

        Returns:
            Optional[bytes]: The content of the test case, or None if the download failed.
        """
        raise NotImplementedError()

    @abstractmethod
    def fetch_issue_report(self, issue_id: int) -> Optional[OSSFuzzIssueReport]:
        """
        Fetches the detailed issue report for a given OSSFuzz issue ID.

        This is an abstract method that subclasses must implement to retrieve
        information about a specific issue identified by its unique ID. The method
        returns an object containing the details of the issue if it exists, or None
        if no such issue is found.

        Args:
            issue_id (int): The unique identifier of the OSSFuzz issue to fetch.

        Returns:
            Optional[OSSFuzzIssueReport]: An instance of OSSFuzzIssueReport containing
            issue details if found, or None if the issue does not exist.

        Raises:
            NotImplementedError: This method must be implemented by derived classes.
        """
        raise NotImplementedError()

    @abstractmethod
    def fetch_issue_id(self, url: str) -> Tuple[str, int]:
        """
        Extracts the issue URL and issue ID from a given OSS-Fuzz or Chromium issue tracker URL.

        This function handles two known host formats:
        - For Chromium issues (`bugs.chromium.org`), it attempts to extract the final redirected URL
          containing the actual issue ID using a regex match on the response body.
        - For OSS-Fuzz issues (`issues.oss-fuzz.com`), it extracts the issue ID from the query component of the URL.

        Args:
            url (str): The URL to extract the issue ID from.

        Returns:
            Tuple[str, int]: A tuple containing:
                - The resolved issue URL (either the original or the redirected one),
                - The extracted issue ID as an integer.

        Raises:
            Exception: If the URL's host is not recognized (i.e., not `bugs.chromium.org` or `issues.oss-fuzz.com`).

        Notes:
            - Uses a hardcoded User-Agent header to mimic a browser request.
            - Relies on regex to find redirect URLs in Chromium issue pages.
        """
        raise NotImplementedError()
