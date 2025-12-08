import re
import requests

from cement import Handler
from pydantic import AnyHttpUrl, HttpUrl
from typing import Optional, Tuple

from ..handlers import HandlersInterface
from ..core.models.report import OSSFuzzIssueReport
from ..core.interfaces.oss_fuzz import OSSFuzzInterface
from ..utils.parse.report import parse_oss_fuzz_report_to_dict
from ..common.constants import USER_AGENT_HEADERS, HTTP_HEADERS


class OSSFuzzHandler(OSSFuzzInterface, HandlersInterface, Handler):
    class Meta:
        label = "oss_fuzz"

    def _setup(self, app):
        super()._setup(app)
        self.base_url = HttpUrl("https://issues.oss-fuzz.com")
        self.old_base_url = HttpUrl("https://bugs.chromium.org")

    @property
    def action_issues_url(self) -> HttpUrl:
        return HttpUrl(f"{self.base_url}/action/issues")

    def fetch_test_case_content(self, url: AnyHttpUrl) -> Optional[bytes]:
        """
        Retrieves the content of a test case from a URL without saving it.

        Args:
            url (AnyHttpUrl): The URL to download the test case from.

        Returns:
            Optional[bytes]: The content of the test case, or None if the download failed.
        """
        try:
            self.app.log.info(f"Downloading test case content from {url}")
            response = requests.get(str(url), headers=USER_AGENT_HEADERS, stream=True)

            if response.status_code != 200:
                self.app.log.warning(f"Failed to download test case: HTTP {response.status_code}")
                return None

            # Return the content as bytes
            return response.content

        except Exception as e:
            self.app.log.error(f"Error downloading test case content: {str(e)}")
            return None

    def fetch_issue_report(self, issue_id: int) -> Optional[OSSFuzzIssueReport]:
        try:
            self.app.log.info(f"Fetching OSS-Fuzz bug report from {self.action_issues_url}/{issue_id}")
            response = requests.get(f"{self.action_issues_url}/{issue_id}", headers=USER_AGENT_HEADERS)

            if response.status_code != 200:
                self.app.log.warning(f"Failed to fetch bug report: HTTP {response.status_code}")
                return None

            decoded = response.text.encode('utf-8').decode('unicode_escape')
            decoded = decoded.replace("Detailed report:", "Detailed Report:")
            data_clean = decoded.split("Detailed Report:")

            if len(data_clean) < 2:
                self.app.log.warning(f"issue content not split by 'Detailed Report:'")
                return None

            data_clean = data_clean[1].split("Issue filed automatically.")

            if len(data_clean) != 2:
                self.app.log.warning(f"issue content not split by 'Issue filed automatically.'")
                return None

            report_dict = parse_oss_fuzz_report_to_dict(data_clean[0])
            report_dict["id"] = issue_id

            # Create and return the OSSFuzzReport object
            return OSSFuzzIssueReport(**report_dict)

        except Exception as e:
            self.app.log.error(f"Error parsing OSS-Fuzz bug report: {str(e)}")
            return None

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
            Tuple[str, str]: A tuple containing:
                - The resolved issue URL (either the original or the redirected one),
                - The extracted issue ID as an integer.

        Raises:
            Exception: If the URL's host is not recognized (i.e., not `bugs.chromium.org` or `issues.oss-fuzz.com`).

        Notes:
            - Uses a hardcoded User-Agent header to mimic a browser request.
            - Relies on regex to find redirect URLs in Chromium issue pages.
        """
        url_obj = AnyHttpUrl(url)

        if url_obj.host == self.old_base_url.host:
            response = requests.get(url, headers=HTTP_HEADERS, allow_redirects=True)
            match = re.search(r'const\s+url\s*=\s*"([^"]+)"', response.text)

            if match:
                redirect_url = match.group(1)
                self.app.log.info(f"Extracted redirect URL: {redirect_url}")
                return redirect_url, int(redirect_url.split("/")[-1])
            elif url_obj.query:
                self.app.log.warning("Redirect URL not found in response. Fallback to default issue id.")
                return url, int(url_obj.query.split("=")[-1])
            else:
                raise ValueError("Could not extract redirect URL nor the issue ID.")

        elif url_obj.host == self.base_url.host:
            return url, int(url_obj.query.split("/")[-1])
        else:
            raise Exception(f"Unknown host: {url_obj.host}")
