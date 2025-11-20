import re
import json
import requests

from pathlib import Path
from cement import Handler
from pydantic import AnyHttpUrl, HttpUrl
from typing import Optional, Tuple
from osvutils.types.osv import OSV

from ..core.models.report import OSSFuzzIssueReport
from ..core.interfaces import HandlersInterface
from ..utils.parse.report import parse_oss_fuzz_report_to_dict
from ..common.constants import USER_AGENT_HEADERS, HTTP_HEADERS


class OSSFuzzHandler(HandlersInterface, Handler):

    class Meta:
        label = "oss_fuzz"

    def _setup(self, app):
        super()._setup(app)
        self.base_url = HttpUrl("https://issues.oss-fuzz.com")
        self.old_base_url = HttpUrl("https://bugs.chromium.org")
        self._mappings = {}
        self._mappings_path = app.app_dir / "osv_issue_mapping.json"

        # Load mappings from file if it exists
        if self._mappings_path.exists():
            try:
                with self._mappings_path.open('r') as f:
                    self._mappings = json.load(f)
                app.log.info(f"Loaded mappings from {self._mappings_path}")
            except json.JSONDecodeError:
                app.log.warning(f"Error decoding mappings file: {self._mappings_path}")
            except Exception as e:
                app.log.warning(f"Error loading mappings file: {str(e)}")

    @property
    def mappings(self):
        """
        Getter for the mappings dictionary.

        Returns:
            dict: The mappings dictionary mapping OSV IDs to issue IDs.
        """
        return self._mappings

    def set_mappings(self, osv_id: str, issue_id: str):
        """
        Setter for the mappings dictionary. Updates the mappings dictionary and saves it to the file.

        Args:
            osv_id (str): The OSV ID to map.
            issue_id (str): The issue ID to map to.
        """
        self._mappings[osv_id] = issue_id

        try:
            # Save the updated mappings
            with self._mappings_path.open('w') as f:
                json.dump(self._mappings, f, indent=4)

            self.app.log.info(f"Updated mappings with {osv_id} -> {issue_id}")
        except Exception as e:
            self.app.log.warning(f"Error updating mappings file: {str(e)}")

    @property
    def action_issues_url(self) -> HttpUrl:
        return HttpUrl(f"{self.base_url}/action/issues")

    def get_test_case(self, url: AnyHttpUrl) -> Optional[Path]:
        testcase_id = None

        for param, value in url.query_params():
            if param == "testcase_id":
                testcase_id = value
                break

        if not testcase_id:
            return None

        testcase_path = self.app.testcases_dir / testcase_id

        # Check if the file already exists
        if testcase_path.exists():
            self.app.log.info(f"Test case file already exists at {testcase_path}")
            return testcase_path

        # If not, fetch the test case content
        self.app.log.info(f"Downloading test case from {url}")
        content = self.fetch_test_case_content(url)

        if content is None:
            return None

        # Save the content to the file
        try:
            with testcase_path.open(mode='wb') as f:
                f.write(content)

            self.app.log.info(f"Test case saved to {testcase_path}")
            return testcase_path
        except Exception as e:
            self.app.log.error(f"Error saving test case: {str(e)}")
            return None

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

    def get_issue_id(self, osv_record: OSV) -> Optional[str]:
        # Check if the OSV ID exists in the mappings
        if osv_record.id in self.mappings:
            self.app.log.info(f"Found issue ID for {osv_record.id} in local mappings")
            return self.mappings[osv_record.id]

        # If not found in mappings, fetch from references
        for ref in osv_record.references:
            _, issue_id = self.fetch_issue_id(ref.url)

            if issue_id:
                # Update mappings with the new association
                self.set_mappings(osv_record.id, issue_id)
                return issue_id

        return None

    def get_issue_report(self, osv_record: OSV) -> Optional[OSSFuzzIssueReport]:
        issue_id = self.get_issue_id(osv_record)

        if not issue_id:
            return None

        issue_report_path = self.app.issues_dir / f"{issue_id}.json"

        if not issue_report_path.exists():
            issue_report = self.fetch_issue_report(issue_id)

            if issue_report:
                with issue_report_path.open(mode="w") as f:
                    oss_fuzz_issue_report_json = issue_report.model_dump_json(indent=4)
                    f.write(oss_fuzz_issue_report_json)

                return issue_report
        else:
            self.app.log.info(f"Using cached issue report for {osv_record.id}")
            with issue_report_path.open(mode="r") as f:
                oss_fuzz_issue_report_dict = json.load(f)
                return OSSFuzzIssueReport(**oss_fuzz_issue_report_dict)

        return None

    def fetch_issue_report(self, issue_id: str) -> Optional[OSSFuzzIssueReport]:
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

    def fetch_issue_id(self, url: str) -> Tuple[str, str]:
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
                - The extracted issue ID as a string.

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
                return redirect_url, redirect_url.split("/")[-1]
            elif url_obj.query:
                self.app.log.warning("Redirect URL not found in response. Fallback to default issue id.")
                return url, url_obj.query.split("=")[-1]
            else:
                raise ValueError("Could not extract redirect URL nor the issue ID.")

        elif url_obj.host == self.base_url.host:
            return url, url_obj.query.split("/")[-1]
        else:
            raise Exception(f"Unknown host: {url_obj.host}")
