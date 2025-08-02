import json
import requests
from pathlib import Path

from cement import Handler
from typing import Tuple
from pydantic import HttpUrl

from osvutils.types.osv import OSV
from osvutils.types.range import GitRange
from osvutils.types.event import Introduced, Fixed

from ..common.constants import HTTP_HEADERS
from ..core.exc import OSVError
from ..core.interfaces import HandlersInterface

class OSVHandler(HandlersInterface, Handler):
    """
        OSV handler
    """

    class Meta:
        label = 'osv'

    def _setup(self, app):
        super()._setup(app)
        # TODO: should be passed through configs
        self.version: str = 'v1'
        self.base_api_url = HttpUrl('https://api.osv.dev')

    @property
    def api_url(self) -> HttpUrl:
        return HttpUrl(f"{self.base_api_url}/{self.version}")

    @property
    def vuln_api_url(self) -> HttpUrl:
        return HttpUrl(f"{self.api_url}/vulns")

    def fetch_vulnerability(self, osv_id: str) -> dict:
        """
        Fetch vulnerability information from OSV API.

        Args:
            osv_id: The OSV ID of the vulnerability.

        Returns:
            OSV: The vulnerability record.

        Raises:
            OSVError: If fetching the vulnerability fails.
        """
        try:
            self.app.log.info(f"Fetching vulnerability {osv_id} from OSV API")

            response = requests.get(url=f"{self.vuln_api_url}/{osv_id}", headers=HTTP_HEADERS)

            if not response.status_code == 200:
                raise ValueError(
                    f'OSV API returned {response.status_code} for call to {response.url}: {response.text}'
                )

            json_dict = response.json()

            return json_dict
        except Exception as e:
            self.app.log.error(f"Error fetching vulnerability {osv_id}: {str(e)}")
            raise OSVError(f"Failed to fetch vulnerability {osv_id}: {str(e)}")

    def get_record(self, osv_id: str) -> OSV:
        """
        Get an OSV record by ID. First checks if the record exists locally,
        and if not, fetches it from the OSV API and saves it locally.

        Args:
            osv_id: The OSV ID of the vulnerability.

        Returns:
            OSV: The vulnerability record.

        Raises:
            OSVError: If getting the vulnerability fails.
        """
        # Check if the record exists locally
        record_path = self.app.records_dir / f"{osv_id}.json"

        if record_path.exists():
            try:
                self.app.log.info(f"Loading vulnerability {osv_id} from local storage")

                with record_path.open(mode='r') as f:
                    json_dict = json.load(f)

                return OSV(**json_dict)
            except Exception as e:
                self.app.log.error(f"Error loading vulnerability {osv_id} from local storage: {str(e)}")
                # If loading fails, try to fetch it from the API

        # If the record doesn't exist locally or loading failed, fetch it from the API
        osv_dict = self.fetch_vulnerability(osv_id)

        # Save the fetched record locally
        try:
            self.app.log.info(f"Saving vulnerability {osv_id} to local storage")

            with record_path.open(mode='w') as f:
                # Now serialize to JSON and save
                json.dump(osv_dict, f, indent=4)

        except Exception as e:
            self.app.log.warning(f"Error saving vulnerability {osv_id} to local storage: {str(e)}")
            # Continue even if saving fails
        # keep this here for the current version of osvutils (since it is buggy and will overwrite the dictionary)
        return OSV(**osv_dict)

    def get_git_range(self, osv: OSV) -> Tuple[GitRange, str, str]:
        errors = []

        if len(osv.affected) == 0:
            errors.append(f"{osv.id} misses affected ranges")

        introduced_version = None
        fix_version = None
        git_range = None

        for affected in osv.affected:
            for git_range in affected.get_git_ranges():
                for event in git_range.events:
                    if isinstance(event, Introduced):
                        introduced_version = event.version
                    if isinstance(event, Fixed):
                        fix_version = event.version

                if introduced_version and fix_version:
                    break

        if not git_range:
            errors.append(f"Missing git ranges")

        if not introduced_version:
            errors.append("Missing introduced commit")

        if not fix_version:
            errors.append("Missing fixed commit")

        # TODO: add more checks as needed

        # If we have errors, raise an exception
        if errors:
            error_message = f"OSV record {osv.id} cannot be reproduced: {', '.join(errors)}"
            self.app.log.error(error_message)
            raise OSVError(error_message)

        self.app.log.info(f"OSV record {osv.id} has valid git range")

        return git_range, introduced_version, fix_version
