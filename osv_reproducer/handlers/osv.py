import requests

from typing import List
from cement import Handler
from pydantic import HttpUrl

from osvutils.types.osv import OSV
from osvutils.types.event import Fixed, Introduced

from ..common.constants import HTTP_HEADERS

from ..core.exc import OSVError
from ..handlers import HandlersInterface
from ..core.interfaces.osv import OSVInterface
from ..core.models.project import ProjectRange


class OSVHandler(OSVInterface, HandlersInterface, Handler):
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

    def fetch_vulnerability(self, osv_id: str) -> OSV:
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

            return OSV(**json_dict)
        except Exception as e:
            self.app.log.error(f"Error fetching vulnerability {osv_id}: {str(e)}")
            raise OSVError(f"Failed to fetch vulnerability {osv_id}: {str(e)}")

    def get_project_ranges(self, osv: OSV) -> List[ProjectRange]:
        project_ranges = []

        for affected in osv.affected:
            for git_range in affected.get_git_ranges():
                project_range = ProjectRange(owner=git_range.repo.owner, name=git_range.repo.name)

                for event in git_range.events:
                    if isinstance(event, Introduced):
                        project_range.vul_sha = event.version
                    if isinstance(event, Fixed):
                        project_range.fix_sha = event.version

                if not project_range.vul_sha:
                    self.app.log.warning(f"No vulnerability commit found for {git_range.repo}")
                    continue

                if not project_range.fix_sha:
                    self.app.log.warning(f"No fixed commit found for {git_range.repo}")
                    continue

                project_ranges.append(project_range)

        self.app.log.info(f"OSV record {osv.id} has valid git range")

        return project_ranges
