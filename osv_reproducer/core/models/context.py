from typing import Dict
from pydantic import BaseModel

from .project import ProjectInfo
from .report import OSSFuzzIssueReport
from ..common.enums import ReproductionMode


class ReproductionContext(BaseModel):
    id: str
    mode: ReproductionMode
    issue_report: OSSFuzzIssueReport
    project_info: ProjectInfo
    mount_files: Dict[str, str]
    repositories: dict
    timestamp: str

    @property
    def fuzzer_container_name(self):
         return f"{self.issue_report.project}_{self.timestamp}"

    @property
    def runner_container_name(self):
        return f"{self.issue_report.project}_{self.issue_report.id}_{self.mode}"
