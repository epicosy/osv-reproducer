from pathlib import Path
from dataclasses import dataclass

from .project import ProjectInfo
from .report import OSSFuzzIssueReport


@dataclass
class ReproductionContext:
    issue_report: OSSFuzzIssueReport
    project_info: ProjectInfo
    snapshot: dict
    timestamp: str
    test_case_path: Path

    @property
    def fuzzer_container_name(self):
         return f"{self.issue_report.project}_{self.timestamp}"
