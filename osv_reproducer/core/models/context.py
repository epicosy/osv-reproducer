from pathlib import Path
from dataclasses import dataclass

from .project import ProjectInfo
from .report import OSSFuzzIssueReport
from ..common.enums import ReproductionMode


@dataclass
class ReproductionContext:
    mode: ReproductionMode
    issue_report: OSSFuzzIssueReport
    project_info: ProjectInfo
    snapshot: dict
    timestamp: str
    test_case_path: Path

    @property
    def fuzzer_container_name(self):
         return f"{self.issue_report.project}_{self.timestamp}"

    @property
    def runner_container_name(self):
        return f"{self.issue_report.project}_{self.issue_report.id}_{self.mode}"

    @property
    def run_fuzzer_container_name(self):
        return f"{self.issue_report.project}_{self.issue_report.id}_{self.mode}_run"