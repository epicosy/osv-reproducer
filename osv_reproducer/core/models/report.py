from typing import Optional, Tuple
from pydantic import BaseModel, AnyHttpUrl

from .result import CrashInfo


class OSSFuzzIssueReport(BaseModel):
    id: int
    project: str
    fuzzing_engine: str
    fuzz_target: str
    job_type: str
    platform_id: str
    sanitizer: str
    severity: Optional[str] = None
    testcase_url: AnyHttpUrl
    regressed_url: AnyHttpUrl
    crash_info: CrashInfo

    @property
    def testcase_id(self) -> int:
        for param, value in self.testcase_url.query_params():
            if param == "testcase_id":
                return int(value)

        raise ValueError(f"No testcase_id found in {self.testcase_url}")

    @property
    def architecture(self) -> str:
        values = self.job_type.split("_")

        if len(values) == 4:
            # should be fuzzing_engine, sanitizer, arch, project
            return values[2]

        # return default architecture
        return "x86_64"

    @property
    def range(self) -> Tuple[Optional[str], Optional[str]]:
        parts = []

        for param, value in self.regressed_url.query_params():
            if param in ["range", "revision"]:
                parts = value.split(":")
                break

        if len(parts) == 1:
            return parts[0], parts[0]

        if len(parts) == 2:
            return parts[0], parts[1]

        return None, None
