from pydantic import BaseModel, AnyHttpUrl

from .result import CrashInfo


class OSSFuzzIssueReport(BaseModel):
    id: str
    project: str
    fuzzing_engine: str
    fuzz_target: str
    job_type: str
    platform_id: str
    sanitizer: str
    severity: str
    testcase_url: AnyHttpUrl
    regressed_url: AnyHttpUrl
    crash_info: CrashInfo

    @property
    def architecture(self) -> str:
        values = self.job_type.split("_")

        if len(values) == 4:
            # should be fuzzing_engine, sanitizer, arch, project
            return values[2]

        # return default architecture
        return "x86_64"

    @property
    def range(self) -> list:
        for param, value in self.regressed_url.query_params():
            if param == "range":
                return value.split(":")

        return []
