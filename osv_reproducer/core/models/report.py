from pydantic import BaseModel, AnyHttpUrl


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
    crash_type: str
    crash_address: str
    crash_state: str

    @property
    def architecture(self) -> str:
        fuzzing_engine, sanitizer, arch, project = self.job_type.split("_")
        return arch
