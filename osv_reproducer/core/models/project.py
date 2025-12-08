from typing import Optional, List, Dict

from pydantic import BaseModel, AnyUrl, Field


class ProjectInfo(BaseModel):
    name: str
    language: str
    repo_path: str
    main_repo: AnyUrl
    main_repo_id: int
    oss_fuzz_repo_sha: str
    homepage: Optional[str] = Field(None)
    primary_contact: Optional[str] = Field(None)
    fuzzing_engines: Optional[List[str]] = Field(default_factory=list)
    sanitizers: Optional[List[str|dict]] = Field(default_factory=list)
    vendor_ccs: Optional[List[str]] = Field(default_factory=list)
    auto_ccs: Optional[List[str]] = Field(default_factory=list)
    file_github_issue: Optional[bool] = Field(default=None)
    coverage_extra_args: Optional[str] = Field(default=None)
    architectures: Optional[List[str]] = Field(default_factory=list)
    builds_per_day: Optional[int] = Field(default_factory=int)
    disabled: Optional[bool] = Field(default=None)
    blackbox: Optional[bool] = Field(default=None)
    selective_unpack: Optional[bool] = Field(default=None)
    view_restrictions: Optional[str] = Field(default=None)
    run_tests: Optional[bool] = Field(default=None)
    labels: Optional[Dict[str, List[str]]] = Field(default_factory=dict)
    help_url: Optional[AnyUrl] = None


class ProjectRange(BaseModel):
    owner: str
    name: str
    vul_sha: Optional[str] = None
    fix_sha: Optional[str] = None

    def __str__(self):
        return f"{self.owner}/{self.name}"
