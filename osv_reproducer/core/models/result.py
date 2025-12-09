from typing import Optional
from pydantic import BaseModel, Field
from sarif_pydantic.sarif import Stack


class CrashInfo(BaseModel):
    impact: str
    operation: Optional[str] = Field(default=None)
    size: Optional[int] = Field(default=None)
    address: Optional[str] = Field(default=None)
    stack: Stack


class RunStatus(BaseModel):
    context_ok: bool = False
    builder_ok: bool = False
    runner_ok: bool = False
    verifier_ok: bool = False
    exit_code: Optional[int] = None
    error: str = None
