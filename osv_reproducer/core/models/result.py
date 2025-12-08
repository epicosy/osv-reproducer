from typing import Optional, List
from pydantic import BaseModel, Field
from sarif_pydantic.sarif import Stack


class CrashInfo(BaseModel):
    impact: str
    operation: Optional[str] = Field(default=None)
    size: Optional[int] = Field(default=None)
    address: Optional[str] = Field(default=None)
    stack: Stack


class VerificationResult(BaseModel):
    """Result of vulnerability verification."""
    success: bool = Field(default=False)
    matched_frame: Optional[str] = None
    error_messages: List[str] = Field(default_factory=list)


class RunStatus(BaseModel):
    context_ok: bool = False
    build_ok: bool = False
    fuzzing_ok: bool = False
    verification_ok: bool = False
    exit_code: Optional[int] = None
    error: str = None
