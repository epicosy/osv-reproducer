from pathlib import Path
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
    crash_signature: Optional[str] = None
    stack_trace: Optional[str] = None
    error_messages: List[str] = Field(default_factory=list)


class ReproductionResult(BaseModel):
    """Result of the reproduction process."""
    osv_id: str
    verification: Optional[VerificationResult] = None
    output_dir: Optional[str|Path] = None
