from enum import Enum
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass
from pydantic import BaseModel, Field

from .build import BuildInfo


class ReproductionStatus(Enum):
    """Status of the reproduction process."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILURE = "failure"


class CrashInfo(BaseModel):
    impact: str
    operation: str
    size: int
    address: str
    function: str
    stack_trace: Optional[List[str]] = Field(default_factory=list)
    file: str


@dataclass
class VerificationResult:
    """Result of vulnerability verification."""
    success: bool
    crash_signature: Optional[str] = None
    stack_trace: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class ReproductionResult:
    """Result of the reproduction process."""
    osv_id: str
    status: ReproductionStatus
    vulnerable_build: Optional[BuildInfo] = None
    fixed_build: Optional[BuildInfo] = None
    verification: Optional[VerificationResult] = None
    output_dir: Optional[str|Path] = None
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        """Return True if reproduction was successful."""
        return self.status == ReproductionStatus.SUCCESS
