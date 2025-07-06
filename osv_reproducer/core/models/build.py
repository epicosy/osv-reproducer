from pathlib import Path
from typing import Optional, Dict
from dataclasses import dataclass, field


@dataclass
class BuildInfo:
    """Information about a build."""
    project: str
    commit: str
    dockerfile_path: Optional[Path] = None
    build_script_path: Optional[Path] = None
    dependencies: Dict[str, str] = field(default_factory=dict)
    environment_variables: Dict[str, str] = field(default_factory=dict)
