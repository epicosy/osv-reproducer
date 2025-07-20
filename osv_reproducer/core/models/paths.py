from pathlib import Path
from dataclasses import dataclass


@dataclass
class PathsLayout:
    base_path: Path
    project_path: Path

    @property
    def out(self):
        return self.base_path / "out"

    @property
    def work(self):
        return self.base_path / "work"

    @property
    def src(self):
        return self.project_path / "src"
