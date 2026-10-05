from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from core.dialog_resources import DialogControl, DialogResource
from core.project import Project

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def sample_dialog() -> DialogResource:
    return DialogResource(
        x=0,
        y=0,
        width=160,
        height=80,
        style=0x50000000,
        title="Resource Studio Dialog",
        controls=[DialogControl(100, 8, 8, 60, 14, 0x50010000, 0, 0x0082, "OK")],
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    original_hash = sha256(FIXTURE)
    with tempfile.TemporaryDirectory() as temporary:
        project = Project.open_pe(FIXTURE, Path(temporary) / "project")
        project.apply_dialog(sample_dialog(), 9000, 1033, add=True)
        assert project.workspace_path is not None
        assert project.workspace_path.is_file()
        backup = project.workspace_path.with_suffix(project.workspace_path.suffix + ".before-typed.bak")
        assert backup.is_file()
        assert project.audit.path.is_file()
        assert any(entry.resource_type == "DIALOG" for entry in project.entries.values())
    assert sha256(FIXTURE) == original_hash
    print("dialog-project-tests: passed")


if __name__ == "__main__":
    main()
