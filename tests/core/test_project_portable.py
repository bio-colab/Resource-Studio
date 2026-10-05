from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from core.project import Project


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    original_hash = sha256(FIXTURE)
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        source_project = Project.open_pe(FIXTURE, directory / "source-project")
        portable = source_project.export_git(directory / "portable")
        assert (portable / "project.json").is_file()
        assert list((portable / "resources").glob("*.bin"))
        assert list((portable / "workspace").iterdir())
        imported = Project.import_git(portable, directory / "imported-project")
        assert imported.entries.keys() == source_project.entries.keys()
        assert imported.workspace_path is not None and imported.workspace_path.is_file()
        assert any(event["operation"] == "project.import_git" for event in imported.audit.read())
    assert sha256(FIXTURE) == original_hash
    print("project-portable-tests: passed")


if __name__ == "__main__":
    main()
