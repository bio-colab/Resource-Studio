from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from core.project import Project


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"
MANIFEST = "<?xml version='1.0'?><assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'><assemblyIdentity name='RestoreTest' version='1.0.0.0'/></assembly>"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    original_hash = sha256(FIXTURE)
    with tempfile.TemporaryDirectory() as temporary:
        project = Project.open_pe(FIXTURE, Path(temporary) / "project")
        snapshot = project.snapshot("before-edit")
        workspace_before = project.workspace_path.read_bytes()
        assert snapshot.with_suffix(snapshot.suffix + ".workspace").is_file()
        project.apply_manifest(MANIFEST)
        assert project.workspace_path.read_bytes() != workspace_before
        project.restore_snapshot(snapshot)
        assert project.workspace_path.read_bytes() == workspace_before
        assert project.workspace_path.with_suffix(project.workspace_path.suffix + ".before-restore.bak").is_file()
        assert any(event["operation"] == "project.restore_snapshot" for event in project.audit.read())
        assert Project.load(project.project_dir).entries.keys() == project.entries.keys()
    assert sha256(FIXTURE) == original_hash
    print("project-restore-tests: passed")


if __name__ == "__main__":
    main()
