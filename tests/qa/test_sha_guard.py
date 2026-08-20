from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from core.pe_writer import LiefPEWriter
from core.project import Project


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"
MANIFEST = "<?xml version='1.0'?><assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'><assemblyIdentity name='ShaGuard' version='1.0.0.0'/></assembly>"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    before = digest(FIXTURE)
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        project = Project.open_pe(FIXTURE, directory / "project")
        snapshot = project.snapshot("baseline")
        project.apply_manifest(MANIFEST)
        project.restore_snapshot(snapshot)
        project.build(directory / "built.dll")
        portable = project.export_git(directory / "portable")
        imported = Project.import_git(portable, directory / "imported")
        assert imported.workspace_path is not None
        writer_output = directory / "writer.dll"
        LiefPEWriter().replace_manifest(FIXTURE, writer_output, MANIFEST)
        assert digest(writer_output) != before
    assert digest(FIXTURE) == before
    print("sha-guard-tests: passed")


if __name__ == "__main__":
    main()
