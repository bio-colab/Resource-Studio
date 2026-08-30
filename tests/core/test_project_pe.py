from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from core.project import Project

MANIFEST = """<?xml version='1.0'?><assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'><assemblyIdentity name='ProjectTest' version='1.0.0.0'/></assembly>"""


def main() -> None:
    source = Path("tests/fixtures/sample.dll").resolve()
    original_bytes = source.read_bytes()
    original_hash = hashlib.sha256(original_bytes).hexdigest()
    with tempfile.TemporaryDirectory() as temporary:
        project = Project.open_pe(source, Path(temporary) / "project")
        assert project.workspace_path is not None and project.workspace_path.is_file()
        assert project.entries
        assert project.original_sha256 == original_hash
        output = project.save_as(Path(temporary) / "copy.dll")
        assert output.is_file()
        assert output.read_bytes() == project.workspace_path.read_bytes()
        applied_output = project.apply_manifest(MANIFEST)
        assert applied_output.is_file()
        assert project.workspace_path.read_bytes() != original_bytes
        assert source.read_bytes() == original_bytes
        assert hashlib.sha256(source.read_bytes()).hexdigest() == original_hash
        assert project.project_file.is_file()
        assert project.workspace_path.with_suffix(project.workspace_path.suffix + ".before-apply.bak").is_file()
        events = project.audit.read()
        assert [event["operation"] for event in events] == ["project.open_pe", "project.save_as", "project.apply_manifest"]
        assert events[-1]["details"]["verified"] is True
    print("project-pe-tests: passed")


if __name__ == "__main__":
    main()
