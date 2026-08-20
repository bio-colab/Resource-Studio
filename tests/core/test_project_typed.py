from __future__ import annotations

import hashlib
import struct
import tempfile
from pathlib import Path

from core.project import Project
from core.res_format import ResRecord
from core.version_info import VersionInfo


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def dib() -> bytes:
    header = struct.pack("<IiiHHIIiiII", 40, 2, 2, 1, 24, 0, 16, 0, 0, 0, 0)
    return header + b"\x00" * 16


def main() -> None:
    original_hash = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory() as temporary:
        project = Project.open_pe(FIXTURE, Path(temporary) / "project")
        output = project.apply_typed_resource("BITMAP", 99, 1033, dib(), add=True)
        assert output.is_file()
        assert project.get("BITMAP", "99", 1033) is not None
        assert project.workspace_path is not None
        assert project.workspace_path.with_suffix(project.workspace_path.suffix + ".before-typed.bak").is_file()
        assert any(event["operation"] == "project.apply_typed_resource" for event in project.audit.read())
        version = VersionInfo(file_version="1.2.3.4", product_version="4.3.2.1", strings={"FileDescription": "Project"}, translations=[0x0409])
        version_output = project.apply_version_info(version, 2000, 1033, add=True)
        assert version_output.is_file()
        assert project.get("VERSION", "2000", 1033) is not None

        res_output = project.apply_res_record(ResRecord("RCDATA", 1000, 1033, b"portable-res"), add=True)
        assert res_output.is_file()
        assert project.get("RCDATA", "1000", 1033) is not None
        assert project.workspace_path.with_suffix(project.workspace_path.suffix + ".before-res.bak").is_file()
        assert any(event["operation"] == "project.apply_res_record" for event in project.audit.read())
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == original_hash
    print("project-typed-tests: passed")


if __name__ == "__main__":
    main()
