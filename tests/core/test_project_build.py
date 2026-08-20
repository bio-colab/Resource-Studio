from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from core.project import Project, ResourceEntry


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    original_hash = sha256(FIXTURE)
    with tempfile.TemporaryDirectory() as temporary:
        project = Project.open_pe(FIXTURE, Path(temporary) / "project")
        output = Path(temporary) / "built.dll"
        project.build(output)
        assert output.is_file()
        assert any(event["operation"] == "project.build" for event in project.audit.read())

        project.put(ResourceEntry("RCDATA", "999", 1033, b"not in workspace"))
        try:
            project.build(Path(temporary) / "should-not-build.dll")
        except ValueError as exc:
            assert "do not match" in str(exc)
        else:
            raise AssertionError("descriptor/workspace mismatch was not rejected")
    assert sha256(FIXTURE) == original_hash
    print("project-build-tests: passed")


if __name__ == "__main__":
    main()
