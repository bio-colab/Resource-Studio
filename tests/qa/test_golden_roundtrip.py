from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from core.project import Project


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"
GOLDEN = ROOT / "tests" / "golden" / "sample_resources.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records(project: Project) -> list[dict[str, object]]:
    return [
        {
            "language": entry.language,
            "name": entry.name,
            "sha256": entry.sha256,
            "size": len(entry.data),
            "type": entry.resource_type,
        }
        for entry in sorted(project.entries.values(), key=lambda item: item.key)
    ]


def main() -> None:
    original_hash = sha256(FIXTURE)
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as temporary:
        project = Project.open_pe(FIXTURE, Path(temporary) / "project")
        assert records(project) == expected
        output = Path(temporary) / "roundtrip.dll"
        project.save_as(output)
        reopened = Project.open_pe(output, Path(temporary) / "reopened")
        assert records(reopened) == expected
    assert sha256(FIXTURE) == original_hash
    print("golden-roundtrip-tests: passed")


if __name__ == "__main__":
    main()
