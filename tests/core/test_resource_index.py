from __future__ import annotations

from pathlib import Path

from core.health import PEHealth
from core.project import Project


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    with __import__("tempfile").TemporaryDirectory() as temporary:
        project = Project.open_pe(FIXTURE, Path(temporary) / "project")
        index = project.index_resources()
        assert len(index.items) == len(project.entries)
        item = index.items[0]
        assert item.resource_type == "MANIFEST"
        assert item.name == "1"
        assert item.language == 1033
        assert item.size == 381
        assert len(item.sha256) == 64
        assert isinstance(item.offset, int)
    report = PEHealth.inspect(FIXTURE).to_dict()
    assert report["resourceIndex"]
    assert report["resourceIndex"][0]["sha256"] == item.sha256
    assert report["resourceIndex"][0]["offset"] == item.offset
    print("resource-index-tests: passed")


if __name__ == "__main__":
    main()
