from __future__ import annotations

from pathlib import Path

from core.project import Project
from core.roundtrip_contracts import default_registry

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    registry = default_registry()
    assert registry.names() == ("manifest.xml", "menu.binary", "raw.bytes", "version-info.binary")
    raw = registry.evaluate("raw.bytes", b"\x00\x01stable")
    assert raw.passed and raw.byte_equal and raw.semantic_equal

    with __import__("tempfile").TemporaryDirectory() as temporary:
        project = Project.open_pe(FIXTURE, Path(temporary) / "project")
        entries = list(project.entries.values())
    by_type = {}
    for entry in entries:
        by_type.setdefault(entry.resource_type, entry)
    tested = 1
    if "MANIFEST" in by_type:
        result = registry.evaluate("manifest.xml", by_type["MANIFEST"].data)
        assert result.passed, result.to_dict()
        assert result.kind == "canonical"
        tested += 1
    if "MENU" in by_type:
        result = registry.evaluate("menu.binary", by_type["MENU"].data)
        assert result.passed, result.to_dict()
        assert result.kind == "semantic"
        tested += 1
    if "VERSION" in by_type:
        result = registry.evaluate("version-info.binary", by_type["VERSION"].data)
        assert result.passed, result.to_dict()
        assert result.kind == "semantic"
        tested += 1
    assert tested >= 1
    print("roundtrip-contract-tests: passed")


if __name__ == "__main__":
    main()
