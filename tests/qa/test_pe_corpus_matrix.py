from __future__ import annotations

import hashlib
import json
import struct
import tempfile
from pathlib import Path

from core.health import PEHealth
from core.image_resources import IconCursorGroup, IconCursorEntry
from core.pe_inspector import PEInspector
from core.pe_writer import LiefPEWriter
from core.project import Project
from core.string_table import StringTableBlock
from core.version_info import VersionInfo

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"
MANIFEST = ROOT / "tests" / "corpus_manifest.json"


def dib() -> bytes:
    header = struct.pack("<IiiHHIIiiII", 40, 2, 2, 1, 24, 0, 16, 0, 0, 0, 0)
    return header + bytes(range(16))


def icon_dib() -> bytes:
    header = struct.pack("<IiiHHIIiiII", 40, 2, 4, 1, 32, 0, 16, 0, 0, 0, 0)
    return header + bytes(range(16)) + bytes(8)


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    pe_entries = [item for item in manifest["entries"] if item.get("expectedParse") == "pe"]
    assert len(pe_entries) >= 9
    for item in pe_entries:
        path = ROOT / item["path"]
        report = PEHealth.inspect(path)
        assert report.is_pe is True, path
        inspector = PEInspector.inspect(path)
        assert inspector.machine, path
        assert inspector.size == path.stat().st_size, path
        project = Project.open_pe(path, ROOT / "tests" / ".tmp-corpus-project" / path.stem)
        assert project.entries or item.get("profile") == "minimal", path
    assert {item["architecture"] for item in pe_entries if item.get("kind") == "generated-pe"} >= {"x86", "x64"}
    original_hash = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    writer = LiefPEWriter()
    with tempfile.TemporaryDirectory(prefix="resource-studio-pe-corpus-") as temporary:
        current = FIXTURE
        operations = [
            ("add-rcdata.dll", lambda source, target: writer.add_resource(source, target, "RCDATA", 7000, 1033, b"corpus-rcdata")),
            ("add-bitmap.dll", lambda source, target: writer.add_typed_resource(source, target, "BITMAP", 7001, 1033, dib())),
            ("add-icon.dll", lambda source, target: writer.add_resource(source, target, "ICON", 7003, 1033, icon_dib())),
            ("add-group-icon.dll", lambda source, target: writer.add_typed_resource(source, target, "GROUP_ICON", 7002, 1033, IconCursorGroup("ICON", (IconCursorEntry(2, 2, 0, 1, 32, len(icon_dib()), 7003),)).to_bytes())),
            ("add-string.dll", lambda source, target: writer.add_typed_resource(source, target, "STRING", 7004, 1033, StringTableBlock(1, ("corpus",) + ("",) * 15).to_bytes())),
            ("add-version.dll", lambda source, target: writer.add_typed_resource(source, target, "VERSION", 7005, 1033, VersionInfo(file_version="1.2.3.4", product_version="4.3.2.1", strings={"FileDescription": "corpus"}, translations=[0x0409]).to_bytes())),
            ("change-language.dll", lambda source, target: writer.change_language(source, target, "RCDATA", 7000, 1033, 1025)),
            ("delete-bitmap.dll", lambda source, target: writer.delete_resource(source, target, "BITMAP", 7001, 1033)),
        ]
        seen_types: set[str] = set()
        for name, operation in operations:
            output = Path(temporary) / name
            result = operation(current, output)
            assert result.verified is True
            report = PEHealth.inspect(output)
            assert report.is_pe is True
            assert report.resource_index
            inspector = PEInspector.inspect(output)
            assert inspector.machine
            assert inspector.size == output.stat().st_size
            project = Project.open_pe(output, Path(temporary) / (output.stem + "-project"))
            assert project.entries
            seen_types.update(entry.resource_type for entry in project.entries.values())
            current = output
        assert {"RCDATA", "BITMAP", "ICON", "GROUP_ICON", "STRING", "VERSION"}.issubset(seen_types)
        assert Project.open_pe(current, Path(temporary) / "final-project").get("RCDATA", "7000", 1033) is None
        assert Project.open_pe(current, Path(temporary) / "final-project-1025").get("RCDATA", "7000", 1025) is not None
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == original_hash
    print("pe-corpus-matrix-tests: passed")


if __name__ == "__main__":
    main()
