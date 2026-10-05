from __future__ import annotations

import tempfile
from pathlib import Path

from core.fuzz_harness import assert_no_unexpected_failures, run_parser_cases
from core.manifest import ManifestDocument
from core.menu_resources import MenuResource
from core.project import Project
from core.version_info import VersionInfo

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        project = Project.open_pe(FIXTURE, Path(temporary) / "project")
        entries = list(project.entries.values())
    seeds = [b"", b"\x00", b"\xff" * 32, b"A" * 4096]
    parsers = {
        "manifest": (ManifestDocument.parse, next((entry.data for entry in entries if entry.resource_type == "MANIFEST"), None)),
        "menu": (MenuResource.parse, next((entry.data for entry in entries if entry.resource_type == "MENU"), None)),
        "version-info": (VersionInfo.from_bytes, next((entry.data for entry in entries if entry.resource_type == "VERSION"), None)),
    }
    total = 0
    tested_parsers = 0
    for name, (parser, valid_seed) in parsers.items():
        if valid_seed is None:
            continue
        outcomes = run_parser_cases(name, parser, [valid_seed, *seeds])
        assert_no_unexpected_failures(outcomes)
        assert any(item.status == "accepted" for item in outcomes), (name, [item.to_dict() for item in outcomes])
        assert any(item.status == "expected-rejected" for item in outcomes)
        total += len(outcomes)
        tested_parsers += 1
    assert tested_parsers >= 1
    assert total >= tested_parsers * 5
    print("parser-fuzz-harness-tests: passed")


if __name__ == "__main__":
    main()
