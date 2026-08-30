from __future__ import annotations

import hashlib
import json
from pathlib import Path

import lief

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tests" / "corpus_manifest.json"


def main() -> None:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert payload["format"] == "resource_studio.corpus.v1"
    assert payload["entries"]
    pe_entries = []
    for item in payload["entries"]:
        path = ROOT / item["path"]
        assert path.is_file(), path
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"], path
        if item["expectedParse"] == "pe":
            pe_entries.append(item)
            assert item.get("architecture"), path
            assert item.get("profile"), path
            assert item.get("toolchain"), path
            binary = lief.parse(str(path))
            assert isinstance(binary, lief.PE.Binary), path
        else:
            try:
                binary = lief.parse(str(path))
            except Exception:
                binary = None
            assert not isinstance(binary, lief.PE.Binary), path
    generated = [item for item in pe_entries if item.get("kind") == "generated-pe"]
    assert {item["architecture"] for item in generated} >= {"x86", "x64"}
    assert {item["profile"] for item in generated} >= {"minimal", "resource-heavy", "packed-benign", "overlay", "weird-alignment", "test-signed"}
    assert any("multiple-language" in item.get("resourceCoverage", []) for item in generated)
    assert any("named" in item.get("resourceCoverage", []) for item in generated)
    assert any("numeric" in item.get("resourceCoverage", []) for item in generated)
    print("corpus-manifest-tests: passed")


if __name__ == "__main__":
    main()
