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
    for item in payload["entries"]:
        path = ROOT / item["path"]
        assert path.is_file(), path
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"], path
        if item["expectedParse"] == "pe":
            binary = lief.parse(str(path))
            assert isinstance(binary, lief.PE.Binary), path
        else:
            try:
                binary = lief.parse(str(path))
            except Exception:
                binary = None
            assert not isinstance(binary, lief.PE.Binary), path
    print("corpus-manifest-tests: passed")


if __name__ == "__main__":
    main()
