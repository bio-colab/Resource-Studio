from __future__ import annotations

import hashlib
import shutil
import tempfile
from pathlib import Path

from core.pe_metadata import PEMetadataInspector


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    before = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    regular = PEMetadataInspector.inspect(FIXTURE).to_dict()
    assert regular["isMui"] is False
    assert regular["isDotNet"] is False
    assert regular["resourceSeparation"]["resourceDirectory"] == ".rsrc"
    with tempfile.TemporaryDirectory() as temporary:
        mui_dir = Path(temporary) / "en-US"
        mui_dir.mkdir()
        mui = mui_dir / "shell.mui"
        shutil.copy2(FIXTURE, mui)
        report = PEMetadataInspector.inspect(mui).to_dict()
        assert report["isMui"] is True
        assert report["isSatelliteHint"] is True
        assert report["languageHint"] == "en-US"
        assert report["resourceSeparation"]["writeSupported"] is False
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == before
    print("pe-metadata-tests: passed")


if __name__ == "__main__":
    main()
