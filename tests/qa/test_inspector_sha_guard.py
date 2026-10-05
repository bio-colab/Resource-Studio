from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from core.diff import diff_image_payloads
from core.pe_inspector import PEInspector


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    before = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    report = PEInspector.inspect(FIXTURE)
    assert report.sha256 == before
    with tempfile.TemporaryDirectory() as temporary:
        left = Path(temporary) / "left.bin"
        right = Path(temporary) / "right.bin"
        left.write_bytes(b"BM\x00\x01")
        right.write_bytes(b"BM\x00\x02")
        diff = diff_image_payloads(left.read_bytes(), right.read_bytes(), kind="bitmap")
        assert diff.status == "modified"
        assert diff.before["sha256"] != diff.after["sha256"]
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == before
    print("inspector-sha-guard-tests: passed")


if __name__ == "__main__":
    main()
