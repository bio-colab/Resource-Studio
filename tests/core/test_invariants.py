from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from core.invariants import compare_surgical_change
from core.pe_writer import LiefPEWriter


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    original_hash = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "changed.dll"
        LiefPEWriter().add_resource(FIXTURE, output, "RCDATA", 700, 1033, b"invariant")
        report = compare_surgical_change(FIXTURE, output)
        assert report.valid
        assert not report.violations
        assert report.before.to_dict()["sections"]
        assert report.before.resources
        assert report.after.resources
        assert not report.before.resource_issues
        assert not report.after.resource_issues
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == original_hash
    print("invariant-tests: passed")


if __name__ == "__main__":
    main()
