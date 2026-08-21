from __future__ import annotations

import tempfile
from pathlib import Path

from core.health import PEHealth


ROOT = Path(__file__).resolve().parents[2]
NOT_PE = ROOT / "tests" / "fixtures" / "not-pe.txt"
CASES = (
    b"",
    b"MZ",
    b"MZ" + b"broken" * 16,
    b"MZ" + b"\x00" * 128,
    b"not-a-pe" * 64,
)


def main() -> None:
    report = PEHealth.inspect(NOT_PE)
    assert report.is_pe is False
    assert report.status == "NOT_PE"
    assert report.warnings
    with tempfile.TemporaryDirectory() as temporary:
        for index, payload in enumerate(CASES):
            malformed = Path(temporary) / f"malformed-{index}.bin"
            malformed.write_bytes(payload)
            try:
                malformed_report = PEHealth.inspect(malformed)
            except ValueError:
                continue
            assert malformed_report.is_pe is False
            assert malformed_report.status in {"NOT_PE", "MALFORMED_PE"}
    print("malformed-input-tests: passed")


if __name__ == "__main__":
    main()
