from __future__ import annotations

import os
from pathlib import Path

from core.pe_integrity import inspect_integrity

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    report = inspect_integrity(FIXTURE)
    assert report.path.endswith("sample.dll")
    assert report.stored_checksum >= 0
    assert report.lief_checksum >= 0
    assert isinstance(report.signature_present, bool)
    if os.name == "nt":
        assert report.windows_status == 0, report.to_dict()
        assert report.windows_checksum is not None
    else:
        assert report.windows_checksum is None
    print("pe-integrity-tests: passed")


if __name__ == "__main__":
    main()
