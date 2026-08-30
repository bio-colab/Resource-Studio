from __future__ import annotations

import os
from pathlib import Path

from core.windows_resource_oracle import compare_with_lief, inspect

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    if os.name != "nt":
        print("windows-resource-oracle-tests: skipped (Windows only)")
        return
    report = inspect(FIXTURE)
    assert report.resource_count > 0
    assert not report.warnings
    comparison = compare_with_lief(FIXTURE)
    assert comparison.matches, comparison.to_dict()
    print("windows-resource-oracle-tests: passed")


if __name__ == "__main__":
    main()
