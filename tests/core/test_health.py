from __future__ import annotations

from pathlib import Path

from core.health import PEHealth


def main() -> None:
    report = PEHealth.inspect(Path("tests/fixtures/sample.dll"))
    assert report.is_pe is True
    assert report.size > 0
    assert report.sha256
    assert report.resource_count >= 1
    assert report.sections >= 1
    assert report.signed is False
    non_pe = Path("tests/fixtures/not-pe.txt")
    report2 = PEHealth.inspect(non_pe)
    assert report2.is_pe is False
    assert report2.warnings
    print("health-tests: passed")


if __name__ == "__main__":
    main()
