from __future__ import annotations

import hashlib
from pathlib import Path

from core.pe_inspector import PEInspector


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    before = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    report = PEInspector.inspect(FIXTURE)
    payload = report.to_dict()
    assert payload["sha256"] == before
    assert payload["machine"]
    assert payload["entrypoint"] > 0
    assert payload["sections"]
    assert payload["imports"]
    assert payload["relocations"]
    assert payload["debug"]
    assert isinstance(payload["exports"], list)
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == before
    print("pe-inspector-tests: passed")


if __name__ == "__main__":
    main()
