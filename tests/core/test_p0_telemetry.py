import json
import os
import tempfile
from pathlib import Path

import lief

from core.p0_telemetry import measure

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-p0-test-") as temporary:
        destination = Path(temporary) / "telemetry.jsonl"
        previous = os.environ.get("RESOURCE_STUDIO_P0_TELEMETRY_PATH")
        os.environ["RESOURCE_STUDIO_P0_TELEMETRY_PATH"] = str(destination)
        try:
            with measure("test.p0"):
                assert FIXTURE.read_bytes()
                assert lief.parse(str(FIXTURE)) is not None
        finally:
            if previous is None:
                os.environ.pop("RESOURCE_STUDIO_P0_TELEMETRY_PATH", None)
            else:
                os.environ["RESOURCE_STUDIO_P0_TELEMETRY_PATH"] = previous
        payload = json.loads(destination.read_text(encoding="utf-8"))
        assert payload["schema"] == "resource_studio.p0_telemetry.v1"
        assert payload["status"] == "completed"
        assert payload["counters"]["liefParse"] == 1
        assert payload["counters"]["fullFileReads"] >= 1
    print("p0-telemetry-tests: passed")


if __name__ == "__main__":
    main()
