import json
import os
import tempfile
from pathlib import Path

from core.p0_telemetry import measure
from core.verification import VerificationContext

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="verification-context-test-") as temporary:
        telemetry_path = Path(temporary) / "telemetry.jsonl"
        previous = os.environ.get("RESOURCE_STUDIO_P0_TELEMETRY_PATH")
        os.environ["RESOURCE_STUDIO_P0_TELEMETRY_PATH"] = str(telemetry_path)
        try:
            with measure("test.verification_context"):
                context = VerificationContext.from_path(FIXTURE)
        finally:
            if previous is None:
                os.environ.pop("RESOURCE_STUDIO_P0_TELEMETRY_PATH", None)
            else:
                os.environ["RESOURCE_STUDIO_P0_TELEMETRY_PATH"] = previous
        assert context.state.resources
        assert context.graph.leaves
        assert context.deep_invariants["valid"] is True
        assert "checksumValidLief" in context.integrity
        payload = json.loads(telemetry_path.read_text(encoding="utf-8"))
        assert payload["counters"]["liefParse"] == 1
    print("verification-context-tests: passed")


if __name__ == "__main__":
    main()
