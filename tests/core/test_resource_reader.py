import json
import os
import tempfile
from pathlib import Path

from core.p0_telemetry import measure
from core.project import Project
from core.resource_reader import ResourceReader

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-reader-test-") as temporary:
        telemetry_path = Path(temporary) / "telemetry.jsonl"
        previous = os.environ.get("RESOURCE_STUDIO_P0_TELEMETRY_PATH")
        os.environ["RESOURCE_STUDIO_P0_TELEMETRY_PATH"] = str(telemetry_path)
        try:
            with measure("test.resource_reader"):
                reader = ResourceReader(FIXTURE)
                entries = reader.entries
        finally:
            if previous is None:
                os.environ.pop("RESOURCE_STUDIO_P0_TELEMETRY_PATH", None)
            else:
                os.environ["RESOURCE_STUDIO_P0_TELEMETRY_PATH"] = previous
        assert entries
        assert any(entry.resource_type == "MANIFEST" for entry in entries)
        with tempfile.TemporaryDirectory(prefix="resource-reader-legacy-") as legacy:
            project = Project.open_pe(FIXTURE, Path(legacy) / "project")
            expected = {(entry.key, entry.sha256) for entry in project.entries.values()}
        actual = {(entry.key, entry.sha256) for entry in entries}
        assert actual == expected
        assert not (Path(temporary) / "project").exists()
        payload = json.loads(telemetry_path.read_text(encoding="utf-8"))
        assert payload["counters"]["liefParse"] == 1
        assert payload["counters"]["temporaryDirectories"] == 0
        assert payload["counters"]["temporaryFiles"] == 0
    print("resource-reader-tests: passed")


if __name__ == "__main__":
    main()
