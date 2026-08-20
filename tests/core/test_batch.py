from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from core.batch import BatchError, BatchWorkspace

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    original_hash = sha256(FIXTURE)
    with tempfile.TemporaryDirectory(prefix="resource-studio-batch-test-") as temporary:
        root = Path(temporary)
        payload = root / "manifest.xml"
        payload.write_text('<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"/>', encoding="utf-8")
        first = root / "first.dll"
        second = root / "second.dll"
        manifest = root / "batch.json"
        manifest.write_text(
            json.dumps(
                {
                    "format": "resource_studio.batch.v1",
                    "jobs": [
                        {
                            "input": str(FIXTURE),
                            "output": str(first),
                            "operations": [{"action": "replace", "type": "MANIFEST", "name": 1, "language": 1033, "dataFile": str(payload)}],
                        },
                        {
                            "input": str(FIXTURE),
                            "output": str(second),
                            "operations": [{"action": "delete", "type": "MANIFEST", "name": 1, "language": 1033}],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        workspace = BatchWorkspace.load(manifest)
        plan = workspace.plan()
        assert plan["willWrite"] is True
        assert not first.exists() and not second.exists()
        applied = workspace.apply(root / "batch-report.json")
        assert all(job["verified"] for job in applied["jobs"])
        assert first.is_file() and second.is_file()
        assert (root / "batch-report.json").is_file()
        first_hash = sha256(first)
        workspace.apply()
        assert sha256(first) == first_hash
        assert first.with_suffix(first.suffix + ".batch.bak").is_file()
        assert sha256(FIXTURE) == original_hash
        bad = root / "bad.json"
        bad.write_text(
            json.dumps({"format": "resource_studio.batch.v1", "jobs": [{"input": str(FIXTURE), "output": str(FIXTURE), "operations": [{"action": "delete", "type": "MANIFEST", "name": 1, "language": 1033}]}]}),
            encoding="utf-8",
        )
        try:
            BatchWorkspace.load(bad)
        except BatchError:
            pass
        else:
            raise AssertionError("in-place batch output was accepted")
    assert sha256(FIXTURE) == original_hash
    print("batch-tests: passed")


if __name__ == "__main__":
    main()
