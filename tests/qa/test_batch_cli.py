from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    original = __import__("hashlib").sha256(FIXTURE.read_bytes()).hexdigest()
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    with tempfile.TemporaryDirectory(prefix="resource-studio-batch-cli-") as temporary:
        root = Path(temporary)
        payload = root / "manifest.xml"
        payload.write_text('<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"/>', encoding="utf-8")
        output = root / "output.dll"
        manifest = root / "batch.json"
        manifest.write_text(json.dumps({"format": "resource_studio.batch.v1", "jobs": [{"input": str(FIXTURE), "output": str(output), "operations": [{"action": "replace", "type": "MANIFEST", "name": 1, "language": 1033, "dataFile": str(payload)}]}]}), encoding="utf-8")
        plan = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "batch", "plan", str(manifest), "--json"], capture_output=True, text=True, env=env, check=False)
        assert plan.returncode == 0, plan.stderr
        assert json.loads(plan.stdout)["willWrite"] is True
        assert not output.exists()
        report = root / "report.json"
        applied = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "batch", "apply", str(manifest), "--report", str(report), "--json"], capture_output=True, text=True, env=env, check=False)
        assert applied.returncode == 0, applied.stderr
        assert output.is_file() and report.is_file()
    assert __import__("hashlib").sha256(FIXTURE.read_bytes()).hexdigest() == original
    print("batch-cli-tests: passed")


if __name__ == "__main__":
    main()
