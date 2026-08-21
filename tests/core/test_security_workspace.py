import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from core.evidence_ledger import EvidenceLedger
from core.security_workspace import stage_readonly_copy

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-security-workspace-") as temporary:
        root = Path(temporary)
        staged = stage_readonly_copy(FIXTURE, root / "staged")
        staged_path = Path(staged.path)
        assert staged.sha256
        assert staged.size == FIXTURE.stat().st_size
        assert staged_path.read_bytes() == FIXTURE.read_bytes()
        if os.name != "nt":
            assert stat.S_IMODE(staged_path.stat().st_mode) & stat.S_IWUSR == 0
        again = stage_readonly_copy(FIXTURE, root / "staged")
        assert again.path == staged.path
        assert again.sha256 == staged.sha256

        ledger_path = root / "security-ledger.jsonl"
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        command = [sys.executable, str(ROOT / "resource_studio_cli.py"), "security", str(FIXTURE), "--stage-root", str(root / "cli-staged"), "--ledger", str(ledger_path), "--json"]
        completed = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
        assert completed.returncode == 0, completed.stderr
        payload = json.loads(completed.stdout)
        assert payload["stagedArtifact"]["sha256"] == payload["target"]["sha256"]
        assert payload["ledger"]["entrySha256"]
        verification = EvidenceLedger(ledger_path).verify()
        assert verification.valid
        assert verification.entries == 1
    print("security-workspace-tests: passed")


if __name__ == "__main__":
    main()
