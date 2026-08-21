import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core.case_lifecycle import CaseFile, CaseLifecycleError

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="resource-studio-case-") as temporary:
        root = Path(temporary)
        case_path = root / "sample.case.json"
        case = CaseFile.create(FIXTURE)
        case.save(case_path)
        assert case.payload["status"] == "OPEN"
        case.add_security_report(__import__("core.security_analysis", fromlist=["analyze_security"]).analyze_security(FIXTURE))
        assert case.payload["status"] == "ANALYZED"
        case.transition("REPORTED")
        case.transition("CLOSED")
        assert case.verify_audit()["valid"]
        case.save(case_path)
        loaded = CaseFile.load(case_path)
        assert loaded.payload["status"] == "CLOSED"
        assert loaded.verify_audit()["valid"]
        try:
            loaded.transition("OPEN")
        except CaseLifecycleError:
            pass
        else:
            raise AssertionError("closed cases must not transition backwards")

        env = {**__import__("os").environ, "PYTHONPATH": str(ROOT)}
        cli_case = root / "cli.case.json"
        create = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "case", "create", str(FIXTURE), "--output", str(cli_case), "--json"], capture_output=True, text=True, env=env, check=False)
        assert create.returncode == 0, create.stderr
        analyze = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "case", "analyze", str(cli_case), str(FIXTURE), "--json"], capture_output=True, text=True, env=env, check=False)
        assert analyze.returncode == 0, analyze.stderr
        payload = json.loads(analyze.stdout)
        assert payload["evidenceGraphHash"]
        show = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "case", "show", str(cli_case), "--json"], capture_output=True, text=True, env=env, check=False)
        assert show.returncode == 0, show.stderr
        assert json.loads(show.stdout)["auditVerification"]["valid"]
    print("case-lifecycle-tests: passed")


if __name__ == "__main__":
    main()
