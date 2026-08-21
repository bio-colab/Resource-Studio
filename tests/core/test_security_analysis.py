import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core.security_analysis import analyze_security

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    report = analyze_security(FIXTURE)
    assert report["schema"] == "resource_studio.security_report.v1"
    assert report["parse"]["status"] == "VALID_PE"
    assert report["access"]["readable"] is True
    assert report["runtime"]["executed"] is False
    assert report["externalScans"] == []
    assert report["target"]["sha256"]
    assert report["evidence"]["schema"] == "resource_studio.evidence_summary.v1"
    assert report["evidenceHash"]

    with tempfile.TemporaryDirectory(prefix="resource-studio-security-test-") as temporary:
        root = Path(temporary)
        non_pe = root / "not-pe.bin"
        non_pe.write_bytes(b"not a PE")
        non_pe_report = analyze_security(non_pe)
        assert non_pe_report["parse"]["status"] == "CORRUPT_OR_UNSUPPORTED"
        assert any(item["category"] == "CORRUPTION" for item in non_pe_report["findings"])
        missing_report = analyze_security(root / "missing.exe")
        assert missing_report["parse"]["status"] == "NOT_READ"
        assert missing_report["access"]["lockStatus"] == "MISSING"

        env = {**__import__("os").environ, "PYTHONPATH": str(ROOT)}
        cli = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "security", str(FIXTURE), "--json"], capture_output=True, text=True, env=env, check=False)
        assert cli.returncode == 0, cli.stderr
        assert json.loads(cli.stdout)["schema"] == "resource_studio.security_report.v1"
        report_cli = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "report", "security", str(FIXTURE), "--format", "json"], capture_output=True, text=True, env=env, check=False)
        assert report_cli.returncode == 0, report_cli.stderr
        assert json.loads(report_cli.stdout)["runtime"]["executed"] is False
    print("security-analysis-tests: passed")


if __name__ == "__main__":
    main()
