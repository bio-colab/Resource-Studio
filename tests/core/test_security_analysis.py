import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core.runtime_evidence import load_runtime_evidence
from core.security_analysis import analyze_security

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    report = analyze_security(FIXTURE)
    assert report["schema"] == "resource_studio.security_report.v1"
    assert report["parse"]["status"] == "VALID_PE"
    assert report["access"]["readable"] is True
    assert report["runtime"]["executed"] is False
    assert report["runtime"]["status"] == "RUNTIME_NOT_ASSESSED"
    assert report["staticCode"]["schema"] == "resource_studio.static_code_analysis.v1"
    assert report["staticCode"]["status"] in {"ANALYZED", "DECODER_UNAVAILABLE", "UNSUPPORTED_ARCH", "NO_CODE_DECODED"}
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
        overlay = root / "overlay.dll"
        overlay.write_bytes(FIXTURE.read_bytes() + b"RANSOM decrypt https://example.invalid")
        overlay_report = analyze_security(overlay)
        kinds = {item["kind"] for item in overlay_report["staticIndicators"]}
        assert "OVERLAY_DATA" in {item["kind"] for item in overlay_report["unpackingIndicators"]}
        assert "OVERLAY_DATA" in kinds
        assert "ransom-note-marker" in kinds
        assert all(item["confidence"] in {"HIGH", "LIMITED"} for item in overlay_report["staticIndicators"])

        evidence = root / "telemetry.json"
        evidence.write_text(json.dumps({"targetSha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), "provider": "external-test", "capturedAtUtc": "2026-01-01T00:00:00Z", "events": [{"kind": "process.create"}], "limitations": ["captured outside Resource Studio"]}), encoding="utf-8")
        imported = load_runtime_evidence(evidence, kind="behavioralTelemetry", target_sha256=hashlib.sha256(FIXTURE.read_bytes()).hexdigest())
        imported_report = analyze_security(FIXTURE, runtime_evidence=(imported,))
        assert imported_report["runtime"]["executed"] is False
        assert imported_report["runtime"]["status"] == "EXTERNAL_EVIDENCE_IMPORTED"
        assert imported_report["runtimeEvidence"][0]["kind"] == "behavioralTelemetry"

        env = {**__import__("os").environ, "PYTHONPATH": str(ROOT)}
        cli_runtime = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "security", str(FIXTURE), "--behavioral-telemetry", str(evidence), "--memory-evidence", str(evidence), "--api-trace", str(evidence), "--json"], capture_output=True, text=True, env=env, check=False)
        assert cli_runtime.returncode == 0, cli_runtime.stderr
        cli_runtime_payload = json.loads(cli_runtime.stdout)
        assert cli_runtime_payload["runtime"]["executed"] is False
        assert cli_runtime_payload["runtime"]["evidenceCount"] == 3
        cli = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "security", str(FIXTURE), "--json"], capture_output=True, text=True, env=env, check=False)
        assert cli.returncode == 0, cli.stderr
        assert json.loads(cli.stdout)["schema"] == "resource_studio.security_report.v1"
        report_cli = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "report", "security", str(FIXTURE), "--format", "json"], capture_output=True, text=True, env=env, check=False)
        assert report_cli.returncode == 0, report_cli.stderr
        assert json.loads(report_cli.stdout)["runtime"]["executed"] is False
    print("security-analysis-tests: passed")


if __name__ == "__main__":
    main()
