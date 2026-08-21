import json
import subprocess
import sys
import tempfile
from pathlib import Path

from core.security_analysis import analyze_security
from core.security_providers import ExternalScanResult, external_scan_hash, load_external_scan

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    target_sha256 = __import__("hashlib").sha256(FIXTURE.read_bytes()).hexdigest()
    result = ExternalScanResult.from_mapping({
        "provider": "test-provider",
        "status": "NOT_DETECTED",
        "targetSha256": target_sha256,
        "toolVersion": "test-1",
        "ruleset": {"name": "fixture-rules", "version": "1"},
        "exitCode": 0,
        "matches": [],
        "limitations": ["synthetic regression result"],
    })
    assert result.to_dict()["format"] == "resource_studio.external_scan.v1"
    assert external_scan_hash(result)
    report = analyze_security(FIXTURE, (result,))
    assert report["externalScans"][0]["provider"] == "test-provider"
    assert not any(item["category"] == "EXTERNAL_SCAN" for item in report["findings"])

    wrong = ExternalScanResult.from_mapping({"provider": "test-provider", "status": "DETECTED", "targetSha256": "0" * 64, "matches": [{"rule": "synthetic"}]})
    wrong_report = analyze_security(FIXTURE, (wrong,))
    assert any(item["category"] == "EXTERNAL_SCAN" and item["severity"] == "HIGH" for item in wrong_report["findings"])

    with tempfile.TemporaryDirectory(prefix="resource-studio-security-provider-") as temporary:
        source = Path(temporary) / "scan.json"
        source.write_text(json.dumps(result.to_dict()), encoding="utf-8")
        loaded = load_external_scan(source)
        assert loaded.provider == result.provider
        env = {**__import__("os").environ, "PYTHONPATH": str(ROOT)}
        cli = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "security", str(FIXTURE), "--external-result", str(source), "--json"], capture_output=True, text=True, env=env, check=False)
        assert cli.returncode == 0, cli.stderr
        assert json.loads(cli.stdout)["externalScans"][0]["provider"] == "test-provider"
    print("security-provider-tests: passed")


if __name__ == "__main__":
    main()
