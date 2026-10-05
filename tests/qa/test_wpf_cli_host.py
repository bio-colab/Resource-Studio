from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"
assert FIXTURE.is_file()


def _run_host(request_lines: list[dict], *, pythonpath: str | None) -> list[dict]:
    env = dict(os.environ)
    if pythonpath is None:
        env.pop("PYTHONPATH", None)
    else:
        env["PYTHONPATH"] = pythonpath
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "tools" / "wpf_cli_host.py")],
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write("".join(json.dumps(item) + "\n" for item in request_lines))
    process.stdin.close()
    responses = [json.loads(line) for line in process.stdout if line.strip()]
    process.wait(timeout=60)
    return responses


def test_cli_host_serves_multiple_stateless_requests_without_pythonpath() -> None:
    """Script-mode launch must self-heal sys.path (no PYTHONPATH set)."""
    request_lines = [
        {"id": 1, "argv": ["--help"]},
        {"id": 2, "argv": ["validate", str(FIXTURE), "--json"]},
        {"id": 3, "argv": ["validate", str(FIXTURE), "--json"]},
    ]
    responses = _run_host(request_lines, pythonpath=None)
    assert [item["id"] for item in responses] == [1, 2, 3]
    assert all(item["ok"] for item in responses), responses
    assert "resource-studio" in responses[0]["output"]
    assert json.loads(responses[1]["output"])["status"] == "VALID_PE"
    # Stateless executor: identical request twice gives identical payload.
    assert responses[2]["output"] == responses[1]["output"]


def test_cli_host_survives_malformed_requests() -> None:
    responses = _run_host(
        [
            {"id": 1, "argv": "not-a-list"},
            {"id": 2, "argv": ["missing", "command"]},
        ],
        pythonpath=None,
    )
    assert [item["id"] for item in responses] == [1, 2]
    assert not any(item["ok"] for item in responses)
    assert all(item["exitCode"] == 2 for item in responses)


def test_cli_host_reports_failing_command_and_keeps_serving() -> None:
    responses = _run_host(
        [
            {"id": 1, "argv": ["validate", str(ROOT / "tests" / "fixtures" / "not-pe.txt")]},
            {"id": 2, "argv": ["--help"]},
        ],
        pythonpath=None,
    )
    assert responses[0]["ok"] is False
    assert responses[0]["exitCode"] != 0
    assert responses[1]["ok"] is True


def test_cli_host_applies_request_env_for_telemetry(tmp_path: Path) -> None:
    destination = tmp_path / "p0-telemetry.jsonl"
    request_lines = [
        {
            "id": 1,
            "argv": ["validate", str(FIXTURE), "--json"],
            "env": {"RESOURCE_STUDIO_P0_TELEMETRY_PATH": str(destination)},
        },
        {"id": 2, "argv": ["validate", str(FIXTURE), "--json"]},
    ]
    responses = _run_host(request_lines, pythonpath=None)
    assert all(item["ok"] for item in responses)
    assert destination.is_file(), "CLI telemetry must be written when env is applied"
    first_line = json.loads(destination.read_text(encoding="utf-8").splitlines()[0])
    assert first_line["schema"] == "resource_studio.p0_telemetry.v1"


def test_apply_and_restore_env_roundtrip() -> None:
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import wpf_cli_host as host

        had_missing = "RS_PROBE_MISSING" in os.environ
        missing_old = os.environ.get("RS_PROBE_MISSING")
        existing_old = os.environ.get("RS_PROBE_EXISTING")
        try:
            os.environ.pop("RS_PROBE_MISSING", None)
            os.environ["RS_PROBE_EXISTING"] = "old"
            saved = host._apply_env({"RS_PROBE_MISSING": "new", "RS_PROBE_EXISTING": "new"})
            assert os.environ["RS_PROBE_MISSING"] == "new"
            assert os.environ["RS_PROBE_EXISTING"] == "new"
            host._restore_env(saved)
            assert "RS_PROBE_MISSING" not in os.environ
            assert os.environ["RS_PROBE_EXISTING"] == "old"
        finally:
            os.environ.pop("RS_PROBE_MISSING", None)
            if existing_old is None:
                os.environ.pop("RS_PROBE_EXISTING", None)
            else:
                os.environ["RS_PROBE_EXISTING"] = existing_old
            if had_missing and missing_old is not None:
                os.environ["RS_PROBE_MISSING"] = missing_old
    finally:
        if str(ROOT / "tools") in sys.path:
            sys.path.remove(str(ROOT / "tools"))


def test_read_host_also_self_heals_without_pythonpath() -> None:
    """Regression: wpf_read_host.py failed to import resource_studio_cli when
    launched as a script with no PYTHONPATH (the WPF launch mode)."""
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "tools" / "wpf_read_host.py")],
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    request = {"id": 1, "argv": ["list", str(FIXTURE), "--json"]}
    process.stdin.write(json.dumps(request) + "\n")
    process.stdin.close()
    responses = [json.loads(line) for line in process.stdout if line.strip()]
    process.wait(timeout=30)
    assert [item["id"] for item in responses] == [1]
    assert responses[0]["ok"], responses
    assert json.loads(responses[0]["output"])[0]["type"] == "MANIFEST"


if __name__ == "__main__":
    test_cli_host_serves_multiple_stateless_requests_without_pythonpath()
    test_cli_host_survives_malformed_requests()
    test_cli_host_reports_failing_command_and_keeps_serving()
    tmp = Path(os.environ.get("TMPDIR", "/tmp")) / "rs-cli-host-telemetry-test"
    tmp.mkdir(parents=True, exist_ok=True)
    test_cli_host_applies_request_env_for_telemetry(tmp)
    test_apply_and_restore_env_roundtrip()
    test_read_host_also_self_heals_without_pythonpath()
    print("wpf-cli-host-tests: passed")
