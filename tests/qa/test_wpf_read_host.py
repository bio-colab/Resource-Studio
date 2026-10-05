from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"
assert FIXTURE.is_file()


def test_wpf_read_host_handles_multiple_requests_in_one_process() -> None:
    assert FIXTURE is not None
    request_lines = [
        {"id": 1, "argv": ["list", str(FIXTURE), "--json"]},
        {"id": 2, "argv": ["search", str(FIXTURE), "manifest", "--json"]},
    ]
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "tools" / "wpf_read_host.py")],
        cwd=ROOT,
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT)},
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
    assert process.wait(timeout=15) == 0
    assert [item["id"] for item in responses] == [1, 2]
    assert all(item["ok"] for item in responses)
    assert json.loads(responses[0]["output"])[0]["type"] == "MANIFEST"
    assert any(hit["type"] == "MANIFEST" for hit in json.loads(responses[1]["output"]))


if __name__ == "__main__":
    test_wpf_read_host_handles_multiple_requests_in_one_process()
    print("wpf-read-host-tests: passed")
