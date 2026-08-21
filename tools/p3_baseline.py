"""Measure cold one-shot CLI calls against a warm JSONL read host session."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def fixture() -> Path:
    configured = os.environ.get("P3_BASELINE_INPUT")
    if configured:
        return Path(configured).expanduser().resolve()
    for pattern in ("*.dll", "*.exe", "*.sys"):
        candidate = next((ROOT / "tests" / "fixtures").glob(pattern), None)
        if candidate is not None:
            return candidate.resolve()
    raise FileNotFoundError("set P3_BASELINE_INPUT or add a PE fixture under tests/fixtures")


def read_host_request(process: subprocess.Popen[str], request_id: int, argv: list[str]) -> dict[str, Any]:
    assert process.stdin is not None and process.stdout is not None
    process.stdin.write(json.dumps({"id": request_id, "argv": argv}) + "\n")
    process.stdin.flush()
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("read host closed stdout")
    return json.loads(line)


def measure_cli(argv: list[str]) -> float:
    started = time.perf_counter()
    result = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), *argv], cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)
    return round((time.perf_counter() - started) * 1000, 3)


def main() -> int:
    source = fixture()
    commands = [
        ["list", str(source), "--json"],
        ["search", str(source), "manifest", "--json"],
        ["inspect", str(source), "--json"],
    ]
    cli_ms = [measure_cli(argv) for argv in commands]
    started = time.perf_counter()
    host = subprocess.Popen(
        [sys.executable, str(ROOT / "tools" / "wpf_read_host.py")],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    host_ms: list[float] = []
    try:
        for index, argv in enumerate(commands, start=1):
            request_started = time.perf_counter()
            response = read_host_request(host, index, argv)
            host_ms.append(round((time.perf_counter() - request_started) * 1000, 3))
            if not response.get("ok"):
                raise RuntimeError(response.get("output", "host request failed"))
    finally:
        if host.stdin is not None:
            host.stdin.close()
        host.wait(timeout=15)
    output = {
        "schema": "resource_studio.p3_baseline.v1",
        "input": str(source),
        "commands": commands,
        "coldCliMs": cli_ms,
        "warmHostRequestMs": host_ms,
        "hostProcessCount": 1,
        "hostLifetimeMs": round((time.perf_counter() - started) * 1000, 3),
        "note": "This is a local process-startup comparison, not a Windows UI benchmark.",
    }
    destination = Path(os.environ.get("P3_BASELINE_OUTPUT", str(ROOT / "p3-baseline.json"))).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
