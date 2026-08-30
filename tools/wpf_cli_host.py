"""Long-lived CLI host for the WPF shell (write path).

Same wire protocol as wpf_read_host: one JSON request per line on stdin and
one JSON response per line on stdout. Diagnostics never use stdout.

    request : {"id": <any>, "argv": [<str>, ...], "env": {<str>: <str>}?}
    response: {"id", "ok", "exitCode", "output", "stopped"}

The host is a STATELESS executor: every request runs resource_studio_cli.main
in-process from scratch, re-reading inputs from disk exactly as a spawned
`python resource_studio_cli.py ...` would. Nothing is cached between requests,
so there is no invalidation semantics to reason about — behavior is
bit-for-bit identical to process-per-action, minus the process startup and
import cost (lief stays warm in memory, which is the point). The client in
CliProcessRunner.cs restarts the host if the process ever dies and falls back
to direct spawning if the host cannot start at all.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

# Script-mode launch (py.exe -3.12 tools/wpf_cli_host.py) puts tools/ on
# sys.path[0] and NOT the repo root; self-heal before project imports.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from wpf_read_host import dispatch_cli, write_response  # noqa: E402


def _apply_env(overrides: dict[str, str]) -> dict[str, str | None]:
    saved: dict[str, str | None] = {}
    for key, value in overrides.items():
        saved[key] = os.environ.get(key)
        os.environ[key] = str(value)
    return saved


def _restore_env(saved: dict[str, str | None]) -> None:
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def handle_request(request: Any) -> tuple[int, str, Any]:
    """Validate one request; returns (exit_code, output, request_id)."""
    request_id = request.get("id") if isinstance(request, dict) else None
    argv = request.get("argv") if isinstance(request, dict) else None
    if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv):
        raise ValueError("argv must be a list of strings")
    env = request.get("env")
    if env is None:
        env = {}
    if not isinstance(env, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in env.items()
    ):
        raise ValueError("env must be a mapping of strings to strings")
    saved = _apply_env(env)
    try:
        code, output = dispatch_cli(argv)
    finally:
        _restore_env(saved)
    return code, output, request_id


def main() -> int:
    for raw_line in sys.stdin:
        if not raw_line.strip():
            continue
        request: Any = None
        try:
            request = json.loads(raw_line)
            code, output, request_id = handle_request(request)
        except Exception as exc:
            request_id = request.get("id") if isinstance(request, dict) else None
            code, output = 2, f"error: {exc}"
        write_response(request_id, code, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
