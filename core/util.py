"""Cross-cutting micro-helpers shared across core modules, the CLI, and tools.

This module intentionally imports nothing from other core modules so that any
layer can depend on it without creating import cycles. The CLI imports it
lazily inside command functions to preserve the module-startup contract
(tests/qa/test_cli_startup_contract.py).
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    """Streaming SHA-256 of a file, read in 1 MiB chunks."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def numeric_value(value: Any, default: int = 0) -> int:
    """Coerce loosely typed PE metadata into an int, tolerating nested tuples."""
    if isinstance(value, (tuple, list)):
        return numeric_value(value[0], default) if value else default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def unescape_rc_string(value: str) -> str:
    """Resolve RC string escapes (\\n, \\r, \\", \\\\); a dangling backslash survives."""
    result: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            result.append({"n": "\n", "r": "\r", "\\": "\\", '"': '"'}.get(character, character))
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            result.append(character)
    if escaped:
        result.append("\\")
    return "".join(result)


__all__ = ["sha256_file", "numeric_value", "unescape_rc_string"]
