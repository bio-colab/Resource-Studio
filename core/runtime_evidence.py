from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


_SCHEMA = "resource_studio.runtime_evidence.v1"
_KINDS = {"behavioralTelemetry", "memoryAnalysis", "apiCallTrace"}


def load_runtime_evidence(path: Path, *, kind: str, target_sha256: str) -> dict[str, Any]:
    """Load an externally captured artifact; never starts or attaches to a target."""

    if kind not in _KINDS:
        raise ValueError(f"unsupported runtime evidence kind: {kind}")
    source = Path(path).expanduser().resolve()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read runtime evidence: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("runtime evidence must be a JSON object")
    declared_sha256 = str(payload.get("targetSha256", "")).lower()
    if len(declared_sha256) != 64 or any(char not in "0123456789abcdef" for char in declared_sha256):
        raise ValueError("runtime evidence targetSha256 must be a SHA-256 hex string")
    target_sha256 = str(target_sha256).lower()
    if declared_sha256 != target_sha256:
        raise ValueError(f"runtime evidence targets {declared_sha256}, expected {target_sha256}")
    events = payload.get("events", [])
    if not isinstance(events, list) or not all(isinstance(item, Mapping) for item in events):
        raise ValueError("runtime evidence events must be a list of objects")
    normalized = {
        "schema": _SCHEMA,
        "kind": kind,
        "sourcePath": str(source),
        "sourceSha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "targetSha256": declared_sha256,
        "capturedAtUtc": str(payload.get("capturedAtUtc", "")),
        "provider": str(payload.get("provider", "external")),
        "events": [dict(item) for item in events],
        "limitations": [str(item) for item in payload.get("limitations", [])] if isinstance(payload.get("limitations", []), list) else [],
        "executedByResourceStudio": False,
    }
    normalized["evidenceSha256"] = hashlib.sha256(json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return normalized


__all__ = ["load_runtime_evidence"]
