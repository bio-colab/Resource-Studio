from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def environment_fingerprint() -> dict[str, Any]:
    try:
        import lief
        lief_version = str(getattr(lief, "__version__", "unknown"))
    except Exception:
        lief_version = "unavailable"
    details = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "windowsBuild": platform.version() if os.name == "nt" else None,
        "lief": lief_version,
        "gitCommit": _git_commit(),
        "dotnet": _command_version("dotnet"),
    }
    return {"sha256": hashlib.sha256(canonical_json(details)).hexdigest(), "details": details}


def build_provenance(
    input_path: Path,
    output_path: Path,
    *,
    project_format: str,
    resources: Iterable[Any],
) -> dict[str, Any]:
    try:
        import lief

        lief_version = str(getattr(lief, "__version__", "unknown"))
    except Exception:
        lief_version = "unavailable"
    return {
        "format": "resource_studio.build_provenance.v1",
        "createdUtc": datetime.now(timezone.utc).isoformat(),
        "input": {"path": str(Path(input_path).resolve()), "sha256": _sha256(Path(input_path))},
        "output": {"path": str(Path(output_path).resolve()), "sha256": _sha256(Path(output_path))},
        "projectFormat": project_format,
        "runtime": {"python": sys.version.split()[0], "platform": platform.platform(), "lief": lief_version},
        "resources": [
            {"type": entry.resource_type, "name": entry.name, "language": entry.language, "size": len(entry.data), "sha256": entry.sha256}
            for entry in sorted(resources, key=lambda item: item.key)
        ],
        "licenses": {"backend": "LIEF", "backendLicense": "Apache-2.0", "resourceHackerBundled": False},
    }


def write_provenance(path: Path, payload: dict[str, Any]) -> Path:
    path = Path(path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _git_commit() -> str | None:
    try:
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=2, check=False)
        value = result.stdout.strip()
        return value or None
    except (OSError, subprocess.SubprocessError):
        return None


def _command_version(command: str) -> str | None:
    try:
        result = subprocess.run([command, "--version"], capture_output=True, text=True, timeout=2, check=False)
        value = (result.stdout or result.stderr).splitlines()[0].strip()
        return value or None
    except (OSError, subprocess.SubprocessError, IndexError):
        return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
