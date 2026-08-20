from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
