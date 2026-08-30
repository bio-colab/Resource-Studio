"""Registration and bounded inspection of files under the configured root."""
import uuid
from pathlib import Path
from typing import Any

from rs_mcp.pemodel import _parse_pe, _resource_entries, _sha256
from rs_mcp.state import FILES, MAX_FILE_BYTES, ROOT, _persist_state, _record_event

def _safe_path(path: str) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    if candidate.is_symlink():
        raise ValueError("symbolic links are not accepted in the read-only workspace")
    resolved = candidate.resolve(strict=True)
    if resolved != ROOT and ROOT not in resolved.parents:
        raise ValueError(f"path is outside the configured root: {resolved}")
    if not resolved.is_file():
        raise ValueError("path is not a regular file")
    if resolved.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"file exceeds the {MAX_FILE_BYTES} byte limit")
    return resolved


def _read_file(path: Path) -> bytes:
    with path.open("rb") as stream:
        return stream.read(MAX_FILE_BYTES + 1)


def _register_file(path: Path, *, role: str = "source") -> dict[str, Any]:
    resolved = _safe_path(str(path))
    data = _read_file(resolved)
    file_id = f"file_{uuid.uuid4().hex[:16]}"
    record = {
        "fileId": file_id,
        "path": str(resolved),
        "sha256": _sha256(data),
        "size": len(data),
        "role": role,
    }
    FILES[file_id] = record
    _record_event("file.registered", fileId=file_id, sha256=record["sha256"], size=record["size"], role=role)
    _persist_state()
    return record


def _resolve_file(*, file_id: str | None = None, path: str | None = None, role: str = "source") -> dict[str, Any]:
    if file_id and path:
        raise ValueError("provide file_id or path, not both")
    if file_id:
        record = FILES.get(file_id)
        if record is None:
            raise ValueError(f"unknown fileId: {file_id}")
        resolved = _safe_path(record["path"])
        current = _register_file(resolved, role=record.get("role", role))
        if current["sha256"] != record["sha256"]:
            raise ValueError("registered file changed after fileId creation; register it again")
        return record
    if path:
        return _register_file(_safe_path(path), role=role)
    raise ValueError("file_id is required; path is accepted only for initial registration")


def _file_ref(record: dict[str, Any]) -> dict[str, Any]:
    return {key: record[key] for key in ("fileId", "sha256", "size", "role")}


def _inspect(path: str) -> dict[str, Any]:
    resolved = _safe_path(path)
    data = _read_file(resolved)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("file exceeds the configured limit")
    pe = _parse_pe(data)
    resources: list[dict[str, Any]] = []
    warnings: list[str] = []
    if pe["is_pe"]:
        try:
            resources = _resource_entries(data, pe)
        except ValueError as exc:
            warnings.append(str(exc))
    else:
        warnings.append("file is not a valid PE image")
    return {
        "schemaVersion": "resource_studio.inspect.v1",
        "path": str(resolved),
        "size": len(data),
        "sha256": _sha256(data),
        "pe": pe,
        "resourceCount": len(resources),
        "resources": resources,
        "warnings": warnings,
        "readOnly": True,
    }
