"""Read-only inspection and indexing tools."""
from pathlib import Path
from typing import Any

from core.health import PEHealth

from rs_mcp.app import server
from rs_mcp.files import _file_ref, _inspect, _resolve_file

@server.tool(
    name="resource_studio.inspect_file",
    title="Inspect a PE file",
    description="Read-only inspection of a local file's hash, PE headers, sections, and resource count.",
    structured_output=True,
)
def inspect_file(path: str | None = None, file_id: str | None = None) -> dict[str, Any]:
    """Inspect a registered file, or register a path on first use."""
    record = _resolve_file(file_id=file_id, path=path)
    inspected = _inspect(record["path"])
    health = PEHealth.inspect(Path(record["path"]))
    return {
        **inspected,
        "file": _file_ref(record),
        "health": health.to_dict(),
        "manifestUri": f"resource://file/{record['fileId']}/manifest",
    }


@server.tool(
    name="resource_studio.index_resources",
    title="Index Win32 resources",
    description="Read-only enumeration of Win32 resource type, name, language, size, offset, and SHA-256.",
    structured_output=True,
)
def index_resources(path: str | None = None, file_id: str | None = None) -> dict[str, Any]:
    """Index resources in a registered file, or register a path on first use."""
    record = _resolve_file(file_id=file_id, path=path)
    inspected = _inspect(record["path"])
    return {
        "schemaVersion": "resource_studio.resource_index.v1",
        "path": inspected["path"],
        "file": _file_ref(record),
        "sha256": inspected["sha256"],
        "resourceCount": inspected["resourceCount"],
        "resources": inspected["resources"],
        "warnings": inspected["warnings"],
        "readOnly": True,
    }
