from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import shutil
import struct
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import unquote

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.external_integrations import IntegrationError, IntegrationGateway, IntegrationRegistry
from core.msix import MSIXError, apply_package_change, inspect_package
from core.health import PEHealth
from core.pe_writer import LiefPEWriter
from core.plugin_host import ADMIN_RUNTIME_PERMISSIONS, SUPPORTED_RUNTIME_PERMISSIONS, PluginHost, PluginHostError
from core.plugins import PluginRegistry
from mcp.server import MCPServer

LOGGER = logging.getLogger("resource_studio.mcp")
ROOT = Path(os.environ.get("RESOURCE_STUDIO_ROOT", Path.cwd())).expanduser().resolve()
STATE_ROOT = ROOT / ".resource-studio"
WORKSPACE_ROOT = STATE_ROOT / "workspaces"
STATE_PATH = STATE_ROOT / "mcp-state.json"
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_RESOURCE_NODES = 100_000
FILES: dict[str, dict[str, Any]] = {}
WORKSPACES: dict[str, dict[str, Any]] = {}
PLANS: dict[str, dict[str, Any]] = {}
AUDIT: dict[str, dict[str, Any]] = {}
PLUGIN_RUNTIME_PLANS: dict[str, dict[str, Any]] = {}
PLUGIN_DISABLED: dict[str, str] = {}
MAX_RESOURCE_RAW_BYTES = 4 * 1024 * 1024
CONFIRMATION_TTL_SECONDS = 10 * 60
PLUGIN_ROOT = STATE_ROOT / "plugins"
PLUGIN_REGISTRY = PluginRegistry(audit_path=STATE_ROOT / "plugin-audit.jsonl")
PLUGIN_DISCOVERY: list[dict[str, Any]] = []
INTEGRATION_PLANS: dict[str, dict[str, Any]] = {}
INTEGRATION_REGISTRY = IntegrationRegistry(STATE_ROOT / "integrations.json")
INTEGRATION_GATEWAY = IntegrationGateway(INTEGRATION_REGISTRY)
PACKAGE_PLANS: dict[str, dict[str, Any]] = {}

TYPE_NAMES = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATORS",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    17: "DLGINCLUDE",
    19: "PLUGPLAY",
    20: "VXD",
    21: "ANICURSOR",
    22: "ANIICON",
    23: "HTML",
    24: "MANIFEST",
}

server = MCPServer(
    "resource-studio",
    version="0.2.0",
    title="Resource Studio MCP",
    description="PE and Win32 resource inspection with isolated workspaces and dry-run plans.",
    instructions=(
        "Inspection and indexing are read-only. Workspace creation copies a source into an "
        "internal isolated directory. Planning never changes the source or workspace file. "
        "Apply is limited to confirmed same-size replacement in the workspace copy."
    ),
    log_level="INFO",
)


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


STATE_LOCK = threading.RLock()


def _state_payload() -> dict[str, Any]:
    return {
        "schemaVersion": "resource_studio.mcp_state.v1",
        "files": FILES,
        "workspaces": WORKSPACES,
        "plans": PLANS,
        "audit": AUDIT,
        "pluginRuntimePlans": PLUGIN_RUNTIME_PLANS,
        "pluginDisabled": PLUGIN_DISABLED,
        "packagePlans": PACKAGE_PLANS,
    }


def _persist_state() -> None:
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".tmp")
    with STATE_LOCK:
        temporary.write_text(json.dumps(_state_payload(), ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(STATE_PATH)


def _load_state() -> None:
    if not STATE_PATH.is_file():
        return
    try:
        payload = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        if payload.get("schemaVersion") != "resource_studio.mcp_state.v1":
            return
        FILES.update({str(key): value for key, value in payload.get("files", {}).items() if isinstance(value, dict)})
        WORKSPACES.update({str(key): value for key, value in payload.get("workspaces", {}).items() if isinstance(value, dict)})
        PLANS.update({str(key): value for key, value in payload.get("plans", {}).items() if isinstance(value, dict)})
        AUDIT.update({str(key): value for key, value in payload.get("audit", {}).items() if isinstance(value, dict)})
        PLUGIN_RUNTIME_PLANS.update({str(key): value for key, value in payload.get("pluginRuntimePlans", {}).items() if isinstance(value, dict)})
        PLUGIN_DISABLED.update({str(key): str(value) for key, value in payload.get("pluginDisabled", {}).items()})
        PACKAGE_PLANS.update({str(key): value for key, value in payload.get("packagePlans", {}).items() if isinstance(value, dict)})
        for plan in PLANS.values():
            if plan.get("status") == "planned":
                plan["status"] = "stale_after_restart"
            plan["confirmationToken"] = None
            plan["exportConfirmationToken"] = None
        for package_plan in PACKAGE_PLANS.values():
            if package_plan.get("status") == "planned":
                package_plan["status"] = "stale_after_restart"
            package_plan["confirmationToken"] = None
        for runtime_plan in PLUGIN_RUNTIME_PLANS.values():
            if runtime_plan.get("status") == "planned":
                runtime_plan["status"] = "stale_after_restart"
            runtime_plan["confirmationToken"] = None

    except (OSError, ValueError, TypeError) as exc:
        LOGGER.warning("could not restore MCP state: %s", exc)


def _discover_plugins() -> list[dict[str, Any]]:
    global PLUGIN_REGISTRY
    PLUGIN_ROOT.mkdir(parents=True, exist_ok=True)
    PLUGIN_REGISTRY = PluginRegistry(audit_path=STATE_ROOT / "plugin-audit.jsonl")
    discovered: list[dict[str, Any]] = []
    for manifest_path in sorted(PLUGIN_ROOT.glob("*/plugin.json")):
        relative_path = manifest_path.relative_to(ROOT).as_posix()
        try:
            manifest = PLUGIN_REGISTRY.register_file(manifest_path)
            if manifest.plugin_id in PLUGIN_DISABLED:
                PLUGIN_REGISTRY.disable(manifest.plugin_id, PLUGIN_DISABLED[manifest.plugin_id])
            compatible, reason = PLUGIN_REGISTRY.compatibility(manifest)
            discovered.append({
                "pluginId": manifest.plugin_id,
                "enabled": PLUGIN_REGISTRY.is_enabled(manifest.plugin_id),
                "disabledReason": PLUGIN_REGISTRY.disabled_reason(manifest.plugin_id),
                "name": manifest.name,
                "version": manifest.version,
                "api": manifest.api,
                "kind": manifest.kind,
                "permissions": sorted(manifest.permissions),
                "entry": manifest.entry,
                "manifestPath": relative_path,
                "status": "discovered" if compatible else "incompatible",
                "reason": reason,
                "executesCode": False,
            })
        except Exception as exc:
            discovered.append({
                "manifestPath": relative_path,
                "status": "rejected",
                "reason": str(exc),
                "executesCode": False,
            })
    PLUGIN_DISCOVERY[:] = discovered
    return list(discovered)


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


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("truncated PE data")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("truncated PE data")
    return struct.unpack_from("<I", data, offset)[0]


def _resource_label(data: bytes, base: int, value: int) -> str | int:
    if value & 0x80000000:
        offset = base + (value & 0x7FFFFFFF)
        length = _u16(data, offset)
        end = offset + 2 + length * 2
        if end > len(data):
            raise ValueError("truncated resource name")
        return data[offset + 2 : end].decode("utf-16le", errors="replace")
    return value & 0xFFFF


def _type_label(value: str | int) -> str | int:
    if isinstance(value, int):
        return TYPE_NAMES.get(value, value)
    return value


def _parse_pe(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "is_pe": False,
        "architecture": None,
        "machine": None,
        "number_of_sections": 0,
        "resource_directory": None,
        "sections": [],
    }
    if len(data) < 64 or data[:2] != b"MZ":
        return result
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return result

    coff = pe_offset + 4
    machine = _u16(data, coff)
    section_count = _u16(data, coff + 2)
    optional_size = _u16(data, coff + 16)
    optional = coff + 20
    if optional + optional_size > len(data):
        raise ValueError("truncated optional header")
    magic = _u16(data, optional)
    if magic == 0x10B:
        architecture = "PE32"
        directory_start = optional + 96
    elif magic == 0x20B:
        architecture = "PE32+"
        directory_start = optional + 112
    else:
        raise ValueError(f"unsupported optional-header magic: 0x{magic:04x}")

    sections_start = optional + optional_size
    sections: list[dict[str, int]] = []
    for index in range(section_count):
        current = sections_start + index * 40
        if current + 40 > len(data):
            raise ValueError("truncated section table")
        name = data[current : current + 8].rstrip(b"\0").decode("ascii", errors="replace")
        sections.append(
            {
                "index": index,
                "name": name,
                "virtual_size": _u32(data, current + 8),
                "virtual_address": _u32(data, current + 12),
                "raw_size": _u32(data, current + 16),
                "raw_pointer": _u32(data, current + 20),
            }
        )

    resource_rva = 0
    resource_size = 0
    resource_entry = directory_start + 2 * 8
    if resource_entry + 8 <= optional + optional_size:
        resource_rva = _u32(data, resource_entry)
        resource_size = _u32(data, resource_entry + 4)

    result.update(
        {
            "is_pe": True,
            "architecture": architecture,
            "machine": f"0x{machine:04x}",
            "number_of_sections": section_count,
            "sections": sections,
            "resource_directory": {"rva": resource_rva, "size": resource_size},
        }
    )
    return result


def _rva_to_offset(pe: dict[str, Any], rva: int) -> int | None:
    for section in pe["sections"]:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if start <= rva < start + span:
            return section["raw_pointer"] + (rva - start)
    return None


def _resource_entries(data: bytes, pe: dict[str, Any]) -> list[dict[str, Any]]:
    directory = pe["resource_directory"]
    if not directory or not directory["rva"]:
        return []
    resource_base = _rva_to_offset(pe, directory["rva"])
    if resource_base is None or resource_base >= len(data):
        return []

    found: list[dict[str, Any]] = []
    visited: set[int] = set()
    node_count = 0

    def walk(directory_offset: int, path: list[str | int], depth: int) -> None:
        nonlocal node_count
        node_count += 1
        if node_count > MAX_RESOURCE_NODES or depth > 3:
            raise ValueError("resource directory exceeds safe traversal limits")
        if directory_offset in visited:
            return
        visited.add(directory_offset)
        if directory_offset + 16 > len(data):
            raise ValueError("truncated resource directory")
        named = _u16(data, directory_offset + 12)
        ids = _u16(data, directory_offset + 14)
        total = named + ids
        entries_offset = directory_offset + 16
        if entries_offset + total * 8 > len(data):
            raise ValueError("truncated resource entries")

        for index in range(total):
            entry = entries_offset + index * 8
            label = _resource_label(data, resource_base, _u32(data, entry))
            target = _u32(data, entry + 4)
            if target & 0x80000000:
                walk(resource_base + (target & 0x7FFFFFFF), path + [label], depth + 1)
                continue
            data_entry = resource_base + target
            if data_entry + 16 > len(data):
                raise ValueError("truncated resource data entry")
            payload_rva = _u32(data, data_entry)
            payload_size = _u32(data, data_entry + 4)
            payload_offset = _rva_to_offset(pe, payload_rva)
            if payload_offset is None or payload_offset + payload_size > len(data):
                payload_offset = None
            resource_type = _type_label(path[0]) if path else "UNKNOWN"
            resource_name = path[1] if len(path) > 1 else "UNKNOWN"
            language = path[2] if len(path) > 2 else None
            payload_hash = None
            if payload_offset is not None:
                payload_hash = _sha256(data[payload_offset : payload_offset + payload_size])
            found.append(
                {
                    "type": resource_type,
                    "name": resource_name,
                    "language": language,
                    "size": payload_size,
                    "data_rva": payload_rva,
                    "data_offset": payload_offset,
                    "sha256": payload_hash,
                }
            )

    walk(resource_base, [], 0)
    found.sort(key=lambda item: (str(item["type"]), str(item["name"]), str(item["language"])))
    return found


def _workspace(workspace_id: str) -> dict[str, Any]:
    workspace = WORKSPACES.get(workspace_id)
    if workspace is None:
        raise ValueError(f"unknown workspace: {workspace_id}")
    return workspace


def _require_confirmation(plan: dict[str, Any], confirmation_token: str, confirmed: bool) -> None:
    if not confirmed:
        raise ValueError("explicit human confirmation is required")
    if confirmation_token != plan.get("confirmationToken"):
        raise ValueError("invalid or expired confirmation token")
    created = float(plan.get("confirmationCreatedAt", 0))
    if created <= 0 or time.time() - created > CONFIRMATION_TTL_SECONDS:
        raise ValueError("confirmation token expired; rebuild the plan")


def _resource_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (str(item.get("type")), str(item.get("name")), str(item.get("language")))


def _resource_lookup(resources: list[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    return {_resource_key(item): item for item in resources}


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


@server.resource(
    "resource://workspace/info",
    name="workspace_info",
    title="Resource Studio workspace information",
    description="Read-only information about the configured local workspace.",
    mime_type="application/json",
)
def workspace_info() -> str:
    return json.dumps(
        {
            "schemaVersion": "resource_studio.workspace.v1",
            "root": str(ROOT),
            "readOnly": True,
            "maxFileBytes": MAX_FILE_BYTES,
            "maxResourceRawBytes": MAX_RESOURCE_RAW_BYTES,
            "serverVersion": "0.3.0",
            "sessionState": "in_memory",
        },
        ensure_ascii=False,
    )


@server.tool(
    name="resource_studio.register_file",
    title="Register a local file",
    description="Register a file under the configured root and return a session-scoped fileId and immutable hash.",
    structured_output=True,
)
def register_file(path: str) -> dict[str, Any]:
    record = _register_file(_safe_path(path))
    return {
        "schemaVersion": "resource_studio.file.v1",
        **_file_ref(record),
        "readOnly": True,
        "manifestUri": f"resource://file/{record['fileId']}/manifest",
    }


@server.resource(
    "resource://plugins",
    name="plugins",
    title="Discovered Resource Studio plugins",
    description="Read-only validated plugin manifests; discovery never executes plugin entrypoints.",
    mime_type="application/json",
)
def plugins_resource() -> str:
    return json.dumps({"schemaVersion": "resource_studio.plugins.v1", "plugins": _discover_plugins(), "readOnly": True}, ensure_ascii=False)


@server.resource(
    "resource://workspace/{workspace_id}",
    name="workspace",
    title="Resource Studio isolated workspace",
    description="Read-only metadata for an isolated workspace created in this server session.",
    mime_type="application/json",
)
def workspace_resource(workspace_id: str) -> str:
    return json.dumps({"schemaVersion": "resource_studio.workspace.v1", **_workspace(workspace_id)}, ensure_ascii=False)


@server.resource(
    "resource://file/{file_id}/manifest",
    name="file_manifest",
    title="PE file manifest",
    description="Read-only PE and resource manifest for a registered file.",
    mime_type="application/json",
)
def file_manifest(file_id: str) -> str:
    record = _resolve_file(file_id=file_id)
    inspected = _inspect(record["path"])
    return json.dumps(
        {
            "schemaVersion": "resource_studio.file_manifest.v1",
            "file": _file_ref(record),
            "pe": inspected["pe"],
            "resourceCount": inspected["resourceCount"],
            "resources": inspected["resources"],
            "warnings": inspected["warnings"],
            "readOnly": True,
        },
        ensure_ascii=False,
    )


@server.resource(
    "resource://file/{file_id}/resource/{resource_key}",
    name="file_resource",
    title="PE resource payload",
    description="Read-only metadata and bounded base64 payload for one registered PE resource.",
    mime_type="application/json",
)
def file_resource(file_id: str, resource_key: str) -> str:
    record = _resolve_file(file_id=file_id)
    inspected = _inspect(record["path"])
    parts = unquote(resource_key).split("/", 2)
    if len(parts) != 3:
        raise ValueError("resource_key must contain type/name/language")
    wanted = tuple(parts)
    item = next((candidate for candidate in inspected["resources"] if _resource_key(candidate) == wanted), None)
    if item is None:
        raise ValueError("resource was not found in the registered file")
    payload = None
    if item.get("data_offset") is not None and item.get("size", 0) <= MAX_RESOURCE_RAW_BYTES:
        data = _read_file(Path(record["path"]))
        offset = int(item["data_offset"])
        size = int(item["size"])
        payload = base64.b64encode(data[offset : offset + size]).decode("ascii")
    return json.dumps(
        {
            "schemaVersion": "resource_studio.resource.v1",
            "file": _file_ref(record),
            "resource": item,
            "payloadBase64": payload,
            "payloadIncluded": payload is not None,
            "readOnly": True,
        },
        ensure_ascii=False,
    )


@server.resource(
    "resource://plan/{plan_id}",
    name="plan",
    title="Resource Studio change plan",
    description="Read-only change plan awaiting confirmation or already applied.",
    mime_type="application/json",
)
def plan_resource(plan_id: str) -> str:
    return json.dumps(get_plan(plan_id), ensure_ascii=False)


@server.resource(
    "resource://operation/{operation_id}/audit",
    name="operation_audit",
    title="Resource Studio operation audit",
    description="Read-only audit record for a verified operation.",
    mime_type="application/json",
)
def operation_audit(operation_id: str) -> str:
    return json.dumps(read_audit(operation_id), ensure_ascii=False)


@server.prompt(
    name="review_change",
    title="Review a Resource Studio change",
    description="Prepare a human-readable review request for a planned change.",
)
def review_change(plan_id: str) -> list[dict[str, Any]]:
    plan = get_plan(plan_id)
    return [{"role": "user", "content": {"type": "text", "text": "Review this Resource Studio plan before confirmation:\n" + json.dumps(plan, ensure_ascii=False, indent=2)}}]


@server.prompt(
    name="pe_triage",
    title="Triage a PE manifest",
    description="Prepare a read-only triage prompt from a registered file manifest.",
)
def pe_triage(file_id: str) -> list[dict[str, Any]]:
    manifest = json.loads(file_manifest(file_id))
    return [{"role": "user", "content": {"type": "text", "text": "Triage this PE manifest without executing the file:\n" + json.dumps(manifest, ensure_ascii=False, indent=2)}}]


@server.tool(
    name="resource_studio.create_workspace",
    title="Create an isolated workspace",
    description="Copy a source file into an internal isolated workspace without changing the source.",
    structured_output=True,
)
def create_workspace(path: str | None = None, file_id: str | None = None) -> dict[str, Any]:
    """Create a disposable isolated copy for future plans and modifications."""
    source_record = _resolve_file(file_id=file_id, path=path)
    source = Path(source_record["path"])
    source_data = _read_file(source)
    workspace_id = f"ws_{uuid.uuid4().hex[:16]}"
    workspace_dir = WORKSPACE_ROOT / workspace_id
    workspace_dir.mkdir(parents=True, exist_ok=False)
    workspace_path = workspace_dir / source.name
    shutil.copy2(source, workspace_path)
    workspace_data = _read_file(workspace_path)
    WORKSPACES[workspace_id] = {
        "workspace_id": workspace_id,
        "source_path": str(source),
        "source_file_id": source_record["fileId"],
        "source_sha256": _sha256(source_data),
        "workspace_path": str(workspace_path),
        "workspace_sha256": _sha256(workspace_data),
    }
    _persist_state()
    return {
        "schemaVersion": "resource_studio.workspace.v1",
        "workspaceId": workspace_id,
        "sourcePath": str(source),
        "sourceFileId": source_record["fileId"],
        "sourceSha256": _sha256(source_data),
        "workspacePath": str(workspace_path),
        "workspaceSha256": _sha256(workspace_data),
        "sourceReadOnly": True,
        "sourceFile": _file_ref(source_record),
        "workspaceReady": True,
    }


@server.tool(
    name="resource_studio.diff_files",
    title="Compare two PE files",
    description="Read-only structural and resource comparison of two files under the configured root.",
    structured_output=True,
)
def diff_files(
    path_a: str | None = None,
    path_b: str | None = None,
    file_id_a: str | None = None,
    file_id_b: str | None = None,
) -> dict[str, Any]:
    """Compare two registered files or paths without modifying either file."""
    left_record = _resolve_file(file_id=file_id_a, path=path_a)
    right_record = _resolve_file(file_id=file_id_b, path=path_b)
    left = _inspect(left_record["path"])
    right = _inspect(right_record["path"])
    left_resources = _resource_lookup(left["resources"])
    right_resources = _resource_lookup(right["resources"])
    keys = sorted(set(left_resources) | set(right_resources))
    changes: list[dict[str, Any]] = []
    for key in keys:
        before = left_resources.get(key)
        after = right_resources.get(key)
        if before is None:
            status = "added"
        elif after is None:
            status = "removed"
        elif before.get("sha256") != after.get("sha256") or before.get("size") != after.get("size"):
            status = "modified"
        else:
            status = "unchanged"
        changes.append({"type": key[0], "name": key[1], "language": key[2], "status": status})
    return {
        "schemaVersion": "resource_studio.diff.v1",
        "left": {"path": left["path"], **_file_ref(left_record)},
        "right": {"path": right["path"], **_file_ref(right_record)},
        "fileChanged": left["sha256"] != right["sha256"],
        "changes": changes,
        "readOnly": True,
    }


@server.tool(
    name="resource_studio.plan_resource_change",
    title="Plan a resource change",
    description="Create a dry-run add, replace, or delete plan for an isolated workspace; never writes files.",
    structured_output=True,
)
def plan_resource_change(
    workspace_id: str,
    operation: str,
    resource_type: str,
    resource_name: str,
    language: int | None = None,
    payload_path: str | None = None,
    target_language: int | None = None,
) -> dict[str, Any]:
    """Create a non-writing resource plan against an isolated workspace."""
    if operation not in {"add", "replace", "delete", "change-language"}:
        raise ValueError("operation must be add, replace, delete, or change-language")
    if operation == "change-language" and target_language is None:
        raise ValueError("target_language is required for change-language")
    workspace = _workspace(workspace_id)
    inspected = _inspect(workspace["workspace_path"])
    candidates = [
        item
        for item in inspected["resources"]
        if str(item.get("type")) == resource_type and str(item.get("name")) == resource_name
    ]
    if language is None and operation in {"replace", "delete", "change-language"}:
        if len(candidates) != 1:
            raise ValueError("language is required when the resource has multiple language variants")
        current = candidates[0]
        planned_language = current.get("language")
    else:
        planned_language = 1033 if language is None else language
        target_key = (resource_type, resource_name, str(planned_language))
        current = _resource_lookup(inspected["resources"]).get(target_key)
    if operation in {"replace", "delete", "change-language"} and current is None:
        raise ValueError("the requested resource does not exist in the workspace")
    if operation == "change-language" and planned_language is None:
        planned_language = 1033
    if operation == "change-language" and target_language == planned_language:
        raise ValueError("target_language must differ from the source language")
    if operation == "change-language" and _resource_lookup(inspected["resources"]).get((resource_type, resource_name, str(target_language))) is not None:
        raise ValueError("target language resource already exists")
    if operation == "add" and current is not None:
        raise ValueError("the requested resource already exists; use replace instead")

    payload = None
    if operation in {"add", "replace"}:
        if not payload_path:
            raise ValueError("payload_path is required for add and replace")
        payload_file = _safe_path(payload_path)
        payload_data = _read_file(payload_file)
        payload = {
            "path": str(payload_file),
            "sha256": _sha256(payload_data),
            "size": len(payload_data),
        }

    plan_id = f"plan_{uuid.uuid4().hex[:16]}"
    plan = {
        "schemaVersion": "resource_studio.plan.v1",
        "planId": plan_id,
        "workspaceId": workspace_id,
        "workspacePath": workspace["workspace_path"],
        "workspaceSha256": workspace["workspace_sha256"],
        "operation": operation,
        "resource": {
            "type": resource_type,
            "name": resource_name,
            "language": planned_language,
            "targetLanguage": target_language,
        },
        "before": current,
        "payload": payload,
        "writesFiles": False,
        "requiresConfirmation": True,
        "confirmationToken": uuid.uuid4().hex,
        "confirmationCreatedAt": time.time(),
        "status": "planned",
    }
    PLANS[plan_id] = plan
    _persist_state()
    return plan


@server.tool(
    name="resource_studio.apply_plan",
    title="Apply a confirmed plan",
    description="Apply only a confirmed same-size replacement inside the isolated workspace and verify the result.",
    structured_output=True,
)
def apply_plan(plan_id: str, confirmation_token: str, confirmed: bool = False) -> dict[str, Any]:
    """Apply a confirmed resource operation through the shared PE writer and verifier."""
    plan = PLANS.get(plan_id)
    if plan is None:
        raise ValueError(f"unknown plan: {plan_id}")
    if plan.get("status") != "planned":
        raise ValueError("plan is not pending")
    _require_confirmation(plan, confirmation_token, confirmed)

    workspace = _workspace(plan["workspaceId"])
    workspace_path = Path(workspace["workspace_path"])
    current_workspace_sha = _sha256(_read_file(workspace_path))
    if current_workspace_sha != plan["workspaceSha256"]:
        raise ValueError("workspace changed after the plan was created; rebuild the plan")

    resource = plan["resource"]
    operation = plan["operation"]
    resource_name: str | int = resource["name"]
    if isinstance(resource_name, str) and resource_name.isdecimal():
        resource_name = int(resource_name)
    language = resource.get("language")
    if language is not None:
        language = int(language)
    if operation == "change-language" and language is None:
        language = 1033
    target_language = resource.get("targetLanguage")
    if target_language is not None:
        target_language = int(target_language)
    payload = None
    if operation in {"add", "replace"}:
        payload_path = (plan.get("payload") or {}).get("path")
        if not payload_path:
            raise ValueError("plan does not contain a writable resource payload")
        payload = _read_file(_safe_path(payload_path))

    output_path = workspace_path.with_name(f"{workspace_path.stem}.{operation}.applied{workspace_path.suffix}")
    writer = LiefPEWriter()
    if operation == "replace":
        result = writer.replace_typed_resource(workspace_path, output_path, resource["type"], resource_name, language, payload, backup_existing_output=False)
    elif operation == "add":
        if not isinstance(resource_name, int) or language is None:
            raise ValueError("add requires a numeric resource name and language")
        result = writer.add_typed_resource(workspace_path, output_path, resource["type"], resource_name, language, payload, backup_existing_output=False)
    elif operation == "delete":
        result = writer.delete_resource(workspace_path, output_path, resource["type"], resource_name, language, backup_existing_output=False)
    elif operation == "change-language":
        if language is None or target_language is None:
            raise ValueError("change-language requires source and target languages")
        result = writer.change_language(workspace_path, output_path, resource["type"], resource_name, language, target_language, backup_existing_output=False)
    else:
        raise ValueError(f"unsupported plan operation: {operation}")

    output = _inspect(str(output_path))
    output_record = _register_file(output_path, role="verified_output")
    source_key = (str(resource["type"]), str(resource["name"]), str(language))
    target_key = (str(resource["type"]), str(resource["name"]), str(target_language))
    before = plan.get("before") or {}
    output_lookup = _resource_lookup(output["resources"])
    after = output_lookup.get(target_key if operation == "change-language" else source_key)
    if after is None and operation in {"add", "replace"}:
        candidates = [item for item in output["resources"] if str(item.get("type")) == str(resource["type"]) and str(item.get("name")) == str(resource["name"])]
        if len(candidates) == 1:
            after = candidates[0]
    if operation == "delete":
        verified_change = result.verified and after is None
    elif operation == "change-language":
        verified_change = result.verified
    else:
        verified_change = result.verified and after is not None and after.get("sha256") == _sha256(payload or b"")
    if not verified_change:
        output_path.unlink(missing_ok=True)
        raise ValueError("shared writer verification did not expose the requested round-trip change")

    operation_id = f"op_{uuid.uuid4().hex[:16]}"
    change = {
        "type": str(resource["type"]),
        "name": str(resource["name"]),
        "language": str(language),
        "action": operation,
        "beforeSha256": before.get("sha256"),
        "afterSha256": (_sha256(payload) if operation in {"add", "replace"} else (before.get("sha256") if operation == "change-language" else None)),
    }
    if operation == "change-language":
        change["targetLanguage"] = str(target_language)
    audit = {
        "schemaVersion": "resource_studio.audit.v1",
        "operationId": operation_id,
        "planId": plan_id,
        "workspaceId": plan["workspaceId"],
        "operation": operation,
        "sourceWorkspaceSha256": current_workspace_sha,
        "sourceFile": _file_ref(FILES[workspace["source_file_id"]]),
        "outputPath": str(output_path),
        "outputFile": _file_ref(output_record),
        "outputSha256": result.after_sha256,
        "resource": change,
        "verified": result.verified and verified_change,
        "verification": result.verification or {},
        "forensicEvidence": result.forensic_evidence or {},
    }
    plan["status"] = "applied"
    plan["usedConfirmation"] = True
    plan["confirmationUsedAt"] = time.time()
    plan["outputPath"] = str(output_path)
    plan["exportConfirmationToken"] = uuid.uuid4().hex
    plan["exportConfirmationCreatedAt"] = time.time()
    AUDIT[operation_id] = audit
    _persist_state()
    return {
        "schemaVersion": "resource_studio.result.v1",
        "operationId": operation_id,
        "planId": plan_id,
        "status": "verified" if audit["verified"] else "failed",
        "source": {"workspaceId": plan["workspaceId"], "sha256": current_workspace_sha},
        "output": {"file": _file_ref(output_record), "pathPolicy": "workspace-only"},
        "outputPath": str(output_path),
        "outputSha256": result.after_sha256,
        "changes": [change],
        "warnings": list((result.verification or {}).get("warnings", [])),
        "verification": {
            "reopened": True,
            "resourceRoundTrip": verified_change,
            "writer": result.verification or {},
            "forensic": result.forensic_evidence or {},
            "signatureStatus": "checked_by_writer",
        },
        "auditUri": f"resource://operation/{operation_id}/audit",
        "exportConfirmationRequired": True,
        "exportConfirmationToken": plan["exportConfirmationToken"],
    }


@server.tool(
    name="resource_studio.export_workspace",
    title="Export a verified workspace output",
    description="Copy a verified workspace result to a new user-selected file after an explicit export confirmation.",
    structured_output=True,
)
def export_workspace(plan_id: str, confirmation_token: str, destination_path: str, confirmed: bool = False) -> dict[str, Any]:
    plan = PLANS.get(plan_id)
    if plan is None:
        raise ValueError(f"unknown plan: {plan_id}")
    if plan.get("status") != "applied":
        raise ValueError("only an applied verified plan can be exported")
    if not confirmed or confirmation_token != plan.get("exportConfirmationToken"):
        raise ValueError("explicit export confirmation is required")
    created = float(plan.get("exportConfirmationCreatedAt", 0))
    if created <= 0 or time.time() - created > CONFIRMATION_TTL_SECONDS:
        raise ValueError("export confirmation token expired; rebuild the apply result")
    source = _safe_path(plan["outputPath"])
    destination = Path(destination_path).expanduser()
    if not destination.is_absolute():
        destination = ROOT / destination
    destination = destination.resolve()
    if destination == source or destination.is_symlink() or ROOT not in destination.parents:
        raise ValueError("export destination must be a new regular file under the configured root")
    if destination.exists():
        raise ValueError("export destination already exists; choose a new Save As path")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    exported = _register_file(destination, role="exported_output")
    operation_id = f"op_{uuid.uuid4().hex[:16]}"
    audit = {
        "schemaVersion": "resource_studio.audit.v1",
        "operationId": operation_id,
        "planId": plan_id,
        "operation": "export",
        "sourceFile": _file_ref(FILES[_workspace(plan["workspaceId"])["source_file_id"]]),
        "outputFile": _file_ref(exported),
        "outputSha256": exported["sha256"],
        "verified": exported["sha256"] == _sha256(source.read_bytes()),
    }
    AUDIT[operation_id] = audit
    plan["exportedFileId"] = exported["fileId"]
    plan["exportConfirmationUsedAt"] = time.time()
    _persist_state()
    return {
        "schemaVersion": "resource_studio.result.v1",
        "operationId": operation_id,
        "planId": plan_id,
        "status": "verified" if audit["verified"] else "failed",
        "source": {"file": _file_ref(FILES[_workspace(plan["workspaceId"])["source_file_id"]])},
        "output": {"file": _file_ref(exported), "pathPolicy": "new-file-under-root"},
        "changes": [],
        "warnings": [],
        "verification": {"reopened": True, "sha256MatchesSource": audit["verified"]},
        "auditUri": f"resource://operation/{operation_id}/audit",
    }


@server.tool(
    name="resource_studio.cancel_plan",
    title="Cancel a change plan",
    description="Cancel a pending plan before any mutation occurs.",
    structured_output=True,
)
def cancel_plan(plan_id: str) -> dict[str, Any]:
    plan = PLANS.get(plan_id)
    if plan is None:
        raise ValueError(f"unknown plan: {plan_id}")
    if plan.get("status") != "planned":
        raise ValueError("only a pending plan can be cancelled")
    plan["status"] = "cancelled"
    plan["confirmationToken"] = None
    _persist_state()
    return {"schemaVersion": "resource_studio.plan.v1", "planId": plan_id, "status": "cancelled", "writesFiles": False}


@server.tool(
    name="resource_studio.read_audit",
    title="Read an operation audit",
    description="Read the structured audit record for a verified isolated operation.",
    structured_output=True,
)
def read_audit(operation_id: str) -> dict[str, Any]:
    """Read an audit record created during this server session."""
    audit = AUDIT.get(operation_id)
    if audit is None:
        raise ValueError(f"unknown operation: {operation_id}")
    return audit


@server.tool(
    name="resource_studio.get_plan",
    title="Read a change plan",
    description="Read a previously created dry-run plan without changing files.",
    structured_output=True,
)
def get_plan(plan_id: str) -> dict[str, Any]:
    """Return a stored plan from the current server session."""
    plan = PLANS.get(plan_id)
    if plan is None:
        raise ValueError(f"unknown plan: {plan_id}")
    return plan


def _plugin_record(plugin_id: str) -> dict[str, Any]:
    records = {item.get("pluginId"): item for item in _discover_plugins()}
    record = records.get(plugin_id)
    if record is None:
        raise ValueError(f"unknown or rejected plugin: {plugin_id}")
    return record


def _plugin_directory(plugin_id: str) -> Path:
    candidate = (PLUGIN_ROOT / plugin_id).resolve()
    if candidate != PLUGIN_ROOT and PLUGIN_ROOT not in candidate.parents:
        raise ValueError("plugin directory is outside the configured plugin root")
    if not candidate.is_dir():
        raise ValueError("plugin directory is not available")
    return candidate


def _admin_token_matches(token: str | None) -> bool:
    configured = os.environ.get("RESOURCE_STUDIO_MCP_ADMIN_TOKEN", "")
    return bool(configured) and bool(token) and hmac.compare_digest(token, configured)


def _runtime_grants(manifest_id: str, permissions: list[str] | None) -> frozenset[str]:
    manifest = PLUGIN_REGISTRY.get(manifest_id)
    grants = frozenset(str(permission) for permission in (permissions or []))
    if not grants.issubset(manifest.permissions):
        raise ValueError("requested runtime permission is not declared by the plugin manifest")
    return grants


def _require_runtime_confirmation(plan: dict[str, Any], confirmation_token: str, confirmed: bool) -> None:
    if not confirmed:
        raise ValueError("explicit human confirmation is required for plugin execution")
    if not hmac.compare_digest(str(plan.get("confirmationToken", "")), confirmation_token):
        raise ValueError("invalid plugin execution confirmation token")
    created = float(plan.get("createdAt", 0))
    if created <= 0 or time.time() - created > CONFIRMATION_TTL_SECONDS:
        raise ValueError("plugin execution confirmation expired; rebuild the plan")


@server.tool(
    name="resource_studio.inspect_package",
    title="Inspect an MSIX or AppX package",
    description="Read-only bounded inspection of package entries, AppxManifest.xml, AppxBlockMap.xml, and PRI metadata.",
    structured_output=True,
)
def inspect_package_tool(path: str | None = None, file_id: str | None = None) -> dict[str, Any]:
    record = _resolve_file(file_id=file_id, path=path)
    try:
        report = inspect_package(Path(record["path"]))
    except MSIXError as exc:
        raise ValueError(str(exc)) from exc
    return {**report, "file": _file_ref(record), "readOnly": True}


@server.tool(
    name="resource_studio.plan_package_change",
    title="Plan an MSIX package change",
    description="Create a non-writing package mutation plan. The source remains read-only and output is staged separately.",
    structured_output=True,
)
def plan_package_change(
    path: str | None = None,
    file_id: str | None = None,
    action: str = "replace",
    member_name: str = "",
    payload_path: str | None = None,
) -> dict[str, Any]:
    record = _resolve_file(file_id=file_id, path=path)
    try:
        before = inspect_package(Path(record["path"]))
    except MSIXError as exc:
        raise ValueError(str(exc)) from exc
    if action not in {"add", "replace", "delete"}:
        raise ValueError("package action must be add, replace, or delete")
    if not member_name or ".." in member_name.replace("\\", "/").split("/"):
        raise ValueError("member_name must be a non-empty safe package path")
    payload = None
    if payload_path is not None:
        if action == "delete":
            raise ValueError("delete does not accept payload_path")
        payload = _read_file(_safe_path(payload_path))
        if len(payload) > 256 * 1024 * 1024:
            raise ValueError("package payload exceeds the configured limit")
    if action in {"add", "replace"} and payload is None:
        raise ValueError("payload_path is required for add and replace")
    plan_id = f"package_plan_{uuid.uuid4().hex[:16]}"
    output_dir = STATE_ROOT / "package-workspaces" / plan_id
    output_dir.mkdir(parents=True, exist_ok=True)
    payload_file = output_dir / "payload.bin"
    if payload is not None:
        payload_file.write_bytes(payload)
    plan = {
        "schemaVersion": "resource_studio.msix_plan.v1",
        "planId": plan_id,
        "file": _file_ref(record),
        "sourcePath": record["path"],
        "action": action,
        "memberName": member_name,
        "payloadSha256": _sha256(payload) if payload is not None else None,
        "payloadPath": str(payload_file) if payload is not None else None,
        "beforeSha256": before["sha256"],
        "outputDir": str(output_dir),
        "confirmationToken": uuid.uuid4().hex,
        "createdAt": time.time(),
        "status": "planned",
        "requiresHumanConfirmation": True,
        "engine": "MakeAppx.exe",
        "writesSource": False,
    }
    PACKAGE_PLANS[plan_id] = plan
    _persist_state()
    return plan


@server.tool(
    name="resource_studio.apply_package_change",
    title="Apply a confirmed MSIX package change",
    description="Rebuild a staged MSIX package with MakeAppx.exe on Windows, reopen it, and return bounded verification metadata.",
    structured_output=True,
)
def apply_package_change_tool(plan_id: str, confirmation_token: str, confirmed: bool) -> dict[str, Any]:
    plan = PACKAGE_PLANS.get(plan_id)
    if plan is None:
        raise ValueError(f"unknown package plan: {plan_id}")
    if plan.get("status") != "planned":
        raise ValueError("only a pending package plan can be applied")
    _require_runtime_confirmation(plan, confirmation_token, confirmed)
    source = Path(plan["sourcePath"]).resolve()
    output_dir = Path(plan["outputDir"]).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / (source.stem + ".applied" + source.suffix)
    payload = None
    if plan.get("payloadPath"):
        payload_path = Path(str(plan["payloadPath"])).resolve()
        if output_dir not in payload_path.parents or not payload_path.is_file():
            raise ValueError("package payload staging path is invalid")
        payload = payload_path.read_bytes()
        if _sha256(payload) != plan.get("payloadSha256"):
            raise ValueError("staged package payload hash does not match the plan")
    try:
        result = apply_package_change(
            source,
            output,
            action=str(plan["action"]),
            member_name=str(plan["memberName"]),
            payload=payload,
        )
    except MSIXError as exc:
        plan["status"] = "failed"
        plan["error"] = str(exc)
        plan["confirmationToken"] = None
        _persist_state()
        raise ValueError(str(exc)) from exc
    plan["status"] = "completed"
    plan["confirmationToken"] = None
    plan["result"] = result
    _persist_state()
    return result


@server.tool(
    name="resource_studio.list_integrations",
    title="List configured external integrations",
    description="Read-only list of explicitly configured HTTPS integrations and their fixed operations; secrets are never returned.",
    structured_output=True,
)
def list_integrations() -> dict[str, Any]:
    INTEGRATION_REGISTRY.reload()
    return {
        "schemaVersion": "resource_studio.integrations.v1",
        "integrations": INTEGRATION_REGISTRY.list(),
        "errors": INTEGRATION_REGISTRY.errors(),
        "readOnly": True,
    }


@server.tool(
    name="resource_studio.plan_integration_request",
    title="Plan an external integration request",
    description="Create an in-memory, non-executing request plan for one allowlisted integration operation.",
    structured_output=True,
)
def plan_integration_request(
    integration_id: str,
    operation: str,
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    INTEGRATION_REGISTRY.reload()
    spec = INTEGRATION_REGISTRY.get(integration_id)
    spec.operation(operation)
    payload = request or {}
    try:
        serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValueError("integration request must be JSON serializable") from exc
    if len(serialized.encode("utf-8")) > 1_048_576:
        raise ValueError("integration request exceeds the configured size limit")
    plan_id = f"integration_plan_{uuid.uuid4().hex[:16]}"
    plan = {
        "schemaVersion": "resource_studio.integration_plan.v1",
        "planId": plan_id,
        "integrationId": integration_id,
        "operation": operation,
        "request": payload,
        "requestSha256": _sha256(serialized.encode("utf-8")),
        "configSha256": INTEGRATION_REGISTRY.config_sha256,
        "confirmationToken": uuid.uuid4().hex,
        "createdAt": time.time(),
        "status": "planned",
        "requiresHumanConfirmation": True,
        "requiresAdminAuthorization": True,
        "executesNetwork": False,
    }
    INTEGRATION_PLANS[plan_id] = plan
    return {key: value for key, value in plan.items() if key != "request"} | {"request": payload}


@server.tool(
    name="resource_studio.apply_integration_request",
    title="Execute a confirmed external integration request",
    description="Execute only the fixed HTTPS operation from an approved in-memory plan; arbitrary URLs and headers are forbidden.",
    structured_output=True,
)
def apply_integration_request(
    plan_id: str,
    confirmation_token: str,
    confirmed: bool,
    admin_confirmation_token: str | None = None,
) -> dict[str, Any]:
    plan = INTEGRATION_PLANS.get(plan_id)
    if plan is None:
        raise ValueError(f"unknown integration plan: {plan_id}")
    if plan.get("status") != "planned":
        raise ValueError("only a pending integration plan can be applied")
    _require_runtime_confirmation(plan, confirmation_token, confirmed)
    INTEGRATION_REGISTRY.reload()
    if plan.get("configSha256") != INTEGRATION_REGISTRY.config_sha256:
        raise ValueError("integration configuration changed after planning; rebuild the request")
    if not _admin_token_matches(admin_confirmation_token):
        raise ValueError("valid admin authorization is required before external data transfer")
    try:
        result = INTEGRATION_GATEWAY.request_json(
            str(plan["integrationId"]),
            str(plan["operation"]),
            dict(plan["request"]),
        )
    except IntegrationError as exc:
        plan["status"] = "failed"
        plan["error"] = str(exc)
        plan["confirmationToken"] = None
        raise ValueError(str(exc)) from exc
    operation_id = f"integration_{uuid.uuid4().hex[:16]}"
    plan["status"] = "completed"
    plan["confirmationToken"] = None
    AUDIT[operation_id] = {
        "schemaVersion": "resource_studio.integration_audit.v1",
        "operationId": operation_id,
        "integrationId": plan["integrationId"],
        "operation": plan["operation"],
        "requestSha256": plan["requestSha256"],
        "status": "completed",
        "secretsIncluded": False,
    }
    return {
        "schemaVersion": "resource_studio.integration_result.v1",
        "operationId": operation_id,
        "status": "completed",
        "integrationId": result["integrationId"],
        "operation": result["operation"],
        "response": result["data"],
        "auditUri": f"resource://operation/{operation_id}/audit",
    }


@server.tool(
    name="resource_studio.inspect_plugin",
    title="Inspect a plugin runtime contract",
    description="Read-only plugin manifest, permission declaration, quarantine state, and runtime policy.",
    structured_output=True,
)
def inspect_plugin(plugin_id: str) -> dict[str, Any]:
    record = _plugin_record(plugin_id)
    return {
        "schemaVersion": "resource_studio.plugin_runtime.v1",
        "plugin": record,
        "runtimePolicy": {
            "outOfProcess": True,
            "requiresPlan": True,
            "requiresHumanConfirmation": True,
            "adminTokenRequiredFor": sorted(ADMIN_RUNTIME_PERMISSIONS),
            "entrypointExecution": True,
        },
        "readOnly": True,
    }


@server.tool(
    name="resource_studio.plan_plugin_execution",
    title="Plan a plugin execution",
    description="Create a non-executing plugin runtime plan with a bounded JSON request and explicit permission grants.",
    structured_output=True,
)
def plan_plugin_execution(
    plugin_id: str,
    request: dict[str, Any],
    granted_permissions: list[str] | None = None,
) -> dict[str, Any]:
    _plugin_record(plugin_id)
    _runtime_grants(plugin_id, granted_permissions)
    try:
        serialized = json.dumps(request, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValueError("plugin request must be JSON serializable") from exc
    if len(serialized.encode("utf-8")) > 1_048_576:
        raise ValueError("plugin request exceeds the configured size limit")
    grants = _runtime_grants(plugin_id, granted_permissions)
    unsupported = grants - SUPPORTED_RUNTIME_PERMISSIONS
    if unsupported:
        raise ValueError("plugin runtime capability is not enabled for: " + ", ".join(sorted(unsupported)))
    plan_id = f"plugin_plan_{uuid.uuid4().hex[:16]}"
    plan = {
        "schemaVersion": "resource_studio.plugin_execution_plan.v1",
        "planId": plan_id,
        "pluginId": plugin_id,
        "request": request,
        "grantedPermissions": sorted(grants),
        "adminRequired": bool(grants & {"project.modify", "files.write.project-output", "network", "process.execute", "clipboard.read", "clipboard.write"}),
        "confirmationToken": uuid.uuid4().hex,
        "createdAt": time.time(),
        "status": "planned",
        "executesCode": False,
    }
    PLUGIN_RUNTIME_PLANS[plan_id] = plan
    _persist_state()
    return plan


@server.tool(
    name="resource_studio.apply_plugin_execution",
    title="Execute a confirmed plugin plan",
    description="Execute one approved plugin plan out of process with bounded resources and optional admin authorization.",
    structured_output=True,
)
def apply_plugin_execution(
    plan_id: str,
    confirmation_token: str,
    confirmed: bool,
    admin_confirmation_token: str | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    plan = PLUGIN_RUNTIME_PLANS.get(plan_id)
    if plan is None:
        raise ValueError(f"unknown plugin execution plan: {plan_id}")
    if plan.get("status") != "planned":
        raise ValueError("only a pending plugin execution plan can be applied")
    _require_runtime_confirmation(plan, confirmation_token, confirmed)
    if timeout_seconds <= 0 or timeout_seconds > 30:
        raise ValueError("timeout_seconds must be between 0 and 30")
    if os.environ.get("RESOURCE_STUDIO_MCP_ALLOW_PLUGIN_EXECUTION", "false").lower() != "true":
        raise ValueError("plugin execution is disabled by default; set RESOURCE_STUDIO_MCP_ALLOW_PLUGIN_EXECUTION=true after review")
    admin_authorized = _admin_token_matches(admin_confirmation_token)
    if not admin_authorized:
        raise ValueError("valid admin authorization is required before executing plugin code")
    plugin_id = str(plan["pluginId"])
    _plugin_record(plugin_id)
    plugin_dir = _plugin_directory(plugin_id)
    try:
        result = PluginHost().run_registered(
            PLUGIN_REGISTRY,
            plugin_id,
            plugin_dir,
            dict(plan["request"]),
            granted_permissions=plan["grantedPermissions"],
            admin_authorized=admin_authorized,
            timeout_seconds=timeout_seconds,
        )
    except PluginHostError as exc:
        PLUGIN_DISABLED[plugin_id] = str(exc)
        plan["status"] = "failed"
        plan["error"] = str(exc)
        plan["confirmationToken"] = None
        _persist_state()
        raise ValueError(str(exc)) from exc
    plan["status"] = "completed"
    plan["confirmationToken"] = None
    plan["result"] = {"pluginId": result.plugin_id, "response": result.response, "stderr": result.stderr}
    _persist_state()
    return {
        "schemaVersion": "resource_studio.plugin_execution_result.v1",
        "planId": plan_id,
        "status": "completed",
        "pluginId": result.plugin_id,
        "response": result.response,
        "stderr": result.stderr,
        "outOfProcess": True,
        "audit": "plugin.runtime.execute",
    }


@server.tool(
    name="resource_studio.enable_plugin",
    title="Re-enable a quarantined plugin",
    description="Administrative action to re-enable a disabled plugin after review.",
    structured_output=True,
)
def enable_plugin(plugin_id: str, admin_confirmation_token: str) -> dict[str, Any]:
    if not _admin_token_matches(admin_confirmation_token):
        raise ValueError("valid admin authorization is required")
    _plugin_record(plugin_id)
    PLUGIN_REGISTRY.enable(plugin_id)
    PLUGIN_DISABLED.pop(plugin_id, None)
    _persist_state()
    return {"schemaVersion": "resource_studio.plugin_admin.v1", "pluginId": plugin_id, "status": "enabled", "adminAction": True}


@server.tool(
    name="resource_studio.list_plugins",
    title="List discovered plugins",
    description="Read-only discovery of validated plugin manifests; no plugin entrypoint is executed.",
    structured_output=True,
)
def list_plugins() -> dict[str, Any]:
    return {"schemaVersion": "resource_studio.plugins.v1", "plugins": _discover_plugins(), "readOnly": True}


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


_load_state()
_discover_plugins()


if __name__ == "__main__":
    logging.basicConfig(stream=__import__("sys").stderr, level=logging.INFO)
    LOGGER.info("starting Resource Studio MCP stdio server; root=%s", ROOT)
    server.run("stdio")
