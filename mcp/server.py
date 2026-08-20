from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import struct
import uuid
from pathlib import Path
from typing import Any

from mcp.server import MCPServer

LOGGER = logging.getLogger("resource_studio.mcp")
ROOT = Path(os.environ.get("RESOURCE_STUDIO_ROOT", Path.cwd())).expanduser().resolve()
WORKSPACE_ROOT = ROOT / ".resource-studio" / "workspaces"
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_RESOURCE_NODES = 100_000
WORKSPACES: dict[str, dict[str, Any]] = {}
PLANS: dict[str, dict[str, Any]] = {}
AUDIT: dict[str, dict[str, Any]] = {}

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


def _read_file(path: Path) -> bytes:
    with path.open("rb") as stream:
        return stream.read(MAX_FILE_BYTES + 1)


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
            "serverVersion": "0.2.0",
        },
        ensure_ascii=False,
    )


@server.tool(
    name="resource_studio.create_workspace",
    title="Create an isolated workspace",
    description="Copy a source file into an internal isolated workspace without changing the source.",
    structured_output=True,
)
def create_workspace(path: str) -> dict[str, Any]:
    """Create a disposable isolated copy for future plans and modifications."""
    source = _safe_path(path)
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
        "source_sha256": _sha256(source_data),
        "workspace_path": str(workspace_path),
        "workspace_sha256": _sha256(workspace_data),
    }
    return {
        "schemaVersion": "resource_studio.workspace.v1",
        "workspaceId": workspace_id,
        "sourcePath": str(source),
        "sourceSha256": _sha256(source_data),
        "workspacePath": str(workspace_path),
        "workspaceSha256": _sha256(workspace_data),
        "sourceReadOnly": True,
        "workspaceReady": True,
    }


@server.tool(
    name="resource_studio.diff_files",
    title="Compare two PE files",
    description="Read-only structural and resource comparison of two files under the configured root.",
    structured_output=True,
)
def diff_files(path_a: str, path_b: str) -> dict[str, Any]:
    """Compare two files without modifying either file."""
    left = _inspect(path_a)
    right = _inspect(path_b)
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
        "left": {"path": left["path"], "sha256": left["sha256"]},
        "right": {"path": right["path"], "sha256": right["sha256"]},
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
) -> dict[str, Any]:
    """Create a non-writing resource plan against an isolated workspace."""
    if operation not in {"add", "replace", "delete"}:
        raise ValueError("operation must be add, replace, or delete")
    workspace = _workspace(workspace_id)
    inspected = _inspect(workspace["workspace_path"])
    candidates = [
        item
        for item in inspected["resources"]
        if str(item.get("type")) == resource_type and str(item.get("name")) == resource_name
    ]
    if language is None and operation in {"replace", "delete"}:
        if len(candidates) != 1:
            raise ValueError("language is required when the resource has multiple language variants")
        current = candidates[0]
        planned_language = current.get("language")
    else:
        planned_language = 1033 if language is None else language
        target_key = (resource_type, resource_name, str(planned_language))
        current = _resource_lookup(inspected["resources"]).get(target_key)
    if operation in {"replace", "delete"} and current is None:
        raise ValueError("the requested resource does not exist in the workspace")
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
        },
        "before": current,
        "payload": payload,
        "writesFiles": False,
        "requiresConfirmation": True,
        "confirmationToken": uuid.uuid4().hex,
        "status": "planned",
    }
    PLANS[plan_id] = plan
    return plan


@server.tool(
    name="resource_studio.apply_plan",
    title="Apply a confirmed plan",
    description="Apply only a confirmed same-size replacement inside the isolated workspace and verify the result.",
    structured_output=True,
)
def apply_plan(plan_id: str, confirmation_token: str, confirmed: bool = False) -> dict[str, Any]:
    """Apply a narrow, confirmed, same-size replacement to a workspace copy."""
    plan = PLANS.get(plan_id)
    if plan is None:
        raise ValueError(f"unknown plan: {plan_id}")
    if plan.get("status") != "planned":
        raise ValueError("plan is not pending")
    if not confirmed:
        raise ValueError("explicit human confirmation is required")
    if confirmation_token != plan.get("confirmationToken"):
        raise ValueError("invalid or expired confirmation token")
    if plan["operation"] != "replace":
        raise ValueError("this milestone only applies same-size replace plans")

    workspace = _workspace(plan["workspaceId"])
    workspace_path = Path(workspace["workspace_path"])
    current_workspace_data = _read_file(workspace_path)
    current_workspace_sha = _sha256(current_workspace_data)
    if current_workspace_sha != plan["workspaceSha256"]:
        raise ValueError("workspace changed after the plan was created; rebuild the plan")

    before = plan.get("before") or {}
    offset = before.get("data_offset")
    size = before.get("size")
    payload_info = plan.get("payload") or {}
    payload_path = payload_info.get("path")
    if offset is None or size is None or not payload_path:
        raise ValueError("plan does not contain a writable resource payload")
    payload_file = _safe_path(payload_path)
    payload = _read_file(payload_file)
    if len(payload) != size:
        raise ValueError("safe same-size backend rejected a payload size change")
    if offset < 0 or offset + size > len(current_workspace_data):
        raise ValueError("resource data range is outside the workspace file")

    output_path = workspace_path.with_name(f"{workspace_path.stem}.applied{workspace_path.suffix}")
    patched = bytearray(current_workspace_data)
    patched[offset : offset + size] = payload
    output_path.write_bytes(patched)
    output = _inspect(str(output_path))
    key = _resource_key(before)
    after = _resource_lookup(output["resources"]).get(key)
    payload_sha = _sha256(payload)
    if after is None or after.get("sha256") != payload_sha:
        output_path.unlink(missing_ok=True)
        raise ValueError("post-write verification failed; output was removed")

    operation_id = f"op_{uuid.uuid4().hex[:16]}"
    audit = {
        "schemaVersion": "resource_studio.audit.v1",
        "operationId": operation_id,
        "planId": plan_id,
        "workspaceId": plan["workspaceId"],
        "operation": "replace",
        "sourceWorkspaceSha256": current_workspace_sha,
        "outputPath": str(output_path),
        "outputSha256": output["sha256"],
        "resource": {"type": key[0], "name": key[1], "language": key[2]},
        "beforeSha256": before.get("sha256"),
        "afterSha256": after.get("sha256"),
        "verified": True,
    }
    plan["status"] = "applied"
    plan["usedConfirmation"] = True
    plan["outputPath"] = str(output_path)
    AUDIT[operation_id] = audit
    return {
        "schemaVersion": "resource_studio.apply.v1",
        "operationId": operation_id,
        "planId": plan_id,
        "status": "verified",
        "outputPath": str(output_path),
        "outputSha256": output["sha256"],
        "changes": [{"beforeSha256": before.get("sha256"), "afterSha256": after.get("sha256")}],
        "verification": {"reopened": True, "resourceHashMatchesPayload": True},
        "auditUri": f"resource://operation/{operation_id}/audit",
    }


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


@server.tool(
    name="resource_studio.inspect_file",
    title="Inspect a PE file",
    description="Read-only inspection of a local file's hash, PE headers, sections, and resource count.",
    structured_output=True,
)
def inspect_file(path: str) -> dict[str, Any]:
    """Inspect a file under the configured read-only root without modifying it."""
    return _inspect(path)


@server.tool(
    name="resource_studio.index_resources",
    title="Index Win32 resources",
    description="Read-only enumeration of Win32 resource type, name, language, size, offset, and SHA-256.",
    structured_output=True,
)
def index_resources(path: str) -> dict[str, Any]:
    """Index resources in a PE file under the configured root without modifying it."""
    inspected = _inspect(path)
    return {
        "schemaVersion": "resource_studio.resource_index.v1",
        "path": inspected["path"],
        "sha256": inspected["sha256"],
        "resourceCount": inspected["resourceCount"],
        "resources": inspected["resources"],
        "warnings": inspected["warnings"],
        "readOnly": True,
    }


if __name__ == "__main__":
    logging.basicConfig(stream=__import__("sys").stderr, level=logging.INFO)
    LOGGER.info("starting Resource Studio MCP stdio server; root=%s", ROOT)
    server.run("stdio")
