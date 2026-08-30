"""MCP discovery surface: session resources, file/plan/audit resources, prompts."""
import base64
import json
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from rs_mcp.app import server
from rs_mcp.files import _file_ref, _inspect, _read_file, _register_file, _resolve_file, _safe_path
from rs_mcp.handlers_workspace import get_plan, read_audit
from rs_mcp.pemodel import _resource_key
from rs_mcp.plugins import _discover_plugins
from rs_mcp.state import (
    AUDIT,
    EVENTS,
    FILES,
    LIVE_ANALYSIS_REPORTS,
    LIVE_ANALYSIS_SESSIONS,
    MAX_FILE_BYTES,
    MAX_RESOURCE_RAW_BYTES,
    MAX_SESSION_EVENTS,
    OBSERVABILITY_METADATA,
    PLANS,
    ROOT,
    SESSION_STARTED_AT,
    STATE_LOCK,
    WORKSPACES,
)
from rs_mcp import state as mcp_state
from rs_mcp.workspaces import _workspace

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


@server.resource(
    "resource://session/state",
    name="session_state",
    title="Resource Studio MCP session state",
    description="Read-only summary of registered files, workspaces, plans, audits, and event sequence.",
    mime_type="application/json",
)
def session_state() -> str:
    with STATE_LOCK:
        payload = {
            "schemaVersion": "resource_studio.session_state.v1",
            "sessionStartedAt": SESSION_STARTED_AT,
            "serverVersion": "0.3.0",
            "counts": {
                "files": len(FILES),
                "workspaces": len(WORKSPACES),
                "plans": len(PLANS),
                "audits": len(AUDIT),
                "liveAnalysisSessions": len(LIVE_ANALYSIS_SESSIONS),
                "liveAnalysisReports": len(LIVE_ANALYSIS_REPORTS),
                "events": len(EVENTS),
            },
            "pendingPlans": sorted(plan_id for plan_id, plan in PLANS.items() if plan.get("status") == "planned"),
            "lastEventSequence": mcp_state.EVENT_SEQUENCE,
            "readOnly": True,
        }
    return json.dumps(payload, ensure_ascii=False)


@server.resource(
    "resource://session/events",
    name="session_events",
    title="Resource Studio MCP operation events",
    description="Read-only bounded event history for this MCP session; events never grant mutation authority.",
    mime_type="application/json",
)
def session_events() -> str:
    with STATE_LOCK:
        payload = {
            "schemaVersion": "resource_studio.events.v1",
            "sessionStartedAt": SESSION_STARTED_AT,
            "events": list(EVENTS),
            "maxEvents": MAX_SESSION_EVENTS,
            "readOnly": True,
        }
    return json.dumps(payload, ensure_ascii=False)


@server.resource(
    "resource://tools/metadata",
    name="tools_metadata",
    title="Resource Studio MCP tool observability contract",
    description="Read-only side-effect, precondition, confirmation, and audit metadata for Resource Studio tools.",
    mime_type="application/json",
)
def tools_metadata() -> str:
    return json.dumps(
        {
            "schemaVersion": "resource_studio.tool_metadata.v1",
            "tools": OBSERVABILITY_METADATA,
            "readOnly": True,
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
