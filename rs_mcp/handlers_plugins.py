"""Plugin runtime administration tools (inspect, plan, apply, enable, list)."""
import json
import os
import time
import uuid
from typing import Any

from core.plugin_host import ADMIN_RUNTIME_PERMISSIONS, SUPPORTED_RUNTIME_PERMISSIONS, PluginHost, PluginHostError

from rs_mcp import plugins as plugin_store
from rs_mcp.app import server
from rs_mcp.plugins import (
    _admin_token_matches,
    _discover_plugins,
    _plugin_directory,
    _plugin_record,
    _require_runtime_confirmation,
    _runtime_grants,
)
from rs_mcp.state import PLUGIN_DISABLED, PLUGIN_RUNTIME_PLANS, _persist_state

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
            plugin_store.PLUGIN_REGISTRY,
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
    plugin_store.PLUGIN_REGISTRY.enable(plugin_id)
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
