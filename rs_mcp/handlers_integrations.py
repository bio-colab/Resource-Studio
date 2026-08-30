"""Allowlisted external integration request tools (plan + admin-gated apply)."""
import json
import time
import uuid
from typing import Any

from core.external_integrations import IntegrationError

from rs_mcp.app import server
from rs_mcp.integrations import INTEGRATION_GATEWAY, INTEGRATION_REGISTRY
from rs_mcp.pemodel import _sha256
from rs_mcp.plugins import _admin_token_matches, _require_runtime_confirmation
from rs_mcp.state import AUDIT, INTEGRATION_PLANS

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
