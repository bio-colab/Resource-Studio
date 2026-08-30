"""MSIX package inspection and planned-change tools."""
import time
import uuid
from pathlib import Path
from typing import Any

from core.msix import MSIXError, apply_package_change, inspect_package

from rs_mcp.app import server
from rs_mcp.files import _file_ref, _read_file, _resolve_file, _safe_path
from rs_mcp.pemodel import _sha256
from rs_mcp.plugins import _require_runtime_confirmation
from rs_mcp.state import PACKAGE_PLANS, STATE_ROOT, _persist_state

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
