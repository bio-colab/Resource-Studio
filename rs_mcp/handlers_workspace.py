"""Core workspace lifecycle tools: create, diff, plan, apply, export, cancel."""
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from core.pe_writer import LiefPEWriter

from rs_mcp.app import server
from rs_mcp.files import _file_ref, _inspect, _read_file, _register_file, _resolve_file, _safe_path
from rs_mcp.pemodel import _resource_lookup, _sha256
from rs_mcp.state import (
    AUDIT,
    CONFIRMATION_TTL_SECONDS,
    FILES,
    PLANS,
    ROOT,
    WORKSPACES,
    WORKSPACE_ROOT,
    _persist_state,
    _record_event,
)
from rs_mcp.workspaces import _require_confirmation, _workspace

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
    _record_event("workspace.created", workspaceId=workspace_id, sourceFileId=source_record["fileId"], sourceSha256=_sha256(source_data))
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
    _record_event("plan.created", planId=plan_id, workspaceId=workspace_id, operation=operation, resource=plan["resource"])
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
    _record_event("plan.applied", operationId=operation_id, planId=plan_id, verified=audit["verified"], outputSha256=result.after_sha256)
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
    _record_event("workspace.exported", operationId=operation_id, planId=plan_id, fileId=exported["fileId"], sha256=exported["sha256"], verified=audit["verified"])
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
    _record_event("plan.cancelled", planId=plan_id)
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
