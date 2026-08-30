"""Session configuration, in-memory stores, event stream, and persistence.

All mutable MCP session state lives here; handler modules import the store
objects and mutate them in place. _load_state() restores persisted stores
in place so object identity stays stable across module boundaries.
"""
import json
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.live_analysis import LiveAnalysisSession

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


INTEGRATION_PLANS: dict[str, dict[str, Any]] = {}


PACKAGE_PLANS: dict[str, dict[str, Any]] = {}
LIVE_ANALYSIS_SESSIONS: dict[str, LiveAnalysisSession] = {}
LIVE_ANALYSIS_REPORTS: dict[str, dict[str, Any]] = {}
MAX_SESSION_EVENTS = 512
SESSION_STARTED_AT = datetime.now(UTC).isoformat()
EVENTS: list[dict[str, Any]] = []
EVENT_SEQUENCE = 0


OBSERVABILITY_METADATA: dict[str, dict[str, Any]] = {
    "resource_studio.register_file": {"effect": "register", "readOnly": True, "preconditions": ["path is under configured root", "regular file", "size within limit"], "confirmation": "none", "audit": "session event"},
    "resource_studio.inspect_file": {"effect": "inspect", "readOnly": True, "preconditions": ["registered or allowed path"], "confirmation": "none", "audit": "session event"},
    "resource_studio.index_resources": {"effect": "index", "readOnly": True, "preconditions": ["registered or allowed path"], "confirmation": "none", "audit": "session event"},
    "resource_studio.diff_files": {"effect": "diff", "readOnly": True, "preconditions": ["two files under configured root"], "confirmation": "none", "audit": "session event"},
    "resource_studio.create_workspace": {"effect": "create_isolated_copy", "readOnly": True, "preconditions": ["source file is registered or under root"], "confirmation": "none", "audit": "session event"},
    "resource_studio.plan_resource_change": {"effect": "plan", "readOnly": True, "preconditions": ["workspace exists", "resource target is explicit"], "confirmation": "not required to plan", "audit": "plan record"},
    "resource_studio.apply_plan": {"effect": "mutate_workspace", "readOnly": False, "preconditions": ["pending plan", "matching workspace hash", "valid confirmation token"], "confirmation": "human confirmation required", "audit": "verified operation audit"},
    "resource_studio.export_workspace": {"effect": "write_new_output", "readOnly": False, "preconditions": ["applied verified plan", "valid export token", "new output path"], "confirmation": "independent confirmation required", "audit": "export audit"},
    "resource_studio.cancel_plan": {"effect": "cancel_plan", "readOnly": True, "preconditions": ["pending plan"], "confirmation": "none", "audit": "session event"},
    "resource_studio.get_plan": {"effect": "read_plan", "readOnly": True, "preconditions": ["known plan id"], "confirmation": "none", "audit": "session event"},
    "resource_studio.read_audit": {"effect": "read_audit", "readOnly": True, "preconditions": ["known operation id"], "confirmation": "none", "audit": "session event"},
    "resource_studio.inspect_package": {"effect": "inspect_package", "readOnly": True, "preconditions": ["package under configured root"], "confirmation": "none", "audit": "session event"},
    "resource_studio.plan_package_change": {"effect": "plan_package_change", "readOnly": True, "preconditions": ["package inspection"], "confirmation": "not required to plan", "audit": "plan record"},
    "resource_studio.apply_package_change": {"effect": "mutate_package_output", "readOnly": False, "preconditions": ["pending package plan", "valid confirmation and admin policy"], "confirmation": "human confirmation required", "audit": "package audit"},
    "resource_studio.list_integrations": {"effect": "list_integrations", "readOnly": True, "preconditions": [], "confirmation": "none", "audit": "session event"},
    "resource_studio.plan_integration_request": {"effect": "plan_external_request", "readOnly": True, "preconditions": ["allowlisted operation"], "confirmation": "not required to plan", "audit": "plan record"},
    "resource_studio.apply_integration_request": {"effect": "external_request", "readOnly": False, "preconditions": ["matching plan", "admin authorization", "HTTPS allowlist"], "confirmation": "human confirmation required", "audit": "integration audit"},
    "resource_studio.inspect_plugin": {"effect": "inspect_plugin", "readOnly": True, "preconditions": ["plugin manifest under plugin root"], "confirmation": "none", "audit": "session event"},
    "resource_studio.plan_plugin_execution": {"effect": "plan_plugin_execution", "readOnly": True, "preconditions": ["validated plugin manifest"], "confirmation": "not required to plan", "audit": "plan record"},
    "resource_studio.apply_plugin_execution": {"effect": "execute_plugin", "readOnly": False, "preconditions": ["matching plan", "supported grant", "admin authorization when required"], "confirmation": "human confirmation required", "audit": "plugin audit"},
    "resource_studio.enable_plugin": {"effect": "enable_plugin", "readOnly": False, "preconditions": ["known plugin", "admin authorization"], "confirmation": "administrative confirmation required", "audit": "plugin audit"},
    "resource_studio.list_plugins": {"effect": "list_plugins", "readOnly": True, "preconditions": [], "confirmation": "none", "audit": "session event"},
    "resource_studio.live_analysis_contract": {"effect": "describe_live_analysis", "readOnly": True, "preconditions": [], "confirmation": "none", "audit": "session event"},
    "resource_studio.start_live_analysis_session": {"effect": "create_analysis_session", "readOnly": True, "preconditions": ["registered file", "valid target SHA-256"], "confirmation": "none", "audit": "session event"},
    "resource_studio.import_live_analysis": {"effect": "import_external_evidence", "readOnly": True, "preconditions": ["known live-analysis session", "report under configured root", "matching target SHA-256"], "confirmation": "none", "audit": "session event"},
}

def _record_event(event_kind: str, **details: Any) -> None:
    global EVENT_SEQUENCE
    with STATE_LOCK:
        EVENT_SEQUENCE += 1
        EVENTS.append({
            "schemaVersion": "resource_studio.event.v1",
            "eventId": f"evt_{EVENT_SEQUENCE:08d}",
            "sequence": EVENT_SEQUENCE,
            "timestamp": datetime.now(UTC).isoformat(),
            "kind": event_kind,
            "details": details,
            "readOnly": True,
        })
        if len(EVENTS) > MAX_SESSION_EVENTS:
            del EVENTS[:-MAX_SESSION_EVENTS]


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
