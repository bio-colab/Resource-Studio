"""Plugin discovery, registry, and runtime confirmation gates.

Owns PLUGIN_REGISTRY: _discover_plugins() rebinds it, so callers must reach
it through this module (rs_mcp.plugins.PLUGIN_REGISTRY) instead of binding
it with a from-import.
"""
import hmac
import os
import time
from pathlib import Path
from typing import Any

from core.plugins import PluginRegistry

from rs_mcp.state import CONFIRMATION_TTL_SECONDS, PLUGIN_DISABLED, PLUGIN_ROOT, ROOT, STATE_ROOT

PLUGIN_REGISTRY = PluginRegistry(audit_path=STATE_ROOT / "plugin-audit.jsonl")
PLUGIN_DISCOVERY: list[dict[str, Any]] = []

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
