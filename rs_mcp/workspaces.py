"""Workspace lookup and plan confirmation helpers."""
import time
from typing import Any

from rs_mcp.state import CONFIRMATION_TTL_SECONDS, WORKSPACES

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
