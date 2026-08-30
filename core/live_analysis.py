from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from .runtime_evidence import load_runtime_evidence

_SCHEMA = "resource_studio.live_analysis.v1"
_CONTRACT_SCHEMA = "resource_studio.live_analysis_contract.v1"
_KINDS = ("behavioralTelemetry", "memoryAnalysis", "apiCallTrace")
_SHA256_LENGTH = 64


def _valid_sha256(value: str) -> str:
    normalized = str(value).lower()
    if len(normalized) != _SHA256_LENGTH or any(char not in "0123456789abcdef" for char in normalized):
        raise ValueError("target_sha256 must be a SHA-256 hex string")
    return normalized


def _stable_hash(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class LiveAnalysisSession:
    session_id: str
    target_sha256: str
    provider: str
    started_at_utc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": _SCHEMA,
            "sessionId": self.session_id,
            "targetSha256": self.target_sha256,
            "provider": self.provider,
            "startedAtUtc": self.started_at_utc,
            "mode": "read-only-external-import",
            "executedByResourceStudio": False,
            "attachedToProcess": False,
            "readOnly": True,
        }


class LiveAnalysisAdapter:
    """Read-only adapter for importing externally captured live-analysis evidence.

    This first implementation deliberately has no process, debugger, memory, or
    network control. It binds imported observations to a target hash and session.
    """

    @staticmethod
    def contract() -> dict[str, Any]:
        return {
            "schema": _CONTRACT_SCHEMA,
            "mode": "read-only-external-import",
            "capabilities": {
                "behavioralTelemetry": "import-only",
                "memoryAnalysis": "import-only",
                "apiCallTrace": "import-only",
                "startsProcess": False,
                "attachesToProcess": False,
                "readsLiveMemory": False,
                "executesDebuggerCommands": False,
                "writesTarget": False,
            },
            "requiredBinding": "targetSha256",
            "kinds": list(_KINDS),
            "limitations": [
                "Resource Studio does not capture live telemetry in this adapter.",
                "Imported observations are evidence, not a malware verdict.",
                "The external provider and capture environment remain part of provenance.",
            ],
            "readOnly": True,
        }

    def start_session(self, target_sha256: str, *, provider: str = "external") -> LiveAnalysisSession:
        return LiveAnalysisSession(
            session_id=f"live_{uuid.uuid4().hex[:16]}",
            target_sha256=_valid_sha256(target_sha256),
            provider=str(provider or "external"),
            started_at_utc=datetime.now(UTC).isoformat(),
        )

    def import_report(
        self,
        session: LiveAnalysisSession,
        path: Path,
        *,
        kind: str,
    ) -> dict[str, Any]:
        if kind not in _KINDS:
            raise ValueError(f"unsupported live-analysis evidence kind: {kind}")
        normalized = load_runtime_evidence(Path(path), kind=kind, target_sha256=session.target_sha256)
        normalized.update(
            {
                "schema": _SCHEMA,
                "sessionId": session.session_id,
                "adapter": "resource_studio.live_analysis",
                "mode": "read-only-external-import",
                "executedByResourceStudio": False,
                "attachedToProcess": False,
                "readOnly": True,
            }
        )
        normalized["limitations"] = list(normalized.get("limitations", []))
        for limitation in self.contract()["limitations"]:
            if limitation not in normalized["limitations"]:
                normalized["limitations"].append(limitation)
        payload = dict(normalized)
        payload.pop("evidenceSha256", None)
        normalized["evidenceSha256"] = _stable_hash(payload)
        return normalized


__all__ = ["LiveAnalysisAdapter", "LiveAnalysisSession"]
