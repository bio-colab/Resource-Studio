from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping


_ALLOWED_STATUS = {"DETECTED", "NOT_DETECTED", "UNKNOWN", "NOT_SCANNED", "ERROR"}


@dataclass(frozen=True)
class ExternalScanResult:
    provider: str
    status: str
    target_sha256: str | None
    tool_version: str | None
    ruleset: Mapping[str, Any] | None
    exit_code: int | None
    matches: tuple[Mapping[str, Any], ...]
    captured_at_utc: str
    limitations: tuple[str, ...]

    FORMAT = "resource_studio.external_scan.v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.FORMAT,
            "provider": self.provider,
            "status": self.status,
            "targetSha256": self.target_sha256,
            "toolVersion": self.tool_version,
            "ruleset": dict(self.ruleset) if self.ruleset else None,
            "exitCode": self.exit_code,
            "matches": [dict(item) for item in self.matches],
            "capturedAtUtc": self.captured_at_utc,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ExternalScanResult:
        provider = str(value.get("provider", "")).strip()
        status = str(value.get("status", "")).upper()
        target_sha256 = value.get("targetSha256")
        if not provider:
            raise ValueError("external scan provider is required")
        if status not in _ALLOWED_STATUS:
            raise ValueError(f"unsupported external scan status: {status!r}")
        if target_sha256 is not None:
            target_sha256 = str(target_sha256).lower()
            if len(target_sha256) != 64 or any(char not in "0123456789abcdef" for char in target_sha256):
                raise ValueError("targetSha256 must be a lowercase or uppercase SHA-256 hex string")
        matches = value.get("matches", [])
        if not isinstance(matches, list) or not all(isinstance(item, Mapping) for item in matches):
            raise ValueError("external scan matches must be a list of objects")
        limitations = value.get("limitations", [])
        if not isinstance(limitations, list):
            raise ValueError("external scan limitations must be a list")
        return cls(
            provider=provider,
            status=status,
            target_sha256=target_sha256,
            tool_version=str(value["toolVersion"]) if value.get("toolVersion") is not None else None,
            ruleset=dict(value["ruleset"]) if isinstance(value.get("ruleset"), Mapping) else None,
            exit_code=int(value["exitCode"]) if value.get("exitCode") is not None else None,
            matches=tuple(dict(item) for item in matches),
            captured_at_utc=str(value.get("capturedAtUtc") or datetime.now(UTC).isoformat()),
            limitations=tuple(str(item) for item in limitations),
        )


def load_external_scan(path: Any) -> ExternalScanResult:
    source = getattr(path, "expanduser", lambda: path)().resolve()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read external scan result: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("external scan result must be a JSON object")
    return ExternalScanResult.from_mapping(payload)


def external_scan_hash(result: ExternalScanResult) -> str:
    return hashlib.sha256(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


__all__ = ["ExternalScanResult", "external_scan_hash", "load_external_scan"]
