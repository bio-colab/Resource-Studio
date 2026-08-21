from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from .evidence_graph import EvidenceGraph
from .security_analysis import analyze_security


_SCHEMA = "resource_studio.case.v1"
_STATUSES = ("OPEN", "TRIAGED", "ANALYZED", "REPORTED", "CLOSED")
_TRANSITIONS = {"OPEN": {"TRIAGED"}, "TRIAGED": {"ANALYZED"}, "ANALYZED": {"REPORTED"}, "REPORTED": {"CLOSED"}, "CLOSED": set()}


class CaseLifecycleError(ValueError):
    pass


class CaseFile:
    def __init__(self, payload: Mapping[str, Any]) -> None:
        self.payload: dict[str, Any] = json.loads(json.dumps(payload, ensure_ascii=False))
        if self.payload.get("schema") != _SCHEMA:
            raise CaseLifecycleError("unsupported case schema")
        if self.payload.get("status") not in _STATUSES:
            raise CaseLifecycleError("unsupported case status")

    @classmethod
    def create(cls, artifact_path: Path) -> "CaseFile":
        source = Path(artifact_path).expanduser().resolve()
        if not source.is_file():
            raise CaseLifecycleError(f"artifact is not a regular file: {source}")
        data = source.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        now = datetime.now(UTC).isoformat()
        payload = {
            "schema": _SCHEMA,
            "caseId": f"CASE-{sha256[:16].upper()}",
            "status": "OPEN",
            "createdUtc": now,
            "updatedUtc": now,
            "artifact": {"path": str(source), "name": source.name, "size": len(data), "sha256": sha256},
            "evidenceGraph": None,
            "findings": [],
            "reports": [],
            "timeline": [],
            "audit": {"events": []},
        }
        case = cls(payload)
        case._append_event("CASE_CREATED", {"status": "OPEN", "artifactSha256": sha256}, actor="resource-studio")
        return case

    @classmethod
    def load(cls, path: Path) -> "CaseFile":
        source = Path(path).expanduser().resolve()
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CaseLifecycleError(f"cannot load case: {exc}") from exc
        if not isinstance(payload, dict):
            raise CaseLifecycleError("case file must contain a JSON object")
        return cls(payload)

    def save(self, path: Path) -> Path:
        destination = Path(path).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(self.payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=str(destination.parent), text=True)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            try:
                Path(temporary).unlink()
            except OSError:
                pass
        return destination

    def transition(self, status: str, *, actor: str = "resource-studio", note: str | None = None) -> None:
        status = status.upper()
        current = str(self.payload["status"])
        if status not in _STATUSES:
            raise CaseLifecycleError(f"unsupported case status: {status}")
        if status not in _TRANSITIONS[current]:
            raise CaseLifecycleError(f"invalid case transition: {current} -> {status}")
        if status == "CLOSED" and not self.payload.get("evidenceGraph"):
            raise CaseLifecycleError("case cannot close without an evidence graph")
        self.payload["status"] = status
        self._append_event("STATUS_CHANGED", {"from": current, "to": status, "note": note}, actor=actor)

    def add_security_report(self, report: Mapping[str, Any], *, actor: str = "resource-studio") -> None:
        target = report.get("target", {})
        expected_sha = str(self.payload["artifact"]["sha256"])
        actual_sha = str(target.get("sha256", ""))
        if actual_sha and actual_sha != expected_sha:
            raise CaseLifecycleError(f"report artifact hash mismatch: {actual_sha} != {expected_sha}")
        summary = report.get("evidence")
        if not isinstance(summary, Mapping):
            raise CaseLifecycleError("security report does not contain an evidence summary")
        graph = EvidenceGraph.from_summary(summary)
        self.payload["evidenceGraph"] = graph.to_dict()
        self.payload["evidenceGraphHash"] = graph.graph_hash()
        self.payload["findings"] = list(report.get("findings", []))
        self.payload["reports"].append({"kind": "security", "schema": report.get("schema"), "evidenceHash": report.get("evidenceHash"), "graphHash": graph.graph_hash(), "report": dict(report)})
        if self.payload["status"] == "OPEN":
            self.payload["status"] = "ANALYZED"
        self._append_event("SECURITY_REPORT_ADDED", {"evidenceHash": report.get("evidenceHash"), "graphHash": graph.graph_hash()}, actor=actor)

    def add_note(self, note: str, *, actor: str = "resource-studio") -> None:
        if not str(note).strip():
            raise CaseLifecycleError("case note cannot be empty")
        self._append_event("NOTE_ADDED", {"note": str(note)}, actor=actor)

    def timeline(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.payload.get("timeline", []))

    def state_hash(self) -> str:
        return hashlib.sha256(_canonical(self.payload)).hexdigest()

    def _append_event(self, event_type: str, data: Mapping[str, Any], *, actor: str) -> None:
        previous = self.payload["audit"]["events"][-1].get("eventHash") if self.payload["audit"]["events"] else None
        event = {"type": event_type, "createdUtc": datetime.now(UTC).isoformat(), "actor": actor, "previousEventHash": previous, "data": dict(data)}
        event["eventHash"] = hashlib.sha256(_canonical(event)).hexdigest()
        self.payload["audit"]["events"].append(event)
        self.payload["timeline"].append({"type": event_type, "createdUtc": event["createdUtc"], "actor": actor, "data": dict(data), "eventHash": event["eventHash"]})
        self.payload["updatedUtc"] = event["createdUtc"]

    def verify_audit(self) -> dict[str, Any]:
        errors: list[str] = []
        previous = None
        events = self.payload.get("audit", {}).get("events", [])
        for index, event in enumerate(events):
            if event.get("previousEventHash") != previous:
                errors.append(f"event {index}: previous hash mismatch")
            stored = event.get("eventHash")
            unsigned = dict(event)
            unsigned.pop("eventHash", None)
            if stored != hashlib.sha256(_canonical(unsigned)).hexdigest():
                errors.append(f"event {index}: event hash mismatch")
            previous = stored
        return {"valid": not errors, "events": len(events), "errors": errors}


def analyze_into_case(case_path: Path, artifact_path: Path) -> CaseFile:
    case = CaseFile.load(case_path)
    case.add_security_report(analyze_security(artifact_path))
    return case


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


__all__ = ["CaseFile", "CaseLifecycleError", "analyze_into_case"]
