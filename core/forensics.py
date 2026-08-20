from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .deep_invariants import inspect_deep
from .invariants import snapshot
from .pe_integrity import inspect_integrity
from .verification import ResourceGraph, VerificationReport, verify_candidate


@dataclass(frozen=True)
class ForensicBaseline:
    """Immutable evidence snapshot captured independently of the Writer."""

    schema: str
    source_path: str
    captured_at_utc: str
    sha256: str
    size: int
    pe: dict[str, Any]
    resource_graph: dict[str, Any]
    deep_invariants: dict[str, Any]
    integrity: dict[str, Any]

    @classmethod
    def from_path(cls, path: Path) -> "ForensicBaseline":
        source = Path(path).expanduser().resolve()
        raw = source.read_bytes()
        return cls(
            schema="resource_studio.forensic_baseline.v1",
            source_path=str(source),
            captured_at_utc=datetime.now(UTC).isoformat(),
            sha256=hashlib.sha256(raw).hexdigest(),
            size=len(raw),
            pe=snapshot(source).to_dict(),
            resource_graph=ResourceGraph.from_path(source).to_dict(),
            deep_invariants=inspect_deep(source).to_dict(),
            integrity=inspect_integrity(source).to_dict(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "sourcePath": self.source_path,
            "capturedAtUtc": self.captured_at_utc,
            "sha256": self.sha256,
            "size": self.size,
            "pe": dict(self.pe),
            "resourceGraph": dict(self.resource_graph),
            "deepInvariants": dict(self.deep_invariants),
            "integrity": dict(self.integrity),
        }


@dataclass(frozen=True)
class ForensicEvidence:
    """Independent, attributable evidence for one PE transformation."""

    operation_id: str
    operation: str
    target: dict[str, Any]
    baseline: ForensicBaseline
    result: ForensicBaseline
    verification: VerificationReport

    def to_dict(self) -> dict[str, Any]:
        diff = dict(self.verification.semantic_diff)
        changed = [list(item) for item in diff.get("changed", [])]
        added = [list(item) for item in diff.get("added", [])]
        removed = [list(item) for item in diff.get("removed", [])]
        target_key = [self.target.get("type"), str(self.target.get("name")), self.target.get("language")]
        unintended = [item for item in changed + added + removed if item != target_key]
        return {
            "schema": "resource_studio.forensic_evidence.v1",
            "operationId": self.operation_id,
            "operation": self.operation,
            "target": dict(self.target),
            "baseline": self.baseline.to_dict(),
            "result": self.result.to_dict(),
            "forensicDifference": {
                "targeted": {
                    "key": target_key,
                    "changed": target_key in changed,
                    "added": target_key in added,
                    "removed": target_key in removed,
                    "beforeSha256": self._resource_hash(self.baseline, target_key),
                    "afterSha256": self._resource_hash(self.result, target_key),
                },
                "resourceTree": {
                    "intendedChanges": int(target_key in changed) + int(target_key in added) + int(target_key in removed),
                    "unintendedChanges": len(unintended),
                    "changed": changed,
                    "added": added,
                    "removed": removed,
                    "unintended": unintended,
                },
                "pePreservation": dict(self.verification.preservation),
                "integrity": dict(self.verification.integrity),
                "signature": dict(self.verification.signature),
                "windows": dict(self.verification.windows),
                "passed": self.verification.passed,
            },
            "verification": self.verification.to_dict(),
        }

    @staticmethod
    def _resource_hash(baseline: ForensicBaseline, key: list[Any]) -> str | None:
        for leaf in baseline.resource_graph.get("leaves", []):
            if [leaf.get("type"), str(leaf.get("name")), leaf.get("language")] == key:
                return str(leaf.get("sha256"))
        return None


def verify_transformation(
    before_path: Path,
    candidate_path: Path,
    *,
    resource_type: str | int,
    resource_name: str | int,
    language: int | None,
    operation: str,
    operation_id: str,
    expected_data: bytes | None = None,
    committed: bool = False,
) -> ForensicEvidence:
    """Build evidence after independent reopen; Writer is not the evidence source."""

    before = ForensicBaseline.from_path(before_path)
    result = ForensicBaseline.from_path(candidate_path)
    verification = verify_candidate(
        before_path,
        candidate_path,
        resource_type=resource_type,
        resource_name=resource_name,
        language=language,
        operation=operation,
        expected_data=expected_data,
        committed=committed,
    )
    return ForensicEvidence(
        operation_id=operation_id,
        operation=operation,
        target={"type": str(resource_type), "name": str(resource_name), "language": language},
        baseline=before,
        result=result,
        verification=verification,
    )
