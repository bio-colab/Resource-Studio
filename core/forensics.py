from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .provenance import canonical_json, environment_fingerprint
from .verification import ResourceGraph, VerificationContext, VerificationReport, verify_candidate


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
        return cls.from_context(VerificationContext.from_path(path))

    @classmethod
    def from_context(cls, context: VerificationContext) -> "ForensicBaseline":
        source = context.path
        raw = source.read_bytes()
        return cls(
            schema="resource_studio.forensic_baseline.v1",
            source_path=str(source),
            captured_at_utc=datetime.now(UTC).isoformat(),
            sha256=hashlib.sha256(raw).hexdigest(),
            size=len(raw),
            pe=context.state.to_dict(),
            resource_graph=context.graph.to_dict(),
            deep_invariants=dict(context.deep_invariants),
            integrity=dict(context.integrity),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
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
        return json.loads(json.dumps(payload, ensure_ascii=False))

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ForensicBaseline":
        if payload.get("schema") != "resource_studio.forensic_baseline.v1":
            raise ValueError("unsupported forensic baseline schema")
        return cls(
            schema=str(payload["schema"]),
            source_path=str(payload["sourcePath"]),
            captured_at_utc=str(payload["capturedAtUtc"]),
            sha256=str(payload["sha256"]),
            size=int(payload["size"]),
            pe=dict(payload["pe"]),
            resource_graph=dict(payload["resourceGraph"]),
            deep_invariants=dict(payload["deepInvariants"]),
            integrity=dict(payload["integrity"]),
        )

    def save(self, path: Path) -> Path:
        target = Path(path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self.to_dict(), stream, ensure_ascii=False, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, target)
        except Exception:
            Path(temporary_name).unlink(missing_ok=True)
            raise
        return target

    @classmethod
    def load(cls, path: Path) -> "ForensicBaseline":
        payload = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("forensic baseline artifact must be a JSON object")
        return cls.from_dict(payload)


@dataclass(frozen=True)
class ForensicEvidence:
    """Independent, attributable evidence for one PE transformation."""

    operation_id: str
    operation: str
    target: dict[str, Any]
    baseline: ForensicBaseline
    result: ForensicBaseline
    verification: VerificationReport
    previous_evidence_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        from .evidence_model import build_evidence_summary
        from .preservation import build_preservation_map
        from .pure_loader_oracle import select_from_graph
        from .raw_resource_parser import compare_with_graph, parse_raw_resources

        diff = dict(self.verification.semantic_diff)
        pure_loader = select_from_graph(
            self.result.resource_graph,
            self.target.get("type"),
            self.target.get("name"),
            self.target.get("language"),
        )
        preservation_map = build_preservation_map(
            self.baseline.source_path,
            self.result.source_path,
            resource_type=self.target.get("type"),
            resource_name=self.target.get("name"),
            language=self.target.get("language"),
        )
        raw_report = parse_raw_resources(self.result.source_path)
        raw_comparison = compare_with_graph(raw_report, self.result.resource_graph)
        evidence_summary = build_evidence_summary(
            self.result.source_path,
            signature=self.verification.signature,
            integrity=self.result.integrity,
            resource_graph=self.result.resource_graph,
            raw_resource=raw_report.to_dict(),
            raw_comparison=raw_comparison.to_dict(),
            verification=self.verification.to_dict(),
        )
        before_rich = self.baseline.integrity.get("richHeaderSha256")
        after_rich = self.result.integrity.get("richHeaderSha256")
        rich_changed = before_rich != after_rich if before_rich or after_rich else False
        changed = [list(item) for item in diff.get("changed", [])]
        added = [list(item) for item in diff.get("added", [])]
        removed = [list(item) for item in diff.get("removed", [])]
        target_key = [self.target.get("type"), str(self.target.get("name")), self.target.get("language")]
        source_key = [self.target.get("type"), str(self.target.get("name")), self.target.get("sourceLanguage")]
        intended_keys = [target_key]
        if self.operation == "change-language" and self.target.get("sourceLanguage") is not None:
            intended_keys.append(source_key)
        matches_intended = lambda item: any(self._target_key_matches(item, key) for key in intended_keys)
        unintended = [item for item in changed + added + removed if not matches_intended(item)]
        targeted_changed = any(self._target_key_matches(item, target_key) for item in changed)
        targeted_added = any(self._target_key_matches(item, target_key) for item in added)
        targeted_removed = any(self._target_key_matches(item, target_key) for item in removed)
        source_removed = any(self._target_key_matches(item, source_key) for item in removed) if self.operation == "change-language" else False
        payload = {
            "schema": "resource_studio.forensic_evidence.v1",
            "operationId": self.operation_id,
            "operation": self.operation,
            "target": dict(self.target),
            "baseline": self.baseline.to_dict(),
            "result": self.result.to_dict(),
            "forensicDifference": {
                "targeted": {
                    "key": target_key,
                    "changed": targeted_changed,
                    "added": targeted_added,
                    "removed": targeted_removed,
                    "sourceRemoved": source_removed,
                    "sourceKey": source_key if self.operation == "change-language" else None,
                    "beforeSha256": self._resource_hash(self.baseline, source_key if self.operation == "change-language" else target_key),
                    "afterSha256": self._resource_hash(self.result, target_key),
                },
                "resourceTree": {
                    "intendedChanges": int(targeted_changed) + int(targeted_added) + int(targeted_removed),
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
                "platformLimited": self.verification.platform_limited,
                "pureLoader": pure_loader.to_dict(),
                "bytePreservation": preservation_map.to_dict(),
                "rawResource": {"report": raw_report.to_dict(), "comparison": raw_comparison.to_dict()},
                "richHeader": {"beforeSha256": before_rich, "afterSha256": after_rich, "changed": rich_changed},
                "passed": self.verification.passed and preservation_map.passed and raw_comparison.matches and not rich_changed,
                "verified": self.verification.verified and preservation_map.passed and raw_comparison.matches and not rich_changed,
            },
            "verification": self.verification.to_dict(),
            "evidenceSummary": evidence_summary,
            "chain": {
                "prevSha256": self.previous_evidence_sha256,
                "envFingerprint": environment_fingerprint(),
                "commandLine": list(sys.argv),
            },
        }
        payload["sha256"] = hashlib.sha256(canonical_json(payload)).hexdigest()
        return json.loads(json.dumps(payload, ensure_ascii=False))

    @staticmethod
    def _target_key_matches(item: list[Any], target_key: list[Any]) -> bool:
        return (
            len(item) == 3
            and item[0] == target_key[0]
            and item[1] == target_key[1]
            and (target_key[2] is None or int(item[2]) == int(target_key[2]))
        )

    @classmethod
    def _resource_hash(cls, baseline: ForensicBaseline, key: list[Any]) -> str | None:
        matches = [
            str(leaf.get("sha256"))
            for leaf in baseline.resource_graph.get("leaves", [])
            if cls._target_key_matches(
                [leaf.get("type"), str(leaf.get("name")), leaf.get("language")], key
            )
        ]
        return matches[0] if len(matches) == 1 else None


def verify_transformation(
    before_path: Path,
    candidate_path: Path,
    *,
    resource_type: str | int,
    resource_name: str | int,
    language: int | None,
    operation: str,
    operation_id: str,
    source_language: int | None = None,
    expected_data: bytes | None = None,
    committed: bool = False,
    baseline: ForensicBaseline | None = None,
    previous_evidence_sha256: str | None = None,
    before_context: VerificationContext | None = None,
    candidate_context: VerificationContext | None = None,
) -> ForensicEvidence:
    """Build evidence after independent reopen; Writer is not the evidence source."""

    before = baseline or ForensicBaseline.from_context(before_context) if before_context is not None else baseline or ForensicBaseline.from_path(before_path)
    result = ForensicBaseline.from_context(candidate_context) if candidate_context is not None else ForensicBaseline.from_path(candidate_path)
    verification = verify_candidate(
        before_path,
        candidate_path,
        resource_type=resource_type,
        resource_name=resource_name,
        language=language,
        operation=operation,
        source_language=source_language,
        expected_data=expected_data,
        committed=committed,
        before_context=before_context,
        candidate_context=candidate_context,
    )
    target_payload = {"type": str(resource_type), "name": str(resource_name), "language": language}
    if source_language is not None:
        target_payload["sourceLanguage"] = source_language
    return ForensicEvidence(
        operation_id=operation_id,
        operation=operation,
        target=target_payload,
        baseline=before,
        result=result,
        verification=verification,
        previous_evidence_sha256=previous_evidence_sha256,
    )
