from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Iterable, Mapping


ANNOTATION_SCHEMA = "resource_studio.evidence_annotation.v1"
SELECTION_SCHEMA = "resource_studio.evidence_selection.v1"


def create_annotation(
    *,
    target_kind: str,
    target_id: str,
    tag: str | None = None,
    note: str | None = None,
    actor: str = "resource-studio",
    artifact_sha256: str,
    graph_hash: str | None = None,
    created_utc: str | None = None,
) -> dict[str, Any]:
    target_kind = str(target_kind).strip()
    target_id = str(target_id).strip()
    actor = str(actor).strip()
    tag = str(tag).strip() if tag is not None else None
    note = str(note).strip() if note is not None else None
    if not target_kind or not target_id:
        raise ValueError("annotation target kind and id are required")
    if not tag and not note:
        raise ValueError("annotation requires a tag or note")
    if not actor:
        raise ValueError("annotation actor is required")
    if not str(artifact_sha256).strip():
        raise ValueError("annotation artifact sha256 is required")
    created_utc = created_utc or datetime.now(UTC).isoformat()
    payload: dict[str, Any] = {
        "schema": ANNOTATION_SCHEMA,
        "target": {"kind": target_kind, "id": target_id},
        "artifactSha256": str(artifact_sha256),
        "actor": actor,
        "createdUtc": str(created_utc),
    }
    if graph_hash:
        payload["graphHash"] = str(graph_hash)
    if tag:
        payload["tag"] = tag
    if note:
        payload["note"] = note
    payload["annotationId"] = "ANN-" + hashlib.sha256(_canonical(payload)).hexdigest()[:20].upper()
    return payload


def build_selection_manifest(
    case_payload: Mapping[str, Any],
    *,
    annotation_ids: Iterable[str] = (),
    tags: Iterable[str] = (),
) -> dict[str, Any]:
    annotations = [item for item in case_payload.get("annotations", []) if isinstance(item, Mapping)]
    by_id = {str(item.get("annotationId")): dict(item) for item in annotations}
    wanted_ids = {str(value).strip() for value in annotation_ids if str(value).strip()}
    wanted_tags = {str(value).strip() for value in tags if str(value).strip()}
    if not wanted_ids and not wanted_tags:
        raise ValueError("selection requires at least one annotation id or tag")
    selected = [
        item
        for item in annotations
        if str(item.get("annotationId")) in wanted_ids or (str(item.get("tag", "")) in wanted_tags)
    ]
    if wanted_ids - set(by_id):
        missing = ", ".join(sorted(wanted_ids - set(by_id)))
        raise ValueError(f"annotation was not found: {missing}")
    if not selected:
        raise ValueError("selection did not match any annotation")
    selected.sort(key=lambda item: str(item.get("annotationId")))
    targets = sorted(
        {json.dumps(item["target"], ensure_ascii=False, sort_keys=True, separators=(",", ":")) for item in selected}
    )
    payload: dict[str, Any] = {
        "schema": SELECTION_SCHEMA,
        "caseId": case_payload.get("caseId"),
        "artifact": dict(case_payload.get("artifact", {})),
        "evidenceGraphHash": case_payload.get("evidenceGraphHash"),
        "annotationIds": [str(item["annotationId"]) for item in selected],
        "annotations": selected,
        "targets": [json.loads(item) for item in targets],
    }
    payload["selectionHash"] = hashlib.sha256(_canonical(payload)).hexdigest()
    return payload


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


__all__ = ["ANNOTATION_SCHEMA", "SELECTION_SCHEMA", "build_selection_manifest", "create_annotation"]
