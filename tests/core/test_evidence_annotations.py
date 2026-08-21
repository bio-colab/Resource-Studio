from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from core.case_lifecycle import CaseFile
from core.evidence_annotations import build_selection_manifest


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = next((ROOT / "tests" / "fixtures").glob("*.dll"))


def test_annotations_bind_to_artifact_and_export_selection() -> None:
    with tempfile.TemporaryDirectory() as directory:
        case_path = Path(directory) / "case.json"
        selection_path = Path(directory) / "selection.json"
        case = CaseFile.create(FIXTURE)
        original_sha = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
        annotation = case.add_annotation(
            target_kind="resource",
            target_id="MANIFEST:1:1033",
            tag="important",
            note="manifest is relevant to the case",
            actor="tester",
        )
        case.save(case_path)
        output = case.export_selection(selection_path, tags=("important",))
        manifest = json.loads(output.read_text(encoding="utf-8"))
        assert manifest["schema"] == "resource_studio.evidence_selection.v1"
        assert manifest["artifact"]["sha256"] == original_sha
        assert manifest["annotationIds"] == [annotation["annotationId"]]
        assert manifest["targets"] == [{"id": "MANIFEST:1:1033", "kind": "resource"}]
        assert manifest["selectionHash"]
        assert case.payload["artifact"]["sha256"] == original_sha
        assert case.verify_audit()["valid"]
        assert any(event["type"] == "ANNOTATION_ADDED" for event in case.payload["audit"]["events"])


def test_selection_rejects_missing_annotation() -> None:
    case = CaseFile.create(FIXTURE)
    try:
        build_selection_manifest(case.payload, annotation_ids=("ANN-MISSING",))
    except ValueError as exc:
        assert "annotation was not found" in str(exc)
    else:
        raise AssertionError("missing annotation should be rejected")


if __name__ == "__main__":
    test_annotations_bind_to_artifact_and_export_selection()
    test_selection_rejects_missing_annotation()
    print("evidence-annotation-tests: passed")
