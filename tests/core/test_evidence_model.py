import hashlib
from pathlib import Path

from core.evidence_model import build_evidence_summary, evidence_summary_hash
from core.pe_inspector import PEInspector
from core.pe_integrity import inspect_integrity
from core.raw_resource_parser import compare_with_graph, parse_raw_resources
from core.signature import inspect_signature
from core.verification import ResourceGraph


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    original_hash = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    inspector = PEInspector.inspect(FIXTURE).to_dict()
    signature = inspect_signature(FIXTURE).to_dict()
    integrity = inspect_integrity(FIXTURE).to_dict()
    graph = ResourceGraph.from_path(FIXTURE).to_dict()
    raw = parse_raw_resources(FIXTURE)
    raw_payload = raw.to_dict()
    comparison = compare_with_graph(raw, graph).to_dict()
    summary = build_evidence_summary(
        FIXTURE,
        inspector=inspector,
        signature=signature,
        integrity=integrity,
        resource_graph=graph,
        raw_resource=raw_payload,
        raw_comparison=comparison,
    )
    assert summary["schema"] == "resource_studio.evidence_summary.v1"
    assert summary["artifact"]["sha256"] == original_hash
    assert summary["corroboration"]["resourceGraphVsRaw"] == "CORROBORATED"
    assert summary["statistics"]["resources"] == graph["leafCount"]
    assert summary["observations"]
    assert all(item["source"] and item["parser"] and item["confidence"] for item in summary["observations"])
    assert all(item["id"].startswith("F-") for item in summary["findings"])
    summary_copy = dict(summary)
    summary_copy["capturedAtUtc"] = "2099-01-01T00:00:00+00:00"
    summary_copy["artifact"] = dict(summary["artifact"], path="/different/machine/sample.dll")
    assert evidence_summary_hash(summary) == evidence_summary_hash(summary_copy)
    assert len(evidence_summary_hash(summary)) == 64
    print("evidence-model-tests: passed")


if __name__ == "__main__":
    main()
