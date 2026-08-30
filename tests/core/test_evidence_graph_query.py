import hashlib
import json
import subprocess
import sys
from pathlib import Path

from core.evidence_graph import EvidenceGraph
from core.evidence_query import EvidenceQueryError, query_summary, records_from_summary
from core.security_analysis import analyze_security
from core.security_providers import ExternalScanResult

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.dll"


def main() -> None:
    report = analyze_security(FIXTURE)
    summary = report["evidence"]
    graph = EvidenceGraph.from_summary(summary)
    graph_payload = graph.to_dict()
    assert graph_payload["schema"] == "resource_studio.evidence_graph.v1"
    assert graph.graph_hash() == EvidenceGraph.from_summary(summary).graph_hash()
    assert any(edge["relation"] == "corroborates" for edge in graph_payload["edges"])
    assert any(node["kind"] == "observation" for node in graph_payload["nodes"])

    icon_results = query_summary(summary, 'resource.type == "MANIFEST"')
    assert all(item.get("resource.type") == "MANIFEST" for item in icon_results)
    size_results = query_summary(summary, "resource.size >= 0")
    assert size_results
    confidence_results = query_summary(summary, "evidence.confidence >= 0.8")
    assert confidence_results
    combined = query_summary(summary, 'resource.type == "MANIFEST" and resource.size >= 0')
    assert combined
    parenthesized = query_summary(summary, '(resource.type == "MANIFEST" AND resource.size >= 0)')
    assert parenthesized
    uppercase = query_summary(summary, 'resource.type == "MANIFEST" OR resource.size < 0')
    assert uppercase
    contains = query_summary(summary, 'resource.type CONTAINS "manif"')
    assert contains

    external = ExternalScanResult(
        provider="test-provider",
        status="DETECTED",
        target_sha256=hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
        tool_version="test-1",
        ruleset={"name": "test"},
        exit_code=1,
        matches=({"rule": "demo"},),
        captured_at_utc="2026-01-01T00:00:00+00:00",
        limitations=(),
    )
    external_summary = analyze_security(FIXTURE, (external,))["evidence"]
    external_records = [item for item in records_from_summary(external_summary) if item.get("scope") == "externalScan"]
    assert external_records and external_records[0]["externalScan.status"] == "DETECTED"
    assert query_summary(external_summary, 'externalScan.status == "DETECTED"')
    assert query_summary(external_summary, 'externalScan.provider CONTAINS "test"')

    try:
        query_summary(summary, "os.system == 1")
    except EvidenceQueryError:
        pass
    else:
        raise AssertionError("unsupported namespace must be rejected")

    env = {**__import__("os").environ, "PYTHONPATH": str(ROOT)}
    graph_cli = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "evidence-graph", str(FIXTURE), "--json"], capture_output=True, text=True, env=env, check=False)
    assert graph_cli.returncode == 0, graph_cli.stderr
    assert json.loads(graph_cli.stdout)["schema"] == "resource_studio.evidence_graph.v1"
    query_cli = subprocess.run([sys.executable, str(ROOT / "resource_studio_cli.py"), "evidence-query", str(FIXTURE), 'resource.type == "MANIFEST"', "--json"], capture_output=True, text=True, env=env, check=False)
    assert query_cli.returncode == 0, query_cli.stderr
    assert json.loads(query_cli.stdout)["query"] == 'resource.type == "MANIFEST"'
    print("evidence-graph-query-tests: passed")


if __name__ == "__main__":
    main()
