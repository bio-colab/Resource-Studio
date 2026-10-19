from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.behavioral_graph import build_resource_behavior_graph

TARGETS = [
    Path("C:/Program Files/7-Zip/7zFM.exe"),
    Path("C:/Windows/System32/charmap.exe"),
]


def verify_behavioral_graph(target: Path) -> dict:
    if not target.is_file():
        return {"target": str(target), "status": "SKIPPED_NOT_FOUND"}

    graph = build_resource_behavior_graph(target)
    issues = []

    if len(graph.nodes) == 0:
        issues.append("Graph has 0 nodes")

    node_ids = {n.id for n in graph.nodes}
    for edge in graph.edges:
        if edge.source not in node_ids:
            issues.append(f"Edge source {edge.source} not in graph nodes")
        if edge.target not in node_ids:
            issues.append(f"Edge target {edge.target} not in graph nodes")
        if edge.confidence <= 0:
            issues.append(f"Edge {edge.edge_type} has non-positive confidence")

    if not graph.mermaid_diagram.startswith("flowchart LR"):
        issues.append("Mermaid diagram header invalid")

    return {
        "target": target.name,
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "traces": len(graph.traces),
        "nodeTypes": list({n.node_type for n in graph.nodes}),
        "edgeTypes": list({e.edge_type for e in graph.edges}),
        "issues": issues,
        "status": "PASS" if not issues else "FAIL",
    }


def main() -> int:
    all_passed = True
    print("=== Phase 4: Resource-to-Behavior Graph Conformance Test ===")
    for target in TARGETS:
        if not target.is_file():
            continue
        res = verify_behavioral_graph(target)
        print(f"\nTarget: {res['target']}")
        print(f"  Nodes:      {res['nodes']} ({res['nodeTypes']})")
        print(f"  Edges:      {res['edges']} ({res['edgeTypes']})")
        print(f"  Traces:     {res['traces']}")
        if res["issues"]:
            print(f"  Issues ({len(res['issues'])}):")
            for issue in res["issues"]:
                print(f"    - {issue}")
            all_passed = False
        else:
            print("  Status: 100% GRAPH TOPOLOGY & EVIDENCE CONCORDANCE")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
