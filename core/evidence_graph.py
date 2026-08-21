from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


_SCHEMA = "resource_studio.evidence_graph.v1"
_RELATIONS = {"corroborates", "contradicts", "derives-from", "supports", "references"}


@dataclass(frozen=True)
class EvidenceNode:
    id: str
    kind: str
    value: Any
    source_ref: str | None = None
    confidence: str | float | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"id": self.id, "kind": self.kind, "value": self.value}
        if self.source_ref is not None:
            payload["sourceRef"] = self.source_ref
        if self.confidence is not None:
            payload["confidence"] = self.confidence
        return payload


@dataclass(frozen=True)
class EvidenceEdge:
    source: str
    relation: str
    target: str
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {"source": self.source, "relation": self.relation, "target": self.target}
        if self.detail is not None:
            payload["detail"] = self.detail
        return payload


class EvidenceGraph:
    """Deterministic, read-only-friendly graph built from normalized evidence."""

    def __init__(self, nodes: Iterable[EvidenceNode] = (), edges: Iterable[EvidenceEdge] = ()) -> None:
        self._nodes: dict[str, EvidenceNode] = {node.id: node for node in nodes}
        self._edges: set[EvidenceEdge] = set()
        for edge in edges:
            self.add_edge(edge.source, edge.relation, edge.target, edge.detail)

    @classmethod
    def from_summary(cls, summary: Mapping[str, Any]) -> "EvidenceGraph":
        graph = cls()
        artifact = summary.get("artifact", {})
        artifact_sha = str(artifact.get("sha256", ""))
        graph.add_node("artifact", "artifact", dict(artifact), source_ref="file-bytes", confidence="HIGH")
        observations = [item for item in summary.get("observations", []) if isinstance(item, Mapping)]
        for item in observations:
            node_id = str(item.get("id", ""))
            if not node_id:
                continue
            graph.add_node(node_id, "observation", dict(item), source_ref=str(item.get("source", "")), confidence=item.get("confidence"))
            graph.add_edge(node_id, "derives-from", "artifact", "observation belongs to the analyzed artifact")
        findings = [item for item in summary.get("findings", []) if isinstance(item, Mapping)]
        for item in findings:
            node_id = str(item.get("id", ""))
            if not node_id:
                continue
            graph.add_node(node_id, "finding", dict(item), confidence=item.get("confidence"))
            for observation_id in item.get("observationIds", []):
                if str(observation_id) in graph._nodes:
                    graph.add_edge(node_id, "derives-from", str(observation_id))
        graph._add_corroboration_edges(observations)
        if artifact_sha:
            graph.add_node(f"artifact:{artifact_sha}", "artifact-hash", artifact_sha, source_ref="file-bytes", confidence="HIGH")
            graph.add_edge("artifact", "supports", f"artifact:{artifact_sha}")
        return graph

    def add_node(self, node_id: str, kind: str, value: Any, *, source_ref: str | None = None, confidence: str | float | None = None) -> str:
        node_id = str(node_id).strip()
        kind = str(kind).strip()
        if not node_id or not kind:
            raise ValueError("evidence node id and kind are required")
        node = EvidenceNode(node_id, kind, value, source_ref, confidence)
        existing = self._nodes.get(node_id)
        if existing is not None and existing != node:
            raise ValueError(f"evidence node already exists with different value: {node_id}")
        self._nodes[node_id] = node
        return node_id

    def add_edge(self, source: str, relation: str, target: str, detail: str | None = None) -> None:
        source = str(source).strip()
        target = str(target).strip()
        relation = str(relation).strip()
        if source == target:
            raise ValueError("self-referencing evidence edges are not allowed")
        if relation not in _RELATIONS:
            raise ValueError(f"unsupported evidence relation: {relation}")
        if source not in self._nodes or target not in self._nodes:
            raise KeyError(f"edge endpoint is not in graph: {source} -> {target}")
        self._edges.add(EvidenceEdge(source, relation, target, detail))

    def node(self, node_id: str) -> EvidenceNode | None:
        return self._nodes.get(node_id)

    def nodes(self) -> tuple[EvidenceNode, ...]:
        return tuple(self._nodes[key] for key in sorted(self._nodes))

    def edges(self) -> tuple[EvidenceEdge, ...]:
        return tuple(sorted(self._edges, key=lambda edge: (edge.source, edge.relation, edge.target, edge.detail or "")))

    def neighbors(self, node_id: str, relation: str | None = None) -> tuple[EvidenceEdge, ...]:
        return tuple(edge for edge in self.edges() if edge.source == node_id and (relation is None or edge.relation == relation))

    def to_dict(self) -> dict[str, Any]:
        return {"schema": _SCHEMA, "nodes": [node.to_dict() for node in self.nodes()], "edges": [edge.to_dict() for edge in self.edges()]}

    def graph_hash(self) -> str:
        canonical = json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _add_corroboration_edges(self, observations: list[Mapping[str, Any]]) -> None:
        by_key: dict[tuple[str, str, str], list[str]] = {}
        for item in observations:
            value = item.get("value")
            if item.get("property") != "sha256" or value is None:
                continue
            key = (str(item.get("subject")), str(value), str(item.get("source")))
            by_key.setdefault(key, []).append(str(item.get("id")))
        for subject in sorted({key[0] for key in by_key}):
            groups = [(key, ids) for key, ids in by_key.items() if key[0] == subject]
            for left_key, left_ids in groups:
                for right_key, right_ids in groups:
                    if left_key >= right_key or left_key[1] != right_key[1] or left_key[2] == right_key[2]:
                        continue
                    for left_id in left_ids:
                        for right_id in right_ids:
                            self.add_edge(left_id, "corroborates", right_id, f"same sha256 for {subject}")


__all__ = ["EvidenceEdge", "EvidenceGraph", "EvidenceNode"]
