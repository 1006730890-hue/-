"""Auditable provenance DAG for MCP and multi-agent traces."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ProvenanceNode:
    node_id: str
    kind: str
    label: str
    trust: str = "trusted"
    classification: str = "public"
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceEdge:
    source: str
    target: str
    relation: str
    data: dict[str, Any] = field(default_factory=dict)


class ProvenanceGraph:
    """Build a cycle-checked graph suitable for UI DAG rendering and replay."""

    def __init__(self) -> None:
        self.nodes: dict[str, ProvenanceNode] = {}
        self.edges: list[ProvenanceEdge] = []

    def add_node(self, node_id: str, kind: str, label: str, *, trust: str = "trusted",
                 classification: str = "public", **data: Any) -> str:
        self.nodes[node_id] = ProvenanceNode(node_id, kind, label, trust, classification, data)
        return node_id

    def link(self, source: str, target: str, relation: str, **data: Any) -> None:
        if source not in self.nodes or target not in self.nodes:
            raise KeyError("both provenance edge endpoints must exist")
        if any(edge.source == source and edge.target == target and edge.relation == relation and edge.data == data for edge in self.edges):
            return
        self.edges.append(ProvenanceEdge(source, target, relation, data))

    def source_to_tool(self, source_id: str, tool_call_id: str, *, relation: str = "flows_to") -> None:
        self.link(source_id, tool_call_id, relation)

    def validate(self) -> dict[str, Any]:
        adjacency: dict[str, list[str]] = {node: [] for node in self.nodes}
        for edge in self.edges:
            adjacency[edge.source].append(edge.target)
        visiting: set[str] = set()
        visited: set[str] = set()
        cycles: list[str] = []

        def visit(node: str) -> None:
            if node in visiting:
                cycles.append(node)
                return
            if node in visited:
                return
            visiting.add(node)
            for child in adjacency[node]:
                visit(child)
            visiting.remove(node)
            visited.add(node)

        for node in adjacency:
            visit(node)
        return {"acyclic": not cycles, "cycles": cycles, "node_count": len(self.nodes), "edge_count": len(self.edges)}

    def to_dict(self) -> dict[str, Any]:
        return {"nodes": [asdict(node) for node in self.nodes.values()],
                "edges": [asdict(edge) for edge in self.edges], "validation": self.validate()}
