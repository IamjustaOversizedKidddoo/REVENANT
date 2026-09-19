"""
REVENANT — Attack Graph Data Schemas & Model
Defines nodes, directed edges, graph traversal, choke point analysis,
and Mermaid.js diagram synthesis.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from control_plane.schemas.models import Severity


class NodeType(str, Enum):
    ASSET = "ASSET"
    VULNERABILITY = "VULNERABILITY"
    CREDENTIAL = "CREDENTIAL"
    IDENTITY = "IDENTITY"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    OBJECTIVE = "OBJECTIVE"


class EdgeRelationship(str, Enum):
    EXPOSES = "EXPOSES"
    AFFECTS = "AFFECTS"
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    ESCALATES_TO = "ESCALATES_TO"
    LEADS_TO = "LEADS_TO"
    HOSTS = "HOSTS"
    MEMBER_OF = "MEMBER_OF"


class GraphNode(BaseModel):
    """A vertex in the security attack graph."""
    id: str
    label: str
    node_type: NodeType
    severity: Optional[Severity] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """A directed edge representing an exploit step, permission, or exposure."""
    source: str
    target: str
    relationship: EdgeRelationship
    label: Optional[str] = None
    weight: float = 1.0


class AttackGraph(BaseModel):
    """Directed multi-domain attack graph."""
    nodes: Dict[str, GraphNode] = Field(default_factory=dict)
    edges: List[GraphEdge] = Field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        """Add or update a node in the graph."""
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add a directed edge if not already present."""
        if edge.source not in self.nodes:
            # Auto-create source node if missing
            self.add_node(GraphNode(id=edge.source, label=edge.source, node_type=NodeType.ASSET))
        if edge.target not in self.nodes:
            # Auto-create target node if missing
            self.add_node(GraphNode(id=edge.target, label=edge.target, node_type=NodeType.ASSET))

        # Check duplicate
        for e in self.edges:
            if e.source == edge.source and e.target == edge.target and e.relationship == edge.relationship:
                return
        self.edges.append(edge)

    def get_adjacency(self) -> Dict[str, List[str]]:
        """Construct adjacency map for graph traversal."""
        adj: Dict[str, List[str]] = {nid: [] for nid in self.nodes}
        for edge in self.edges:
            if edge.source in adj:
                adj[edge.source].append(edge.target)
        return adj

    def find_attack_paths(self, max_depth: int = 6) -> List[List[str]]:
        """
        Find critical attack paths originating from entry points (assets/credentials)
        leading to high-impact objectives or critical compromise nodes.
        """
        adj = self.get_adjacency()
        paths: List[List[str]] = []

        # Entry points: nodes with in-degree == 0, or ASSET / CREDENTIAL nodes
        in_degrees: Dict[str, int] = {nid: 0 for nid in self.nodes}
        for edge in self.edges:
            if edge.target in in_degrees:
                in_degrees[edge.target] += 1

        entry_nodes = [
            nid for nid, in_deg in in_degrees.items()
            if in_deg == 0 or self.nodes[nid].node_type in [NodeType.CREDENTIAL, NodeType.VULNERABILITY]
        ]

        # Target / impact nodes: nodes marked OBJECTIVE or with CRITICAL severity or Domain Admin / Root
        target_nodes = {
            nid for nid, node in self.nodes.items()
            if node.node_type == NodeType.OBJECTIVE
            or node.severity == Severity.CRITICAL
            or any(kw in node.label.lower() for kw in ["admin", "root", "domain admin", "esc1", "s3", "privilege"])
        }

        def dfs(current: str, current_path: List[str], visited: Set[str]):
            if len(current_path) > max_depth:
                return
            if current in target_nodes and len(current_path) > 1:
                paths.append(list(current_path))

            for neighbor in adj.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    current_path.append(neighbor)
                    dfs(neighbor, current_path, visited)
                    current_path.pop()
                    visited.remove(neighbor)

        for entry in entry_nodes:
            dfs(entry, [entry], {entry})

        # Sort paths by length descending and limit
        paths.sort(key=lambda p: len(p), reverse=True)
        return paths[:15]

    def find_choke_points(self) -> List[Dict[str, Any]]:
        """
        Identify critical security choke points (nodes with highest intermediate traversal
        or betweenness centrality across attack paths). Remediating these breaks multiple chains.
        """
        paths = self.find_attack_paths()
        node_frequency: Dict[str, int] = {}

        for path in paths:
            # Exclude endpoints, count intermediate bottleneck nodes
            for nid in path:
                node_frequency[nid] = node_frequency.get(nid, 0) + 1

        choke_points = []
        for nid, count in sorted(node_frequency.items(), key=lambda x: x[1], reverse=True):
            node = self.nodes.get(nid)
            if not node:
                continue
            choke_points.append({
                "node_id": node.id,
                "label": node.label,
                "node_type": node.node_type.value,
                "severity": node.severity.value if node.severity else "INFO",
                "attack_paths_affected": count,
                "remediation_priority": "CRITICAL" if count >= 3 else ("HIGH" if count >= 2 else "MEDIUM"),
            })

        return choke_points[:10]

    def to_mermaid(self, direction: str = "LR") -> str:
        """Generate clean, GitHub-flavored Mermaid.js flowchart syntax."""
        lines = [f"```mermaid", f"flowchart {direction}"]

        # Style classes
        lines.append("    classDef asset fill:#1f2937,stroke:#4b5563,stroke-width:1px,color:#f3f4f6;")
        lines.append("    classDef vulnCrit fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fef2f2;")
        lines.append("    classDef vulnHigh fill:#831843,stroke:#ec4899,stroke-width:2px,color:#fdf2f8;")
        lines.append("    classDef cred fill:#78350f,stroke:#f59e0b,stroke-width:2px,color:#fffbeb;")
        lines.append("    classDef identity fill:#1e1b4b,stroke:#6366f1,stroke-width:2px,color:#eef2ff;")
        lines.append("    classDef cloud fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#ecfdf5;")

        node_name_map: Dict[str, str] = {}
        for idx, (nid, node) in enumerate(self.nodes.items()):
            safe_var = f"N{idx}"
            node_name_map[nid] = safe_var

            # Sanitize label for Mermaid
            clean_label = node.label.replace('"', "'").replace("[", "(").replace("]", ")")
            if len(clean_label) > 45:
                clean_label = clean_label[:42] + "..."

            # Shape by node type
            if node.node_type == NodeType.CREDENTIAL:
                lines.append(f'    {safe_var}[/"🔑 {clean_label}"/]')
            elif node.node_type == NodeType.VULNERABILITY:
                lines.append(f'    {safe_var}["⚡ {clean_label}"]')
            elif node.node_type == NodeType.IDENTITY:
                lines.append(f'    {safe_var}(["👤 {clean_label}"])')
            elif node.node_type == NodeType.CLOUD_RESOURCE:
                lines.append(f'    {safe_var}[("☁️ {clean_label}")]')
            else:
                lines.append(f'    {safe_var}["🖥️ {clean_label}"]')

            # Class assignment
            if node.node_type == NodeType.CREDENTIAL:
                lines.append(f"    class {safe_var} cred;")
            elif node.node_type == NodeType.IDENTITY:
                lines.append(f"    class {safe_var} identity;")
            elif node.node_type == NodeType.CLOUD_RESOURCE:
                lines.append(f"    class {safe_var} cloud;")
            elif node.severity == Severity.CRITICAL:
                lines.append(f"    class {safe_var} vulnCrit;")
            elif node.severity == Severity.HIGH:
                lines.append(f"    class {safe_var} vulnHigh;")
            else:
                lines.append(f"    class {safe_var} asset;")

        for edge in self.edges:
            s_var = node_name_map.get(edge.source)
            t_var = node_name_map.get(edge.target)
            if s_var and t_var:
                rel_label = f"|{edge.relationship.value}|" if edge.relationship else ""
                lines.append(f"    {s_var} -->{rel_label} {t_var}")

        lines.append("```")
        return "\n".join(lines)
