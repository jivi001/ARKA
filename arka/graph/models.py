"""
ARKA Knowledge Graph Domain Models.

Adheres to:
- ARKA TRD v2.2 Section 26 (Knowledge Graph Schema)
- ARKA PRD v2.2 Section 18 & 21 (Observation Graph & Provenance)
- AGENTS.md (Invariant 13: Observations != Authorization)
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import time
from typing import Any, Dict, List, Optional


class NodeType(str, Enum):
    """Categorization of graph nodes representing assessed entities and findings."""

    ASSET = "Asset"
    HOST = "Host"
    IP = "IP"
    DOMAIN = "Domain"
    PORT = "Port"
    SERVICE = "Service"
    TECHNOLOGY = "Technology"
    ENDPOINT = "Endpoint"
    CREDENTIAL = "Credential"
    VULNERABILITY = "Vulnerability"
    EVIDENCE = "Evidence"
    FINDING = "Finding"
    TASK = "Task"
    AGENT = "Agent"


class EdgeType(str, Enum):
    """Categorization of directed relationships between graph entities."""

    RESOLVES_TO = "RESOLVES_TO"
    RUNS = "RUNS"
    EXPOSES = "EXPOSES"
    USES = "USES"
    AFFECTED_BY = "AFFECTED_BY"
    SUPPORTED_BY = "SUPPORTED_BY"
    DISCOVERED_BY = "DISCOVERED_BY"
    EVIDENCED_BY = "EVIDENCED_BY"
    DERIVED_FROM = "DERIVED_FROM"


@dataclass
class GraphNode:
    """An observed security entity in the mission knowledge graph."""

    node_id: str
    node_type: NodeType
    mission_id: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at_unix: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "mission_id": self.mission_id,
            "label": self.label,
            "properties": self.properties,
            "created_at_unix": self.created_at_unix,
        }


@dataclass
class GraphEdge:
    """
    A proven directed relationship between two entities.
    
    Mandatory Security Property:
    - Must be bound to a verified cryptographic evidence artifact (`evidence_ref` + `evidence_hash`).
    - Unproven or fabricated edges are rejected (CTRL-GRAPH-INTEGRITY-001).
    """

    edge_id: str
    mission_id: str
    source_id: str
    edge_type: EdgeType
    target_id: str
    evidence_ref: str
    evidence_hash: str
    confidence: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at_unix: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "mission_id": self.mission_id,
            "source_id": self.source_id,
            "edge_type": self.edge_type.value,
            "target_id": self.target_id,
            "evidence_ref": self.evidence_ref,
            "evidence_hash": self.evidence_hash,
            "confidence": self.confidence,
            "properties": self.properties,
            "created_at_unix": self.created_at_unix,
        }


@dataclass
class GraphSubgraph:
    """A bounded subgraph slice for contextual reasoning."""

    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }
