"""
ARKA Knowledge Graph Store.

Implements:
- CTRL-GRAPH-INTEGRITY-001: Knowledge Graph Assertion Provenance Validation
- TEST-GRAPHIFY-POISONING-001: Knowledge Graph Provenance Verification Contract
- GATE-GRAPH-INTEGRITY-001: Knowledge Graph Provenance Validation Gate
- Invariant 13: Knowledge graphs represent observations and relationships, not authorization.
"""

from collections import defaultdict, deque
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from arka.evidence.store import EvidenceStore

from .exceptions import (
    GraphMissionIsolationError,
    NodeNotFoundError,
    UnverifiedAssertionError,
)
from .models import EdgeType, GraphEdge, GraphNode, GraphSubgraph, NodeType

logger = logging.getLogger("arka.graph.store")


class KnowledgeGraphStore:
    """
    Mission-isolated knowledge graph store enforcing cryptographic evidence binding.
    """

    def __init__(self, evidence_store: Optional[EvidenceStore] = None):
        self.evidence_store = evidence_store
        self._lock = threading.Lock()
        # mission_id -> {node_id -> GraphNode}
        self._nodes: Dict[str, Dict[str, GraphNode]] = defaultdict(dict)
        # mission_id -> {edge_id -> GraphEdge}
        self._edges: Dict[str, Dict[str, GraphEdge]] = defaultdict(dict)
        # mission_id -> {source_id -> List[edge_id]}
        self._out_edges: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        # mission_id -> {target_id -> List[edge_id]}
        self._in_edges: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))

    def add_node(
        self,
        mission_id: str,
        node_id: str,
        node_type: NodeType,
        label: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> GraphNode:
        """Adds or updates an observed entity in the mission knowledge graph."""
        if not mission_id or not node_id:
            raise ValueError("mission_id and node_id cannot be empty.")

        node = GraphNode(
            node_id=node_id,
            node_type=node_type,
            mission_id=mission_id,
            label=label,
            properties=properties or {},
            created_at_unix=time.time(),
        )

        with self._lock:
            self._nodes[mission_id][node_id] = node

        return node

    def add_edge(
        self,
        mission_id: str,
        source_id: str,
        edge_type: EdgeType,
        target_id: str,
        evidence_ref: str,
        evidence_hash: Optional[str] = None,
        confidence: float = 1.0,
        properties: Optional[Dict[str, Any]] = None,
    ) -> GraphEdge:
        """
        Creates a proven directed edge between two entities.
        
        Enforces TEST-GRAPHIFY-POISONING-001:
        - Rejects edges lacking valid cryptographic evidence references.
        - Verifies evidence existence and SHA-256 hash in EvidenceStore.
        """
        if not evidence_ref or not str(evidence_ref).strip():
            raise UnverifiedAssertionError(
                "Knowledge graph assertion rejected: edges cannot be formed without valid "
                "cryptographic evidence references (CTRL-GRAPH-INTEGRITY-001)."
            )

        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"Confidence score {confidence} must be between 0.0 and 1.0.")

        resolved_hash = evidence_hash

        # Cryptographic verification against EvidenceStore
        if self.evidence_store:
            record = self.evidence_store.get(evidence_ref, mission_id=mission_id)
            if not record:
                raise UnverifiedAssertionError(
                    f"Evidence reference '{evidence_ref}' does not exist in EvidenceStore "
                    f"or belongs to a different mission."
                )

            if evidence_hash and evidence_hash != record.content_hash:
                raise UnverifiedAssertionError(
                    f"Cryptographic hash mismatch for evidence '{evidence_ref}'! "
                    f"Expected {record.content_hash}, got {evidence_hash}."
                )

            resolved_hash = record.content_hash
        else:
            if not resolved_hash:
                raise UnverifiedAssertionError(
                    "Missing evidence_hash when standalone KnowledgeGraphStore is operated without EvidenceStore."
                )

        with self._lock:
            mission_nodes = self._nodes[mission_id]
            if source_id not in mission_nodes:
                raise NodeNotFoundError(
                    f"Source node '{source_id}' does not exist in mission '{mission_id}'."
                )
            if target_id not in mission_nodes:
                raise NodeNotFoundError(
                    f"Target node '{target_id}' does not exist in mission '{mission_id}'."
                )

            edge_id = f"edge-{uuid.uuid4().hex}"
            edge = GraphEdge(
                edge_id=edge_id,
                mission_id=mission_id,
                source_id=source_id,
                edge_type=edge_type,
                target_id=target_id,
                evidence_ref=evidence_ref,
                evidence_hash=resolved_hash,
                confidence=confidence,
                properties=properties or {},
                created_at_unix=time.time(),
            )

            self._edges[mission_id][edge_id] = edge
            self._out_edges[mission_id][source_id].append(edge_id)
            self._in_edges[mission_id][target_id].append(edge_id)

        logger.debug(
            f"Added proven edge ({source_id}) -[{edge_type.value}]-> ({target_id}) "
            f"evidenced by '{evidence_ref}'."
        )
        return edge

    def get_node(self, mission_id: str, node_id: str) -> Optional[GraphNode]:
        """Retrieves a node, enforcing mission boundary isolation."""
        with self._lock:
            return self._nodes.get(mission_id, {}).get(node_id)

    def get_neighbors(
        self,
        mission_id: str,
        node_id: str,
        edge_type: Optional[EdgeType] = None,
        direction: str = "both",
    ) -> List[Tuple[GraphEdge, GraphNode]]:
        """
        Retrieves neighboring nodes along with their connecting proven edges.
        direction: "out", "in", or "both".
        """
        results: List[Tuple[GraphEdge, GraphNode]] = []
        with self._lock:
            mission_nodes = self._nodes.get(mission_id, {})
            mission_edges = self._edges.get(mission_id, {})

            edge_ids: Set[str] = set()
            if direction in ("out", "both"):
                edge_ids.update(self._out_edges.get(mission_id, {}).get(node_id, []))
            if direction in ("in", "both"):
                edge_ids.update(self._in_edges.get(mission_id, {}).get(node_id, []))

            for eid in edge_ids:
                edge = mission_edges.get(eid)
                if not edge:
                    continue
                if edge_type and edge.edge_type != edge_type:
                    continue

                neighbor_id = edge.target_id if edge.source_id == node_id else edge.source_id
                neighbor_node = mission_nodes.get(neighbor_id)
                if neighbor_node:
                    results.append((edge, neighbor_node))

        return results

    def query_subgraph(
        self,
        mission_id: str,
        root_id: str,
        max_depth: int = 2,
    ) -> GraphSubgraph:
        """
        Extracts a bounded contextual subgraph starting from root_id using BFS.
        """
        visited_nodes: Dict[str, GraphNode] = {}
        collected_edges: Dict[str, GraphEdge] = {}

        with self._lock:
            root = self._nodes.get(mission_id, {}).get(root_id)
            if not root:
                return GraphSubgraph()

            queue: deque = deque([(root_id, 0)])
            visited_nodes[root_id] = root

            while queue:
                curr_id, depth = queue.popleft()
                if depth >= max_depth:
                    continue

                # Traverse outgoing edges
                for eid in self._out_edges.get(mission_id, {}).get(curr_id, []):
                    edge = self._edges[mission_id].get(eid)
                    if edge and edge.edge_id not in collected_edges:
                        collected_edges[edge.edge_id] = edge
                        target_node = self._nodes[mission_id].get(edge.target_id)
                        if target_node and edge.target_id not in visited_nodes:
                            visited_nodes[edge.target_id] = target_node
                            queue.append((edge.target_id, depth + 1))

        return GraphSubgraph(
            nodes=list(visited_nodes.values()),
            edges=list(collected_edges.values()),
        )

    def verify_provenance_integrity(self, mission_id: str) -> Tuple[bool, List[str]]:
        """
        Scans all edges in the mission graph and re-verifies their cryptographic evidence references.
        Returns (is_intact: bool, corrupted_or_unproven_edge_ids: List[str]).
        """
        corrupted: List[str] = []

        with self._lock:
            mission_edges = list(self._edges.get(mission_id, {}).values())

        for edge in mission_edges:
            if not edge.evidence_ref:
                corrupted.append(edge.edge_id)
                continue

            if self.evidence_store:
                record = self.evidence_store.get(edge.evidence_ref, mission_id=mission_id)
                if not record:
                    corrupted.append(edge.edge_id)
                elif record.content_hash != edge.evidence_hash:
                    corrupted.append(edge.edge_id)

        return (len(corrupted) == 0, corrupted)

    def export_graphify(self, mission_id: str) -> Dict[str, Any]:
        """
        Exports the mission knowledge graph in Graphify-compatible visualization schema.
        """
        with self._lock:
            nodes = [n.to_dict() for n in self._nodes.get(mission_id, {}).values()]
            edges = [e.to_dict() for e in self._edges.get(mission_id, {}).values()]

        return {
            "mission_id": mission_id,
            "exported_at_unix": time.time(),
            "nodes_count": len(nodes),
            "edges_count": len(edges),
            "nodes": nodes,
            "edges": edges,
        }
