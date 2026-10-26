"""
Unit Tests for ARKA Knowledge Graph (Module J).

Validates:
- CTRL-GRAPH-INTEGRITY-001: Knowledge Graph Assertion Provenance Validation
- TEST-GRAPHIFY-POISONING-001: Knowledge Graph Provenance Verification Contract
- GATE-GRAPH-INTEGRITY-001: Knowledge Graph Provenance Validation Gate
- Neutralization of THREAT-GRAPHIFY-POISONING
- Invariant 13: Knowledge graphs represent observations and relationships, not authorization.
"""

import unittest

from arka.evidence import (
    EvidencePipeline,
    EvidenceProvenance,
    EvidenceStore,
    EvidenceType,
)
from arka.graph import (
    EdgeType,
    KnowledgeGraphStore,
    NodeNotFoundError,
    NodeType,
    UnverifiedAssertionError,
)


class TestKnowledgeGraph(unittest.TestCase):
    def setUp(self):
        self.evidence_store = EvidenceStore()
        self.pipeline = EvidencePipeline()
        self.graph = KnowledgeGraphStore(evidence_store=self.evidence_store)

        # Ingest genuine evidence in EvidenceStore
        self.prov_alpha = EvidenceProvenance(
            mission_id="mission-alpha",
            task_id="task-001",
            collector="nmap",
        )
        self.evidence_alpha = self.pipeline.quarantine_and_parse(
            raw_bytes=b"Port 443 open on target.example",
            provenance=self.prov_alpha,
            evidence_type=EvidenceType.PORT_SCAN,
        )
        self.evidence_store.put(self.evidence_alpha)

        # Ingest evidence for mission-beta
        self.prov_beta = EvidenceProvenance(
            mission_id="mission-beta",
            task_id="task-002",
            collector="nmap",
        )
        self.evidence_beta = self.pipeline.quarantine_and_parse(
            raw_bytes=b"Port 22 open on beta.example",
            provenance=self.prov_beta,
            evidence_type=EvidenceType.PORT_SCAN,
        )
        self.evidence_store.put(self.evidence_beta)

    def test_add_nodes_and_proven_edge_success(self):
        """Valid nodes and edge bound to authentic evidence succeed."""
        h_node = self.graph.add_node(
            mission_id="mission-alpha",
            node_id="host:target.example",
            node_type=NodeType.HOST,
            label="target.example",
        )
        p_node = self.graph.add_node(
            mission_id="mission-alpha",
            node_id="port:443",
            node_type=NodeType.PORT,
            label="TCP/443",
        )

        edge = self.graph.add_edge(
            mission_id="mission-alpha",
            source_id="host:target.example",
            edge_type=EdgeType.EXPOSES,
            target_id="port:443",
            evidence_ref=self.evidence_alpha.evidence_id,
            evidence_hash=self.evidence_alpha.content_hash,
        )

        self.assertEqual(edge.source_id, "host:target.example")
        self.assertEqual(edge.target_id, "port:443")
        self.assertEqual(edge.evidence_ref, self.evidence_alpha.evidence_id)
        self.assertEqual(edge.evidence_hash, self.evidence_alpha.content_hash)

    def test_graphify_poisoning_rejected_empty_evidence(self):
        """
        TEST-GRAPHIFY-POISONING-001:
        Adversary attempts to add an edge without providing an evidence reference.
        Must be rejected with UnverifiedAssertionError.
        """
        self.graph.add_node("mission-alpha", "host:target.example", NodeType.HOST, "target.example")
        self.graph.add_node("mission-alpha", "port:80", NodeType.PORT, "TCP/80")

        with self.assertRaises(UnverifiedAssertionError):
            self.graph.add_edge(
                mission_id="mission-alpha",
                source_id="host:target.example",
                edge_type=EdgeType.EXPOSES,
                target_id="port:80",
                evidence_ref="",  # Empty
            )

    def test_graphify_poisoning_rejected_fake_evidence(self):
        """
        TEST-GRAPHIFY-POISONING-001:
        Adversary attempts to link nodes using nonexistent fabricated evidence ID.
        Must be rejected with UnverifiedAssertionError.
        """
        self.graph.add_node("mission-alpha", "host:target.example", NodeType.HOST, "target.example")
        self.graph.add_node("mission-alpha", "port:80", NodeType.PORT, "TCP/80")

        with self.assertRaises(UnverifiedAssertionError):
            self.graph.add_edge(
                mission_id="mission-alpha",
                source_id="host:target.example",
                edge_type=EdgeType.EXPOSES,
                target_id="port:80",
                evidence_ref="evi-fabricated-nonexistent",
            )

    def test_graphify_poisoning_rejected_hash_mismatch(self):
        """
        TEST-GRAPHIFY-POISONING-001:
        Adversary attempts to pass valid evidence_ref but forged/mismatched content hash.
        Must be rejected with UnverifiedAssertionError.
        """
        self.graph.add_node("mission-alpha", "host:target.example", NodeType.HOST, "target.example")
        self.graph.add_node("mission-alpha", "port:443", NodeType.PORT, "TCP/443")

        with self.assertRaises(UnverifiedAssertionError):
            self.graph.add_edge(
                mission_id="mission-alpha",
                source_id="host:target.example",
                edge_type=EdgeType.EXPOSES,
                target_id="port:443",
                evidence_ref=self.evidence_alpha.evidence_id,
                evidence_hash="0000000000000000000000000000000000000000000000000000000000000000",
            )

    def test_graphify_poisoning_rejected_cross_mission_evidence(self):
        """
        Adversary attempts to form an edge in mission-alpha using valid evidence from mission-beta.
        EvidenceStore mission isolation must block this with UnverifiedAssertionError.
        """
        self.graph.add_node("mission-alpha", "host:target.example", NodeType.HOST, "target.example")
        self.graph.add_node("mission-alpha", "port:22", NodeType.PORT, "TCP/22")

        with self.assertRaises(UnverifiedAssertionError):
            self.graph.add_edge(
                mission_id="mission-alpha",
                source_id="host:target.example",
                edge_type=EdgeType.EXPOSES,
                target_id="port:22",
                evidence_ref=self.evidence_beta.evidence_id,  # Belongs to mission-beta
            )

    def test_node_not_found_rejected(self):
        """Linking nonexistent nodes is rejected with NodeNotFoundError."""
        with self.assertRaises(NodeNotFoundError):
            self.graph.add_edge(
                mission_id="mission-alpha",
                source_id="host:nonexistent",
                edge_type=EdgeType.EXPOSES,
                target_id="port:443",
                evidence_ref=self.evidence_alpha.evidence_id,
            )

    def test_query_subgraph_and_neighbors(self):
        """Querying neighbors and bounded subgraph slices works correctly."""
        self.graph.add_node("mission-alpha", "host:A", NodeType.HOST, "Host A")
        self.graph.add_node("mission-alpha", "ip:10.0.0.1", NodeType.IP, "IP 10.0.0.1")
        self.graph.add_node("mission-alpha", "port:443", NodeType.PORT, "TCP/443")

        self.graph.add_edge(
            "mission-alpha", "host:A", EdgeType.RESOLVES_TO, "ip:10.0.0.1",
            evidence_ref=self.evidence_alpha.evidence_id,
        )
        self.graph.add_edge(
            "mission-alpha", "ip:10.0.0.1", EdgeType.EXPOSES, "port:443",
            evidence_ref=self.evidence_alpha.evidence_id,
        )

        # Neighbors
        neighbors = self.graph.get_neighbors("mission-alpha", "host:A")
        self.assertEqual(len(neighbors), 1)
        self.assertEqual(neighbors[0][1].node_id, "ip:10.0.0.1")

        # Subgraph
        subgraph = self.graph.query_subgraph("mission-alpha", "host:A", max_depth=2)
        self.assertEqual(len(subgraph.nodes), 3)
        self.assertEqual(len(subgraph.edges), 2)

    def test_provenance_integrity_scan(self):
        """verify_provenance_integrity detects valid graphs and flags tampered references."""
        self.graph.add_node("mission-alpha", "host:A", NodeType.HOST, "Host A")
        self.graph.add_node("mission-alpha", "port:443", NodeType.PORT, "TCP/443")

        edge = self.graph.add_edge(
            "mission-alpha", "host:A", EdgeType.EXPOSES, "port:443",
            evidence_ref=self.evidence_alpha.evidence_id,
        )

        is_intact, corrupted = self.graph.verify_provenance_integrity("mission-alpha")
        self.assertTrue(is_intact)
        self.assertEqual(len(corrupted), 0)

        # Manually tamper with edge evidence hash in memory
        edge.evidence_hash = "corrupted_hash"
        is_intact2, corrupted2 = self.graph.verify_provenance_integrity("mission-alpha")
        self.assertFalse(is_intact2)
        self.assertIn(edge.edge_id, corrupted2)

    def test_export_graphify_schema(self):
        """export_graphify outputs structured nodes, edges, and counts."""
        self.graph.add_node("mission-alpha", "host:A", NodeType.HOST, "Host A")
        self.graph.add_node("mission-alpha", "port:443", NodeType.PORT, "TCP/443")
        self.graph.add_edge(
            "mission-alpha", "host:A", EdgeType.EXPOSES, "port:443",
            evidence_ref=self.evidence_alpha.evidence_id,
        )

        exported = self.graph.export_graphify("mission-alpha")
        self.assertEqual(exported["mission_id"], "mission-alpha")
        self.assertEqual(exported["nodes_count"], 2)
        self.assertEqual(exported["edges_count"], 1)


if __name__ == "__main__":
    unittest.main()
