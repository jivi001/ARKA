"""
ARKA Knowledge Graph Exceptions.

Enforces:
- Invariant 13: Knowledge graphs represent observations and relationships, not authorization.
- Invariant INV-007 / INV-003: Unverified assertions cannot influence agent planning or kernel policy.
- Neutralization of THREAT-GRAPHIFY-POISONING (CTRL-GRAPH-INTEGRITY-001 / GATE-GRAPH-INTEGRITY-001).
"""


class GraphError(Exception):
    """Base exception for all knowledge graph operations."""

    pass


class UnverifiedAssertionError(GraphError):
    """
    Raised when an edge or relationship assertion lacks a valid cryptographic evidence reference
    or when the referenced evidence hash does not match (TEST-GRAPHIFY-POISONING-001).
    """

    pass


class GraphMissionIsolationError(GraphError):
    """Raised on cross-mission node or edge creation or query attempts."""

    pass


class NodeNotFoundError(GraphError):
    """Raised when a referenced node ID is not found in the mission graph."""

    pass


class GraphAuthorizationBypassError(GraphError):
    """
    Raised when a component attempts to treat a graph observation as authorization authority.
    DISCOVERED != AUTHORIZED. Only the Rust Security Kernel can authorize actions.
    """

    pass
