"""
ARKA Agent-to-Agent (A2A) Structured Wire Models.

Adheres to:
- ARKA TRD v2.2 Section 14 (A2A Protocol)
- ARKA PRD v2.2 Section 9 (Agent-to-Agent Communication)
- AGENTS.md (Invariants 1-5)
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
import time
from typing import Any, Dict, List, Optional
import uuid


class A2aMessageType(str, Enum):
    """Authoritative A2A message types."""

    TASK_DELEGATION = "TASK_DELEGATION"
    TASK_RESULT = "TASK_RESULT"
    FINDING = "FINDING"
    STATUS_QUERY = "STATUS_QUERY"
    STATUS_UPDATE = "STATUS_UPDATE"
    ERROR = "ERROR"


@dataclass
class Finding:
    """Structured assessment finding exchanged between agents."""

    asset: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    vulnerability_id: Optional[str] = None
    severity: Optional[str] = None
    confidence: float = 0.0
    evidence_refs: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TaskDelegation:
    """Sub-task delegated from coordinator (e.g. Orchestrator) to specialized agent."""

    task_id: str
    task_name: str
    capability: str
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: str = "NORMAL"
    timeout_seconds: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TaskResult:
    """Result of a delegated sub-task returned to coordinator."""

    task_id: str
    status: str  # "COMPLETED", "FAILED", "BLOCKED"
    summary: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class A2aMessageEnvelope:
    """
    Authoritative Cryptographic Message Envelope for Inter-Agent Communication.
    
    All A2A messages are signed with Ed25519 under KeyDomain::TokenSigning.
    Replay protection uses (sender_id, nonce) and message_id with 60-second TTL.
    """

    message_id: str
    mission_id: str
    sender_id: str
    recipient_id: str
    message_type: A2aMessageType
    timestamp: float
    nonce: str
    payload: Dict[str, Any]
    payload_hash: str
    signature: str
    kid: str
    parent_task_id: Optional[str] = None
    schema_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "mission_id": self.mission_id,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "parent_task_id": self.parent_task_id,
            "message_type": (
                self.message_type.value
                if isinstance(self.message_type, A2aMessageType)
                else str(self.message_type)
            ),
            "schema_version": self.schema_version,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "payload": self.payload,
            "payload_hash": self.payload_hash,
            "signature": self.signature,
            "kid": self.kid,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "A2aMessageEnvelope":
        m_type_raw = data.get("message_type")
        if isinstance(m_type_raw, A2aMessageType):
            m_type = m_type_raw
        else:
            try:
                m_type = A2aMessageType(str(m_type_raw))
            except ValueError:
                m_type = A2aMessageType.ERROR

        return cls(
            message_id=str(data.get("message_id", "")),
            mission_id=str(data.get("mission_id", "")),
            sender_id=str(data.get("sender_id", "")),
            recipient_id=str(data.get("recipient_id", "")),
            parent_task_id=data.get("parent_task_id"),
            message_type=m_type,
            schema_version=str(data.get("schema_version", "1.0.0")),
            timestamp=float(data.get("timestamp", 0.0)),
            nonce=str(data.get("nonce", "")),
            payload=dict(data.get("payload", {})),
            payload_hash=str(data.get("payload_hash", "")),
            signature=str(data.get("signature", "")),
            kid=str(data.get("kid", "")),
        )


@dataclass
class A2aVerificationResult:
    """Outcome of validating and verifying an incoming A2A message."""

    is_valid: bool
    envelope: Optional[A2aMessageEnvelope] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
