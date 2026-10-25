"""
ARKA Evidence Domain Models.

Adheres to:
- ARKA TRD v2.2 Section 21 (Evidence Ingestion & Immutability)
- ARKA TRD v2.2 Section 22 (Evidence Classification Pipeline)
- ARKA PRD v2.2 Section 18 (Sensitive Data Handling) & Section 21 (Evidence Lifecycle)
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
import time
from typing import Any, Dict, List, Optional
import uuid


class TrustLevel(str, Enum):
    """Trust classification of the evidence origin."""

    TRUSTED = "TRUSTED"        # Kernel-generated, operator-issued, or verified dual-chain signed
    UNTRUSTED = "UNTRUSTED"    # Target-sourced, external network response, or worker output
    UNKNOWN = "UNKNOWN"        # Unverified origin


class SensitivityLevel(str, Enum):
    """Information sensitivity classification for DLP and outbound LLM context controls."""

    PUBLIC = "PUBLIC"              # Public OSINT, DNS records, public internet banners
    INTERNAL = "INTERNAL"          # Internal IP space, architecture layouts, non-sensitive configs
    CONFIDENTIAL = "CONFIDENTIAL"  # Vulnerability PoCs, application endpoints, infrastructure details
    SECRET = "SECRET"              # Credentials, private keys, API tokens, session cookies, PII


class EvidenceType(str, Enum):
    """Categorization of evidence artifacts."""

    STDOUT = "STDOUT"
    STDERR = "STDERR"
    STRUCTURED_OUTPUT = "STRUCTURED_OUTPUT"
    RAW_NETWORK_RESPONSE = "RAW_NETWORK_RESPONSE"
    PORT_SCAN = "PORT_SCAN"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    VULN_SCAN = "VULN_SCAN"
    CUSTOM = "CUSTOM"


@dataclass(frozen=True)
class EvidenceProvenance:
    """Immutable provenance metadata bound to an evidence artifact."""

    mission_id: str
    task_id: str
    collector: str
    action_id: Optional[str] = None
    capability_id: Optional[str] = None
    worker_profile: Optional[str] = None
    target: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceProvenance":
        return cls(
            mission_id=str(data["mission_id"]),
            task_id=str(data["task_id"]),
            collector=str(data.get("collector", "unknown")),
            action_id=data.get("action_id"),
            capability_id=data.get("capability_id"),
            worker_profile=data.get("worker_profile"),
            target=data.get("target"),
        )


@dataclass
class EvidenceRecord:
    """
    Tamper-evident, content-addressed evidence artifact.
    
    Invariants:
    - Evidence is immutable once ingested.
    - content_hash matches raw_content SHA-256 under DOMAIN_EVIDENCE ('ARKA-EVIDENCE-V1:').
    - Evaluated for trust and sensitivity classifications before storage.
    """

    evidence_id: str
    provenance: EvidenceProvenance
    evidence_type: EvidenceType
    raw_content: bytes
    content_hash: str
    size_bytes: int
    created_at_unix: float
    trust: TrustLevel
    sensitivity: SensitivityLevel
    structured_data: Optional[Dict[str, Any]] = None
    redacted_content: Optional[str] = None
    parent_refs: List[str] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "provenance": self.provenance.to_dict(),
            "evidence_type": self.evidence_type.value,
            "content_hash": self.content_hash,
            "size_bytes": self.size_bytes,
            "created_at_unix": self.created_at_unix,
            "trust": self.trust.value,
            "sensitivity": self.sensitivity.value,
            "structured_data": self.structured_data,
            "redacted_content": self.redacted_content,
            "parent_refs": self.parent_refs,
            "truncated": self.truncated,
        }
