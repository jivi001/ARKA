"""
Untrusted Raw Action Proposal Data Model.
Adheres strictly to ARKA PRD v2.2 and crates/arka-core-types/src/actions.rs.
"""

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Dict, Optional
import uuid

from .exceptions import InvalidProposalError


@dataclass
class RawActionProposal:
    """
    Untrusted action proposal emitted by an AI agent reasoning step.
    Must pass through ActionNormalizer and AuthorizationEngine before execution.
    """

    mission_id: str
    capability_id: str
    target: str
    parameters: Dict[str, Any]
    proposal_id: str = field(default_factory=lambda: f"prop-{uuid.uuid4().hex[:16]}")
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex)
    declared_risk: Optional[str] = None
    parent_task_id: Optional[str] = None

    def __post_init__(self):
        if not self.proposal_id or not self.proposal_id.strip():
            raise InvalidProposalError("proposal_id must not be empty")
        if not self.mission_id or not self.mission_id.strip():
            raise InvalidProposalError("mission_id must not be empty")
        if not self.capability_id or not self.capability_id.strip():
            raise InvalidProposalError("capability_id must not be empty")
        if not self.target or not self.target.strip():
            raise InvalidProposalError("target must not be empty")
        if not isinstance(self.parameters, dict):
            raise InvalidProposalError("parameters must be a key-value dictionary")
        if not self.nonce or not self.nonce.strip():
            raise InvalidProposalError("nonce must not be empty")

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts proposal to a dictionary matching Rust RawActionProposal serde schema.
        Omits None optional fields to conform to skip_serializing_if = "Option::is_none".
        """
        data: Dict[str, Any] = {
            "proposal_id": self.proposal_id,
            "mission_id": self.mission_id,
            "capability_id": self.capability_id,
            "target": self.target,
            "parameters": self.parameters,
            "nonce": self.nonce,
        }
        if self.declared_risk is not None:
            data["declared_risk"] = self.declared_risk
        if self.parent_task_id is not None:
            data["parent_task_id"] = self.parent_task_id
        return data

    def to_json(self) -> str:
        """Serializes proposal to JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))
