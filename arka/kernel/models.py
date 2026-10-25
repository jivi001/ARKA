"""
Kernel Bridge Request and Response Data Models.
Adheres strictly to ADR-007 Section 4.2 & 4.3.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from arka.agents.proposal import RawActionProposal


class KernelDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass
class KernelExecutionResult:
    state: str
    evidence_hashes: List[str]
    execution_id: str


@dataclass
class KernelErrorPayload:
    code: str
    message: str
    retryable: bool = False


@dataclass
class KernelRequest:
    proposal: RawActionProposal
    request_id: str = field(default_factory=lambda: f"req-{uuid.uuid4().hex[:16]}")
    client_version: str = "3.0.0"
    operation: str = "AUTHORIZE_AND_EXECUTE"
    auth_token: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "request_id": self.request_id,
            "client_version": self.client_version,
            "operation": self.operation,
            "proposal": self.proposal.to_dict(),
        }
        if self.auth_token is not None:
            d["auth_token"] = self.auth_token
        return d


@dataclass
class KernelResponse:
    request_id: str
    decision: KernelDecision
    action_id: Optional[str] = None
    action_hash: Optional[str] = None
    execution_result: Optional[KernelExecutionResult] = None
    error: Optional[KernelErrorPayload] = None

    @property
    def is_allow(self) -> bool:
        return self.decision == KernelDecision.ALLOW

    @property
    def is_require_approval(self) -> bool:
        return self.decision == KernelDecision.REQUIRE_APPROVAL

    @property
    def is_deny(self) -> bool:
        return self.decision == KernelDecision.DENY

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KernelResponse":
        decision = KernelDecision(data["decision"])
        exec_res = None
        if data.get("execution_result"):
            er = data["execution_result"]
            exec_res = KernelExecutionResult(
                state=er["state"],
                evidence_hashes=er.get("evidence_hashes", []),
                execution_id=er["execution_id"],
            )

        err_res = None
        if data.get("error"):
            e = data["error"]
            err_res = KernelErrorPayload(
                code=e["code"],
                message=e["message"],
                retryable=e.get("retryable", False),
            )

        return cls(
            request_id=data["request_id"],
            decision=decision,
            action_id=data.get("action_id"),
            action_hash=data.get("action_hash"),
            execution_result=exec_res,
            error=err_res,
        )
