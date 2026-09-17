"""WebSecurityAgent domain models, action definitions, state machine, and budgets for Phase 3.9.

Enforces:
1. Deterministic state transitions (INITIALIZED -> DISCOVERING -> ANALYZING -> VALIDATING -> etc.).
2. Deterministic action budgets (max requests, pages, depth, iterations, time, bytes).
3. Loop prevention and action deduplication via canonical SHA-256 fingerprinting.
4. Separation of LLM confidence from authoritative ARKA evidence confidence.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from arka.app.core.state.models import utc_now
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest
from arka.app.web.analysis.models import (
    SecurityFinding,
    SecurityHypothesis,
    SecurityObservation,
)


class WebAgentState(str, Enum):
    """Authoritative lifecycle states for WebSecurityAgent state machine."""

    INITIALIZED = "initialized"
    DISCOVERING = "discovering"
    ANALYZING = "analyzing"
    VALIDATING = "validating"
    WAITING_APPROVAL = "waiting_approval"
    EXECUTING = "executing"
    CORRELATING = "correlating"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


class InvalidStateTransitionError(Exception):
    """Raised when an illegal state transition is attempted."""

    def __init__(self, current_state: WebAgentState, target_state: WebAgentState):
        self.current_state = current_state
        self.target_state = target_state
        super().__init__(
            f"Invalid state transition attempted: '{current_state.value}' -> '{target_state.value}'"
        )


VALID_STATE_TRANSITIONS: dict[WebAgentState, set[WebAgentState]] = {
    WebAgentState.INITIALIZED: {
        WebAgentState.DISCOVERING,
        WebAgentState.EXECUTING,
        WebAgentState.FAILED,
    },
    WebAgentState.DISCOVERING: {
        WebAgentState.ANALYZING,
        WebAgentState.WAITING_APPROVAL,
        WebAgentState.EXECUTING,
        WebAgentState.FAILED,
        WebAgentState.PAUSED,
        WebAgentState.COMPLETED,
    },
    WebAgentState.ANALYZING: {
        WebAgentState.VALIDATING,
        WebAgentState.DISCOVERING,
        WebAgentState.WAITING_APPROVAL,
        WebAgentState.EXECUTING,
        WebAgentState.CORRELATING,
        WebAgentState.COMPLETED,
        WebAgentState.FAILED,
        WebAgentState.PAUSED,
    },
    WebAgentState.VALIDATING: {
        WebAgentState.CORRELATING,
        WebAgentState.ANALYZING,
        WebAgentState.WAITING_APPROVAL,
        WebAgentState.EXECUTING,
        WebAgentState.COMPLETED,
        WebAgentState.FAILED,
        WebAgentState.PAUSED,
    },
    WebAgentState.WAITING_APPROVAL: {
        WebAgentState.EXECUTING,
        WebAgentState.FAILED,
        WebAgentState.PAUSED,
    },
    WebAgentState.EXECUTING: {
        WebAgentState.DISCOVERING,
        WebAgentState.ANALYZING,
        WebAgentState.VALIDATING,
        WebAgentState.CORRELATING,
        WebAgentState.COMPLETED,
        WebAgentState.FAILED,
        WebAgentState.PAUSED,
    },
    WebAgentState.CORRELATING: {
        WebAgentState.COMPLETED,
        WebAgentState.DISCOVERING,
        WebAgentState.ANALYZING,
        WebAgentState.FAILED,
        WebAgentState.PAUSED,
    },
    WebAgentState.PAUSED: {
        WebAgentState.DISCOVERING,
        WebAgentState.ANALYZING,
        WebAgentState.VALIDATING,
        WebAgentState.EXECUTING,
        WebAgentState.CORRELATING,
        WebAgentState.COMPLETED,
        WebAgentState.FAILED,
    },
    WebAgentState.COMPLETED: set(),
    WebAgentState.FAILED: set(),
}


class WebAgentTerminationReason(str, Enum):
    """Authoritative termination reasons for WebSecurityAgent."""

    OBJECTIVES_SATISFIED = "objectives_satisfied"
    MAX_ITERATIONS_REACHED = "max_iterations_reached"
    BUDGET_EXHAUSTED = "budget_exhausted"
    NO_FURTHER_ACTIONS = "no_further_actions"
    SCOPE_DENIED = "scope_denied"
    FATAL_ERROR = "fatal_error"


class WebActionBudget(BaseModel):
    """Deterministic resource limits and bounds for an assessment engagement."""

    model_config = ConfigDict(frozen=True)

    max_requests: int = Field(default=100, ge=1, le=1000)
    max_pages: int = Field(default=30, ge=1, le=200)
    max_depth: int = Field(default=3, ge=1, le=10)
    max_concurrent_requests: int = Field(default=5, ge=1, le=20)
    max_execution_time_seconds: int = Field(default=600, ge=10, le=7200)
    max_agent_iterations: int = Field(default=10, ge=1, le=50)
    max_findings: int = Field(default=50, ge=1, le=500)
    max_evidence_bytes: int = Field(default=10_000_000, ge=1000)
    max_response_bytes: int = Field(default=2_000_000, ge=1000)


class WebActionBudgetUsed(BaseModel):
    """Tracks consumed resources against deterministic budgets."""

    requests_sent: int = 0
    pages_crawled: int = 0
    max_depth_reached: int = 0
    execution_time_seconds: float = 0.0
    iterations_completed: int = 0
    findings_produced: int = 0
    evidence_bytes: int = 0
    response_bytes: int = 0

    def is_exhausted(self, budget: WebActionBudget) -> tuple[bool, str | None]:
        """Check if any deterministic budget limit has been reached."""
        if self.requests_sent >= budget.max_requests:
            return True, f"Max requests reached ({self.requests_sent}/{budget.max_requests})"
        if self.pages_crawled >= budget.max_pages:
            return True, f"Max pages crawled ({self.pages_crawled}/{budget.max_pages})"
        if self.iterations_completed >= budget.max_agent_iterations:
            return (
                True,
                f"Max agent iterations reached "
                f"({self.iterations_completed}/{budget.max_agent_iterations})",
            )
        if self.findings_produced >= budget.max_findings:
            return (
                True,
                f"Max findings budget reached ({self.findings_produced}/{budget.max_findings})",
            )
        if self.evidence_bytes >= budget.max_evidence_bytes:
            return (
                True,
                f"Max evidence bytes reached ({self.evidence_bytes}/{budget.max_evidence_bytes})",
            )
        return False, None


def compute_web_action_fingerprint(
    tool_name: str,
    target: str,
    arguments: dict[str, Any],
    engagement_id: str = "",
) -> str:
    """Compute a deterministic, timestamp-free SHA-256 fingerprint for an action."""
    normalized_eng = engagement_id.strip().lower()
    normalized_tool = tool_name.strip().lower()
    normalized_target = target.strip().lower()
    canonical_args = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    payload = f"{normalized_eng}:{normalized_tool}:{normalized_target}:{canonical_args}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class WebAction(BaseModel):
    """A proposed action produced by the WebSecurityAgent reasoning step."""

    model_config = ConfigDict(frozen=True)

    action_id: str
    tool_name: str
    target: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    engagement_id: str = ""

    def to_candidate_request(self) -> CandidateToolRequest:
        """Convert into an untrusted CandidateToolRequest."""
        args = dict(self.arguments)
        if (
            self.tool_name in ("web_crawler", "openapi_analyze", "graphql_analyze")
            and "target" not in args
        ):
            args["target"] = self.target
        if self.tool_name == "http_request" and "url" not in args:
            args["url"] = self.target
        return CandidateToolRequest(
            tool_name=self.tool_name,
            target=self.target,
            arguments=args,
            reason=self.reason,
        )

    @property
    def fingerprint(self) -> str:
        return compute_web_action_fingerprint(
            self.tool_name, self.target, self.arguments, self.engagement_id
        )


class WebSecurityPlan(BaseModel):
    """Plan generated by WebSecurityAgent containing candidate tool actions."""

    model_config = ConfigDict(frozen=True)

    plan_id: str
    engagement_id: str
    iteration: int
    reasoning: str
    candidate_actions: list[WebAction] = Field(default_factory=list)
    should_terminate: bool = False
    termination_reason: WebAgentTerminationReason | None = None


class WebSecurityState(BaseModel):
    """Execution state tracking for WebSecurityAgent."""

    engagement_id: str
    agent_state: WebAgentState = WebAgentState.INITIALIZED
    iteration: int = 0
    max_iterations: int = 5
    budget: WebActionBudget = Field(default_factory=WebActionBudget)
    budget_used: WebActionBudgetUsed = Field(default_factory=WebActionBudgetUsed)
    executed_action_fingerprints: set[str] = Field(default_factory=set)
    action_counts: dict[str, int] = Field(default_factory=dict)  # Loop / oscillation detection
    discovered_endpoints_count: int = 0
    discovered_urls: set[str] = Field(default_factory=set)
    observations: list[SecurityObservation] = Field(default_factory=list)
    hypotheses: list[SecurityHypothesis] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)
    active_session_id: str | None = None
    is_complete: bool = False
    termination_reason: WebAgentTerminationReason | None = None
    created_at: Any = Field(default_factory=utc_now)
    updated_at: Any = Field(default_factory=utc_now)

    def transition_to(self, new_state: WebAgentState) -> None:
        """Deterministically transition agent state verifying allowed transitions."""
        if new_state == self.agent_state:
            return

        allowed = VALID_STATE_TRANSITIONS.get(self.agent_state, set())
        if new_state not in allowed:
            raise InvalidStateTransitionError(self.agent_state, new_state)

        self.agent_state = new_state
        if new_state == WebAgentState.COMPLETED or new_state == WebAgentState.FAILED:
            self.is_complete = True
        self.updated_at = utc_now()
