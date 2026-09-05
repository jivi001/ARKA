"""ReconAgent typed state models, action definitions, and configuration.

Ensures strict typing, deterministic serialization, auditability, and checkpoint
compatibility for ARKA Phase 2.2.4 ReconAgent.
"""

from __future__ import annotations

import hashlib
import json
import operator
from enum import Enum
from typing import Annotated, Any, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from arka.app.core.state.models import utc_now


class ReconTerminationReason(str, Enum):
    """Authoritative termination reasons for ReconAgent."""

    OBJECTIVES_SATISFIED = "objectives_satisfied"
    MAX_ITERATIONS_REACHED = "max_iterations_reached"
    MAX_ACTIONS_REACHED = "max_actions_reached"
    MAX_REPEATED_ACTIONS_REACHED = "max_repeated_actions_reached"
    NO_USEFUL_NEXT_ACTION = "no_useful_next_action"
    SCOPE_EXHAUSTED = "scope_exhausted"
    REPEATED_FAILURES = "repeated_failures"
    SAFETY_POLICY_REJECTION = "safety_policy_rejection"
    FATAL_ERROR = "fatal_error"


def compute_action_fingerprint(
    tool_name: str,
    operation: str,
    target: str,
    arguments: dict[str, Any],
) -> str:
    """Compute a deterministic, timestamp-free SHA-256 fingerprint for an action.

    Guarantees idempotency detection across iterations and resumes.
    """
    normalized_tool = tool_name.strip().lower()
    normalized_op = operation.strip().lower()
    normalized_target = target.strip().lower()
    # Canonical JSON: sorted keys, compact separators, deterministic
    canonical_args = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    payload = f"{normalized_tool}:{normalized_op}:{normalized_target}:{canonical_args}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ReconAction(BaseModel):
    """An individual candidate reconnaissance action proposed by the LLM or agent."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(..., min_length=1, description="Tool identifier, e.g. 'nmap'")
    operation: str = Field(
        default="scan", min_length=1, description="Operation mode, e.g. 'scan', 'probe'"
    )
    arguments: dict[str, Any] = Field(
        default_factory=dict, description="Typed arguments matching tool schema"
    )
    target: str = Field(..., min_length=1, description="Target IP, hostname, CIDR, or URL")
    rationale: str = Field(default="", description="Reconnaissance rationale or hypothesis")

    def fingerprint(self) -> str:
        """Return the deterministic fingerprint for this action."""
        return compute_action_fingerprint(
            self.tool_name, self.operation, self.target, self.arguments
        )


class ReconPlan(BaseModel):
    """Structured reconnaissance plan produced by LLM Gateway."""

    model_config = ConfigDict(extra="ignore")

    objective: str = Field(..., description="High-level reconnaissance objective")
    reasoning_summary: str = Field(default="", description="Summary of reasoning")
    candidate_actions: list[ReconAction] = Field(
        default_factory=list, description="Ordered list of proposed candidate actions"
    )
    stop_condition: str | None = Field(
        default=None, description="Condition under which recon should terminate"
    )


class ReconAnalysis(BaseModel):
    """Structured analysis of tool execution results produced by LLM Gateway."""

    model_config = ConfigDict(extra="ignore")

    summary: str = Field(default="", description="Summary of what the tool result revealed")
    findings: list[str] = Field(default_factory=list, description="Concrete security observations")
    hypotheses: list[str] = Field(
        default_factory=list, description="Hypotheses regarding targets or attack surface"
    )
    identified_targets: list[str] = Field(
        default_factory=list,
        description="Newly discovered target addresses/hostnames (DISCOVERED != AUTHORIZED)",
    )
    next_recommended_actions: list[ReconAction] = Field(
        default_factory=list, description="Recommended follow-up actions"
    )
    should_stop: bool = Field(
        default=False, description="Whether reconnaissance goals are now satisfied"
    )
    stop_reason: ReconTerminationReason | None = Field(
        default=None, description="Reason to stop if should_stop is True"
    )


class ReconAgentConfig(BaseModel):
    """Safety configuration and bounded loop limits for ReconAgent."""

    model_config = ConfigDict(extra="forbid")

    max_iterations: int = Field(
        default=10, ge=1, le=50, description="Maximum planning/execution iterations"
    )
    max_actions: int = Field(
        default=25, ge=1, le=100, description="Maximum total tool executions permitted"
    )
    max_repeated_action_attempts: int = Field(
        default=2, ge=1, le=5, description="Maximum repeated executions of the exact same action"
    )
    max_consecutive_failures: int = Field(
        default=3, ge=1, le=10, description="Max consecutive rejections/failures before stopping"
    )
    temperature: float = Field(default=0.0, ge=0.0, le=1.0, description="LLM temperature")


class ReconState(BaseModel):
    """Typed, serializable state representation for ReconAgent."""

    model_config = ConfigDict(extra="forbid")

    engagement_id: str = Field(..., description="Active engagement UUID")
    authorized_scope: dict[str, Any] = Field(
        default_factory=dict, description="ScopeDefinition as serialized dict"
    )
    recon_objectives: list[str] = Field(
        default_factory=list, description="List of reconnaissance objectives"
    )
    current_assets: list[str] = Field(
        default_factory=list, description="Observed canonical asset identifiers or addresses"
    )
    current_services: list[str] = Field(
        default_factory=list, description="Observed canonical service identifiers"
    )
    current_technologies: list[str] = Field(
        default_factory=list, description="Observed canonical technology identifiers"
    )
    current_endpoints: list[str] = Field(
        default_factory=list, description="Observed canonical endpoint identifiers"
    )
    completed_actions: list[dict[str, Any]] = Field(
        default_factory=list, description="History of completed candidate actions"
    )
    pending_actions: list[dict[str, Any]] = Field(
        default_factory=list, description="Pending candidate actions from plan"
    )
    executed_fingerprints: dict[str, int] = Field(
        default_factory=dict, description="Fingerprint execution counts for idempotency"
    )
    tool_results: list[dict[str, Any]] = Field(
        default_factory=list, description="Summarized tool execution results"
    )
    evidence_refs: list[str] = Field(
        default_factory=list, description="SHA-256 cryptographic evidence reference IDs"
    )
    observations: list[str] = Field(
        default_factory=list, description="Accumulated observations from tool output"
    )
    hypotheses: list[str] = Field(default_factory=list, description="Active working hypotheses")
    errors: list[str] = Field(default_factory=list, description="Errors or rejections encountered")
    iteration: int = Field(default=0, ge=0, description="Current iteration counter")
    action_count: int = Field(default=0, ge=0, description="Total executed actions counter")
    consecutive_failures: int = Field(
        default=0, ge=0, description="Consecutive failed/rejected actions counter"
    )
    status: str = Field(
        default="initialized",
        description="Status: 'initialized', 'running', 'paused', 'completed', 'failed', 'stopped'",
    )
    termination_reason: ReconTerminationReason | None = Field(
        default=None, description="Explicit termination reason when completed or stopped"
    )
    last_candidate_request: dict[str, Any] | None = Field(
        default=None, description="Most recent CandidateToolRequest"
    )
    last_tool_result: dict[str, Any] | None = Field(
        default=None, description="Most recent ToolResult"
    )
    created_at: str = Field(default_factory=lambda: utc_now().isoformat())
    updated_at: str = Field(default_factory=lambda: utc_now().isoformat())


class ReconAgentState(TypedDict):
    """LangGraph-compatible state dictionary for the ReconAgent workflow."""

    # Engagement & scope
    engagement_id: str
    authorized_scope: dict[str, Any]
    recon_objectives: list[str]

    # Asset state
    current_assets: list[str]
    current_services: list[str]
    current_technologies: list[str]
    current_endpoints: list[str]

    # Current task / action
    current_task_id: str
    current_action: dict[str, Any] | None

    # Actions queue & idempotency
    pending_actions: list[dict[str, Any]]
    executed_fingerprints: dict[str, int]

    # LLM Interaction
    llm_plan_raw: str
    llm_analysis_raw: str

    # Tool Execution Pipeline
    candidate_tool_request: dict[str, Any] | None
    policy_decision: dict[str, Any] | None
    tool_request: dict[str, Any] | None
    tool_result: dict[str, Any] | None

    # Approval Gate
    requires_approval: bool
    approval_id: str | None
    approval_status: str

    # Accumulators (Annotated with operator.add)
    completed_actions: Annotated[list[dict[str, Any]], operator.add]
    tool_results: Annotated[list[dict[str, Any]], operator.add]
    evidence_refs: Annotated[list[str], operator.add]
    observations: Annotated[list[str], operator.add]
    hypotheses: Annotated[list[str], operator.add]
    errors: Annotated[list[str], operator.add]
    audit_trail: Annotated[list[str], operator.add]

    # Loop control & limits
    iteration: int
    action_count: int
    consecutive_failures: int
    max_iterations: int
    max_actions: int
    max_repeated_action_attempts: int
    max_consecutive_failures: int

    # Status & Termination
    status: str
    should_continue: bool
    termination_reason: str | None
