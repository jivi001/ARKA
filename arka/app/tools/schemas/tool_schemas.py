"""Tool request and response schemas.

Defines both untrusted candidate proposals from LLMs (CandidateToolRequest)
and authoritative, deterministic execution requests (ToolRequest).
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from arka.app.core.state.models import RiskLevel, new_id, utc_now


class ToolDefinition(BaseModel):
    """Registration schema for a tool in the Tool Registry."""

    name: str
    description: str
    version: str = "1.0.0"
    input_schema: dict[str, Any]  # JSON Schema
    output_schema: dict[str, Any]  # JSON Schema
    risk_level: RiskLevel
    required_permissions: list[str] = Field(default_factory=list)
    allowed_environments: list[str] = Field(default_factory=lambda: ["sandbox"])
    timeout_seconds: int = 300
    rate_limit_per_minute: int = 60
    evidence_required: bool = True
    category: str = "general"
    enabled: bool = True

    def determine_risk(self, arguments: dict[str, Any] | None = None) -> RiskLevel:
        """Derive the authoritative risk level for given execution arguments.

        Defaults to the tool's static risk_level. Tool-specific definitions
        can override this to implement deterministic operation-level risk escalation.
        """
        return self.risk_level


class CandidateToolRequest(BaseModel):
    """Untrusted candidate tool request proposed by an LLM or agent reasoning step.

    Contains ONLY the proposed action details. It CANNOT specify authorization,
    scope validation, risk level, or approval state.
    """

    tool_name: str
    target: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


class ToolRequest(BaseModel):
    """An authoritative request to execute a tool.

    Security fields (scope_validated, policy_approved, risk_level, approval_id)
    must only be populated by trusted ARKA validation components (ScopeGuard,
    PolicyEngine, ApprovalManager, ToolRegistry), NEVER from LLM output.
    """

    request_id: str = Field(default_factory=new_id)
    engagement_id: str
    task_id: str
    agent_id: str
    tool_name: str
    target: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    scope_validated: bool = False
    scope_version: int = 1
    policy_approved: bool = False
    approval_id: str | None = None
    requested_at: datetime = Field(default_factory=utc_now)


class ToolResult(BaseModel):
    """Result from a tool execution."""

    result_id: str = Field(default_factory=new_id)
    request_id: str
    engagement_id: str
    task_id: str
    tool_name: str
    success: bool
    output: dict[str, Any] = Field(default_factory=dict)
    raw_output: str | None = None
    error: str | None = None
    execution_time_ms: int = 0
    evidence_refs: list[str] = Field(default_factory=list)
    executed_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
