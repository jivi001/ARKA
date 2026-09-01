"""
Audit event schemas.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from arka.app.core.state.models import new_id, utc_now


class AuditEventType(str, Enum):
    ENGAGEMENT_CREATED = "engagement.created"
    ENGAGEMENT_STARTED = "engagement.started"
    ENGAGEMENT_PAUSED = "engagement.paused"
    ENGAGEMENT_STOPPED = "engagement.stopped"
    ENGAGEMENT_COMPLETED = "engagement.completed"
    TASK_CREATED = "task.created"
    TASK_STARTED = "task.started"
    TASK_COMPLETED = "task.completed"
    TASK_FAILED = "task.failed"
    TOOL_REQUESTED = "tool.requested"
    TOOL_EXECUTED = "tool.executed"
    TOOL_FAILED = "tool.failed"
    SCOPE_VALIDATED = "scope.validated"
    SCOPE_VIOLATION = "scope.violation"
    POLICY_DECISION = "policy.decision"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_REJECTED = "approval.rejected"
    APPROVAL_EXPIRED = "approval.expired"
    LLM_REQUEST = "llm.request"
    LLM_RESPONSE = "llm.response"
    LLM_ERROR = "llm.error"
    AGENT_STARTED = "agent.started"
    AGENT_STOPPED = "agent.stopped"
    SECURITY_ALERT = "security.alert"
    EXECUTION_REQUESTED = "execution.requested"
    EXECUTION_AUTHORIZED = "execution.authorized"
    EXECUTION_STARTED = "execution.started"
    EXECUTION_COMPLETED = "execution.completed"
    EXECUTION_FAILED = "execution.failed"
    EXECUTION_TIMED_OUT = "execution.timed_out"
    EXECUTION_CANCELLED = "execution.cancelled"
    EXECUTION_REJECTED = "execution.rejected"
    EVIDENCE_RECORDED = "evidence.recorded"


class AuditEvent(BaseModel):
    """Append-only audit event for compliance and security."""

    event_id: str = Field(default_factory=new_id)
    event_type: AuditEventType
    timestamp: datetime = Field(default_factory=utc_now)
    engagement_id: str | None = None
    task_id: str | None = None
    agent_id: str | None = None
    actor: str  # who/what initiated this
    action: str
    target: str | None = None
    tool_name: str | None = None
    authorization_decision: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    result_status: str | None = None
    error: str | None = None
    evidence_ref: str | None = None
    correlation_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
