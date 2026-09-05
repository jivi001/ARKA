"""
Core state models for the ARKA platform.
Defines engagements, tasks, agents, policy decisions, and findings.
"""

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid.uuid4())


# --- Enums ---
class EngagementStatus(str, Enum):
    CREATED = "created"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalStatus(str, Enum):
    REQUIRED = "required"
    GRANTED = "granted"
    REJECTED = "rejected"
    EXPIRED = "expired"


class PolicyDecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


# --- Core Models ---


class ScopeTarget(BaseModel):
    """A single target within an engagement scope."""

    domains: list[str] = Field(default_factory=list)
    subdomains_allowed: bool = True
    ip_addresses: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    port_ranges: list[str] = Field(default_factory=list)  # e.g., "80-443"


class ScopeDefinition(BaseModel):
    """Complete scope definition for an engagement."""

    scope_id: str = Field(default_factory=new_id)
    engagement_id: str
    version: int = Field(default=1, ge=1)
    includes: ScopeTarget = Field(default_factory=ScopeTarget)
    excludes: ScopeTarget = Field(default_factory=ScopeTarget)
    notes: str = ""
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class EngagementState(BaseModel):
    """Top-level engagement state."""

    engagement_id: str = Field(default_factory=new_id)
    name: str
    description: str = ""
    objective: str = ""
    status: EngagementStatus = EngagementStatus.CREATED
    scope: ScopeDefinition | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class TaskState(BaseModel):
    """State for an individual task within an engagement."""

    task_id: str = Field(default_factory=new_id)
    engagement_id: str
    agent_id: str
    parent_task_id: str | None = None
    name: str
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    target: str | None = None
    requested_action: str | None = None
    input_data: dict[str, Any] = Field(default_factory=dict)
    output_data: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None


class AgentState(BaseModel):
    """State representation for an ARKA agent."""

    agent_id: str = Field(default_factory=new_id)
    agent_type: str  # e.g., "orchestrator", "recon", "exploit"
    engagement_id: str
    current_task_id: str | None = None
    status: str = "idle"
    capabilities: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class PolicyDecision(BaseModel):
    """Record of a policy decision."""

    decision_id: str = Field(default_factory=new_id)
    engagement_id: str
    task_id: str
    agent_id: str
    action: str
    target: str
    tool_name: str | None = None
    decision: PolicyDecisionType
    reason: str
    risk_level: RiskLevel = RiskLevel.LOW
    requires_approval: bool = False
    approval_id: str | None = None
    scope_version: int = 1
    decided_at: datetime = Field(default_factory=utc_now)


class ApprovalRequest(BaseModel):
    """Human approval request."""

    approval_id: str = Field(default_factory=new_id)
    engagement_id: str
    task_id: str
    agent_id: str
    action: str
    target: str
    tool_name: str
    risk_level: RiskLevel
    reason: str
    scope_version: int = Field(default=1, ge=1)
    details: dict[str, Any] = Field(default_factory=dict)
    status: ApprovalStatus = ApprovalStatus.REQUIRED
    requested_at: datetime = Field(default_factory=utc_now)
    decided_at: datetime | None = None
    decided_by: str | None = None
    expiry_seconds: int = 3600  # 1 hour default
    rejection_reason: str | None = None
    correlation_id: str | None = None

    @property
    def is_expired(self) -> bool:
        if self.status != ApprovalStatus.REQUIRED:
            return False
        from datetime import timedelta

        return utc_now() > self.requested_at + timedelta(seconds=self.expiry_seconds)


class EvidenceReference(BaseModel):
    """Reference to evidence collected during assessment."""

    evidence_id: str = Field(default_factory=new_id)
    engagement_id: str
    task_id: str
    evidence_type: str  # screenshot, output, file, log
    source_tool: str
    description: str = ""
    content_hash: str | None = None
    storage_path: str | None = None
    content_preview: str | None = None  # truncated preview
    collected_at: datetime = Field(default_factory=utc_now)


class FindingCandidate(BaseModel):
    """A potential security finding identified during assessment."""

    finding_id: str = Field(default_factory=new_id)
    engagement_id: str
    task_id: str
    agent_id: str
    title: str
    description: str
    severity: RiskLevel = RiskLevel.LOW
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    target: str
    evidence_refs: list[str] = Field(default_factory=list)
    verified: bool = False
    false_positive: bool = False
    created_at: datetime = Field(default_factory=utc_now)
