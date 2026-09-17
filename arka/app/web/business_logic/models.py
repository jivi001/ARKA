"""Domain models for Phase 3.8 Business-Logic and Access-Control Analysis.

Defines:
- Workflow, WorkflowStep, WorkflowPrecondition, StateTransition
- StateAnomaly, StateAnomalyType
- TestIdentity, AccessControlRole
- AccessControlCheck, AccessControlCheckType
Strictly enforces:
1. Section 3.8.5: Zero automatic execution of destructive operations.
2. Section 3.8.4: Strictly bounded IDOR probes between authorized test identities.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from arka.app.core.state.models import RiskLevel, new_id, utc_now
from arka.app.web.models.auth import SessionContext
from arka.app.web.models.http import HTTPMethod


class DestructiveActionCategory(str, Enum):
    """Actions that alter irreversible state and must NEVER be automatically executed."""

    PURCHASE_PAYMENT = "purchase_payment"
    DELETE_ACCOUNT = "delete_account"
    DELETE_DATABASE = "delete_database"
    FINANCIAL_TRANSACTION = "financial_transaction"
    SEND_MESSAGE_OR_EMAIL = "send_message_or_email"
    MODIFY_PRODUCTION_DATA = "modify_production_data"


class StateAnomalyType(str, Enum):
    """Anomalies detected in business logic state transitions."""

    PREREQUISITE_BYPASS = "prerequisite_bypass"
    IMPOSSIBLE_STATE_TRANSITION = "impossible_state_transition"
    INCONSISTENT_AUTHORIZATION = "inconsistent_authorization"
    OBJECT_OWNERSHIP_MISMATCH = "object_ownership_mismatch"
    UNEXPECTED_STATE_CHANGE = "unexpected_state_change"


class AccessControlRole(str, Enum):
    """Canonical test identity roles for multi-tenant access control analysis."""

    ANONYMOUS = "anonymous"
    USER = "user"
    ADMIN = "admin"
    AUDITOR = "auditor"


class AccessControlCheckType(str, Enum):
    """Categories of access control verification."""

    HORIZONTAL_IDOR_BOLA = "horizontal_idor_bola"
    VERTICAL_PRIVILEGE_ESCALATION = "vertical_privilege_escalation"
    UNAUTHENTICATED_ACCESS = "unauthenticated_access"


class WorkflowPrecondition(BaseModel):
    """A required state or preceding step that must be satisfied before execution."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., min_length=1)
    required_state_key: str = Field(...)
    expected_value: Any = Field(...)
    description: str = Field(default="")


class WorkflowStep(BaseModel):
    """A discrete operational step in a business workflow."""

    model_config = ConfigDict(frozen=True)

    step_id: str = Field(default_factory=new_id)
    name: str = Field(..., min_length=1)
    method: HTTPMethod = Field(default=HTTPMethod.GET)
    endpoint_url: str = Field(..., min_length=1)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    preconditions: list[WorkflowPrecondition] = Field(default_factory=list)
    expected_status_codes: list[int] = Field(default_factory=lambda: [200, 201, 204])
    state_updates: dict[str, Any] = Field(default_factory=dict)
    is_destructive: bool = Field(default=False)
    destructive_category: DestructiveActionCategory | None = None


class Workflow(BaseModel):
    """A stateful sequence of application operations."""

    workflow_id: str = Field(default_factory=new_id)
    engagement_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    steps: list[WorkflowStep] = Field(default_factory=list)
    current_step_index: int = 0
    current_state: dict[str, Any] = Field(default_factory=dict)
    completed: bool = False
    created_at: datetime = Field(default_factory=utc_now)


class StateAnomaly(BaseModel):
    """Empirically observed business logic flaw or state violation."""

    anomaly_id: str = Field(default_factory=new_id)
    engagement_id: str = Field(..., min_length=1)
    workflow_id: str = Field(default="")
    step_name: str = Field(default="")
    anomaly_type: StateAnomalyType
    title: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    severity: RiskLevel = Field(default=RiskLevel.MEDIUM)
    evidence_data: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=utc_now)


class TestIdentity(BaseModel):
    """Explicitly authorized test identity for access control and IDOR evaluation."""

    __test__ = False

    identity_id: str = Field(default_factory=new_id)
    engagement_id: str = Field(default="")
    name: str = Field(default="")
    tenant_id: str = Field(default="")
    role: AccessControlRole = Field(default=AccessControlRole.USER)
    session_context: SessionContext | None = None
    owned_resource_urls: list[str] = Field(
        default_factory=list,
        description="Controlled test resources owned by this test identity",
    )

    @property
    def session(self) -> SessionContext | None:
        return self.session_context

    @model_validator(mode="before")
    @classmethod
    def _normalize_identity(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "session" in data and "session_context" not in data:
                data["session_context"] = data["session"]
            if not data.get("name") and data.get("identity_id"):
                data["name"] = str(data["identity_id"])
            if not data.get("engagement_id"):
                sess = data.get("session_context")
                if sess and hasattr(sess, "engagement_id"):
                    data["engagement_id"] = sess.engagement_id
                elif isinstance(sess, dict) and "engagement_id" in sess:
                    data["engagement_id"] = sess["engagement_id"]
                else:
                    data["engagement_id"] = "eng-default"
        return data


class AccessControlCheck(BaseModel):
    """Deterministic access control probe specification."""

    model_config = ConfigDict(frozen=True)

    check_id: str = Field(default_factory=new_id)
    engagement_id: str = Field(..., min_length=1)
    check_type: AccessControlCheckType
    subject_identity_id: str = Field(..., description="Test identity performing request")
    owner_identity_id: str | None = Field(
        default=None, description="Test identity that owns resource"
    )
    target_url: str = Field(...)
    method: HTTPMethod = Field(default=HTTPMethod.GET)
    max_probes: int = Field(default=2, ge=1, le=3)
    created_at: datetime = Field(default_factory=utc_now)
