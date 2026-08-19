"""Engagement management API endpoints."""
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from arka.app.api.errors import NotFoundError, ConflictError
from arka.app.api.deps import get_audit_service
from arka.app.audit.service import AuditService
from arka.app.audit.schemas import AuditEventType
from arka.app.core.state.models import (
    EngagementState,
    EngagementStatus,
    ScopeDefinition,
    ScopeTarget,
    new_id,
    utc_now,
)

router = APIRouter(prefix="/engagements", tags=["engagements"])

# --- In-memory store for Phase 1 (database-backed in later phases) ---
_engagements: dict[str, EngagementState] = {}


# --- Request/Response Models ---


class CreateEngagementRequest(BaseModel):
    """Request to create a new engagement."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    objective: str = ""
    scope: dict[str, Any] | None = None


class EngagementResponse(BaseModel):
    """Response for a single engagement."""

    engagement_id: str
    name: str
    description: str
    objective: str
    status: str
    scope: dict[str, Any] | None = None
    created_at: str
    updated_at: str
    started_at: str | None = None
    completed_at: str | None = None

    @classmethod
    def from_state(cls, state: EngagementState) -> "EngagementResponse":
        """Create response from EngagementState."""
        return cls(
            engagement_id=state.engagement_id,
            name=state.name,
            description=state.description,
            objective=state.objective,
            status=state.status.value,
            scope=state.scope.model_dump() if state.scope else None,
            created_at=state.created_at.isoformat(),
            updated_at=state.updated_at.isoformat(),
            started_at=state.started_at.isoformat() if state.started_at else None,
            completed_at=state.completed_at.isoformat() if state.completed_at else None,
        )


class EngagementListResponse(BaseModel):
    """Response for listing engagements."""

    engagements: list[EngagementResponse]
    total: int


# --- Endpoints ---


@router.post("", response_model=EngagementResponse, status_code=201)
async def create_engagement(
    request: CreateEngagementRequest,
    audit: AuditService = Depends(get_audit_service),
) -> EngagementResponse:
    """Create a new engagement."""
    engagement_id = new_id()

    # Build scope if provided
    scope = None
    if request.scope:
        includes_data = request.scope.get("includes", {})
        excludes_data = request.scope.get("excludes", {})
        scope = ScopeDefinition(
            engagement_id=engagement_id,
            includes=ScopeTarget(**includes_data) if includes_data else ScopeTarget(),
            excludes=ScopeTarget(**excludes_data) if excludes_data else ScopeTarget(),
            notes=request.scope.get("notes", ""),
        )

    state = EngagementState(
        engagement_id=engagement_id,
        name=request.name,
        description=request.description,
        objective=request.objective,
        scope=scope,
    )
    _engagements[engagement_id] = state

    await audit.record_action(
        event_type=AuditEventType.ENGAGEMENT_CREATED,
        actor="api",
        action="create_engagement",
        engagement_id=engagement_id,
        result_status="success",
    )

    return EngagementResponse.from_state(state)


@router.get("/{engagement_id}", response_model=EngagementResponse)
async def get_engagement(engagement_id: str) -> EngagementResponse:
    """Get engagement details by ID."""
    state = _engagements.get(engagement_id)
    if not state:
        raise NotFoundError("Engagement", engagement_id)
    return EngagementResponse.from_state(state)


@router.post("/{engagement_id}/start", response_model=EngagementResponse)
async def start_engagement(
    engagement_id: str,
    audit: AuditService = Depends(get_audit_service),
) -> EngagementResponse:
    """Start an engagement."""
    state = _engagements.get(engagement_id)
    if not state:
        raise NotFoundError("Engagement", engagement_id)

    if state.status not in (EngagementStatus.CREATED, EngagementStatus.PAUSED):
        raise ConflictError(
            f"Cannot start engagement in '{state.status.value}' state. "
            f"Must be 'created' or 'paused'."
        )

    if not state.scope:
        raise ConflictError("Cannot start engagement without a scope definition.")

    state.status = EngagementStatus.ACTIVE
    state.started_at = utc_now()
    state.updated_at = utc_now()

    await audit.record_action(
        event_type=AuditEventType.ENGAGEMENT_STARTED,
        actor="api",
        action="start_engagement",
        engagement_id=engagement_id,
        result_status="success",
    )

    return EngagementResponse.from_state(state)


@router.post("/{engagement_id}/pause", response_model=EngagementResponse)
async def pause_engagement(
    engagement_id: str,
    audit: AuditService = Depends(get_audit_service),
) -> EngagementResponse:
    """Pause an active engagement."""
    state = _engagements.get(engagement_id)
    if not state:
        raise NotFoundError("Engagement", engagement_id)

    if state.status != EngagementStatus.ACTIVE:
        raise ConflictError(
            f"Cannot pause engagement in '{state.status.value}' state. Must be 'active'."
        )

    state.status = EngagementStatus.PAUSED
    state.updated_at = utc_now()

    await audit.record_action(
        event_type=AuditEventType.ENGAGEMENT_PAUSED,
        actor="api",
        action="pause_engagement",
        engagement_id=engagement_id,
        result_status="success",
    )

    return EngagementResponse.from_state(state)


@router.post("/{engagement_id}/stop", response_model=EngagementResponse)
async def stop_engagement(
    engagement_id: str,
    audit: AuditService = Depends(get_audit_service),
) -> EngagementResponse:
    """Stop an engagement."""
    state = _engagements.get(engagement_id)
    if not state:
        raise NotFoundError("Engagement", engagement_id)

    if state.status in (EngagementStatus.COMPLETED, EngagementStatus.STOPPED):
        raise ConflictError(
            f"Engagement is already in terminal state '{state.status.value}'."
        )

    state.status = EngagementStatus.STOPPED
    state.completed_at = utc_now()
    state.updated_at = utc_now()

    await audit.record_action(
        event_type=AuditEventType.ENGAGEMENT_STOPPED,
        actor="api",
        action="stop_engagement",
        engagement_id=engagement_id,
        result_status="success",
    )

    return EngagementResponse.from_state(state)


@router.get("/{engagement_id}/tasks")
async def get_engagement_tasks(engagement_id: str) -> dict:
    """Get tasks for an engagement.

    Phase 1: Returns empty list. Tasks are created by the orchestrator
    and will be populated when the LangGraph runtime is running.
    """
    state = _engagements.get(engagement_id)
    if not state:
        raise NotFoundError("Engagement", engagement_id)

    return {"engagement_id": engagement_id, "tasks": [], "total": 0}


@router.get("/{engagement_id}/audit")
async def get_engagement_audit(
    engagement_id: str,
    limit: int = 100,
    offset: int = 0,
    audit: AuditService = Depends(get_audit_service),
) -> dict:
    """Get audit trail for an engagement."""
    state = _engagements.get(engagement_id)
    if not state:
        raise NotFoundError("Engagement", engagement_id)

    events = await audit.get_events(engagement_id=engagement_id, limit=limit, offset=offset)
    return {
        "engagement_id": engagement_id,
        "events": [e.model_dump() for e in events],
        "total": len(events),
        "limit": limit,
        "offset": offset,
    }
