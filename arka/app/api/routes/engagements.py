"""Engagement management API endpoints."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from arka.app.api.deps import (
    get_approval_manager,
    get_audit_service,
    get_scope_repository,
)
from arka.app.api.errors import ConflictError, NotFoundError, ValidationError
from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.scope import (
    ScopeConflictError,
    ScopeRepository,
    ScopeValidationError,
    validate_scope_definition,
)
from arka.app.core.state.models import (
    EngagementState,
    EngagementStatus,
    ScopeDefinition,
    ScopeTarget,
    new_id,
    utc_now,
)
from arka.app.database.models import Engagement

router = APIRouter(prefix="/engagements", tags=["engagements"])

# In-memory working cache
_engagements: dict[str, EngagementState] = {}


# --- Request/Response Models ---


class ScopeTargetPayload(BaseModel):
    """Payload representing a target group (included or excluded) in an engagement scope."""

    domains: list[str] = Field(default_factory=list)
    subdomains_allowed: bool = True
    ip_addresses: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    port_ranges: list[str] = Field(default_factory=list)


class SetScopeRequest(BaseModel):
    """Request to create or replace an engagement's scope.

    Semantics: CREATE-OR-REPLACE (not merge).
    """

    includes: ScopeTargetPayload
    excludes: ScopeTargetPayload | None = None
    notes: str = ""
    expected_version: int | None = Field(
        None, description="Expected current version for optimistic concurrency control"
    )


class ScopeResponse(BaseModel):
    """Response representing an engagement's authoritative scope."""

    scope_id: str
    engagement_id: str
    version: int
    includes: dict[str, Any]
    excludes: dict[str, Any]
    notes: str
    created_at: str
    updated_at: str

    @classmethod
    def from_definition(cls, scope: ScopeDefinition) -> ScopeResponse:
        return cls(
            scope_id=scope.scope_id,
            engagement_id=scope.engagement_id,
            version=scope.version,
            includes=scope.includes.model_dump(),
            excludes=scope.excludes.model_dump(),
            notes=scope.notes,
            created_at=scope.created_at.isoformat(),
            updated_at=scope.updated_at.isoformat(),
        )


class CreateEngagementRequest(BaseModel):
    """Request to create a new engagement."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    objective: str = ""
    scope: SetScopeRequest | dict[str, Any] | None = None


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
    def from_state(cls, state: EngagementState) -> EngagementResponse:
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


# --- Helper Functions ---


def _safe_uuid(val: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(val))
    except (ValueError, AttributeError):
        return uuid.uuid5(uuid.NAMESPACE_DNS, str(val))


async def _get_or_load_engagement(
    engagement_id: str,
    scope_repo: ScopeRepository,
) -> EngagementState | None:
    """Retrieve engagement state from memory, or rehydrate from PostgreSQL if available."""
    if engagement_id in _engagements:
        state = _engagements[engagement_id]
        if not state.scope:
            state.scope = await scope_repo.get_scope(engagement_id)
        return state

    if scope_repo._session_factory:
        try:
            eng_uuid = _safe_uuid(engagement_id)
            async with scope_repo._session_factory() as session:
                stmt = select(Engagement).where(Engagement.id == eng_uuid)
                res = await session.execute(stmt)
                db_eng = res.scalar_one_or_none()
                if db_eng:
                    scope_def = await scope_repo.get_scope(engagement_id)
                    state = EngagementState(
                        engagement_id=str(db_eng.id),
                        name=db_eng.name,
                        description=db_eng.description or "",
                        objective=db_eng.objective or "",
                        status=EngagementStatus(db_eng.status),
                        scope=scope_def,
                        created_at=db_eng.created_at,
                        updated_at=db_eng.updated_at,
                        started_at=db_eng.started_at,
                        completed_at=db_eng.completed_at,
                        metadata=db_eng.metadata_ or {},
                    )
                    _engagements[engagement_id] = state
                    return state
        except Exception:
            pass

    return None


# --- Endpoints ---


@router.post("", response_model=EngagementResponse, status_code=201)
async def create_engagement(
    request: CreateEngagementRequest,
    scope_repo: ScopeRepository = Depends(get_scope_repository),
    audit: AuditService = Depends(get_audit_service),
) -> EngagementResponse:
    """Create a new engagement."""
    engagement_id = new_id()
    now = utc_now()

    # Build and validate initial scope if provided
    scope = None
    if request.scope:
        if isinstance(request.scope, SetScopeRequest):
            scope_dict = request.scope.model_dump()
        else:
            scope_dict = request.scope

        includes_data = scope_dict.get("includes", {})
        excludes_data = scope_dict.get("excludes", {})
        raw_scope = ScopeDefinition(
            engagement_id=engagement_id,
            version=1,
            includes=ScopeTarget(**includes_data) if includes_data else ScopeTarget(),
            excludes=ScopeTarget(**excludes_data) if excludes_data else ScopeTarget(),
            notes=scope_dict.get("notes", ""),
        )
        try:
            validated_scope = validate_scope_definition(raw_scope)
            scope = await scope_repo.save_scope(validated_scope)
        except ScopeValidationError as e:
            raise ValidationError(str(e)) from e

    state = EngagementState(
        engagement_id=engagement_id,
        name=request.name,
        description=request.description,
        objective=request.objective,
        scope=scope,
        created_at=now,
        updated_at=now,
    )
    _engagements[engagement_id] = state

    # Persist Engagement in PostgreSQL if available
    if scope_repo._session_factory:
        try:
            eng_uuid = _safe_uuid(engagement_id)
            async with scope_repo._session_factory() as session, session.begin():
                db_eng = Engagement(
                    id=eng_uuid,
                    name=request.name,
                    description=request.description,
                    objective=request.objective,
                    status=state.status.value,
                    created_at=now,
                    updated_at=now,
                )
                session.add(db_eng)
        except Exception:
            pass

    await audit.record_action(
        event_type=AuditEventType.ENGAGEMENT_CREATED,
        actor="api",
        action="create_engagement",
        engagement_id=engagement_id,
        result_status="success",
    )

    return EngagementResponse.from_state(state)


@router.get("/{engagement_id}", response_model=EngagementResponse)
async def get_engagement(
    engagement_id: str,
    scope_repo: ScopeRepository = Depends(get_scope_repository),
) -> EngagementResponse:
    """Get engagement details by ID."""
    state = await _get_or_load_engagement(engagement_id, scope_repo)
    if not state:
        raise NotFoundError("Engagement", engagement_id)
    return EngagementResponse.from_state(state)


@router.post("/{engagement_id}/scope", response_model=ScopeResponse)
async def set_engagement_scope(
    engagement_id: str,
    request: SetScopeRequest,
    scope_repo: ScopeRepository = Depends(get_scope_repository),
    approval_manager: ApprovalManager = Depends(get_approval_manager),
    audit: AuditService = Depends(get_audit_service),
) -> ScopeResponse:
    """Create or replace the authoritative scope for an engagement.

    Semantics: CREATE-OR-REPLACE (not merge).
    Allowed only in 'created' or 'paused' state.
    Rejected with 409 Conflict if active (running) or terminal.
    If 'paused', mutating scope atomically invalidates all active approvals.
    """
    state = await _get_or_load_engagement(engagement_id, scope_repo)
    if not state:
        raise NotFoundError("Engagement", engagement_id)

    if state.status == EngagementStatus.ACTIVE:
        raise ConflictError(
            "Cannot modify scope of an active engagement. Pause the engagement first."
        )
    if state.status in (
        EngagementStatus.COMPLETED,
        EngagementStatus.STOPPED,
        EngagementStatus.FAILED,
    ):
        raise ConflictError(
            f"Cannot modify scope of an engagement in terminal state '{state.status.value}'."
        )

    # Build and validate ScopeDefinition
    try:
        raw_includes = ScopeTarget(**request.includes.model_dump())
        raw_excludes = (
            ScopeTarget(**request.excludes.model_dump()) if request.excludes else ScopeTarget()
        )
        current_scope = await scope_repo.get_scope(engagement_id) or state.scope
        scope_def = ScopeDefinition(
            scope_id=current_scope.scope_id if current_scope else new_id(),
            engagement_id=engagement_id,
            version=current_scope.version if current_scope else 1,
            includes=raw_includes,
            excludes=raw_excludes,
            notes=request.notes,
        )
        validated_scope = validate_scope_definition(scope_def)
    except ScopeValidationError as e:
        raise ValidationError(str(e)) from e

    # Persist atomically via ScopeRepository
    try:
        invalidate_approvals = state.status == EngagementStatus.PAUSED
        saved_scope = await scope_repo.save_scope(
            scope=validated_scope,
            expected_version=request.expected_version,
            invalidate_approvals=invalidate_approvals,
            approval_manager=approval_manager,
        )
    except ScopeConflictError as e:
        raise ConflictError(str(e)) from e

    # Synchronize in-memory state
    state.scope = saved_scope
    state.updated_at = utc_now()

    # Emit audit event
    await audit.record_action(
        event_type=AuditEventType.SCOPE_VALIDATED,
        actor="api",
        action="set_scope",
        engagement_id=engagement_id,
        parameters={
            "scope_id": saved_scope.scope_id,
            "version": saved_scope.version,
            "included_domains": saved_scope.includes.domains,
            "included_ips": saved_scope.includes.ip_addresses,
            "included_cidrs": saved_scope.includes.cidrs,
            "included_urls": saved_scope.includes.urls,
            "included_ports": saved_scope.includes.ports,
            "included_port_ranges": saved_scope.includes.port_ranges,
            "approvals_invalidated": invalidate_approvals,
        },
        result_status="success",
    )

    return ScopeResponse.from_definition(saved_scope)


@router.get("/{engagement_id}/scope", response_model=ScopeResponse)
async def get_engagement_scope(
    engagement_id: str,
    scope_repo: ScopeRepository = Depends(get_scope_repository),
) -> ScopeResponse:
    """Get the authoritative scope for an engagement."""
    state = await _get_or_load_engagement(engagement_id, scope_repo)
    if not state:
        raise NotFoundError("Engagement", engagement_id)

    scope = await scope_repo.get_scope(engagement_id) or state.scope
    if not scope:
        raise NotFoundError("Scope definition", engagement_id)

    return ScopeResponse.from_definition(scope)


@router.post("/{engagement_id}/start", response_model=EngagementResponse)
async def start_engagement(
    engagement_id: str,
    scope_repo: ScopeRepository = Depends(get_scope_repository),
    audit: AuditService = Depends(get_audit_service),
) -> EngagementResponse:
    """Start an engagement."""
    state = await _get_or_load_engagement(engagement_id, scope_repo)
    if not state:
        raise NotFoundError("Engagement", engagement_id)

    if state.status not in (EngagementStatus.CREATED, EngagementStatus.PAUSED):
        raise ConflictError(
            f"Cannot start engagement in '{state.status.value}' state. "
            f"Must be 'created' or 'paused'."
        )

    if not state.scope:
        state.scope = await scope_repo.get_scope(engagement_id)

    if not state.scope:
        raise ConflictError("Cannot start engagement without a scope definition.")

    state.status = EngagementStatus.ACTIVE
    state.started_at = utc_now()
    state.updated_at = utc_now()

    # Sync status to PostgreSQL
    if scope_repo._session_factory:
        try:
            eng_uuid = _safe_uuid(engagement_id)
            async with scope_repo._session_factory() as session, session.begin():
                await session.execute(
                    update(Engagement)
                    .where(Engagement.id == eng_uuid)
                    .values(
                        status=state.status.value,
                        started_at=state.started_at,
                        updated_at=state.updated_at,
                    )
                )
        except Exception:
            pass

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
    scope_repo: ScopeRepository = Depends(get_scope_repository),
    audit: AuditService = Depends(get_audit_service),
) -> EngagementResponse:
    """Pause an active engagement."""
    state = await _get_or_load_engagement(engagement_id, scope_repo)
    if not state:
        raise NotFoundError("Engagement", engagement_id)

    if state.status != EngagementStatus.ACTIVE:
        raise ConflictError(
            f"Cannot pause engagement in '{state.status.value}' state. Must be 'active'."
        )

    state.status = EngagementStatus.PAUSED
    state.updated_at = utc_now()

    if scope_repo._session_factory:
        try:
            eng_uuid = _safe_uuid(engagement_id)
            async with scope_repo._session_factory() as session, session.begin():
                await session.execute(
                    update(Engagement)
                    .where(Engagement.id == eng_uuid)
                    .values(status=state.status.value, updated_at=state.updated_at)
                )
        except Exception:
            pass

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
    scope_repo: ScopeRepository = Depends(get_scope_repository),
    audit: AuditService = Depends(get_audit_service),
) -> EngagementResponse:
    """Stop an engagement."""
    state = await _get_or_load_engagement(engagement_id, scope_repo)
    if not state:
        raise NotFoundError("Engagement", engagement_id)

    if state.status in (EngagementStatus.COMPLETED, EngagementStatus.STOPPED):
        raise ConflictError(f"Engagement is already in terminal state '{state.status.value}'.")

    state.status = EngagementStatus.STOPPED
    state.completed_at = utc_now()
    state.updated_at = utc_now()

    if scope_repo._session_factory:
        try:
            eng_uuid = _safe_uuid(engagement_id)
            async with scope_repo._session_factory() as session, session.begin():
                await session.execute(
                    update(Engagement)
                    .where(Engagement.id == eng_uuid)
                    .values(
                        status=state.status.value,
                        completed_at=state.completed_at,
                        updated_at=state.updated_at,
                    )
                )
        except Exception:
            pass

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
    """Get tasks for an engagement."""
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


class ReconRunRequest(BaseModel):
    objective: str = "Autonomous reconnaissance"
    max_iterations: int = 10


@router.post("/{engagement_id}/recon")
async def run_engagement_recon(
    engagement_id: str,
    request: ReconRunRequest | None = None,
    audit: AuditService = Depends(get_audit_service),
) -> dict:
    """Trigger autonomous reconnaissance on an authorized engagement."""
    state = _engagements.get(engagement_id)
    if not state:
        raise NotFoundError("Engagement", engagement_id)

    objective = request.objective if request else "Autonomous reconnaissance"
    await audit.record_action(
        event_type=AuditEventType.TASK_STARTED,
        actor="api",
        action="recon_triggered",
        engagement_id=engagement_id,
        parameters={"objective": objective},
        result_status="success",
    )

    return {
        "engagement_id": engagement_id,
        "status": "initiated",
        "objective": objective,
    }
