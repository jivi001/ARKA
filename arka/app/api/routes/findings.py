"""Findings API endpoints with 5-stage epistemic lifecycle and human confirmation."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from arka.app.api.deps import get_audit_service
from arka.app.api.errors import NotFoundError
from arka.app.api.stream_bus import get_event_broadcaster
from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.database.models import FindingDB
from arka.app.database.session import get_session_factory

logger = logging.getLogger(__name__)

router = APIRouter(tags=["findings"])

# In-memory store for fallback/testing
_memory_findings: dict[str, dict[str, Any]] = {}


class FindingResponse(BaseModel):
    """Authoritative representation of a security finding in the epistemic ladder."""

    finding_id: str
    engagement_id: str
    title: str
    description: str
    severity: str
    lifecycle_stage: str
    confidence: float
    target: str
    check_type: str
    asset_id: str | None = None
    endpoint_id: str | None = None
    detection_sources: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    llm_reasoning: str | None = None
    validation_method: str | None = None
    validation_details: dict[str, Any] = Field(default_factory=dict)
    human_confirmed_by: str | None = None
    human_confirmed_at: str | None = None
    remediation: str | None = None
    created_at: str
    updated_at: str


class CreateFindingRequest(BaseModel):
    """Payload to record a new security observation or candidate finding."""

    title: str
    description: str = ""
    severity: str = "medium"
    lifecycle_stage: str = "OBSERVED"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    target: str
    check_type: str = "generic"
    asset_id: str | None = None
    endpoint_id: str | None = None
    detection_sources: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    llm_reasoning: str | None = None
    remediation: str | None = None


class ConfirmFindingRequest(BaseModel):
    """Human operator confirmation payload."""

    confirmed_by: str = Field(..., description="Identifier of human operator confirming finding")
    notes: str = Field(default="", description="Operator confirmation notes or validation summary")


@router.get("/engagements/{engagement_id}/findings", response_model=list[FindingResponse])
async def list_engagement_findings(
    engagement_id: str,
    severity: str | None = Query(
        None, description="Filter by severity: info, low, medium, high, critical"
    ),
    stage: str | None = Query(
        None, alias="lifecycle_stage", description="Filter by epistemic stage"
    ),
) -> list[FindingResponse]:
    """List all findings for an engagement across the 5-stage epistemic lifecycle."""
    results: list[FindingResponse] = []

    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            eng_uuid = uuid.UUID(engagement_id)
            query = select(FindingDB).where(FindingDB.engagement_id == eng_uuid)
            if severity:
                query = query.where(FindingDB.severity == severity.lower())
            if stage:
                query = query.where(FindingDB.lifecycle_stage == stage.upper())

            db_rows = (await session.execute(query)).scalars().all()
            for row in db_rows:
                results.append(
                    FindingResponse(
                        finding_id=str(row.id),
                        engagement_id=str(row.engagement_id),
                        title=row.title,
                        description=row.description,
                        severity=row.severity,
                        lifecycle_stage=row.lifecycle_stage,
                        confidence=row.confidence,
                        target=row.target,
                        check_type=row.check_type,
                        asset_id=str(row.asset_id) if row.asset_id else None,
                        endpoint_id=str(row.endpoint_id) if row.endpoint_id else None,
                        detection_sources=row.detection_sources or [],
                        evidence_refs=row.evidence_refs or [],
                        llm_reasoning=row.llm_reasoning,
                        validation_method=row.validation_method,
                        validation_details=row.validation_details or {},
                        human_confirmed_by=row.human_confirmed_by,
                        human_confirmed_at=row.human_confirmed_at.isoformat()
                        if row.human_confirmed_at
                        else None,
                        remediation=row.remediation,
                        created_at=row.created_at.isoformat() if row.created_at else "",
                        updated_at=row.updated_at.isoformat() if row.updated_at else "",
                    )
                )
    except Exception:
        # Fallback to in-memory store
        for f in _memory_findings.values():
            if f.get("engagement_id") == engagement_id:
                if severity and f.get("severity", "").lower() != severity.lower():
                    continue
                if stage and f.get("lifecycle_stage", "").upper() != stage.upper():
                    continue
                results.append(FindingResponse(**f))

    return results


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str) -> FindingResponse:
    """Retrieve details of a single finding."""
    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            f_uuid = uuid.UUID(finding_id)
            row = (
                await session.execute(select(FindingDB).where(FindingDB.id == f_uuid))
            ).scalar_one_or_none()
            if row:
                return FindingResponse(
                    finding_id=str(row.id),
                    engagement_id=str(row.engagement_id),
                    title=row.title,
                    description=row.description,
                    severity=row.severity,
                    lifecycle_stage=row.lifecycle_stage,
                    confidence=row.confidence,
                    target=row.target,
                    check_type=row.check_type,
                    asset_id=str(row.asset_id) if row.asset_id else None,
                    endpoint_id=str(row.endpoint_id) if row.endpoint_id else None,
                    detection_sources=row.detection_sources or [],
                    evidence_refs=row.evidence_refs or [],
                    llm_reasoning=row.llm_reasoning,
                    validation_method=row.validation_method,
                    validation_details=row.validation_details or {},
                    human_confirmed_by=row.human_confirmed_by,
                    human_confirmed_at=row.human_confirmed_at.isoformat()
                    if row.human_confirmed_at
                    else None,
                    remediation=row.remediation,
                    created_at=row.created_at.isoformat() if row.created_at else "",
                    updated_at=row.updated_at.isoformat() if row.updated_at else "",
                )
    except Exception:
        pass

    if finding_id in _memory_findings:
        return FindingResponse(**_memory_findings[finding_id])

    raise NotFoundError("Finding", finding_id)


@router.post("/findings/{finding_id}/confirm", response_model=FindingResponse)
async def confirm_finding(
    finding_id: str,
    payload: ConfirmFindingRequest,
    audit_service: AuditService = Depends(get_audit_service),
) -> FindingResponse:
    """Promote a finding to HUMAN_CONFIRMED status.

    Only human operators may transition a finding into this status.
    The LLM has ZERO authority to perform this transition.
    """
    now = datetime.now(UTC)
    confirmed_data: dict[str, Any] | None = None

    try:
        session_factory = get_session_factory()
        async with session_factory() as session, session.begin():
            f_uuid = uuid.UUID(finding_id)
            row = (
                await session.execute(select(FindingDB).where(FindingDB.id == f_uuid))
            ).scalar_one_or_none()
            if not row:
                raise NotFoundError("Finding", finding_id)

            row.lifecycle_stage = "HUMAN_CONFIRMED"
            row.human_confirmed_by = payload.confirmed_by
            row.human_confirmed_at = now
            if payload.notes:
                details = dict(row.validation_details or {})
                details["operator_notes"] = payload.notes
                row.validation_details = details

            confirmed_data = {
                "finding_id": str(row.id),
                "engagement_id": str(row.engagement_id),
                "title": row.title,
                "description": row.description,
                "severity": row.severity,
                "lifecycle_stage": row.lifecycle_stage,
                "confidence": row.confidence,
                "target": row.target,
                "check_type": row.check_type,
                "asset_id": str(row.asset_id) if row.asset_id else None,
                "endpoint_id": str(row.endpoint_id) if row.endpoint_id else None,
                "detection_sources": row.detection_sources or [],
                "evidence_refs": row.evidence_refs or [],
                "llm_reasoning": row.llm_reasoning,
                "validation_method": row.validation_method,
                "validation_details": row.validation_details or {},
                "human_confirmed_by": row.human_confirmed_by,
                "human_confirmed_at": now.isoformat(),
                "remediation": row.remediation,
                "created_at": row.created_at.isoformat() if row.created_at else "",
                "updated_at": now.isoformat(),
            }
    except NotFoundError:
        raise
    except Exception:
        if finding_id not in _memory_findings:
            raise NotFoundError("Finding", finding_id) from None
        f = _memory_findings[finding_id]
        f["lifecycle_stage"] = "HUMAN_CONFIRMED"
        f["human_confirmed_by"] = payload.confirmed_by
        f["human_confirmed_at"] = now.isoformat()
        if payload.notes:
            f.setdefault("validation_details", {})["operator_notes"] = payload.notes
        confirmed_data = f

    # Record audit log
    await audit_service.record_action(
        event_type=AuditEventType.FINDING_RECORDED,
        actor=payload.confirmed_by,
        action="human_confirm_finding",
        target=confirmed_data["target"] if confirmed_data else finding_id,
        engagement_id=confirmed_data.get("engagement_id"),
        parameters={
            "finding_id": finding_id,
            "lifecycle_stage": "HUMAN_CONFIRMED",
            "notes": payload.notes,
        },
        result_status="success",
    )

    # Broadcast event
    broadcaster = get_event_broadcaster()
    broadcaster.broadcast_nowait(
        event_type="finding_confirmed",
        data={
            "finding_id": finding_id,
            "lifecycle_stage": "HUMAN_CONFIRMED",
            "confirmed_by": payload.confirmed_by,
        },
        engagement_id=confirmed_data.get("engagement_id"),
    )

    assert confirmed_data is not None
    return FindingResponse(**confirmed_data)


@router.post(
    "/engagements/{engagement_id}/findings",
    response_model=FindingResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_finding(
    engagement_id: str,
    payload: CreateFindingRequest,
    audit_service: AuditService = Depends(get_audit_service),
) -> FindingResponse:
    """Record a new finding in the epistemic ladder."""
    # Deterministic guardrail: automated/untrusted calls cannot create finding
    # as VALIDATED or HUMAN_CONFIRMED
    stage = payload.lifecycle_stage.upper()
    if stage in ("VALIDATED", "HUMAN_CONFIRMED"):
        stage = "CANDIDATE"

    finding_id = str(uuid.uuid4())
    now = datetime.now(UTC)

    finding_dict = {
        "finding_id": finding_id,
        "engagement_id": engagement_id,
        "title": payload.title,
        "description": payload.description,
        "severity": payload.severity.lower(),
        "lifecycle_stage": stage,
        "confidence": payload.confidence,
        "target": payload.target,
        "check_type": payload.check_type,
        "asset_id": payload.asset_id,
        "endpoint_id": payload.endpoint_id,
        "detection_sources": payload.detection_sources,
        "evidence_refs": payload.evidence_refs,
        "llm_reasoning": payload.llm_reasoning,
        "validation_method": None,
        "validation_details": {},
        "human_confirmed_by": None,
        "human_confirmed_at": None,
        "remediation": payload.remediation,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }

    try:
        session_factory = get_session_factory()
        async with session_factory() as session, session.begin():
            row = FindingDB(
                id=uuid.UUID(finding_id),
                engagement_id=uuid.UUID(engagement_id),
                title=payload.title,
                description=payload.description,
                severity=payload.severity.lower(),
                lifecycle_stage=stage,
                confidence=payload.confidence,
                target=payload.target,
                check_type=payload.check_type,
                asset_id=uuid.UUID(payload.asset_id) if payload.asset_id else None,
                endpoint_id=uuid.UUID(payload.endpoint_id) if payload.endpoint_id else None,
                detection_sources=payload.detection_sources,
                evidence_refs=payload.evidence_refs,
                llm_reasoning=payload.llm_reasoning,
                remediation=payload.remediation,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
    except Exception:
        pass

    _memory_findings[finding_id] = finding_dict

    broadcaster = get_event_broadcaster()
    broadcaster.broadcast_nowait(
        event_type="finding_created",
        data={
            "finding_id": finding_id,
            "title": payload.title,
            "severity": payload.severity,
            "lifecycle_stage": stage,
            "target": payload.target,
        },
        engagement_id=engagement_id,
    )

    return FindingResponse(**finding_dict)
