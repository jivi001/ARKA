"""Approvals API endpoints for human-in-the-loop control plane."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from arka.app.api.deps import get_approval_manager, get_audit_service
from arka.app.api.errors import NotFoundError, ValidationError
from arka.app.api.stream_bus import get_event_broadcaster
from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.state.models import ApprovalRequest, ApprovalStatus

logger = logging.getLogger(__name__)

router = APIRouter(tags=["approvals"])


class ApprovalResponse(BaseModel):
    """Authoritative representation of an approval request."""

    approval_id: str
    engagement_id: str
    task_id: str
    agent_id: str
    action: str
    target: str
    tool_name: str
    risk_level: str
    reason: str
    scope_version: int
    arguments_hash: str | None
    status: str
    requested_at: str
    decided_at: str | None
    decided_by: str | None
    rejection_reason: str | None
    correlation_id: str | None
    details: dict[str, Any]

    @classmethod
    def from_model(cls, req: ApprovalRequest) -> ApprovalResponse:
        arg_hash = req.arguments_hash or (req.details or {}).get("arguments_hash")
        return cls(
            approval_id=req.approval_id,
            engagement_id=req.engagement_id,
            task_id=req.task_id,
            agent_id=req.agent_id,
            action=req.action,
            target=req.target,
            tool_name=req.tool_name,
            risk_level=req.risk_level.value
            if hasattr(req.risk_level, "value")
            else str(req.risk_level),
            reason=req.reason,
            scope_version=req.scope_version,
            arguments_hash=arg_hash,
            status=req.status.value if hasattr(req.status, "value") else str(req.status),
            requested_at=req.requested_at.isoformat() if req.requested_at else "",
            decided_at=req.decided_at.isoformat() if req.decided_at else None,
            decided_by=req.decided_by,
            rejection_reason=req.rejection_reason,
            correlation_id=req.correlation_id,
            details=req.details or {},
        )


class ApprovalDecisionRequest(BaseModel):
    """Request payload to approve or reject a gated tool execution."""

    decision: str = Field(..., description="'GRANTED' or 'REJECTED'")
    decided_by: str = Field(default="operator", description="Identifier of human operator")
    reason: str = Field(default="", description="Reason for rejection or approval rationale")


@router.get("/approvals", response_model=list[ApprovalResponse])
async def list_approvals(
    engagement_id: str | None = Query(None, description="Optional engagement filter"),
    status_filter: str | None = Query(
        None, alias="status", description="Status filter: required, granted, rejected, expired"
    ),
    approval_manager: ApprovalManager = Depends(get_approval_manager),
) -> list[ApprovalResponse]:
    """List approval requests with optional status and engagement filtering."""
    all_reqs: list[ApprovalRequest] = []

    # Get cached and pending requests
    if status_filter == "required" or status_filter is None:
        all_reqs.extend(approval_manager.get_pending(engagement_id=engagement_id))

    # Also check full list from manager if status is different
    for req in list(approval_manager._requests.values()):
        if req not in all_reqs:
            if engagement_id and req.engagement_id != engagement_id:
                continue
            if status_filter:
                st_val = req.status.value if hasattr(req.status, "value") else str(req.status)
                if st_val.lower() != status_filter.lower():
                    continue
            all_reqs.append(req)

    return [ApprovalResponse.from_model(r) for r in all_reqs]


@router.get("/approvals/{approval_id}", response_model=ApprovalResponse)
async def get_approval(
    approval_id: str,
    approval_manager: ApprovalManager = Depends(get_approval_manager),
) -> ApprovalResponse:
    """Retrieve details of a single approval request."""
    req = await approval_manager.get_request_async(approval_id)
    if not req:
        raise NotFoundError("ApprovalRequest", approval_id)
    return ApprovalResponse.from_model(req)


@router.post("/approvals/{approval_id}/decide", response_model=ApprovalResponse)
async def decide_approval(
    approval_id: str,
    payload: ApprovalDecisionRequest,
    approval_manager: ApprovalManager = Depends(get_approval_manager),
    audit_service: AuditService = Depends(get_audit_service),
) -> ApprovalResponse:
    """Decide on a pending approval request (GRANTED or REJECTED)."""
    decision_clean = payload.decision.strip().upper()
    if decision_clean not in ("GRANTED", "REJECTED"):
        raise ValidationError(
            f"Invalid decision '{payload.decision}'. Must be GRANTED or REJECTED."
        )

    req = await approval_manager.get_request_async(approval_id)
    if not req:
        raise NotFoundError("ApprovalRequest", approval_id)

    if req.status != ApprovalStatus.REQUIRED:
        raise ValidationError(
            f"Approval is in state '{req.status.value}', only REQUIRED requests can be decided."
        )

    if decision_clean == "GRANTED":
        updated_req = approval_manager.approve(
            approval_id=approval_id,
            approved_by=payload.decided_by,
        )
    else:
        updated_req = approval_manager.reject(
            approval_id=approval_id,
            rejected_by=payload.decided_by,
            reason=payload.reason,
        )

    # Record security audit record
    await audit_service.record_action(
        event_type=AuditEventType.APPROVAL_DECISION,
        actor=payload.decided_by,
        action=f"approval_{decision_clean.lower()}",
        target=req.target,
        engagement_id=req.engagement_id,
        task_id=req.task_id,
        tool_name=req.tool_name,
        authorization_decision=decision_clean,
        parameters={
            "approval_id": approval_id,
            "decision": decision_clean,
            "reason": payload.reason,
            "arguments_hash": req.arguments_hash,
            "scope_version": req.scope_version,
        },
        result_status="success",
    )

    # Broadcast event over SSE
    broadcaster = get_event_broadcaster()
    broadcaster.broadcast_nowait(
        event_type="approval_decided",
        data={
            "approval_id": approval_id,
            "decision": decision_clean,
            "decided_by": payload.decided_by,
            "tool_name": req.tool_name,
            "target": req.target,
            "status": updated_req.status.value
            if hasattr(updated_req.status, "value")
            else str(updated_req.status),
        },
        engagement_id=req.engagement_id,
    )

    return ApprovalResponse.from_model(updated_req)
