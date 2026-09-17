"""Policy decisions and Tool Execution audit endpoints."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import select

from arka.app.database.models import PolicyDecisionDB, ToolRun
from arka.app.database.session import get_session_factory

logger = logging.getLogger(__name__)

router = APIRouter(tags=["policy-decisions"])


class PolicyDecisionResponse(BaseModel):
    """Authoritative record of a deterministic policy evaluation."""

    decision_id: str
    engagement_id: str
    task_id: str
    agent_id: str
    action: str
    target: str
    tool_name: str | None
    decision: str
    reason: str
    risk_level: str
    requires_approval: bool
    decided_at: str


class ToolRunResponse(BaseModel):
    """Record of a tool execution in the sandbox/runtime."""

    run_id: str
    request_id: str
    engagement_id: str
    task_id: str
    tool_name: str
    target: str | None
    arguments: dict[str, Any]
    success: bool
    error: str | None
    execution_time_ms: int
    executed_at: str
    completed_at: str | None


@router.get(
    "/engagements/{engagement_id}/policy-decisions",
    response_model=list[PolicyDecisionResponse],
)
async def list_policy_decisions(engagement_id: str) -> list[PolicyDecisionResponse]:
    """List historical policy evaluation decisions for an engagement."""
    results: list[PolicyDecisionResponse] = []

    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            eng_uuid = uuid.UUID(engagement_id)
            rows = (
                (
                    await session.execute(
                        select(PolicyDecisionDB)
                        .where(PolicyDecisionDB.engagement_id == eng_uuid)
                        .order_by(PolicyDecisionDB.decided_at.desc())
                        .limit(100)
                    )
                )
                .scalars()
                .all()
            )

            for r in rows:
                results.append(
                    PolicyDecisionResponse(
                        decision_id=str(r.id),
                        engagement_id=str(r.engagement_id),
                        task_id=str(r.task_id),
                        agent_id=r.agent_id,
                        action=r.action,
                        target=r.target,
                        tool_name=r.tool_name,
                        decision=r.decision,
                        reason=r.reason,
                        risk_level=r.risk_level,
                        requires_approval=r.requires_approval,
                        decided_at=r.decided_at.isoformat() if r.decided_at else "",
                    )
                )
    except Exception:
        pass

    return results


@router.get(
    "/engagements/{engagement_id}/tool-requests",
    response_model=list[ToolRunResponse],
)
async def list_tool_requests(engagement_id: str) -> list[ToolRunResponse]:
    """List tool execution history for an engagement."""
    results: list[ToolRunResponse] = []

    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            eng_uuid = uuid.UUID(engagement_id)
            rows = (
                (
                    await session.execute(
                        select(ToolRun)
                        .where(ToolRun.engagement_id == eng_uuid)
                        .order_by(ToolRun.executed_at.desc())
                        .limit(100)
                    )
                )
                .scalars()
                .all()
            )

            for r in rows:
                results.append(
                    ToolRunResponse(
                        run_id=str(r.id),
                        request_id=r.request_id,
                        engagement_id=str(r.engagement_id),
                        task_id=str(r.task_id),
                        tool_name=r.tool_name,
                        target=r.target,
                        arguments=r.arguments or {},
                        success=r.success,
                        error=r.error,
                        execution_time_ms=r.execution_time_ms,
                        executed_at=r.executed_at.isoformat() if r.executed_at else "",
                        completed_at=r.completed_at.isoformat() if r.completed_at else None,
                    )
                )
    except Exception:
        pass

    return results
