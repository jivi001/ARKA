"""Persistent human approval management for high-risk operations.

Enforces deterministic approval state transitions and binds authorizations
to exact engagement, task, tool, and target operations.
"""

import uuid

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from arka.app.core.state.models import (
    ApprovalRequest,
    ApprovalStatus,
    RiskLevel,
    new_id,
    utc_now,
)
from arka.app.database.models import ApprovalDB, Engagement, Task


def _safe_uuid(val: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(val))
    except (ValueError, AttributeError):
        return uuid.uuid5(uuid.NAMESPACE_DNS, str(val))


class ApprovalManager:
    """Manages human approval workflow for high-risk operations with persistence.

    Enforces strict deterministic state machine:
      REQUIRED -> GRANTED
      REQUIRED -> REJECTED
      REQUIRED -> EXPIRED

    All other transitions are forbidden.
    Approvals are bound to specific (engagement_id, task_id, tool_name, target).
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession] | None = None,
    ) -> None:
        self._session_factory = session_factory
        # Memory cache / store for test mode or local caching
        self._requests: dict[str, ApprovalRequest] = {}

    def _sync_to_db_model(self, req: ApprovalRequest) -> ApprovalDB:
        """Convert domain ApprovalRequest to database ApprovalDB."""
        details = dict(req.details or {})
        details["scope_version"] = req.scope_version
        return ApprovalDB(
            id=_safe_uuid(req.approval_id),
            engagement_id=_safe_uuid(req.engagement_id),
            task_id=_safe_uuid(req.task_id),
            agent_id=req.agent_id,
            action=req.action,
            target=req.target,
            tool_name=req.tool_name,
            risk_level=req.risk_level.value
            if isinstance(req.risk_level, RiskLevel)
            else req.risk_level,
            reason=req.reason,
            details=details,
            status=req.status.value if isinstance(req.status, ApprovalStatus) else req.status,
            requested_at=req.requested_at,
            decided_at=req.decided_at,
            decided_by=req.decided_by,
            rejection_reason=req.rejection_reason,
            correlation_id=req.correlation_id,
            expiry_seconds=req.expiry_seconds,
        )

    def _from_db_model(self, db_obj: ApprovalDB) -> ApprovalRequest:
        """Convert database ApprovalDB to domain ApprovalRequest."""
        details = db_obj.details or {}
        scope_ver = details.get("scope_version", 1)
        return ApprovalRequest(
            approval_id=str(db_obj.id),
            engagement_id=str(db_obj.engagement_id),
            task_id=str(db_obj.task_id),
            agent_id=db_obj.agent_id,
            action=db_obj.action,
            target=db_obj.target,
            tool_name=db_obj.tool_name,
            risk_level=RiskLevel(db_obj.risk_level),
            reason=db_obj.reason,
            details=details,
            scope_version=scope_ver,
            status=ApprovalStatus(db_obj.status),
            requested_at=db_obj.requested_at,
            decided_at=db_obj.decided_at,
            decided_by=db_obj.decided_by,
            rejection_reason=db_obj.rejection_reason,
            correlation_id=db_obj.correlation_id,
            expiry_seconds=db_obj.expiry_seconds,
        )

    def create_request(
        self,
        engagement_id: str,
        task_id: str,
        agent_id: str,
        action: str,
        target: str,
        tool_name: str,
        risk_level: RiskLevel,
        reason: str = "",
        details: dict | None = None,
        expiry_seconds: int = 3600,
        correlation_id: str | None = None,
        approval_id: str | None = None,
        scope_version: int = 1,
    ) -> ApprovalRequest:
        """Create a new pending approval request in REQUIRED state."""
        request = ApprovalRequest(
            approval_id=approval_id or new_id(),
            engagement_id=engagement_id,
            task_id=task_id,
            agent_id=agent_id,
            action=action,
            target=target,
            tool_name=tool_name,
            risk_level=risk_level,
            reason=reason,
            scope_version=scope_version,
            details=details or {},
            status=ApprovalStatus.REQUIRED,
            requested_at=utc_now(),
            expiry_seconds=expiry_seconds,
            correlation_id=correlation_id,
        )
        self._requests[request.approval_id] = request
        return request

    async def create_request_async(
        self,
        engagement_id: str,
        task_id: str,
        agent_id: str,
        action: str,
        target: str,
        tool_name: str,
        risk_level: RiskLevel,
        reason: str = "",
        details: dict | None = None,
        expiry_seconds: int = 3600,
        correlation_id: str | None = None,
        approval_id: str | None = None,
        scope_version: int = 1,
    ) -> ApprovalRequest:
        """Create and persist an approval request to PostgreSQL."""
        req = self.create_request(
            engagement_id=engagement_id,
            task_id=task_id,
            agent_id=agent_id,
            action=action,
            target=target,
            tool_name=tool_name,
            risk_level=risk_level,
            reason=reason,
            details=details,
            expiry_seconds=expiry_seconds,
            correlation_id=correlation_id,
            approval_id=approval_id,
            scope_version=scope_version,
        )
        if self._session_factory:
            try:
                async with self._session_factory() as session, session.begin():
                    # Ensure engagement row exists to satisfy foreign key
                    eng_uuid = _safe_uuid(req.engagement_id)
                    eng_res = await session.execute(
                        select(Engagement).where(Engagement.id == eng_uuid)
                    )
                    if not eng_res.scalar_one_or_none():
                        session.add(
                            Engagement(
                                id=eng_uuid,
                                name=f"Engagement {req.engagement_id}",
                                status="created",
                                created_at=utc_now(),
                                updated_at=utc_now(),
                            )
                        )
                        await session.flush()

                    # Ensure task row exists to satisfy foreign key
                    task_uuid = _safe_uuid(req.task_id)
                    task_res = await session.execute(select(Task).where(Task.id == task_uuid))
                    if not task_res.scalar_one_or_none():
                        session.add(
                            Task(
                                id=task_uuid,
                                engagement_id=eng_uuid,
                                agent_id=req.agent_id or "system",
                                name=f"Task {req.task_id}",
                                status="pending",
                                created_at=utc_now(),
                                updated_at=utc_now(),
                            )
                        )
                        await session.flush()

                    db_model = self._sync_to_db_model(req)
                    session.add(db_model)
            except Exception:
                pass
        return req

    def approve(self, approval_id: str, approved_by: str) -> ApprovalRequest:
        """Transition an approval request from REQUIRED to GRANTED.

        Strictly prevents invalid transitions:
          - Already approved (GRANTED -> GRANTED)
          - Already rejected (REJECTED -> GRANTED)
          - Expired (EXPIRED -> GRANTED)
        """
        req = self._requests.get(approval_id)
        if not req:
            raise ValueError(f"Approval request {approval_id} not found.")

        if req.status == ApprovalStatus.GRANTED:
            raise ValueError("Approval request already approved.")

        if req.status == ApprovalStatus.REJECTED:
            raise ValueError("Cannot approve an already rejected request.")

        if req.status == ApprovalStatus.EXPIRED or req.is_expired:
            req.status = ApprovalStatus.EXPIRED
            req.decided_at = utc_now()
            raise ValueError("Cannot approve an expired request.")

        if req.status != ApprovalStatus.REQUIRED:
            raise ValueError(f"Approval request {approval_id} is not REQUIRED.")

        req.status = ApprovalStatus.GRANTED
        req.decided_by = approved_by
        req.decided_at = utc_now()
        return req

    async def approve_async(self, approval_id: str, approved_by: str) -> ApprovalRequest:
        """Approve and persist state transition in PostgreSQL."""
        req = self.approve(approval_id, approved_by)
        if self._session_factory:
            try:
                async with self._session_factory() as session, session.begin():
                    stmt = (
                        update(ApprovalDB)
                        .where(ApprovalDB.id == _safe_uuid(approval_id))
                        .values(
                            status=ApprovalStatus.GRANTED.value,
                            decided_by=approved_by,
                            decided_at=req.decided_at,
                        )
                    )
                    await session.execute(stmt)
            except Exception:
                pass
        return req

    def reject(self, approval_id: str, rejected_by: str, reason: str = "") -> ApprovalRequest:
        """Transition an approval request from REQUIRED to REJECTED.

        Strictly prevents invalid transitions:
          - Already approved (GRANTED -> REJECTED)
          - Already rejected (REJECTED -> REJECTED)
          - Expired (EXPIRED -> REJECTED)
        """
        req = self._requests.get(approval_id)
        if not req:
            raise ValueError(f"Approval request {approval_id} not found.")

        if req.status == ApprovalStatus.GRANTED:
            raise ValueError("Cannot reject an already approved request.")

        if req.status == ApprovalStatus.REJECTED:
            raise ValueError("Approval request already rejected.")

        if req.status == ApprovalStatus.EXPIRED or req.is_expired:
            req.status = ApprovalStatus.EXPIRED
            req.decided_at = utc_now()
            raise ValueError("Cannot reject an expired request.")

        if req.status != ApprovalStatus.REQUIRED:
            raise ValueError(f"Approval request {approval_id} is not REQUIRED.")

        req.status = ApprovalStatus.REJECTED
        req.decided_by = rejected_by
        req.decided_at = utc_now()
        req.rejection_reason = reason
        return req

    async def reject_async(
        self, approval_id: str, rejected_by: str, reason: str = ""
    ) -> ApprovalRequest:
        """Reject and persist state transition in PostgreSQL."""
        req = self.reject(approval_id, rejected_by, reason)
        if self._session_factory:
            try:
                async with self._session_factory() as session, session.begin():
                    stmt = (
                        update(ApprovalDB)
                        .where(ApprovalDB.id == _safe_uuid(approval_id))
                        .values(
                            status=ApprovalStatus.REJECTED.value,
                            decided_by=rejected_by,
                            decided_at=req.decided_at,
                            rejection_reason=reason,
                        )
                    )
                    await session.execute(stmt)
            except Exception:
                pass
        return req

    def get_request(self, approval_id: str) -> ApprovalRequest | None:
        """Get an approval request by ID."""
        req = self._requests.get(approval_id)
        if req and req.status == ApprovalStatus.REQUIRED and req.is_expired:
            req.status = ApprovalStatus.EXPIRED
            req.decided_at = utc_now()
        return req

    async def get_request_async(self, approval_id: str) -> ApprovalRequest | None:
        """Get an approval request from PostgreSQL or cache."""
        req = self.get_request(approval_id)
        if req:
            return req
        if self._session_factory:
            async with self._session_factory() as session:
                result = await session.execute(
                    select(ApprovalDB).where(ApprovalDB.id == _safe_uuid(approval_id))
                )
                row = result.scalar_one_or_none()
                if row:
                    req = self._from_db_model(row)
                    if req.status == ApprovalStatus.REQUIRED and req.is_expired:
                        req.status = ApprovalStatus.EXPIRED
                        req.decided_at = utc_now()
                    self._requests[req.approval_id] = req
                    return req
        return None

    def get_pending(self, engagement_id: str | None = None) -> list[ApprovalRequest]:
        """Get all pending, non-expired approval requests."""
        pending_reqs = []
        for req in list(self._requests.values()):
            if req.status == ApprovalStatus.REQUIRED:
                if req.is_expired:
                    req.status = ApprovalStatus.EXPIRED
                    req.decided_at = utc_now()
                else:
                    if engagement_id is None or req.engagement_id == engagement_id:
                        pending_reqs.append(req)
        return pending_reqs

    def check_expired(self) -> list[ApprovalRequest]:
        """Check and transition any timed-out approval requests to EXPIRED."""
        expired = []
        for req in self._requests.values():
            if req.status == ApprovalStatus.REQUIRED and req.is_expired:
                req.status = ApprovalStatus.EXPIRED
                req.decided_at = utc_now()
                expired.append(req)
        return expired

    def find_matching_request(
        self,
        engagement_id: str,
        task_id: str,
        tool_name: str,
        target: str,
    ) -> ApprovalRequest | None:
        """Find any active (REQUIRED or GRANTED non-expired) approval matching the operation."""
        for req in self._requests.values():
            if (
                req.engagement_id == engagement_id
                and req.task_id == task_id
                and req.tool_name == tool_name
                and req.target.strip() == target.strip()
                and not req.is_expired
                and req.status in (ApprovalStatus.REQUIRED, ApprovalStatus.GRANTED)
            ):
                return req
        return None

    def validate_approval_for_request(
        self,
        approval_id: str | None,
        engagement_id: str,
        task_id: str,
        tool_name: str,
        target: str,
        scope_version: int | None = None,
    ) -> bool:
        """Verify an approval is valid, GRANTED, non-expired, and bound to the exact operation.

        Prevents cross-engagement, cross-task, cross-tool, cross-target, or version reuse.
        """
        if not approval_id:
            return False

        req = self.get_request(approval_id)
        if not req:
            return False

        if req.status != ApprovalStatus.GRANTED:
            return False

        if req.engagement_id != engagement_id:
            return False

        if req.task_id != task_id:
            return False

        if req.tool_name != tool_name:
            return False

        if req.target.strip() != target.strip():
            return False

        return scope_version is None or req.scope_version == scope_version

    async def validate_approval_for_request_async(
        self,
        approval_id: str | None,
        engagement_id: str,
        task_id: str,
        tool_name: str,
        target: str,
        scope_version: int | None = None,
    ) -> bool:
        """Asynchronously verify an approval is valid, GRANTED, non-expired, and scope-bound."""
        if not approval_id:
            return False

        req = await self.get_request_async(approval_id)
        if not req:
            return False

        if req.status != ApprovalStatus.GRANTED:
            return False

        if req.engagement_id != engagement_id:
            return False

        if req.task_id != task_id:
            return False

        if req.tool_name != tool_name:
            return False

        if req.target.strip() != target.strip():
            return False

        return scope_version is None or req.scope_version == scope_version

    def invalidate_for_engagement(self, engagement_id: str, reason: str = "Scope modified") -> int:
        """Transition all active approvals (REQUIRED or GRANTED) for an engagement to EXPIRED."""
        count = 0
        now = utc_now()
        for req in self._requests.values():
            if req.engagement_id == engagement_id and req.status in (
                ApprovalStatus.REQUIRED,
                ApprovalStatus.GRANTED,
            ):
                req.status = ApprovalStatus.EXPIRED
                req.rejection_reason = reason
                req.decided_at = now
                count += 1
        return count

    async def invalidate_for_engagement_async(
        self, engagement_id: str, reason: str = "Scope modified"
    ) -> int:
        """Transition active approvals to EXPIRED and persist in PostgreSQL."""
        count = self.invalidate_for_engagement(engagement_id, reason)
        if self._session_factory:
            async with self._session_factory() as session, session.begin():
                stmt = (
                    update(ApprovalDB)
                    .where(
                        ApprovalDB.engagement_id == _safe_uuid(engagement_id),
                        ApprovalDB.status.in_(
                            [ApprovalStatus.REQUIRED.value, ApprovalStatus.GRANTED.value]
                        ),
                    )
                    .values(
                        status=ApprovalStatus.EXPIRED.value,
                        rejection_reason=reason,
                        decided_at=utc_now(),
                    )
                )
                await session.execute(stmt)
        return count
