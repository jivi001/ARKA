from datetime import datetime, timezone, timedelta
from typing import Optional

from arka.app.core.state.models import ApprovalRequest, ApprovalStatus, RiskLevel, new_id, utc_now


class ApprovalManager:
    """Manages human approval workflow for high-risk operations."""

    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}

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
    ) -> ApprovalRequest:
        request = ApprovalRequest(
            approval_id=new_id(),
            engagement_id=engagement_id,
            task_id=task_id,
            agent_id=agent_id,
            action=action,
            target=target,
            tool_name=tool_name,
            risk_level=risk_level,
            reason=reason,
            details=details or {},
            status=ApprovalStatus.REQUIRED,
            requested_at=utc_now(),
            expiry_seconds=expiry_seconds,
        )
        self._requests[request.approval_id] = request
        return request

    def approve(self, approval_id: str, approved_by: str) -> ApprovalRequest:
        req = self._requests.get(approval_id)
        if not req:
            raise ValueError(f"Approval request {approval_id} not found.")

        if req.status != ApprovalStatus.REQUIRED:
            raise ValueError(f"Approval request {approval_id} is not REQUIRED.")

        req.status = ApprovalStatus.GRANTED
        req.decided_by = approved_by
        req.decided_at = utc_now()
        return req

    def reject(self, approval_id: str, rejected_by: str, reason: str = "") -> ApprovalRequest:
        req = self._requests.get(approval_id)
        if not req:
            raise ValueError(f"Approval request {approval_id} not found.")

        if req.status != ApprovalStatus.REQUIRED:
            raise ValueError(f"Approval request {approval_id} is not REQUIRED.")

        req.status = ApprovalStatus.REJECTED
        req.decided_by = rejected_by
        req.decided_at = utc_now()
        if reason:
            req.reason = reason
        return req

    def get_request(self, approval_id: str) -> Optional[ApprovalRequest]:
        return self._requests.get(approval_id)

    def get_pending(self, engagement_id: Optional[str] = None) -> list[ApprovalRequest]:
        pending_reqs = []
        for req in self._requests.values():
            if req.status == ApprovalStatus.REQUIRED and not req.is_expired:
                if engagement_id is None or req.engagement_id == engagement_id:
                    pending_reqs.append(req)
        return pending_reqs

    def check_expired(self) -> list[ApprovalRequest]:
        """Check and expire any timed-out approval requests."""
        expired = []
        for req in self._requests.values():
            if req.status == ApprovalStatus.REQUIRED and req.is_expired:
                req.status = ApprovalStatus.EXPIRED
                req.decided_at = utc_now()
                expired.append(req)
        return expired
