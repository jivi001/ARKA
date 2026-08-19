import pytest

from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.state.models import ApprovalStatus, RiskLevel


@pytest.fixture
def approval_manager():
    return ApprovalManager()


class TestApprovalManager:
    def test_create_request(self, approval_manager: ApprovalManager):
        req = approval_manager.create_request(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            action="run-tool",
            target="example.com",
            tool_name="nmap",
            risk_level=RiskLevel.HIGH,
            details={"ports": "80,443"},
        )
        assert req.approval_id is not None
        fetched = approval_manager.get_request(req.approval_id)
        assert fetched is not None
        assert fetched.status == ApprovalStatus.REQUIRED
        assert fetched.engagement_id == "eng-1"
        assert fetched.details == {"ports": "80,443"}

    def test_approve(self, approval_manager: ApprovalManager):
        req = approval_manager.create_request(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            action="run-tool",
            target="example.com",
            tool_name="nmap",
            risk_level=RiskLevel.HIGH,
        )
        approved_req = approval_manager.approve(req.approval_id, "admin")
        assert approved_req.status == ApprovalStatus.GRANTED
        assert approved_req.decided_by == "admin"
        assert approved_req.decided_at is not None

    def test_reject(self, approval_manager: ApprovalManager):
        req = approval_manager.create_request(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            action="run-tool",
            target="example.com",
            tool_name="nmap",
            risk_level=RiskLevel.HIGH,
        )
        rejected_req = approval_manager.reject(req.approval_id, "admin", "Risk too high")
        assert rejected_req.status == ApprovalStatus.REJECTED
        assert rejected_req.decided_by == "admin"
        assert rejected_req.rejection_reason == "Risk too high"

    def test_expiration(self, approval_manager: ApprovalManager):
        req = approval_manager.create_request(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            action="run-tool",
            target="example.com",
            tool_name="nmap",
            risk_level=RiskLevel.HIGH,
            expiry_seconds=-1,
        )
        expired = approval_manager.check_expired()
        assert len(expired) == 1
        assert expired[0].approval_id == req.approval_id
        assert expired[0].status == ApprovalStatus.EXPIRED

    def test_get_pending(self, approval_manager: ApprovalManager):
        req = approval_manager.create_request(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            action="run-tool",
            target="example.com",
            tool_name="nmap",
            risk_level=RiskLevel.HIGH,
        )
        pending = approval_manager.get_pending("eng-1")
        assert len(pending) == 1
        assert pending[0].approval_id == req.approval_id

    def test_cannot_approve_already_approved_request(self, approval_manager: ApprovalManager):
        req = approval_manager.create_request(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            action="run-tool",
            target="example.com",
            tool_name="nmap",
            risk_level=RiskLevel.HIGH,
        )
        approval_manager.approve(req.approval_id, "admin1")
        with pytest.raises(ValueError, match="already approved"):
            approval_manager.approve(req.approval_id, "admin2")

    def test_cannot_approve_already_rejected_request(self, approval_manager: ApprovalManager):
        req = approval_manager.create_request(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            action="run-tool",
            target="example.com",
            tool_name="nmap",
            risk_level=RiskLevel.HIGH,
        )
        approval_manager.reject(req.approval_id, "admin1", "Denial")
        with pytest.raises(ValueError, match="already rejected"):
            approval_manager.approve(req.approval_id, "admin2")

    def test_cannot_reject_already_approved_request(self, approval_manager: ApprovalManager):
        req = approval_manager.create_request(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            action="run-tool",
            target="example.com",
            tool_name="nmap",
            risk_level=RiskLevel.HIGH,
        )
        approval_manager.approve(req.approval_id, "admin1")
        with pytest.raises(ValueError, match="already approved"):
            approval_manager.reject(req.approval_id, "admin2", "Denial")

    def test_cannot_approve_or_reject_expired_request(self, approval_manager: ApprovalManager):
        req = approval_manager.create_request(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            action="run-tool",
            target="example.com",
            tool_name="nmap",
            risk_level=RiskLevel.HIGH,
            expiry_seconds=-1,
        )
        with pytest.raises(ValueError, match="expired"):
            approval_manager.approve(req.approval_id, "admin")

    def test_validate_approval_for_request_binding(self, approval_manager: ApprovalManager):
        req = approval_manager.create_request(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            action="execute_tool:nmap",
            target="example.com",
            tool_name="nmap",
            risk_level=RiskLevel.HIGH,
        )
        approval_manager.approve(req.approval_id, "admin")

        # Valid exact match
        assert (
            approval_manager.validate_approval_for_request(
                req.approval_id, "eng-1", "task-1", "nmap", "example.com"
            )
            is True
        )

        # Cross-engagement reuse attempt
        assert (
            approval_manager.validate_approval_for_request(
                req.approval_id, "eng-OTHER", "task-1", "nmap", "example.com"
            )
            is False
        )

        # Cross-task reuse attempt
        assert (
            approval_manager.validate_approval_for_request(
                req.approval_id, "eng-1", "task-OTHER", "nmap", "example.com"
            )
            is False
        )

        # Cross-tool reuse attempt
        assert (
            approval_manager.validate_approval_for_request(
                req.approval_id, "eng-1", "task-1", "sqlmap", "example.com"
            )
            is False
        )

        # Cross-target reuse attempt
        assert (
            approval_manager.validate_approval_for_request(
                req.approval_id, "eng-1", "task-1", "nmap", "other-target.com"
            )
            is False
        )
