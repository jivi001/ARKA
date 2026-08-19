"""Safe mock-tool end-to-end integration tests.

Verifies complete execution pipeline without invoking any real penetration-testing tools:
- LOW-risk automatic policy clearance and execution
- HIGH-risk approval requirement, persistence, approval, and authorized execution
- Zero network scanning, zero subprocess execution, zero external access
"""

import pytest

from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import (
    ApprovalStatus,
    PolicyDecisionType,
    RiskLevel,
    ScopeDefinition,
    ScopeTarget,
)
from arka.app.tools.mock.tools import register_mock_tools
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest


@pytest.fixture
def e2e_scope() -> ScopeDefinition:
    return ScopeDefinition(
        engagement_id="eng-mock-e2e",
        includes=ScopeTarget(
            domains=["target.local", "api.target.local"],
            subdomains_allowed=True,
            ip_addresses=["10.0.0.5"],
            cidrs=["10.0.0.0/24"],
            ports=[80, 443, 8080],
        ),
    )


@pytest.fixture
def audit_service() -> AuditService:
    return AuditService()


@pytest.fixture
def approval_manager() -> ApprovalManager:
    return ApprovalManager()


@pytest.fixture
def mock_pipeline(e2e_scope, audit_service, approval_manager):
    guard = ScopeGuard(e2e_scope)
    policy = PolicyEngine(guard)
    registry = ToolRegistry(
        policy_engine=policy,
        audit_service=audit_service,
        approval_manager=approval_manager,
    )
    register_mock_tools(registry, guard)
    return {
        "guard": guard,
        "policy": policy,
        "registry": registry,
        "approvals": approval_manager,
        "audit": audit_service,
    }


class TestMockToolEndToEnd:
    @pytest.mark.asyncio
    async def test_low_risk_echo_tool_e2e_flow(self, mock_pipeline):
        registry: ToolRegistry = mock_pipeline["registry"]
        audit: AuditService = mock_pipeline["audit"]

        candidate = CandidateToolRequest(
            tool_name="echo_test",
            target="target.local",
            arguments={"message": "Safe reconnaissance message"},
            reason="Verify host reachability",
        )

        # 1. Authoritative validation
        auth_req, decision, err = registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-mock-e2e",
            task_id="task-1",
            agent_id="recon_agent",
        )

        assert err is None
        assert auth_req is not None
        assert decision.decision == PolicyDecisionType.ALLOW
        assert auth_req.scope_validated is True
        assert auth_req.policy_approved is True
        assert auth_req.risk_level == RiskLevel.LOW

        # 2. Execution through security boundary
        result = await registry.execute(auth_req)

        assert result.success is True
        assert result.output["target"] == "target.local"
        assert result.output["echo"]["message"] == "Safe reconnaissance message"

        # 3. Audit verification
        events = await audit.get_events(engagement_id="eng-mock-e2e")
        assert len(events) >= 3
        event_types = [e.event_type for e in events]
        assert AuditEventType.POLICY_DECISION in event_types
        assert AuditEventType.TOOL_REQUESTED in event_types
        assert AuditEventType.TOOL_EXECUTED in event_types

    @pytest.mark.asyncio
    async def test_high_risk_mock_tool_requires_approval_and_executes_when_approved(
        self, mock_pipeline
    ):
        registry: ToolRegistry = mock_pipeline["registry"]
        approvals: ApprovalManager = mock_pipeline["approvals"]
        audit: AuditService = mock_pipeline["audit"]

        candidate = CandidateToolRequest(
            tool_name="high_risk_mock",
            target="target.local",
            arguments={"operation": "simulate_exploit", "payload": " harmless_test_token"},
            reason="Assess vulnerability remediation status",
        )

        # 1. First attempt without approval -> MUST require approval
        auth_req, decision, err = registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-mock-e2e",
            task_id="task-high-1",
            agent_id="exploit_agent",
        )

        assert auth_req is None
        assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL
        assert "Requires human approval" in (err or "")

        # 2. Human approval gate: create persistent request
        app_req = approvals.create_request(
            engagement_id="eng-mock-e2e",
            task_id="task-high-1",
            agent_id="exploit_agent",
            action="execute_tool:high_risk_mock",
            target=candidate.target,
            tool_name=candidate.tool_name,
            risk_level=decision.risk_level,
            reason=candidate.reason,
            details=candidate.arguments,
        )
        assert app_req.status == ApprovalStatus.REQUIRED

        # 3. Human grants approval
        approved_req = approvals.approve(app_req.approval_id, "lead_security_architect")
        assert approved_req.status == ApprovalStatus.GRANTED
        assert approved_req.decided_by == "lead_security_architect"

        # 4. Revalidate with granted approval ID
        auth_req, _decision_2, err_2 = registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-mock-e2e",
            task_id="task-high-1",
            agent_id="exploit_agent",
            approval_id=app_req.approval_id,
        )

        assert err_2 is None
        assert auth_req is not None
        assert auth_req.policy_approved is True
        assert auth_req.scope_validated is True
        assert auth_req.approval_id == app_req.approval_id

        # 5. Execute approved high-risk tool
        result = await registry.execute(auth_req)

        assert result.success is True
        assert result.output["action"] == "simulated_high_risk_operation"
        assert result.output["approved_by"] == app_req.approval_id

        # 6. Audit trail verification
        events = await audit.get_events(engagement_id="eng-mock-e2e", task_id="task-high-1")
        assert len(events) >= 2
        assert any(e.event_type == AuditEventType.TOOL_EXECUTED for e in events)

    @pytest.mark.asyncio
    async def test_high_risk_mock_tool_rejected_when_approval_denied(self, mock_pipeline):
        registry: ToolRegistry = mock_pipeline["registry"]
        approvals: ApprovalManager = mock_pipeline["approvals"]

        candidate = CandidateToolRequest(
            tool_name="high_risk_mock",
            target="target.local",
            arguments={"operation": "simulate_exploit"},
            reason="Unapproved penetration test",
        )

        # Create approval request
        app_req = approvals.create_request(
            engagement_id="eng-mock-e2e",
            task_id="task-rejected-1",
            agent_id="exploit_agent",
            action="execute_tool:high_risk_mock",
            target=candidate.target,
            tool_name=candidate.tool_name,
            risk_level=RiskLevel.HIGH,
        )

        # Reject approval
        approvals.reject(app_req.approval_id, "security_lead", "Out of testing window")

        # Attempt to validate
        auth_req, _decision, err = registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-mock-e2e",
            task_id="task-rejected-1",
            agent_id="exploit_agent",
            approval_id=app_req.approval_id,
        )

        assert auth_req is None
        assert "Requires human approval" in (err or "")
