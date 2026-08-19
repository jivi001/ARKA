"""End-to-End integration tests for Phase 1 + Phase 2.1 Execution Engine Pipeline."""

import pytest

from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import RiskLevel, ScopeDefinition, ScopeTarget
from arka.app.execution.manager import ExecutionManager
from arka.app.execution.sandbox.local import LocalSafeRuntime
from arka.app.tools.mock.tools import EchoToolExecutor, HighRiskMockToolExecutor
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import (
    CandidateToolRequest,
    ToolDefinition,
)


@pytest.fixture
def audit_service():
    return AuditService()


@pytest.fixture
def scope_guard():
    return ScopeGuard(
        ScopeDefinition(
            engagement_id="eng-e2e-scope",
            includes=ScopeTarget(
                cidrs=["192.168.1.0/24", "10.0.0.0/8"],
                domains=["authorized.internal", "app.corp.local"],
            ),
            excludes=ScopeTarget(
                cidrs=["10.0.0.1/32"],
                domains=["forbidden.corp.local"],
            ),
        )
    )


@pytest.fixture
def policy_engine(scope_guard):
    return PolicyEngine(scope_guard=scope_guard)


@pytest.fixture
def approval_manager():
    return ApprovalManager()


@pytest.fixture
def execution_manager(audit_service):
    return ExecutionManager(
        audit_service=audit_service,
        runtime=LocalSafeRuntime(),
    )


@pytest.fixture
def tool_registry(policy_engine, audit_service, approval_manager, execution_manager):
    registry = ToolRegistry(
        policy_engine=policy_engine,
        audit_service=audit_service,
        approval_manager=approval_manager,
        execution_manager=execution_manager,
    )
    # Register Low Risk Tool
    registry.register(
        ToolDefinition(
            name="echo_test",
            description="Low risk echo tool",
            input_schema={
                "type": "object",
                "properties": {"message": {"type": "string"}},
                "required": ["message"],
            },
            output_schema={"type": "object"},
            risk_level=RiskLevel.LOW,
            timeout_seconds=10,
        ),
        EchoToolExecutor(),
    )
    # Register High Risk Tool
    registry.register(
        ToolDefinition(
            name="high_risk_mock",
            description="High risk mock tool",
            input_schema={
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
            output_schema={"type": "object"},
            risk_level=RiskLevel.HIGH,
            timeout_seconds=10,
        ),
        HighRiskMockToolExecutor(),
    )
    return registry


class TestExecutionEngineE2E:
    @pytest.mark.asyncio
    async def test_low_risk_tool_e2e_pipeline(
        self,
        tool_registry: ToolRegistry,
        audit_service: AuditService,
        execution_manager: ExecutionManager,
    ):
        """Prove the full pipeline: CandidateProposal -> ToolRegistry -> ScopeGuard -> PolicyEngine

        -> Authoritative ToolRequest -> ExecutionManager -> SandboxRuntime -> Evidence -> Audit.
        """
        candidate = CandidateToolRequest(
            tool_name="echo_test",
            target="192.168.1.55",
            arguments={"message": "e2e_recon_test"},
            reason="Phase 2.1 E2E Test",
        )

        # 1. Deterministic Control Plane Validation
        tool_req, decision, err = tool_registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-e2e-1",
            task_id="task-e2e-1",
            agent_id="agent-e2e-1",
        )

        assert tool_req is not None
        assert err is None
        assert decision is not None
        assert decision.decision.value == "allow"
        assert tool_req.scope_validated is True
        assert tool_req.policy_approved is True

        # 2. Execution Plane Execution
        result = await tool_registry.execute(tool_req)

        assert result.success is True
        assert result.output.get("echo") == {"message": "e2e_recon_test"}
        assert result.output.get("target") == "192.168.1.55"
        assert len(result.evidence_refs) == 1

        # 3. Verify Cryptographic Evidence Integrity
        evidence_id = result.evidence_refs[0]
        assert execution_manager.evidence_store.verify_integrity(evidence_id) is True

        # 4. Verify Immutable Audit Events
        events = await audit_service.get_events(engagement_id="eng-e2e-1")
        event_types = [e.event_type for e in events]
        assert AuditEventType.POLICY_DECISION in event_types
        assert AuditEventType.TOOL_REQUESTED in event_types
        assert AuditEventType.EXECUTION_REQUESTED in event_types
        assert AuditEventType.EXECUTION_AUTHORIZED in event_types
        assert AuditEventType.EXECUTION_STARTED in event_types
        assert AuditEventType.TOOL_EXECUTED in event_types
        assert AuditEventType.EXECUTION_COMPLETED in event_types

    @pytest.mark.asyncio
    async def test_high_risk_tool_approval_and_execution_pipeline(
        self,
        tool_registry: ToolRegistry,
        approval_manager: ApprovalManager,
        audit_service: AuditService,
    ):
        """Prove the high risk approval pipeline with persistent approval gate

        and sandbox execution.
        """
        candidate = CandidateToolRequest(
            tool_name="high_risk_mock",
            target="app.corp.local",
            arguments={"command": "exploit_simulation"},
            reason="High risk security verification",
        )

        # 1. First attempt: No approval -> Must require approval
        tool_req, decision, err = tool_registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-e2e-2",
            task_id="task-e2e-2",
            agent_id="agent-e2e-2",
        )
        assert tool_req is None
        assert decision is not None
        assert decision.decision.value == "require_approval"
        assert "Requires human approval" in (err or "")

        # 2. Human approval requested
        approval = approval_manager.create_request(
            engagement_id="eng-e2e-2",
            task_id="task-e2e-2",
            agent_id="agent-e2e-2",
            action="execute:high_risk_mock",
            tool_name="high_risk_mock",
            target="app.corp.local",
            risk_level=RiskLevel.HIGH,
        )

        # 3. Human grants approval
        approval_manager.approve(approval.approval_id, approved_by="sec_admin")

        # 4. Second attempt with valid approval ID -> Approved
        approved_req, _decision2, err2 = tool_registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-e2e-2",
            task_id="task-e2e-2",
            agent_id="agent-e2e-2",
            approval_id=approval.approval_id,
        )
        assert approved_req is not None
        assert err2 is None
        assert approved_req.scope_validated is True
        assert approved_req.policy_approved is True
        assert approved_req.approval_id == approval.approval_id

        # 5. Execute approved high-risk tool in sandbox
        result = await tool_registry.execute(approved_req)
        assert result.success is True
        assert result.output.get("action") == "simulated_high_risk_operation"
        assert result.output.get("approved_by") == approval.approval_id
        assert len(result.evidence_refs) == 1

        # 6. Audit check
        events = await audit_service.get_events(engagement_id="eng-e2e-2")
        event_types = [e.event_type for e in events]
        assert AuditEventType.EXECUTION_COMPLETED in event_types

    @pytest.mark.asyncio
    async def test_out_of_scope_rejection_no_execution(
        self,
        tool_registry: ToolRegistry,
        audit_service: AuditService,
    ):
        """Prove that out-of-scope targets are strictly denied with zero execution."""
        candidate = CandidateToolRequest(
            tool_name="echo_test",
            target="10.0.0.1",  # Denied CIDR
            arguments={"message": "scan"},
        )

        tool_req, decision, err = tool_registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-e2e-3",
            task_id="task-e2e-3",
            agent_id="agent-e2e-3",
        )

        assert tool_req is None
        assert decision is not None
        assert decision.decision.value == "deny"
        assert "Target out of scope" in (err or "") or "Policy denied" in (err or "")

        # Verify no execution events occurred
        events = await audit_service.get_events(engagement_id="eng-e2e-3")
        assert len(events) == 0
