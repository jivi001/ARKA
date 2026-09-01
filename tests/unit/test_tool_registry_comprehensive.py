"""Comprehensive unit test suite for ToolRegistry.

Tests tool registry security boundary:
- Tool existence and enabled status validation
- Input schema argument validation (required, unknown, type mismatch)
- PolicyEngine & ScopeGuard integration
- ApprovalManager validation & cross-engagement/target binding
- Timeout handling & executor exception handling
- Immutable audit event generation
"""

import asyncio

import pytest

from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import (
    PolicyDecisionType,
    RiskLevel,
    ScopeDefinition,
    ScopeTarget,
)
from arka.app.tools.registry.registry import (
    ToolExecutor,
    ToolRegistry,
)
from arka.app.tools.schemas.tool_schemas import (
    CandidateToolRequest,
    ToolDefinition,
    ToolRequest,
    ToolResult,
)


class SimpleMockExecutor(ToolExecutor):
    def __init__(self, should_fail: bool = False, delay_seconds: float = 0.0):
        self.should_fail = should_fail
        self.delay_seconds = delay_seconds

    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        if self.delay_seconds > 0:
            await asyncio.sleep(self.delay_seconds)
        if self.should_fail:
            raise RuntimeError("Underlying executor failed catastrophically")
        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name=request.tool_name,
            success=True,
            output={"executed": True, "target": request.target, "args": request.arguments},
        )


@pytest.fixture
def test_scope() -> ScopeDefinition:
    return ScopeDefinition(
        engagement_id="eng-reg-1",
        includes=ScopeTarget(
            domains=["target.com"],
            subdomains_allowed=True,
            ip_addresses=["10.0.0.1"],
        ),
    )


@pytest.fixture
def audit_service() -> AuditService:
    return AuditService()


@pytest.fixture
def approval_manager() -> ApprovalManager:
    return ApprovalManager()


@pytest.fixture
def registry(test_scope, audit_service, approval_manager) -> ToolRegistry:
    guard = ScopeGuard(test_scope)
    engine = PolicyEngine(guard)
    reg = ToolRegistry(
        policy_engine=engine,
        audit_service=audit_service,
        approval_manager=approval_manager,
    )

    # Register standard low-risk tool
    low_def = ToolDefinition(
        name="low_scan",
        description="Low risk scanner",
        version="1.0.0",
        input_schema={
            "type": "object",
            "properties": {
                "depth": {"type": "integer"},
                "mode": {"type": "string"},
                "verbose": {"type": "boolean"},
            },
            "required": ["depth"],
        },
        output_schema={"type": "object"},
        risk_level=RiskLevel.LOW,
        timeout_seconds=2,
    )
    reg.register(low_def, SimpleMockExecutor())

    # Register high-risk tool
    high_def = ToolDefinition(
        name="high_exploit",
        description="High risk simulation",
        version="1.0.0",
        input_schema={
            "type": "object",
            "properties": {
                "payload": {"type": "string"},
            },
            "required": ["payload"],
        },
        output_schema={"type": "object"},
        risk_level=RiskLevel.HIGH,
        timeout_seconds=2,
    )
    reg.register(high_def, SimpleMockExecutor())

    # Register disabled tool
    disabled_def = ToolDefinition(
        name="disabled_tool",
        description="Disabled tool",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        risk_level=RiskLevel.LOW,
        enabled=False,
    )
    reg.register(disabled_def, SimpleMockExecutor())

    # Register slow tool for timeout testing
    slow_def = ToolDefinition(
        name="slow_tool",
        description="Slow tool",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        risk_level=RiskLevel.LOW,
        timeout_seconds=1,
    )
    reg.register(slow_def, SimpleMockExecutor(delay_seconds=2.0))

    # Register crashing tool
    crash_def = ToolDefinition(
        name="crash_tool",
        description="Crashing tool",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        risk_level=RiskLevel.LOW,
    )
    reg.register(crash_def, SimpleMockExecutor(should_fail=True))

    return reg


class TestToolRegistryValidation:
    def test_unknown_tool_candidate_validation(self, registry: ToolRegistry):
        candidate = CandidateToolRequest(
            tool_name="nonexistent_tool",
            target="target.com",
            arguments={},
        )
        auth_req, _decision, err = registry.validate_candidate_request(
            candidate, "eng-1", "task-1", "agent-1"
        )
        assert auth_req is None
        assert "Unknown tool" in (err or "")

    def test_disabled_tool_candidate_validation(self, registry: ToolRegistry):
        candidate = CandidateToolRequest(
            tool_name="disabled_tool",
            target="target.com",
            arguments={},
        )
        auth_req, _decision, err = registry.validate_candidate_request(
            candidate, "eng-1", "task-1", "agent-1"
        )
        assert auth_req is None
        assert "is disabled" in (err or "")

    def test_missing_required_argument(self, registry: ToolRegistry):
        candidate = CandidateToolRequest(
            tool_name="low_scan",
            target="target.com",
            arguments={"mode": "fast"},  # missing required 'depth'
        )
        auth_req, _decision, err = registry.validate_candidate_request(
            candidate, "eng-1", "task-1", "agent-1"
        )
        assert auth_req is None
        assert "Missing required argument: depth" in (err or "")

    def test_unknown_unexpected_argument(self, registry: ToolRegistry):
        candidate = CandidateToolRequest(
            tool_name="low_scan",
            target="target.com",
            arguments={"depth": 3, "unrecognized_field": "test"},
        )
        auth_req, _decision, err = registry.validate_candidate_request(
            candidate, "eng-1", "task-1", "agent-1"
        )
        assert auth_req is None
        assert "Unknown argument: unrecognized_field" in (err or "")

    def test_argument_type_mismatch(self, registry: ToolRegistry):
        candidate = CandidateToolRequest(
            tool_name="low_scan",
            target="target.com",
            arguments={"depth": "not-an-int"},  # expected integer
        )
        auth_req, _decision, err = registry.validate_candidate_request(
            candidate, "eng-1", "task-1", "agent-1"
        )
        assert auth_req is None
        assert "Invalid type for argument 'depth': expected integer" in (err or "")

    def test_out_of_scope_policy_denial(self, registry: ToolRegistry):
        candidate = CandidateToolRequest(
            tool_name="low_scan",
            target="unauthorized-domain.com",
            arguments={"depth": 2},
        )
        auth_req, decision, err = registry.validate_candidate_request(
            candidate, "eng-1", "task-1", "agent-1"
        )
        assert auth_req is None
        assert decision is not None
        assert decision.decision == PolicyDecisionType.DENY
        assert "Policy denied" in (err or "")

    def test_high_risk_requires_approval_when_not_approved(self, registry: ToolRegistry):
        candidate = CandidateToolRequest(
            tool_name="high_exploit",
            target="target.com",
            arguments={"payload": "test_payload"},
        )
        auth_req, decision, err = registry.validate_candidate_request(
            candidate, "eng-1", "task-1", "agent-1"
        )
        assert auth_req is None
        assert decision is not None
        assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL
        assert "Requires human approval" in (err or "")

    def test_high_risk_allowed_with_valid_bound_approval(
        self, registry: ToolRegistry, approval_manager: ApprovalManager
    ):
        # Create persistent approval
        app_req = approval_manager.create_request(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            action="execute_tool:high_exploit",
            target="target.com",
            tool_name="high_exploit",
            risk_level=RiskLevel.HIGH,
        )
        approval_manager.approve(app_req.approval_id, "admin_user")

        candidate = CandidateToolRequest(
            tool_name="high_exploit",
            target="target.com",
            arguments={"payload": "test_payload"},
        )
        auth_req, _decision, err = registry.validate_candidate_request(
            candidate,
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            approval_id=app_req.approval_id,
        )
        assert err is None
        assert auth_req is not None
        assert auth_req.policy_approved is True
        assert auth_req.scope_validated is True
        assert auth_req.approval_id == app_req.approval_id
        assert auth_req.risk_level == RiskLevel.HIGH

    def test_cross_engagement_or_target_approval_rejected(
        self, registry: ToolRegistry, approval_manager: ApprovalManager
    ):
        # Approval for eng-1, task-1, target.com
        app_req = approval_manager.create_request(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            action="execute_tool:high_exploit",
            target="target.com",
            tool_name="high_exploit",
            risk_level=RiskLevel.HIGH,
        )
        approval_manager.approve(app_req.approval_id, "admin_user")

        candidate = CandidateToolRequest(
            tool_name="high_exploit",
            target="target.com",
            arguments={"payload": "test_payload"},
        )

        # Attempt to use approval in different engagement 'eng-2'
        auth_req, _decision, err = registry.validate_candidate_request(
            candidate,
            engagement_id="eng-2",
            task_id="task-1",
            agent_id="agent-1",
            approval_id=app_req.approval_id,
        )
        assert auth_req is None
        assert "Requires human approval" in (err or "")


class TestToolRegistryExecution:
    @pytest.mark.asyncio
    async def test_successful_execution_and_audit(
        self, registry: ToolRegistry, audit_service: AuditService
    ):
        req = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="low_scan",
            target="target.com",
            arguments={"depth": 2, "mode": "stealth"},
            scope_validated=True,
            policy_approved=True,
            risk_level=RiskLevel.LOW,
        )
        result = await registry.execute(req)
        assert result.success is True
        assert result.output.get("executed") is True
        assert result.execution_time_ms >= 0

        # Verify audit trail
        events = await audit_service.get_events(engagement_id="eng-1")
        assert any(e.event_type == AuditEventType.TOOL_REQUESTED for e in events)
        assert any(e.event_type == AuditEventType.TOOL_EXECUTED for e in events)
        assert any(e.event_type == AuditEventType.POLICY_DECISION for e in events)

    @pytest.mark.asyncio
    async def test_execution_timeout_handled(
        self, registry: ToolRegistry, audit_service: AuditService
    ):
        req = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="slow_tool",
            target="target.com",
            arguments={},
            scope_validated=True,
            policy_approved=True,
        )
        result = await registry.execute(req)
        assert result.success is False
        assert "timed out" in (result.error or "")

        events = await audit_service.get_events(engagement_id="eng-1")
        assert any(e.event_type == AuditEventType.TOOL_FAILED for e in events)

    @pytest.mark.asyncio
    async def test_executor_crash_handled(
        self, registry: ToolRegistry, audit_service: AuditService
    ):
        req = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="crash_tool",
            target="target.com",
            arguments={},
            scope_validated=True,
            policy_approved=True,
        )
        result = await registry.execute(req)
        assert result.success is False
        assert "Execution error" in (result.error or "")

        events = await audit_service.get_events(engagement_id="eng-1")
        assert any(e.event_type == AuditEventType.TOOL_FAILED for e in events)
