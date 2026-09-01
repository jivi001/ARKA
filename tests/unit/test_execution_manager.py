import asyncio

import pytest

from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.state.models import RiskLevel
from arka.app.execution.evidence import EvidenceStore
from arka.app.execution.manager import ExecutionManager
from arka.app.execution.policy import ExecutionPolicy
from arka.app.execution.sandbox.local import LocalSafeRuntime
from arka.app.execution.schemas import (
    EvidenceType,
    ExecutionLimits,
    ExecutionStatus,
)
from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest, ToolResult


class DummyEchoExecutor:
    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name=request.tool_name,
            success=True,
            output={"echo": request.arguments.get("msg", ""), "target": request.target},
            execution_time_ms=5,
        )


class DummyMultiOutputExecutor:
    """Mock executor that produces raw_output, structured output, and stderr."""

    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name=request.tool_name,
            success=False,
            output={"partial": "data"},
            raw_output="<xml>raw scan output</xml>",
            error="warning: host was slow to respond",
            execution_time_ms=10,
        )


class DummySlowExecutor:
    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        await asyncio.sleep(2.0)
        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name=request.tool_name,
            success=True,
            output={},
        )


class DummyFailingExecutor:
    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        raise RuntimeError("Simulated executor internal error")


@pytest.fixture
def audit_service():
    return AuditService()


@pytest.fixture
def execution_manager(audit_service):
    return ExecutionManager(
        audit_service=audit_service,
        policy=ExecutionPolicy(default_limits=ExecutionLimits(max_execution_time_seconds=5)),
        runtime=LocalSafeRuntime(),
        evidence_store=EvidenceStore(),
    )


@pytest.fixture
def echo_tool_def():
    return ToolDefinition(
        name="echo_tool",
        description="Echo tool for tests",
        input_schema={"type": "object", "properties": {"msg": {"type": "string"}}},
        output_schema={"type": "object"},
        risk_level=RiskLevel.LOW,
        timeout_seconds=5,
        enabled=True,
    )


class TestExecutionManagerLifecycle:
    @pytest.mark.asyncio
    async def test_successful_execution_pipeline(
        self,
        execution_manager: ExecutionManager,
        echo_tool_def: ToolDefinition,
        audit_service: AuditService,
    ):
        request = ToolRequest(
            engagement_id="eng-100",
            task_id="task-100",
            agent_id="agent-recon",
            tool_name="echo_tool",
            target="192.168.1.10",
            arguments={"msg": "hello_arka"},
            scope_validated=True,
            policy_approved=True,
        )

        exec_res, tool_res = await execution_manager.execute_tool(
            request=request,
            tool_def=echo_tool_def,
            executor_func=DummyEchoExecutor(),
        )

        # Verify ExecutionResult
        assert exec_res.status == ExecutionStatus.COMPLETED
        assert exec_res.exit_code == 0
        assert exec_res.structured_output == {"echo": "hello_arka", "target": "192.168.1.10"}
        assert len(exec_res.evidence_references) == 1
        assert exec_res.evidence_references[0].sha256 != ""

        # Verify ToolResult
        assert tool_res.success is True
        assert len(tool_res.evidence_refs) == 1

        # Verify EvidenceStore integrity
        ev_id = tool_res.evidence_refs[0]
        assert execution_manager.evidence_store.verify_integrity(ev_id) is True

        # Verify Audit Trail
        events = await audit_service.get_events(engagement_id="eng-100")
        event_types = [e.event_type for e in events]
        assert AuditEventType.EXECUTION_REQUESTED in event_types
        assert AuditEventType.EXECUTION_AUTHORIZED in event_types
        assert AuditEventType.EXECUTION_STARTED in event_types
        assert AuditEventType.EXECUTION_COMPLETED in event_types
        assert AuditEventType.TOOL_EXECUTED in event_types

    @pytest.mark.asyncio
    async def test_unvalidated_tool_request_rejected(
        self,
        execution_manager: ExecutionManager,
        echo_tool_def: ToolDefinition,
        audit_service: AuditService,
    ):
        # Missing scope validation
        request = ToolRequest(
            engagement_id="eng-100",
            task_id="task-100",
            agent_id="agent-recon",
            tool_name="echo_tool",
            target="192.168.1.10",
            arguments={"msg": "hello"},
            scope_validated=False,
            policy_approved=True,
        )

        exec_res, tool_res = await execution_manager.execute_tool(
            request=request,
            tool_def=echo_tool_def,
            executor_func=DummyEchoExecutor(),
        )

        assert exec_res.status == ExecutionStatus.REJECTED
        assert tool_res.success is False
        assert "not scope-validated" in (tool_res.error or "")

        events = await audit_service.get_events(engagement_id="eng-100")
        assert any(e.event_type == AuditEventType.EXECUTION_REJECTED for e in events)

    @pytest.mark.asyncio
    async def test_execution_timeout_enforcement(
        self, execution_manager: ExecutionManager, audit_service: AuditService
    ):
        slow_def = ToolDefinition(
            name="slow_tool",
            description="Slow tool",
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            risk_level=RiskLevel.LOW,
            timeout_seconds=1,  # 1 second timeout
            enabled=True,
        )

        request = ToolRequest(
            engagement_id="eng-timeout",
            task_id="task-timeout",
            agent_id="agent-recon",
            tool_name="slow_tool",
            target="10.0.0.1",
            arguments={},
            scope_validated=True,
            policy_approved=True,
        )

        exec_res, tool_res = await execution_manager.execute_tool(
            request=request,
            tool_def=slow_def,
            executor_func=DummySlowExecutor(),
        )

        assert exec_res.status == ExecutionStatus.TIMED_OUT
        assert tool_res.success is False
        assert "timed out" in (tool_res.error or "")

        events = await audit_service.get_events(engagement_id="eng-timeout")
        event_types = [e.event_type for e in events]
        assert AuditEventType.EXECUTION_TIMED_OUT in event_types
        assert AuditEventType.TOOL_FAILED in event_types

    @pytest.mark.asyncio
    async def test_executor_error_handling_and_cleanup(
        self,
        execution_manager: ExecutionManager,
        echo_tool_def: ToolDefinition,
        audit_service: AuditService,
    ):
        request = ToolRequest(
            engagement_id="eng-crash",
            task_id="task-crash",
            agent_id="agent-recon",
            tool_name="echo_tool",
            target="10.0.0.1",
            arguments={"msg": "test"},
            scope_validated=True,
            policy_approved=True,
        )

        exec_res, tool_res = await execution_manager.execute_tool(
            request=request,
            tool_def=echo_tool_def,
            executor_func=DummyFailingExecutor(),
        )

        assert exec_res.status == ExecutionStatus.FAILED
        assert tool_res.success is False
        assert "Simulated executor internal error" in (tool_res.error or "")

        events = await audit_service.get_events(engagement_id="eng-crash")
        assert any(e.event_type == AuditEventType.EXECUTION_FAILED for e in events)

    @pytest.mark.asyncio
    async def test_multi_artifact_evidence_and_audit_event(
        self,
        execution_manager: ExecutionManager,
        echo_tool_def: ToolDefinition,
        audit_service: AuditService,
    ):
        """Verify that an execution producing stdout, structured dict, and stderr
        records 3 separate cryptographic evidence items and emits EVIDENCE_RECORDED.
        """
        request = ToolRequest(
            engagement_id="eng-multi-ev",
            task_id="task-multi-ev",
            agent_id="agent-recon",
            tool_name="multi_tool",
            target="192.168.1.50",
            arguments={},
            scope_validated=True,
            policy_approved=True,
        )

        exec_res, tool_res = await execution_manager.execute_tool(
            request=request,
            tool_def=echo_tool_def,
            executor_func=DummyMultiOutputExecutor(),
        )

        # 1. Verify 3 evidence references recorded
        assert len(tool_res.evidence_refs) == 3
        assert len(exec_res.evidence_references) == 3

        # 2. Check each evidence type
        stored_refs = [
            execution_manager.evidence_store.get_evidence(eid) for eid in tool_res.evidence_refs
        ]
        types = {r.evidence_type for r in stored_refs if r is not None}
        assert types == {
            EvidenceType.RAW_STDOUT.value,
            EvidenceType.STRUCTURED_RESULT.value,
            EvidenceType.RAW_STDERR.value,
        }

        # 3. Verify cryptographic integrity on all 3
        for eid in tool_res.evidence_refs:
            assert execution_manager.evidence_store.verify_integrity(eid) is True

        # 4. Verify EVIDENCE_RECORDED audit event emitted
        events = await audit_service.get_events(engagement_id="eng-multi-ev")
        event_types = [e.event_type for e in events]
        assert AuditEventType.EVIDENCE_RECORDED in event_types
        ev_recorded_event = next(
            e for e in events if e.event_type == AuditEventType.EVIDENCE_RECORDED
        )
        assert ev_recorded_event.parameters["evidence_count"] == 3
        assert ev_recorded_event.parameters["evidence_ids"] == tool_res.evidence_refs
