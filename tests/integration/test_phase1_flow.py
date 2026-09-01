"""Complete Phase 1 end-to-end flow integration test.

Tests the complete ARKA Phase-1 pipeline:
CLI/API → Engagement → Task → LangGraph → LLM Gateway → CandidateToolRequest
→ ToolRegistry → ScopeGuard → PolicyEngine → ApprovalManager → Authoritative ToolRequest
→ Mock Tool → ToolResult → Audit
"""

import json
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from arka.app.agents.orchestrator.graph import create_orchestrator_graph
from arka.app.api import create_app
from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import (
    ApprovalStatus,
    RiskLevel,
    ScopeDefinition,
    ScopeTarget,
)
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.tools.mock.tools import register_mock_tools
from arka.app.tools.registry.registry import ToolRegistry


@pytest.fixture
def api_client():
    app = create_app()
    return TestClient(app)


class TestPhase1CompleteFlow:
    def test_api_engagement_full_lifecycle(self, api_client: TestClient):
        # 1. Create Engagement with complete Scope definition
        create_res = api_client.post(
            "/engagements",
            json={
                "name": "Phase 1 Enterprise Security Assessment",
                "description": "Authorized penetration testing assessment",
                "objective": "Assess externally exposed assets within approved scope",
                "scope": {
                    "includes": {
                        "domains": ["assessment.target.com"],
                        "subdomains_allowed": True,
                        "ip_addresses": ["192.168.10.50"],
                        "cidrs": ["192.168.10.0/24"],
                        "ports": [80, 443, 8080],
                    },
                    "excludes": {
                        "domains": ["admin.assessment.target.com"],
                        "ip_addresses": ["192.168.10.254"],
                    },
                },
            },
        )
        assert create_res.status_code == 201
        eng_data = create_res.json()
        eng_id = eng_data["engagement_id"]
        assert eng_data["status"] == "created"
        assert eng_data["scope"]["includes"]["domains"] == ["assessment.target.com"]

        # 2. Get Engagement by ID
        get_res = api_client.get(f"/engagements/{eng_id}")
        assert get_res.status_code == 200
        assert get_res.json()["engagement_id"] == eng_id

        # 3. Start Engagement -> ACTIVE
        start_res = api_client.post(f"/engagements/{eng_id}/start")
        assert start_res.status_code == 200
        assert start_res.json()["status"] == "active"

        # 4. Pause Engagement -> PAUSED
        pause_res = api_client.post(f"/engagements/{eng_id}/pause")
        assert pause_res.status_code == 200
        assert pause_res.json()["status"] == "paused"

        # 5. Resume (Start) Engagement -> ACTIVE
        resume_res = api_client.post(f"/engagements/{eng_id}/start")
        assert resume_res.status_code == 200
        assert resume_res.json()["status"] == "active"

        # 6. Stop Engagement -> STOPPED (Terminal)
        stop_res = api_client.post(f"/engagements/{eng_id}/stop")
        assert stop_res.status_code == 200
        assert stop_res.json()["status"] == "stopped"

        # 7. Audit trail check via API
        audit_res = api_client.get(f"/engagements/{eng_id}/audit")
        assert audit_res.status_code == 200
        events = audit_res.json()["events"]
        assert len(events) >= 4

    @pytest.mark.asyncio
    async def test_complete_orchestrator_low_risk_execution_flow(self):
        # 1. Setup scope and security components
        scope = ScopeDefinition(
            engagement_id="eng-phase1-low",
            includes=ScopeTarget(
                domains=["target.corp"],
                subdomains_allowed=True,
                ip_addresses=["10.0.1.5"],
            ),
        )
        guard = ScopeGuard(scope)
        policy = PolicyEngine(guard)
        audit = AuditService()
        approvals = ApprovalManager()
        tools = ToolRegistry(policy, audit, approvals)
        register_mock_tools(tools, guard)

        # 2. Mock LLM Gateway response for low risk echo tool
        llm = LLMGateway(audit_service=audit)
        low_risk_llm_json = json.dumps(
            {
                "action": "request_tool",
                "task_name": "recon_echo",
                "tool": "echo_test",
                "target": "target.corp",
                "arguments": {"message": "Service probe"},
                "reason": "Reconnaissance of target domain",
            }
        )
        mock_choice = SimpleNamespace(
            message=SimpleNamespace(content=low_risk_llm_json, role="assistant")
        )
        mock_usage = SimpleNamespace(prompt_tokens=20, completion_tokens=10, total_tokens=30)
        llm_mock_res = SimpleNamespace(choices=[mock_choice], usage=mock_usage, model="gpt-4o")

        llm._router = cast(Any, SimpleNamespace(acompletion=AsyncMock(return_value=llm_mock_res)))

        # 3. Create Orchestrator Graph
        checkpointer = MemorySaver()
        graph = create_orchestrator_graph(
            llm_gateway=llm,
            tool_registry=tools,
            audit_service=audit,
            policy_engine=policy,
            scope_guard=guard,
            approval_manager=approvals,
            checkpointer=checkpointer,
        )

        initial_state: dict[str, Any] = {
            "engagement_id": "eng-phase1-low",
            "engagement_name": "Phase 1 Low Risk Test",
            "objective": "Test deterministic low-risk pipeline",
            "status": "created",
            "scope": scope.model_dump(),
            "current_task_id": "task-low-1",
            "current_task_name": "init",
            "current_task_status": "pending",
            "llm_response": "",
            "llm_structured_output": {},
            "candidate_tool_request": None,
            "policy_decision": None,
            "tool_request": None,
            "tool_result": None,
            "should_continue": True,
            "requires_approval": False,
            "approval_id": None,
            "approval_status": "none",
            "tasks_completed": [],
            "audit_trail": [],
            "errors": [],
            "iteration_count": 0,
            "max_iterations": 1,
        }

        config = {"configurable": {"thread_id": "eng-phase1-low:task-low-1"}}
        final_state = await graph.ainvoke(initial_state, config=config)

        # 4. Assert execution completed successfully
        assert final_state["tool_result"] is not None
        assert final_state["tool_result"]["success"] is True
        assert final_state["tool_result"]["output"]["target"] == "target.corp"
        assert "recon_echo" in final_state["tasks_completed"]

        # 5. Audit trail verification
        events = await audit.get_events(engagement_id="eng-phase1-low")
        assert len(events) >= 2
        event_actions = [e.action for e in events]
        assert any("execute:echo_test" in a for a in event_actions)

    @pytest.mark.asyncio
    async def test_complete_orchestrator_high_risk_interrupt_and_approval_flow(self):
        # 1. Setup scope and security components
        scope = ScopeDefinition(
            engagement_id="eng-phase1-high",
            includes=ScopeTarget(
                domains=["target.corp"],
                subdomains_allowed=True,
                ip_addresses=["10.0.1.5"],
            ),
        )
        guard = ScopeGuard(scope)
        policy = PolicyEngine(guard)
        audit = AuditService()
        approvals = ApprovalManager()
        tools = ToolRegistry(policy, audit, approvals)
        register_mock_tools(tools, guard)

        # 2. Mock LLM Gateway response for HIGH risk mock tool
        llm = LLMGateway(audit_service=audit)
        high_risk_llm_json = json.dumps(
            {
                "action": "request_tool",
                "task_name": "simulate_exploit_task",
                "tool": "high_risk_mock",
                "target": "target.corp",
                "arguments": {"operation": "exploit_simulation", "payload": " harmless_test"},
                "reason": "Simulate exploit under controlled scope",
            }
        )
        mock_choice = SimpleNamespace(
            message=SimpleNamespace(content=high_risk_llm_json, role="assistant")
        )
        mock_usage = SimpleNamespace(prompt_tokens=20, completion_tokens=10, total_tokens=30)
        llm_mock_res = SimpleNamespace(choices=[mock_choice], usage=mock_usage, model="gpt-4o")

        llm._router = cast(Any, SimpleNamespace(acompletion=AsyncMock(return_value=llm_mock_res)))

        # 3. Create Orchestrator Graph
        checkpointer = MemorySaver()
        graph = create_orchestrator_graph(
            llm_gateway=llm,
            tool_registry=tools,
            audit_service=audit,
            policy_engine=policy,
            scope_guard=guard,
            approval_manager=approvals,
            checkpointer=checkpointer,
        )

        initial_state: dict[str, Any] = {
            "engagement_id": "eng-phase1-high",
            "engagement_name": "Phase 1 High Risk Approval Test",
            "objective": "Test human approval gate interruption and resume",
            "status": "created",
            "scope": scope.model_dump(),
            "current_task_id": "task-high-1",
            "current_task_name": "init",
            "current_task_status": "pending",
            "llm_response": "",
            "llm_structured_output": {},
            "candidate_tool_request": None,
            "policy_decision": None,
            "tool_request": None,
            "tool_result": None,
            "should_continue": True,
            "requires_approval": False,
            "approval_id": None,
            "approval_status": "none",
            "tasks_completed": [],
            "audit_trail": [],
            "errors": [],
            "iteration_count": 0,
            "max_iterations": 1,
        }

        config = {"configurable": {"thread_id": "eng-phase1-high:task-high-1"}}

        # 4. Invoke graph -> Must interrupt at tool_request approval gate
        _state_after_interrupt = await graph.ainvoke(initial_state, config=config)

        # Graph should pause at interrupt
        pending_approvals = approvals.get_pending("eng-phase1-high")
        assert len(pending_approvals) == 1
        approval_req = pending_approvals[0]
        assert approval_req.status == ApprovalStatus.REQUIRED
        assert approval_req.tool_name == "high_risk_mock"
        assert approval_req.risk_level == RiskLevel.HIGH

        # 5. Human grants approval in ApprovalManager
        approvals.approve(approval_req.approval_id, "lead_security_architect")

        # 6. Resume graph from checkpoint with approval command
        resume_command: Any = Command(
            resume={"status": "approved", "approved_by": "lead_security_architect"}
        )
        final_state = await graph.ainvoke(resume_command, config=config)

        # 7. Assert high risk tool executed after approval
        assert final_state["tool_result"] is not None
        assert final_state["tool_result"]["success"] is True
        assert final_state["tool_result"]["output"]["approved_by"] == approval_req.approval_id
        assert "simulate_exploit_task" in final_state["tasks_completed"]

        # 8. Verify audit trail
        events = await audit.get_events(engagement_id="eng-phase1-high")
        assert any(e.event_type == AuditEventType.TOOL_EXECUTED for e in events)
