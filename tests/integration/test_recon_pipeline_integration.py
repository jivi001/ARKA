"""Integration tests for ARKA Phase 2.2.4 ReconAgent.

Validates the full reconnaissance pipeline flow:
ReconAgent -> CandidateToolRequest -> ToolRegistry -> ScopeGuard -> PolicyEngine
-> ApprovalManager -> ExecutionManager -> NmapToolExecutor -> ToolResult -> EvidenceStore
-> AssetNormalizer -> AssetRepository -> AuditService

Also validates the interruptible LangGraph workflow and human-in-the-loop approval gates.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from arka.app.agents.recon.agent import ReconAgent
from arka.app.agents.recon.graph import create_recon_graph
from arka.app.agents.recon.models import (
    ReconAgentConfig,
    ReconAgentState,
    ReconState,
    ReconTerminationReason,
)
from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.execution.evidence import EvidenceStore
from arka.app.execution.manager import ExecutionManager
from arka.app.execution.sandbox.local import LocalSafeRuntime
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.tools.nmap.definition import register_nmap_tool
from arka.app.tools.registry.registry import ToolRegistry


@pytest.fixture
def recon_e2e_scope() -> ScopeDefinition:
    return ScopeDefinition(
        engagement_id="eng-recon-e2e",
        includes=ScopeTarget(
            domains=["target.corp"],
            ip_addresses=["192.168.1.50"],
            cidrs=["192.168.1.0/24"],
            ports=[80, 443, 8080],
        ),
        excludes=ScopeTarget(ip_addresses=["192.168.1.254"]),
    )


@pytest.fixture
def recon_e2e_env(recon_e2e_scope: ScopeDefinition):
    guard = ScopeGuard(recon_e2e_scope)
    policy = PolicyEngine(guard)
    audit = AuditService()
    approvals = ApprovalManager()
    evidence_store = EvidenceStore()
    runtime = LocalSafeRuntime()
    exec_manager = ExecutionManager(
        audit_service=audit,
        runtime=runtime,
        evidence_store=evidence_store,
    )
    registry = ToolRegistry(
        policy_engine=policy,
        audit_service=audit,
        approval_manager=approvals,
        execution_manager=exec_manager,
    )
    register_nmap_tool(registry)
    asset_repo = InMemoryAssetRepository()
    normalizer = AssetNormalizer()
    llm = LLMGateway(audit_service=audit)

    agent = ReconAgent(
        llm_gateway=llm,
        tool_registry=registry,
        audit_service=audit,
        scope_guard=guard,
        policy_engine=policy,
        approval_manager=approvals,
        asset_repository=asset_repo,
        asset_normalizer=normalizer,
        evidence_store=evidence_store,
        config=ReconAgentConfig(max_iterations=5, max_actions=10),
    )

    return SimpleNamespace(
        guard=guard,
        policy=policy,
        audit=audit,
        approvals=approvals,
        evidence_store=evidence_store,
        registry=registry,
        asset_repo=asset_repo,
        normalizer=normalizer,
        llm=llm,
        agent=agent,
        scope=recon_e2e_scope,
    )


class TestReconPipelineIntegration:
    """Full pipeline integration testing for ReconAgent."""

    @pytest.mark.asyncio
    async def test_full_recon_agent_lifecycle_and_asset_provenance(self, recon_e2e_env):
        """Test complete ReconAgent lifecycle through ExecutionManager and AssetRepository."""
        target_ip = "192.168.1.50"

        # Mock LLM: Step 1 proposes Nmap scan; Step 2 analyzes result and marks complete
        plan_response = json.dumps(
            {
                "objective": "Identify open services on target host",
                "reasoning_summary": "Initial discovery scan on authorized target",
                "candidate_actions": [
                    {
                        "tool_name": "nmap",
                        "operation": "scan",
                        "target": target_ip,
                        "arguments": {"ports": "80,443", "service_detection": True},
                        "rationale": "Initial web service enumeration",
                    }
                ],
                "stop_condition": None,
            }
        )

        analysis_response = json.dumps(
            {
                "summary": "Discovered nginx web server running HTTP and HTTPS",
                "findings": [
                    "Port 80/tcp open (nginx 1.24.0)",
                    "Port 443/tcp open (nginx 1.24.0 with SSL)",
                ],
                "hypotheses": ["Primary target surface is web application"],
                "identified_targets": [target_ip],
                "next_recommended_actions": [],
                "should_stop": True,
                "stop_reason": "objectives_satisfied",
            }
        )

        call_count = 0

        async def mock_acompletion(**kwargs):
            nonlocal call_count
            call_count += 1
            content = plan_response if call_count == 1 else analysis_response
            choice = SimpleNamespace(message=SimpleNamespace(content=content, role="assistant"))
            usage = SimpleNamespace(prompt_tokens=25, completion_tokens=15, total_tokens=40)
            return SimpleNamespace(choices=[choice], usage=usage, model="gpt-4o")

        recon_e2e_env.llm._router = cast(Any, SimpleNamespace(acompletion=mock_acompletion))

        initial_state = ReconState(
            engagement_id="eng-recon-e2e",
            authorized_scope=recon_e2e_env.scope.model_dump(),
            recon_objectives=["Identify open services on target host"],
        )

        # Execute full ReconAgent loop
        final_state = await recon_e2e_env.agent.run(initial_state)

        # 1. Verify agent termination state
        assert final_state.status == "completed"
        assert final_state.termination_reason == ReconTerminationReason.OBJECTIVES_SATISFIED
        assert final_state.action_count == 1
        assert len(final_state.completed_actions) == 1
        assert final_state.completed_actions[0]["authorized"] is True
        assert final_state.completed_actions[0]["success"] is True

        # 2. Verify evidence stored in EvidenceStore
        assert len(final_state.evidence_refs) >= 1
        for ev_id in final_state.evidence_refs:
            assert recon_e2e_env.evidence_store.verify_integrity(ev_id) is True
            stored_ev = recon_e2e_env.evidence_store.get_evidence(ev_id)
            assert stored_ev is not None
            assert stored_ev.engagement_id == "eng-recon-e2e"

        # 3. Verify canonical asset and service records in AssetRepository
        assets = recon_e2e_env.asset_repo.get_assets_by_engagement("eng-recon-e2e")
        assert len(assets) == 1
        asset = assets[0]
        assert asset.address == target_ip
        assert len(asset.evidence_refs) >= 1
        assert asset.evidence_refs[0] in final_state.evidence_refs

        services = recon_e2e_env.asset_repo.get_services_by_asset(asset.asset_id)
        assert len(services) == 2
        service_ports = {s.port for s in services}
        assert service_ports == {80, 443}

        # 4. Verify observations and hypotheses extracted
        assert any("nginx" in obs for obs in final_state.observations)
        assert any("web application" in hyp for hyp in final_state.hypotheses)

        # 5. Verify audit events recorded
        events = await recon_e2e_env.audit.get_events(engagement_id="eng-recon-e2e")
        event_types = [e.event_type for e in events]
        assert AuditEventType.EVIDENCE_RECORDED.value in event_types
        assert AuditEventType.TOOL_EXECUTED.value in event_types
        assert AuditEventType.LLM_RESPONSE.value in event_types

    @pytest.mark.asyncio
    async def test_recon_langgraph_workflow_with_human_approval_gate(self, recon_e2e_env):
        """Test the interruptible LangGraph workflow when high-risk approval is required."""
        target_ip = "192.168.1.50"

        # Plan proposing an aggressive scan requiring approval (default_scripts=True)
        high_risk_plan = json.dumps(
            {
                "objective": "Aggressive reconnaissance scan",
                "reasoning_summary": "Run default scripts for vulnerability discovery",
                "candidate_actions": [
                    {
                        "tool_name": "nmap",
                        "operation": "scan",
                        "target": target_ip,
                        "arguments": {"ports": "80", "default_scripts": True},
                        "rationale": "High-risk probe",
                    }
                ],
                "stop_condition": None,
            }
        )

        analysis_done = json.dumps(
            {
                "summary": "Completed aggressive scan",
                "findings": ["Nginx web server confirmed"],
                "hypotheses": [],
                "identified_targets": [target_ip],
                "next_recommended_actions": [],
                "should_stop": True,
                "stop_reason": "objectives_satisfied",
            }
        )

        call_count = 0

        async def mock_acompletion(**kwargs):
            nonlocal call_count
            call_count += 1
            content = high_risk_plan if call_count == 1 else analysis_done
            choice = SimpleNamespace(message=SimpleNamespace(content=content, role="assistant"))
            usage = SimpleNamespace(prompt_tokens=20, completion_tokens=20, total_tokens=40)
            return SimpleNamespace(choices=[choice], usage=usage, model="gpt-4o")

        recon_e2e_env.llm._router = cast(Any, SimpleNamespace(acompletion=mock_acompletion))

        checkpointer = MemorySaver()
        graph = create_recon_graph(
            llm_gateway=recon_e2e_env.llm,
            tool_registry=recon_e2e_env.registry,
            audit_service=recon_e2e_env.audit,
            scope_guard=recon_e2e_env.guard,
            policy_engine=recon_e2e_env.policy,
            approval_manager=recon_e2e_env.approvals,
            asset_repository=recon_e2e_env.asset_repo,
            asset_normalizer=recon_e2e_env.normalizer,
            evidence_store=recon_e2e_env.evidence_store,
            checkpointer=checkpointer,
        )

        thread_id = "recon-thread-high-risk-1"
        config = {"configurable": {"thread_id": thread_id}}

        initial_state: ReconAgentState = {
            "engagement_id": "eng-recon-e2e",
            "authorized_scope": recon_e2e_env.scope.model_dump(),
            "recon_objectives": ["Aggressive scan with approval gate"],
            "current_assets": [],
            "current_services": [],
            "current_technologies": [],
            "current_endpoints": [],
            "current_task_id": "task-init",
            "current_action": None,
            "pending_actions": [],
            "executed_fingerprints": {},
            "llm_plan_raw": "",
            "llm_analysis_raw": "",
            "candidate_tool_request": None,
            "policy_decision": None,
            "tool_request": None,
            "tool_result": None,
            "requires_approval": False,
            "approval_id": None,
            "approval_status": "none",
            "completed_actions": [],
            "tool_results": [],
            "evidence_refs": [],
            "observations": [],
            "hypotheses": [],
            "errors": [],
            "audit_trail": [],
            "iteration": 0,
            "action_count": 0,
            "consecutive_failures": 0,
            "max_iterations": 3,
            "max_actions": 5,
            "max_repeated_action_attempts": 2,
            "max_consecutive_failures": 3,
            "status": "running",
            "should_continue": True,
            "termination_reason": None,
        }

        # 1. Run graph until human approval interrupt
        _interrupted_state = await graph.ainvoke(initial_state, config=config)

        # Graph suspended at interrupt
        state_snapshot = await graph.aget_state(config)
        assert len(state_snapshot.tasks) > 0
        interrupts = state_snapshot.tasks[0].interrupts
        assert len(interrupts) > 0
        approval_payload = interrupts[0].value
        assert approval_payload["tool"] == "nmap"
        assert approval_payload["risk_level"] == "high"

        # 2. Operator grants approval and resumes graph execution
        approval_id = approval_payload["approval_id"]
        recon_e2e_env.approvals.approve(approval_id=approval_id, approved_by="security_officer")

        resume_command: Command[Any] = Command(
            resume={"status": "approved", "approved_by": "security_officer"}
        )
        resumed_final_state = await graph.ainvoke(resume_command, config=config)

        # 3. Assert graph completed execution successfully
        assert resumed_final_state["status"] == "completed"
        assert len(resumed_final_state["completed_actions"]) == 1
        assert resumed_final_state["completed_actions"][0]["success"] is True
        assert target_ip in resumed_final_state["current_assets"]
