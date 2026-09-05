"""Unit tests for ARKA Phase 2.2.4 ReconAgent.

Tests state serialization, action validation, plan validation, fingerprint determinism,
idempotency, loop limit enforcement, failure thresholds, and result processing.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from arka.app.agents.recon.agent import ReconAgent
from arka.app.agents.recon.models import (
    ReconAction,
    ReconAgentConfig,
    ReconAnalysis,
    ReconPlan,
    ReconState,
    ReconTerminationReason,
    compute_action_fingerprint,
)
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.execution.evidence import EvidenceStore
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.tools.nmap.definition import register_nmap_tool
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import ToolResult


@pytest.fixture
def recon_scope() -> ScopeDefinition:
    return ScopeDefinition(
        engagement_id="eng-recon-unit",
        includes=ScopeTarget(
            domains=["recon.target.corp"],
            ip_addresses=["192.168.1.10", "10.0.0.5"],
            cidrs=["192.168.1.0/24"],
        ),
        excludes=ScopeTarget(ip_addresses=["192.168.1.254"]),
    )


@pytest.fixture
def recon_services(recon_scope: ScopeDefinition):
    guard = ScopeGuard(recon_scope)
    policy = PolicyEngine(guard)
    audit = AuditService()
    approvals = ApprovalManager()
    registry = ToolRegistry(policy, audit, approvals)
    register_nmap_tool(registry)
    evidence_store = EvidenceStore()
    asset_repo = InMemoryAssetRepository()
    normalizer = AssetNormalizer()
    llm = LLMGateway(audit_service=audit)

    return SimpleNamespace(
        guard=guard,
        policy=policy,
        audit=audit,
        approvals=approvals,
        registry=registry,
        evidence_store=evidence_store,
        asset_repo=asset_repo,
        normalizer=normalizer,
        llm=llm,
    )


class TestReconModelsAndFingerprinting:
    """Validate typing, Pydantic schemas, and deterministic fingerprinting."""

    def test_recon_action_validation(self):
        action = ReconAction(
            tool_name="nmap",
            operation="scan",
            arguments={"ports": "80,443"},
            target="192.168.1.10",
            rationale="Initial web probe",
        )
        assert action.tool_name == "nmap"
        assert action.target == "192.168.1.10"
        assert action.fingerprint() == action.fingerprint()

    def test_action_fingerprint_determinism(self):
        # Fingerprint must be identical despite dictionary key ordering or whitespace
        fp1 = compute_action_fingerprint(
            tool_name="nmap",
            operation="scan",
            target="192.168.1.10",
            arguments={"ports": "80,443", "timing_template": 2},
        )
        fp2 = compute_action_fingerprint(
            tool_name="NMAP ",
            operation=" SCAN ",
            target=" 192.168.1.10 ",
            arguments={"timing_template": 2, "ports": "80,443"},
        )
        assert fp1 == fp2
        assert len(fp1) == 64  # SHA-256 hex string

    def test_action_fingerprint_sensitivity(self):
        fp1 = compute_action_fingerprint("nmap", "scan", "192.168.1.10", {"ports": "80"})
        fp2 = compute_action_fingerprint("nmap", "scan", "192.168.1.10", {"ports": "443"})
        fp3 = compute_action_fingerprint("nmap", "scan", "192.168.1.11", {"ports": "80"})
        assert fp1 != fp2
        assert fp1 != fp3

    def test_recon_state_serialization_roundtrip(self, recon_scope: ScopeDefinition):
        state = ReconState(
            engagement_id="eng-test-1",
            authorized_scope=recon_scope.model_dump(),
            recon_objectives=["Find all web servers"],
            current_assets=["192.168.1.10"],
            iteration=2,
            action_count=3,
        )
        serialized = state.model_dump_json()
        deserialized = ReconState.model_validate_json(serialized)
        assert deserialized.engagement_id == "eng-test-1"
        assert deserialized.current_assets == ["192.168.1.10"]
        assert deserialized.iteration == 2

    def test_recon_plan_validation(self):
        raw_json = {
            "objective": "Port scan target subnet",
            "reasoning_summary": "Identify live web services",
            "candidate_actions": [
                {
                    "tool_name": "nmap",
                    "operation": "scan",
                    "arguments": {"ports": "80,443"},
                    "target": "192.168.1.10",
                    "rationale": "Web discovery",
                }
            ],
            "stop_condition": None,
        }
        plan = ReconPlan.model_validate(raw_json)
        assert len(plan.candidate_actions) == 1
        assert plan.candidate_actions[0].tool_name == "nmap"

    def test_recon_analysis_validation(self):
        raw_json = {
            "summary": "Nmap completed with 2 open ports",
            "findings": ["Port 80 is open", "Port 443 is open"],
            "hypotheses": ["Target hosts web application"],
            "identified_targets": ["192.168.1.10"],
            "next_recommended_actions": [],
            "should_stop": True,
            "stop_reason": "objectives_satisfied",
        }
        analysis = ReconAnalysis.model_validate(raw_json)
        assert analysis.should_stop is True
        assert analysis.stop_reason == ReconTerminationReason.OBJECTIVES_SATISFIED


class TestReconAgentExecutionLogic:
    """Validate ReconAgent methods and safety loop boundaries."""

    @pytest.mark.asyncio
    async def test_prioritize_next_action_idempotency(self, recon_services):
        agent = ReconAgent(
            llm_gateway=recon_services.llm,
            tool_registry=recon_services.registry,
            audit_service=recon_services.audit,
            scope_guard=recon_services.guard,
            policy_engine=recon_services.policy,
            config=ReconAgentConfig(max_repeated_action_attempts=2),
        )

        action = ReconAction(
            tool_name="nmap",
            operation="scan",
            arguments={"ports": "80"},
            target="192.168.1.10",
        )
        fp = action.fingerprint()

        state = ReconState(
            engagement_id="eng-unit",
            pending_actions=[action.model_dump(), action.model_dump()],
            executed_fingerprints={fp: 1},
        )

        # First pop: executions is 1 < 2, should be accepted
        next_act = agent.prioritize_next_action(state)
        assert next_act is not None
        assert next_act.fingerprint() == fp

        # Simulate execution count incremented to 2
        state.executed_fingerprints[fp] = 2

        # Second pop: executions is 2 >= max (2), should be discarded
        next_act_2 = agent.prioritize_next_action(state)
        assert next_act_2 is None
        assert any("reached max repeated attempts" in e for e in state.errors)

    @pytest.mark.asyncio
    async def test_step_terminates_on_max_iterations(self, recon_services):
        agent = ReconAgent(
            llm_gateway=recon_services.llm,
            tool_registry=recon_services.registry,
            audit_service=recon_services.audit,
            scope_guard=recon_services.guard,
            policy_engine=recon_services.policy,
            config=ReconAgentConfig(max_iterations=3),
        )

        state = ReconState(
            engagement_id="eng-unit",
            iteration=3,
        )

        updated_state = await agent.step(state)
        assert updated_state.status == "completed"
        assert updated_state.termination_reason == ReconTerminationReason.MAX_ITERATIONS_REACHED

    @pytest.mark.asyncio
    async def test_step_terminates_on_max_actions(self, recon_services):
        agent = ReconAgent(
            llm_gateway=recon_services.llm,
            tool_registry=recon_services.registry,
            audit_service=recon_services.audit,
            scope_guard=recon_services.guard,
            policy_engine=recon_services.policy,
            config=ReconAgentConfig(max_actions=5),
        )

        state = ReconState(
            engagement_id="eng-unit",
            action_count=5,
        )

        updated_state = await agent.step(state)
        assert updated_state.status == "completed"
        assert updated_state.termination_reason == ReconTerminationReason.MAX_ACTIONS_REACHED

    @pytest.mark.asyncio
    async def test_step_terminates_on_consecutive_failures(self, recon_services):
        agent = ReconAgent(
            llm_gateway=recon_services.llm,
            tool_registry=recon_services.registry,
            audit_service=recon_services.audit,
            scope_guard=recon_services.guard,
            policy_engine=recon_services.policy,
            config=ReconAgentConfig(max_consecutive_failures=3),
        )

        state = ReconState(
            engagement_id="eng-unit",
            consecutive_failures=3,
        )

        updated_state = await agent.step(state)
        assert updated_state.status == "failed"
        assert updated_state.termination_reason == ReconTerminationReason.REPEATED_FAILURES

    @pytest.mark.asyncio
    async def test_plan_reconnaissance_handles_malformed_llm_json(self, recon_services):
        mock_choice = SimpleNamespace(
            message=SimpleNamespace(content="Not valid json output here", role="assistant")
        )
        mock_usage = SimpleNamespace(prompt_tokens=10, completion_tokens=10, total_tokens=20)
        llm_mock_res = SimpleNamespace(choices=[mock_choice], usage=mock_usage)
        recon_services.llm._router = cast(
            Any, SimpleNamespace(acompletion=AsyncMock(return_value=llm_mock_res))
        )

        agent = ReconAgent(
            llm_gateway=recon_services.llm,
            tool_registry=recon_services.registry,
            audit_service=recon_services.audit,
            scope_guard=recon_services.guard,
            policy_engine=recon_services.policy,
        )

        state = ReconState(engagement_id="eng-unit")
        plan = await agent.plan_reconnaissance(state)
        assert plan is None
        assert len(state.errors) > 0
        assert "Failed to parse LLM reconnaissance plan" in state.errors[0]

    @pytest.mark.asyncio
    async def test_process_tool_result_populates_asset_repository(self, recon_services):
        agent = ReconAgent(
            llm_gateway=recon_services.llm,
            tool_registry=recon_services.registry,
            audit_service=recon_services.audit,
            scope_guard=recon_services.guard,
            policy_engine=recon_services.policy,
            asset_repository=recon_services.asset_repo,
            asset_normalizer=recon_services.normalizer,
        )

        # Simulated Nmap XML result
        simulated_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.10" version="7.95">
<host>
<status state="up"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" product="nginx" version="1.24.0"/>
</port>
</ports>
</host>
</nmaprun>"""

        tool_result = ToolResult(
            request_id="req-unit-1",
            engagement_id="eng-unit",
            task_id="task-unit-1",
            tool_name="nmap",
            success=True,
            output={"host_count": 1},
            raw_output=simulated_xml,
            evidence_refs=["ev-sha256-test-1"],
        )

        state = ReconState(engagement_id="eng-unit")
        action = ReconAction(
            tool_name="nmap",
            operation="scan",
            target="192.168.1.10",
            arguments={},
        )

        await agent.process_tool_result(
            result=tool_result,
            state=state,
            original_action=action,
            task_id="task-unit-1",
        )

        # Assert state updated
        assert "192.168.1.10" in state.current_assets
        assert "ev-sha256-test-1" in state.evidence_refs

        # Assert persisted in repository
        assets = recon_services.asset_repo.get_assets_by_engagement("eng-unit")
        assert len(assets) == 1
        assert assets[0].address == "192.168.1.10"
        services = recon_services.asset_repo.get_services_by_asset(assets[0].asset_id)
        assert len(services) == 1
        assert services[0].port == 80
        assert services[0].product == "nginx"
