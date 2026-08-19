"""Integration tests for Nmap adapter through the full ARKA pipeline (Phase 2.2.1).

Proves:
- Full pipeline: CandidateToolRequest -> ToolRegistry -> PolicyEngine -> ExecutionManager
- In-scope target executes successfully
- Out-of-scope target rejected by PolicyEngine
- Evidence and audit records generated
"""

import pytest

from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import RiskLevel, ScopeDefinition, ScopeTarget
from arka.app.tools.nmap.definition import register_nmap_tool
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest


@pytest.fixture
def nmap_scope():
    return ScopeDefinition(
        engagement_id="nmap-int-test",
        includes=ScopeTarget(
            ip_addresses=["192.168.1.10", "10.0.0.1"],
            cidrs=["192.168.1.0/24"],
            domains=["example.com"],
            subdomains_allowed=True,
            ports=[22, 80, 443],
        ),
        excludes=ScopeTarget(
            ip_addresses=["192.168.1.100"],
            domains=["admin.example.com"],
        ),
    )


@pytest.fixture
def nmap_integration_registry(nmap_scope):
    scope_guard = ScopeGuard(nmap_scope)
    policy = PolicyEngine(scope_guard)
    audit = AuditService()
    approval_mgr = ApprovalManager()
    registry = ToolRegistry(policy, audit, approval_manager=approval_mgr)
    register_nmap_tool(registry)
    return registry, audit, approval_mgr


class TestNmapFullPipelineIntegration:
    @pytest.mark.asyncio
    async def test_in_scope_basic_scan_succeeds(self, nmap_integration_registry):
        registry, _audit, _approval_mgr = nmap_integration_registry

        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="192.168.1.10",
            arguments={"ports": "80,443", "service_detection": True},
            reason="Port scan for authorized target",
        )

        req, _decision, err = registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-nmap-int",
            task_id="task-nmap-int",
            agent_id="agent-recon",
        )
        assert req is not None, f"Validation failed: {err}"
        assert err is None
        assert req.scope_validated is True
        assert req.policy_approved is True

        result = await registry.execute(req)
        assert result.success is True
        assert result.output.get("host_count") == 1
        assert len(result.output.get("hosts", [])) == 1
        assert result.output.get("argv") is not None

        # Verify argv contains only allowlisted flags
        argv = result.output["argv"]
        assert argv[0] == "nmap"
        assert "-sV" in argv
        assert "-oX" in argv
        assert "192.168.1.10" in argv

    @pytest.mark.asyncio
    async def test_out_of_scope_target_rejected(self, nmap_integration_registry):
        registry, _audit, _approval_mgr = nmap_integration_registry

        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="10.99.99.99",
            arguments={"ports": "80"},
        )

        req, _decision, err = registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-nmap-int",
            task_id="task-nmap-int",
            agent_id="agent-recon",
        )
        assert req is None
        assert err is not None

    @pytest.mark.asyncio
    async def test_excluded_target_rejected(self, nmap_integration_registry):
        registry, _audit, _approval_mgr = nmap_integration_registry

        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="192.168.1.100",
            arguments={"ports": "80"},
        )

        req, _decision, err = registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-nmap-int",
            task_id="task-nmap-int",
            agent_id="agent-recon",
        )
        assert req is None
        assert err is not None

    @pytest.mark.asyncio
    async def test_aggressive_config_requires_escalation(self, nmap_integration_registry):
        registry, _audit, _approval_mgr = nmap_integration_registry

        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="192.168.1.10",
            arguments={"default_scripts": True, "timing_template": 4},
        )

        req, decision, err = registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-nmap-int",
            task_id="task-nmap-int",
            agent_id="agent-recon",
        )
        # PolicyEngine escalates to HIGH risk -> requires approval before ToolRequest is issued
        assert req is None
        assert decision is not None
        assert decision.decision.value == "require_approval"
        assert decision.risk_level == RiskLevel.HIGH
        assert "human approval" in (err or "").lower()

    @pytest.mark.asyncio
    async def test_aggressive_config_with_approval_succeeds(self, nmap_integration_registry):
        registry, _audit, approval_mgr = nmap_integration_registry

        # Create and grant approval
        approval = approval_mgr.create_request(
            engagement_id="eng-nmap-int",
            task_id="task-nmap-int",
            agent_id="agent-recon",
            action="execute_tool:nmap",
            tool_name="nmap",
            target="192.168.1.10",
            risk_level=RiskLevel.HIGH,
        )
        approval_mgr.approve(approval.approval_id, approved_by="sec_admin")

        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="192.168.1.10",
            arguments={"default_scripts": True, "timing_template": 4},
        )

        req, _decision, err = registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-nmap-int",
            task_id="task-nmap-int",
            agent_id="agent-recon",
            approval_id=approval.approval_id,
        )
        assert req is not None, f"Candidate validation failed: {err}"
        assert req.approval_id == approval.approval_id
        assert req.risk_level == RiskLevel.HIGH
        assert req.scope_validated is True
        assert req.policy_approved is True

        result = await registry.execute(req)
        assert result.success is True
        assert result.output.get("host_count") == 1

    @pytest.mark.asyncio
    async def test_audit_trail_generated(self, nmap_integration_registry):
        registry, audit, _approval_mgr = nmap_integration_registry

        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="192.168.1.10",
            arguments={"ports": "80"},
        )

        req, _dec, _err = registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-nmap-audit",
            task_id="task-nmap-audit",
            agent_id="agent-recon",
        )
        assert req is not None

        await registry.execute(req)

        events = await audit.get_events(engagement_id="eng-nmap-audit")
        assert len(events) > 0
        event_types = [e.event_type.value for e in events]
        # At minimum, policy decision and execution events should be recorded
        assert "policy.decision" in event_types

    @pytest.mark.asyncio
    async def test_unknown_arguments_rejected(self, nmap_integration_registry):
        registry, _audit, _approval_mgr = nmap_integration_registry

        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="192.168.1.10",
            arguments={"ports": "80", "script_args": "exploit=true"},
        )

        req, _dec, err = registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-nmap-int",
            task_id="task-nmap-int",
            agent_id="agent-recon",
        )
        assert req is None
        assert "Unknown argument" in (err or "")
