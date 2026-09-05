"""Security tests for Recon Orchestration Bridge and Execution Boundaries.

MANDATORY INVARIANTS TESTED:
1. CandidateToolRequest -> ScopeGuard -> DENY
2. ExecutionManager.execute_tool is NEVER called on denial
3. ToolExecutor.execute is NEVER called on denial
4. Discovery != Authorization: Discovered infrastructure never expands scope
5. Scope version mutation invalidates prior authorizations
6. High-risk actions cannot bypass ApprovalManager in autonomous loop
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.execution.evidence import EvidenceStore
from arka.app.execution.manager import ExecutionManager
from arka.app.tools.nmap.definition import get_nmap_tool_definition
from arka.app.tools.nmap.executor import NmapToolExecutor
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest, ToolRequest


@pytest.fixture
def auth_scope_v1() -> ScopeDefinition:
    """Authoritative scope definition version 1."""
    return ScopeDefinition(
        engagement_id="eng-sec-test-1",
        version=1,
        includes=ScopeTarget(
            ip_addresses=["127.0.0.1"],
            ports=[3000],
        ),
        excludes=ScopeTarget(
            ip_addresses=["10.0.0.1"],
        ),
    )


@pytest.fixture
def security_context(auth_scope_v1):
    """Construct complete security pipeline with spy capabilities."""
    audit = AuditService()
    scope_guard = ScopeGuard(auth_scope_v1)
    policy_engine = PolicyEngine(scope_guard)
    approvals = ApprovalManager()
    evidence_store = EvidenceStore()
    execution_manager = ExecutionManager(audit_service=audit, evidence_store=evidence_store)
    registry = ToolRegistry(
        policy_engine=policy_engine,
        audit_service=audit,
        approval_manager=approvals,
        execution_manager=execution_manager,
    )

    executor = NmapToolExecutor()
    registry.register(get_nmap_tool_definition(), executor)

    return {
        "scope_guard": scope_guard,
        "policy_engine": policy_engine,
        "approvals": approvals,
        "execution_manager": execution_manager,
        "registry": registry,
        "executor": executor,
        "scope_v1": auth_scope_v1,
    }


def test_untrusted_candidate_action_out_of_scope_denied(security_context):
    """Test out-of-scope candidate action is authoritatively rejected."""
    registry: ToolRegistry = security_context["registry"]

    candidate = CandidateToolRequest(
        tool_name="nmap",
        target="127.0.0.1:4000",  # Port 4000 is out of scope (only 3000 is authorized)
        arguments={"ports": "4000"},
        reason="Recon probe",
    )

    auth_req, decision, err = registry.validate_candidate_request(
        candidate=candidate,
        engagement_id="eng-sec-test-1",
        task_id="task-1",
        agent_id="recon_agent",
    )

    assert auth_req is None, (
        "Out-of-scope candidate request must NOT produce an authoritative ToolRequest"
    )
    assert decision is not None
    assert decision.decision.value == "deny"
    assert "Port 4000 not in scope" in (err or "")


@pytest.mark.asyncio
async def test_execution_manager_not_called_on_denial(security_context):
    """MANDATORY SECURITY INVARIANT:

    CandidateToolRequest -> ScopeGuard -> DENY
    assert ExecutionManager.execute_tool NOT CALLED
    assert ToolExecutor.execute NOT CALLED
    """
    registry: ToolRegistry = security_context["registry"]
    execution_manager: ExecutionManager = security_context["execution_manager"]
    executor: NmapToolExecutor = security_context["executor"]

    with (
        patch.object(execution_manager, "execute_tool", new_callable=AsyncMock) as mock_em_exec,
        patch.object(executor, "execute", new_callable=AsyncMock) as mock_tool_exec,
    ):
        # Attempt to directly execute an out-of-scope tool request
        unauthorized_req = ToolRequest(
            engagement_id="eng-sec-test-1",
            task_id="task-1",
            agent_id="recon_agent",
            tool_name="nmap",
            target="192.168.1.55",  # completely out of scope
            arguments={"ports": "80"},
            reason="Adversarial attempt",
        )

        result = await registry.execute(unauthorized_req)

        # 1. Result must indicate failure
        assert result.success is False
        assert "Policy denied" in result.error

        # 2. ExecutionManager must NEVER be reached
        mock_em_exec.assert_not_called()

        # 3. ToolExecutor must NEVER be reached
        mock_tool_exec.assert_not_called()


@pytest.mark.asyncio
async def test_discovery_does_not_expand_scope(security_context):
    """MANDATORY SECURITY INVARIANT: DISCOVERY != AUTHORIZATION.

    Even if recon discovers infrastructure (e.g. port 4000), it cannot be targeted
    until the scope is authoritatively updated in PostgreSQL.
    """
    registry: ToolRegistry = security_context["registry"]
    asset_repo = InMemoryAssetRepository()

    from arka.app.core.assets.models import Asset, AssetType, NormalizedAssetBundle, Service

    # Step 1: Simulate asset discovery through evidence ingestion
    # Discovers service on port 4000 on 127.0.0.1
    discovered_asset = Asset(
        asset_id="asset-1",
        engagement_id="eng-sec-test-1",
        address="127.0.0.1",
        asset_type=AssetType.IP,
    )
    discovered_service = Service(
        service_id="svc-1",
        asset_id="asset-1",
        engagement_id="eng-sec-test-1",
        port=4000,
        protocol="tcp",
        state="open",
    )
    bundle = NormalizedAssetBundle(
        engagement_id="eng-sec-test-1",
        assets=[discovered_asset],
        services=[discovered_service],
    )
    asset_repo.save_bundle(bundle)

    # Step 2: Agent attempts to target the newly discovered port 4000
    candidate_on_discovered_port = CandidateToolRequest(
        tool_name="nmap",
        target="127.0.0.1:4000",
        arguments={"ports": "4000"},
        reason="Explore newly discovered port 4000",
    )

    auth_req, decision, err = registry.validate_candidate_request(
        candidate=candidate_on_discovered_port,
        engagement_id="eng-sec-test-1",
        task_id="task-1",
        agent_id="recon_agent",
    )

    # Must be denied despite having been discovered
    assert auth_req is None
    assert decision.decision.value == "deny"
    assert "Port 4000 not in scope" in (err or "")


@pytest.mark.asyncio
async def test_scope_version_mutation_invalidates_prior_request(auth_scope_v1):
    """MANDATORY SECURITY INVARIANT: Scope version binding.

    A request validated under scope v1 cannot execute if the authoritative
    scope has incremented to v2 where that target is excluded.
    """
    audit = AuditService()
    # Scope v2 excludes the target that was in scope v1
    scope_v2 = ScopeDefinition(
        engagement_id="eng-sec-test-1",
        version=2,
        includes=ScopeTarget(ip_addresses=["127.0.0.1"], ports=[3000]),
        excludes=ScopeTarget(ip_addresses=["127.0.0.1"]),  # Now excluded!
    )
    guard_v2 = ScopeGuard(scope_v2)
    policy_v2 = PolicyEngine(guard_v2)
    registry_v2 = ToolRegistry(
        policy_engine=policy_v2,
        audit_service=audit,
    )
    registry_v2.register(get_nmap_tool_definition(), NmapToolExecutor())

    # Create a request constructed under old scope v1
    stale_req = ToolRequest(
        engagement_id="eng-sec-test-1",
        task_id="task-1",
        agent_id="recon_agent",
        tool_name="nmap",
        target="127.0.0.1:3000",
        arguments={"ports": "3000"},
        reason="Old scan",
        scope_version=1,  # Old version!
    )

    # Executing against registry with scope v2 must be DENIED
    result = await registry_v2.execute(stale_req)
    assert result.success is False
    assert "Scope version mismatch" in result.error or "Policy denied" in result.error


@pytest.mark.asyncio
async def test_approval_not_bypassed_in_autonomous_loop(security_context):
    """Verify high-risk tools cannot execute without ApprovalManager approval."""
    registry: ToolRegistry = security_context["registry"]

    # Request aggressive scan with default scripts (-sC) which escalates risk to HIGH
    high_risk_candidate = CandidateToolRequest(
        tool_name="nmap",
        target="127.0.0.1:3000",
        arguments={"ports": "3000", "default_scripts": True},
        reason="Aggressive vulnerability scan",
    )

    auth_req, decision, err = registry.validate_candidate_request(
        candidate=high_risk_candidate,
        engagement_id="eng-sec-test-1",
        task_id="task-1",
        agent_id="recon_agent",
        approval_id=None,  # No approval provided!
    )

    assert auth_req is None, "High risk tool without approval must NOT be authorized"
    assert decision.decision.value == "require_approval"
    assert "Requires human approval" in (err or "")
