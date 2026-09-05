"""Adversarial and security isolation tests for ARKA scope boundaries."""

import pytest

from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.models import Asset, AssetType, NormalizedAssetBundle
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope import (
    ScopeGuard,
    ScopeValidationError,
    ScopeViolation,
    validate_scope_definition,
)
from arka.app.core.state.models import (
    ApprovalStatus,
    RiskLevel,
    ScopeDefinition,
    ScopeTarget,
)
from arka.app.execution.engine import ExecutionEngine
from arka.app.tools.mock.tools import EchoToolExecutor, get_echo_tool_definition
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import ToolRequest


class TestCrossEngagementScopeIsolation:
    """Verify complete isolation between different engagements and their scopes."""

    def test_cross_engagement_target_isolation(self):
        # Engagement A: authorized ONLY for 127.0.0.1:3000
        scope_a = ScopeDefinition(
            engagement_id="eng-A",
            version=1,
            includes=ScopeTarget(
                ip_addresses=["127.0.0.1"],
                ports=[3000],
            ),
        )
        guard_a = ScopeGuard(scope_a)

        # Engagement B: authorized ONLY for 10.0.0.1:80
        scope_b = ScopeDefinition(
            engagement_id="eng-B",
            version=1,
            includes=ScopeTarget(
                ip_addresses=["10.0.0.1"],
                ports=[80],
            ),
        )
        guard_b = ScopeGuard(scope_b)

        # Target A
        assert guard_a.validate_target("127.0.0.1:3000") is True
        with pytest.raises(ScopeViolation):
            guard_b.validate_target("127.0.0.1:3000")

        # Target B
        assert guard_b.validate_target("10.0.0.1:80") is True
        with pytest.raises(ScopeViolation):
            guard_a.validate_target("10.0.0.1:80")

    def test_cross_engagement_approval_isolation(self):
        manager = ApprovalManager()

        # Approval created for Engagement A
        req_a = manager.create_request(
            engagement_id="eng-A",
            task_id="task-1",
            agent_id="recon-1",
            action="execute_tool:nmap",
            target="127.0.0.1:3000",
            tool_name="nmap",
            risk_level=RiskLevel.HIGH,
            scope_version=1,
        )
        manager.approve(req_a.approval_id, approved_by="admin")

        # Attempt to use Approval A in Engagement B must fail
        assert not manager.validate_approval_for_request(
            approval_id=req_a.approval_id,
            engagement_id="eng-B",
            task_id="task-1",
            tool_name="nmap",
            target="127.0.0.1:3000",
            scope_version=1,
        )

        # Valid for Engagement A
        assert manager.validate_approval_for_request(
            approval_id=req_a.approval_id,
            engagement_id="eng-A",
            task_id="task-1",
            tool_name="nmap",
            target="127.0.0.1:3000",
            scope_version=1,
        )


class TestDiscoveredNotAuthorizedInvariant:
    """MANDATORY INVARIANT: DISCOVERED != AUTHORIZED.

    Assets discovered during reconnaissance MUST NEVER automatically become authorized targets.
    """

    def test_discovered_asset_never_expands_scope(self):
        initial_scope = ScopeDefinition(
            engagement_id="eng-juice",
            version=1,
            includes=ScopeTarget(
                ip_addresses=["127.0.0.1"],
                ports=[3000],
            ),
        )
        guard = ScopeGuard(initial_scope)
        repo = InMemoryAssetRepository()

        # Simulate reconnaissance discovery of an out-of-scope service / asset
        discovered_asset = Asset(
            asset_id="asset-discovered-1",
            engagement_id="eng-juice",
            asset_type=AssetType.IP,
            address="127.0.0.1",
            status="discovered",
            metadata={"discovered_port": 4000, "service": "internal-admin"},
        )
        bundle = NormalizedAssetBundle(
            engagement_id="eng-juice",
            assets=[discovered_asset],
        )
        repo.save_bundle(bundle)

        # Confirm asset is recorded in repository for risk knowledge
        assert repo.get_asset_by_id("asset-discovered-1") is not None

        # Verify initial scope definition was NOT modified
        assert 4000 not in initial_scope.includes.ports

        # Verify ScopeGuard STILL strictly denies the discovered port 4000
        with pytest.raises(ScopeViolation):
            guard.validate_target("127.0.0.1:4000")

        # In-scope port 3000 remains authorized
        assert guard.validate_target("127.0.0.1:3000") is True


class TestScopeVersionBindingSecurity:
    """Verify that approvals and execution requests are strictly bound to scope version."""

    def test_scope_mutation_invalidates_active_approvals(self):
        manager = ApprovalManager()

        req = manager.create_request(
            engagement_id="eng-version",
            task_id="task-1",
            agent_id="agent-1",
            action="execute_tool:nmap",
            target="127.0.0.1:3000",
            tool_name="nmap",
            risk_level=RiskLevel.HIGH,
            scope_version=1,
        )
        manager.approve(req.approval_id, approved_by="admin")

        # Valid under scope v1
        assert manager.validate_approval_for_request(
            approval_id=req.approval_id,
            engagement_id="eng-version",
            task_id="task-1",
            tool_name="nmap",
            target="127.0.0.1:3000",
            scope_version=1,
        )

        # Scope mutates to v2 -> invalidation triggered
        invalidated_count = manager.invalidate_for_engagement(
            engagement_id="eng-version",
            reason="Scope mutated to version 2",
        )
        assert invalidated_count == 1

        # Check approval status is EXPIRED
        updated_req = manager.get_request(req.approval_id)
        assert updated_req is not None
        assert updated_req.status == ApprovalStatus.EXPIRED

        # Verification under v2 fails because status is EXPIRED and version mismatch
        assert not manager.validate_approval_for_request(
            approval_id=req.approval_id,
            engagement_id="eng-version",
            task_id="task-1",
            tool_name="nmap",
            target="127.0.0.1:3000",
            scope_version=2,
        )

    @pytest.mark.asyncio
    async def test_execution_engine_rejects_stale_scope_version_request(self):
        from arka.app.audit.service import AuditService

        scope_v1 = ScopeDefinition(
            engagement_id="eng-1",
            version=1,
            includes=ScopeTarget(ip_addresses=["127.0.0.1"], ports=[3000]),
        )
        audit = AuditService()
        policy = PolicyEngine(ScopeGuard(scope_v1))
        registry = ToolRegistry(policy, audit)
        mock_def = get_echo_tool_definition()
        registry.register(mock_def, EchoToolExecutor())
        engine = ExecutionEngine(tool_registry=registry, audit_service=audit)

        # Request created under Scope v1
        req_v1 = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name=mock_def.name,
            target="127.0.0.1:3000",
            arguments={"message": "hello"},
            scope_validated=True,
            policy_approved=True,
            scope_version=1,
        )

        # Execution against expected scope v2 must be rejected
        with pytest.raises(ValueError) as exc:
            await engine.execute(req_v1, expected_scope_version=2)
        assert "Scope version mismatch" in str(exc.value)

        # Execution against matching scope v1 succeeds
        result = await engine.execute(req_v1, expected_scope_version=1)
        assert result.success is True


class TestURLPathSemanticsSecurity:
    """Verify exact URL path prefix enforcement in ScopeGuard."""

    def test_url_path_prefix_matching(self):
        scope = ScopeDefinition(
            engagement_id="eng-url",
            version=1,
            includes=ScopeTarget(
                urls=["http://127.0.0.1:3000/api"],
            ),
            excludes=ScopeTarget(
                urls=["http://127.0.0.1:3000/api/internal"],
            ),
        )
        guard = ScopeGuard(scope)

        # Path matching /api or subpaths allowed
        assert guard.validate_url("http://127.0.0.1:3000/api") is True
        assert guard.validate_url("http://127.0.0.1:3000/api/v1/users") is True
        assert guard.validate_url("http://127.0.0.1:3000/api/products/123") is True

        # Path outside /api strictly denied
        assert guard.validate_url("http://127.0.0.1:3000/admin") is False
        assert guard.validate_url("http://127.0.0.1:3000/login") is False

        # Excluded subpath /api/internal strictly denied
        assert guard.validate_url("http://127.0.0.1:3000/api/internal") is False
        assert guard.validate_url("http://127.0.0.1:3000/api/internal/keys") is False


class TestAdversarialTamperingAndSuffixCollisions:
    """Test adversarial injection payloads and suffix confusion attacks."""

    def test_suffix_collision_attack_prevention(self):
        scope = ScopeDefinition(
            engagement_id="eng-suffix",
            version=1,
            includes=ScopeTarget(
                domains=["target.com"],
                subdomains_allowed=True,
            ),
        )
        guard = ScopeGuard(scope)

        # Legitimate domain and subdomains
        assert guard.validate_domain("target.com") is True
        assert guard.validate_domain("api.target.com") is True
        assert guard.validate_domain("v1.api.target.com") is True

        # Suffix collision attacks (evil-target.com, nottarget.com) MUST be rejected
        assert guard.validate_domain("evil-target.com") is False
        assert guard.validate_domain("nottarget.com") is False
        assert guard.validate_domain("target.com.attacker.com") is False
        assert guard.validate_domain("fake-target.com") is False

    def test_injection_payloads_in_scope_rejected(self):
        # Disallow command injection characters in domain targets
        with pytest.raises(ScopeValidationError):
            validate_scope_definition(
                ScopeDefinition(
                    engagement_id="eng-inj",
                    includes=ScopeTarget(domains=["target.com; cat /etc/passwd"]),
                )
            )

        with pytest.raises(ScopeValidationError):
            validate_scope_definition(
                ScopeDefinition(
                    engagement_id="eng-inj",
                    includes=ScopeTarget(domains=["target.com | echo pwned"]),
                )
            )

        with pytest.raises(ScopeValidationError):
            validate_scope_definition(
                ScopeDefinition(
                    engagement_id="eng-inj",
                    includes=ScopeTarget(domains=["$(whoami).target.com"]),
                )
            )
