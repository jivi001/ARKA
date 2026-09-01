"""Security tests for ARKA asset normalization and strict authorization boundary.

Verifies the foundational invariant: DISCOVERED != AUTHORIZED.
Discovered infrastructure stored in the asset database is observation-only data
and NEVER expands authorization scope or bypasses ScopeGuard / PolicyEngine.
"""

import pytest

from arka.app.core.assets.models import AssetType
from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard, ScopeViolation
from arka.app.core.state.models import (
    PolicyDecisionType,
    ScopeDefinition,
    ScopeTarget,
)
from arka.app.tools.mock.tools import EchoToolExecutor, get_echo_tool_definition
from arka.app.tools.nmap.schemas import (
    NmapHost,
    NmapPort,
    NmapResult,
    NmapService,
)
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest


@pytest.fixture
def authorized_scope() -> ScopeDefinition:
    """Scope explicitly restricted to 192.168.1.0/24 and authorized.com."""
    return ScopeDefinition(
        engagement_id="eng-sec-1",
        includes=ScopeTarget(
            domains=["authorized.com"],
            subdomains_allowed=False,
            cidrs=["192.168.1.0/24"],
            ports=[80, 443],
        ),
        excludes=ScopeTarget(
            ip_addresses=["192.168.1.254"],
        ),
    )


@pytest.fixture
def scope_guard(authorized_scope) -> ScopeGuard:
    return ScopeGuard(authorized_scope)


@pytest.fixture
def policy_engine(scope_guard) -> PolicyEngine:
    return PolicyEngine(scope_guard)


@pytest.fixture
def normalizer() -> AssetNormalizer:
    return AssetNormalizer()


@pytest.fixture
def asset_repo() -> InMemoryAssetRepository:
    return InMemoryAssetRepository()


class TestDiscoveredNotAuthorizedInvariant:
    """CRITICAL SECURITY INVARIANT: DISCOVERED != AUTHORIZED."""

    def test_discovered_out_of_scope_asset_remains_unauthorized(
        self, normalizer, asset_repo, scope_guard, policy_engine
    ):
        """When Nmap discovers an out-of-scope IP (e.g. 10.0.0.50), storing it in the

        asset repository MUST NOT authorize future scans against it.
        """
        # 1. Nmap discovers 10.0.0.50 (which is out of scope 192.168.1.0/24)
        discovered_host = NmapHost(
            address="10.0.0.50",
            status="up",
            ports=[
                NmapPort(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service=NmapService(name="http", product="nginx", version="1.24.0"),
                )
            ],
        )
        nmap_res = NmapResult(hosts=[discovered_host])

        bundle = normalizer.normalize_nmap_result(
            result=nmap_res,
            engagement_id="eng-sec-1",
            target="192.168.1.10",  # Initial authorized target
            evidence_refs=["ev-scan-01"],
        )

        # 2. Persist in asset repository
        asset_repo.save_bundle(bundle)
        assets = asset_repo.get_assets_by_engagement("eng-sec-1")
        assert len(assets) == 1
        assert assets[0].address == "10.0.0.50"

        # 3. VERIFY: ScopeGuard STILL rejects the discovered asset
        with pytest.raises(ScopeViolation):
            scope_guard.validate_target("10.0.0.50")

        # 4. VERIFY: ToolRegistry / PolicyEngine rejects tool execution on discovered asset
        from arka.app.audit.service import AuditService

        registry = ToolRegistry(policy_engine, AuditService())
        registry.register(get_echo_tool_definition(), EchoToolExecutor())

        candidate = CandidateToolRequest(
            tool_name="echo_test",
            target="10.0.0.50",
            arguments={"message": "probe"},
            reason="follow-up scan on discovered asset",
        )

        tool_req, decision, _err = registry.validate_candidate_request(
            candidate,
            engagement_id="eng-sec-1",
            task_id="task-followup",
            agent_id="recon-agent",
        )

        assert tool_req is None
        assert decision is not None
        assert decision.decision == PolicyDecisionType.DENY
        reason_lower = decision.reason.lower()
        assert "out of scope" in reason_lower or "not in scope" in reason_lower

    def test_discovered_subdomain_when_subdomains_disallowed(
        self, normalizer, asset_repo, scope_guard, policy_engine
    ):
        """When subdomains are disallowed in scope, discovering admin.authorized.com

        does NOT allow scanning admin.authorized.com.
        """
        discovered_host = NmapHost(
            address="192.168.1.50",
            hostnames=["admin.authorized.com"],
            status="up",
        )
        bundle = normalizer.normalize_nmap_result(
            result=NmapResult(hosts=[discovered_host]),
            engagement_id="eng-sec-1",
            evidence_refs=["ev-subdomain"],
        )
        asset_repo.save_bundle(bundle)

        # Domain is disallowed because subdomains_allowed=False
        with pytest.raises(ScopeViolation):
            scope_guard.validate_target("admin.authorized.com")


class TestAdversarialInputsAndSanitization:
    """Test handling of hostile/malformed data from untrusted scan outputs."""

    def test_command_injection_in_service_banner_treated_as_inert_data(
        self, normalizer, asset_repo
    ):
        """Service banners containing shell injection payloads must be stored as inert text."""
        malicious_banner = "nginx/1.24.0; rm -rf /; $(reboot); `id` | cat /etc/passwd"
        host = NmapHost(
            address="192.168.1.10",
            status="up",
            ports=[
                NmapPort(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service=NmapService(
                        name="http",
                        product="nginx",
                        version="1.24.0",
                        extra_info=malicious_banner,
                    ),
                )
            ],
        )
        bundle = normalizer.normalize_nmap_result(
            result=NmapResult(hosts=[host]),
            engagement_id="eng-sec-1",
            evidence_refs=["ev-inj"],
        )
        asset_repo.save_bundle(bundle)

        services = asset_repo.get_services_by_asset(bundle.assets[0].asset_id)
        assert len(services) == 1
        assert malicious_banner in services[0].banner

    def test_oversized_banner_strings_handled_safely(self, normalizer, asset_repo):
        """Oversized banner strings do not crash the normalizer."""
        huge_banner = "A" * 65536
        host = NmapHost(
            address="192.168.1.10",
            status="up",
            ports=[
                NmapPort(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service=NmapService(name="http", extra_info=huge_banner),
                )
            ],
        )
        bundle = normalizer.normalize_nmap_result(
            result=NmapResult(hosts=[host]),
            engagement_id="eng-sec-1",
        )
        assert len(bundle.services) == 1
        assert len(bundle.services[0].banner) >= 65536

    def test_malformed_ip_address_handled_without_crash(self, normalizer):
        """Malformed IP strings in host output are processed defensively without crashing."""
        host = NmapHost(
            address="999.999.999.999.invalid-ip",
            hostnames=["corrupt.target"],
            status="up",
        )
        bundle = normalizer.normalize_nmap_result(
            result=NmapResult(hosts=[host]),
            engagement_id="eng-sec-1",
        )
        assert len(bundle.assets) == 1
        assert bundle.assets[0].asset_type in (AssetType.HOST, AssetType.IP)


class TestEngagementIsolation:
    """Test strict cross-engagement isolation."""

    def test_cross_engagement_asset_isolation(self, normalizer, asset_repo):
        host1 = NmapHost(address="192.168.1.10", status="up")
        bundle1 = normalizer.normalize_nmap_result(
            result=NmapResult(hosts=[host1]),
            engagement_id="eng-A",
            evidence_refs=["ev-A"],
        )
        bundle2 = normalizer.normalize_nmap_result(
            result=NmapResult(hosts=[host1]),
            engagement_id="eng-B",
            evidence_refs=["ev-B"],
        )
        asset_repo.save_bundle(bundle1)
        asset_repo.save_bundle(bundle2)

        assets_a = asset_repo.get_assets_by_engagement("eng-A")
        assets_b = asset_repo.get_assets_by_engagement("eng-B")

        assert len(assets_a) == 1
        assert len(assets_b) == 1
        # Distinct deterministic asset IDs due to engagement separation
        assert assets_a[0].asset_id != assets_b[0].asset_id
        assert assets_a[0].evidence_refs == ["ev-A"]
        assert assets_b[0].evidence_refs == ["ev-B"]
