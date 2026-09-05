"""Security and adversarial tests for Phase 2 tool adapters (OWASP Agent Matrix).

Validates strict enforcement of trust boundaries:
1. LLM cannot inject shell meta-characters or arbitrary flags.
2. Path traversal in templates and wordlists is rejected.
3. Out-of-scope targets are strictly denied by ScopeGuard.
4. DISCOVERED != AUTHORIZED: Discovered assets never auto-expand scope.
5. Operation-level risk escalation requires explicit approval.
"""

from __future__ import annotations

import pytest

from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import (
    PolicyDecisionType,
    RiskLevel,
    ScopeDefinition,
    ScopeTarget,
    new_id,
)
from arka.app.tools.amass.definition import get_amass_tool_definition, register_amass_tool
from arka.app.tools.amass.executor import AmassToolExecutor
from arka.app.tools.amass.schemas import AmassScanConfig
from arka.app.tools.ffuf.definition import get_ffuf_tool_definition, register_ffuf_tool
from arka.app.tools.ffuf.executor import FfufToolExecutor
from arka.app.tools.ffuf.schemas import FfufScanConfig
from arka.app.tools.nuclei.definition import get_nuclei_tool_definition, register_nuclei_tool
from arka.app.tools.nuclei.executor import NucleiToolExecutor
from arka.app.tools.nuclei.schemas import NucleiScanConfig
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest, ToolRequest
from arka.app.tools.whatweb.definition import register_whatweb_tool


@pytest.fixture
def security_test_env():
    """Environment with strict scope (192.168.1.0/24, example.corp)."""
    scope = ScopeDefinition(
        engagement_id="eng-sec-test",
        includes=ScopeTarget(
            ip_addresses=["192.168.1.10", "192.168.1.20"],
            cidrs=["192.168.1.0/24"],
            domains=["example.corp", "api.example.corp"],
        ),
        excludes=ScopeTarget(ip_addresses=["192.168.1.254"]),
    )
    guard = ScopeGuard(scope)
    audit = AuditService()
    policy = PolicyEngine(guard)
    approvals = ApprovalManager()
    registry = ToolRegistry(policy, audit, approvals)

    register_nuclei_tool(registry)
    register_ffuf_tool(registry)
    register_whatweb_tool(registry)
    register_amass_tool(registry)

    repo = InMemoryAssetRepository()
    normalizer = AssetNormalizer()

    return {
        "scope_guard": guard,
        "policy": policy,
        "approvals": approvals,
        "registry": registry,
        "repo": repo,
        "normalizer": normalizer,
    }


# ==============================================================================
# 1. ARGUMENT INJECTION & TRAVERSAL PREVENTION
# ==============================================================================


def test_nuclei_path_traversal_and_flag_injection() -> None:
    """Ensure NucleiScanConfig rejects path traversal and raw flag injections."""
    # Path traversal
    with pytest.raises(ValueError, match="only alphanumeric relative paths allowed"):
        NucleiScanConfig(templates=["../../../../etc/shadow"])

    # Absolute path injection
    with pytest.raises(ValueError, match="only alphanumeric relative paths allowed"):
        NucleiScanConfig(templates=["/var/tmp/malicious.yaml"])

    # Semicolon injection in tag
    with pytest.raises(ValueError, match="only alphanumeric characters and hyphens allowed"):
        NucleiScanConfig(tags=["cve;rm -rf /"])


def test_ffuf_wordlist_traversal_and_shell_injection() -> None:
    """Ensure FfufScanConfig rejects unauthorized wordlists and path traversal."""
    with pytest.raises(ValueError, match="not in approved allowlist"):
        FfufScanConfig(wordlist="../../etc/passwd")

    with pytest.raises(ValueError, match="not in approved allowlist"):
        FfufScanConfig(wordlist="/root/secret_wordlist.txt")


def test_amass_mode_injection() -> None:
    """Ensure AmassScanConfig rejects arbitrary mode arguments."""
    with pytest.raises(ValueError, match="must be 'passive' or 'active'"):
        AmassScanConfig(mode="active; reboot")


# ==============================================================================
# 2. OUT-OF-SCOPE TARGET DENIAL (SCOPEGUARD ENFORCEMENT)
# ==============================================================================


def test_out_of_scope_target_rejected_for_all_adapters(security_test_env: dict) -> None:
    """Verify ToolRegistry blocks out-of-scope targets across all tool adapters."""
    registry: ToolRegistry = security_test_env["registry"]
    out_of_scope_targets = ["10.0.0.99", "8.8.8.8", "unauthorized.evil.com", "192.168.1.254"]

    for tool_name in ["nuclei", "ffuf", "whatweb", "amass"]:
        for target in out_of_scope_targets:
            candidate = CandidateToolRequest(
                tool_name=tool_name,
                target=target,
                arguments={},
                reason="Adversarial out-of-scope attempt",
            )
            auth_req, decision, err = registry.validate_candidate_request(
                candidate=candidate,
                engagement_id="eng-sec-test",
                task_id=new_id(),
                agent_id="test-agent",
            )
            assert auth_req is None, f"Tool {tool_name} should reject out-of-scope target {target}"
            assert decision is not None
            assert decision.decision == PolicyDecisionType.DENY
            assert "out of scope" in (err or "").lower()


# ==============================================================================
# 3. OPERATION-LEVEL RISK ESCALATION ENFORCEMENT
# ==============================================================================


@pytest.mark.asyncio
async def test_nuclei_critical_severity_denied_without_approval(security_test_env: dict) -> None:
    """Critical severity Nuclei scans require HIGH risk approval."""
    registry: ToolRegistry = security_test_env["registry"]

    candidate = CandidateToolRequest(
        tool_name="nuclei",
        target="192.168.1.10",
        arguments={"severity": ["critical"]},
        reason="Aggressive critical vuln scan",
    )
    auth_req, decision, err = registry.validate_candidate_request(
        candidate=candidate,
        engagement_id="eng-sec-test",
        task_id=new_id(),
        agent_id="test-agent",
    )
    # Blocked by registry without approval because critical severity escalates to HIGH risk
    assert auth_req is None
    assert decision is not None
    assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL
    assert decision.risk_level == RiskLevel.HIGH
    assert "Requires human approval" in (err or "")

    # Attempt execution without approval ID must also be rejected by executor
    req = ToolRequest(
        engagement_id="eng-sec-test",
        task_id=new_id(),
        agent_id="test-agent",
        tool_name="nuclei",
        target="192.168.1.10",
        arguments={"severity": ["critical"]},
        risk_level=RiskLevel.HIGH,
        approval_id=None,
    )
    executor = NucleiToolExecutor()
    definition = get_nuclei_tool_definition()
    result = await executor.execute(req, definition)
    assert result.success is False
    assert "requires HIGH risk approval" in (result.error or "")


@pytest.mark.asyncio
async def test_ffuf_high_rate_denied_without_approval(security_test_env: dict) -> None:
    """High rate ffuf scans require HIGH risk approval."""
    executor = FfufToolExecutor()
    definition = get_ffuf_tool_definition()

    req = ToolRequest(
        engagement_id="eng-sec-test",
        task_id=new_id(),
        agent_id="test-agent",
        tool_name="ffuf",
        target="http://192.168.1.10",
        arguments={"rate": 90},
        approval_id=None,
    )
    result = await executor.execute(req, definition)
    assert result.success is False
    assert "requires HIGH risk approval" in (result.error or "")


@pytest.mark.asyncio
async def test_amass_active_mode_denied_without_approval(security_test_env: dict) -> None:
    """Active Amass scans require HIGH risk approval."""
    executor = AmassToolExecutor()
    definition = get_amass_tool_definition()

    req = ToolRequest(
        engagement_id="eng-sec-test",
        task_id=new_id(),
        agent_id="test-agent",
        tool_name="amass",
        target="example.corp",
        arguments={"mode": "active"},
        approval_id=None,
    )
    result = await executor.execute(req, definition)
    assert result.success is False
    assert "requires HIGH risk approval" in (result.error or "")


# ==============================================================================
# 4. DISCOVERED != AUTHORIZED INVARIANT
# ==============================================================================


def test_discovered_assets_cannot_be_scanned_if_out_of_scope(security_test_env: dict) -> None:
    """MANDATORY INVARIANT: Discovered != Authorized.

    If Amass discovers a new host (e.g. dev.external.corp) that is outside the
    ScopeDefinition, it is recorded in the AssetRepository as 'discovered' but
    ScopeGuard MUST STILL REJECT ANY SUBSEQUENT ACTIONS against it.
    """
    normalizer: AssetNormalizer = security_test_env["normalizer"]
    repo: InMemoryAssetRepository = security_test_env["repo"]
    registry: ToolRegistry = security_test_env["registry"]

    from arka.app.tools.amass.parser import parse_amass_json

    discovered_jsonl = (
        '{"name": "dev.external.corp", "domain": "external.corp", '
        '"addresses": [{"ip": "172.16.0.50"}], "tag": "dns"}'
    )
    amass_res = parse_amass_json(discovered_jsonl, domain="external.corp")
    bundle = normalizer.normalize_amass_result(
        result=amass_res,
        engagement_id="eng-sec-test",
        target="external.corp",
    )
    # Save into knowledge repository
    repo.save_bundle(bundle)

    # Verify asset is stored as 'discovered'
    assets = repo.get_assets_by_engagement("eng-sec-test")
    assert any(a.hostname == "dev.external.corp" and a.status == "discovered" for a in assets)

    # Now an agent attempts to target dev.external.corp with Nmap or Nuclei
    candidate = CandidateToolRequest(
        tool_name="nuclei",
        target="dev.external.corp",
        arguments={},
        reason="Probe discovered host",
    )
    auth_req, _decision, err = registry.validate_candidate_request(
        candidate=candidate,
        engagement_id="eng-sec-test",
        task_id=new_id(),
        agent_id="recon-agent",
    )
    assert auth_req is None
    assert err is not None
    assert "out of scope" in err.lower()
