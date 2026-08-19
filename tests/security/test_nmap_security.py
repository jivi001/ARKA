"""Security tests for Nmap adapter proving injection immunity (Phase 2.2.1).

Proves:
- LLM cannot inject arbitrary Nmap flags (no raw flag field exists)
- Shell metacharacters are treated as literal data
- Command substitution is impossible
- Path traversal is rejected
- Unauthorized/excluded targets are rejected by ScopeGuard/PolicyEngine
- Aggressive configs without approval are rejected by escalation
"""

import pytest

from arka.app.audit.service import AuditService
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.tools.nmap.definition import get_nmap_tool_definition, register_nmap_tool
from arka.app.tools.nmap.executor import NmapToolExecutor
from arka.app.tools.nmap.schemas import NmapScanConfig
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest, ToolRequest


@pytest.fixture
def nmap_scope():
    return ScopeDefinition(
        engagement_id="sec-test-nmap",
        includes=ScopeTarget(
            ip_addresses=["192.168.1.10"],
            cidrs=["192.168.1.0/24"],
            domains=["example.com"],
            subdomains_allowed=True,
            ports=[22, 80, 443, 8080],
        ),
        excludes=ScopeTarget(
            ip_addresses=["192.168.1.100"],
            domains=["admin.example.com"],
        ),
    )


@pytest.fixture
def nmap_scope_guard(nmap_scope):
    return ScopeGuard(nmap_scope)


@pytest.fixture
def nmap_policy(nmap_scope_guard):
    return PolicyEngine(nmap_scope_guard)


@pytest.fixture
def nmap_registry(nmap_policy):
    audit = AuditService()
    registry = ToolRegistry(nmap_policy, audit)
    register_nmap_tool(registry)
    return registry


class TestNmapArgumentInjectionImmunity:
    """Prove the LLM cannot inject arbitrary Nmap flags."""

    def test_no_raw_flag_field_exists(self):
        """NmapScanConfig has no field for arbitrary flags."""
        fields = set(NmapScanConfig.model_fields.keys())
        assert fields == {"ports", "service_detection", "default_scripts", "timing_template"}

    def test_shell_metacharacters_in_ports_rejected(self):
        payloads = [
            "; cat /etc/passwd",
            "| id",
            "& whoami",
            "$(cat /etc/shadow)",
            "`id`",
            "80\n; rm -rf /",
        ]
        for payload in payloads:
            with pytest.raises(ValueError):
                NmapScanConfig(ports=payload)

    def test_file_read_in_ports_rejected(self):
        with pytest.raises(ValueError):
            NmapScanConfig(ports="-iL /etc/hosts")

    def test_output_redirection_in_ports_rejected(self):
        with pytest.raises(ValueError):
            NmapScanConfig(ports="-oN /tmp/scan.txt")

    def test_extra_arguments_rejected_by_schema(self, nmap_registry: ToolRegistry):
        """ToolRegistry rejects unknown argument keys via schema validation."""
        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="192.168.1.10",
            arguments={
                "ports": "80",
                "--script": "http-sql-injection",  # arbitrary flag injection
            },
        )
        _req, _dec, err = nmap_registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-sec",
            task_id="task-sec",
            agent_id="agent-sec",
        )
        assert err is not None
        assert "Unknown argument" in err

    def test_arbitrary_flag_via_arguments_rejected(self, nmap_registry: ToolRegistry):
        """Attempt to inject -iL, --script=, -oN via arguments dict."""
        injections = [
            {"-iL": "/etc/hosts"},
            {"--script": "exploit"},
            {"-oN": "/tmp/out.txt"},
            {"raw_flags": "--privileged"},
        ]
        for injection_args in injections:
            candidate = CandidateToolRequest(
                tool_name="nmap",
                target="192.168.1.10",
                arguments=injection_args,
            )
            _req, _dec, err = nmap_registry.validate_candidate_request(
                candidate=candidate,
                engagement_id="eng-sec",
                task_id="task-sec",
                agent_id="agent-sec",
            )
            assert err is not None, f"Should reject injection: {injection_args}"


class TestNmapScopeEnforcement:
    """Prove out-of-scope targets never reach Nmap execution."""

    def test_in_scope_target_allowed(self, nmap_registry: ToolRegistry):
        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="192.168.1.10",
            arguments={"ports": "80"},
        )
        req, _dec, err = nmap_registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-scope",
            task_id="task-scope",
            agent_id="agent-scope",
        )
        assert req is not None
        assert err is None

    def test_out_of_scope_target_denied(self, nmap_registry: ToolRegistry):
        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="10.99.99.99",
            arguments={"ports": "80"},
        )
        req, _dec, err = nmap_registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-scope",
            task_id="task-scope",
            agent_id="agent-scope",
        )
        assert req is None
        assert "out of scope" in (err or "").lower() or "denied" in (err or "").lower()

    def test_excluded_target_denied(self, nmap_registry: ToolRegistry):
        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="192.168.1.100",
            arguments={"ports": "80"},
        )
        req, _dec, err = nmap_registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-scope",
            task_id="task-scope",
            agent_id="agent-scope",
        )
        assert req is None
        assert err is not None

    def test_excluded_domain_denied(self, nmap_registry: ToolRegistry):
        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="admin.example.com",
            arguments={"ports": "80"},
        )
        req, _dec, err = nmap_registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-scope",
            task_id="task-scope",
            agent_id="agent-scope",
        )
        assert req is None
        assert err is not None


class TestNmapOperationEscalation:
    """Prove aggressive configs without approval are rejected."""

    @pytest.mark.asyncio
    async def test_default_scripts_without_approval_rejected(self):
        executor = NmapToolExecutor()
        defn = get_nmap_tool_definition()

        request = ToolRequest(
            engagement_id="eng-esc",
            task_id="task-esc",
            agent_id="agent-esc",
            tool_name="nmap",
            target="192.168.1.10",
            arguments={"default_scripts": True},
            scope_validated=True,
            policy_approved=True,
            approval_id=None,  # No approval
        )

        result = await executor.execute(request, defn)
        assert result.success is False
        assert "HIGH risk approval" in (result.error or "")
        assert result.output.get("escalation_required") is True

    @pytest.mark.asyncio
    async def test_aggressive_timing_without_approval_rejected(self):
        executor = NmapToolExecutor()
        defn = get_nmap_tool_definition()

        request = ToolRequest(
            engagement_id="eng-esc",
            task_id="task-esc",
            agent_id="agent-esc",
            tool_name="nmap",
            target="192.168.1.10",
            arguments={"timing_template": 4},
            scope_validated=True,
            policy_approved=True,
            approval_id=None,
        )

        result = await executor.execute(request, defn)
        assert result.success is False
        assert "HIGH risk approval" in (result.error or "")

    @pytest.mark.asyncio
    async def test_aggressive_config_with_approval_succeeds(self):
        executor = NmapToolExecutor()
        defn = get_nmap_tool_definition()

        request = ToolRequest(
            engagement_id="eng-esc",
            task_id="task-esc",
            agent_id="agent-esc",
            tool_name="nmap",
            target="192.168.1.10",
            arguments={"default_scripts": True, "timing_template": 4},
            scope_validated=True,
            policy_approved=True,
            approval_id="approved-by-human",
        )

        result = await executor.execute(request, defn)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_non_aggressive_config_without_approval_succeeds(self):
        executor = NmapToolExecutor()
        defn = get_nmap_tool_definition()

        request = ToolRequest(
            engagement_id="eng-esc",
            task_id="task-esc",
            agent_id="agent-esc",
            tool_name="nmap",
            target="192.168.1.10",
            arguments={"ports": "80,443", "timing_template": 2},
            scope_validated=True,
            policy_approved=True,
        )

        result = await executor.execute(request, defn)
        assert result.success is True
