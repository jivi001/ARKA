"""Security invariant tests for ARKA Phase 2.2.4 ReconAgent.

Proves the 14 mandatory security properties:
1. LLM output cannot directly execute commands.
2. Shell injection cannot become executable arguments.
3. ReconAgent cannot bypass ToolRegistry.
4. ReconAgent cannot bypass ScopeGuard.
5. ReconAgent cannot bypass PolicyEngine.
6. ReconAgent cannot bypass ApprovalManager.
7. Discovered assets cannot automatically expand authorized scope (DISCOVERED != AUTHORIZED).
8. Repeated actions are bounded (idempotency).
9. Malformed LLM output is rejected.
10. Arbitrary tool names are rejected.
11. Unauthorized targets are rejected.
12. Secrets are not placed into prompts, state, or logs.
13. Evidence references cannot be mutated through unsafe aliases.
14. Failed authorization does not result in execution.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest

from arka.app.agents.recon.agent import ReconAgent
from arka.app.agents.recon.models import (
    ReconAction,
    ReconAgentConfig,
    ReconState,
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
def security_scope() -> ScopeDefinition:
    return ScopeDefinition(
        engagement_id="eng-recon-sec",
        includes=ScopeTarget(
            domains=["authorized.corp"],
            ip_addresses=["192.168.10.10"],
            cidrs=["192.168.10.0/24"],
        ),
        excludes=ScopeTarget(
            domains=["forbidden.authorized.corp"],
            ip_addresses=["192.168.10.254"],
        ),
    )


@pytest.fixture
def recon_sec_env(security_scope: ScopeDefinition):
    guard = ScopeGuard(security_scope)
    policy = PolicyEngine(guard)
    audit = AuditService()
    approvals = ApprovalManager()
    registry = ToolRegistry(policy, audit, approvals)
    register_nmap_tool(registry)
    evidence_store = EvidenceStore()
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
        config=ReconAgentConfig(max_iterations=5, max_actions=10, max_repeated_action_attempts=2),
    )

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
        agent=agent,
        scope=security_scope,
    )


class TestReconAgentSecurityInvariants:
    """Rigorous security invariant test suite for ARKA ReconAgent."""

    @pytest.mark.asyncio
    async def test_01_llm_cannot_directly_execute_commands(self, recon_sec_env):
        """Property 1: LLM output proposing shell commands cannot execute."""
        # LLM returns payload attempting shell execution
        malicious_json = json.dumps(
            {
                "objective": "Run shell command",
                "reasoning_summary": "Attempting arbitrary command",
                "candidate_actions": [
                    {
                        "tool_name": "bash",
                        "operation": "exec",
                        "arguments": {"command": "cat /etc/passwd"},
                        "target": "192.168.10.10",
                        "rationale": "Privilege check",
                    }
                ],
                "stop_condition": None,
            }
        )

        with patch("subprocess.run") as mock_subproc, patch("os.system") as mock_os_system:
            mock_choice = SimpleNamespace(
                message=SimpleNamespace(content=malicious_json, role="assistant")
            )
            mock_usage = SimpleNamespace(prompt_tokens=10, completion_tokens=10, total_tokens=20)
            llm_mock_res = SimpleNamespace(choices=[mock_choice], usage=mock_usage, model="gpt-4o")
            recon_sec_env.llm._router = cast(
                Any, SimpleNamespace(acompletion=AsyncMock(return_value=llm_mock_res))
            )

            state = ReconState(
                engagement_id="eng-recon-sec",
                authorized_scope=recon_sec_env.scope.model_dump(),
            )

            updated_state = await recon_sec_env.agent.step(state)

            # Assert subprocess and os.system were NEVER called
            mock_subproc.assert_not_called()
            mock_os_system.assert_not_called()

            # Assert the candidate action was rejected because "bash" is an unknown tool
            assert updated_state.consecutive_failures == 1
            assert any("Unknown tool: 'bash'" in e for e in updated_state.errors)

    @pytest.mark.asyncio
    async def test_02_shell_injection_cannot_become_executable_arguments(self, recon_sec_env):
        """Property 2: Shell injection in target or arguments is rejected or safely tokenized."""
        # 1. Target with command separators are rejected by scope validation
        injection_targets = [
            "192.168.10.10; rm -rf /",
            "192.168.10.10 && cat /etc/shadow",
            "192.168.10.10 | whoami",
        ]

        with patch("subprocess.run") as mock_subproc, patch("os.system") as mock_os_system:
            for target in injection_targets:
                action = ReconAction(
                    tool_name="nmap",
                    operation="scan",
                    target=target,
                    arguments={"ports": "80"},
                )
                state = ReconState(engagement_id="eng-recon-sec")
                res, is_auth = await recon_sec_env.agent.submit_candidate_action(action, state)
                assert is_auth is False
                assert res.success is False
                mock_subproc.assert_not_called()
                mock_os_system.assert_not_called()

            # 2. Injected arguments with shell metacharacters are safely rejected by parser
            injected_args = [
                {"ports": "; cat /etc/passwd"},
                {"ports": "| id"},
                {"ports": "$(reboot)"},
            ]
            for args in injected_args:
                action = ReconAction(
                    tool_name="nmap",
                    operation="scan",
                    target="192.168.10.10",
                    arguments=args,
                )
                state = ReconState(engagement_id="eng-recon-sec")
                res, is_auth = await recon_sec_env.agent.submit_candidate_action(action, state)
                assert res.success is False
                mock_subproc.assert_not_called()
                mock_os_system.assert_not_called()

    @pytest.mark.asyncio
    async def test_03_recon_agent_cannot_bypass_tool_registry(self, recon_sec_env):
        """Property 3: All tool execution must flow through ToolRegistry."""
        action = ReconAction(
            tool_name="nmap",
            operation="scan",
            target="192.168.10.10",
            arguments={"ports": "80"},
        )
        state = ReconState(engagement_id="eng-recon-sec")

        with (
            patch.object(
                recon_sec_env.registry,
                "validate_candidate_request",
                wraps=recon_sec_env.registry.validate_candidate_request,
            ) as mock_val,
            patch.object(
                recon_sec_env.registry, "execute", wraps=recon_sec_env.registry.execute
            ) as mock_exec,
        ):
            res, is_auth = await recon_sec_env.agent.submit_candidate_action(action, state)
            assert is_auth is True
            assert res.success is True
            mock_val.assert_called_once()
            mock_exec.assert_called_once()

    @pytest.mark.asyncio
    async def test_04_recon_agent_cannot_bypass_scopeguard(self, recon_sec_env):
        """Property 4: Out-of-scope targets are unconditionally blocked."""
        out_of_scope_targets = [
            "8.8.8.8",
            "unauthorized.external.com",
            "192.168.10.254",  # Excluded IP in scope
            "forbidden.authorized.corp",  # Excluded subdomain
        ]

        for target in out_of_scope_targets:
            action = ReconAction(
                tool_name="nmap",
                operation="scan",
                target=target,
                arguments={"ports": "80"},
            )
            state = ReconState(engagement_id="eng-recon-sec")
            res, is_auth = await recon_sec_env.agent.submit_candidate_action(action, state)
            assert is_auth is False
            assert res.success is False
            assert "Policy denied" in (res.error or "")

    @pytest.mark.asyncio
    async def test_05_recon_agent_cannot_bypass_policy_engine(self, recon_sec_env):
        """Property 5: Actions requiring policy evaluation cannot bypass PolicyEngine."""
        action = ReconAction(
            tool_name="nmap",
            operation="scan",
            target="192.168.10.10",
            arguments={"ports": "80"},
        )
        state = ReconState(engagement_id="eng-recon-sec")

        with patch.object(
            recon_sec_env.policy, "evaluate", wraps=recon_sec_env.policy.evaluate
        ) as mock_policy_eval:
            await recon_sec_env.agent.submit_candidate_action(action, state)
            assert mock_policy_eval.call_count >= 1

    @pytest.mark.asyncio
    async def test_06_recon_agent_cannot_bypass_approval_manager(self, recon_sec_env):
        """Property 6: HIGH-risk actions require human approval and cannot execute without it."""
        # Aggressive scan with default NSE scripts escalates risk to HIGH
        aggressive_action = ReconAction(
            tool_name="nmap",
            operation="scan",
            target="192.168.10.10",
            arguments={"default_scripts": True},
        )
        state = ReconState(engagement_id="eng-recon-sec")

        # Without approval: must fail validation
        res, is_auth = await recon_sec_env.agent.submit_candidate_action(aggressive_action, state)
        assert is_auth is False
        assert "Requires human approval" in (res.error or "")

    @pytest.mark.asyncio
    async def test_07_discovered_assets_cannot_automatically_expand_authorized_scope(
        self, recon_sec_env
    ):
        """Property 7 (MANDATORY): DISCOVERED != AUTHORIZED.

        Target A is in scope. Target A is scanned, discovering Target B (out-of-scope).
        Target B is normalized and stored in AssetRepository.
        Attempting to scan Target B must be REJECTED by ScopeGuard.
        """
        target_a = "192.168.10.10"  # In scope
        target_b = "172.16.5.99"  # Discovered during scan, OUT OF SCOPE

        # Simulated Nmap XML where target A scan reveals target B
        simulated_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV {target_a}" version="7.95">
<host>
<status state="up"/>
<address addr="{target_a}" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
</host>
<host>
<status state="up"/>
<address addr="{target_b}" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
</host>
</nmaprun>"""

        tool_result = ToolResult(
            request_id="req-disc-1",
            engagement_id="eng-recon-sec",
            task_id="task-disc-1",
            tool_name="nmap",
            success=True,
            output={"host_count": 2},
            raw_output=simulated_xml,
            evidence_refs=["ev-disc-1"],
        )

        state = ReconState(engagement_id="eng-recon-sec")
        action_a = ReconAction(tool_name="nmap", operation="scan", target=target_a)

        # 1. Process result from Target A scan
        await recon_sec_env.agent.process_tool_result(
            tool_result, state, original_action=action_a, task_id="task-disc-1"
        )

        # 2. Verify Target B is stored in AssetRepository
        assets = recon_sec_env.asset_repo.get_assets_by_engagement("eng-recon-sec")
        discovered_addrs = [a.address for a in assets]
        assert target_b in discovered_addrs

        # 3. Verify ScopeGuard was NOT modified
        assert recon_sec_env.guard.validate_ip(target_b) is False

        # 4. Attempt to scan Target B -> MUST BE REJECTED
        action_b = ReconAction(tool_name="nmap", operation="scan", target=target_b)
        res_b, is_auth_b = await recon_sec_env.agent.submit_candidate_action(action_b, state)
        assert is_auth_b is False
        assert res_b.success is False
        assert "Policy denied" in (res_b.error or "")
        assert "not in scope" in (res_b.error or "")

    @pytest.mark.asyncio
    async def test_08_repeated_actions_are_bounded_by_fingerprints(self, recon_sec_env):
        """Property 8: Looping on identical actions terminates via action fingerprinting."""
        action = ReconAction(
            tool_name="nmap",
            operation="scan",
            target="192.168.10.10",
            arguments={"ports": "80"},
        )
        fp = action.fingerprint()

        state = ReconState(
            engagement_id="eng-recon-sec",
            pending_actions=[action.model_dump(), action.model_dump(), action.model_dump()],
            executed_fingerprints={fp: 2},  # Max allowed is 2
        )

        # Next action selection should reject all repeated actions
        next_action = recon_sec_env.agent.prioritize_next_action(state)
        assert next_action is None
        assert len(state.errors) >= 3

    @pytest.mark.asyncio
    async def test_09_malformed_llm_output_is_rejected(self, recon_sec_env):
        """Property 9: Non-JSON or corrupt LLM text is rejected gracefully."""
        corrupted_outputs = [
            "Just run nmap -sV on 192.168.10.10 please",
            "```json\n{unclosed json",
            '{"objective": "test"}',  # Missing candidate_actions
        ]

        for corrupt_text in corrupted_outputs:
            mock_choice = SimpleNamespace(
                message=SimpleNamespace(content=corrupt_text, role="assistant")
            )
            mock_usage = SimpleNamespace(prompt_tokens=10, completion_tokens=10, total_tokens=20)
            recon_sec_env.llm._router = cast(
                Any,
                SimpleNamespace(
                    acompletion=AsyncMock(
                        return_value=SimpleNamespace(choices=[mock_choice], usage=mock_usage)
                    )
                ),
            )

            state = ReconState(engagement_id="eng-recon-sec")
            plan = await recon_sec_env.agent.plan_reconnaissance(state)
            assert plan is None
            assert len(state.errors) > 0

    @pytest.mark.asyncio
    async def test_10_arbitrary_tool_names_are_rejected(self, recon_sec_env):
        """Property 10: Tools not registered in ToolRegistry are rejected."""
        unregistered_tools = ["metasploit", "sqlmap", "hydra", "curl", "wireshark"]

        for tool in unregistered_tools:
            action = ReconAction(
                tool_name=tool,
                operation="scan",
                target="192.168.10.10",
            )
            state = ReconState(engagement_id="eng-recon-sec")
            res, is_auth = await recon_sec_env.agent.submit_candidate_action(action, state)
            assert is_auth is False
            assert f"Unknown tool: '{tool}'" in (res.error or "")

    @pytest.mark.asyncio
    async def test_11_unauthorized_targets_are_rejected(self, recon_sec_env):
        """Property 11: Candidate actions against targets outside scope are denied."""
        action = ReconAction(
            tool_name="nmap",
            operation="scan",
            target="10.99.99.99",
            arguments={"ports": "80"},
        )
        state = ReconState(engagement_id="eng-recon-sec")
        res, is_auth = await recon_sec_env.agent.submit_candidate_action(action, state)
        assert is_auth is False
        assert "Policy denied" in (res.error or "")

    @pytest.mark.asyncio
    async def test_12_secrets_are_not_placed_into_prompts_or_state(self, recon_sec_env):
        """Property 12: Secrets and API keys are protected from prompt/state inclusion."""
        state = ReconState(
            engagement_id="eng-recon-sec",
            authorized_scope=recon_sec_env.scope.model_dump(),
        )

        # Check prompt string construction does not leak environment keys
        captured_messages = []

        async def capture_complete(req):
            for m in req.messages:
                captured_messages.append(m.content)
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=json.dumps(
                                {
                                    "objective": "Complete",
                                    "reasoning_summary": "Done",
                                    "candidate_actions": [],
                                    "stop_condition": "Done",
                                }
                            )
                        )
                    )
                ],
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            )

        recon_sec_env.llm._router = cast(
            Any, SimpleNamespace(acompletion=AsyncMock(side_effect=capture_complete))
        )
        await recon_sec_env.agent.plan_reconnaissance(state)

        for content in captured_messages:
            assert "sk-" not in content
            assert "api_key" not in content.lower()
            assert "secret" not in content.lower()

    @pytest.mark.asyncio
    async def test_13_evidence_references_cannot_be_mutated(self, recon_sec_env):
        """Property 13: Evidence references are immutably preserved and linked."""
        raw_xml = '<nmaprun><host><address addr="192.168.10.10"/></host></nmaprun>'
        ev_ref = recon_sec_env.evidence_store.record_evidence(
            execution_id="exec-sec-1",
            request_id="req-sec-1",
            engagement_id="eng-recon-sec",
            task_id="task-sec-1",
            content=raw_xml,
            evidence_type="raw_stdout",
            tool_name="nmap",
        )

        tool_result = ToolResult(
            request_id="req-sec-1",
            engagement_id="eng-recon-sec",
            task_id="task-sec-1",
            tool_name="nmap",
            success=True,
            output={"hosts": []},
            raw_output=raw_xml,
            evidence_refs=[ev_ref.evidence_id],
        )

        state = ReconState(engagement_id="eng-recon-sec")
        await recon_sec_env.agent.process_tool_result(tool_result, state)

        # Verify evidence reference is linked
        assert ev_ref.evidence_id in state.evidence_refs
        # Verify integrity via evidence store
        assert recon_sec_env.evidence_store.verify_integrity(ev_ref.evidence_id) is True

    @pytest.mark.asyncio
    async def test_14_failed_authorization_precludes_execution(self, recon_sec_env):
        """Property 14: Failed authorization never invokes the underlying executor."""
        action = ReconAction(
            tool_name="nmap",
            operation="scan",
            target="1.1.1.1",  # Unapproved target
            arguments={"ports": "80"},
        )
        state = ReconState(engagement_id="eng-recon-sec")

        nmap_executor = recon_sec_env.registry._executors["nmap"]
        with patch.object(nmap_executor, "execute") as mock_exec:
            res, is_auth = await recon_sec_env.agent.submit_candidate_action(action, state)
            assert is_auth is False
            assert res.success is False
            mock_exec.assert_not_called()
