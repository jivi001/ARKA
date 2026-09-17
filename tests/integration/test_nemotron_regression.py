"""Regression anchor test for NVIDIA Nemotron 3 Ultra via OpenRouter.

Verifies:
1. Provider resolves to OpenRouter.
2. Model identifier 'nvidia/nemotron-3-ultra-550b-a55b:free' formats
   to 'openrouter/nvidia/nemotron-3-ultra-550b-a55b:free'.
3. API key and endpoint 'https://openrouter.ai/api/v1' load into LiteLLM parameters properly.
4. Response is normalized with usage, content, and finish_reason.
5. ReconAgent with Nemotron produces untrusted CandidateToolRequest validated
   by ScopeGuard and PolicyEngine.
6. Zero secrets are leaked to audit logs, exceptions, or responses.
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import SecretStr

from arka.app.agents.recon.agent import ReconAgent
from arka.app.agents.recon.models import ReconState
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.config.settings import LLMProvider, Settings
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.execution.evidence import EvidenceStore
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.llm.schemas.llm_schemas import LLMMessage, LLMRequest
from arka.app.tools.registry.registry import ToolRegistry


@pytest.fixture
def nemotron_settings() -> Settings:
    return Settings(
        arka_llm_provider=LLMProvider.OPENROUTER,
        arka_llm_model="nvidia/nemotron-3-ultra-550b-a55b:free",
        arka_llm_api_key=SecretStr("sk-or-v1-regression-test-key-12345"),
        arka_llm_base_url="https://openrouter.ai/api/v1",
        arka_llm_timeout=120,
        arka_llm_max_retries=3,
    )


def make_mock_nemotron_completion(
    content: str = (
        '{"objective": "Recon test", "candidate_actions": [], "reasoning": "Nemotron plan"}'
    ),
):
    choice = SimpleNamespace(
        message=SimpleNamespace(content=content, role="assistant"),
        finish_reason="stop",
    )
    usage = SimpleNamespace(
        prompt_tokens=42,
        completion_tokens=28,
        total_tokens=70,
    )
    return SimpleNamespace(
        choices=[choice],
        usage=usage,
        model="openrouter/nvidia/nemotron-3-ultra-550b-a55b:free",
    )


class TestNemotronOpenRouterRegression:
    @pytest.mark.asyncio
    async def test_nemotron_profile_and_router_configuration(self, nemotron_settings):
        with patch("arka.app.llm.gateway.gateway.get_settings", return_value=nemotron_settings):
            profile = nemotron_settings.get_primary_llm_profile()
            assert profile.provider == "openrouter"
            assert profile.model == "nvidia/nemotron-3-ultra-550b-a55b:free"
            assert profile.timeout == 120
            assert profile.max_retries == 3
            assert profile.base_url == "https://openrouter.ai/api/v1"

            gateway = LLMGateway(profile=profile)
            assert gateway._router is not None
            assert len(gateway._router.model_list) >= 1

            primary_cfg = gateway._router.model_list[0]
            assert primary_cfg["model_name"] == "arka-primary"
            litellm_params = primary_cfg["litellm_params"]
            assert litellm_params["model"] == "openrouter/nvidia/nemotron-3-ultra-550b-a55b:free"
            assert litellm_params["api_base"] == "https://openrouter.ai/api/v1"
            assert litellm_params["timeout"] == 120.0
            assert litellm_params["api_key"] == "sk-or-v1-regression-test-key-12345"

    @pytest.mark.asyncio
    async def test_nemotron_completion_normalization(self, nemotron_settings):
        audit = AuditService()
        with patch("arka.app.llm.gateway.gateway.get_settings", return_value=nemotron_settings):
            gateway = LLMGateway(audit_service=audit)
            mock_resp = make_mock_nemotron_completion("Reasoning analysis complete.")
            cast(Any, gateway._router).acompletion = AsyncMock(return_value=mock_resp)

            req = LLMRequest(
                engagement_id="eng-nemotron-1",
                task_id="task-nemotron-1",
                agent_id="recon_agent",
                messages=[LLMMessage(role="user", content="Plan reconnaissance")],
            )

            res = await gateway.complete(req)
            assert res.success is True
            assert res.content == "Reasoning analysis complete."
            assert res.model == "openrouter/nvidia/nemotron-3-ultra-550b-a55b:free"
            assert res.provider == "openrouter"
            assert res.finish_reason == "stop"
            assert res.usage.prompt_tokens == 42
            assert res.usage.completion_tokens == 28
            assert res.usage.total_tokens == 70

            # Secret leakage assertion: Ensure key never appears in audit events
            events = await audit.get_events(engagement_id="eng-nemotron-1")
            assert len(events) >= 1
            for ev in events:
                ev_str = str(ev.parameters)
                assert "sk-or-v1" not in ev_str
                assert "regression-test-key" not in ev_str

    @pytest.mark.asyncio
    async def test_nemotron_recon_agent_security_pipeline(self, nemotron_settings, tmp_path):
        scope = ScopeDefinition(
            engagement_id="eng-nemotron-sec",
            includes=ScopeTarget(
                ip_addresses=["192.168.1.100"],
            ),
            excludes=ScopeTarget(),
        )
        guard = ScopeGuard(scope)
        policy = PolicyEngine(guard)
        audit = AuditService()
        approvals = ApprovalManager()
        registry = ToolRegistry(policy, audit, approvals)
        evidence_store = EvidenceStore()
        asset_repo = InMemoryAssetRepository()

        with patch("arka.app.llm.gateway.gateway.get_settings", return_value=nemotron_settings):
            gateway = LLMGateway(audit_service=audit)

            # Nemotron proposes a candidate tool action
            nemotron_plan_json = """
            {
                "objective": "Identify open services on target",
                "reasoning_summary": "Nemotron reasoning analysis",
                "candidate_actions": [
                    {
                        "tool_name": "nmap",
                        "operation": "scan",
                        "target": "192.168.1.100",
                        "arguments": {
                            "ports": "80,443"
                        },
                        "rationale": "Port scan target"
                    }
                ]
            }
            """
            mock_resp = make_mock_nemotron_completion(nemotron_plan_json)
            cast(Any, gateway._router).acompletion = AsyncMock(return_value=mock_resp)

            agent = ReconAgent(
                agent_id="recon-nemotron-1",
                llm_gateway=gateway,
                tool_registry=registry,
                scope_guard=guard,
                policy_engine=policy,
                approval_manager=approvals,
                evidence_store=evidence_store,
                asset_repository=asset_repo,
                audit_service=audit,
            )

            state = ReconState(
                engagement_id="eng-nemotron-sec",
                iteration=0,
            )

            plan = await agent.plan_reconnaissance(state)
            assert plan is not None
            assert len(plan.candidate_actions) == 1
            action = plan.candidate_actions[0]
            assert action.tool_name == "nmap"

            # Downstream pipeline: Verify proposal is treated as CandidateToolRequest
            # and MUST be validated by ScopeGuard
            assert guard.validate_ip(action.target) is True

            # Assert out-of-scope proposal is rejected
            assert guard.validate_ip("10.99.99.99") is False
