"""Unit tests for WebSecurityAgent and pipeline security invariants."""

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from arka.app.agents.web.agent import WebSecurityAgent
from arka.app.agents.web.models import (
    InvalidStateTransitionError,
    WebActionBudget,
    WebActionBudgetUsed,
    WebAgentState,
    WebSecurityState,
)
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.llm.schemas.llm_schemas import LLMResponse
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.web.tools.definitions import get_web_crawler_tool_definition
from arka.app.web.tools.executors import WebCrawlerToolExecutor


@pytest.fixture
def scope_guard() -> ScopeGuard:
    scope = ScopeDefinition(
        engagement_id="eng-web-agent",
        includes=ScopeTarget(
            domains=["authorized.example.com"],
            ports=[80, 443],
        ),
        excludes=ScopeTarget(
            domains=["evil.attacker.com"],
        ),
    )
    return ScopeGuard(scope)


@pytest.fixture
def tool_registry(scope_guard: ScopeGuard) -> ToolRegistry:
    audit = AuditService()
    policy = PolicyEngine(scope_guard=scope_guard)
    approvals = ApprovalManager()
    registry = ToolRegistry(
        policy_engine=policy,
        audit_service=audit,
        approval_manager=approvals,
    )
    # Register web_crawler
    crawler_def = get_web_crawler_tool_definition()
    crawler_exec = WebCrawlerToolExecutor(scope_guard=scope_guard)
    registry.register(crawler_def, crawler_exec)
    return registry


@pytest.mark.asyncio
async def test_web_agent_planning_and_scope_rejection(
    scope_guard: ScopeGuard,
    tool_registry: ToolRegistry,
) -> None:
    """Security invariant: LLM proposals cannot execute directly
    and out-of-scope targets are rejected.
    """
    mock_model_output = json.dumps(
        {
            "reasoning": (
                "Crawl the target web application and then crawl external unauthorized link"
            ),
            "candidate_actions": [
                {
                    "tool_name": "web_crawler",
                    "target": "https://authorized.example.com/",
                    "arguments": {"target": "https://authorized.example.com/", "max_pages": 5},
                    "reason": "Authorized seed crawl",
                },
                {
                    "tool_name": "web_crawler",
                    "target": "https://evil.attacker.com/internal",
                    "arguments": {"target": "https://evil.attacker.com/internal"},
                    "reason": "Out of scope proposal",
                },
            ],
            "should_terminate": False,
        }
    )

    mock_llm_gateway = MagicMock(spec=LLMGateway)
    mock_llm_gateway.complete = AsyncMock(
        return_value=LLMResponse(
            request_id="req-test-1",
            content=mock_model_output,
            model="test-model",
            provider="test-provider",
        )
    )

    audit = AuditService()
    policy = PolicyEngine(scope_guard=scope_guard)
    repo = InMemoryAssetRepository()

    agent = WebSecurityAgent(
        agent_id="web-agent-1",
        llm_gateway=mock_llm_gateway,
        tool_registry=tool_registry,
        scope_guard=scope_guard,
        policy_engine=policy,
        asset_repository=repo,
        audit_service=audit,
    )

    state = WebSecurityState(engagement_id="eng-web-agent")

    # 1. Plan
    plan = await agent.plan_reconnaissance(state, seed_target="https://authorized.example.com/")
    assert len(plan.candidate_actions) == 2

    # 2. Execute plan through authoritative security pipeline
    results = await agent.execute_plan(state, plan)
    assert len(results) == 2

    # The out-of-scope target must be denied by PolicyEngine/ScopeGuard
    res_out_of_scope = results[1]
    assert res_out_of_scope.success is False
    assert "Policy denied" in (res_out_of_scope.error or "") or "Scope" in (
        res_out_of_scope.error or ""
    )


def test_web_agent_state_machine_transitions():
    """Section 3.9.1: Deterministic state machine validation."""
    state = WebSecurityState(engagement_id="eng-sm-test")
    assert state.agent_state == WebAgentState.INITIALIZED

    # Valid transitions:
    # INITIALIZED -> DISCOVERING -> ANALYZING -> VALIDATING -> CORRELATING -> COMPLETED
    state.transition_to(WebAgentState.DISCOVERING)
    assert state.agent_state == WebAgentState.DISCOVERING

    state.transition_to(WebAgentState.ANALYZING)
    assert state.agent_state == WebAgentState.ANALYZING

    state.transition_to(WebAgentState.VALIDATING)
    assert state.agent_state == WebAgentState.VALIDATING

    state.transition_to(WebAgentState.CORRELATING)
    assert state.agent_state == WebAgentState.CORRELATING

    state.transition_to(WebAgentState.COMPLETED)
    assert state.agent_state == WebAgentState.COMPLETED
    assert state.is_complete is True

    # Invalid transition from COMPLETED (terminal state)
    with pytest.raises(InvalidStateTransitionError):
        state.transition_to(WebAgentState.DISCOVERING)


def test_web_agent_action_budget_enforcement():
    """Section 3.9.2: Deterministic budget bounds."""
    budget = WebActionBudget(max_requests=2, max_pages=5)
    used = WebActionBudgetUsed(requests_sent=1, pages_crawled=2)

    exhausted, _ = used.is_exhausted(budget)
    assert exhausted is False

    # Exceed max_requests
    used.requests_sent = 2
    exhausted, reason = used.is_exhausted(budget)
    assert exhausted is True
    assert "Max requests reached" in (reason or "")


@pytest.mark.asyncio
async def test_web_agent_loop_prevention(
    scope_guard: ScopeGuard,
    tool_registry: ToolRegistry,
):
    """Section 3.9.3: Loop prevention and action deduplication."""
    mock_model_output = json.dumps(
        {
            "reasoning": "Repeat same crawl",
            "candidate_actions": [
                {
                    "tool_name": "web_crawler",
                    "target": "https://authorized.example.com/",
                    "arguments": {"target": "https://authorized.example.com/"},
                    "reason": "Repeated crawl attempt",
                }
            ],
            "should_terminate": False,
        }
    )

    mock_llm_gateway = MagicMock(spec=LLMGateway)
    mock_llm_gateway.complete = AsyncMock(
        return_value=LLMResponse(
            request_id="req-test-loop",
            content=mock_model_output,
            model="test-model",
            provider="test-provider",
        )
    )

    agent = WebSecurityAgent(
        agent_id="web-agent-loop",
        llm_gateway=mock_llm_gateway,
        tool_registry=tool_registry,
        scope_guard=scope_guard,
        policy_engine=PolicyEngine(scope_guard=scope_guard),
    )

    state = WebSecurityState(engagement_id="eng-loop-test")

    # Run execution 1
    plan1 = await agent.plan_reconnaissance(state, seed_target="https://authorized.example.com/")
    results1 = await agent.execute_plan(state, plan1)
    assert len(results1) == 1

    # In iteration 2, the agent tries to execute the exact same fingerprint again
    plan2 = await agent.plan_reconnaissance(state, seed_target="https://authorized.example.com/")
    # Planning filters out already executed actions
    assert len(plan2.candidate_actions) == 0
