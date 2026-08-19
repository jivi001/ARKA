"""Comprehensive unit test suite for PolicyEngine.

Tests deterministic authorization behavior:
- Risk level thresholds (LOW, MEDIUM -> ALLOW; HIGH, CRITICAL -> REQUIRE_APPROVAL)
- Out-of-scope targets ALWAYS resulting in DENY regardless of risk level
- Excluded targets resulting in DENY
- Evaluation with both CandidateToolRequest and ToolRequest
- Rejection of LLM-supplied security bypass attempts
"""

import pytest

from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import (
    PolicyDecisionType,
    RiskLevel,
    ScopeDefinition,
    ScopeTarget,
)
from arka.app.tools.schemas.tool_schemas import (
    CandidateToolRequest,
    ToolDefinition,
    ToolRequest,
)


@pytest.fixture
def test_scope() -> ScopeDefinition:
    return ScopeDefinition(
        engagement_id="eng-policy-test",
        includes=ScopeTarget(
            domains=["authorized.com"],
            subdomains_allowed=True,
            ip_addresses=["10.0.0.5"],
            cidrs=["10.0.0.0/24"],
        ),
        excludes=ScopeTarget(
            domains=["excluded.authorized.com"],
            ip_addresses=["10.0.0.99"],
        ),
    )


@pytest.fixture
def policy_engine(test_scope) -> PolicyEngine:
    guard = ScopeGuard(test_scope)
    return PolicyEngine(guard)


def make_tool_def(name: str, risk: RiskLevel) -> ToolDefinition:
    return ToolDefinition(
        name=name,
        description=f"Test tool with {risk.value} risk",
        version="1.0.0",
        input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
        output_schema={"type": "object", "properties": {}},
        risk_level=risk,
    )


class TestPolicyRiskLevels:
    def test_low_risk_is_allowed(self, policy_engine: PolicyEngine):
        tool_def = make_tool_def("low_tool", RiskLevel.LOW)
        candidate = CandidateToolRequest(
            tool_name="low_tool",
            target="authorized.com",
            arguments={},
            reason="recon",
        )
        decision = policy_engine.evaluate(candidate, tool_def, "eng-1", "task-1", "agent-1")
        assert decision.decision == PolicyDecisionType.ALLOW
        assert decision.requires_approval is False
        assert decision.risk_level == RiskLevel.LOW

    def test_medium_risk_is_allowed(self, policy_engine: PolicyEngine):
        tool_def = make_tool_def("med_tool", RiskLevel.MEDIUM)
        candidate = CandidateToolRequest(
            tool_name="med_tool",
            target="authorized.com",
            arguments={},
            reason="service scan",
        )
        decision = policy_engine.evaluate(candidate, tool_def, "eng-1", "task-1", "agent-1")
        assert decision.decision == PolicyDecisionType.ALLOW
        assert decision.requires_approval is False
        assert decision.risk_level == RiskLevel.MEDIUM

    def test_high_risk_requires_approval(self, policy_engine: PolicyEngine):
        tool_def = make_tool_def("high_tool", RiskLevel.HIGH)
        candidate = CandidateToolRequest(
            tool_name="high_tool",
            target="authorized.com",
            arguments={},
            reason="exploit simulation",
        )
        decision = policy_engine.evaluate(candidate, tool_def, "eng-1", "task-1", "agent-1")
        assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL
        assert decision.requires_approval is True
        assert decision.risk_level == RiskLevel.HIGH

    def test_critical_risk_requires_approval(self, policy_engine: PolicyEngine):
        tool_def = make_tool_def("crit_tool", RiskLevel.CRITICAL)
        candidate = CandidateToolRequest(
            tool_name="crit_tool",
            target="authorized.com",
            arguments={},
            reason="destructive check",
        )
        decision = policy_engine.evaluate(candidate, tool_def, "eng-1", "task-1", "agent-1")
        assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL
        assert decision.requires_approval is True
        assert decision.risk_level == RiskLevel.CRITICAL


class TestPolicyScopeEnforcement:
    def test_out_of_scope_target_is_denied_for_low_risk(self, policy_engine: PolicyEngine):
        tool_def = make_tool_def("low_tool", RiskLevel.LOW)
        candidate = CandidateToolRequest(
            tool_name="low_tool",
            target="evil.com",
            arguments={},
            reason="probe",
        )
        decision = policy_engine.evaluate(candidate, tool_def, "eng-1", "task-1", "agent-1")
        assert decision.decision == PolicyDecisionType.DENY
        assert "Target out of scope" in decision.reason

    def test_out_of_scope_target_is_denied_for_high_risk(self, policy_engine: PolicyEngine):
        # Even if approval would normally be required,
        # out of scope targets MUST be DENIED immediately
        tool_def = make_tool_def("high_tool", RiskLevel.HIGH)
        candidate = CandidateToolRequest(
            tool_name="high_tool",
            target="evil.com",
            arguments={},
            reason="exploit",
        )
        decision = policy_engine.evaluate(candidate, tool_def, "eng-1", "task-1", "agent-1")
        assert decision.decision == PolicyDecisionType.DENY
        assert "Target out of scope" in decision.reason

    def test_excluded_target_is_denied(self, policy_engine: PolicyEngine):
        tool_def = make_tool_def("low_tool", RiskLevel.LOW)
        candidate = CandidateToolRequest(
            tool_name="low_tool",
            target="excluded.authorized.com",
            arguments={},
            reason="test",
        )
        decision = policy_engine.evaluate(candidate, tool_def, "eng-1", "task-1", "agent-1")
        assert decision.decision == PolicyDecisionType.DENY

        candidate_ip = CandidateToolRequest(
            tool_name="low_tool",
            target="10.0.0.99",
            arguments={},
            reason="test",
        )
        decision_ip = policy_engine.evaluate(candidate_ip, tool_def, "eng-1", "task-1", "agent-1")
        assert decision_ip.decision == PolicyDecisionType.DENY


class TestPolicyConfigurableThresholds:
    def test_adjust_medium_threshold_to_require_approval(self, policy_engine: PolicyEngine):
        tool_def = make_tool_def("med_tool", RiskLevel.MEDIUM)
        candidate = CandidateToolRequest(
            tool_name="med_tool",
            target="authorized.com",
            arguments={},
            reason="scan",
        )
        policy_engine.set_approval_threshold(RiskLevel.MEDIUM, True)
        decision = policy_engine.evaluate(candidate, tool_def, "eng-1", "task-1", "agent-1")
        assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL
        assert decision.requires_approval is True


class TestPolicyCannotBeBypassedByRequestFields:
    def test_authoritative_risk_derived_from_definition_not_request(
        self, policy_engine: PolicyEngine
    ):
        high_tool_def = make_tool_def("high_tool", RiskLevel.HIGH)
        # Attempt to pass a ToolRequest claiming risk_level=LOW and policy_approved=True
        untrusted_request = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="high_tool",
            target="authorized.com",
            arguments={},
            reason="exploit",
            risk_level=RiskLevel.LOW,
            policy_approved=True,
            scope_validated=True,
        )
        decision = policy_engine.evaluate(untrusted_request, high_tool_def)
        # PolicyEngine must ignore request's claimed risk level and use ToolDefinition's HIGH risk
        assert decision.risk_level == RiskLevel.HIGH
        assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL
        assert decision.requires_approval is True
