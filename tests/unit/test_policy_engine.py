from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.state.models import PolicyDecisionType, RiskLevel
from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest


class TestPolicyEngine:
    def test_allow_low_risk(self, policy_engine: PolicyEngine):
        tool_def = ToolDefinition(
            name="echo",
            description="Echo",
            version="1.0",
            risk_level=RiskLevel.LOW,
            input_schema={},
            output_schema={},
        )
        tool_req = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="echo",
            target="example.com",
            reason="test",
        )
        decision = policy_engine.evaluate(tool_req, tool_def)
        assert decision.decision == PolicyDecisionType.ALLOW

    def test_deny_out_of_scope(self, policy_engine: PolicyEngine):
        tool_def = ToolDefinition(
            name="echo",
            description="Echo",
            version="1.0",
            risk_level=RiskLevel.LOW,
            input_schema={},
            output_schema={},
        )
        tool_req = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="echo",
            target="evil.com",
            reason="test",
        )
        decision = policy_engine.evaluate(tool_req, tool_def)
        assert decision.decision == PolicyDecisionType.DENY

    def test_require_approval_high_risk(self, policy_engine: PolicyEngine):
        tool_def = ToolDefinition(
            name="exploit",
            description="Exploit",
            version="1.0",
            risk_level=RiskLevel.HIGH,
            input_schema={},
            output_schema={},
        )
        tool_req = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="exploit",
            target="example.com",
            reason="test",
        )
        decision = policy_engine.evaluate(tool_req, tool_def)
        assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL

    def test_configurable_thresholds(self, policy_engine: PolicyEngine):
        tool_def = ToolDefinition(
            name="scan",
            description="Scan",
            version="1.0",
            risk_level=RiskLevel.MEDIUM,
            input_schema={},
            output_schema={},
        )
        tool_req = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="scan",
            target="example.com",
            reason="test",
        )
        policy_engine.set_approval_threshold(RiskLevel.MEDIUM, True)
        decision = policy_engine.evaluate(tool_req, tool_def)
        assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL
