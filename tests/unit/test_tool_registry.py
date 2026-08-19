import pytest
from arka.app.tools.schemas.tool_schemas import ToolRequest
from arka.app.tools.registry.registry import ToolRegistry

class TestToolRegistry:
    @pytest.mark.asyncio
    async def test_execute_echo_tool(self, tool_registry: ToolRegistry):
        request = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="echo_test",
            target="example.com",
            arguments={"message": "hello"},
            reason="test"
        )
        result = await tool_registry.execute(request)
        assert result.success is True
        assert "hello" in str(result.output)

    @pytest.mark.asyncio
    async def test_unknown_tool(self, tool_registry: ToolRegistry):
        request = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="unknown-tool",
            target="example.com",
            arguments={},
            reason="test"
        )
        result = await tool_registry.execute(request)
        assert result.success is False
        assert "Unknown tool" in str(result.error)

    @pytest.mark.asyncio
    async def test_scope_violation(self, tool_registry: ToolRegistry):
        request = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="echo_test",
            target="evil.com",
            arguments={"message": "hello"},
            reason="test"
        )
        result = await tool_registry.execute(request)
        assert result.success is False
        assert "Policy denied" in str(result.error) or "out of scope" in str(result.error)

    @pytest.mark.asyncio
    async def test_risk_classification(self, tool_registry: ToolRegistry):
        tool = tool_registry.get_tool("echo_test")
        assert tool is not None
        assert tool.risk_level is not None
