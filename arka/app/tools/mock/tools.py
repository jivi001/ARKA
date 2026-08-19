from typing import Any

from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest, ToolResult
from arka.app.tools.registry.registry import ToolExecutor, ToolRegistry
from arka.app.core.scope.scopeguard import ScopeGuard, ScopeViolation
from arka.app.core.state.models import RiskLevel


class EchoToolExecutor(ToolExecutor):
    """Safe test tool that echoes input. For Phase 1 testing only."""
    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name="echo_test",
            success=True,
            output={"echo": request.arguments, "target": request.target},
            raw_output=f"Echo: {request.arguments}",
            execution_time_ms=0,
            evidence_refs=[],
        )

class ScopeCheckToolExecutor(ToolExecutor):
    """Tool that validates whether a target is in scope."""
    def __init__(self, scope_guard: ScopeGuard):
        self._scope_guard = scope_guard
    
    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        try:
            in_scope = self._scope_guard.validate_target(request.target)
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name="scope_check",
                success=True,
                output={"target": request.target, "in_scope": in_scope},
                raw_output=f"Target {request.target} is in scope: {in_scope}",
                execution_time_ms=0,
                evidence_refs=[],
            )
        except ScopeViolation as e:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name="scope_check",
                success=True,  # The check succeeded, the target is just out of scope
                output={"target": request.target, "in_scope": False, "reason": e.reason},
                raw_output=f"Target {request.target} out of scope: {e.reason}",
                execution_time_ms=0,
                evidence_refs=[],
            )

def get_echo_tool_definition() -> ToolDefinition:
    """Get the definition for the mock echo tool."""
    return ToolDefinition(
        name="echo_test",
        description="A mock tool that echoes its input.",
        version="1.0.0",
        input_schema={
            "type": "object",
            "properties": {
                "message": {"type": "string"}
            },
            "required": ["message"]
        },
        output_schema={
            "type": "object",
            "properties": {
                "echo": {"type": "object"},
                "target": {"type": "string"}
            }
        },
        risk_level=RiskLevel.LOW,
        required_permissions=[],
        allowed_environments=["test", "dev", "prod"],
        timeout_seconds=5,
        rate_limit_per_minute=60,
        evidence_required=False,
        category="mock",
        enabled=True
    )

def get_scope_check_tool_definition() -> ToolDefinition:
    """Get the definition for the mock scope check tool."""
    return ToolDefinition(
        name="scope_check",
        description="A tool that checks if a target is in scope.",
        version="1.0.0",
        input_schema={
            "type": "object",
            "properties": {},
            "required": []
        },
        output_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "in_scope": {"type": "boolean"},
                "reason": {"type": "string"}
            }
        },
        risk_level=RiskLevel.LOW,
        required_permissions=[],
        allowed_environments=["test", "dev", "prod"],
        timeout_seconds=5,
        rate_limit_per_minute=60,
        evidence_required=False,
        category="mock",
        enabled=True
    )

def register_mock_tools(registry: ToolRegistry, scope_guard: ScopeGuard) -> None:
    """Register all mock tools for Phase 1 testing."""
    registry.register(get_echo_tool_definition(), EchoToolExecutor())
    registry.register(get_scope_check_tool_definition(), ScopeCheckToolExecutor(scope_guard))
