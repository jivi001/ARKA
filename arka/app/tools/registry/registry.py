from abc import ABC, abstractmethod
import asyncio
import time
from typing import Any

from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest, ToolResult
from arka.app.core.scope.scopeguard import ScopeGuard, ScopeViolation
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.state.models import PolicyDecisionType
from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService


class ToolExecutor(ABC):
    """Abstract base class for tool executors."""

    @abstractmethod
    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        """Execute the tool request."""
        pass


class ToolRegistryError(Exception):
    def __init__(self, message: str, tool_name: str = ""):
        self.tool_name = tool_name
        super().__init__(message)


class ToolRegistry:
    """Central registry for all ARKA tools.
    
    Security boundary: validates all tool requests before execution.
    The LLM never directly executes tools - everything goes through this registry.
    """
    
    def __init__(self, policy_engine: PolicyEngine, audit_service: AuditService):
        self._tools: dict[str, ToolDefinition] = {}
        self._executors: dict[str, ToolExecutor] = {}
        self._policy = policy_engine
        self._audit = audit_service
    
    def register(self, definition: ToolDefinition, executor: ToolExecutor) -> None:
        """Register a tool with its executor."""
        if definition.name in self._tools:
            raise ToolRegistryError(f"Tool '{definition.name}' already registered", definition.name)
        self._tools[definition.name] = definition
        self._executors[definition.name] = executor
    
    def unregister(self, tool_name: str) -> None:
        """Unregister a tool."""
        if tool_name not in self._tools:
            raise ToolRegistryError(f"Tool '{tool_name}' not found", tool_name)
        del self._tools[tool_name]
        del self._executors[tool_name]
    
    def get_tool(self, tool_name: str) -> ToolDefinition | None:
        return self._tools.get(tool_name)
    
    def list_tools(self) -> list[ToolDefinition]:
        return list(self._tools.values())
    
    async def execute(self, request: ToolRequest) -> ToolResult:
        """Execute a tool request through the full security pipeline.
        
        Pipeline:
        1. Validate tool exists
        2. Validate tool is enabled
        3. Validate arguments against input schema
        4. Policy check (scope + risk + approval)
        5. Execute through the tool executor
        6. Audit log the result
        """
        # 1. Lookup
        tool_def = self._tools.get(request.tool_name)
        if not tool_def:
            await self._audit.record_action(
                event_type=AuditEventType.TOOL_FAILED,
                actor=request.agent_id,
                action=f"tool_request:{request.tool_name}",
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                target=request.target,
                result_status="error",
                error=f"Unknown tool: {request.tool_name}",
                correlation_id=request.request_id,
            )
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Unknown tool: {request.tool_name}",
                output={},
                raw_output="",
                execution_time_ms=0,
                evidence_refs=[],
            )
        
        # 2. Check enabled
        if not tool_def.enabled:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Tool '{request.tool_name}' is disabled",
                output={},
                raw_output="",
                execution_time_ms=0,
                evidence_refs=[],
            )
        
        # 3. Validate arguments
        validation_error = self._validate_arguments(request, tool_def)
        if validation_error:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=validation_error,
                output={},
                raw_output="",
                execution_time_ms=0,
                evidence_refs=[],
            )
        
        # 4. Policy check
        decision = self._policy.evaluate(request, tool_def)
        await self._audit.record_action(
            event_type=AuditEventType.POLICY_DECISION,
            actor="policy_engine",
            action=f"evaluate:{request.tool_name}",
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            target=request.target,
            authorization_decision=decision.decision.value,
            parameters={"risk_level": decision.risk_level.value},
            result_status=decision.decision.value,
            correlation_id=request.request_id,
        )
        
        if decision.decision == PolicyDecisionType.DENY:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Policy denied: {decision.reason}",
                output={},
                raw_output="",
                execution_time_ms=0,
                evidence_refs=[],
            )
        
        if decision.decision == PolicyDecisionType.REQUIRE_APPROVAL:
            if not request.policy_approved:
                return ToolResult(
                    request_id=request.request_id,
                    engagement_id=request.engagement_id,
                    task_id=request.task_id,
                    tool_name=request.tool_name,
                    success=False,
                    error=f"Requires human approval. Risk level: {decision.risk_level.value}",
                    output={},
                    raw_output="",
                    execution_time_ms=0,
                    evidence_refs=[],
                )
        
        # 5. Execute
        executor = self._executors[request.tool_name]
        
        await self._audit.record_action(
            event_type=AuditEventType.TOOL_REQUESTED,
            actor=request.agent_id,
            action=f"execute:{request.tool_name}",
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            target=request.target,
            parameters=request.arguments,
            correlation_id=request.request_id,
        )
        
        start = time.monotonic()
        try:
            result = await asyncio.wait_for(
                executor.execute(request, tool_def),
                timeout=tool_def.timeout_seconds
            )
            result.execution_time_ms = int((time.monotonic() - start) * 1000)
            
            await self._audit.record_action(
                event_type=AuditEventType.TOOL_EXECUTED,
                actor=request.agent_id,
                action=f"executed:{request.tool_name}",
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                target=request.target,
                result_status="success" if result.success else "failed",
                error=result.error,
                correlation_id=request.request_id,
            )
            return result
            
        except asyncio.TimeoutError:
            elapsed = int((time.monotonic() - start) * 1000)
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Tool execution timed out after {tool_def.timeout_seconds}s",
                output={},
                raw_output="",
                execution_time_ms=elapsed,
                evidence_refs=[],
            )
        except Exception as e:
            elapsed = int((time.monotonic() - start) * 1000)
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Execution error: {str(e)}",
                output={},
                raw_output="",
                execution_time_ms=elapsed,
                evidence_refs=[],
            )
    
    def _validate_arguments(self, request: ToolRequest, tool_def: ToolDefinition) -> str | None:
        """Validate request arguments against tool's input schema. Returns error string or None."""
        schema = tool_def.input_schema
        required = schema.get("required", [])
        properties = schema.get("properties", {})
        for field in required:
            if field not in request.arguments:
                return f"Missing required argument: {field}"
        for key in request.arguments:
            if key not in properties:
                return f"Unknown argument: {key}"
        return None
