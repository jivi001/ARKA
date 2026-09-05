from abc import ABC, abstractmethod
from typing import Any

from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.state.models import PolicyDecision, PolicyDecisionType
from arka.app.execution.manager import ExecutionManager
from arka.app.tools.schemas.tool_schemas import (
    CandidateToolRequest,
    ToolDefinition,
    ToolRequest,
    ToolResult,
)


class ToolExecutor(ABC):
    """Abstract base class for tool executors."""

    @abstractmethod
    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        """Execute the tool request."""


class ToolRegistryError(Exception):
    def __init__(self, message: str, tool_name: str = ""):
        self.tool_name = tool_name
        super().__init__(message)


class ToolRegistry:
    """Central registry and execution security boundary for all ARKA tools.

    The LLM never directly executes tools — all execution flows through this registry.
    Ensures input schema validation, deterministic scope validation, policy enforcement,
    persistent approval verification, sandboxed execution, and immutable audit logging.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        audit_service: AuditService,
        approval_manager: ApprovalManager | None = None,
        execution_manager: ExecutionManager | None = None,
    ):
        self._tools: dict[str, ToolDefinition] = {}
        self._executors: dict[str, ToolExecutor] = {}
        self._policy = policy_engine
        self._audit = audit_service
        self._approval_manager = approval_manager
        self._execution_manager = execution_manager or ExecutionManager(audit_service=audit_service)

    def set_approval_manager(self, approval_manager: ApprovalManager) -> None:
        """Set or update the approval manager instance."""
        self._approval_manager = approval_manager

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

    def validate_candidate_request(
        self,
        candidate: CandidateToolRequest,
        engagement_id: str,
        task_id: str,
        agent_id: str,
        approval_id: str | None = None,
    ) -> tuple[ToolRequest | None, PolicyDecision | None, str | None]:
        """Authoritatively validate an untrusted CandidateToolRequest.

        Returns (authoritative_tool_request, policy_decision, error_message).
        If validation or policy check fails, authoritative_tool_request is None.
        """
        # 1. Lookup tool
        tool_def = self._tools.get(candidate.tool_name)
        if not tool_def:
            return None, None, f"Unknown tool: '{candidate.tool_name}'"

        # 2. Check enabled
        if not tool_def.enabled:
            return None, None, f"Tool '{candidate.tool_name}' is disabled"

        # 3. Validate arguments against schema
        arg_err = self._validate_arguments(candidate.arguments, tool_def)
        if arg_err:
            return None, None, arg_err

        # 4. Policy evaluation (ScopeGuard + Risk Level + Approval)
        decision = self._policy.evaluate(
            candidate,
            tool_def,
            engagement_id=engagement_id,
            task_id=task_id,
            agent_id=agent_id,
        )

        if decision.decision == PolicyDecisionType.DENY:
            return None, decision, f"Policy denied: {decision.reason}"

        if decision.decision == PolicyDecisionType.REQUIRE_APPROVAL:
            # Check if valid approval exists
            is_approved = False
            if self._approval_manager and approval_id:
                is_approved = self._approval_manager.validate_approval_for_request(
                    approval_id=approval_id,
                    engagement_id=engagement_id,
                    task_id=task_id,
                    tool_name=candidate.tool_name,
                    target=candidate.target,
                )

            if not is_approved:
                return (
                    None,
                    decision,
                    f"Requires human approval. Risk level: {decision.risk_level.value}",
                )

            # Approved
            tool_req = ToolRequest(
                engagement_id=engagement_id,
                task_id=task_id,
                agent_id=agent_id,
                tool_name=candidate.tool_name,
                target=candidate.target,
                arguments=candidate.arguments,
                reason=candidate.reason,
                risk_level=decision.risk_level,
                scope_validated=True,
                scope_version=decision.scope_version,
                policy_approved=True,
                approval_id=approval_id,
            )
            return tool_req, decision, None

        # ALLOW
        tool_req = ToolRequest(
            engagement_id=engagement_id,
            task_id=task_id,
            agent_id=agent_id,
            tool_name=candidate.tool_name,
            target=candidate.target,
            arguments=candidate.arguments,
            reason=candidate.reason,
            risk_level=tool_def.risk_level,
            scope_validated=True,
            scope_version=decision.scope_version,
            policy_approved=True,
        )
        return tool_req, decision, None

    async def execute(self, request: ToolRequest) -> ToolResult:
        """Execute an authoritative tool request through the security boundary.

        Pipeline:
        1. Validate tool exists and is enabled
        2. Validate arguments against schema
        3. Deterministic PolicyEngine check
        4. Approval verification
        5. Execute through executor with timeout
        6. Audit log all events
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
        validation_error = self._validate_arguments(request.arguments, tool_def)
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
            # Check approval validity
            is_valid_approval = request.policy_approved
            if self._approval_manager and request.approval_id:
                is_valid_approval = self._approval_manager.validate_approval_for_request(
                    approval_id=request.approval_id,
                    engagement_id=request.engagement_id,
                    task_id=request.task_id,
                    tool_name=request.tool_name,
                    target=request.target,
                )

            if not is_valid_approval:
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

        # 5. Execute via authoritative ExecutionManager
        request.scope_validated = True
        request.policy_approved = True
        executor = self._executors[request.tool_name]
        if self._execution_manager:
            _exec_res, tool_result = await self._execution_manager.execute_tool(
                request, tool_def, executor
            )
            return tool_result

        return await executor.execute(request, tool_def)

    def _validate_arguments(
        self, arguments: dict[str, Any] | None, tool_def: ToolDefinition
    ) -> str | None:
        """Validate arguments against tool's input schema.

        Checks required fields, unknown fields, and types.
        """
        if arguments is None:
            return "Arguments cannot be None"

        schema = tool_def.input_schema
        if not schema:
            return None

        required = schema.get("required", [])
        properties = schema.get("properties", {})

        for field in required:
            if field not in arguments:
                return f"Missing required argument: {field}"

        for key, val in arguments.items():
            if key not in properties:
                return f"Unknown argument: {key}"

            prop_spec = properties[key]
            expected_type = prop_spec.get("type")
            if expected_type == "string" and not isinstance(val, str):
                return f"Invalid type for argument '{key}': expected string"
            elif expected_type == "integer" and (not isinstance(val, int) or isinstance(val, bool)):
                return f"Invalid type for argument '{key}': expected integer"
            elif expected_type == "boolean" and not isinstance(val, bool):
                return f"Invalid type for argument '{key}': expected boolean"
            elif expected_type == "array" and not isinstance(val, list):
                return f"Invalid type for argument '{key}': expected array"
            elif expected_type == "object" and not isinstance(val, dict):
                return f"Invalid type for argument '{key}': expected object"

        return None
