from typing import TYPE_CHECKING

from arka.app.audit.service import AuditService
from arka.app.execution.manager import ExecutionManager
from arka.app.tools.schemas.tool_schemas import ToolRequest, ToolResult

if TYPE_CHECKING:
    from arka.app.tools.registry.registry import ToolRegistry


class ExecutionEngine:
    """Sandboxed execution engine for ARKA tools.

    All tool execution flows through the ToolRegistry and ExecutionManager.
    The engine only accepts authoritative ToolRequests that have passed:
    - ScopeGuard validation (scope_validated=True)
    - PolicyEngine authorization (policy_approved=True)
    - ApprovalManager gate (if required)
    """

    def __init__(
        self,
        tool_registry: "ToolRegistry",
        audit_service: AuditService,
        execution_manager: ExecutionManager | None = None,
    ):
        self._registry = tool_registry
        self._audit = audit_service
        self._execution_manager = execution_manager or ExecutionManager(audit_service=audit_service)

    async def execute(self, request: ToolRequest) -> ToolResult:
        """Execute a validated tool request through the authoritative security boundary."""
        if not request.scope_validated:
            raise ValueError("ToolRequest must be scope-validated before execution")
        if not request.policy_approved:
            raise ValueError("ToolRequest must be policy-approved before execution")

        return await self._registry.execute(request)
