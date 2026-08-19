from arka.app.tools.schemas.tool_schemas import ToolRequest, ToolResult
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.audit.service import AuditService


class ExecutionEngine:
    """Sandboxed execution engine for ARKA tools.
    
    All tool execution MUST go through this engine.
    The engine only accepts validated ToolRequests that have passed:
    - ScopeGuard validation
    - PolicyEngine authorization
    - Approval gate (if required)
    """
    
    def __init__(self, tool_registry: ToolRegistry, audit_service: AuditService):
        self._registry = tool_registry
        self._audit = audit_service
    
    async def execute(self, request: ToolRequest) -> ToolResult:
        """Execute a validated tool request.
        
        Delegates to the ToolRegistry which handles the full security pipeline.
        """
        if not request.scope_validated:
            raise ValueError("ToolRequest must be scope-validated before execution")
        
        return await self._registry.execute(request)
