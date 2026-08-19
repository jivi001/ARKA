from abc import ABC

from arka.app.audit.service import AuditService
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.tools.registry.registry import ToolRegistry


class BaseAgent(ABC):
    """Base class for all ARKA agents."""

    def __init__(
        self,
        agent_id: str,
        agent_type: str,
        llm_gateway: LLMGateway,
        tool_registry: ToolRegistry,
        audit_service: AuditService,
    ):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.llm = llm_gateway
        self.tools = tool_registry
        self.audit = audit_service
