"""
Orchestrator Agent Implementation.

Primary Responsibility: Mission planning, sub-task delegation, status aggregation.
Permitted Capabilities: DELEGATION_MANAGEMENT, STATUS_QUERY
Maximum Default Risk Class: OBSERVATION
"""

from typing import Optional, Set

from arka.gateway.client import GatewayClient
from .base import AgentRole, BaseAgent

ORCHESTRATOR_PERMITTED_CAPABILITIES: Set[str] = {
    "DELEGATION_MANAGEMENT",
    "STATUS_QUERY",
}


class OrchestratorAgent(BaseAgent):
    """
    Autonomous Orchestrator Agent coordinating multi-agent missions without direct target execution.
    """

    def __init__(
        self,
        agent_id: str = "agent-orchestrator-01",
        gateway_client: Optional[GatewayClient] = None,
        default_provider: str = "mock",
        default_model: str = "mock-agent",
    ):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.ORCHESTRATOR,
            permitted_capabilities=ORCHESTRATOR_PERMITTED_CAPABILITIES,
            max_risk_class="OBSERVATION",
            gateway_client=gateway_client or GatewayClient(),
            default_provider=default_provider,
            default_model=default_model,
        )
