"""
Reconnaissance Agent Implementation.

Primary Responsibility: Passive and active perimeter mapping.
Permitted Capabilities: DNS_LOOKUP, TCP_CONNECT, PORT_SCAN, WEB_DISCOVERY, OSINT_LOOKUP
Maximum Default Risk Class: MODERATE
"""

from typing import Optional, Set

from arka.gateway.client import GatewayClient
from .base import AgentRole, BaseAgent

RECON_PERMITTED_CAPABILITIES: Set[str] = {
    "DNS_LOOKUP",
    "TCP_CONNECT",
    "PORT_SCAN",
    "WEB_DISCOVERY",
    "OSINT_LOOKUP",
}


class ReconnaissanceAgent(BaseAgent):
    """
    Autonomous Reconnaissance Agent specializing in network and perimeter discovery.
    """

    def __init__(
        self,
        agent_id: str = "agent-recon-01",
        gateway_client: Optional[GatewayClient] = None,
        default_provider: str = "mock",
        default_model: str = "mock-agent",
    ):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.RECONNAISSANCE,
            permitted_capabilities=RECON_PERMITTED_CAPABILITIES,
            max_risk_class="MODERATE",
            gateway_client=gateway_client or GatewayClient(),
            default_provider=default_provider,
            default_model=default_model,
        )
