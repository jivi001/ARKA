"""
Vulnerability Analysis Agent Implementation.

Primary Responsibility: Banner grabbing, technology identification, endpoint analysis.
Permitted Capabilities: HTTP_REQUEST, SERVICE_ENUMERATION, BROWSER_AUTOMATION
Maximum Default Risk Class: MODERATE
"""

from typing import Optional, Set

from arka.gateway.client import GatewayClient
from .base import AgentRole, BaseAgent

VULN_ANALYSIS_PERMITTED_CAPABILITIES: Set[str] = {
    "HTTP_REQUEST",
    "SERVICE_ENUMERATION",
    "BROWSER_AUTOMATION",
}


class VulnerabilityAnalysisAgent(BaseAgent):
    """
    Autonomous Vulnerability Analysis Agent specializing in fingerprinting and service auditing.
    """

    def __init__(
        self,
        agent_id: str = "agent-vuln-01",
        gateway_client: Optional[GatewayClient] = None,
        default_provider: str = "mock",
        default_model: str = "mock-agent",
    ):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.VULNERABILITY_ANALYSIS,
            permitted_capabilities=VULN_ANALYSIS_PERMITTED_CAPABILITIES,
            max_risk_class="MODERATE",
            gateway_client=gateway_client or GatewayClient(),
            default_provider=default_provider,
            default_model=default_model,
        )
