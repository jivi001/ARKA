"""Amass tool definition and registration for ARKA.

Provides the ToolDefinition for OWASP Amass network mapping and subdomain enumeration
with deterministic operation-level risk escalation, and a registration function.
"""

from __future__ import annotations

from typing import Any

from arka.app.core.state.models import RiskLevel
from arka.app.tools.amass.executor import AmassToolExecutor
from arka.app.tools.amass.schemas import AmassScanConfig
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import ToolDefinition


class AmassToolDefinition(ToolDefinition):
    """Amass tool definition supporting deterministic operation-level risk escalation."""

    def determine_risk(self, arguments: dict[str, Any] | None = None) -> RiskLevel:
        """Derive authoritative risk level based on Amass scan parameters.

        - Passive mode (OSINT scraping): RiskLevel.LOW
        - Active mode (DNS resolution / probing): RiskLevel.HIGH (requires human approval)
        """
        if not arguments:
            return self.risk_level
        try:
            config = AmassScanConfig(
                mode=arguments.get("mode", "passive"),
                timeout_minutes=arguments.get("timeout_minutes", 5),
            )
            if config.requires_escalation():
                return RiskLevel.HIGH
        except Exception:
            pass
        return self.risk_level


def get_amass_tool_definition() -> AmassToolDefinition:
    """Get the AmassToolDefinition.

    Base risk level is LOW (passive OSINT). Operation-level escalation to HIGH
    is evaluated deterministically when active probing is requested.
    """
    return AmassToolDefinition(
        name="amass",
        description=(
            "In-depth attack surface mapping and asset discovery using open source "
            "information gathering and active network mapping."
        ),
        version="v4.2.0",
        input_schema={
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["passive", "active"],
                    "description": "Enumeration mode: 'passive' (safe OSINT) or 'active' (DNS).",
                },
                "timeout_minutes": {
                    "type": "integer",
                    "description": "Timeout in minutes (1-30).",
                },
            },
            "required": [],
        },
        output_schema={
            "type": "object",
            "properties": {
                "records": {"type": "array"},
                "record_count": {"type": "integer"},
                "domain": {"type": "string"},
                "argv": {"type": "array"},
            },
        },
        risk_level=RiskLevel.LOW,
        required_permissions=["recon:dns_enum"],
        allowed_environments=["sandbox", "test", "dev", "prod"],
        timeout_seconds=900,
        rate_limit_per_minute=5,
        evidence_required=True,
        category="reconnaissance",
        enabled=True,
    )


def register_amass_tool(registry: ToolRegistry) -> None:
    """Register the Amass tool adapter with the ToolRegistry."""
    registry.register(get_amass_tool_definition(), AmassToolExecutor())
