"""Nmap tool definition and registration for ARKA Phase 2.2.1.

Provides the ToolDefinition for Nmap with deterministic operation-level
risk escalation, and a registration function that registers Nmap with ToolRegistry.
"""

from __future__ import annotations

from typing import Any

from arka.app.core.state.models import RiskLevel
from arka.app.tools.nmap.executor import NmapToolExecutor
from arka.app.tools.nmap.schemas import NmapScanConfig
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import ToolDefinition


class NmapToolDefinition(ToolDefinition):
    """Nmap tool definition supporting deterministic operation-level risk escalation."""

    def determine_risk(self, arguments: dict[str, Any] | None = None) -> RiskLevel:
        """Derive authoritative risk level based on Nmap scan parameters.

        - Normal port scan / service detection: RiskLevel.MEDIUM (auto-allowed within scope)
        - Aggressive scan (default_scripts=True or timing_template >= 3): RiskLevel.HIGH
          (requires human approval)
        """
        if not arguments:
            return self.risk_level
        try:
            config = NmapScanConfig(
                ports=arguments.get("ports"),
                service_detection=arguments.get("service_detection", True),
                default_scripts=arguments.get("default_scripts", False),
                timing_template=arguments.get("timing_template", 2),
            )
            if config.requires_escalation():
                return RiskLevel.HIGH
        except Exception:
            pass
        return self.risk_level


def get_nmap_tool_definition() -> NmapToolDefinition:
    """Get the NmapToolDefinition.

    Base risk level is MEDIUM. Operation-level escalation to HIGH
    is evaluated deterministically by determine_risk() when aggressive
    configurations are requested.
    """
    return NmapToolDefinition(
        name="nmap",
        description=(
            "Nmap network scanner for port discovery, service detection, "
            "and version enumeration. Scans authorized targets only."
        ),
        version="7.95",
        input_schema={
            "type": "object",
            "properties": {
                "ports": {
                    "type": "string",
                    "description": (
                        "Port specification (e.g. '80,443' or '1-1024'). "
                        "Only digits, commas, and hyphens allowed."
                    ),
                },
                "service_detection": {
                    "type": "boolean",
                    "description": "Enable service/version detection (-sV). Default: true.",
                },
                "default_scripts": {
                    "type": "boolean",
                    "description": (
                        "Enable default NSE scripts (-sC). "
                        "Escalates risk to HIGH requiring human approval."
                    ),
                },
                "timing_template": {
                    "type": "integer",
                    "description": ("Timing template 0-4. Values >= 3 escalate risk to HIGH."),
                },
            },
            "required": [],
        },
        output_schema={
            "type": "object",
            "properties": {
                "scan_metadata": {"type": "object"},
                "hosts": {"type": "array"},
                "host_count": {"type": "integer"},
                "argv": {"type": "array"},
            },
        },
        risk_level=RiskLevel.MEDIUM,
        required_permissions=["recon:scan"],
        allowed_environments=["sandbox", "test", "dev", "prod"],
        timeout_seconds=600,
        rate_limit_per_minute=10,
        evidence_required=True,
        category="reconnaissance",
        enabled=True,
    )


def register_nmap_tool(registry: ToolRegistry) -> None:
    """Register the Nmap tool adapter with the ToolRegistry."""
    registry.register(get_nmap_tool_definition(), NmapToolExecutor())
