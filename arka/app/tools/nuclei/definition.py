"""Nuclei tool definition and registration for ARKA.

Provides the ToolDefinition for Nuclei vulnerability scanner with
deterministic operation-level risk escalation, and a registration function.
"""

from __future__ import annotations

from typing import Any

from arka.app.core.state.models import RiskLevel
from arka.app.tools.nuclei.executor import NucleiToolExecutor
from arka.app.tools.nuclei.schemas import NucleiScanConfig
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import ToolDefinition


class NucleiToolDefinition(ToolDefinition):
    """Nuclei tool definition supporting deterministic operation-level risk escalation."""

    def determine_risk(self, arguments: dict[str, Any] | None = None) -> RiskLevel:
        """Derive authoritative risk level based on Nuclei scan parameters.

        - Standard scan (info/low/medium severity): RiskLevel.MEDIUM
        - High/Critical severity or rate_limit > 100: RiskLevel.HIGH (requires human approval)
        """
        if not arguments:
            return self.risk_level
        try:
            config = NucleiScanConfig(
                templates=arguments.get("templates"),
                tags=arguments.get("tags"),
                severity=arguments.get("severity"),
                rate_limit=arguments.get("rate_limit", 50),
                timeout=arguments.get("timeout", 5),
            )
            if config.requires_escalation():
                return RiskLevel.HIGH
        except Exception:
            pass
        return self.risk_level


def get_nuclei_tool_definition() -> NucleiToolDefinition:
    """Get the NucleiToolDefinition.

    Base risk level is MEDIUM. Operation-level escalation to HIGH
    is evaluated deterministically when high/critical severities or high rates are requested.
    """
    return NucleiToolDefinition(
        name="nuclei",
        description=(
            "Fast and customizable vulnerability scanner based on simple YAML DSL. "
            "Scans authorized targets for security misconfigurations and known vulnerabilities."
        ),
        version="v3.3.0",
        input_schema={
            "type": "object",
            "properties": {
                "templates": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowed templates/categories (e.g. ['cves', 'misconfig']).",
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowed template tags (e.g. ['cve', 'tech']).",
                },
                "severity": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Severities: 'info', 'low', 'medium', 'high', 'critical'.",
                },
                "rate_limit": {
                    "type": "integer",
                    "description": "Rate limit (requests/sec). Values > 100 escalate risk to HIGH.",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds.",
                },
            },
            "required": [],
        },
        output_schema={
            "type": "object",
            "properties": {
                "findings": {"type": "array"},
                "finding_count": {"type": "integer"},
                "target": {"type": "string"},
                "argv": {"type": "array"},
            },
        },
        risk_level=RiskLevel.MEDIUM,
        required_permissions=["recon:vuln_scan"],
        allowed_environments=["sandbox", "test", "dev", "prod"],
        timeout_seconds=900,
        rate_limit_per_minute=5,
        evidence_required=True,
        category="vulnerability_scanner",
        enabled=True,
    )


def register_nuclei_tool(registry: ToolRegistry) -> None:
    """Register the Nuclei tool adapter with the ToolRegistry."""
    registry.register(get_nuclei_tool_definition(), NucleiToolExecutor())
