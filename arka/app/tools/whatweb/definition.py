"""WhatWeb tool definition and registration for ARKA.

Provides the ToolDefinition for WhatWeb web technology fingerprinter
with deterministic operation-level risk escalation, and a registration function.
"""

from __future__ import annotations

from typing import Any

from arka.app.core.state.models import RiskLevel
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import ToolDefinition
from arka.app.tools.whatweb.executor import WhatWebToolExecutor
from arka.app.tools.whatweb.schemas import WhatWebScanConfig


class WhatWebToolDefinition(ToolDefinition):
    """WhatWeb tool definition supporting deterministic operation-level risk escalation."""

    def determine_risk(self, arguments: dict[str, Any] | None = None) -> RiskLevel:
        """Derive authoritative risk level based on WhatWeb scan parameters.

        - Standard scan (aggression=1): RiskLevel.LOW
        - Aggressive scan (aggression=3): RiskLevel.HIGH (requires human approval)
        """
        if not arguments:
            return self.risk_level
        try:
            config = WhatWebScanConfig(
                aggression=arguments.get("aggression", 1),
                no_errors=arguments.get("no_errors", True),
            )
            if config.requires_escalation():
                return RiskLevel.HIGH
        except Exception:
            pass
        return self.risk_level


def get_whatweb_tool_definition() -> WhatWebToolDefinition:
    """Get the WhatWebToolDefinition.

    Base risk level is LOW. Operation-level escalation to HIGH
    is evaluated deterministically when aggression >= 3 is requested.
    """
    return WhatWebToolDefinition(
        name="whatweb",
        description=(
            "Next generation web scanner that identifies technologies, content management systems, "
            "web servers, JavaScript libraries, and embedded devices."
        ),
        version="0.5.5",
        input_schema={
            "type": "object",
            "properties": {
                "aggression": {
                    "type": "integer",
                    "description": "Aggression level (1-3). Value 3 escalates to HIGH.",
                },
                "no_errors": {
                    "type": "boolean",
                    "description": "Suppress error messages.",
                },
            },
            "required": [],
        },
        output_schema={
            "type": "object",
            "properties": {
                "targets": {"type": "array"},
                "target_count": {"type": "integer"},
                "argv": {"type": "array"},
            },
        },
        risk_level=RiskLevel.LOW,
        required_permissions=["recon:tech_fingerprint"],
        allowed_environments=["sandbox", "test", "dev", "prod"],
        timeout_seconds=300,
        rate_limit_per_minute=20,
        evidence_required=True,
        category="reconnaissance",
        enabled=True,
    )


def register_whatweb_tool(registry: ToolRegistry) -> None:
    """Register the WhatWeb tool adapter with the ToolRegistry."""
    registry.register(get_whatweb_tool_definition(), WhatWebToolExecutor())
