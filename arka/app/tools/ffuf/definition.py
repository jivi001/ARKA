"""ffuf tool definition and registration for ARKA.

Provides the ToolDefinition for ffuf web directory and parameter discovery tool
with deterministic operation-level risk escalation, and a registration function.
"""

from __future__ import annotations

from typing import Any

from arka.app.core.state.models import RiskLevel
from arka.app.tools.ffuf.executor import FfufToolExecutor
from arka.app.tools.ffuf.schemas import FfufScanConfig
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import ToolDefinition


class FfufToolDefinition(ToolDefinition):
    """ffuf tool definition supporting deterministic operation-level risk escalation."""

    def determine_risk(self, arguments: dict[str, Any] | None = None) -> RiskLevel:
        """Derive authoritative risk level based on ffuf scan parameters.

        - Standard scan (rate <= 50, depth <= 2): RiskLevel.MEDIUM
        - High rate (>50 rps) or deep recursion (>2): RiskLevel.HIGH (requires human approval)
        """
        if not arguments:
            return self.risk_level
        try:
            config = FfufScanConfig(
                wordlist=arguments.get("wordlist", "common.txt"),
                rate=arguments.get("rate", 20),
                recursion=arguments.get("recursion", False),
                recursion_depth=arguments.get("recursion_depth", 1),
                match_codes=arguments.get("match_codes", "200,204,301,302,307,401,403"),
                filter_codes=arguments.get("filter_codes", "404"),
            )
            if config.requires_escalation():
                return RiskLevel.HIGH
        except Exception:
            pass
        return self.risk_level


def get_ffuf_tool_definition() -> FfufToolDefinition:
    """Get the FfufToolDefinition.

    Base risk level is MEDIUM. Operation-level escalation to HIGH
    is evaluated deterministically when high rate or deep recursion is requested.
    """
    return FfufToolDefinition(
        name="ffuf",
        description=(
            "Fast web fuzzer for directory, file, and endpoint discovery. "
            "Scans authorized HTTP/HTTPS targets using allowlisted wordlists."
        ),
        version="2.1.0",
        input_schema={
            "type": "object",
            "properties": {
                "wordlist": {
                    "type": "string",
                    "description": "Approved wordlist (e.g. 'common.txt', 'api-endpoints.txt').",
                },
                "rate": {
                    "type": "integer",
                    "description": "Requests/sec (1-100). Values > 50 escalate risk to HIGH.",
                },
                "recursion": {
                    "type": "boolean",
                    "description": "Enable directory recursion.",
                },
                "recursion_depth": {
                    "type": "integer",
                    "description": "Recursion depth (1-3). Values > 2 escalate risk to HIGH.",
                },
                "match_codes": {
                    "type": "string",
                    "description": "Comma-separated HTTP status codes to match (e.g. '200,301').",
                },
                "filter_codes": {
                    "type": "string",
                    "description": "Comma-separated HTTP status codes to filter out (e.g. '404').",
                },
            },
            "required": [],
        },
        output_schema={
            "type": "object",
            "properties": {
                "matches": {"type": "array"},
                "match_count": {"type": "integer"},
                "target_url": {"type": "string"},
                "argv": {"type": "array"},
            },
        },
        risk_level=RiskLevel.MEDIUM,
        required_permissions=["recon:dir_fuzz"],
        allowed_environments=["sandbox", "test", "dev", "prod"],
        timeout_seconds=600,
        rate_limit_per_minute=10,
        evidence_required=True,
        category="web_scanner",
        enabled=True,
    )


def register_ffuf_tool(registry: ToolRegistry) -> None:
    """Register the ffuf tool adapter with the ToolRegistry."""
    registry.register(get_ffuf_tool_definition(), FfufToolExecutor())
