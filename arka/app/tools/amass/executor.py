"""Amass tool executor for ARKA.

Implements the ToolExecutor interface for Amass subdomain/DNS enumerator.
Constructs safe argv, simulates/executes the scan, and parses JSON output.
"""

from __future__ import annotations

from arka.app.tools.amass.parser import parse_amass_json
from arka.app.tools.amass.schemas import AmassScanConfig
from arka.app.tools.registry.registry import ToolExecutor
from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest, ToolResult

_SIMULATED_AMASS_JSONL = (
    '{{"name": "{target}", "domain": "{target}", "addresses": '
    '[{{"ip": "93.184.216.34", "cidr": "93.184.216.0/24"}}], "tag": "dns"}}\n'
    '{{"name": "api.{target}", "domain": "{target}", "addresses": '
    '[{{"ip": "93.184.216.35", "cidr": "93.184.216.0/24"}}], "tag": "cert"}}\n'
    '{{"name": "auth.{target}", "domain": "{target}", "addresses": '
    '[{{"ip": "93.184.216.36", "cidr": "93.184.216.0/24"}}], "tag": "cert"}}\n'
    '{{"name": "dev.{target}", "domain": "{target}", "addresses": '
    '[{{"ip": "93.184.216.37", "cidr": "93.184.216.0/24"}}], "tag": "dns"}}\n'
)


class AmassToolExecutor(ToolExecutor):
    """Amass-specific tool executor implementing ToolExecutor."""

    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        """Execute an Amass enumeration through the ARKA execution pipeline."""
        # 1. Parse and validate scan configuration from allowlist
        try:
            config = AmassScanConfig(
                mode=request.arguments.get("mode", "passive"),
                timeout_minutes=request.arguments.get("timeout_minutes", 5),
            )
        except (ValueError, TypeError) as e:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Invalid Amass configuration: {e}",
                output={},
                raw_output="",
            )

        # 2. Risk escalation check
        if config.requires_escalation() and not request.approval_id:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error="Configuration requires HIGH risk approval: active mode",
                output={"escalation_required": True, "reasons": ["mode=active"]},
                raw_output="",
            )

        # 3. Construct safe argv
        target = request.target
        argv = config.to_argv(target)

        # 4. Generate simulated output (or read from custom arguments for testing)
        if "simulated_output" in request.arguments:
            simulated_raw = str(request.arguments["simulated_output"])
        else:
            simulated_raw = _SIMULATED_AMASS_JSONL.format(target=target)

        # 5. Parse output
        amass_result = parse_amass_json(simulated_raw, domain=target)

        if not amass_result.success:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Amass parse error: {amass_result.error}",
                output={"parse_error": amass_result.error},
                raw_output=simulated_raw[:10_000],
            )

        # 6. Return structured ToolResult
        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name="amass",
            success=True,
            output={
                "domain": target,
                "records": [r.model_dump() for r in amass_result.records],
                "record_count": len(amass_result.records),
                "argv": argv,
                "metadata": amass_result.metadata,
            },
            raw_output=simulated_raw,
        )
