"""Nuclei tool executor for ARKA.

Implements the ToolExecutor interface for Nuclei vulnerability scanner.
Constructs safe argv, simulates/executes the scan, and parses JSON output.
"""

from __future__ import annotations

from arka.app.tools.nuclei.parser import parse_nuclei_json
from arka.app.tools.nuclei.schemas import NucleiScanConfig
from arka.app.tools.registry.registry import ToolExecutor
from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest, ToolResult

# Template simulated JSON for Nuclei findings
_SIMULATED_NUCLEI_OUTPUT = (
    '{{"template-id": "ssl-issuer", "info": {{"name": "SSL Issuer Details", '
    '"severity": "info", "description": "Displays SSL certificate issuer details"}}, '
    '"type": "ssl", "host": "{target}", "matched-at": "{target}:443"}}\n'
    '{{"template-id": "http-missing-security-headers", "info": {{"name": '
    '"Missing Security Headers", "severity": "low", "description": "Missing security headers"}}, '
    '"type": "http", "host": "{target}", "matched-at": "{target}/", '
    '"extracted-results": ["HSTS missing", "CSP missing"]}}\n'
)


_SIMULATED_NUCLEI_HIGH_OUTPUT = (
    '{{"template-id": "cve-2023-38606", "info": {{"name": "Critical RCE Probe", '
    '"severity": "high", "description": "Potentially vulnerable service detected", '
    '"classification": {{"cve-id": "CVE-2023-38606", "cvss-score": 8.8}}}}, '
    '"type": "http", "host": "{target}", "matched-at": "{target}/api/v1/debug"}}\n'
)


class NucleiToolExecutor(ToolExecutor):
    """Nuclei-specific tool executor implementing ToolExecutor."""

    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        """Execute a Nuclei scan through the ARKA execution pipeline."""
        # 1. Parse and validate scan configuration from allowlist
        try:
            config = NucleiScanConfig(
                templates=request.arguments.get("templates"),
                tags=request.arguments.get("tags"),
                severity=request.arguments.get("severity"),
                rate_limit=request.arguments.get("rate_limit", 50),
                timeout=request.arguments.get("timeout", 5),
            )
        except (ValueError, TypeError) as e:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Invalid Nuclei configuration: {e}",
                output={},
                raw_output="",
            )

        # 2. Risk escalation check
        if config.requires_escalation() and not request.approval_id:
            reasons: list[str] = []
            if config.rate_limit > 100:
                reasons.append(f"rate_limit={config.rate_limit} (>100)")
            if config.severity and any(s in ("high", "critical") for s in config.severity):
                reasons.append(f"high/critical severity requested: {config.severity}")
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error="Configuration requires HIGH risk approval: " + ", ".join(reasons),
                output={"escalation_required": True, "reasons": reasons},
                raw_output="",
            )

        # 3. Construct safe argv
        argv = config.to_argv(request.target)

        # 4. Generate simulated output (or read from custom arguments for testing)
        target = request.target
        if "simulated_output" in request.arguments:
            simulated_raw = str(request.arguments["simulated_output"])
        else:
            simulated_raw = _SIMULATED_NUCLEI_OUTPUT.format(target=target)
            if config.severity and any(s in ("high", "critical") for s in config.severity):
                simulated_raw += _SIMULATED_NUCLEI_HIGH_OUTPUT.format(target=target)

        # 5. Parse output
        nuclei_result = parse_nuclei_json(simulated_raw, target=target)

        if not nuclei_result.success:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Nuclei parse error: {nuclei_result.error}",
                output={"parse_error": nuclei_result.error},
                raw_output=simulated_raw[:10_000],
            )

        # 6. Return structured ToolResult with full raw_output for EvidenceStore
        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name="nuclei",
            success=True,
            output={
                "target": target,
                "findings": [f.model_dump() for f in nuclei_result.findings],
                "finding_count": len(nuclei_result.findings),
                "argv": argv,
                "metadata": nuclei_result.metadata,
            },
            raw_output=simulated_raw,
        )
