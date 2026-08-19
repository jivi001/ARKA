"""Nmap tool executor for ARKA Phase 2.2.1.

Implements the ToolExecutor interface. The executor is called by ExecutionManager
AFTER all upstream authorization (ScopeGuard, PolicyEngine, ApprovalManager)
is complete. It constructs safe argv, delegates execution, and parses XML results.

The executor does NOT:
- Authorize itself
- Validate scope independently
- Approve itself
- Call subprocess directly
- Call Docker directly
- Call the LLM
- Write audit records directly
- Bypass ToolRegistry
"""

from __future__ import annotations

from arka.app.tools.nmap.parser import parse_nmap_xml
from arka.app.tools.nmap.schemas import NmapScanConfig
from arka.app.tools.registry.registry import ToolExecutor
from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest, ToolResult

# Static simulated Nmap XML for Phase 2.2.1 (adapter & parser foundation).
# Real nmap binary execution will be enabled when DockerSandboxRuntime
# connects to a live Docker daemon in a future phase.
_SIMULATED_NMAP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX - {target}" \
start="1724000000" startstr="Mon Aug 19 00:00:00 2026" \
version="7.95" xmloutputversion="1.05">
<host starttime="1724000000" endtime="1724000010">
<status state="up" reason="syn-ack"/>
<address addr="{target}" addrtype="ipv4"/>
<hostnames><hostname name="{target}" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.24.0" extrainfo="" \
method="probeMatch" conf="10">
<cpe>cpe:/a:nginx:nginx:1.24.0</cpe>
</service>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
<service name="https" product="nginx" version="1.24.0" extrainfo="SSL" \
method="probeMatch" conf="10">
<cpe>cpe:/a:nginx:nginx:1.24.0</cpe>
</service>
</port>
</ports>
</host>
<runstats>
<finished time="1724000010" timestr="Mon Aug 19 00:00:10 2026" \
elapsed="10.00" exit="success"/>
<hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""


class NmapToolExecutor(ToolExecutor):
    """Nmap-specific tool executor implementing the ToolExecutor interface.

    Constructs validated argv from typed NmapScanConfig fields,
    parses XML output, and returns structured NmapResult.

    In Phase 2.2.1 (Adapter & Parser Foundation), execution is simulated.
    The adapter, parser, argument safety, evidence, and audit flow are
    fully functional and production-quality.
    """

    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        """Execute an Nmap scan through the ARKA execution pipeline.

        This method is called by ExecutionManager after all upstream
        authorization is complete. It does NOT authorize, scope-check,
        or approve — those are handled by the pipeline.
        """
        # 1. Construct safe scan configuration from allowlisted arguments
        try:
            config = NmapScanConfig(
                ports=request.arguments.get("ports"),
                service_detection=request.arguments.get("service_detection", True),
                default_scripts=request.arguments.get("default_scripts", False),
                timing_template=request.arguments.get("timing_template", 2),
            )
        except (ValueError, TypeError) as e:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Invalid Nmap configuration: {e}",
                output={},
                raw_output="",
            )

        # 2. Operation-level risk escalation check
        if config.requires_escalation() and not request.approval_id:
            escalation_reasons: list[str] = []
            if config.default_scripts:
                escalation_reasons.append("default_scripts=True (-sC)")
            if config.timing_template >= 3:
                escalation_reasons.append(
                    f"timing_template={config.timing_template} (-T{config.timing_template})"
                )
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=(
                    "Configuration requires HIGH risk approval: " + ", ".join(escalation_reasons)
                ),
                output={"escalation_required": True, "reasons": escalation_reasons},
                raw_output="",
            )

        # 3. Construct safe argv from typed fields only
        argv = config.to_argv(request.target)

        # 4. Simulate Nmap execution (Phase 2.2.1 foundation)
        # In future phases, this will be replaced by real subprocess
        # execution through DockerSandboxRuntime.
        simulated_xml = _SIMULATED_NMAP_XML.format(target=request.target)

        # 5. Parse XML output
        nmap_result = parse_nmap_xml(simulated_xml)

        if not nmap_result.success:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Nmap XML parse error: {nmap_result.error}",
                output={"parse_error": nmap_result.error},
                raw_output=simulated_xml[:10_000],
            )

        # 6. Build structured result
        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name="nmap",
            success=True,
            output={
                "scan_metadata": nmap_result.scan_metadata,
                "hosts": [h.model_dump() for h in nmap_result.hosts],
                "host_count": len(nmap_result.hosts),
                "argv": argv,
            },
            raw_output=simulated_xml,
        )
