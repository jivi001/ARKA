"""ffuf tool executor for ARKA.

Implements the ToolExecutor interface for ffuf web fuzzer.
Constructs safe argv, simulates/executes the scan, and parses JSON output.
"""

from __future__ import annotations

from arka.app.tools.ffuf.parser import parse_ffuf_json
from arka.app.tools.ffuf.schemas import FfufScanConfig
from arka.app.tools.registry.registry import ToolExecutor
from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest, ToolResult

_SIMULATED_FFUF_JSON = """\
{{
  "commandline": "ffuf -u {target}/FUZZ -w wordlists/common.txt -o - -of json",
  "config": {{
    "url": "{target}/FUZZ"
  }},
  "results": [
    {{
      "input": {{"FUZZ": "robots.txt"}},
      "position": 1,
      "status": 200,
      "length": 154,
      "words": 12,
      "lines": 5,
      "content-type": "text/plain",
      "url": "{target}/robots.txt"
    }},
    {{
      "input": {{"FUZZ": "login"}},
      "position": 2,
      "status": 200,
      "length": 3420,
      "words": 210,
      "lines": 80,
      "content-type": "text/html",
      "url": "{target}/login"
    }},
    {{
      "input": {{"FUZZ": "api"}},
      "position": 3,
      "status": 301,
      "length": 178,
      "words": 8,
      "lines": 4,
      "redirectlocation": "{target}/api/",
      "url": "{target}/api"
    }},
    {{
      "input": {{"FUZZ": "admin"}},
      "position": 4,
      "status": 403,
      "length": 250,
      "words": 15,
      "lines": 6,
      "content-type": "text/html",
      "url": "{target}/admin"
    }}
  ]
}}
"""


class FfufToolExecutor(ToolExecutor):
    """ffuf-specific tool executor implementing ToolExecutor."""

    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        """Execute a ffuf directory scan through the ARKA execution pipeline."""
        # 1. Parse and validate scan configuration from allowlist
        try:
            config = FfufScanConfig(
                wordlist=request.arguments.get("wordlist", "common.txt"),
                rate=request.arguments.get("rate", 20),
                recursion=request.arguments.get("recursion", False),
                recursion_depth=request.arguments.get("recursion_depth", 1),
                match_codes=request.arguments.get("match_codes", "200,204,301,302,307,401,403"),
                filter_codes=request.arguments.get("filter_codes", "404"),
            )
        except (ValueError, TypeError) as e:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Invalid ffuf configuration: {e}",
                output={},
                raw_output="",
            )

        # 2. Risk escalation check
        if config.requires_escalation() and not request.approval_id:
            reasons: list[str] = []
            if config.rate > 50:
                reasons.append(f"rate={config.rate} (>50)")
            if config.recursion_depth > 2:
                reasons.append(f"recursion_depth={config.recursion_depth} (>2)")
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
        target = request.target
        argv = config.to_argv(target)

        # 4. Generate simulated output (or read from custom arguments for testing)
        target_norm = target.rstrip("/")
        if "simulated_output" in request.arguments:
            simulated_raw = str(request.arguments["simulated_output"])
        else:
            simulated_raw = _SIMULATED_FFUF_JSON.format(target=target_norm)

        # 5. Parse output
        ffuf_result = parse_ffuf_json(simulated_raw, target_url=target_norm)

        if not ffuf_result.success:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"ffuf parse error: {ffuf_result.error}",
                output={"parse_error": ffuf_result.error},
                raw_output=simulated_raw[:10_000],
            )

        # 6. Return structured ToolResult
        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name="ffuf",
            success=True,
            output={
                "target_url": target_norm,
                "matches": [m.model_dump() for m in ffuf_result.matches],
                "match_count": len(ffuf_result.matches),
                "argv": argv,
                "metadata": ffuf_result.metadata,
            },
            raw_output=simulated_raw,
        )
