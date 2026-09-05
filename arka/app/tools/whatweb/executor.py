"""WhatWeb tool executor for ARKA.

Implements the ToolExecutor interface for WhatWeb technology fingerprinter.
Constructs safe argv, simulates/executes the scan, and parses JSON output.
"""

from __future__ import annotations

from arka.app.tools.registry.registry import ToolExecutor
from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest, ToolResult
from arka.app.tools.whatweb.parser import parse_whatweb_json
from arka.app.tools.whatweb.schemas import WhatWebScanConfig

_SIMULATED_WHATWEB_JSON = """\
[
  {{
    "target": "{target}",
    "http_status": 200,
    "plugins": {{
      "HTTPServer": {{
        "string": ["nginx/1.24.0"],
        "version": ["1.24.0"],
        "cpe": ["cpe:/a:nginx:nginx:1.24.0"]
      }},
      "PHP": {{
        "version": ["8.2.10"],
        "cpe": ["cpe:/a:php:php:8.2.10"]
      }},
      "Bootstrap": {{
        "version": ["5.3.0"]
      }},
      "X-Powered-By": {{
        "string": ["PHP/8.2.10"]
      }},
      "Country": {{
        "string": ["UNITED STATES"],
        "module": ["US"]
      }}
    }}
  }}
]
"""


class WhatWebToolExecutor(ToolExecutor):
    """WhatWeb-specific tool executor implementing ToolExecutor."""

    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        """Execute a WhatWeb scan through the ARKA execution pipeline."""
        # 1. Parse and validate scan configuration from allowlist
        try:
            config = WhatWebScanConfig(
                aggression=request.arguments.get("aggression", 1),
                no_errors=request.arguments.get("no_errors", True),
            )
        except (ValueError, TypeError) as e:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Invalid WhatWeb configuration: {e}",
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
                error="Configuration requires HIGH risk approval: aggression >= 3",
                output={"escalation_required": True, "reasons": ["aggression >= 3"]},
                raw_output="",
            )

        # 3. Construct safe argv
        target = request.target
        argv = config.to_argv(target)

        # 4. Generate simulated output (or read from custom arguments for testing)
        if "simulated_output" in request.arguments:
            simulated_raw = str(request.arguments["simulated_output"])
        else:
            simulated_raw = _SIMULATED_WHATWEB_JSON.format(target=target)

        # 5. Parse output
        whatweb_result = parse_whatweb_json(simulated_raw, target=target)

        if not whatweb_result.success:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"WhatWeb parse error: {whatweb_result.error}",
                output={"parse_error": whatweb_result.error},
                raw_output=simulated_raw[:10_000],
            )

        # 6. Return structured ToolResult
        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name="whatweb",
            success=True,
            output={
                "target": target,
                "targets": [t.model_dump() for t in whatweb_result.targets],
                "target_count": len(whatweb_result.targets),
                "argv": argv,
                "metadata": whatweb_result.metadata,
            },
            raw_output=simulated_raw,
        )
