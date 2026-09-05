"""ffuf web fuzzer adapter for ARKA."""

from arka.app.tools.ffuf.definition import (
    FfufToolDefinition,
    get_ffuf_tool_definition,
    register_ffuf_tool,
)
from arka.app.tools.ffuf.executor import FfufToolExecutor
from arka.app.tools.ffuf.parser import parse_ffuf_json
from arka.app.tools.ffuf.schemas import (
    FfufMatch,
    FfufResult,
    FfufScanConfig,
)

__all__ = [
    "FfufMatch",
    "FfufResult",
    "FfufScanConfig",
    "FfufToolDefinition",
    "FfufToolExecutor",
    "get_ffuf_tool_definition",
    "parse_ffuf_json",
    "register_ffuf_tool",
]
