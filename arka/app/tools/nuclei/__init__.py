"""Nuclei vulnerability scanner adapter for ARKA."""

from arka.app.tools.nuclei.definition import (
    NucleiToolDefinition,
    get_nuclei_tool_definition,
    register_nuclei_tool,
)
from arka.app.tools.nuclei.executor import NucleiToolExecutor
from arka.app.tools.nuclei.parser import parse_nuclei_json
from arka.app.tools.nuclei.schemas import (
    NucleiFinding,
    NucleiResult,
    NucleiScanConfig,
)

__all__ = [
    "NucleiFinding",
    "NucleiResult",
    "NucleiScanConfig",
    "NucleiToolDefinition",
    "NucleiToolExecutor",
    "get_nuclei_tool_definition",
    "parse_nuclei_json",
    "register_nuclei_tool",
]
