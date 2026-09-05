"""Amass subdomain/DNS enumerator adapter for ARKA."""

from arka.app.tools.amass.definition import (
    AmassToolDefinition,
    get_amass_tool_definition,
    register_amass_tool,
)
from arka.app.tools.amass.executor import AmassToolExecutor
from arka.app.tools.amass.parser import parse_amass_json
from arka.app.tools.amass.schemas import (
    AmassAddress,
    AmassRecord,
    AmassResult,
    AmassScanConfig,
)

__all__ = [
    "AmassAddress",
    "AmassRecord",
    "AmassResult",
    "AmassScanConfig",
    "AmassToolDefinition",
    "AmassToolExecutor",
    "get_amass_tool_definition",
    "parse_amass_json",
    "register_amass_tool",
]
