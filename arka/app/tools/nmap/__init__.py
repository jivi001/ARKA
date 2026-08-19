"""ARKA Nmap Adapter & Parser Foundation (Phase 2.2.1).

Provides the Nmap tool adapter, safe argument model, XML parser,
and tool registration for the ARKA execution pipeline.
"""

from arka.app.tools.nmap.definition import get_nmap_tool_definition, register_nmap_tool
from arka.app.tools.nmap.executor import NmapToolExecutor
from arka.app.tools.nmap.parser import parse_nmap_xml
from arka.app.tools.nmap.schemas import (
    NmapHost,
    NmapPort,
    NmapResult,
    NmapScanConfig,
    NmapScript,
    NmapService,
)

__all__ = [
    "NmapHost",
    "NmapPort",
    "NmapResult",
    "NmapScanConfig",
    "NmapScript",
    "NmapService",
    "NmapToolExecutor",
    "get_nmap_tool_definition",
    "parse_nmap_xml",
    "register_nmap_tool",
]
