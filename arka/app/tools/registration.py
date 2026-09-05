"""Explicit, deterministic tool registration for ARKA.

Every tool must be registered here. No dynamic discovery.
Registration order is deterministic and audit-logged.
"""

from __future__ import annotations

from arka.app.observability.logging import get_logger
from arka.app.tools.nmap.definition import register_nmap_tool
from arka.app.tools.registry.registry import ToolRegistry

logger = get_logger(__name__)


def register_all_tools(registry: ToolRegistry) -> None:
    """Register all production tools with the ToolRegistry.

    Each tool is registered explicitly. No dynamic filesystem scanning.
    Registration is idempotent — duplicate registration is caught by ToolRegistry.
    """
    registered: list[str] = []

    # Nmap — Phase 2.2.1 adapter (simulated executor)
    try:
        register_nmap_tool(registry)
        registered.append("nmap")
    except Exception as e:
        logger.warning(f"Failed to register nmap tool: {e}")

    logger.info(f"Tool registration complete: {registered}")
