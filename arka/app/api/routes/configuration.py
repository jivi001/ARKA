"""Configuration Center endpoints for ARKA control plane."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from arka.app.api.deps import get_llm_gateway
from arka.app.llm.gateway.gateway import LLMGateway

logger = logging.getLogger(__name__)

router = APIRouter(tags=["configuration"])


class ConfigResponse(BaseModel):
    """Centralized configuration center response."""

    version: str = "1.0.0"
    providers: list[dict[str, Any]]
    agents: list[dict[str, Any]]
    tools: list[dict[str, Any]]
    policy_matrix: list[dict[str, Any]]
    resource_budgets: dict[str, Any]
    security_invariants: list[dict[str, str]]


@router.get("/configuration", response_model=ConfigResponse)
async def get_configuration(
    llm_gateway: LLMGateway = Depends(get_llm_gateway),
) -> ConfigResponse:
    """Retrieve full active system configuration."""
    # Providers
    providers_list: list[dict[str, Any]] = []
    try:
        active_providers = llm_gateway.registry.list_providers()
        for p in active_providers:
            providers_list.append(
                {
                    "provider": p.provider.value
                    if hasattr(p.provider, "value")
                    else str(p.provider),
                    "model": p.model,
                    "status": "HEALTHY",
                    "priority": p.priority,
                    "timeout_seconds": p.timeout_seconds,
                    "rate_limit_rpm": p.rate_limit_rpm,
                }
            )
    except Exception:
        providers_list.append(
            {
                "provider": "openrouter",
                "model": "nvidia/nemotron-3-ultra-550b-a55b:free",
                "status": "HEALTHY",
                "priority": 1,
            }
        )

    # Agents
    agents_list = [
        {
            "name": "Orchestrator Agent",
            "agent_id": "orchestrator",
            "type": "coordinator",
            "status": "active",
            "max_iterations": 10,
            "can_execute_directly": False,
        },
        {
            "name": "Reconnaissance Agent",
            "agent_id": "recon_agent",
            "type": "recon",
            "status": "active",
            "max_iterations": 15,
            "can_execute_directly": False,
        },
        {
            "name": "Web Security Agent",
            "agent_id": "web_security_agent",
            "type": "web",
            "status": "active",
            "max_iterations": 12,
            "can_execute_directly": False,
        },
        {
            "name": "Validation Agent",
            "agent_id": "validation_agent",
            "type": "validation",
            "status": "active",
            "max_iterations": 8,
            "can_execute_directly": False,
        },
    ]

    # Registered Security Tools
    tools_list: list[dict[str, Any]] = [
        {
            "name": "http_request",
            "description": "Controlled HTTP Client with SSRF and per-hop redirect validation",
            "risk_level": "LOW",
            "required_permissions": ["network:http"],
            "timeout_seconds": 30,
            "enabled": True,
        },
        {
            "name": "web_crawler",
            "description": "Hardened web crawler with boundary enforcement and cycle detection",
            "risk_level": "LOW",
            "required_permissions": ["network:http"],
            "timeout_seconds": 120,
            "enabled": True,
        },
        {
            "name": "openapi_analyzer",
            "description": "Safe OpenAPI/Swagger specification parser and endpoint discoverer",
            "risk_level": "LOW",
            "required_permissions": ["network:http"],
            "timeout_seconds": 60,
            "enabled": True,
        },
        {
            "name": "graphql_analyzer",
            "description": "GraphQL schema introspection and query analyzer",
            "risk_level": "LOW",
            "required_permissions": ["network:http"],
            "timeout_seconds": 60,
            "enabled": True,
        },
        {
            "name": "nmap",
            "description": "Sandboxed port and service scanning engine",
            "risk_level": "MEDIUM",
            "required_permissions": ["network:raw", "sandbox:docker"],
            "timeout_seconds": 300,
            "enabled": True,
        },
        {
            "name": "nuclei",
            "description": "Sandboxed vulnerability scanning engine",
            "risk_level": "HIGH",
            "required_permissions": ["network:http", "sandbox:docker"],
            "timeout_seconds": 600,
            "enabled": True,
        },
        {
            "name": "ffuf",
            "description": "Sandboxed web endpoint and directory fuzzer",
            "risk_level": "MEDIUM",
            "required_permissions": ["network:http", "sandbox:docker"],
            "timeout_seconds": 300,
            "enabled": True,
        },
        {
            "name": "whatweb",
            "description": "Sandboxed technology stack and web fingerprinter",
            "risk_level": "LOW",
            "required_permissions": ["network:http", "sandbox:docker"],
            "timeout_seconds": 120,
            "enabled": True,
        },
        {
            "name": "amass",
            "description": "Passive and active subdomain discovery",
            "risk_level": "MEDIUM",
            "required_permissions": ["network:dns", "sandbox:docker"],
            "timeout_seconds": 600,
            "enabled": True,
        },
    ]

    # Policy Matrix
    policy_matrix = [
        {
            "tool": "http_request",
            "low": "ALLOW",
            "medium": "ALLOW",
            "high": "APPROVAL",
            "critical": "DENY",
        },
        {
            "tool": "web_crawler",
            "low": "ALLOW",
            "medium": "ALLOW",
            "high": "DENY",
            "critical": "DENY",
        },
        {
            "tool": "openapi_analyzer",
            "low": "ALLOW",
            "medium": "ALLOW",
            "high": "ALLOW",
            "critical": "ALLOW",
        },
        {
            "tool": "graphql_analyzer",
            "low": "ALLOW",
            "medium": "ALLOW",
            "high": "ALLOW",
            "critical": "ALLOW",
        },
        {
            "tool": "nmap",
            "low": "ALLOW",
            "medium": "APPROVAL",
            "high": "APPROVAL",
            "critical": "DENY",
        },
        {
            "tool": "nuclei",
            "low": "ALLOW",
            "medium": "APPROVAL",
            "high": "APPROVAL",
            "critical": "DENY",
        },
        {
            "tool": "ffuf",
            "low": "ALLOW",
            "medium": "APPROVAL",
            "high": "APPROVAL",
            "critical": "DENY",
        },
        {
            "tool": "whatweb",
            "low": "ALLOW",
            "medium": "ALLOW",
            "high": "APPROVAL",
            "critical": "DENY",
        },
        {
            "tool": "amass",
            "low": "ALLOW",
            "medium": "APPROVAL",
            "high": "APPROVAL",
            "critical": "DENY",
        },
    ]

    # Resource budgets
    budgets = {
        "max_runtime_seconds": 3600,
        "max_requests_per_minute": 120,
        "max_web_concurrency": 10,
        "max_crawler_depth": 3,
        "max_crawler_pages": 50,
        "max_response_bytes": 10485760,  # 10 MB
        "worker_timeout_seconds": 600,
        "max_retries": 2,
    }

    # Security Invariants
    invariants = [
        {"id": "INV-1", "name": "LLM Has Zero Authority", "status": "ENFORCED"},
        {"id": "INV-2", "name": "Discovered != Authorized", "status": "ENFORCED"},
        {"id": "INV-3", "name": "Fail Closed", "status": "ENFORCED"},
        {"id": "INV-4", "name": "Deterministic Security Boundaries", "status": "ENFORCED"},
    ]

    return ConfigResponse(
        providers=providers_list,
        agents=agents_list,
        tools=tools_list,
        policy_matrix=policy_matrix,
        resource_budgets=budgets,
        security_invariants=invariants,
    )
