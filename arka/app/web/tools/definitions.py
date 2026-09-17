"""ToolDefinition factories for ARKA Web Security Tools."""

from __future__ import annotations

from typing import Any

from arka.app.core.state.models import RiskLevel
from arka.app.tools.schemas.tool_schemas import ToolDefinition


def get_web_crawler_tool_definition() -> ToolDefinition:
    """Return canonical ToolDefinition for the web crawler tool."""
    return ToolDefinition(
        name="web_crawler",
        description="Autonomous scope-bounded web crawler discovering links, forms, and assets.",
        version="1.0.0",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Seed URL to crawl"},
                "max_pages": {"type": "integer", "default": 30, "minimum": 1, "maximum": 200},
                "max_depth": {"type": "integer", "default": 3, "minimum": 1, "maximum": 10},
                "same_origin_only": {"type": "boolean", "default": True},
                "allow_subdomains": {"type": "boolean", "default": False},
                "respect_robots_txt": {"type": "boolean", "default": True},
                "follow_redirects": {"type": "boolean", "default": True},
                "parse_sitemap": {"type": "boolean", "default": True},
                "request_timeout": {"type": "number", "default": 10.0},
            },
            "required": ["target"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "pages_crawled": {"type": "integer"},
                "urls_discovered": {"type": "array", "items": {"type": "string"}},
                "endpoints_count": {"type": "integer"},
                "forms_count": {"type": "integer"},
            },
        },
        risk_level=RiskLevel.LOW,
        required_permissions=["network:http"],
        allowed_environments=["sandbox", "local"],
        timeout_seconds=120,
        rate_limit_per_minute=60,
        evidence_required=True,
        category="reconnaissance",
    )


def get_http_request_tool_definition() -> ToolDefinition:
    """Return canonical ToolDefinition for the controlled HTTP request tool."""

    class DynamicRiskHTTPRequestToolDefinition(ToolDefinition):
        def determine_risk(self, arguments: dict[str, Any] | None = None) -> RiskLevel:
            if not arguments:
                return self.risk_level
            method = str(arguments.get("method", "GET")).upper()
            if method in ("DELETE", "PUT", "PATCH"):
                return RiskLevel.HIGH
            if method == "POST":
                return RiskLevel.MEDIUM
            return RiskLevel.LOW

    return DynamicRiskHTTPRequestToolDefinition(
        name="http_request",
        description="Controlled HTTP client executing authorized and SSRF-validated web requests.",
        version="1.0.0",
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target HTTP URL"},
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                    "default": "GET",
                },
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "body": {"type": "string"},
                "timeout": {"type": "number", "default": 10.0},
            },
            "required": ["url"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "status_code": {"type": "integer"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
                "elapsed_time_ms": {"type": "number"},
                "evidence_ref": {"type": "string"},
            },
        },
        risk_level=RiskLevel.LOW,
        required_permissions=["network:http"],
        allowed_environments=["sandbox", "local"],
        timeout_seconds=30,
        rate_limit_per_minute=120,
        evidence_required=True,
        category="active_probing",
    )


def get_openapi_analyze_tool_definition() -> ToolDefinition:
    """Return canonical ToolDefinition for OpenAPI discovery and schema analysis."""
    return ToolDefinition(
        name="openapi_analyze",
        description="Discovers and analyzes OpenAPI / Swagger specifications and endpoints.",
        version="1.0.0",
        input_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target base URL or OpenAPI document URL",
                },
            },
            "required": ["target"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "operations_count": {"type": "integer"},
                "servers": {"type": "array", "items": {"type": "string"}},
                "security_schemes": {"type": "array", "items": {"type": "string"}},
            },
        },
        risk_level=RiskLevel.LOW,
        required_permissions=["network:http"],
        allowed_environments=["sandbox", "local"],
        timeout_seconds=60,
        rate_limit_per_minute=30,
        evidence_required=True,
        category="reconnaissance",
    )


def get_graphql_analyze_tool_definition() -> ToolDefinition:
    """Return canonical ToolDefinition for GraphQL discovery and schema analysis."""
    return ToolDefinition(
        name="graphql_analyze",
        description="Discovers and analyzes GraphQL endpoints and runs bounded introspection.",
        version="1.0.0",
        input_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target base URL or GraphQL endpoint URL",
                },
            },
            "required": ["target"],
        },
        output_schema={
            "type": "object",
            "properties": {
                "introspection_enabled": {"type": "boolean"},
                "queries_count": {"type": "integer"},
                "mutations_count": {"type": "integer"},
                "types_count": {"type": "integer"},
            },
        },
        risk_level=RiskLevel.LOW,
        required_permissions=["network:http"],
        allowed_environments=["sandbox", "local"],
        timeout_seconds=60,
        rate_limit_per_minute=30,
        evidence_required=True,
        category="reconnaissance",
    )
