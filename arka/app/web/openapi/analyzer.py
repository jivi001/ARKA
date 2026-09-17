"""OpenAPI and Swagger Discovery and Schema Analyzer."""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING

from arka.app.web.models.endpoint import DiscoveredWebEndpoint
from arka.app.web.models.http import HTTPMethod, HTTPRequest
from arka.app.web.openapi.models import OpenAPISchema, OpenAPIServer
from arka.app.web.openapi.parser import OpenAPIParseError, SafeOpenAPIParser

if TYPE_CHECKING:
    from arka.app.core.scope.scopeguard import ScopeGuard
    from arka.app.web.client.client import ControlledHTTPClient

# Conventional paths where OpenAPI and Swagger documents are hosted
CONVENTIONAL_OPENAPI_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
]


class OpenAPIAnalyzer:
    """Discovers and safely analyzes OpenAPI / Swagger specifications."""

    def __init__(
        self,
        http_client: ControlledHTTPClient | None = None,
        scope_guard: ScopeGuard | None = None,
        parser: SafeOpenAPIParser | None = None,
    ) -> None:
        self.http_client = http_client
        self.scope_guard = scope_guard
        self.parser = parser or SafeOpenAPIParser()

    async def discover_and_analyze(
        self,
        base_url: str,
        custom_paths: list[str] | None = None,
    ) -> list[OpenAPISchema]:
        """Probe conventional OpenAPI paths on base_url and analyze discovered specifications."""
        if not self.http_client:
            raise ValueError("ControlledHTTPClient is required for network discovery.")

        candidate_paths = custom_paths or CONVENTIONAL_OPENAPI_PATHS
        schemas: list[OpenAPISchema] = []

        parsed_base = urllib.parse.urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}".rstrip("/")

        for path in candidate_paths:
            full_url = urllib.parse.urljoin(origin, path)

            # ScopeGuard pre-check before even attempting the request
            if self.scope_guard and not self.scope_guard.validate_url(full_url):
                continue

            req = HTTPRequest(
                method=HTTPMethod.GET,
                url=full_url,
                headers={"Accept": "application/json, application/yaml, text/yaml, */*"},
                timeout=10.0,
            )

            tx = await self.http_client.execute(req)
            if tx.response and tx.response.status_code == 200 and tx.response.body:
                try:
                    schema = self.analyze_content(tx.response.body, source_url=full_url)
                    schemas.append(schema)
                except OpenAPIParseError:
                    # Not a valid OpenAPI document at this candidate path
                    continue

        return schemas

    def analyze_content(self, content: str | bytes, source_url: str = "") -> OpenAPISchema:
        """Parse OpenAPI specification content and validate server scopes.

        CRITICAL INVARIANT: Declared servers are NEVER blindly authorized.
        Every server is validated against ScopeGuard; out-of-scope servers are
        flagged with in_authorized_scope=False and cannot expand scanning scope.
        """
        raw_schema = self.parser.parse(content, source_url=source_url)

        # Re-evaluate all servers against ScopeGuard
        scoped_servers: list[OpenAPIServer] = []
        for server in raw_schema.servers:
            in_scope = False
            if self.scope_guard:
                in_scope = self.scope_guard.validate_url(server.url)
            scoped_servers.append(
                OpenAPIServer(
                    url=server.url,
                    description=server.description,
                    in_authorized_scope=in_scope,
                )
            )

        return raw_schema.model_copy(update={"servers": scoped_servers})

    def extract_endpoints_from_schema(
        self, schema: OpenAPISchema, fallback_origin: str = ""
    ) -> list[DiscoveredWebEndpoint]:
        """Transform OpenAPI operations into DiscoveredWebEndpoints.

        Enforces the invariant: DISCOVERED != AUTHORIZED.
        Destructive operations (DELETE, PUT) are flagged and must undergo policy evaluation.
        """
        # Select base URL: prefer an authorized server URL if available, else fallback_origin
        chosen_base = fallback_origin
        for s in schema.servers:
            if s.in_authorized_scope:
                chosen_base = s.url
                break

        if not chosen_base and schema.source_url:
            parsed = urllib.parse.urlparse(schema.source_url)
            chosen_base = f"{parsed.scheme}://{parsed.netloc}"

        chosen_base = chosen_base.rstrip("/")
        endpoints: list[DiscoveredWebEndpoint] = []

        for op in schema.operations:
            full_url = urllib.parse.urljoin(chosen_base + "/", op.path.lstrip("/"))

            ep = DiscoveredWebEndpoint(
                url=full_url,
                method=op.method,
                parameters=op.parameters,
                source="openapi",
                title=op.summary or op.operation_id,
                metadata={
                    "discovered_not_authorized": True,
                    "is_destructive": op.is_destructive,
                    "operation_id": op.operation_id,
                    "tags": op.tags,
                    "security_requirements": op.security_requirements,
                    "request_body_types": op.request_body_content_types,
                    "spec_title": schema.title,
                    "spec_version": schema.spec_version,
                },
            )
            endpoints.append(ep)

        return endpoints
