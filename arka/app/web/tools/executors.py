"""ToolExecutor implementations for ARKA Web Security Tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from arka.app.tools.registry.registry import ToolExecutor
from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest, ToolResult
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.crawler.config import CrawlerConfig
from arka.app.web.crawler.crawler import WebCrawler
from arka.app.web.discovery.integrator import WebDiscoveryIntegrator
from arka.app.web.graphql.analyzer import GraphQLAnalyzer
from arka.app.web.models.http import HTTPMethod, HTTPRequest
from arka.app.web.openapi.analyzer import OpenAPIAnalyzer

if TYPE_CHECKING:
    from arka.app.core.assets.repository import AssetRepository, InMemoryAssetRepository
    from arka.app.core.scope.scopeguard import ScopeGuard
    from arka.app.execution.evidence import EvidenceStore


class WebCrawlerToolExecutor(ToolExecutor):
    """Executes the scope-bounded web crawler tool."""

    def __init__(
        self,
        scope_guard: ScopeGuard | None = None,
        evidence_store: EvidenceStore | None = None,
        asset_repository: AssetRepository | InMemoryAssetRepository | None = None,
        http_client: ControlledHTTPClient | None = None,
    ) -> None:
        self.scope_guard = scope_guard
        self.evidence_store = evidence_store
        self.asset_repository = asset_repository
        self.http_client = http_client

    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        target = request.target
        args = request.arguments

        config_kwargs: dict[str, Any] = {}
        for k in (
            "max_pages",
            "max_depth",
            "same_origin_only",
            "allow_subdomains",
            "respect_robots_txt",
            "parse_sitemap",
            "request_timeout",
            "max_requests",
        ):
            if k in args:
                config_kwargs[k] = args[k]
        config = CrawlerConfig(**config_kwargs)

        client = self.http_client or ControlledHTTPClient(
            scope_guard=self.scope_guard,
            evidence_store=self.evidence_store,
        )

        crawler = WebCrawler(
            config=config,
            client=client,
            scope_guard=self.scope_guard,
        )

        try:
            crawl_result = await crawler.crawl(
                target, engagement_id=request.engagement_id, task_id=request.task_id
            )

            # Integrate discovered endpoints into canonical asset repository
            integrator = WebDiscoveryIntegrator(
                engagement_id=request.engagement_id,
                asset_repository=self.asset_repository,
                evidence_store=self.evidence_store,
                scope_guard=self.scope_guard,
            )
            raw_summary = json.dumps(
                {
                    "target_url": crawl_result.target_url,
                    "pages_crawled": crawl_result.pages_crawled,
                    "urls_discovered": crawl_result.urls_discovered,
                    "endpoints": [ep.model_dump() for ep in crawl_result.endpoints],
                },
                default=str,
            )
            bundle = integrator.integrate_crawl_result(
                crawl_result=crawl_result,
                evidence_content=raw_summary,
                execution_id=request.request_id,
                task_id=request.task_id,
            )
            if self.asset_repository is not None:
                await integrator.persist_bundle(bundle)

            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=True,
                output={
                    "target_url": crawl_result.target_url,
                    "pages_crawled": crawl_result.pages_crawled,
                    "urls_discovered": crawl_result.urls_discovered,
                    "endpoints_count": len(crawl_result.endpoints),
                    "forms_count": len(crawl_result.forms),
                },
                raw_output=raw_summary,
            )
        except Exception as e:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"Web crawler execution error: {e}",
                output={},
                raw_output="",
            )


class HTTPRequestToolExecutor(ToolExecutor):
    """Executes validated and SSRF-defended HTTP requests."""

    def __init__(
        self,
        scope_guard: ScopeGuard | None = None,
        evidence_store: EvidenceStore | None = None,
        http_client: ControlledHTTPClient | None = None,
    ) -> None:
        self.scope_guard = scope_guard
        self.evidence_store = evidence_store
        self.http_client = http_client or ControlledHTTPClient(
            scope_guard=scope_guard,
            evidence_store=evidence_store,
        )

    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        args = request.arguments
        url = args.get("url") or request.target
        method_str = str(args.get("method", "GET")).upper()
        headers = args.get("headers", {})
        body = args.get("body")
        timeout = float(args.get("timeout", 10.0))

        http_req = HTTPRequest(
            method=HTTPMethod(method_str),
            url=url,
            headers=headers,
            body=body,
            timeout=timeout,
        )

        tx = await self.http_client.execute(
            request=http_req,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
        )

        if tx.error or not tx.response:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=tx.error or "HTTP request failed without response",
                output={"error": tx.error},
                raw_output=tx.error or "",
            )

        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name=request.tool_name,
            success=True,
            output={
                "status_code": tx.response.status_code,
                "url": tx.response.url,
                "headers": tx.response.safe_headers_for_logging(),
                "body": tx.response.body[:2000],
                "elapsed_time_ms": tx.duration_ms,
                "evidence_ref": tx.evidence_ref,
            },
            raw_output=tx.response.body,
        )


class OpenAPIAnalyzeToolExecutor(ToolExecutor):
    """Executes OpenAPI specification discovery and schema analysis."""

    def __init__(
        self,
        scope_guard: ScopeGuard | None = None,
        evidence_store: EvidenceStore | None = None,
        asset_repository: AssetRepository | InMemoryAssetRepository | None = None,
        http_client: ControlledHTTPClient | None = None,
    ) -> None:
        self.scope_guard = scope_guard
        self.evidence_store = evidence_store
        self.asset_repository = asset_repository
        self.http_client = http_client or ControlledHTTPClient(
            scope_guard=scope_guard,
            evidence_store=evidence_store,
        )

    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        target = request.target
        analyzer = OpenAPIAnalyzer(
            http_client=self.http_client,
            scope_guard=self.scope_guard,
        )

        try:
            # If target looks like a specific openapi path or file, query it directly
            if target.endswith((".json", ".yaml", ".yml")):
                schemas = [
                    await self._analyze_single(
                        analyzer, target, request.engagement_id, request.task_id
                    )
                ]
            else:
                schemas = await analyzer.discover_and_analyze(target)

            valid_schemas = [s for s in schemas if s is not None]
            all_endpoints = []
            for s in valid_schemas:
                all_endpoints.extend(
                    analyzer.extract_endpoints_from_schema(s, fallback_origin=target)
                )

            if self.asset_repository is not None and all_endpoints:
                integrator = WebDiscoveryIntegrator(
                    engagement_id=request.engagement_id,
                    asset_repository=self.asset_repository,
                    evidence_store=self.evidence_store,
                    scope_guard=self.scope_guard,
                )
                bundle = integrator.build_bundle_from_discovered_endpoints(
                    endpoints=all_endpoints,
                    source="openapi",
                )
                await integrator.persist_bundle(bundle)

            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=True,
                output={
                    "schemas_found": len(valid_schemas),
                    "endpoints_discovered": len(all_endpoints),
                    "titles": [s.title for s in valid_schemas],
                },
                raw_output=json.dumps([s.model_dump() for s in valid_schemas], default=str),
            )
        except Exception as e:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"OpenAPI analysis error: {e}",
                output={},
                raw_output="",
            )

    async def _analyze_single(
        self, analyzer: OpenAPIAnalyzer, url: str, engagement_id: str, task_id: str
    ):
        req = HTTPRequest(method=HTTPMethod.GET, url=url, timeout=10.0)
        tx = await self.http_client.execute(req, engagement_id=engagement_id, task_id=task_id)
        if tx.response and tx.response.status_code == 200 and tx.response.body:
            return analyzer.analyze_content(tx.response.body, source_url=url)
        return None


class GraphQLAnalyzeToolExecutor(ToolExecutor):
    """Executes GraphQL discovery and introspection analysis."""

    def __init__(
        self,
        scope_guard: ScopeGuard | None = None,
        evidence_store: EvidenceStore | None = None,
        asset_repository: AssetRepository | InMemoryAssetRepository | None = None,
        http_client: ControlledHTTPClient | None = None,
    ) -> None:
        self.scope_guard = scope_guard
        self.evidence_store = evidence_store
        self.asset_repository = asset_repository
        self.http_client = http_client or ControlledHTTPClient(
            scope_guard=scope_guard,
            evidence_store=evidence_store,
        )

    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        target = request.target
        analyzer = GraphQLAnalyzer(
            http_client=self.http_client,
            scope_guard=self.scope_guard,
        )

        try:
            schema = await analyzer.introspect_endpoint(target, engagement_id=request.engagement_id)
            if not schema:
                # Try discovery if target was base URL
                schemas = await analyzer.discover_endpoints(target)
                schema = schemas[0] if schemas else None

            if not schema:
                return ToolResult(
                    request_id=request.request_id,
                    engagement_id=request.engagement_id,
                    task_id=request.task_id,
                    tool_name=request.tool_name,
                    success=True,
                    output={"graphql_detected": False},
                    raw_output="No active GraphQL endpoint detected at target.",
                )

            endpoints = analyzer.extract_endpoints_from_schema(schema)
            if self.asset_repository is not None and endpoints:
                integrator = WebDiscoveryIntegrator(
                    engagement_id=request.engagement_id,
                    asset_repository=self.asset_repository,
                    evidence_store=self.evidence_store,
                    scope_guard=self.scope_guard,
                )
                bundle = integrator.build_bundle_from_discovered_endpoints(
                    endpoints=endpoints,
                    source="graphql",
                )
                await integrator.persist_bundle(bundle)

            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=True,
                output={
                    "graphql_detected": True,
                    "introspection_enabled": schema.introspection_enabled,
                    "queries_count": len(schema.queries),
                    "mutations_count": len(schema.mutations),
                    "subscriptions_count": len(schema.subscriptions),
                    "types_count": len(schema.types),
                },
                raw_output=json.dumps(schema.model_dump(), default=str),
            )
        except Exception as e:
            return ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=f"GraphQL analysis error: {e}",
                output={},
                raw_output="",
            )
