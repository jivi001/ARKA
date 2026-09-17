"""Unit tests for Phase 3 web security tool definitions and executors."""

import httpx
import pytest

from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import RiskLevel, ScopeDefinition, ScopeTarget
from arka.app.execution.evidence import EvidenceStore
from arka.app.tools.schemas.tool_schemas import ToolRequest
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.tools.definitions import (
    get_graphql_analyze_tool_definition,
    get_http_request_tool_definition,
    get_openapi_analyze_tool_definition,
    get_web_crawler_tool_definition,
)
from arka.app.web.tools.executors import (
    HTTPRequestToolExecutor,
    WebCrawlerToolExecutor,
)


@pytest.fixture
def scope_guard() -> ScopeGuard:
    scope = ScopeDefinition(
        engagement_id="eng-web-tools",
        includes=ScopeTarget(
            domains=["target.example.com"],
            ports=[80, 443],
        ),
    )
    return ScopeGuard(scope)


def test_tool_definitions_risk_levels() -> None:
    crawl_def = get_web_crawler_tool_definition()
    assert crawl_def.risk_level == RiskLevel.LOW

    openapi_def = get_openapi_analyze_tool_definition()
    assert openapi_def.risk_level == RiskLevel.LOW

    graphql_def = get_graphql_analyze_tool_definition()
    assert graphql_def.risk_level == RiskLevel.LOW

    # HTTP request tool has dynamic operation-level risk escalation
    http_def = get_http_request_tool_definition()
    assert http_def.determine_risk({"method": "GET"}) == RiskLevel.LOW
    assert http_def.determine_risk({"method": "POST"}) == RiskLevel.MEDIUM
    assert http_def.determine_risk({"method": "DELETE"}) == RiskLevel.HIGH
    assert http_def.determine_risk({"method": "PUT"}) == RiskLevel.HIGH


@pytest.mark.asyncio
async def test_http_request_tool_executor(scope_guard: ScopeGuard) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            text='{"message": "success"}',
        )

    transport = httpx.MockTransport(handler)
    evidence_store = EvidenceStore()
    client = ControlledHTTPClient(
        transport=transport, scope_guard=scope_guard, evidence_store=evidence_store
    )
    executor = HTTPRequestToolExecutor(
        scope_guard=scope_guard, evidence_store=evidence_store, http_client=client
    )

    tool_def = get_http_request_tool_definition()
    req = ToolRequest(
        engagement_id="eng-web-tools",
        task_id="task-1",
        agent_id="agent-1",
        tool_name="http_request",
        target="https://target.example.com/api/test",
        arguments={"url": "https://target.example.com/api/test", "method": "GET"},
    )

    result = await executor.execute(req, tool_def)
    assert result.success is True
    assert result.output["status_code"] == 200
    assert "evidence_ref" in result.output


@pytest.mark.asyncio
async def test_web_crawler_tool_executor_persists_endpoints(scope_guard: ScopeGuard) -> None:
    html_content = """
    <html>
      <body>
        <a href="/page1">Page 1</a>
        <a href="/page2">Page 2</a>
      </body>
    </html>
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "text/html"},
            text=html_content,
        )

    transport = httpx.MockTransport(handler)
    repo = InMemoryAssetRepository()
    evidence_store = EvidenceStore()
    client = ControlledHTTPClient(
        transport=transport, scope_guard=scope_guard, evidence_store=evidence_store
    )

    executor = WebCrawlerToolExecutor(
        scope_guard=scope_guard,
        evidence_store=evidence_store,
        asset_repository=repo,
        http_client=client,
    )

    tool_def = get_web_crawler_tool_definition()
    req = ToolRequest(
        engagement_id="eng-web-tools",
        task_id="task-crawl",
        agent_id="agent-1",
        tool_name="web_crawler",
        target="https://target.example.com/",
        arguments={"target": "https://target.example.com/", "max_pages": 5, "max_depth": 2},
    )

    result = await executor.execute(req, tool_def)
    assert result.success is True
    assert result.output["pages_crawled"] >= 1

    # Verify endpoints persisted in repository
    stored_endpoints = repo.get_endpoints_by_engagement("eng-web-tools")
    assert len(stored_endpoints) >= 1
    for ep in stored_endpoints:
        assert ep.metadata["discovered_not_authorized"] is True
