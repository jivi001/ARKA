"""Security tests for Phase 3.5 GraphQL analyzer."""

import httpx
import pytest

from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.graphql.analyzer import GraphQLAnalyzer, GraphQLAnalyzerError


@pytest.fixture
def scope_guard() -> ScopeGuard:
    scope = ScopeDefinition(
        engagement_id="eng-graphql-sec",
        includes=ScopeTarget(
            domains=["authorized.example.com"],
            ports=[80, 443],
        ),
        excludes=ScopeTarget(
            domains=["evil.attacker.com"],
        ),
    )
    return ScopeGuard(scope)


@pytest.mark.asyncio
async def test_unauthorized_graphql_endpoint_blocked(scope_guard: ScopeGuard) -> None:
    """Security: GraphQL queries to out-of-scope targets are blocked by ScopeGuard."""
    client = ControlledHTTPClient(scope_guard=scope_guard)
    analyzer = GraphQLAnalyzer(http_client=client, scope_guard=scope_guard)

    # Attempt to query unauthorized host
    schema = await analyzer.introspect_endpoint("https://evil.attacker.com/graphql")
    assert schema is None


@pytest.mark.asyncio
async def test_redirect_to_unauthorized_graphql_host_blocked(scope_guard: ScopeGuard) -> None:
    """Security: Redirect from authorized endpoint to unauthorized GraphQL host is blocked."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=302,
            headers={"Location": "https://evil.attacker.com/graphql"},
        )

    transport = httpx.MockTransport(handler)
    client = ControlledHTTPClient(transport=transport, scope_guard=scope_guard)
    analyzer = GraphQLAnalyzer(http_client=client, scope_guard=scope_guard)

    schema = await analyzer.introspect_endpoint("https://authorized.example.com/graphql")
    assert schema is None


def test_oversized_introspection_payload_rejected() -> None:
    """Security: Enforces max response size to prevent memory exhaustion."""
    analyzer = GraphQLAnalyzer(max_response_size=1024)  # 1 KB limit
    huge_data = " " * 2048
    with pytest.raises(GraphQLAnalyzerError, match="exceeds maximum limit"):
        analyzer.parse_introspection_response(
            huge_data, endpoint_url="https://authorized.example.com/graphql"
        )
