"""Unit tests for Phase 3.1 WebSSRFValidator and ControlledHTTPClient."""

import httpx
import pytest

from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.execution.evidence import EvidenceStore
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.client.ssrf import WebSSRFError, WebSSRFValidator
from arka.app.web.models.http import HTTPMethod, HTTPRequest


@pytest.fixture
def scoped_guard():
    scope = ScopeDefinition(
        engagement_id="eng-web-1",
        includes=ScopeTarget(
            domains=["authorized.example.com"],
            urls=["http://authorized.example.com/api"],
            ip_addresses=["127.0.0.1"],  # e.g. explicitly scoped local target
            ports=[80, 443, 3000],
        ),
        excludes=ScopeTarget(
            domains=["forbidden.example.com"],
        ),
    )
    return ScopeGuard(scope)


class TestWebSSRFValidator:
    def test_prohibited_schemes(self):
        with pytest.raises(WebSSRFError, match="Prohibited URL scheme"):
            WebSSRFValidator.validate_url("file:///etc/passwd")

        with pytest.raises(WebSSRFError, match="Prohibited URL scheme"):
            WebSSRFValidator.validate_url("gopher://127.0.0.1:70")

    def test_cloud_metadata_unconditionally_blocked(self, scoped_guard):
        # Metadata is unconditionally blocked even if in scope
        metadata_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.253/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
        ]
        for target in metadata_targets:
            with pytest.raises(WebSSRFError, match="metadata"):
                WebSSRFValidator.validate_url(target, scoped_guard)

    def test_unauthorized_internal_network_blocked(self, scoped_guard):
        unauthorized_targets = [
            "http://10.0.0.1/admin",
            "http://192.168.1.1/",
            "http://172.16.0.5:8080/",
        ]
        for target in unauthorized_targets:
            with pytest.raises(
                WebSSRFError, match=r"outside authorized engagement scope|restricted"
            ):
                WebSSRFValidator.validate_url(target, scoped_guard)

    def test_in_scope_target_allowed(self, scoped_guard):
        # http://authorized.example.com/api is explicitly in scope
        WebSSRFValidator.validate_url("http://authorized.example.com/api/v1/users", scoped_guard)

    def test_in_scope_local_ip_allowed(self, scoped_guard):
        # 127.0.0.1 is in scoped_guard included IPs and port 3000 in ports
        WebSSRFValidator.validate_url("http://127.0.0.1:3000/rest/products", scoped_guard)

    def test_out_of_scope_target_blocked(self, scoped_guard):
        with pytest.raises(WebSSRFError, match="outside authorized engagement scope"):
            WebSSRFValidator.validate_url("http://evil-attacker.com/steal", scoped_guard)

    def test_excluded_domain_blocked(self, scoped_guard):
        with pytest.raises(WebSSRFError, match="outside authorized engagement scope"):
            WebSSRFValidator.validate_url("http://forbidden.example.com/", scoped_guard)


class TestControlledHTTPClient:
    @pytest.mark.asyncio
    async def test_client_executes_request_with_mock_transport(self, scoped_guard):
        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"status": "success", "data": [1, 2, 3]},
                headers={"Content-Type": "application/json"},
            )

        transport = httpx.MockTransport(mock_handler)
        evidence_store = EvidenceStore()
        client = ControlledHTTPClient(
            scope_guard=scoped_guard,
            evidence_store=evidence_store,
            transport=transport,
        )

        req = HTTPRequest(url="http://authorized.example.com/api/items", method=HTTPMethod.GET)
        tx = await client.execute(req, engagement_id="eng-web-1", task_id="task-1")

        assert tx.is_success() is True
        assert tx.response is not None
        assert tx.response.status_code == 200
        assert '"status"' in tx.response.body and '"success"' in tx.response.body
        assert tx.evidence_ref is not None

        # Verify evidence was recorded in EvidenceStore
        stored = evidence_store.get_evidence(tx.evidence_ref)
        assert stored is not None
        assert stored.tool_name == "controlled_http_client"

    @pytest.mark.asyncio
    async def test_client_blocks_ssrf_without_making_network_call(self, scoped_guard):
        transport_called = False

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal transport_called
            transport_called = True
            return httpx.Response(200, text="Should never be reached")

        transport = httpx.MockTransport(mock_handler)
        client = ControlledHTTPClient(scope_guard=scoped_guard, transport=transport)

        req = HTTPRequest(url="http://169.254.169.254/latest/meta-data/")
        tx = await client.execute(req, engagement_id="eng-web-1")

        assert tx.response is None
        assert "SSRF/Scope validation blocked" in (tx.error or "")
        assert transport_called is False

    @pytest.mark.asyncio
    async def test_redirect_to_unauthorized_destination_is_blocked(self, scoped_guard):
        async def mock_handler(request: httpx.Request) -> httpx.Response:
            if str(request.url) == "http://authorized.example.com/api/redirect":
                # Malicious or out-of-scope redirect
                return httpx.Response(
                    302,
                    headers={"Location": "http://169.254.169.254/latest/meta-data/"},
                )
            return httpx.Response(200, text="Internal metadata")

        transport = httpx.MockTransport(mock_handler)
        client = ControlledHTTPClient(scope_guard=scoped_guard, transport=transport)

        req = HTTPRequest(
            url="http://authorized.example.com/api/redirect",
            follow_redirects=True,
        )
        tx = await client.execute(req, engagement_id="eng-web-1")

        assert tx.error is not None
        assert "blocked by SSRF/ScopeGuard" in tx.error

    @pytest.mark.asyncio
    async def test_response_truncation_on_oversized_body(self, scoped_guard):
        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"A" * 2000)

        transport = httpx.MockTransport(mock_handler)
        client = ControlledHTTPClient(
            scope_guard=scoped_guard,
            max_response_size=500,  # Max 500 bytes
            transport=transport,
        )

        req = HTTPRequest(url="http://authorized.example.com/api/large")
        tx = await client.execute(req, engagement_id="eng-web-1")

        assert tx.response is not None
        assert tx.response.truncated is True
        assert len(tx.response.raw_body_bytes or b"") == 500
