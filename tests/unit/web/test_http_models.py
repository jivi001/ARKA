"""Unit tests for Phase 3.1 HTTP domain models, parameters, and authentication."""

import pytest
from pydantic import SecretStr

from arka.app.web.models.auth import AuthenticationContext, AuthType, SessionContext
from arka.app.web.models.endpoint import DiscoveredForm, DiscoveredWebEndpoint, FormField
from arka.app.web.models.http import (
    MAX_BODY_BYTES,
    HTTPMethod,
    HTTPRequest,
    HTTPResponse,
    HTTPTransaction,
    normalize_http_url,
)
from arka.app.web.models.parameters import Parameter, ParameterLocation


class TestHTTPRequestModels:
    def test_valid_get_request(self):
        req = HTTPRequest(url="https://example.com/api/v1/users", method=HTTPMethod.GET)
        assert req.method == HTTPMethod.GET
        assert req.url == "https://example.com/api/v1/users"
        assert req.path == "/api/v1/users"
        assert req.follow_redirects is False

    def test_valid_post_request_with_body(self):
        req = HTTPRequest(
            url="http://example.com:8080/login",
            method="POST",
            body='{"user": "alice"}',
            content_type="application/json",
            headers={"X-Custom": "test"},
        )
        assert req.method == HTTPMethod.POST
        assert req.url == "http://example.com:8080/login"
        assert req.body == '{"user": "alice"}'
        assert req.content_type == "application/json"

    def test_invalid_http_method(self):
        with pytest.raises(ValueError, match="Invalid HTTP method"):
            HTTPRequest(url="http://example.com", method="INVALID_METHOD")

    def test_invalid_url_scheme(self):
        with pytest.raises(ValueError, match="Only HTTP/HTTPS supported"):
            HTTPRequest(url="ftp://example.com/file.txt")

        with pytest.raises(ValueError, match="URL cannot be empty"):
            HTTPRequest(url="   ")

    def test_url_normalization(self):
        # Default port 80 for HTTP omitted
        url1, host1, port1, _path1 = normalize_http_url("HTTP://EXAMPLE.COM:80/path/./sub//")
        assert url1 == "http://example.com/path/./sub/"
        assert host1 == "example.com"
        assert port1 == 80

        # Default port 443 for HTTPS omitted
        url2, host2, port2, _path2 = normalize_http_url("https://Example.Com:443/test")
        assert url2 == "https://example.com/test"
        assert host2 == "example.com"
        assert port2 == 443

        # Non-default port retained
        url3, _host3, port3, _path3 = normalize_http_url("https://example.com:8443/test")
        assert url3 == "https://example.com:8443/test"
        assert port3 == 8443

    def test_headers_size_bound(self):
        huge_headers = {f"header_{i}": "x" * 1000 for i in range(100)}  # ~100KB > 64KB
        with pytest.raises(ValueError, match="headers exceed maximum allowed size"):
            HTTPRequest(url="http://example.com", headers=huge_headers)

    def test_body_size_bound(self):
        oversized_body = "x" * (MAX_BODY_BYTES + 100)
        with pytest.raises(ValueError, match="body exceeds maximum allowed size"):
            HTTPRequest(url="http://example.com", method="POST", body=oversized_body)

    def test_timeout_bounds(self):
        with pytest.raises(ValueError):
            HTTPRequest(url="http://example.com", timeout=0.01)  # ge=0.1
        with pytest.raises(ValueError):
            HTTPRequest(url="http://example.com", timeout=120.0)  # le=60.0

    def test_sensitive_header_redaction_in_request(self):
        req = HTTPRequest(
            url="http://example.com/secret",
            headers={
                "Authorization": "Bearer sk-super-secret-token",
                "Cookie": "session_id=12345",
                "X-Api-Key": "key-xyz",
                "Content-Type": "application/json",
            },
        )
        safe = req.safe_headers_for_logging()
        assert safe["Authorization"] == "[REDACTED]"
        assert safe["Cookie"] == "[REDACTED]"
        assert safe["X-Api-Key"] == "[REDACTED]"
        assert safe["Content-Type"] == "application/json"


class TestHTTPResponseModels:
    def test_http_response_properties(self):
        resp = HTTPResponse(
            status_code=200,
            headers={"Content-Type": "application/json", "Set-Cookie": "session=secret"},
            body='{"status": "ok"}',
            url="http://example.com/api",
            elapsed_time_ms=45.2,
        )
        assert resp.is_success() is True
        assert resp.is_redirect() is False
        assert resp.is_client_error() is False
        assert resp.is_server_error() is False
        assert resp.status_code == 200

        safe_headers = resp.safe_headers_for_logging()
        assert safe_headers["Set-Cookie"] == "[REDACTED]"
        assert safe_headers["Content-Type"] == "application/json"

    def test_response_status_categories(self):
        r302 = HTTPResponse(status_code=302, url="http://example.com")
        assert r302.is_redirect() is True

        r404 = HTTPResponse(status_code=404, url="http://example.com")
        assert r404.is_client_error() is True

        r500 = HTTPResponse(status_code=500, url="http://example.com")
        assert r500.is_server_error() is True


class TestHTTPTransaction:
    def test_transaction_creation(self):
        req = HTTPRequest(url="http://example.com/api")
        resp = HTTPResponse(status_code=200, url="http://example.com/api")
        tx = HTTPTransaction(
            engagement_id="eng-123",
            task_id="task-456",
            request=req,
            response=resp,
            duration_ms=50.0,
            evidence_ref="ev-789",
        )
        assert tx.engagement_id == "eng-123"
        assert tx.is_success() is True
        assert tx.evidence_ref == "ev-789"


class TestAuthenticationAndSessionModels:
    def test_bearer_auth_attachment(self):
        auth = AuthenticationContext(
            auth_type=AuthType.BEARER,
            credentials=SecretStr("my-jwt-token"),
        )
        req = HTTPRequest(url="http://example.com/profile")
        attached = auth.attach_to_request(req)
        assert attached.headers["Authorization"] == "Bearer my-jwt-token"

        safe_headers = auth.safe_headers_for_logging()
        assert safe_headers["Authorization"] == "Bearer [REDACTED]"

    def test_api_key_auth_attachment(self):
        auth = AuthenticationContext(
            auth_type=AuthType.API_KEY,
            credentials=SecretStr("api-key-123"),
            header_name="X-API-Key",
        )
        req = HTTPRequest(url="http://example.com/data")
        attached = auth.attach_to_request(req)
        assert attached.headers["X-API-Key"] == "api-key-123"

    def test_session_context(self):
        session = SessionContext(
            engagement_id="eng-123",
            auth_context=AuthenticationContext(auth_type=AuthType.NONE),
        )
        assert session.active is True
        assert session.session_id is not None


class TestParameterAndEndpointModels:
    def test_parameter_creation(self):
        p = Parameter(
            name="id",
            location=ParameterLocation.QUERY,
            param_type="integer",
            sample_value="42",
            required=True,
        )
        assert p.name == "id"
        assert p.location == ParameterLocation.QUERY
        assert p.required is True

    def test_discovered_endpoint_and_form(self):
        form = DiscoveredForm(
            action="/search",
            method=HTTPMethod.GET,
            page_url="http://example.com/home",
            fields=[
                FormField(name="q", field_type="text", required=True),
                FormField(name="submit", field_type="submit"),
            ],
        )
        endpoint = DiscoveredWebEndpoint(
            url="http://example.com/search",
            host="example.com",
            port=80,
            path="/search",
            method=HTTPMethod.GET,
            forms=[form],
            source="crawler",
        )
        assert endpoint.host == "example.com"
        assert len(endpoint.forms) == 1
        assert len(endpoint.forms[0].fields) == 2
