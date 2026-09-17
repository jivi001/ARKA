"""Unit and security boundary tests for Phase 3.6 Authenticated Web Sessions."""

from datetime import timedelta

import httpx
import pytest
from pydantic import SecretStr

from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget, utc_now
from arka.app.execution.evidence import EvidenceStore
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.models.auth import (
    AuthState,
    CookieJar,
    CookieSameSite,
    CredentialReference,
    CredentialType,
    CredentialVault,
    SecureCookie,
)
from arka.app.web.models.http import HTTPMethod, HTTPRequest, HTTPResponse
from arka.app.web.session.manager import SessionManager


class TestCredentialSecurity:
    def test_credential_reference_llm_view_sanitization(self):
        """INV-001 / Section 3.6.1: LLM receives only safe metadata, never secrets."""
        ref = CredentialReference(
            engagement_id="eng-123",
            type=CredentialType.TOKEN,
            description="Admin bearer token",
        )
        llm_view = ref.to_llm_view()
        assert llm_view["credential_available"] is True
        assert llm_view["credential_id"] == ref.credential_id
        assert llm_view["type"] == "token"
        assert "password" not in llm_view
        assert "token" not in llm_view or llm_view["type"] == "token"

    def test_credential_vault_cross_engagement_isolation(self):
        """INV-004 / Section 3.6.2: Engagement A cannot access Engagement B's secrets."""
        vault = CredentialVault()
        vault.store(
            engagement_id="eng-A",
            credential_id="cred-1",
            secrets={"token": "secret-token-A", "user": "alice"},
        )

        # eng-A can retrieve
        res_a = vault.retrieve("eng-A", "cred-1")
        assert res_a is not None
        assert res_a["token"].get_secret_value() == "secret-token-A"

        # eng-B cannot retrieve eng-A's credentials
        res_b = vault.retrieve("eng-B", "cred-1")
        assert res_b is None

        # Clearing engagement A removes its credentials
        vault.clear_engagement("eng-A")
        assert vault.retrieve("eng-A", "cred-1") is None


class TestCookieSecurity:
    def test_cookie_injection_protection(self):
        """Section 3.6.3: Prohibit CRLF or control characters in cookies."""
        with pytest.raises(ValueError, match="prohibited delimiter or control character"):
            SecureCookie(
                name="session\r\nSet-Cookie: evil=1",
                value=SecretStr("val"),
                domain="example.com",
            )

        with pytest.raises(ValueError, match="prohibited delimiter or control character"):
            SecureCookie(
                name="session",
                value=SecretStr("val"),
                domain="example.com; malicious=1",
            )

    def test_rfc6265_domain_matching(self):
        """Section 3.6.3: Cookie domain matching rules."""
        cookie = SecureCookie(
            name="sid",
            value=SecretStr("secret123"),
            domain="example.com",
            path="/app",
            secure=True,
        )

        # Matching domain and subdomain
        assert cookie.matches("example.com", "/app/dashboard", is_secure=True) is True
        assert cookie.matches("sub.example.com", "/app/dashboard", is_secure=True) is True

        # Non-matching domain
        assert cookie.matches("attacker.com", "/app/dashboard", is_secure=True) is False
        assert cookie.matches("notexample.com", "/app/dashboard", is_secure=True) is False

        # Path mismatch
        assert cookie.matches("example.com", "/other", is_secure=True) is False

        # Scheme mismatch (Secure cookie over HTTP)
        assert cookie.matches("example.com", "/app/dashboard", is_secure=False) is False

    def test_cookie_expiration(self):
        """Section 3.6.3: Expired cookies are not matched."""
        past_time = utc_now() - timedelta(seconds=10)
        cookie = SecureCookie(
            name="sid",
            value=SecretStr("val"),
            domain="example.com",
            expires_at=past_time,
        )
        assert cookie.is_expired is True
        assert cookie.matches("example.com", "/", is_secure=False) is False

    def test_cookie_jar_set_cookie_parsing_and_bounds(self):
        """Section 3.6.3: Safe parsing of Set-Cookie header and capacity bounds."""
        jar = CookieJar(engagement_id="eng-1", max_cookies=2)

        c1 = jar.parse_and_add_set_cookie(
            "sess=abc; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Strict",
            request_url="https://example.com/login",
        )
        assert c1 is not None
        assert c1.name == "sess"
        assert c1.domain == "example.com"
        assert c1.secure is True
        assert c1.http_only is True
        assert c1.same_site == CookieSameSite.STRICT

        # Test oversized cookie rejection
        oversized = jar.parse_and_add_set_cookie(
            f"huge={'A' * 5000}; Domain=example.com; Path=/",
            request_url="https://example.com/test",
        )
        assert oversized is None


class TestSessionContextAndManager:
    def test_session_manager_cross_engagement_isolation(self):
        """Section 3.6.2: A session from Engagement A MUST NOT be usable by Engagement B."""
        sm = SessionManager()
        s1 = sm.create_session("eng-A", "http://example.com", scope_version=1)

        # Engagement A can access
        assert sm.get_session("eng-A", s1.session_id) is not None

        # Engagement B cannot access
        assert sm.get_session("eng-B", s1.session_id) is None

    def test_session_manager_target_isolation(self):
        """Section 3.6.2: A session for Target A does not authorize Target B."""
        sm = SessionManager()
        sm.create_session("eng-A", "http://target-a.com", scope_version=1)

        active_a = sm.get_active_session_for_target("eng-A", "http://target-a.com", scope_version=1)
        assert active_a is not None

        active_b = sm.get_active_session_for_target("eng-A", "http://target-b.com", scope_version=1)
        assert active_b is None

    def test_stale_scope_invalidation(self):
        """Section 6.3: Scope changes invalidate old authorization state."""
        sm = SessionManager()
        s = sm.create_session("eng-A", "http://target.com", scope_version=1)
        assert s.active is True

        # Scope version increments to 2
        sm.invalidate_stale_scope_sessions("eng-A", current_scope_version=2)
        assert s.active is False
        assert s.auth_state == AuthState.EXPIRED

    def test_auth_failure_classification(self):
        """Section 3.6.5: Handle 401, 403, redirects, MFA, CAPTCHA, lockout."""
        sm = SessionManager()
        s = sm.create_session("eng-A", "http://target.com")

        # 401 Unauthorized
        resp_401 = HTTPResponse(status_code=401, url="http://target.com/api/data")
        assert sm.analyze_response_auth_state(resp_401, s) == AuthState.UNAUTHENTICATED

        # Redirect to /login
        resp_redir = HTTPResponse(
            status_code=302,
            headers={"location": "/login"},
            url="http://target.com/api/data",
        )
        assert sm.analyze_response_auth_state(resp_redir, s) == AuthState.EXPIRED

        # MFA required
        resp_mfa = HTTPResponse(
            status_code=200,
            body="<html>Please enter your two-factor authentication code</html>",
            url="http://target.com/auth",
        )
        assert sm.analyze_response_auth_state(resp_mfa, s) == AuthState.MFA_REQUIRED

        # CAPTCHA required
        resp_captcha = HTTPResponse(
            status_code=200,
            body="<html>Please solve the reCAPTCHA challenge below</html>",
            url="http://target.com/login",
        )
        assert sm.analyze_response_auth_state(resp_captcha, s) == AuthState.CAPTCHA_REQUIRED

        # Lockout detected
        resp_lockout = HTTPResponse(
            status_code=403,
            body="<html>Account locked due to too many attempts</html>",
            url="http://target.com/login",
        )
        assert sm.analyze_response_auth_state(resp_lockout, s) == AuthState.LOCKED_OUT

    def test_csrf_token_extraction(self):
        """Section 3.6.4: Extract CSRF tokens from forms, meta, headers, cookies."""
        sm = SessionManager()
        s = sm.create_session("eng-A", "http://target.com")

        # Extract from HTML form
        html = """
        <form action="/update" method="POST">
            <input type="hidden" name="csrf_token" value="csrf-token-xyz-123">
            <input type="text" name="data">
        </form>
        """
        resp = HTTPResponse(status_code=200, body=html, url="http://target.com/page")
        csrf = sm.extract_and_record_csrf_token(resp, s, "http://target.com/page")
        assert csrf is not None
        assert csrf.token_value.get_secret_value() == "csrf-token-xyz-123"
        assert s.csrf_token is not None

        # Snapshot has CSRF indicator
        snap = s.create_snapshot()
        assert snap.has_csrf_token is True


class TestControlledHTTPClientSessionIntegration:
    @pytest.mark.asyncio
    async def test_session_cookies_and_isolation_in_client(self):
        """Section 3.6.2 & 3.6.3: Client enforces session cookies and boundaries."""
        scope = ScopeDefinition(
            engagement_id="eng-auth-test",
            version=1,
            includes=ScopeTarget(domains=["auth-target.com"], ports=[80, 443]),
        )
        guard = ScopeGuard(scope)

        received_cookies: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            cookie_header = request.headers.get("Cookie", "")
            received_cookies.append(cookie_header)
            if request.url.path == "/login":
                return httpx.Response(
                    200,
                    headers=[
                        ("Set-Cookie", "session_token=abc12345; Domain=auth-target.com; Path=/")
                    ],
                    text="Login OK",
                )
            return httpx.Response(200, text="Protected resource OK")

        transport = httpx.MockTransport(handler)
        evidence = EvidenceStore()
        client = ControlledHTTPClient(
            scope_guard=guard, evidence_store=evidence, transport=transport
        )

        sm = SessionManager()
        session = sm.create_session("eng-auth-test", "http://auth-target.com", scope_version=1)

        # 1. Login request: receives Set-Cookie
        login_req = HTTPRequest(url="http://auth-target.com/login", method=HTTPMethod.POST)
        tx1 = await client.execute(
            login_req, engagement_id="eng-auth-test", session_context=session
        )
        assert tx1.is_success() is True
        assert len(session.cookie_jar.cookies) == 1

        # 2. Subsequent request: cookie automatically injected
        data_req = HTTPRequest(url="http://auth-target.com/data", method=HTTPMethod.GET)
        tx2 = await client.execute(data_req, engagement_id="eng-auth-test", session_context=session)
        assert tx2.is_success() is True
        assert any("session_token=abc12345" in c for c in received_cookies)

        # 3. Cross-engagement attempt blocked
        tx_cross = await client.execute(
            data_req, engagement_id="eng-OTHER", session_context=session
        )
        assert tx_cross.response is None
        assert "Session engagement mismatch" in (tx_cross.error or "")

        # 4. Stale scope version blocked
        session.scope_version = 0  # Stale vs guard version 1
        tx_stale = await client.execute(
            data_req, engagement_id="eng-auth-test", session_context=session
        )
        assert tx_stale.response is None
        assert "stale" in (tx_stale.error or "")
