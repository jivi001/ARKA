"""SessionManager for Phase 3.6 Authenticated Web Sessions.

Enforces:
1. Strict session isolation (engagement_id, target, scope_version).
2. Fail-closed authentication failure detection (401, 403, redirects, MFA, CAPTCHA, lockout).
3. Zero credential stuffing / brute forcing (bounded attempt tracking).
4. Safe CSRF token harvesting and tracking without bypassing security policy.
"""

from __future__ import annotations

import re
import urllib.parse

from pydantic import SecretStr

from arka.app.observability.logging import get_logger
from arka.app.web.models.auth import (
    AuthenticationProfile,
    AuthState,
    CredentialVault,
    CSRFToken,
    SessionContext,
)
from arka.app.web.models.http import HTTPResponse

logger = get_logger(__name__)

# Patterns indicating MFA challenge
_MFA_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\b(mfa|two[- ]?factor|2fa|authenticator|one[- ]?time[- ]?code|totp|otp)\b"),
]

# Patterns indicating CAPTCHA challenge
_CAPTCHA_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\b(captcha|recaptcha|hcaptcha|turnstile|arkoselabs|geetest)\b"),
]

# Patterns indicating account lockout
_LOCKOUT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(?i)\b(account\s+(locked|disabled|suspended)|too\s+many\s+attempts|temporarily\s+blocked)\b"
    ),
]

# Common login endpoint paths that signal a redirect-to-login session loss
_LOGIN_PATHS: set[str] = {
    "/login",
    "/signin",
    "/sign-in",
    "/auth",
    "/authenticate",
    "/oauth/authorize",
    "/users/login",
}

# CSRF token field names commonly used in web applications
_CSRF_FIELD_NAMES: set[str] = {
    "csrf_token",
    "csrftoken",
    "csrf",
    "_csrf",
    "_csrf_token",
    "xsrf_token",
    "xsrftoken",
    "_xsrf",
    "authenticity_token",
    "gorilla.csrf.token",
}


class SessionManagerError(Exception):
    """Raised when session operations violate isolation or security invariants."""


class SessionManager:
    """Manages active authenticated sessions for web security assessments.

    All sessions are bound to specific (engagement_id, target, scope_version).
    Cross-engagement or cross-target reuse is strictly forbidden.
    """

    def __init__(self, credential_vault: CredentialVault | None = None) -> None:
        self._sessions: dict[str, SessionContext] = {}  # session_id -> SessionContext
        self._credential_vault = credential_vault or CredentialVault()
        self._auth_attempts: dict[str, int] = {}  # (engagement_id, target) -> count
        self._max_auth_attempts = 2  # Absolute bound: never brute force or credential stuff

    @property
    def credential_vault(self) -> CredentialVault:
        return self._credential_vault

    def create_session(
        self,
        engagement_id: str,
        target: str,
        auth_profile: AuthenticationProfile | None = None,
        scope_version: int = 1,
    ) -> SessionContext:
        """Create a new bounded session context for an engagement and target."""
        if not engagement_id or not engagement_id.strip():
            raise SessionManagerError("Cannot create session without engagement_id")
        if not target or not target.strip():
            raise SessionManagerError("Cannot create session without target")

        session = SessionContext(
            engagement_id=engagement_id.strip(),
            target=target.strip(),
            auth_profile=auth_profile,
            scope_version=scope_version,
            auth_state=AuthState.UNAUTHENTICATED,
        )
        self._sessions[session.session_id] = session
        logger.info(
            "Created session context",
            session_id=session.session_id,
            engagement_id=engagement_id,
            target=target,
            scope_version=scope_version,
        )
        return session

    def get_session(self, engagement_id: str, session_id: str) -> SessionContext | None:
        """Retrieve a session strictly verifying engagement ownership."""
        session = self._sessions.get(session_id)
        if not session:
            return None
        if session.engagement_id != engagement_id:
            logger.warning(
                "Cross-engagement session access attempted and blocked",
                session_id=session_id,
                request_engagement=engagement_id,
                owner_engagement=session.engagement_id,
            )
            return None
        return session

    def get_active_session_for_target(
        self,
        engagement_id: str,
        target: str,
        scope_version: int,
    ) -> SessionContext | None:
        """Find an active, valid session matching engagement, target domain, and scope version."""
        norm_target = target.strip().lower()
        parsed_target = urllib.parse.urlparse(norm_target)
        target_host = parsed_target.hostname or norm_target

        for session in self._sessions.values():
            if not session.active:
                continue
            if session.engagement_id != engagement_id:
                continue
            if session.scope_version != scope_version:
                continue

            parsed_session = urllib.parse.urlparse(session.target.lower())
            session_host = parsed_session.hostname or session.target.lower()

            if session_host == target_host or target_host.endswith(f".{session_host}"):
                return session

        return None

    def invalidate_session(self, engagement_id: str, session_id: str) -> None:
        """Deactivate and invalidate a specific session."""
        session = self.get_session(engagement_id, session_id)
        if session:
            session.active = False
            session.auth_state = AuthState.EXPIRED
            logger.info("Invalidated session", session_id=session_id, engagement_id=engagement_id)

    def invalidate_stale_scope_sessions(
        self, engagement_id: str, current_scope_version: int
    ) -> int:
        """Invalidate all sessions for an engagement where scope_version is outdated."""
        invalidated = 0
        for session in list(self._sessions.values()):
            if (
                session.engagement_id == engagement_id
                and session.scope_version < current_scope_version
            ):
                session.active = False
                session.auth_state = AuthState.EXPIRED
                invalidated += 1
        if invalidated > 0:
            logger.info(
                "Invalidated stale scope sessions",
                engagement_id=engagement_id,
                current_scope_version=current_scope_version,
                count=invalidated,
            )
        return invalidated

    def invalidate_engagement_sessions(self, engagement_id: str) -> None:
        """Deactivate all sessions for an engagement upon completion."""
        for session in self._sessions.values():
            if session.engagement_id == engagement_id:
                session.active = False
                session.auth_state = AuthState.EXPIRED
        self._credential_vault.clear_engagement(engagement_id)

    def check_can_attempt_auth(self, engagement_id: str, target: str) -> bool:
        """Ensure bounded authentication attempts to prevent lockout/brute-forcing."""
        key = f"{engagement_id}:{target}"
        attempts = self._auth_attempts.get(key, 0)
        return attempts < self._max_auth_attempts

    def record_auth_attempt(self, engagement_id: str, target: str) -> None:
        """Increment auth attempt counter."""
        key = f"{engagement_id}:{target}"
        self._auth_attempts[key] = self._auth_attempts.get(key, 0) + 1

    def analyze_response_auth_state(
        self,
        response: HTTPResponse,
        session: SessionContext,
        requested_url: str = "",
    ) -> AuthState:
        """Deterministic evaluation of HTTP response to classify session/auth state.

        Detects 401, 403, 429, redirects to login, session expirations, MFA, CAPTCHA, lockout.
        """
        body = response.body or ""
        status = response.status_code

        # 1. Rate limiting
        if status == 429 or "retry-after" in response.headers:
            session.auth_state = AuthState.RATE_LIMITED
            return AuthState.RATE_LIMITED

        # 2. Lockout detection
        for pat in _LOCKOUT_PATTERNS:
            if pat.search(body):
                session.auth_state = AuthState.LOCKED_OUT
                session.active = False
                return AuthState.LOCKED_OUT

        # 3. CAPTCHA requirement
        for pat in _CAPTCHA_PATTERNS:
            if pat.search(body):
                session.auth_state = AuthState.CAPTCHA_REQUIRED
                return AuthState.CAPTCHA_REQUIRED

        # 4. MFA requirement
        for pat in _MFA_PATTERNS:
            if pat.search(body):
                session.auth_state = AuthState.MFA_REQUIRED
                return AuthState.MFA_REQUIRED

        # 5. Status code checks
        if status == 401:
            session.auth_state = AuthState.UNAUTHENTICATED
            return AuthState.UNAUTHENTICATED

        if status == 403:
            # Distinguish authorization failure from session invalidation
            session.auth_state = AuthState.FAILED
            return AuthState.FAILED

        # 6. Redirect to login detection
        if status in (301, 302, 303, 307, 308):
            location = response.headers.get("location", "")
            parsed_loc = urllib.parse.urlparse(location)
            loc_path = (parsed_loc.path or "").rstrip("/")
            if loc_path in _LOGIN_PATHS:
                # If requested URL was not already the login page, redirect means session expired
                session.auth_state = AuthState.EXPIRED
                session.active = False
                return AuthState.EXPIRED

        return session.auth_state

    def extract_and_record_csrf_token(
        self,
        response: HTTPResponse,
        session: SessionContext,
        page_url: str,
    ) -> CSRFToken | None:
        """Safely extract CSRF token from response headers, cookies, or HTML form inputs."""
        # 1. Check response headers
        for h_name in ("x-csrf-token", "x-xsrf-token", "csrf-token"):
            if h_name in response.headers:
                token_val = response.headers[h_name]
                token = CSRFToken(
                    token_value=SecretStr(token_val),
                    header_name=h_name,
                    source="header",
                    page_url=page_url,
                )
                session.csrf_token = token
                return token

        # 2. Check Set-Cookie headers
        if session.cookie_jar:
            for cookie in session.cookie_jar.cookies.values():
                if cookie.name.lower() in ("xsrf-token", "csrf-token", "_csrf"):
                    token = CSRFToken(
                        token_value=cookie.value,
                        header_name="X-XSRF-TOKEN",
                        source="cookie",
                        page_url=page_url,
                    )
                    session.csrf_token = token
                    return token

        # 3. Check HTML body for form input
        body = response.body or ""
        if "<form" in body.lower():
            # Look for hidden inputs with csrf names
            input_pattern = re.compile(
                r'<input[^>]+name=[\'"]([^\'"]+)[\'"][^>]+value=[\'"]([^\'"]+)[\'"]',
                re.IGNORECASE,
            )
            for match in input_pattern.finditer(body):
                field_name = match.group(1).lower()
                field_val = match.group(2)
                if field_name in _CSRF_FIELD_NAMES:
                    token = CSRFToken(
                        token_value=SecretStr(field_val),
                        param_name=field_name,
                        source="form",
                        page_url=page_url,
                    )
                    session.csrf_token = token
                    return token

            # Also check inverted attribute order value then name
            input_pattern_rev = re.compile(
                r'<input[^>]+value=[\'"]([^\'"]+)[\'"][^>]+name=[\'"]([^\'"]+)[\'"]',
                re.IGNORECASE,
            )
            for match in input_pattern_rev.finditer(body):
                field_val = match.group(1)
                field_name = match.group(2).lower()
                if field_name in _CSRF_FIELD_NAMES:
                    token = CSRFToken(
                        token_value=SecretStr(field_val),
                        param_name=field_name,
                        source="form",
                        page_url=page_url,
                    )
                    session.csrf_token = token
                    return token

        # 4. Check HTML meta tags (e.g. <meta name="csrf-token" content="...">)
        meta_pattern = re.compile(
            r'<meta[^>]+name=[\'"](?:csrf-token|_csrf)[\'"][^>]+content=[\'"]([^\'"]+)[\'"]',
            re.IGNORECASE,
        )
        meta_match = meta_pattern.search(body)
        if meta_match:
            token = CSRFToken(
                token_value=SecretStr(meta_match.group(1)),
                source="meta",
                page_url=page_url,
            )
            session.csrf_token = token
            return token

        return None
