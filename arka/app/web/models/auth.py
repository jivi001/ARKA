"""Authentication, session state, and identity-aware analysis models for ARKA Web Security.

Provides secure representation of authentication profiles, session contexts,
credential references, cookie jars, CSRF tokens, and session snapshots.
Strictly enforces:
1. Zero credential leakage to logs, audit, evidence metadata, or LLM prompts.
2. Cross-engagement and cross-target session isolation.
3. Scope version binding and fail-closed authentication failure handling.
"""

from __future__ import annotations

import contextlib
import urllib.parse
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from arka.app.core.state.models import new_id, utc_now
from arka.app.web.models.http import HTTPMethod, HTTPRequest


class AuthType(str, Enum):
    """Supported authentication schemes for web/API operations."""

    NONE = "none"
    BEARER = "bearer"
    BASIC = "basic"
    API_KEY = "api_key"
    COOKIE = "cookie"
    CUSTOM_HEADER = "custom_header"
    OAUTH2_TOKEN = "oauth2_token"
    FORM_LOGIN = "form_login"


class AuthState(str, Enum):
    """Authoritative lifecycle state of a web session."""

    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"
    EXPIRED = "expired"
    LOCKED_OUT = "locked_out"
    MFA_REQUIRED = "mfa_required"
    CAPTCHA_REQUIRED = "captcha_required"
    RATE_LIMITED = "rate_limited"
    FAILED = "failed"


class CredentialType(str, Enum):
    """Types of credentials tracked by reference."""

    TOKEN = "token"
    USERNAME_PASSWORD = "username_password"
    API_KEY = "api_key"
    SESSION_COOKIE = "session_cookie"
    CUSTOM = "custom"


class CredentialReference(BaseModel):
    """Non-sensitive pointer to a credential stored in the secure vault.

    INV-001 / Section 3.6.1: The LLM receives ONLY this reference with
    credential_available = True. Plaintext credentials are NEVER exposed.
    """

    model_config = ConfigDict(frozen=True)

    credential_id: str = Field(default_factory=new_id)
    engagement_id: str = Field(..., min_length=1)
    type: CredentialType = Field(default=CredentialType.TOKEN)
    description: str = Field(default="", description="Safe, non-secret description")
    created_at: datetime = Field(default_factory=utc_now)

    def to_llm_view(self) -> dict[str, Any]:
        """Expose a completely sanitized representation to LLM reasoning prompts."""
        return {
            "credential_id": self.credential_id,
            "credential_available": True,
            "type": self.type.value,
            "description": self.description,
        }


class CredentialVault:
    """In-memory isolated vault storing sensitive secrets indexed by engagement and credential ID.

    Enforces strict cross-engagement isolation: an engagement cannot access
    credentials belonging to a different engagement.
    """

    def __init__(self) -> None:
        self._vault: dict[tuple[str, str], dict[str, SecretStr]] = {}

    def store(
        self,
        engagement_id: str,
        credential_id: str,
        secrets: dict[str, SecretStr | str],
    ) -> None:
        """Store secrets securely converted to SecretStr."""
        normalized: dict[str, SecretStr] = {}
        for k, v in secrets.items():
            if isinstance(v, SecretStr):
                normalized[k] = v
            else:
                normalized[k] = SecretStr(str(v))
        self._vault[(engagement_id, credential_id)] = normalized

    def retrieve(self, engagement_id: str, credential_id: str) -> dict[str, SecretStr] | None:
        """Retrieve secrets strictly verifying engagement ownership."""
        return self._vault.get((engagement_id, credential_id))

    def remove(self, engagement_id: str, credential_id: str) -> None:
        """Remove secrets from vault."""
        self._vault.pop((engagement_id, credential_id), None)

    def clear_engagement(self, engagement_id: str) -> None:
        """Purge all credentials for an engagement upon completion."""
        keys = [k for k in self._vault if k[0] == engagement_id]
        for k in keys:
            del self._vault[k]


class CookieSameSite(str, Enum):
    """SameSite cookie attribute values."""

    STRICT = "Strict"
    LAX = "Lax"
    NONE = "None"


class SecureCookie(BaseModel):
    """Immutable representation of a single HTTP cookie with strict security validation."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., min_length=1, max_length=256)
    value: SecretStr = Field(..., description="Encapsulated secret cookie value")
    domain: str = Field(..., min_length=1)
    path: str = Field(default="/")
    secure: bool = Field(default=False)
    http_only: bool = Field(default=False)
    same_site: CookieSameSite = Field(default=CookieSameSite.LAX)
    expires_at: datetime | None = Field(default=None)
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("name", "domain", "path")
    @classmethod
    def validate_no_control_chars(cls, v: str) -> str:
        """Prevent cookie injection attacks via CRLF or semicolons."""
        if any(c in v for c in ("\r", "\n", ";", "\x00")):
            raise ValueError("Cookie field contains prohibited delimiter or control character")
        return v.strip()

    @field_validator("path")
    @classmethod
    def ensure_leading_slash(cls, v: str) -> str:
        clean = v.strip()
        return clean if clean.startswith("/") else f"/{clean}"

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return utc_now() > self.expires_at

    def matches(self, target_host: str, target_path: str, is_secure: bool) -> bool:
        """Check if cookie applies to target host, path, and security scheme under RFC 6265."""
        if self.is_expired:
            return False

        # 1. Scheme security check
        if self.secure and not is_secure:
            return False

        # 2. Domain matching
        norm_target_host = target_host.strip().lower()
        norm_cookie_domain = self.domain.strip().lower().lstrip(".")

        if norm_target_host != norm_cookie_domain and not norm_target_host.endswith(
            f".{norm_cookie_domain}"
        ):
            return False

        # 3. Path matching: request path must start with cookie path
        norm_target_path = target_path if target_path.startswith("/") else f"/{target_path}"
        norm_cookie_path = self.path if self.path.endswith("/") else f"{self.path}/"
        return (
            norm_target_path == self.path
            or norm_target_path.startswith(norm_cookie_path)
            or self.path == "/"
        )

    def to_header_str(self) -> str:
        """Format cookie for outbound HTTP Cookie header."""
        return f"{self.name}={self.value.get_secret_value()}"

    def safe_repr(self) -> str:
        """Safe logging representation masking the value."""
        return (
            f"{self.name}=[REDACTED]; domain={self.domain}; path={self.path}; secure={self.secure}"
        )


class CookieJar(BaseModel):
    """Secure, bounded container for session cookies bound to an engagement."""

    engagement_id: str = Field(..., min_length=1)
    cookies: dict[str, SecureCookie] = Field(default_factory=dict)
    max_cookies: int = Field(default=100, ge=1, le=1000)

    def _make_key(self, domain: str, path: str, name: str) -> str:
        return f"{domain.strip().lower()}:{path.strip()}:{name.strip()}"

    def add_cookie(self, cookie: SecureCookie) -> None:
        """Add or overwrite a cookie respecting bounds and engagement."""
        key = self._make_key(cookie.domain, cookie.path, cookie.name)
        if len(self.cookies) >= self.max_cookies and key not in self.cookies:
            # Purge expired cookies first
            self.clear_expired()
            if len(self.cookies) >= self.max_cookies:
                # Drop oldest cookie
                oldest_key = min(self.cookies.keys(), key=lambda k: self.cookies[k].created_at)
                del self.cookies[oldest_key]
        self.cookies[key] = cookie

    def clear_expired(self) -> None:
        """Purge expired cookies."""
        expired_keys = [k for k, v in self.cookies.items() if v.is_expired]
        for k in expired_keys:
            del self.cookies[k]

    def get_matching_cookies(self, url: str) -> list[SecureCookie]:
        """Find active cookies matching the given URL."""
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        is_secure = parsed.scheme.lower() == "https"

        matching = []
        for cookie in list(self.cookies.values()):
            if cookie.matches(host, path, is_secure):
                matching.append(cookie)
        return matching

    def get_cookie_header(self, url: str) -> str | None:
        """Build the combined Cookie header string for a URL, or None if no cookies match."""
        matching = self.get_matching_cookies(url)
        if not matching:
            return None
        return "; ".join(c.to_header_str() for c in matching)

    def parse_and_add_set_cookie(
        self, set_cookie_str: str, request_url: str
    ) -> SecureCookie | None:
        """Parse a Set-Cookie header and add to jar if valid according to request URL."""
        if not set_cookie_str or not set_cookie_str.strip():
            return None

        parts = [p.strip() for p in set_cookie_str.split(";") if p.strip()]
        if not parts:
            return None

        # First part is name=value
        name_val = parts[0]
        if "=" not in name_val:
            return None
        name, val = name_val.split("=", 1)
        name = name.strip()
        val = val.strip()

        # Reject oversized values to prevent buffer/header exhaustion
        if len(name) > 256 or len(val) > 4096:
            return None

        parsed_req = urllib.parse.urlparse(request_url)
        req_host = (parsed_req.hostname or "").lower()

        domain = req_host
        path = "/"
        secure = False
        http_only = False
        same_site = CookieSameSite.LAX
        expires_at = None

        for attr in parts[1:]:
            attr_lower = attr.lower()
            if attr_lower == "secure":
                secure = True
            elif attr_lower == "httponly":
                http_only = True
            elif attr_lower.startswith("samesite="):
                s_val = attr.split("=", 1)[1].strip().capitalize()
                if s_val == "Strict":
                    same_site = CookieSameSite.STRICT
                elif s_val == "None":
                    same_site = CookieSameSite.NONE
                else:
                    same_site = CookieSameSite.LAX
            elif attr_lower.startswith("domain="):
                d_val = attr.split("=", 1)[1].strip().lower().lstrip(".")
                # RFC 6265: cookie domain must match or be parent of request host
                if req_host == d_val or req_host.endswith(f".{d_val}"):
                    domain = d_val
            elif attr_lower.startswith("path="):
                path = attr.split("=", 1)[1].strip() or "/"
            elif attr_lower.startswith("max-age="):
                with contextlib.suppress(ValueError):
                    seconds = int(attr.split("=", 1)[1].strip())
                    from datetime import timedelta

                    expires_at = utc_now() + timedelta(seconds=max(seconds, 0))

        try:
            cookie = SecureCookie(
                name=name,
                value=SecretStr(val),
                domain=domain,
                path=path,
                secure=secure,
                http_only=http_only,
                same_site=same_site,
                expires_at=expires_at,
            )
            self.add_cookie(cookie)
            return cookie
        except ValueError:
            return None


class CSRFToken(BaseModel):
    """Captured CSRF token with observation provenance."""

    model_config = ConfigDict(frozen=True)

    token_id: str = Field(default_factory=new_id)
    token_value: SecretStr = Field(..., description="Sensitive token value")
    param_name: str = Field(default="csrf_token")
    header_name: str = Field(default="X-CSRF-Token")
    source: str = Field(default="form", description="form, meta, header, or cookie")
    page_url: str = Field(default="")
    observed_at: datetime = Field(default_factory=utc_now)


class AuthenticationProfile(BaseModel):
    """Declared authentication specifications and parameters for an engagement target."""

    model_config = ConfigDict(frozen=True)

    profile_id: str = Field(default_factory=new_id)
    engagement_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    auth_type: AuthType = Field(default=AuthType.NONE)
    target_domain: str = Field(..., min_length=1)
    credential_ref: CredentialReference | None = Field(default=None)
    login_url: str | None = Field(default=None)
    login_method: HTTPMethod = Field(default=HTTPMethod.POST)
    login_payload_template: dict[str, str] = Field(default_factory=dict)
    token_header_name: str = Field(default="Authorization")
    token_prefix: str = Field(default="Bearer ")
    scope_version: int = Field(default=1, ge=1)
    created_at: datetime = Field(default_factory=utc_now)


class SessionSnapshot(BaseModel):
    """Immutable audit snapshot of session state at a point in time."""

    model_config = ConfigDict(frozen=True)

    snapshot_id: str = Field(default_factory=new_id)
    session_id: str = Field(..., min_length=1)
    engagement_id: str = Field(..., min_length=1)
    target: str = Field(...)
    auth_state: AuthState
    cookie_count: int = 0
    cookie_names: list[str] = Field(default_factory=list)
    has_csrf_token: bool = False
    scope_version: int = 1
    timestamp: datetime = Field(default_factory=utc_now)


class AuthenticationContext(BaseModel):
    """Secure authentication state container with redacted serialization."""

    model_config = ConfigDict(frozen=True)

    auth_type: AuthType = Field(default=AuthType.NONE)
    credentials: SecretStr | None = Field(default=None, description="Primary secret or token")
    header_name: str | None = Field(
        default=None, description="Header name for API_KEY or CUSTOM_HEADER"
    )
    headers: dict[str, SecretStr] = Field(
        default_factory=dict, description="Additional sensitive headers"
    )
    cookies: dict[str, SecretStr] = Field(
        default_factory=dict, description="Sensitive session cookies"
    )
    description: str = Field(default="", description="Safe contextual note for audit")

    def safe_headers_for_logging(self) -> dict[str, str]:
        """Return headers with all secret values redacted."""
        clean: dict[str, str] = {}
        for k in self.headers:
            clean[k] = "[REDACTED]"
        if self.auth_type == AuthType.BEARER:
            clean["Authorization"] = "Bearer [REDACTED]"
        elif self.auth_type == AuthType.BASIC:
            clean["Authorization"] = "Basic [REDACTED]"
        elif self.auth_type == AuthType.API_KEY and self.header_name:
            clean[self.header_name] = "[REDACTED]"
        return clean

    def attach_to_request(self, request: HTTPRequest) -> HTTPRequest:
        """Attach authentication headers and cookies to an outbound request securely."""
        merged_headers = dict(request.headers)

        if self.auth_type == AuthType.BEARER and self.credentials:
            merged_headers["Authorization"] = f"Bearer {self.credentials.get_secret_value()}"
        elif self.auth_type == AuthType.BASIC and self.credentials:
            merged_headers["Authorization"] = f"Basic {self.credentials.get_secret_value()}"
        elif (
            self.auth_type in (AuthType.API_KEY, AuthType.CUSTOM_HEADER)
            and self.header_name
            and self.credentials
        ):
            merged_headers[self.header_name] = self.credentials.get_secret_value()

        for k, v in self.headers.items():
            merged_headers[k] = v.get_secret_value()

        if self.cookies:
            cookie_strs = [f"{k}={v.get_secret_value()}" for k, v in self.cookies.items()]
            existing_cookie = merged_headers.get("Cookie", "")
            if existing_cookie:
                cookie_strs.insert(0, existing_cookie)
            merged_headers["Cookie"] = "; ".join(cookie_strs)

        req_dict = request.model_dump()
        req_dict["headers"] = merged_headers
        return HTTPRequest(**req_dict)


class SessionContext(BaseModel):
    """Session representation for correlated multi-request assessment."""

    session_id: str = Field(default_factory=new_id)
    engagement_id: str = Field(..., min_length=1)
    target: str = Field(default="", description="Bound target URL or domain")
    scope_version: int = Field(default=1, ge=1)
    auth_profile: AuthenticationProfile | None = Field(default=None)
    auth_state: AuthState = Field(default=AuthState.UNAUTHENTICATED)
    auth_context: AuthenticationContext = Field(default_factory=AuthenticationContext)
    cookie_jar: CookieJar = Field(default_factory=lambda: CookieJar(engagement_id="default"))
    csrf_token: CSRFToken | None = Field(default=None)
    active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def _ensure_cookie_jar(cls, data: Any) -> Any:
        if isinstance(data, dict):
            eng_id = data.get("engagement_id", "default")
            if not data.get("cookie_jar"):
                data["cookie_jar"] = CookieJar(engagement_id=eng_id)
        return data

    def create_snapshot(self) -> SessionSnapshot:
        """Create an immutable snapshot for auditing."""
        cookie_names = [c.name for c in self.cookie_jar.cookies.values()]
        return SessionSnapshot(
            session_id=self.session_id,
            engagement_id=self.engagement_id,
            target=self.target,
            auth_state=self.auth_state,
            cookie_count=len(cookie_names),
            cookie_names=cookie_names,
            has_csrf_token=self.csrf_token is not None,
            scope_version=self.scope_version,
            timestamp=utc_now(),
        )
