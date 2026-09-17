"""HTTP domain models for ARKA Web and API Security Subsystem.

Provides immutable, bounded, and strongly-typed models for HTTP requests,
responses, and transactions with sensitive header sanitization.
"""

from __future__ import annotations

import re
import urllib.parse
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from arka.app.core.state.models import new_id, utc_now

# Safety bounds
MAX_HEADERS_BYTES = 65_536  # 64 KB
MAX_BODY_BYTES = 5_242_880  # 5 MB
MAX_CAPTURED_BODY_BYTES = 2_097_152  # 2 MB
MAX_TIMEOUT_SECONDS = 60.0
MAX_REDIRECTS = 10

SENSITIVE_HEADER_KEYS: frozenset[str] = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "apikey",
        "api-key",
        "proxy-authorization",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "session",
        "token",
        "bearer",
        "secret",
    }
)


class HTTPMethod(str, Enum):
    """Standard HTTP methods supported by ARKA."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


def normalize_http_url(raw_url: str) -> tuple[str, str, int, str]:
    """Normalize a target URL.

    Returns:
        tuple[str, str, int, str]: (normalized_url, host, port, path)

    Raises:
        ValueError: If URL is empty, malformed, or has an invalid scheme.
    """
    clean_url = raw_url.strip()
    if not clean_url:
        raise ValueError("URL cannot be empty")

    if not clean_url.lower().startswith(("http://", "https://")):
        raise ValueError(f"Invalid URL scheme in '{clean_url}'. Only HTTP/HTTPS supported.")

    parsed = urllib.parse.urlparse(clean_url)
    scheme = (parsed.scheme or "http").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme '{scheme}'. Only http and https allowed.")

    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError(f"Could not extract valid hostname from '{clean_url}'")

    port = parsed.port or (443 if scheme == "https" else 80)

    # Normalize path: ensure leading slash, collapse multiple slashes, resolve '.' and '..'
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    path = re.sub(r"/+", "/", path)

    # Reconstruct normalized URL (standard port omitted, query preserved, fragment dropped)
    netloc = (
        host
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        else f"{host}:{port}"
    )
    query = parsed.query

    normalized_url = urllib.parse.urlunparse((scheme, netloc, path, "", query, ""))
    return normalized_url, host, port, path


class HTTPRequest(BaseModel):
    """Normalized, strongly-typed outbound HTTP request specification."""

    model_config = ConfigDict(frozen=True)

    method: HTTPMethod = Field(default=HTTPMethod.GET)
    url: str = Field(..., description="Target URL")
    headers: dict[str, str] = Field(default_factory=dict)
    query_parameters: dict[str, Any] = Field(default_factory=dict)
    path: str = Field(default="/")
    body: str | bytes | None = Field(default=None)
    content_type: str | None = Field(default=None)
    timeout: float = Field(default=10.0, ge=0.1, le=MAX_TIMEOUT_SECONDS)
    follow_redirects: bool = Field(default=False)
    max_redirects: int = Field(default=5, ge=0, le=MAX_REDIRECTS)

    @field_validator("method", mode="before")
    @classmethod
    def _validate_method(cls, v: Any) -> HTTPMethod:
        if isinstance(v, HTTPMethod):
            return v
        if isinstance(v, str):
            v_upper = v.strip().upper()
            try:
                return HTTPMethod(v_upper)
            except ValueError as err:
                raise ValueError(
                    f"Invalid HTTP method '{v}'. Must be one of {[m.value for m in HTTPMethod]}"
                ) from err
        raise ValueError(f"Invalid method type '{type(v)}'")

    @model_validator(mode="before")
    @classmethod
    def _validate_and_normalize(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        url_raw = data.get("url", "")
        norm_url, _host, _port, path = normalize_http_url(str(url_raw))
        data["url"] = norm_url
        if "path" not in data or not data["path"]:
            data["path"] = path

        # Validate headers size
        headers = data.get("headers") or {}
        header_bytes = sum(len(str(k)) + len(str(v)) for k, v in headers.items())
        if header_bytes > MAX_HEADERS_BYTES:
            raise ValueError(
                f"Request headers exceed maximum allowed size of {MAX_HEADERS_BYTES} bytes"
            )

        # Validate body size
        body = data.get("body")
        if body is not None:
            body_len = len(body) if isinstance(body, (bytes, str)) else len(str(body))
            if body_len > MAX_BODY_BYTES:
                raise ValueError(
                    f"Request body exceeds maximum allowed size of {MAX_BODY_BYTES} bytes"
                )

        return data

    def safe_headers_for_logging(self) -> dict[str, str]:
        """Return headers with credentials and sensitive values redacted."""
        clean: dict[str, str] = {}
        for k, v in self.headers.items():
            if k.lower() in SENSITIVE_HEADER_KEYS or any(
                s in k.lower() for s in ("token", "auth", "secret", "key")
            ):
                clean[k] = "[REDACTED]"
            else:
                clean[k] = v
        return clean


class HTTPResponse(BaseModel):
    """Normalized response data from an executed HTTP request."""

    model_config = ConfigDict(frozen=True)

    status_code: int = Field(..., ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", description="Captured response body text")
    raw_body_bytes: bytes | None = Field(default=None, repr=False)
    content_type: str = Field(default="")
    url: str = Field(..., description="Final URL after any redirects")
    elapsed_time_ms: float = Field(default=0.0, ge=0.0)
    redirect_chain: list[str] = Field(default_factory=list)
    truncated: bool = Field(default=False)

    def safe_headers_for_logging(self) -> dict[str, str]:
        """Return headers with sensitive cookies and auth credentials redacted."""
        clean: dict[str, str] = {}
        for k, v in self.headers.items():
            if k.lower() in SENSITIVE_HEADER_KEYS or any(
                s in k.lower() for s in ("token", "auth", "secret", "key")
            ):
                clean[k] = "[REDACTED]"
            else:
                clean[k] = v
        return clean

    def is_success(self) -> bool:
        """True if status code is in 200..299 range."""
        return 200 <= self.status_code <= 299

    def is_redirect(self) -> bool:
        """True if status code is in 300..399 range."""
        return 300 <= self.status_code <= 399

    def is_client_error(self) -> bool:
        """True if status code is in 400..499 range."""
        return 400 <= self.status_code <= 499

    def is_server_error(self) -> bool:
        """True if status code is in 500..599 range."""
        return 500 <= self.status_code <= 599


class HTTPTransaction(BaseModel):
    """Canonical observation unit for an outbound HTTP interaction."""

    model_config = ConfigDict(frozen=True)

    transaction_id: str = Field(default_factory=new_id)
    engagement_id: str = Field(..., min_length=1)
    task_id: str = Field(default="")
    request: HTTPRequest
    response: HTTPResponse | None = Field(default=None)
    error: str | None = Field(default=None)
    timestamp: datetime = Field(default_factory=utc_now)
    duration_ms: float = Field(default=0.0, ge=0.0)
    evidence_ref: str | None = Field(default=None)

    def is_success(self) -> bool:
        """True if the transaction completed with a successful HTTP response."""
        return self.response is not None and self.response.is_success()
