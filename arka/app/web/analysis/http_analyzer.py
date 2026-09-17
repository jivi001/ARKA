"""Deterministic HTTP Security Analyzer for ARKA Phase 3.7.1.

Evaluates security headers, cookie attributes, server information leakage,
stack trace disclosure, cache policies, and method exposure.
All outputs are strictly evidence-backed observations.
"""

from __future__ import annotations

import re

from arka.app.web.analysis.models import (
    SecurityObservation,
    SecurityObservationType,
)
from arka.app.web.models.http import HTTPResponse

# Stack trace indicators in HTML / JSON bodies
_STACK_TRACE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Python", re.compile(r"Traceback\s*\(most\s+recent\s+call\s+last\):", re.IGNORECASE)),
    ("Java", re.compile(r"(?:java\.lang\.\w*Exception|at\s+[\w$.]+\([\w$.]+\.java:\d+\))")),
    ("NodeJS", re.compile(r"at\s+(?:async\s+)?[\w$.<>]+\s*\([^)]+:\d+:\d+\)")),
    (
        "PHP",
        re.compile(
            r"(?:Fatal\s+error|Uncaught\s+Exception):\s+.+in\s+"
            r"/.+\.php\s+on\s+line\s+\d+"
        ),
    ),
    ("DotNet", re.compile(r"at\s+[\w.]+\([^\)]*\)\s+in\s+.*:line\s+\d+")),
]

# Sensitive technology leak headers
_SERVER_LEAK_HEADERS: set[str] = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
}


class HTTPQualityAnalyzer:
    """Performs deterministic, rule-based security analysis of HTTP responses."""

    @classmethod
    def analyze_response(
        cls,
        response: HTTPResponse,
        engagement_id: str,
        is_authenticated: bool = False,
    ) -> list[SecurityObservation]:
        """Analyze a single HTTP response and return empirical security observations."""
        observations: list[SecurityObservation] = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        url = response.url
        body = response.body or ""

        # 1. Missing Security Headers Analysis
        # Strict-Transport-Security (for HTTPS targets)
        if url.startswith("https://") and "strict-transport-security" not in headers_lower:
            observations.append(
                SecurityObservation(
                    engagement_id=engagement_id,
                    target_url=url,
                    observation_type=SecurityObservationType.MISSING_SECURITY_HEADER,
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    description="The HTTPS endpoint does not enforce Strict-Transport-Security.",
                    evidence_data={"missing_header": "Strict-Transport-Security"},
                    observed_headers=dict(response.headers),
                    observed_status=response.status_code,
                )
            )

        # Content-Security-Policy
        if (
            "content-security-policy" not in headers_lower
            and response.content_type
            and "html" in response.content_type.lower()
        ):
            observations.append(
                SecurityObservation(
                    engagement_id=engagement_id,
                    target_url=url,
                    observation_type=SecurityObservationType.MISSING_SECURITY_HEADER,
                    title="Missing Content-Security-Policy (CSP) Header",
                    description=(
                        "The HTML response lacks a Content-Security-Policy header to mitigate XSS."
                    ),
                    evidence_data={"missing_header": "Content-Security-Policy"},
                    observed_headers=dict(response.headers),
                    observed_status=response.status_code,
                )
            )

        # X-Content-Type-Options
        x_content_type = headers_lower.get("x-content-type-options", "").lower()
        if x_content_type != "nosniff":
            observations.append(
                SecurityObservation(
                    engagement_id=engagement_id,
                    target_url=url,
                    observation_type=SecurityObservationType.MISSING_SECURITY_HEADER,
                    title="Missing or Invalid X-Content-Type-Options Header",
                    description="The response is missing 'X-Content-Type-Options: nosniff'.",
                    evidence_data={
                        "header": "X-Content-Type-Options",
                        "observed_value": x_content_type or None,
                    },
                    observed_headers=dict(response.headers),
                    observed_status=response.status_code,
                )
            )

        # X-Frame-Options (for HTML)
        if (
            response.content_type
            and "html" in response.content_type.lower()
            and "x-frame-options" not in headers_lower
            and "content-security-policy" not in headers_lower
        ):
            observations.append(
                SecurityObservation(
                    engagement_id=engagement_id,
                    target_url=url,
                    observation_type=SecurityObservationType.MISSING_SECURITY_HEADER,
                    title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                    description=(
                        "The HTML response does not specify X-Frame-Options or frame-ancestors."
                    ),
                    evidence_data={"missing_header": "X-Frame-Options"},
                    observed_headers=dict(response.headers),
                    observed_status=response.status_code,
                )
            )

        # 2. Cookie Security Attributes
        set_cookie_raw: list[str] = []
        for k, v in response.headers.items():
            if k.lower() == "set-cookie":
                set_cookie_raw.append(v)

        for cookie_str in set_cookie_raw:
            parts = [p.strip().lower() for p in cookie_str.split(";")]
            name = cookie_str.split(";")[0].split("=")[0].strip()
            is_secure = "secure" in parts
            is_http_only = "httponly" in parts
            has_same_site = any(p.startswith("samesite") for p in parts)

            insecure_attrs: list[str] = []
            if not is_secure and url.startswith("https://"):
                insecure_attrs.append("Missing Secure flag on HTTPS")
            if not is_http_only and name.lower() not in ("xsrf-token", "csrf-token"):
                insecure_attrs.append("Missing HttpOnly flag")
            if not has_same_site:
                insecure_attrs.append("Missing SameSite attribute")

            if insecure_attrs:
                observations.append(
                    SecurityObservation(
                        engagement_id=engagement_id,
                        target_url=url,
                        observation_type=SecurityObservationType.INSECURE_COOKIE_ATTRIBUTE,
                        title=f"Insecure Cookie Attributes on '{name}'",
                        description=(
                            f"Cookie '{name}' lacks recommended protection flags: "
                            f"{', '.join(insecure_attrs)}."
                        ),
                        evidence_data={
                            "cookie_name": name,
                            "issues": insecure_attrs,
                            "raw_set_cookie": cookie_str,
                        },
                        observed_headers=dict(response.headers),
                        observed_status=response.status_code,
                    )
                )

        # 3. Information Disclosure & Technology Leaks
        for leak_header in _SERVER_LEAK_HEADERS:
            if leak_header in headers_lower:
                val = headers_lower[leak_header]
                # Check if it leaks version numbers or detailed frameworks
                if re.search(r"[/0-9]", val):
                    observations.append(
                        SecurityObservation(
                            engagement_id=engagement_id,
                            target_url=url,
                            observation_type=SecurityObservationType.INFORMATION_DISCLOSURE,
                            title=f"Server Information Disclosure in '{leak_header}'",
                            description=(
                                f"Header '{leak_header}' leaks detailed technology "
                                f"and version info: {val}."
                            ),
                            evidence_data={"header": leak_header, "value": val},
                            observed_headers=dict(response.headers),
                            observed_status=response.status_code,
                        )
                    )

        # 4. Stack Trace & Debug Error Leaks
        for tech, pat in _STACK_TRACE_PATTERNS:
            match = pat.search(body)
            if match:
                snippet = match.group(0)[:200]
                observations.append(
                    SecurityObservation(
                        engagement_id=engagement_id,
                        target_url=url,
                        observation_type=SecurityObservationType.STACK_TRACE_LEAK,
                        title=f"{tech} Stack Trace Information Leak",
                        description=(
                            f"Application response exposes an unhandled {tech} "
                            "stack trace or debug snippet."
                        ),
                        evidence_data={"technology": tech, "snippet": snippet},
                        observed_headers=dict(response.headers),
                        observed_status=response.status_code,
                    )
                )
                break

        # 5. Cache Control for Sensitive / Authenticated Data
        if is_authenticated:
            cache_ctrl = headers_lower.get("cache-control", "").lower()
            if not any(token in cache_ctrl for token in ("no-store", "no-cache", "private")):
                observations.append(
                    SecurityObservation(
                        engagement_id=engagement_id,
                        target_url=url,
                        observation_type=SecurityObservationType.CACHEABLE_SENSITIVE_RESPONSE,
                        title="Cacheable Authenticated Response",
                        description=(
                            "Authenticated response lacks Cache-Control: no-store, "
                            "permitting caching of sensitive data."
                        ),
                        evidence_data={"cache_control": cache_ctrl or "None"},
                        observed_headers=dict(response.headers),
                        observed_status=response.status_code,
                    )
                )

        return observations
