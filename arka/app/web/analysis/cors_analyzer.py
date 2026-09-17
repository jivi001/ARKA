"""Deterministic CORS Security Analyzer for ARKA Phase 3.7.2.

Safely tests:
- Wildcard origins (*).
- Origin reflection against benign test origins.
- Null origin allowance.
- Dangerous combination of reflected origin + Access-Control-Allow-Credentials: true.
Strictly non-destructive, normalized comparisons, zero reliance on server's claims.
"""

from __future__ import annotations

import urllib.parse

from arka.app.web.analysis.models import (
    SecurityObservation,
    SecurityObservationType,
)
from arka.app.web.models.http import HTTPResponse

CANARY_TEST_ORIGIN = "https://canary.arka-security.internal"
NULL_TEST_ORIGIN = "null"


def normalize_origin(raw_origin: str) -> str:
    """Normalize origin string to scheme://host[:port]."""
    clean = raw_origin.strip().lower()
    if clean == "null":
        return "null"
    parsed = urllib.parse.urlparse(clean)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or clean
    port = parsed.port
    if port and ((scheme == "http" and port != 80) or (scheme == "https" and port != 443)):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


class CORSAnalyzer:
    """Deterministic analyzer for Cross-Origin Resource Sharing (CORS) configurations."""

    @classmethod
    def analyze_cors(
        cls,
        response: HTTPResponse,
        engagement_id: str,
        sent_origin: str | None = None,
    ) -> list[SecurityObservation]:
        """Convenience method for CORS analysis."""
        origin = sent_origin
        if origin is None:
            ac_origin = response.headers.get("Access-Control-Allow-Origin") or response.headers.get(
                "access-control-allow-origin"
            )
            if ac_origin and ac_origin.strip() not in ("*", "null"):
                origin = ac_origin.strip()
        return cls.analyze_cors_response(response, origin, engagement_id)

    @classmethod
    def analyze_cors_response(
        cls,
        response: HTTPResponse,
        sent_origin: str | None,
        engagement_id: str,
    ) -> list[SecurityObservation]:
        """Analyze a response for CORS misconfigurations and security risks."""
        observations: list[SecurityObservation] = []
        headers_lower = {k.lower(): v.strip() for k, v in response.headers.items()}
        url = response.url

        allow_origin = headers_lower.get("access-control-allow-origin")
        if not allow_origin:
            return observations

        allow_credentials_str = headers_lower.get("access-control-allow-credentials", "").lower()
        allows_credentials = allow_credentials_str == "true"
        norm_allow_origin = normalize_origin(allow_origin)

        # 1. Check for origin reflection
        if sent_origin:
            norm_sent_origin = normalize_origin(sent_origin)
            if norm_allow_origin == norm_sent_origin:
                if allows_credentials:
                    # High risk: Arbitrary origin reflected with credentials enabled!
                    observations.append(
                        SecurityObservation(
                            engagement_id=engagement_id,
                            target_url=url,
                            observation_type=SecurityObservationType.CORS_ORIGIN_REFLECTION,
                            title="Arbitrary CORS Origin Reflection with Credentials",
                            description=(
                                f"Endpoint reflects arbitrary supplied Origin '{sent_origin}' in "
                                "Access-Control-Allow-Origin with credentials enabled."
                            ),
                            evidence_data={
                                "sent_origin": sent_origin,
                                "reflected_origin": allow_origin,
                                "allows_credentials": True,
                            },
                            observed_headers=dict(response.headers),
                            observed_status=response.status_code,
                        )
                    )
                else:
                    # Medium risk: Origin reflected without credentials
                    observations.append(
                        SecurityObservation(
                            engagement_id=engagement_id,
                            target_url=url,
                            observation_type=SecurityObservationType.CORS_ORIGIN_REFLECTION,
                            title="CORS Origin Reflection",
                            description=(
                                f"Endpoint reflects arbitrary Origin '{sent_origin}' "
                                "in Access-Control-Allow-Origin."
                            ),
                            evidence_data={
                                "sent_origin": sent_origin,
                                "reflected_origin": allow_origin,
                                "allows_credentials": False,
                            },
                            observed_headers=dict(response.headers),
                            observed_status=response.status_code,
                        )
                    )

        # 2. Check for null origin allowance
        if allow_origin.strip().lower() == "null":
            observations.append(
                SecurityObservation(
                    engagement_id=engagement_id,
                    target_url=url,
                    observation_type=SecurityObservationType.PERMISSIVE_CORS,
                    title="Permissive CORS Policy Allowing 'null' Origin",
                    description=(
                        "Endpoint explicitly allows 'null' Origin, which can be "
                        "exploited by sandboxed iframes."
                    ),
                    evidence_data={
                        "allow_origin": "null",
                        "allows_credentials": allows_credentials,
                    },
                    observed_headers=dict(response.headers),
                    observed_status=response.status_code,
                )
            )

        # 3. Wildcard origin on authenticated / sensitive responses
        if allow_origin.strip() == "*":
            observations.append(
                SecurityObservation(
                    engagement_id=engagement_id,
                    target_url=url,
                    observation_type=SecurityObservationType.PERMISSIVE_CORS,
                    title="Wildcard Access-Control-Allow-Origin (*)",
                    description=(
                        "Endpoint exposes a wildcard CORS origin header (*), "
                        "permitting public cross-origin access."
                    ),
                    evidence_data={
                        "allow_origin": "*",
                        "allows_credentials": allows_credentials,
                    },
                    observed_headers=dict(response.headers),
                    observed_status=response.status_code,
                )
            )

        return observations
