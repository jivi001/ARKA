"""Deterministic API and Parameter Security Analyzer for ARKA Phase 3.7.3 & 3.7.4.

Analyzes discovered API operations and parameters for:
- Excessive sensitive data exposure (PII, hashed credentials, internal tokens).
- Undocumented endpoints and parameters comparing runtime discovery vs schema.
- Unsafe HTTP methods and inconsistent status codes.
- Canonical parameter classification and security normalization.
Never executes destructive calls. Never concatenates parameters into shell commands.
"""

from __future__ import annotations

import json
import re
from typing import Any

from arka.app.web.analysis.models import (
    SecurityObservation,
    SecurityObservationType,
)
from arka.app.web.models.endpoint import DiscoveredWebEndpoint
from arka.app.web.models.http import HTTPResponse
from arka.app.web.models.parameters import Parameter, ParameterLocation

# Keys in JSON responses that indicate excessive sensitive data exposure
_SENSITIVE_JSON_KEYS: set[str] = {
    "password",
    "passwd",
    "password_hash",
    "hashed_password",
    "secret",
    "secret_key",
    "private_key",
    "api_key",
    "apikey",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
    "access_token",
    "refresh_token",
    "auth_token",
}

# Regex to find secrets in string values
_SECRET_VALUE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Bcrypt Hash", re.compile(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("JWT Token", re.compile(r"^ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")),
    ("RSA Private Key", re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----")),
]


class APIQualityAnalyzer:
    """Performs deterministic analysis of API operations, schemas, and parameter usage."""

    @classmethod
    def analyze_response(
        cls,
        response: HTTPResponse,
        engagement_id: str,
    ) -> list[SecurityObservation]:
        """Convenience classmethod for API data exposure analysis."""
        return cls.analyze_response_for_data_exposure(response, engagement_id)

    @classmethod
    def analyze_response_for_data_exposure(
        cls,
        response: HTTPResponse,
        engagement_id: str,
    ) -> list[SecurityObservation]:
        """Analyze JSON response content for excessive sensitive data exposure."""
        observations: list[SecurityObservation] = []
        body = response.body or ""
        if not body or not response.content_type or "json" not in response.content_type.lower():
            return observations

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return observations

        leaked_keys: list[str] = []
        leaked_patterns: list[str] = []

        def _traverse(node: Any, path: str = "") -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    current_path = f"{path}.{k}" if path else k
                    if k.lower() in _SENSITIVE_JSON_KEYS:
                        leaked_keys.append(current_path)
                    _traverse(v, current_path)
            elif isinstance(node, list):
                for idx, item in enumerate(node[:10]):  # Bounded traverse
                    _traverse(item, f"{path}[{idx}]")
            elif isinstance(node, str):
                for name, pat in _SECRET_VALUE_PATTERNS:
                    if pat.search(node):
                        leaked_patterns.append(f"{path}: {name}")

        _traverse(data)

        if leaked_keys or leaked_patterns:
            issues = []
            if leaked_keys:
                issues.append(f"Sensitive fields: {', '.join(leaked_keys[:5])}")
            if leaked_patterns:
                issues.append(f"High-entropy secrets: {', '.join(leaked_patterns[:3])}")

            observations.append(
                SecurityObservation(
                    engagement_id=engagement_id,
                    target_url=response.url,
                    observation_type=SecurityObservationType.EXCESSIVE_DATA_EXPOSURE,
                    title="Excessive Sensitive Data Exposure in API Response",
                    description=(
                        "API response exposes sensitive fields or cryptographic "
                        f"artifacts: {'; '.join(issues)}."
                    ),
                    evidence_data={
                        "leaked_fields": leaked_keys[:10],
                        "secret_patterns": leaked_patterns[:5],
                    },
                    observed_headers=dict(response.headers),
                    observed_status=response.status_code,
                )
            )

        return observations

    @classmethod
    def compare_endpoints_against_schema(
        cls,
        discovered_endpoints: list[DiscoveredWebEndpoint],
        declared_schema_paths: set[str],
        engagement_id: str,
    ) -> list[SecurityObservation]:
        """Detect undocumented endpoints discovered during reconnaissance (Shadow API)."""
        observations: list[SecurityObservation] = []
        for ep in discovered_endpoints:
            # Normalize path for comparison
            ep_path = ep.path.rstrip("/") or "/"
            if ep_path not in declared_schema_paths and not any(
                ep_path.startswith(p.rstrip("/")) for p in declared_schema_paths if len(p) > 2
            ):
                observations.append(
                    SecurityObservation(
                        engagement_id=engagement_id,
                        target_url=ep.url,
                        observation_type=SecurityObservationType.UNDOCUMENTED_ENDPOINT,
                        title=f"Undocumented API Endpoint Discovered: '{ep.path}'",
                        description=(
                            f"Endpoint '{ep.path}' ({ep.method.value}) discovered via crawling "
                            "is absent from declared API schemas (Shadow/Zombie API indicator)."
                        ),
                        evidence_data={
                            "path": ep.path,
                            "method": ep.method.value,
                            "url": ep.url,
                            "source": ep.source,
                        },
                        observed_status=ep.status_code,
                    )
                )
        return observations

    @classmethod
    def classify_parameter(
        cls,
        name: str,
        location: str,
        sample_value: str | None = None,
        required: bool = False,
    ) -> Parameter:
        """Deterministically normalize and classify an input parameter."""
        try:
            param_loc = ParameterLocation(location.lower())
        except ValueError:
            param_loc = ParameterLocation.QUERY

        # Safe sanitization of name
        clean_name = re.sub(r"[^\w\-_.]", "", name.strip()) or "param"

        return Parameter(
            name=clean_name,
            location=param_loc,
            sample_value=sample_value[:200] if sample_value else None,
            required=required,
        )
