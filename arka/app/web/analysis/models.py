"""Domain models for Phase 3.7 Web/API Security Analysis Engine.

Defines:
- SecurityObservation
- SecurityHypothesis
- SecurityTest
- SecurityFinding
- FindingEvidence
Strictly enforces:
1. Invariant INV-001 / INV-005: LLM has zero authority to declare findings validated.
2. Authoritative evidence binding: every finding must cite immutable SHA-256 digests.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from arka.app.core.state.models import RiskLevel, new_id, utc_now
from arka.app.web.models.http import HTTPMethod


class SecurityObservationType(str, Enum):
    """Categories of deterministic observations extracted from web/API traffic."""

    MISSING_SECURITY_HEADER = "missing_security_header"
    INSECURE_COOKIE_ATTRIBUTE = "insecure_cookie_attribute"
    PERMISSIVE_CORS = "permissive_cors"
    CORS_ORIGIN_REFLECTION = "cors_origin_reflection"
    UNEXPECTED_HTTP_METHOD = "unexpected_http_method"
    INFORMATION_DISCLOSURE = "information_disclosure"
    STACK_TRACE_LEAK = "stack_trace_leak"
    CACHEABLE_SENSITIVE_RESPONSE = "cacheable_sensitive_response"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    UNDOCUMENTED_ENDPOINT = "undocumented_endpoint"
    UNDOCUMENTED_PARAMETER = "undocumented_parameter"
    AUTH_REQUIREMENT_MISSING = "auth_requirement_missing"
    SCHEMA_DISCREPANCY = "schema_discrepancy"
    CSRF_PROTECTION_MISSING = "csrf_protection_missing"


class FindingValidationStatus(str, Enum):
    """Authoritative lifecycle status for security findings."""

    OBSERVED = "observed"
    SUSPECTED = "suspected"
    VALIDATING = "validating"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"


class SecurityObservation(BaseModel):
    """An empirical observation discovered during web scanning, crawling, or schema analysis."""

    model_config = ConfigDict(frozen=True)

    observation_id: str = Field(default_factory=new_id)
    engagement_id: str = Field(..., min_length=1)
    target_url: str = Field(..., min_length=1)
    observation_type: SecurityObservationType
    title: str = Field(..., min_length=1)
    description: str = Field(default="")
    evidence_data: dict[str, Any] = Field(default_factory=dict)
    observed_headers: dict[str, str] = Field(default_factory=dict)
    observed_status: int | None = None
    observed_at: datetime = Field(default_factory=utc_now)


class SecurityHypothesis(BaseModel):
    """A deterministic deduction that a potential vulnerability exists based on observations."""

    model_config = ConfigDict(frozen=True)

    hypothesis_id: str = Field(default_factory=new_id)
    engagement_id: str = Field(..., min_length=1)
    observation_ids: list[str] = Field(default_factory=list)
    vulnerability_type: str = Field(..., min_length=1)
    target_url: str = Field(..., min_length=1)
    reasoning: str = Field(..., min_length=1)
    suggested_safe_probe: str | None = None
    risk_level: RiskLevel = Field(default=RiskLevel.LOW)
    created_at: datetime = Field(default_factory=utc_now)


class SecurityTest(BaseModel):
    """A bounded, non-destructive probe specification to verify a security hypothesis."""

    model_config = ConfigDict(frozen=True)

    test_id: str = Field(default_factory=new_id)
    hypothesis_id: str = Field(..., min_length=1)
    engagement_id: str = Field(..., min_length=1)
    target_url: str = Field(..., min_length=1)
    probe_method: HTTPMethod = Field(default=HTTPMethod.GET)
    probe_headers: dict[str, str] = Field(default_factory=dict)
    probe_body: str | None = None
    validation_rule: str = Field(
        ..., description="Deterministic assertion rule name that verifies vulnerability"
    )
    is_safe: bool = Field(default=True, description="Strictly non-destructive")
    max_requests: int = Field(default=3, ge=1, le=5)
    created_at: datetime = Field(default_factory=utc_now)


class FindingEvidence(BaseModel):
    """Cryptographic provenance linking a finding to immutable evidence records."""

    model_config = ConfigDict(frozen=True)

    evidence_id: str = Field(default_factory=new_id)
    finding_id: str = Field(..., min_length=1)
    execution_id: str = Field(default="")
    request_id: str = Field(default="")
    tool_name: str = Field(default="web_security_analyzer")
    content_hash: str = Field(..., min_length=64, max_length=64, description="SHA-256 digest")
    description: str = Field(default="")
    timestamp: datetime = Field(default_factory=utc_now)


class SecurityFinding(BaseModel):
    """Authoritative, evidence-backed security finding."""

    finding_id: str = Field(default_factory=new_id)
    engagement_id: str = Field(..., min_length=1)
    hypothesis_id: str | None = None
    title: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    severity: RiskLevel = Field(default=RiskLevel.LOW)
    evidence_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Deterministic confidence derived purely from empirical evidence",
    )
    llm_suggested_priority: str | None = Field(
        default=None, description="Non-authoritative LLM suggestion for analyst triage"
    )
    target_url: str = Field(..., min_length=1)
    cwe_id: str | None = None
    check_type: Any | None = None
    remediation: str = Field(default="")
    status: FindingValidationStatus = Field(default=FindingValidationStatus.SUSPECTED)
    evidence_refs: list[str] = Field(default_factory=list)
    cryptographic_evidence: list[FindingEvidence] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def mark_validated(self, evidence: FindingEvidence) -> None:
        """Authoritatively mark finding as validated with cryptographic evidence."""
        self.status = FindingValidationStatus.VALIDATED
        self.evidence_confidence = 1.0
        self.cryptographic_evidence.append(evidence)
        if evidence.content_hash not in self.evidence_refs:
            self.evidence_refs.append(evidence.content_hash)
        self.updated_at = utc_now()

    def mark_false_positive(self, reason: str = "") -> None:
        """Mark as false positive when safe verification fails."""
        self.status = FindingValidationStatus.FALSE_POSITIVE
        self.evidence_confidence = 0.0
        self.updated_at = utc_now()
