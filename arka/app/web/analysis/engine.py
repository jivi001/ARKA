"""Deterministic Web & API Security Analysis Engine for ARKA Phase 3.7.

Implements the authoritative validation pipeline:
Observation
 ↓
Hypothesis
 ↓
Deterministic Validation Rule
 ↓
Candidate Safe Probe
 ↓
ScopeGuard & PolicyEngine
 ↓
Approval if required
 ↓
Execution & Cryptographic Evidence
 ↓
Validated Finding / False Positive
"""

from __future__ import annotations

from arka.app.core.state.models import RiskLevel
from arka.app.execution.evidence import EvidenceStore
from arka.app.observability.logging import get_logger
from arka.app.web.analysis.api_analyzer import APIQualityAnalyzer
from arka.app.web.analysis.cors_analyzer import (
    CANARY_TEST_ORIGIN,
    CORSAnalyzer,
)
from arka.app.web.analysis.http_analyzer import HTTPQualityAnalyzer
from arka.app.web.analysis.models import (
    FindingEvidence,
    FindingValidationStatus,
    SecurityFinding,
    SecurityHypothesis,
    SecurityObservation,
    SecurityObservationType,
    SecurityTest,
)
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.models.http import HTTPMethod, HTTPRequest, HTTPResponse

logger = get_logger(__name__)


class WebSecurityAnalysisEngine:
    """Deterministic orchestrator for web and API vulnerability analysis and safe verification."""

    def __init__(
        self,
        http_client: ControlledHTTPClient,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        self.http_client = http_client
        self.evidence_store = evidence_store or EvidenceStore()
        self.http_analyzer = HTTPQualityAnalyzer()
        self.cors_analyzer = CORSAnalyzer()
        self.api_analyzer = APIQualityAnalyzer()

    def analyze_http_traffic(
        self,
        response: HTTPResponse,
        engagement_id: str,
        is_authenticated: bool = False,
    ) -> list[SecurityObservation]:
        """Run all passive observation analyzers over an HTTP response."""
        observations: list[SecurityObservation] = []
        observations.extend(
            self.http_analyzer.analyze_response(response, engagement_id, is_authenticated)
        )
        observations.extend(self.cors_analyzer.analyze_cors_response(response, None, engagement_id))
        observations.extend(
            self.api_analyzer.analyze_response_for_data_exposure(response, engagement_id)
        )
        return observations

    def derive_hypotheses(
        self,
        observations: list[SecurityObservation],
        engagement_id: str,
    ) -> list[SecurityHypothesis]:
        """Deterministically map empirical observations to testable security hypotheses."""
        hypotheses: list[SecurityHypothesis] = []

        for obs in observations:
            if obs.observation_type == SecurityObservationType.CORS_ORIGIN_REFLECTION:
                hypotheses.append(
                    SecurityHypothesis(
                        engagement_id=engagement_id,
                        observation_ids=[obs.observation_id],
                        vulnerability_type="CORS_ORIGIN_REFLECTION",
                        target_url=obs.target_url,
                        reasoning=obs.description,
                        suggested_safe_probe="Probe CORS with benign canary Origin header",
                        risk_level=RiskLevel.HIGH
                        if obs.evidence_data.get("allows_credentials")
                        else RiskLevel.MEDIUM,
                    )
                )
            elif obs.observation_type == SecurityObservationType.EXCESSIVE_DATA_EXPOSURE:
                hypotheses.append(
                    SecurityHypothesis(
                        engagement_id=engagement_id,
                        observation_ids=[obs.observation_id],
                        vulnerability_type="API_EXCESSIVE_DATA_EXPOSURE",
                        target_url=obs.target_url,
                        reasoning=obs.description,
                        risk_level=RiskLevel.HIGH,
                    )
                )
            elif obs.observation_type == SecurityObservationType.STACK_TRACE_LEAK:
                hypotheses.append(
                    SecurityHypothesis(
                        engagement_id=engagement_id,
                        observation_ids=[obs.observation_id],
                        vulnerability_type="INFORMATION_DISCLOSURE_STACK_TRACE",
                        target_url=obs.target_url,
                        reasoning=obs.description,
                        risk_level=RiskLevel.MEDIUM,
                    )
                )
            elif obs.observation_type == SecurityObservationType.MISSING_SECURITY_HEADER:
                hypotheses.append(
                    SecurityHypothesis(
                        engagement_id=engagement_id,
                        observation_ids=[obs.observation_id],
                        vulnerability_type="INSECURE_HTTP_SECURITY_HEADERS",
                        target_url=obs.target_url,
                        reasoning=obs.description,
                        risk_level=RiskLevel.LOW,
                    )
                )
            elif obs.observation_type == SecurityObservationType.INSECURE_COOKIE_ATTRIBUTE:
                hypotheses.append(
                    SecurityHypothesis(
                        engagement_id=engagement_id,
                        observation_ids=[obs.observation_id],
                        vulnerability_type="INSECURE_COOKIE_CONFIGURATION",
                        target_url=obs.target_url,
                        reasoning=obs.description,
                        risk_level=RiskLevel.MEDIUM,
                    )
                )

        return hypotheses

    def generate_safe_test(
        self,
        hypothesis: SecurityHypothesis,
    ) -> SecurityTest | None:
        """Create a bounded, deterministic, non-destructive probe to test a hypothesis."""
        if hypothesis.vulnerability_type == "CORS_ORIGIN_REFLECTION":
            return SecurityTest(
                hypothesis_id=hypothesis.hypothesis_id,
                engagement_id=hypothesis.engagement_id,
                target_url=hypothesis.target_url,
                probe_method=HTTPMethod.GET,
                probe_headers={"Origin": CANARY_TEST_ORIGIN},
                validation_rule="verify_cors_canary_reflection",
                is_safe=True,
                max_requests=1,
            )

        if hypothesis.vulnerability_type == "INSECURE_HTTP_SECURITY_HEADERS":
            return SecurityTest(
                hypothesis_id=hypothesis.hypothesis_id,
                engagement_id=hypothesis.engagement_id,
                target_url=hypothesis.target_url,
                probe_method=HTTPMethod.GET,
                validation_rule="verify_missing_headers",
                is_safe=True,
                max_requests=1,
            )

        return None

    async def execute_safe_test(
        self,
        test: SecurityTest,
        hypothesis: SecurityHypothesis,
        task_id: str = "",
    ) -> SecurityFinding:
        """Execute the safe probe through ControlledHTTPClient and authoritatively score finding."""
        probe_req = HTTPRequest(
            url=test.target_url,
            method=test.probe_method,
            headers=test.probe_headers,
            body=test.probe_body,
        )

        tx = await self.http_client.execute(
            probe_req,
            engagement_id=test.engagement_id,
            task_id=task_id,
        )

        finding = SecurityFinding(
            engagement_id=test.engagement_id,
            hypothesis_id=hypothesis.hypothesis_id,
            title=f"Validated: {hypothesis.vulnerability_type}",
            description=hypothesis.reasoning,
            severity=hypothesis.risk_level,
            target_url=test.target_url,
            status=FindingValidationStatus.SUSPECTED,
        )

        if not tx.response:
            finding.mark_false_positive(f"Probe execution failed: {tx.error}")
            return finding

        # Apply deterministic validation rule
        is_verified = False
        evidence_desc = ""

        if test.validation_rule == "verify_cors_canary_reflection":
            resp_headers_lower = {k.lower(): v.strip() for k, v in tx.response.headers.items()}
            allow_origin = resp_headers_lower.get("access-control-allow-origin")
            if allow_origin and (allow_origin == CANARY_TEST_ORIGIN or allow_origin.strip() == "*"):
                is_verified = True
                evidence_desc = (
                    f"Verified: Server responded with Access-Control-Allow-Origin: {allow_origin} "
                    f"to probe Origin: {CANARY_TEST_ORIGIN}"
                )

        elif test.validation_rule == "verify_missing_headers":
            resp_headers_lower = {k.lower(): v.strip() for k, v in tx.response.headers.items()}
            # If still missing critical headers on live probe, verified
            if "content-security-policy" not in resp_headers_lower:
                is_verified = True
                evidence_desc = "Verified: Content-Security-Policy remains absent on live probe"

        if is_verified and tx.evidence_ref:
            stored_ev = self.evidence_store.get_evidence(tx.evidence_ref)
            sha256 = stored_ev.sha256 if stored_ev else "0" * 64
            ev = FindingEvidence(
                finding_id=finding.finding_id,
                execution_id=task_id,
                request_id=test.target_url,
                content_hash=sha256,
                description=evidence_desc,
            )
            finding.mark_validated(ev)
            logger.info("Security finding deterministically validated", title=finding.title)
        else:
            finding.mark_false_positive("Deterministic verification rule criteria not satisfied")

        return finding
