"""Unit tests for Phase 3.7 Web/API Security Analysis Engine."""

import httpx
import pytest

from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.execution.evidence import EvidenceStore
from arka.app.web.analysis.api_analyzer import APIQualityAnalyzer
from arka.app.web.analysis.cors_analyzer import (
    CORSAnalyzer,
)
from arka.app.web.analysis.engine import WebSecurityAnalysisEngine
from arka.app.web.analysis.http_analyzer import HTTPQualityAnalyzer
from arka.app.web.analysis.models import (
    FindingValidationStatus,
    SecurityObservationType,
)
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.models.endpoint import DiscoveredWebEndpoint
from arka.app.web.models.http import HTTPResponse
from arka.app.web.models.parameters import ParameterLocation


class TestHTTPQualityAnalyzer:
    def test_missing_security_headers(self):
        analyzer = HTTPQualityAnalyzer()
        resp = HTTPResponse(
            status_code=200,
            headers={"Server": "nginx"},
            content_type="text/html",
            url="https://example.com/index.html",
        )
        obs = analyzer.analyze_response(resp, engagement_id="eng-test")
        types = [o.observation_type for o in obs]

        assert SecurityObservationType.MISSING_SECURITY_HEADER in types
        assert any("Strict-Transport-Security" in o.title for o in obs)
        assert any("Content-Security-Policy" in o.title for o in obs)
        assert any("X-Content-Type-Options" in o.title for o in obs)

    def test_insecure_cookies(self):
        analyzer = HTTPQualityAnalyzer()
        resp = HTTPResponse(
            status_code=200,
            headers={"Set-Cookie": "sessionid=xyz123; Path=/"},
            url="https://example.com/app",
        )
        obs = analyzer.analyze_response(resp, engagement_id="eng-test")
        cookie_obs = [
            o
            for o in obs
            if o.observation_type == SecurityObservationType.INSECURE_COOKIE_ATTRIBUTE
        ]
        assert len(cookie_obs) == 1
        assert "sessionid" in cookie_obs[0].title
        assert "Missing Secure flag" in str(cookie_obs[0].evidence_data)
        assert "Missing HttpOnly flag" in str(cookie_obs[0].evidence_data)

    def test_stack_trace_and_server_leak(self):
        analyzer = HTTPQualityAnalyzer()
        resp = HTTPResponse(
            status_code=500,
            headers={"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"},
            body=(
                "Fatal error: Uncaught Exception: DB connection failed "
                "in /var/www/db.php on line 42"
            ),
            url="http://example.com/api/error",
        )
        obs = analyzer.analyze_response(resp, engagement_id="eng-test")
        types = [o.observation_type for o in obs]
        assert SecurityObservationType.INFORMATION_DISCLOSURE in types
        assert SecurityObservationType.STACK_TRACE_LEAK in types
        assert any("PHP Stack Trace" in o.title for o in obs)


class TestCORSAnalyzer:
    def test_cors_origin_reflection_with_credentials(self):
        analyzer = CORSAnalyzer()
        resp = HTTPResponse(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "https://attacker.example.com",
                "Access-Control-Allow-Credentials": "true",
            },
            url="http://example.com/api/user",
        )
        obs = analyzer.analyze_cors_response(
            resp, sent_origin="https://attacker.example.com", engagement_id="eng-test"
        )
        assert len(obs) == 1
        assert obs[0].observation_type == SecurityObservationType.CORS_ORIGIN_REFLECTION
        assert "Credentials" in obs[0].title

    def test_cors_wildcard_origin(self):
        analyzer = CORSAnalyzer()
        resp = HTTPResponse(
            status_code=200,
            headers={"Access-Control-Allow-Origin": "*"},
            url="http://example.com/api/items",
        )
        obs = analyzer.analyze_cors_response(resp, sent_origin=None, engagement_id="eng-test")
        assert any(o.observation_type == SecurityObservationType.PERMISSIVE_CORS for o in obs)


class TestAPIQualityAnalyzer:
    def test_excessive_data_exposure(self):
        analyzer = APIQualityAnalyzer()
        resp = HTTPResponse(
            status_code=200,
            content_type="application/json",
            body=(
                '{"user": "alice", "password_hash": '
                '"$2a$12$e8N4Y9Kx9g8d.8nQ7k2u8e8N4Y9Kx9g8d.8nQ7k2u8e8N4Y9Kx9g8", '
                '"ssn": "000-12-3456"}'
            ),
            url="http://example.com/api/profile",
        )
        obs = analyzer.analyze_response_for_data_exposure(resp, engagement_id="eng-test")
        assert len(obs) == 1
        assert obs[0].observation_type == SecurityObservationType.EXCESSIVE_DATA_EXPOSURE
        assert "password_hash" in str(obs[0].evidence_data["leaked_fields"])

    def test_compare_endpoints_against_schema(self):
        analyzer = APIQualityAnalyzer()
        discovered = [
            DiscoveredWebEndpoint(url="http://example.com/api/users", path="/api/users"),
            DiscoveredWebEndpoint(url="http://example.com/internal/debug", path="/internal/debug"),
        ]
        declared = {"/api/users"}
        obs = analyzer.compare_endpoints_against_schema(
            discovered, declared, engagement_id="eng-test"
        )
        assert len(obs) == 1
        assert obs[0].observation_type == SecurityObservationType.UNDOCUMENTED_ENDPOINT
        assert "/internal/debug" in obs[0].title

    def test_parameter_classification(self):
        p = APIQualityAnalyzer.classify_parameter(
            name="auth_token",
            location="header",
            sample_value="Bearer 123",
            required=True,
        )
        assert p.name == "auth_token"
        assert p.location == ParameterLocation.HEADER
        assert p.required is True


class TestWebSecurityAnalysisEngineE2E:
    @pytest.mark.asyncio
    async def test_engine_hypothesis_and_safe_validation_pipeline(self):
        """Validates Observation -> Hypothesis -> Safe Test -> Execution -> Validated Finding."""
        scope = ScopeDefinition(
            engagement_id="eng-analysis-e2e",
            version=1,
            includes=ScopeTarget(domains=["cors-target.com"], ports=[80, 443]),
        )
        guard = ScopeGuard(scope)

        async def handler(request: httpx.Request) -> httpx.Response:
            origin = request.headers.get("Origin", "")
            return httpx.Response(
                200,
                headers={"Access-Control-Allow-Origin": origin},
                text="Canary CORS reflection test",
            )

        transport = httpx.MockTransport(handler)
        evidence = EvidenceStore()
        client = ControlledHTTPClient(
            scope_guard=guard, evidence_store=evidence, transport=transport
        )
        engine = WebSecurityAnalysisEngine(http_client=client, evidence_store=evidence)

        # 1. Initial observed response with reflection
        initial_resp = HTTPResponse(
            status_code=200,
            headers={"Access-Control-Allow-Origin": "https://canary.arka-security.internal"},
            url="http://cors-target.com/api/data",
        )
        observations = engine.cors_analyzer.analyze_cors_response(
            initial_resp,
            sent_origin="https://canary.arka-security.internal",
            engagement_id="eng-analysis-e2e",
        )
        assert len(observations) == 1

        # 2. Derive hypothesis
        hypotheses = engine.derive_hypotheses(observations, engagement_id="eng-analysis-e2e")
        assert len(hypotheses) == 1
        hyp = hypotheses[0]
        assert hyp.vulnerability_type == "CORS_ORIGIN_REFLECTION"

        # 3. Generate safe test
        test = engine.generate_safe_test(hyp)
        assert test is not None
        assert test.is_safe is True
        assert test.max_requests == 1

        # 4. Execute test and deterministically score finding
        finding = await engine.execute_safe_test(test, hyp, task_id="task-cors-01")
        assert finding.status == FindingValidationStatus.VALIDATED
        assert finding.evidence_confidence == 1.0
        assert len(finding.cryptographic_evidence) == 1
        assert len(finding.cryptographic_evidence[0].content_hash) == 64
