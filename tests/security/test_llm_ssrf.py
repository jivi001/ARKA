"""Security tests for SSRF prevention in LLM base_url endpoints."""

import pytest

from arka.app.llm.schemas.profile import LLMProfile
from arka.app.llm.security.ssrf import SSRFViolationError, validate_llm_endpoint


class TestLLMSSRFProtection:
    @pytest.mark.parametrize(
        "malicious_url",
        [
            "http://169.254.169.254/latest/meta-data",
            "https://169.254.169.254/computeMetadata/v1",
            "http://localhost:8080/admin",
            "https://127.0.0.1:9000",
            "http://127.0.0.1:6379",
            "https://10.0.0.5/api",
            "https://172.16.0.10:443",
            "https://192.168.1.1/setup",
            "http://metadata.google.internal",
            "https://instance-data/latest",
            "https://service.internal/llm",
            "https://vault.local:8200",
            "file:///etc/passwd",
            "gopher://127.0.0.1:25",
            "ftp://anonymous@internal.corp",
        ],
    )
    def test_ssrf_forbidden_destinations_blocked(self, malicious_url: str):
        with pytest.raises((SSRFViolationError, ValueError)):
            validate_llm_endpoint(malicious_url, allow_private=False, allow_http=False)

    @pytest.mark.parametrize(
        "legitimate_url",
        [
            "https://openrouter.ai/api/v1",
            "https://api.openai.com/v1",
            "https://api.anthropic.com",
            "https://api.groq.com/openai/v1",
            "https://integrate.api.nvidia.com/v1",
            "https://api.deepseek.com/v1",
            "https://generativelanguage.googleapis.com",
            "https://custom-proxy.example.com/v1",
        ],
    )
    def test_legitimate_endpoints_allowed(self, legitimate_url: str):
        sanitized = validate_llm_endpoint(legitimate_url, allow_private=False, allow_http=False)
        assert sanitized == legitimate_url.rstrip("/")

    def test_insecure_http_rejected_in_production(self):
        with pytest.raises(SSRFViolationError, match="Insecure HTTP scheme is not permitted"):
            validate_llm_endpoint("http://example.com/api", allow_http=False, allow_private=False)

    def test_test_mode_permits_private_http_endpoints(self):
        url = "http://127.0.0.1:8000/v1"
        sanitized = validate_llm_endpoint(url, allow_private=True, allow_http=True)
        assert sanitized == "http://127.0.0.1:8000/v1"

    def test_llm_profile_rejects_empty_provider_or_model(self):
        with pytest.raises(ValueError):
            LLMProfile(provider="", model="gpt-4o")

        with pytest.raises(ValueError):
            LLMProfile(provider="openai", model="")
