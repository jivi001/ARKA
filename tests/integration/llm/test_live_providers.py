"""Opt-in live provider integration tests.

These tests execute real API calls to configured external providers ONLY when
explicitly enabled via:
    ARKA_LLM_LIVE_TESTS=1

If disabled, all tests in this module are skipped.
If enabled, tests only run for providers that have active API keys configured in the environment.
"""

import os

import pytest

from arka.app.core.config import get_settings
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.llm.schemas.llm_schemas import LLMMessage, LLMRequest

pytestmark = pytest.mark.skipif(
    os.environ.get("ARKA_LLM_LIVE_TESTS", "").lower() not in ("1", "true"),
    reason="Live LLM integration tests require ARKA_LLM_LIVE_TESTS=1",
)


class TestLiveLLMProviders:
    @pytest.mark.asyncio
    async def test_live_active_provider_ping(self):
        """Send a minimal harmless prompt to the currently configured primary provider."""
        settings = get_settings()
        key = settings.get_effective_llm_api_key(settings.arka_llm_provider)
        if not key or not key.get_secret_value():
            pytest.skip(
                f"No API key configured for primary provider '{settings.arka_llm_provider.value}'"
            )

        gateway = LLMGateway()
        req = LLMRequest(
            messages=[
                LLMMessage(role="user", content="Say 'ARKA is operational' and nothing else.")
            ],
            max_tokens=20,
            temperature=0.0,
        )

        response = await gateway.complete(req)
        assert response.success is True
        assert response.content
        assert response.provider == settings.arka_llm_provider.value
        assert response.latency_ms > 0

    @pytest.mark.parametrize(
        "provider_name",
        ["openai", "anthropic", "openrouter", "groq", "nvidia", "deepseek", "gemini"],
    )
    @pytest.mark.asyncio
    async def test_live_provider_if_configured(self, provider_name: str):
        """Test each individual provider if credentials exist in the environment."""
        settings = get_settings()
        key = settings.get_effective_llm_api_key(provider_name)
        if not key or not key.get_secret_value():
            pytest.skip(f"No API key present for '{provider_name}'")

        from arka.app.llm.schemas.profile import LLMProfile

        # Default fast/small model per provider for testing
        default_test_models = {
            "openai": "gpt-4o-mini",
            "anthropic": "claude-3-haiku-20240307",
            "openrouter": "nvidia/nemotron-3-ultra-550b-a55b:free",
            "groq": "llama-3.1-8b-instant",
            "nvidia": "meta/llama-3.1-8b-instruct",
            "deepseek": "deepseek-chat",
            "gemini": "gemini-1.5-flash",
        }
        model = default_test_models.get(provider_name, "default")
        profile = LLMProfile(
            provider=provider_name,
            model=model,
            api_key=key,
            timeout=60,
        )

        gateway = LLMGateway(profile=profile)
        req = LLMRequest(
            messages=[
                LLMMessage(role="user", content="Say 'ARKA operational test' and nothing else.")
            ],
            max_tokens=20,
            temperature=0.0,
        )

        response = await gateway.complete(req)
        assert response.success is True
        assert response.content
        assert response.provider == provider_name
