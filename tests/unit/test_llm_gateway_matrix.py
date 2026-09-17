"""Comprehensive Mock Provider and Fallback Matrix Tests for LLMGateway."""

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import litellm.exceptions
import pytest
from pydantic import SecretStr

from arka.app.audit.service import AuditService
from arka.app.llm.gateway.gateway import LLMGateway, LLMGatewayError
from arka.app.llm.schemas.llm_schemas import LLMMessage, LLMRequest
from arka.app.llm.schemas.profile import LLMProfile


def make_mock_response(
    content: str = "Test LLM output",
    model: str = "test-model",
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
    finish_reason: str = "stop",
):
    choice = SimpleNamespace(
        message=SimpleNamespace(content=content, role="assistant"),
        finish_reason=finish_reason,
    )
    usage = SimpleNamespace(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
    )
    return SimpleNamespace(
        choices=[choice],
        usage=usage,
        model=model,
    )


class TestMockProviderMatrix:
    @pytest.mark.parametrize(
        ("provider_name", "model_id", "expected_prefix"),
        [
            ("openai", "gpt-4o", "openai/gpt-4o"),
            ("anthropic", "claude-3-5-sonnet", "anthropic/claude-3-5-sonnet"),
            (
                "openrouter",
                "nvidia/nemotron-3-ultra-550b-a55b:free",
                "openrouter/nvidia/nemotron-3-ultra-550b-a55b:free",
            ),
            ("groq", "llama-3.3-70b-versatile", "groq/llama-3.3-70b-versatile"),
            ("nvidia", "meta/llama-3.1-70b-instruct", "nvidia_nim/meta/llama-3.1-70b-instruct"),
            ("deepseek", "deepseek-chat", "deepseek/deepseek-chat"),
            ("gemini", "gemini-1.5-pro", "gemini/gemini-1.5-pro"),
        ],
    )
    @pytest.mark.asyncio
    async def test_all_seven_providers_mock_completion(
        self, provider_name: str, model_id: str, expected_prefix: str
    ):
        profile = LLMProfile(
            provider=provider_name,
            model=model_id,
            api_key=SecretStr(f"sk-{provider_name}-key-12345"),
        )
        gateway = LLMGateway(profile=profile)
        assert gateway._router is not None

        # Verify router configuration formatting
        model_cfg = gateway._router.model_list[0]["litellm_params"]
        assert model_cfg["model"] == expected_prefix

        # Mock completion execution
        mock_resp = make_mock_response(
            content=f"Response from {provider_name}",
            model=expected_prefix,
        )
        cast(Any, gateway._router).acompletion = AsyncMock(return_value=mock_resp)

        req = LLMRequest(
            messages=[LLMMessage(role="user", content="Test prompt")],
        )
        res = await gateway.complete(req)
        assert res.success is True
        assert res.content == f"Response from {provider_name}"
        assert res.provider == provider_name
        assert res.model == expected_prefix
        assert res.usage.prompt_tokens == 10
        assert res.usage.completion_tokens == 5
        assert res.usage.total_tokens == 15
        assert res.finish_reason == "stop"


class TestMockErrorNormalizationMatrix:
    @pytest.fixture
    def gateway(self) -> LLMGateway:
        profile = LLMProfile(
            provider="openai",
            model="gpt-4o",
            api_key=SecretStr("sk-test-mock-key"),
        )
        gw = LLMGateway(profile=profile)
        return gw

    @pytest.mark.asyncio
    async def test_authentication_error_401(self, gateway):
        cast(Any, gateway._router).acompletion = AsyncMock(
            side_effect=litellm.exceptions.AuthenticationError(
                message="Invalid API Key",
                model="gpt-4o",
                llm_provider="openai",
            )
        )
        with pytest.raises(LLMGatewayError) as exc_info:
            await gateway.complete(LLMRequest(messages=[LLMMessage(role="user", content="hi")]))

        err = exc_info.value
        assert err.status_code == 401
        assert err.retryable is False
        assert "Authentication failed" in str(err)

    @pytest.mark.asyncio
    async def test_context_window_exceeded_400(self, gateway):
        cast(Any, gateway._router).acompletion = AsyncMock(
            side_effect=litellm.exceptions.ContextWindowExceededError(
                message="Context length exceeded",
                model="gpt-4o",
                llm_provider="openai",
            )
        )
        with pytest.raises(LLMGatewayError) as exc_info:
            await gateway.complete(LLMRequest(messages=[LLMMessage(role="user", content="hi")]))

        err = exc_info.value
        assert err.status_code == 400
        assert err.retryable is False

    @pytest.mark.asyncio
    async def test_rate_limit_error_429(self, gateway):
        cast(Any, gateway._router).acompletion = AsyncMock(
            side_effect=litellm.exceptions.RateLimitError(
                message="Rate limit reached",
                model="gpt-4o",
                llm_provider="openai",
            )
        )
        with pytest.raises(LLMGatewayError) as exc_info:
            await gateway.complete(LLMRequest(messages=[LLMMessage(role="user", content="hi")]))

        err = exc_info.value
        assert err.status_code == 429
        assert err.retryable is True

    @pytest.mark.asyncio
    async def test_timeout_error_504(self, gateway):
        cast(Any, gateway._router).acompletion = AsyncMock(
            side_effect=litellm.exceptions.Timeout(
                message="Timed out",
                model="gpt-4o",
                llm_provider="openai",
            )
        )
        with pytest.raises(LLMGatewayError) as exc_info:
            await gateway.complete(LLMRequest(messages=[LLMMessage(role="user", content="hi")]))

        err = exc_info.value
        assert err.status_code == 504
        assert err.retryable is True

    @pytest.mark.asyncio
    async def test_service_unavailable_503(self, gateway):
        cast(Any, gateway._router).acompletion = AsyncMock(
            side_effect=litellm.exceptions.ServiceUnavailableError(
                message="Service down",
                model="gpt-4o",
                llm_provider="openai",
            )
        )
        with pytest.raises(LLMGatewayError) as exc_info:
            await gateway.complete(LLMRequest(messages=[LLMMessage(role="user", content="hi")]))

        err = exc_info.value
        assert err.status_code == 503
        assert err.retryable is True


class TestFallbackChainMatrix:
    @pytest.mark.asyncio
    async def test_primary_fail_fallback_succeeds(self):
        fb_profile = LLMProfile(
            provider="groq",
            model="llama-3.3-70b-versatile",
            api_key=SecretStr("gsk-fallback-key"),
        )
        primary_profile = LLMProfile(
            provider="openrouter",
            model="nvidia/nemotron-3-ultra-550b-a55b:free",
            api_key=SecretStr("sk-or-primary-key"),
            fallbacks=[fb_profile],
        )
        gateway = LLMGateway(profile=primary_profile)
        assert gateway._router is not None
        assert len(gateway._router.model_list) == 2
        assert gateway._router.fallbacks == [{"arka-primary": ["arka-fallback-0"]}]

        # acompletion returns fallback result
        mock_fallback_resp = make_mock_response(
            content="Fallback succeeded",
            model="groq/llama-3.3-70b-versatile",
        )
        cast(Any, gateway._router).acompletion = AsyncMock(return_value=mock_fallback_resp)

        res = await gateway.complete(LLMRequest(messages=[LLMMessage(role="user", content="Plan")]))
        assert res.success is True
        assert res.content == "Fallback succeeded"
        assert res.model == "groq/llama-3.3-70b-versatile"

    @pytest.mark.asyncio
    async def test_secret_redaction_in_audit_and_exceptions(self):
        audit = AuditService()
        profile = LLMProfile(
            provider="openai",
            model="gpt-4o",
            api_key=SecretStr("sk-super-secret-key-that-must-never-leak-999"),
        )
        gateway = LLMGateway(profile=profile, audit_service=audit)

        cast(Any, gateway._router).acompletion = AsyncMock(
            side_effect=litellm.exceptions.AuthenticationError(
                message="sk-super-secret-key-that-must-never-leak-999 is invalid",
                model="gpt-4o",
                llm_provider="openai",
            )
        )

        with pytest.raises(LLMGatewayError) as exc_info:
            await gateway.complete(
                LLMRequest(
                    engagement_id="eng-redact-test",
                    messages=[LLMMessage(role="user", content="Test")],
                )
            )

        err_msg = str(exc_info.value)
        assert "sk-super-secret-key" not in err_msg

        # Check audit trail
        events = await audit.get_events(engagement_id="eng-redact-test")
        for ev in events:
            assert "sk-super-secret-key" not in str(ev.parameters)

    @pytest.mark.asyncio
    async def test_opt_in_sanitized_raw_response(self):
        profile = LLMProfile(
            provider="openai",
            model="gpt-4o",
            api_key=SecretStr("sk-test-key"),
        )
        gateway = LLMGateway(profile=profile)
        mock_resp = make_mock_response("Hello world")
        cast(Any, gateway._router).acompletion = AsyncMock(return_value=mock_resp)

        # Default: raw_response is None
        res_default = await gateway.complete(
            LLMRequest(messages=[LLMMessage(role="user", content="hi")], include_raw=False)
        )
        assert res_default.raw_response is None

        # Opt-in: raw_response populated and sanitized
        res_opt_in = await gateway.complete(
            LLMRequest(messages=[LLMMessage(role="user", content="hi")], include_raw=True)
        )
        assert res_opt_in.raw_response is not None
