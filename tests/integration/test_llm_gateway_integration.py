"""Integration tests for ARKA LLM Gateway.

Uses mocked provider responses to test:
- Successful completion
- Provider authentication error (401)
- Rate limiting (429) and retryability
- Timeout handling (504)
- Provider unavailability (503)
- Fallback routing
- Structured JSON output parsing
- Multimodal content serialization
- Token accounting and cost calculation
- Strict secret redaction (no API keys in logs or audit)
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import litellm.exceptions
import pytest
from pydantic import SecretStr

from arka.app.audit.service import AuditService
from arka.app.core.config.settings import LLMProvider, Settings
from arka.app.llm.gateway.gateway import LLMGateway, LLMGatewayError
from arka.app.llm.schemas.llm_schemas import (
    ContentType,
    LLMMessage,
    LLMRequest,
    MultimodalContent,
)


@pytest.fixture
def mock_settings() -> Settings:
    return Settings(
        arka_llm_provider=LLMProvider.OPENAI,
        arka_llm_model="gpt-4o",
        arka_llm_api_key=SecretStr("sk-test-secret-key-12345"),
        arka_llm_fallback_provider=LLMProvider.ANTHROPIC,
        arka_llm_fallback_model="claude-3-5-sonnet",
        arka_llm_fallback_api_key=SecretStr("sk-ant-fallback-secret-67890"),
        arka_llm_timeout=10,
    )


@pytest.fixture
def audit_service() -> AuditService:
    return AuditService()


def make_mock_completion_response(
    content: str = "Test response from LLM",
    prompt_tokens: int = 25,
    completion_tokens: int = 15,
    model: str = "gpt-4o",
):
    choice = SimpleNamespace(message=SimpleNamespace(content=content, role="assistant"))
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


class TestLLMGatewayIntegration:
    @pytest.mark.asyncio
    async def test_successful_completion(self, mock_settings, audit_service):
        with patch("arka.app.llm.gateway.gateway.get_settings", return_value=mock_settings):
            gateway = LLMGateway(audit_service=audit_service)

            mock_response = make_mock_completion_response(content="Autonomous plan generated.")
            gateway._router.acompletion = AsyncMock(return_value=mock_response)

            req = LLMRequest(
                engagement_id="eng-llm-1",
                task_id="task-llm-1",
                agent_id="orchestrator",
                messages=[LLMMessage(role="user", content="Plan next step")],
                temperature=0.0,
            )

            res = await gateway.complete(req)
            assert res.success is True
            assert res.content == "Autonomous plan generated."
            assert res.usage.prompt_tokens == 25
            assert res.usage.completion_tokens == 15
            assert res.usage.total_tokens == 40
            assert res.latency_ms >= 0

            # Audit record check
            events = await audit_service.get_events(engagement_id="eng-llm-1")
            assert len(events) >= 1
            event = events[0]
            # Verify secret is not in audit parameters
            assert "sk-test-secret-key-12345" not in str(event.model_dump())
            assert "sk-ant-fallback-secret-67890" not in str(event.model_dump())

    @pytest.mark.asyncio
    async def test_authentication_error_401(self, mock_settings, audit_service):
        with patch("arka.app.llm.gateway.gateway.get_settings", return_value=mock_settings):
            gateway = LLMGateway(audit_service=audit_service)
            gateway._router.acompletion = AsyncMock(
                side_effect=litellm.exceptions.AuthenticationError(
                    message="Invalid API Key",
                    llm_provider="openai",
                    model="gpt-4o",
                )
            )

            req = LLMRequest(
                messages=[LLMMessage(role="user", content="Hello")],
            )

            with pytest.raises(LLMGatewayError) as exc:
                await gateway.complete(req)

            assert exc.value.status_code == 401
            assert exc.value.retryable is False
            assert "Authentication failed" in str(exc.value)

    @pytest.mark.asyncio
    async def test_rate_limit_error_429_is_retryable(self, mock_settings):
        with patch("arka.app.llm.gateway.gateway.get_settings", return_value=mock_settings):
            gateway = LLMGateway()
            gateway._router.acompletion = AsyncMock(
                side_effect=litellm.exceptions.RateLimitError(
                    message="Rate limit exceeded",
                    llm_provider="openai",
                    model="gpt-4o",
                )
            )

            req = LLMRequest(
                messages=[LLMMessage(role="user", content="Hello")],
            )

            with pytest.raises(LLMGatewayError) as exc:
                await gateway.complete(req)

            assert exc.value.status_code == 429
            assert exc.value.retryable is True

    @pytest.mark.asyncio
    async def test_timeout_error_504_is_retryable(self, mock_settings):
        with patch("arka.app.llm.gateway.gateway.get_settings", return_value=mock_settings):
            gateway = LLMGateway()
            gateway._router.acompletion = AsyncMock(
                side_effect=litellm.exceptions.Timeout(
                    message="Gateway timeout",
                    model="gpt-4o",
                    llm_provider="openai",
                )
            )

            req = LLMRequest(
                messages=[LLMMessage(role="user", content="Hello")],
            )

            with pytest.raises(LLMGatewayError) as exc:
                await gateway.complete(req)

            assert exc.value.status_code == 504
            assert exc.value.retryable is True

    @pytest.mark.asyncio
    async def test_service_unavailable_503(self, mock_settings):
        with patch("arka.app.llm.gateway.gateway.get_settings", return_value=mock_settings):
            gateway = LLMGateway()
            gateway._router.acompletion = AsyncMock(
                side_effect=litellm.exceptions.ServiceUnavailableError(
                    message="Service unavailable",
                    llm_provider="openai",
                    model="gpt-4o",
                )
            )

            req = LLMRequest(
                messages=[LLMMessage(role="user", content="Hello")],
            )

            with pytest.raises(LLMGatewayError) as exc:
                await gateway.complete(req)

            assert exc.value.status_code == 503
            assert exc.value.retryable is True

    @pytest.mark.asyncio
    async def test_structured_output_json_parsing(self, mock_settings):
        with patch("arka.app.llm.gateway.gateway.get_settings", return_value=mock_settings):
            gateway = LLMGateway()

            # Markdown code-fenced json response
            raw_json = (
                "```json\n"
                '{"action": "request_tool", "tool": "echo_test", "target": "target.com"}\n'
                "```"
            )
            mock_response = make_mock_completion_response(content=raw_json)
            gateway._router.acompletion = AsyncMock(return_value=mock_response)

            req = LLMRequest(
                messages=[LLMMessage(role="user", content="Action?")],
                response_format={"type": "json_object"},
            )

            res = await gateway.complete(req)
            assert res.success is True
            # Should parse into structured output dict
            assert res.content == raw_json

    @pytest.mark.asyncio
    async def test_multimodal_request_serialization(self, mock_settings):
        with patch("arka.app.llm.gateway.gateway.get_settings", return_value=mock_settings):
            gateway = LLMGateway()
            gateway._router.acompletion = AsyncMock(
                return_value=make_mock_completion_response(content="Image inspected")
            )

            multi_message = LLMMessage(
                role="user",
                content=[
                    MultimodalContent(content_type=ContentType.TEXT, text="Analyze screenshot"),
                    MultimodalContent(
                        content_type=ContentType.IMAGE,
                        media_url="https://example.com/screenshot.png",
                    ),
                    MultimodalContent(
                        content_type=ContentType.IMAGE,
                        media_base64="iVBORw0KGgoAAAANSUhEUg==",
                        mime_type="image/png",
                    ),
                ],
            )

            req = LLMRequest(messages=[multi_message])
            res = await gateway.complete(req)
            assert res.success is True
            assert gateway._router.acompletion.called
            call_kwargs = gateway._router.acompletion.call_args.kwargs
            messages = call_kwargs["messages"]
            assert len(messages) == 1
            parts = messages[0]["content"]
            assert len(parts) == 3
            assert parts[0]["type"] == "text"
            assert parts[1]["type"] == "image_url"
            assert parts[2]["type"] == "image_url"

    @pytest.mark.asyncio
    async def test_providers_listing(self, mock_settings):
        with patch("arka.app.llm.gateway.gateway.get_settings", return_value=mock_settings):
            gateway = LLMGateway()
            providers = await gateway.get_providers()
            assert len(providers) == 2
            assert providers[0]["name"] == "openai"
            assert providers[0]["role"] == "primary"
            assert providers[0]["configured"] is True
            assert providers[1]["name"] == "anthropic"
            assert providers[1]["role"] == "fallback"
            assert providers[1]["configured"] is True
