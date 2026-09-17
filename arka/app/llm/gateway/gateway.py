"""ARKA LLM Gateway — universal provider-neutral interface for all LLM operations."""

from __future__ import annotations

import contextlib
import json
import time
from typing import Any

import litellm
from litellm import Router as LiteLLMRouter

from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.config import get_settings
from arka.app.core.config.settings import LLMProvider, Settings
from arka.app.llm.providers.base import LLMGatewayError
from arka.app.llm.providers.registry import ProviderRegistry
from arka.app.llm.schemas.llm_schemas import (
    LLMMessage,
    LLMRequest,
    LLMResponse,
    TokenUsage,
)
from arka.app.llm.schemas.profile import LLMProfile
from arka.app.observability.logging import get_logger

logger = get_logger(__name__)


class LLMGateway:
    """ARKA LLM Gateway — provider-neutral interface for all LLM operations.

    Agents must use this gateway exclusively. Never instantiate provider clients directly.
    Security Invariant: The LLM is an untrusted reasoning engine with ZERO execution authority.
    """

    def __init__(
        self,
        audit_service: AuditService | None = None,
        profile: LLMProfile | None = None,
    ):
        settings = get_settings()
        litellm.drop_params = True
        litellm.set_verbose = False

        self._settings = settings
        self._audit = audit_service
        self._profile: LLMProfile = profile or settings.get_primary_llm_profile()
        self._router: LiteLLMRouter | None = self._build_router(self._profile, settings)

    def _get_model_string(
        self, provider: LLMProvider | str, model: str, base_url: str | None = None
    ) -> str:
        """Convert ARKA provider/model to litellm model string.

        Preserved for backward compatibility.
        """
        prov_str = provider.value if isinstance(provider, LLMProvider) else str(provider)
        try:
            adapter = ProviderRegistry.resolve(prov_str)
            return adapter.format_model_name(model, base_url)
        except Exception:
            if "/" in model:
                return model
            return f"openai/{model}"

    def _build_router(self, profile: LLMProfile, settings: Settings) -> LiteLLMRouter | None:
        """Build a LiteLLM Router with primary profile and fallback profiles."""
        primary_key = profile.api_key.get_secret_value() if profile.api_key else ""
        if not primary_key:
            return None

        model_list: list[dict[str, Any]] = []
        fallbacks: list[dict[str, list[str]]] = []

        # Primary profile
        try:
            primary_adapter = ProviderRegistry.resolve(profile.provider)
            primary_params = primary_adapter.build_litellm_params(profile)
        except Exception as e:
            logger.warning(f"Failed to resolve primary adapter for '{profile.provider}': {e}")
            formatted_model = self._get_model_string(
                profile.provider, profile.model, profile.base_url
            )
            primary_params = {
                "model": formatted_model,
                "api_key": primary_key,
                "timeout": float(profile.timeout),
            }
            if profile.base_url:
                primary_params["api_base"] = profile.base_url

        model_list.append(
            {
                "model_name": "arka-primary",
                "litellm_params": primary_params,
            }
        )

        # Fallback profiles
        fb_names: list[str] = []
        for idx, fb in enumerate(profile.fallbacks):
            fb_key = fb.api_key.get_secret_value() if fb.api_key else ""
            if not fb_key:
                continue

            try:
                fb_adapter = ProviderRegistry.resolve(fb.provider)
                fb_params = fb_adapter.build_litellm_params(fb)
            except Exception as e:
                logger.warning(f"Failed to resolve fallback adapter for '{fb.provider}': {e}")
                fb_formatted = self._get_model_string(fb.provider, fb.model, fb.base_url)
                fb_params = {
                    "model": fb_formatted,
                    "api_key": fb_key,
                    "timeout": float(fb.timeout),
                }
                if fb.base_url:
                    fb_params["api_base"] = fb.base_url

            fb_name = f"arka-fallback-{idx}"
            model_list.append(
                {
                    "model_name": fb_name,
                    "litellm_params": fb_params,
                }
            )
            fb_names.append(fb_name)

        if fb_names:
            fallbacks.append({"arka-primary": fb_names})

        return LiteLLMRouter(
            model_list=model_list,
            fallbacks=fallbacks if fallbacks else None,  # type: ignore[arg-type]
            num_retries=profile.max_retries,
            allowed_fails=3,
            cooldown_time=60,
            timeout=float(profile.timeout),
        )

    def _sanitize_raw_response(self, raw: Any) -> dict[str, Any]:
        """Safely sanitize raw provider response for opt-in inclusion."""

        def _sanitize(obj: Any) -> Any:
            if isinstance(obj, dict):
                clean_dict: dict[str, Any] = {}
                for k, v in obj.items():
                    key_str = str(k)
                    if any(
                        sec in key_str.lower()
                        for sec in ("key", "token", "auth", "secret", "cookie")
                    ):
                        clean_dict[key_str] = "[REDACTED]"
                    else:
                        clean_dict[key_str] = _sanitize(v)
                return clean_dict
            if isinstance(obj, list):
                return [_sanitize(x) for x in obj]
            if hasattr(obj, "model_dump"):
                return _sanitize(obj.model_dump())
            if hasattr(obj, "__dict__"):
                return _sanitize(obj.__dict__)
            return obj

        res = _sanitize(raw)
        if isinstance(res, dict):
            return res
        return {"data": res}

    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Send a completion request through the gateway.

        Handles provider routing, retries, fallbacks, token tracking, and error normalization.
        """
        if self._router is None:
            raise LLMGatewayError(
                "LLM Gateway not configured. Set ARKA_LLM_API_KEY or provider-specific API key.",
                status_code=503,
            )

        provider = request.provider or self._profile.provider
        model = request.model or self._profile.model

        # Build messages for litellm
        messages: list[Any] = []
        for msg in request.messages:
            if isinstance(msg.content, str):
                messages.append({"role": msg.role, "content": msg.content})
            else:
                # Multimodal content - build content array
                content_parts: list[dict[str, Any]] = []
                for part in msg.content:
                    if part.content_type.value == "text":
                        content_parts.append({"type": "text", "text": part.text or ""})
                    elif part.content_type.value == "image":
                        if part.media_url:
                            content_parts.append(
                                {"type": "image_url", "image_url": {"url": part.media_url}}
                            )
                        elif part.media_base64:
                            mime = part.mime_type or "image/png"
                            content_parts.append(
                                {
                                    "type": "image_url",
                                    "image_url": {"url": f"data:{mime};base64,{part.media_base64}"},
                                }
                            )
                    else:
                        content_parts.append({"type": "text", "text": part.text or ""})
                messages.append({"role": msg.role, "content": content_parts})

        # Build call kwargs
        call_kwargs: dict[str, Any] = {
            "model": "arka-primary",
            "messages": messages,
            "temperature": request.temperature,
        }
        if request.max_tokens:
            call_kwargs["max_tokens"] = request.max_tokens
        if request.response_format:
            call_kwargs["response_format"] = request.response_format
        if request.timeout:
            call_kwargs["timeout"] = float(request.timeout)

        start_time = time.monotonic()

        try:
            response = await self._router.acompletion(**call_kwargs)  # type: ignore[call-overload]
            latency_ms = int((time.monotonic() - start_time) * 1000)

            choice = response.choices[0] if getattr(response, "choices", None) else None
            content = choice.message.content if choice and getattr(choice, "message", None) else ""
            content = content or ""
            finish_reason = getattr(choice, "finish_reason", None)
            usage = getattr(response, "usage", None)

            # Calculate cost
            try:
                cost = float(litellm.completion_cost(completion_response=response))
            except Exception:
                cost = None

            token_usage = TokenUsage(
                prompt_tokens=getattr(usage, "prompt_tokens", 0),
                completion_tokens=getattr(usage, "completion_tokens", 0),
                total_tokens=getattr(usage, "total_tokens", 0),
                cost_usd=cost,
            )

            # Try to parse structured output
            structured = None
            if request.response_format and content:
                with contextlib.suppress(json.JSONDecodeError):
                    structured = json.loads(content)

            # Opt-in sanitized raw response
            raw_response = None
            if request.include_raw:
                raw_response = self._sanitize_raw_response(response)

            actual_model = getattr(response, "model", None) or model

            llm_response = LLMResponse(
                request_id=request.request_id,
                provider=provider,
                model=actual_model,
                content=content,
                structured_output=structured,
                usage=token_usage,
                finish_reason=finish_reason,
                raw_response=raw_response,
                latency_ms=latency_ms,
                success=True,
            )

            # Audit logging without credentials
            if self._audit:
                await self._audit.record_action(
                    event_type=AuditEventType.LLM_RESPONSE,
                    actor="llm_gateway",
                    action="completion",
                    engagement_id=request.engagement_id,
                    task_id=request.task_id,
                    agent_id=request.agent_id,
                    parameters={
                        "provider": provider,
                        "model": actual_model,
                        "prompt_tokens": token_usage.prompt_tokens,
                        "completion_tokens": token_usage.completion_tokens,
                        "total_tokens": token_usage.total_tokens,
                        "latency_ms": latency_ms,
                    },
                    result_status="success",
                    correlation_id=request.request_id,
                )

            return llm_response

        except Exception as exc:
            try:
                adapter = ProviderRegistry.resolve(provider)
                gateway_err = adapter.normalize_error(exc, provider, model)
            except Exception:
                gateway_err = LLMGatewayError(
                    f"LLM Gateway error for provider '{provider}': {exc}",
                    provider=provider,
                    model=model,
                    status_code=500,
                )

            # Audit failure event without leaking secrets
            if self._audit:
                with contextlib.suppress(Exception):
                    await self._audit.record_action(
                        event_type=AuditEventType.LLM_RESPONSE,
                        actor="llm_gateway",
                        action="completion_failure",
                        engagement_id=request.engagement_id,
                        task_id=request.task_id,
                        agent_id=request.agent_id,
                        parameters={
                            "provider": provider,
                            "model": model,
                            "error": str(gateway_err),
                            "status_code": gateway_err.status_code,
                        },
                        result_status="failure",
                        correlation_id=request.request_id,
                    )
            raise gateway_err from exc

    async def health_check(self, check_connectivity: bool = False) -> dict[str, Any]:
        """Check provider status and optional connectivity.

        Args:
            check_connectivity: If True, executes a ping prompt against the model.
                Defaults to False to avoid consuming expensive model tokens.
        """
        if self._router is None:
            return {
                "status": "UNCONFIGURED",
                "provider": self._profile.provider,
                "model": self._profile.model,
                "configured": False,
                "available": False,
            }

        if not check_connectivity:
            return {
                "status": "CONFIGURED",
                "provider": self._profile.provider,
                "model": self._profile.model,
                "configured": True,
                "available": True,
            }

        try:
            response = await self.complete(
                LLMRequest(
                    messages=[LLMMessage(role="user", content="ping")],
                    max_tokens=5,
                    temperature=0.0,
                )
            )
            return {
                "status": "AVAILABLE",
                "provider": response.provider,
                "model": response.model,
                "configured": True,
                "available": True,
                "latency_ms": response.latency_ms,
            }
        except LLMGatewayError as e:
            return {
                "status": "UNAVAILABLE",
                "provider": e.provider,
                "model": e.model,
                "configured": True,
                "available": False,
                "error": str(e),
            }

    async def get_providers(self) -> list[dict[str, Any]]:
        """List all supported providers and their configuration status."""
        supported = ProviderRegistry.list_supported()
        active_provider = ProviderRegistry.normalize_provider_name(self._profile.provider)
        active_model = self._profile.model

        fallback_providers = {
            ProviderRegistry.normalize_provider_name(fb.provider) for fb in self._profile.fallbacks
        }

        results: list[dict[str, Any]] = []
        for name in supported:
            adapter = ProviderRegistry.resolve(name)
            key = self._settings.get_effective_llm_api_key(name)
            is_configured = bool(key and key.get_secret_value())

            if name == active_provider:
                role = "primary"
                status = "ACTIVE" if is_configured else "CONFIGURED_INCOMPLETE"
                model_name = active_model
            elif name in fallback_providers:
                role = "fallback"
                fb_prof = next((fb for fb in self._profile.fallbacks if fb.provider == name), None)
                if fb_prof and fb_prof.api_key and fb_prof.api_key.get_secret_value():
                    is_configured = True
                status = "AVAILABLE" if is_configured else "UNCONFIGURED"
                model_name = fb_prof.model if fb_prof else ""
            else:
                role = "available"
                status = "CONFIGURED" if is_configured else "SUPPORTED"
                model_name = ""

            caps = adapter.get_capabilities(model_name or "default")
            results.append(
                {
                    "name": name,
                    "aliases": list(adapter.supported_aliases),
                    "role": role,
                    "status": status,
                    "configured": is_configured,
                    "model": model_name,
                    "capabilities": caps.model_dump(),
                }
            )

        return results
