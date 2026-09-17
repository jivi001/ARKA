"""Base adapter for LLM providers."""

from abc import ABC, abstractmethod
from typing import Any

from litellm.exceptions import (
    APIConnectionError,
    APIError,
    AuthenticationError,
    ContentPolicyViolationError,
    ContextWindowExceededError,
    RateLimitError,
    ServiceUnavailableError,
    Timeout,
)

from arka.app.llm.schemas.capabilities import ModelCapabilities, resolve_model_capabilities
from arka.app.llm.schemas.profile import LLMProfile


class LLMGatewayError(Exception):
    """Base exception for LLM Gateway errors."""

    def __init__(
        self,
        message: str,
        provider: str = "",
        model: str = "",
        status_code: int = 500,
        retryable: bool = False,
    ):
        self.provider = provider
        self.model = model
        self.status_code = status_code
        self.retryable = retryable
        super().__init__(message)


class BaseProviderAdapter(ABC):
    """Abstract base class for provider-specific LLM adapters."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Canonical provider name."""

    @property
    @abstractmethod
    def supported_aliases(self) -> tuple[str, ...]:
        """Aliases mapping to this provider."""

    @property
    @abstractmethod
    def default_env_var(self) -> str:
        """Default environment variable for provider API key."""

    def format_model_name(self, model: str, base_url: str | None = None) -> str:
        """Format ARKA model identifier into LiteLLM format."""
        prefix = f"{self.provider_name}/"
        if model.startswith(prefix):
            return model
        if "/" in model:
            return model
        return f"{prefix}{model}"

    def get_capabilities(self, model: str) -> ModelCapabilities:
        """Resolve capabilities for this provider and model."""
        return resolve_model_capabilities(self.provider_name, model)

    def build_litellm_params(self, profile: LLMProfile) -> dict[str, Any]:
        """Construct litellm parameters dict for this provider profile."""
        api_key = profile.api_key.get_secret_value() if profile.api_key else ""
        formatted_model = self.format_model_name(profile.model, profile.base_url)

        params: dict[str, Any] = {
            "model": formatted_model,
            "api_key": api_key,
            "timeout": float(profile.timeout),
        }
        if profile.base_url:
            base_url = profile.base_url.rstrip("/")
            if base_url.endswith("/chat/completions"):
                base_url = base_url[: -len("/chat/completions")]
            params["api_base"] = base_url

        return params

    def normalize_error(self, exc: Exception, provider: str, model: str) -> LLMGatewayError:
        """Translate provider and LiteLLM exceptions into structured LLMGatewayError."""
        if isinstance(exc, LLMGatewayError):
            return exc
        if isinstance(exc, AuthenticationError):
            return LLMGatewayError(
                f"Authentication failed for provider '{provider}'",
                provider=provider,
                model=model,
                status_code=401,
                retryable=False,
            )
        if isinstance(exc, ContextWindowExceededError):
            return LLMGatewayError(
                f"Context window exceeded for model '{model}'",
                provider=provider,
                model=model,
                status_code=400,
                retryable=False,
            )
        if isinstance(exc, RateLimitError):
            return LLMGatewayError(
                f"Rate limit exceeded for provider '{provider}'",
                provider=provider,
                model=model,
                status_code=429,
                retryable=True,
            )
        if isinstance(exc, (Timeout, TimeoutError)):
            return LLMGatewayError(
                f"Request timed out for provider '{provider}'",
                provider=provider,
                model=model,
                status_code=504,
                retryable=True,
            )
        if isinstance(exc, (APIConnectionError, ServiceUnavailableError)):
            return LLMGatewayError(
                f"Provider '{provider}' is unavailable",
                provider=provider,
                model=model,
                status_code=503,
                retryable=True,
            )
        if isinstance(exc, ContentPolicyViolationError):
            return LLMGatewayError(
                f"Content policy violation from provider '{provider}'",
                provider=provider,
                model=model,
                status_code=400,
                retryable=False,
            )
        if isinstance(exc, APIError):
            status = getattr(exc, "status_code", 500)
            retryable = status in (429, 500, 502, 503, 504)
            return LLMGatewayError(
                f"API error from provider '{provider}': {exc}",
                provider=provider,
                model=model,
                status_code=status,
                retryable=retryable,
            )

        return LLMGatewayError(
            f"Unexpected error from provider '{provider}': {exc}",
            provider=provider,
            model=model,
            status_code=500,
            retryable=False,
        )
