"""Provider registry and resolution for ARKA Universal LLM subsystem."""

from typing import ClassVar

from arka.app.llm.providers.anthropic import AnthropicAdapter
from arka.app.llm.providers.base import BaseProviderAdapter
from arka.app.llm.providers.deepseek import DeepSeekAdapter
from arka.app.llm.providers.gemini import GeminiAdapter
from arka.app.llm.providers.groq import GroqAdapter
from arka.app.llm.providers.nvidia import NVIDIAAdapter
from arka.app.llm.providers.openai import OpenAIAdapter
from arka.app.llm.providers.openrouter import OpenRouterAdapter
from arka.app.llm.schemas.capabilities import ModelCapabilities


class UnknownProviderError(ValueError):
    """Raised when an unrecognized LLM provider name is supplied."""


class ProviderRegistry:
    """Registry and resolver for LLM provider adapters."""

    _adapters: ClassVar[dict[str, BaseProviderAdapter]] = {}
    _alias_map: ClassVar[dict[str, str]] = {}

    @classmethod
    def _initialize_defaults(cls) -> None:
        if cls._adapters:
            return

        adapters: list[BaseProviderAdapter] = [
            OpenAIAdapter(),
            AnthropicAdapter(),
            OpenRouterAdapter(),
            GroqAdapter(),
            NVIDIAAdapter(),
            DeepSeekAdapter(),
            GeminiAdapter(),
        ]
        for adapter in adapters:
            cls.register(adapter)

    @classmethod
    def register(cls, adapter: BaseProviderAdapter) -> None:
        """Register a provider adapter and its supported aliases."""
        canonical = adapter.provider_name.lower().strip()
        cls._adapters[canonical] = adapter
        cls._alias_map[canonical] = canonical

        for alias in adapter.supported_aliases:
            norm_alias = cls._normalize_key(alias)
            cls._alias_map[norm_alias] = canonical

    @classmethod
    def _normalize_key(cls, name: str) -> str:
        """Normalize a provider identifier or alias."""
        return name.lower().strip().replace("_", "-")

    @classmethod
    def normalize_provider_name(cls, name: str) -> str:
        """Resolve a provider name or alias to its canonical name."""
        cls._initialize_defaults()
        if not name or not isinstance(name, str):
            raise UnknownProviderError("Provider name cannot be empty")

        key = cls._normalize_key(name)
        if key in cls._alias_map:
            return cls._alias_map[key]

        # Check raw stripped name
        raw_key = name.lower().strip()
        if raw_key in cls._adapters:
            return raw_key

        supported = sorted(cls.list_supported())
        raise UnknownProviderError(
            f"Unknown LLM provider: '{name}'. Supported providers: {', '.join(supported)}"
        )

    @classmethod
    def resolve(cls, name: str) -> BaseProviderAdapter:
        """Resolve a provider name or alias to its registered adapter."""
        canonical = cls.normalize_provider_name(name)
        return cls._adapters[canonical]

    @classmethod
    def is_supported(cls, name: str) -> bool:
        """Check if a provider name or alias is supported."""
        cls._initialize_defaults()
        try:
            cls.normalize_provider_name(name)
            return True
        except UnknownProviderError:
            return False

    @classmethod
    def list_supported(cls) -> list[str]:
        """Return the list of canonical supported provider names."""
        cls._initialize_defaults()
        return sorted(cls._adapters.keys())

    @classmethod
    def get_capabilities(cls, provider: str, model: str) -> ModelCapabilities:
        """Resolve model capabilities via the appropriate provider adapter."""
        adapter = cls.resolve(provider)
        return adapter.get_capabilities(model)
