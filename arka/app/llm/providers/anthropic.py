"""Anthropic provider adapter."""

from arka.app.llm.providers.base import BaseProviderAdapter


class AnthropicAdapter(BaseProviderAdapter):
    """Adapter for Anthropic (Claude) models."""

    @property
    def provider_name(self) -> str:
        return "anthropic"

    @property
    def supported_aliases(self) -> tuple[str, ...]:
        return ("anthropic", "claude")

    @property
    def default_env_var(self) -> str:
        return "ANTHROPIC_API_KEY"

    def format_model_name(self, model: str, base_url: str | None = None) -> str:
        if model.startswith("anthropic/"):
            return model
        return f"anthropic/{model}"
