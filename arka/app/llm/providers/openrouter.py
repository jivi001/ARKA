"""OpenRouter provider adapter."""

from arka.app.llm.providers.base import BaseProviderAdapter


class OpenRouterAdapter(BaseProviderAdapter):
    """Adapter for OpenRouter models (including NVIDIA Nemotron via OpenRouter)."""

    @property
    def provider_name(self) -> str:
        return "openrouter"

    @property
    def supported_aliases(self) -> tuple[str, ...]:
        return ("openrouter",)

    @property
    def default_env_var(self) -> str:
        return "OPENROUTER_API_KEY"

    def format_model_name(self, model: str, base_url: str | None = None) -> str:
        if model.startswith("openrouter/"):
            return model
        return f"openrouter/{model}"
