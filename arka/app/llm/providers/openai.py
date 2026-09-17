"""OpenAI provider adapter."""

from arka.app.llm.providers.base import BaseProviderAdapter


class OpenAIAdapter(BaseProviderAdapter):
    """Adapter for OpenAI models."""

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def supported_aliases(self) -> tuple[str, ...]:
        return ("openai",)

    @property
    def default_env_var(self) -> str:
        return "OPENAI_API_KEY"

    def format_model_name(self, model: str, base_url: str | None = None) -> str:
        if model.startswith("openai/"):
            return model
        return f"openai/{model}"
