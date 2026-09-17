"""Groq provider adapter."""

from arka.app.llm.providers.base import BaseProviderAdapter


class GroqAdapter(BaseProviderAdapter):
    """Adapter for Groq models."""

    @property
    def provider_name(self) -> str:
        return "groq"

    @property
    def supported_aliases(self) -> tuple[str, ...]:
        return ("groq",)

    @property
    def default_env_var(self) -> str:
        return "GROQ_API_KEY"

    def format_model_name(self, model: str, base_url: str | None = None) -> str:
        if model.startswith("groq/"):
            return model
        return f"groq/{model}"
