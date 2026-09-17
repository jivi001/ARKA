"""Google Gemini provider adapter."""

from arka.app.llm.providers.base import BaseProviderAdapter


class GeminiAdapter(BaseProviderAdapter):
    """Adapter for Google Gemini models."""

    @property
    def provider_name(self) -> str:
        return "gemini"

    @property
    def supported_aliases(self) -> tuple[str, ...]:
        return ("gemini", "google", "google-gemini")

    @property
    def default_env_var(self) -> str:
        return "GEMINI_API_KEY"

    def format_model_name(self, model: str, base_url: str | None = None) -> str:
        if model.startswith("gemini/"):
            return model
        return f"gemini/{model}"
