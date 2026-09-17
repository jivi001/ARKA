"""DeepSeek provider adapter."""

from arka.app.llm.providers.base import BaseProviderAdapter


class DeepSeekAdapter(BaseProviderAdapter):
    """Adapter for DeepSeek models."""

    @property
    def provider_name(self) -> str:
        return "deepseek"

    @property
    def supported_aliases(self) -> tuple[str, ...]:
        return ("deepseek",)

    @property
    def default_env_var(self) -> str:
        return "DEEPSEEK_API_KEY"

    def format_model_name(self, model: str, base_url: str | None = None) -> str:
        if model.startswith("deepseek/"):
            return model
        return f"deepseek/{model}"
