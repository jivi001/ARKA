"""NVIDIA API provider adapter."""

from arka.app.llm.providers.base import BaseProviderAdapter


class NVIDIAAdapter(BaseProviderAdapter):
    """Adapter for NVIDIA API / NIM models."""

    @property
    def provider_name(self) -> str:
        return "nvidia"

    @property
    def supported_aliases(self) -> tuple[str, ...]:
        return ("nvidia", "nvidia-api", "nvidia_nim")

    @property
    def default_env_var(self) -> str:
        return "NVIDIA_API_KEY"

    def format_model_name(self, model: str, base_url: str | None = None) -> str:
        if model.startswith("nvidia_nim/"):
            return model
        if model.startswith("nvidia/"):
            # e.g. nvidia/nemotron-4-340b-instruct -> nvidia_nim/nvidia/nemotron-4-340b-instruct
            return f"nvidia_nim/{model}"
        return f"nvidia_nim/{model}"
