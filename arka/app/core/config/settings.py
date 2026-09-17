from enum import Enum
from typing import Any

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class SecretsBackend(str, Enum):
    ENV = "env"
    VAULT = "vault"


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    NVIDIA = "nvidia"
    KIMI = "kimi"
    OPENROUTER = "openrouter"
    GROQ = "groq"
    DEEPSEEK = "deepseek"
    GEMINI = "gemini"
    CUSTOM = "custom"


class WorkerBackendType(str, Enum):
    IN_PROCESS = "in_process"
    ARQ = "arq"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Worker Backend
    arka_worker_backend: WorkerBackendType | None = None

    # Database
    database_url: str = "postgresql+asyncpg://arka:arka@localhost:5432/arka"
    database_sync_url: str = "postgresql://arka:arka@localhost:5432/arka"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # LLM
    arka_llm_provider: LLMProvider = LLMProvider.OPENAI
    arka_llm_model: str = "gpt-4o"
    arka_llm_api_key: SecretStr = SecretStr("")
    arka_llm_base_url: str | None = None
    arka_llm_timeout: int = 30
    arka_llm_max_retries: int = 3

    # Provider-specific API keys (optional, used if arka_llm_api_key is unset)
    openai_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    openrouter_api_key: SecretStr | None = None
    groq_api_key: SecretStr | None = None
    nvidia_api_key: SecretStr | None = None
    deepseek_api_key: SecretStr | None = None
    gemini_api_key: SecretStr | None = None

    # Fallback LLM
    arka_llm_fallback_provider: LLMProvider | None = None
    arka_llm_fallback_model: str | None = None
    arka_llm_fallback_api_key: SecretStr | None = None
    arka_llm_fallback_base_url: str | None = None

    # Langfuse
    langfuse_host: str | None = None
    langfuse_public_key: str | None = None
    langfuse_secret_key: SecretStr | None = None
    langfuse_enabled: bool = False

    # Application
    arka_env: Environment = Environment.DEVELOPMENT
    arka_log_level: LogLevel = LogLevel.INFO
    arka_debug: bool = False

    # Secrets
    arka_secrets_backend: SecretsBackend = SecretsBackend.ENV
    vault_addr: str | None = None
    vault_token: SecretStr | None = None

    @field_validator(
        "arka_llm_fallback_provider",
        "arka_llm_fallback_model",
        "arka_llm_fallback_api_key",
        "arka_llm_fallback_base_url",
        "arka_llm_base_url",
        "langfuse_host",
        "langfuse_public_key",
        "langfuse_secret_key",
        "vault_addr",
        "vault_token",
        mode="before",
    )
    @classmethod
    def empty_str_to_none(cls, v: Any) -> Any:
        if v == "" or (isinstance(v, str) and not v.strip()):
            return None
        return v

    @property
    def is_production(self) -> bool:
        return self.arka_env == Environment.PRODUCTION

    @property
    def is_testing(self) -> bool:
        return self.arka_env == Environment.TESTING

    @property
    def resolved_worker_backend(self) -> WorkerBackendType:
        """Centralized worker backend resolution:
        - If explicitly set via ARKA_WORKER_BACKEND, use that value.
        - In production, default to ARQ.
        - Otherwise, default to IN_PROCESS for local development and tests.
        """
        if self.arka_worker_backend is not None:
            return self.arka_worker_backend
        if self.is_production:
            return WorkerBackendType.ARQ
        return WorkerBackendType.IN_PROCESS

    def get_effective_llm_api_key(self, provider: str | LLMProvider | None = None) -> SecretStr:
        """Resolve the effective API key for a provider.

        Precedence:
        1. If the requested provider matches primary arka_llm_provider and
           arka_llm_api_key is set -> arka_llm_api_key
        2. Provider-specific setting / env var (e.g. openai_api_key)
        3. If no specific provider was requested -> arka_llm_api_key
        4. Empty SecretStr
        """
        target_provider = provider or self.arka_llm_provider
        prov_name = (
            target_provider.value
            if isinstance(target_provider, LLMProvider)
            else str(target_provider)
        ).lower()

        primary_prov_name = self.arka_llm_provider.value.lower()

        # If this provider is the configured primary provider, arka_llm_api_key takes precedence
        if (prov_name == primary_prov_name or provider is None) and (
            self.arka_llm_api_key and self.arka_llm_api_key.get_secret_value()
        ):
            return self.arka_llm_api_key

        # If this provider is the configured fallback provider and fallback api key is set
        fallback_prov_name = (
            self.arka_llm_fallback_provider.value.lower()
            if self.arka_llm_fallback_provider
            else None
        )
        if prov_name == fallback_prov_name and (
            self.arka_llm_fallback_api_key and self.arka_llm_fallback_api_key.get_secret_value()
        ):
            return self.arka_llm_fallback_api_key

        provider_map: dict[str, SecretStr | None] = {
            "openai": self.openai_api_key,
            "anthropic": self.anthropic_api_key,
            "claude": self.anthropic_api_key,
            "openrouter": self.openrouter_api_key,
            "groq": self.groq_api_key,
            "nvidia": self.nvidia_api_key,
            "nvidia-api": self.nvidia_api_key,
            "nvidia_nim": self.nvidia_api_key,
            "deepseek": self.deepseek_api_key,
            "gemini": self.gemini_api_key,
            "google": self.gemini_api_key,
            "google-gemini": self.gemini_api_key,
        }

        key = provider_map.get(prov_name)
        if key and key.get_secret_value():
            return key

        return SecretStr("")

    def get_primary_llm_profile(self) -> Any:
        """Construct the active primary LLMProfile and fallback profiles from settings."""
        from arka.app.llm.schemas.profile import LLMProfile

        fallbacks: list[LLMProfile] = []
        if self.arka_llm_fallback_provider and self.arka_llm_fallback_model:
            fb_key = (
                self.arka_llm_fallback_api_key
                if self.arka_llm_fallback_api_key
                and self.arka_llm_fallback_api_key.get_secret_value()
                else self.get_effective_llm_api_key(self.arka_llm_fallback_provider)
            )
            fb_profile = LLMProfile(
                provider=self.arka_llm_fallback_provider.value,
                model=self.arka_llm_fallback_model,
                api_key=fb_key,
                base_url=self.arka_llm_fallback_base_url,
                timeout=self.arka_llm_timeout,
                max_retries=self.arka_llm_max_retries,
            )
            fallbacks.append(fb_profile)

        primary_key = self.get_effective_llm_api_key(self.arka_llm_provider)

        return LLMProfile(
            provider=self.arka_llm_provider.value,
            model=self.arka_llm_model,
            api_key=primary_key,
            base_url=self.arka_llm_base_url,
            timeout=self.arka_llm_timeout,
            max_retries=self.arka_llm_max_retries,
            fallbacks=fallbacks,
        )
