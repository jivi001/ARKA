from enum import Enum

from pydantic import SecretStr
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
    CUSTOM = "custom"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

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

    @property
    def is_production(self) -> bool:
        return self.arka_env == Environment.PRODUCTION

    @property
    def is_testing(self) -> bool:
        return self.arka_env == Environment.TESTING
