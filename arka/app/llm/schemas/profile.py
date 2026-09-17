"""LLM profile abstraction for ARKA Universal LLM Provider Subsystem."""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator

from arka.app.llm.schemas.capabilities import (
    ModelCapabilities,
    resolve_model_capabilities,
)
from arka.app.llm.security.ssrf import validate_llm_endpoint


class LLMProfile(BaseModel):
    """Universal configuration profile for an LLM provider/model deployment.

    Encompasses credentials reference, model name, endpoint, timeouts,
    capabilities, and nested fallback profiles.
    """

    provider: str
    model: str
    api_key: SecretStr = Field(default_factory=lambda: SecretStr(""))
    base_url: str | None = None
    capabilities: ModelCapabilities | None = None
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, gt=0)
    timeout: int = Field(default=30, gt=0)
    max_retries: int = Field(default=3, ge=0)
    fallbacks: list[LLMProfile] = Field(default_factory=list)
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("provider", mode="before")
    @classmethod
    def validate_provider(cls, v: Any) -> str:
        if not v or not str(v).strip():
            raise ValueError("Provider name cannot be empty")
        return str(v).strip().lower()

    @field_validator("model", mode="before")
    @classmethod
    def validate_model(cls, v: Any) -> str:
        if not v or not str(v).strip():
            raise ValueError("Model name cannot be empty")
        return str(v).strip()

    @field_validator("base_url", mode="before")
    @classmethod
    def validate_endpoint(cls, v: Any) -> str | None:
        if not v or not str(v).strip():
            return None
        url_str = str(v).strip()
        # In test or dev mode, permit localhost/mock endpoints
        is_test_or_dev = (
            os.environ.get("ARKA_ENV", "").lower() in ("development", "testing")
            or os.environ.get("PYTEST_CURRENT_TEST") is not None
            or os.environ.get("ARKA_ALLOW_INSECURE_LLM_ENDPOINTS", "").lower() in ("1", "true")
        )
        return validate_llm_endpoint(
            url_str,
            allow_private=is_test_or_dev,
            allow_http=is_test_or_dev,
        )

    @model_validator(mode="after")
    def populate_capabilities_if_missing(self) -> LLMProfile:
        if self.capabilities is None:
            self.capabilities = resolve_model_capabilities(self.provider, self.model)
        return self
