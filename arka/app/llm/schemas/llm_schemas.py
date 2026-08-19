"""
LLM request and response schemas.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from arka.app.core.state.models import new_id, utc_now


class ContentType(str, Enum):
    TEXT = "text"
    IMAGE = "image"
    HTML = "html"
    JSON_DATA = "json"
    TERMINAL_OUTPUT = "terminal_output"
    HTTP_RESPONSE = "http_response"


class MultimodalContent(BaseModel):
    """A piece of multimodal content for LLM input."""

    content_type: ContentType
    text: str | None = None
    media_url: str | None = None
    media_base64: str | None = None
    mime_type: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class LLMMessage(BaseModel):
    """A message in a conversation with the LLM."""

    role: str  # system, user, assistant
    content: str | list[MultimodalContent]
    name: str | None = None


class LLMRequest(BaseModel):
    """Request to the ARKA LLM Gateway."""

    request_id: str = Field(default_factory=new_id)
    engagement_id: str | None = None
    agent_id: str | None = None
    task_id: str | None = None
    provider: str | None = None  # override default
    model: str | None = None  # override default
    messages: list[LLMMessage]
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_tokens: int | None = None
    response_format: dict[str, Any] | None = None  # structured output schema
    timeout: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    requested_at: datetime = Field(default_factory=utc_now)


class TokenUsage(BaseModel):
    """Token usage from an LLM response."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float | None = None


class LLMResponse(BaseModel):
    """Response from the ARKA LLM Gateway."""

    response_id: str = Field(default_factory=new_id)
    request_id: str
    provider: str
    model: str
    content: str
    structured_output: dict[str, Any] | None = None
    usage: TokenUsage = Field(default_factory=TokenUsage)
    latency_ms: int = 0
    success: bool = True
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    responded_at: datetime = Field(default_factory=utc_now)
