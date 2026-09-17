"""Model capability abstraction for ARKA."""

from pydantic import BaseModel, Field


class ModelCapabilities(BaseModel):
    """Capabilities supported by a specific LLM model."""

    chat: bool = True
    structured_output: bool = True
    tool_calling: bool = False
    json_mode: bool = True
    streaming: bool = True
    vision: bool = False
    reasoning: bool = False
    metadata: dict[str, bool] = Field(default_factory=dict)


# Known model capability heuristics based on model family / identifiers
_VISION_PATTERNS = (
    "gpt-4o",
    "gpt-4-turbo",
    "claude-3",
    "gemini-1.5",
    "gemini-2",
    "vl",
    "vision",
    "pixtral",
)

_REASONING_PATTERNS = (
    "o1",
    "o3",
    "deepseek-reasoner",
    "deepseek-r1",
    "nemotron",
    "qwq",
    "reasoner",
    "thinking",
)

_TOOL_CALLING_PATTERNS = (
    "gpt-4",
    "gpt-3.5-turbo",
    "claude-3",
    "gemini-1.5",
    "gemini-2",
    "llama-3",
    "deepseek-chat",
    "mistral",
)


def resolve_model_capabilities(provider: str, model: str) -> ModelCapabilities:
    """Resolve capabilities specifically for a given provider and model.

    Capabilities are primarily model-specific rather than blindly assumed per provider.
    """
    model_lower = model.lower()

    has_vision = any(pat in model_lower for pat in _VISION_PATTERNS)
    has_reasoning = any(pat in model_lower for pat in _REASONING_PATTERNS)
    has_tool_calling = any(pat in model_lower for pat in _TOOL_CALLING_PATTERNS)

    # Some reasoning models (like early o1-preview) had json_mode or tool_calling restrictions
    supports_json = True
    if "o1-mini" in model_lower or "o1-preview" in model_lower:
        supports_json = False

    return ModelCapabilities(
        chat=True,
        structured_output=supports_json,
        tool_calling=has_tool_calling,
        json_mode=supports_json,
        streaming=True,
        vision=has_vision,
        reasoning=has_reasoning,
    )
