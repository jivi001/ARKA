"""LLM provider adapters and registry for ARKA Universal LLM Subsystem."""

from arka.app.llm.providers.anthropic import AnthropicAdapter
from arka.app.llm.providers.base import BaseProviderAdapter, LLMGatewayError
from arka.app.llm.providers.deepseek import DeepSeekAdapter
from arka.app.llm.providers.gemini import GeminiAdapter
from arka.app.llm.providers.groq import GroqAdapter
from arka.app.llm.providers.nvidia import NVIDIAAdapter
from arka.app.llm.providers.openai import OpenAIAdapter
from arka.app.llm.providers.openrouter import OpenRouterAdapter
from arka.app.llm.providers.registry import ProviderRegistry, UnknownProviderError

__all__ = [
    "AnthropicAdapter",
    "BaseProviderAdapter",
    "DeepSeekAdapter",
    "GeminiAdapter",
    "GroqAdapter",
    "LLMGatewayError",
    "NVIDIAAdapter",
    "OpenAIAdapter",
    "OpenRouterAdapter",
    "ProviderRegistry",
    "UnknownProviderError",
]
