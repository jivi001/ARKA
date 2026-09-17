"""Unit tests for Universal LLM Provider adapters, registry, and capabilities."""

import pytest
from pydantic import SecretStr

from arka.app.core.config.settings import LLMProvider, Settings
from arka.app.llm.providers.registry import ProviderRegistry, UnknownProviderError
from arka.app.llm.schemas.capabilities import resolve_model_capabilities
from arka.app.llm.schemas.profile import LLMProfile


class TestProviderRegistryAndResolution:
    @pytest.mark.parametrize(
        ("input_alias", "expected_canonical"),
        [
            ("openai", "openai"),
            ("OpenAI", "openai"),
            ("anthropic", "anthropic"),
            ("claude", "anthropic"),
            ("Claude", "anthropic"),
            ("openrouter", "openrouter"),
            ("OpenRouter", "openrouter"),
            ("groq", "groq"),
            ("Groq", "groq"),
            ("nvidia", "nvidia"),
            ("nvidia-api", "nvidia"),
            ("nvidia_nim", "nvidia"),
            ("deepseek", "deepseek"),
            ("DeepSeek", "deepseek"),
            ("gemini", "gemini"),
            ("Gemini", "gemini"),
            ("google", "gemini"),
            ("google-gemini", "gemini"),
            ("google_gemini", "gemini"),
        ],
    )
    def test_provider_name_normalization(self, input_alias: str, expected_canonical: str):
        resolved = ProviderRegistry.normalize_provider_name(input_alias)
        assert resolved == expected_canonical
        assert ProviderRegistry.is_supported(input_alias) is True

    def test_unknown_provider_raises_typed_error(self):
        with pytest.raises(UnknownProviderError, match="Unknown LLM provider: 'foobar'"):
            ProviderRegistry.resolve("foobar")

        assert ProviderRegistry.is_supported("foobar") is False

    def test_empty_provider_raises_typed_error(self):
        with pytest.raises(UnknownProviderError):
            ProviderRegistry.normalize_provider_name("")

    def test_list_supported_contains_all_seven_providers(self):
        supported = ProviderRegistry.list_supported()
        expected = {"openai", "anthropic", "openrouter", "groq", "nvidia", "deepseek", "gemini"}
        assert expected.issubset(set(supported))


class TestModelFormatting:
    def test_openai_formatting(self):
        adapter = ProviderRegistry.resolve("openai")
        assert adapter.format_model_name("gpt-4o") == "openai/gpt-4o"
        assert adapter.format_model_name("openai/gpt-4o") == "openai/gpt-4o"

    def test_anthropic_formatting(self):
        adapter = ProviderRegistry.resolve("anthropic")
        assert adapter.format_model_name("claude-3-5-sonnet") == "anthropic/claude-3-5-sonnet"
        assert adapter.format_model_name("anthropic/claude-3-opus") == "anthropic/claude-3-opus"

    def test_openrouter_formatting(self):
        adapter = ProviderRegistry.resolve("openrouter")
        assert (
            adapter.format_model_name("nvidia/nemotron-3-ultra-550b-a55b:free")
            == "openrouter/nvidia/nemotron-3-ultra-550b-a55b:free"
        )
        assert (
            adapter.format_model_name("openrouter/meta-llama/llama-3-70b")
            == "openrouter/meta-llama/llama-3-70b"
        )

    def test_groq_formatting(self):
        adapter = ProviderRegistry.resolve("groq")
        assert (
            adapter.format_model_name("llama-3.3-70b-versatile") == "groq/llama-3.3-70b-versatile"
        )
        assert adapter.format_model_name("groq/mixtral-8x7b-32768") == "groq/mixtral-8x7b-32768"

    def test_nvidia_formatting(self):
        adapter = ProviderRegistry.resolve("nvidia")
        assert (
            adapter.format_model_name("meta/llama-3.1-70b-instruct")
            == "nvidia_nim/meta/llama-3.1-70b-instruct"
        )
        assert (
            adapter.format_model_name("nvidia_nim/nemotron-4-340b") == "nvidia_nim/nemotron-4-340b"
        )

    def test_deepseek_formatting(self):
        adapter = ProviderRegistry.resolve("deepseek")
        assert adapter.format_model_name("deepseek-chat") == "deepseek/deepseek-chat"
        assert (
            adapter.format_model_name("deepseek/deepseek-reasoner") == "deepseek/deepseek-reasoner"
        )

    def test_gemini_formatting(self):
        adapter = ProviderRegistry.resolve("gemini")
        assert adapter.format_model_name("gemini-1.5-pro") == "gemini/gemini-1.5-pro"
        assert adapter.format_model_name("gemini/gemini-1.5-flash") == "gemini/gemini-1.5-flash"


class TestModelCapabilitiesResolution:
    def test_vision_capabilities_detected(self):
        caps_gpt4o = resolve_model_capabilities("openai", "gpt-4o")
        assert caps_gpt4o.vision is True
        assert caps_gpt4o.tool_calling is True

        caps_claude = resolve_model_capabilities("anthropic", "claude-3-5-sonnet")
        assert caps_claude.vision is True

        caps_gemini = resolve_model_capabilities("gemini", "gemini-1.5-pro")
        assert caps_gemini.vision is True

    def test_reasoning_capabilities_detected(self):
        caps_o1 = resolve_model_capabilities("openai", "o1-preview")
        assert caps_o1.reasoning is True

        caps_deepseek_r1 = resolve_model_capabilities("deepseek", "deepseek-reasoner")
        assert caps_deepseek_r1.reasoning is True

        caps_nemotron = resolve_model_capabilities(
            "openrouter", "nvidia/nemotron-3-ultra-550b-a55b:free"
        )
        assert caps_nemotron.reasoning is True

    def test_standard_model_without_vision_or_reasoning(self):
        caps = resolve_model_capabilities("groq", "llama-3-8b-instruct")
        assert caps.chat is True
        assert caps.structured_output is True
        assert caps.vision is False
        assert caps.reasoning is False


class TestProviderConfigurationAndSettings:
    def test_valid_profile_creation(self):
        profile = LLMProfile(
            provider="openai",
            model="gpt-4o",
            api_key=SecretStr("sk-openai-test"),
            timeout=45,
            temperature=0.2,
            max_tokens=1000,
        )
        assert profile.provider == "openai"
        assert profile.model == "gpt-4o"
        assert profile.timeout == 45
        assert profile.temperature == 0.2
        assert profile.max_tokens == 1000
        assert profile.capabilities is not None
        assert profile.capabilities.vision is True

    def test_invalid_temperature_rejected(self):
        with pytest.raises(ValueError):
            LLMProfile(provider="openai", model="gpt-4o", temperature=2.5)

        with pytest.raises(ValueError):
            LLMProfile(provider="openai", model="gpt-4o", temperature=-0.1)

    def test_invalid_timeout_rejected(self):
        with pytest.raises(ValueError):
            LLMProfile(provider="openai", model="gpt-4o", timeout=0)

    def test_provider_specific_key_resolution(self):
        # When primary provider is openrouter, only openrouter gets arka_llm_api_key
        settings = Settings(
            arka_llm_provider=LLMProvider.OPENROUTER,
            arka_llm_model="nvidia/nemotron-3-ultra-550b-a55b:free",
            arka_llm_api_key=SecretStr("sk-openrouter-key-999"),
            openai_api_key=SecretStr("sk-openai-key-111"),
            anthropic_api_key=None,
        )

        assert (
            settings.get_effective_llm_api_key("openrouter").get_secret_value()
            == "sk-openrouter-key-999"
        )
        assert (
            settings.get_effective_llm_api_key("openai").get_secret_value() == "sk-openai-key-111"
        )
        assert settings.get_effective_llm_api_key("anthropic").get_secret_value() == ""
        assert settings.get_effective_llm_api_key("groq").get_secret_value() == ""

    def test_nested_fallbacks_in_profile(self):
        fb1 = LLMProfile(
            provider="groq",
            model="llama-3.3-70b-versatile",
            api_key=SecretStr("gsk-test"),
        )
        fb2 = LLMProfile(
            provider="deepseek",
            model="deepseek-chat",
            api_key=SecretStr("dsk-test"),
        )
        primary = LLMProfile(
            provider="openrouter",
            model="nvidia/nemotron-3-ultra-550b-a55b:free",
            api_key=SecretStr("sk-or-test"),
            fallbacks=[fb1, fb2],
        )
        assert len(primary.fallbacks) == 2
        assert primary.fallbacks[0].provider == "groq"
        assert primary.fallbacks[1].provider == "deepseek"
