# LLM Providers Configuration

This document describes configuring and managing primary and fallback LLM providers in ARKA.

---

## 1. Supported Providers

ARKA integrates with external and private model providers via **LiteLLM**:

| Provider Enum | Identifier (`ARKA_LLM_PROVIDER`) | Recommended Models | Environment Variable Prefix |
|---|---|---|---|
| `LLMProvider.OPENAI` | `openai` | `gpt-4o`, `gpt-4o-mini`, `o1-mini` | `OPENAI_API_KEY` or `ARKA_LLM_API_KEY` |
| `LLMProvider.ANTHROPIC` | `anthropic` | `claude-3-5-sonnet-20240620`, `claude-3-haiku` | `ANTHROPIC_API_KEY` or `ARKA_LLM_API_KEY` |
| `LLMProvider.GOOGLE` | `google` | `gemini-1.5-pro`, `gemini-1.5-flash` | `GEMINI_API_KEY` or `ARKA_LLM_API_KEY` |
| `LLMProvider.NVIDIA` | `nvidia` | `meta/llama-3-70b-instruct`, `mistralai/mixtral-8x22b-instruct` | `NVIDIA_API_KEY` or `ARKA_LLM_API_KEY` |
| `LLMProvider.KIMI` | `kimi` | `moonshot-v1-8k`, `moonshot-v1-32k` | `MOONSHOT_API_KEY` or `ARKA_LLM_API_KEY` |
| `LLMProvider.CUSTOM` | `custom` | Any OpenAI-compatible local/VPC endpoint (vLLM, Ollama, TGI) | `ARKA_LLM_BASE_URL` + `ARKA_LLM_API_KEY` |

---

## 2. Configuration Example

### Primary and Fallback Configuration in `.env`

```ini
# Primary Provider (e.g. OpenAI GPT-4o)
ARKA_LLM_PROVIDER=openai
ARKA_LLM_MODEL=gpt-4o
ARKA_LLM_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxx
ARKA_LLM_TIMEOUT=30
ARKA_LLM_MAX_RETRIES=3

# Optional Fallback Provider (e.g. Anthropic Claude 3.5 Sonnet)
ARKA_LLM_FALLBACK_PROVIDER=anthropic
ARKA_LLM_FALLBACK_MODEL=claude-3-5-sonnet-20240620
ARKA_LLM_FALLBACK_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxx
```

---

## 3. CLI Provider Verification

Verify active provider configurations from the CLI:

```bash
# List configured providers and status
arka provider list

# Test provider connectivity and latency
arka provider test --prompt "ping"
```
