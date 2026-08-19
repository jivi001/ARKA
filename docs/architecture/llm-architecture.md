# LLM Architecture

ARKA uses a provider-neutral **LLM Gateway** built on **LiteLLM** to decouple agent logic from external AI model vendors.

---

## 1. Design Principles

1. **Provider Neutrality**: Agent implementations never import vendor SDKs (`openai`, `anthropic`, `google.generativeai`) directly. All calls go through `LLMGateway` (`arka/app/llm/gateway/gateway.py`).
2. **Automatic Fallback Routing**: If the primary provider experiences rate limits (429) or outages (503), the gateway routes requests to a configured secondary provider.
3. **Strict Secret Masking**: API keys, bearer tokens, and credentials are encapsulated in Pydantic `SecretStr` objects and never leaked to logs or audit records.
4. **Token & Cost Accounting**: Prompt tokens, completion tokens, latency (ms), and estimated USD cost are tracked for every invocation.

---

## 2. LLM Gateway Pipeline

```mermaid
flowchart LR
    Agent[Agent / Orchestrator] -->|LLMRequest| Gateway[LLMGateway]
    
    subgraph Router["LiteLLM Router"]
        Primary["Primary Provider\n(e.g., OpenAI / GPT-4o)"]
        Fallback["Fallback Provider\n(e.g., Anthropic / Claude)"]
    end
    
    Gateway --> Router
    Primary -.->|429 / 503 / Timeout| Fallback
    
    Router --> Normalizer[Error Normalization & Token Accounting]
    Normalizer --> Audit[AuditService (Secret-Redacted)]
    Normalizer -->|LLMResponse| Agent
```

---

## 3. Provider Mapping Reference

`LLMGateway._get_model_string()` maps internal `LLMProvider` enums to explicit LiteLLM prefixes:

| Internal Provider Enum | LiteLLM Prefix | Example Configured Model | Routed Model String |
|---|---|---|---|
| `LLMProvider.OPENAI` | `openai/` | `gpt-4o` | `openai/gpt-4o` |
| `LLMProvider.ANTHROPIC` | `anthropic/` | `claude-3-5-sonnet` | `anthropic/claude-3-5-sonnet` |
| `LLMProvider.GOOGLE` | `gemini/` | `gemini-1.5-pro` | `gemini/gemini-1.5-pro` |
| `LLMProvider.NVIDIA` | `nvidia_nim/` | `meta/llama-3-70b-instruct` | `nvidia_nim/meta/llama-3-70b-instruct` |
| `LLMProvider.KIMI` | `openai/` | `moonshot-v1-8k` | `openai/moonshot-v1-8k` |
| `LLMProvider.CUSTOM` | `openai/` | `custom-model` | `openai/custom-model` |

---

## 4. Error Normalization & Status Mapping

All provider-specific exceptions are caught and transformed into a unified `LLMGatewayError`:

| Vendor Error Scenario | Normalized Status Code | Retryable Flag |
|---|:---:|:---:|
| Invalid API Key / Authentication Failed | `401` | `False` |
| Rate Limit Exceeded / Quota Exhausted | `429` | `True` |
| Provider Unavailable / Bad Gateway / Connection Error | `503` | `True` |
| Gateway Timeout (`timeout_seconds` reached) | `504` | `True` |
| Context Window Exceeded | `400` | `False` |
| Content Policy / Guardrail Violation | `400` | `False` |
| Unknown API Error | `500` (or upstream status) | `False` |
