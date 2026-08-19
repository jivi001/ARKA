# ADR-001: API-First LLM Architecture via LiteLLM

## Status
Accepted

## Context
ARKA requires integration with diverse state-of-the-art Large Language Models (OpenAI, Anthropic Claude, Google Gemini, Nvidia NIM, and private self-hosted vLLM/Ollama endpoints). Binding agent logic directly to vendor-specific SDKs creates tight coupling, increases maintenance overhead, and complicates fallback routing.

## Decision
We adopt **LiteLLM** as the provider-neutral routing engine encapsulated within an internal `LLMGateway` (`arka/app/llm/gateway/gateway.py`). All agent interactions with language models must pass through `LLMGateway.complete()`.

## Alternatives Considered
1. **LangChain LLM Wrappers**: Heavyweight, frequent breaking changes, and redundant with our direct LangGraph integration.
2. **Direct Vendor SDKs (`openai`, `anthropic`)**: High maintenance burden, duplicate retry/error-handling logic, and difficult fallback routing.

## Consequences
- **Positive**: Single unified completion contract (`LLMRequest` / `LLMResponse`), automated fallback routing on 429/503 errors, consistent token/cost accounting, and centralized secret masking.
- **Negative**: Adds LiteLLM as an external dependency; requires maintaining prefix mappings for vendor routing.

## Security Implications
API keys are managed via Pydantic `SecretStr` and never exposed in error messages or logs. Fallback requests are scrubbed of vendor-specific headers.

## Date
2026-08-19
