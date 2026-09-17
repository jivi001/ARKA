# Universal LLM Subsystem & Gateway

The **LLMGateway** (`arka/app/llm/gateway/gateway.py`) is ARKA's provider-neutral abstraction interface for all large language model interactions.

---

## 1. Architectural Philosophy & Security Invariant

> **The LLM is an untrusted reasoning engine and has ZERO authorization or execution authority.**

Under no circumstances can an LLM response bypass or grant execution permission. All candidate proposals must pass through the authoritative chain:

```
LLM Output
  ↓
CandidateToolRequest (Untrusted)
  ↓
ToolRegistry (Schema & Allowed Tool Enforcement)
  ↓
ScopeGuard (Inclusion/Exclusion Validation)
  ↓
PolicyEngine (Authoritative Risk Evaluation)
  ↓
ApprovalManager (Human-in-the-loop Gate if Risk >= High)
  ↓
ExecutionManager (Isolated Container Sandbox)
```

---

## 2. Universal Provider Architecture

ARKA natively supports seven production LLM providers via a unified `LLMProfile` abstraction and LiteLLM routing engine:

1. **OpenAI** (`openai/`) — GPT-4o, GPT-4o-mini, o1, o3-mini
2. **Anthropic / Claude** (`anthropic/`) — Claude 3.5 Sonnet, Claude 3.7 Sonnet, Claude 3 Haiku
3. **OpenRouter** (`openrouter/`) — Multi-provider aggregator; regression anchor for **NVIDIA Nemotron 3 Ultra**
4. **Groq** (`groq/`) — Llama 3.3 70B, Mixtral 8x7B
5. **NVIDIA API / NIM** (`nvidia_nim/`) — Nemotron-4 340B, Llama 3.1 70B Instruct
6. **DeepSeek** (`deepseek/`) — DeepSeek V3, DeepSeek R1
7. **Google Gemini** (`gemini/`) — Gemini 1.5 Pro, Gemini 1.5 Flash, Gemini 2.0 Flash

### Provider Aliases
The gateway recognizes canonical aliases (e.g., `claude` -> `anthropic`, `google` -> `gemini`, `nvidia-api` -> `nvidia`).

---

## 3. SSRF Protection & Endpoint Hardening

To prevent Server-Side Request Forgery (SSRF) and metadata service exfiltration, all custom `base_url` endpoints are validated at profile instantiation time by `validate_llm_endpoint` (`arka/app/llm/security/ssrf.py`):

- **Blocked Schemes**: Only `https://` (and `http://` in explicit non-production/test environments) are permitted.
- **Blocked IP Ranges**:
  - Loopback: `127.0.0.0/8`, `::1`
  - RFC 1918 Private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - Link-Local: `169.254.0.0/16`, `fe80::/10`
  - Unique Local: `fc00::/7`
- **Blocked Cloud Metadata Endpoints**:
  - AWS/GCP/Azure link-local: `169.254.169.254`
  - Google metadata hostname: `metadata.google.internal`
  - Alibaba/Oracle metadata endpoints: `100.100.100.200`, `169.254.169.254`
- **Target Network Isolation**: LLM endpoints are strictly prevented from targeting engagement assessment subnets or private corporate infrastructure.

---

## 4. Model Capabilities

Capabilities (`vision`, `reasoning`, `tool_calling`, `json_mode`) are **model-specific**, not provider-generic. For example:
- `deepseek-chat` supports tool calling and JSON mode; `deepseek-reasoner` (R1) focuses on deep reasoning.
- `claude-3-5-sonnet` supports vision and tool calling.
- `nvidia/nemotron-3-ultra-550b-a55b:free` supports reasoning and JSON output.

Capabilities are resolved dynamically via `resolve_model_capabilities(provider, model)`.

---

## 5. Gateway Features & Invariants

1. **Nested Fallbacks**: `LLMProfile` supports an ordered list of fallback profiles (`fallbacks: list[LLMProfile]`). When the primary provider encounters a rate limit (429) or transient outage (503), LiteLLM seamlessly cascades to the next configured fallback.
2. **Opt-in Sanitized Raw Responses**: Persistent `LLMResponse` does not store `raw_response` by default. When explicitly requested with `include_raw=True`, secrets (`api_key`, `token`, `auth`, `secret`, `cookie`) are recursively scrubbed before returning.
3. **Deterministic Provider Status**:
   - `SUPPORTED`: Valid provider name known to ARKA.
   - `CONFIGURED`: API key and valid profile credentials present in environment.
   - `ACTIVE`: The currently selected primary provider in configuration.
   - `AVAILABLE`: Configured fallback provider ready for traffic.
4. **Token-Free Health Checks**: `gateway.health_check(check_connectivity=False)` inspects local configuration and capabilities without sending API ping requests, avoiding unnecessary token spend.

---

## 6. CLI Management

Inspect and manage providers using the `arka llm` CLI:

```bash
# List supported and active providers
uv run arka llm providers

# View active configuration without credentials
uv run arka llm config

# Test LLM completion safely
uv run arka llm test --prompt "Ping test"
```

---

## 7. REST Endpoints

- `GET /llm/providers`: Returns supported providers, configuration status, capabilities, and active role without leaking credentials.
- `GET /llm/status?check_connectivity=false`: Returns operational health, latency metrics, and profile metadata.
