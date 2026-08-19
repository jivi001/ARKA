# Configuration & Environment Variables

ARKA is configured using environment variables managed by Pydantic Settings (`arka/app/core/config.py`).

---

## 1. Environment Variables Reference

| Variable | Description | Default Value | Required | Sensitive |
|---|---|---|:---:|:---:|
| `DATABASE_URL` | Async PostgreSQL connection URI | `postgresql+asyncpg://arka:arka@localhost:5432/arka` | **Yes** | Yes |
| `DATABASE_SYNC_URL` | Sync PostgreSQL connection URI (for migrations) | `postgresql://arka:arka@localhost:5432/arka` | **Yes** | Yes |
| `REDIS_URL` | Redis server connection URI | `redis://localhost:6379/0` | **Yes** | No |
| `ARKA_ENV` | Application environment (`development`, `staging`, `production`) | `development` | No | No |
| `ARKA_LOG_LEVEL` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | `INFO` | No | No |
| `ARKA_DEBUG` | Debug mode toggle | `false` | No | No |
| `ARKA_LLM_PROVIDER` | Primary model vendor (`openai`, `anthropic`, `google`, `nvidia`, `custom`) | `openai` | **Yes** | No |
| `ARKA_LLM_MODEL` | Primary model identifier | `gpt-4o` | **Yes** | No |
| `ARKA_LLM_API_KEY` | Primary model API authentication key | `""` | **Yes** | **Yes** |
| `ARKA_LLM_BASE_URL` | Base URL for custom/VPC OpenAI-compatible endpoints | `""` | No | No |
| `ARKA_LLM_TIMEOUT` | Gateway completion timeout in seconds | `30` | No | No |
| `ARKA_LLM_MAX_RETRIES` | Maximum retry attempts for transient errors | `3` | No | No |
| `ARKA_LLM_FALLBACK_PROVIDER` | Secondary fallback model vendor | `""` | No | No |
| `ARKA_LLM_FALLBACK_MODEL` | Secondary fallback model identifier | `""` | No | No |
| `ARKA_LLM_FALLBACK_API_KEY` | Secondary fallback API key | `""` | No | **Yes** |
| `ARKA_LLM_FALLBACK_BASE_URL` | Base URL for fallback endpoint | `""` | No | No |
| `LANGFUSE_ENABLED` | Enable Langfuse LLM telemetry | `false` | No | No |
| `LANGFUSE_HOST` | Langfuse instance host URL | `""` | No | No |
| `LANGFUSE_PUBLIC_KEY` | Langfuse public API key | `""` | No | No |
| `LANGFUSE_SECRET_KEY` | Langfuse secret API key | `""` | No | **Yes** |
| `ARKA_SECRETS_BACKEND` | Secrets backend (`env` or `vault`) | `env` | No | No |
| `VAULT_ADDR` | HashiCorp Vault server address | `""` | No | No |
| `VAULT_TOKEN` | HashiCorp Vault authentication token | `""` | No | **Yes** |

---

## 2. Secrets Backend Architecture

- **`env` Backend**: Reads secrets directly from process environment or `.env` files.
- **`vault` Backend (`PLANNED` for Phase 2)**: Dynamically fetches credentials and API keys from HashiCorp Vault via AppRole authentication.
