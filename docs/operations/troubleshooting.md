# Troubleshooting & Diagnostics

This document provides diagnosis procedures and solutions for common operational issues.

---

## 1. Common Failure Modes & Solutions

### 1. Database Connection Refused (`WinError 1225` / `Connection refused`)
- **Cause**: PostgreSQL is not running or listening on port 5432.
- **Solution**: Start PostgreSQL via `docker compose -f docker/docker-compose.yml up -d postgres` or verify `DATABASE_URL` in `.env`.

### 2. LLM Gateway Error: `503 LLM Gateway not configured`
- **Cause**: `ARKA_LLM_API_KEY` is not set or empty.
- **Solution**: Export `ARKA_LLM_API_KEY` or set it in your `.env` file.

### 3. LiteLLM Routing Error: `BadRequestError: LLM Provider NOT provided`
- **Cause**: The model string lacks an explicit provider prefix (e.g. `gpt-4o` instead of `openai/gpt-4o`).
- **Solution**: Ensure requests go through `LLMGateway._get_model_string()`, which automatically attaches the correct prefix.

### 4. Graph Execution Paused / Waiting
- **Cause**: The proposed action triggered a high-risk policy check and entered LangGraph `interrupt()`.
- **Solution**: Query `GET /approvals` or run `arka audit <id>` to inspect the pending approval ID, then approve or reject the request via the API or CLI.
