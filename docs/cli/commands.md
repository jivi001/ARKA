# Command-Line Interface (CLI) Reference

The ARKA CLI (`arka`) is built with **Typer** and **Rich** (`arka/app/cli/main.py`).

---

## 1. Global Commands

### `arka health`
Checks ARKA API server, PostgreSQL database, and Redis connectivity.

```bash
$ uv run arka health
[✓] API Server: Online (http://localhost:8000)
[✓] Database: Connected (PostgreSQL 16)
[✓] Redis: Connected
```

---

## 2. LLM Provider Commands (`arka provider`)

### `arka provider list`
Lists configured primary and fallback LLM model providers.

```bash
$ uv run arka provider list
╭──────────────────┬─────────────────┬──────────────────────┬──────────╮
│ Role             │ Provider        │ Model                │ Status   │
├──────────────────┼─────────────────┼──────────────────────┼──────────┤
│ Primary          │ openai          │ gpt-4o               │ ACTIVE   │
│ Fallback         │ anthropic       │ claude-3-5-sonnet    │ READY    │
╰──────────────────┴─────────────────┴──────────────────────┴──────────╯
```

### `arka provider test`
Sends a test prompt to verify connectivity and measure latency.

```bash
$ uv run arka provider test --prompt "Ping test"
[✓] Response received in 420ms (Tokens: 18, Cost: $0.00009)
```

---

## 3. Engagement Management Commands (`arka engagement`)

### `arka engagement create`
Creates a new engagement.

```bash
$ uv run arka engagement create "Q3 Audit" --objective "External assessment"
[✓] Engagement created successfully. ID: 123e4567-e89b-12d3-a456-426614174000
```

### `arka engagement start <id>`
Starts orchestrator workflow for an engagement.

```bash
$ uv run arka engagement start 123e4567-e89b-12d3-a456-426614174000
```

### `arka engagement status <id>`
Displays real-time status and task progress.

```bash
$ uv run arka engagement status 123e4567-e89b-12d3-a456-426614174000
```

### `arka engagement pause <id>` / `arka engagement stop <id>`
Pauses or terminates an active engagement.

---

## 4. Tasks & Audit Commands

### `arka tasks <engagement_id>`
Lists all executed and pending tasks for an engagement.

```bash
$ uv run arka tasks 123e4567-e89b-12d3-a456-426614174000
```

### `arka audit <engagement_id>`
Displays the sanitized audit trail in a formatted terminal table.

```bash
$ uv run arka audit 123e4567-e89b-12d3-a456-426614174000
```
