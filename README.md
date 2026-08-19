# ARKA — Autonomous Risk Knowledge & Assessment

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2+-orange.svg)](https://github.com/langchain-ai/langgraph)
[![License: Proprietary / Authorized](https://img.shields.io/badge/license-Authorized_Use_Only-red.svg)](LICENSE)
[![Tests: 137 Passing](https://img.shields.io/badge/tests-137%20passed%20(100%25)-brightgreen.svg)](tests/)
[![Coverage: 78%](https://img.shields.io/badge/coverage-78%25-green.svg)](tests/)

**ARKA** is an enterprise-grade AI-orchestrated autonomous penetration testing and risk assessment platform. It coordinates multi-agent reasoning, deterministic scoping, policy enforcement, human approval workflows, and isolated tool execution to evaluate the security posture of modern networks and applications.

---

> [!CAUTION]
> **LEGAL AND AUTHORIZED-USE NOTICE**
> 
> ARKA is designed **EXCLUSIVELY FOR AUTHORIZED SECURITY ASSESSMENTS**.
> 
> You must only run this software against systems and networks that you explicitly own or have documented, legal authorization to test (such as a signed Rules of Engagement or Statement of Work). Unauthorized scanning, penetration testing, or exploitation of computer systems is illegal and may violate local, national, and international cybercrime laws.

---

## Current Status & Roadmap

| Phase | Milestone | Status | Core Deliverables |
|---|---|:---:|---|
| **Phase 1** | **Secure Agent Control Plane** | **`IMPLEMENTED`** | Zero-trust LangGraph orchestrator, deterministic ScopeGuard, PolicyEngine, persistent PostgreSQL approvals, LiteLLM gateway, append-only audit, safe mock tools. |
| **Phase 2** | **Secure Tool Execution & Reconnaissance** | **`PLANNED`** | Ephemeral Docker runner, network namespace filtering, Nmap/Nuclei/ffuf adapters, structured output parsers, Reconnaissance Agent, asset normalization. |
| **Phase 3** | **Web/API Security Analysis** | **`PLANNED`** | Web crawling, OpenAPI/GraphQL schema fuzzing, authenticated session handling, business logic flaw detection, Web Security Agent. |
| **Phase 4** | **Controlled Exploitation & Validation** | **`PLANNED`** | PoC validation engine, strict human-in-the-loop exploit gating, non-destructive validation payloads, Exploitation Agent. |
| **Phase 5** | **Attack Graph & Autonomous Attack Paths** | **`PLANNED`** | Graph-based attack path modeling (Neo4j / NetworkX), multi-hop scenario planning, risk calculation, automated executive reporting. |
| **Phase 6** | **Advanced Multimodal & Enterprise** | **`PLANNED`** | UI/UX screenshot analysis, SSO/RBAC integration, SIEM event streaming, multi-tenant fleet orchestration. |

---

## Core Principles & Trust Model

The central invariant of ARKA's security architecture is: **The LLM is an untrusted reasoning engine and has ZERO authorization authority.**

```
LLM proposes
    ↓
CandidateToolRequest (untrusted)
    ↓
Deterministic validation & Input schema checking
    ↓
ScopeGuard (IPv4/IPv6/CIDR/Domain/URL/Port validation; exclusions override inclusions)
    ↓
PolicyEngine (Authoritative risk evaluation & single source of truth)
    ↓
ApprovalManager (if required; persistent PostgreSQL state machine with strict transition guards)
    ↓
Authoritative ToolRequest (trusted validation booleans stamped ONLY by security boundary)
    ↓
ToolRegistry (execution boundary, timeouts, exception safety)
    ↓
ToolResult
    ↓
Append-Only Audit Trail (immutable, secret-redacted, defensive copies)
```

- **Scope Exclusions Override Inclusions**: If any target matches an exclusion rule, it is immediately denied.
- **Persistent Human Gates**: Operations classified as `HIGH` or `CRITICAL` risk require explicit operator approval stored in PostgreSQL and bound to the exact operational context `(engagement_id, task_id, tool_name, target)`.
- **Append-Only Immutability**: All security actions produce an append-only audit record with credential sanitization and defensive memory copying.
- **Zero Real Offense in Tests**: Automated test suites operate 100% in-memory with safe mock tools, executing zero network scanning or subshell commands.

---

## Technology Stack

- **Core Runtime**: Python 3.13+
- **API Framework**: FastAPI & Pydantic v2
- **Agent Orchestration**: LangGraph (cyclical graphs, durable checkpoints, `interrupt()`)
- **LLM Gateway**: LiteLLM (OpenAI, Anthropic, Gemini, Nvidia NIM, custom endpoints, fallback routing)
- **Data Persistence**: PostgreSQL 16+ & SQLAlchemy 2.0 (asyncpg)
- **Schema Migrations**: Alembic
- **Task Queue & Cache**: Arq & Redis 7+
- **CLI Interface**: Typer & Rich
- **Observability**: Structlog & Langfuse
- **Quality Gates**: Pytest, Ruff, Mypy

---

## Quick Start & Installation

### 1. Prerequisites
- Python 3.13+
- `uv` (recommended) or `pip`
- Docker & Docker Compose (for PostgreSQL & Redis)

### 2. Setup
```bash
# Clone the repository
git clone <repository_url>
cd ARKA

# Install dependencies in virtual environment
uv sync

# Configure environment variables
cp .env.example .env
```

### 3. Start Supporting Infrastructure
```bash
# Start PostgreSQL and Redis via Docker
docker compose -f docker/docker-compose.yml up -d postgres redis

# Run database migrations
uv run alembic upgrade head
```

### 4. Launch Services
```bash
# Start the API server locally
uv run uvicorn arka.app.api:app --reload --port 8000

# Or start the entire platform in Docker
docker compose -f docker/docker-compose.yml up -d
```

---

## CLI Reference

The ARKA CLI (`arka`) provides full operational control over the platform:

```bash
# Check platform health and database connectivity
uv run arka health

# Manage LLM Providers
uv run arka provider list
uv run arka provider test --prompt "Ping test"

# Manage Engagements
uv run arka engagement create "Q3 Penetration Test" --objective "Assess perimeter and web assets"
uv run arka engagement start <engagement_id>
uv run arka engagement status <engagement_id>
uv run arka engagement pause <engagement_id>
uv run arka engagement stop <engagement_id>

# View Tasks & Audit Logs
uv run arka tasks <engagement_id>
uv run arka audit <engagement_id>
```

---

## REST API Overview

Interactive Swagger documentation is available at `http://localhost:8000/docs`.

Key endpoint groups:
- `GET /health`: Health and connectivity status.
- `POST /engagements`: Create an assessment with scope boundaries.
- `POST /engagements/{id}/start`: Launch orchestrator execution.
- `GET /approvals`: List pending human-in-the-loop authorization gates.
- `POST /approvals/{id}/decide`: Submit approval decision (`GRANTED` / `REJECTED`).
- `GET /engagements/{id}/audit`: Retrieve immutable audit events.

---

## Testing & Verification Baseline

Every commit is verified against rigorous automated quality gates:

```bash
# Run complete test suite (137 tests passing)
uv run pytest

# Run tests with coverage report (78% codebase line coverage)
uv run pytest --cov=arka --cov-report=term-missing

# Linting and formatting checks (Ruff)
uv run ruff check .
uv run ruff format --check .

# Static type checking (Mypy)
uv run mypy
```

---

## Documentation System

Complete, version-controlled documentation is maintained in the [`docs/`](docs/) directory:

- [Documentation Index](docs/README.md)
- [Architecture Overview](docs/architecture/overview.md)
- [System Architecture](docs/architecture/system-architecture.md)
- [Trust Boundaries & Authorization Model](docs/architecture/trust-boundaries.md)
- [Security Model](docs/security/security-model.md)
- [Scope Enforcement (ScopeGuard)](docs/security/scope-enforcement.md)
- [Persistent Approval System](docs/security/approval-system.md)
- [LLM Gateway & Routing](docs/llm/gateway.md)
- [Testing Strategy](docs/testing/strategy.md)
- [Phase 1 Verification Report](docs/phases/phase-1.md)
- [Phase 1 Hardening Log](docs/phases/phase-1-hardening.md)
- [Phase 2 Execution & Reconnaissance Plan](docs/phases/phase-2.md)
- [Architecture Decision Records (ADRs)](docs/decisions/)
