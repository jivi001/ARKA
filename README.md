# ARKA — Autonomous Risk Knowledge & Assessment

ARKA is an AI-driven autonomous penetration-testing platform designed to evaluate and enhance the security posture of modern systems.

**⚠️ WARNING: Use this tool ONLY on systems and networks you explicitly own or have documented, legal authorization to test. Unauthorized use of this software is strictly prohibited and may violate local, state, federal, or international laws.**

## Quick Start

### 1. Requirements
- Python 3.13+
- Docker and Docker Compose
- Node.js (for frontend in future phases)

### 2. Installation
Clone the repository and set up a virtual environment:

```bash
git clone <repository_url>
cd ARKA
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/Mac: source .venv/bin/activate
pip install -e ".[dev]"
```

### 3. Configuration
Copy `.env.example` to `.env` and configure your settings:

```bash
cp .env.example .env
```

### 4. Running the Platform

To start all services using Docker Compose:

```bash
cd docker
docker-compose up -d
```

To run the API server locally for development:

```bash
uvicorn arka.app.api:app --reload
```

## Architecture

ARKA is built using a modern async Python stack:
- **FastAPI**: High-performance API layer
- **Pydantic**: Type-safe configuration and schema validation
- **SQLAlchemy & Alembic**: Database ORM and migrations
- **PostgreSQL**: Primary relational data store
- **Redis & Arq**: Distributed caching and async task queues
- **LangGraph & LiteLLM**: Agentic workflows and LLM integrations

## CLI Reference

The ARKA CLI offers tools to manage the platform from the command line.

```bash
# Check API health
arka health

# Manage LLM Providers
arka provider list
arka provider test --prompt "Hello ARKA"

# Manage Engagements
arka engagement create "Initial Pentest"
arka engagement start <uuid>
arka engagement status <uuid>
arka engagement pause <uuid>
arka engagement stop <uuid>

# View Tasks & Audit Logs
arka tasks <uuid>
arka audit <uuid>
```

## API Reference
By default, the API is accessible at `http://localhost:8000`.
Check the Swagger documentation at `http://localhost:8000/docs` for the interactive API explorer.

## Development

- **Formatting & Linting**: ARKA uses `ruff` for code formatting and linting.
- **Type Checking**: Run `mypy .` to verify type hints.
- **Testing**: Tests are executed via `pytest`.

```bash
pytest
```

## Phase 1 Components

- Core setup with FastAPI, PostgreSQL, Redis
- Database Models for Engagements, Tasks, and Audit Logs
- LiteLLM integration for Model routing
- Typer-based Command Line Interface
- Distributed Task Execution using Arq
- Dockerized deployment setup

## Security Model

ARKA strictly enforces a deterministic operational model:
- **Least Privilege**: Components run with minimal required permissions. 
- **Immutable Auditing**: All actions are logged and verifiable.
- **No Direct Execution**: LLM output is parsed, validated, and sandboxed before execution.

