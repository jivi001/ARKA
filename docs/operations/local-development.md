# Local Development Workflow

This guide covers setting up ARKA for local development and running quality checks.

---

## 1. Prerequisites

- Python 3.13+
- `uv` (recommended package manager) or standard `pip`
- Docker & Docker Compose (for local PostgreSQL & Redis)

---

## 2. Setup Instructions

```bash
# 1. Clone repository
git clone <repository_url>
cd ARKA

# 2. Set up virtual environment and install dependencies
uv sync

# 3. Configure environment
cp .env.example .env

# 4. Start local backing services (PostgreSQL & Redis)
docker compose -f docker/docker-compose.yml up -d postgres redis

# 5. Run database migrations
uv run alembic upgrade head

# 6. Start the API server
uv run uvicorn arka.app.api:app --reload --port 8000
```

---

## 3. Running Verification Gates

```bash
# Run all tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=arka --cov-report=term-missing

# Linting
uv run ruff check .

# Formatting check
uv run ruff format --check .

# Static type checking
uv run mypy
```
