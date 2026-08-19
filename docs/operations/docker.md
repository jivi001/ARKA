# Docker Deployment & Multi-Container Setup

ARKA provides Docker configurations for running the API server, async workers, and backing datastores in containerized environments.

---

## 1. Docker Compose Services (`docker/docker-compose.yml`)

The compose topology defines four isolated containers:

| Service | Image / Build | Port Mapping | Purpose |
|---|---|---|---|
| `arka-api` | Built from `Dockerfile` | `8000:8000` | FastAPI application server and REST endpoints. |
| `arka-worker` | Built from `Dockerfile` | N/A | Distributed Arq background worker. |
| `postgres` | `postgres:16-alpine` | `5432:5432` | Relational database and LangGraph state store. |
| `redis` | `redis:7-alpine` | `6379:6379` | Queue broker and cache. |

---

## 2. Docker Operations

```bash
# Start all containers in background
docker compose -f docker/docker-compose.yml up -d

# View real-time container logs
docker compose -f docker/docker-compose.yml logs -f arka-api

# Stop all containers
docker compose -f docker/docker-compose.yml down
```
