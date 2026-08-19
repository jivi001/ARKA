# Database Architecture

This document describes ARKA's PostgreSQL database layer, connection management, and pool configuration.

---

## 1. Engine & Connection Pooling

ARKA interacts with PostgreSQL using **SQLAlchemy 2.0 async engine** paired with the **asyncpg** driver (`arka/app/database/session.py`):

```python
def get_async_engine():
    settings = get_settings()
    return create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
```

- **Connection Pool**: Uses `QueuePool` with health checks (`pool_pre_ping=True`) to automatically discard disconnected sockets.
- **Session Factory**: `async_sessionmaker(..., expire_on_commit=False)` prevents lazy-loading race conditions across async tasks.
- **Dependency Injection**: FastAPI endpoints acquire scoped database sessions via `Depends(get_session)`.
