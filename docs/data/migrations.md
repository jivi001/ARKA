# Database Migrations Guide

ARKA uses **Alembic** for managing schema migrations against PostgreSQL.

---

## 1. Migration Revision History

| Revision ID | Name | Parent Revision | Description |
|---|---|---|---|
| `001_initial_schema` | `initial schema` | `<base>` | Initial creation of `engagements`, `tasks`, `approvals`, `audit_events`, `targets`, and `findings` tables. |
| `002_approval_fields` | `add approval fields` | `001_initial_schema` | Added `details` (JSONB), `rejection_reason` (String), and `correlation_id` (String) to `approvals` table. |

---

## 2. Running Migrations

```bash
# Check migration history
uv run alembic history

# Upgrade database to head revision
uv run alembic upgrade head

# Downgrade by one revision
uv run alembic downgrade -1

# Generate a new auto-detected migration
uv run alembic revision --autogenerate -m "description_of_change"
```

---

## 3. Migration Best Practices

1. **Always use async engines**: Ensure `migrations/env.py` runs migrations through `run_async_migrations()`.
2. **Deterministic column types**: Explicitly specify column sizes and JSONB data types rather than generic types.
3. **Verify offline generation**: Inspect generated SQL statements before running in production.
