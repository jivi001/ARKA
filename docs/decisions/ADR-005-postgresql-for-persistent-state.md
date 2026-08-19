# ADR-005: PostgreSQL for Persistent State

## Status
Accepted

## Context
ARKA requires persistent, relational, transaction-safe storage for engagements, tasks, human approvals, audit logs, and LangGraph execution checkpoints. Storage must support high concurrency, JSONB indexing for semi-structured security artifacts, and robust migration tooling.

## Decision
We adopt **PostgreSQL 16+** with **SQLAlchemy 2.0 async engine** (`asyncpg`) as the primary relational database, coupled with **Alembic** for version-controlled schema migrations.

## Alternatives Considered
1. **SQLite**: Lightweight for local testing, but lacks native async concurrency, robust JSONB querying, and distributed multi-worker support.
2. **MongoDB / Document DB**: Strong for unstructured documents, but lacks strict relational integrity and transactional ACID guarantees needed for audit and approval state machines.

## Consequences
- **Positive**: Full ACID transactional guarantees, JSONB storage for tool parameters and artifacts, native integration with LangGraph async checkpointers, and mature Alembic migrations.
- **Negative**: Requires running a PostgreSQL service locally (via Docker) or in cloud infrastructure.

## Security Implications
Enforces foreign key relationships, audit immutability constraints, and transaction isolation for approval state transitions.

## Date
2026-08-19
