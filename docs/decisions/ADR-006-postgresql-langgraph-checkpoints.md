# ADR-006: PostgreSQL LangGraph Checkpoints

## Status
Accepted

## Context
Penetration tests are long-running operations that frequently pause for human approval gates or require server maintenance reboots. Losing in-memory graph state when execution is interrupted forces operators to restart assessments from scratch, wasting time and risking duplicate scanning.

## Decision
We configure the LangGraph orchestrator graph to use `AsyncPostgresSaver` in production. Checkpoint snapshots and intermediate channel writes are committed to PostgreSQL tables (`checkpoints`, `checkpoint_writes`) on every graph node transition.

## Alternatives Considered
1. **In-Memory Checkpointing (`MemorySaver`)**: Fast and zero-dependency, but state is lost immediately on process restart or container termination (retained exclusively for unit testing).
2. **Redis-Based Checkpointing**: Fast, but lacks long-term durability, relational joins with engagement tables, and historical audit correlation.

## Consequences
- **Positive**: Complete process crash resilience. Paused approval states survive server restarts indefinitely.
- **Negative**: Adds minor I/O latency per graph transition; requires maintaining LangGraph checkpoint database tables.

## Security Implications
Checkpoints capture sanitized state transitions, ensuring that resumed workflows cannot be manipulated to alter previous node decisions.

## Date
2026-08-19
