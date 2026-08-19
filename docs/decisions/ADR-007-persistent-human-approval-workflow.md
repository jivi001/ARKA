# ADR-007: Persistent Human Approval Workflow

## Status
Accepted

## Context
High-risk and critical-risk security operations (such as aggressive port scanning, web fuzzing, or vulnerability exploit validation) require explicit human consent. In-memory approval flags can be replayed, forged, or lost during network disconnects.

## Decision
We implement a persistent `ApprovalManager` (`arka/app/core/approvals/manager.py`) backed by PostgreSQL. The approval model enforces a strict state machine (`REQUIRED -> GRANTED`, `REQUIRED -> REJECTED`, `REQUIRED -> EXPIRED`) and exact operation binding to `(engagement_id, task_id, tool_name, target)`.

## Alternatives Considered
1. **Interactive Terminal Prompts (`input()`)**: Blocks the main Python thread and does not scale to multi-operator API workflows.
2. **Stateless JWT Approval Tokens**: Cryptographically sound, but difficult to revoke, query across dashboards, or record detailed rejection reasons.

## Consequences
- **Positive**: Operations are queryable via REST API and CLI (`arka audit`, `GET /approvals`), durable across restarts, auditable with timestamps and operator IDs, and immune to cross-target replay attacks.
- **Negative**: Adds database round-trips for approval lookups and updates.

## Security Implications
Prevents approval reuse across different targets, tasks, or engagements. Invalid state transitions (e.g. attempting to grant an expired or already-rejected request) are blocked with `ValueError`.

## Date
2026-08-19
