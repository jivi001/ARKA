# ADR-008: Append-Only Audit Architecture

## Status
Accepted

## Context
Penetration testing platforms must provide non-repudiation and complete compliance auditing for all reconnaissance, scanning, and exploitation attempts. If an audit system allows modification or deletion of past records, malicious agents or compromised operators could tamper with evidence or hide unauthorized actions.

## Decision
We implement an append-only `AuditService` (`arka/app/audit/service.py`) that strictly exposes record creation APIs and provides no update, modify, clear, or delete methods. To prevent in-memory tampering, `get_events()` returns defensive deep copies. Furthermore, all logged payloads undergo recursive secret sanitization.

## Alternatives Considered
1. **Standard Python Logging / Loguru**: Excellent for stdout/stderr debugging, but lacks structured relational querying, correlation ID indexing, and programmatically queryable audit trails.
2. **Direct Database Inserts in Nodes**: Leads to fragmented schema handling and risks leaking unsanitized API keys or passwords.

## Consequences
- **Positive**: Cryptographic-grade compliance log, automated credential protection, zero-tamper memory model, and standardized event schema.
- **Negative**: Deep copying large audit payloads has minor CPU overhead for high-volume logs.

## Security Implications
Guarantees that sensitive credentials (`api_key`, `password`, `tokens`) never persist in plain text, and historical security decisions cannot be rewritten.

## Date
2026-08-19
