# Security & Immutability Test Catalog

This document details tests verifying audit immutability, tamper resistance, and credential redaction.

---

## 1. Audit Immutability Tests (`tests/security/test_audit_immutability.py`)

- **Strict Append-Only**: Asserts `AuditService` has no delete/update methods.
- **Defensive Copy Tamper Resistance**: Modifies dictionaries returned by `get_events()` and confirms internal state remains unchanged.
- **Credential Redaction**: Submits sensitive keys (`api_key`, `password`, `token`, `secret`, `vault_token`) and verifies they are replaced with `"[REDACTED]"`.
- **Correlation ID Consistency**: Verifies correlation IDs are properly preserved across distributed execution steps.

---

## 2. Security Boundary Tests (`tests/security/test_security.py`)

- **Scope Injection Prevention**: Tests malformed IP strings, header injection, and parameter tampering.
- **Unauthorized Bypass Attempts**: Asserts that crafted requests attempting to pass `scope_validated=True` directly are rejected.
- **Subdomain Boundary Verification**: Tests edge-case domain syntax (e.g. `example.com.evil.com`, `evil-example.com`).
