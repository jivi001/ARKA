# Phase 1 Hardening Log

This document details all hardening changes implemented to complete and secure Phase 1 of ARKA.

---

## 1. Orchestrator Trust-Boundary Hardening
- **Problem**: The orchestrator previously contained hardcoded risk evaluations and allowed boolean authorization flags to be set directly.
- **Previous Behavior**: Orchestrator node attempted to decide risk levels and set approval flags.
- **New Behavior**: Orchestrator extracts untrusted `CandidateToolRequest` objects and delegates all authorization to `PolicyEngine` and `ToolRegistry`.
- **Implementation**: `arka/app/agents/orchestrator/graph.py`
- **Tests**: `tests/integration/test_phase1_flow.py`

---

## 2. CandidateToolRequest Separation
- **Problem**: A single `ToolRequest` class contained both untrusted parameters and trusted validation booleans (`scope_validated`, `policy_approved`).
- **Previous Behavior**: Untrusted inputs could theoretically set `scope_validated=True`.
- **New Behavior**: Separated untrusted `CandidateToolRequest` from authoritative `ToolRequest`. Only `ToolRegistry` can construct `ToolRequest`.
- **Implementation**: `arka/app/tools/schemas/tool_schemas.py`
- **Tests**: `tests/unit/test_tool_registry_comprehensive.py`

---

## 3. ScopeGuard Deterministic Hardening
- **Problem**: Potential subdomain suffix collisions (`evil-example.com`) and cross-version IP crashes (`IPv4Address` compared to `IPv6Network`).
- **Previous Behavior**: Incomplete suffix checks and unhandled `TypeError` exceptions.
- **New Behavior**: Strict dot-separated subdomain boundaries, version-guarded IP containment, URL extraction, and port range parsing. Exclusions strictly override inclusions.
- **Implementation**: `arka/app/core/scope/scopeguard.py`
- **Tests**: `tests/unit/test_scopeguard_comprehensive.py` (28 tests)

---

## 4. PolicyEngine Single Source of Truth
- **Problem**: Risk levels and approval requirements were evaluated in multiple disparate components.
- **Previous Behavior**: Inconsistent risk rules across agents and tools.
- **New Behavior**: Consolidated all evaluation into `PolicyEngine`. Out-of-scope targets ALWAYS return `DENY`.
- **Implementation**: `arka/app/core/policies/engine.py`
- **Tests**: `tests/unit/test_policy_comprehensive.py` (9 tests)

---

## 5. Persistent Approvals & Strict State Machine
- **Problem**: Approvals were stored in transient memory and lacked state transition validation.
- **Previous Behavior**: Approvals lost on server reboot; invalid state transitions not guarded.
- **New Behavior**: Stored in PostgreSQL with strict transitions (`REQUIRED -> GRANTED`, `REQUIRED -> REJECTED`, `REQUIRED -> EXPIRED`) and exact operation binding.
- **Implementation**: `arka/app/core/approvals/manager.py`, `arka/app/database/models.py`
- **Migration**: `migrations/versions/002_approval_fields.py`
- **Tests**: `tests/unit/test_approval_manager.py` (10 tests)

---

## 6. Durable LangGraph PostgreSQL Checkpointing
- **Problem**: Graph state lost on interrupt or process restart.
- **Previous Behavior**: In-memory checkpointer only.
- **New Behavior**: Added `AsyncPostgresSaver` support with `MemorySaver` fallback for tests.
- **Implementation**: `arka/app/agents/orchestrator/graph.py`
- **Tests**: `tests/integration/test_phase1_flow.py`

---

## 7. Tool Registry Input Validation & Execution Protection
- **Problem**: Unknown arguments or parameter type mismatches could crash executors.
- **Previous Behavior**: Blind argument forwarding.
- **New Behavior**: JSON schema validation (required args, unknown arg rejection, type checking), timeouts, and safe exception wrapping.
- **Implementation**: `arka/app/tools/registry/registry.py`
- **Tests**: `tests/unit/test_tool_registry_comprehensive.py` (12 tests)

---

## 8. Safe Mock Tools
- **Problem**: Integration tests risked invoking live tools or network calls.
- **Previous Behavior**: Incomplete mock fixtures.
- **New Behavior**: Implemented `EchoToolExecutor` (Low) and `HighRiskMockToolExecutor` (High) with zero network/subshell execution.
- **Implementation**: `arka/app/tools/mock/tools.py`
- **Tests**: `tests/integration/test_mock_tool_e2e.py` (3 tests)

---

## 9. LLM Gateway Routing & Error Normalization
- **Problem**: Missing provider prefixes caused LiteLLM routing errors; unmasked API keys in string dumps.
- **Previous Behavior**: Unprefixed model strings and unhandled vendor exceptions.
- **New Behavior**: Explicit provider prefix mapping, error normalization (401, 429, 503, 504), token tracking, and secret masking.
- **Implementation**: `arka/app/llm/gateway/gateway.py`
- **Tests**: `tests/integration/test_llm_gateway_integration.py` (8 tests)

---

## 10. Audit Immutability & Secret Scrubbing
- **Problem**: Audit logs could be mutated in memory or leak sensitive API tokens.
- **Previous Behavior**: Modifiable dictionary references and raw parameter logging.
- **New Behavior**: Strict append-only service, defensive deep copies, and recursive secret scrubbing (`api_key`, `password`, `tokens`).
- **Implementation**: `arka/app/audit/service.py`
- **Tests**: `tests/security/test_audit_immutability.py` (4 tests)
