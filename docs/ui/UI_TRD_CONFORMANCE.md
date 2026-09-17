# ARKA Web Console — TRD Conformance Matrix

| Requirement ID | TRD Architecture Requirement | Status | Evidence / Verification Details |
|---|---|---|---|
| TRD-ARCH-001 | Zero Authority Operator Interface | **PASS** | UI contains zero direct execution authority. All actions dispatched to FastAPI backend. |
| TRD-ARCH-002 | Strict Gating Pipeline | **PASS** | Request flow follows `CandidateToolRequest` → `ToolRegistry` → `ScopeGuard` → `PolicyEngine` → `ApprovalManager` → `ExecutionManager`. |
| TRD-ARCH-003 | Argument Hash Bound Approvals (SEC-01) | **PASS** | `ApprovalManager` binds tokens to SHA-256 argument hash. Unit tests in `test_approval_arg_binding.py` pass. |
| TRD-ARCH-004 | Discovered != Authorized Boundary | **PASS** | Discovered entities default to `DISCOVERED — NOT AUTHORIZED` and cannot be scanned without Scope Delta. |
| TRD-ARCH-005 | Fail-Closed Architecture | **PASS** | All policy, scope, and network checks fail closed on any ambiguity or API disconnect. |
| TRD-ARCH-006 | Epistemic Ladder Enforcement | **PASS** | Epistemic stages strictly enforced in SQLAlchemy model and API endpoints. LLM calls cannot set `VALIDATED`. |
| TRD-ARCH-007 | Immutable Scope History | **PASS** | Historical scope definitions are versioned (`v1`, `v2`) and never mutated in place. |
| TRD-ARCH-008 | Secret Isolation | **PASS** | Client browser never receives or stores plaintext passwords, API keys, or session tokens. Vault URIs used exclusively. |
| TRD-ARCH-009 | Real-Time SSE Event Bus | **PASS** | `EventBroadcaster` in `arka/app/api/stream_bus.py` broadcasts events to `/api/stream` and `/api/engagements/{id}/stream`. |
| TRD-ARCH-010 | Static Pre-rendering & Production Optimization | **PASS** | `pnpm --prefix frontend build` compiles 15 static routes with 0 errors. |
