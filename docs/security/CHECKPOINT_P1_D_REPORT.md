# CHECKPOINT P1-D VERIFICATION REPORT
## Authorization Engine, Authority Delegation, Approval Binding & Replay Protection

**Project:** ARKA — Autonomous Risk Knowledge & Assessment  
**Phase:** 1 — Security Kernel Foundation  
**Checkpoint:** P1-D  
**Security Classification:** Security-Critical / Formal Audit Trail  
**Date:** 2026-10-05  

---

## 1. Executive Summary

Checkpoint P1-D establishes the deterministic Policy & Authorization Layer of the ARKA Security Kernel. It implements the core decision boundary that evaluates normalized canonical actions against authenticated security context, mission state, scope definitions, authority delegations, approval bindings, and transactional replay protection.

All 9 dedicated Checkpoint P1-D security tests pass, including the mandatory 10-thread concurrent submission stress test on a real file-based SQLite database configured with WAL mode and `BEGIN IMMEDIATE` transactions.

---

## 2. Security Invariant Enforcement

| Invariant | Specification | Implementation Verification | Status |
|:---|:---|:---|:---:|
| **INV-003** | **Child Authority Cannot Exceed Parent Authority** | `Authority::validate_child_delegation` strictly verifies subset relationships on scope (`child.scope ⊆ parent.scope`), capabilities (`child.caps ⊆ parent.caps`), monotonically non-increasing risk (`child.max_risk <= parent.max_risk`), budget, expiry (`child.expiry <= parent.expiry`), and delegation depth bounds. | **PASS** |
| **INV-007** | **Approval Is Bound to the Exact Action** | `Approval::validate_for_action` binds the approval to the SHA-256 action hash (`action.action_hash`). Any alteration to the target, capability, mission, or parameters yields a completely different action hash, causing immediate DENY. | **PASS** |
| **INV-008** | **Replay Is Denied** | `SqliteTransaction::try_consume_replay` records unique replay keys in the SQLite `replay_log` table under atomic `BEGIN IMMEDIATE` transaction. Duplicate sequential submissions and concurrent submissions fail closed. | **PASS** |
| **INV-009** | **Mission Isolation** | Cross-mission actions and cross-mission approval usage fail closed during authorization checks. Replay keys include domain-separated `mission_id` binding. | **PASS** |

---

## 3. Architecture & Core Components

```
                   ┌────────────────────────────────────────┐
                   │ AuthenticatedContext + CanonicalAction │
                   └───────────────────┬────────────────────┘
                                       │
                                       ▼
                   ┌────────────────────────────────────────┐
                   │       AuthorizationEngine              │
                   │                                        │
                   │  1. Check Mission State (Active)       │
                   │  2. Scope Evaluation (Allow / Deny)    │
                   │  3. Replay Protection (Atomic Consume) │
                   │  4. Risk & Approval Check:             │
                   │     - Low / Moderate: ALLOW            │
                   │     - High / Critical:                 │
                   │       * No approval: REQUIRE_APPROVAL  │
                   │       * Approval present: Validate:    │
                   │         - Exact Action Hash (TOCTOU)   │
                   │         - Approver != Requester        │
                   │         - Expiry & Consumption         │
                   └───────────────────┬────────────────────┘
                                       │
                         ALLOW / DENY / REQUIRE_APPROVAL
```

### 3.1 Authority Delegation Model (`crates/arka-core-types/src/authority.rs`)
- Validates parent-to-child delegation across 6 orthogonal dimensions:
  1. Scope containment: all child inclusions must be wholly covered by parent inclusions, and no child rules may contradict parent exclusions.
  2. Capability containment: `child.capabilities ⊆ parent.capabilities`.
  3. Risk class monotonicity: `child.max_risk <= parent.max_risk`.
  4. Budget ceiling: `child.budget_cents <= parent.budget_cents`.
  5. Expiration ceiling: `child.expires_at_unix <= parent.expires_at_unix`.
  6. Delegation depth bound: `child.delegation_depth < parent.max_delegation_depth`.

### 3.2 Action Approval Model (`crates/arka-core-types/src/approval.rs`)
- Binds directly to the deterministic RFC 8785 canonical action hash.
- **Two-Person Integrity (Section 19):** Approver identity cannot match the requesting actor (`approver != requester`), preventing self-authorization.
- **TOCTOU Defense:** Any parameter or target modification creates a hash mismatch between the approved hash and the evaluated action hash.
- **Single-Use Consumption:** Approvals are marked `CONSUMED` atomically within the authorization transaction.

### 3.3 Authorization Engine (`crates/arka-kernel/src/policy/engine.rs`)
- Returns strongly-typed `AuthorizationDecision`:
  - `Allow { action }`
  - `Deny { error }`
  - `RequireApproval { action, action_hash, risk_class }`
- Orchestrates multi-check pipeline in strict order:
  1. Mission state check (must be `Active`).
  2. Scope engine evaluation (inclusions, exclusions, cloud metadata defenses).
  3. Replay consumption (atomic consumption prior to approval check).
  4. Risk determination & approval verification.
  5. Storage persistence of action audit record.

### 3.4 Concurrency & SQLite WAL Architecture (`crates/arka-storage-sqlite/`)
- Uses `BEGIN IMMEDIATE` transactions on dedicated pooled connections to eliminate SQLite upgrade-lock contention and deadlocks.
- Configures `busy_timeout(Duration::from_secs(15))` and `synchronous(Normal)` with WAL mode.
- Unique constraint on `replay_log.replay_key` enforces single-winner semantics across concurrent callers.

---

## 4. Test Verification Suite (`checkpoint_p1_d_test.rs`)

| Test Identifier | Invariant / Requirement | Execution Result |
|:---|:---|:---:|
| `test_delegation_001_valid_child_authority` | Verifies legal sub-delegation strictly within parent scope, caps, and risk | **PASS** |
| `test_delegation_002_expansion_attempts_rejected` | Rejects capability expansion, risk expansion, expiry expansion, and depth violations | **PASS** |
| `test_authz_001_allow_in_scope_moderate_action` | In-scope `PORT_SCAN` (Moderate risk) yields `ALLOW` | **PASS** |
| `test_authz_002_require_approval_for_high_risk_action` | High-risk `CONTROLLED_EXPLOITATION` without prior approval yields `REQUIRE_APPROVAL` | **PASS** |
| `test_approval_001_valid_approval_unlocks_action` | Valid operator approval bound to exact action hash unlocks high-risk action | **PASS** |
| `test_approval_002_parameter_mutation_invalidates_approval_toctou` | Mutating payload parameters invalidates action hash, triggering immediate TOCTOU `DENY` | **PASS** |
| `test_approval_003_self_approval_forbidden` | Approver identity matching requester identity is rejected with `SelfApprovalForbidden` | **PASS** |
| `test_replay_001_sequential_replay_denied` | Immediate replay of consumed action is denied with `ReplayDetected` | **PASS** |
| `test_replay_concurrent_001_exactly_one_success` | **Mandatory Concurrency Stress Test:** 10 threads submit identical action simultaneously to file-based SQLite database. Exactly 1 succeeds (`ALLOW`), all other 9 are denied with `ReplayDetected`. | **PASS** |

---

## 5. Build, Lint & Phase 0 Validation Results

- **Rust Compiler & Clippy:** `cargo clippy --all-targets --all-features -- -D warnings` — **0 warnings, clean**.
- **Rust Code Formatting:** `cargo fmt --check` — **Compliant**.
- **Total Test Count:** 77 passing tests across all crates (P1-A: 12, P1-B: 12, P1-C: 11, P1-D: 9, Core/Crypto/Kernel unit tests: 33).
- **Phase 0 Integrity:**
  - `python3 security/validator/validate_security_model.py` — **All 23 baseline manifests intact, 100% traceability coverage**.
  - `python3 -m unittest discover tests/security` — **22/22 unit tests passing**.

---

## 6. Checkpoint Certification

Checkpoint P1-D is complete and verified against all PRD, TRD, and Agent Execution Contract v2 requirements. Authorization decisions, authority delegation boundaries, approval bindings, and replay protections are fully operational and verified under high concurrency.
