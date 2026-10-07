# ARKA Phase 1 Remediation Architecture & Execution Plan

**Project:** ARKA — Autonomous Risk Knowledge & Assessment  
**Phase:** Phase 1 — Security Kernel Foundation  
**Mode:** Remediation Planning & Verification (Checkpoints 0–3)  
**Objective:** Remediate all 4 audit findings (P1-FIX-01 through P1-FIX-04) to advance ARKA from `PHASE 1 — PASS WITH WARNINGS` to `PHASE 1 — PASS` and `GO TO PHASE 2`.  
**Date:** 2026-10-05  

---

## 1. Graph Construction (ARKA-P1-REMEDIATION-GRAPH)

Built from the codebase graph (1518 nodes, 2318 edges across 99 communities in `graphify-out/`):

### 1.1 Core Security Data Flow
```text
[Untrusted Input (JSON)]
         │
         ▼
[crates/arka-kernel/src/actions/normalizer.rs] (ActionNormalizer::normalize_from_json)
   ├── StrictJsonParser (max 64KB, max depth 8, duplicate key rejection)
   ├── TargetParser::parse(raw_target) ────────────────────────────────────────────────────────┐
   │      ├── split_host_port                                                                  │
   │      ├── [P1-FIX-01] Ambiguous IP Checks (Hex, Octal, Decimal Int, Trailing Hex)          │
   │      ├── [P1-FIX-03] parse_url -> normalize_path (Percent-Decoding + Path Traversal)     │
   │      ├── parse_ip_or_socket (IPv4, IPv6, IPv4-mapped IPv6)                                │
   │      └── parse_domain (ASCII, trailing dot removal, case normalization)                   │
   ├── JCS Canonicalization (RFC 8785) -> DOMAIN_PARAM SHA-256                                │
   ├── Authoritative Risk Derivation (StandardCapabilityRegistry)                              │
   └── DOMAIN_ACTION SHA-256 -> CanonicalAction                                                │
                                                                                               │
[crates/arka-kernel/src/policy/engine.rs] (AuthorizationEngine::authorize)                     │
   │                                                                                           │
   ├── Step 1: StorageTransaction::is_emergency_stop_active ───────────────────┐               │
   │      └── Active => DENY (Immediate Fail-Closed)                           │               │
   ├── Step 2: StorageTransaction::get_mission ────────────────────────────────┤               │
   │      └── State != Active => DENY (MissionStateInvalid)                    │               │
   ├── Step 3: ScopeEngine::evaluate(scope, &action.target) ◄──────────────────┴───────────────┘
   │      ├── Exclusions override Inclusions                                   │
   │      ├── is_restricted_address (SSRF / Cloud Metadata / Loopback)         │
   │      └── Inclusions => Default Deny                                       │
   │                                                                           │
   ├── Step 4: Approval Check [P1-FIX-02]                                      │
   │      ├── needs_approval && approval.is_none():                            │
   │      │      ├── DO NOT CONSUME REPLAY KEY                                 │
   │      │      ├── Record APPROVAL_REQUIRED in action table                  │
   │      │      ├── Append dual audit records (sys + mis)                     │
   │      │      ├── COMMIT transaction                                        │
   │      │      └── Return AuthorizationDecision::RequireApproval             │
   │      │                                                                    │
   │      └── needs_approval && approval.is_some():                            │
   │             ├── Validate approval (action_hash, approver != subject, exp) │
   │             └── StorageTransaction::consume_approval                      │
   │                                                                           │
   ├── Step 5: Replay Protection Check-and-Consume [P1-FIX-02]                 │
   │      └── StorageTransaction::try_consume_replay (Atomic WAL BEGIN IMMEDIATE)
   │             └── ReplayDetected => DENY (Fail-Closed)                      │
   │                                                                           │
   ├── Step 6: Finalize Authorized Action                                      │
   │      ├── Record AUTHORIZED in action table                                │
   │      ├── Append dual audit records (sys + mis)                            │
   │      ├── COMMIT transaction                                               │
   │      └── Return AuthorizationDecision::Allow { action }                   │
   └───────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Four-Fix Impact Map

| Fix ID | Finding ID | Severity | Affected Component | Target File | Impacted Callers & Tests |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **P1-FIX-01** | `ARKA-ADV-015` | **HIGH** | `TargetParser` IP & Domain routing | `crates/arka-kernel/src/scope/parser.rs` | `ActionNormalizer`, `ScopeEngine`, `checkpoint_p1_b_test.rs` |
| **P1-FIX-02** | `ARKA-AUTHZ-001` | **HIGH** | `AuthorizationEngine` approval/replay flow | `crates/arka-kernel/src/policy/engine.rs` | `checkpoint_p1_d_test.rs`, `checkpoint_p1_e_test.rs` |
| **P1-FIX-03** | `ARKA-ADV-021` | **MEDIUM** | `TargetParser::normalize_path` | `crates/arka-kernel/src/scope/parser.rs` | `TargetParser::parse_url`, `ScopeRule::matches`, `checkpoint_p1_b_test.rs` |
| **P1-FIX-04** | `ARKA-CI-001` | **MEDIUM** | CI / Automation | `.github/workflows/rust-ci.yml` | GitHub Actions remote gate |

---

## 3. Remediation Specifications

### Fix 1: Trailing-Hex IPv4 Representation Defense (P1-FIX-01 / ARKA-ADV-015)
- **Vulnerable Behavior:** Mixed-radix IPv4 strings (e.g. `169.254.169.0xfe`, `127.0.0.0x1`) fail `last_label.chars().all(|c| c.is_ascii_digit())` and fall through to `parse_domain`, bypassing IP restricted address checks.
- **Remediation Specification:**
  In `TargetParser::parse`:
  Before falling through to `parse_domain`, check if `host_part` is a dotted format where all segments are numeric or hexadecimal literals.
  Specifically, if `host_part.split('.')` has 4 segments and any segment starts with `0x`/`0X` or contains non-decimal characters while other segments are decimal numbers, it is an ambiguous hexadecimal IPv4 address representation.
  In compliance with Section 25, strictly **REJECT** the target with:
  `Err(KernelSecurityError::ScopeDenied("Ambiguous hexadecimal IP representation rejected".to_string()))`.
- **Security Property:** Ambiguous hex IP representations are denied at the parser boundary; zero bypass into `CanonicalTarget::Domain` or `CanonicalTarget::Ip`.

### Fix 2: Two-Step Approval / Replay Lifecycle (P1-FIX-02 / ARKA-AUTHZ-001)
- **Vulnerable Behavior:** `AuthorizationEngine::authorize` consumes the replay key in `replay_log` before evaluating approvals. When returning `RequireApproval`, the replay key is committed, causing the subsequent approved execution call to fail with `ReplayDetected`.
- **Remediation Specification:**
  In `AuthorizationEngine::authorize`:
  1. Move `tx.try_consume_replay(&replay_key, ...)` down so that it occurs **only** when authorizing execution.
  2. When `needs_approval && approval.is_none()`:
     - Record action record with status `"APPROVAL_REQUIRED"`.
     - Record audit events with `"APPROVAL_REQUIRED"`.
     - Commit transaction **without** calling `try_consume_replay`.
     - Return `AuthorizationDecision::RequireApproval`.
  3. When an approved call arrives (`approval.is_some()`):
     - Validate the approval (`apprv.validate_for_action`).
     - Consume approval in storage (`tx.consume_approval`).
     - Call `tx.try_consume_replay(&replay_key, ...)` atomically.
     - Record action record with status `"AUTHORIZED"`.
     - Append dual audit records.
     - Commit transaction and return `AuthorizationDecision::Allow`.
  4. If re-executed a third time with the same proposal/action nonce:
     - `tx.try_consume_replay` detects the consumed key and fails closed with `KernelSecurityError::ReplayDetected`.
- **Security Property:** Replay key is consumed strictly on authorization execution; two-step approval flow functions cleanly without replay deadlock.

### Fix 3: URL Path Percent-Decoding & Traversal Defense (P1-FIX-03 / ARKA-ADV-021)
- **Vulnerable Behavior:** `TargetParser::normalize_path` splits on literal `/` without percent-decoding `%2e%2e`, allowing sub-path prefix bypasses against backend reverse proxies.
- **Remediation Specification:**
  In `TargetParser`:
  Implement a strict, fail-closed `percent_decode_path` helper:
  1. Decode `%xx` two-digit hex sequences to bytes.
  2. Validate that the decoded bytes represent valid UTF-8.
  3. Detect and reject double encoding: if decoded path contains `%25` followed by hex digits representing dots or slashes (`%252e`, `%252f`), or if decoded string still contains encoded traversal sequences, return `KernelSecurityError::ScopeDenied("Double-encoded path traversal detected")`.
  4. Decode `%2f` / `%2F` to `/` to prevent encoded slash evasion.
  5. Feed the decoded path into `normalize_path` to collapse `.` and `..` segments iteratively.
- **Security Property:** Path traversal sequences (`%2e%2e`, `/../`, `%2f`) are fully canonicalized prior to scope prefix matching.

### Fix 4: Dedicated GitHub Actions Rust CI Workflow (P1-FIX-04 / ARKA-CI-001)
- **Specification:**
  Create `.github/workflows/rust-ci.yml`:
  - Triggers on `push` to `main`, `feat/**`, and `pull_request` to `main`.
  - Permissions: `contents: read`.
  - Pinned actions with immutable SHAs (`actions/checkout`, `dtolnay/rust-toolchain`).
  - Jobs:
    1. `rust-fmt`: `cargo fmt --check`
    2. `rust-clippy`: `cargo clippy --all-targets --all-features -- -D warnings`
    3. `rust-test`: `cargo test --all`
- **Security Property:** Automated, unbypassable remote PR gating of all Rust security invariants and test suites.

---

## 4. Multi-Agent Organization & Single-Writer Assignment

In accordance with Sections 6–20:
- **Lead Architect Agent (Orchestrator):** Owns architecture impact analysis, dependency graph, and checkpoint progression.
- **Security Architect Agent:** Owns threat analysis and attack-surface verification.
- **Rust Kernel Engineer (Single Writer):** Sole author of kernel modifications in `crates/arka-kernel/src/`.
- **DevOps / Security Agent:** Author of `.github/workflows/rust-ci.yml`.
- **QA & Testing Agent:** Author of regression and boundary tests.
- **Adversarial Security Agent:** Author of adversarial bypass tests.
- **Independent Security Reviewer:** Read-only auditor verifying the remediation.
- **Final Phase Gatekeeper:** Evaluates all reports and issues the final Phase 1 signoff.
