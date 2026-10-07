# ARKA — Autonomous Risk Knowledge & Assessment Platform

[![Rust 1.80+](https://img.shields.io/badge/rust-1.80+-orange.svg)](https://www.rust-lang.org/)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Security Kernel: Phase 1](https://img.shields.io/badge/security%20kernel-Phase%201%20Audited%20(PASS)-brightgreen.svg)](docs/security/PHASE_1_INDEPENDENT_RE_AUDIT_REPORT.md)
[![Security Foundation: Phase 0](https://img.shields.io/badge/security%20foundation-P0%20established-brightgreen.svg)](docs/security/P0_SECURITY_FOUNDATION_REPORT.md)
[![Traceability: 100%](https://img.shields.io/badge/traceability-100%25%20(35%2F35%20threats)-brightgreen.svg)](security/traceability/security-traceability.yaml)
[![Unsafe Code: Forbidden](https://img.shields.io/badge/unsafe%20code-forbidden%20(%23!%5Bforbid(unsafe_code)%5D)-blue.svg)](crates/)
[![License: Proprietary / Authorized](https://img.shields.io/badge/license-Authorized_Use_Only-red.svg)](LICENSE)

**ARKA** is an enterprise-grade AI-orchestrated autonomous risk assessment and authorized penetration testing platform governed by a deterministic, zero-trust Rust Security Kernel. It coordinates multi-agent reasoning, strict cryptographic domain separation, immutable dual audit ledgers, human-in-the-loop approvals, and isolated sandbox execution to assess complex network perimeters and modern web architectures.

---

> [!CAUTION]
> ### LEGAL & AUTHORIZED-USE NOTICE
> ARKA is designed **EXCLUSIVELY FOR AUTHORIZED SECURITY ASSESSMENTS**.
> 
> You must only run this software against systems, applications, and networks that you explicitly own or have documented, legal authorization to test (such as a signed Rules of Engagement or Statement of Work). Unauthorized scanning, penetration testing, or exploitation of computer systems is strictly illegal and violates national and international cybercrime laws.

---

## Core Security Invariant & Authority Model

The foundational principle of ARKA's architecture is:

$$\mathbf{DISCOVERED \neq AUTHORIZED}$$

**The LLM and agent reasoning plane have ZERO direct execution authority.**

```text
                             UNTRUSTED ZONE
        ┌────────────────────────────────────────────────────────┐
        │  LLM Intelligence / Multi-Agent Outputs / Raw Input    │
        └───────────────────────────┬────────────────────────────┘
                                    │ RawActionProposal (JSON)
                                    ▼
        ┌────────────────────────────────────────────────────────┐
        │                  ARKA SECURITY KERNEL                  │
        │                                                        │
        │  1. Authentication & Context (Ed25519 Signed Token)    │
        │  2. Strict JSON Parsing (Max 64KB, Depth <= 8, No Dup) │
        │  3. Normalization (RFC 8785 JCS, Domain Separation)    │
        │  4. Authoritative Risk Derivation (INV-005)            │
        │  5. Scope Engine (Exclusions > Inclusions > Default)   │
        │  6. Emergency Stop Barrier (Monotonic Persistence)     │
        │  7. Authority Bounds & Delegation Depth Check          │
        │  8. Single-Use Replay Protection (BEGIN IMMEDIATE)     │
        │  9. Two-Person Approval Verification (TOCTOU Bound)    │
        │ 10. Atomic Unit of Work Commit + Dual Audit Appending  │
        └───────────────────────────┬────────────────────────────┘
                                    │
                     ALLOW / DENY / REQUIRE_APPROVAL
                                    │
                                    ▼
                              FUTURE BROKER
```

- **Deterministic Kernel Authority**: The Rust Security Kernel is the sole cryptographic authority governing action validation and authorization.
- **Fail-Closed Default (INV-010)**: Any error, unhandled exception, timeout, or ambiguity in policy evaluation immediately defaults to unconditional `DENY`.
- **Zero Raw LLM Secret Exposure (INV-013)**: Credentials and cryptographic signing keys are never exposed in prompt contexts, logs, or persistent databases.
- **Synchronous Emergency Stop (INV-010)**: Triggering emergency stop immediately blocks authorization across active missions and persists across storage/engine restarts.
- **Autonomous Multi-Agent Model**: All agents and LLM reasoning pipelines are governed by [`AGENTS.md`](AGENTS.md) / [`agent.md`](agent.md) defining strict role taxonomy, non-executable boundaries, and mandatory Two-Person Integrity human approval gates.

---

## Roadmap & Phase Status (PRD v2.2 / TRD v2.2 Lifecycle)

In strict accordance with the ARKA Security Baseline, phase statuses are governed by verifiable repository evidence and acceptance gates recorded in [`security/acceptance/phase-status.yaml`](security/acceptance/phase-status.yaml):

| Phase | Milestone | Status | Core Architecture & Deliverables |
|:---:|---|:---:|---|
| **Phase 0** | **P0 Security Foundation** | **`COMPLETE`** | 35 canonical threats, 38 controls, 36 blocking gates, 100% bidirectional traceability, 6-domain key policy, hardened CI supply chain, 43 test contracts, and validator meta-testing. |
| **Phase 1** | **Deterministic Security Kernel** | **`COMPLETE (PASS)`** | Deterministic Rust Security Kernel (`arka-core-types`, `arka-crypto`, `arka-kernel`, `arka-storage-sqlite`). `#![forbid(unsafe_code)]`, RFC 8785 JCS canonicalization, single-use replay protection with SQLite WAL `BEGIN IMMEDIATE`, dual signed audit hash chains (`AUDIT-SIGNING`), and persistent Emergency Stop. Remediation verified; 92/92 Rust tests passing. Re-audit PASS ([`PHASE_1_INDEPENDENT_RE_AUDIT_REPORT.md`](docs/security/PHASE_1_INDEPENDENT_RE_AUDIT_REPORT.md)). |
| **Phase 2** | **Execution Broker & Sandboxing** | `NEXT` | Pre-connect SSRF guard (`CTRL-SSRF-001`), DNS pinning (`CTRL-DNS-PINNING-001`), HTTP redirect interception (`CTRL-REDIRECT-FILTER-001`), rootless Linux container isolation (`CTRL-SANDBOX-CONTAINMENT-001`). |
| **Phase 3** | **Intelligence & Multi-Agent Plane** | `PLANNED` | Inter-agent message signing (`CTRL-A2A-AUTH-001`), dual-boundary prompt framing (`CTRL-PROMPT-GUARD-001`), ANSI terminal stripping, quarantined evidence parsing (`CTRL-PARSER-SANDBOX-001`). |
| **Phase 6** | **Credential Vault & Session Broker** | `PLANNED` | Hardware/KMS Key Encryption Key (KEK) wrapping (`CTRL-CRED-ISOLATION-001`), ephemeral in-memory POSIX secret injection, zero plain-text storage. |
| **Phase 9+** | **Strong Virtualization Isolation** | `PLANNED` | Hardware-assisted microVM hypervisor isolation (Firecracker / gVisor) for controlled high-risk exploitation. |

> [!IMPORTANT]
> **Active Operational Invariant**: `PRODUCTION_EXECUTION_ALLOWED = false`. Production tool execution and automated network penetration testing remain blocked until Phase 2 Execution Broker and Sandboxing gates are established.

---

## Rust Security Kernel Workspace (`crates/`)

The Phase 1 Security Kernel is implemented as a fine-grained, modular Rust workspace under `crates/` enforcing complete separation between domain types, cryptography, core business logic, and storage persistence:

```text
crates/
├── arka-core-types/         # Pure domain types, IDs, Subject, Mission, Scope, Actions, Approvals, Audit
├── arka-crypto/             # RFC 8785 JCS, domain-separated SHA-256, DevKeyProvider (6 domains), StrictJsonParser
├── arka-kernel/             # Auth, MissionService, TargetParser & ScopeEngine, CapabilityRegistry, ActionNormalizer, PolicyEngine, AuditChainEngine, EmergencyStopService
└── arka-storage-sqlite/     # SqliteStorage, SqliteTransaction with WAL mode, BEGIN IMMEDIATE, schema migrations
```

### Cryptographic Key Management (6 Isolated Domains)
In compliance with **INV-011**, ARKA cryptographically isolates keys into 6 non-overlapping domains:
1. `RootAnchor`: Master offline signing anchor.
2. `TokenSigning`: Ephemeral capability and authorization token signing (`ARKA-TOKEN-V1:`).
3. `AuditSigning`: Immutable dual audit hash-chain signing (`ARKA-AUDIT-v1:`).
4. `CredentialKek`: Key Encryption Key for credential enveloping.
5. `MissionDataEncryption`: Ephemeral per-mission AES-256-GCM data encryption.
6. `WorkerIdentity`: Ephemeral Ed25519 identity for worker containers.

### Audit Anchoring Pipeline
$$\text{Event} \longrightarrow \text{RFC 8785 JCS} \longrightarrow \text{SHA-256 Hash Chain} \longrightarrow \text{Ed25519 Audit Sign} \longrightarrow \text{Persistent WAL} \longrightarrow \text{Atomic Transaction}$$

---

## Quick Start & Executable Verification

### 1. Prerequisites
- **Rust 1.80+ (Stable)** (`rustc`, `cargo`, `rustfmt`, `clippy`)
- **Python 3.13+** (Runtime & Security Model Validator)
- **SQLite 3.35+** (WAL Mode support)
- **Node.js 20+ & pnpm v9+** (Frontend Operator Console)

### 2. Verify the Rust Security Kernel (Phase 1)
Run the complete Rust compiler lints and test suite:

```bash
# 1. Check strict Rust formatting
cargo fmt --check

# 2. Run Clippy compiler lints (zero warnings enforced with -D warnings)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Run all workspace unit and integration tests (87 tests passing)
cargo test --all
```

### 3. Verify the Security Model & Baseline (Phase 0)
Run the authoritative security validator and test suites:

```bash
# 1. Run Core Security Model & Traceability Validation (100% coverage, 24 manifest files)
python3 security/validator/validate_security_model.py

# 2. Run Validator Negative Meta-Test Suite (12 synthetic mutation attacks rejected)
python3 security/validator/validate_security_model.py --meta-tests

# 3. Run Security Foundation & Cryptographic Unit Tests (22 tests passing)
python3 -m unittest discover tests/security

# 4. Verify Phase 0 Cryptographic Baseline Manifest (24/24 files verified OK)
cd security && sha256sum -c baseline.manifest && cd ..
```

---

## Repository Structure

```text
ARKA/
├── Cargo.toml                       # Root Rust workspace manifest (4 crates)
├── Cargo.lock                       # Pinned Rust dependencies
├── ARKA_PRD_v2.2.md                 # Authoritative Product Requirements Document
├── ARKA_TRD_v2.2.md                 # Authoritative Technical Requirements Document
├── crates/                          # Phase 1 Deterministic Security Kernel
│   ├── arka-core-types/             # Domain models, strongly-typed IDs, errors
│   ├── arka-crypto/                 # RFC 8785 JCS canonicalization, Ed25519, SHA-256
│   ├── arka-kernel/                 # Normalization, scope, policy, audit, e-stop
│   └── arka-storage-sqlite/         # WAL-mode atomic SQLite persistence & schema
├── security/                        # Authoritative Security Foundation (Phase 0)
│   ├── baseline.manifest            # SHA-256 cryptographic seal over 24 security files
│   ├── threat-model/                # Assets, actors, boundaries, surfaces, threats
│   ├── controls/                    # 38 security controls
│   ├── acceptance/                  # 36 blocking gates & phase status registry
│   ├── traceability/                # 100% bidirectional traceability matrix
│   ├── keys/                        # 6-domain key policy & Rust trait specification
│   ├── tests/                       # 43 security test contracts
│   └── validator/                   # Security model validator & meta-test engine
├── tests/
│   └── security/                    # Phase 0 test suite, meta-tests, crypto tests
├── docs/
│   └── security/                    # Authoritative security documentation
│       ├── README.md                # Security documentation index
│       ├── PHASE_1_ARCHITECTURE_PLAN.md        # Phase 1 architecture & execution blueprint
│       ├── PHASE_1_COMPLETION_REPORT.md        # Checkpoint completion & adversarial answers
│       ├── PHASE_1_VERIFICATION_AUDIT_REPORT.md# Multi-agent completion verification audit
│       ├── CHECKPOINT_P1_A_REPORT.md           # Tokens, IDs, Mission State Machine
│       ├── CHECKPOINT_P1_B_REPORT.md           # Scope Engine, Negative Parser Defenses
│       ├── CHECKPOINT_P1_C_REPORT.md           # Capability Registry, Normalization
│       ├── CHECKPOINT_P1_D_REPORT.md           # Policy Engine, Approvals, Replay WAL
│       ├── CHECKPOINT_P1_E_REPORT.md           # Dual Audit Chains, Persistent E-Stop
│       ├── P0_SECURITY_FOUNDATION_REPORT.md    # Phase 0 comprehensive foundation report
│       ├── BRANCH_PROTECTION.md                # Branch protection specification
│       └── SUPPLY_CHAIN_POLICY.md              # Supply chain security policy
├── arka/                            # Python agent & intelligence plane
└── frontend/                        # Operator Console (Next.js / React)
```

---

## Authoritative Documentation

- 📄 [Product Requirements Document (PRD v2.2)](ARKA_PRD_v2.2.md)
- 📄 [Technical Requirements Document (TRD v2.2)](ARKA_TRD_v2.2.md)
- 📄 [Security Documentation Index](docs/security/README.md)
- 📄 [Phase 1 Verification Audit Report](docs/security/PHASE_1_VERIFICATION_AUDIT_REPORT.md)
- 📄 [Phase 1 Completion Report](docs/security/PHASE_1_COMPLETION_REPORT.md)
- 📄 [Phase 1 Architecture Plan](docs/security/PHASE_1_ARCHITECTURE_PLAN.md)
- 📄 [Phase 0 Security Foundation Report](docs/security/P0_SECURITY_FOUNDATION_REPORT.md)
- 📄 [Branch Protection & Governance](docs/security/BRANCH_PROTECTION.md)
- 📄 [Supply Chain Security Policy](docs/security/SUPPLY_CHAIN_POLICY.md)
