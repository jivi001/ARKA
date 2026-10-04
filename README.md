# ARKA — Autonomous Risk Knowledge & Assessment Platform

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2+-orange.svg)](https://github.com/langchain-ai/langgraph)
[![Security Foundation: Phase 0](https://img.shields.io/badge/security%20foundation-P0%20established-brightgreen.svg)](docs/security/P0_SECURITY_FOUNDATION_REPORT.md)
[![Traceability: 100%](https://img.shields.io/badge/traceability-100%25%20(35%2F35%20threats)-brightgreen.svg)](security/traceability/security-traceability.yaml)
[![License: Proprietary / Authorized](https://img.shields.io/badge/license-Authorized_Use_Only-red.svg)](LICENSE)

**ARKA** is an enterprise-grade AI-orchestrated autonomous risk assessment and penetration testing platform governed by a deterministic, zero-trust security kernel. It coordinates multi-agent reasoning, strict cryptographic domain separation, immutable audit ledgers, human-in-the-loop approvals, and isolated sandbox execution to assess complex network perimeters and modern web architectures.

---

> [!CAUTION]
> ### LEGAL & AUTHORIZED-USE NOTICE
> ARKA is designed **EXCLUSIVELY FOR AUTHORIZED SECURITY ASSESSMENTS**.
> 
> You must only run this software against systems, applications, and networks that you explicitly own or have documented, legal authorization to test (such as a signed Rules of Engagement or Statement of Work). Unauthorized scanning, penetration testing, or exploitation of computer systems is strictly illegal and may violate local, national, and international cybercrime laws.

---

## Core Security Invariant & Authority Model

The foundational principle of ARKA's architecture is:

$$\mathbf{DISCOVERED \neq AUTHORIZED}$$

**The LLM and agent reasoning plane have ZERO direct execution authority.**

```text
LLM proposes
     ↓
Deterministic Security Kernel authorizes (INV-001, INV-002, INV-010)
     ↓
Execution Broker mediates (INV-009 SSRF Guard, DNS Pinning)
     ↓
Rootless Container Sandbox contains (INV-008, INV-014)
     ↓
Append-Only Audit Ledger records (INV-012 SHA-256 Hash Chain)
     ↓
Human Controls High-Risk Actions (INV-005 Parameter Hash Binding)
```

- **Deterministic Kernel Authority**: The Rust Security Kernel is the sole cryptographic authority for issuing capability tokens and granting access.
- **Fail-Closed Default (INV-010)**: Any error, unhandled exception, timeout, or ambiguity in policy evaluation immediately defaults to unconditional `DENY`.
- **Zero Raw LLM Secret Exposure (INV-013)**: Credentials and cryptographic signing keys are never exposed in prompt contexts, application logs, or persistent databases.
- **Synchronous Emergency Stop (INV-014)**: Triggering emergency stop broadcasts an immediate signal cascade terminating all active worker processes and revoking tokens within 500ms.

---

## Roadmap & Phase Status (TRD v2.1 Lifecycle)

In strict accordance with the ARKA Security Baseline, phase statuses are governed by verifiable repository evidence and acceptance gates recorded in [`security/acceptance/phase-status.yaml`](security/acceptance/phase-status.yaml):

| Phase | Milestone | Status | Core Architecture & Deliverables |
|:---:|---|:---:|---|
| **Phase 0** | **P0 Security Foundation** | **`COMPLETE_WITH_WARNINGS`** | 35 canonical threats, 38 controls, 36 blocking gates, 100% bidirectional traceability, 6-domain key policy, hardened CI supply chain, 43 test contracts, and validator meta-testing. *(Warning: GitHub branch protection requires manual activation by repo owner).* |
| **Phase 1** | **Deterministic Security Kernel** | `NOT_STARTED` | Rust kernel state machine, single-use nonce replay protection (`CTRL-REPLAY-001`), RFC 8785 canonical hash binding (`CTRL-TOCTOU-BINDING-001`), Ed25519 token minting, and SQLite WAL persistence. |
| **Phase 2** | **Execution Broker & Sandboxing** | `NOT_STARTED` | Pre-connect SSRF guard (`CTRL-SSRF-001`), DNS pinning (`CTRL-DNS-PINNING-001`), HTTP redirect interception (`CTRL-REDIRECT-FILTER-001`), rootless Linux container isolation (`CTRL-SANDBOX-CONTAINMENT-001`). |
| **Phase 3** | **Intelligence & Multi-Agent Plane** | `NOT_STARTED` | Inter-agent message signing (`CTRL-A2A-AUTH-001`), dual-boundary prompt framing (`CTRL-PROMPT-GUARD-001`), ANSI terminal stripping, quarantined evidence parsing (`CTRL-PARSER-SANDBOX-001`). |
| **Phase 6** | **Credential Vault & Session Broker** | `NOT_STARTED` | Hardware/KMS Key Encryption Key (KEK) wrapping (`CTRL-CRED-ISOLATION-001`), ephemeral in-memory POSIX secret injection, zero plain-text storage. |
| **Phase 9+** | **Strong Virtualization Isolation** | `NOT_STARTED` | Hardware-assisted microVM hypervisor isolation (Firecracker / gVisor) for controlled high-risk exploitation. |

> [!IMPORTANT]
> **Active Operational Invariant**: `PRODUCTION_EXECUTION_ALLOWED = false`. Production tool execution and automated network penetration testing remain blocked until Phase 1+ deterministic security kernel gates are satisfied.

---

## Security Foundation Architecture (`security/`)

The repository contains a machine-readable security foundation that makes development traceable, testable, and resistant to bypass:

```text
security/
├── baseline.manifest               # SHA-256 cryptographic seal over 24 security files
├── threat-model/
│   ├── assets.yaml                 # 11 canonical platform assets
│   ├── actors.yaml                 # 13 platform actors and execution roles
│   ├── trust-boundaries.yaml       # 10 formal trust boundaries (TB-EXT to TB-HOST)
│   ├── attack-surfaces.yaml        # 10 exposed attack surfaces
│   ├── threats.yaml                # 35 canonical threats (STRIDE / OWASP / ATLAS)
│   └── schemas/                    # Draft-07 JSON schemas for all models
├── controls/
│   ├── controls.yaml               # 38 concrete security controls
│   └── schemas/                    # JSON schema for control definitions
├── acceptance/
│   ├── gates.yaml                  # 36 blocking security acceptance gates
│   ├── phase-status.yaml           # Authoritative phase lifecycle registry
│   └── schemas/                    # Schemas for gates and phase status
├── traceability/
│   ├── security-traceability.yaml  # 100% bidirectional threat-to-gate matrix (35 entries)
│   └── schemas/                    # Schema enforcing full referential integrity
├── keys/
│   ├── key-management-policy.yaml  # 6 independent cryptographic key domains
│   ├── key_provider.rs             # Formal Rust trait specification for Phase 1 Kernel
│   └── schemas/                    # Key management policy schema
├── tests/
│   ├── tests.yaml                  # 43 test contracts (Phase 1+ strictly PENDING)
│   └── schemas/                    # Test contract schema
└── validator/
    └── validate_security_model.py  # Authoritative model validator & meta-test runner
```

### Cryptographic Key Management (6 Isolated Domains)
In compliance with **INV-011**, ARKA isolates keys into 6 non-overlapping domains:
1. `ROOT-ANCHOR`: Master offline signing anchor (HSM / M-of-N quorum).
2. `TOKEN-SIGNING`: Ephemeral capability and authorization token signing (Rust Kernel process memory).
3. `AUDIT-SIGNING`: Immutable audit hash-chain signing (Audit Ledger process).
4. `CREDENTIAL-KEK`: AES-256-GCM Key Encryption Key for credential enveloping.
5. `MISSION-DATA-ENCRYPTION`: Ephemeral per-mission AES-256-GCM data encryption.
6. `WORKER-IDENTITY`: Ephemeral Ed25519 mTLS identity for worker containers ($\le$ 300s).

### Audit Anchoring Pipeline (6 Stages)
$$\text{Event} \longrightarrow \text{RFC 8785 JCS} \longrightarrow \text{SHA-256 Hash Chain} \longrightarrow \text{Ed25519 Audit Sign} \longrightarrow \text{Persistent WAL} \longrightarrow \text{RFC 3161 Anchor}$$

---

## Supply Chain & Hardened CI Pipeline

All merges to `main` are guarded by six dedicated, blocking CI checks in [`.github/workflows/security-foundation.yml`](.github/workflows/security-foundation.yml):

```text
┌───────────────────────┐
│     CI-SEC-MODEL      │ Threat Model JSON schema compliance & referential integrity
└──────────┬────────────┘
           │
┌──────────▼────────────┐
│  CI-SEC-TRACEABILITY  │ 100% Bidirectional threat-to-gate matrix verification
└──────────┬────────────┘
           │
┌──────────▼────────────┐
│   CI-SEC-VALIDATOR    │ Baseline manifest SHA-256 verification & negative meta-tests
└───────────────────────┘
┌───────────────────────┐
│    CI-SEC-SECRETS     │ Full-history Gitleaks secret and token leak detection
└───────────────────────┘
┌───────────────────────┐
│  CI-SEC-DEPENDENCIES  │ pip-audit (Python) and pnpm audit (Frontend) vulnerability gates
└───────────────────────┘
┌───────────────────────┐
│      CI-SEC-SBOM      │ CycloneDX machine-readable SBOM generation and retention
└───────────────────────┘
```

- **Zero Write Tokens**: Global workflow `permissions: contents: read`.
- **Commit-SHA Pinning**: All third-party actions pinned to full 40-character SHAs (e.g., `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`).
- **Fork Protection**: Standard `pull_request` execution prevents secret exfiltration (`pull_request_target` is strictly prohibited).
- **Human Governance**: [`.github/CODEOWNERS`](.github/CODEOWNERS) assigns `@jivi001` review authority over all security files.
- **Branch Protection**: Required settings documented in [`docs/security/BRANCH_PROTECTION.md`](docs/security/BRANCH_PROTECTION.md).

---

## Quick Start & Verification

### 1. Prerequisites
- **Python 3.13+** (Runtime & Security Validator)
- **Node.js 20+ & pnpm v9+** (Frontend Operator Console)
- **Docker & Docker Compose** (PostgreSQL 16+, Redis 7+)

### 2. Verify the Security Foundation
Run the authoritative security validator and test suites directly:

```bash
# 1. Run Core Security Model & Traceability Validation (100% coverage, 24 manifest files)
python3 security/validator/validate_security_model.py

# 2. Run Validator Negative Meta-Test Suite (12 synthetic mutation attacks rejected)
python3 security/validator/validate_security_model.py --meta-tests

# 3. Run Security Foundation & Cryptographic Unit Tests (22 tests passing)
python3 -m unittest tests/security/test_foundation_suite.py \
                    tests/security/test_validator_meta.py \
                    tests/security/test_key_provider.py
```

### 3. Local Development Setup
```bash
# Clone the repository
git clone https://github.com/jivi001/ARKA.git
cd ARKA

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -e ".[dev]"

# Configure environment variables
cp .env.example .env
```

---

## Repository Structure

```text
ARKA/
├── .github/
│   ├── CODEOWNERS                  # Strict human ownership for security paths
│   └── workflows/
│       └── security-foundation.yml  # 6 blocking CI supply chain and security gates
├── arka/
│   ├── core/
│   │   └── crypto/                 # KeyProvider ABC & DevelopmentKeyProvider
│   ├── app/                        # FastAPI application, CLI, and API routes
│   └── orchestration/              # Multi-agent coordination logic
├── frontend/                       # Next.js 16 / React 19 Operator Console
├── security/                       # Authoritative Security Foundation (P0)
│   ├── baseline.manifest           # Cryptographic baseline manifest
│   ├── threat-model/               # Assets, actors, boundaries, surfaces, threats
│   ├── controls/                   # 38 security controls
│   ├── acceptance/                 # 36 blocking gates & phase status registry
│   ├── traceability/               # 100% bidirectional traceability matrix
│   ├── keys/                       # 6-domain key policy & Rust trait specification
│   ├── tests/                      # 43 security test contracts
│   └── validator/                  # Security model validator & meta-test engine
├── tests/
│   └── security/                   # Foundation test suite, meta-tests, crypto tests
└── docs/
    └── security/
        ├── P0_SECURITY_FOUNDATION_REPORT.md  # Comprehensive Phase 0 report
        ├── BRANCH_PROTECTION.md              # Branch protection specification
        └── SUPPLY_CHAIN_POLICY.md            # Supply chain security policy
```

---

## Authoritative Documentation

- 📄 [Phase 0 Security Foundation Report](docs/security/P0_SECURITY_FOUNDATION_REPORT.md)
- 📄 [Technical Requirements Document (TRD v2.1)](ARKA_TRD_v2.1.md)
- 📄 [Product Requirements Document (PRD)](PRD(1).md)
- 📄 [Branch Protection & Governance](docs/security/BRANCH_PROTECTION.md)
- 📄 [Supply Chain Security Policy](docs/security/SUPPLY_CHAIN_POLICY.md)
- 📄 [Architecture Decision Records (ADRs)](docs/decisions/)
