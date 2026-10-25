# ARKA Phase 3 — Module A Architecture Decision Register & Governance Synthesis

**Document:** `docs/security/PHASE_3_MODULE_A_ARCHITECTURE_DECISIONS.md`  
**Classification:** Internal Security Architecture & Governance Specification  
**Date:** 2026-10-25  
**Authors:** Senior Rust Security Architect, Python AI Systems Engineer, Application Security Reviewer  
**Governing Documents:** ARKA PRD v2.2, ARKA TRD v2.2, `AGENTS.md`, `.github/CODEOWNERS`  
**Target Milestone:** Phase 3 Module A — Architecture, Contracts, and Governance Baseline  
**Overall Architecture Status:** `BLOCKED` (Awaiting human CODEOWNER architectural ratifications)

---

## 1. Executive Summary

This document synthesizes the formal architecture decision landscape for **ARKA Phase 3: Intelligence & Multi-Agent Plane**. 

The ARKA architecture enforces a strict hierarchy:
$$\mathbf{DISCOVERED \neq AUTHORIZED}$$
$$\mathbf{\text{Reasoning Plane (Untrusted Python)}} \xrightarrow{\text{Proposals Only}} \mathbf{\text{Kernel (Authoritative Rust)}} \xrightarrow{\text{Authorized Execution}} \mathbf{\text{Broker (Sandboxed Workers)}}$$

Phase 3 introduces significant architectural complexity: autonomous agent loops, multi-agent coordination (A2A), LLM inference gateway, and cross-language IPC between Python and Rust. 

To prevent security drift, premature implementation, or accidental bypasses, all architectural decisions are strictly registered, versioned, and bound to human CODEOWNER approval.

---

## 2. Master Architecture Decision Record (ADR) Index

| ADR ID | Title | Phase | Status | Decision Authority | Security Scope |
|---|---|:---:|:---:|:---:|---|
| [**ADR-001**](file:///home/exu0/cybersecurity/Programs/ARKA/docs/security/adr/ADR-001-HTTP-TRANSPORT-AND-PINNED-DIALING.md) | HTTP Transport Selection, Direct-IP Dialing, and TLS Binding | Phase 2 | **ACCEPTED** | Senior AI Systems Architect, Principal Rust Security Engineer | Enforces single-query DNS resolution, IP pinning, RFC1918/Loopback denial, and Rustls hostname binding. |
| [**ADR-002**](file:///home/exu0/cybersecurity/Programs/ARKA/docs/security/adr/ADR-002-WORKER-IDENTITY-AND-MTLS.md) | Worker Identity and Mutual TLS Transport Architecture | Phase 2 | **ACCEPTED** | Senior Security Engineer, Broker Systems Architect | Enforces short-lived mTLS worker identities under `KeyDomain::WorkerIdentity`. |
| [**ADR-003**](file:///home/exu0/cybersecurity/Programs/ARKA/docs/security/adr/ADR-003-ROOTLESS-SANDBOX-CONTAINMENT.md) | Rootless Container Sandboxing and Bubblewrap Enforcement | Phase 2 | **ACCEPTED** | Principal Security Engineer, Linux Systems Architect | Enforces unprivileged Bubblewrap namespaces, read-only rootfs, Seccomp filtering, and PID isolation. |
| [**ADR-004**](file:///home/exu0/cybersecurity/Programs/ARKA/docs/security/adr/ADR-004-GATEWAY-TOPOLOGY-AND-CREDENTIAL-ISOLATION.md) | LLM Gateway Process Topology, Credential Isolation, and Pinned Egress | Phase 3 | **PROPOSED** | Human CODEOWNER (`@jivi001`) | Establishes dedicated OS process boundary for LLM Gateway; isolates provider API keys from agent contexts. |
| [**ADR-005**](file:///home/exu0/cybersecurity/Programs/ARKA/docs/security/adr/ADR-005-A2A-IDENTITY-AND-MESSAGE-CONTRACT.md) | Agent-to-Agent (A2A) Identity, Authentication Metadata, and Cryptographic Message Contract | Phase 3 | **PROPOSED** | Human CODEOWNER (`@jivi001`) | Specifies wire envelope, Ed25519 signatures, replay rejection, and cross-mission message quarantine. |
| [**ADR-006**](file:///home/exu0/cybersecurity/Programs/ARKA/docs/security/adr/ADR-006-ACTION-NORMALIZATION-AND-CANONICALIZATION.md) | Single Action Normalization Boundary, RFC 8785 JCS Canonicalization, and Tool Mediation | Phase 3 | **PROPOSED** | Human CODEOWNER (`@jivi001`) | Confirms RFC 8785 JCS standard, `StrictJsonParser` limits, and single ingress function `normalize_action()`. |
| [**ADR-007**](file:///home/exu0/cybersecurity/Programs/ARKA/docs/security/adr/ADR-007-PYTHON-RUST-IPC-TRANSPORT-AND-AUTHENTICATION.md) | Python-to-Rust Local IPC Transport, Service Boundary, and Mutual Authentication Contract | Phase 3 | **PROPOSED** | Human CODEOWNER (`@jivi001`) | Specifies dedicated `arka-kerneld` daemon, `/run/arka/kernel.sock` UDS, `SO_PEERCRED`, and Ed25519 token authentication. |

---

## 3. Analysis of Open Human Decisions (DEC-01 through DEC-14)

The Phase 3.1c decision register (`docs/security/PHASE_3.1C_DECISION_REGISTER.md`) enumerates fourteen critical decisions that block Phase 3 ratification and runtime implementation. Below is the structured analysis of their status, dependencies, and proposed resolution pathways:

### 3.1 Gateway & Secret Boundaries (DEC-01, DEC-02, DEC-07, DEC-08)
- **DEC-01 (Critical — Gateway Topology & OS Identity):**  
  *Issue:* Agents cannot be co-located with provider credentials under a shared UID.  
  *Proposal:* ADR-004 proposes a dedicated background service running as `arka-gateway` communicating via `/run/arka/gateway.sock` with `SO_PEERCRED` checks.  
  *Required Human Decision:* `@jivi001` must formally approve the separate-process boundary, runtime service manager (systemd), and UDS permissions. Real-secret co-location in agent memory remains strictly forbidden.
- **DEC-02 (Critical — TLS Transport Implementation Gap):**  
  *Issue:* Accepted ADR-001 specifies Hyper/Rustls, but the current implementation in `crates/arka-network-policy` only verifies TCP pinning and peer IP comparison without full TLS handshake test evidence.  
  *Required Human Decision:* Require full TLS SNI, certificate chain validation, and hostname verification test evidence before claiming egress compliance.
- **DEC-07 (High — Provider Destination & Local-Model Policy):**  
  *Issue:* Uncontrolled outbound HTTP requests can lead to SSRF or data exfiltration.  
  *Proposal:* Explicit provider allowlist in configuration (e.g., `api.openai.com:443`, `api.anthropic.com:443`). Local models must use dedicated Unix domain sockets or strictly isolated localhost endpoints without ambient proxy inheritance.  
  *Required Human Decision:* Ratify default redirect denial and provider destination policy.
- **DEC-08 (High — External Data Classifications):**  
  *Issue:* PRD §18 defines `public`, `internal`, `confidential`, `secret`, but provider egress mapping is unratified.  
  *Proposal:* External LLM providers receive `public` data only. Secrets, credentials, capability tokens, and internal keys are hard-blocked by DLP.  
  *Required Human Decision:* Approve default egress mapping and DLP fail-closed rules.

### 3.2 Cryptographic & Canonicalization Standards (DEC-03, DEC-04, DEC-05, DEC-06)
- **DEC-03 (Critical — RFC 8785 JCS Ratification & Hash Compatibility):**  
  *Issue:* Existing Rust routine in `arka-crypto` implements basic key ordering, but full UTF-16 code unit ordering, number formatting per IEEE 754, and Python/Rust cross-language hash parity are not formally proven.  
  *Proposal:* Formally ratify RFC 8785 JCS across both Rust and Python; implement shared test vectors (`docs/security/PHASE_3.1C_PROTOCOL_TEST_VECTORS.md`).  
  *Required Human Decision:* Ratify JCS and approve migration path for existing historical audit records.
- **DEC-04 (High — A2A Key Domain & Signing Authority):**  
  *Issue:* Current Key Management Policy defines 6 domains, but lacks a dedicated `KeyDomain::AgentMessageSigning`. Drafts proposing in-agent private keys risk LLM prompt-injection exfiltration.  
  *Proposal:* Dedicated key domain `KeyDomain::AgentMessageSigning`; agents obtain signatures via authenticated local agent daemon or hardware-backed keystore.  
  *Required Human Decision:* Formally approve new key domain and signing custody model.
- **DEC-05 (High — A2A Expiry & Clock Skew):**  
  *Proposal:* Maximum message TTL of 60 seconds; maximum future clock skew tolerance of 30 seconds; monotonically increasing message sequence numbers.  
  *Required Human Decision:* Ratify exact TTL and clock synchronization requirements.
- **DEC-06 (High — Replay State Durability):**  
  *Proposal:* In-memory Bloom filters are advisory only; durable replay protection must be backed by SQLite `replay_log` with atomic check-and-consume transactions.  
  *Required Human Decision:* Ratify SQLite as the sole authoritative replay barrier.

### 3.3 Authorization & Kernel-Broker Integrity (DEC-10, DEC-11, DEC-14)
- **DEC-10 (High — Kernel-to-Broker Authorization Proof):**  
  *Issue:* The broker currently accepts a public `CanonicalAction` and only checks that hash fields are non-empty strings. Reachability from an agent process could constitute an authorization bypass.  
  *Proposal:* ADR-007 encapsulates the Execution Broker entirely inside `arka-kerneld`. Python agents have zero physical access to the broker socket. The broker receives actions strictly via internal function calls from the kernel after SQLite commit.  
  *Required Human Decision:* Ratify the single-process Kernel-Broker service boundary to eliminate direct broker exposure.
- **DEC-11 (High — Capability Parameter Schemas):**  
  *Issue:* Currently, capability parameters in `RawActionProposal` are arbitrary `serde_json::Value`.  
  *Proposal:* Register JSON Schema definitions for every standard capability in `StandardCapabilityRegistry`; reject non-conforming parameters at normalization time.  
  *Required Human Decision:* Approve schema registry ownership and strict schema validation.
- **DEC-14 (Release Blocker — Production Execution Enablement):**  
  *Issue:* Phase 2 is `COMPLETE_WITH_WARNINGS` with production execution disabled.  
  *Rule:* Production execution remains disabled throughout Phase 3 design. Enabling target execution requires explicit, independent human authorization.

---

## 4. Proposed Architecture Decision (ADR-007)

ADR-007 resolves the Python-to-Rust communication gap identified in Finding 2.

```mermaid
flowchart TD
    subgraph AgentRuntime ["Python Agent Runtime (UID: arka-agent)"]
        Agent[Autonomous Agent / Gateway Client]
        PyBridge[KernelClient Bridge]
        Agent --> PyBridge
    end

    subgraph IPCBoundary ["Local Unix Domain Socket Boundary"]
        UDS["/run/arka/kernel.sock\n(mode 0660, arka-kernel:arka-agent)"]
        SO_PEERCRED["Kernel SO_PEERCRED Verification\n(Asserts Caller UID == arka-agent)"]
        PyBridge -->|Length-Prefixed JSON <= 64KB| UDS
        UDS --> SO_PEERCRED
    end

    subgraph KernelDaemon ["Rust Kernel Service Daemon (arka-kerneld, UID: arka-kernel)"]
        SO_PEERCRED --> StrictParser[StrictJsonParser\n<=64KB, depth <=8, no dups]
        StrictParser --> TokenVerify[Ed25519 Token Verifier\nKeyDomain::TokenSigning]
        TokenVerify --> Normalizer[ActionNormalizer::normalize()]
        Normalizer --> AuthzEngine[AuthorizationEngine::authorize()]
        
        AuthzEngine -->|Commit Atomic| DB[(SQLite WAL Storage\nmissions, replay, audit)]
        AuthzEngine -->|Authorized Action| Broker[Execution Broker\ncrates/arka-execution-broker]
    end

    Broker -->|Sandboxed Task| Worker[Isolated Worker Container]
```

### Key Architectural Commitments of ADR-007:
1. **No Shared Address Space:** Complete rejection of PyO3/FFI in-process bindings to prevent Python memory scanning or interpreter crash propagation.
2. **Deterministic Kernel Superiority:** `arka-kerneld` is the authoritative coordinator. Agents propose; kernel authorizes; broker executes.
3. **Hardened Local UDS:** `/run/arka/kernel.sock` with `0660` permissions, group-restricted to `arka-agent`, with kernel-enforced `SO_PEERCRED` checks and Ed25519 cryptographic token validation.

---

## 5. Governance Pathway & Required Actions

To unblock Phase 3 implementation, the following actions are formally submitted to `@jivi001`:

```text
+-----------------------------------------------------------------------------------+
|                     FORMAL CODEOWNER ACTION REQUEST                               |
+-----------------------------------------------------------------------------------+
| 1. Review and Ratify ADR-004 (LLM Gateway Topology & Credential Isolation).      |
| 2. Review and Ratify ADR-005 (A2A Cryptographic Message Contract).                |
| 3. Review and Ratify ADR-006 (Action Normalization & RFC 8785 JCS).              |
| 4. Review and Ratify ADR-007 (Python-to-Rust IPC Transport & Service Boundary).   |
| 5. Formally Accept Decisions DEC-01 through DEC-14 in Decision Register.          |
| 6. Approve Proposed Dedicated Gate: GATE-PROVIDER-CRED-ISOLATION-001.             |
| 7. Complete Phase 1 and Phase 2 Formal Release Attestations in phase-status.yaml. |
+-----------------------------------------------------------------------------------+
```

Until these formal human actions are completed and recorded, **Phase 3 implementation remains BLOCKED**.
