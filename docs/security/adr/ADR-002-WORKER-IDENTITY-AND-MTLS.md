# ADR-002: Worker-to-Broker Authentication, Ephemeral Identity, and Mutual TLS (mTLS)

**Status:** Accepted (P2-A Architecture Decision)  
**Date:** 2026-10-09  
**Authors:** Senior AI Systems Architect, Principal Rust Security Engineer  
**Phase:** Phase 2 — Execution Foundation & Sandboxing  
**Classification:** Security-Critical Architectural Contract  

---

## 1. Context and Problem Statement

ARKA Phase 2 introduces isolated execution workers running in rootless Linux containers/processes. The Rust Execution Broker supervises these workers and dispatches kernel-authorized action proposals.

Because worker processes are untrusted execution environments that process potentially hostile target responses, the communication channel between the Execution Broker and the Worker presents significant attack surfaces:
1. **Worker Impersonation:** An unauthenticated local process or rogue container could connect to the broker and submit fabricated results or falsified evidence.
2. **Broker Impersonation:** A compromised environment could intercept worker connections and capture sensitive action context.
3. **Cross-Worker / Cross-Mission Tampering:** A worker assigned to Mission $A$ must be cryptographically barred from receiving or acknowledging execution units belonging to Mission $B$.
4. **Replay and Out-of-Sequence Attacks:** Stale or intercepted execution messages could be replayed to trigger duplicate execution or state machine confusion.
5. **Key Confusion / Domain Bleed:** Insecure identity implementations might attempt to reuse existing platform tokens (`TOKEN-SIGNING`) for transport encryption, violating the fundamental cryptographic domain separation invariant.

---

## 2. Decision

We mandate **TLS 1.3 Mutual Authentication (mTLS)** with **ephemeral, per-execution certificates** governed strictly under the **`KeyDomain::WorkerIdentity`** cryptographic domain.

### 2.1 Cryptographic Domain Separation
- **Key Domain:** `KeyDomain::WorkerIdentity` (as defined in `key-management-policy.yaml` and `crates/arka-crypto/src/provider.rs`).
- **Isolation Rule:** Under no circumstances may `KeyDomain::TokenSigning` (Ed25519 token signatures), `KeyDomain::AuditSigning` (dual audit chains), or root anchor keys be used for worker transport identity.

### 2.2 Ephemeral Certificate Lifecycle

```text
       Execution Broker                              Worker Sandbox
              |                                            |
1. Generate Ephemeral CA (in-memory)                       |
   KeyDomain::WorkerIdentity                               |
              |                                            |
2. Issue Ephemeral Worker Leaf Cert                        |
   - Subject: CN = worker.<exec_id>.arka                   |
   - SAN / Extension: mission_id, exec_id,                 |
     capability_id, nonce                                  |
   - Validity: [now, now + timeout]                        |
              |                                            |
3. Provision Worker Process -----------------------------> | Start container with
   (Pass Worker Leaf + Key + CA cert via isolated pipe)    | ephemeral cert/key
              |                                            |
4. TLS 1.3 Handshake (mTLS) <============================> |
   - Worker verifies Broker Cert against CA Root           |
   - Broker verifies Worker Cert against CA Root           |
              |                                            |
5. Identity Binding Verification                           |
   - Broker asserts peer cert SAN matches active:          |
     (mission_id, exec_id, capability_id, nonce)           |
              |                                            |
6. Bounded Execution & Result Transfer <==================>| Strict Serde protocol
              |                                            |
7. Immediate Teardown & Revocation                         |
   - Zeroize in-memory ephemeral keys                      | Terminate container
   - Invalidate TLS session                                | Wiped by OS
```

#### Step 1: Ephemeral Root Trust Anchor
- Each Execution Broker instance generates an ephemeral internal Certificate Authority (CA) upon initialization, residing strictly in protected memory (`zeroize`).
- The CA certificate is self-signed and exists solely for the lifespan of the broker instance or execution batch.

#### Step 2: Per-Execution Leaf Issuance
- For every bounded execution unit, the Broker issues an ephemeral X.509 leaf certificate for the worker.
- **Validity Window:** Bound strictly to the execution deadline:
  $$\text{validity} = [\text{current\_time}, \text{current\_time} + \text{execution\_timeout}]$$
  Maximum allowed lifetime is 300 seconds (5 minutes). Not valid before issuance; expires automatically upon deadline.

#### Step 3: Identity Binding & Subject Formatting
The leaf certificate embeds the authorization parameters:
- **Common Name (CN):** `worker.<execution_id>.arka`
- **Subject Alternative Name (SAN) / Custom Extension:**
  - `mission_id`: String (matches active mission)
  - `execution_id`: UUID / strongly-typed `ExecutionId`
  - `capability_id`: Standard capability (e.g. `TCP_CONNECT`)
  - `nonce`: 128-bit cryptographically secure random value

#### Step 4: Mutual TLS Handshake & Verification
- **Worker Verification:** Worker validates Broker's server certificate against the provided broker CA root.
- **Broker Verification:**
  - Broker demands and validates the worker's client certificate against the broker CA root.
  - Broker verifies that `now() < not_after`.
  - Broker parses the certificate extension and asserts that `mission_id`, `execution_id`, `capability_id`, and `nonce` match the dispatch record **byte-for-byte**.
  - Any mismatch immediately terminates the connection with a security alert and marks the dispatch as `FAILED`.

#### Step 5: Ephemeral Revocation & Clean Teardown
- Upon task completion, timeout, cancellation, or Emergency Stop:
  1. The Broker terminates the TLS session.
  2. The ephemeral private key material in both Broker and Worker memory is cleared using `zeroize`.
  3. The worker container/process is terminated (`SIGKILL` after grace period).
  4. The ephemeral certificate is marked consumed/revoked in the broker's active session table; any subsequent connection attempt with the same certificate is rejected.

---

## 3. Threat Mitigations

| Threat | Mitigation Mechanism |
|---|---|
| **THREAT-FORGED-A2A-MESSAGE** (`GATE-A2A-AUTH-001`) | Client certificate required on all worker connections; untrusted local sockets cannot inject messages. |
| **THREAT-TOKEN-THEFT** (`GATE-TOKEN-PROTECTION-001`) | Worker identity uses ephemeral TLS credentials, never raw authentication tokens. No bearer tokens transmitted. |
| **Cross-Mission Attack** (`GATE-MISSION-ISOLATION-001`) | Leaf certificates are cryptographically bound to `mission_id`. A worker cannot acknowledge actions for another mission. |
| **Replay Attack** (`GATE-REPLAY-001`) | Ephemeral validity window (max 300s) and single-use `nonce` prevent reusing certificates or message frames. |
| **Emergency Stop Bypass** (`GATE-EMERGENCY-STOP-001`) | E-Stop immediately tears down the TLS transport listener and invalidates all ephemeral worker identities. |

---

## 4. Consequences and Verification

### Positive Consequences
- Guarantees end-to-end cryptographic mutual authentication between Broker and Worker.
- Ephemeral lifecycle eliminates long-lived certificate management, CRL distribution, and persistent key theft risks.
- Enforces multi-tenancy and mission isolation at the transport layer.

### Negative / Operational Trade-offs
- CPU overhead of generating ephemeral keys and X.509 certificates per execution (mitigated by fast Ed25519 key generation in Rust: <50 microseconds per keypair).
- Requires packaging `rustls` and X.509 parsing primitives into both broker and worker binaries.

### Verification Plan
- Integration test: Broker rejects connection from a worker with a certificate signed by an untrusted CA.
- Integration test: Broker rejects connection from a worker presenting an expired ephemeral certificate.
- Integration test: Broker rejects connection from a worker whose certificate carries a mismatched `mission_id` or `execution_id`.
- Replay test: Broker rejects reconnection using an already-consumed ephemeral client certificate.
