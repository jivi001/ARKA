# ADR-005: Agent-to-Agent (A2A) Identity, Authentication Metadata, and Cryptographic Message Contract

**Status:** PROPOSED (Pending Human Ratification by `@jivi001`)  
**Date:** 2026-10-18  
**Authors:** Principal AI Security Architect, Rust/Python Systems Engineer  
**Phase:** Phase 3 — Intelligence & Multi-Agent Plane  
**Classification:** Security-Critical Architectural Contract  

---

## 1. Context and Problem Statement

In ARKA Phase 3, autonomous operations are partitioned across specialized agent roles (Orchestrator, Reconnaissance, Vulnerability Analysis, Exploitation Validation, Reporting). These agents must communicate asynchronously to delegate subtasks, report discovered findings, request tool execution proposals, and synchronize mission state.

In an adversarial offensive-security environment, inter-agent messaging presents an expansive attack surface governed by non-negotiable architectural invariants:

$$\mathbf{INV-002:}\quad \text{Agents MUST NOT possess direct target-side execution capabilities.}$$

$$\mathbf{INV-004:}\quad \text{A child task's authority MUST be a monotonic subset of its parent's authority.}$$

$$\mathbf{INV-007:}\quad \text{Target-derived content MUST NOT be interpreted as trusted instructions.}$$

$$\mathbf{INV-010:}\quad \text{Security-control failure MUST result in denial, not fallback execution (Fail Closed).}$$

### Adversarial Threat Vectors Against A2A Communication

1. **Agent Impersonation & Forgery (`THREAT-FORGED-A2A-MESSAGE`):** A compromised agent or external adversary injects forged findings (e.g. claiming a target IP is vulnerable or within scope) to manipulate orchestration planning.
2. **Replay & Cross-Mission State Confusion:** An attacker captures valid signed messages from Mission A and replays them into Mission B to trigger unauthorized reassessment or scope confusion.
3. **Prompt-Induced Key Exfiltration:** If private signing keys are placed directly into agent working memory or prompt templates, an LLM subject to prompt injection can be coerced into printing its raw private key bytes in its reasoning output or tool parameters.
4. **Authority Escalation via Delegation Spoofing:** An agent fabricates a delegation chain claiming it was authorized by the Orchestrator with higher capability bounds.

ARKA requires an immutable, verifiable, and strictly typed A2A message contract that prevents forgery, enforces cross-mission isolation, guarantees replay protection, and isolates signing keys from LLM prompt contexts.

---

## 2. A2A Wire Message Contract & Envelope Specification

All inter-agent messages must adhere to a strict canonical wire envelope. No untrusted or unstructured fields are permitted.

```json
{
  "$schema": "https://arka.security/schemas/v1/a2a-message.json",
  "header": {
    "message_id": "msg_01J9Y78B9X4A5C6D7E8F9G0H1J",
    "mission_id": "mis_01J9Y70A1B2C3D4E5F6G7H8J9K",
    "sender": {
      "agent_id": "agent_recon_01",
      "role": "Reconnaissance",
      "token_id": "tok_01J9Y70X9Y8Z7W6V5U4T3S2R1Q"
    },
    "recipient": {
      "target_type": "Direct",
      "agent_id": "agent_vuln_analysis_01"
    },
    "parent_task_id": "task_01J9Y71M2N3P4Q5R6S7T8U9V0W",
    "schema_version": "1.0.0",
    "timestamp_unix": 1729272000,
    "nonce": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
  },
  "payload_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "payload": {
    "message_type": "DiscoveredEndpointFinding",
    "data": {
      "target": "target.corp.example",
      "port": 443,
      "protocol": "tcp",
      "confidence": 0.95,
      "evidence_ref": "ev_01J9Y72A1B2C3D4E5F6G7H8J9K"
    }
  },
  "signature_metadata": {
    "kid": "agent-recon-01-v1-a1b2c3d4",
    "algorithm": "Ed25519",
    "signature": "3b6f...hex_encoded_64_byte_ed25519_signature..."
  }
}
```

### 2.1 Envelope Field Invariants

1. **Strict Deserialization (`deny_unknown_fields`):** Any message containing undocumented attributes, extra top-level fields, or mismatched data types must be immediately rejected during JSON parsing.
2. **Size and Depth Ceilings:** Raw wire message size is strictly capped at $256\text{ KB}$. Nesting depth is limited to $\le 8$ levels.
3. **Payload Hash Binding:** `payload_hash` must be the SHA-256 digest of the RFC 8785 canonical bytes of the `payload` object under domain `ARKA-A2A-PAYLOAD-V1:`:
   $$\text{payload\_hash} = \text{SHA256}(\text{"ARKA-A2A-PAYLOAD-V1:"} \parallel \text{JCS}(\text{payload}))$$
4. **Signature Construction:** The Ed25519 signature is computed over the domain-separated canonical serialization of the `header` and `payload_hash`:
   $$\text{SigPayload} = \text{"ARKA-A2A-MSG-V1:"} \parallel \text{JCS}(\{\text{"header"}: \text{header}, \text{"payload\_hash"}: \text{payload\_hash}\})$$
   $$\text{signature} = \text{Ed25519\_Sign}(\text{PrivateKey}_{\text{sender}}, \text{SigPayload})$$

---

## 3. Threat Mitigations & Verification State Machine

```mermaid
flowchart TD
    Ingress[Ingress A2A Message JSON] --> StrictParse[StrictJsonParser: Size <= 256KB, Depth <= 8, No Dups]
    StrictParse --> SchemaVal[Schema Validation: deny_unknown_fields]
    SchemaVal --> MissionCheck{header.mission_id == active_mission?}
    
    MissionCheck -- No --> DropMission[DROP: CrossMissionDenied Alert]
    MissionCheck -- Yes --> TimeCheck{abs(now - timestamp) <= 60s?}
    
    TimeCheck -- No --> DropExpired[DROP: MessageExpired Alert]
    TimeCheck -- Yes --> ReplayCheck{nonce seen in mission cache?}
    
    ReplayCheck -- Yes --> DropReplay[DROP: ReplayDetected Alert]
    ReplayCheck -- No --> HashCheck{SHA256(payload) == payload_hash?}
    
    HashCheck -- No --> DropHash[DROP: PayloadTampered Alert]
    HashCheck -- Yes --> TokenCheck{sender.token_id valid & active?}
    
    TokenCheck -- No --> DropToken[DROP: TokenRevokedOrInvalid Alert]
    TokenCheck -- Yes --> SigCheck{Ed25519_Verify(signature) == OK?}
    
    SigCheck -- No --> DropSig[DROP: InvalidSignature Alert]
    SigCheck -- Yes --> CommitNonce[Atomic Record Nonce in Ephemeral Cache]
    CommitNonce --> DispatchAgent[Dispatch Payload to Agent Reasoning Loop]
```

### 3.1 Temporal Validity & Monotonic Replay Protection
- **Sliding Expiration Window:** A message is valid if and only if $|\text{Clock}_{\text{now}} - \text{timestamp\_unix}| \le 60\text{ seconds}$. Messages outside this window are dropped without processing.
- **Replay Cache:** The agent runtime maintains an in-memory sliding Bloom filter and SQLite replay index keyed by `(mission_id, sender_id, nonce)`. Re-submission of a previously processed nonce within the expiration window immediately aborts processing.

### 3.2 Cross-Mission Cryptographic Boundary
- The recipient agent asserts that `header.mission_id` matches its own authenticated mission context byte-for-byte.
- In accordance with the Fail-Closed principle (INV-010), cross-mission messages trigger an immediate high-priority audit alert (`CrossMissionAccessDenied`) and are purged.

---

## 4. Key Ownership & Signing Architecture Alternatives

Two architectural models for private-key ownership and message signing were evaluated:

```text
Model 1: Direct Agent Possession (Ephemeral In-Memory Keypair)
+-----------------------------------------------------------+
| Python Agent Process                                      |
|   - Generates Ed25519 keypair at initialization           |
|   - Registers public key with Kernel for Token issuance   |
|   - Stores PrivateKey in Python heap                      |
|   - Signs messages directly via cryptography.hazmat       |
+-----------------------------------------------------------+

Model 2: Broker-Mediated Signing (Local Agent Runtime Supervisor)
+-------------------------------+       +------------------------------------+
| Python Agent Process (Logic)  |       | Agent Runtime Supervisor (Isolated)|
| - Constructs Payload JSON     |       | - Holds PrivateKey in protected mem|
| - Sends to Supervisor over IPC| ====> | - Validates Task & Mission State   |
| - NEVER SEES PRIVATE KEY      |       | - Signs & Assembles A2A Envelope   |
+-------------------------------+       +------------------------------------+
```

### 4.1 Comparative Analysis

| Feature | Model 1: Direct Agent Possession | Model 2: Broker-Mediated Signing |
|---|---|---|
| **Protection Against Prompt Injection** | **Vulnerable:** If an agent is manipulated via prompt injection into running arbitrary Python code or reflecting memory, the raw private key can be exfiltrated. | **Impenetrable:** Agent reasoning loop has zero physical access to private key bytes; key never enters agent memory. |
| **Protection Against LLM Context Leakage** | Requires rigorous code discipline in prompt construction to avoid passing the key object to LLM templates. | Guaranteed by architectural separation; supervisor is outside LLM context. |
| **Operational & Architecture Complexity** | Low; pure library calls within the Python agent process. | Moderate; requires a local supervisor daemon or IPC socket per agent. |
| **Key Zeroization & Lifecycle Control** | Subject to Python garbage collector unpredictability; memory scrubbing is difficult. | Enforced via Rust `zeroize` or dedicated Python memory management. |

### 4.2 Architectural Recommendation

> [!IMPORTANT]
> **Proposed Recommendation:** We propose **Model 2 (Broker-Mediated Signing)** for production deployments, with **Model 1 (Ephemeral In-Memory Keypair)** permitted strictly during early Phase 3 development and unit testing under explicit developer configuration (`ARKA_ALLOW_DIRECT_AGENT_KEYS=true`).
> 
> Under both models, **raw private keys are strictly forbidden from entering LLM prompts, agent memory graphs, logs, or persistent databases.**

---

## 5. Non-Claims & Verification Prerequisites

- **No Premature Verification Claim:** This specification is an architectural design. No claims are made that A2A forgery resistance is verified until executable tests under Phase 3.1c demonstrate:
  1. `test_a2a_forged_signature_rejected`: Modifying one byte of payload invalidates signature.
  2. `test_a2a_cross_mission_replay_aborted`: Replaying an A2A message to a different mission fails closed.
  3. `test_a2a_expired_message_rejected`: Submitting a message with timestamp older than 60s is dropped.
  4. `test_a2a_unknown_fields_rejected`: Ingress message with extra attributes fails deserialization.

---

## 6. Decision Status & Human Sign-Off Requirement

**Decision Status:** `PROPOSED / PENDING HUMAN DECISION`  
**Required Approver:** Cryptographic Lead & Human CODEOWNER (`@jivi001`)  
**Open Choices for Approver:**
1. Approve Model 2 (Broker-Mediated Signing) as the target architecture.
2. Formally authorize Model 1 as an interim development baseline for Phase 3.1c unit testing.
