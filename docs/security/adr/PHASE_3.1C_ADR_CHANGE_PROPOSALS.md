# Phase 3.1c — ADR Change Proposals

**Status:** Proposed amendments only; no ADR is ratified or modified by this file.
**Baseline:** `abf6da7b005e7ed8b49991c00667eb6242d00d6e`
**Approval:** Human security owner and CODEOWNER review required before architecture lock.

## ADR-001 — HTTP transport and pinned dialing

**Current record:** Accepted Phase 2 decision selecting Hyper/Tokio/Rustls and a direct-IP connector.
**Finding:** Current workspace source implements pinned TCP dialing and peer-IP comparison only. `Cargo.toml` and crate manifests contain no Hyper or TLS dependency. There is no TLS handshake, SNI, certificate-chain validation, or hostname verification in `DirectIpConnector`.

**Proposal:** Keep ADR-001 accepted as the intended transport architecture, but add an implementation status note and an explicit evidence gate. Do not describe Phase 2 or Phase 3 provider traffic as TLS protected until a concrete transport implementation and negative TLS tests exist. DNS/IP pinning and TLS authentication are separate requirements.

**Required evidence:** tests for TLS version policy, valid and invalid chain, wrong hostname, SNI, expired certificate, redirect revalidation, DNS re-resolution per connection, proxy environment bypass, and peer IP equality. No runtime implementation is part of Phase 3.1c.

## ADR-004 — Gateway process topology and provider credential isolation

**Current record:** Untracked draft proposes a standalone Rust `arka-gatewayd`, UDS, `SO_PEERCRED`, and a development co-location flag. Status is proposed.

**Keep:** The PRD/TRD logical Gateway is the only component allowed to resolve and use provider credentials. Its credential has inference access only.

**Amend:**

1. Replace “recommended/verified standalone daemon” language with a **candidate topology**. PRD/TRD mandate a logical Gateway but do not approve a Rust daemon or exact deployment.
2. Require a separate OS security principal/process from untrusted agents for any process that reads real provider credentials. Reject a co-located agent/Gateway mode even when an environment variable labels it unsafe. A test harness may use synthetic credentials only.
3. Specify a candidate UDS contract: restricted filesystem ownership/mode, kernel-verified peer credentials, plus kernel-issued identity/token authorization bound to agent, mission, task, audience, expiry, and revocation. Peer UID alone authenticates a local process; it does not grant an inference or ARKA capability.
4. Make socket path, service identities, group provisioning, service manager, and local-model exception explicit human decisions. Exact proposed values are in the reconciled plan.
5. Remove the 10 MiB JSON message ceiling unless a separately approved parser boundary supports it. For JSON handled by the existing strict parser, use at most 64 KiB/depth 8 until a dedicated parser contract is implemented and tested.
6. Replace “Pinned TLS 1.3” implementation claims with “required, not currently implemented.” Direct IP pinning does not establish encryption, certificate trust, or hostname identity.
7. Replace regex-only DLP claims with layered controls: process-level secret separation, trusted source classification, typed/minimized payload construction, policy checks, outbound destination restrictions, and pattern scanning as defense in depth.
8. Remove provider SDK and direct-network fallback from the agent plane. Credential-source, policy, DNS, TLS, audit, or Gateway failure denies the dependent inference request.

**Human decisions:** deployment topology; dev/CI secret source; provider destination/redirect policy; local-model endpoint policy; external data classes permitted per provider.

## ADR-005 — A2A identity and message contract

**Current record:** Untracked draft proposes 256 KiB messages, timestamp window, ephemeral Bloom cache, SQLite index, two key custody models, and direct in-agent signing for development. Status is proposed.

**Amend:**

1. Set the proposed v1 encoded message cap to 65,536 bytes and nesting depth to 8 to match `StrictJsonParser`; require exact same behavior at every ingress. ADR-004's proposed 10 MiB gateway JSON must be reconciled separately.
2. Reject duplicate keys, trailing JSON, unknown envelope fields, unknown version, unsupported payload fields, invalid Unicode/number values, malformed signature encodings, and unexpected recipients before dispatch.
3. Bind the signature to the version, message ID, sender, recipient/audience, mission, task, issue/expiry, nonce, key ID, fixed algorithm, and payload hash. Resolve the key ID through a trusted registry bound to kernel-issued AgentId/MissionId/task claims. Header fields alone never prove identity.
4. Define a payload digest and signature preimage with separate fixed domain separators. If JCS is selected, first ratify it and pass official plus ARKA-specific shared vectors. Do not claim parity based on current source.
5. Replace the Bloom filter as a decision mechanism with a durable unique replay ledger. Atomically reserve nonce and inbox state before dispatch, handle concurrent duplicates with one winner, persist across restart, and use an idempotent outbox/inbox recovery path.
6. Specify explicit expiry and clock-skew bounds; the draft's absolute 60-second window is only a candidate. Reject expired, excessively future-dated, or overlong messages.
7. Reject direct agent possession of message-signing keys. `ARKA_ALLOW_DIRECT_AGENT_KEYS=true` conflicts with the invariant that secrets are unavailable to untrusted agents. A signing service must construct and sign only typed, authorized message envelopes derived from active kernel-issued task state; no arbitrary-byte signing API.
8. Add a distinct `AGENT-MESSAGE-SIGNING` key domain or an equivalent separately approved key domain. Do not reuse TOKEN-SIGNING, AUDIT-SIGNING, or WORKER-IDENTITY key material. Current key-policy and Python KeyDomain lists do not define this domain.
9. Add recipient validation, immediate revocation, bounded rotation overlap, per-agent/mission rate limits, sanitised errors, and explicit key destruction/retention rules.

**Human decisions:** key custody/service ownership; new key domain; exact expiry/skew; rotation overlap; supported message types and fan-out semantics.

## ADR-006 — Action normalization and canonicalization

**Current record:** Untracked draft says JCS is authoritative and proposes a native LLM tool-call adapter. Status is proposed.

**Amend:**

1. Keep the TRD single normalization entry requirement. A tool-call adapter may only translate a fixed registered tool name and typed arguments into a raw ActionProposal; it must not execute or dispatch.
2. Bind identity, mission, task, capability, scope, risk, policy version, approval, and replay to trusted kernel context. The LLM cannot set trusted identity, scope, risk, approval state, or policy fields.
3. Add capability-specific parameter schemas. Current `parameters: Value` has no registry schema, so envelope `deny_unknown_fields` does not reject unknown tool arguments.
4. Treat RFC 8785 as **proposed pending ratification**, not “reaffirmed authoritative.” Current Rust `canonical.rs` is not sufficient evidence of JCS conformance; Python implementation and interoperability tests are absent.
5. Preserve the existing Phase 1 hash format unless an approved versioned migration is made. Any switch to a conformant JCS implementation must be assessed for compatibility with stored approvals, audit records, replay keys, and existing hashes.
6. Reject trailing data at raw JSON ingress; require a shared strict parser contract or equivalent independently tested behavior in each language.
7. Do not call a public/deserializable `CanonicalAction` proof of authorization. Require an unforgeable kernel decision receipt or durable authorization state that the Broker verifies before side effects.
8. Add tests for direct and native-tool-call paths, unknown fields at envelope and parameter levels, duplicate keys, trailing data, risk/identity spoofing, action hash mutation, and a forged CanonicalAction submitted directly to the Broker.

**Human decisions:** JCS ratification and hash migration policy; schema ownership; kernel-to-broker receipt shape; tool-name-to-capability registry ownership.

## Security acceptance registry proposal

The current gate registry correctly maps `GATE-REPLAY-001` to `TEST-REPLAY-001`. A separate status inconsistency remains: Phase 2 is `COMPLETE_WITH_WARNINGS` and its test registry has `IMPLEMENTED_PASSING` entries, while some Phase 2 rows in `security/traceability/security-traceability.yaml` remain pending with null target paths. Do not silently change the security baselines; the Security Architecture Owner should reconcile statuses and evidence links through the approved registry process.

The eight registered Phase 3 gates remain pending: content isolation, prompt guard, tool output, A2A authentication, egress filter, parser sandbox, graph integrity, and LLM egress. Expand their test contracts for the new requirements or add separate gates for A2A replay/mission/recipient, signer restriction, parser exhaustion, gateway OS isolation, transport TLS/pinning, and action authorization bypass. OWASP category mapping alone does not satisfy these gates.

## ADR-002 and ADR-003

No architecture change is proposed. Preserve worker mTLS identity separation and rootless sandbox containment. A2A message keys must not reuse worker identity keys. Existing Phase 2 production-execution restrictions remain in force until formal release approval.

