# ARKA Phase 3.1c — Architecture Reconciliation Report

**Status:** Proposed reconciliation; human ratification pending
**Verdict:** PASS WITH BLOCKERS for this documentation package. Phase 3 acceptance is not passed.
**Baseline:** `feat/p2-execution-plane`, commit `abf6da7b005e7ed8b49991c00667eb6242d00d6e`
**Scope:** Documentation and read-only source review only. No runtime behavior is changed or authorized.

## 1. Decision summary

The Phase 3 drafts are not an approved architecture baseline. The repository records Phase 3 as `NOT_STARTED`; the proposed ADR-004, ADR-005, ADR-006, Phase 3 plan, and Phase 3 OWASP traceability file are untracked worktree files with pending approval labels. No historical Git diff or dedicated Phase 3.1b completion report is available. Their current contents were inspected directly and preserved.

The reconciliation keeps the PRD/TRD logical LLM Gateway and A2A requirements, but does not ratify a standalone Rust daemon, the proposed A2A envelope, or RFC 8785 JCS. Those decisions are explicitly open in the decision register. The current source does not support the drafts' claims of TLS 1.3, A2A signing/replay, provider credential isolation, DLP, Python/Rust canonicalization parity, or a Phase 3 execution path.

The required security contract remains: LLMs and agents propose data only; deterministic trusted components make authorization decisions; every side effect uses the approved kernel-to-broker path; missing or inconsistent state denies; provider secrets never enter the agent or model context; production execution remains disabled pending explicit human release approval.

## 2. Baseline and evidence boundary

| Area | Repository evidence | Reconciliation status |
|---|---|---|
| Governance | `AGENTS.md`, mirrored by `agent.md`; `skills.md` says skills are advisory and project policy wins | Governing source is present. `skills.json` referenced by `skills.md` is absent; `skills-lock.json` exists. |
| Product and technical requirements | `ARKA_PRD_v2.2.md`, `ARKA_TRD_v2.2.md` | Present. PRD §9 and TRD §14 require versioned A2A; TRD §§28–30 require gateway credential isolation, classification, and prompt defenses. |
| Acceptance | `security/acceptance/gates.yaml`, `security/acceptance/phase-status.yaml`, `security/tests/tests.yaml`, `security/traceability/security-traceability.yaml`, and `mvp security acceptance gates.md` | Present. Phase 3 is NOT_STARTED. The 7 Phase 3 tests have null test paths and pending status. The MVP additions are explicitly proposed, not adopted. |
| Existing approved ADRs | ADR-001 through ADR-003 | Present and reviewed. ADR-001 describes Hyper/Rustls and TLS verification; current workspace source contains no TLS implementation or Hyper/Rustls dependency. |
| Phase 3 drafts | Phase 3 plan, OWASP Phase 3 matrix, ADR-004/005/006, plus the earlier OWASP stub | Present as untracked files. Git diff is empty for tracked files and cannot show history for untracked files. No dedicated 3.1b report was found. |
| A2A/Gateway implementation | `rg --files crates arka` | No A2A module, gateway crate, agent runtime, provider adapter, Python canonicalizer, or provider credential loader is present. |
| Current JSON/action path | `crates/arka-crypto/src/json_strict.rs`, `crates/arka-kernel/src/actions/normalizer.rs`, `crates/arka-core-types/src/actions.rs` | Rust action ingress has a 64 KiB cap, depth 8, duplicate-key rejection, and strict top-level action fields. |
| Current network path | `crates/arka-network-policy/src/dns.rs`, `validator.rs`, `connector.rs`, `redirect.rs` | DNS resolution, IP checks, pinned TCP dialing, peer IP comparison, and redirect revalidation exist. This is not a TLS or provider HTTP client. |
| Production status | `security/acceptance/phase-status.yaml` | Phase 2 is COMPLETE_WITH_WARNINGS and production execution is disabled pending human release sign-off. Phase 3 is NOT_STARTED. |

## 3. Findings ranked by severity

### Critical — current canonicalizer is not evidence of RFC 8785 conformance

`crates/arka-crypto/src/canonical.rs` sorts keys using Rust `BTreeMap<String, _>` ordering and comments that this matches UTF-16 ordering. RFC 8785 requires ordering property names by UTF-16 code units; the RFC explicitly says UTF-8/UTF-32 order can differ. The code also serializes integer variants directly and uses Rust `f64::to_string()`; the repository has only simple ASCII key-order and whitespace tests, not the RFC number/string edge vectors. No Python canonicalizer or cross-language test suite exists.

Therefore the draft's statements that this is a verified JCS implementation or that Python/Rust hashes will match are unsupported. Because the existing kernel uses this routine in action parameter and action hashes, exact compatibility with its current hash format must be preserved or migrated only through a separately approved versioned change. RFC 8785 remains proposed pending ratification and executable evidence. See [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), especially §§3.1–3.2 and Appendix B.

### Critical — TLS 1.3 and certificate/hostname verification are not implemented in the current connector

`DirectIpConnector::connect` creates `tokio::net::TcpStream`, connects to the pinned IP, and checks `peer_addr`. It performs no TLS handshake, certificate-chain validation, SNI, or hostname verification. The workspace manifests contain no Hyper or TLS crate. ADR-001 is an accepted design decision, not proof that this implementation exists. The Phase 3 draft must not claim “Pinned TLS 1.3” based on the TCP connector.

A future provider transport must separately prove: allowed DNS name, resolved IPv4/IPv6 set validation, exact pinned-IP TCP dial, TLS protocol policy, SNI for the configured hostname, trusted-root chain verification, hostname verification against that hostname, and rejection of redirects/downgrades not explicitly authorized.

### High — gateway and provider-secret isolation are specified only on paper

The PRD/TRD require a logical LLM Gateway to be the only provider-credential resolver. No gateway process, service identity, UDS, peer-authentication code, provider adapter, secret source, endpoint allowlist, OS egress policy, DLP, or provider error redaction exists in source. An environment-variable label such as `ARKA_UNSAFE_DEV_CO_LOCATED_GATEWAY=true` cannot establish isolation. A process holding real provider secrets must not share an OS identity or address space with an untrusted agent process.

The gateway may fail closed when unavailable or when its credential source, policy, DNS, TLS, or audit dependency is unavailable. It must never fall back to a provider SDK in the agent process.

### High — A2A is absent, and the draft exceeds the actual parser bound

There is no A2A transport or parser. The existing Rust `StrictJsonParser` accepts at most 65,536 bytes and depth 8. ADR-005 proposes 256 KiB, while ADR-004 proposes 10 MiB gateway JSON. Those are incompatible with reuse of the existing parser. Set A2A v1 to a 64 KiB encoded-message ceiling and depth 8 unless a separately reviewed parser contract replaces that limit at every ingress. Reject duplicate keys and unknown envelope fields. Python A2A currently has no actual parser; its contract must match the Rust boundary.

The A2A draft also lacks a complete trusted key-to-AgentId/MissionId binding, recipient/audience enforcement, key revocation/rotation rules, bounded signing authority, and durable atomic replay semantics. Its in-memory Bloom filter does not provide a correctness guarantee. No A2A test is implemented or executed.

### High — strict JSON parser does not visibly enforce end-of-input

`StrictJsonParser::parse` calls `seed.deserialize(&mut deserializer)` but does not call the deserializer's end-of-input check. No trailing-data test exists. Until an executable negative test proves that concatenated JSON and non-whitespace trailing data are rejected, strict single-document parsing is unverified. Every JSON ingress contract must reject trailing non-whitespace bytes before policy evaluation.

### High — broker API does not show an unforgeable kernel authorization receipt

`ExecutionBroker::execute_action` accepts a publicly constructible `CanonicalAction`. Its visible integrity preflight checks only that `action_hash` and `parameter_hash` are non-empty; the broker does not visibly recompute them or prove that the kernel authorized that exact action. This source review does not prove a reachable production bypass because no external process API is present, but the kernel-to-broker trust boundary is not evidenced by the code inspected. A forged-action negative test and an unforgeable, mission-bound authorization receipt or durable authorized-state lookup are required before claiming this boundary is verified.

### High — action parameter schemas are not enforced at normalization

`RawActionProposal.parameters` is arbitrary `serde_json::Value`. The current capability metadata lists risk, target classes, timeout, and sandbox profile, but no parameter schema. The normalizer validates the envelope, mission, capability possession, risk declaration, and target class; it does not validate parameter names and types against a per-capability schema. Thus `deny_unknown_fields` on the envelope does not reject unknown tool parameters. The native LLM tool-call adapter is absent. A registry-backed parameter schema must be enforced before authorization.

### Medium — Phase 2 traceability status conflicts with phase and test registries

The phase status registry records Phase 2 as `COMPLETE_WITH_WARNINGS`, and the test registry marks several Phase 2 tests `IMPLEMENTED_PASSING`; however, Phase 2 traceability entries such as `TRACE-SSRF-001` retain `PENDING(phase=2)` and `target_path: null`. The report does not change the security baseline. The Security Architecture Owner must reconcile the affected traceability statuses and evidence links before claiming bidirectional phase completion.

### Medium — proposed Phase 3 evidence is not acceptance evidence

The Phase 3 registry has pending tests with null paths, no CI run IDs, and no Phase 3 evidence artifacts. The OWASP taxonomy rows are planning coverage only. A mapping to an OWASP category does not establish a complete threat model, mitigation, or executable test.

### Medium — draft status and repository history are not reproducible

The current Phase 3 plan and ADR-004/005/006 are untracked. No tracked diff or completion report is available. They are treated as current draft inputs, not approved architecture or historical evidence. This report does not rewrite them.

## 4. Reconciled architecture contract

1. **Authority:** LLM output, agent messages, retrieved material, tool output, and discovered assets are untrusted. Only the deterministic Rust Security Kernel authorizes actions. Discovery never changes scope or authorization.
2. **Execution:** All security-sensitive side effects pass through the existing approved kernel-to-Execution-Broker path. No agent, provider, A2A message, tool call, gateway, or task scheduler can authorize or directly dispatch an action. Authorization, approval, replay consumption, audit, and dispatch must fail closed.
3. **Gateway:** Keep the logical LLM Gateway required by PRD/TRD. Candidate topology is a separate service process and OS identity, reached over a permission-restricted UDS. Exact implementation technology, UID/GID provisioning, socket path, and deployment are pending human decision. Real provider secrets may not be available to agent processes, including development agents. Gateway unavailability means no inference call; no direct SDK or proxy fallback.
4. **Transport:** Pinning is DNS/IP policy plus TCP dialing. TLS and hostname verification are separate controls and currently absent. A future gateway must use an operator-owned endpoint allowlist, ignore ambient proxy variables, validate every IPv4/IPv6 answer, pin each connection, bind SNI/certificate verification to the configured hostname, disable redirects by default, and reject metadata, loopback, link-local, private, multicast, unspecified, and IPv4-mapped evasions unless a separately approved provider profile explicitly permits a local endpoint.
5. **A2A:** Messages carry data only. Versioned strict envelopes bind sender, recipient, mission, task, issue/expiry, nonce, payload hash, key ID, and algorithm. The authenticated sender identity is derived from a kernel-verifiable token/key registry, never trusted from message fields alone. Durable replay handling is atomic across concurrent requests and restarts. A signing service signs only allowlisted, schema-validated messages derived from an active agent/task context; it cannot sign arbitrary bytes or grant authority.
6. **Canonicalization:** JCS is a proposed standard pending ratification. Current Rust code is not sufficient evidence of conformance. All signing/hashing boundaries reject duplicate keys, invalid Unicode, unsupported numeric values, unknown fields, and trailing data. Rust and Python must pass the same committed vectors before either side claims parity.
7. **Credential and egress controls:** Credential source ownership, OS isolation, request authorization, classification, and outbound filtering are separate controls. Secret-pattern matching is defense in depth only. Deterministic source labels and allowlisted context construction enforce data minimization. External transmission defaults to public data only; secret credentials/tokens are always denied and confidential/internal material requires an explicit operator/provider policy. Any uncertain classification or filter failure denies the request.
8. **Production:** The existing Phase 2 production-execution hold remains. Phase 3 egress and agent runtime are also disabled until architecture approval, OS-level evidence, security tests, and explicit human release authorization are recorded.

## 5. Deliverables and limitations

The companion files in this package are the [reconciled plan](PHASE_3.1C_ARCHITECTURE_PLAN.md), [ADR change proposals](adr/PHASE_3.1C_ADR_CHANGE_PROPOSALS.md), [security traceability matrix](PHASE_3.1C_SECURITY_TRACEABILITY.csv), [protocol/vector specification](PHASE_3.1C_PROTOCOL_TEST_VECTORS.md), [human decision register](PHASE_3.1C_DECISION_REGISTER.md), and [validation report](PHASE_3.1C_VALIDATION_REPORT.md). They are proposals. They do not alter the source of truth in the PRD/TRD, machine-readable gate registries, accepted ADRs, baseline manifest, runtime source, executable tests, dependencies, or production settings.

No claim is made that a Phase 3 control is implemented, executed, or passed. The only evidence statuses retained for existing Phase 1/2 controls are those supported by current source/test paths and the repository registries; the validation report records what was actually run in this documentation review.

