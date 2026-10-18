# ARKA Phase 3 — Reconciled Architecture Plan (Proposal)

**Status:** Proposed; human decisions in `PHASE_3.1C_DECISION_REGISTER.md` block ratification
**Supersedes:** None. This is a review copy; untracked Phase 3 drafts remain untouched.
**Baseline:** `abf6da7b005e7ed8b49991c00667eb6242d00d6e`
**Scope:** Architecture and test contracts only. No Phase 3 runtime work is authorized by this document.

## 1. Governing invariants

- LLMs and agents have zero authorization authority.
- DISCOVERED is never AUTHORIZED.
- The deterministic Rust Security Kernel owns authorization, scope, risk derivation, approval, replay, and emergency-stop decisions.
- Missing, malformed, ambiguous, expired, revoked, inconsistent, or unverifiable state denies.
- Every security-sensitive side effect flows through the approved Execution Broker boundary.
- Provider credentials and other secrets are never available to untrusted agents, prompts, logs, memory, evidence, or ordinary mission records.
- Production execution and production LLM egress remain disabled until explicit human release approval and required evidence exist.
- Existing accepted architecture remains in force unless a named human decision formally supersedes it.

## 2. Logical architecture and trust boundaries

~~~mermaid
flowchart LR
    Operator[Human operator] --> Kernel[Deterministic Rust Security Kernel]
    Agent[Untrusted Python agent and LLM output] -->|untrusted proposal| Normalize[Strict action ingress and normalization]
    Agent <-->|data-only A2A| A2A[Authenticated A2A boundary]
    Agent <-->|model request/result only| Gateway[Isolated LLM Gateway]
    Normalize --> Kernel
    Kernel -->|authorized action only| Broker[Execution Broker]
    Broker --> Worker[Isolated worker]
    Worker -->|untrusted output| Evidence[Evidence quarantine and classification]
    Evidence --> Agent
    Gateway -->|approved model payload| Provider[Configured LLM provider]
~~~

The LLM Gateway and A2A service are not shown as authorization authorities. A2A payloads and model outputs can inform proposals only. The Kernel decides whether a proposal is allowed; the Broker verifies an authorization proof before dispatch. A later implementation must prove this boundary with a forged-action negative test.

## 3. Gateway and provider transport contract

### 3.1 Process and credential ownership

**Required security property:** the process that can read provider credentials is isolated from every untrusted agent process. A real provider secret must never be loaded into the agent's environment, filesystem namespace, or address space. Co-location under an “unsafe” mode flag is not an acceptable isolation control.

**Candidate local deployment contract for human review:**

- Separate service identities for the agent, kernel, gateway, and broker. At minimum, agent and gateway use distinct UIDs and private data directories. Agent cannot ptrace the gateway or read its proc/memory files.
- Candidate UDS: `/run/arka/llm-gateway.sock`, owned by the gateway service identity, group-restricted to the authorized agent service group, mode `0660`. Agent identity can connect but cannot replace the socket or read gateway credential files.
- Gateway checks Linux `SO_PEERCRED` on every accepted connection. Peer UID/GID is an IPC authentication input, not an authorization decision.
- Each inference request must also carry a short-lived kernel-issued identity token bound to agent, mission, task, gateway audience, and expiry. Gateway validates it against trusted key/revocation state and deterministic provider/data policy. The token grants no provider credential or target execution authority.
- Only the Gateway credential resolver reads the provider secret source. The source may be an approved OS secret store or production secret manager. If an environment variable remains allowed for local development by PRD §17/TRD §28, it is injected only into the Gateway process and never inherited by agent processes. No committed, image-baked, agent-readable, or shared-UID `.env` exception is permitted.
- Gateway never returns provider credentials, authorization headers, or raw secret-source errors. Secrets are kept only as long as required for a provider call and are excluded from prompts, audit, logs, evidence, memory, and crash diagnostics.
- Startup fails closed if the configured policy, credential source, revocation state, or required audit path is unavailable. Shutdown stops accepting requests, cancels or marks in-flight calls uncertain, closes sockets, and clears transient buffers. A crash cannot trigger direct-agent provider fallback.
- Human decision remains open on the selected OS deployment model, service manager, UID/GID provisioning, socket path/group, credential source, and whether a remote gateway is ever in scope.

### 3.2 Request authorization, data policy, and egress

- Agents submit model input and receive model output; Gateway requests do not grant action authority. Provider choice, endpoint, model, timeout, token budget, and classification policy come from operator-controlled configuration, never agent-controlled arbitrary URLs.
- External provider destinations are exact allowlisted hostnames and ports in operator-owned configuration. The agent plane has no direct IP route or arbitrary outbound socket permission. Gateway ignores `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and equivalent ambient proxy settings unless an explicitly configured and independently secured proxy is approved.
- Resolve every new connection immediately before dialing; validate all returned A and AAAA addresses; reject mixed safe/unsafe answers; pin the selected IP to that TCP connection and verify the peer address. Re-run policy for each connection. A DNS result is not authorization.
- Block loopback, RFC1918, IPv6 ULA, link-local, cloud metadata, unspecified, multicast, IPv4-mapped IPv6 bypasses, and out-of-allowlist endpoints by default. Local models need a separate operator-configured provider profile and an explicit, narrowly scoped local transport policy; there is no implicit localhost exception.
- Redirects are disabled by default. If a provider requires a redirect, do not follow it automatically: parse the location, require the destination to be on the approved endpoint list, resolve and validate it again, maintain TLS hostname checks, enforce a hop ceiling, and reject HTTPS-to-HTTP downgrade.
- TLS policy is independent from DNS/IP pinning. The transport must prove TLS version policy, SNI, chain validation against configured roots, and certificate hostname verification against the allowlisted hostname. Current source proves only TCP pinning and peer-IP comparison.
- Bound connect, TLS handshake, request, read, total time, response bytes, request bytes, concurrency, retries, tokens, and provider cost. Retry only idempotent inference requests within the approved budget; persistent errors fail closed without credential-bearing diagnostics.

### 3.3 Classification and payload filtering

Use PRD §18 labels: trust `trusted | untrusted | unknown`; sensitivity `public | internal | confidential | secret`.

- Evidence receives deterministic provenance and sensitivity labels before persistence or model-context construction. An LLM classifier may offer a suggestion but cannot downgrade labels or approve egress.
- Proposed default: send only public content to an external provider. Reject secret content, provider/API credentials, target credentials, session tokens, capability tokens, signing keys, private keys, and audit secrets in all modes. Internal/confidential data remains blocked until an operator-approved provider policy explicitly allows the required class and mission.
- Build model context from typed, allowlisted fields and evidence references. Minimize fields and tokens before serialization. Preserve provenance and redaction results.
- Regex/token-pattern scanning is defense in depth. It cannot prove isolation or detect every secret. The security property depends on process-level secret separation, classified sources, deterministic payload construction, and OS egress controls.
- If any item is unclassified, contradictory, unknown, or cannot be safely transformed, deny the request. Do not silently truncate/strip values in a way that changes policy meaning.

## 4. A2A message contract

A2A is data exchange only. It cannot create tasks with broader authority, issue/revoke tokens, alter scope, approve actions, set risk, invoke the Broker, or sign arbitrary authorization assertions.

### 4.1 V1 candidate envelope

The precise schema is proposed pending ADR-005 ratification. Required protected fields:

- `protocol`: fixed identifier `arka-a2a`.
- `schema_version`: exact supported version; unknown versions deny.
- `message_id`: unique typed ID.
- `mission_id`, `sender_agent_id`, `recipient_agent_id`, `parent_task_id`.
- `issued_at_unix`, `expires_at_unix`, `nonce`.
- `payload_type`, typed `payload`, `payload_hash`.
- `key_id`, fixed algorithm `Ed25519`, detached signature.

Candidate encoding is UTF-8 JSON, maximum encoded size 65,536 bytes, maximum nesting depth 8. The existing Rust StrictJsonParser is the only implemented strict parser and already uses those bounds for action JSON. Until an A2A parser exists, no Python-only boundary may claim equivalent behavior. Duplicate keys, trailing content, unknown envelope fields, unknown payload fields for a given schema, invalid IDs, invalid Unicode, invalid signature encoding, and unsupported versions are rejected before dispatch. There is no permissive fallback parser.

### 4.2 Signature, identity, and key lifecycle

- Hash the payload using SHA-256 over a fixed domain separator plus canonical payload bytes. Sign a separate domain-separated preimage containing the exact schema version, message ID, mission, sender, recipient/audience, task, issued/expiry times, nonce, key ID, and payload hash.
- Signature algorithm is fixed by protocol version; reject caller-selected algorithms. Encode 64-byte Ed25519 signatures as canonical unpadded base64url; reject alternate encodings and wrong lengths.
- Resolve key ID through a trusted registry. The registry binds public key, AgentId, permitted mission/task, validity interval, key domain, and revocation state. Header claims alone never establish identity. Mission and recipient are bound in the signed preimage and compared against the authenticated receiver context.
- Key rotation uses distinct key IDs and a short verify-only overlap no longer than the maximum message lifetime. Revocation denies immediately. Unknown, expired, mismatched-domain, or revoked key means reject.
- Existing key policy and Python KeyDomain list have no agent-message-signing domain. A new `AGENT-MESSAGE-SIGNING` domain, distinct from TOKEN-SIGNING, AUDIT-SIGNING, and WORKER-IDENTITY, is a proposal requiring security-owner ratification.
- A signing service accepts only a typed message request for a live kernel-issued agent/task context, validated against allowlisted message and recipient types. It constructs the protected envelope itself. It cannot sign arbitrary bytes, caller-supplied identity/mission/recipient claims, action authorization, scope changes, approvals, capability tokens, or delegation bounds beyond a kernel-issued parent token. The signing key never enters the agent process or LLM context.

### 4.3 Time and durable replay

Candidate time rule: use UTC Unix seconds; require `issued_at <= now + 30 seconds`, `expires_at > now`, and `0 < expires_at - issued_at <= 60 seconds`. Reject missing timestamps, future timestamps outside permitted skew, expired messages, non-monotonic clock state, or expiry exceeding the policy ceiling. The 30-second skew and 60-second lifetime are proposals, not ratified values.

Generate at least 128 bits of CSPRNG nonce. Key durable replay state by mission, sender, recipient, key ID, and nonce. In one durable SQLite transaction, enforce a unique constraint and record the accepted message/inbox state. Concurrent duplicates have exactly one winner; all others deny. Commit before any agent dispatch. Use a transactional outbox/inbox or idempotent dispatch ID so a crash after acceptance cannot cause a second processing or lose replay state. Replay state survives process restarts and is retained through the maximum expiry plus clock-skew window. Bloom filters may accelerate lookup but never decide acceptance.

### 4.4 Rejection semantics

Reject the entire message before agent dispatch on any parse, size, depth, schema, key, identity, audience, mission, task, signature, payload-hash, time, replay, revocation, or storage error. Do not partially process payloads, retry with a permissive parser, fall back to memory-only replay, or expose internal mission/key details in caller errors. Emit a sanitized audit event with stable reason code and message ID/hash only; do not log raw payload or secrets.

## 5. Canonicalization and Rust/Python interoperability

JCS remains **proposed**, even though current Rust source labels its routine JCS. The current implementation is not demonstrated conformant and no Python canonicalizer exists.

If ratified, all implementations must follow RFC 8785 / I-JSON behavior:

- Reject duplicate JSON property names before object construction and reject trailing non-whitespace.
- Preserve Unicode strings as supplied without normalization; reject malformed UTF-8 and lone surrogates. Property ordering uses UTF-16 code units, not locale order or code-point order.
- Use the RFC's ECMAScript-compatible IEEE-754 number serialization. Reject NaN/Infinity and numbers outside the agreed exact input model; represent large exact integers as decimal strings when necessary. Negative zero serializes per RFC behavior.
- Emit UTF-8 with no insignificant whitespace. Reject unknown fields at typed protocol envelopes; payload schemas are version-specific and also reject unknown fields by default.
- Both languages consume the same parsed value semantics and use the exact same domain separators, byte encoding, digest encoding, and signature preimage.
- The committed vector set includes official RFC vectors and ARKA-specific success/error vectors. CI must run them in both Rust and Python and compare canonical bytes, hashes, and signature preimages byte-for-byte. No parity claim is allowed on source inspection alone.

## 6. Authorization and action normalization boundary

- LLM native tool calls and agent proposals are untrusted data. They must be mapped to a fixed registered CapabilityId, wrapped with mission/task identity derived from the authenticated context, and submitted as one raw proposal to the deterministic Rust normalizer.
- The model cannot supply authoritative AgentId, MissionId, risk, scope, approval result, policy version, or authorization token. Those values come from authenticated kernel state.
- The kernel validates strict JSON, typed identifiers, mission binding, capability possession, capability-specific parameter schema, target type, scope, risk derivation, e-stop, budget, approval, and replay. Only a kernel authorization decision can yield an execution receipt/state.
- The Broker accepts only the exact authorized receipt/state and independently checks action/parameter hashes, mission, expiry, single-use status, approval binding, and e-stop. A nonempty hash or a deserialized CanonicalAction alone is insufficient proof.
- Any parse, schema, authorization, approval, replay, audit, database, policy, or dispatch-integrity failure denies. No alternate SDK, shell, direct HTTP, worker, or agent-to-broker path exists.

The current normalizer covers important fields, but source inspection found no capability parameter schemas and no verifiable kernel authorization receipt at the Broker boundary. These are implementation blockers, not completed Phase 1/2 properties.

## 7. Delivery checkpoints and blocking evidence

### P3-A — Architecture and baseline decisions

Deliver: human-approved ADR-004/005/006 amendments; explicit gateway deployment and data policy; resolved key domain and replay contract; corrected acceptance-gate mapping; approved JCS status. No runtime work.

### P3-B — Protocol, schemas, and canonicalization

Implement strict parser end checks and versioned A2A schemas; create capability parameter schemas; select/validate canonicalization implementation; implement the shared cross-language vectors. Required evidence includes negative malformed/duplicate/unknown-field tests, resource bounds, RFC vectors, Python/Rust byte parity, and independent review.

### P3-C — Gateway, signer, and operating-system isolation

Implement approved gateway process/UID/UDS, peer credentials plus kernel-token authorization, credential source isolation, deterministic DLP/classification, provider endpoint policy, pinned TCP plus TLS/hostname verification, no agent direct egress, bounded timeouts/budgets, revocation, and fail-closed startup/shutdown. Required evidence includes OS-level process/memory/socket tests and adversarial provider transport tests.

### P3-D — Agents, evidence, and operations

Implement agent roles only after the authority boundary is proven. Add prompt-injection and tool-output quarantine, deterministic evidence classification/provenance, parser containment, graph provenance, recursion and cost budgets, and end-to-end denial tests. OWASP mappings are input taxonomy, not acceptance evidence.

### Production release gate

No production execution or provider egress until all mandatory gates have test paths, CI run IDs, commit SHA, hashed artifacts, independent review, human CODEOWNER release approval, and any required external OS configuration is verified. Phase 2 production execution remains disabled per the current phase-status registry.

