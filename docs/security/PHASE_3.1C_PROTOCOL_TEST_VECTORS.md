# Phase 3.1c — Protocol and Canonicalization Test-Vector Specification

**Status:** Specified proposal; no runtime implementation or test vectors are added in this documentation phase.
**Purpose:** Define reproducible Rust/Python protocol behavior before implementation.
**Normative source:** RFC 8785 remains proposed pending explicit ARKA ratification.

## 1. Shared test-vector format

Commit each vector as a data fixture with:

- Stable vector ID and protocol/schema version.
- Input UTF-8 bytes in hex and a human-readable JSON form where valid.
- Expected parse result: accept or reject, with stable reason category.
- For accepted JSON: canonical UTF-8 bytes in hex, payload digest, signature preimage bytes in hex, and expected decoded signature length/encoding when relevant.
- Rust and Python implementation/version identifiers used to produce the result.
- An independently checked expected value. Do not generate expected values at test runtime using the implementation under test.

For each accepted vector, both languages must match canonical bytes, SHA-256 input bytes, payload hash, signature preimage, and verify result byte-for-byte. The same commit SHA and vector artifact hash must be retained in CI evidence. A mismatch denies the message/action and blocks the gate.

## 2. JSON parser and envelope cases

Use the same 65,536-byte maximum encoded message size and depth 8 at every current JSON ingress unless an approved replacement parser defines and proves another contract.

| Vector | Input condition | Expected result |
|---|---|---|
| JSON-01 | Valid UTF-8 object within limits | Accept after strict schema validation |
| JSON-02 | Exactly 65,536 encoded bytes | Accept only if valid and within field/schema budgets |
| JSON-03 | 65,537 encoded bytes | Reject before full parse/allocation |
| JSON-04 | Maximum permitted nesting | Accept if schema permits |
| JSON-05 | Nesting one level over 8 | Reject before dispatch |
| JSON-06 | Duplicate top-level key | Reject before map materialization |
| JSON-07 | Duplicate nested key in payload | Reject before map materialization |
| JSON-08 | Valid JSON followed by a second JSON value | Reject trailing content |
| JSON-09 | Valid JSON followed by non-whitespace garbage | Reject trailing content |
| JSON-10 | Unknown schema version | Reject; no fallback parser |
| JSON-11 | Unknown envelope field | Reject |
| JSON-12 | Unknown typed payload field | Reject for that schema version |
| JSON-13 | Invalid UTF-8 or lone surrogate escape | Reject |
| JSON-14 | Non-finite or unsupported numeric value | Reject |
| JSON-15 | Oversized array/object count under byte cap | Reject under explicit item-count/resource ceiling |
| JSON-16 | Parser cancellation, allocation cap, timeout, or storage failure | Deny and leave no partially accepted message |

The current Rust parser has tests for duplicate keys, depth, and oversize, but no visible end-of-input check. There is no Python A2A parser. These vectors are requirements, not passing evidence.

## 3. JCS success vectors

If and only if ARKA ratifies RFC 8785, include official RFC 8785 examples (including §3.2.2 and Appendix B) and the following cross-language cases:

| Vector | Input property | Required result |
|---|---|---|
| JCS-01 | Object key order changes | Same canonical bytes and hash |
| JCS-02 | Nested objects and objects inside arrays | Recursive object sorting; preserve array order |
| JCS-03 | ASCII and escaped/unescaped equivalent strings | RFC-defined string serialization |
| JCS-04 | Control characters U+0000 through U+001F | Required lowercase escape forms |
| JCS-05 | Non-BMP key U+10000 with BMP key U+E000 | UTF-16 code-unit order, not Rust/Python scalar order |
| JCS-06 | Composed and decomposed Unicode | Preserve exact code-point sequence; do not normalize |
| JCS-07 | Binary64 edge numbers and exponent boundaries | Match ECMAScript-compatible RFC output |
| JCS-08 | Positive and negative zero | Match RFC serialization behavior |
| JCS-09 | Large integer outside exact binary64 representation | Reject or use string by the ratified ARKA data model |
| JCS-10 | Equivalent input number spellings | Same parsed IEEE-754 value and canonical bytes where valid |

Require at least 100 independently sourced shared vectors, including all applicable official RFC vectors. The vector count alone is not a conformance claim; include boundary and rejection classes above.

## 4. JCS rejection vectors

| Vector | Input condition | Expected result |
|---|---|---|
| JCS-R01 | Duplicate object names | Reject before canonicalization |
| JCS-R02 | Lone surrogate / invalid Unicode | Reject |
| JCS-R03 | NaN, Infinity, or -Infinity | Reject |
| JCS-R04 | Integer outside ratified safe numeric model | Reject or require decimal string |
| JCS-R05 | Unknown signed-header field | Reject |
| JCS-R06 | Canonicalization implementation error | Deny; no fallback serializer |
| JCS-R07 | Rust and Python byte mismatch | Deny and fail CI gate |

## 5. A2A payload hash and signature vectors

Candidate version-1 byte contract, pending ADR-005 and JCS ratification:

1. Payload bytes are canonicalized under the ratified scheme.
2. Payload hash is lowercase hexadecimal SHA-256 of `ARKA-A2A-PAYLOAD-V1\0` concatenated with canonical payload bytes.
3. Protected signature object contains protocol, schema version, message ID, mission ID, sender AgentId, recipient AgentId/audience, parent task ID, issued-at, expiry, nonce, payload type, payload hash, key ID, and fixed algorithm identifier.
4. Signature preimage is `ARKA-A2A-MSG-V1\0` concatenated with canonical UTF-8 bytes of the protected object. Signature is detached Ed25519; canonical unpadded base64url encoding must decode to exactly 64 bytes.
5. The untrusted signature field is excluded from the protected object. No other field may be excluded. All identity/audience/time/key fields are signed.

Add positive vectors for sender and receiver on the same mission/task; negative vectors for one-byte changes to each protected field, payload, recipient, mission, task, nonce, key ID, algorithm, signature, and version. Wrong KID/domain, unknown key, revoked key, expired key, wrong mission, wrong recipient, altered payload hash, invalid base64url, non-64-byte signature, and unsupported algorithm all reject.

## 6. Replay, time, concurrency, and restart vectors

Candidate policy values remain pending human approval: maximum message lifetime 60 seconds and future clock skew 30 seconds.

- Issue at current time: accepted once.
- Issue 31 seconds in the future: reject.
- Expiry equal to or before now: reject.
- Lifetime zero or above 60 seconds: reject.
- Missing, negative, overflowing, or malformed timestamps: reject.
- Clock rollback/unverifiable time: deny until trusted time state is restored.
- Repeat same (mission, sender, recipient, KID, nonce): second submission rejects.
- Submit identical nonce concurrently from 2–100 workers: exactly one acceptance, all others replay-denied.
- Restart after durable acceptance: same message remains rejected.
- Crash between replay reservation and agent dispatch: recovery resumes the same durable inbox record idempotently; it must not create a second processing.
- Failure to commit the replay/inbox transaction: do not dispatch.
- Bloom-filter hit/miss must never determine acceptance; durable unique storage is authoritative.

## 7. Signing-service capability vectors

The signer accepts only a typed request bound to active kernel-authenticated agent/task context and an allowlisted message schema. Test:

- Valid finding message signed for the authorized recipient and mission.
- Caller changes sender, recipient, mission, task, expiry, payload type, or key ID: reject or ignore caller-supplied protected values and derive them from trusted context.
- Request asks signer to sign arbitrary bytes, a capability token, action authorization, approval, scope expansion, delegation with increased bounds, or unknown payload type: reject.
- Revoked/expired parent identity or absent task context: reject.
- Message rate or size budget exceeded: reject.
- Signer unavailable or key-domain mismatch: deny; no in-agent private-key fallback.
- Prompt injection asks agent to reveal/use signing key: no key bytes are present in agent memory or prompt context.

## 8. Required test IDs and evidence

Existing pending registry entries to implement and expand:

- `TEST-A2A-FORGERY-001`: signature and protected-field mutation rejection.
- `TEST-PROMPT-INJECTION-001`: target-sourced content cannot change policy or cause an unauthorized action.
- `TEST-LLM-EGRESS-001`: secret, token, credential, and forbidden classification blocks before provider socket write.
- `TEST-EVIDENCE-PARSER-001`: hostile parser content is bounded and isolated.

Proposed additions requiring security registry approval:

- `TEST-A2A-REPLAY-001`, `TEST-A2A-MISSION-001`, `TEST-A2A-RECIPIENT-001`, `TEST-A2A-EXPIRY-001`, `TEST-A2A-REVOKED-KEY-001`.
- `TEST-A2A-STRICT-JSON-001`, `TEST-A2A-RESOURCE-001`, `TEST-A2A-FUZZ-001`, `TEST-A2A-SIGNER-BOUNDARY-001`.
- `TEST-PY-RUST-JCS-001`, `TEST-ACTION-TRAILING-JSON-001`.
- `TEST-GATEWAY-OS-ISOLATION-001`, `TEST-GATEWAY-UDS-PEERCRED-001`, `TEST-GATEWAY-TLS-PIN-001`, `TEST-GATEWAY-ENDPOINT-ALLOWLIST-001`, `TEST-AGENT-EGRESS-OS-001`.
- `TEST-LLM-DATA-CLASS-001`, `TEST-LLM-REDIRECT-001`, `TEST-GATEWAY-FAIL-CLOSED-001`.
- `TEST-BROKER-FORGED-ACTION-001`, `TEST-CAPABILITY-PARAM-SCHEMA-001`.

Each passing test artifact must identify test ID, source/vector hash, commit SHA, CI run ID, environment, expected and actual outcome, and independent reviewer. OS isolation tests must run under real OS identities/network policy; mocks alone do not satisfy them.

