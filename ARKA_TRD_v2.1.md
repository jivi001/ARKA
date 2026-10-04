# ARKA — Technical Requirements Document (TRD)
## Revised Security-Hardened Engineering Baseline v2.1
**Architecture:** Rust Security Kernel + Python Intelligence Plane + Sandboxed Execution Plane  
**Target OS:** Debian/Ubuntu Linux; Windows workers  
**Status:** Engineering baseline  
**Normative terms:** MUST, MUST NOT, SHOULD, SHOULD NOT, MAY

---

# 1. Technical Architecture

```text
+---------------------------+
| Presentation / UI         |
+-------------+-------------+
              |
              | authenticated API
              v
+---------------------------+
| Rust Security Kernel      |
|---------------------------|
| Identity                  |
| Mission / Scope           |
| Capability Registry       |
| Action Normalizer         |
| Policy Engine             |
| Risk Engine               |
| Approval Engine           |
| Resource Governor         |
| Credential Broker         |
| Audit / Provenance        |
| Emergency Stop            |
+------+--------------------+
       |
       +----------------------+
       |                      |
       v                      v
+-------------+       +-------------------+
| Intelligence|       | Execution Broker  |
| Plane       |       |                   |
|-------------|       | Rust controlled  |
| Python      |       | execution path   |
| Agents      |       +---------+---------+
| LLM Gateway |                 |
+-------------+                 v
                         +-------------+
                         | Sandbox     |
                         | Linux/Win   |
                         +------+------+
                                |
                                v
                         Authorized Target
```

The Python plane MUST NOT have a direct route to target-scoped networks.

---

# 2. Technology Stack

## 2.1 Rust

Use Rust for:

- Security kernel.
- Policy engine.
- Action normalization.
- Capability enforcement.
- Execution broker.
- Mission isolation enforcement.
- Audit chain.
- Resource governance.
- Credential session control.

Recommended ecosystem:

- Tokio.
- Axum.
- Serde.
- SQLx or equivalent typed database layer.
- Ed25519 implementation.
- tracing.
- UUID/ULID.
- cryptographic hashing libraries.
- OS/network policy integration.

## 2.2 Python

Use Python for:

- Agents.
- LLM adapters.
- Planning.
- Evidence analysis.
- OSINT orchestration.
- Finding correlation.
- Report generation.

Python MUST NOT become a security authority.

## 2.3 Storage

MVP:

- SQLite for single-machine metadata where appropriate.
- WAL mode.
- Strict mission IDs on every record.
- Separate credential storage boundary.

Later:

- PostgreSQL for distributed/multi-user deployment.

## 2.4 Messaging

MVP:

- authenticated local/in-process event mechanism.

Later:

- Redis/NATS for distributed A2A/event delivery.

A message bus MUST NOT become an authorization mechanism.

---

# 3. Trust Boundaries

Required trust zones:

```text
T0 Human / Operator
T1 Presentation
T2 Security Kernel
T3 Intelligence Plane
T4 Execution Broker
T5 Sandbox
T6 Target
T7 External Web / OSINT
T8 LLM Provider
```

Trust assumptions:

- T6 and T7 are hostile/untrusted data sources.
- T8 is external infrastructure and must be treated according to provider/data policy.
- T3 is less trusted than T2.
- T5 is adversarial-execution capable.
- T2 is the security authority.

---

# 4. Security Invariants

## INV-001 — LLM Zero Authority

The LLM MUST NOT directly execute tools, modify scope, approve actions, issue credentials, or alter policy.

## INV-002 — Agent Zero Execution Authority

Agents MUST NOT possess direct target-side execution capabilities.

## INV-003 — DISCOVERED != AUTHORIZED

Discovery MUST NOT modify authorization.

## INV-004 — Child Cannot Exceed Parent

A child task's:

- scope;
- capabilities;
- budgets;
- credential privileges;
- execution class

MUST be a subset of its parent's authority.

## INV-005 — Approval Parameter Binding

Approval MUST bind to a canonical hash of the complete normalized action parameters.

Any parameter mutation invalidates approval.

## INV-006 — Replay Protection

A completed or expired ActionProposal MUST NOT execute again.

## INV-007 — Target Data Is Untrusted

Target-derived content MUST NOT be interpreted as trusted instructions.

## INV-008 — Single Execution Path

Every external side effect MUST flow through the Rust Execution Broker.

## INV-009 — No Parallel Execution Authority

No component outside the Execution Broker may possess an execution capability capable of independently producing target-side or host-side security-sensitive side effects.

## INV-010 — Fail Closed

Security-control failure MUST result in denial, not fallback execution.

---

# 5. Action Model

Canonical action:

```json
{
  "action_id": "act_...",
  "mission_id": "mis_...",
  "parent_task_id": "task_...",
  "capability": "HTTP_REQUEST",
  "target": {
    "hostname": "target.example",
    "ip": "203.0.113.10",
    "port": 443
  },
  "parameters": {},
  "requested_by": "agent-web-01",
  "risk_class": "CONTROLLED",
  "expires_at": "..."
}
```

The system MUST canonicalize parameters before hashing.

Hash input MUST include:

- mission ID;
- parent task;
- capability;
- target;
- normalized parameters;
- relevant policy version;
- authorization context.

---

# 6. Action State Machine

```text
PROPOSED
   |
   v
NORMALIZED
   |
   v
VALIDATING
   |
   +---- DENIED
   |
   +---- APPROVAL_REQUIRED
   |          |
   |          v
   |       APPROVED
   |          |
   +----------+
              |
              v
          AUTHORIZED
              |
              v
          DISPATCHED
              |
              v
          EXECUTING
          /       \
         v         v
    COMPLETED    FAILED
```

Invalid transitions MUST be rejected.

A completed action MUST become non-replayable.

---

# 7. Action Normalization

All of the following MUST enter the same function:

- agent ActionProposal;
- LLM native tool call;
- human-triggered security action;
- internally generated remediation/retest action.

There MUST NOT be a second execution path for LLM function-calling.

Canonical function:

```text
normalize_action(input)
    -> canonical Action
```

Only normalized actions may reach authorization.

---

# 8. Capability Model

Capabilities are explicit typed permissions.

Examples:

```text
DNS_LOOKUP
TCP_CONNECT
PORT_SCAN
HTTP_REQUEST
WEB_DISCOVERY
BROWSER_AUTOMATION
OSINT_LOOKUP
PCAP_CAPTURE
SERVICE_ENUMERATION
CREDENTIAL_VALIDATION
CONTROLLED_EXPLOITATION
WINDOWS_COMMAND
LINUX_TOOL_EXECUTION
```

Capabilities MUST specify:

- ID;
- risk class;
- required approvals;
- allowed target classes;
- network requirements;
- resource limits;
- sandbox profile;
- evidence types;
- credential requirements.

There is no generic unrestricted `SHELL` capability.

---

# 9. Risk Classes

Suggested classes:

```text
OBSERVATION
LOW
MODERATE
HIGH
CRITICAL
```

Risk is determined by deterministic policy.

Examples:

- Passive DNS lookup → OBSERVATION.
- Authorized port scan → LOW/MODERATE.
- Authenticated testing → HIGH.
- Controlled exploitation → CRITICAL.

Risk classification is not itself authorization.

---

# 10. Scope Engine

Scope must support:

- IPv4.
- IPv6.
- CIDR.
- DNS names.
- URL origins.
- ports.
- protocols.
- path restrictions where applicable.

Scope evaluation MUST happen:

1. proposal time;
2. authorization time;
3. execution time;
4. network connection time.

---

# 11. SSRF and Redirect Controls

Every HTTP-capable worker MUST:

1. Resolve destination.
2. Validate resolved IP.
3. Validate against mission scope.
4. Block disallowed ranges.
5. Connect.
6. Revalidate every redirect.
7. Revalidate DNS results.
8. Prevent DNS rebinding.
9. Prevent metadata endpoint access unless explicitly authorized.

Default-deny ranges include appropriate:

- loopback;
- link-local;
- RFC1918;
- IPv6 local/link-local;
- cloud metadata addresses.

Exceptions require explicit scope.

---

# 12. Intelligence Plane Network Policy

Python agents MUST NOT have:

- direct route to target networks;
- unrestricted Docker bridge access;
- raw socket access;
- arbitrary outbound HTTP to targets.

Allowed network destinations SHOULD be limited to:

- Rust kernel;
- configured LLM endpoints;
- explicitly approved control-plane services.

This must be enforced at OS/container network level, not merely in Python code.

---

# 13. Agent Identity

Each agent receives a short-lived Ed25519-signed identity/capability token.

Token contains:

```text
agent_id
mission_id
parent_task_id
capabilities
scope_ref
issued_at
expires_at
token_id
parent_token_id
```

Tokens MUST:

- be memory-only;
- never be written to disk;
- never enter LLM context;
- never appear in logs;
- be short-lived;
- be revocable;
- be mission-bound.

---

# 14. A2A Protocol

Messages MUST include:

- message ID;
- mission ID;
- sender;
- recipient;
- parent task;
- schema version;
- timestamp;
- nonce;
- payload hash;
- signature/authentication metadata.

Replay detection uses message ID/nonce plus lifecycle state.

Agents cannot issue capability tokens.

---

# 15. Governing Council

The governing layer validates:

- schema;
- mission relationship;
- proposal consistency;
- confidence;
- evidence references;
- task dependency;
- policy metadata.

It MUST NOT bypass the Rust authorization engine.

---

# 16. Execution Broker

The broker is the only component allowed to dispatch executable capabilities.

Responsibilities:

- verify action hash;
- verify approval;
- verify token;
- verify scope;
- verify budget;
- create sandbox;
- establish network policy;
- inject permitted credentials;
- execute;
- capture evidence;
- clean up;
- report result.

Broker failure MUST deny execution.

---

# 17. Sandbox Requirements

MVP Linux sandbox:

- rootless container;
- seccomp;
- AppArmor where supported;
- dropped capabilities;
- read-only root filesystem;
- no privileged mode;
- isolated PID namespace;
- isolated network namespace;
- explicit egress allowlist;
- CPU limit;
- memory limit;
- process limit;
- disk quota;
- execution timeout.

Sandbox MUST NOT:

- reach host network;
- reach other mission sandboxes;
- mount host filesystem except explicit read-only inputs;
- access another mission's credentials.

---

# 18. Strong Isolation

Future high-risk execution SHOULD support:

- gVisor;
- Firecracker;
- microVM;
- dedicated VM workers.

`CONTROLLED_EXPLOITATION` MUST remain disabled until the required isolation profile is available.

Configuration:

```text
ENABLE_CONTROLLED_EXPLOITATION=false
```

Any attempt to enable it without the required isolation profile MUST fail closed.

---

# 19. Credential Architecture

Credential material is owned by the Credential Broker.

The LLM MUST NOT receive raw credential material by default.

Credential session:

```json
{
  "session_id": "cred_...",
  "mission_id": "mis_...",
  "capability": "CREDENTIAL_VALIDATION",
  "target": "...",
  "issued_at": "...",
  "expires_at": "...",
  "revocable": true
}
```

Credentials MUST be:

- encrypted at rest;
- separated from ordinary mission data;
- access-controlled;
- time-limited;
- mission-bound;
- capability-bound;
- revocable.

Encryption keys MUST NOT be stored beside ciphertext.

MVP should use an OS-backed secret store where practical.

---

# 20. Credential Revocation

Revocation MUST perform:

```text
revoke session
      |
      +--> broker invalidates session
      |
      +--> terminate dependent execution
      |
      +--> revoke network access
      |
      +--> scrub temporary credential material
      |
      +--> record audit event
```

Revocation cannot depend solely on a future credential check.

---

# 21. Evidence Architecture

Evidence object:

```json
{
  "evidence_id": "ev_...",
  "mission_id": "mis_...",
  "task_id": "task_...",
  "source": "nmap",
  "created_at": "...",
  "content_hash": "...",
  "trust": "untrusted",
  "sensitivity": "internal",
  "content_ref": "...",
  "parent_refs": []
}
```

Evidence is immutable.

Parsers MUST run in an appropriate sandbox.

Evidence parsing is itself an attack surface.

---

# 22. Evidence Classification

Classification occurs at ingestion:

```text
raw artifact
    ↓
safe parser
    ↓
trust classification
    ↓
sensitivity classification
    ↓
hash
    ↓
immutable persistence
```

The LLM outbound policy MUST consume these classifications.

Classification must not rely exclusively on an LLM.

---

# 23. Audit System

Use a hash chain:

```text
H0
 |
 v
Event1 -> H1
 |
 v
Event2 -> H2
 |
 v
Event3 -> H3
```

Each event:

```text
previous_hash
event_payload
event_hash
```

Audit MUST record:

- proposal;
- normalization;
- policy decision;
- approval;
- execution;
- evidence;
- failures;
- revocation;
- emergency stop.

---

# 24. Evidence Integrity

Evidence records MUST be content-addressed or hash-bound.

A post-creation mutation MUST be detectable.

Where possible, use append-only storage semantics.

---

# 25. Mission Isolation

Every mission-owned resource MUST contain mission identity.

Database queries MUST enforce mission ownership.

Application-level filtering alone SHOULD NOT be the only isolation boundary for secrets.

Required isolated objects:

- evidence;
- memory;
- knowledge graph;
- credentials;
- agents;
- tasks;
- workers;
- capability tokens;
- audit views.

---

# 26. Knowledge Graph

Nodes:

```text
Asset
Host
IP
Domain
Port
Service
Technology
Endpoint
Credential
Vulnerability
Evidence
Finding
Task
Agent
```

Edges:

```text
RESOLVES_TO
RUNS
EXPOSES
USES
AFFECTED_BY
SUPPORTED_BY
DISCOVERED_BY
EVIDENCED_BY
DERIVED_FROM
```

The graph stores observations and relationships, not authorization.

---

# 27. Memory Architecture

Memory tiers:

1. Mission state.
2. Evidence.
3. Structured findings.
4. Knowledge graph.
5. Agent working memory.
6. Long-term reusable knowledge where policy permits.

Memory retrieval MUST enforce mission isolation.

Untrusted target content MUST retain trust metadata.

---

# 28. LLM Gateway

Provider adapters SHOULD support:

- OpenAI-compatible APIs.
- Anthropic-compatible APIs.
- local models.
- future providers.

Gateway responsibilities:

- model selection;
- timeout;
- retry;
- cost tracking;
- context policy;
- data classification;
- redaction;
- structured output validation.

LLM provider output MUST be treated as untrusted input.

---

# 29. LLM Data Policy

Before external transmission:

```text
evidence
  ↓
classification
  ↓
sensitivity policy
  ↓
redaction/minimization
  ↓
provider policy
  ↓
LLM
```

Professional deployments SHOULD support:

- local models;
- provider contractual controls;
- configurable retention policy;
- explicit external-data policy.

---

# 30. Prompt-Injection Defense

Agents MUST treat:

- web pages;
- documents;
- HTTP bodies;
- screenshots;
- source code;
- tool output;
- OSINT content

as untrusted data.

Instruction-like text inside evidence MUST NOT automatically become an instruction to the agent.

Agent system instructions remain outside target-derived evidence.

---

# 31. Tool Output Security

Tool output MUST be:

- schema-validated where structured;
- size-limited;
- classified;
- sanitized for control characters where necessary;
- associated with provenance;
- prevented from modifying policy state.

---

# 32. Resource Governor

Limits:

```text
mission CPU
mission memory
mission storage
agent CPU
agent memory
tool execution time
network bytes
request count
LLM tokens
LLM spend
```

Agents cannot modify their own budgets.

Exceeding a budget MUST halt the affected execution path.

---

# 33. Failure Semantics

Failure classes:

```text
AUTHORIZATION_FAILURE
SCOPE_FAILURE
CAPABILITY_FAILURE
POLICY_FAILURE
SANDBOX_FAILURE
NETWORK_POLICY_FAILURE
CREDENTIAL_FAILURE
RESOURCE_EXHAUSTION
PROVIDER_FAILURE
EVIDENCE_FAILURE
AUDIT_FAILURE
```

Security failures MUST deny.

Transient intelligence failures MAY trigger bounded retry.

Execution retries MUST not bypass authorization.

---

# 34. Fallback Behavior

If an agent discovers nothing:

```text
No Finding
   ↓
Record negative observation
   ↓
Check remaining authorized hypotheses
   ↓
Request additional evidence
   ↓
Re-plan
```

ARKA MUST NOT:

- expand scope automatically;
- escalate privileges automatically;
- invent credentials;
- switch to unauthorized targets.

If all authorized hypotheses fail, the task terminates as inconclusive/negative.

---

# 35. Credential-Required Targets

If target requires authentication:

```text
detect authentication
      ↓
classify requirement
      ↓
check mission credential policy
      |
      +-- no credential authorized -> report blocked state
      |
      +-- credential available -> request scoped credential session
      |
      v
broker validates session
      ↓
authorized execution
```

ARKA MUST NOT fabricate authorization.

---

# 36. OSINT Architecture

OSINT workers may access external sources only through approved capabilities.

External sources are untrusted.

OSINT results require:

- source URL/reference;
- retrieval time;
- content hash where practical;
- confidence;
- provenance.

OSINT discovery does not authorize target execution.

---

# 37. Recon Tool Integration

Tools should be wrapped as typed capabilities rather than exposed as arbitrary binaries.

Example:

```text
NMAP_SCAN
  inputs:
    target_scope
    ports
    timing_profile
  outputs:
    hosts
    ports
    services
    evidence_refs
```

The wrapper validates parameters before execution.

---

# 38. Browser Automation

Browser automation MUST run inside the Execution Broker.

Python agents MUST NOT directly launch Playwright against targets.

Required controls:

- target scope;
- navigation allowlist;
- redirect validation;
- DNS validation;
- download restrictions;
- filesystem isolation;
- resource limits;
- screenshot evidence;
- browser process cleanup.

---

# 39. Linux Worker

Linux worker should support controlled tool wrappers.

No unrestricted shell API is exposed to agents.

Tools are selected from an allowlisted registry.

---

# 40. Windows Worker

Windows worker requirements:

- non-admin by default;
- PowerShell Constrained Language Mode where applicable;
- WDAC/AppLocker allowlisting;
- explicit executable allowlist;
- isolated workspace;
- credential injection through broker;
- process timeout;
- process-tree cleanup;
- network policy enforcement.

A capability cannot activate if required Windows controls are absent.

---

# 41. API Security

Use:

- TLS/mTLS where appropriate;
- authenticated service identity;
- short-lived service tokens;
- request IDs;
- replay protection;
- schema validation;
- rate limiting;
- authorization checks.

Cross-plane communications MUST authenticate both sides.

---

# 42. Authentication

Human authentication SHOULD support:

- local authentication for MVP;
- MFA;
- OIDC;
- future SSO/SAML.

High-risk approval operations require strong authentication.

---

# 43. Approval Service

Approval object:

```json
{
  "approval_id": "apr_...",
  "mission_id": "mis_...",
  "action_hash": "...",
  "approver": "user-123",
  "issued_at": "...",
  "expires_at": "...",
  "status": "approved"
}
```

The executor MUST recompute the action hash and compare it with the approval.

Mismatch = DENY.

---

# 44. Emergency Stop

Emergency stop must be implemented at the kernel/broker layer.

It must:

- block new dispatches;
- invalidate tokens;
- revoke credential sessions;
- terminate workers;
- cut worker network access;
- clean temporary credentials;
- append audit event.

Agent requests cannot override emergency stop.

---

# 45. Concurrency

Mission resources must use explicit concurrency controls.

SQLite MVP:

- WAL;
- transactions;
- foreign keys;
- appropriate indexes;
- serialized security-sensitive mutations.

Security state transitions MUST be transactional.

---

# 46. Database Core Schema

Minimum entities:

```text
users
missions
mission_scopes
agents
agent_tokens
tasks
action_proposals
approvals
executions
capabilities
credential_sessions
evidence
findings
knowledge_nodes
knowledge_edges
audit_events
resource_budgets
workers
```

Foreign keys MUST enforce ownership relationships.

---

# 47. Transactional Requirements

The following MUST be atomic where applicable:

- authorization state transition;
- approval consumption;
- execution dispatch state;
- credential session creation/revocation;
- emergency stop state;
- budget consumption.

Avoid check-then-act races.

---

# 48. Replay Protection

Replay keys may combine:

```text
mission_id
action_id
proposal_id
nonce
```

Completed proposals MUST be marked terminal.

An identical old proposal MUST NOT cause a second execution.

---

# 49. TOCTOU Protection

Approval must reference the canonical parameter hash.

At execution:

```text
received action
     ↓
canonicalize
     ↓
hash
     ↓
compare approval hash
     ↓
execute only if equal
```

Do not trust cached proposal parameters.

---

# 50. Network Egress

Sandbox egress is deny-by-default.

Rules are generated from:

- mission scope;
- capability;
- protocol;
- destination;
- port;
- worker policy.

Network rules MUST be applied before execution.

---

# 51. Metadata Endpoint Protection

Default deny:

```text
169.254.169.254
169.254.170.2
IPv6 cloud metadata equivalents
loopback
link-local
private networks
```

Exceptions require explicit authorized internal-testing scope.

---

# 52. Dependency Security

Use:

- pinned dependencies;
- lockfiles;
- vulnerability scanning;
- SBOM generation;
- signed/verified container images where available;
- minimal base images;
- reproducible builds where practical.

No agent may install arbitrary dependencies into the host.

---

# 53. Secret Management

Secrets MUST NOT be:

- committed;
- logged;
- inserted into prompts;
- stored in ordinary mission tables;
- exposed in error messages.

Use environment injection only inside tightly controlled execution boundaries and prefer file descriptors/IPC or platform secret facilities where possible.

---

# 54. Logging

Application logs MUST NOT contain:

- raw passwords;
- private keys;
- access tokens;
- session credentials;
- agent capability tokens.

Structured logging should include correlation IDs.

---

# 55. Reporting Pipeline

```text
Evidence
   ↓
Finding Correlation
   ↓
Severity / Confidence
   ↓
Evidence Validation
   ↓
Report Generation
   ↓
Human Review
   ↓
Final Report
```

LLM-generated narrative MUST reference structured evidence.

---

# 56. Observability

Metrics:

- actions proposed;
- actions denied;
- actions approved;
- actions executed;
- execution failures;
- sandbox failures;
- policy failures;
- evidence count;
- agent latency;
- LLM latency;
- LLM cost;
- resource usage.

Observability data must obey secret-redaction rules.

---

# 57. Testing Strategy

Testing layers:

1. Unit.
2. Property-based.
3. Integration.
4. Security regression.
5. Sandbox.
6. Network policy.
7. Fuzzing.
8. End-to-end.
9. Red-team simulation.

---

# 58. Mandatory Security Tests

## Authorization

- [ ] LLM cannot approve its own action.
- [ ] Agent cannot directly execute a capability.
- [ ] Child cannot exceed parent capability.
- [ ] Child cannot expand parent scope.
- [ ] Parameter mutation invalidates approval.
- [ ] Replayed proposal cannot execute.
- [ ] Expired approval cannot execute.
- [ ] Denied action cannot execute.

## Mission isolation

- [ ] Mission A cannot read Mission B evidence.
- [ ] Mission A cannot access Mission B credentials.
- [ ] Mission A cannot access Mission B memory.
- [ ] Mission A cannot access Mission B knowledge graph.
- [ ] Mission A cannot access Mission B workers.
- [ ] Agent cannot acquire another mission's token.

## Network

- [ ] Intelligence Plane cannot route to target networks.
- [ ] Sandbox cannot access host network.
- [ ] Sandbox cannot access another mission sandbox.
- [ ] SSRF to metadata endpoints is blocked.
- [ ] Redirect to out-of-scope target is blocked.
- [ ] DNS rebinding is blocked.
- [ ] Private-range access is blocked unless authorized.

## Credential

- [ ] Raw credential is not visible to LLM by default.
- [ ] Credential session is mission-bound.
- [ ] Credential session is capability-bound.
- [ ] Credential session expires.
- [ ] Credential session can be revoked.
- [ ] Revocation terminates dependent execution.
- [ ] Credential material is scrubbed after emergency stop.

## Evidence

- [ ] Evidence receives sensitivity classification at ingestion.
- [ ] Evidence receives trust classification at ingestion.
- [ ] Evidence mutation is detectable.
- [ ] Evidence parser cannot directly access host resources.

## Agent identity

- [ ] Agent token cannot be forged.
- [ ] Agent token cannot be reused after expiry.
- [ ] Agent token cannot be used by another mission.
- [ ] Agent token is not written to disk.
- [ ] Agent token is not visible to LLM context.
- [ ] Revocation invalidates token.

## Resource governance

- [ ] Agent cannot increase its own budget.
- [ ] Budget exhaustion halts execution.
- [ ] LLM cost limit is enforced.
- [ ] Worker timeout terminates execution.

## Execution

- [ ] All execution reaches broker.
- [ ] No direct Playwright path exists in Python.
- [ ] No generic shell capability exists.
- [ ] Exploitation is disabled by default.
- [ ] Exploitation cannot run without required isolation.

## Windows

- [ ] PowerShell capability requires required policy mode.
- [ ] Application allowlisting is enforced.
- [ ] Disallowed executable cannot run.
- [ ] Worker cleanup terminates child processes.

---

# 59. Fuzzing Targets

Fuzz:

- Action normalization.
- Scope parser.
- CIDR parser.
- URL parser.
- redirect handling.
- DNS resolution state.
- A2A message parser.
- Evidence parsers.
- report input schemas.
- capability manifests.

---

# 60. Property-Based Security Properties

Examples:

```text
For every action:
authorized(action) == false
    => execution(action) == impossible
```

```text
For every child:
authority(child) ⊆ authority(parent)
```

```text
For every approval:
hash(execution_parameters) == approved_hash
```

```text
For every mission:
resource.mission_id == requester.mission_id
```

---

# 61. Build Pipeline

CI SHOULD execute:

```text
format
lint
unit tests
integration tests
security tests
dependency scan
SBOM
container scan
fuzz smoke tests
```

Release MUST fail when security gates fail.

---

# 62. Repository Structure

Suggested:

```text
arka/
├── kernel/
│   ├── auth/
│   ├── policy/
│   ├── scope/
│   ├── capabilities/
│   ├── approvals/
│   ├── execution/
│   ├── credentials/
│   ├── audit/
│   ├── missions/
│   └── resources/
│
├── intelligence/
│   ├── agents/
│   ├── llm/
│   ├── planning/
│   ├── a2a/
│   ├── osint/
│   ├── analysis/
│   └── reporting/
│
├── workers/
│   ├── linux/
│   └── windows/
│
├── evidence/
├── schemas/
├── policies/
├── migrations/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   ├── fuzz/
│   └── e2e/
│
├── ui/
└── docs/
```

---

# 63. API Contract Principles

APIs MUST:

- use versioned schemas;
- reject unknown security-critical fields where appropriate;
- validate all IDs;
- validate mission ownership;
- use explicit capability identifiers;
- return deterministic authorization errors;
- avoid leaking secrets.

Suggested API groups:

```text
/v1/auth
/v1/missions
/v1/scopes
/v1/agents
/v1/actions
/v1/approvals
/v1/executions
/v1/evidence
/v1/findings
/v1/audit
/v1/reports
/v1/workers
/v1/emergency-stop
```

---

# 64. Error Model

Example:

```json
{
  "error": {
    "code": "SCOPE_DENIED",
    "message": "Requested destination is outside mission scope.",
    "request_id": "req_...",
    "retryable": false
  }
}
```

Errors MUST NOT expose credentials or sensitive target information unnecessarily.

---

# 65. Development Order

The team MUST NOT begin by building autonomous exploitation.

Required order:

```text
1. Security kernel
2. Data model
3. Scope engine
4. Capability model
5. Action normalization
6. Authorization
7. Audit
8. Broker
9. Sandbox
10. Network policy
11. Evidence pipeline
12. Agent protocol
13. LLM gateway
14. Basic agents
15. Recon
16. OSINT
17. Reporting
18. Credentials
19. Windows worker
20. Strong isolation
21. Controlled exploitation
```

---

# 66. Definition of Technical Completion

MVP cannot be declared complete until:

- [ ] No LLM direct execution path exists.
- [ ] No Python target-network route exists.
- [ ] No generic shell capability exists.
- [ ] All actions use normalization.
- [ ] All actions use deterministic authorization.
- [ ] All approvals are parameter-hash bound.
- [ ] Replay protection works.
- [ ] Mission isolation tests pass.
- [ ] Network egress tests pass.
- [ ] SSRF/redirect/DNS-rebinding tests pass.
- [ ] Audit hash chain passes integrity verification.
- [ ] Evidence integrity is verifiable.
- [ ] Evidence classification occurs at ingestion.
- [ ] Credential sessions are scoped and revocable.
- [ ] Credential revocation actively cleans dependent execution.
- [ ] Agent tokens are ephemeral and memory-only.
- [ ] Tokens never enter LLM context.
- [ ] Resource exhaustion fails closed.
- [ ] Emergency stop works.
- [ ] Controlled exploitation defaults OFF.
- [ ] Required isolation is enforced before exploitation.
- [ ] Windows PowerShell controls are mandatory where exposed.
- [ ] LLM native tool calls use the same authorization path.
- [ ] All security tests pass in CI.

---

# 67. Threat Model Summary

Primary threats:

1. Malicious target content.
2. Prompt injection.
3. Tool-output poisoning.
4. Rogue agent.
5. Forged A2A message.
6. Token theft.
7. Replay.
8. Scope expansion.
9. SSRF.
10. DNS rebinding.
11. Credential theft.
12. Sandbox escape.
13. Host compromise.
14. Cross-mission data leakage.
15. Audit tampering.
16. Evidence tampering.
17. Resource exhaustion.
18. LLM provider data exposure.
19. Dependency compromise.
20. Operator misuse.

Every threat must map to:

```text
threat
→ control
→ implementation
→ test
→ acceptance criterion
```

---

# 68. Residual Risks

Known residual risks include:

- container escape before microVM isolation;
- compromised host;
- malicious or compromised LLM provider;
- vulnerabilities in third-party tools;
- operator authorization mistakes;
- previously issued secrets residing temporarily in process memory;
- incomplete OS-specific sandbox enforcement.

Residual risks must be documented rather than hidden.

---

# 69. Security Review Gates

Before each major phase:

```text
Architecture Review
      ↓
Threat Model Review
      ↓
Implementation Review
      ↓
Security Tests
      ↓
Adversarial Tests
      ↓
Release Gate
```

A failed security gate blocks the phase.

---

# 70. Final Technical Principle

ARKA is not an LLM with security tools attached.

It is a deterministic security-control architecture with an AI reasoning subsystem attached to it.

The implementation must preserve this hierarchy:

```text
Human Intent
      ↓
Policy
      ↓
Authorization
      ↓
Execution Broker
      ↓
Sandbox
      ↓
Target
```

AI operates beside and above the execution system for reasoning, but never above the authorization boundary.

---

# Appendix A — Canonical Security Rules

```text
MUST:
- authorize every side effect;
- enforce scope at execution time;
- validate network destinations at connection time;
- bind approvals to canonical parameters;
- isolate missions;
- classify evidence at ingestion;
- audit security-sensitive transitions;
- fail closed.

MUST NOT:
- allow LLM direct execution;
- allow agent direct execution;
- allow automatic scope expansion;
- expose raw credentials by default;
- allow generic unrestricted shell;
- trust target-derived instructions;
- allow stale proposals to replay;
- allow parameter substitution after approval;
- permit Python agents to bypass the broker.
```

---

# Appendix B — Engineering Rule

When a proposed implementation conflicts with a security invariant:

```text
implementation loses.
```

The architecture is not changed merely because a shortcut makes agent development easier.
