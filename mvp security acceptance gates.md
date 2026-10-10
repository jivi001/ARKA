# ARKA — MVP Security Acceptance Gates

## Existing MVP Security Acceptance Gates

### IDENTITY & AUTHORIZATION

- [ ] Agent cannot forge another agent's identity.
- [ ] Agent cannot acquire another agent's capability token.
- [ ] Agent cannot expand its own capability set.
- [ ] Agent cannot expand mission scope.
- [ ] Agent cannot modify authorization policy.
- [ ] Agent cannot approve its own action.
- [ ] Approved action cannot execute with parameters different from the approved parameter hash.
- [ ] Expired approval cannot authorize execution.
- [ ] Revoked approval cannot authorize execution.

### REPLAY & MESSAGE SECURITY

- [ ] A stale/replayed ActionProposal cannot re-execute after original completion.
- [ ] A message from one mission cannot be accepted by another mission.
- [ ] A message with an invalid signature/token cannot be accepted.
- [ ] A message outside its validity window cannot be accepted.
- [ ] Agent-to-agent messages preserve mission and provenance identity.

### MISSION ISOLATION

- [ ] Agent cannot access another mission's evidence.
- [ ] Agent cannot access another mission's credentials.
- [ ] Agent cannot access another mission's knowledge graph.
- [ ] Agent cannot access another mission's execution artifacts.
- [ ] Mission identifiers cannot be substituted to bypass isolation.
- [ ] Cross-mission database queries are rejected by the authorization layer.

### EXECUTION AUTHORITY

- [ ] Agent cannot directly execute a subprocess.
- [ ] Agent cannot directly access target-scoped network resources.
- [ ] Agent cannot directly invoke Playwright against a target.
- [ ] Browser execution cannot bypass the Rust Execution Broker.
- [ ] Tool execution without an authorized capability is rejected.
- [ ] Capability parameters are validated before execution.
- [ ] Execution cannot continue after capability expiration.

### NETWORK SECURITY

- [ ] Python Intelligence Plane has no network route to target-scoped hosts at the OS/network-policy layer.
- [ ] Python Intelligence Plane can reach only explicitly permitted services such as the Rust kernel and approved LLM endpoints.
- [ ] Execution sandbox cannot bypass its mission network policy.
- [ ] Sandbox cannot reach another mission's sandbox.
- [ ] Sandbox cannot reach the host network namespace.
- [ ] Sandbox cannot access unauthorized containers.
- [ ] Unauthorized RFC1918 destinations are blocked.
- [ ] Unauthorized link-local destinations are blocked.
- [ ] Cloud metadata endpoints are blocked by default.
- [ ] Destination IP is validated at connection time.
- [ ] Destination IP is revalidated after DNS resolution.
- [ ] Every HTTP redirect is revalidated before connection.
- [ ] DNS rebinding cannot move an authorized hostname to an unauthorized IP.
- [ ] Proxy configuration cannot bypass destination policy.
- [ ] IPv4 and IPv6 destinations are independently policy-validated.

### RESOURCE GOVERNANCE

- [ ] Agent cannot modify its own resource limits.
- [ ] Mission cannot silently exceed its resource budget.
- [ ] Agent exceeding its budget is halted.
- [ ] Mission exceeding its budget fails closed.
- [ ] LLM expenditure cannot exceed the configured mission budget.
- [ ] Tool concurrency cannot exceed the configured limit.
- [ ] Request-rate limits cannot be overridden by an agent.
- [ ] Repeated failed hypotheses cannot create unlimited retries.

### CREDENTIAL SECURITY

- [ ] Credentials are encrypted at rest.
- [ ] Credentials never appear in ordinary application logs.
- [ ] LLM cannot directly access the credential vault.
- [ ] Agent cannot retrieve credentials outside its mission.
- [ ] Credential access requires an authorized capability.
- [ ] Credential broker issues mission-bound access.
- [ ] Credential sessions are time-limited.
- [ ] Credential sessions are revocable.
- [ ] Credential access is auditable.
- [ ] Raw credentials are not unnecessarily exposed to agents.
- [ ] Credential capability is disabled when the mission policy forbids it.

### EVIDENCE SECURITY

- [ ] Evidence records cannot be modified after creation without detection.
- [ ] Evidence provenance cannot be replaced without detection.
- [ ] Evidence is bound to the originating mission.
- [ ] Evidence is bound to the originating action.
- [ ] Evidence is bound to the originating agent/capability.
- [ ] Evidence parser compromise cannot directly compromise the Rust kernel.
- [ ] Malformed evidence cannot crash the trusted control plane.
- [ ] Evidence hashes detect post-creation modification.

### AUDIT SECURITY

- [ ] Audit events are append-oriented.
- [ ] Audit records contain integrity metadata.
- [ ] Audit-chain modification is detectable.
- [ ] Audit events identify the actor that caused the event.
- [ ] Audit events identify the authorization decision.
- [ ] Audit events identify the executed parameter set.
- [ ] Audit events cannot be deleted by an agent.
- [ ] Audit events cannot be rewritten by a sandboxed tool.

### UNTRUSTED CONTENT

- [ ] Target content cannot become ARKA instructions.
- [ ] HTTP responses cannot modify agent authority.
- [ ] Tool output cannot modify agent authority.
- [ ] Browser content cannot modify agent authority.
- [ ] RAG content cannot modify agent authority.
- [ ] Evidence cannot modify authorization policy.
- [ ] Memory cannot grant capabilities.
- [ ] External documents cannot grant capabilities.
- [ ] Prompt injection cannot bypass deterministic authorization.

### SANDBOX SECURITY

- [ ] Sandbox cannot access the Rust kernel's private filesystem.
- [ ] Sandbox cannot access the credential store.
- [ ] Sandbox cannot access another mission's artifacts.
- [ ] Sandbox cannot access the host Docker socket.
- [ ] Sandbox cannot modify its own security profile.
- [ ] Sandbox cannot disable seccomp/AppArmor/gVisor policy.
- [ ] Sandbox cannot obtain host-level privileges through configuration.
- [ ] Sandbox cleanup occurs after normal completion.
- [ ] Sandbox cleanup occurs after timeout.
- [ ] Sandbox cleanup occurs after worker failure.

### FAILURE & RECOVERY

- [ ] Authorization failure results in DENY.
- [ ] Policy-engine failure results in DENY.
- [ ] Identity validation failure results in DENY.
- [ ] Network-policy failure results in DENY.
- [ ] Credential-broker failure results in DENY.
- [ ] Resource-governor failure results in DENY.
- [ ] Worker failure cannot grant additional authority.
- [ ] Agent restart cannot restore expired authority.
- [ ] Stale execution requests cannot resume automatically.
- [ ] Mission cancellation terminates active authorized execution.

## Proposed Additions to `mvp security acceptance gates.md`

**Status:** Proposed. Requires human security-owner review before merge (`AGENTS.md` §19.1).

**Traceability:** INV-xxx = TRD §4; PRD §32 / TRD §58 / TRD §66 noted per section.

Each gate is written so it can be demonstrated by an executable test. Gates marked `[OS]` require OS/network-level evidence; a mock does not satisfy them. Gates marked `[DEFER]` belong to a later phase and should be carried as NOT RUN until then.

### PROVIDER CREDENTIAL SECURITY  (INV-011, INV-012; TRD 28.1-28.7)

- [ ] [OS] Provider credentials are not readable by the agent OS identity/process.
- [ ] Provider credentials are resolved only by the LLM Gateway.
- [ ] Agent code cannot import a provider SDK (CI import-ban test passes).
- [ ] Provider credentials never appear in prompts sent to the model.
- [ ] Provider credentials never appear in agent memory or knowledge-graph content.
- [ ] Provider credentials never appear in evidence records.
- [ ] Provider credentials never appear in audit payloads.
- [ ] Provider credentials never appear in ActionProposal objects.
- [ ] Provider credentials never appear in logs, traces, crash reports, or telemetry (verified with synthetic keys, including on provider-error paths).
- [ ] Authorization headers and bearer tokens are redacted before any log or diagnostic emission.
- [ ] A provider failure does not place credential material in an error message.
- [ ] Provider credentials are not present in source, Git history, or container images (secret-scan passes on repository and built images).
- [ ] Provider credentials are not stored as plaintext in the application database.
- [ ] Provider credentials are never copied into mission records.
- [ ] A provider credential is rejected by every ARKA authentication/authorization path.
- [ ] A provider credential cannot be used to execute, change scope, approve, change policy, issue capabilities, or reach the credential broker.
- [ ] Provider credentials are bound to configured provider endpoints.
- [ ] The Gateway refuses to present a credential to an endpoint outside its binding.
- [ ] An agent cannot modify provider endpoint or credential-binding configuration.
- [ ] Provider credential rotation takes effect without exposing the old or new value.
- [ ] Provider credential revocation / provider disablement stops inference calls.
- [ ] Credential-source unavailability results in DENY (no fallback credential, no unauthenticated call).
- [ ] Local .env files are gitignored and are not used in production configuration.

### LLM AUTHORITY PATH  (INV-001, INV-008, INV-009; PRD 32; TRD 7, 66)

- [ ] LLM native tool calls enter the same normalize_action path as agent proposals.
- [ ] A native tool call denied by policy cannot execute.
- [ ] No code path exists from LLM output to the Execution Broker that skips normalization.
- [ ] Malformed or oversized LLM structured output is rejected before crossing a trust boundary.
- [ ] LLM output cannot set risk_class, approval status, scope, or identity fields that the kernel trusts.
- [ ] LLM outbound context passes classification and redaction before transmission.
- [ ] [OS] The Python plane's only permitted outbound route is the LLM Gateway's pinned provider hosts and the Rust kernel.
- [ ] Attempted exfiltration of classified-secret evidence via prompt content is blocked or redacted.

### DELEGATION & CHILD AUTHORITY  (INV-004; TRD 58, 60)

- [ ] Child scope is a subset of parent scope.
- [ ] Child capabilities are a subset of parent capabilities.
- [ ] Child budgets do not exceed parent budgets.
- [ ] Child credential privileges do not exceed parent privileges.
- [ ] Child execution class and risk ceiling do not exceed parent's.
- [ ] Child token expiry does not exceed parent token expiry.
- [ ] Revoking a parent token invalidates its descendant tokens.
- [ ] Property-based test: for every generated child, authority(child) is a subset of authority(parent).

### AGENT TOKEN HANDLING  (TRD 13; TRD 66)

- [ ] Agent tokens are held in memory only and are never written to disk.
- [ ] Agent tokens never appear in LLM context.
- [ ] Agent tokens never appear in logs.
- [ ] Agent tokens carry mission, audience, expiry, and unique token identity, all verified at the enforcement point.
- [ ] A decoded-but-unverified token is rejected.
- [ ] Token-signing keys, audit-signing keys, and worker identity keys are distinct (no key-domain confusion).
- [ ] A token signed under the wrong key domain is rejected.

### EXPLOITATION GATING  (PRD 14, 32; TRD 18, 66)

- [ ] ENABLE_CONTROLLED_EXPLOITATION defaults to false.
- [ ] Setting the flag to true without the required isolation profile fails closed.
- [ ] Setting the flag alone does not authorize any exploitation action.
- [ ] CONTROLLED_EXPLOITATION requires explicit capability, policy permission, and human approval.
- [ ] Vulnerability discovery does not implicitly create an exploitation proposal that can execute.

### EMERGENCY STOP  (PRD 24, 32; TRD 44)

- [ ] Emergency stop blocks all new dispatches.
- [ ] Emergency stop invalidates active capability tokens.
- [ ] Emergency stop revokes active credential sessions.
- [ ] Emergency stop terminates dependent sandbox workers.
- [ ] [OS] Emergency stop removes worker network access.
- [ ] Emergency stop scrubs temporary credential material.
- [ ] Emergency stop appends an integrity-protected audit event.
- [ ] An agent request cannot override or clear emergency stop.
- [ ] Emergency-stop state is persistent across kernel restart.
- [ ] Unverifiable emergency-stop state results in DENY for new security-sensitive execution.

### A2A MESSAGE SECURITY  (TRD 14, 16 (AGENTS); PRD 9)

- [ ] A message with a previously seen message ID or nonce is rejected.
- [ ] A message whose payload hash does not match its content is rejected.
- [ ] A message addressed to a different recipient is rejected.
- [ ] An unknown schema version is rejected.
- [ ] Oversized or excessively nested payloads are rejected before expensive parsing.
- [ ] An agent-to-agent message cannot issue tokens, expand scope, approve actions, or invoke capabilities.
- [ ] Fuzzing of the A2A message parser produces no panic or authorization bypass.

### EVIDENCE CLASSIFICATION  (PRD 18, 32; TRD 22, 58)

- [ ] Every evidence object has trust and sensitivity classification before persistence.
- [ ] Classification does not rely exclusively on an LLM.
- [ ] Evidence is classified before any external LLM transmission.
- [ ] Secrets in evidence are redacted or minimized per policy before leaving the system.
- [ ] Parser size and structure limits reject oversized or deeply nested artifacts.

### APPROVAL SEPARATION OF DUTIES  (AGENTS 6.4; TRD 43)

- [ ] A requester cannot approve their own action where independent approval is required.
- [ ] A single-use approval cannot be consumed twice (concurrent consumption test).
- [ ] An approval for one mission or capability cannot authorize another.

### DISPATCH RECOVERY & IDEMPOTENCY  (AGENTS 6.5)

- [ ] A crash between dispatch and result does not cause a blind second execution.
- [ ] Uncertain execution status is recorded in audit and resolved per the approved recovery policy.
- [ ] Dispatch uses durable dispatch identifiers and explicit lifecycle states.

### DEVELOPMENT PIPELINE & SUPPLY CHAIN  (AGENTS 17, 25; TRD 52, 61)

- [ ] Protected paths require human security-owner review (CODEOWNERS + branch protection verified).
- [ ] CI fails when a security test is deleted, skipped, or marked ignore without flagged approval.
- [ ] #![forbid(unsafe_code)] is present in every first-party crate root (CI-verified).
- [ ] Secret scanning runs in pre-commit and CI and blocks on findings.
- [ ] Dependency audit, lockfile check, and SBOM generation run in CI.
- [ ] Container images are scanned and built from minimal base images.
- [ ] Dev/CI agent environments hold no production secrets.

### WINDOWS CONTROLS  [DEFER to Phase 7; carry as NOT RUN until then]  (PRD 20; TRD 40, 58)

- [ ] PowerShell capability requires Constrained Language Mode.
- [ ] Application allowlisting (WDAC/AppLocker) is enforced.
- [ ] A disallowed executable cannot run.
- [ ] Failure to establish required Windows controls results in capability DENY.
- [ ] Worker cleanup terminates the full child process tree.
- [ ] No generic unrestricted PowerShell/shell capability is exposed.

### FAILURE & RECOVERY  (additions to existing section)

- [ ] LLM Gateway failure results in DENY of the dependent intelligence operation (no direct fallback).
- [ ] Audit-commit failure results in DENY where durable audit is required.
- [ ] Evidence-pipeline failure does not admit unclassified evidence.
### EXISTING-GATE AMENDMENTS (suggested wording changes)

These are retained as proposed amendments; they have not been applied to the existing gates.

- "Python Intelligence Plane can reach only explicitly permitted services such as the Rust kernel and approved LLM endpoints."

-> Amend to: "...only the Rust kernel and the LLM Gateway; the Gateway reaches only pinned provider hosts." Reason: closes the generic-LLM-endpoint exfiltration route.

- "Mission cancellation terminates active authorized execution."

-> Keep, and add the EMERGENCY STOP section above. Cancellation and emergency stop are distinct.

- "Credential capability is disabled when the mission policy forbids it."

-> Add "(target credentials)" to disambiguate from provider credentials, which are covered in the new PROVIDER CREDENTIAL SECURITY section.
