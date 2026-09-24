IDENTITY & AUTHORIZATION
────────────────────────────────────────────────────────────

[ ] Agent cannot forge another agent's identity.
[ ] Agent cannot acquire another agent's capability token.
[ ] Agent cannot expand its own capability set.
[ ] Agent cannot expand mission scope.
[ ] Agent cannot modify authorization policy.
[ ] Agent cannot approve its own action.
[ ] Approved action cannot execute with parameters different from the approved parameter hash.
[ ] Expired approval cannot authorize execution.
[ ] Revoked approval cannot authorize execution.


REPLAY & MESSAGE SECURITY
────────────────────────────────────────────────────────────

[ ] A stale/replayed ActionProposal cannot re-execute after original completion.
[ ] A message from one mission cannot be accepted by another mission.
[ ] A message with an invalid signature/token cannot be accepted.
[ ] A message outside its validity window cannot be accepted.
[ ] Agent-to-agent messages preserve mission and provenance identity.


MISSION ISOLATION
────────────────────────────────────────────────────────────

[ ] Agent cannot access another mission's evidence.
[ ] Agent cannot access another mission's credentials.
[ ] Agent cannot access another mission's knowledge graph.
[ ] Agent cannot access another mission's execution artifacts.
[ ] Mission identifiers cannot be substituted to bypass isolation.
[ ] Cross-mission database queries are rejected by the authorization layer.


EXECUTION AUTHORITY
────────────────────────────────────────────────────────────

[ ] Agent cannot directly execute a subprocess.
[ ] Agent cannot directly access target-scoped network resources.
[ ] Agent cannot directly invoke Playwright against a target.
[ ] Browser execution cannot bypass the Rust Execution Broker.
[ ] Tool execution without an authorized capability is rejected.
[ ] Capability parameters are validated before execution.
[ ] Execution cannot continue after capability expiration.


NETWORK SECURITY
────────────────────────────────────────────────────────────

[ ] Python Intelligence Plane has no network route to target-scoped hosts
    at the OS/network-policy layer.
[ ] Python Intelligence Plane can reach only explicitly permitted services
    such as the Rust kernel and approved LLM endpoints.
[ ] Execution sandbox cannot bypass its mission network policy.
[ ] Sandbox cannot reach another mission's sandbox.
[ ] Sandbox cannot reach the host network namespace.
[ ] Sandbox cannot access unauthorized containers.
[ ] Unauthorized RFC1918 destinations are blocked.
[ ] Unauthorized link-local destinations are blocked.
[ ] Cloud metadata endpoints are blocked by default.
[ ] Destination IP is validated at connection time.
[ ] Destination IP is revalidated after DNS resolution.
[ ] Every HTTP redirect is revalidated before connection.
[ ] DNS rebinding cannot move an authorized hostname to an unauthorized IP.
[ ] Proxy configuration cannot bypass destination policy.
[ ] IPv4 and IPv6 destinations are independently policy-validated.


RESOURCE GOVERNANCE
────────────────────────────────────────────────────────────

[ ] Agent cannot modify its own resource limits.
[ ] Mission cannot silently exceed its resource budget.
[ ] Agent exceeding its budget is halted.
[ ] Mission exceeding its budget fails closed.
[ ] LLM expenditure cannot exceed the configured mission budget.
[ ] Tool concurrency cannot exceed the configured limit.
[ ] Request-rate limits cannot be overridden by an agent.
[ ] Repeated failed hypotheses cannot create unlimited retries.


CREDENTIAL SECURITY
────────────────────────────────────────────────────────────

[ ] Credentials are encrypted at rest.
[ ] Credentials never appear in ordinary application logs.
[ ] LLM cannot directly access the credential vault.
[ ] Agent cannot retrieve credentials outside its mission.
[ ] Credential access requires an authorized capability.
[ ] Credential broker issues mission-bound access.
[ ] Credential sessions are time-limited.
[ ] Credential sessions are revocable.
[ ] Credential access is auditable.
[ ] Raw credentials are not unnecessarily exposed to agents.
[ ] Credential capability is disabled when the mission policy forbids it.


EVIDENCE SECURITY
────────────────────────────────────────────────────────────

[ ] Evidence records cannot be modified after creation without detection.
[ ] Evidence provenance cannot be replaced without detection.
[ ] Evidence is bound to the originating mission.
[ ] Evidence is bound to the originating action.
[ ] Evidence is bound to the originating agent/capability.
[ ] Evidence parser compromise cannot directly compromise the Rust kernel.
[ ] Malformed evidence cannot crash the trusted control plane.
[ ] Evidence hashes detect post-creation modification.


AUDIT SECURITY
────────────────────────────────────────────────────────────

[ ] Audit events are append-oriented.
[ ] Audit records contain integrity metadata.
[ ] Audit-chain modification is detectable.
[ ] Audit events identify the actor that caused the event.
[ ] Audit events identify the authorization decision.
[ ] Audit events identify the executed parameter set.
[ ] Audit events cannot be deleted by an agent.
[ ] Audit events cannot be rewritten by a sandboxed tool.


UNTRUSTED CONTENT
────────────────────────────────────────────────────────────

[ ] Target content cannot become ARKA instructions.
[ ] HTTP responses cannot modify agent authority.
[ ] Tool output cannot modify agent authority.
[ ] Browser content cannot modify agent authority.
[ ] RAG content cannot modify agent authority.
[ ] Evidence cannot modify authorization policy.
[ ] Memory cannot grant capabilities.
[ ] External documents cannot grant capabilities.
[ ] Prompt injection cannot bypass deterministic authorization.


SANDBOX SECURITY
────────────────────────────────────────────────────────────

[ ] Sandbox cannot access the Rust kernel's private filesystem.
[ ] Sandbox cannot access the credential store.
[ ] Sandbox cannot access another mission's artifacts.
[ ] Sandbox cannot access the host Docker socket.
[ ] Sandbox cannot modify its own security profile.
[ ] Sandbox cannot disable seccomp/AppArmor/gVisor policy.
[ ] Sandbox cannot obtain host-level privileges through configuration.
[ ] Sandbox cleanup occurs after normal completion.
[ ] Sandbox cleanup occurs after timeout.
[ ] Sandbox cleanup occurs after worker failure.


FAILURE & RECOVERY
────────────────────────────────────────────────────────────

[ ] Authorization failure results in DENY.
[ ] Policy-engine failure results in DENY.
[ ] Identity validation failure results in DENY.
[ ] Network-policy failure results in DENY.
[ ] Credential-broker failure results in DENY.
[ ] Resource-governor failure results in DENY.
[ ] Worker failure cannot grant additional authority.
[ ] Agent restart cannot restore expired authority.
[ ] Stale execution requests cannot resume automatically.
[ ] Mission cancellation terminates active authorized execution.