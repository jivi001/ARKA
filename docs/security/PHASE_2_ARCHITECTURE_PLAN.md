# ARKA Phase 2 — Execution Foundation & Sandboxing
**Status:** Planning baseline — ready for implementation after governance prerequisites are reconciled  
**Repository:** https://github.com/jivi001/ARKA  
**Verified against:** `main` at `2dbd5b4062be0ab9e99073ff072ffbc0e625b1e7` and PRD/TRD v2.2  
**Date:** 2026-10-09

## 1. Executive decision

Phase 2 builds the first real execution boundary around the existing Rust Security Kernel. It delivers a Rust-controlled Execution Broker, rootless Linux worker/sandbox, connection-time destination validation, DNS pinning, redirect revalidation, resource governance, and deterministic teardown.

**Phase 2 must not enable production execution or controlled exploitation by default.** The acceptance criteria need to prove that an unauthorized side effect is impossible, not merely that the application returns a denial response. Keep `PRODUCTION_EXECUTION_ALLOWED=false` while developing and until formal sign-off.

### Repository verification summary

- The repository README and Phase 1 independent re-audit report Phase 0 and Phase 1 as complete, with a Phase 1 PASS and 92 Rust tests reported.
- `security/acceptance/phase-status.yaml` is stale/inconsistent: Phase 0 says `COMPLETE_WITH_WARNINGS` because GitHub branch protection still needs manual activation; Phase 1 says `NOT_STARTED`, despite the re-audit and merged Phase 1 work. Reconcile this machine-readable status before relying on it as the release authority.
- The branch protection specification explicitly says enforcement is `BLOCKED_EXTERNAL_CONFIGURATION`. Verify live GitHub settings in repository settings; a documentation checklist is not evidence that protection is enabled.
- The checked `frontend/package.json` and `frontend/` paths were not found on `main`, although the README mentions a future Operator Console. Therefore treat the UI as not yet established in the current main-branch tree.
- Phase 2 is listed as `NOT_STARTED` in the phase status registry. The current Phase 2 gate registry contains blocking gates for SSRF, DNS rebinding/IP pinning, sandbox containment, cloud metadata blocking, IPv6 policy, redirects, browser mediation, and sandbox cleanup.

## 2. Objective and scope

### In scope

1. **Execution Broker (Rust):** the sole dispatcher for security-sensitive execution. It accepts only a kernel-authorized canonical action, verifies action hash, mission, capability, target, expiry, approval where required, current emergency-stop state, and resource budget immediately before dispatch.
2. **Worker lifecycle:** provision, start, supervise, timeout, terminate and clean up one isolated worker per bounded execution unit. Make lifecycle transitions explicit and auditable.
3. **Linux sandbox:** rootless container; non-root process; dropped capabilities; no privileged mode; read-only base filesystem; isolated PID and network namespaces; seccomp; AppArmor where available; explicit mounts; deny-by-default egress; CPU, memory, process, disk and wall-clock limits.
4. **ScopeGuard / SSRF protection:** connect-time destination validation, canonical target matching, IPv4/IPv6 policy checks, blocked loopback/link-local/private/metadata destinations unless explicitly authorized by mission scope, and DNS pinning to the validated address.
5. **HTTP redirect control:** every redirect is intercepted, parsed and revalidated against mission scope, policy and destination IP before a new connection. Never inherit trust from the previous hop.
6. **Resource governance:** bounded concurrency, timeouts, request/network budgets where observable, task and mission quotas, cancellation propagation and fail-closed behavior.
7. **Evidence/result boundary:** bounded structured result envelope containing execution ID, canonical action reference/hash, worker identity, exit status, timestamps, bounded output/evidence references and integrity metadata. Tool output is untrusted.
8. **Audit and emergency stop integration:** record dispatch decision, worker creation, start, completion/failure, network-policy denial, timeout, cleanup result, and cancellation in a tamper-evident audit trail. Emergency stop must prevent new dispatch and cancel active work.
9. **Security tests and CI gates:** unit, integration, adversarial network, sandbox containment, resource exhaustion, lifecycle/cleanup, fuzzing and end-to-end tests.

### Explicitly out of scope for Phase 2

- Autonomous multi-agent planning, A2A protocol and LLM gateway (Phase 3).
- Credential vault/session broker (Phase 6); do not invent a raw-secret injection shortcut.
- Windows execution worker (later Windows phase).
- Controlled exploitation. It must remain disabled until the specified stronger isolation and separate acceptance gates are satisfied.
- Distributed workers, Redis/NATS, PostgreSQL, and production multi-user infrastructure unless an explicit architecture decision is approved.
- UI-triggered direct tool execution, unrestricted shell, arbitrary binary installation or ad hoc commands.

## 3. Architecture and trust boundaries

```text
Operator UI (read/submit authorized requests only)
                 |
       Authenticated versioned API
                 |
        Rust Security Kernel
  normalize -> authorize -> approval
  scope -> budget -> replay -> audit
                 |
        Authorized canonical action
                 |
        Rust Execution Broker
  re-check hash / approval / scope /
  e-stop / expiry / budget before dispatch
                 |
      Worker Supervisor / Policy Setup
                 |
     Rootless Linux Sandbox / Worker
  non-root, seccomp, namespace isolation,
  read-only filesystem, cgroups/quotas
                 |
     Enforced egress + ScopeGuard
  DNS pinning, connect-time IP validation,
  redirect revalidation, IPv4/IPv6 rules
                 |
       Explicitly authorized target

Python Intelligence Plane: no direct target-network route.
UI: no local subprocess, raw socket, Playwright or tool execution authority.
All target-side side effects: broker-mediated.
```

The broker should depend on narrow, typed interfaces; it must not reimplement a second authorization policy. The kernel remains the authorization authority, while the broker verifies the authorization artifact at the point of effect and enforces execution-specific controls. If any required check cannot be completed, do not dispatch.

## 4. Recommended repository layout

Extend the current Rust workspace rather than replacing the Phase 1 crates. Proposed layout (final names can be aligned with current naming conventions during the architecture checkpoint):

```text
crates/
  arka-core-types/
  arka-crypto/
  arka-kernel/
  arka-storage-sqlite/
  arka-execution-broker/       # broker orchestration and execution state
  arka-worker-protocol/        # typed, versioned broker-worker contracts
  arka-network-policy/         # pure policy decisions and target/IP types
workers/
  linux/
    container/                 # rootless runtime profile/configuration
    wrappers/                  # allowlisted typed capability adapters
tests/
  phase2/
    broker/
    sandbox/
    network/
    redirects/
    resources/
    lifecycle/
    e2e/
docs/security/
  PHASE_2_ARCHITECTURE_PLAN.md
  PHASE_2_CHECKPOINT_REPORTS/
security/
  controls/
  acceptance/gates.yaml
  traceability/
```

Do not force OS-specific container orchestration, process supervision or firewall implementation into the pure deterministic kernel crate. Keep platform-side effects behind narrow interfaces, and explicitly review the trusted computing base.

## 5. Technology direction

Use the current Rust workspace, Tokio async runtime, Serde with strict/versioned schemas, Axum only if a broker-facing API is required, existing crypto/hash abstractions, and existing SQLite/WAL transactional patterns where persistence is needed. Keep dependencies minimal and locked.

For the Linux worker, choose one supported rootless runtime and document its exact security profile. Pin the runtime and helper binary versions (and image digests where applicable), record provenance/checksums, scan runtime and worker-image dependencies in CI, and block on known high/critical vulnerabilities under the security policy. Define an update/exception process so pinning does not become permanent vulnerability retention. Validate the actual runtime behavior on the target development OS and CI runner instead of assuming that “containerized” means contained. Apply OS-level network controls before starting a worker. Docker alone is not a sufficient boundary for high-risk exploitation; stronger isolation belongs to the later microVM/gVisor phase.

Avoid adding Redis/NATS or a broad orchestration framework for the single-machine MVP. Add dependencies only with a threat-model entry, maintenance review, lockfile change, vulnerability/license checks and tests.

## 6. Implementation checkpoints

### P2-A — Architecture lock and governance prerequisites
- Reconcile Phase 0/1 status registry with audit reports and actual merge/CI evidence.
- A human CODEOWNER (not the implementation agent) reviews Phase 1 audit artifacts and updates `phase-status.yaml` only after recording the exact audit report/commit SHA and CI run IDs reviewed. The reviewer's identity and rationale must be captured in the review/commit history; do not self-attest.
- Confirm GitHub branch protection/rulesets are active. Attach a live `gh api repos/jivi001/ARKA/branches/main/protection` result (or equivalent API evidence) and CI evidence; the documentation checklist alone is insufficient.
- Map each Phase 2 threat → control → implementation → test → acceptance gate.
- Freeze the HTTP transport decision before P2-A closes. The current workspace `Cargo.toml` does not select `reqwest` or `hyper` as a direct workspace dependency, so the HTTP stack and pinned-dial mechanism remain undecided.
- Define the first live capability as `TCP_CONNECT` to a controlled local test fixture only, and only after network-policy enforcement is active. Use a no-op worker before that. Keep `HTTP_REQUEST` disabled until P2-D and P2-E are complete. No generic shell.
- Exit: approved design, stable contracts, traceability, CI plan and no unresolved ambiguity over who can cause side effects.

### P2-B — Broker contract and lifecycle
- Define typed request/response models and versioning.
- Define execution state machine, e.g. `AUTHORIZED → DISPATCHING → RUNNING → COMPLETED | FAILED | TIMED_OUT | CANCELLED`; reject invalid transitions.
- Bind execution to mission ID, action ID, canonical action hash, capability, target, policy version, expiry and authorization record.
- Recheck approval/expiry, emergency stop and budgets immediately before dispatch. Consume dispatch idempotently with a durable unique constraint on `(action_id, dispatch_attempt=1)` and the transition to `DISPATCHING` in the same database transaction. A retry must read and return the existing dispatch record, never insert a second dispatch. Define crash recovery for the commit-before-worker-start and worker-start-before-result windows; uncertain outcomes must not trigger automatic re-execution.
- Implement bounded queue/concurrency and cancellation.
- Exit: no dispatch without a valid authorized artifact; no replay; cancellation and crash recovery do not restore authority.

### P2-C — Rootless sandbox and worker supervision
- Implement minimal rootless worker startup, one allowlisted capability adapter, resource limits and explicit mounts.
- Set non-root UID, read-only root filesystem, no privileged mode, dropped Linux capabilities, seccomp, PID/network namespaces, no host Docker socket, and no broad host mounts.
- Enforce bounded stdout/stderr and structured result size; protect the broker from hostile output.
- Implement timeout, kill process tree/container, clean temporary workspace and ensure no worker or credential-like temporary material remains.
- Exit: adversarial tests cannot access host filesystem/socket, host network, another mission workspace or another worker; cleanup works after success, failure, timeout and broker restart.

### P2-D — Connection-time network enforcement
- Add a single destination-validation path used by every network-capable wrapper.
- Resolve DNS once for each connection attempt, validate every returned address against mission scope and blocked ranges, and bind the actual socket dial to the validated address. The HTTP implementation MUST use either (a) a custom resolver/connector that returns only the validated pinned address, or (b) direct-IP dialing while independently preserving the original hostname for TLS SNI, certificate verification and HTTP `Host`/`:authority`. Passing the original hostname to a client that performs a fresh OS DNS lookup is prohibited. The selected client/connector behavior must be covered by an integration test proving the socket peer equals the validated IP.
- Before P2-A closes, evaluate the chosen Rust HTTP stack's resolver/connector hooks against the pinned dependency version. The current workspace manifest does not choose `reqwest` or `hyper`; do not assume either is configured. If using reqwest, prove the exact version's custom resolver/connector behavior in a test; if that cannot enforce the peer-IP invariant, implement a custom connector or direct-IP dialer.
- Defend against DNS rebinding and time-of-check/time-of-use gaps; avoid re-resolving an unchecked hostname after validation.
- Independently handle IPv4, IPv6, IPv4-mapped IPv6, loopback, link-local, private ranges and metadata addresses. Reject or explicitly canonicalize zone-ID/scoped IPv6 literals (for example `fe80::1%eth0`); cover NAT64-synthesized destinations and embedded IPv4 policy; reject ambiguous/non-canonical IPv4 forms including decimal integer, octal and hexadecimal forms (for example `2130706433`, `0177.0.0.1`, and `0x7f000001`) unless a single parser canonicalizes them to the same policy representation before authorization. The actual connected peer address remains the final enforcement point.
- Ensure Python/agent processes have no route to target networks; enforce this at OS/network namespace/firewall level, not just in application code.
- Exit: network-level tests prove disallowed packets are not emitted, including on errors and fallback paths.

### P2-E — HTTP redirects and browser boundary
- Disable automatic redirect following in the HTTP adapter or install an interception layer that validates every hop before connecting.
- Every redirect hop MUST call the exact same single destination-validation function and pinned-dial path used for the initial request in P2-D. No lighter redirect-only hostname check or alternate network dial path is permitted. Each hop resets trust and revalidates scheme, hostname, effective port, resolved IP, scope, exclusions and redirect count; DNS pinning is repeated for the new destination before connecting.
- Reject downgrade/unsupported schemes, ambiguous host forms, credentials in URL, excessive redirect chains, and out-of-policy downloads.
- Browser automation is not permitted to create an alternate network path. If a browser is included now, force all requests through broker-controlled proxy/network policy; otherwise defer browser execution and keep its gate explicitly blocked.
- Exit: redirect to loopback/private/metadata/out-of-scope destinations is denied before connection; browser cannot bypass mediation.

### P2-F — Resource governor, audit, evidence and e-stop
- Apply execution timeout, CPU, memory, process, disk and concurrency ceilings before workload start.
- Bound network/request usage where instrumentation supports it; enforce LLM budgets in Phase 3, not by adding a premature LLM subsystem here.
- Persist state transitions and append corresponding audit events. Record worker/runtime profile and cleanup outcome.
- Ensure emergency stop stops new dispatches, cancels active workers, revokes runtime network access and audits the event.
- Store untrusted output as bounded evidence with provenance and content hash; do not let output change policy, scope or capability.
- Exit: quota exhaustion, missing audit, policy failure, broker errors and stop signals fail closed with an auditable terminal state.

### P2-G — Adversarial verification and release gate
- Run all Rust format/lint/unit tests and Phase 0 validator/meta-tests.
- Run new broker/worker integration tests on supported Linux.
- Run SSRF, DNS rebinding, redirect, IPv6, metadata, sandbox escape-surface, resource, replay/race, e-stop and teardown tests.
- Add fuzz targets for URL/target parsing, redirect handling, worker messages and output parsers; add property tests for “unauthorized action implies no side effect”.
- Attach CI run IDs, commit SHA, test outputs and artifact hashes to gate evidence.
- Exit: all blocking Phase 2 gates pass; adversarial review approves; no critical/high unresolved finding; operator signs phase completion report. If any gate fails, release remains blocked.

## 7. Required Phase 2 test matrix

| Domain | Positive test | Mandatory negative/adversarial tests |
|---|---|---|
| Broker authority | Valid, current, authorized action dispatches once | Forged/expired token, altered action hash, missing approval, replay, wrong mission, stale policy, e-stop all deny with zero side effects |
| Target scope | Explicitly authorized test endpoint reachable via broker | Out-of-scope host/port, exclusion, discovered-only asset, DNS alias outside scope denied |
| SSRF / metadata | Allowed address and port only | Loopback, RFC1918, link-local, metadata IP, IPv4-mapped IPv6, IPv6 zone IDs (`%interface`), NAT64-synthesized targets, decimal/octal/hex IPv4 forms and parser differential cases denied unless explicit scope permits |
| DNS pinning | Captured socket peer equals the validated IP while TLS SNI/certificate verification use the intended hostname | Rebinding answer change; mixed safe/unsafe answer sets; client-side re-resolution; custom resolver/connector bypass; address differs from validated pin; e-stop between DNS validation and connection completion |
| HTTP redirects | In-scope redirect accepted when policy allows | Redirect to different/out-of-scope host, private IP, metadata, IPv6 local address, scheme/port change or excessive chain denied before follow |
| Sandbox | Worker can perform only its narrow capability | Root/privileged mode, host path, Docker socket, host network, other mission artifacts, capability escalation, mount/network namespace escape attempts denied |
| Resources | Within-budget task completes | CPU/memory/process/disk/time/concurrency limits exceeded; cancellation race; no orphan process/container |
| Evidence/result | Well-formed bounded result persisted with hash | Oversized output, malformed JSON, control/ANSI escapes, fabricated provenance, parser crash; broker survives and policy is unchanged |
| Audit/e-stop | Complete lifecycle auditable | Audit store failure, worker crash, kernel unavailable, stop during dispatch/run, and e-stop after DNS validation but before/during pinned connect; cancel connection and revoke egress; no unaudited success and no post-stop execution |
| Build/supply chain | Reproducible locked build and security scans | Dependency vulnerability, unpinned workflow action, failed security test or missing gate artifact blocks merge/release |

**Test design rule:** every denial test must assert absence of the external side effect, not only the returned error code.

## 8. Phase 2 acceptance gates

Implement and attach evidence to the existing gates in `security/acceptance/gates.yaml`:

- `GATE-SSRF-001` / `CTRL-SSRF-001`: RFC1918 or loopback connection is not permitted unless explicitly authorized by scope.
- `GATE-DNS-REBIND-001` / `CTRL-DNS-PINNING-001`: connection cannot differ from the validated resolved IP.
- `GATE-METADATA-BLOCK-001`: metadata endpoint access denied by default.
- `GATE-IPV6-POLICY-001`: unscoped IPv6 connections denied.
- `GATE-REDIRECT-FILTER-001`: out-of-scope redirect not followed.
- `GATE-SANDBOX-CONTAINMENT-001`: worker is non-root and cannot access host filesystem beyond explicit safe inputs.
- `GATE-BROWSER-SANDBOX-001`: browser requests cannot bypass broker mediation, if browser functionality is in scope.
- `GATE-SANDBOX-CLEANUP-001`: no lingering container or temporary material after task completion/failure.
- Resource, fail-closed, replay, emergency-stop and audit gates remain blocking where applicable.

Each gate must map to threat, control, test, and required evidence. Update traceability schemas and validators when adding controls; do not just append unchecked YAML. Resolve the resource-gate split now: retain the existing Phase 1 resource/budget gate for kernel-side quota decisions and add a distinct blocking Phase 2 gate `GATE-WORKER-RESOURCE-001` for OS-enforced cgroup/process/memory/CPU/disk limits and kill-on-exhaustion. Give it a Phase 2 threat/control/test mapping and a unique ID; do not repurpose or duplicate `GATE-RESOURCE-LIMIT-001`.

## 9. API and integration contracts

### Broker request
Require a versioned schema containing request ID, mission ID, action ID, action hash, capability ID, canonical target reference, policy version, authorization/approval reference, expiry and bounded typed parameters. The broker must not accept arbitrary command strings as executable authority.

### Broker response
Return a deterministic state, execution ID, correlation/request ID, bounded error code, timestamps, and evidence references. Do not leak secrets, internal stack traces or sensitive network details. “Accepted” means queued, not executed successfully.

### Worker protocol
Use a versioned typed protocol. Authenticate broker and worker identity. Bind messages to mission, execution, capability and nonce/request ID. Reject unknown security-critical fields. Worker output is never an authorization artifact.

### Failure semantics
Any unavailable authorization service, stale/invalid approval, policy failure, unknown target, DNS uncertainty, unestablished sandbox policy, audit failure where required, resource governor failure or worker identity failure → **DENY / DO NOT DISPATCH**. Retry only safe intelligence/control operations; never blindly rerun a side-effecting execution.

## 10. Frontend decision: defer to Phase 2.5 by default

**Recommendation: defer frontend implementation until the broker, sandbox and network-policy path has passed P2-G, unless a separate reviewer has explicit capacity.** A thin read-only mock can be designed in parallel, but do not split the security reviewer's attention across a second implementation surface during the highest-risk phase. If parallel work is staffed independently, the UI must remain a client only and must not delay P2-B through P2-G. The repository README describes an Apple-inspired operator console and mentions Next.js/React, Node.js 20+ and pnpm, but the inspected `main` tree does not currently contain `frontend/` or `frontend/package.json`. Create it in an isolated branch after the API contract is agreed; do not let UI work delay sandbox/network gates.

### Safe frontend scope
1. Mission list/detail and explicit scope review.
2. Execution queue and lifecycle status (queued/running/completed/denied/failed/timed-out/cancelled).
3. Approval inbox showing exact normalized action, target, parameters summary, risk, evidence rationale, expiry and hash binding. Approval posts a decision to the kernel API; the browser never signs/authorizes locally.
4. Evidence/result viewer with untrusted-content escaping, size bounds and provenance/hash metadata.
5. Security status page: emergency stop, worker health, policy denials, resource budgets and audit events.
6. Configuration views are read-only initially, except changes explicitly exposed through authenticated kernel APIs.

### UI security restrictions
- No direct subprocesses, raw sockets, Nmap invocation, Playwright target access, or direct worker endpoints.
- Do not store authorization tokens or secrets in localStorage/sessionStorage; use a secure server-side session pattern where the deployment model supports it.
- Treat evidence, hostnames, paths, terminal output, markdown and filenames as untrusted. Escape/render safely; never execute supplied HTML.
- Destructive/high-risk actions require explicit contextual confirmation and server-side approval validation.
- Separate UI authentication from action authorization. Hiding a button is not access control.
- Show clear “simulation / execution disabled” status until the Phase 2 gates are formally accepted.

### Suggested frontend stack
Use Next.js/React only if the team is committed to a browser-based dashboard (as README suggests), TypeScript strict mode, a small UI component system, schema-generated or shared typed API contracts, and pinned dependencies. Keep the backend's Rust security boundary authoritative. Do not add a frontend backend-for-frontend that can execute tools or become a second policy engine.

## 11. Recommended work order

1. Fix phase-status and repository governance discrepancies; verify branch protection.
2. Approve Phase 2 architecture and API/worker schemas.
3. Implement typed execution broker and lifecycle with a fake/no-op worker first.
4. Implement rootless worker start/stop, resource limits and cleanup.
5. Implement network policy, destination validation and DNS pinning.
6. Add redirect enforcement and browser mediation decision.
7. Wire audit/e-stop/evidence/result handling.
8. Run adversarial tests, fuzzing, CI and independent security review.
9. Only after P2-G passes, start Phase 2.5 frontend work against the frozen API contracts (unless independently staffed and isolated).
10. Update phase-status registry only after the acceptance artifacts exist; keep production execution disabled until a separate explicit release sign-off.

## 12. Definition of Done

Phase 2 is complete only when all conditions below are evidenced on the merged candidate commit:

- [ ] Broker is the only external side-effect dispatcher.
- [ ] Every dispatch binds to a canonical, authorized action hash and current mission scope.
- [ ] No direct target-network route exists from the Python intelligence plane.
- [ ] Rootless sandbox profile is enforced by the OS/runtime and tested.
- [ ] SSRF, metadata, DNS pinning/rebinding, redirect and IPv6 blocking tests pass at connection level, including parser-differential corpus and packet-capture-backed absence-of-side-effect assertions.
- [ ] Every HTTP redirect hop calls the identical P2-D destination-validation and pinned-dial path.
- [ ] E-stop during the DNS-validation-to-connect window cancels the connection and prevents target traffic.
- [ ] Browser path cannot bypass broker mediation or remains disabled.
- [ ] CPU, memory, process, disk, wall-clock and concurrency limits stop work when exceeded.
- [ ] Cancellation/emergency stop prevents new work and terminates active work.
- [ ] Worker cleanup succeeds after success, failure, timeout and crash.
- [ ] Evidence and audit records are provenance-bound and tampering is detectable.
- [ ] `GATE-WORKER-RESOURCE-001` proves OS-level worker resource enforcement separately from Phase 1 kernel-side budget decisions.
- [ ] Rootless runtime and worker image versions are pinned and included in vulnerability/supply-chain scanning.
- [ ] All mandatory Phase 2 gates pass with CI run ID, commit SHA and artifact hashes.
- [ ] Threat/control/test/gate traceability is valid.
- [ ] Independent adversarial review has no unresolved critical/high blockers.
- [ ] Phase status file, README, reports and CI evidence agree.
- [ ] Production execution and controlled exploitation remain disabled until separately authorized.

## 13. Immediate next actions

1. Reconcile `security/acceptance/phase-status.yaml` with the Phase 1 audit; verify actual GitHub branch protection, and record the remaining Phase 0 warning honestly.
2. Add `docs/security/PHASE_2_ARCHITECTURE_PLAN.md` and use P2-A through P2-G as gated checkpoints with a stop-and-review point after each.
3. Begin with **P2-B broker contract + fake worker**, not a real scanning tool. Prove authorization, replay, fail-closed and audit wiring before enabling any network-side behavior.
4. Decide whether the first UI milestone is read-only status/mission/evidence browsing. Recommended answer: yes, in parallel on an isolated branch, while the broker/sandbox remains the critical path.

---
**Authority rule:** If implementation convenience conflicts with a security invariant, the implementation must change. No execution is enabled solely because the UI, API or worker appears functional.
