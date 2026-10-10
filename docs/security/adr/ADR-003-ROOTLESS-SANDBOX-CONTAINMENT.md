# ADR-003: Linux Rootless Sandbox, Bubblewrap Container Enclosure, Seccomp, and Resource Containment

**Status:** Accepted (P2-C Architecture Decision)  
**Date:** 2026-10-09  
**Authors:** Senior AI Systems Architect, Principal Rust Security Engineer  
**Phase:** Phase 2 — Execution Foundation & Sandboxing  
**Classification:** Security-Critical Architectural Contract  

---

## 1. Context and Problem Statement

ARKA executes authorized, security-relevant capabilities (such as network probing, port discovery, and technology identification) against external targets. The execution plane operates under the foundational security principle:

$$\mathbf{TARGET\ RESPONSES\ ARE\ UNTRUSTED\ AND\ ADVERSARIAL}$$

When executing any capability:
1. **Target-Side Exploitation:** An adversary may return malformed banner strings, exploit parser bugs in network tools, or attempt container breakout.
2. **Host File & Secret Compromise:** An untrusted execution process must have zero access to the host filesystem, host Docker socket, operator credentials, SQLite state databases, or private signing keys (`AUDIT-SIGNING`, `TOKEN-SIGNING`).
3. **Lateral Network Egress:** A compromised or misbehaving capability worker must not be able to pivot to internal network assets, localhost services (`127.0.0.1`), or cloud metadata endpoints (`169.254.169.254`).
4. **Denial of Service & Resource Runaway:** A worker process must not be able to fork-bomb, consume unbounded host memory, or pin CPU cores indefinitely.
5. **Lingering Artifacts & TOCTOU:** Temporary files, IPC pipes, or socket descriptors must be deterministically eradicated upon execution completion, failure, or timeout.

Phase 2 requires an isolated Linux execution sandbox that guarantees that execution cannot access host resources, cannot escalate privileges, cannot escape its resource boundaries, and leaves zero persistent traces post-execution.

---

## 2. Decision

We select **Bubblewrap (`bwrap`)** as the unprivileged, rootless container isolation engine for the ARKA Phase 2 Linux execution plane, supervised directly by `crates/arka-execution-broker` via an asynchronous, zero-unsafe Rust supervisor (`SandboxSupervisor`).

### 2.1 Rationale for Bubblewrap (`bwrap`)

1. **Unprivileged Rootless Execution:** `bwrap` creates new Linux user namespaces (`CLONE_NEWUSER`) without requiring daemon processes (`dockerd`), background services, or root privileges.
2. **Zero Unsafe Rust Required:** The Rust broker supervises `bwrap` purely through safe process execution abstractions (`tokio::process::Command`), fulfilling ARKA's strict `#![forbid(unsafe_code)]` invariant.
3. **Granular Filesystem Virtualization:** Provides fine-grained mount control (`--ro-bind`, `--tmpfs`, `--proc`, `--dev`, `--dir`), allowing the construction of an ephemeral, read-only root environment with zero host visibility.
4. **Comprehensive Namespace Partitioning:** Supports user, mount, PID, IPC, UTS, and network namespace unsharing in a single atomic invocation.
5. **Built-in Seccomp BPF Integration:** Accepts compiled BPF seccomp filter descriptors directly via `--seccomp <fd>`, locking down system calls before capability entry.
6. **Parent-Death Synchronization:** Uses `--die-with-parent` to prevent orphaned background processes if the broker supervisor process is abruptly terminated.

---

## 3. Sandboxed Execution Architecture

```text
+-----------------------------------------------------------------------+
| ARKA Execution Broker (Trusted Rust Process)                         |
|                                                                       |
|  1. Ingests authorized CanonicalAction & verified Approval            |
|  2. Allocates isolated ephemeral scratch directory: /tmp/arka-run-XXX  |
|  3. Constructs strict bwrap containment argument vector               |
|  4. Applies Resource Limits (Timeout, Output Caps, Limits)            |
+-----------------------------------v-----------------------------------+
                                    |
          fork() + execvp("bwrap") via tokio::process::Command
                                    |
+-----------------------------------v-----------------------------------+
| Bubblewrap (bwrap 0.12+) Enclosure                                   |
|                                                                       |
|  [Namespaces]                                                         |
|   - CLONE_NEWUSER:  Mapped to unprivileged UID/GID                    |
|   - CLONE_NEWNS:    Isolated mount table                              |
|   - CLONE_NEWPID:   Isolated PID namespace (Worker is PID 2)          |
|   - CLONE_NEWNET:   Isolated network namespace (Loopback only)        |
|   - CLONE_NEWIPC:   Isolated IPC queues & shared memory               |
|   - CLONE_NEWUTS:   Isolated hostname ("arka-sandbox")                |
|                                                                       |
|  [Filesystem Enclosure]                                               |
|   - /usr, /bin, /lib, /lib64 : Read-only host system binaries         |
|   - /etc/resolv.conf, /etc/ssl: Read-only minimal configs (explicit)  |
|   - /proc : Isolated procfs (host PIDs invisible)                     |
|   - /dev  : Minimal devices (null, zero, urandom, random)             |
|   - /tmp  : Ephemeral in-memory tmpfs                                 |
|   - /work : Tightly bound ephemeral mission scratch directory         |
|   - Host paths (/home, /root, /var, /etc/shadow) : COMPLETELY ABSENT  |
|                                                                       |
|  [Privilege & Kernel Hardening]                                       |
|   - Linux Capabilities: ALL dropped (--cap-drop ALL)                  |
|   - PR_SET_NO_NEW_PRIVS: Active                                       |
|   - Seccomp BPF: Restricts dangerous syscalls                         |
|   - Lifetime: --die-with-parent (SIGKILL if broker exits)             |
+-----------------------------------v-----------------------------------+
                                    |
                          Capability Executable
                     (e.g., TCP_CONNECT Test Probe)
```

---

## 4. Resource Governance & Limits

To satisfy **GATE-WORKER-RESOURCE-001** and mitigate **THREAT-RESOURCE-EXHAUSTION**:

1. **Wall-Clock Execution Timeout:** Every sandbox run is governed by `deadline_unix` (default 30 seconds). Upon expiration:
   - SIGTERM is sent to the process group.
   - After a 500ms grace period, SIGKILL is issued unconditionally.
2. **Bounded Output Buffering:** `stdout` and `stderr` streams are ingested asynchronously with an unyielding 16 KB hard cap (`MAX_STDOUT_BYTES`, `MAX_STDERR_BYTES`). Excess output is truncated safely, and the truncation flag is recorded in the execution envelope.
3. **Memory and Process Limits:** When Linux cgroups v2 are delegated, memory is constrained via `memory.max` and processes via `pids.max`. As an invariant secondary defense, POSIX `prlimit` bounds process virtual memory and maximum file descriptor count.

---

## 5. Ephemeral Teardown and Deterministic Cleanup

To satisfy **GATE-SANDBOX-CLEANUP-001** and mitigate **THREAT-SANDBOX-CLEANUP-FAILURE**:

1. **Ephemeral Scratch Scoping:** Every execution receives a dedicated temporary directory (`/tmp/arka-exec-<execution_id>`).
2. **Deterministic Cleanup Protocol:** The supervisor executes cleanup inside a RAII guard / `finally` block:
   - Ensures child process termination (status reaped).
   - Recursively deletes the ephemeral scratch directory.
   - Validates that zero lingering processes or file descriptors remain associated with `execution_id`.
3. **Crash Recovery Sweep:** On broker startup, the recovery routine scans for orphaned scratch directories from interrupted executions and purges them immediately.

---

## 6. Fail-Closed Enforcement

1. **Runtime Verification:** Before dispatching to the sandbox, the supervisor verifies that `/usr/bin/bwrap` exists, is executable, and supports unprivileged user namespaces. If validation fails, dispatch immediately aborts with `BrokerError::SandboxInitializationFailure`.
2. **Zero Permissive Fallback:** If seccomp compilation fails, or if namespace creation returns `EPERM` or `ENOSYS`, execution fails closed. The system will **never** execute an unconfined host process as a fallback.
3. **Production Execution Lockdown:** `PRODUCTION_EXECUTION_ALLOWED=false` remains strictly enforced. Live target scanning cannot proceed until all Phase 2 security gates are formally signed off.

---

## 7. Security Acceptance Gate Traceability

| Gate ID | Control ID | Test ID | Verification Requirement |
|---|---|---|---|
| `GATE-SANDBOX-CONTAINMENT-001` | `CTRL-SANDBOX-CONTAINMENT-001` | `TEST-SANDBOX-PRIV-001` | Prove worker runs with unprivileged UID, dropped capabilities, read-only rootfs, and no host filesystem access. |
| `GATE-SANDBOX-CLEANUP-001` | `CTRL-SANDBOX-CLEANUP-001` | `TEST-SANDBOX-CLEANUP-001` | Prove ephemeral scratch directories and child process trees are purged on completion, failure, and timeout. |
| `GATE-WORKER-RESOURCE-001` | `CTRL-WORKER-RESOURCE-001` | `TEST-WORKER-RESOURCE-001` | Prove wall-clock timeout kills runaway processes within 500ms grace; output streams capped at 16 KB. |
