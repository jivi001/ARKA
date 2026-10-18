# ADR-004: LLM Gateway Process Topology, Credential Isolation, and Pinned Egress

**Status:** PROPOSED (Pending Human Ratification by `@jivi001`)  
**Date:** 2026-10-18  
**Authors:** Principal AI Security Architect, Rust/Python Systems Engineer  
**Phase:** Phase 3 — Intelligence & Multi-Agent Plane  
**Classification:** Security-Critical Architectural Contract  

---

## 1. Context and Problem Statement

ARKA Phase 3 introduces the Intelligence Plane, composed of autonomous Python agent reasoning loops, multi-agent coordination, and external Large Language Model (LLM) integrations (OpenAI-compatible endpoints, Anthropic-compatible endpoints, and local models).

LLM providers require high-privilege API credentials (e.g., secret bearer tokens or API keys). Within the ARKA architecture, the handling of these secrets is governed by strict, non-negotiable architectural invariants:

$$\mathbf{INV-011:}\quad \text{LLM provider credentials MUST be resolved only by the LLM Gateway and MUST NOT enter agent context, evidence, audit, memory, ActionProposal objects, or logs.}$$

$$\mathbf{INV-012:}\quad \text{An LLM provider credential MUST grant inference access only and MUST NOT grant ARKA execution, scope, approval, policy, capability, or credential-broker authority.}$$

$$\mathbf{INV-001:}\quad \text{The LLM plane has zero direct operating system, shell, socket, or network execution authority.}$$

### The Threat Model for the Intelligence Plane

1. **Adversarial Input & Indirect Prompt Injection:** Autonomous agents ingest untrusted external data (HTML responses, DNS records, terminal outputs, OSINT artifacts, poisoned documents). Adversaries will attempt indirect prompt injection to force the LLM into exfiltrating environment variables, reading local files, or forging action proposals.
2. **Process Inspection & Memory Disclosure:** If an agent executes within the same operating system identity (UID) or memory space as the LLM Gateway, a compromised agent can read credentials via `/proc/<pid>/environ`, inspect heap memory via `ptrace(2)` or `/proc/<pid>/mem`, or intercept socket traffic.
3. **Network Egress Bypass:** If the agent process possesses direct outbound network routing, an attacker can direct it to transmit exfiltrated data directly to an external server, bypassing the LLM Gateway's data-loss prevention (DLP) and audit controls.

ARKA requires an implementation-ready gateway architecture that deterministically isolates LLM provider credentials, enforces endpoint-pinned network egress, and prevents same-host privilege escalation by compromised agents.

---

## 2. Architectural Topology Alternatives

Three distinct process and isolation topologies were investigated:

```text
Topology 1: Dedicated OS User + Authenticated Unix-Domain Socket (UDS) IPC
+-----------------------------------+         +------------------------------------+
|  Agent Process (UID: arka-agent)  |         | Gateway Process (UID: arka-gateway)|
|  - Zero provider secrets in env   |         | - Holds provider API keys in memory|
|  - Network egress: DENIED by OS   |         | - Egress: PINNED via nftables/sock |
|  - File access: Restricted        |         | - Resolves model requests          |
+-----------------+-----------------+         +-----------------+------------------+
                  |                                             ^
                  |======== Authenticated UDS (SO_PEERCRED) =====|
                            (/run/arka/gateway.sock, mode 0660)

Topology 2: Separately Restricted Container Sandbox (Rootless Bubblewrap / OCI)
+-----------------------------------+         +------------------------------------+
| Agent Container Namespace (bwrap) |         | Gateway Container Namespace (bwrap)|
| - Isolated PID, Mount, Net NS     |         | - Dedicated veth or UDS socket     |
| - Read-only rootfs, empty /proc   |         | - Provider secrets in memory tmpfs |
| - Bridge net: Gateway IP only     |         | - Egress: Pinned to Provider IP    |
+-----------------+-----------------+         +-----------------+------------------+
                  |                                             ^
                  |============ Mounted UDS or Internal Bridge =|

Topology 3: Rust-Hosted Provider Proxy
  Variant A: Same-Process Language Bindings (PyO3 / C-FFI)  [REJECTED - INSECURE]
  Variant B: Dedicated Rust Daemon Process (arka-gatewayd) [RECOMMENDED PROPOSAL]
```

### 2.1 Comparative Analysis Matrix

| Evaluation Dimension | Option 1: Dedicated OS User + UDS IPC | Option 2: Restricted Container (bwrap) | Option 3A: Same-Process PyO3 Bindings | Option 3B: Standalone Rust Daemon (`arka-gatewayd`) |
|---|---|---|---|---|
| **Compromised-Agent Credential Isolation** | **High:** Linux Discretionary Access Control (DAC) blocks cross-UID `/proc` and file reads. | **Maximum:** Kernel namespace separation (PID, Mount) renders Gateway completely invisible. | **ZERO (FAIL):** Shared virtual address space; Python `ctypes`/heap scanning reads Rust memory. | **High:** Separate address space and OS process boundary; zero memory sharing. |
| **Same-UID `/proc` & `ptrace` Exposure** | **Eliminated:** Different UIDs (`arka-agent` vs `arka-gateway`) block `PTRACE_ATTACH` and `/proc/<pid>/environ`. | **Eliminated:** Gateway PID does not exist inside Agent's PID namespace. | **Extreme Vulnerability:** Same PID; full arbitrary memory read/write. | **Eliminated:** Runs as distinct UID or isolated background service. |
| **IPC Authentication & Impersonation** | **Deterministic:** Kernel-verified peer credentials via `getsockopt(..., SO_PEERCRED)` assert peer UID/PID. | **Strong:** Socket mounted exclusively into authorized container mounts; peer UID checked. | **None:** In-process function invocation. | **Deterministic:** Unix Domain Socket with `SO_PEERCRED` verification. |
| **Network Egress Restriction** | **OS-Enforced:** `nftables` owner-match module (`-m owner --uid-owner arka-gateway`) permits egress only for Gateway. | **Namespace-Enforced:** Agent network namespace has zero default route; veth routes strictly to Gateway. | **Impossible to Isolate:** Agent and Gateway share identical network socket permissions. | **OS-Enforced:** Gateway binary uses Phase 2 `DirectIpConnector` / socket pinning. |
| **Operational & CI Complexity** | **Moderate:** Requires provisioning two OS users during platform install; works in standard Linux CI. | **High:** Requires rootless user namespaces (`bwrap` / `crun`) for orchestrating multiple containers. | **Low:** Single Python binary build. | **Moderate-Low:** Native Rust binary integration with existing workspace; simple daemon service. |
| **Memory Safety & Zeroization** | Dependent on Python runtime garbage collection in Gateway. | Dependent on container runtime process cleanup. | Rust memory protections bypassed by Python runtime flaws. | **Maximum:** Rust `zeroize` and `secrecy` crates guarantee immediate memory scrubbing. |

### 2.2 Rejection of Option 3A (Same-Process Language Bindings)

> [!CAUTION]
> **Definitive Architectural Rejection:** Running the LLM Gateway inside the same process as the Python agent plane (e.g., via PyO3, ctypes, or embedded C-extensions) is **strictly forbidden**. In a shared address space, any prompt injection or malicious dependency achieving arbitrary code execution in Python can read raw memory buffers, dump process heap, or hook C-level function pointers, directly exfiltrating provider secrets in violation of INV-011.

---

## 3. Decision Specification (Proposed Baseline)

We propose **Option 3B: Standalone Rust LLM Gateway Daemon (`arka-gatewayd`) communicating over Authenticated Unix-Domain Socket IPC**, with support for **Option 1 OS User Separation**.

```text
[ UNTRUSTED REASONING PLANE ]                     [ TRUSTED GATEWAY BOUNDARY ]
+----------------------------+                   +--------------------------------------------+
| Python Agent Runtime       |                   | Standalone Rust Gateway (arka-gatewayd)    |
| (UID: arka-agent)          |                   | (UID: arka-gateway)                        |
|                            |                   |                                            |
| 1. Model Request Payload   |                   | 2. Ingest Request over UDS                 |
|    - Prompt / Context      |                   |    - Assert SO_PEERCRED (UID == arka-agent)|
|    - Model / Parameters    |                   | 3. DLP & Data Classification Filter        |
|    - ZERO Credentials      |                   |    - Strip accidental tokens/secrets       |
|                            |                   |    - Enforce sensitivity policies          |
|                            |                   | 4. Resolve Provider Secret                 |
|                            |                   |    - OS Keyring / KMS / Env (Gateway only) |
|                            |                   | 5. Deterministic Direct-IP Pinned Egress   |
|                            |                   |    - DirectIpConnector dials Pinned IP     |
|                            |                   |    - Rustls TLS 1.3 Handshake              |
|                            |                   | 6. Untrusted Output Ingestion              |
| 8. Receive Sanitized Text  |                   | 7. Sanitize & Strip Control Sequences      |
+-------------+--------------+                   +---------------------+----------------------+
              |                                                        |
              |==== Authenticated UDS (/run/arka/gateway.sock) ========|
                               Mode: 0660 (arka-gateway:arka-agent)
```

### 3.1 IPC Authentication Protocol

1. The gateway listens on a dedicated Unix Domain Socket at `/run/arka/gateway.sock` (permissions `0660`, owned by `arka-gateway:arka-agent`).
2. Upon connection `accept()`, the gateway immediately executes `getsockopt` with `SO_PEERCRED` on Linux (or `LOCAL_PEERCRED` on BSD/macOS).
3. The gateway verifies:
   - `peer_uid == get_uid("arka-agent")` (or authorized mission executor).
   - If UID does not match authorized identities, the connection is immediately aborted (`fail closed`).
4. Every incoming IPC message must adhere to a strict versioned JSON schema (`RawGatewayRequest`), enforcing a 10MB payload ceiling and maximum recursion depth of 8.

### 3.2 Provider Endpoint Pinning & Egress Restrictions

The Gateway must not use uncontrolled OS DNS resolution or arbitrary HTTP client libraries. In accordance with Phase 2 ADR-001:

1. **ScopeGuard Resolution:** When dialing an external provider endpoint (e.g. `api.openai.com`, `api.anthropic.com`):
   - The Gateway executes DNS resolution using `arka_network_policy::dns::DirectIpResolver`.
   - The resolved IP is validated: RFC 1918 private ranges, loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and IPv4-mapped IPv6 evasions are rejected unless explicitly targeting an operator-configured local mock (e.g., local Ollama instance on `127.0.0.1:11434` during laboratory testing).
   - The selected IP is pinned for the socket duration (`PinnedDestination`).
2. **Direct IP Socket Dialing:** The socket dials `SocketAddr(pinned_ip, 443)` directly via `tokio::net::TcpStream`.
3. **SNI & TLS Verification:** Rustls performs TLS 1.3 handshake against `pinned_ip`, asserting that the server certificate validates against WebPKI roots for the original provider hostname.
4. **Host-Level Firewall Enforcement:** In production, host `nftables` rules drop any outbound SYN packet from `arka-agent` UID, ensuring physical egress is technically impossible outside the Gateway daemon.

### 3.3 Data Classification & Outbound DLP Pipeline

Before any prompt payload is transmitted across the external provider connection, it must traverse the Gateway's deterministic data-classification pipeline:

1. **Sensitivity Filter:** Verifies that context chunks do not carry classification `Secret` or `Confidential` that forbids external LLM processing.
2. **Deterministic Token & Secret DLP:** Scans outbound JSON for:
   - ARKA internal identity tokens (`ARKA-TOKEN-V1:`).
   - Ed25519 hex-encoded private keys.
   - Provider API keys (regex matching OpenAI `sk-proj-*`, Anthropic `sk-ant-*`, etc.).
   - Discovered target credentials tagged in evidence.
   If any pattern matches, the outbound transmission is **aborted immediately**, logging a security violation audit event (`GATE-EGRESS-FILTER-001`).
3. **Untrusted Model Output Handling:** Responses returned from LLMs are treated as untrusted data:
   - Scrubbed of ANSI control codes and escape sequences.
   - Schema-validated before returning to the agent.
   - Prohibited from self-authorizing actions.

---

## 4. Development `.env` Assessment & Exception Policy

### 4.1 Requirement Conflict Analysis

- **TRD §28.3:** *"Local `.env` files MAY be used only as a developer convenience and MUST be excluded from version control. Production deployments MUST use an approved secret-management mechanism rather than relying on committed or image-baked `.env` files."*
- **Key Management Policy:** [`security/keys/key-management-policy.yaml`](file:///home/exu0/cybersecurity/Programs/ARKA/security/keys/key-management-policy.yaml#L89) lists `.env configuration files` as a `prohibited_destination`.
- **Invariant INV-011:** Provider credentials must never enter agent context or environment.

### 4.2 Adversarial Vulnerability of Unrestricted `.env`

If a developer places `.env` in the repository root and executes `python -m arka.agents.recon`, the Python agent process directly inherits `os.environ["OPENAI_API_KEY"]` and has direct filesystem read access to `.env`. 

Under prompt injection, an attacker instructing the agent to execute a file read or reflect environment variables can immediately steal the developer's API key, violating INV-011.

### 4.3 Proposed Development Resolution: The Gateway-Only Loader Pattern

To reconcile developer convenience with cryptographic isolation:

1. **Gateway-Exclusive Ingestion:** The `.env` file must be read **exclusively by `arka-gatewayd`**.
2. **Sanitized Agent Environment:** When development startup scripts launch the agent plane, they must strip provider variables:
   ```bash
   env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY python -m arka.agents.orchestrator
   ```
3. **File Permission Hardening:** Development documentation must instruct developers to enforce `chmod 0600 .env`.
4. **Development Exception Flag (`DEV-EXC-001`):**
   If a developer runs agents and the gateway co-located in a single process without OS user isolation:
   - The platform must require an explicit environment variable: `ARKA_UNSAFE_DEV_CO_LOCATED_GATEWAY=true`.
   - The platform will log a critical warning and refuse to start if `ARKA_ENVIRONMENT=production` or `ARKA_ENVIRONMENT=staging`.
   - This exception is narrowly scoped to local unit testing and **requires human CODEOWNER ratification**.

---

## 5. Non-Claims & Verification Prerequisites

- **No OS-Level Isolation Claim:** It is explicitly acknowledged that **no topology has passed OS-level isolation testing at this architecture stage**.
- **Prerequisites for Acceptance:** Full verification of ADR-004 requires implementing executable adversarial tests under Phase 3.1c:
  1. `test_agent_cannot_read_gateway_proc_environ`: Assert DAC blocks `/proc/<gateway_pid>/environ`.
  2. `test_agent_cannot_dial_external_network`: Assert network namespace / firewall drops direct agent egress.
  3. `test_uds_peercred_enforcement`: Assert foreign UID connections are rejected.
  4. `test_dlp_outbound_token_abort`: Assert attempt to send internal token aborts connection.

---

## 6. Decision Status & Human Sign-Off Requirement

**Decision Status:** `PROPOSED / PENDING HUMAN DECISION`  
**Required Approver:** Principal Security Architect & Human CODEOWNER (`@jivi001`)  
**Recommended Action:** Approve Option 3B (Standalone Rust Gateway Daemon + UDS IPC) with Gateway-Exclusive `.env` loading and formal registration of `DEV-EXC-001`.
