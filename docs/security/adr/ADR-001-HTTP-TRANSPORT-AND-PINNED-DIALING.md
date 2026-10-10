# ADR-001: HTTP Transport Selection, Direct-IP Dialing, and TLS Binding

**Status:** Accepted (P2-A Architecture Decision)  
**Date:** 2026-10-09  
**Authors:** Senior AI Systems Architect, Principal Rust Security Engineer  
**Phase:** Phase 2 — Execution Foundation & Sandboxing  
**Classification:** Security-Critical Architectural Contract  

---

## 1. Context and Problem Statement

ARKA Phase 2 introduces the Execution Broker, which dispatches authorized capabilities (starting with `TCP_CONNECT` to local fixtures, followed by `HTTP_REQUEST` in P2-D/P2-E). 

Standard HTTP client implementations (such as default configurations of `reqwest` or `curl`) exhibit critical security vulnerabilities in hostile target environments:
1. **Autonomous OS DNS Resolution:** They pass domain names to OS resolvers (`getaddrinfo`) at connection time, creating a Time-of-Check to Time-of-Use (TOCTOU) gap between initial scope authorization and physical network connection.
2. **DNS Rebinding Vulnerability:** An adversary who controls an authoritative DNS server can return an authorized public IP address on the first query, followed by an unauthorized private or loopback IP (`127.0.0.1`, `169.254.169.254`) on subsequent connections.
3. **Automatic Redirect Blindness:** Default clients follow HTTP 3xx redirects automatically across hosts, schemes, ports, and IP classes without consulting the authorization engine or network policy.
4. **IPv6 and Representation Evasion:** Ambiguous target representations (e.g., octal/hexadecimal IPv4, IPv4-mapped IPv6, zone IDs) can bypass naive string-based filters if not canonicalized before dialing.

ARKA requires an HTTP client architecture that guarantees that **every outbound byte connects exclusively to a pre-validated, in-scope IP address**, while preserving strict TLS security.

---

## 2. Decision

We select **Hyper 1.x** with **Tokio**, **Rustls**, and a custom **ScopeGuard Direct-IP Connector** as the foundational HTTP transport for ARKA Phase 2.

### 2.1 Technology Stack Selection
- **HTTP Engine:** `hyper` (v1.x) with `hyper-util` client helpers.
- **Async Runtime:** `tokio` (v1.x) with `tokio::net::TcpStream`.
- **TLS Engine:** `rustls` (v0.23+) with `webpki-roots` and `rustls-pki-types`.
- **No Heavy Client Wrapper:** We explicitly avoid high-level HTTP client libraries that conceal DNS resolution or socket creation behind opaque abstractions.

### 2.2 Direct-IP Dialing Architecture

```text
[Authorized Action] 
       |
       v
[ScopeGuard::resolve_and_validate(target)] 
       |---> DNS query executed once
       |---> All returned IPs validated against Scope, Exclusions, RFC1918, Loopback, Cloud Metadata
       |---> Single validated IP selected (pinned_ip)
       v
[DirectIpConnector::connect(target_uri, pinned_ip)]
       |---> tokio::net::TcpStream::connect(SocketAddr(pinned_ip, port))
       |---> Assert: socket.peer_addr()?.ip() == pinned_ip
       v
[RustlsClientConnector::handshake(socket, original_hostname)]
       |---> SNI = original_hostname (e.g. "target.example.com")
       |---> Certificate Chain Validation = ENABLED (WebPKI roots)
       |---> Hostname Verification = original_hostname
       v
[Hyper HTTP/1.1 / HTTP/2 Handshake]
       |---> HTTP Host / :authority = original_hostname
       v
[Established Encrypted Channel to Validated IP]
```

### 2.3 Strict Security Invariants Enforced

1. **Zero Secondary DNS Lookups:** The transport layer is structurally forbidden from invoking `getaddrinfo` or any DNS resolver. It dials raw `SocketAddr(pinned_ip, port)`.
2. **Socket Peer Verification:** Immediately following TCP handshake completion, the connector verifies:
   $$\mathbf{socket.peer\_addr()?.ip() == pinned\_ip}$$
   If any discrepancy exists (e.g., transparent proxy or OS socket confusion), the connection is immediately aborted.
3. **Uncompromised TLS Verification:** Direct-IP dialing **never disables or weakens TLS**:
   - The original canonical hostname is retained as the authoritative TLS `ServerName`.
   - Complete X.509 certificate chain validation is enforced against root anchors.
   - Hostname verification confirms that the leaf certificate matches the original hostname, not the pinned IP.
   - Untrusted, expired, revoked, or wrong-host certificates fail closed with `RequireTlsVerification`.
4. **HTTP Header Integrity:** The HTTP request `Host` (or HTTP/2 `:authority`) header remains bound to `original_hostname`, preventing virtual-host routing confusion.
5. **Per-Hop Redirect Revalidation:** Automatic redirect following is strictly disabled. Every 3xx response is intercepted, its `Location` header is parsed and normalized, and the new destination must undergo the identical DNS resolution, ScopeGuard policy evaluation, and Direct-IP connection sequence.
6. **Emergency Stop Interception:** The connector checks the persistent monotonic Emergency Stop state before DNS resolution, before TCP dialing, and before TLS handshake. If E-Stop is engaged, connection is refused immediately.

---

## 3. Threat Mitigations

| Threat | Mitigation Mechanism |
|---|---|
| **THREAT-SSRF** (`GATE-SSRF-001`) | ScopeGuard default-denies RFC 1918, loopback, link-local, and multicast IP ranges before dialing. |
| **THREAT-DNS-REBINDING** (`GATE-DNS-REBIND-001`) | Connect-time DNS query produces a pinned IP; socket dials only that IP. Rebinding between lookup and connect is mathematically impossible. |
| **THREAT-METADATA-ENDPOINT-ACCESS** (`GATE-METADATA-BLOCK-001`) | Explicitly blocks `169.254.169.254`, IPv6 metadata endpoints (`fd00:ec2::254`), and cloud provider link-local metadata ranges. |
| **THREAT-IPV6-POLICY-BYPASS** (`GATE-IPV6-POLICY-001`) | IPv6 destinations require explicit dual-stack scope policy; unscoped IPv6, IPv4-mapped IPv6, and scoped zone identifiers (`%eth0`) are rejected. |
| **THREAT-REDIRECT-VALIDATION-BYPASS** (`GATE-REDIRECT-FILTER-001`) | Zero trust inheritance across hops. Each redirect resets validation state. |

---

## 4. Consequences and Verification

### Positive Consequences
- Guarantees deterministic network policy enforcement at the physical socket layer.
- Completely eliminates DNS rebinding and TOCTOU DNS poisoning attacks.
- Preserves full cryptographic TLS integrity without compromising on host certificate checks.
- Unit and integration tests can deterministically simulate and verify connection boundaries using local loopback fixtures.

### Negative / Operational Trade-offs
- Custom connector implementation requires maintenance of low-level `hyper` and `rustls` glue code.
- Cannot leverage off-the-shelf high-level cookie jars or session state from generic HTTP libraries (acceptable since ARKA execution units are stateless and ephemeral).

### Verification Plan
- Unit tests asserting `DirectIpConnector` rejects connecting when socket peer != pinned IP.
- Integration tests against mock TLS servers verifying that expired, self-signed, and wrong-hostname certificates fail closed.
- Negative tests verifying that emergency stop triggered mid-handshake cleanly terminates the socket without outbound request transmission.
