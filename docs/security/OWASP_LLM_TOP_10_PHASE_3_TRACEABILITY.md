# ARKA Phase 3 — OWASP Top 10 for LLM Applications (2025) Traceability Matrix

**Status:** PROPOSED Architecture Traceability Baseline  
**Date:** 2026-10-18  
**Taxonomy Baseline:** OWASP Top 10 for Large Language Model Applications (2025 Taxonomy)  
**Governing Baseline:** ARKA PRD v2.2, ARKA TRD v2.2, Phase 3 Architecture Plan  
**Classification:** Security Architecture & Compliance Traceability  

---

## 1. Scope and Taxonomy Separation

> [!IMPORTANT]
> **Taxonomy Distinction:** This document governs risks specific to **Large Language Model Applications (OWASP LLM Top 10 2025)**. 
> 
> It is strictly distinct from the **OWASP Web Application Security Top 10 (2021/2025)** mapped in Phase 2 ([`docs/security/OWASP_TOP_10_PHASE_2_TRACEABILITY.md`](file:///home/exu0/cybersecurity/Programs/ARKA/docs/security/OWASP_TOP_10_PHASE_2_TRACEABILITY.md)), which addressed broker APIs, sandbox containment, SSRF, DNS rebinding, and worker protocols.

This matrix transitions the initial planning stub ([`docs/security/OWASP_LLM_TOP_10_PHASE_3_TRACEABILITY_STUB.md`](file:///home/exu0/cybersecurity/Programs/ARKA/docs/security/OWASP_LLM_TOP_10_PHASE_3_TRACEABILITY_STUB.md)) into an implementation-ready requirements and verification baseline for Phase 3.

---

## 2. Comprehensive Traceability Matrix

Every category in the 2025 OWASP LLM taxonomy is mapped to registered ARKA threat identifiers, security controls, test contracts, acceptance gates, and design specifications:

| OWASP LLM Category | Primary ARKA Threats | Enforcing Controls | Linked Tests & Acceptance Gates | Implementation Component & ADR Reference | Status |
|---|---|---|---|---|:---:|
| **LLM01: Prompt Injection** | `THREAT-PROMPT-INJECTION`<br>`THREAT-MALICIOUS-TARGET-CONTENT` | `CTRL-PROMPT-GUARD-001`<br>`CTRL-CONTENT-ISOLATION-001` | `TEST-PROMPT-INJECTION-001`<br>`GATE-PROMPT-GUARD-001` | `COMP-LLM-GW`<br>`ADR-004`, `ADR-006` | `PENDING(phase=3)` |
| **LLM02: Sensitive Information Disclosure** | `THREAT-LLM-EGRESS-DATA-LEAKAGE`<br>`THREAT-LLM-PROVIDER-EXPOSURE` | `CTRL-LLM-EGRESS-DLP-001`<br>`CTRL-EGRESS-FILTER-001` | `TEST-LLM-EGRESS-001`<br>`GATE-LLM-EGRESS-001`<br>`GATE-EGRESS-FILTER-001` | `COMP-LLM-GW`<br>`ADR-004` | `PENDING(phase=3)` |
| **LLM03: Supply Chain** | `THREAT-DEPENDENCY-COMPROMISE` | `CTRL-SUPPLY-CHAIN-AUDIT-001`<br>`CTRL-LLM-MODEL-PROVENANCE-001` | `TEST-SUPPLY-CHAIN-001`<br>`GATE-SUPPLY-CHAIN-001` | Platform Build & Packaging<br>`docs/security/SUPPLY_CHAIN_POLICY.md` | `PENDING(phase=3)` |
| **LLM04: Data and Model Poisoning** | `THREAT-GRAPHIFY-POISONING`<br>`THREAT-MALICIOUS-TARGET-CONTENT` | `CTRL-GRAPH-INTEGRITY-001`<br>`CTRL-CONTENT-ISOLATION-001` | `TEST-GRAPHIFY-POISONING-001`<br>`TEST-RAG-POISONING-001`<br>`GATE-GRAPH-INTEGRITY-001` | `COMP-KG`<br>`ADR-005` | `PENDING(phase=3)` |
| **LLM05: Improper Output Handling** | `THREAT-TOOL-OUTPUT-POISONING`<br>`THREAT-EVIDENCE-PARSER-COMPROMISE` | `CTRL-TOOL-OUTPUT-SANITIZATION-001`<br>`CTRL-PARSER-SANDBOX-001` | `TEST-TOOL-POISONING-001`<br>`TEST-EVIDENCE-PARSER-001`<br>`GATE-TOOL-OUTPUT-001`<br>`GATE-PARSER-SANDBOX-001` | `COMP-SANDBOX`<br>`COMP-EVID`<br>`ADR-006` | `PENDING(phase=3)` |
| **LLM06: Excessive Agency** | `THREAT-ROGUE-AGENT`<br>`THREAT-SCOPE-EXPANSION` | `CTRL-AGENT-SUPERVISION-001`<br>`CTRL-SCOPE-ENFORCEMENT-001`<br>`CTRL-DUAL-AUTHORIZATION-001` | `TEST-RESOURCE-001`<br>`TEST-CAPABILITY-SCOPE-001`<br>`GATE-ROGUE-AGENT-001` | Deterministic Security Kernel<br>`crates/arka-kernel`<br>`ADR-005`, `ADR-006` | `PENDING(phase=3)` |
| **LLM07: System Prompt Leakage** | `THREAT-LLM-EGRESS-DATA-LEAKAGE` | `CTRL-LLM-EGRESS-DLP-001` | `TEST-LLM-EGRESS-001`<br>`GATE-LLM-EGRESS-001` | `COMP-LLM-GW`<br>`ADR-004` | `PENDING(phase=3)` |
| **LLM08: Vector & Embedding Weaknesses** | `THREAT-GRAPHIFY-POISONING` | `CTRL-GRAPH-INTEGRITY-001` | `TEST-GRAPHIFY-POISONING-001`<br>`GATE-GRAPH-INTEGRITY-001` | `COMP-KG` | `PENDING(phase=3)` |
| **LLM09: Misinformation** | `THREAT-MALICIOUS-TARGET-CONTENT`<br>`THREAT-GRAPHIFY-POISONING` | `CTRL-CONTENT-ISOLATION-001`<br>`CTRL-GRAPH-INTEGRITY-001` | `GATE-CONTENT-ISOLATION-001`<br>`GATE-GRAPH-INTEGRITY-001` | `COMP-EVID`<br>`COMP-KG` | `PENDING(phase=3)` |
| **LLM10: Unbounded Consumption** | `THREAT-RESOURCE-EXHAUSTION`<br>`THREAT-BUDGET-OVERRUN` | `CTRL-RESOURCE-LIMIT-001`<br>`CTRL-BUDGET-ENFORCEMENT-001` | `TEST-RESOURCE-001`<br>`GATE-WORKER-RESOURCE-001` | `COMP-LLM-GW`<br>`ResourceGovernor`<br>`ADR-004` | `PENDING(phase=3)` |

---

## 3. Deep Architectural Risk Controls

### LLM01: Prompt Injection Defense
- **Dual-Boundary Framing (`CTRL-PROMPT-GUARD-001`):** Ingested target data, HTTP responses, and tool outputs are strictly enclosed in structured XML/JSON data envelopes (`<untrusted_target_data>...</untrusted_target_data>`) with randomized per-request nonce delimiters.
- **Architectural Zero Authority (INV-001):** Natural language instructions inside data payloads cannot execute commands or modify scope. The deterministic Rust Security Kernel evaluates structured action proposals independently of model narrative.

### LLM02 & LLM07: Sensitive Information & System Prompt Leakage
- **Gateway Isolation & Credential Stripping (`CTRL-LLM-EGRESS-DLP-001` / ADR-004):** LLM provider credentials and internal authentication tokens (`ARKA-TOKEN-V1:`, Ed25519 keys) are quarantined within the Gateway process. Outbound payloads are inspected; any payload containing internal tokens or configured secrets is aborted immediately before socket transmission.
- **System Prompt Secrecy Non-Reliance:** Prompts are structured assuming that prompt extraction cannot be completely prevented by prompt engineering alone. Security boundaries rely exclusively on cryptographic tokens and kernel authorization, never on prompt secrecy.

### LLM03: Supply Chain Security
- **Multi-Plane Dependency Locking:** Rust dependencies are pinned and verified via `Cargo.lock` and `cargo audit`. Python dependencies for Phase 3 must be strictly pinned with cryptographic hashes (`requirements.txt` with `--require-hashes` / `pip-tools`) and audited via `pip-audit`.
- **Model Weight & API Provenance:** External LLM adapters must connect strictly to pinned endpoints verified by TLS 1.3 WebPKI certificates. Local models (Ollama/GGUF) must verify SHA-256 model weight checksums before loading.

### LLM04 & LLM08: Data, Model, and Vector Poisoning
- **Knowledge Graph Provenance Binding (`CTRL-GRAPH-INTEGRITY-001`):** Every node and edge inserted into the knowledge graph must carry a cryptographic pointer (`evidence_hash`) linking to immutable evidence ingested by the Execution Broker. Unevidenced assertions cannot be used for automated planning.

### LLM05: Improper Output Handling
- **Tool Output Sanitization (`CTRL-TOOL-OUTPUT-SANITIZATION-001`):** Raw stdout/stderr and target web responses are processed by sanitizers that strip ANSI escape codes, terminal escape sequences (`\x1b`), and nested delimiters before storage or LLM context inclusion.
- **Isolated Evidence Parsing (`CTRL-PARSER-SANDBOX-001`):** Parsers for complex target artifacts (XML, PDF, HTML, JSON) execute inside unprivileged memory-limited sandboxes to prevent parser memory-corruption exploits.

### LLM06: Excessive Agency
- **Monotonic Authority Delegation (INV-004):** Child agents cannot be spawned with capability sets, budgets, or scopes broader than their parent.
- **Deterministic Action Normalization (`ADR-006`):** All LLM native tool calls must pass through `ActionNormalizer`. Generic unrestricted shell or arbitrary code execution capabilities are forbidden. High-risk actions require human Two-Person Integrity approval.

### LLM10: Unbounded Consumption
- **Token & Request Rate Limiting (`COMP-LLM-GW`):** The LLM Gateway enforces per-minute token ceilings, request rate limits, and maximum context window limits.
- **Recursion & Loop Guards:** Agent reasoning loops are constrained by explicit recursion depth limits (default: 10 iterations) and mission execution timeouts enforced by `crates/arka-execution-broker::ResourceGovernor`.

---

## 4. Verification Non-Claims & Gate Status

- **Paper-Only Baseline:** This document establishes the formal traceability requirements. No control or gate in this matrix is claimed as implemented or passed.
- **Status:** All Phase 3 entries remain `PENDING(phase=3)` until implementation and executable negative test suites are completed and audited under Phase 3.1c/3.1d.
