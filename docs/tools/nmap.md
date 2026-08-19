# Nmap Tool Adapter Documentation

## 1. Overview

The Nmap Tool Adapter is the first real security tool adapter integrated into the ARKA platform (Phase 2.2.1). It provides structured port discovery, service detection, and version enumeration capabilities while maintaining ARKA's strict security invariants:

- **Explicit Argument Allowlist**: The LLM cannot specify arbitrary CLI flags.
- **ScopeGuard Authority**: Target authorization is strictly validated by ScopeGuard before execution.
- **Operation-Level Risk Escalation**: Non-intrusive scans are `RiskLevel.MEDIUM`; aggressive scans automatically escalate to `RiskLevel.HIGH` and require human approval.
- **Defensive XML Parsing**: Parsed using `defusedxml` to prevent XML entity attacks.
- **Cryptographic Provenance**: Raw XML and structured outputs are recorded in the `EvidenceStore` with SHA-256 digests.
- **Append-Only Audit Logging**: All lifecycle events are logged to `AuditService`.

---

## 2. Architecture & Pipeline

```
LLM / Agent Proposes
        ↓
CandidateToolRequest (Untrusted)
        ↓
ToolRegistry Schema Validation
        ↓
ScopeGuard (Inclusions & Exclusions)
        ↓
PolicyEngine (Operation-Level Risk Evaluation)
        ↓ (If HIGH: ApprovalManager Gate)
Authoritative ToolRequest
        ↓
ExecutionManager (Sandbox Lifecycle & Resource Limits)
        ↓
NmapToolExecutor
        ↓
Nmap Execution (Simulated in Phase 2.2.1)
        ↓
Nmap XML Output
        ↓
NmapXmlParser (defusedxml)
        ↓
NmapResult (Structured Domain Model)
        ↓
EvidenceStore (SHA-256) & AuditService
```

---

## 3. Configuration & Argument Allowlist

The adapter exposes only typed, validated fields via `NmapScanConfig`. There is **zero raw CLI flag passthrough**.

| Field | Type | Default | Generated Flag | Risk Escalation | Description |
|---|---|---|---|---|---|
| `ports` | `str \| None` | `None` | `-p <ports>` | No | Strict regex: `^[0-9]+([,\-][0-9]+)*$` |
| `service_detection` | `bool` | `True` | `-sV` | No | Enables service and version detection |
| `default_scripts` | `bool` | `False` | `-sC` | **Yes (HIGH)** | Enables default NSE scripts |
| `timing_template` | `int` (0–4) | `2` | `-T<0-4>` | **Yes (if ≥ 3)** | Scan timing template (0=Paranoid, 4=Aggressive) |
| Output Format | Hardcoded | — | `-oX -` | — | XML to stdout (not user-configurable) |
| Target | Authoritative | — | `<target>` | — | Extracted from `ToolRequest.target` |

---

## 4. Risk Model & Approval Behavior

1. **Standard Reconnaissance (`RiskLevel.MEDIUM`)**:
   - Configuration: `default_scripts=False`, `timing_template <= 2`.
   - Behavior: `PolicyEngine` returns `ALLOW`.
   - Execution proceeds immediately within authorized scope.

2. **Aggressive / Intrusive Reconnaissance (`RiskLevel.HIGH`)**:
   - Configuration: `default_scripts=True` (`-sC`) OR `timing_template >= 3` (`-T3`, `-T4`).
   - Behavior: `PolicyEngine` derives `RiskLevel.HIGH` via `NmapToolDefinition.determine_risk()`.
   - Decision: `REQUIRE_APPROVAL`.
   - Flow: Must be explicitly approved via `ApprovalManager` before an authoritative `ToolRequest` can be executed.

---

## 5. XML Parser Security (`defusedxml`)

All Nmap output is parsed using `defusedxml.ElementTree`:
- Defends against XML entity expansion (billion laughs attack).
- Defends against external entity injection (XXE).
- Defends against quadratic blowup attacks.
- Returns structured `NmapResult(success=False, error=...)` on malformed XML without unhandled exceptions.

---

## 6. Known Limitations (Phase 2.2.1)

- **Simulated Execution**: In Phase 2.2.1, execution is simulated in-memory using validated XML fixtures via `LocalSafeRuntime`. Real subprocess execution of the `nmap` binary will be enabled when `DockerSandboxRuntime` is connected to a live Docker daemon in Phase 2.2.2+.
