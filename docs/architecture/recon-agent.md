# ARKA ReconAgent Architecture & Security Model

**Status**: Verified (Phase 2.2.4)  
**Component**: `arka.app.agents.recon`  
**Base Class**: `arka.app.agents.base.agent.BaseAgent`  

---

## 1. Executive Summary

`ReconAgent` is ARKA's autonomous reconnaissance planning and orchestration agent. It coordinates with the provider-agnostic `LLMGateway` to synthesize high-level assessment objectives into structured reconnaissance plans and candidate actions, submits untrusted candidate requests strictly through ARKA's authoritative security pipeline, and normalizes observed infrastructure into canonical, deduplicated `Asset`, `Service`, `Technology`, and `Endpoint` records linked to cryptographic evidence provenance.

---

## 2. Core Security Boundaries & Trust Architecture

`ReconAgent` is strictly an **orchestration component**, not an authorization or execution component. It possesses zero execution privileges and zero ability to alter authorization boundaries.

```text
User / API
    ↓
Engagement / ReconAgent
    ↓
LLM Gateway (Provider Agnostic)
    ↓
CandidateToolRequest (Untrusted proposal)
    ↓
ToolRegistry (Authoritative registry boundary)
    ↓
ScopeGuard (Deterministic CIDR/IP/Domain matching)
    ↓
PolicyEngine (Risk level & policy evaluation)
    ↓
ApprovalManager (Human approval gate for HIGH risk)
    ↓
Authoritative ToolRequest (Trusted execution contract)
    ↓
ExecutionManager (Timeout, limits, sandbox isolation)
    ↓
SandboxRuntime / NmapToolExecutor
    ↓
ToolResult
    ↓
EvidenceStore (Cryptographic SHA-256 capture)
    ↓
AssetNormalizer (Tool observation → Canonical models)
    ↓
AssetRepository (Deduplicated canonical asset storage)
    ↓
AuditService (Immutable hash-chained event trail)
```

### Invariant 1: LLM is Never Trusted
The LLM proposes hypotheses, targets, arguments, and follow-ups. The LLM cannot:
- Execute subprocesses, shell commands, or Docker containers.
- Directly call tool adapters or write to the database.
- Modify scope definitions or approve its own proposed actions.
- Directly mutate `EvidenceStore` or `AssetRepository`.

### Invariant 2: DISCOVERED ≠ AUTHORIZED
Reconnaissance frequently uncovers previously unknown hosts, IPs, or domains (e.g., secondary addresses discovered in Nmap XML).
- Discovered entities are normalized and stored in `AssetRepository` as observed infrastructure.
- **Discovery never expands authorization scope.** `ScopeGuard` and `ScopeDefinition` remain immutable during result processing.
- Any subsequent candidate action proposing a discovered asset must independently pass `ScopeGuard` evaluation. If the discovered target is outside the original engagement scope, it is blocked with a `PolicyDecisionType.DENY`.

### Invariant 3: Idempotency & Action Fingerprinting
To prevent runaway loops and infinite duplicate scans, each proposed action is assigned a deterministic, timestamp-free SHA-256 fingerprint:
$$\text{fingerprint} = \text{SHA256}(\text{tool\_name} + \text{operation} + \text{normalized\_target} + \text{canonical\_json}(\text{arguments}))$$
- Timestamps, correlation IDs, and run UUIDs are excluded from fingerprint computation.
- The agent tracks execution counts per fingerprint. Actions exceeding `max_repeated_action_attempts` (default: 2) are automatically discarded.

### Invariant 4: Bounded Recon Loop & Safety Limits
Execution is bounded by explicit, tunable limits configured via `ReconAgentConfig`:
- `max_iterations` (default: 10)
- `max_actions` (default: 25)
- `max_repeated_action_attempts` (default: 2)
- `max_consecutive_failures` (default: 3)

---

## 3. Data & State Models

### ReconState
Typed, serializable Pydantic model maintaining agent state across iterations:
- `engagement_id`: Active engagement UUID string.
- `authorized_scope`: Serialized `ScopeDefinition` dictionary.
- `recon_objectives`: High-level operational objectives.
- `current_assets`: Observed canonical asset addresses/identifiers.
- `current_services`: Observed canonical service specifications.
- `current_technologies`: Observed technology CPEs/versions.
- `current_endpoints`: Observed web endpoints.
- `completed_actions`: Execution history and outcomes.
- `pending_actions`: Queue of proposed actions from the current plan.
- `executed_fingerprints`: Mapping of action fingerprints to execution counts.
- `tool_results`: Summaries of executed tool results.
- `evidence_refs`: Cryptographic SHA-256 evidence reference IDs.
- `observations`: Accumulated security findings.
- `hypotheses`: Active security hypotheses.
- `errors`: Accumulated rejections and error messages.
- `iteration`: Current iteration count.
- `action_count`: Total executed actions count.
- `consecutive_failures`: Consecutive rejection/failure counter.
- `status`: Lifecycle state (`initialized`, `running`, `paused`, `completed`, `failed`, `stopped`).
- `termination_reason`: Explicit `ReconTerminationReason`.

### ReconTerminationReason
Enumerated termination conditions:
- `OBJECTIVES_SATISFIED`: Recon goals reached or LLM stop condition met.
- `MAX_ITERATIONS_REACHED`: Reached configured iteration limit.
- `MAX_ACTIONS_REACHED`: Reached configured total action execution limit.
- `MAX_REPEATED_ACTIONS_REACHED`: Bounded identical scan loop detected.
- `NO_USEFUL_NEXT_ACTION`: No further valid candidate actions available.
- `SCOPE_EXHAUSTED`: All authorized targets enumerated.
- `REPEATED_FAILURES`: Exceeded consecutive failure/rejection threshold.
- `SAFETY_POLICY_REJECTION`: Halted due to security policy rejection.
- `FATAL_ERROR`: Unrecoverable execution exception.

---

## 4. LLM Gateway Integration

ReconAgent interacts with the LLM strictly via `LLMGateway`:
- Model-agnostic prompting: Requests structured JSON matching `ReconPlan` or `ReconAnalysis`.
- No provider-specific SDKs or hard-coded models.
- Graceful error recovery: Malformed, ambiguous, or non-JSON output is safely rejected without falling back to shell interpreters.

---

## 5. Result Processing & Evidence Provenance

Upon receiving a `ToolResult` from `ToolRegistry.execute`:
1. **Evidence Linkage**: Retrieves SHA-256 `evidence_refs` recorded by `ExecutionManager` and links them to the agent's state.
2. **Canonical Normalization**: When Nmap XML is present, `AssetNormalizer.normalize_nmap_result` parses the output into a `NormalizedAssetBundle`.
3. **Repository Persistence**: Upserts the bundle to `AssetRepository` (PostgreSQL or `InMemoryAssetRepository`).
4. **Auditability**: Records `EVIDENCE_RECORDED`, `TOOL_EXECUTED`, and `LLM_RESPONSE` events via `AuditService`.

---

## 6. Current Limitations (Phase 2.2.4)

1. **Tool Scope**: Phase 2.2.4 integrates the verified Nmap adapter. Additional reconnaissance adapters (`nuclei`, `ffuf`, `whatweb`, `amass`) will be added in subsequent phases.
2. **Evidence Persistence**: Evidence is captured cryptographically in memory via `EvidenceStore`. PostgreSQL byte-store persistence will be introduced in future database phases.
3. **Sandbox Execution**: Nmap is executed through `LocalSafeRuntime` with verified argument safety. Production multi-container sandboxing will be active once Docker daemon integration is completed.
