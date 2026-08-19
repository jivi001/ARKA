# Policy Engine Architecture (PolicyEngine)

The **PolicyEngine** (`arka/app/core/policies/engine.py`) is the single source of truth for authorization decisions and risk evaluation in ARKA.

---

## 1. Responsibilities

- Evaluating `CandidateToolRequest` and `ToolRequest` objects against security policy.
- Deriving authoritative risk levels from registered `ToolDefinition.risk_level`.
- Deciding whether an action requires human approval, is allowed automatically, or is denied.

---

## 2. Decision Logic Matrix

```mermaid
flowchart TD
    Eval[Evaluate Candidate / Tool Request] --> ScopeCheck{Target In Scope?}
    
    ScopeCheck -->|No| DENY([Decision: DENY\nReason: Target out of scope])
    ScopeCheck -->|Yes| RiskCheck{Authoritative Risk Level}
    
    RiskCheck -->|LOW / MEDIUM| ThresholdCheck1{Approval Required by Policy?}
    RiskCheck -->|HIGH / CRITICAL| ThresholdCheck2{Approval Required by Policy?}
    
    ThresholdCheck1 -->|False (Default)| ALLOW([Decision: ALLOW\nrequires_approval = False])
    ThresholdCheck1 -->|True (Configured)| REQ1([Decision: REQUIRE_APPROVAL\nrequires_approval = True])
    
    ThresholdCheck2 -->|True (Default)| REQ2([Decision: REQUIRE_APPROVAL\nrequires_approval = True])
    ThresholdCheck2 -->|False (Configured)| ALLOW
```

### Risk Level Rules:
1. **Out-of-Scope Rule**: If a target fails `ScopeGuard.validate_target()`, the decision is **ALWAYS `DENY`**, regardless of whether approval exists or what risk level is assigned.
2. **Authoritative Risk Derivation**: The request's self-claimed risk is ignored. The risk level is sourced from `ToolDefinition.risk_level`.
3. **Thresholds**:
   - `RiskLevel.LOW`: Auto-approved by default (`requires_approval = False`).
   - `RiskLevel.MEDIUM`: Auto-approved by default (`requires_approval = False`).
   - `RiskLevel.HIGH`: Requires human approval (`requires_approval = True`).
   - `RiskLevel.CRITICAL`: Requires human approval (`requires_approval = True`).
4. **Configurable Thresholds**: Operators can dynamically adjust approval requirements via `PolicyEngine.set_approval_threshold(risk_level, requires_approval)`.
