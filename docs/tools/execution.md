# Tool Execution Pipeline

This document details the step-by-step lifecycle of tool execution from candidate validation to output result capture.

---

## 1. Execution Boundary Flow

```mermaid
sequenceDiagram
    participant Caller as Orchestrator / Worker
    participant Registry as ToolRegistry
    participant Scope as ScopeGuard
    participant Policy as PolicyEngine
    participant AM as ApprovalManager
    participant Audit as AuditService
    participant Exec as ToolExecutor

    Note over Caller,Registry: Step 1: Candidate Validation
    Caller->>Registry: validate_candidate_request(CandidateToolRequest, approval_id)
    Registry->>Scope: validate_target(target)
    Registry->>Policy: evaluate(CandidateToolRequest, ToolDefinition)
    opt Requires Approval
        Registry->>AM: validate_approval_for_request(approval_id, ...)
    end
    Registry-->>Caller: (Authoritative ToolRequest, PolicyDecision, error)

    Note over Caller,Registry: Step 2: Tool Execution Boundary
    Caller->>Registry: execute(ToolRequest)
    Registry->>Audit: record_action(TOOL_REQUESTED)
    
    critical Execute with Timeout
        Registry->>Exec: execute(ToolRequest, ToolDefinition)
        Exec-->>Registry: ToolResult
    option Timeout / Exception
        Registry->>Registry: Catch timeout / exception -> ToolResult(success=False)
    end

    Registry->>Audit: record_action(TOOL_EXECUTED or TOOL_FAILED)
    Registry-->>Caller: ToolResult
```

---

## 2. Tool Result Contract (`ToolResult`)

Every execution returns a standardized `ToolResult`:

```python
class ToolResult(BaseModel):
    request_id: str
    engagement_id: str
    task_id: str
    tool_name: str
    success: bool
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    execution_time_ms: int = 0
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
```
