# System Architecture

This document details the architectural tiers, data flow, and runtime interaction models across the ARKA platform.

---

## 1. Architectural Tiers

ARKA separates responsibilities into four distinct runtime tiers to guarantee that untrusted operations cannot cross into privileged execution contexts:

```mermaid
flowchart TB
    subgraph Tier1["1. Interface Tier"]
        CLI["Typer CLI (arka)"]
        API["FastAPI REST API"]
    end

    subgraph Tier2["2. Orchestration & Intelligence Tier"]
        Orch["LangGraph Orchestrator Graph"]
        Gateway["LiteLLM Gateway"]
        Checkpointer["PostgreSQL Checkpointer (AsyncPostgresSaver)"]
    end

    subgraph Tier3["3. Security & Policy Enforcement Tier"]
        Scope["ScopeGuard (Subnet/Domain Engine)"]
        Policy["PolicyEngine (Deterministic Risk Rules)"]
        Approval["ApprovalManager (Persistent Transitions)"]
        Audit["AuditService (Immutable Audit Trail)"]
        Registry["ToolRegistry (Execution Boundary)"]
    end

    subgraph Tier4["4. Execution & Persistence Tier"]
        Worker["Arq Async Worker (Redis Queue)"]
        Executors["Tool Executors (Mock in Phase 1)"]
        PostgresDB[(PostgreSQL Database)]
        RedisCache[(Redis Cache & Broker)]
    end

    CLI --> API
    API --> Orch
    Orch <--> Gateway
    Orch <--> Checkpointer
    Checkpointer --> PostgresDB
    
    Orch --> Registry
    Registry --> Scope
    Registry --> Policy
    Registry --> Approval
    Registry --> Audit
    
    Approval <--> PostgresDB
    Audit --> PostgresDB
    
    Registry --> Worker
    Worker <--> RedisCache
    Worker --> Executors
```

---

## 2. End-to-End Operational Lifecycle

The operational lifecycle of a penetration testing assessment proceeds in well-defined stages:

```mermaid
sequenceDiagram
    autonumber
    actor Operator as Security Operator
    participant API as FastAPI API
    participant Graph as LangGraph Orchestrator
    participant LLM as LLM Gateway
    participant Registry as ToolRegistry
    participant Policy as PolicyEngine
    participant AM as ApprovalManager
    participant Tool as Tool Executor
    participant Audit as AuditService

    Operator->>API: POST /engagements (Name, Objective, ScopeDefinition)
    API->>Audit: Record ENGAGEMENT_CREATED
    Operator->>API: POST /engagements/{id}/start
    API->>Audit: Record ENGAGEMENT_STARTED
    API->>Graph: Initialize Graph Execution (initial_state)

    loop Iterative Agent Execution Loop
        Graph->>LLM: Complete prompt (current context, tasks, observations)
        LLM-->>Graph: Structured JSON proposal
        Graph->>Graph: Parse proposal -> CandidateToolRequest (untrusted)
        
        Graph->>Registry: validate_candidate_request(CandidateToolRequest)
        Registry->>Policy: evaluate(CandidateToolRequest)
        Policy-->>Registry: PolicyDecision (ALLOW | REQUIRE_APPROVAL | DENY)
        
        alt PolicyDecision is DENY (Out of Scope / Prohibited)
            Registry-->>Graph: Error: Target out of scope / Policy denied
            Graph->>Audit: Record POLICY_DECISION (denied)
            Graph->>Graph: Mark task failed / replan
        else PolicyDecision is REQUIRE_APPROVAL (High/Critical Risk)
            Registry->>AM: find_matching_request / create_request (REQUIRED)
            Registry-->>Graph: Interruption required (approval_id)
            Graph->>Graph: interrupt(approval_id) [Execution Suspends]
            
            Operator->>API: View pending approval
            Operator->>API: POST approval decision (GRANTED)
            API->>AM: approve(approval_id)
            Operator->>Graph: Resume graph Command(resume=approved)
            
            Graph->>Registry: validate_candidate_request(approval_id)
            Registry->>AM: validate_approval_for_request(approval_id)
            AM-->>Registry: Valid & Granted
            Registry-->>Graph: Authoritative ToolRequest
        else PolicyDecision is ALLOW (Low/Medium Risk in Scope)
            Registry-->>Graph: Authoritative ToolRequest (trusted booleans set)
        end
        
        opt Authorized Tool Execution
            Graph->>Registry: execute(Authoritative ToolRequest)
            Registry->>Audit: Record TOOL_REQUESTED
            Registry->>Tool: execute(ToolRequest, ToolDefinition)
            Tool-->>Registry: ToolResult (output, success, execution_time_ms)
            Registry->>Audit: Record TOOL_EXECUTED / TOOL_FAILED
            Registry-->>Graph: ToolResult
            Graph->>Graph: Process observations & update state
        end
    end

    Graph->>API: Final execution state
    API-->>Operator: Assessment status & task report
```

---

## 3. Tier Separation Guarantees

1. **Memory Isolation**: Untrusted candidate data is maintained in a distinct Pydantic schema (`CandidateToolRequest`). Authoritative `ToolRequest` objects can only be minted within `ToolRegistry` after all security gates pass.
2. **Crash Resilience**: Because LangGraph checkpoints state after every node transition in PostgreSQL, any unexpected server reboot or process crash preserves the exact graph position and pending approvals.
3. **Audit Immutability**: The `AuditService` runs within the application process but treats all events as append-only records, preventing in-memory or database mutation.
