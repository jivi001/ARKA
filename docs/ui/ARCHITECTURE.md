# ARKA Web Security Operations Console — Architecture Specification

## 1. System Overview

The **ARKA Web Security Operations Console** transforms ARKA from a terminal/CLI-operated security platform into a production-grade, tactical Security Operations Center (SOC) visual interface. 

The console operates strictly as an **operator visibility and control interface**. It possesses **ZERO execution authority**. All security decisions, tool proposals, scope boundaries, and policy evaluations remain entirely governed by ARKA's authoritative deterministic backend plane.

```
                    ┌─────────────────────────────────────────┐
                    │     ARKA Web Console (Next.js 16)       │
                    │   React 19 / TanStack Query / SSE Bus   │
                    └────────────────────┬────────────────────┘
                                         │ HTTP REST / SSE
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │        FastAPI Application Layer        │
                    │   (/api/* routes, auth, session context) │
                    └────────────────────┬────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │      LangGraph Multi-Agent Runtime      │
                    │   (ReconAgent, WebSecurityAgent, etc.)  │
                    └────────────────────┬────────────────────┘
                                         │ Untrusted CandidateToolRequest
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │       DETERMINISTIC CONTROL PLANE       │
                    │  ToolRegistry → ScopeGuard → Policy     │
                    └────────────────────┬────────────────────┘
                                         │
                                ┌────────┴────────┐
                                ▼                 ▼
                             [ ALLOW ]      [ APPROVAL_REQ ]
                                │                 │
                                │           Operator Token
                                │       (Arg Hash Bound SEC-01)
                                │                 │
                                └────────┬────────┘
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │            ExecutionManager             │
                    │      (Sandboxed Tool Execution)         │
                    └────────────────────┬────────────────────┘
                                         │
                        ┌────────────────┼────────────────┐
                        ▼                ▼                ▼
                 EvidenceStore    Normalized Graph   AuditLedger
```

---

## 2. Invariable Security Guardrails

The architecture strictly upholds the following non-negotiable security invariants:

1. **INV-1: Zero LLM Authority**
   - The LLM only proposes `CandidateToolRequest`.
   - The UI never directly invokes shell, subprocess, Docker, Nmap, or network executors.
   - All tool dispatches must pass through `ToolRegistry` → `ScopeGuard` → `PolicyEngine` → `ApprovalManager` → `ExecutionManager`.

2. **INV-2: DISCOVERED != AUTHORIZED**
   - Crawled URLs, endpoints, parameters, OpenAPI servers, GraphQL endpoints, and discovered subdomains are strictly classified as `DISCOVERED — NOT AUTHORIZED`.
   - The UI clearly differentiates discovered entities from authorized scope. Expanding scope requires an explicit, audited Scope Delta (PRD-029).

3. **INV-3: Fail-Closed On Unknowns**
   - If an API, scope check, or policy lookup is unreachable or indeterminate, the control plane immediately rejects execution (`DENY`).
   - The UI never assumes API unavailability implies `ALLOW`.

4. **INV-4: Epistemic Ladder Preservation**
   - Findings progress through five strict epistemic stages: `OBSERVED` → `CANDIDATE` → `SUPPORTED` → `VALIDATED` → `HUMAN CONFIRMED`.
   - LLM reasoning can only produce hypotheses (`CANDIDATE`).
   - The LLM is forbidden from promoting findings to `VALIDATED` (which requires deterministic verification) or `HUMAN CONFIRMED` (which requires operator sign-off).

5. **INV-5: Argument-Bound Approvals (SEC-01 Mitigation)**
   - All gated approvals cryptographically bind to the canonical SHA-256 hash of the exact tool request arguments:
     $$\text{arguments\_hash} = \text{SHA256}(\text{canonical\_json}(\text{arguments}))$$
   - Any modification or tampering with arguments invalidates the approval token.

---

## 3. Frontend Architecture

- **Framework**: Next.js 16 (App Router), React 19, TypeScript 5.9.
- **Styling**: Tailwind CSS v4, custom "ARKA Tactical SOC" tokens.
- **State Management**: TanStack Query (server state & caching), Zustand (client UI & alerts store).
- **Topology Graph**: `@xyflow/react` (React Flow) rendering canonical Graphify entities.
- **Data Tables**: TanStack Table for dense, virtualized security logs and asset inventories.
- **Real-Time Streaming**: Server-Sent Events (SSE) via `/api/stream` and `/api/engagements/{id}/stream`.
- **Proxy Rewrites**: Development and runtime proxying maps `/api/*` to FastAPI backend (`http://127.0.0.1:8000`).
