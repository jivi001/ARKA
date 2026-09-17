# ARKA Web Console — PRD Conformance Matrix

| Requirement ID | PRD Section / Requirement Description | Status | Evidence / Implementation Details |
|---|---|---|---|
| PRD-UI-001 | Visual Security Operations Console | **PASS** | Implemented Next.js 16 Console in `frontend/` with tactical SOC theme and global shell. |
| PRD-UI-002 | Real-Time Dashboard & Telemetry | **PASS** | Dashboard (`/`) provides 7 metric cards, live assessment overview, policy decisions table, and SSE connection. |
| PRD-UI-003 | Multi-Step Assessment Wizard | **PASS** | 9-step wizard (`/assessments/create`) including targets, inclusions, exclusions, profile, auth, budgets, and scope preview. |
| PRD-UI-004 | Effective Scope Preview | **PASS** | Scope preview component clearly renders inclusions and exclusions, enforcing "Exclusions Override Inclusions". |
| PRD-UI-005 | Operator Approval Center | **PASS** | Approvals view (`/approvals`) displays exact arguments, SHA-256 hash, and provides exact request approval/rejection. |
| PRD-UI-006 | Scope Delta Management (PRD-029) | **PASS** | Discovered assets have a "Propose Scope Delta" action creating immutable new scope versions without mutating history. |
| PRD-UI-007 | Normalized Attack Surface | **PASS** | Attack surface page (`/attack-surface`) categorizes assets, endpoints, and services with `DISCOVERED != AUTHORIZED`. |
| PRD-UI-008 | Epistemic Findings Ladder | **PASS** | 5-stage epistemic ladder (`OBSERVED` → `CANDIDATE` → `SUPPORTED` → `VALIDATED` → `HUMAN CONFIRMED`) in `/findings`. |
| PRD-UI-009 | Human Finding Confirmation | **PASS** | Operator confirmation modal with audit notes in `POST /findings/{id}/confirm`. LLM cannot promote findings. |
| PRD-UI-010 | Canonical Graphify Topology | **PASS** | Attack graph (`/graph`) integrates React Flow with Graphify backend API to visualize assets, services, endpoints, and findings. |
| PRD-UI-011 | Centralized Configuration Center | **PASS** | Configuration page (`/configuration`) covers providers, agents, policy matrix, tools, budgets, and invariants. |
| PRD-UI-012 | Autonomous Operations Pipeline | **PASS** | Operations view (`/operations`) displays agent reasoning trajectory and tool proposal decision chain breakdowns. |
| PRD-UI-013 | Executive & Technical Reports | **PASS** | Reports page (`/reports`) compiles markdown technical/executive reports via backend service. |
| PRD-UI-014 | Immutable Audit Trail | **PASS** | Searchable audit ledger in `/audit` displaying cryptographic hashes and decision outcomes. |
| PRD-UI-015 | Deterministic Emergency Killswitch | **PASS** | `HALT AGENTS` button in TopNav triggers instant cancellation of running reasoning loops and tool dispatches. |
