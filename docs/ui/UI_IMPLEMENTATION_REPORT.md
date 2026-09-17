# ARKA Web Security Operations Console — Implementation Report

## 1. Executive Summary

The **ARKA Web Security Operations Console** has been designed, implemented, and verified in the ARKA repository. The console establishes a production-grade, tactical visual interface replacing terminal-only operator workflows while strictly preserving ARKA's deterministic security control plane, zero-authority LLM invariant, argument-bound approval model (SEC-01 mitigation), and epistemic finding ladder.

---

## 2. Technical Architecture & Tech Stack

- **Frontend Framework**: Next.js 16.3.5 (App Router), React 19.2.8, TypeScript 5.9.3.
- **Styling**: Tailwind CSS v4.3.3, `@tailwindcss/postcss`, custom tactical SOC theme.
- **Data Fetching & State**: TanStack Query v5, Zustand v5, TanStack Table v9.
- **Topology Graph**: `@xyflow/react` v12 (React Flow) rendering canonical Graphify knowledge graph nodes and edges.
- **Real-Time Streaming**: Server-Sent Events (SSE) backed by an in-memory asyncio pub/sub event bus (`EventBroadcaster`).
- **Backend Architecture**: FastAPI, SQLAlchemy async with PostgreSQL, Pydantic v2, ARQ / Redis worker pools, LiteLLM / OpenRouter with NVIDIA Nemotron-3 Ultra.

---

## 3. Pages & Features Implemented

1. **Global Application Shell (`/`)**
   - Topbar with real-time SSE stream status, active assessment context switcher, live control plane indicators, emergency killswitch (`HALT AGENTS`), and authoritative operator badge.
   - Sidebar navigation with route links, live pending approvals counter badge, and deterministic plane telemetry.

2. **Dashboard (`/`)**
   - 7 tactical metric cards: Active Engagements, Pending Approvals, Authorized Assets, Discovered Assets, Endpoints Mapped, Evidence Records, Validated Findings.
   - Active Assessment Overview card with phase telemetry, active agent indicator, target URL, and trajectory progress bar.
   - Recent Policy Decisions & Candidate Tool Requests table.
   - Pending Approvals quick-action box with argument hash verification.
   - Autonomous Architecture Invariant summary.

3. **Create Assessment Wizard (`/assessments/create`)**
   - 9-step guided wizard: Basic Info & Affirmation → Inclusions → Exclusions (override rule) → Assessment Profile → Authentication Reference → Resource Budgets → Effective Scope Preview → Final Invariant Validation → Creation.

4. **Assessments Directory (`/assessments`)**
   - Comprehensive grid of active and historical security assessments.

5. **Operator Approval Center (`/approvals`)**
   - Pending, Approved, and Rejected tabs.
   - Detailed table displaying ID, agent, tool, exact target, risk level, arguments SHA-256 hash, and scope version.
   - Exact Argument Binding Inspection Modal (SEC-01 mitigation).
   - Exact request approval and rejection actions.

6. **Normalized Attack Surface (`/attack-surface`)**
   - Assets, Endpoints, and Services tabs.
   - Clear visual distinction between `AUTHORIZED` and `DISCOVERED — NOT AUTHORIZED`.
   - PRD-029 Scope Delta Modal allowing explicit proposal of immutable new scope versions for discovered assets.

7. **Findings & Epistemic Verification (`/findings`)**
   - Five-stage epistemic lifecycle: `OBSERVED` → `CANDIDATE` → `SUPPORTED` → `VALIDATED` → `HUMAN CONFIRMED`.
   - Visual Epistemic Ladder widget.
   - Distinct separation of LLM confidence from deterministic validation.
   - Authoritative human operator confirmation modal with audit notes.

8. **Graphify / Attack Graph (`/graph`)**
   - Interactive React Flow canvas rendering assets, services, endpoints, findings, and relationships (`runs_on`, `exposes`, `affects`).
   - Node and edge filtering by entity type.
   - Integrated Node Inspector Drawer.

9. **Autonomous Operations Pipeline (`/operations`)**
   - Multi-agent reasoning and dispatch trajectory visualization.
   - Detailed tool request explorer with status filters and decision breakdown modals.

10. **Configuration Center (`/configuration`)**
    - LLM Providers (OpenRouter, NVIDIA Nemotron 3 Ultra, status, capabilities, isolated secrets).
    - Multi-agent configuration and concurrency limits.
    - Deterministic Security Policy Matrix.
    - Tool Registry (HTTP, Crawler, OpenAPI, GraphQL, Nmap, Nuclei).
    - Resource Budget Envelopes.
    - Platform Invariants Display.

11. **Executive & Technical Reporting (`/reports`)**
    - Report generator configuring archetypes and artifact sections.
    - Markdown preview and download functionality.

12. **Immutable Audit Trail (`/audit`)**
    - Searchable table of cryptographically hashed audit events with detail inspector.

13. **Infrastructure Health (`/health`)**
    - Real-time status cards for API Gateway, PostgreSQL, Redis, Workers, LLM Gateway, and Sandboxes.

---

## 4. Security Hardening & Vulnerability Remediation

1. **SEC-01: Approval Argument Tampering Mitigation**
   - Implemented cryptographic argument hash binding in `ApprovalManager` (`compute_arguments_hash()`).
   - Validated that tampered arguments are immediately rejected with `403 Forbidden`.
   - Added unit test `tests/security/test_approval_arg_binding.py` with 100% pass rate.

2. **Epistemic Integrity**
   - Guarded finding promotion in `POST /engagements/{id}/findings` to prevent untrusted calls from claiming `VALIDATED` or `HUMAN_CONFIRMED`.
   - Provided dedicated endpoint `POST /findings/{id}/confirm` exclusively for authenticated operators.

3. **Zero Execution Authority in Browser**
   - Guaranteed all tool execution requests flow through authoritative backend filters: `ToolRegistry` → `ScopeGuard` → `PolicyEngine` → `ApprovalManager` → `ExecutionManager`.

---

## 5. Verification & Test Results

- **TypeScript Compilation (`tsc --noEmit`)**: PASSED (0 errors).
- **Next.js Production Build (`pnpm build`)**: PASSED (15 static routes pre-rendered).
- **Security Tests (`test_approval_arg_binding.py`)**: 3/3 PASSED.
- **Console API Tests (`test_console_endpoints.py`)**: 5/5 PASSED.
- **Python Lint (`ruff check`)**: PASSED (0 warnings/errors).
