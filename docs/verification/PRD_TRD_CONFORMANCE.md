# ARKA — PRD / TRD Conformance Matrix

**Date:** 2026-09-17  
**Auditor:** Antigravity IDE Autonomous Verification Engine  
**Repository:** `jivi001/ARKA`  
**Git Baseline:** Commit `8aabb7b`  
**Scope:** Full-System Verification against `docs/PRD.md` and `docs/TRD.md`  

---

## 1. Conformance Methodology & Classification

Every P0 system requirement has been evaluated against the authoritative hierarchy:
1. Actual source code implementation
2. Actual automated unit/integration test results
3. Actual runtime execution behavior
4. Database & persistence schema
5. PRD & TRD documentation

### Classification Categories:
- **`IMPLEMENTED + VERIFIED`**: Code exists, automated tests pass, and empirical runtime behavior is verified.
- **`IMPLEMENTED + NOT VERIFIED`**: Code exists and passes unit tests, but runtime deployment/integration lacks empirical verification.
- **`PARTIALLY IMPLEMENTED`**: Core logic exists, but critical edge cases, sub-features, or security guarantees are missing or incomplete.
- **`DOCUMENTED ONLY`**: Feature is specified in PRD/TRD/ADR/README, but zero corresponding code exists in the repository.
- **`BROKEN`**: Code exists but fails tests or causes runtime crashes / errors under normal operation.
- **`MISSING`**: Functional requirement completely omitted from the codebase.
- **`CONFLICTING`**: Source implementation directly violates or contradicts the documented security specification.

---

## 2. P0 Requirements Conformance Matrix

| Req ID | Requirement Description | Source Location | Test Location | Runtime Verification | Status | Evidence / Verification Notes | Residual Gap |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **P0-01** | **Deterministic Scope Enforcement**<br>ScopeGuard validates IP, CIDR, domain, URL, ports. Exclusions strictly override inclusions. | [`arka/app/core/scope/scopeguard.py`](file:///d:/Programs/Security/ARKA/arka/app/core/scope/scopeguard.py) | `tests/unit/test_scope_security.py`, `tests/redteam/test_attacks_1_10.py` | `verification/tests/run_security_harness.py` (Tests 04, 05) | **IMPLEMENTED + VERIFIED** | Runtime blocked out-of-scope (`evil.com`) and excluded (`excluded.authorized.local`). CIDRs and port ranges verified. | Direct empty target `target=""` string bypassed earlier regex; fixed in Phase 1 regression test. |
| **P0-02** | **Deterministic Policy Engine**<br>Evaluates CandidateToolRequest against ScopeGuard, tool permissions, and risk level. | [`arka/app/core/policies/engine.py`](file:///d:/Programs/Security/ARKA/arka/app/core/policies/engine.py) | `tests/unit/test_policy_engine.py`, `tests/unit/test_policy_comprehensive.py` | `verification/tests/run_security_harness.py` (Tests 01, 06) | **IMPLEMENTED + VERIFIED** | Correctly maps risk levels (LOW/MEDIUM/HIGH/CRITICAL). Emits `REQUIRE_APPROVAL` for HIGH-risk actions. | None. |
| **P0-03** | **Human Approval Workflow**<br>ApprovalManager state machine: REQUIRED -> GRANTED / REJECTED / EXPIRED. Scope-version binding. | [`arka/app/core/approvals/manager.py`](file:///d:/Programs/Security/ARKA/arka/app/core/approvals/manager.py) | `tests/unit/test_approval_manager.py`, `tests/redteam/test_attacks_1_10.py` | `verification/tests/run_security_harness.py` (Tests 08-10, Section 9) | **PARTIALLY IMPLEMENTED** | Validates `(engagement, task, tool, target, scope_version)`. Enforces valid state transitions and expiry. | **VULNERABILITY:** Arguments are NOT bound to approval in `validate_candidate_request`. Allows argument manipulation. Merkle batching not implemented. |
| **P0-04** | **Untrusted LLM Boundary**<br>`CandidateToolRequest` vs `ToolRequest`. LLM has ZERO execution authority. | [`arka/app/tools/registry/registry.py`](file:///d:/Programs/Security/ARKA/arka/app/tools/registry/registry.py), [`arka/app/tools/schemas/tool_schemas.py`](file:///d:/Programs/Security/ARKA/arka/app/tools/schemas/tool_schemas.py) | `tests/unit/test_execution_policy.py`, `tests/security/test_llm_security.py` | `verification/tests/run_security_harness.py` (Section 5) | **IMPLEMENTED + VERIFIED** | Candidate requests cannot execute directly. Stamped booleans required before dispatch. | `ExecutionManager` trusts `scope_validated=True` stamp without re-evaluating ScopeGuard directly. |
| **P0-05** | **Exclusive Tool Registry Boundary**<br>Deterministic tool registration. Schema validation for arguments. No shell access. | [`arka/app/tools/registry/registry.py`](file:///d:/Programs/Security/ARKA/arka/app/tools/registry/registry.py), [`arka/app/tools/registration.py`](file:///d:/Programs/Security/ARKA/arka/app/tools/registration.py) | `tests/unit/test_nmap_adapter.py`, `tests/security/test_tool_adapters_security.py` | `verification/tests/run_security_harness.py` (Tests 02, 03, 16) | **IMPLEMENTED + VERIFIED** | Unknown tools and invalid schemas rejected before policy checks. Shell metacharacters treated as literals. | `register_all_tools()` only registers `nmap`; `nuclei`, `whatweb`, `ffuf`, `amass` must be registered manually. |
| **P0-06** | **Execution Engine & Sandboxing**<br>Isolated runtime execution (`LocalSafeRuntime`, `DockerSandboxRuntime`). Timeout enforcement. | [`arka/app/execution/manager.py`](file:///d:/Programs/Security/ARKA/arka/app/execution/manager.py), [`arka/app/execution/sandbox/`](file:///d:/Programs/Security/ARKA/arka/app/execution/sandbox/) | `tests/integration/test_execution_engine.py`, `tests/security/test_execution_security.py` | `verification/tests/run_security_harness.py` (Section 10) | **IMPLEMENTED + VERIFIED** | Local safe runtime captures execution time, stdout, stderr, and enforces timeout cancellation. | Docker sandbox requires running daemon (`npipe` Windows pipe failed during live local test). |
| **P0-07** | **Append-Only Cryptographic Audit**<br>SHA-256 event chaining, actor, action, parameters, result status. Tamper evidence. | [`arka/app/audit/service.py`](file:///d:/Programs/Security/ARKA/arka/app/audit/service.py), [`arka/app/audit/schemas.py`](file:///d:/Programs/Security/ARKA/arka/app/audit/schemas.py) | `tests/unit/test_audit_service.py`, `tests/security/test_audit_immutability.py` | `verification/tests/run_security_harness.py` | **IMPLEMENTED + VERIFIED** | In-memory and PostgreSQL append-only audit events. Sequence and hash verification passed. | Memory audit events lost across new instances unless PostgreSQL factory injected. |
| **P0-08** | **Cryptographic Evidence Pipeline**<br>Content-addressed SHA-256 storage, metadata hashing, immutable references. | [`arka/app/execution/evidence.py`](file:///d:/Programs/Security/ARKA/arka/app/execution/evidence.py) | `tests/unit/test_evidence_pipeline.py`, `tests/security/test_evidence_security.py` | `tests/integration/test_evidence_integration.py` | **IMPLEMENTED + VERIFIED** | Raw bytes content-hashed to SHA-256. Validated in tests. | Metadata mutation post-creation permitted in domain model (flagged in Attack 13). |
| **P0-09** | **Hardened HTTP Client & SSRF**<br>Pre-request SSRF check, redirect hop re-validation, restricted IP subnet blocking. | [`arka/app/web/client/client.py`](file:///d:/Programs/Security/ARKA/arka/app/web/client/client.py), [`arka/app/web/client/ssrf.py`](file:///d:/Programs/Security/ARKA/arka/app/web/client/ssrf.py) | `tests/security/test_llm_ssrf.py`, `tests/security/web/test_web_security_hardening.py` | `verification/tests/run_security_harness.py` (Section 6, 14 vectors) | **IMPLEMENTED + VERIFIED** | All 14 SSRF vectors blocked (loopback, 0.0.0.0, RFC1918, metadata IPs, IPv6). Redirect to 127.0.0.1 blocked on hop. | DNS rebinding during connection window mitigated via socket IP inspection. |
| **P0-10** | **Persistent Relational State**<br>PostgreSQL models and migrations for engagements, tasks, approvals, audit, evidence. | [`arka/app/database/models.py`](file:///d:/Programs/Security/ARKA/arka/app/database/models.py), [`migrations/`](file:///d:/Programs/Security/ARKA/migrations/) | `tests/integration/test_process_persistence.py` | Live API verification (`GET /health`, `/ready`) | **PARTIALLY IMPLEMENTED** | Relational tables exist for Engagements, Tasks, Scopes, Approvals, Evidence, Audit, Assets. | **CRITICAL DEFECT:** No `FindingDB` table exists in SQLAlchemy models or Alembic migrations! |
| **P0-11** | **Finding Epistemic Ladder**<br>`OBSERVED -> CANDIDATE -> SUPPORTED -> VALIDATED -> HUMAN_CONFIRMED`. No LLM self-promotion. | [`arka/app/agents/validation/agent.py`](file:///d:/Programs/Security/ARKA/arka/app/agents/validation/agent.py), [`arka/app/core/assets/models.py`](file:///d:/Programs/Security/ARKA/arka/app/core/assets/models.py) | `tests/unit/test_asset_models.py`, `tests/redteam/test_attacks_1_10.py` | `verification/tests/run_security_harness.py` (Section 8) | **CONFLICTING / BROKEN** | `FindingStatus` enum only implements `[observed, suspected, validating, validated, false_positive]`. | **CRITICAL VULNERABILITY:** `ValidationAgent._assess_results` directly adopts raw LLM response `data.get("status")` as `VALIDATED`. |
| **P0-12** | **Multi-Agent Orchestrator**<br>LangGraph state machine dynamically coordinating Recon, Web, and Validation agents. | [`arka/app/agents/orchestrator/graph.py`](file:///d:/Programs/Security/ARKA/arka/app/agents/orchestrator/graph.py) | `tests/acceptance/test_full_acceptance_oat.py` | LangGraph compilation inspection | **PARTIALLY IMPLEMENTED** | Single-agent tool loop compiles with 9 nodes and MemorySaver checkpointing. | Does NOT coordinate child agents. `ReconAgent`, `WebAgent`, and `ValidationAgent` are decoupled and absent from graph. |
| **P0-13** | **Asynchronous Job Workers**<br>Arq worker backend for queueing background scans and recon tasks via Redis. | [`arka/app/workers/arq_worker.py`](file:///d:/Programs/Security/ARKA/arka/app/workers/arq_worker.py), [`arka/app/workers/backend.py`](file:///d:/Programs/Security/ARKA/arka/app/workers/backend.py) | `tests/unit/test_api.py` | `verification/terminal/cli_tests.txt` | **IMPLEMENTED + NOT VERIFIED** | Worker functions implemented for recon, nuclei, nmap. Enforces scope re-check in worker before dispatch. | Redis server was not running during local audit; worker jobs queued in-memory fallback. |
| **P0-14** | **Hardened Web Crawling & Discovery**<br>Bounded HTML crawler, safe OpenAPI parser (5MB, depth 20), GraphQL introspection analyzer. | [`arka/app/web/crawler/`](file:///d:/Programs/Security/ARKA/arka/app/web/crawler/), [`arka/app/web/openapi/`](file:///d:/Programs/Security/ARKA/arka/app/web/openapi/), [`arka/app/web/graphql/`](file:///d:/Programs/Security/ARKA/arka/app/web/graphql/) | `tests/security/web/` | `verification/tests/run_security_harness.py` (Section 7) | **IMPLEMENTED + VERIFIED** | Crawler limits frozen (max 200 pages, 10 depth). OpenAPI rejects documents >5MB and external refs. GraphQL bounded. | Fastify / WebSocket discovery not implemented. |
| **P0-15** | **Operator Interface & UI**<br>FastAPI REST endpoints, CLI commands, Real-Time Dashboard, Approval Panel. | [`arka/app/api/`](file:///d:/Programs/Security/ARKA/arka/app/api/), [`arka/app/cli/`](file:///d:/Programs/Security/ARKA/arka/app/cli/) | `tests/unit/test_api.py` | `verification/api/verify_live_api.py`, CLI tests | **PARTIALLY IMPLEMENTED** | CLI operational (`arka health`, `arka llm`, `arka recon`). 19 FastAPI endpoints operational. | **MISSING:** Zero dashboard/UI code. `GET /approvals`, `POST /approvals/{id}/decide`, and `/web/*` return 404. |

---

## 3. High-Priority Functional Gaps

### 3.1 Critical (P0) Gaps
1. **Missing `FindingDB` Database Table:**
   - Findings cannot be persisted to PostgreSQL. They are stored only in memory (`InMemoryAssetRepository`). Any API restart destroys all discovered vulnerabilities.
2. **LLM Finding Promotion Vulnerability:**
   - `ValidationAgent._assess_results` promotes candidate findings to `VALIDATED` based on raw LLM JSON response rather than deterministic execution evidence.
3. **Approval Request-Hash Binding Gap:**
   - Approvals do not bind request arguments. A human approving a safe read command can have that approval token reused for an exploit against the same target.
4. **Missing Approval REST Endpoints:**
   - Documented `GET /approvals` and `POST /approvals/{id}/decide` do not exist in FastAPI routes. Human operators cannot decide approvals via the REST API.
5. **Disconnected Multi-Agent Graph:**
   - `OrchestratorAgent` cannot delegate tasks to `ReconAgent`, `WebAgent`, or `ValidationAgent` in LangGraph.

### 3.2 Medium (P1) Gaps
1. **Missing Web Assessment Dashboard:** No web interface exists (FastAPI Swagger UI `/docs` is the only UI).
2. **Missing CLI Web Routes:** CLI commands `arka web crawl`, `arka web openapi`, `arka web graphql` fail because FastAPI has no `/web` router mounted.
3. **Unresolved Merge Conflict Markers:** Git conflict markers exist in `docs/PRD.md` (lines 3, 703) and `docs/TRD.md` (24 locations).
