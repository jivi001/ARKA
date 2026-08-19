# Changelog

All notable changes to the ARKA platform are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-08-19

### Phase 1: Secure Agent Control Plane (Hardened & Verified)

### Added
- **Untrusted Candidate Proposal Schema**: Added `CandidateToolRequest` to explicitly separate untrusted LLM proposals from authoritative `ToolRequest` objects.
- **Safe Mock Tool Executors**: Added `EchoToolExecutor` (Low Risk) and `HighRiskMockToolExecutor` (High Risk) for in-memory integration testing with zero external network or subprocess execution.
- **Durable PostgreSQL Checkpointing**: Added `AsyncPostgresSaver` support in `OrchestratorGraph` with fallback to `MemorySaver` for unit test environments.
- **Persistent Human Approval Workflow**: Implemented PostgreSQL-backed `ApprovalManager` with strict state machine validation (`REQUIRED -> GRANTED`, `REQUIRED -> REJECTED`, `REQUIRED -> EXPIRED`) and exact operation binding `(engagement_id, task_id, tool_name, target)`.
- **Database Migration 002**: Added Alembic migration `002_approval_fields.py` introducing `details`, `rejection_reason`, and `correlation_id` columns to the `approvals` table.
- **Comprehensive Documentation Suite**: Created full technical documentation hierarchy in `docs/` covering architecture, security, agents, LLM gateway, tools, data, testing, operations, phase roadmaps, and Architecture Decision Records (ADR-001 through ADR-010).

### Changed
- **Orchestrator Trust Boundary**: Refactored `arka/app/agents/orchestrator/graph.py` to remove hardcoded risk evaluations and LLM authorization authority; all candidate actions are now delegated to `PolicyEngine` and `ToolRegistry`.
- **Policy Engine Single Source of Truth**: Hardened `PolicyEngine` to be the sole authority for risk evaluation; out-of-scope targets ALWAYS return `DENY` regardless of risk level or claimed approval.
- **Tool Registry Execution Boundary**: Enhanced `ToolRegistry` with JSON schema parameter validation (required arguments, unknown argument rejection, and primitive type validation) and asynchronous timeout enforcement.
- **LLM Gateway Prefix Routing**: Updated `LLMGateway` to attach explicit LiteLLM provider prefixes (`openai/`, `anthropic/`, `gemini/`, `nvidia_nim/`) to avoid routing exceptions.

### Security
- **ScopeGuard Suffix Collision Defense**: Enforced strict dot-delimited boundaries in domain checks to prevent suffix collision attacks (`evil-example.com` targeting `example.com`).
- **Exclusion Precedence**: Guaranteed that excluded domains, IPs, and CIDR subnets always override matching inclusions in `ScopeGuard`.
- **Cross-Version IP Containment**: Added version guards to prevent `TypeError` exceptions when evaluating mixed IPv4 and IPv6 CIDR subnets.
- **Audit Immutability & Secret Sanitization**: Enforced append-only constraints and defensive deep copying in `AuditService`, with recursive redaction of credentials (`api_key`, `password`, `tokens`, `secrets`).

### Fixed
- Fixed unhandled LiteLLM provider routing errors for non-OpenAI models.
- Fixed type annotations across CLI, database session async generators, and workers for mypy compliance.
- Fixed LangGraph node re-execution on resume by implementing `ApprovalManager.find_matching_request()` to prevent duplicate approval creation.

### Tests
- Added 28 comprehensive unit tests for ScopeGuard (`tests/unit/test_scopeguard_comprehensive.py`).
- Added 9 comprehensive unit tests for PolicyEngine (`tests/unit/test_policy_comprehensive.py`).
- Added 12 comprehensive unit tests for ToolRegistry (`tests/unit/test_tool_registry_comprehensive.py`).
- Added 3 mock tool end-to-end integration tests (`tests/integration/test_mock_tool_e2e.py`).
- Added 8 LLM Gateway integration tests (`tests/integration/test_llm_gateway_integration.py`).
- Added 4 security and audit immutability tests (`tests/security/test_audit_immutability.py`).
- Added 3 master lifecycle and LangGraph interrupt/resume tests (`tests/integration/test_phase1_flow.py`).
- Total test verification: **137 passing tests (100% pass rate, 78% codebase coverage)**.
