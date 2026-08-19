# Changelog

All notable changes to the ARKA platform are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.1] - 2026-08-19

### Phase 2.2.1: Nmap Adapter & Parser Foundation (Complete)

### Added
- **Nmap Adapter & Safe Domain Models**: Added `NmapScanConfig` (`arka/app/tools/nmap/schemas.py`) enforcing an explicit argument allowlist (`-sV`, `-sC`, `-p`, `-T{0-4}`, `-oX -`) with strict port regex validation and zero raw flag passthrough.
- **Structured Nmap Output Models**: Added `NmapHost`, `NmapPort`, `NmapService`, `NmapScript`, and `NmapResult` models.
- **Mandatory Defused XML Parser**: Added `parse_nmap_xml` (`arka/app/tools/nmap/parser.py`) using `defusedxml` to parse hosts, ports, service banners, CPE lists, and NSE script output safely from untrusted target responses.
- **Operation-Level Risk Escalation**: Added `NmapToolDefinition` with `determine_risk()` dynamically deriving `RiskLevel.HIGH` when aggressive options (`default_scripts=True` or `timing_template >= 3`) are requested, mandating `ApprovalManager` gate.
- **Extensible Risk Evaluation**: Added `determine_risk()` method on `ToolDefinition` and integrated with `PolicyEngine.evaluate()`.
- **Nmap Tool Executor**: Implemented `NmapToolExecutor` (`arka/app/tools/nmap/executor.py`) bridging the Nmap adapter to `ExecutionManager` and `EvidenceStore`.
- **XML Fixtures & Comprehensive Tests**: Added realistic XML fixtures and 67 automated test cases:
  - `tests/unit/test_nmap_parser.py` (basic scan, multi-host, CPEs, scripts, malformed XML, empty result).
  - `tests/unit/test_nmap_adapter.py` (argument allowlist construction, port validation, timing bounds, tool definition).
  - `tests/security/test_nmap_security.py` (flag injection immunity, shell metacharacters, scope enforcement, escalation enforcement).
  - `tests/integration/test_nmap_adapter.py` (full pipeline: CandidateToolRequest -> ToolRegistry -> PolicyEngine -> ExecutionManager).

### Changed
- **Dependencies**: Added `defusedxml>=0.7.0` to mandatory dependencies in `pyproject.toml`.

---

## [0.2.0] - 2026-08-19

### Phase 2.1: Secure Execution Engine & Sandboxing (Complete)

### Added
- **Execution Domain Models**: Added `ExecutionStatus`, `NetworkProfile`, `ExecutionLimits`, `ExecutionRequest`, `ExecutionResult`, and `EvidenceReference` (`arka/app/execution/schemas.py`).
- **ExecutionManager**: Implemented authoritative execution bridge (`arka/app/execution/manager.py`) enforcing pre-execution authorization checks, sandbox lifecycle, timeout termination, resource cleanup, and cryptographic evidence generation.
- **ExecutionPolicy**: Added deterministic runtime constraints (`arka/app/execution/policy.py`) enforcing argument array format, forbidding shell interpreters (`sh`, `bash`, `cmd.exe`, `powershell.exe`, etc.), sanitizing environment variables, and enforcing `NO_NETWORK` profile.
- **Sandbox Runtime Abstractions**: Added `SandboxRuntime` ABC with `LocalSafeRuntime` (in-memory zero-network mock testing) and `DockerSandboxRuntime` (least-privilege container baseline with non-root user, read-only rootfs, dropped capabilities, no-new-privileges, and no Docker socket exposure).
- **Cryptographic Evidence Store**: Added `EvidenceStore` (`arka/app/execution/evidence.py`) calculating SHA-256 integrity digests over raw tool outputs, structured results, and execution telemetry.
- **ADR-011**: Added Architecture Decision Record for Secure Execution Engine and Sandbox Isolation Architecture (`docs/decisions/ADR-011-secure-execution-engine-and-sandboxing.md`).
- **Phase 2.1 Tests**: Added comprehensive test suites:
  - `tests/unit/test_execution_manager.py` (lifecycle, timeouts, errors, rejections, evidence).
  - `tests/unit/test_execution_policy.py` (forbidden shells, env sanitization, argument validation).
  - `tests/unit/test_sandbox_runtime.py` (LocalSafeRuntime & DockerSandboxRuntime configurations).
  - `tests/security/test_execution_security.py` (injection immunity, untrusted tool output).
  - `tests/integration/test_execution_engine.py` (full pipeline with low/high risk tools and scope denial).

### Changed
- **ToolRegistry Integration**: Integrated `ExecutionManager` into `ToolRegistry.execute()`, routing all tool execution through sandbox isolation and cryptographic evidence recording while maintaining 100% backward compatibility.
- **Audit Event Types**: Extended `AuditEventType` with `EXECUTION_REQUESTED`, `EXECUTION_AUTHORIZED`, `EXECUTION_STARTED`, `EXECUTION_COMPLETED`, `EXECUTION_FAILED`, `EXECUTION_TIMED_OUT`, `EXECUTION_CANCELLED`, and `EXECUTION_REJECTED`.

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
