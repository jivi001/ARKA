# Testing Strategy & Quality Baseline

This document outlines the testing architecture, quality gates, and safety constraints enforced across ARKA.

---

## 1. Testing Philosophy: Zero Real Offense

> [!IMPORTANT]
> Automated tests in ARKA must **NEVER** execute real network scanning, raw packet transmission, subshell execution, or external API exploits.
>
> All testing must execute safely in-memory using deterministic mock tools (`EchoToolExecutor`, `HighRiskMockToolExecutor`) and mocked LLM providers (`unittest.mock`, `respx`).

---

## 2. Quality Gates & Verification Baseline

Every commit must pass four automated quality gates:

1. **Pytest Suite**: 100% test pass rate across all unit, integration, and security suites.
2. **Code Coverage**: Minimum 75% codebase line coverage (Baseline: **78%**).
3. **Ruff Linter & Formatter**: Clean report on `ruff check .` and `ruff format --check .`.
4. **Mypy Static Type Checker**: Clean report on `mypy`.

```bash
# Run all quality checks
uv run pytest --cov=arka --cov-report=term-missing
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

---

## 3. Test Suite Directory Structure

```
tests/
├── unit/                               # Unit test suites
│   ├── test_scopeguard.py              # Baseline ScopeGuard unit tests
│   ├── test_scopeguard_comprehensive.py# Hardened ScopeGuard tests (28 tests)
│   ├── test_policy_engine.py           # Baseline PolicyEngine unit tests
│   ├── test_policy_comprehensive.py    # Hardened PolicyEngine tests (9 tests)
│   ├── test_approval_manager.py        # ApprovalManager state machine tests (10 tests)
│   ├── test_tool_registry.py           # Baseline ToolRegistry unit tests
│   ├── test_tool_registry_comprehensive.py # Schema & timeout validation tests (12 tests)
│   ├── test_audit_service.py           # AuditService unit tests (5 tests)
│   └── test_api.py                     # FastAPI routes unit tests (8 tests)
│
├── integration/                        # End-to-end integration tests
│   ├── test_mock_tool_e2e.py           # Safe mock tool end-to-end execution (3 tests)
│   ├── test_llm_gateway_integration.py # LLMGateway routing & error normalization (8 tests)
│   └── test_phase1_flow.py             # Complete Phase 1 lifecycle & graph flow (3 tests)
│
└── security/                           # Security & immutability tests
    ├── test_security.py                # Scope injection & bypass tests (5 tests)
    └── test_audit_immutability.py      # Immutability, tampering, secret redaction (4 tests)
```
