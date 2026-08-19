# Integration Test Catalog

This document catalogs the integration and end-to-end test suites.

---

## 1. Mock Tool End-to-End (`tests/integration/test_mock_tool_e2e.py`)

- **Low-Risk Flow**: Tests automatic validation, policy check, in-memory execution, and result capture with `EchoToolExecutor`.
- **High-Risk Approval Flow**: Simulates human-in-the-loop approval granting for `HighRiskMockToolExecutor`.
- **High-Risk Denial Flow**: Simulates operator rejection and asserts tool execution is prevented.

---

## 2. LLM Gateway Integration (`tests/integration/test_llm_gateway_integration.py`)

- **Completion Routing**: Tests message serialization and completion parsing.
- **Provider Fallback**: Verifies that primary provider failure triggers automatic retry to fallback provider.
- **Error Normalization**: Asserts mapping of upstream errors (401, 429, 503, 504) to `LLMGatewayError`.
- **Multimodal Serialization**: Tests text, base64 image, and remote image URL serialization.
- **Secret Masking**: Confirms API keys are never leaked into string representations.

---

## 3. Phase 1 Master Lifecycle Flow (`tests/integration/test_phase1_flow.py`)

- **API & Storage Lifecycle**: Creates engagement, persists state, fetches tasks, checks health.
- **Low-Risk Orchestrator Cycle**: Runs full LangGraph agent loop with `EchoToolExecutor`, verifying state transitions and output parsing.
- **High-Risk Interruption & Resumption**: Executes orchestrator loop with `HighRiskMockToolExecutor`, captures LangGraph `interrupt()`, approves request via `ApprovalManager`, and verifies clean graph resumption via `Command(resume=...)`.
