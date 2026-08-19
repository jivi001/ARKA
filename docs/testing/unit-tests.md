# Unit Test Catalog

This document catalogs unit test suites verifying core components in isolation.

---

## 1. ScopeGuard Tests (`tests/unit/test_scopeguard_comprehensive.py`)

- **Domain Suffix Collision Prevention**: Ensures `evil-example.com` or `notexample.com` are blocked when `example.com` is in scope.
- **Cross-Version IP / CIDR Checks**: Verifies that mixed IPv4 and IPv6 network lists do not trigger `TypeError` exceptions.
- **CIDR Overlap Exclusions**: Confirms that included `/16` ranges reject sub-allocated `/24` excluded subnets.
- **URL Host & Port Parsing**: Validates that HTTP/HTTPS URLs with custom ports are properly deconstructed and checked.
- **Port Range Parsing**: Tests parsing and boundary checks for expressions like `8000-9000`.

---

## 2. PolicyEngine Tests (`tests/unit/test_policy_comprehensive.py`)

- **Out-of-Scope Rule**: Verifies that out-of-scope targets produce `DENY` even if risk is `LOW` or approval is claimed.
- **Risk Level Derivation**: Confirms risk levels are derived exclusively from `ToolDefinition.risk_level`.
- **Dynamic Threshold Configuration**: Tests customizing approval requirements via `set_approval_threshold()`.
- **Bypass Resistance**: Confirms forged approval IDs or client-side risk claims are ignored.

---

## 3. ApprovalManager Tests (`tests/unit/test_approval_manager.py`)

- **State Machine Transitions**: Validates allowed transitions (`REQUIRED -> GRANTED`, `REQUIRED -> REJECTED`, `REQUIRED -> EXPIRED`).
- **Terminal State Protection**: Asserts that `GRANTED` or `REJECTED` requests reject subsequent state changes.
- **Operation Binding**: Verifies that changing target, engagement, or tool name causes `validate_approval_for_request()` to fail.

---

## 4. ToolRegistry Tests (`tests/unit/test_tool_registry_comprehensive.py`)

- **Schema Argument Validation**: Tests required argument enforcement, unknown argument rejection, and type verification.
- **Timeout Isolation**: Confirms that long-running tasks are aborted via `asyncio.wait_for()`.
- **Crash Recovery**: Asserts that tools throwing exceptions return structured `ToolResult(success=False)`.
