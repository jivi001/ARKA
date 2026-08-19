# Safe Mock Tools Implementation

ARKA provides built-in mock tool executors (`arka/app/tools/mock/tools.py`) to enable 100% automated test coverage without executing real offensive actions or touching external networks.

---

## 1. Mock Tools Catalog

| Tool Name | Class Name | Risk Level | Purpose |
|---|---|:---:|---|
| `echo_test` | `EchoToolExecutor` | `LOW` | Verifies low-risk automatic execution, argument passing, and response parsing. |
| `high_risk_mock` | `HighRiskMockToolExecutor` | `HIGH` | Verifies human approval requirement, LangGraph interruption, and resumption after approval. |

---

## 2. Implementation & Safety Guarantees

### Zero Real Offense Rule:
- Mock tools execute purely in-memory.
- **Zero subprocess / OS shell execution**: `subprocess`, `os.system`, and `popen` are not invoked.
- **Zero external network sockets**: `socket`, `urllib`, and raw packets are not transmitted.

### `EchoToolExecutor` (Low Risk)
Echoes provided messages and parameters back into the execution result:

```python
class EchoToolExecutor(ToolExecutor):
    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name=request.tool_name,
            success=True,
            output={
                "target": request.target,
                "status": "online",
                "echo": request.arguments,
            },
        )
```

### `HighRiskMockToolExecutor` (High Risk)
Simulates a high-risk penetration testing operation, verifying that an approval was granted:

```python
class HighRiskMockToolExecutor(ToolExecutor):
    async def execute(self, request: ToolRequest, definition: ToolDefinition) -> ToolResult:
        return ToolResult(
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            tool_name=request.tool_name,
            success=True,
            output={
                "target": request.target,
                "action": "simulated_high_risk_operation",
                "approved_by": request.approval_id,
                "findings": ["Simulated vulnerability verification completed."],
            },
        )
```
