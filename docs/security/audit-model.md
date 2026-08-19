# Audit Model & Immutability Architecture

The **AuditService** (`arka/app/audit/service.py`) provides an authoritative, append-only compliance log for all actions within ARKA.

---

## 1. Compliance Immutability Guarantees

1. **Strict Append-Only**: The `AuditService` exposes only `record()` and `record_action()` write methods. It contains **no update, modify, delete, clear, or remove APIs**.
2. **Defensive Copying**: When callers query `get_events()`, the service returns deep copies (`deepcopy`) of internal `AuditEvent` records. Modifying or mutating returned lists or objects has zero effect on the internal audit log.
3. **Correlation Tracking**: Every event records `correlation_id`, `engagement_id`, `task_id`, `agent_id`, `actor`, `event_type`, `action`, `result_status`, and high-precision UTC timestamp.

---

## 2. Automated Credential Sanitization

To prevent API keys, database credentials, or tokens from leaking into logs or SIEM forwarders, `AuditService._redact_dict` recursively sanitizes sensitive keys before recording:

```python
SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "auth_token",
    "token",
    "secret",
    "password",
    "vault_token",
    "private_key",
}
```

Any dictionary key matching these case-insensitively has its value replaced with `"[REDACTED]"`.

---

## 3. Audit Event Types (`AuditEventType`)

| Event Type | Trigger | Key Captured Parameters |
|---|---|---|
| `ENGAGEMENT_CREATED` | Creation of a new assessment | `engagement_id`, `name`, `scope` |
| `ENGAGEMENT_STARTED` | Assessment transitioned to active | `engagement_id`, `started_at` |
| `ENGAGEMENT_PAUSED` | Assessment execution paused | `engagement_id` |
| `ENGAGEMENT_STOPPED` | Assessment terminated | `engagement_id`, `completed_at` |
| `SCOPE_VALIDATED` | Target evaluated against ScopeGuard | `target`, `in_scope`, `reason` |
| `POLICY_DECISION` | Action evaluated by PolicyEngine | `decision`, `risk_level`, `requires_approval` |
| `APPROVAL_REQUESTED` | Elevated action submitted for human review | `approval_id`, `risk_level`, `tool_name`, `target` |
| `APPROVAL_GRANTED` | Operator approved action | `approval_id`, `decided_by` |
| `APPROVAL_REJECTED` | Operator rejected action | `approval_id`, `decided_by`, `rejection_reason` |
| `APPROVAL_EXPIRED` | Approval request timed out | `approval_id`, `expired_at` |
| `TOOL_REQUESTED` | Authoritative tool execution initiated | `tool_name`, `target`, `parameters` (redacted) |
| `TOOL_EXECUTED` | Tool execution completed successfully | `tool_name`, `target`, `execution_time_ms` |
| `TOOL_FAILED` | Tool execution failed or timed out | `tool_name`, `target`, `error` |
| `LLM_REQUEST` / `LLM_RESPONSE` | LLM Gateway completion cycle | `provider`, `model`, `tokens`, `latency_ms` |
