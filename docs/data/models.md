# Data Models Reference

This document catalogs the SQLAlchemy ORM models (`arka/app/database/models.py`) and Pydantic domain models (`arka/app/core/state/models.py`).

---

## 1. Relational Models (SQLAlchemy)

### `EngagementDB` (`engagements`)
Stores security assessment metadata and scoping configurations:
- `id`: UUID (Primary Key)
- `name`: String (Engagement name)
- `description`: Text
- `objective`: Text
- `status`: String (`created`, `active`, `paused`, `completed`, `stopped`, `failed`)
- `scope`: JSONB (Serialized `ScopeDefinition`)
- `created_at`, `updated_at`, `started_at`, `completed_at`: DateTime (UTC)

### `ApprovalDB` (`approvals`)
Stores persistent human approval gates:
- `id`: UUID (Primary Key)
- `engagement_id`: String (Foreign reference)
- `task_id`: String (Nullable)
- `agent_id`: String
- `action`: String (e.g., `execute_tool:nmap`)
- `target`: String
- `tool_name`: String
- `risk_level`: String (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- `status`: String (`required`, `granted`, `rejected`, `expired`)
- `reason`: Text
- `details`: JSONB (Arguments and parameters)
- `rejection_reason`: Text
- `correlation_id`: String
- `requested_at`, `decided_at`, `expires_at`: DateTime (UTC)
- `decided_by`: String

### `AuditEventDB` (`audit_events`)
Stores append-only security and compliance records:
- `id`: UUID (Primary Key)
- `engagement_id`, `task_id`, `agent_id`: String
- `event_type`: String (`AuditEventType`)
- `actor`: String
- `action`: String
- `target`, `tool_name`, `authorization_decision`: String
- `parameters`, `metadata`: JSONB (Sanitized)
- `result_status`, `error`, `evidence_ref`, `correlation_id`: String
- `timestamp`: DateTime (UTC)

---

## 2. Domain State Models (Pydantic)

- `EngagementState`: In-memory state tracking active engagements.
- `ScopeDefinition`: Structured inclusion/exclusion targets (`ScopeTarget`).
- `PolicyDecision`: Authorization result (`PolicyDecisionType`, `RiskLevel`, `requires_approval`).
- `ApprovalRequest`: Domain representation of human authorization gate.
