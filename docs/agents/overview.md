# Agents Overview

This document describes the agent architecture, base abstractions, and taxonomy of specialized agents across ARKA's multi-phase roadmap.

---

## 1. Agent Architecture Philosophy

All agents in ARKA inherit from `BaseAgent` (`arka/app/agents/base/agent.py`) and adhere to the following contracts:

1. **State Isolation**: Agent state is immutable within iterations and updated through explicit graph channel reducers.
2. **Deterministic Security Mediation**: Agents interact with the external world exclusively through `ToolRegistry` and `AuditService`.
3. **No Direct Model Vendor Access**: Agents query LLMs solely through the `LLMGateway`.

```python
class BaseAgent(ABC):
    """Base class for all ARKA agents."""

    def __init__(
        self,
        agent_id: str,
        agent_type: str,
        llm_gateway: LLMGateway,
        tool_registry: ToolRegistry,
        audit_service: AuditService,
    ):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.llm = llm_gateway
        self.tools = tool_registry
        self.audit = audit_service
```

---

## 2. Agent Taxonomy & Roadmap

| Agent Type | Phase | Status | Primary Responsibility |
|---|:---:|:---:|---|
| **Orchestrator Agent** | Phase 1 | **`IMPLEMENTED`** | High-level planning, engagement coordination, task sequencing, and human approval flow. |
| **Reconnaissance Agent** | Phase 2 | **`PLANNED`** | Port scanning, service enumeration, subdomain discovery, and asset inventory. |
| **Web/API Security Agent** | Phase 3 | **`PLANNED`** | Endpoint crawling, OpenAPI schema analysis, and web vulnerability analysis. |
| **Exploitation Agent** | Phase 4 | **`PLANNED`** | Controlled vulnerability validation and proof-of-concept generation under strict approval. |
| **Reporting & Synthesis Agent** | Phase 5 | **`PLANNED`** | Vulnerability deduplication, risk scoring, and executive report generation. |
