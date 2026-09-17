# ARKA — Technical Requirements Document (TRD)

<<<<<<< HEAD
**Product:** ARKA — Autonomous Risk Knowledge & Assessment
**Repository:** `jivi001/ARKA`
**Document status:** Production Engineering Baseline
**Version:** 2.0
**Date:** 2026-09-16
**Audience:** Security engineering, backend engineering, platform engineering, DevSecOps, SRE and application security
**Primary constraint:** Authorized security assessment only

=======
**Document status:** Proposed engineering baseline  
**Product:** ARKA — Autonomous Risk Knowledge & Assessment  
**Repository:** `jivi001/ARKA`  
**Date:** 2026-09-16  
**Audience:** Security engineering, backend/platform engineering, DevSecOps, application security, SRE  
**Primary constraint:** Authorized security assessment only

> **Repository grounding:** The current repository contains the documented four-tier architecture, deterministic ScopeGuard/PolicyEngine/ApprovalManager/ToolRegistry control plane, LangGraph orchestration, PostgreSQL persistence/checkpointing, Redis/Arq execution infrastructure and canonical security data models. fileciteturn6file0L2-L2 Phase 2 documentation records secure execution, reconnaissance, evidence, canonical models, correlation and validation capabilities. fileciteturn7file0L2-L2 The repository README/roadmap still contains stale `PLANNED` labels for some completed phases; implementation work must treat the actual source tree and verified OAT as authoritative and synchronize documentation as part of this TRD.

>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
---

# 1. ARCHITECTURAL OVERVIEW

<<<<<<< HEAD
## 1.1 Architectural objective

ARKA implements **Bounded Autonomy**.

The architecture deliberately separates:

```text
Reasoning
```

from:

```text
Authority
```

The LLM reasons.

Deterministic components authorize.

The execution runtime executes only authoritative requests.

---

# 1.2 Target architecture

```mermaid
flowchart TB

    Operator[Security Operator]

    subgraph Interface["Interface"]
        CLI[Typer CLI]
        API[FastAPI]
        UI[Future Operator UI]
    end

    subgraph Reasoning["Reasoning Layer"]
        Graph[LangGraph Orchestrator]
        Agents[Recon / Web / Validation Agents]
        LLM[LLM Gateway]
        Provider[OpenRouter Reference Adapter]
    end

    subgraph Planning["Deterministic Investigation Layer"]
        Intent[High-Level Investigation Intent]
        Planner[Deterministic Investigation Planner]
        Tasks[Investigation Task Expansion]
    end

    subgraph Security["Deterministic Security Control Plane"]
=======
## 1.1 System objectives

The technical architecture must provide:

- deterministic authorization;
- strict target scoping;
- isolated tool execution;
- durable workflow state;
- evidence provenance;
- immutable auditability;
- bounded autonomous reasoning;
- controlled authentication/session handling;
- safe web/API analysis;
- reliable worker execution;
- provider-independent LLM integration;
- observable and recoverable operations.

The existing architecture explicitly separates interface, orchestration/intelligence, security/policy, and execution/persistence tiers. fileciteturn6file0L2-L2

## 1.2 Proposed target architecture

```mermaid
flowchart TB
    Operator[Security Operator]

    subgraph Interface[Interface Tier]
        CLI[Typer CLI]
        API[FastAPI REST API]
        FutureUI[Web Console]
    end

    subgraph Control[Agent / Control Tier]
        Graph[LangGraph Orchestrator]
        Agents[Recon / Web / Validation Agents]
        LLM[LLMGateway]
        Provider[Provider Registry]
    end

    subgraph Security[Deterministic Security Boundary]
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
        Candidate[CandidateToolRequest]
        Registry[ToolRegistry]
        Scope[ScopeGuard]
        Policy[PolicyEngine]
        Approval[ApprovalManager]
<<<<<<< HEAD
        AuthRequest[Authoritative ToolRequest]
        Lease[Execution Lease / Idempotency]
    end

    subgraph Execution["Execution"]
        Exec[ExecutionManager]
        Sandbox[Sandbox Runtime]
        HTTP[Controlled HTTP Client]
        Crawl[Bounded Crawler]
        OpenAPI[OpenAPI Analyzer]
        GraphQL[GraphQL Analyzer]
        SecurityTools[Nmap / Nuclei / ffuf / WhatWeb / Amass]
    end

    subgraph Persistence["Persistence"]
        PG[(PostgreSQL)]
        Redis[(Redis / Arq)]
        Blob[(Object Storage)]
        Audit[Audit Sequencer]
        Evidence[Evidence Metadata]
        Secrets[Secret Reference Store]
=======
        AuthZ[Authoritative ToolRequest]
        Idempotency[Execution Idempotency / Lease]
    end

    subgraph Execution[Execution Tier]
        Exec[ExecutionManager]
        Runtime[Sandbox Runtime]
        HTTP[Controlled HTTP Client]
        Crawler[Web Crawler]
        APIAnalyzers[OpenAPI / GraphQL / Web Analysis]
        NetworkTools[Nmap / Nuclei / ffuf / WhatWeb / Amass]
    end

    subgraph Data[Data & Evidence Tier]
        PG[(PostgreSQL)]
        Redis[(Redis / Arq)]
        Evidence[EvidenceStore]
        Audit[AuditService]
        Secrets[Credential / Secret References]
        GraphStore[Canonical Knowledge Graph]
    end

    subgraph Observability[Observability]
        Metrics[Metrics]
        Logs[Structured Logs]
        Traces[Tracing / LLM Observability]
        Alerts[Alerts]
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
    end

    Operator --> CLI
    Operator --> API
<<<<<<< HEAD
    Operator --> UI

    CLI --> API
    API --> Graph

    Graph --> Agents
    Agents --> LLM
    LLM --> Provider

    LLM --> Intent
    Intent --> Planner
    Planner --> Tasks
    Tasks --> Candidate

    Agents --> Candidate

    Candidate --> Registry
    Registry --> Scope
    Scope --> Policy

    Policy --> Approval
    Approval --> AuthRequest
    Policy --> AuthRequest

    AuthRequest --> Lease
    Lease --> Exec

    Exec --> Sandbox
    Sandbox --> HTTP
    Sandbox --> Crawl
    Sandbox --> OpenAPI
    Sandbox --> GraphQL
    Sandbox --> SecurityTools

    Exec --> Evidence
    Evidence --> Blob
    Evidence --> PG

    Exec --> Audit
    Audit --> PG

    Graph --> PG
    Graph --> Redis
    Secrets --> Exec
```

---

# 1.3 Deterministic Investigation Planner

This is a core architectural component.

It sits between:

```text
LLM reasoning
```

and:

```text
CandidateToolRequest
```

The LLM should not individually generate every mechanical security operation.

Instead it may emit a high-level intent:

```json
{
  "intent": "MAP_API_ATTACK_SURFACE",
  "target_endpoint": "https://app.example.test",
  "reason": "Application exposes API references"
}
```

The deterministic planner expands this into controlled tasks:

```text
MAP_API_ATTACK_SURFACE
        |
        +--> locate OpenAPI documents
        |
        +--> inspect known API paths
        |
        +--> normalize endpoints
        |
        +--> normalize parameters
        |
        +--> identify authentication schemes
        |
        +--> build API inventory
        |
        +--> store observations
```

The planner determines:

* which deterministic workflows are applicable;
* required tool calls;
* budgets;
* task dependencies;
* allowed task classes;
* evidence requirements.

The LLM cannot modify planner safety constraints.

---

# 1.4 Why the planner exists

Without the planner:

```text
observation
   ↓
LLM
   ↓
tool
   ↓
observation
   ↓
LLM
   ↓
tool
```

creates unnecessary:

* latency;
* token usage;
* provider dependency;
* reasoning variance;
* failure modes.

With the planner:

```text
LLM
 ↓
high-level intent
 ↓
deterministic investigation planner
 ↓
standard task graph
 ↓
security control plane
```

The LLM is reserved for decisions requiring interpretation, prioritization or hypothesis generation.

---

# 1.5 Trust boundaries

## TB-1 — Target to ARKA

Target content is hostile data.

It must never be interpreted as trusted instructions.

---

## TB-2 — LLM to ARKA

LLM output is untrusted.

The model cannot create an authoritative execution request.

---

## TB-3 — Planner to security boundary

Planner-generated tasks remain subject to the same ScopeGuard and PolicyEngine checks.

Planner logic is not an authorization bypass.

---

## TB-4 — Security plane to execution

Only an authoritative request can enter ExecutionManager.

---

## TB-5 — Credential boundary

Credentials exist only as references outside the execution context.

Secrets are injected only after authorization.

---

## TB-6 — Execution to evidence

Execution results are sanitized, hashed and persisted as evidence metadata plus object storage payload.

---

# 1.6 Security invariants

```text
LLM != Authority

DISCOVERED != AUTHORIZED

CandidateToolRequest != ToolRequest

Approval != Permission

Approval != Wildcard

Credential Reference != Credential

Evidence != Execution Capability

Observation != Finding

Finding != Validation

LLM Confidence != Validation
```

---

# 1.7 Technology stack

| Layer               | Technology                              |
| ------------------- | --------------------------------------- |
| Language            | Python 3.13+                            |
| API                 | FastAPI                                 |
| Schemas             | Pydantic v2                             |
| Agent orchestration | LangGraph                               |
| LLM abstraction     | LiteLLM + LLMGateway                    |
| Primary LLM routing | OpenRouter                              |
| Database            | PostgreSQL 16+                          |
| ORM                 | SQLAlchemy 2.0                          |
| DB driver           | asyncpg                                 |
| Migrations          | Alembic                                 |
| Queue/cache         | Redis 7+                                |
| Workers             | Arq                                     |
| CLI                 | Typer + Rich                            |
| HTTP                | httpx                                   |
| XML parser          | defusedxml                              |
| YAML parser         | safe PyYAML loader                      |
| Runtime             | DockerSandboxRuntime / LocalSafeRuntime |
| Logging             | Structlog                               |
| LLM observability   | Langfuse                                |
| Testing             | Pytest                                  |
| Linting             | Ruff                                    |
| Typing              | Mypy                                    |

OpenRouter is the **primary reference adapter**.

Additional provider adapters may exist behind the same interface, but production optimization and regression testing should initially center on the OpenRouter reference path.
=======
    Operator --> FutureUI
    CLI --> API
    API --> Graph
    Graph --> Agents
    Agents --> LLM
    LLM --> Provider
    Agents --> Candidate
    Candidate --> Registry
    Registry --> Scope
    Scope --> Policy
    Policy --> Approval
    Approval --> AuthZ
    Policy --> AuthZ
    AuthZ --> Idempotency
    Idempotency --> Exec
    Exec --> Runtime
    Runtime --> HTTP
    Runtime --> Crawler
    Runtime --> APIAnalyzers
    Runtime --> NetworkTools
    HTTP --> Evidence
    Crawler --> Evidence
    APIAnalyzers --> Evidence
    NetworkTools --> Evidence
    Exec --> Audit
    Evidence --> PG
    Audit --> PG
    Graph --> PG
    Graph --> Redis
    Secrets --> Exec
    Graph --> GraphStore
    API --> Metrics
    Exec --> Metrics
    API --> Logs
    Exec --> Logs
    Graph --> Traces
    Metrics --> Alerts
```

## 1.3 Trust boundaries

### TB-1: External target → ARKA

All target content is hostile/untrusted data.

### TB-2: LLM → ARKA

All model output is untrusted structured data.

### TB-3: Candidate → authoritative request

This is the primary authorization boundary. Only deterministic code can create an authoritative `ToolRequest`.

### TB-4: Control plane → execution plane

Execution is possible only after scope, policy, approval and runtime checks succeed.

### TB-5: Credential store → execution

Credentials are referenced through opaque handles and injected only into the authorized execution context.

### TB-6: Execution → persistence

Execution results are normalized, sanitized and content-addressed before becoming durable evidence.

## 1.4 Technology stack

| Layer | Technology | Requirement |
|---|---|---|
| Language | Python 3.13+ | Strong typing and modern async runtime |
| API | FastAPI | REST API with Pydantic contracts |
| Validation | Pydantic v2 | Strict request/response schemas |
| Agent orchestration | LangGraph | Durable, interruptible workflows |
| LLM abstraction | LiteLLM + LLMGateway | Provider abstraction, retries, fallback and normalized responses |
| Database | PostgreSQL 16+ | Durable application/security state |
| ORM | SQLAlchemy 2.0 + asyncpg | Async database access |
| Migrations | Alembic | Versioned schema changes |
| Queue/cache | Redis 7+ | Task queue/broker and bounded caching |
| Workers | Arq | Async background execution |
| CLI | Typer + Rich | Operator workflow |
| Runtime isolation | DockerSandboxRuntime + LocalSafeRuntime | Least-privilege execution |
| HTTP | httpx.AsyncClient | Controlled HTTP access |
| XML | defusedxml | Safe XML parsing |
| YAML | PyYAML safe loader | No unsafe object construction |
| Observability | Structlog + Langfuse | Structured logs and LLM traces |
| Testing | Pytest | Unit, security, integration and acceptance tests |
| Static quality | Ruff + Mypy | Formatting/lint/type gates |

The repository README documents this core stack. fileciteturn4file0L2-L2

## 1.5 Architectural invariants

### Security invariants

```text
LLM != Authority
DISCOVERED != AUTHORIZED
DENY != ERROR TO IGNORE
Approval != Global Permission
Credential Reference != Credential Value
Evidence != Execution Capability
```

### Execution rule

```text
No authoritative ToolRequest
        => no execution
```

### Scope rule

```text
Any exclusion match
        => DENY
```

### Approval rule

```text
HIGH / CRITICAL operation
        => valid contextual approval
        => execution
```
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef

---

# 2. DATA MODEL & SCHEMA DESIGN

<<<<<<< HEAD
## 2.1 Storage architecture

ARKA explicitly separates:

### PostgreSQL

Stores:

* metadata;
* identifiers;
* hashes;
* relationships;
* lifecycle state;
* policy decisions;
* observations;
* findings;
* audit metadata;
* workflow state;
* execution state.

### Object Storage

Stores:

* raw HTTP transactions;
* compressed tool output;
* large JSON;
* crawler payloads;
* sanitized response bodies;
* other bulk evidence.

Supported implementations:

```text
S3
MinIO
Local filesystem/blob store for development
```

Object names are content addressed:

```text
sha256/<first-two>/<full-sha256>.gz
```

PostgreSQL stores only:

```text
sha256
size
content_type
compression
storage_ref
metadata
```

---

# 2.2 Core relational schema

The following schema represents the security-critical relational model.

---

## 2.2.1 `users`

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    external_subject VARCHAR(255) UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL
        CHECK (role IN ('operator', 'approver')),
    status VARCHAR(32) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_status
    ON users(status);
```

ARKA intentionally uses a two-role model:

```text
operator
approver
```

Platform administration is an infrastructure/deployment concern rather than a third application authorization hierarchy.

---

# 2.2.2 `engagements`

```sql
CREATE TABLE engagements (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    objective TEXT NOT NULL,
    status VARCHAR(32) NOT NULL
        CHECK (
            status IN (
                'created',
                'running',
                'paused',
                'stopping',
                'stopped',
                'completed',
                'failed'
            )
        ),
    created_by UUID NOT NULL REFERENCES users(id),
    current_scope_version INTEGER NOT NULL DEFAULT 1,
    started_at TIMESTAMPTZ,
    stopped_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_engagements_status_created
    ON engagements(status, created_at);
```

---

# 2.2.3 `scope_versions`

Scope is immutable.

```sql
CREATE TABLE scope_versions (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL REFERENCES engagements(id),
    version INTEGER NOT NULL,
    rules_json JSONB NOT NULL,
    scope_sha256 CHAR(64) NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (engagement_id, version),
    UNIQUE (engagement_id, scope_sha256)
);

CREATE INDEX idx_scope_versions_engagement
    ON scope_versions(engagement_id, version);
```

`scope_sha256` is computed over canonicalized scope rules.

---

# 2.2.4 `scope_rules`

```sql
CREATE TABLE scope_rules (
    id UUID PRIMARY KEY,
    scope_version_id UUID NOT NULL
        REFERENCES scope_versions(id)
        ON DELETE CASCADE,
    rule_type VARCHAR(32) NOT NULL
        CHECK (
            rule_type IN (
                'ip',
                'cidr',
                'domain',
                'url',
                'port'
            )
        ),
    value TEXT NOT NULL,
    action VARCHAR(16) NOT NULL
        CHECK (action IN ('include', 'exclude')),
    priority INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_scope_rules_version
    ON scope_rules(scope_version_id, rule_type, action);
```

Exclusions always override inclusions.

---

# 2.2.5 `workflow_runs`

A workflow run represents one durable execution of an assessment workflow.

```sql
CREATE TABLE workflow_runs (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    workflow_type VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL
        CHECK (
            status IN (
                'created',
                'running',
                'paused',
                'waiting_approval',
                'stopping',
                'completed',
                'failed',
                'cancelled'
            )
        ),
    graph_version VARCHAR(64) NOT NULL,
    checkpoint_ref VARCHAR(255),
    checkpoint_sha256 CHAR(64),
    current_node VARCHAR(128),
    current_scope_version INTEGER NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    last_heartbeat_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_workflow_runs_engagement_status
    ON workflow_runs(engagement_id, status);

CREATE INDEX idx_workflow_runs_heartbeat
    ON workflow_runs(status, last_heartbeat_at);
```

Checkpoint payloads may reside in the LangGraph persistence mechanism or object storage, while PostgreSQL retains authoritative checkpoint metadata.

---

# 2.2.6 `tasks`

Tasks represent atomic units of deterministic work.

```sql
CREATE TABLE tasks (
    id UUID PRIMARY KEY,
    workflow_run_id UUID NOT NULL
        REFERENCES workflow_runs(id),
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    parent_task_id UUID
        REFERENCES tasks(id),
    task_type VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL
        CHECK (
            status IN (
                'queued',
                'running',
                'waiting_approval',
                'succeeded',
                'failed',
                'cancelled',
                'blocked'
            )
        ),
    priority INTEGER NOT NULL DEFAULT 100,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    idempotency_key VARCHAR(255) NOT NULL,
    scope_version INTEGER NOT NULL,
    budget_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    input_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    output_summary_json JSONB,
    error_code VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,

    UNIQUE (engagement_id, idempotency_key)
);

CREATE INDEX idx_tasks_workflow_status
    ON tasks(workflow_run_id, status);

CREATE INDEX idx_tasks_engagement_status_priority
    ON tasks(engagement_id, status, priority);
```

Task payloads must not contain raw credentials.

---

# 2.2.7 `candidate_tool_requests`

This table stores untrusted model proposals.

```sql
CREATE TABLE candidate_tool_requests (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    workflow_run_id UUID
        REFERENCES workflow_runs(id),
    task_id UUID
        REFERENCES tasks(id),
    llm_invocation_id UUID,
    candidate_type VARCHAR(64) NOT NULL,
    tool_name VARCHAR(128) NOT NULL,
    target_canonical TEXT,
    arguments_json JSONB NOT NULL,
    arguments_sha256 CHAR(64) NOT NULL,
    rationale TEXT,
    model_confidence NUMERIC(5,4)
        CHECK (
            model_confidence IS NULL
            OR (
                model_confidence >= 0
                AND model_confidence <= 1
            )
        ),
    status VARCHAR(32) NOT NULL
        CHECK (
            status IN (
                'proposed',
                'accepted_for_evaluation',
                'rejected',
                'converted'
            )
        ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_candidate_requests_engagement_created
    ON candidate_tool_requests(engagement_id, created_at);

CREATE INDEX idx_candidate_requests_hash
    ON candidate_tool_requests(arguments_sha256);
```

No row in this table grants execution authority.

---

# 2.2.8 `policy_decisions`

Every candidate evaluated by the security control plane produces a durable decision.

```sql
CREATE TABLE policy_decisions (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    candidate_request_id UUID NOT NULL
        REFERENCES candidate_tool_requests(id),
    scope_version INTEGER NOT NULL,
    policy_profile VARCHAR(128) NOT NULL,
    scope_decision VARCHAR(16) NOT NULL
        CHECK (
            scope_decision IN ('ALLOW', 'DENY')
        ),
    policy_decision VARCHAR(32) NOT NULL
        CHECK (
            policy_decision IN (
                'ALLOW',
                'DENY',
                'APPROVAL_REQUIRED'
            )
        ),
    reason_code VARCHAR(64) NOT NULL,
    reason_detail TEXT,
    evaluated_target TEXT,
    request_sha256 CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policy_decisions_engagement_created
    ON policy_decisions(engagement_id, created_at);

CREATE INDEX idx_policy_decisions_candidate
    ON policy_decisions(candidate_request_id);
```

Security decisions must use authoritative state from PostgreSQL.

---

# 2.2.9 `assets`

```sql
CREATE TABLE assets (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    asset_type VARCHAR(32) NOT NULL,
    canonical_value TEXT NOT NULL,
    authorization_state VARCHAR(32) NOT NULL
        CHECK (
            authorization_state IN (
                'discovered',
                'authorized',
                'rejected'
            )
        ),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (engagement_id, asset_type, canonical_value)
);

CREATE INDEX idx_assets_engagement_state
    ON assets(engagement_id, authorization_state);
```

---

# 2.2.10 `services`

```sql
CREATE TABLE services (
    id UUID PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id),
    protocol VARCHAR(16) NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    product VARCHAR(255),
    version VARCHAR(255),
    state VARCHAR(32),

    UNIQUE(asset_id, protocol, port)
);

CREATE INDEX idx_services_asset
    ON services(asset_id);
```

---

# 2.2.11 `technologies`

```sql
CREATE TABLE technologies (
    id UUID PRIMARY KEY,
    asset_id UUID REFERENCES assets(id),
    service_id UUID REFERENCES services(id),
    name VARCHAR(255) NOT NULL,
    version VARCHAR(255),
    confidence NUMERIC(5,4)
        CHECK (
            confidence IS NULL
            OR (
                confidence >= 0
                AND confidence <= 1
            )
        )
);

CREATE INDEX idx_technologies_asset
    ON technologies(asset_id);

CREATE INDEX idx_technologies_service
    ON technologies(service_id);
```

---

# 2.2.12 `endpoints`

```sql
CREATE TABLE endpoints (
    id UUID PRIMARY KEY,
    asset_id UUID REFERENCES assets(id),
    service_id UUID REFERENCES services(id),
    method VARCHAR(16) NOT NULL,
    normalized_url TEXT NOT NULL,
    path TEXT NOT NULL,
    source VARCHAR(64) NOT NULL,
    auth_required BOOLEAN,
    authorization_state VARCHAR(32) NOT NULL
        CHECK (
            authorization_state IN (
                'discovered',
                'authorized',
                'rejected'
            )
        ),

    UNIQUE(asset_id, method, normalized_url)
);

CREATE INDEX idx_endpoints_asset
    ON endpoints(asset_id);

CREATE INDEX idx_endpoints_service
    ON endpoints(service_id);
```

---

# 2.2.13 `parameters`

```sql
CREATE TABLE parameters (
    id UUID PRIMARY KEY,
    endpoint_id UUID NOT NULL
        REFERENCES endpoints(id)
        ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    location VARCHAR(32) NOT NULL
        CHECK (
            location IN (
                'path',
                'query',
                'header',
                'cookie',
                'body'
            )
        ),
    data_type VARCHAR(64),
    required BOOLEAN NOT NULL DEFAULT false,
    sensitivity VARCHAR(32) NOT NULL DEFAULT 'normal',

    UNIQUE(endpoint_id, name, location)
);

CREATE INDEX idx_parameters_endpoint
    ON parameters(endpoint_id);
```

---

# 2.2.14 `auth_profiles`

```sql
CREATE TABLE auth_profiles (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    name VARCHAR(255) NOT NULL,
    auth_type VARCHAR(32) NOT NULL,
    credential_ref VARCHAR(255) NOT NULL,
    target_origin TEXT NOT NULL,
    status VARCHAR(32) NOT NULL
        CHECK(status IN ('active', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_auth_profiles_engagement_status
    ON auth_profiles(engagement_id, status);
```

`credential_ref` is an opaque secret-manager reference.

---

# 2.2.15 `sessions`

```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    scope_version_id UUID NOT NULL
        REFERENCES scope_versions(id),
    auth_profile_id UUID NOT NULL
        REFERENCES auth_profiles(id),
    target_origin TEXT NOT NULL,
    status VARCHAR(32) NOT NULL
        CHECK (
            status IN (
                'active',
                'expired',
                'revoked'
            )
        ),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_sessions_engagement_status_expiry
    ON sessions(engagement_id, status, expires_at);
```

Raw cookies, bearer tokens and API keys are not stored here.

---

# 2.2.16 `observations`

Observations are the first-class evidence-backed security signals before finding promotion.

```sql
CREATE TABLE observations (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    task_id UUID
        REFERENCES tasks(id),
    asset_id UUID
        REFERENCES assets(id),
    endpoint_id UUID
        REFERENCES endpoints(id),
    observation_type VARCHAR(128) NOT NULL,
    source_type VARCHAR(64) NOT NULL,
    source_ref UUID,
    status VARCHAR(32) NOT NULL
        CHECK (
            status IN (
                'observed',
                'corroborated',
                'invalidated'
            )
        ),
    summary TEXT NOT NULL,
    data_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence_sha256 CHAR(64),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_observations_engagement_created
    ON observations(engagement_id, created_at);

CREATE INDEX idx_observations_endpoint
    ON observations(endpoint_id);

CREATE INDEX idx_observations_type
    ON observations(engagement_id, observation_type);
```

---

# 2.2.17 `findings`

```sql
CREATE TABLE findings (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    title TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL
        CHECK (
            severity IN (
                'INFO',
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),
    epistemic_state VARCHAR(32) NOT NULL
        CHECK (
            epistemic_state IN (
                'OBSERVED',
                'CANDIDATE',
                'SUPPORTED',
                'VALIDATED',
                'HUMAN_CONFIRMED'
            )
        ),
    confidence NUMERIC(5,4)
        CHECK (
            confidence >= 0
            AND confidence <= 1
        ),
    description TEXT NOT NULL,
    remediation TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    validated_at TIMESTAMPTZ,
    human_confirmed_at TIMESTAMPTZ
);

CREATE INDEX idx_findings_engagement_state
    ON findings(engagement_id, epistemic_state);

CREATE INDEX idx_findings_engagement_severity
    ON findings(engagement_id, severity);
```

Application code must enforce that only authorized validation engines can set:

```text
VALIDATED
```

and only an authorized human actor can set:

```text
HUMAN_CONFIRMED
```

---

# 2.2.18 `evidence`

```sql
CREATE TABLE evidence (
    sha256 CHAR(64) PRIMARY KEY,
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    evidence_type VARCHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL
        CHECK(size_bytes >= 0),
    content_type VARCHAR(255),
    compression VARCHAR(32) NOT NULL DEFAULT 'gzip',
    storage_ref TEXT NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_evidence_engagement_created
    ON evidence(engagement_id, created_at);
```

---

# 2.2.19 `finding_evidence`

This provides the required many-to-many relationship between findings and evidence.

```sql
CREATE TABLE finding_evidence (
    finding_id UUID NOT NULL
        REFERENCES findings(id)
        ON DELETE CASCADE,
    evidence_sha256 CHAR(64) NOT NULL
        REFERENCES evidence(sha256),
    relevance VARCHAR(32) NOT NULL
        CHECK (
            relevance IN (
                'primary',
                'supporting',
                'reproduction',
                'context'
            )
        ),
    relevance_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (finding_id, evidence_sha256)
);

CREATE INDEX idx_finding_evidence_evidence
    ON finding_evidence(evidence_sha256);
```

---

# 2.2.20 `llm_invocations`

```sql
CREATE TABLE llm_invocations (
    id UUID PRIMARY KEY,
    engagement_id UUID
        REFERENCES engagements(id),
    workflow_run_id UUID
        REFERENCES workflow_runs(id),
    provider VARCHAR(128) NOT NULL,
    model VARCHAR(255) NOT NULL,
    request_type VARCHAR(64) NOT NULL,
    input_tokens BIGINT,
    output_tokens BIGINT,
    total_tokens BIGINT,
    latency_ms BIGINT,
    estimated_cost_usd NUMERIC(12,6),
    status VARCHAR(32) NOT NULL
        CHECK (
            status IN (
                'started',
                'succeeded',
                'failed',
                'timeout'
            )
        ),
    error_code VARCHAR(64),
    prompt_sha256 CHAR(64),
    response_sha256 CHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_llm_invocations_engagement_created
    ON llm_invocations(engagement_id, created_at);

CREATE INDEX idx_llm_invocations_provider_model
    ON llm_invocations(provider, model);
```

Raw prompts/responses are not stored by default.

---

# 2.2.21 `approval_requests`

```sql
CREATE TABLE approval_requests (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    task_id UUID
        REFERENCES tasks(id),
    tool_name VARCHAR(128) NOT NULL,
    target_canonical TEXT NOT NULL,
    arguments_sha256 CHAR(64) NOT NULL,
    scope_version INTEGER NOT NULL,
    risk_level VARCHAR(16) NOT NULL,
    approval_mode VARCHAR(16) NOT NULL
        CHECK (
            approval_mode IN ('single', 'batch')
        ),
    batch_merkle_root CHAR(64),
    status VARCHAR(32) NOT NULL
        CHECK (
            status IN (
                'required',
                'granted',
                'rejected',
                'expired',
                'revoked',
                'executed'
            )
        ),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    decided_by UUID REFERENCES users(id),
    decided_at TIMESTAMPTZ
);

CREATE INDEX idx_approval_engagement_status_expiry
    ON approval_requests(engagement_id, status, expires_at);
```

Batch approvals MUST include `batch_merkle_root`.

---

# 2.2.22 `tool_executions`

```sql
CREATE TABLE tool_executions (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    task_id UUID
        REFERENCES tasks(id),
    tool_name VARCHAR(128) NOT NULL,
    request_sha256 CHAR(64) NOT NULL,
    approval_request_id UUID
        REFERENCES approval_requests(id),
    status VARCHAR(32) NOT NULL
        CHECK (
            status IN (
                'queued',
                'running',
                'succeeded',
                'failed',
                'cancelled'
            )
        ),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    evidence_sha256 CHAR(64)
        REFERENCES evidence(sha256)
);

CREATE UNIQUE INDEX uq_tool_execution_request
    ON tool_executions(engagement_id, request_sha256);

CREATE INDEX idx_tool_execution_engagement_status
    ON tool_executions(engagement_id, status);
```

---

# 2.2.23 `audit_events`

```sql
CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    engagement_id UUID NOT NULL
        REFERENCES engagements(id),
    sequence BIGINT NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    actor_type VARCHAR(32) NOT NULL,
    actor_id UUID,
    correlation_id UUID,
    payload_json JSONB NOT NULL,
    previous_hash CHAR(64),
    event_hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (engagement_id, sequence),
    UNIQUE (engagement_id, event_hash)
);

CREATE INDEX idx_audit_events_engagement_sequence
    ON audit_events(engagement_id, sequence);
```

---

# 2.3 Entity relationship diagram

```mermaid
erDiagram

    USERS ||--o{ ENGAGEMENTS : creates
    ENGAGEMENTS ||--o{ SCOPE_VERSIONS : owns
    SCOPE_VERSIONS ||--o{ SCOPE_RULES : contains

    ENGAGEMENTS ||--o{ WORKFLOW_RUNS : executes
    WORKFLOW_RUNS ||--o{ TASKS : contains
    TASKS ||--o{ TASKS : decomposes

    ENGAGEMENTS ||--o{ CANDIDATE_TOOL_REQUESTS : receives
    WORKFLOW_RUNS ||--o{ CANDIDATE_TOOL_REQUESTS : produces
    TASKS ||--o{ CANDIDATE_TOOL_REQUESTS : generates

    CANDIDATE_TOOL_REQUESTS ||--o{ POLICY_DECISIONS : evaluated_by

    ENGAGEMENTS ||--o{ ASSETS : discovers
=======
## 2.1 Design principles

1. Security-critical records are engagement-scoped.
2. Foreign keys enforce ownership relationships.
3. UUIDs are preferred for externally visible identifiers.
4. Scope changes create a new immutable scope version.
5. Evidence is content-addressed by SHA-256.
6. Audit events are append-only.
7. Credentials are never stored in normal domain records as plaintext values.
8. Discovery records do not imply authorization.
9. Findings retain provenance to observations/evidence.
10. Security state transitions are transactionally persisted.

## 2.2 Core entities

### `users`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Stable user identity |
| external_subject | VARCHAR(255) | UNIQUE | Identity-provider subject |
| display_name | VARCHAR(255) | | Human-readable name |
| status | VARCHAR(32) | | active/suspended |
| created_at | TIMESTAMPTZ | | Creation time |
| updated_at | TIMESTAMPTZ | | Last update |

### `engagements`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Engagement identity |
| name | VARCHAR(255) | | Required |
| objective | TEXT | | Assessment objective |
| status | VARCHAR(32) | | lifecycle state |
| created_by | UUID | FK users.id | Owner |
| scope_version | INTEGER | | Current scope version |
| started_at | TIMESTAMPTZ | | Optional |
| stopped_at | TIMESTAMPTZ | | Optional |
| created_at | TIMESTAMPTZ | | Creation |
| updated_at | TIMESTAMPTZ | | Update |

### `scope_versions`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Scope version identity |
| engagement_id | UUID | FK | Parent engagement |
| version | INTEGER | UNIQUE(engagement_id,version) | Monotonic |
| rules_json | JSONB | | Canonical normalized scope |
| created_by | UUID | FK | Operator |
| created_at | TIMESTAMPTZ | | Immutable |

### `scope_rules`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Rule identity |
| scope_version_id | UUID | FK | Scope version |
| rule_type | VARCHAR(32) | | ip/cidr/domain/url/port |
| value | TEXT | | Canonical rule |
| action | VARCHAR(16) | | include/exclude |
| priority | INTEGER | | Deterministic evaluation |

### `assets`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Deterministic canonical identity |
| engagement_id | UUID | FK | Engagement ownership |
| asset_type | VARCHAR(32) | | host/ip/domain |
| canonical_value | TEXT | | Normalized identity |
| discovered_not_authorized | BOOLEAN | | Default true for discovery |
| authorization_state | VARCHAR(32) | | discovered/authorized/rejected |
| first_seen_at | TIMESTAMPTZ | | Provenance |
| last_seen_at | TIMESTAMPTZ | | Provenance |

### `services`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Canonical service identity |
| asset_id | UUID | FK | Parent asset |
| protocol | VARCHAR(16) | | tcp/udp/http/https/etc. |
| port | INTEGER | | 1–65535 |
| product | VARCHAR(255) | | Optional |
| version | VARCHAR(255) | | Optional |
| state | VARCHAR(32) | | observed state |

### `technologies`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Identity |
| asset_id | UUID | FK | Optional asset |
| service_id | UUID | FK | Optional service |
| name | VARCHAR(255) | | Product/framework |
| version | VARCHAR(255) | | Optional |
| confidence | NUMERIC(5,4) | | 0–1 |

### `endpoints`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Deterministic canonical identity |
| asset_id | UUID | FK | Parent asset |
| service_id | UUID | FK | Optional service |
| method | VARCHAR(16) | | Normalized HTTP method |
| normalized_url | TEXT | | Canonical URL |
| path | TEXT | | Normalized path |
| discovered_not_authorized | BOOLEAN | | Default true |
| auth_required | BOOLEAN | | Observation |
| source | VARCHAR(64) | | crawler/openapi/graphql/manual |

### `parameters`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Identity |
| endpoint_id | UUID | FK | Parent endpoint |
| name | VARCHAR(255) | | Parameter name |
| location | VARCHAR(32) | | path/query/header/cookie/body |
| data_type | VARCHAR(64) | | Normalized type |
| required | BOOLEAN | | Schema property |
| sensitivity | VARCHAR(32) | | normal/secret/personal |

### `sessions`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Opaque session handle |
| engagement_id | UUID | FK | Isolation |
| scope_version_id | UUID | FK | Authorization context |
| auth_profile_id | UUID | FK | Authentication definition |
| target_origin | TEXT | | Canonical origin |
| status | VARCHAR(32) | | active/expired/revoked |
| expires_at | TIMESTAMPTZ | | Mandatory expiry |
| created_at | TIMESTAMPTZ | | Creation |
| last_used_at | TIMESTAMPTZ | | Activity |

Raw session credentials MUST NOT be stored in this table.

### `auth_profiles`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Identity |
| engagement_id | UUID | FK | Isolation |
| name | VARCHAR(255) | | Operator-visible name |
| auth_type | VARCHAR(32) | | cookie/bearer/api_key/form |
| credential_ref | VARCHAR(255) | | External secret reference |
| target_origin | TEXT | | Bound origin |
| status | VARCHAR(32) | | active/revoked |
| created_at | TIMESTAMPTZ | | |

### `findings`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Finding identity |
| engagement_id | UUID | FK | Ownership |
| title | TEXT | | Finding title |
| severity | VARCHAR(16) | | INFO/LOW/MEDIUM/HIGH/CRITICAL |
| status | VARCHAR(32) | | observed/suspected/validated/false_positive/remediated |
| confidence | NUMERIC(5,4) | | 0–1 |
| description | TEXT | | Sanitized description |
| remediation | TEXT | | Guidance |
| first_seen_at | TIMESTAMPTZ | | |
| last_validated_at | TIMESTAMPTZ | | |

### `evidence`

| Column | Type | Key | Requirements |
|---|---|---|---|
| sha256 | CHAR(64) | PK | Content address |
| engagement_id | UUID | FK | Ownership |
| evidence_type | VARCHAR(32) | | HTTP/STDOUT/STDERR/JSON/etc. |
| size_bytes | BIGINT | | Bounded |
| metadata_json | JSONB | | Sanitized metadata |
| storage_ref | TEXT | | Blob/object reference |
| created_at | TIMESTAMPTZ | | Immutable |

### `audit_events`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Event identity |
| engagement_id | UUID | FK | Context |
| event_type | VARCHAR(64) | | Security event |
| actor_type | VARCHAR(32) | | human/agent/system |
| actor_id | UUID | | Optional |
| correlation_id | UUID | | Traceability |
| payload_json | JSONB | | Sanitized |
| previous_hash | CHAR(64) | | Chain integrity |
| event_hash | CHAR(64) | UNIQUE | Hash chain |
| created_at | TIMESTAMPTZ | | Immutable |

### `approval_requests`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Approval identity |
| engagement_id | UUID | FK | Isolation |
| task_id | UUID | | Workflow context |
| tool_name | VARCHAR(128) | | Exact tool |
| target_canonical | TEXT | | Exact target |
| arguments_hash | CHAR(64) | | Exact argument binding |
| scope_version | INTEGER | | Scope binding |
| risk_level | VARCHAR(16) | | Risk |
| status | VARCHAR(32) | | required/granted/rejected/expired/executed/revoked |
| requested_at | TIMESTAMPTZ | | |
| expires_at | TIMESTAMPTZ | | Mandatory expiry |
| decided_by | UUID | FK users.id | Approver |
| decided_at | TIMESTAMPTZ | | |

### `tool_executions`

| Column | Type | Key | Requirements |
|---|---|---|---|
| id | UUID | PK | Execution identity |
| engagement_id | UUID | FK | Isolation |
| task_id | UUID | | Workflow |
| tool_name | VARCHAR(128) | | Tool |
| request_hash | CHAR(64) | | Idempotency |
| status | VARCHAR(32) | | queued/running/succeeded/failed/cancelled |
| started_at | TIMESTAMPTZ | | |
| finished_at | TIMESTAMPTZ | | |
| evidence_sha256 | CHAR(64) | FK evidence.sha256 | Result |

## 2.3 Relationship diagram

```mermaid
erDiagram
    USERS ||--o{ ENGAGEMENTS : creates
    ENGAGEMENTS ||--o{ SCOPE_VERSIONS : has
    SCOPE_VERSIONS ||--o{ SCOPE_RULES : contains
    ENGAGEMENTS ||--o{ ASSETS : owns
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
    ASSETS ||--o{ SERVICES : exposes
    ASSETS ||--o{ TECHNOLOGIES : runs
    SERVICES ||--o{ TECHNOLOGIES : identifies
    ASSETS ||--o{ ENDPOINTS : exposes
    SERVICES ||--o{ ENDPOINTS : serves
    ENDPOINTS ||--o{ PARAMETERS : accepts
<<<<<<< HEAD

    ENGAGEMENTS ||--o{ OBSERVATIONS : records
    TASKS ||--o{ OBSERVATIONS : produces
    ENDPOINTS ||--o{ OBSERVATIONS : concerns

    ENGAGEMENTS ||--o{ FINDINGS : contains
    FINDINGS ||--o{ FINDING_EVIDENCE : supported_by
    EVIDENCE ||--o{ FINDING_EVIDENCE : supports

    ENGAGEMENTS ||--o{ LLM_INVOCATIONS : contains
    WORKFLOW_RUNS ||--o{ LLM_INVOCATIONS : invokes

    ENGAGEMENTS ||--o{ AUTH_PROFILES : configures
    AUTH_PROFILES ||--o{ SESSIONS : creates
    ENGAGEMENTS ||--o{ SESSIONS : owns
    SCOPE_VERSIONS ||--o{ SESSIONS : binds

    ENGAGEMENTS ||--o{ APPROVAL_REQUESTS : gates
    USERS ||--o{ APPROVAL_REQUESTS : decides

    ENGAGEMENTS ||--o{ TOOL_EXECUTIONS : contains
    TASKS ||--o{ TOOL_EXECUTIONS : executes
    APPROVAL_REQUESTS ||--o{ TOOL_EXECUTIONS : authorizes
    EVIDENCE ||--o{ TOOL_EXECUTIONS : produces

    ENGAGEMENTS ||--o{ AUDIT_EVENTS : records
```

---

# 2.4 Finding-state enforcement

The database stores:

```text
OBSERVED
CANDIDATE
SUPPORTED
VALIDATED
HUMAN_CONFIRMED
```

but application-layer authorization determines who may transition states.

Allowed transition model:

```text
OBSERVED
   |
   v
CANDIDATE
   |
   v
SUPPORTED
   |
   | deterministic validator only
   v
VALIDATED
   |
   | authorized human only
   v
HUMAN_CONFIRMED
```

Forbidden:

```text
LLM -> VALIDATED
LLM -> HUMAN_CONFIRMED
Tool output -> HUMAN_CONFIRMED
```
=======
    ENGAGEMENTS ||--o{ AUTH_PROFILES : configures
    AUTH_PROFILES ||--o{ SESSIONS : creates
    ENGAGEMENTS ||--o{ SESSIONS : isolates
    SCOPE_VERSIONS ||--o{ SESSIONS : binds
    ENGAGEMENTS ||--o{ FINDINGS : contains
    ENGAGEMENTS ||--o{ EVIDENCE : owns
    ENGAGEMENTS ||--o{ AUDIT_EVENTS : records
    ENGAGEMENTS ||--o{ APPROVAL_REQUESTS : gates
    USERS ||--o{ APPROVAL_REQUESTS : decides
    ENGAGEMENTS ||--o{ TOOL_EXECUTIONS : contains
    EVIDENCE ||--o{ TOOL_EXECUTIONS : supports
```

## 2.4 Indexing requirements

Minimum indexes:

- `engagements(status, created_at)`
- `scope_versions(engagement_id, version)` unique
- `scope_rules(scope_version_id, rule_type, action)`
- `assets(engagement_id, canonical_value)` unique where appropriate
- `services(asset_id, protocol, port)` unique
- `endpoints(asset_id, method, normalized_url)` unique
- `parameters(endpoint_id, name, location)` unique
- `sessions(engagement_id, status, expires_at)`
- `findings(engagement_id, severity, status)`
- `evidence(engagement_id, created_at)`
- `audit_events(engagement_id, created_at)`
- `approval_requests(engagement_id, status, expires_at)`
- `tool_executions(engagement_id, request_hash)`
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef

---

# 3. API SPECIFICATIONS

<<<<<<< HEAD
=======
## 3.1 API conventions

>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
Base path:

```text
/api/v1
```

<<<<<<< HEAD
All responses use:
=======
All API responses should include:
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef

```json
{
  "request_id": "uuid",
  "data": {},
  "error": null
}
```

<<<<<<< HEAD
---

## 3.1 Create engagement

**POST**

```text
/api/v1/engagements
```

=======
Errors:

```json
{
  "request_id": "uuid",
  "data": null,
  "error": {
    "code": "SCOPE_DENIED",
    "message": "Target is outside the effective engagement scope"
  }
}
```

Do not return secrets, raw provider credentials or unsanitized sensitive HTTP headers.

## 3.2 Engagement APIs

### Create engagement

**POST** `/api/v1/engagements`

>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
Request:

```json
{
<<<<<<< HEAD
  "name": "Juice Shop Assessment",
  "objective": "Authorized web application security assessment",
  "scope": {
    "includes": [
      {
        "type": "url",
        "value": "http://127.0.0.1:3000"
      }
    ],
    "excludes": []
=======
  "name": "Web Application Assessment",
  "objective": "Assess authorized application attack surface",
  "scope": {
    "includes": [
      {"type": "url", "value": "http://127.0.0.1:3000"}
    ],
    "excludes": [
      {"type": "url", "value": "http://127.0.0.1:8000"}
    ],
    "ports": [80, 443, 3000]
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
  },
  "policy_profile": "standard-authorized-assessment"
}
```

<<<<<<< HEAD
---

## 3.2 Start engagement

**POST**

```text
/api/v1/engagements/{engagement_id}/start
```

=======
Success `201`:

```json
{
  "request_id": "uuid",
  "data": {
    "id": "uuid",
    "status": "created",
    "scope_version": 1
  },
  "error": null
}
```

Errors:

```json
{
  "request_id": "uuid",
  "data": null,
  "error": {
    "code": "INVALID_SCOPE",
    "message": "Scope contains an invalid or ambiguous target"
  }
}
```

### Start engagement

**POST** `/api/v1/engagements/{engagement_id}/start`

>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
Request:

```json
{
  "assessment_profile": "web-api-standard"
}
```

<<<<<<< HEAD
---

## 3.3 Create scope version

**POST**

```text
/api/v1/engagements/{engagement_id}/scope
```

=======
Success:

```json
{
  "request_id": "uuid",
  "data": {
    "engagement_id": "uuid",
    "status": "running",
    "workflow_id": "uuid"
  },
  "error": null
}
```

### Status

**GET** `/api/v1/engagements/{engagement_id}`

Success:

```json
{
  "request_id": "uuid",
  "data": {
    "id": "uuid",
    "status": "running",
    "phase": "web_analysis",
    "scope_version": 2,
    "tasks_running": 2,
    "pending_approvals": 1,
    "assets": 14,
    "endpoints": 63,
    "findings": 4
  },
  "error": null
}
```

## 3.3 Scope APIs

### Create new scope version

**POST** `/api/v1/engagements/{engagement_id}/scope`

>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
Request:

```json
{
  "includes": [
<<<<<<< HEAD
    {
      "type": "domain",
      "value": "api.example.test"
    }
  ],
  "excludes": []
}
```

The server:

1. canonicalizes rules;
2. computes scope SHA-256;
3. creates immutable scope version;
4. invalidates incompatible approvals;
5. records audit event.

---

# 3.4 Scope Delta

**POST**

```text
/api/v1/engagements/{engagement_id}/scope-deltas
```

Request:

```json
{
  "source_asset": "app.example.test",
  "discovered_asset": "api.example.test",
  "relationship": "API referenced by authorized application",
  "proposed_rules": [
    {
      "type": "domain",
      "value": "api.example.test",
      "action": "include"
    }
  ],
  "risk_level": "LOW",
  "evidence_sha256": "..."
}
```

Response:
=======
    {"type": "domain", "value": "app.example.test"}
  ],
  "excludes": [
    {"type": "host", "value": "admin.example.test"}
  ]
}
```

Success:
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef

```json
{
  "request_id": "uuid",
  "data": {
<<<<<<< HEAD
    "scope_delta_id": "uuid",
    "status": "pending",
    "current_scope_version": 4
=======
    "scope_version": 3,
    "effective_rules": 2
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
  },
  "error": null
}
```

<<<<<<< HEAD
Approval produces a new immutable scope version.

---

# 3.5 Crawl

**POST**

```text
/api/v1/engagements/{engagement_id}/web/crawl
```
=======
Any scope change MUST invalidate incompatible pending approvals.

## 3.4 Web APIs

### Start crawler

**POST** `/api/v1/engagements/{engagement_id}/web/crawl`
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef

Request:

```json
{
  "target": "http://127.0.0.1:3000",
  "max_pages": 100,
  "max_depth": 5,
  "max_requests": 200,
<<<<<<< HEAD
  "max_response_bytes": 1048576
}
```

---

# 3.6 OpenAPI analysis

**POST**

```text
/api/v1/engagements/{engagement_id}/web/openapi
```

=======
  "max_response_bytes": 1048576,
  "session_ref": null
}
```

Success:

```json
{
  "request_id": "uuid",
  "data": {
    "task_id": "uuid",
    "status": "queued"
  },
  "error": null
}
```

### OpenAPI analysis

**POST** `/api/v1/engagements/{engagement_id}/web/openapi`

>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
Request:

```json
{
  "target": "http://127.0.0.1:3000/openapi.json",
  "max_document_bytes": 5242880
}
```

<<<<<<< HEAD
External `$ref` retrieval is disabled by default.

---

# 3.7 GraphQL analysis

**POST**

```text
/api/v1/engagements/{engagement_id}/web/graphql
```
=======
### GraphQL analysis

**POST** `/api/v1/engagements/{engagement_id}/web/graphql`
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef

Request:

```json
{
  "target": "http://127.0.0.1:3000/graphql",
  "introspection": true,
  "max_query_depth": 8,
  "max_response_bytes": 1048576
}
```

<<<<<<< HEAD
---

# 3.8 Approval API

**GET**

```text
/api/v1/approvals?engagement_id={id}&status=required
```

---

## 3.8.1 Single approval

**POST**

```text
/api/v1/approvals/{approval_id}/decide
```
=======
## 3.5 Findings APIs

### List findings

**GET** `/api/v1/engagements/{engagement_id}/findings?status=validated&severity=high`

Success:

```json
{
  "request_id": "uuid",
  "data": {
    "items": [
      {
        "id": "uuid",
        "title": "Potential object-level authorization weakness",
        "severity": "high",
        "status": "validated",
        "confidence": 0.94,
        "evidence": ["sha256:..."],
        "affected_endpoint": "uuid"
      }
    ],
    "total": 1
  },
  "error": null
}
```

## 3.6 Approval APIs

### List approvals

**GET** `/api/v1/approvals?engagement_id={id}&status=required`

### Decide approval

**POST** `/api/v1/approvals/{approval_id}/decide`
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef

Request:

```json
{
  "decision": "GRANTED",
<<<<<<< HEAD
  "reason": "Authorized assessment operation"
}
```

Before execution the system revalidates:

```text
engagement
scope version
request hash
target
policy
approval expiry
approval status
```

---

# 3.9 Batch approval

**POST**

```text
/api/v1/approvals/batch
```

Request:

```json
{
  "engagement_id": "uuid",
  "scope_version": 4,
  "request_ids": [
    "uuid",
    "uuid",
    "uuid"
  ],
  "merkle_root": "sha256...",
  "expires_at": "2026-09-16T20:00:00Z"
}
```

Server verifies that the supplied Merkle root corresponds exactly to the canonicalized requests.

---

# 3.10 Findings

**GET**

```text
/api/v1/engagements/{engagement_id}/findings
```

Filter parameters:

```text
epistemic_state
severity
asset_id
endpoint_id
```

---

# 3.11 Validation

**POST**

```text
/api/v1/findings/{finding_id}/validate
```

This endpoint is not available to the LLM.

The request must reference:

```text
validator_id
validation_method
replay_task_id
evidence_sha256
```

Example:

```json
{
  "validation_method": "deterministic_differential_replay",
  "replay_task_id": "uuid",
  "evidence_sha256": "sha256..."
}
```

---

# 3.12 Human confirmation

**POST**

```text
/api/v1/findings/{finding_id}/confirm
```

Only an authorized approver may transition:

```text
VALIDATED
→
HUMAN_CONFIRMED
```

---

# 3.13 Evidence

**GET**

```text
/api/v1/engagements/{engagement_id}/evidence/{sha256}
```

The response returns:

* metadata;
* content type;
* size;
* creation time;
* sensitivity;
* sanitized payload access.

Large payloads should be streamed from object storage.

---

# 3.14 LLM status

**GET**

```text
/api/v1/llm/status
```

Returns:
=======
  "reason": "Authorized by assessment owner"
}
```

Success:
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef

```json
{
  "request_id": "uuid",
  "data": {
<<<<<<< HEAD
    "reference_provider": "openrouter",
    "model": "configured-model",
    "healthy": true,
    "capabilities": [
      "structured_output"
=======
    "approval_id": "uuid",
    "status": "granted",
    "scope_version": 3,
    "expires_at": "2026-09-16T20:00:00Z"
  },
  "error": null
}
```

The API MUST reject decisions made against stale scope or wrong engagement context.

## 3.7 Audit API

**GET** `/api/v1/engagements/{engagement_id}/audit`

Response:

```json
{
  "request_id": "uuid",
  "data": {
    "items": [
      {
        "id": "uuid",
        "event_type": "POLICY_DECISION",
        "actor_type": "system",
        "decision": "DENY",
        "reason_code": "OUT_OF_SCOPE",
        "event_hash": "sha256..."
      }
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
    ]
  },
  "error": null
}
```

<<<<<<< HEAD
No API keys are returned.
=======
## 3.8 Evidence API

**GET** `/api/v1/engagements/{engagement_id}/evidence/{sha256}`

Return metadata and sanitized content according to evidence sensitivity policy. Do not expose credentials merely because they occurred in an HTTP transaction.

## 3.9 LLM APIs

### Provider status

**GET** `/api/v1/llm/providers`

### LLM status

**GET** `/api/v1/llm/status`

Returned data should expose provider/model/capabilities/health, not API keys.
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef

---

# 4. INFRASTRUCTURE, SCALE & PERFORMANCE

<<<<<<< HEAD
## 4.1 Development topology

```text
FastAPI
   |
PostgreSQL
   |
Redis / Arq
   |
Docker Sandbox
   |
OpenRouter
```

---

# 4.2 Production topology

The initial production architecture deliberately remains small:

```text
                Operator
                   |
                FastAPI
                   |
          +--------+--------+
          |                 |
      PostgreSQL          Redis
          |                 |
          |               Arq
          |                 |
          +--------+--------+
                   |
           ExecutionManager
                   |
          Docker Sandbox Pool
                   |
       Controlled Target Access
```

Object storage is used for large evidence payloads.

No graph database is required.

No multi-cluster control plane is required.

No enterprise fleet scheduler is required.

---

# 4.3 PostgreSQL responsibilities

PostgreSQL is authoritative for:

* engagements;
* scopes;
* policy decisions;
* approvals;
* tasks;
* workflows;
* observations;
* findings;
* evidence metadata;
* execution state;
* audit sequence;
* LLM invocation metadata.

PostgreSQL is not intended to store large raw evidence payloads.

---

# 4.4 Object storage responsibilities

Object storage contains:

```text
compressed HTTP bodies
tool stdout
tool stderr
large JSON
crawler responses
sanitized response bodies
screenshots when introduced
```

Objects are:

```text
gzip(payload)
```

and addressed by:

```text
SHA-256(payload)
```

The hash is calculated over the canonical uncompressed content.

---

# 4.5 Redis responsibilities

Redis provides:

* Arq queue;
* ephemeral locks;
* execution coordination;
* rate limiting;
* short-lived caches;
* audit sequencing support.

Redis is never authoritative for:

```text
scope
approval
policy
execution authorization
finding validation
```

---

# 4.6 Resource budgets

Default limits:

| Resource                   | Default |
| -------------------------- | ------: |
| API requests/user          | 120/min |
| LLM requests/engagement    |  60/min |
| Web concurrency/engagement |      20 |
| Crawl pages/task           |   1,000 |
| Crawl requests/task        |   2,000 |
| HTTP response              |   5 MiB |
| OpenAPI document           |   5 MiB |
| GraphQL response           |   1 MiB |
| Candidate arguments        | 256 KiB |
| Task wall-clock            |  15 min |
| Sandbox memory             |   1 GiB |
| Sandbox CPU                |  1 vCPU |
| Sandbox process limit      |     128 |

These are policy defaults.

LLM output cannot increase them.

---

# 4.7 Deterministic planner budgets

Every deterministic investigation plan must have:

```text
maximum tasks
maximum requests
maximum bytes
maximum execution time
maximum concurrency
```

Example:

```json
{
  "intent": "MAP_API_ATTACK_SURFACE",
  "max_tasks": 50,
  "max_requests": 200,
  "max_bytes": 52428800,
  "max_runtime_seconds": 300
}
```

---

# 4.8 Scaling strategy

The initial scale strategy is vertical simplicity plus bounded concurrency.

Scale only these components independently when measurements justify it:

```text
FastAPI
Arq workers
PostgreSQL connections
sandbox concurrency
object storage
```

Do not introduce:

* Kafka;
* dedicated graph database;
* distributed workflow service;
* service mesh;
* multi-region database;
* multi-tenant fleet scheduler

without workload evidence.

---

# 5. SECURITY REQUIREMENTS

## 5.1 HTTP security pipeline

Every server-side HTTP operation must execute:

```text
Parse URL
   ↓
Canonicalize
   ↓
Scheme validation
   ↓
DNS resolution
   ↓
IP classification
   ↓
ScopeGuard
   ↓
PolicyEngine
   ↓
Connection
```

Redirect:

```text
Response
   ↓
Location
   ↓
Parse
   ↓
DNS
   ↓
IP classification
   ↓
ScopeGuard
   ↓
PolicyEngine
   ↓
Next connection
```

Every redirect hop is independently validated.

---

# 5.2 SSRF protections

Reject:

* loopback;
* RFC1918 private ranges;
* link-local;
* cloud metadata endpoints;
* unsupported schemes;
* malformed IP representations;
* ambiguous hostname representations;
* unauthorized DNS resolutions.

---

# 5.3 Credential boundary

The LLM receives:

```text
credential_ref
```

not:

```text
credential_value
```

The execution runtime resolves the secret only after:

```text
scope
+
policy
+
approval if required
+
session binding
```

---

# 5.4 Session binding

Sessions must be bound to:

```text
engagement_id
scope_version
auth_profile
target_origin
expiry
```

An active session from:

```text
Engagement A
```

must not be usable in:

```text
Engagement B
```

---

# 5.5 Sandbox requirements

Each sandbox must have:

* non-root user;
* dropped Linux capabilities;
* CPU limit;
* memory limit;
* PID limit;
* filesystem restrictions;
* temporary workspace;
* network policy;
* environment allowlist;
* wall-clock deadline;
* output-size limit;
* cleanup guarantee.

The LLM never receives Docker daemon authority.

---

# 6. AUDIT CHAIN CONCURRENCY

## 6.1 Problem

A naive hash chain:

```text
Event B.previous_hash = hash(Event A)
```

is unsafe under concurrent workers.

Two workers can observe the same previous event:

```text
Worker A → previous = X
Worker B → previous = X
```

creating a fork.

---

# 6.2 Required architecture

ARKA uses a **per-engagement audit sequencer**.

Logical flow:

```text
Worker A ─┐
Worker B ─┼──> Audit Event Queue
Worker C ─┘
                  |
                  v
          Per-Engagement Sequencer
                  |
             atomic sequence
                  |
             previous_hash
                  |
                  v
             PostgreSQL
```

---

# 6.3 Sequencing implementation

Redis may provide the atomic sequence allocation:

```text
INCR audit_seq:{engagement_id}
```

but PostgreSQL remains authoritative for persisted audit state.

The sequence allocation and event persistence protocol must ensure that an event cannot be considered committed until its sequence and predecessor relationship are durable.

For high-integrity deployments, a single logical sequencer per engagement may serialize audit commits.

---

# 6.4 Audit event hash

Canonical event:

```text
engagement_id
sequence
event_type
actor
timestamp
payload
previous_hash
```

Hash:

```text
event_hash =
SHA256(canonical_event)
```

The resulting chain is:

```text
E1
 ↓
E2
 ↓
E3
 ↓
E4
```

Concurrent workers cannot independently create competing predecessor states.

---

# 7. APPROVAL BATCH CRYPTOGRAPHY

## 7.1 Canonical request

Each request is serialized deterministically.

Example:

```json
{
  "tool": "http_request",
  "method": "GET",
  "target": "https://app.example.test/api/users",
  "arguments": {},
  "scope_version": 4
}
```

Canonical serialization is hashed:

```text
request_hash = SHA256(canonical_request)
```

---

# 7.2 Merkle construction

For:

```text
R1
R2
R3
R4
```

compute:

```text
H1 = SHA256(R1)
H2 = SHA256(R2)
H3 = SHA256(R3)
H4 = SHA256(R4)

H12 = SHA256(H1 || H2)
H34 = SHA256(H3 || H4)

ROOT = SHA256(H12 || H34)
```

Approval stores:

```text
ROOT
scope_version
request_count
expiry
engagement_id
```

Execution verifies the request membership proof.

---

# 7.3 Batch restrictions

Batch approval is forbidden when:

* risk is high/critical;
* operations are heterogeneous;
* scope versions differ;
* target authorization differs;
* policy profiles differ;
* request arguments change;
* expiry has passed.

---

# 8. DETERMINISTIC FINDING VALIDATION

## 8.1 Validation architecture

```text
Observation
    ↓
LLM hypothesis
    ↓
Candidate Finding
    ↓
Evidence Correlation
    ↓
Deterministic Validator
    ↓
VALIDATED
    ↓
Human Review
    ↓
HUMAN_CONFIRMED
```

---

# 8.2 Deterministic validators

Examples:

```text
HTTP differential validator
Authorization replay validator
Schema invariant validator
Response comparison validator
Known-vulnerability reproduction
Safe proof-of-condition validator
```

Validators must produce:

```text
validator_id
method
input_hash
output_hash
evidence
timestamp
scope_version
```

---

# 8.3 Prohibited validation

The following cannot validate a finding:

```text
LLM confidence > threshold
LLM says "confirmed"
LLM-generated prose
LLM-generated severity
Single speculative observation
```

---

# 9. ERROR HANDLING

Stable error taxonomy:
=======
## 4.1 Runtime topology

Development:

```text
Developer
  |
  +-- FastAPI
  +-- ARQ worker
  +-- PostgreSQL
  +-- Redis
  +-- Docker sandbox
  +-- LLM provider
```

Production target:

```text
Load Balancer
      |
  API replicas
      |
PostgreSQL HA
      |
Redis HA / managed queue
      |
Worker pool
      |
Ephemeral execution runtimes
      |
Controlled external tools / HTTP targets
```

## 4.2 Scaling strategy

### API

- Stateless application replicas where possible.
- No security state held only in process memory.
- Connection pool sizing based on PostgreSQL capacity.
- Per-user/tenant/engagement rate limits in enterprise deployment.

### Workers

- Separate queues for low-risk analysis and gated/high-risk work.
- Bounded concurrency per worker.
- Per-engagement concurrency budget.
- Global platform execution budget.
- Dead-letter handling for irrecoverable tasks.

### PostgreSQL

- Proper indexes listed in the schema section.
- Connection pooling.
- Transactional approval and execution state transitions.
- Point-in-time recovery for production deployments.
- Read replicas only for non-authoritative analytics; security decisions must use authoritative state.

### Redis

Use Redis for:

- task queue/broker;
- ephemeral coordination;
- bounded cache;
- rate-limit counters.

Do not treat Redis as the authoritative source for security decisions.

## 4.3 Rate limiting

Minimum logical limits:

| Resource | Default target |
|---|---:|
| API requests/user | 120/min |
| LLM requests/engagement | 60/min |
| Web requests/engagement | 20 concurrent |
| Crawl pages/task | 1,000 |
| Crawl requests/task | 2,000 |
| HTTP response | 5 MiB |
| OpenAPI document | 5 MiB |
| GraphQL response | 1 MiB |
| Candidate tool arguments | 256 KiB |

These values must be configurable through a validated policy profile and cannot be increased by LLM output.

## 4.4 Resource isolation

Each execution must have:

- CPU limit;
- memory limit;
- process/PID limit;
- wall-clock deadline;
- output-size limit;
- network policy;
- filesystem policy;
- environment-variable allowlist;
- temporary workspace with cleanup.

The existing Phase 2 architecture already documents LocalSafeRuntime and DockerSandboxRuntime with least-privilege execution. fileciteturn7file0L2-L2

## 4.5 Security requirements

### Transport

- TLS 1.2+; TLS 1.3 preferred.
- HSTS for externally exposed web console/API.
- Secure cookie attributes for browser sessions.
- No credentials in URLs.

### Encryption

- PostgreSQL storage encrypted at rest in production.
- Object/evidence storage encrypted at rest.
- Secret manager/KMS for provider and target credentials.
- Key rotation supported.

### Authentication / authorization

Core local deployment may use operator authentication appropriate to the environment. Enterprise deployment must provide:

- OIDC/SAML SSO;
- RBAC;
- least privilege;
- MFA through the identity provider;
- session timeout;
- audit of administrative actions.

Suggested roles:

```text
VIEWER
ANALYST
APPROVER
ENGAGEMENT_MANAGER
PLATFORM_ADMIN
SECURITY_ADMIN
```

No role should automatically bypass ScopeGuard.

### Data privacy

- Data minimization for evidence.
- Configurable evidence retention.
- Redaction before remote LLM transmission.
- Tenant/engagement isolation.
- Export/delete workflows subject to audit and retention policy.
- Data residency controls for enterprise deployment.

### Supply chain

- Lock dependencies.
- Generate SBOM for release builds.
- Scan container images and Python dependencies.
- Sign release artifacts where deployment maturity requires it.
- Pin base images to reviewed versions/digests.

## 4.6 SSRF requirements

All server-side HTTP operations must pass:

```text
URL parser
→ canonicalization
→ scheme allowlist
→ DNS resolution
→ IP classification
→ ScopeGuard
→ connection
```

Redirects repeat the validation process for every hop.

Blocked categories include:

- loopback;
- RFC1918 private networks;
- link-local;
- cloud metadata endpoints;
- unsupported schemes;
- ambiguous/malformed host representations.

## 4.7 Authentication/session requirements

Session references must be:

- random/opaque;
- engagement-bound;
- target-origin-bound;
- scope-version-aware;
- time-limited;
- revocable;
- non-transferable across engagements.

Raw secrets must be injected only into execution contexts that have passed authorization.

---

# 5. ERROR HANDLING & OBSERVABILITY

## 5.1 Error taxonomy

Every subsystem should emit structured errors with stable codes.

Example categories:
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef

```text
VALIDATION_ERROR
SCOPE_DENIED
POLICY_DENIED
APPROVAL_REQUIRED
APPROVAL_INVALID
APPROVAL_EXPIRED
<<<<<<< HEAD
APPROVAL_SCOPE_MISMATCH
=======
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
SESSION_INVALID
SESSION_EXPIRED
SSRF_BLOCKED
REDIRECT_BLOCKED
RESOURCE_LIMIT
TOOL_NOT_FOUND
TOOL_EXECUTION_FAILED
TARGET_TIMEOUT
LLM_PROVIDER_ERROR
LLM_TIMEOUT
LLM_INVALID_OUTPUT
DATABASE_ERROR
QUEUE_ERROR
CHECKPOINT_ERROR
EVIDENCE_ERROR
<<<<<<< HEAD
AUDIT_SEQUENCE_ERROR
INTERNAL_ERROR
```

Security-sensitive errors must not reveal:

* secrets;
* internal credentials;
* infrastructure topology;
* secret-manager identifiers;
* raw provider responses.

---

# 10. GRACEFUL DEGRADATION

## LLM failure

```text
Retry bounded
   ↓
Configured fallback if policy permits
   ↓
Otherwise pause workflow
```

The system must never infer an action because the LLM failed.

---

## Redis failure

```text
Stop new asynchronous execution
```

Existing authoritative state remains in PostgreSQL.

---

## PostgreSQL failure

Fail closed.

No new security-sensitive execution may be authorized without authoritative state.

---

## Sandbox failure

Never fall back to unsandboxed execution.

---

## Target failure

Record:

```text
TARGET_TIMEOUT
TARGET_UNAVAILABLE
TARGET_CONNECTION_ERROR
```

Do not classify target failure as compromise.

---

# 11. OBSERVABILITY

## 11.1 Structured correlation

Every operation propagates:

```text
request_id
engagement_id
workflow_run_id
task_id
candidate_request_id
policy_decision_id
approval_id
execution_id
evidence_sha256
```

---

# 11.2 Required metrics

### Safety

```text
scope_escape_total
unauthorized_execution_total
approval_bypass_total
secret_leak_total
```

Every value must remain:

```text
0
```

---

### Agent

```text
llm_invocations_total
llm_latency_ms
llm_tokens_total
llm_cost_usd
candidate_requests_total
candidate_rejection_total
replanning_total
```

---

### Product

```text
useful_autonomous_actions_total
validated_findings_total
human_confirmed_findings_total
ttff_seconds
analyst_time_seconds
```

---

### Platform

```text
api_latency
api_errors
queue_depth
queue_age
worker_utilization
database_pool_usage
sandbox_count
sandbox_failure_rate
evidence_bytes
```

---

# 11.3 Alerting

| Condition                | Threshold          |
| ------------------------ | ------------------ |
| Unauthorized execution   | Immediate critical |
| Scope escape             | Immediate critical |
| Approval bypass          | Immediate critical |
| Secret leak              | Immediate critical |
| Sandbox escape indicator | Immediate critical |
| Audit sequencing failure | Immediate critical |
| API 5xx                  | >2% for 5 min      |
| Worker failures          | >5% for 10 min     |
| Queue age                | >5 min             |
| PostgreSQL saturation    | >80%               |
| LLM invalid output       | >10% for 15 min    |

---

# 12. LLM ARCHITECTURE

## 12.1 Reference provider

The production reference path is:

```text
ARKA
 ↓
LLMGateway
 ↓
LiteLLM
 ↓
OpenRouter
 ↓
Configured model
```

The existing Nemotron/OpenRouter path remains a regression-critical configuration.

---

# 12.2 Provider abstraction

Provider interface:

```python
class LLMProvider:
    async def complete(...)
    async def structured(...)
    async def health(...)
    def capabilities(...)
```

Provider implementations must not receive security authority.

---

# 12.3 Capability model

Providers advertise capabilities:

```text
structured_output
tool_proposal
long_context
vision
streaming
reasoning
```

The agent must request only capabilities it requires.

---

# 12.4 LLM data minimization

Remote LLM payloads must exclude:

* credentials;
* raw session cookies;
* bearer tokens;
* secret references;
* unnecessary HTTP bodies;
* unnecessary personal information.

Sensitive evidence must be redacted before model transmission.

---

# 13. PERFORMANCE ENGINEERING

## 13.1 LLM efficiency

The Deterministic Investigation Planner reduces unnecessary LLM calls.

Example:

```text
LLM:
"Map API surface"

Planner:
  OpenAPI discovery
  endpoint extraction
  parameter normalization
  security-scheme extraction
  evidence creation
```

The LLM is called again only when interpretation or prioritization is required.

---

# 13.2 Database efficiency

PostgreSQL queries must:

* use indexed foreign keys;
* paginate evidence and findings;
* avoid loading large payloads;
* avoid unbounded JSON aggregation;
* use transactions for security-state changes;
* use recursive CTEs for graph-like queries.

---

# 13.3 Graph requirements without graph database

Attack-path structures are initially represented relationally:

```text
nodes
edges
relationships
```

PostgreSQL recursive CTEs provide traversal.

Example conceptual query:

```sql
WITH RECURSIVE attack_path AS (
    SELECT
        source_id,
        target_id,
        1 AS depth
    FROM attack_edges
    WHERE source_id = $1

    UNION ALL

    SELECT
        e.source_id,
        e.target_id,
        ap.depth + 1
    FROM attack_edges e
    JOIN attack_path ap
      ON e.source_id = ap.target_id
    WHERE ap.depth < $2
)
SELECT *
FROM attack_path;
```

A graph database is not introduced unless measured workloads prove PostgreSQL inadequate.

---

# 14. CLI REQUIREMENTS

The CLI is the primary operator interface until a web console is justified by user evidence.

Required commands:

```text
arka engagement create
arka engagement start
arka engagement pause
arka engagement stop
arka engagement status

arka scope show
arka scope expand

arka approvals list
arka approvals show
arka approvals approve
arka approvals reject

arka findings list
arka findings show
arka findings validate
arka findings confirm

arka evidence get
arka audit list

arka llm status
arka report generate
```

The CLI must never expose raw credentials.

---

# 15. TECHNICAL MILESTONES

## Milestone 0 — Baseline synchronization

* Synchronize documentation.
* Freeze control-plane invariants.
* Verify current OAT baseline.
* Add ADRs.

---

## Milestone 1 — Deterministic Investigation Planner

Implement:

```text
intent schema
planner registry
task expansion
task budgets
planner-to-control-plane integration
```

Exit:

```text
LLM produces high-level intent
Planner creates deterministic tasks
Every task still traverses authorization
```

---

## Milestone 2 — Core persistence completion

Implement:

```text
workflow_runs
tasks
candidate_tool_requests
policy_decisions
observations
finding_evidence
llm_invocations
```

Exit:

```text
Every security-critical state transition is durable.
```

---

## Milestone 3 — Evidence storage separation

Implement:

```text
PostgreSQL metadata
+
S3/MinIO/local object storage
```

Exit:

```text
Large payloads do not live in relational rows.
```

---

## Milestone 4 — Audit sequencer

Implement:

```text
per-engagement sequence
atomic sequence allocation
ordered persistence
hash-chain verification
concurrency tests
```

Exit:

```text
Concurrent workers cannot create audit-chain forks.
```

---

## Milestone 5 — Epistemic validation

Implement:

```text
OBSERVED
CANDIDATE
SUPPORTED
VALIDATED
HUMAN_CONFIRMED
```

and deterministic transition enforcement.

Exit:

```text
LLM cannot produce VALIDATED or HUMAN_CONFIRMED.
```

---

## Milestone 6 — Scope Delta

Implement:

```text
out-of-scope discovery
scope delta generation
operator review
immutable scope version
approval invalidation
resume
```

Exit:

```text
Assessment can expand scope without restart.
```

---

## Milestone 7 — Phase 3.6

Implement:

* authentication profiles;
* credential references;
* session manager;
* target-origin binding;
* scope-version binding;
* expiry;
* revocation.

---

## Milestone 8 — Phase 3.7

Implement:

* authenticated crawler;
* session-aware HTTP;
* authorization-state modeling;
* bounded authenticated traversal.

---

## Milestone 9 — Phase 3.8

Implement:

* differential authorization testing;
* object identifier analysis;
* controlled state transitions;
* deterministic validators;
* evidence-backed finding promotion.

---

## Milestone 10 — Phase 3.9

Implement:

```text
Web Security Agent
```

with:

```text
LLM reasoning
→ intent
→ deterministic planner
→ candidate requests
→ control plane
→ execution
→ observations
→ validation
```

---

# 16. TESTING REQUIREMENTS

Testing must exist at eight levels:

```text
1. Unit
2. Schema
3. Integration
4. Security/adversarial
5. Runtime
6. Live LLM
7. Real controlled target
8. Failure/concurrency
```

---

# 16.1 Security tests

Required adversarial cases:

* scope bypass;
* exclusion precedence;
* IPv4 bypass;
* IPv6 bypass;
* DNS rebinding;
* redirect SSRF;
* encoded IP;
* decimal IP;
* credential leakage;
* prompt injection;
* malformed candidate requests;
* approval replay;
* approval expiry;
* approval scope mismatch;
* batch Merkle tampering;
* task duplication;
* worker restart;
* audit concurrency;
* finding-state privilege escalation.

---

# 16.2 Product benchmark

The primary benchmark environment should include:

```text
OWASP Juice Shop
```

Measure:

```text
coverage
TTFF
validated findings
false positives
useful action rate
analyst intervention
LLM calls
LLM cost
assessment duration
```

---

# 16.3 Agent A/B benchmark

Run:

```text
A: deterministic ARKA
B: ARKA + LLM reasoning
C: manual baseline
```

Compare:

* authorized surface coverage;
* useful actions;
* validated findings;
* analyst time;
* TTFF;
* cost;
* evidence quality.

The purpose is to prove that the LLM provides measurable security-assessment value rather than simply adding architectural complexity.

---

# 17. TECHNICAL RISKS

## Risk 1 — Authorization TOCTOU

Mitigation:

* immutable scope versions;
* execution-time revalidation;
* request hashes;
* transactional state.

---

## Risk 2 — DNS rebinding

Mitigation:

* resolution immediately before connection;
* IP classification;
* controlled connection destination;
* redirect revalidation.

---

## Risk 3 — LLM output drift

Mitigation:

* strict schemas;
* deterministic planner;
* provider regression tests;
* runtime OAT.

---

## Risk 4 — Worker duplicate execution

Mitigation:

* idempotency key;
* unique execution request hash;
* execution leases;
* approval binding.

---

## Risk 5 — Credential contamination

Mitigation:

* opaque references;
* runtime-only injection;
* redaction;
* prompt minimization.

---

## Risk 6 — Evidence explosion

Mitigation:

* content addressing;
* gzip;
* object storage;
* retention policies;
* deduplication.

---

## Risk 7 — Audit race

Mitigation:

* per-engagement sequencer;
* atomic sequence allocation;
* ordered persistence;
* concurrency verification.

---

## Risk 8 — LLM cost/latency

Mitigation:

* deterministic investigation planner;
* caching;
* bounded reasoning;
* only invoke LLM for ambiguous/high-value decisions.

---

## Risk 9 — Architecture drift

Mitigation:

* security ADRs;
* control-plane regression tests;
* mandatory OAT;
* code-review rule requiring all new tools to traverse ToolRegistry → ScopeGuard → PolicyEngine.

---

# 18. ARCHITECTURAL DECISIONS

The following decisions are now explicit.

## ADR-001 — Deterministic authority

**Decision:** LLMs never possess execution authority.

---

## ADR-002 — Deterministic Investigation Planner

**Decision:** Routine investigation workflows are expanded deterministically rather than individually generated by the LLM.

---

## ADR-003 — PostgreSQL as authoritative security state

**Decision:** PostgreSQL remains the authoritative store for security-critical state.

---

## ADR-004 — Object storage for bulk evidence

**Decision:** Large evidence payloads are stored outside PostgreSQL.

---

## ADR-005 — No graph database

**Decision:** Graph relationships are represented relationally until measured workload evidence justifies a dedicated graph engine.

---

## ADR-006 — Two application roles

**Decision:**

```text
Operator
Approver
```

Enterprise RBAC is deferred.

---

## ADR-007 — OpenRouter reference path

**Decision:** OpenRouter is the primary production reference adapter. Other providers remain compatibility adapters rather than parallel optimization targets.

---

## ADR-008 — Epistemic validation

**Decision:** LLM reasoning cannot promote findings to `VALIDATED`.

---

## ADR-009 — Scope Delta

**Decision:** Scope expansion occurs through immutable, operator-approved scope versions and never by discovery inheritance.

---

## ADR-010 — Cryptographically bound approvals

**Decision:** Batch approvals bind to the exact request set through a Merkle root.

---

# 19. OPERATIONAL DEFINITION OF DONE

The system is technically ready for the next major milestone when:

```text
[ ] LLM remains untrusted
[ ] Deterministic planner exists
[ ] CandidateToolRequest remains non-authoritative
[ ] ToolRequest requires deterministic authorization
[ ] ScopeGuard is enforced before execution
[ ] DISCOVERED != AUTHORIZED
[ ] Scope versions are immutable
[ ] Scope Delta workflow is implemented
[ ] Approval requests are contextual
[ ] Batch approvals use cryptographic binding
[ ] Execution is idempotent
[ ] Credentials never enter LLM authority
[ ] SSRF is defended at DNS/IP/redirect/connection layers
[ ] Evidence metadata is relational
[ ] Bulk evidence is object-backed
[ ] Observations are first-class
[ ] Findings use the five-tier epistemic ladder
[ ] LLM cannot mark findings VALIDATED
[ ] Human confirmation is explicitly authorized
[ ] Workflow state is durable
[ ] Tasks are retry-bounded
[ ] Policy decisions are durable
[ ] LLM invocation cost/latency is measurable
[ ] Audit sequencing is concurrency-safe
[ ] Redis is not authoritative
[ ] PostgreSQL is authoritative
[ ] No graph database dependency exists
[ ] OpenRouter reference path is regression-tested
[ ] Security adversarial suite passes
[ ] Runtime OAT passes
[ ] Live LLM OAT passes
[ ] Juice Shop benchmark passes
[ ] Restart/recovery passes
[ ] Documentation matches implementation
```

---

# 20. FINAL ARCHITECTURAL PRINCIPLE

ARKA is not designed around the assumption:

```text
"Give an AI a shell and make it a pentester."
```

ARKA is designed around:

```text
Human authorization
       ↓
LLM reasoning
       ↓
High-level security intent
       ↓
Deterministic Investigation Planner
       ↓
CandidateToolRequest
       ↓
ScopeGuard
       ↓
PolicyEngine
       ↓
ApprovalManager
       ↓
Authoritative ToolRequest
       ↓
Bounded Execution
       ↓
Evidence
       ↓
Observation
       ↓
Epistemic Finding Ladder
       ↓
Deterministic Validation
       ↓
Human Confirmation
```

The architectural contract is therefore:

> **The model may decide what is worth investigating. Deterministic systems decide what is permitted. The execution layer performs only what has been authorized. Evidence determines what is known. Humans determine what is finally accepted.**

That is ARKA's core technical identity.
=======
INTERNAL_ERROR
```

Security-sensitive errors should not reveal implementation secrets or credentials.

## 5.2 Graceful degradation

### LLM provider unavailable

- Retry within bounded policy.
- Use configured fallback provider/model if permitted.
- Preserve workflow state.
- If no safe provider exists, pause rather than execute guessed actions.

### Redis unavailable

- Do not enqueue new execution work.
- Preserve durable state in PostgreSQL where possible.
- Return explicit degraded status.

### PostgreSQL unavailable

- No security-sensitive state transitions should be treated as successful.
- Do not execute actions requiring authoritative state.
- Return degraded/fail-closed status.

### Target unavailable

- Mark task failed/blocked according to error type.
- Preserve evidence of the failure.
- Permit bounded retry.
- Do not infer target compromise from availability failure.

### Sandbox unavailable

- Do not execute outside the approved runtime.
- Mark execution blocked.
- Audit the failure.

## 5.3 Structured logging

Every security-relevant log should contain where applicable:

```json
{
  "timestamp": "...",
  "level": "INFO",
  "request_id": "uuid",
  "engagement_id": "uuid",
  "task_id": "uuid",
  "candidate_id": "uuid",
  "tool_request_id": "uuid",
  "tool_name": "http_request",
  "policy_decision": "ALLOW",
  "scope_decision": "ALLOW",
  "approval_state": "NOT_REQUIRED",
  "execution_id": "uuid"
}
```

Never log:

- passwords;
- API keys;
- bearer tokens;
- session cookies;
- full secret-bearing request headers;
- raw credential references if they could reveal secret-manager structure.

## 5.4 Metrics

Required metrics:

### Platform

- API request latency/error rate
- active engagements
- running tasks
- queue depth
- worker utilization
- database pool utilization
- Redis health

### Security

- scope denials
- policy denials
- approval requests
- approval latency
- approval rejection rate
- SSRF blocks
- redirect blocks
- unauthorized candidate requests
- tool execution failures
- sandbox failures

### Agent

- LLM requests
- LLM latency
- token usage
- provider failure rate
- fallback rate
- invalid structured outputs
- replanning count
- tool proposal rejection rate

### Assessment

- assets discovered
- endpoints discovered
- evidence generated
- findings observed/suspected/validated/false-positive
- validation rate
- report generation time

## 5.5 Alert thresholds

Initial operational alerts:

| Condition | Threshold |
|---|---|
| API 5xx | > 2% for 5 min |
| API p95 latency | > 1 s for 10 min |
| Worker failure rate | > 5% for 10 min |
| Queue age | > 5 min for normal work |
| PostgreSQL connection saturation | > 80% for 10 min |
| Redis unavailable | Immediate |
| ScopeGuard failures | Any unexpected internal error |
| Approval bypass detection | Immediate / critical |
| Secret-leak detector | Immediate / critical |
| Sandbox escape indicator | Immediate / critical |
| Unexpected out-of-scope request | Immediate / critical |
| Repeated LLM invalid outputs | > 10% over 15 min |

## 5.6 Tracing

Propagate a correlation ID across:

```text
API
→ workflow
→ LLM call
→ candidate request
→ policy decision
→ approval
→ execution
→ evidence
→ audit
```

LLM traces must sanitize prompts and outputs before external observability systems receive them.

---

# 6. TECHNICAL MILESTONES & IMPLEMENTATION PLAN

## Milestone 0 — Architecture baseline and repository synchronization

### Work

- Synchronize README status with actual implementation.
- Mark Phase 2 and Phase 3.1–3.5 correctly.
- Record OAT baseline.
- Freeze core security invariants.
- Add/update ADRs for major architectural changes.

### Exit criteria

- Documentation matches source tree.
- Existing OAT baseline remains reproducible.
- No Phase 1–3.5 security regression.

---

## Milestone 1 — Security Architecture Hardening

### Work

1. Review ScopeGuard canonicalization.
2. Strengthen DNS/IPv4/IPv6 handling.
3. Revalidate redirects per hop.
4. Harden ToolRegistry schemas.
5. Bind approvals to request hash and scope version.
6. Add execution idempotency.
7. Audit race conditions.
8. Harden EvidenceStore.
9. Harden AuditService.
10. Add secret-leak detection.
11. Add resource budgets.
12. Add structured security error codes.

### Exit criteria

- Security adversarial suite passes.
- No authorization bypass identified.
- Race tests pass.
- Secret-leak tests pass.

---

## Milestone 2 — Phase 3.6 Authentication & Session Foundation

### Work

- AuthProfile model.
- Credential references.
- Session model.
- Session manager.
- target-origin binding.
- scope-version binding.
- expiry/revocation.
- secret injection boundary.
- authentication telemetry.

### Exit criteria

- No raw credential reaches LLM.
- Session cannot cross engagement boundaries.
- Expired/revoked session cannot execute.
- Session state survives restart.

---

## Milestone 3 — Phase 3.7 Authenticated Web Analysis

### Work

- session-aware HTTP client;
- authenticated crawler;
- login/session detection;
- access-state tracking;
- bounded authenticated crawling;
- duplicate/cycle prevention;
- endpoint integration.

### Exit criteria

- Real authenticated Juice Shop test or equivalent controlled target passes.
- SSRF remains enforced under authenticated redirects.
- Discovery does not expand scope.

---

## Milestone 4 — Phase 3.8 Business Logic / Access Control Analysis

### Work

- controlled request variants;
- object identifier analysis;
- role/context comparison;
- response differential analysis;
- state-transition observations;
- confidence scoring;
- validation lifecycle;
- evidence linkage.

### Exit criteria

- Potential authorization anomalies are reported as observations until validated.
- Tests cannot cause uncontrolled destructive behavior.
- Findings retain reproducible evidence.

---

## Milestone 5 — Phase 3.9 Web Security Agent

### Work

- unified web assessment state;
- evidence-aware planning;
- discovery prioritization;
- controlled re-planning;
- deterministic tool selection enforcement;
- approval-aware planning;
- task cancellation;
- durable checkpoint recovery.

### Exit criteria

A live LLM-driven assessment demonstrates:

```text
LLM
→ CandidateToolRequest
→ deterministic gates
→ execution
→ evidence
→ correlation
→ validation
→ report
```

without any direct LLM execution path.

---

## Milestone 6 — Operational Reliability

### Work

- queue retry policies;
- idempotency;
- execution leases;
- cancellation propagation;
- worker restart recovery;
- API restart recovery;
- database transaction hardening;
- health/readiness endpoints;
- resource monitoring.

### Exit criteria

- Failure injection tests pass.
- No duplicate gated execution.
- Recovery does not bypass approval or scope validation.

---

## Milestone 7 — API / CLI / Operator Experience

### Work

- API consistency.
- CLI parity.
- structured output.
- approval UX.
- live assessment status.
- findings/evidence views.
- report generation.

### Exit criteria

A security operator can complete the core workflow without directly accessing internal Python APIs.

---

## Milestone 8 — Phase 3.6–3.9 OAT

### Required test layers

1. Unit.
2. Security/adversarial.
3. Integration.
4. Runtime.
5. Live LLM.
6. Real controlled target.
7. Restart/recovery.
8. Concurrency/race testing.

### Required target

Use a controlled application such as OWASP Juice Shop and dedicated test fixtures for:

- authentication;
- redirects;
- SSRF;
- OpenAPI;
- GraphQL;
- access-control differences;
- oversized responses;
- failures.

### Required final evidence

Produce:

```text
SOURCE_INSPECTED
STATICALLY_VERIFIED
UNIT_TESTED
INTEGRATION_TESTED
RUNTIME_TESTED
LIVE_LLM_TESTED
REAL_TARGET_TESTED
ADVERSARIAL_TESTED
```

Never label unexecuted tests as passed.

---

# TECHNICAL RISKS & ARCHITECTURAL UNKNOWNS

## Risk 1 — Authorization TOCTOU

**Problem:** Scope or approval state can change between validation and execution.  
**Mitigation:** Immutable scope snapshots, transactional state, request hashes and execution-time revalidation.

## Risk 2 — DNS rebinding

**Problem:** Host resolution can change after validation.  
**Mitigation:** Resolve and validate immediately before connection; control connection destination; reject ambiguous resolution; revalidate redirects.

## Risk 3 — LLM output drift

**Problem:** Provider/model changes can alter tool proposal behavior.  
**Mitigation:** strict schemas, deterministic gates, model/provider regression tests and live OAT.

## Risk 4 — Worker duplicate execution

**Problem:** At-least-once queues can produce duplicates.  
**Mitigation:** execution leases, request hashes, idempotency and approval binding.

## Risk 5 — Credential contamination

**Problem:** Authenticated responses may contain secrets or personal data.  
**Mitigation:** redaction pipeline, evidence sensitivity classes, LLM prompt minimization and secret references.

## Risk 6 — Resource exhaustion

**Problem:** Targets or documents can deliberately cause high CPU/memory/network use.  
**Mitigation:** strict budgets at HTTP, parser, crawler, worker and sandbox layers.

## Risk 7 — Architecture drift

**Problem:** New agent/tool features may bypass the established control plane.  
**Mitigation:** architectural review, security ADRs, mandatory control-path tests and OAT regression gates.

## Risk 8 — Remote LLM data exposure

**Problem:** Assessment data may be sent to third-party model providers.  
**Mitigation:** data minimization, configurable provider policy, sensitive-data redaction, local/VPC model options and enterprise residency controls.

## Risk 9 — Documentation divergence

**Problem:** Current README/roadmap status can lag behind actual implementation.  
**Mitigation:** documentation synchronization is a release acceptance criterion.

---

# ARCHITECTURAL DECISIONS REQUIRED BEFORE PHASE 4

1. Whether credential storage uses an external KMS/secrets manager or a local development abstraction.
2. Whether PostgreSQL remains sufficient for Phase 5 attack graphs or a graph database becomes justified.
3. Whether the future UI is a separate frontend service or server-rendered/API-driven application.
4. Exact enterprise RBAC/tenant isolation model.
5. Evidence blob storage backend for production-scale assessments.
6. Remote versus local LLM data handling policy.
7. Exploit authorization model for Phase 4.
8. Maximum autonomy policy per assessment profile.

Until these decisions are resolved, implementation should favor interfaces that preserve the existing deterministic control plane and avoid irreversible infrastructure coupling.

---

# FINAL TECHNICAL DEFINITION OF DONE

The architecture is ready for the next major phase only when:

```text
[ ] Core control plane remains authoritative
[ ] CandidateToolRequest remains untrusted
[ ] ToolRequest can only be minted after deterministic validation
[ ] ScopeGuard is enforced at discovery and execution boundaries
[ ] DISCOVERED != AUTHORIZED is preserved
[ ] Approval is contextual and scope-version-bound
[ ] Execution is idempotent and bounded
[ ] Sandboxes remain least privilege
[ ] Credentials remain outside LLM authority
[ ] SSRF is defended at DNS/IP/redirect/connection layers
[ ] Evidence is content-addressed and immutable
[ ] Audit records are append-only and integrity protected
[ ] PostgreSQL is authoritative for security state
[ ] Redis is not authoritative for authorization
[ ] Worker retries cannot bypass policy
[ ] API/worker restart recovery is verified
[ ] Authentication sessions are isolated
[ ] Web analysis remains bounded
[ ] Findings retain provenance
[ ] LLM provider failures fail safely
[ ] Secret-leak tests pass
[ ] Concurrency tests pass
[ ] Security regression tests pass
[ ] Runtime OAT passes
[ ] Documentation matches implementation
```

**Architecture principle:** ARKA's intelligence may become increasingly autonomous; its authority must not.
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
