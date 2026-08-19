# ARKA Documentation

Welcome to the technical documentation repository for **ARKA (Autonomous Risk Knowledge & Assessment)**.

ARKA is an AI-orchestrated, authorized penetration testing platform built on a deterministic zero-trust architecture. All security operations, tool executions, and state transitions are explicitly scoped, policy-controlled, human-gated when necessary, and immutably audited.

---

## Documentation Directory Structure

```
docs/
├── README.md                           # Master documentation index (this file)
│
├── architecture/                       # System and subsystem architecture specifications
│   ├── overview.md                     # High-level architecture and component topology
│   ├── system-architecture.md          # Architectural tiers, data flow, and lifecycle
│   ├── control-plane.md                # Agent control plane, orchestration, and state machine
│   ├── execution-plane.md              # Tool execution boundaries, workers, and isolation
│   ├── agent-architecture.md           # Agent design, LangGraph integration, and state contracts
│   ├── llm-architecture.md             # Provider abstraction, routing, token tracking, fallbacks
│   ├── data-architecture.md            # Storage layers, checkpointing, and cache topology
│   └── trust-boundaries.md            # Zero-trust model and authoritative enforcement pipeline
│
├── security/                           # Security specifications, threat model, and controls
│   ├── security-model.md               # Core security philosophy and invariant principles
│   ├── scope-enforcement.md            # Deterministic ScopeGuard, subnet containment, exclusions
│   ├── policy-engine.md                # Authoritative PolicyEngine and risk evaluation
│   ├── approval-system.md              # Persistent human-in-the-loop approval state machine
│   ├── tool-execution-security.md      # Sandboxing, parameter validation, and safety controls
│   ├── audit-model.md                  # Append-only audit trail, secret sanitization, integrity
│   └── threat-model.md                 # Threat matrix, attack vectors, and mitigations
│
├── agents/                             # Agent implementations and workflow definitions
│   ├── overview.md                     # Agent taxonomy, lifecycle, and contracts
│   └── orchestrator.md                 # Orchestrator graph, state transitions, and node logic
│
├── llm/                                # LLM Gateway, provider integration, and prompt contracts
│   ├── providers.md                    # Supported LLM providers, model mapping, and fallback
│   ├── gateway.md                      # LLMGateway architecture, error normalization, and retries
│   ├── structured-output.md            # JSON schema output enforcement and parsing strategies
│   └── multimodal.md                   # Multimodal payload serialization and ingestion
│
├── tools/                              # Tool registry, interfaces, and executors
│   ├── registry.md                     # ToolRegistry catalog, definition schema, and registration
│   ├── execution.md                    # Execution pipeline, input validation, and timeouts
│   └── mock-tools.md                   # Safe mock executors for test automation and validation
│
├── data/                               # Persistence, data models, and migration guides
│   ├── database.md                     # PostgreSQL database architecture and connection pooling
│   ├── models.md                       # SQLAlchemy ORM and Pydantic state model schemas
│   ├── migrations.md                   # Alembic migration management and revision history
│   └── persistence.md                  # Durable LangGraph checkpoints and Redis task queue
│
├── api/                                # HTTP API reference and integration contracts
│   └── overview.md                     # FastAPI REST API endpoints, schemas, and lifecycle
│
├── cli/                                # Command-line interface reference
│   └── commands.md                     # Typer CLI reference, subcommands, and operational usage
│
├── testing/                            # Testing strategy, test suites, and quality gates
│   ├── strategy.md                     # Testing philosophy, zero-real-offense rule, and gates
│   ├── unit-tests.md                   # Unit test catalog (ScopeGuard, PolicyEngine, Registry)
│   ├── integration-tests.md            # End-to-end integration and mock tool test suites
│   └── security-tests.md               # Audit immutability, tamper resistance, and scoping tests
│
├── operations/                         # Deployment, runtime configuration, and operations
│   ├── configuration.md                # Environment variables reference and secrets backend
│   ├── local-development.md            # Local development setup, uv, and test execution
│   ├── docker.md                       # Docker Compose multi-container environment
│   └── troubleshooting.md              # Common failure modes, diagnostics, and recovery
│
├── phases/                             # Project phase documentation and roadmaps
│   ├── phase-1.md                      # Phase 1: Secure Agent Control Plane (COMPLETED)
│   ├── phase-1-hardening.md            # Detailed Phase 1 hardening audit and change log
│   ├── phase-2.md                      # Phase 2: Secure Tool Execution & Recon (PLANNED)
│   └── roadmap.md                      # Multi-phase master roadmap and implementation milestones
│
└── decisions/                          # Architecture Decision Records (ADRs)
    ├── ADR-001-api-first-llm-architecture.md
    ├── ADR-002-langgraph-agent-orchestration.md
    ├── ADR-003-deterministic-scopeguard-and-policy-engine.md
    ├── ADR-004-tool-registry-execution-boundary.md
    ├── ADR-005-postgresql-for-persistent-state.md
    ├── ADR-006-postgresql-langgraph-checkpoints.md
    ├── ADR-007-persistent-human-approval-workflow.md
    ├── ADR-008-append-only-audit-architecture.md
    ├── ADR-009-arq-instead-of-celery.md
    └── ADR-010-remote-llm-by-default-with-vpc-support.md
```

---

## Status Classification

Throughout this documentation, all features and components are explicitly tagged with their current implementation status:

| Status | Definition |
|---|---|
| **`IMPLEMENTED`** | Completely implemented, covered by automated test suites, and verified in CI. |
| **`PLANNED`** | Formally designed for a future phase; no production code exists in the repository yet. |
| **`EXPERIMENTAL`** | Prototype or preview feature subject to architectural refactoring. |
| **`DEFERRED`** | Postponed to a later phase or superseded by an alternative architecture. |

---

## Core Principles

1. **Deterministic Authority**: The LLM is an untrusted planner. Authorization decisions, scope enforcement, and execution permissions are executed strictly by deterministic Python components.
2. **Exclusions Override Inclusions**: In scope management, an excluded domain, IP, CIDR subnet, or port always supersedes any overlapping inclusion.
3. **Persistent Approvals**: High and Critical risk actions require human authorization stored persistently in PostgreSQL and bound to the exact `(engagement_id, task_id, tool_name, target)`.
4. **Append-Only Immutability**: All security actions produce an append-only audit event with credential sanitization and defensive memory copying.
5. **Zero Real Offense in Tests**: Automated test suites operate 100% in-memory with safe mock tools, executing zero network scanning or subshell commands.
