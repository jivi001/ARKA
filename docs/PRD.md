# ARKA — Product Requirements Document (PRD)

**Document status:** Proposed product baseline  
**Product:** ARKA — Autonomous Risk Knowledge & Assessment  
**Repository:** `jivi001/ARKA`  
**Date:** 2026-09-16  
**Audience:** Product, security engineering, platform engineering, application security, assessment operators, reviewers  
**Authorization model:** Authorized security assessments only

> **Source-of-truth note:** This PRD is grounded in the current GitHub repository structure and documentation plus the project's reported Phase 1–3.5 operational acceptance results. The repository README currently contains stale roadmap labels for Phases 2 and 3; the dedicated Phase 2 documentation marks its subphases complete, while the latest supplied OAT reports Phase 1, Phase 2, and Phase 3.1–3.5 as operationally passed. This document uses the latter as the current project baseline and identifies the README/roadmap synchronization as a documentation task.

---

## 1. EXECUTIVE SUMMARY & OBJECTIVES

### 1.1 Product overview

ARKA is an AI-orchestrated security assessment platform for authorized penetration testing and risk assessment. It combines autonomous reasoning with a deterministic security control plane so that an LLM can propose analysis actions without acquiring authority to execute them or change authorization boundaries.

The product is designed around a strict trust model:

```text
Human / Engagement Scope
        |
        v
LLM reasoning
        |
        v
CandidateToolRequest (UNTRUSTED)
        |
        v
ToolRegistry
        |
        v
ScopeGuard
        |
        v
PolicyEngine
        |
        +----> ApprovalManager for gated operations
        |
        v
Authoritative ToolRequest
        |
        v
ExecutionManager / Sandbox
        |
        v
EvidenceStore + Canonical Knowledge + AuditService
```

The existing repository uses Python 3.13+, FastAPI/Pydantic, LangGraph, LiteLLM, PostgreSQL/SQLAlchemy, Alembic, Redis/Arq, Typer/Rich, Structlog/Langfuse, Pytest/Ruff/Mypy. The documented architecture separates interface, orchestration/intelligence, security/policy, and execution/persistence tiers. fileciteturn6file0L2-L2

### 1.2 Current product baseline

The repository documents Phase 1 as the secure agent control plane and Phase 2 as secure execution/reconnaissance, including sandboxing, Nmap, Nuclei, ffuf, WhatWeb, Amass, canonical assets, EvidenceStore, ReconAgent, correlation and validation. fileciteturn7file0L2-L2

The latest project OAT supplied for this document reports Phase 1 through Phase 3.5 operationally accepted with a live OpenRouter → Nemotron-3 Ultra path and a local OWASP Juice Shop target. That OAT is the operational baseline for this PRD.

### 1.3 Product vision

ARKA should become a controlled autonomous security-assessment platform that can:

1. Establish explicit assessment scope and rules of engagement.
2. Discover network, web, API and application attack surface.
3. Analyze observations using LLM-assisted reasoning.
4. Execute only deterministic, policy-authorized actions.
5. Preserve evidence and provenance for every meaningful observation.
6. Validate and correlate findings before reporting them.
7. Require human authorization for operations whose risk exceeds the configured autonomy policy.
8. Maintain durable state across application and worker failures.
9. Produce reproducible technical and executive security outputs.
10. Progress toward controlled validation and attack-path analysis without weakening the control plane.

### 1.4 Business goals

| Goal | Why now | Product outcome |
|---|---|---|
| Reduce assessment analyst toil | Modern applications expose large and dynamic attack surfaces | Automate repetitive discovery and analysis while retaining human control over risky actions |
| Improve assessment consistency | Manual workflows vary by operator | Standardize scope, policy, evidence, validation and reporting |
| Make AI-assisted security safer | LLMs are useful planners but are not trusted authorization systems | Keep all authority in deterministic enforcement components |
| Increase evidence quality | Security findings require defensible provenance | Preserve content-addressed evidence and immutable audit history |
| Support modern application testing | Web/API surfaces increasingly dominate application attack paths | Provide HTTP, crawling, OpenAPI, GraphQL, authentication and business-logic analysis |
| Build toward enterprise deployment | Security teams need durable state, RBAC, observability and integrations | Establish a modular platform that can scale beyond a local assessment |

### 1.5 Value proposition

ARKA addresses the gap between conventional security automation, which is deterministic but often operationally fragmented, and LLM agents, which can reason across heterogeneous observations but must not be trusted with direct security authority.

The core value is **bounded autonomy**: ARKA can reason autonomously about what to investigate next while deterministic controls decide whether an action is permitted.

### 1.6 Product principles

1. **Authorized use only.** Every assessment operates under explicit authorization.
2. **LLM is untrusted.** The model is a planner, not an authority.
3. **Discovery never expands scope.** `DISCOVERED != AUTHORIZED`.
4. **Fail closed.** Ambiguous security state results in denial or safe termination.
5. **Human gates remain authoritative.** High-risk and destructive actions require explicit approval according to policy.
6. **Evidence is first-class.** Observations must retain provenance.
7. **Findings require validation.** Detection is not automatically confirmation.
8. **Deterministic security decisions.** Scope and policy decisions do not depend on LLM judgment.
9. **Least privilege.** Runtime, credentials, network access and persistence are minimized.
10. **Operational reproducibility.** Runtime acceptance tests are required in addition to unit tests.

---

## 2. USER PERSONAS & USER JOURNEY

### 2.1 Target personas

#### Persona A — Security Assessment Operator

**Role:** Penetration tester / application security analyst  
**Motivation:** Quickly understand an authorized target, investigate attack surface and obtain defensible evidence.  
**Needs:** Scope controls, visibility into autonomous actions, approvals, findings, evidence and reproducible reports.

#### Persona B — Security Team Lead

**Role:** Application security lead / penetration testing lead  
**Motivation:** Standardize assessment quality across operators and reduce operational risk.  
**Needs:** Engagement management, policy profiles, approval workflows, finding quality, auditability and metrics.

#### Persona C — Security Reviewer / Approver

**Role:** Senior security engineer or assessment owner authorized to approve gated actions  
**Motivation:** Maintain control over higher-risk operations without manually operating every low-risk action.  
**Needs:** Exact action context, target, risk, rationale, scope version, expiration and approval history.

#### Persona D — Security Engineering / Platform Administrator

**Role:** ARKA platform administrator  
**Motivation:** Maintain provider configuration, workers, sandboxes, storage, observability and security posture.  
**Needs:** Health status, runtime controls, configuration, audit logs, failure diagnostics and safe operational controls.

#### Persona E — Client / Security Stakeholder

**Role:** Asset owner, engineering manager or security stakeholder  
**Motivation:** Understand what was tested, what was found and what evidence supports the result.  
**Needs:** Executive summary, severity, affected assets, evidence, remediation guidance and assessment scope.

### 2.2 Core jobs-to-be-done

| JTBD | Desired outcome |
|---|---|
| Define an assessment | Establish exactly what ARKA may and may not test |
| Launch reconnaissance | Discover assets and services without uncontrolled scope expansion |
| Analyze web/API surface | Build an endpoint and parameter inventory and identify security-relevant behavior |
| Investigate findings | Move from observation to validated finding with evidence |
| Approve risky operations | Authorize a precise action without granting broad execution rights |
| Monitor autonomous execution | Understand what ARKA proposed, why it was allowed/denied and what happened |
| Recover from failure | Resume safely after API/worker/database/queue interruption |
| Produce a report | Deliver technically defensible results with provenance |

### 2.3 Primary user journey

```text
Create engagement
  -> Define target and exclusions
  -> Select assessment policy
  -> Validate scope
  -> Start assessment
  -> Reconnaissance
  -> Web/API discovery
  -> LLM proposes next action
  -> Deterministic security gates evaluate action
  -> Execute if authorized / pause for approval / deny
  -> Capture evidence
  -> Normalize and correlate observations
  -> Validate findings
  -> Review findings
  -> Generate report
  -> Close engagement
```

### 2.4 Human approval journey

```text
Agent proposes action
  -> PolicyEngine determines approval required
  -> Approval ticket created with exact context
  -> Operator reviews target/tool/risk/rationale
  -> Grant / reject / expire
  -> Scope and request context revalidated
  -> Execute exactly once if valid
  -> Audit result
```

---

## 3. FUNCTIONAL REQUIREMENTS & USER STORIES

Priority definitions:

- **P0:** Required for safe operation of the core product.
- **P1:** Required for a production-capable assessment workflow.
- **P2:** Valuable extension or enterprise capability.

| User Story ID | As a... | I want to... | So that... | Priority (P0/P1/P2) | Acceptance Criteria (Gherkin) |
|---|---|---|---|---|---|
| PRD-001 | Assessment Operator | Create an engagement with name, objective, authorized targets and exclusions | Every action has an explicit assessment context | P0 | **Given** no engagement exists **When** I submit valid name/objective/scope **Then** ARKA creates an engagement with immutable scope version 1 **And** records an audit event |
| PRD-002 | Assessment Operator | Define IP, CIDR, domain, URL and port constraints | I can precisely bound testing | P0 | **Given** an engagement is editable **When** I define inclusions and exclusions **Then** exclusions override inclusions **And** the resulting scope can be evaluated deterministically |
| PRD-003 | Assessment Operator | Start, pause and stop an engagement | I control autonomous execution | P0 | **Given** a valid engagement **When** I start it **Then** a durable workflow is created **And** pause/stop prevents further execution until the state permits it |
| PRD-004 | Assessment Operator | See the current assessment state | I know whether ARKA is discovering, analyzing, waiting or failed | P0 | **Given** a running engagement **When** I request status **Then** API/CLI returns lifecycle state, task state and last meaningful event |
| PRD-005 | Assessment Operator | Run reconnaissance through ARKA | I can discover authorized infrastructure systematically | P0 | **Given** an authorized target **When** recon starts **Then** tools execute only through the control plane **And** discoveries are stored without expanding scope |
| PRD-006 | Assessment Operator | Run web crawling against an authorized URL | I can inventory web surface | P0 | **Given** an authorized web target **When** crawl starts **Then** crawler enforces depth/page/request/byte budgets **And** out-of-scope links are not requested |
| PRD-007 | Assessment Operator | Analyze OpenAPI documents | I can inventory API operations and security schemes | P0 | **Given** an authorized API target **When** OpenAPI analysis runs **Then** valid operations/parameters/security schemes are normalized **And** external references are not fetched |
| PRD-008 | Assessment Operator | Analyze GraphQL introspection | I can understand GraphQL query/mutation/subscription surface | P0 | **Given** an authorized GraphQL endpoint **When** analysis runs **Then** schema metadata is captured within configured limits **And** destructive mutations are classified but not executed automatically |
| PRD-009 | Assessment Operator | See discovered endpoints separately from authorized endpoints | Discovery cannot silently change the test boundary | P0 | **Given** a crawler/OpenAPI/GraphQL discovery **When** an endpoint is stored **Then** it is marked as discovered **And** ScopeGuard authorization remains unchanged |
| PRD-010 | Assessment Operator | Let the LLM recommend the next analysis action | ARKA can reason across observations | P0 | **Given** current assessment context **When** the LLM proposes a tool action **Then** it becomes CandidateToolRequest **And** no direct execution occurs |
| PRD-011 | Security Reviewer | Review a high-risk approval request | I can authorize exactly what I intend | P0 | **Given** a request requiring approval **When** I open it **Then** UI/API shows engagement, task, tool, target, arguments summary, risk, rationale, scope version and expiry **And** approval cannot be applied to a different context |
| PRD-012 | Security Reviewer | Reject an approval | Risky action does not execute | P0 | **Given** a pending approval **When** I reject it **Then** the request is terminally rejected **And** execution does not occur |
| PRD-013 | Assessment Operator | Inspect HTTP transactions | I can understand request/response behavior | P1 | **Given** an HTTP transaction **When** I view it **Then** sensitive headers are redacted **And** evidence reference and timing metadata are shown |
| PRD-014 | Assessment Operator | Associate findings with evidence | Findings are defensible | P0 | **Given** a finding **When** evidence exists **Then** the finding references content-addressed evidence IDs and provenance |
| PRD-015 | Security Analyst | Distinguish observed, suspected and validated findings | I avoid treating weak signals as confirmed vulnerabilities | P0 | **Given** a candidate finding **When** validation runs **Then** its status changes only through defined validation transitions **And** evidence supports the resulting state |
| PRD-016 | Security Analyst | Correlate observations from multiple tools | Duplicate signals become one canonical asset/finding view | P1 | **Given** equivalent observations from different tools **When** correlation runs **Then** canonical entities are deduplicated while provenance is preserved |
| PRD-017 | Platform Administrator | Configure multiple LLM providers | Provider outages do not stop the product unnecessarily | P1 | **Given** valid provider configuration **When** provider health is tested **Then** ARKA reports capability/status without exposing secrets **And** fallback follows configured policy |
| PRD-018 | Platform Administrator | Observe API/worker/queue health | I can diagnose operational failures | P1 | **Given** a running platform **When** health is requested **Then** API, database, Redis/worker and LLM dependency state are reported separately |
| PRD-019 | Assessment Operator | Resume after a process restart | Assessment state is durable | P0 | **Given** a persisted workflow **When** API/worker restarts **Then** the engagement/checkpoint/approval/evidence state remains recoverable |
| PRD-020 | Security Reviewer | Inspect immutable audit history | I can reconstruct security decisions | P0 | **Given** completed actions **When** audit history is requested **Then** events are ordered, integrity-protected and secrets are redacted |
| PRD-021 | Assessment Operator | Detect SSRF and redirect abuse | ARKA cannot be redirected into unauthorized networks | P0 | **Given** a page or response contains a private/loopback/link-local/metadata URL **When** ARKA considers requesting it **Then** SSRF and scope validation reject the request before network delivery |
| PRD-022 | Assessment Operator | Configure request and crawl budgets | Assessments remain bounded | P0 | **Given** configured maximum pages/requests/depth/bytes/runtime **When** a limit is reached **Then** additional work is rejected or the task terminates safely |
| PRD-023 | Security Analyst | Compare controlled responses for access-control analysis | I can identify potential authorization inconsistencies | P1 | **Given** two authorized security contexts **When** a controlled comparison is run **Then** requests remain within scope/policy **And** differences are recorded as observations rather than automatically confirmed vulnerabilities |
| PRD-024 | Assessment Operator | Generate a technical report | I can deliver reproducible findings | P1 | **Given** an assessment with findings/evidence **When** report generation runs **Then** it includes scope, methodology, findings, evidence references, limitations and timestamps |
| PRD-025 | Client Stakeholder | Read an executive report | I can understand material risk without reading raw telemetry | P1 | **Given** a completed assessment **When** I open the report **Then** it summarizes scope, methodology, key findings, affected assets, severity and remediation priorities |
| PRD-026 | Platform Administrator | Enforce tenant/engagement isolation | Data and credentials cannot cross security contexts | P1 | **Given** two assessment contexts **When** one requests another's object/session/evidence **Then** authorization rejects access |
| PRD-027 | Security Reviewer | See why an action was denied | I can diagnose policy outcomes | P1 | **Given** a denied candidate request **When** I inspect the decision **Then** ARKA provides a structured denial reason without exposing secrets |
| PRD-028 | Assessment Operator | Stop autonomous execution immediately | I can contain an assessment | P0 | **Given** an active engagement **When** stop is requested **Then** new executions are prevented and cancellable work is terminated safely according to runtime guarantees |

### 3.1 Key UI requirements

Although the current repository exposes CLI and REST interfaces rather than a complete end-user UI, the product contract for a future web console is defined here.

#### Engagement creation

Required fields:

- Engagement name
- Objective
- Authorization / rules-of-engagement confirmation
- Target type
- Target values
- Inclusion rules
- Exclusion rules
- Allowed ports
- Assessment profile
- Maximum runtime
- Request/concurrency budgets
- Optional authentication profile reference

The UI must display the resulting normalized scope before activation.

#### Live assessment dashboard

Display:

- Engagement state
- Current workflow/task
- Current phase
- Authorized target count
- Discovered asset count
- Endpoint count
- Findings by lifecycle state
- Pending approvals
- Recent policy decisions
- Tool executions
- Evidence count
- Error/retry indicators
- Last checkpoint

#### Approval panel

Display:

- Approval ID
- Engagement ID
- Task ID
- Tool
- Action
- Target
- Risk level
- Request summary
- Scope version
- Requested at
- Expiry
- Previous decisions
- Approver identity

The UI must not display raw credentials or unsanitized request bodies.

#### Findings view

Display:

- Finding title
- Severity
- Lifecycle status
- Confidence
- Affected asset/endpoint
- First observed / last validated timestamps
- Evidence references
- Detection source(s)
- Validation method
- Remediation guidance
- Scope context

---

## 4. NON-FUNCTIONAL REQUIREMENTS

### 4.1 Security

- All security-sensitive operations MUST traverse deterministic authorization.
- LLM output MUST remain untrusted.
- Discovered resources MUST NOT expand authorization.
- High/critical actions MUST require configured human approval.
- Secrets MUST be redacted from logs, prompts, audit records and API responses.
- HTTP clients MUST enforce SSRF and redirect-hop controls.
- Execution runtimes MUST be least privilege and resource bounded.
- All assessment state MUST be isolated by engagement and, in future multi-tenant deployments, tenant.

### 4.2 Performance targets

These are product targets rather than guarantees and should be measured in CI and representative deployments.

| Operation | Target |
|---|---:|
| Health endpoint | p95 < 300 ms excluding dependency outage |
| Scope evaluation | p95 < 10 ms for a single target |
| Candidate schema validation | p95 < 20 ms excluding database access |
| Policy decision | p95 < 50 ms excluding approval persistence |
| Approval listing | p95 < 300 ms for 100 pending items |
| Evidence metadata retrieval | p95 < 300 ms |
| Standard HTTP request overhead | < 100 ms application overhead excluding target latency |
| API request body default | <= 1 MiB unless endpoint explicitly requires otherwise |
| Web response capture | bounded by configured per-request maximum |

### 4.3 Reliability

- API and worker failures must not silently authorize work.
- Durable checkpoints must permit safe recovery.
- High-risk retries must be idempotent or require reauthorization.
- Database transactions must preserve security-state invariants.
- Redis/queue failure must fail closed for new executions where authorization cannot be established.
- Assessment stop must be observable and durable.

### 4.4 Usability

- Every policy decision should expose a human-readable reason and machine-readable code.
- Approval requests must be understandable without inspecting application logs.
- Destructive actions must be visually distinct from read-only analysis.
- Scope previews must show inclusion/exclusion precedence.
- Long-running work must expose progress and last activity.

### 4.5 Regional and legal constraints

ARKA is intended only for systems for which the operator has explicit authorization. Deployments must account for the jurisdiction of the operator, target, data and cloud provider. Where personal data or regulated information can appear in HTTP bodies, evidence and logs, deployments must implement appropriate data-minimization, retention and access controls.

The product should support configurable data residency and retention in enterprise phases rather than assuming all assessment evidence can be transferred to an external LLM provider.

### 4.6 Compatibility

The current repository baseline targets:

- Python 3.13+
- FastAPI/Pydantic v2
- LangGraph
- LiteLLM
- PostgreSQL 16+
- SQLAlchemy 2.0 / asyncpg
- Alembic
- Redis 7+
- Arq
- Typer/Rich
- Structlog/Langfuse

The documented architecture already uses these technologies. fileciteturn4file0L2-L2

---

## 5. OUT OF SCOPE & FUTURE PHASES

### 5.1 Out of scope for the current Phase 1–3.9 product baseline

1. Uncontrolled exploitation of arbitrary third-party systems.
2. Autonomous destructive exploitation.
3. Automatic authorization of discovered targets.
4. LLM-controlled scope or policy changes.
5. LLM-generated shell commands executed without deterministic tool controls.
6. Credential disclosure to the LLM.
7. Unbounded browser/JavaScript execution.
8. Unbounded crawler traversal.
9. Automatic external `$ref` retrieval from OpenAPI documents.
10. Automatic execution of destructive GraphQL mutations.
11. Autonomous lateral movement.
12. Persistence or malware deployment.
13. Credential theft or credential stuffing against unauthorized accounts.
14. Denial-of-service testing.
15. Multi-tenant enterprise fleet management as a prerequisite for the core assessment workflow.

### 5.2 Phase 3.6–3.9 product expansion

**3.6 — Authenticated Web Session Management**

- Session references and lifecycle
- Cookie/bearer/API-key handling
- Engagement-bound authentication contexts
- Secret isolation
- Session expiration
- Authentication state tracking

**3.7 — Authenticated Crawling and Access-Controlled Analysis**

- Session-aware crawling
- Authenticated endpoint inventory
- Bounded authenticated traversal
- Access-control state modeling

**3.8 — Business Logic and Access-Control Analysis**

- IDOR/BOLA indicators
- Differential authorization observations
- Workflow/state-transition analysis
- Controlled parameter variation
- Finding confidence and validation lifecycle

**3.9 — Web Security Agent Orchestration**

- Multi-stage web assessment planning
- Evidence-aware reasoning
- Deterministic task sequencing
- Autonomous re-planning through CandidateToolRequest
- Strong runtime acceptance testing

### 5.3 Phase 4 — Controlled Exploitation & Validation

The current repository roadmap describes Phase 4 as controlled exploitation and validation with a PoC validation engine, strict human-in-the-loop exploit gating and non-destructive validation payloads. fileciteturn9file0L2-L2

Product requirements for Phase 4 should preserve the existing control-plane architecture and introduce explicit exploit authorization rather than a separate execution path.

### 5.4 Phase 5 — Attack Graph and Autonomous Attack Paths

The roadmap identifies graph-based attack-path modeling, multi-hop scenario planning, risk calculation and executive reporting. fileciteturn9file0L2-L2

### 5.5 Phase 6 — Enterprise and Multimodal

The roadmap identifies UI/screenshot analysis, SSO/RBAC, SIEM streaming and multi-tenant fleet orchestration. fileciteturn9file0L2-L2

---

## 6. SUCCESS METRICS & RISKS

### 6.1 North Star metric

**Authorized Assessment Completion Rate:** percentage of initiated authorized assessments that reach a reproducible final report without a security-boundary violation or unrecoverable platform error.

Target for production maturity: **>= 95%** on representative authorized assessment workloads, excluding external target outages and intentionally injected infrastructure failures.

### 6.2 Primary KPIs

| KPI | Definition | Target |
|---|---|---:|
| Security-boundary violation rate | Unauthorized executions / total executions | 0 |
| Scope escape rate | Requests sent outside effective scope / total requests | 0 |
| Approval bypass rate | High/critical executions without valid approval | 0 |
| Secret leakage rate | Confirmed secret exposures in logs/prompts/API/evidence metadata | 0 |
| Assessment completion rate | Assessments reaching terminal report state safely | >= 95% |
| Evidence coverage | Material findings with provenance/evidence | >= 98% |
| False-positive rate after validation | Findings marked false positive / findings entering validation | < 15% target, measured empirically |
| Recovery success | Recoverable workflows resumed after simulated restart | >= 99% |
| Critical runtime failure recovery | Assessments safely fail closed after injected dependency failures | 100% |

### 6.3 Secondary KPIs

- Median analyst time saved per assessment.
- Discovery-to-finding conversion rate.
- Percentage of observations with multi-source corroboration.
- Mean time from finding observation to validation.
- Mean approval decision time.
- LLM provider fallback success rate.
- Average LLM cost per completed assessment.
- Evidence storage per assessment.
- Tool execution failure rate.
- Crawl duplicate ratio.

### 6.4 Risks

| Risk | Impact | Mitigation |
|---|---|---|
| LLM prompt injection | Unauthorized or unsafe proposed actions | Untrusted CandidateToolRequest + deterministic gates + adversarial tests |
| Scope confusion | Testing unintended systems | Versioned ScopeGuard, exclusion precedence, revalidation at execution |
| SSRF/DNS rebinding | Access to internal infrastructure | DNS/IP validation and per-hop redirect checks |
| Credential leakage | Confidentiality breach | Secret references, redaction, provider isolation, audit sanitization |
| Approval race | Unauthorized high-risk execution | Transactional approval binding and scope-version checks |
| Worker retry duplication | Repeated sensitive action | Idempotency, execution state and approval binding |
| Evidence tampering | Loss of defensibility | Content addressing, append-only storage and audit integrity |
| LLM provider outage | Reduced autonomy | Bounded retries, fallback providers and graceful degradation |
| Target instability | Incomplete assessment | Explicit task state, retry budgets and clear limitations |
| False positives | Analyst trust erosion | Correlation, validation agent and evidence-backed statuses |
| Data residency/privacy | Regulatory exposure | Configurable retention/residency and remote-LLM controls |
| Architecture drift | Security bypasses during feature growth | ADRs, regression OAT, security review gates |
| Stale documentation | Incorrect engineering assumptions | Documentation synchronization as release criterion |

### 6.5 Product release gates

A release cannot be considered production-ready unless:

1. P0 acceptance criteria pass.
2. Existing security regression suites pass.
3. Runtime OAT passes against controlled targets.
4. LLM-driven agentic execution is tested.
5. Scope and approval invariants are adversarially tested.
6. Secrets are not exposed by test telemetry.
7. Persistence/restart behavior is verified.
8. Known limitations are documented.
9. Security architecture documentation matches implementation.
10. The final release commit is traceable to test evidence.

---

## Product Definition of Done

ARKA is product-complete for a milestone when an authorized operator can define scope, launch an assessment, observe bounded autonomous reasoning, approve or deny gated actions, inspect discoveries/findings/evidence, recover from expected infrastructure failures, and generate a defensible report without violating the deterministic security invariants.

The product must never equate autonomous reasoning with autonomous authority.
