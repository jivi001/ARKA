# ARKA — Product Requirements Document (PRD)

<<<<<<< HEAD
**Product:** ARKA — Autonomous Risk Knowledge & Assessment
**Repository:** `jivi001/ARKA`
**Document status:** Production Product Baseline
**Version:** 2.0
**Date:** 2026-09-16
**Audience:** Product, security engineering, application security, penetration testing, platform engineering and assessment operators
**Authorization model:** Authorized security assessments only

---

# 1. EXECUTIVE SUMMARY & OBJECTIVES

## 1.1 Product overview

ARKA is an autonomous security-assessment platform built around **Bounded Autonomy**.

ARKA combines:

* LLM-based reasoning;
* deterministic investigation planning;
* deterministic scope enforcement;
* deterministic policy enforcement;
* contextual human approval;
* isolated execution;
* evidence preservation;
* finding validation;
* immutable auditability.

The fundamental security invariant is:

```text
LLM reasoning
      |
      v
Untrusted CandidateToolRequest
      |
      v
Deterministic Investigation Planner
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
      +------> ApprovalManager
      |
      v
Authoritative ToolRequest
      |
      v
ExecutionManager
      |
      v
Sandbox / Controlled HTTP Runtime
      |
      +------> Evidence
      +------> Observations
      +------> Findings
      +------> Audit
```

The LLM can reason about what should be investigated.

It cannot:

* execute tools;
* authorize itself;
* expand scope;
* approve an action;
* modify policy;
* inject credentials;
* bypass the execution boundary.

**ARKA's intelligence may become increasingly autonomous; its authority must not.**

---

## 1.2 Current product baseline

The repository contains the Phase 1 deterministic control plane and Phase 2 security execution/reconnaissance capabilities, including:

* ScopeGuard;
* PolicyEngine;
* ApprovalManager;
* ToolRegistry;
* ExecutionManager;
* LocalSafeRuntime;
* DockerSandboxRuntime;
* Nmap;
* Nuclei;
* ffuf;
* WhatWeb;
* Amass;
* canonical asset/service/endpoint models;
* EvidenceStore;
* ReconAgent;
* correlation;
* validation;
* durable workflow state.

Phase 3.1–3.5 extends this foundation into:

* HTTP request/response abstraction;
* bounded crawling;
* endpoint/parameter discovery;
* OpenAPI analysis;
* GraphQL analysis.

The repository's README and roadmap have historically contained stale phase labels. The implementation status must be determined from source, tests and operational acceptance evidence rather than stale roadmap labels.

---

## 1.3 Product vision

ARKA will become a security-assessment engine capable of autonomously investigating authorized attack surfaces while keeping all execution authority inside a deterministic zero-trust control plane.

The product must progressively support:

1. Explicit authorization and scope.
2. Network and web attack-surface discovery.
3. API and application-surface analysis.
4. Evidence-backed security observations.
5. Non-destructive vulnerability verification.
6. Controlled authenticated analysis.
7. Access-control and business-logic analysis.
8. Human-gated higher-risk validation.
9. Reproducible reporting.
10. Durable autonomous operation.

---

## 1.4 Core product thesis

Existing security automation generally falls into three categories:

```text
Deterministic scanners
        |
        +-- predictable
        +-- bounded
        +-- limited reasoning

LLM agents
        |
        +-- flexible reasoning
        +-- broad adaptation
        +-- unsafe if directly empowered

Autonomous pentest platforms
        |
        +-- autonomous attack execution
        +-- exploit validation
        +-- enterprise-scale operations
```

ARKA occupies a deliberate fourth position:

```text
Autonomous reasoning
+
Deterministic investigation
+
Deterministic authorization
+
Bounded execution
+
Evidence-backed epistemic progression
```

The product is not intended to prove that an LLM can independently operate a shell.

The product is intended to prove that an LLM can provide useful security reasoning **without becoming a security authority**.

---

# 2. MARKET POSITIONING & COMPETITIVE DIFFERENTIATION

## 2.1 Competitive landscape

ARKA operates in a rapidly developing autonomous offensive-security market.

The relevant comparison set includes:

* Strix;
* XBOW;
* Horizon3 NodeZero;
* Pentera;
* conventional penetration-testing tooling;
* vulnerability scanners;
* internal security automation platforms.

The comparison below describes publicly documented capabilities and ARKA's intended architecture. It is not a claim that the competing systems are unsafe; each platform implements its own governance and safety mechanisms.

---

## 2.2 Competitive architecture comparison

| Dimension             | ARKA                                                                          | Strix                                                              | XBOW                                           | NodeZero                                  | Pentera                                          |
| --------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------ | ---------------------------------------------- | ----------------------------------------- | ------------------------------------------------ |
| Primary model         | Bounded autonomous security assessment                                        | Autonomous AI pentesting                                           | Autonomous offensive security                  | Autonomous penetration testing            | Automated security/exposure validation           |
| LLM role              | Untrusted reasoning/planning                                                  | Agent directly operates security tooling inside sandbox            | Autonomous agents coordinate offensive testing | Autonomous attack orchestration           | Agentic AI adapts deterministic attack execution |
| Execution authority   | Deterministic control plane only                                              | Agents can operate terminal/browser/runtime tooling inside sandbox | Autonomous attack workers execute testing      | Autonomous attack platform                | Controlled attack engine                         |
| Tool execution        | Authoritative request after deterministic gates                               | Agent-operated sandbox tooling                                     | Autonomous offensive toolkit                   | Autonomous attack engine                  | Deterministic/agentic attack execution           |
| Scope model           | Versioned deterministic scope; discovery never authorizes                     | User-defined target/scoping model                                  | Defined target/scope with governed execution   | Customer-defined testing environment      | Customer-defined attack surface and guardrails   |
| Scope expansion       | Explicit immutable scope-delta workflow                                       | Target/agent workflow                                              | Platform-governed                              | Platform-governed                         | Platform-governed                                |
| Validation philosophy | 5-tier epistemic ladder; non-destructive validation before human confirmation | Strong emphasis on working PoCs                                    | Strong emphasis on independent exploit proof   | Exploit/attack-path validation            | Real attack/exposure validation                  |
| Human approval        | Contextual deterministic gate                                                 | Platform-dependent                                                 | Governed execution                             | Customer controls and platform governance | Customer-defined guardrails                      |
| Evidence              | Content-addressed evidence + observations + audit                             | Reproduction/PoC-oriented evidence                                 | Complete finding traces and exploit proof      | Attack-path evidence                      | Validated exposure evidence                      |
| Main differentiation  | Security authority remains outside the agent                                  | Agentic offensive flexibility                                      | Scale + exploit proof                          | Enterprise attack-path validation         | Continuous enterprise exposure validation        |
| Deployment philosophy | Self-controlled assessment engine                                             | Open-source/self-hosted + managed platform                         | Commercial autonomous platform                 | Commercial enterprise platform            | Commercial enterprise platform                   |
| Open-source core      | Yes                                                                           | Yes                                                                | No                                             | No                                        | No                                               |

Strix publicly documents browser automation, HTTP proxying, terminal access, Python runtime and Docker-based execution, alongside multi-agent orchestration and proof-of-concept validation.

XBOW publicly describes autonomous agents that map applications, coordinate attacks, exploit vulnerabilities and use independent validation to prove findings.

Horizon3 describes NodeZero as an autonomous penetration-testing platform capable of chaining weaknesses and safely exploiting them to expose attack paths.

Pentera describes a platform combining deterministic attack logic with agentic AI, continuously validating exploitable exposure across internal, external, cloud and web environments.

---

## 2.3 ARKA's architectural differentiation

### Execution authority

ARKA intentionally establishes:

```text
LLM
 !=
Execution Authority
```

The model emits:

```text
CandidateToolRequest
```

which is untrusted.

Only deterministic components can produce:

```text
Authoritative ToolRequest
```

This creates a stronger separation between reasoning and authorization than an architecture in which an agent can directly invoke arbitrary shell, Python or browser tooling.

---

## 2.4 Scope rigor

ARKA treats discovery and authorization as separate domains:

```text
DISCOVERED != AUTHORIZED
```

A discovered:

```text
api.internal.example.com
```

does not become authorized merely because:

* an LLM discovered it;
* a crawler reached a reference to it;
* another tool reported it;
* it belongs to the same organization;
* it appears related to an authorized application.

Every execution must be evaluated against an immutable scope version.

HTTP redirects repeat validation at every hop.

DNS resolution is validated before connection.

---

## 2.5 Validation differentiation

ARKA does not equate:

```text
LLM confidence
```

with:

```text
security validation
```

The product uses a five-tier epistemic ladder:

```text
OBSERVED
   ↓
CANDIDATE
   ↓
SUPPORTED
   ↓
VALIDATED
   ↓
HUMAN_CONFIRMED
```

This intentionally separates:

* raw tool observations;
* security hypotheses;
* corroborated evidence;
* deterministic technical validation;
* human acceptance.

An LLM can propose or explain a finding.

It cannot promote a finding to `VALIDATED`.

---

# 3. BUSINESS GOALS

## 3.1 Primary goals

| Goal                               | Product outcome                                |
| ---------------------------------- | ---------------------------------------------- |
| Reduce repetitive assessment work  | Autonomous discovery and analysis              |
| Preserve human control             | Deterministic authorization and approval       |
| Improve finding quality            | Evidence and deterministic validation          |
| Reduce analyst time                | Useful autonomous investigations               |
| Increase assessment consistency    | Standardized workflow and evidence model       |
| Make AI security testing auditable | Complete decision and execution provenance     |
| Support modern application testing | Web/API/authentication/access-control analysis |

---

## 3.2 Non-goals

ARKA is not intended to:

* provide unrestricted autonomous hacking;
* bypass authorization;
* automatically test discovered third-party infrastructure;
* deploy malware;
* perform persistence;
* perform uncontrolled destructive exploitation;
* perform denial-of-service testing;
* treat LLM output as trusted authorization.

---

# 4. USER PERSONAS & USER JOURNEY

## 4.1 Security Assessment Operator

**Role:** Penetration tester / application security analyst.

**Motivation:** Reduce repetitive work while retaining direct control over assessment boundaries.

**Needs:**

* scope;
* discovery;
* evidence;
* findings;
* approvals;
* live execution state;
* reports.

---

## 4.2 Security Team Lead

**Role:** Security lead / pentest lead.

**Motivation:** Improve assessment consistency and analyst productivity.

**Needs:**

* policy profiles;
* metrics;
* finding quality;
* evidence;
* approval governance.

---

## 4.3 Security Approver

**Role:** Authorized senior security engineer.

**Motivation:** Control higher-risk actions without reviewing every low-risk operation.

**Needs:**

* exact target;
* exact action;
* exact request;
* risk;
* rationale;
* scope version;
* cryptographic request binding.

---

## 4.4 Platform Operator

**Role:** Person operating ARKA infrastructure.

**Motivation:** Keep assessment infrastructure available and secure.

**Needs:**

* health;
* worker state;
* provider state;
* sandbox state;
* storage;
* audit.

---

## 4.5 Security Stakeholder

**Role:** Asset owner / engineering manager / security stakeholder.

**Motivation:** Understand actual security exposure.

**Needs:**

* findings;
* evidence;
* impact;
* remediation;
* report.

---

# 5. CORE JOBS-TO-BE-DONE

| JTBD                    | Outcome                                            |
| ----------------------- | -------------------------------------------------- |
| Define assessment       | Precisely establish authorization                  |
| Discover attack surface | Build canonical authorized attack surface          |
| Investigate             | Determine what deserves deeper analysis            |
| Validate                | Convert observations into evidence-backed findings |
| Approve                 | Authorize exact higher-risk operations             |
| Monitor                 | Understand autonomous behavior                     |
| Recover                 | Resume safely after infrastructure failures        |
| Report                  | Produce reproducible assessment results            |

---

# 6. PRIMARY USER JOURNEY

```text
Create Engagement
       ↓
Define Scope
       ↓
Review Effective Scope
       ↓
Start Assessment
       ↓
Deterministic Reconnaissance
       ↓
Web/API Discovery
       ↓
LLM Reasoning
       ↓
Deterministic Investigation Planner
       ↓
Candidate Tool Request
       ↓
ScopeGuard
       ↓
PolicyEngine
       ↓
 ┌───────────────┬────────────────┐
 │               │                │
ALLOW        APPROVAL          DENY
 │               │                │
 ↓               ↓                ↓
Execute      Human review      Explain
 │               │
 ↓               ↓
Evidence      Grant/Reject
 │
 ↓
Observation
 ↓
Candidate Finding
 ↓
Support / Corroboration
 ↓
Deterministic Validation
 ↓
Validated Finding
 ↓
Human Confirmation
 ↓
Report
=======
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
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
```

---

<<<<<<< HEAD
# 7. FUNCTIONAL REQUIREMENTS & USER STORIES

Priority:

* **P0:** Safety-critical/core product.
* **P1:** Production assessment capability.
* **P2:** Future extension.

| ID          | As a...      | I want to...                                      | So that...                                                                           | Priority | Acceptance Criteria                                                                                                                                                                                                                                                                                                                                                              |
| ----------- | ------------ | ------------------------------------------------- | ------------------------------------------------------------------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| PRD-001     | Operator     | Create an engagement                              | Testing has explicit authorization context                                           | P0       | Given valid scope, when engagement is created, then immutable scope version 1 exists and is audited                                                                                                                                                                                                                                                                              |
| PRD-002     | Operator     | Define IP/CIDR/domain/URL/port rules              | Testing is deterministic                                                             | P0       | Given include/exclude rules, when normalized, then exclusions override inclusions                                                                                                                                                                                                                                                                                                |
| PRD-003     | Operator     | Start/pause/stop an assessment                    | I control autonomous execution                                                       | P0       | Given a running assessment, when stop is requested, then new execution is prevented                                                                                                                                                                                                                                                                                              |
| PRD-004     | Operator     | View assessment state                             | I understand current activity                                                        | P0       | Status exposes phase, task, approvals and recent events                                                                                                                                                                                                                                                                                                                          |
| PRD-005     | Operator     | Run reconnaissance                                | Infrastructure is discovered systematically                                          | P0       | All tools pass through authorization                                                                                                                                                                                                                                                                                                                                             |
| PRD-006     | Operator     | Crawl authorized web targets                      | Web attack surface is mapped                                                         | P0       | Crawl respects depth/request/page/byte budgets                                                                                                                                                                                                                                                                                                                                   |
| PRD-007     | Operator     | Analyze OpenAPI                                   | API surface is normalized                                                            | P0       | Operations and parameters are extracted without automatic external `$ref` fetching                                                                                                                                                                                                                                                                                               |
| PRD-008     | Operator     | Analyze GraphQL                                   | GraphQL attack surface is modeled                                                    | P0       | Introspection respects depth and response limits                                                                                                                                                                                                                                                                                                                                 |
| PRD-009     | Operator     | Separate discovered from authorized assets        | Discovery cannot expand authorization                                                | P0       | Discovered targets cannot execute until authorized                                                                                                                                                                                                                                                                                                                               |
| PRD-010     | Operator     | Use LLM reasoning                                 | Complex observations can be interpreted                                              | P0       | LLM output becomes untrusted candidate data                                                                                                                                                                                                                                                                                                                                      |
| PRD-011     | Approver     | Review exact risky requests                       | I can authorize precisely                                                            | P0       | Request includes target, tool, arguments hash, scope version and risk                                                                                                                                                                                                                                                                                                            |
| PRD-012     | Approver     | Reject requests                                   | Unsafe work does not execute                                                         | P0       | Rejected request becomes terminal                                                                                                                                                                                                                                                                                                                                                |
| PRD-013     | Analyst      | Inspect HTTP transactions                         | I can understand behavior                                                            | P1       | Sensitive headers and credentials are redacted                                                                                                                                                                                                                                                                                                                                   |
| PRD-014     | Analyst      | Link evidence to findings                         | Findings are defensible                                                              | P0       | Finding references evidence hashes                                                                                                                                                                                                                                                                                                                                               |
| PRD-015     | Analyst      | Track epistemic state                             | I know evidence strength                                                             | P0       | Findings follow the five-tier ladder                                                                                                                                                                                                                                                                                                                                             |
| PRD-016     | Analyst      | Correlate observations                            | Duplicate signals become canonical                                                   | P1       | Correlation preserves provenance                                                                                                                                                                                                                                                                                                                                                 |
| PRD-017     | Operator     | Configure OpenRouter                              | LLM reasoning is available                                                           | P1       | Provider health/capability is exposed without secrets                                                                                                                                                                                                                                                                                                                            |
| PRD-018     | Operator     | View platform health                              | Failures are diagnosable                                                             | P1       | API, worker, database, queue and LLM health are separated                                                                                                                                                                                                                                                                                                                        |
| PRD-019     | Operator     | Resume after restart                              | Work is durable                                                                      | P0       | Persisted workflow resumes without bypassing authorization                                                                                                                                                                                                                                                                                                                       |
| PRD-020     | Approver     | Inspect audit history                             | Security decisions are reconstructable                                               | P0       | Events are ordered and integrity protected                                                                                                                                                                                                                                                                                                                                       |
| PRD-021     | Operator     | Prevent SSRF                                      | Targets cannot redirect ARKA into unauthorized networks                              | P0       | DNS/IP/scope validation occurs before network delivery                                                                                                                                                                                                                                                                                                                           |
| PRD-022     | Operator     | Set resource budgets                              | Assessments remain bounded                                                           | P0       | Limits cannot be expanded by LLM output                                                                                                                                                                                                                                                                                                                                          |
| PRD-023     | Analyst      | Perform controlled differential analysis          | Authorization anomalies can be investigated                                          | P1       | Results are observations until deterministic validation                                                                                                                                                                                                                                                                                                                          |
| PRD-024     | Operator     | Generate technical reports                        | Results are deliverable                                                              | P1       | Report includes scope, evidence and limitations                                                                                                                                                                                                                                                                                                                                  |
| PRD-025     | Stakeholder  | Read executive findings                           | Risk is understandable                                                               | P1       | Report summarizes validated findings and business impact                                                                                                                                                                                                                                                                                                                         |
| PRD-026     | Operator     | Maintain assessment isolation                     | Data cannot cross engagements                                                        | P1       | Cross-engagement access is denied                                                                                                                                                                                                                                                                                                                                                |
| PRD-027     | Operator     | Understand policy denials                         | I can troubleshoot                                                                   | P1       | Structured denial reason is available                                                                                                                                                                                                                                                                                                                                            |
| PRD-028     | Operator     | Immediately stop execution                        | I can contain activity                                                               | P0       | New execution is blocked and active work is cancelled safely                                                                                                                                                                                                                                                                                                                     |
| **PRD-029** | **Operator** | **Review and approve a proposed scope expansion** | **A valuable discovered asset can be authorized without terminating the assessment** | **P0**   | **Given an out-of-scope high-value asset is discovered, when ARKA proposes a Scope Delta, then it shows target, relationship, reason, boundary impact, proposed rules and risk; when the operator approves, then a new immutable scope version is created, incompatible approvals are invalidated, the new scope is re-evaluated and the assessment resumes without restarting** |

---

# 8. SCOPE EXPANSION WORKFLOW

## 8.1 Problem

Strict scope isolation can create operator friction when an authorized application discovers a related service.

Example:

```text
app.example.com
      ↓
API reference
      ↓
api.example.com
```

`api.example.com` remains unauthorized.

ARKA must not automatically access it.

Instead it creates:

```text
Scope Delta
```

---

## 8.2 Scope Delta

A Scope Delta contains:

* originating engagement;
* current scope version;
* discovered asset;
* discovery evidence;
* relationship to authorized target;
* proposed scope rule;
* proposed exclusions;
* boundary impact;
* risk classification;
* expected investigation;
* expiration if applicable.

Example:

```json
{
  "source_asset": "app.example.com",
  "discovered_asset": "api.example.com",
  "relationship": "API referenced by authorized application",
  "proposed_change": {
    "include": {
      "type": "domain",
      "value": "api.example.com"
    }
  },
  "boundary_impact": "Adds one explicitly identified domain",
  "risk": "LOW"
}
```

---

## 8.3 Scope Delta approval

Approval means:

```text
current scope
      +
exact Scope Delta
      ↓
new immutable scope version
```

It does **not** mean:

```text
approve all discovered domains
```

The new scope is independently hashed and evaluated.

---

# 9. EPISTEMIC FINDING LADDER

ARKA MUST use exactly five primary finding states.

```text
OBSERVED
   ↓
CANDIDATE
   ↓
SUPPORTED
   ↓
VALIDATED
   ↓
HUMAN_CONFIRMED
```

## 9.1 OBSERVED

A tool or analyzer produced a security-relevant signal.

Example:

```text
HTTP response changed after identifier modification.
```

No vulnerability claim is made.

---

## 9.2 CANDIDATE

The system has enough evidence to formulate a security hypothesis.

Example:

```text
Potential object-level authorization weakness.
```

---

## 9.3 SUPPORTED

Independent evidence supports the hypothesis.

Possible support:

* second request;
* second tool;
* deterministic differential;
* corroborating metadata;
* repeatable observation.

---

## 9.4 VALIDATED

A deterministic verification mechanism has reproduced the security condition within the authorized test boundary.

Allowed validators include:

* deterministic verification engine;
* replay script;
* controlled differential baseline;
* deterministic request comparison;
* predefined security invariant.

**LLM output MUST NEVER transition a finding to `VALIDATED`.**

---

## 9.5 HUMAN_CONFIRMED

An authorized human reviews the validated evidence and confirms the finding for the assessment report.

---

## 9.6 LLM restrictions

The LLM may:

* create observations;
* propose candidate findings;
* explain evidence;
* recommend validation;
* prioritize investigation.

The LLM may not:

* mark a finding `VALIDATED`;
* mark a finding `HUMAN_CONFIRMED`;
* override a deterministic validator;
* manufacture validation evidence.

---

# 10. APPROVAL BATCHING

## 10.1 Problem

One approval per low-impact repetitive operation creates approval fatigue.

ARKA therefore supports bounded batching.

---

## 10.2 Eligible operations

Batch approval is allowed only when:

* operations are homogeneous;
* risk is low;
* all targets are already authorized;
* policy explicitly permits batching;
* resource budgets are preserved;
* each request is independently valid.

---

## 10.3 Cryptographic binding

A batch contains the exact canonicalized requests:

```text
R1
R2
R3
...
Rn
```

The system computes:

```text
leaf_i = SHA256(canonical_request_i)
```

and constructs a Merkle tree:

```text
          Merkle Root
          /          \
       H12            H34
      /  \           /  \
    H1    H2       H3    H4
```

The approval binds to:

```text
engagement_id
scope_version
policy_version
batch_id
request_count
merkle_root
expiry
```

The approval grants authorization only to requests represented by the exact Merkle root.

It MUST NOT grant:

```text
"all requests of this type"
```

or:

```text
"all requests against this host"
```

---

# 11. NON-FUNCTIONAL REQUIREMENTS

## 11.1 Security

Hard requirements:

* zero unauthorized execution;
* zero scope escape;
* zero approval bypass;
* zero intentional secret exposure;
* fail-closed authorization;
* deterministic scope evaluation;
* deterministic approval validation;
* isolated execution;
* SSRF protection;
* redirect revalidation;
* DNS/IP validation;
* bounded resources.

---

## 11.2 Product performance targets

| Operation                                      |                           Target |
| ---------------------------------------------- | -------------------------------: |
| Health endpoint                                |                     p95 < 300 ms |
| Scope evaluation                               |                      p95 < 10 ms |
| Candidate validation                           |         p95 < 20 ms excluding DB |
| Policy evaluation                              |                      p95 < 50 ms |
| Evidence metadata retrieval                    |                     p95 < 300 ms |
| Approval list                                  |                     p95 < 300 ms |
| Standard application overhead per HTTP request | <100 ms excluding target latency |

These are engineering targets and must be validated using representative workloads.

---

## 11.3 Usability

The operator must be able to understand:

* what ARKA discovered;
* what it wants to do;
* why it wants to do it;
* whether it is authorized;
* why it was allowed/denied;
* what evidence resulted.

---

# 12. OUT OF SCOPE

The current product baseline does not include:

1. Uncontrolled exploitation.
2. Autonomous destructive exploitation.
3. Authorization expansion through discovery.
4. Arbitrary shell execution by the LLM.
5. Credential disclosure to the LLM.
6. Malware deployment.
7. Persistence.
8. Lateral movement outside explicit authorization.
9. Denial-of-service testing.
10. Unbounded browser automation.
11. Automatic external OpenAPI `$ref` retrieval.
12. Automatic destructive GraphQL mutation execution.
13. Multi-tenant enterprise fleet management.
14. SAML/enterprise federation as a core dependency.
15. Multimodal security UI as a core dependency.
16. Dedicated graph database infrastructure.

---

# 13. FUTURE ROADMAP

## Phase 3.6

Authenticated session foundation.

## Phase 3.7

Authenticated web analysis.

## Phase 3.8

Business logic and access-control analysis.

## Phase 3.9

Web Security Agent.

## Phase 4

Controlled exploitation and validation.

## Phase 5

Attack-path analysis using PostgreSQL-backed graph structures initially.

## Future Enterprise

Only after demonstrated product demand:

* SSO/SAML;
* enterprise RBAC;
* multi-tenant fleet orchestration;
* SIEM integrations;
* multimodal UI;
* large-scale centralized deployment.

These are explicitly **future capabilities**, not prerequisites for the core product.

---

# 14. SUCCESS METRICS & KPIs

ARKA separates **hard safety constraints** from **optimization metrics**.

---

## 14.1 Hard safety invariants

These are not optimization targets.

They are mandatory constraints.

| Metric                  | Target |
| ----------------------- | -----: |
| Scope escapes           |  **0** |
| Unauthorized executions |  **0** |
| Approval bypasses       |  **0** |
| Secret leaks            |  **0** |

A release fails if any of these occur.

---

## 14.2 Product efficacy

### Useful Autonomous Action Rate

```text
useful authorized actions
-------------------------
all autonomous candidate actions
```

Target:

**≥70%**

A useful action is one that:

* advances attack-surface understanding;
* produces relevant evidence;
* performs meaningful validation;
* contributes to a finding;
* or materially advances an assessment objective.

---

## 14.3 Analyst Time Leverage

Target:

**≥5x reduction in analyst time per validated finding**

Measured as:

```text
human analyst time required manually
-------------------------------------
human analyst time required with ARKA
```

This is measured against a standardized benchmark methodology.

---

## 14.4 Time-to-First-Finding

TTFF measures:

```text
assessment start
        ↓
first validated finding
```

The primary benchmark target is OWASP Juice Shop and equivalent controlled applications.

TTFF must be tracked separately from:

* first observation;
* first candidate;
* first supported finding;
* first validated finding.

---

## 14.5 Secondary metrics

* authorized attack-surface coverage;
* findings validated per analyst hour;
* analyst intervention rate;
* candidate rejection rate;
* duplicate action rate;
* LLM calls per validated finding;
* LLM cost per validated finding;
* evidence generated per assessment;
* recovery success rate;
* validation success rate;
* time spent waiting for approvals.

---

# 15. PRODUCT RISKS

| Risk                        | Impact                   | Mitigation                                |
| --------------------------- | ------------------------ | ----------------------------------------- |
| LLM hallucination           | Bad investigation        | Strict schemas + deterministic gates      |
| Prompt injection            | Unsafe proposals         | Treat target content as untrusted         |
| Scope ambiguity             | Unauthorized access      | Immutable scope versions                  |
| Scope expansion friction    | Operator abandonment     | Scope Delta workflow                      |
| Approval fatigue            | Unsafe habitual approval | Cryptographically bound batching          |
| False positives             | Loss of trust            | Epistemic ladder                          |
| LLM overuse                 | Cost/latency             | Deterministic Investigation Planner       |
| Evidence explosion          | Storage cost             | Content addressing + object storage       |
| Provider outage             | Lost autonomy            | Bounded fallback/pause                    |
| Worker duplication          | Repeated action          | Idempotency                               |
| Target instability          | Incomplete assessment    | Explicit task state                       |
| Architecture drift          | Security bypass          | ADRs + OAT                                |
| Competitive parity pressure | Scope creep              | Focus on bounded-autonomy differentiation |

---

# 16. RELEASE GATES

A production release requires:

1. All P0 stories pass.
2. Hard safety invariants remain zero.
3. Scope expansion is tested adversarially.
4. Approval batching is cryptographically verified.
5. Epistemic state transitions are enforced.
6. LLM cannot promote findings to `VALIDATED`.
7. Runtime OAT passes.
8. Live LLM testing passes.
9. Restart/recovery passes.
10. Evidence integrity passes.
11. Audit integrity passes.
12. No secret leakage is detected.
13. Documentation matches implementation.

---

# 17. PRODUCT DEFINITION OF DONE

ARKA's core product is complete when an authorized operator can:

```text
Define scope
   ↓
Start assessment
   ↓
Discover assets
   ↓
Investigate intelligently
   ↓
Request controlled actions
   ↓
Pass deterministic security gates
   ↓
Capture evidence
   ↓
Progress findings through epistemic states
   ↓
Validate findings deterministically
   ↓
Human-confirm findings
   ↓
Generate a reproducible report
```

while maintaining:

```text
LLM != Authority
DISCOVERED != AUTHORIZED
VALIDATED != LLM_CONFIDENCE
APPROVAL != WILDCARD_PERMISSION
```

ARKA's product differentiation is therefore not simply:

> "AI can hack."

It is:

> **AI can reason autonomously about security while a deterministic system retains absolute authority over what may actually happen.**
=======
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
>>>>>>> efcaa89b635a2842cdd01e4215ad6be9403053ef
