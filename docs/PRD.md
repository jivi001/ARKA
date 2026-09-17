# ARKA — Product Requirements Document (PRD)

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
```

---

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
