ARKA — Product Requirements Document (PRD)

Revised Security-Hardened Baseline v2.2

Product: ARKA — Autonomous Risk Knowledge & Assessment
Status: Proposed / Architecture-Frozen Baseline
Platforms: Debian/Ubuntu Linux; Windows GUI/worker support
Primary implementation direction: Rust security kernel + Python intelligence/agent plane
Document purpose: Product behavior, scope, security invariants, user workflows, requirements, and acceptance criteria.

1. Executive Summary

ARKA is an authorized offensive-security and security-assessment orchestration platform designed to combine deterministic security controls with AI-assisted reasoning.

ARKA is intended for:

CTF and laboratory environments.

Explicitly authorized penetration testing.

Security research performed within an operator-defined scope.

Reconnaissance and attack-surface mapping.

Vulnerability analysis.

Controlled exploitation in explicitly authorized environments.

OSINT collection and correlation.

Technology-stack and infrastructure identification.

Evidence collection and provenance.

Automated security reporting.

ARKA is not designed as an unrestricted autonomous hacking system.

The central product principle is:

LLM proposes. Deterministic kernel authorizes. Broker executes. Sandbox contains. Evidence records. Human controls high-risk actions.

The LLM and agent plane has zero direct execution authority.

The security kernel is authoritative over:

Mission scope.

Capabilities.

Authorization.

Risk.

Approval requirements.

Resource budgets.

Network policy.

Credential sessions.

Execution.

Auditability.

Core invariant

DISCOVERED != AUTHORIZED

Discovery of an IP, hostname, port, credential, endpoint, vulnerability, redirect target, or technology does not grant permission to interact with it.

2. Product Goals

2.1 Primary goals

Provide a unified security-assessment workflow.

Allow AI agents to reason over reconnaissance and evidence.

Generate structured, testable action proposals.

Prevent agents and LLMs from directly executing tools.

Enforce authorization deterministically.

Maintain strict mission and target isolation.

Execute tools inside controlled environments.

Maintain tamper-evident audit and evidence provenance.

Support Linux and Windows workers.

Produce detailed professional security reports.

Support both CTF/Lab and Professional Authorized modes.

Provide a modular architecture capable of evolving into distributed execution.

2.2 Secondary goals

Reduce repetitive analyst work.

Correlate findings across tools.

Build a persistent mission knowledge graph.

Support multi-agent specialization.

Provide explainable action rationales without exposing chain-of-thought.

Make every significant action reproducible from evidence and authorization records.

3. Non-Goals

ARKA will not:

Provide unrestricted autonomous network access.

Treat LLM output as authorization.

permit an agent to spawn arbitrary shell commands.

permit arbitrary tool installation during a mission.

bypass human approval for actions classified as requiring approval.

automatically expand target scope from discovered infrastructure.

expose raw credentials to the LLM by default.

use generic unrestricted PowerShell as an LLM-facing capability.

rely on prompt instructions as the primary security boundary.

assume Docker alone is an equivalent security boundary to a VM/hypervisor.

silently continue after resource or authorization failures.

4. Operating Modes

4.1 CTF/Lab Mode

Designed for controlled environments.

Properties:

Explicit target scope.

Controlled exploitation enabled only when configured.

Lower operational friction.

Local/self-hosted LLM support encouraged.

Strong sandboxing remains mandatory.

Results are still fully audited.

4.2 Professional Authorized Mode

Designed for explicitly authorized security engagements.

Additional controls:

Explicit engagement scope.

Operator identity.

Strong approval workflows.

Detailed audit.

Data-handling policy.

LLM data classification.

Credential governance.

Optional dual approval for critical operations.

Engagement evidence retention policy.

4.3 Mode isolation

Mode configuration cannot silently downgrade security requirements.

Professional Mode cannot inherit weaker controls from CTF Mode.

5. Users

5.1 Operator

Creates missions, defines scope, reviews findings, and approves actions.

5.2 Security Reviewer

Reviews high-risk actions and reports.

5.3 Administrator

Configures ARKA infrastructure, workers, policies, providers, and security controls.

5.4 AI Agents

Specialized reasoning components.

Agents do not possess independent authorization authority.

6. Core Workflow

Operator
   |
   v
Mission Creation
   |
   v
Scope Definition
   |
   v
Reconnaissance
   |
   v
Evidence Ingestion
   |
   v
Knowledge Graph
   |
   v
Agent Analysis
   |
   v
Action Proposal
   |
   v
Deterministic Authorization
   |
   +---- DENY ----> Audit
   |
   +---- APPROVAL -> Human
   |
   v
Execution Broker
   |
   v
Sandbox / Worker
   |
   v
Evidence
   |
   v
Classification + Provenance
   |
   v
Knowledge Graph
   |
   v
Next Agent Cycle

There is no valid alternative execution path.

7. Product Architecture

7.1 Presentation Plane

Responsibilities:

Mission management.

Scope management.

Live activity.

Approval interface.

Evidence exploration.

Report generation.

Configuration.

The presentation layer cannot execute security tools directly.

7.2 Security Kernel

The Rust kernel is the security authority.

Responsibilities:

Authentication.

Authorization.

Scope validation.

Capability validation.

Action normalization.

Risk evaluation.

Approval enforcement.

Parameter-hash binding.

Resource governance.

Execution-broker mediation.

Mission isolation.

Audit.

Emergency stop.

7.3 Intelligence Plane

Python-based.

Responsibilities:

Agent orchestration.

LLM integration.

Reasoning.

Hypothesis generation.

Evidence correlation.

Planning.

OSINT reasoning.

Finding analysis.

Report drafting.

It cannot directly access target networks or execute host commands.

7.4 Execution Plane

Responsibilities:

Tool execution.

Network operations.

Browser automation.

Controlled exploitation.

Packet capture where authorized.

Windows/Linux worker execution.

All execution flows through the Rust broker.

8. Agent System

ARKA uses specialized agents rather than a single unrestricted agent.

Possible agents:

Mission Planner.

Recon Agent.

Network Enumeration Agent.

Web Assessment Agent.

Vulnerability Analysis Agent.

OSINT Agent.

Credential Assessment Agent.

Exploitation Planning Agent.

Evidence Analyst.

Technology Fingerprinting Agent.

Report Agent.

Agents communicate through structured JSON contracts.

8.1 Governing council

A deterministic/security-oriented governing layer supervises agent proposals.

The council may:

validate schema;

detect conflicting proposals;

enforce mission constraints;

request additional evidence;

reject malformed proposals.

The council does not replace the security kernel.

The kernel remains authoritative.

9. Agent-to-Agent Communication

All A2A messages use versioned structured schemas.

Example:

{
  "message_type": "finding",
  "mission_id": "mission-123",
  "agent_id": "recon-01",
  "parent_task_id": "task-42",
  "timestamp": "...",
  "confidence": 0.91,
  "finding": {
    "asset": "target.example",
    "port": 22,
    "protocol": "ssh"
  },
  "evidence_refs": ["ev-991"]
}

Agents cannot directly invoke another agent's capabilities.

10. Discovery and Scope

ARKA must distinguish:

discovered asset;

authorized asset;

observed relationship;

executable target.

Example:

Target scope:
10.10.10.10

Discovery:
10.10.10.11

Result:
10.10.10.11 is DISCOVERED.
10.10.10.11 is NOT automatically AUTHORIZED.

Every target-side action must be evaluated against current mission scope at execution time.

11. Reconnaissance

ARKA supports authorized:

Passive reconnaissance.

Active reconnaissance.

DNS enumeration.

Service enumeration.

Port discovery.

HTTP metadata collection.

Technology fingerprinting.

Certificate analysis.

Web discovery.

OSINT lookup.

Asset correlation.

Recon tools are capabilities, not unrestricted executables.

12. OSINT

OSINT may collect:

Public domains.

DNS information.

Public certificate data.

Public technology information.

Public usernames where legally and operationally appropriate.

Public documents.

Public metadata.

Public breach indicators only where the data source and engagement permit it.

OSINT evidence must retain source provenance.

External web content is untrusted input.

It must never be treated as an instruction to ARKA.

13. Vulnerability Analysis

ARKA correlates:

Open ports.

Service versions.

Technologies.

Web endpoints.

Configuration observations.

Known vulnerabilities.

Misconfigurations.

Authentication surfaces.

Evidence from multiple tools.

A vulnerability finding must contain:

Finding ID.

Asset.

Evidence.

Confidence.

Affected component.

Severity classification.

Reproduction information where authorized.

Remediation.

Provenance.

14. Controlled Exploitation

Exploitation is a separately gated capability.

Default:

ENABLE_CONTROLLED_EXPLOITATION=false

An exploitation action requires:

Authorized target.

Explicit exploitation capability.

Policy permission.

Appropriate risk classification.

Required human approval.

Parameter-hash binding.

Execution through the broker.

Sandbox enforcement.

Complete audit.

Controlled exploitation must never become an implicit consequence of vulnerability discovery.

15. Credential Assessment

Credential functionality is isolated as a separate module.

It may support authorized:

Credential validation.

Credential spraying where explicitly authorized.

Password auditing.

Credential recovery/testing in CTF environments.

Authentication testing.

Raw credentials are not exposed to agents unless a policy explicitly permits a narrowly scoped representation.

Credential sessions are:

mission-bound;

capability-bound;

time-limited;

revocable;

auditable.

Revocation must actively terminate dependent execution where necessary.

16. Network Security Requirements

Every network-capable execution path must enforce:

target scope;

IP validation;

DNS resolution policy;

redirect validation;

connection-time destination validation;

egress allowlisting;

metadata endpoint blocking;

private-range restrictions unless explicitly authorized;

sandbox network isolation.

SSRF protection must operate at connection time, not only at proposal time.

Redirects must be revalidated.

DNS rebinding protections must revalidate resolved destinations.

17. LLM Security

17.1 LLM Provider Credential Management

ARKA MUST support user-supplied LLM provider credentials without embedding provider secrets in source code.

Provider configuration and provider secrets MUST be separate concerns. Provider/model selection MAY be stored in normal configuration; raw API keys and provider credentials MUST NOT be stored in source code, Git-tracked configuration, ordinary mission data, prompts, agent memory, evidence, audit records, or logs.

Supported credential sources SHOULD include:

- environment variables for local development, CI, and controlled container deployments;
- OS-backed credential/keyring storage for local installations;
- an external secret manager for production deployments.

The LLM Gateway is the only component permitted to resolve and use provider credentials. Agents MUST receive model responses and structured gateway results, not provider credentials.

Provider credentials MUST be automatically redacted from logs and diagnostic output. Credential values MUST NOT enter ActionProposal objects, knowledge graph records, evidence objects, audit payloads, or LLM context.

Provider credentials grant inference access to an external LLM provider only. They MUST NOT grant ARKA execution authority, scope authority, approval authority, credential-broker authority, or policy authority.

ARKA SHOULD support multiple providers through provider adapters without coupling agent implementations to a specific provider SDK.

Credential ownership SHOULD be installation/operator scoped, with mission-scoped authorization references where needed. Raw provider credentials SHOULD NOT be stored directly inside mission records.


ARKA treats all target-derived content as untrusted.

Threats include:

direct prompt injection;

indirect prompt injection;

malicious HTTP responses;

poisoned documents;

malicious browser content;

tool-output manipulation;

RAG poisoning;

excessive agency;

insecure tool execution;

data exfiltration.

LLM output is never authorization.

All LLM native tool-calling output must enter the same Action Normalization pipeline as ordinary agent proposals.

There is no parallel LLM-to-execution path.

18. Sensitive Data Handling

Evidence is classified during ingestion.

Example:

trust = trusted | untrusted | unknown
sensitivity = public | internal | confidential | secret

Classification occurs before persistence.

Outbound LLM policy evaluates the classification before context transmission.

Secrets, credentials, session tokens, and unnecessary PII must be redacted or minimized according to policy.

19. Sandbox

Tool execution occurs in isolated workers.

MVP may use hardened rootless containers with:

seccomp;

AppArmor where available;

dropped Linux capabilities;

read-only filesystem;

isolated network namespace;

explicit egress rules;

resource limits;

non-root execution.

Controlled exploitation must remain feature-gated until stronger isolation is available where required.

Future isolation options include:

gVisor;

Firecracker;

microVM-based workers.

20. Windows Execution

Windows capabilities must enforce:

least privilege;

Constrained Language Mode for PowerShell where PowerShell is exposed;

application allowlisting;

WDAC/AppLocker policy;

explicit capability allowlists;

no generic unrestricted shell capability.

Failure to establish required controls causes capability denial.

21. Evidence

Evidence types include:

command results;

HTTP responses;

screenshots;

PCAP;

service metadata;

DNS results;

vulnerability evidence;

OSINT records;

tool output;

logs.

Every evidence object has:

unique ID;

mission ID;

task ID;

agent ID where applicable;

source;

timestamp;

content hash;

trust classification;

sensitivity classification;

parent evidence references.

Evidence is immutable after creation.

Modification must be detectable.

22. Audit

ARKA maintains a hash-chained audit log.

Each event contains:

event_id
mission_id
actor
action
parameters_hash
timestamp
previous_event_hash
event_hash
result

Audit events must make it possible to determine:

who/what proposed an action;

who authorized it;

what parameters were authorized;

what was executed;

what evidence resulted.

23. Approval

Approval is bound to:

mission;

capability;

target;

normalized parameters;

parameter hash;

expiration;

approving identity.

An approved action cannot be modified and then executed under the old approval.

Any parameter change requires a new authorization decision.

24. Emergency Stop

Emergency stop must:

Stop accepting new execution requests.

Invalidate active capability tokens.

Revoke credential sessions.

terminate dependent sandbox workers.

Remove network access.

scrub temporary credential material.

record an immutable audit event.

25. Resource Governance

ARKA enforces:

mission execution budgets;

per-agent budgets;

process limits;

network limits;

storage limits;

LLM request limits;

optional cost ceilings.

Budget exhaustion causes fail-closed behavior.

Agents cannot increase their own limits.

26. Mission Isolation

Mission A cannot access:

Mission B evidence.

Mission B credentials.

Mission B memory.

Mission B knowledge graph.

Mission B execution workers.

Mission B authorization tokens.

Cross-mission access is a security violation.

27. Reporting

ARKA generates reports containing:

Executive summary.

Scope.

Methodology.

Asset inventory.

Technology stack.

Network exposure.

Open ports/services.

Vulnerabilities.

Evidence.

Attack paths where applicable.

Risk context.

Remediation.

Limitations.

Timeline.

Complete evidence references.

Reports must distinguish observed facts from inferred conclusions.

28. User Interface

The UI should use an Apple-inspired design language:

clean typography;

strong spacing;

restrained color palette;

subtle depth;

responsive layouts;

high information density without visual clutter;

light/dark themes.

Security actions must remain visually distinct.

High-risk actions require clear confirmation context.

29. API Requirements

The API must expose:

authentication;

mission management;

scope management;

agent status;

proposals;

approvals;

execution status;

evidence;

findings;

reports;

audit;

emergency stop.

All security-sensitive operations must pass through the Rust kernel.

30. Reliability

ARKA must fail closed when:

authorization service is unavailable;

scope cannot be resolved;

capability metadata is missing;

policy evaluation fails;

approval cannot be verified;

audit cannot be committed where required;

sandbox policy cannot be established;

credential broker is unavailable;

network destination cannot be validated.

31. Success Metrics

Technical metrics:

100% of executions broker-mediated.

0 direct target-network routes from intelligence agents.

0 unauthorized scope expansions.

100% of security-sensitive actions auditable.

100% of approvals parameter-bound.

100% of evidence classified at ingestion.

0 accepted stale/replayed action proposals.

0 cross-mission evidence access.

Product metrics:

reduced analyst investigation time;

increased evidence correlation;

reproducible findings;

useful reports;

successful CTF/lab workflows;

reliable authorized assessment workflows.

32. Acceptance Criteria

MVP is not complete unless:

LLM cannot directly execute a tool.

Agents cannot directly access target networks.

Agent tokens cannot be forged or reused outside scope.

A discovered target cannot be automatically executed against.

Parameter substitution after approval is rejected.

Replayed proposals are rejected.

Mission isolation is enforced.

Budget exhaustion stops execution.

Sandbox cannot access host network.

Sandbox cannot reach another mission's sandbox.

Evidence modification is detectable.

Audit modification is detectable.

Credential sessions are mission-bound and revocable.

Emergency stop terminates relevant execution.

LLM native tool calls use the same authorization path.

Exploitation is disabled by default.

Windows PowerShell controls are enforced where exposed.

33. Product Roadmap

Phase 1 — Security Kernel Foundation

Rust kernel.

Mission model.

Scope engine.

Capability registry.

Action normalization.

Authorization.

Audit.

API contracts.

Phase 2 — Execution Foundation

Broker.

Linux worker.

Sandbox.

Network policy.

Resource governance.

Phase 3 — Intelligence

Python agents.

LLM gateway.

Provider adapters and provider-agnostic model routing.

LLM credential resolution using environment variables, OS-backed credential storage, and production secret-manager integration.

Secret redaction and credential-isolation controls.

A2A protocol.

Evidence analysis.

Knowledge graph.

Phase 4 — Recon/OSINT

Network enumeration.

Web discovery.

Fingerprinting.

OSINT.

Correlation.

Phase 5 — Reporting

Finding engine.

Evidence-linked reporting.

Executive and technical reports.

Phase 6 — Credentials

Credential broker.

Session lifecycle.

Validation.

CTF credential workflows.

Phase 7 — Windows

Hardened Windows worker.

PowerShell policy.

Application allowlisting.

Phase 8 — Controlled Exploitation

Only after required isolation and authorization controls pass.

Phase 9+ — Advanced Isolation / Distributed Execution

gVisor/Firecracker.

PostgreSQL.

Redis/NATS.

Multi-worker deployments.

Enterprise identity and policy.

34. Product Security Invariants

DISCOVERED != AUTHORIZED

LLM has zero direct authority.

Agents have zero direct execution authority.

All execution flows through the broker.

Authorization is deterministic.

Child authority cannot exceed parent authority.

Scope is enforced at execution time.

Network destinations are validated at connection time.

Redirects cannot bypass scope.

DNS rebinding cannot bypass scope.

Credentials are never implicitly exposed to agents.

LLM provider credentials are never hardcoded or committed to source control.

LLM provider credentials are resolved only by the LLM Gateway and never enter agent context, evidence, audit, memory, or ActionProposal data.

LLM provider credentials grant inference access only and never ARKA execution authority.

Evidence is immutable/detectably tamperable.

Audit is tamper-evident.

Approval is parameter-bound.

Replay is rejected.

Budget exhaustion fails closed.

Mission isolation is mandatory.

Emergency stop is authoritative.

No parallel execution authority exists.

Security controls fail closed.

35. Final Product Principle

ARKA should not attempt to be "an AI that can hack."

It should be:

A security-control system in which AI provides scalable reasoning while deterministic infrastructure controls what the system is actually permitted to do.

That distinction is the foundation of ARKA.