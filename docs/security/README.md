# ARKA Security Documentation Index

This directory contains the authoritative architecture plans, checkpoint verification reports, security policies, and audit documentation for the ARKA project.

---

## Architecture & Policy

- 📄 [Phase 1 Architecture & Execution Plan](PHASE_1_ARCHITECTURE_PLAN.md): Formal architectural blueprint, multi-crate layout, token design, and checkpoint progression strategy for the Phase 1 Security Kernel.
- 📄 [Phase 0 Security Foundation Report](P0_SECURITY_FOUNDATION_REPORT.md): Comprehensive report covering the machine-readable threat model, 38 controls, 36 acceptance gates, and 100% bidirectional traceability.
- 📄 [Branch Protection & Governance Specification](BRANCH_PROTECTION.md): Required branch protection rules, code owners, and signed commit requirements.
- 📄 [Supply Chain Security Policy](SUPPLY_CHAIN_POLICY.md): Dependency pinning, SBOM generation, vulnerability scanning, and license compliance rules.

---

## Phase 1 Implementation Checkpoint Reports

The Phase 1 Security Kernel was constructed under strict, evidence-backed checkpoint gates with zero unsafe code (`#![forbid(unsafe_code)]`):

1. 📄 [Checkpoint P1-A Verification Report](CHECKPOINT_P1_A_REPORT.md):
   - Cryptographic Ed25519 authentication tokens with RFC 8785 canonical claims and `ARKA-TOKEN-V1:` domain separation.
   - Strongly-typed identifier primitives (`MissionId`, `OperatorId`, `AgentId`, `TaskId`, `CapabilityId`, `TokenId`).
   - 5-state mission lifecycle state machine (`Created`, `Active`, `Paused`, `Completed`, `Terminated`).
   - Tenant isolation and error oracle defense masking internal state.

2. 📄 [Checkpoint P1-B Verification Report](CHECKPOINT_P1_B_REPORT.md):
   - Canonical target representations (`Ip`, `IpPort`, `Cidr`, `Domain`, `UrlOrigin`).
   - Negative bypass parser defenses: octal/hex IP rejection, decimal integers, IPv4-mapped IPv6 normalization, URL userinfo (`@`) and host confusion (`\`) rejection.
   - Deterministic offline Scope Engine: Exclusions unconditionally override Inclusions; default-deny; cloud metadata (`169.254.169.254`) blocked by default.

3. 📄 [Checkpoint P1-C Verification Report](CHECKPOINT_P1_C_REPORT.md):
   - Capability Registry cataloging 11 standard capabilities with authoritative risk classes (`Observation`, `Low`, `Moderate`, `High`, `Critical`).
   - Generic unrestricted shell prohibition (`SHELL`, `BASH`, `SH`, `CMD` rejected).
   - Single normalization boundary (`ActionNormalizer`): max 64KB, depth $\le 8$, duplicate key rejection, `#[serde(deny_unknown_fields)]`.
   - Immutable `CanonicalAction` construction with domain-separated SHA-256 hashes (`ARKA-PARAM-V1:`, `ARKA-ACTION-V1:`).

4. 📄 [Checkpoint P1-D Verification Report](CHECKPOINT_P1_D_REPORT.md):
   - Deterministic Policy Engine returning `Allow`, `Deny`, or `RequireApproval`.
   - Monotonic Authority delegation validating child subset bounds across 6 dimensions.
   - TOCTOU Parameter Hash Binding: Two-Person Integrity approvals cryptographically bound to exact canonical action hash.
   - SQLite WAL atomic Replay Protection using `BEGIN IMMEDIATE` and unique constraints (verified with 10-thread concurrent stress test).

5. 📄 [Checkpoint P1-E Verification Report](CHECKPOINT_P1_E_REPORT.md):
   - Dual SHA-256 cryptographic audit hash chains (Global System and Per-Mission) with Ed25519 digital signatures (`AUDIT-SIGNING`).
   - Detection of payload tampering, broken previous hash links, signature forgery, and sequence gaps.
   - Atomic Unit of Work: State transition, replay consumption, approval verification, and dual audit appends commit atomically.
   - Persistent monotonic Emergency Stop surviving engine and database reboots.

---

## Completion & Verification Audit Reports

- 📄 [Phase 1 Completion Report](PHASE_1_COMPLETION_REPORT.md): Final completion report for the Phase 1 Security Kernel foundation, providing answers to the 22 mandatory adversarial questions and verification metrics.
- 📄 [Phase 1 Multi-Agent Verification Audit Report](PHASE_1_VERIFICATION_AUDIT_REPORT.md): Multi-agent, strictly read-only audit report conducted by 6 specialized audit subagents (Repository, PRD/TRD, Assurance Tests, Adversarial Scope, Persistence/Audit/E-Stop, and Production Readiness).
- 📄 [Phase 1 Remediation Execution Plan](PHASE_1_REMEDIATION_PLAN.md): Formal architectural remediation plan, dependency impact analysis, and single-writer implementation strategy.
- 📄 [Phase 1 Remediation Verification Report](PHASE_1_REMEDIATION_REPORT.md): Definitive resolution and verification report confirming all findings resolved (`PHASE 1 — PASS`, `GO TO PHASE 2`).
- 📄 [Phase 1 Independent Security Re-Audit Report](PHASE_1_INDEPENDENT_RE_AUDIT_REPORT.md): Independent post-remediation security re-audit report and final GO/NO-GO gatekeeper determination confirming all security invariants proven and authorizing transition to Phase 2.

