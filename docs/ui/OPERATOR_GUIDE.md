# ARKA Web Console — Operator Workflow Guide

## 1. Primary Operational Workflow

The ARKA Unified Security Operations Console enables a security operator to conduct end-to-end autonomous assessments visually without opening a terminal:

```
Configure System
       ↓
Create Assessment Wizard (9 Steps)
       ↓
Define Scope & Exclusions (Exclusions Override)
       ↓
Authoritative Scope Preview
       ↓
Launch Assessment
       ↓
Monitor Multi-Agent Trajectory
       ↓
Inspect Candidate Tool Requests & Policy Decisions
       ↓
Approve Exact Request (Cryptographic Hash Bound)
       ↓
Inspect Attack Surface (Discovered != Authorized)
       ↓
Propose Scope Deltas (PRD-029)
       ↓
Validate Epistemic Findings (Human Confirmation)
       ↓
Explore Graphify Attack Relationships
       ↓
Compile Authoritative Report
```

---

## 2. Step-by-Step Operator Instructions

### 2.1 Launching an Assessment
1. Navigate to **Assessments** → **Create Assessment** (`/assessments/create`).
2. **Step 1**: Enter assessment name, objective, and check the **Formal Authorization Affirmation**.
3. **Step 2 & 3**: Enter included domains (e.g. `127.0.0.1`, `localhost`), URLs (e.g. `http://127.0.0.1:3000`), and permitted ports (`3000, 80, 443`).
4. **Step 4**: Enter excluded paths or IPs (e.g. `/admin`, `/ftp`). *Exclusions strictly override inclusions*.
5. **Step 5**: Select the profile archetype (e.g. `Web Application — Safe`).
6. **Step 6**: Provide the Vault Secret Reference for credentials.
7. **Step 7**: Set deterministic resource envelopes (Max runtime, max requests, concurrency).
8. **Step 8**: Inspect the compiled **Effective Scope Preview**.
9. **Step 9**: Verify control plane invariant checks and click **Create Assessment**.

### 2.2 Approving Gated Tool Requests (SEC-01)
1. When an agent proposes a high-risk tool operation (e.g. fuzzing or vulnerability scan), it appears in the **Approvals Center** (`/approvals`).
2. Click **Inspect** to examine:
   - Tool name and exact action.
   - Target host/URL.
   - Full argument JSON payload.
   - Cryptographic SHA-256 argument hash.
3. Click **Approve Exact Request** to authorize that specific execution, or **Reject** to abort it.
   - *Note*: An approval token is valid solely for the exact arguments inspected. Any argument mutation causes the backend to reject execution with code `403`.

### 2.3 Managing Discovered Attack Surface
1. Navigate to **Attack Surface** (`/attack-surface`).
2. Inspect discovered assets, services, and exposed endpoints.
3. Items marked `DISCOVERED — NOT AUTHORIZED` cannot be probed by agents.
4. To include an asset, click **Propose Scope Delta**. Review the boundary impact and commit the change to produce an immutable scope version.

### 2.4 Validating Findings on the Epistemic Ladder
1. Navigate to **Findings** (`/findings`).
2. Select a finding to view its **Epistemic Ladder**:
   - `OBSERVED`: Raw tool telemetry.
   - `CANDIDATE`: Untrusted hypothesis from LLM.
   - `SUPPORTED`: Multi-source telemetry agreement.
   - `VALIDATED`: Deterministic verification passed.
   - `HUMAN CONFIRMED`: Authoritative sign-off by human operator.
3. To confirm a finding, enter operator verification notes and click **Confirm Finding as Operator**.

### 2.5 Emergency Killswitch
- At any time, click the high-visibility red **HALT AGENTS** button in the top navigation bar.
- Provide a justification reason and click **EXECUTE IMMEDIATE HALT**. This immediately revokes active tokens, aborts running agent reasoning loops, and terminates tool sandboxes.
