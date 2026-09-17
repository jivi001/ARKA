# ARKA Security UX & Behavioral Guardrails

## 1. Core Security UX Invariants

In the ARKA Web Security Operations Console, every design and interaction decision is governed by defensive cybersecurity principles:

1. **Explicit Authorization Visibility**
   - The UI strictly differentiates `AUTHORIZED` assets from `DISCOVERED — NOT AUTHORIZED` assets.
   - Discovered assets are displayed in muted slate badges with warning icons, actively preventing operator assumption that discovered equals scanned.

2. **No Bulk Approval Bypass**
   - The UI deliberately does not implement "Approve All", "Approve Tool Forever", or "Skip Policy Checks".
   - Every gated operation requires approving an exact request bound to its arguments hash ($`\text{SHA-256}`$).

3. **Zero Execution Authority in Browser**
   - The Web Console is purely an observational and decision interface.
   - Browser code never spawns subprocesses, never opens raw TCP/UDP sockets, never talks directly to Docker/Nmap/Nuclei, and never holds raw secrets or passwords in client storage.

4. **Epistemic Truthfulness**
   - The UI visually separates LLM hypothesis confidence (e.g. 85%) from deterministic validation (ScopeGuard + replay passing) and authoritative human confirmation.
   - LLM responses are never rendered as unquestioned findings.

5. **Fail-Closed Presentation**
   - If the backend API or streaming bus is temporarily disconnected, the UI transitions to an explicit error/stale warning state. It never falls back to an `ALLOW` assumption.

---

## 2. Anti-Patterns Explicitly Avoided

| Anti-Pattern | Reason for Exclusion |
|---|---|
| *"Enable Autonomous Hacking"* | Marketing hype that obscures control boundaries. ARKA operates as an authorized assessment engine with deterministic policy gating. |
| *"Trust Discovered Assets"* | Violates `INV-2`. Automated target expansion leads to out-of-scope liability and SSRF risks. |
| *"Approve All Pending Requests"* | Violates `INV-1` and enables confused-deputy attacks. |
| *"Expose Credentials in Plaintext"* | Violates credential isolation principles. Secrets remain in backend vault references. |
| *"LLM-Driven Policy Changes"* | LLM cannot modify policy matrices or scope rules. |
