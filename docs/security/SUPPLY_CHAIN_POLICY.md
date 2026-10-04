# ARKA Supply Chain Security Policy & Tooling Rationale

## 1. Scope & Security Boundary
As established in TRD Section 52 and PRD Section 12, the repository and build pipeline represent a critical trust boundary ($TB_{CI}$). An attacker capable of poisoning third-party dependencies, injecting unvetted transitive libraries, or introducing leaked secrets can compromise platform integrity before runtime defenses take effect.

---

## 2. Tool Selection, Rationale, and Failure Behaviors

| Tool | Purpose & Ecosystem | Version Pinning | Invocation Command | Failure Behavior | Limitations |
|---|---|---|---|---|---|
| **pip-audit** | Python dependency vulnerability scanner | PyPI release / action | `pip-audit` | **FAIL-CLOSED (Exit Code 1)**: Any known vulnerability terminates CI pipeline. | Relies on OSV and PyPI advisory databases; cannot detect 0-day supply chain malicious code. |
| **pnpm audit** | Next.js frontend dependency scanner | Built-in pnpm v9+ | `pnpm audit --prod --audit-level=high` | **FAIL-CLOSED (Exit Code 1)**: High/Critical severity advisories block the merge. | Limited to npm registry security advisories; dev-only dependencies exempted if `--prod` used. |
| **gitleaks** | Static secret and credential leak detection | Action SHA `b04eb32` | `gitleaks detect --verbose` | **FAIL-CLOSED (Exit Code 1)**: Prevents committing API keys, private keys, or tokens. | Regex and entropy heuristics; custom internal secret formats require dedicated rules. |
| **CycloneDX** | Software Bill of Materials (SBOM) generation | `cyclonedx-bom` | `cyclonedx-py environment -o sbom.json` | **FAIL-CLOSED**: Failure to generate machine-readable SBOM blocks build. | Reflects installed packages in the build environment; must run after clean dependency resolution. |

---

## 3. GitHub Actions Hardening Invariants

1. **Explicit Minimal Permissions**:
   Every workflow explicitly declares top-level `permissions: contents: read`. No workflow job inherits write permissions unless explicitly required and documented.
2. **Immutable Action Commit SHAs**:
   All third-party GitHub Actions must be pinned to full 40-character commit SHAs (e.g. `actions/checkout@11bd7190...`). Moving tags (`@v4`, `@main`, `@latest`) are strictly forbidden.
3. **Protection Against Fork Pull Request Exploitation**:
   - `pull_request_target` triggers are completely prohibited for any workflow executing code from pull requests.
   - Workflows triggered on `pull_request` run in an unprivileged context without access to write tokens or production secrets.
4. **Mandatory Human Code Ownership**:
   All changes to `.github/`, `.github/workflows/`, and `/security/` require approval from `@jivi001` per `.github/CODEOWNERS`.
