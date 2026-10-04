# ARKA Branch Protection & Security Governance Specification

## Enforcement Status: `BLOCKED_EXTERNAL_CONFIGURATION`

> [!WARNING]
> Automated API enforcement of branch protection rules via GitHub API is currently classified as `BLOCKED_EXTERNAL_CONFIGURATION`. The local environment authenticates via Git SSH protocol without administrative GitHub Personal Access Token (PAT) privileges with `repo:admin` scope.
>
> In accordance with ARKA Hard Security Rule #3 and Section 25, the repository owner (`@jivi001`) must manually configure the branch protection rules specified below in GitHub Repository Settings.

---

## Required Branch Protection Rules for `main`

Navigate to: `https://github.com/jivi001/ARKA/settings/branches`

Click **Add branch protection rule** for branch pattern: `main`

### 1. Require a Pull Request Before Merging
- [x] **Require a pull request before merging**
- [x] **Require approvals**: Minimum `1` approval required.
- [x] **Dismiss stale pull request approvals when new commits are pushed**
- [x] **Require review from Code Owners** (Enforces `.github/CODEOWNERS` for `/security/`, `/arka/core/crypto/`, and `/.github/workflows/`).
- [x] **Restrict who can dismiss pull request reviews** (Designated Platform Administrators only).

### 2. Require Status Checks to Pass Before Merging
- [x] **Require status checks to pass before merging**
- [x] **Require branches to be up to date before merging**
- **Mandatory Blocking Checks**:
  1. `CI-SEC-MODEL` (Validates threat model schemas, referential integrity, and stable IDs)
  2. `CI-SEC-TRACEABILITY` (Validates 100% threat-to-control-to-test-to-gate coverage)
  3. `CI-SEC-VALIDATOR` (Executes full validator suite and meta-test rejection suite)
  4. `CI-SEC-SECRETS` (Gitleaks scan against credential leaks)
  5. `CI-SEC-DEPENDENCIES` (pip-audit Python vulnerability check + pnpm audit frontend check)
  6. `CI-SEC-SBOM` (CycloneDX SBOM generation and manifest verification)

### 3. Strict Merge Restrictions
- [x] **Require signed commits** (Cryptographic commit verification).
- [x] **Require linear history** (Prevent merge commits; enforce rebase or squash).
- [x] **Do not allow bypassing the above settings** (Enforce rules for administrators and repository owners alike).
- [x] **Restrict who can push to matching branches** (Completely disallow direct pushes to `main`).

---

## Audit Verification Command
Once enabled by the repository owner, verify repository protection status via:
```bash
curl -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/jivi001/ARKA/branches/main/protection
```
