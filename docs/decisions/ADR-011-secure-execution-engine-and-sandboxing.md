# ADR-011: Secure Execution Engine and Sandbox Isolation Architecture

## Status
Accepted

## Context
In Phase 1, tool execution was mediated by `ToolRegistry` and executed in-process with mock executors. For Phase 2 and beyond, real offensive and reconnaissance tools (Nmap, ffuf, Nuclei, ZAP) will execute. Direct execution on the host OS poses significant security risks: container breakout, arbitrary shell injection, resource exhaustion, secret leakage, and unconstrained network egress.

## Decision
We implement a decoupled execution engine layer (`arka/app/execution/`):
1. **`ExecutionManager`**: Authoritative execution bridge between the control plane and sandbox isolation runtimes. Only accepts authoritative `ToolRequest` objects stamped with `scope_validated=True` and `policy_approved=True`.
2. **`ExecutionPolicy`**: Enforces strict runtime constraints: forbids shell interpreters (`sh`, `bash`, `cmd.exe`, `powershell.exe`, etc.), requires argument arrays, sanitizes runtime environments (scrubbing secrets and dangerous vars like `LD_PRELOAD`), and enforces network isolation.
3. **`SandboxRuntime` Abstraction**: Hides isolation mechanics behind `create()`, `execute()`, `terminate()`, `destroy()`, and `collect_metadata()`.
   - `LocalSafeRuntime`: Safe in-memory simulation for local testing with zero shell execution and zero network access.
   - `DockerSandboxRuntime`: Least-privilege container baseline (non-root `1000:1000`, read-only rootfs, `ALL` capabilities dropped, `no-new-privileges:true`, no `/var/run/docker.sock`, `network_mode="none"`).
4. **`EvidenceStore`**: Captures SHA-256 cryptographic provenance for all execution outputs.

## Alternatives Considered
1. **Direct Subprocess in Tool Adapters**: Rejected because security controls, resource limits, and sandboxing would be duplicated across each tool adapter.
2. **Privileged Containers with Full Network**: Rejected as a fundamental violation of least privilege and container security best practices.

## Consequences
- **Positive**: Complete decoupling of tool adapters from execution mechanics, rigorous sandbox isolation, cryptographic evidence non-repudiation, and uniform timeout and output byte truncation.
- **Negative**: Adds execution orchestration layer and requires container configuration management for future tool containers.

## Security Implications
Guarantees that untrusted LLM outputs and candidate requests cannot invoke subprocesses or bypass sandbox controls. Ensures defense-in-depth isolation, prevents secret leakage into runtime processes, and maintains non-repudiation of security assessment evidence.

## Date
2026-08-19
