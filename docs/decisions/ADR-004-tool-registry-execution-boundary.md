# ADR-004: Tool Registry as Exclusive Execution Boundary

## Status
Accepted

## Context
Allowing agents or orchestrator nodes to directly instantiate or execute tool binaries, subprocesses, or network clients makes centralized policy enforcement, schema validation, timeout handling, and auditing difficult to maintain and verify.

## Decision
We establish `ToolRegistry` (`arka/app/tools/registry/registry.py`) as the sole entry point and security boundary for tool validation and execution. An untrusted `CandidateToolRequest` must be validated by the registry to mint an authoritative `ToolRequest` before execution can occur.

## Alternatives Considered
1. **LangChain Tool Decorators**: Tools are callable functions directly accessible to agents. Lacks centralized scope mediation and parameter type validation.
2. **Direct Subprocess Spawning in Nodes**: Spawning `subprocess.Popen` directly within graph nodes. Rejected due to lack of isolation and audit fragmentation.

## Consequences
- **Positive**: Strict input schema validation (rejecting unknown arguments and type mismatches), asynchronous timeout enforcement, unified error handling, and guaranteed audit trail creation.
- **Negative**: All new tools must register explicit JSON schemas and implement `ToolExecutor`.

## Security Implications
Prevents argument injection attacks, catches malformed tool payloads, and ensures unapproved tools cannot be executed.

## Date
2026-08-19
