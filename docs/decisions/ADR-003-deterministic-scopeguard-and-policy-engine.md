# ADR-003: Deterministic ScopeGuard and PolicyEngine

## Status
Accepted

## Context
Generative LLMs are probabilistic models susceptible to prompt injection, hallucinations, and goal manipulation. Permitting an LLM to decide whether a target is authorized or whether an action is safe creates unacceptable legal and operational risks.

## Decision
We enforce a zero-trust model where all scope and policy checks are executed strictly by deterministic Python components (`ScopeGuard` and `PolicyEngine`). The LLM's role is strictly limited to proposing untrusted `CandidateToolRequest` objects.

## Alternatives Considered
1. **LLM-Based Policy Verification (Guardrail Agents)**: Asking a secondary LLM "is this target in scope?". Rejected due to vulnerability to adversarial jailbreaks and non-deterministic behavior.
2. **Post-Execution Filtering**: Executing the tool and filtering out-of-scope results. Rejected because unauthorized network scanning is illegal regardless of whether results are discarded.

## Consequences
- **Positive**: 100% deterministic, mathematically verifiable scope containment. Exclusions always override inclusions. Zero chance of prompt injection bypassing scope boundaries.
- **Negative**: Requires strict syntax parsing for IP, CIDR, domain, URL, and port formats.

## Security Implications
Guarantees that no offensive tool or network packet can target an unauthorized system, even if the model is fully compromised by prompt injection.

## Date
2026-08-19
