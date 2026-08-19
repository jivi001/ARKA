# ADR-010: Remote LLM by Default with VPC and Private Provider Support

## Status
Accepted

## Context
High-reasoning intelligence is required for autonomous vulnerability synthesis and multi-step attack planning. While state-of-the-art hosted models (e.g. OpenAI GPT-4o, Anthropic Claude 3.5 Sonnet) offer superior reasoning, enterprise security environments often mandate private, on-premises, or VPC-hosted LLM deployments to prevent sensitive security findings from leaving private networks.

## Decision
ARKA defaults to remote frontier model APIs via `LiteLLM` while providing first-class architectural support for private, self-hosted, and VPC-isolated model endpoints (via `LLMProvider.CUSTOM`, `ARKA_LLM_BASE_URL`, vLLM, Ollama, and Nvidia NIM).

## Alternatives Considered
1. **Local-Only LLM Requirement**: Forcing all deployments to run local 7B/13B models. Rejected because local open-weight models frequently fail complex penetration testing reasoning and structured JSON generation.
2. **Proprietary Cloud-Only Binding**: Relying solely on a single cloud vendor's API. Rejected because it precludes high-security air-gapped enterprise deployments.

## Consequences
- **Positive**: Best-in-class reasoning for standard deployments; enterprise compliance and privacy for air-gapped or VPC deployments.
- **Negative**: Self-hosted local models require GPU infrastructure and may require prompt tuning for structured output reliability.

## Security Implications
When operating with third-party cloud APIs, target credentials and sensitive customer data are sanitized before LLM context serialization. In VPC mode, zero data leaves the customer's network boundary.

## Date
2026-08-19
