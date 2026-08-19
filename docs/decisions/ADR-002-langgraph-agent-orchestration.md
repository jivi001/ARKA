# ADR-002: LangGraph for Agent Orchestration

## Status
Accepted

## Context
Penetration testing agents require complex multi-step reasoning, cyclical retry loops, branching decision trees, state persistence across long-running tasks, and human-in-the-loop interruption capabilities. Linear agent abstractions (such as simple ReAct loops or autogen) lack first-class state checkpointing and fine-grained graph control.

## Decision
We adopt **LangGraph** as the agent orchestration framework. Agents are modeled as directed cyclic state graphs with explicit state schemas (`OrchestratorState`), reducer channels, and native `interrupt()` mechanisms for human authorization gates.

## Alternatives Considered
1. **Custom Python Async While-Loop**: Feasible but requires re-implementing state checkpointing, branch routing, and pause/resume logic from scratch.
2. **AutoGPT / CrewAI**: Opinionated multi-agent frameworks with weak deterministic security boundaries and limited checkpointing support.

## Consequences
- **Positive**: Native cyclical execution, robust thread checkpointing in PostgreSQL, clear separation of graph nodes, and built-in human-in-the-loop pause/resume.
- **Negative**: Learning curve for LangGraph state reducers and graph compilation.

## Security Implications
Graph state is serialized through trusted reducers. The graph cannot transition to privileged execution nodes without passing policy evaluation.

## Date
2026-08-19
