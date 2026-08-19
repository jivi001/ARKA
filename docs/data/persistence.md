# State Persistence & LangGraph Checkpointing

This document describes state persistence across multi-turn agent loops and distributed worker queues.

---

## 1. LangGraph Durable Checkpointing

ARKA orchestrator graphs use `AsyncPostgresSaver` (`langgraph.checkpoint.postgres.aio`) to store serialized state checkpoints in PostgreSQL:

- **Checkpoints Table**: Saves complete state snapshots for each node transition keyed by `thread_id` and `checkpoint_ns`.
- **Checkpoint Writes Table**: Tracks granular channel updates and pending interrupts.
- **Resilience**: If the API server crashes during an assessment, the agent resumes execution from the exact last completed node without re-executing previous tasks.

---

## 2. In-Memory MemorySaver Fallback

During unit and security testing where an external PostgreSQL database is not connected, the orchestrator graph dynamically initializes with `langgraph.checkpoint.memory.MemorySaver`. This allows full graph execution, interruption, and resumption testing in pure in-memory isolation.

---

## 3. Distributed Asynchronous Worker (Arq & Redis)

- **Worker Module**: `arka/app/workers/arq_worker.py`
- **Redis Queue**: Long-running tool executions and batch reconnaissance tasks are queued in Redis and executed by background Arq worker processes.
- **Worker Configuration**:
  ```python
  class WorkerSettings:
      functions = [execute_tool_task, run_agent_task]
      redis_settings = RedisSettings.from_dsn(settings.redis_url)
      max_jobs = 10
      job_timeout = 600
  ```
