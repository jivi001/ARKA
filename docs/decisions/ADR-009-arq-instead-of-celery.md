# ADR-009: Arq for Asynchronous Job Queuing Instead of Celery

## Status
Accepted

## Context
Long-running penetration testing operations (such as extensive port scans, web directory fuzzing, or batch asset enumeration) cannot block FastAPI HTTP request threads. We require a distributed task queue that integrates cleanly with Python's `asyncio` event loop.

## Decision
We select **Arq** (`arq>=0.26`) paired with **Redis** as the asynchronous job queue (`arka/app/workers/arq_worker.py`), rather than Celery.

## Alternatives Considered
1. **Celery**: Industry standard, but historically synchronous/thread-pool based, heavyweight configuration, complex result backends, and awkward native `asyncio` support.
2. **RQ (Redis Queue)**: Simple, but also synchronous worker based.
3. **FastAPI BackgroundTasks**: Suitable for lightweight post-request cleanup, but lacks distributed worker pooling, retries, concurrency limits, and worker restart survival.

## Consequences
- **Positive**: Native `asyncio` support, lightweight codebase, minimal configuration overhead, high throughput, and seamless Redis integration.
- **Negative**: Smaller community ecosystem compared to Celery; requires Redis broker.

## Security Implications
Task payloads are serialized as JSON and executed within worker worker boundaries with configured timeout limits (`job_timeout = 600`).

## Date
2026-08-19
