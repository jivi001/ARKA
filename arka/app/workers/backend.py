"""Worker backend abstraction for ARKA task execution.

Provides a clean boundary between task scheduling and execution:
- ArqWorkerBackend: production, uses Redis/ARQ queue
- InProcessWorkerBackend: development, uses asyncio.create_task()

Both backends execute through the SAME security pipeline.
The InProcessWorkerBackend is NOT a security bypass.
"""

from __future__ import annotations

import asyncio
import inspect
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from arq.connections import ArqRedis

from arka.app.observability.logging import get_logger

if TYPE_CHECKING:
    from arka.app.orchestration.recon_service import ReconOrchestrationService

logger = get_logger(__name__)


class WorkerBackend(ABC):
    """Abstract worker backend for task execution."""

    @abstractmethod
    async def enqueue_recon(
        self,
        task_id: str,
        engagement_id: str,
        objective: str,
        max_iterations: int,
    ) -> str:
        """Enqueue a recon task for asynchronous execution.

        Returns a job identifier.
        """

    @abstractmethod
    async def close(self) -> None:
        """Deterministically close and clean up worker backend resources."""


class InProcessWorkerBackend(WorkerBackend):
    """Development worker that runs tasks in-process via asyncio.

    Uses the SAME orchestration service and security pipeline as production.
    The only difference is scheduling mechanism (asyncio vs Redis queue).
    """

    def __init__(self, orchestrator: ReconOrchestrationService) -> None:
        self._orchestrator = orchestrator
        self._tasks: dict[str, asyncio.Task] = {}

    async def enqueue_recon(
        self,
        task_id: str,
        engagement_id: str,
        objective: str,
        max_iterations: int,
    ) -> str:
        """Execute recon task in-process via asyncio.create_task()."""
        logger.info(
            f"InProcessWorkerBackend: scheduling recon task {task_id} "
            f"for engagement {engagement_id}"
        )

        async def _run() -> None:
            try:
                await self._orchestrator.execute(task_id, auto_mark_failed=True)
            except Exception:
                logger.error(
                    f"InProcessWorkerBackend: task {task_id} raised exception",
                    exc_info=True,
                )
            finally:
                self._tasks.pop(task_id, None)

        bg_task = asyncio.create_task(_run())
        self._tasks[task_id] = bg_task
        return task_id

    async def wait_for_task(self, task_id: str, timeout: float = 5.0) -> None:
        """Wait for an in-process background task to complete execution."""
        task = self._tasks.get(task_id)
        if task is not None and not task.done():
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
            except (TimeoutError, asyncio.TimeoutError):
                logger.warning(
                    f"InProcessWorkerBackend: wait_for_task timed out after "
                    f"{timeout}s for task {task_id}"
                )
                raise TimeoutError(f"Task {task_id} did not finish within {timeout}s") from None

    async def close(self) -> None:
        """Cancel and clean up any in-process tasks."""
        tasks = list(self._tasks.values())
        for t in tasks:
            if not t.done():
                t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()


class ArqWorkerBackend(WorkerBackend):
    """Production worker that enqueues tasks to Redis via ARQ.

    Redis pool ownership is explicit:
    - If pool is provided (e.g. from FastAPI lifespan), lifespan owns its lifecycle.
    - ArqWorkerBackend does not close pools it does not own.
    """

    def __init__(self, redis_pool: ArqRedis | None = None, owns_pool: bool = False) -> None:
        self._redis = redis_pool
        self._owns_pool = owns_pool

    @property
    def redis(self) -> ArqRedis | None:
        return self._redis

    def set_redis_pool(self, redis_pool: ArqRedis | None, owns_pool: bool = False) -> None:
        self._redis = redis_pool
        self._owns_pool = owns_pool

    async def enqueue_recon(
        self,
        task_id: str,
        engagement_id: str,
        objective: str,
        max_iterations: int,
    ) -> str:
        """Enqueue recon task to Redis/ARQ for worker consumption."""
        if self._redis is None:
            raise RuntimeError("ARQ Redis pool not initialized")

        job = await self._redis.enqueue_job(
            "run_orchestrator_task",
            task_id,
            engagement_id,
            objective,
            max_iterations,
        )
        job_id = job.job_id if job else task_id
        logger.info(f"ArqWorkerBackend: enqueued task {task_id} as job {job_id}")
        return job_id

    async def close(self) -> None:
        """Close worker backend resources deterministically."""
        if self._redis is not None and self._owns_pool:
            logger.info("ArqWorkerBackend: closing owned Redis connection pool")
            if hasattr(self._redis, "aclose"):
                await self._redis.aclose()
            elif hasattr(self._redis, "close"):
                res = self._redis.close()
                if inspect.isawaitable(res):
                    await res
            self._redis = None
