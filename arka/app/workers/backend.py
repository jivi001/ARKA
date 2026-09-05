"""Worker backend abstraction for ARKA task execution.

Provides a clean boundary between task scheduling and execution:
- ArqWorkerBackend: production, uses Redis/ARQ queue
- InProcessWorkerBackend: development, uses asyncio.create_task()

Both backends execute through the SAME security pipeline.
The InProcessWorkerBackend is NOT a security bypass.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

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
                await self._orchestrator.execute(task_id)
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


class ArqWorkerBackend(WorkerBackend):
    """Production worker that enqueues tasks to Redis via ARQ."""

    def __init__(self, redis_pool=None) -> None:
        self._redis = redis_pool

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
