"""Async PostgreSQL task persistence for ARKA orchestration.

Provides transactional task CRUD with engagement isolation.
All queries are parameterized. No raw SQL string concatenation.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from arka.app.database.models import Task
from arka.app.observability.logging import get_logger

logger = get_logger(__name__)


class TaskRepository:
    """Async PostgreSQL repository for persistent task state.

    Every method operates within a transactional session.
    Engagement isolation is enforced on all queries.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create_task(
        self,
        engagement_id: str,
        task_type: str,
        name: str,
        objective: str = "",
        max_iterations: int = 10,
        agent_id: str = "recon_agent",
        description: str = "",
    ) -> Task:
        """Create a new persistent task in 'queued' status."""
        async with self._session_factory() as session:
            async with session.begin():
                task = Task(
                    id=uuid.uuid4(),
                    engagement_id=uuid.UUID(engagement_id),
                    agent_id=agent_id,
                    name=name,
                    description=description,
                    task_type=task_type,
                    objective=objective,
                    max_iterations=max_iterations,
                    status="queued",
                )
                session.add(task)
            await session.refresh(task)
            logger.info(
                f"Task created: id={task.id}, engagement={engagement_id}, "
                f"type={task_type}, status=queued"
            )
            return task

    async def get_task(self, task_id: str) -> Task | None:
        """Load a task by its primary key."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(Task).where(Task.id == uuid.UUID(task_id))
            )
            return result.scalar_one_or_none()

    async def get_tasks_by_engagement(
        self,
        engagement_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Task]:
        """Load all tasks for an engagement, ordered by creation time."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(Task)
                .where(Task.engagement_id == uuid.UUID(engagement_id))
                .order_by(Task.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return list(result.scalars().all())

    async def mark_started(self, task_id: str) -> Task | None:
        """Transition task from 'queued' to 'running'."""
        async with self._session_factory() as session:
            async with session.begin():
                result = await session.execute(
                    update(Task)
                    .where(Task.id == uuid.UUID(task_id), Task.status == "queued")
                    .values(status="running", started_at=datetime.now(UTC))
                    .returning(Task)
                )
                row = result.scalar_one_or_none()
                if row is None:
                    logger.warning(f"Task {task_id} not found or not in 'queued' state")
                else:
                    logger.info(f"Task {task_id} marked as running")
                return row

    async def mark_completed(
        self,
        task_id: str,
        output_data: dict[str, Any] | None = None,
        evidence_refs: list[str] | None = None,
    ) -> Task | None:
        """Transition task to 'completed' with results."""
        async with self._session_factory() as session:
            async with session.begin():
                values: dict[str, Any] = {
                    "status": "completed",
                    "completed_at": datetime.now(UTC),
                }
                if output_data is not None:
                    values["output_data"] = output_data
                if evidence_refs is not None:
                    values["evidence_refs"] = evidence_refs

                result = await session.execute(
                    update(Task)
                    .where(Task.id == uuid.UUID(task_id))
                    .values(**values)
                    .returning(Task)
                )
                row = result.scalar_one_or_none()
                if row:
                    logger.info(f"Task {task_id} marked as completed")
                return row

    async def mark_failed(
        self,
        task_id: str,
        error: str,
    ) -> Task | None:
        """Transition task to 'failed' with error information."""
        # Truncate error to prevent unbounded storage
        safe_error = error[:4096] if error else "Unknown error"
        async with self._session_factory() as session:
            async with session.begin():
                result = await session.execute(
                    update(Task)
                    .where(Task.id == uuid.UUID(task_id))
                    .values(
                        status="failed",
                        completed_at=datetime.now(UTC),
                        errors=[safe_error],
                    )
                    .returning(Task)
                )
                row = result.scalar_one_or_none()
                if row:
                    logger.warning(f"Task {task_id} marked as failed: {safe_error[:200]}")
                return row
