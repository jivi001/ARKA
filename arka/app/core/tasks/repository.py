"""Async PostgreSQL task persistence for ARKA orchestration.

Provides transactional task CRUD with engagement isolation and strict state machine transitions.
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


class TaskStateTransitionError(Exception):
    """Raised when an illegal task state machine transition is attempted."""

    def __init__(self, task_id: str, from_status: str, to_status: str, reason: str = "") -> None:
        self.task_id = task_id
        self.from_status = from_status
        self.to_status = to_status
        msg = (
            f"Illegal task transition for {task_id}: cannot transition "
            f"from '{from_status}' to '{to_status}'."
        )
        if reason:
            msg += f" Reason: {reason}"
        super().__init__(msg)


class TaskRepository:
    """Async PostgreSQL repository for persistent task state.

    Enforces strict state machine:
      queued -> running
      running -> queued (retry with durable error tracking)
      queued -> failed (dispatch / enqueue failure)
      running -> completed
      running -> failed
      running -> cancelled
      queued -> cancelled

    All other transitions (e.g. completed -> running, failed -> running) are rejected.
    Engagement isolation is strictly enforced on all queries.
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
        async with self._session_factory() as session, session.begin():
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

    async def get_task_by_id_and_engagement(
        self, task_id: str, engagement_id: str
    ) -> Task | None:
        """Load a task by ID ensuring it belongs to the given engagement (isolation)."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(Task).where(
                    Task.id == uuid.UUID(task_id),
                    Task.engagement_id == uuid.UUID(engagement_id),
                )
            )
            return result.scalar_one_or_none()

    async def get_tasks_by_engagement(
        self,
        engagement_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Task]:
        """Load all tasks for an engagement, ordered by creation time descending."""
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
        """Atomically transition task from 'queued' to 'running'.

        Atomic Compare-And-Swap (CAS): Only succeeds if status is currently 'queued'.
        Returns None if task does not exist or is already running/terminal.
        """
        async with self._session_factory() as session, session.begin():
            result = await session.execute(
                update(Task)
                .where(Task.id == uuid.UUID(task_id), Task.status == "queued")
                .values(
                    status="running",
                    started_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                )
                .returning(Task)
            )
            row = result.scalar_one_or_none()
            if row is None:
                logger.warning(
                    f"Task {task_id} cannot transition to 'running' "
                    "(not found or not in 'queued' state)"
                )
            else:
                logger.info(f"Task {task_id} marked as running")
            return row

    async def mark_completed(
        self,
        task_id: str,
        output_data: dict[str, Any] | None = None,
        evidence_refs: list[str] | None = None,
    ) -> Task | None:
        """Transition task from 'running' to 'completed' with results.

        Enforces that task must currently be in 'running' state.
        Returns None if task is not in 'running' state.
        """
        async with self._session_factory() as session, session.begin():
            values: dict[str, Any] = {
                "status": "completed",
                "completed_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
            }
            if output_data is not None:
                values["output_data"] = output_data
            if evidence_refs is not None:
                values["evidence_refs"] = evidence_refs

            result = await session.execute(
                update(Task)
                .where(Task.id == uuid.UUID(task_id), Task.status == "running")
                .values(**values)
                .returning(Task)
            )
            row = result.scalar_one_or_none()
            if row:
                logger.info(f"Task {task_id} marked as completed")
            else:
                logger.warning(
                    f"Task {task_id} cannot transition to 'completed' (not in 'running' state)"
                )
            return row

    async def mark_retrying(
        self,
        task_id: str,
        error: str,
        retry_count: int,
    ) -> Task | None:
        """Transition task from 'running' back to 'queued' for retry.

        Preserves existing errors and appends the retry error to durable history.
        Enforces that task must currently be in 'running' state.
        Returns None if task is not in 'running' state or not found.
        """
        safe_error = error[:4096] if error else "Transient execution failure"
        retry_entry = f"[Retry {retry_count}] {safe_error}"

        async with self._session_factory() as session, session.begin():
            result = await session.execute(
                select(Task)
                .where(Task.id == uuid.UUID(task_id), Task.status == "running")
                .with_for_update()
            )
            task = result.scalar_one_or_none()
            if not task:
                logger.warning(
                    f"Task {task_id} cannot transition to retry "
                    "(not found or not in 'running' state)"
                )
                return None

            existing_errors = list(task.errors or [])
            existing_errors.append(retry_entry)

            output_data = dict(task.output_data or {})
            output_data["retry_count"] = retry_count

            task.status = "queued"
            task.updated_at = datetime.now(UTC)
            task.errors = existing_errors
            task.output_data = output_data

            logger.info(f"Task {task_id} transitioned back to queued for retry #{retry_count}")
            return task

    async def mark_failed(
        self,
        task_id: str,
        error: str,
    ) -> Task | None:
        """Transition task from 'queued' or 'running' to 'failed'.

        Preserves existing errors and appends the terminal failure error.
        Returns None if task is already in a terminal state ('completed', 'failed', 'cancelled').
        """
        safe_error = error[:4096] if error else "Unknown error"
        async with self._session_factory() as session, session.begin():
            result = await session.execute(
                select(Task)
                .where(
                    Task.id == uuid.UUID(task_id),
                    Task.status.in_(["queued", "running"]),
                )
                .with_for_update()
            )
            task = result.scalar_one_or_none()
            if not task:
                logger.warning(
                    f"Task {task_id} cannot transition to 'failed' (already terminal or not found)"
                )
                return None

            existing_errors = list(task.errors or [])
            existing_errors.append(safe_error)

            task.status = "failed"
            task.completed_at = datetime.now(UTC)
            task.updated_at = datetime.now(UTC)
            task.errors = existing_errors

            logger.warning(f"Task {task_id} marked as failed: {safe_error[:200]}")
            return task

    async def mark_cancelled(
        self,
        task_id: str,
        reason: str = "Cancelled by user or system",
    ) -> Task | None:
        """Transition task from 'queued' or 'running' to 'cancelled'."""
        safe_reason = reason[:1024]
        async with self._session_factory() as session, session.begin():
            result = await session.execute(
                update(Task)
                .where(
                    Task.id == uuid.UUID(task_id),
                    Task.status.in_(["queued", "running"]),
                )
                .values(
                    status="cancelled",
                    completed_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                    errors=[safe_reason],
                )
                .returning(Task)
            )
            row = result.scalar_one_or_none()
            if row:
                logger.info(f"Task {task_id} marked as cancelled: {safe_reason}")
            return row
