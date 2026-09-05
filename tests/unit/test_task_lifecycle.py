"""Unit tests for TaskRepository lifecycle and state machine invariants.

Verifies:
1. Legal transitions: queued -> running -> completed / failed
2. Prohibited transitions: completed -> running, failed -> running
3. Single start ownership / race safety (atomic CAS)
4. Cross-engagement isolation
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from arka.app.core.tasks.repository import TaskRepository
from arka.app.database.models import Base, Engagement


@pytest.fixture
async def async_db():
    """Create in-memory SQLite database for task lifecycle tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Seed an active engagement
    eng_id = uuid.uuid4()
    async with session_factory() as session, session.begin():
        eng = Engagement(
            id=eng_id,
            name="Test Engagement",
            status="active",
        )
        session.add(eng)

    yield session_factory, str(eng_id)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.mark.asyncio
async def test_task_creation_and_initial_state(async_db):
    """Test task is created in queued status with all fields set."""
    session_factory, eng_id = async_db
    repo = TaskRepository(session_factory)

    task = await repo.create_task(
        engagement_id=eng_id,
        task_type="recon",
        name="Port scan",
        objective="Enumerate ports",
        max_iterations=5,
    )

    assert task.status == "queued"
    assert task.task_type == "recon"
    assert task.max_iterations == 5
    assert task.objective == "Enumerate ports"
    assert str(task.engagement_id) == eng_id


@pytest.mark.asyncio
async def test_task_status_machine_legal_transitions(async_db):
    """Test legal transition sequence: queued -> running -> completed."""
    session_factory, eng_id = async_db
    repo = TaskRepository(session_factory)

    task = await repo.create_task(
        engagement_id=eng_id,
        task_type="recon",
        name="Recon Test",
    )
    task_id = str(task.id)

    # 1. queued -> running
    started = await repo.mark_started(task_id)
    assert started is not None
    assert started.status == "running"
    assert started.started_at is not None

    # 2. running -> completed
    completed = await repo.mark_completed(
        task_id=task_id,
        output_data={"ports": [80, 443]},
        evidence_refs=["hash123"],
    )
    assert completed is not None
    assert completed.status == "completed"
    assert completed.completed_at is not None
    assert completed.output_data == {"ports": [80, 443]}
    assert completed.evidence_refs == ["hash123"]


@pytest.mark.asyncio
async def test_task_status_machine_prohibited_transitions(async_db):
    """Test prohibited transitions are rejected (e.g. completed -> running)."""
    session_factory, eng_id = async_db
    repo = TaskRepository(session_factory)

    task = await repo.create_task(engagement_id=eng_id, task_type="recon", name="Recon Test")
    task_id = str(task.id)

    # Transition to running then completed
    await repo.mark_started(task_id)
    await repo.mark_completed(task_id, output_data={"done": True})

    # Try prohibited transition: completed -> running (CAS fails)
    restart_attempt = await repo.mark_started(task_id)
    assert restart_attempt is None, "completed -> running must be rejected"

    # Try prohibited transition: completed -> failed
    fail_attempt = await repo.mark_failed(task_id, error="late failure")
    assert fail_attempt is None, "completed -> failed must be rejected"


@pytest.mark.asyncio
async def test_task_start_single_ownership_race_safety(async_db):
    """Test race safety: multiple concurrent calls to mark_started result in exactly one winner."""
    session_factory, eng_id = async_db
    repo = TaskRepository(session_factory)

    task = await repo.create_task(engagement_id=eng_id, task_type="recon", name="Concurrent Start")
    task_id = str(task.id)

    # Launch 5 concurrent mark_started attempts
    results = await asyncio.gather(
        repo.mark_started(task_id),
        repo.mark_started(task_id),
        repo.mark_started(task_id),
        repo.mark_started(task_id),
        repo.mark_started(task_id),
    )

    # Exactly ONE attempt must succeed (return row), the other 4 must return None
    successes = [r for r in results if r is not None]
    failures = [r for r in results if r is None]

    assert len(successes) == 1, "Exactly one caller must successfully transition task to running"
    assert len(failures) == 4, "All duplicate start calls must be rejected"


@pytest.mark.asyncio
async def test_cross_engagement_task_isolation(async_db):
    """Test tasks for engagement A are never returned when querying engagement B."""
    session_factory, eng_id_a = async_db
    repo = TaskRepository(session_factory)

    # Create engagement B
    eng_id_b = str(uuid.uuid4())
    async with session_factory() as session, session.begin():
        eng_b = Engagement(id=uuid.UUID(eng_id_b), name="Engagement B", status="active")
        session.add(eng_b)

    task_a = await repo.create_task(engagement_id=eng_id_a, task_type="recon", name="Task A")
    task_b = await repo.create_task(engagement_id=eng_id_b, task_type="recon", name="Task B")

    # Query tasks for Engagement A
    tasks_a = await repo.get_tasks_by_engagement(eng_id_a)
    assert len(tasks_a) == 1
    assert str(tasks_a[0].id) == str(task_a.id)

    # Query tasks for Engagement B
    tasks_b = await repo.get_tasks_by_engagement(eng_id_b)
    assert len(tasks_b) == 1
    assert str(tasks_b[0].id) == str(task_b.id)

    # Test single task retrieval with isolation
    task_a_in_b = await repo.get_task_by_id_and_engagement(str(task_a.id), eng_id_b)
    assert task_a_in_b is None, "Task A must not be accessible under Engagement B"

    task_a_in_a = await repo.get_task_by_id_and_engagement(str(task_a.id), eng_id_a)
    assert task_a_in_a is not None
    assert str(task_a_in_a.id) == str(task_a.id)


@pytest.mark.asyncio
async def test_task_retry_lifecycle_and_error_history(async_db):
    """Test retry transitions: queued -> running -> queued -> running -> completed.

    Verifies that retry preserves error history and output_data retry_count.
    """
    session_factory, eng_id = async_db
    repo = TaskRepository(session_factory)

    task = await repo.create_task(
        engagement_id=eng_id,
        task_type="recon",
        name="Retry Lifecycle Test",
    )
    task_id = str(task.id)

    # 1. First run: queued -> running
    started1 = await repo.mark_started(task_id)
    assert started1 is not None
    assert started1.status == "running"

    # 2. Transient error: running -> queued (Retry #1)
    retried1 = await repo.mark_retrying(task_id, error="Network timeout to gateway", retry_count=1)
    assert retried1 is not None
    assert retried1.status == "queued"
    assert retried1.output_data.get("retry_count") == 1
    assert len(retried1.errors) == 1
    assert "[Retry 1] Network timeout to gateway" in retried1.errors[0]

    # Cannot retry a task that is already queued (must be running)
    invalid_retry = await repo.mark_retrying(task_id, error="Double retry", retry_count=2)
    assert invalid_retry is None

    # 3. Second run: queued -> running (Atomic CAS)
    started2 = await repo.mark_started(task_id)
    assert started2 is not None
    assert started2.status == "running"

    # 4. Another transient error: running -> queued (Retry #2)
    retried2 = await repo.mark_retrying(task_id, error="Rate limit exceeded", retry_count=2)
    assert retried2 is not None
    assert retried2.status == "queued"
    assert retried2.output_data.get("retry_count") == 2
    assert len(retried2.errors) == 2
    assert "[Retry 1] Network timeout to gateway" in retried2.errors[0]
    assert "[Retry 2] Rate limit exceeded" in retried2.errors[1]

    # 5. Third run: queued -> running -> completed
    started3 = await repo.mark_started(task_id)
    assert started3 is not None
    assert started3.status == "running"

    completed = await repo.mark_completed(
        task_id=task_id,
        output_data={"ports": [80], "retry_count": 2},
        evidence_refs=["ev_123"],
    )
    assert completed is not None
    assert completed.status == "completed"
    assert completed.output_data["retry_count"] == 2
    assert len(completed.errors) == 2


@pytest.mark.asyncio
async def test_task_retry_exhaustion_to_failed(async_db):
    """Test transition from retrying to terminal failed preserves all error history."""
    session_factory, eng_id = async_db
    repo = TaskRepository(session_factory)

    task = await repo.create_task(
        engagement_id=eng_id,
        task_type="recon",
        name="Exhaustion Test",
    )
    task_id = str(task.id)

    # queued -> running -> retrying
    await repo.mark_started(task_id)
    await repo.mark_retrying(task_id, error="Attempt 1 failed", retry_count=1)

    # queued -> running -> failed (retries exhausted)
    await repo.mark_started(task_id)
    failed = await repo.mark_failed(
        task_id, error="Attempt 2 failed permanently (max retries exhausted)"
    )
    assert failed is not None
    assert failed.status == "failed"
    assert len(failed.errors) == 2
    assert "[Retry 1] Attempt 1 failed" in failed.errors[0]
    assert "Attempt 2 failed permanently" in failed.errors[1]

