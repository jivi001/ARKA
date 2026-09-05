"""Process-boundary persistence tests for ARKA Recon Orchestration.

Verifies Issue #19:
Process A: Creates Engagement -> Scope -> Task -> commits to DB -> terminates completely.
Process B: Fresh Python interpreter process -> reconnects to DB -> loads Task, Engagement, Scope.
Proves zero reliance on in-process caches or memory for durable security state.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def test_cross_process_task_and_scope_persistence():
    """Verify state persistence across genuine separate OS processes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "arka_process_test.db"
        db_url = f"sqlite+aiosqlite:///{db_path.as_posix()}"

        # ---------------------------------------------------------
        # PROCESS A: Initialize DB, create Engagement, Scope, Task, and EXIT
        # ---------------------------------------------------------
        process_a_code = f"""
import asyncio
import json
import uuid
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from arka.app.database.models import Base, Engagement
from arka.app.core.scope.repository import ScopeRepository
from arka.app.core.tasks.repository import TaskRepository
from arka.app.core.state.models import ScopeDefinition, ScopeTarget

async def main():
    engine = create_async_engine("{db_url}", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    eng_id = uuid.uuid4()
    async with factory() as session, session.begin():
        eng = Engagement(
            id=eng_id,
            name="Process A Engagement",
            status="active",
        )
        session.add(eng)

    scope_repo = ScopeRepository(session_factory=factory)
    scope_def = ScopeDefinition(
        engagement_id=str(eng_id),
        version=1,
        includes=ScopeTarget(
            ip_addresses=["127.0.0.1"],
            ports=[3000],
        ),
        excludes=ScopeTarget(),
    )
    saved_scope = await scope_repo.save_scope(scope_def)

    task_repo = TaskRepository(session_factory=factory)
    task = await task_repo.create_task(
        engagement_id=str(eng_id),
        task_type="recon",
        name="Process A Recon Task",
        objective="Cross-process verification",
        max_iterations=7,
    )

    await engine.dispose()

    # Output identifiers for Process B
    print(json.dumps({{
        "engagement_id": str(eng_id),
        "task_id": str(task.id),
        "scope_version": saved_scope.version if hasattr(saved_scope, "version") else 1,
    }}))

asyncio.run(main())
"""

        res_a = subprocess.run(
            [sys.executable, "-c", process_a_code],
            capture_output=True,
            text=True,
            check=True,
        )

        data = json.loads(res_a.stdout.strip().splitlines()[-1])
        eng_id = data["engagement_id"]
        task_id = data["task_id"]

        # ---------------------------------------------------------
        # PROCESS B: Fresh Python process, loads state from DB, validates
        # ---------------------------------------------------------
        process_b_code = f"""
import asyncio
import json
import uuid
import sys
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from arka.app.database.models import Engagement, Task
from arka.app.core.scope.repository import ScopeRepository
from arka.app.core.tasks.repository import TaskRepository

async def main():
    engine = create_async_engine("{db_url}", echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # 1. Verify Engagement
    async with factory() as session:
        eng_res = await session.execute(
            select(Engagement).where(Engagement.id == uuid.UUID("{eng_id}"))
        )
        eng = eng_res.scalar_one_or_none()
        assert eng is not None, "Engagement must exist in Process B"
        assert eng.name == "Process A Engagement"
        assert eng.status == "active"

    # 2. Verify Scope & Version
    scope_repo = ScopeRepository(session_factory=factory)
    scope = await scope_repo.get_scope("{eng_id}")
    assert scope is not None, "Scope must exist in Process B"
    version = scope.version if hasattr(scope, "version") else scope.get("version")
    assert version == 1, "Scope version must be 1"
    includes = scope.includes if hasattr(scope, "includes") else scope.get("includes")
    ports = includes.ports if hasattr(includes, "ports") else includes.get("ports")
    assert ports == [3000], f"Scope ports must be [3000], got {{ports}}"

    # 3. Verify Task
    task_repo = TaskRepository(session_factory=factory)
    task = await task_repo.get_task("{task_id}")
    assert task is not None, "Task must exist in Process B"
    assert task.status == "queued"
    assert task.task_type == "recon"
    assert task.max_iterations == 7
    assert task.objective == "Cross-process verification"
    assert str(task.engagement_id) == "{eng_id}"

    await engine.dispose()
    print("SUCCESS")

asyncio.run(main())
"""

        res_b = subprocess.run(
            [sys.executable, "-c", process_b_code],
            capture_output=True,
            text=True,
            check=True,
        )

        assert "SUCCESS" in res_b.stdout


def _check_postgres_connection(db_url: str) -> bool:
    """Fast check whether PostgreSQL port is open and reachable."""
    import socket
    from urllib.parse import urlparse

    try:
        parsed = urlparse(db_url)
        host = parsed.hostname or "localhost"
        port = parsed.port or 5432
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except Exception:
        return False


def test_cross_process_task_and_scope_persistence_postgres():
    """Verify durable state persistence across genuine separate OS processes using real PostgreSQL.

    Process A: Fresh Python process creates Engagement, Scope, Task in PostgreSQL and exits.
    Process B: Fresh Python process connects to PostgreSQL, loads, verifies, and transitions Task.
    Validates native PostgreSQL types (UUID, JSONB, DateTimeTZ) across true process boundaries.
    """
    import os

    import pytest

    from arka.app.core.config import get_settings

    settings = get_settings()
    db_url = (
        os.environ.get("TEST_DATABASE_URL")
        or os.environ.get("DATABASE_URL")
        or settings.database_url
    )

    if not _check_postgres_connection(db_url):
        pytest.skip(
            f"Real PostgreSQL database not reachable at {db_url}. Skipping live PostgreSQL test."
        )

    # ---------------------------------------------------------
    # PROCESS A: Initialize in PostgreSQL, create Engagement, Scope, Task, and EXIT
    # ---------------------------------------------------------
    process_a_code = f"""
import asyncio
import json
import uuid
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from arka.app.database.models import Base, Engagement
from arka.app.core.scope.repository import ScopeRepository
from arka.app.core.tasks.repository import TaskRepository
from arka.app.core.state.models import ScopeDefinition, ScopeTarget

async def main():
    engine = create_async_engine("{db_url}", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    eng_id = uuid.uuid4()
    async with factory() as session, session.begin():
        eng = Engagement(
            id=eng_id,
            name="PostgreSQL Process A Engagement",
            status="active",
        )
        session.add(eng)

    scope_repo = ScopeRepository(session_factory=factory)
    scope_def = ScopeDefinition(
        engagement_id=str(eng_id),
        version=1,
        includes=ScopeTarget(
            ip_addresses=["10.0.0.1"],
            ports=[8443],
        ),
        excludes=ScopeTarget(),
    )
    saved_scope = await scope_repo.save_scope(scope_def)

    task_repo = TaskRepository(session_factory=factory)
    task = await task_repo.create_task(
        engagement_id=str(eng_id),
        task_type="recon",
        name="PostgreSQL Process A Task",
        objective="Verify real postgres process boundary",
        max_iterations=5,
    )

    await engine.dispose()

    print(json.dumps({{
        "engagement_id": str(eng_id),
        "task_id": str(task.id),
        "scope_version": saved_scope.version if hasattr(saved_scope, "version") else 1,
    }}))

asyncio.run(main())
"""

    res_a = subprocess.run(
        [sys.executable, "-c", process_a_code],
        capture_output=True,
        text=True,
        check=True,
    )

    data = json.loads(res_a.stdout.strip().splitlines()[-1])
    eng_id = data["engagement_id"]
    task_id = data["task_id"]

    # ---------------------------------------------------------
    # PROCESS B: Fresh Python process connects to PostgreSQL, validates, transitions task
    # ---------------------------------------------------------
    process_b_code = f"""
import asyncio
import json
import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from arka.app.database.models import Engagement, Task
from arka.app.core.scope.repository import ScopeRepository
from arka.app.core.tasks.repository import TaskRepository

async def main():
    engine = create_async_engine("{db_url}", echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # 1. Verify Engagement in PostgreSQL
    async with factory() as session:
        eng_res = await session.execute(
            select(Engagement).where(Engagement.id == uuid.UUID("{eng_id}"))
        )
        eng = eng_res.scalar_one_or_none()
        assert eng is not None, "Engagement must exist in PostgreSQL in Process B"
        assert eng.name == "PostgreSQL Process A Engagement"
        assert eng.status == "active"

    # 2. Verify Scope & Version in PostgreSQL
    scope_repo = ScopeRepository(session_factory=factory)
    scope = await scope_repo.get_scope("{eng_id}")
    assert scope is not None, "Scope must exist in PostgreSQL in Process B"
    version = scope.version if hasattr(scope, "version") else scope.get("version")
    assert version == 1, "Scope version must be 1"
    includes = scope.includes if hasattr(scope, "includes") else scope.get("includes")
    ports = includes.ports if hasattr(includes, "ports") else includes.get("ports")
    assert ports == [8443], f"Scope ports must be [8443], got {{ports}}"

    # 3. Verify Task and transition queued -> running in PostgreSQL
    task_repo = TaskRepository(session_factory=factory)
    task = await task_repo.get_task("{task_id}")
    assert task is not None, "Task must exist in PostgreSQL in Process B"
    assert task.status == "queued"

    started_task = await task_repo.mark_started("{task_id}")
    assert started_task is not None
    assert started_task.status == "running"

    await engine.dispose()
    print("POSTGRES_PROCESS_B_SUCCESS")

asyncio.run(main())
"""

    res_b = subprocess.run(
        [sys.executable, "-c", process_b_code],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "POSTGRES_PROCESS_B_SUCCESS" in res_b.stdout

    # Cleanup in PostgreSQL
    cleanup_code = f"""
import asyncio
import uuid
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from arka.app.database.models import Engagement

async def cleanup():
    engine = create_async_engine("{db_url}", echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session, session.begin():
        await session.execute(delete(Engagement).where(Engagement.id == uuid.UUID("{eng_id}")))
    await engine.dispose()

asyncio.run(cleanup())
"""
    subprocess.run([sys.executable, "-c", cleanup_code], capture_output=True, text=True)
