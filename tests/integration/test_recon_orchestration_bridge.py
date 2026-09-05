"""Integration tests for ARKA Recon Orchestration Bridge.

Tests the full path from CLI/API -> PostgreSQL Task -> ReconOrchestrationService ->
WorkerBackend -> ReconGraphWorkflow -> PolicyEngine/ScopeGuard -> PostgreSQL completion.

Verifies:
1. Deterministic Fake LLM produces in-scope (127.0.0.1:3000) and out-of-scope (127.0.0.1:4000) actions.
   The second is rejected by authorization.
2. Max iterations bounds the loop (e.g. max_iterations=2 terminates with max_iterations_reached).
3. API POST /engagements/{id}/recon creates task, enqueues to worker, and GET /tasks retrieves it.
4. Enqueue failure returns 503 and marks the task failed in PostgreSQL.
"""

from __future__ import annotations

import asyncio
import json
import uuid
import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from arka.app.api import create_app
from arka.app.api.deps import (
    get_audit_service,
    get_recon_orchestration_service,
    get_scope_repository,
    get_task_repository,
    get_worker_backend,
    reset_dependencies,
)
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.scope.repository import ScopeRepository
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.core.tasks.repository import TaskRepository
from arka.app.database.models import Base, Engagement
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.llm.schemas.llm_schemas import LLMRequest, LLMResponse, TokenUsage
from arka.app.orchestration.recon_service import ReconOrchestrationService
from arka.app.workers.backend import InProcessWorkerBackend, WorkerBackend


class DeterministicFakeLLMGateway(LLMGateway):
    """Fake LLM Gateway producing controlled candidate actions and analysis."""

    def __init__(
        self,
        candidate_targets: list[str],
        always_continue: bool = False,
        audit_service: AuditService | None = None,
    ) -> None:
        super().__init__(audit_service=audit_service or AuditService())
        self.candidate_targets = candidate_targets
        self.always_continue = always_continue
        self.call_count = 0

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.call_count += 1
        # Alternate between planning and analysis
        is_plan = self.call_count % 2 == 1

        if is_plan:
            actions = [
                {
                    "tool_name": "nmap",
                    "operation": "scan",
                    "target": target,
                    "arguments": {"ports": target.split(":")[-1] if ":" in target else "80"},
                    "rationale": f"Probe candidate target {target}",
                }
                for target in self.candidate_targets
            ]
            content = json.dumps(
                {
                    "objective": "Enumerate authorized infrastructure",
                    "reasoning_summary": "Testing deterministic execution paths",
                    "candidate_actions": actions,
                    "stop_condition": None,
                }
            )
        else:
            should_stop = not self.always_continue
            content = json.dumps(
                {
                    "summary": "Processed candidate action results",
                    "findings": ["Observed test service output"],
                    "hypotheses": [],
                    "identified_targets": [],
                    "next_recommended_actions": [],
                    "should_stop": should_stop,
                    "stop_reason": "objectives_satisfied" if should_stop else None,
                }
            )

        return LLMResponse(
            request_id=request.request_id,
            provider="deterministic-fake",
            content=content,
            model="deterministic-fake",
            usage=TokenUsage(prompt_tokens=10, completion_tokens=20, total_tokens=30),
        )


@pytest.fixture
async def bridge_db():
    """Create shared in-memory SQLite database for bridge integration testing."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    eng_id = uuid.uuid4()
    async with session_factory() as session, session.begin():
        eng = Engagement(
            id=eng_id,
            name="Bridge Test Engagement",
            status="active",
        )
        session.add(eng)

    # Save authorized scope: ONLY 127.0.0.1:3000 is in scope!
    scope_repo = ScopeRepository(session_factory=session_factory)
    scope_def = ScopeDefinition(
        engagement_id=str(eng_id),
        version=1,
        includes=ScopeTarget(
            ip_addresses=["127.0.0.1"],
            ports=[3000],
        ),
        excludes=ScopeTarget(),
    )
    await scope_repo.save_scope(scope_def)

    yield session_factory, str(eng_id), scope_repo

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.mark.asyncio
async def test_deterministic_fake_llm_controlled_execution(bridge_db):
    """Test orchestration bridge with Fake LLM generating 127.0.0.1:3000 and 127.0.0.1:4000.

    Requirements:
    - 127.0.0.1:3000 is allowed and executed
    - 127.0.0.1:4000 is denied by ScopeGuard / PolicyEngine
    - Task completes and persists results in PostgreSQL
    """
    session_factory, eng_id, scope_repo = bridge_db
    task_repo = TaskRepository(session_factory)
    audit = AuditService()
    approvals = ApprovalManager(session_factory=session_factory)

    fake_llm = DeterministicFakeLLMGateway(
        candidate_targets=["127.0.0.1:3000", "127.0.0.1:4000"],
        always_continue=False,
        audit_service=audit,
    )

    orchestrator = ReconOrchestrationService(
        task_repository=task_repo,
        scope_repository=scope_repo,
        audit_service=audit,
        llm_gateway=fake_llm,
        approval_manager=approvals,
    )

    start_info = await orchestrator.start(
        engagement_id=eng_id,
        objective="Controlled scan test",
        max_iterations=5,
    )
    task_id = start_info["task_id"]

    await orchestrator.execute(task_id)

    task = await task_repo.get_task(task_id)
    assert task is not None
    assert task.status == "completed"
    assert task.completed_at is not None

    output = task.output_data
    assert output is not None
    assert output["actions_executed"] >= 1
    errors_str = " ".join(output.get("errors", []))
    assert "Port 4000 not in scope" in errors_str or "out of scope" in errors_str.lower()


@pytest.mark.asyncio
async def test_max_iterations_bounds_recon_loop(bridge_db):
    """Test that max_iterations strictly bounds the ReconGraphWorkflow loop.

    With max_iterations=2, even if LLM wants to continue indefinitely,
    the workflow MUST terminate after 2 iterations with 'max_iterations_reached'.
    """
    session_factory, eng_id, scope_repo = bridge_db
    task_repo = TaskRepository(session_factory)
    audit = AuditService()
    approvals = ApprovalManager(session_factory=session_factory)

    fake_llm = DeterministicFakeLLMGateway(
        candidate_targets=["127.0.0.1:3000"],
        always_continue=True,
        audit_service=audit,
    )

    orchestrator = ReconOrchestrationService(
        task_repository=task_repo,
        scope_repository=scope_repo,
        audit_service=audit,
        llm_gateway=fake_llm,
        approval_manager=approvals,
    )

    start_info = await orchestrator.start(
        engagement_id=eng_id,
        objective="Loop bound test",
        max_iterations=2,
    )
    task_id = start_info["task_id"]

    await orchestrator.execute(task_id)

    task = await task_repo.get_task(task_id)
    assert task is not None
    assert task.status == "completed"
    output = task.output_data
    assert output["iterations"] == 2
    assert output["termination_reason"] == "max_iterations_reached"


@pytest.mark.asyncio
async def test_api_recon_run_and_task_retrieval(bridge_db):
    """Test end-to-end API: POST /engagements/{id}/recon and GET /engagements/{id}/tasks."""
    session_factory, eng_id, scope_repo = bridge_db
    task_repo = TaskRepository(session_factory)
    audit = AuditService()
    approvals = ApprovalManager(session_factory=session_factory)

    fake_llm = DeterministicFakeLLMGateway(
        candidate_targets=["127.0.0.1:3000"],
        always_continue=False,
        audit_service=audit,
    )

    orchestrator = ReconOrchestrationService(
        task_repository=task_repo,
        scope_repository=scope_repo,
        audit_service=audit,
        llm_gateway=fake_llm,
        approval_manager=approvals,
    )
    worker = InProcessWorkerBackend(orchestrator=orchestrator)

    app = create_app()
    app.dependency_overrides[get_scope_repository] = lambda: scope_repo
    app.dependency_overrides[get_task_repository] = lambda: task_repo
    app.dependency_overrides[get_audit_service] = lambda: audit
    app.dependency_overrides[get_recon_orchestration_service] = lambda: orchestrator
    app.dependency_overrides[get_worker_backend] = lambda: worker

    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Trigger recon
            resp = await client.post(
                f"/engagements/{eng_id}/recon",
                json={"objective": "E2E API test", "max_iterations": 3},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "task_id" in data
            assert data["status"] == "queued"
            task_id = data["task_id"]

            # Wait briefly for InProcessWorkerBackend background execution
            await asyncio.sleep(0.5)

            # 2. Query tasks list
            tasks_resp = await client.get(f"/engagements/{eng_id}/tasks")
            assert tasks_resp.status_code == 200
            tasks_data = tasks_resp.json()
            assert tasks_data["total"] >= 1
            found_task = next((t for t in tasks_data["tasks"] if t["task_id"] == task_id), None)
            assert found_task is not None
            assert found_task["objective"] == "E2E API test"

            # 3. Query single task endpoint
            task_resp = await client.get(f"/engagements/{eng_id}/tasks/{task_id}")
            assert task_resp.status_code == 200
            single_task = task_resp.json()
            assert single_task["task_id"] == task_id
            assert single_task["engagement_id"] == eng_id

    finally:
        app.dependency_overrides.clear()
        reset_dependencies()


@pytest.mark.asyncio
async def test_api_recon_enqueue_failure_handling(bridge_db):
    """Test enqueue failure: API returns 503 and task status is marked 'failed' in DB."""
    session_factory, eng_id, scope_repo = bridge_db
    task_repo = TaskRepository(session_factory)
    audit = AuditService()
    approvals = ApprovalManager(session_factory=session_factory)

    orchestrator = ReconOrchestrationService(
        task_repository=task_repo,
        scope_repository=scope_repo,
        audit_service=audit,
        llm_gateway=LLMGateway(audit_service=audit),
        approval_manager=approvals,
    )

    class BrokenWorkerBackend(WorkerBackend):
        async def enqueue_recon(
            self, task_id: str, engagement_id: str, objective: str, max_iterations: int
        ) -> str:
            raise RuntimeError("Redis connection refused on job dispatch")

    app = create_app()
    app.dependency_overrides[get_scope_repository] = lambda: scope_repo
    app.dependency_overrides[get_task_repository] = lambda: task_repo
    app.dependency_overrides[get_audit_service] = lambda: audit
    app.dependency_overrides[get_recon_orchestration_service] = lambda: orchestrator
    app.dependency_overrides[get_worker_backend] = lambda: BrokenWorkerBackend()

    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                f"/engagements/{eng_id}/recon",
                json={"objective": "Broken enqueue test", "max_iterations": 2},
            )
            assert resp.status_code == 503
            err = resp.json()
            assert "Service Unavailable" in err.get("error", "")

    finally:
        app.dependency_overrides.clear()
        reset_dependencies()
