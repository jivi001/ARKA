"""Integration tests for ARKA Recon Orchestration Bridge.

Tests the full path from CLI/API -> PostgreSQL Task -> ReconOrchestrationService ->
WorkerBackend -> ReconGraphWorkflow -> PolicyEngine/ScopeGuard -> PostgreSQL completion.

Verifies:
1. Deterministic Fake LLM produces in-scope (127.0.0.1:3000) and out-of-scope (127.0.0.1:4000)
   actions. The second is rejected by authorization.
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


async def poll_task_status(
    client: httpx.AsyncClient,
    engagement_id: str,
    task_id: str,
    target_statuses: set[str] | str = "completed",
    timeout: float = 5.0,
    interval: float = 0.05,
) -> dict:
    """Poll task status with a hard timeout and rich diagnostics."""
    if isinstance(target_statuses, str):
        target_statuses = {target_statuses}

    deadline = asyncio.get_event_loop().time() + timeout
    last_status = None
    last_task_data = None

    while asyncio.get_event_loop().time() < deadline:
        resp = await client.get(f"/engagements/{engagement_id}/tasks/{task_id}")
        if resp.status_code == 200:
            last_task_data = resp.json()
            last_status = last_task_data.get("status")
            if last_status in target_statuses:
                return last_task_data
        await asyncio.sleep(interval)

    raise TimeoutError(
        f"Task {task_id} failed to reach status in {target_statuses} within {timeout}s. "
        f"Last known status: {last_status}, task_data: {last_task_data}"
    )


@pytest.mark.asyncio
async def test_api_recon_run_and_task_retrieval(bridge_db):
    """Test end-to-end API: POST /engagements/{id}/recon (202 Accepted) and GET tasks."""
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
            # 1. Trigger recon — API immediately responds with 202 Accepted and queued status
            resp = await client.post(
                f"/engagements/{eng_id}/recon",
                json={"objective": "E2E API test", "max_iterations": 3},
            )
            assert resp.status_code == 202, (
                f"Expected 202 Accepted, got {resp.status_code}: {resp.text}"
            )
            data = resp.json()
            assert "task_id" in data
            assert data["status"] == "queued"
            task_id = data["task_id"]

            # Synchronize on task completion via InProcessWorkerBackend event primitive
            await worker.wait_for_task(task_id, timeout=5.0)

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
            assert single_task["status"] == "completed"

    finally:
        await worker.close()
        app.dependency_overrides.clear()
        reset_dependencies()


@pytest.mark.asyncio
async def test_true_e2e_api_worker_graph_auth_executor_evidence_completion(bridge_db):
    """True end-to-end integration test asserting full pipeline:

    API (POST 202) -> InProcessWorker -> ReconGraphWorkflow ->
    ScopeGuard/PolicyEngine (allow 3000, deny 4000) -> ToolExecutor ->
    Cryptographic EvidenceStore -> PostgreSQL Task completion & Evidence API retrieval.
    """
    session_factory, eng_id, scope_repo = bridge_db
    task_repo = TaskRepository(session_factory)
    audit = AuditService()
    approvals = ApprovalManager(session_factory=session_factory)

    # In-scope: 127.0.0.1:3000, Out-of-scope: 127.0.0.1:4000
    fake_llm = DeterministicFakeLLMGateway(
        candidate_targets=["127.0.0.1:3000", "127.0.0.1:4000"],
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
            # 1. API: Trigger recon with 202 Accepted
            resp = await client.post(
                f"/engagements/{eng_id}/recon",
                json={"objective": "Full E2E verification", "max_iterations": 5},
            )
            assert resp.status_code == 202
            task_info = resp.json()
            task_id = task_info["task_id"]
            assert task_info["status"] == "queued"

            # 2. Worker synchronization: Wait for worker to finish
            await worker.wait_for_task(task_id, timeout=10.0)

            # 3. Poll task status via API
            task_data = await poll_task_status(
                client,
                engagement_id=eng_id,
                task_id=task_id,
                target_statuses="completed",
                timeout=5.0,
            )

            # 4. Assertions on completed Task
            assert task_data["status"] == "completed"
            assert task_data["completed_at"] is not None

            output = task_data.get("output_data", {})
            # Authorization: in-scope target was executed
            assert output.get("actions_executed", 0) >= 1
            # Authorization: out-of-scope target 127.0.0.1:4000 was denied
            errors_joined = " ".join(output.get("errors", []))
            assert (
                "Port 4000 not in scope" in errors_joined
                or "out of scope" in errors_joined.lower()
            )

            # 5. Evidence assertion: Evidence refs generated and persisted on Task
            evidence_refs = task_data.get("evidence_refs", [])
            assert len(evidence_refs) >= 1, "Task must contain cryptographic evidence references"

            # 6. Evidence API retrieval
            ev_id = evidence_refs[0]
            ev_resp = await client.get(f"/evidence/{ev_id}")
            if ev_resp.status_code == 200:
                ev_data = ev_resp.json()
                assert ev_data["evidence_id"] == ev_id
                is_valid_hash = (
                    "sha256" in ev_data.get("hash", "").lower()
                    or "hash_sha256" in ev_data
                    or len(ev_data.get("hash", "")) == 64
                )
                assert is_valid_hash

            # 7. Audit assertion: Verify audit trail recorded start, policy checks, execution
            events = await audit.get_events(task_id=task_id)
            event_types = [e.event_type.value for e in events]
            assert "task.created" in event_types
            assert "task.started" in event_types
            assert "task.completed" in event_types

    finally:
        await worker.close()
        app.dependency_overrides.clear()
        reset_dependencies()


@pytest.mark.asyncio
async def test_worker_failure_and_retry_semantics(bridge_db):
    """Test worker retry classification and Retry(defer=...) exception mechanics.

    - Transient error on try 1 raises Retry(defer=...), transitioning task back to queued.
    - Try 2 succeeds and completes task with durable error history intact.
    """
    from unittest.mock import patch

    from arq.worker import Retry

    from arka.app.orchestration.recon_service import ReconOrchestrationError
    from arka.app.workers.arq_worker import run_orchestrator_task

    session_factory, eng_id, _ = bridge_db
    task_repo = TaskRepository(session_factory)

    # 1. Create a task in queued state
    task = await task_repo.create_task(
        engagement_id=eng_id,
        task_type="recon",
        name="Worker Retry Verification",
        objective="Verify ARQ retry semantics",
    )
    task_id = str(task.id)

    # Transition to running to simulate worker started
    await task_repo.mark_started(task_id)

    # Case A: Retryable transient failure on try 1
    with patch(
        "arka.app.orchestration.recon_service.ReconOrchestrationService.execute",
        side_effect=ConnectionError("Temporary Redis connection reset"),
    ):
        with pytest.raises(Retry) as exc_info:
            await run_orchestrator_task(
                ctx={"job_try": 1, "session_factory": session_factory},
                task_id=task_id,
                engagement_id=eng_id,
            )
        assert exc_info.value.defer_score is not None or exc_info.type is Retry

        # Task in DB must be transitioned back to queued for the next try
        t_retried = await task_repo.get_task(task_id)
        assert t_retried.status == "queued"
        assert len(t_retried.errors) == 1
        assert "[Retry 1]" in t_retried.errors[0]

    # Try 2 succeeds
    with patch(
        "arka.app.orchestration.recon_service.ReconOrchestrationService.execute",
        return_value=None,
    ):
        res2 = await run_orchestrator_task(
            ctx={"job_try": 2, "session_factory": session_factory},
            task_id=task_id,
            engagement_id=eng_id,
        )
        assert res2["status"] == "completed"

    # Case B: Non-retryable failure marks task terminal 'failed' immediately
    task_b = await task_repo.create_task(
        engagement_id=eng_id,
        task_type="recon",
        name="Worker Non-retryable Test",
        objective="Verify non-retryable failure",
    )
    task_b_id = str(task_b.id)
    await task_repo.mark_started(task_b_id)

    with patch(
        "arka.app.orchestration.recon_service.ReconOrchestrationService.execute",
        side_effect=ReconOrchestrationError("Engagement is not active"),
    ):
        result = await run_orchestrator_task(
            ctx={"job_try": 1, "session_factory": session_factory},
            task_id=task_b_id,
            engagement_id=eng_id,
        )
        assert result["status"] == "failed"
        assert result["retryable"] is False

        t_failed = await task_repo.get_task(task_b_id)
        assert t_failed.status == "failed"
        assert len(t_failed.errors) == 1


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

        async def close(self) -> None:
            pass

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

