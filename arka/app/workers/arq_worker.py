from typing import ClassVar

from arq.connections import ArqRedis, RedisSettings
from arq.worker import Retry

from arka.app.audit.schemas import AuditEventType
from arka.app.core.config import get_settings
from arka.app.observability.logging import get_logger
from arka.app.orchestration.recon_service import ReconOrchestrationError

logger = get_logger(__name__)


def is_retryable_error(exc: Exception) -> bool:
    """Classify whether a task execution exception is transient and retryable.

    Non-retryable:
    - ReconOrchestrationError (e.g. Engagement not found, not active, missing scope)
    - ValueError, KeyError (invalid input/parameters)

    Retryable:
    - Transient timeouts, network connection drops, database deadlocks/disconnections, etc.
    """
    return not isinstance(exc, (ReconOrchestrationError, ValueError, KeyError))


async def execute_tool_task(ctx: dict, tool_request_data: dict) -> dict:
    """QUARANTINED / DEPRECATED: Direct tool execution via worker is strictly forbidden.

    All security tool executions must flow through the authoritative pipeline:
    ReconOrchestrationService -> ToolRegistry -> ScopeGuard -> PolicyEngine ->
    ApprovalManager -> ExecutionManager.
    """
    raise RuntimeError(
        "execute_tool_task is quarantined and forbidden: all tool execution "
        "must flow through ReconOrchestrationService."
    )


async def run_orchestrator_task(
    ctx: dict,
    task_id: str,
    engagement_id: str,
    objective: str = "Autonomous reconnaissance",
    max_iterations: int = 10,
) -> dict:
    """Worker function to run the ReconAgent through the full security pipeline.

    Constructs a fresh ReconOrchestrationService and executes the recon workflow.
    All tool execution flows through ToolRegistry → ScopeGuard → PolicyEngine →
    ApprovalManager → ExecutionManager. This function NEVER directly invokes tools.

    Implements authoritative retry and failure semantics:
    - Retries transient failures up to WorkerSettings.max_tries using ARQ Retry(defer=...).
    - Updates task status back to 'queued' for retry with durable error logs.
    - Non-retryable errors or retry exhaustion mark the task permanently 'failed'.
    """
    from arka.app.api.deps import (
        get_approval_manager,
        get_audit_service,
        get_llm_gateway,
        get_scope_repository,
    )
    from arka.app.core.tasks.repository import TaskRepository
    from arka.app.database.session import get_session_factory
    from arka.app.orchestration.recon_service import ReconOrchestrationService

    session_factory = (
        ctx["session_factory"]
        if isinstance(ctx, dict) and "session_factory" in ctx and ctx["session_factory"] is not None
        else get_session_factory()
    )
    task_repo = TaskRepository(session_factory=session_factory)
    audit = get_audit_service()
    orchestrator = ReconOrchestrationService(
        task_repository=task_repo,
        scope_repository=get_scope_repository(),
        audit_service=audit,
        llm_gateway=get_llm_gateway(),
        approval_manager=get_approval_manager(),
    )

    job_try = ctx.get("job_try", 1) if isinstance(ctx, dict) else 1
    max_tries = WorkerSettings.max_tries

    try:
        await orchestrator.execute(task_id, auto_mark_failed=False)
        return {"status": "completed", "task_id": task_id, "engagement_id": engagement_id}
    except Exception as exc:
        safe_error = str(exc)[:4096]
        retryable = is_retryable_error(exc)

        if retryable and job_try < max_tries:
            defer_seconds = min(2 ** (job_try - 1), 30)
            logger.warning(
                f"Task {task_id} failed with retryable error on try {job_try}/{max_tries}. "
                f"Scheduling retry #{job_try + 1} in {defer_seconds}s: {safe_error}"
            )
            await task_repo.mark_retrying(
                task_id=task_id,
                error=safe_error,
                retry_count=job_try,
            )
            await audit.record_action(
                event_type=AuditEventType.TASK_FAILED,
                actor="worker",
                action="schedule_task_retry",
                engagement_id=engagement_id,
                task_id=task_id,
                parameters={
                    "job_try": job_try,
                    "max_tries": max_tries,
                    "defer_seconds": defer_seconds,
                },
                result_status="retrying",
                error=safe_error,
            )
            raise Retry(defer=defer_seconds) from exc

        # Non-retryable error or retries exhausted
        logger.error(
            f"Task {task_id} permanently failed on try {job_try}/{max_tries} "
            f"(retryable={retryable}): {safe_error}",
            exc_info=True,
        )
        await task_repo.mark_failed(task_id=task_id, error=safe_error)
        await audit.record_action(
            event_type=AuditEventType.TASK_FAILED,
            actor="worker",
            action="fail_recon_task",
            engagement_id=engagement_id,
            task_id=task_id,
            parameters={
                "job_try": job_try,
                "max_tries": max_tries,
                "exhausted": job_try >= max_tries,
            },
            result_status="failed",
            error=safe_error,
        )
        return {
            "status": "failed",
            "task_id": task_id,
            "error": safe_error,
            "job_try": job_try,
            "retryable": retryable,
        }


async def startup(ctx: dict) -> None:
    """Worker startup hook."""


async def shutdown(ctx: dict) -> None:
    """Worker shutdown hook."""


def get_redis_settings() -> RedisSettings:
    settings = get_settings()
    # Parse redis URL into RedisSettings
    from urllib.parse import urlparse

    parsed = urlparse(settings.redis_url)
    return RedisSettings(
        host=parsed.hostname or "localhost",
        port=parsed.port or 6379,
        database=int(parsed.path.lstrip("/") or "0"),
    )


class WorkerSettings:
    """Arq worker settings."""

    # Production worker ONLY executes run_orchestrator_task (security pipeline enforced)
    functions: ClassVar[list] = [run_orchestrator_task]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = get_redis_settings()
    max_jobs = 10
    job_timeout = 600  # 10 minutes
    retry_jobs = True
    max_tries = 3


async def enqueue_tool_execution(redis: ArqRedis, tool_request_data: dict) -> str:
    """QUARANTINED / DEPRECATED: Direct tool enqueueing is forbidden."""
    raise RuntimeError(
        "enqueue_tool_execution is quarantined and forbidden: all tool execution "
        "must flow through ReconOrchestrationService."
    )


async def enqueue_orchestrator_run(
    redis: ArqRedis,
    task_id: str,
    engagement_id: str,
    objective: str = "Autonomous reconnaissance",
    max_iterations: int = 10,
) -> str:
    """Submit an orchestrator run job."""
    job = await redis.enqueue_job(
        "run_orchestrator_task", task_id, engagement_id, objective, max_iterations
    )
    return job.job_id if job else ""
