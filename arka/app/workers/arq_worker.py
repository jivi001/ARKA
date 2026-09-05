from typing import ClassVar

from arq.connections import ArqRedis, RedisSettings

from arka.app.core.config import get_settings


async def execute_tool_task(ctx: dict, tool_request_data: dict) -> dict:
    """Worker function to execute a tool request asynchronously."""
    # Phase 1: Basic task execution stub
    # In production, this would:
    # 1. Deserialize ToolRequest from tool_request_data
    # 2. Execute through the ToolRegistry
    # 3. Return ToolResult
    return {"status": "completed", "request": tool_request_data}


async def run_orchestrator_task(
    ctx: dict, task_id: str, engagement_id: str, objective: str, max_iterations: int = 10
) -> dict:
    """Worker function to run the ReconAgent through the full security pipeline.

    Constructs a fresh ReconOrchestrationService and executes the recon workflow.
    All tool execution flows through ToolRegistry → ScopeGuard → PolicyEngine →
    ApprovalManager → ExecutionManager. This function NEVER directly invokes tools.
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

    task_repo = TaskRepository(session_factory=get_session_factory())
    orchestrator = ReconOrchestrationService(
        task_repository=task_repo,
        scope_repository=get_scope_repository(),
        audit_service=get_audit_service(),
        llm_gateway=get_llm_gateway(),
        approval_manager=get_approval_manager(),
    )

    try:
        await orchestrator.execute(task_id)
        return {"status": "completed", "task_id": task_id, "engagement_id": engagement_id}
    except Exception as e:
        # orchestrator.execute() already marks task as failed internally,
        # but we catch here for the ARQ job result
        return {"status": "failed", "task_id": task_id, "error": str(e)[:1024]}


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

    functions: ClassVar[list] = [execute_tool_task, run_orchestrator_task]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings()  # Will be overridden at runtime
    max_jobs = 10
    job_timeout = 600  # 10 minutes
    retry_jobs = True
    max_tries = 3


async def enqueue_tool_execution(redis: ArqRedis, tool_request_data: dict) -> str:
    """Submit a tool execution job."""
    job = await redis.enqueue_job("execute_tool_task", tool_request_data)
    return job.job_id if job else ""


async def enqueue_orchestrator_run(redis: ArqRedis, engagement_id: str, objective: str) -> str:
    """Submit an orchestrator run job."""
    job = await redis.enqueue_job("run_orchestrator_task", engagement_id, objective)
    return job.job_id if job else ""
