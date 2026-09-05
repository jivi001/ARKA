"""Recon Orchestration Service — bridge between API and ReconGraphWorkflow.

Responsibilities:
1. Validate engagement lifecycle state directly from PostgreSQL
2. Load authoritative scope and version from PostgreSQL
3. Create persistent task in PostgreSQL
4. Construct isolated per-task orchestration context (ScopeGuard, PolicyEngine, ToolRegistry)
5. Execute ReconGraphWorkflow (LangGraph StateGraph) through the complete security pipeline
6. Persist task results and guarantee state machine transitions

SECURITY INVARIANTS:
- This service NEVER directly executes security tools
- All tool execution flows through: ToolRegistry → ScopeGuard → PolicyEngine →
  ApprovalManager → ExecutionManager
- Discovered infrastructure NEVER expands authorization scope
- LLM output is NEVER trusted or directly executed
- Atomic CAS guarantees single transition to 'running' with single audit event
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from arka.app.agents.recon.graph import create_recon_graph
from arka.app.agents.recon.models import ReconAgentConfig
from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.repository import ScopeRepository
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.core.tasks.repository import TaskRepository
from arka.app.database.models import Engagement
from arka.app.execution.evidence import EvidenceStore
from arka.app.execution.manager import ExecutionManager
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.observability.logging import get_logger
from arka.app.tools.registration import register_all_tools
from arka.app.tools.registry.registry import ToolRegistry

logger = get_logger(__name__)


class ReconOrchestrationError(Exception):
    """Raised when orchestration encounters a non-recoverable error."""


class ReconOrchestrationService:
    """Orchestrates the complete recon lifecycle from API trigger to task completion.

    start() — called synchronously by API route handler (creates task, returns queued status)
    execute() — called asynchronously by worker (runs ReconGraphWorkflow)
    """

    def __init__(
        self,
        task_repository: TaskRepository,
        scope_repository: ScopeRepository,
        audit_service: AuditService,
        llm_gateway: LLMGateway,
        approval_manager: ApprovalManager,
    ) -> None:
        self._task_repo = task_repository
        self._scope_repo = scope_repository
        self._audit = audit_service
        self._llm = llm_gateway
        self._approval_manager = approval_manager

    async def start(
        self,
        engagement_id: str,
        objective: str = "Autonomous reconnaissance",
        max_iterations: int = 10,
    ) -> dict[str, Any]:
        """Create a persistent task in PostgreSQL and prepare for execution.

        Does NOT execute tools. Called synchronously before enqueueing to worker.
        """
        task = await self._task_repo.create_task(
            engagement_id=engagement_id,
            task_type="recon",
            name=f"Reconnaissance: {objective[:100]}",
            objective=objective,
            max_iterations=max_iterations,
            agent_id="recon_agent",
        )

        task_id = str(task.id)

        # Audit: task.created
        await self._audit.record_action(
            event_type=AuditEventType.TASK_CREATED,
            actor="api",
            action="create_recon_task",
            engagement_id=engagement_id,
            task_id=task_id,
            parameters={
                "objective": objective,
                "max_iterations": max_iterations,
                "task_type": "recon",
            },
            result_status="success",
        )

        logger.info(
            f"Recon task created: task_id={task_id}, "
            f"engagement={engagement_id}, objective={objective[:80]}"
        )

        return {
            "task_id": task_id,
            "engagement_id": engagement_id,
            "status": "queued",
            "objective": objective,
        }

    async def execute(self, task_id: str, auto_mark_failed: bool = True) -> None:
        """Execute the complete recon workflow for a persistent task.

        Sole authoritative owner of task status transitions.
        Uses atomic CAS to ensure exactly ONE transition to 'running'.
        Guaranteed to mark task as completed or failed (if auto_mark_failed=True).
        """
        task = await self._task_repo.get_task(task_id)
        if not task:
            logger.error(f"Task {task_id} not found for execution")
            return

        engagement_id = str(task.engagement_id)

        # Atomic Compare-And-Swap transition: queued -> running
        started_task = await self._task_repo.mark_started(task_id)
        if started_task is None:
            logger.warning(
                f"Task {task_id} cannot start (already running or terminated). "
                f"Skipping duplicate execution."
            )
            return

        # Single authoritative TASK_STARTED audit event
        await self._audit.record_action(
            event_type=AuditEventType.TASK_STARTED,
            actor="orchestrator",
            action="start_recon_execution",
            engagement_id=engagement_id,
            task_id=task_id,
            result_status="success",
        )

        try:
            # 1. Validate engagement state in PostgreSQL
            if self._scope_repo._session_factory:
                async with self._scope_repo._session_factory() as session:
                    eng_res = await session.execute(
                        select(Engagement).where(Engagement.id == uuid.UUID(engagement_id))
                    )
                    db_eng = eng_res.scalar_one_or_none()
                    if not db_eng:
                        raise ReconOrchestrationError(
                            f"Engagement {engagement_id} not found in database"
                        )
                    if db_eng.status != "active":
                        raise ReconOrchestrationError(
                            f"Engagement {engagement_id} status is '{db_eng.status}'. "
                            "Must be 'active' to execute."
                        )

            # 2. Load authoritative scope from PostgreSQL
            raw_scope = await self._scope_repo.get_scope(engagement_id)
            if not raw_scope:
                raise ReconOrchestrationError(
                    f"No scope defined for engagement {engagement_id}"
                )

            if isinstance(raw_scope, ScopeDefinition):
                scope_def = raw_scope
                scope_data = raw_scope.model_dump()
            else:
                scope_data = raw_scope
                scope_def = ScopeDefinition(
                    engagement_id=engagement_id,
                    version=scope_data.get("version", 1),
                    includes=ScopeTarget(**(scope_data.get("includes", {}))),
                    excludes=ScopeTarget(**(scope_data.get("excludes", {}))),
                )

            # 3. Construct per-task isolated security boundary components
            scope_guard = ScopeGuard(scope_def)
            policy_engine = PolicyEngine(scope_guard)
            evidence_store = EvidenceStore()
            execution_manager = ExecutionManager(
                audit_service=self._audit,
                evidence_store=evidence_store,
            )
            tool_registry = ToolRegistry(
                policy_engine=policy_engine,
                audit_service=self._audit,
                approval_manager=self._approval_manager,
                execution_manager=execution_manager,
            )

            # 4. Register production tools explicitly into isolated registry
            register_all_tools(tool_registry)

            # 5. Create compiled LangGraph workflow
            config = ReconAgentConfig(
                max_iterations=task.max_iterations,
                max_actions=task.max_iterations * 3,
            )
            asset_repo = InMemoryAssetRepository()
            normalizer = AssetNormalizer()

            graph = create_recon_graph(
                llm_gateway=self._llm,
                tool_registry=tool_registry,
                audit_service=self._audit,
                scope_guard=scope_guard,
                policy_engine=policy_engine,
                approval_manager=self._approval_manager,
                asset_repository=asset_repo,
                asset_normalizer=normalizer,
                evidence_store=evidence_store,
                config=config,
                agent_id="recon_agent",
            )

            # 6. Build initial ReconAgentState dictionary for LangGraph
            initial_state = {
                "engagement_id": engagement_id,
                "current_task_id": task_id,
                "authorized_scope": scope_data,
                "recon_objectives": [task.objective] if task.objective else [
                    "Enumerate open ports and active services"
                ],
                "max_iterations": task.max_iterations,
                "max_actions": task.max_iterations * 3,
            }

            logger.info(
                f"Starting ReconGraphWorkflow execution: task={task_id}, "
                f"engagement={engagement_id}, max_iter={task.max_iterations}"
            )

            thread_config = {"configurable": {"thread_id": task_id}}
            final_state = await graph.ainvoke(initial_state, config=thread_config)

            # 7. Persist results
            output_data = {
                "status": final_state.get("status", "completed"),
                "termination_reason": final_state.get("termination_reason"),
                "iterations": final_state.get("iteration", 0),
                "actions_executed": final_state.get("action_count", 0),
                "assets_discovered": len(final_state.get("current_assets", [])),
                "services_discovered": len(final_state.get("current_services", [])),
                "observations": final_state.get("observations", [])[:20],
                "errors": final_state.get("errors", [])[-10:],
            }
            evidence_refs = list(final_state.get("evidence_refs", []))

            await self._task_repo.mark_completed(
                task_id=task_id,
                output_data=output_data,
                evidence_refs=evidence_refs,
            )

            await self._audit.record_action(
                event_type=AuditEventType.TASK_COMPLETED,
                actor="orchestrator",
                action="complete_recon_execution",
                engagement_id=engagement_id,
                task_id=task_id,
                parameters={
                    "iterations": output_data["iterations"],
                    "actions_executed": output_data["actions_executed"],
                    "assets_discovered": output_data["assets_discovered"],
                },
                result_status="success",
            )

            logger.info(
                f"ReconGraphWorkflow completed: task={task_id}, "
                f"status={output_data['status']}, "
                f"iterations={output_data['iterations']}, "
                f"actions={output_data['actions_executed']}"
            )

        except Exception as e:
            safe_error = str(e)[:4096]
            logger.error(
                f"Recon execution failed: task={task_id}, error={safe_error}",
                exc_info=True,
            )

            if auto_mark_failed:
                await self._task_repo.mark_failed(task_id=task_id, error=safe_error)

                await self._audit.record_action(
                    event_type=AuditEventType.TASK_FAILED,
                    actor="orchestrator",
                    action="fail_recon_execution",
                    engagement_id=engagement_id,
                    task_id=task_id,
                    result_status="failed",
                    error=safe_error,
                )
            raise