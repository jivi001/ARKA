"""Recon Orchestration Service — bridge between API and ReconAgent/ReconGraphWorkflow.

Responsibilities:
1. Validate engagement lifecycle state
2. Load authoritative scope from PostgreSQL
3. Create persistent task
4. Construct orchestration context (ScopeGuard, PolicyEngine, ToolRegistry, etc.)
5. Execute ReconAgent through the complete security pipeline
6. Persist task results

SECURITY INVARIANTS:
- This service NEVER directly executes security tools
- All tool execution flows through: ToolRegistry → ScopeGuard → PolicyEngine → ApprovalManager → ExecutionManager
- Discovered infrastructure NEVER expands authorization scope
- LLM output is NEVER trusted or directly executed
"""

from __future__ import annotations

import json
import traceback
from typing import Any

from arka.app.agents.recon.agent import ReconAgent
from arka.app.agents.recon.models import ReconAgentConfig, ReconState
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

    start() — called by the API route (synchronous, creates task, enqueues)
    execute() — called by the worker (asynchronous, runs ReconAgent)
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
        """Create a persistent task and prepare for asynchronous execution.

        Called by the API route handler. Does NOT execute tools.

        Returns:
            Dict with task_id, engagement_id, status, objective
        """
        # 1. Create persistent task (status: queued)
        task = await self._task_repo.create_task(
            engagement_id=engagement_id,
            task_type="recon",
            name=f"Reconnaissance: {objective[:100]}",
            objective=objective,
            max_iterations=max_iterations,
            agent_id="recon_agent",
        )

        task_id = str(task.id)

        # 2. Audit: task.created
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

    async def execute(self, task_id: str) -> None:
        """Execute the complete recon workflow for a persistent task.

        Called by the worker. Runs ReconAgent through the authoritative
        security pipeline. Guaranteed to mark the task as completed or
        failed regardless of exceptions.

        SECURITY: All tool execution flows through ToolRegistry.
        This method does NOT directly invoke any tool executor.
        """
        task = await self._task_repo.get_task(task_id)
        if not task:
            logger.error(f"Task {task_id} not found for execution")
            return

        engagement_id = str(task.engagement_id)

        # Mark task as running
        await self._task_repo.mark_started(task_id)
        await self._audit.record_action(
            event_type=AuditEventType.TASK_STARTED,
            actor="orchestrator",
            action="start_recon_execution",
            engagement_id=engagement_id,
            task_id=task_id,
            result_status="success",
        )

        try:
            # 1. Load authoritative scope from PostgreSQL
            scope_data = await self._scope_repo.get_scope(engagement_id)
            if not scope_data:
                raise ReconOrchestrationError(
                    f"No scope defined for engagement {engagement_id}"
                )

            scope_def = ScopeDefinition(
                engagement_id=engagement_id,
                version=scope_data.get("version", 1),
                includes=ScopeTarget(**(scope_data.get("includes", {}))),
                excludes=ScopeTarget(**(scope_data.get("excludes", {}))),
            )

            # 2. Construct security boundary components
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

            # 3. Register tools explicitly
            register_all_tools(tool_registry)

            # 4. Create ReconAgent with all security dependencies
            config = ReconAgentConfig(
                max_iterations=task.max_iterations,
                max_actions=task.max_iterations * 3,
            )
            asset_repo = InMemoryAssetRepository()
            normalizer = AssetNormalizer()

            agent = ReconAgent(
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
            )

            # 5. Build initial recon state
            initial_state = ReconState(
                engagement_id=engagement_id,
                authorized_scope=scope_data,
                recon_objectives=[task.objective] if task.objective else [
                    "Enumerate open ports and active services"
                ],
            )

            # 6. Execute ReconAgent loop
            logger.info(
                f"Starting ReconAgent execution: task={task_id}, "
                f"engagement={engagement_id}, max_iter={task.max_iterations}"
            )
            final_state = await agent.run(initial_state)

            # 7. Persist results
            output_data = {
                "status": final_state.status,
                "termination_reason": (
                    final_state.termination_reason.value
                    if final_state.termination_reason
                    else None
                ),
                "iterations": final_state.iteration,
                "actions_executed": final_state.action_count,
                "assets_discovered": len(final_state.current_assets),
                "services_discovered": len(final_state.current_services),
                "observations": final_state.observations[:20],
                "errors": final_state.errors[-10:] if final_state.errors else [],
            }

            await self._task_repo.mark_completed(
                task_id=task_id,
                output_data=output_data,
                evidence_refs=final_state.evidence_refs,
            )

            await self._audit.record_action(
                event_type=AuditEventType.TASK_COMPLETED,
                actor="orchestrator",
                action="complete_recon_execution",
                engagement_id=engagement_id,
                task_id=task_id,
                parameters={
                    "iterations": final_state.iteration,
                    "actions_executed": final_state.action_count,
                    "assets_discovered": len(final_state.current_assets),
                },
                result_status="success",
            )

            logger.info(
                f"ReconAgent completed: task={task_id}, "
                f"status={final_state.status}, "
                f"iterations={final_state.iteration}, "
                f"actions={final_state.action_count}"
            )

        except Exception as e:
            # GUARANTEED: task is always marked as failed on exception
            safe_error = str(e)[:4096]
            logger.error(
                f"Recon execution failed: task={task_id}, error={safe_error}",
                exc_info=True,
            )

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
