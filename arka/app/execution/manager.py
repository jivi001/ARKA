"""Execution Manager orchestrating execution mechanics, sandboxing, and audit for ARKA Phase 2.1."""

import asyncio
import time
from typing import Any

from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.state.models import new_id, utc_now
from arka.app.execution.evidence import EvidenceStore
from arka.app.execution.policy import ExecutionPolicy
from arka.app.execution.sandbox.base import SandboxRuntime
from arka.app.execution.sandbox.local import LocalSafeRuntime
from arka.app.execution.schemas import (
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    NetworkProfile,
)
from arka.app.tools.schemas.tool_schemas import ToolDefinition, ToolRequest, ToolResult


class ExecutionManagerError(Exception):
    """Raised when execution orchestration encounters an unrecoverable failure."""


class ExecutionManager:
    """Authoritative execution manager bridging ARKA control plane to isolated sandboxes.

    Ensures that only authoritative, scope-validated, policy-approved ToolRequests can execute.
    Manages sandbox lifecycle, execution limits, timeout cancellations, evidence collection,
    and append-only audit logging.
    """

    def __init__(
        self,
        audit_service: AuditService,
        policy: ExecutionPolicy | None = None,
        runtime: SandboxRuntime | None = None,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        self.audit = audit_service
        self.policy = policy or ExecutionPolicy()
        self.runtime = runtime or LocalSafeRuntime()
        self.evidence_store = evidence_store or EvidenceStore()

    async def execute_tool(
        self,
        request: ToolRequest,
        tool_def: ToolDefinition,
        executor_func: Any,
    ) -> tuple[ExecutionResult, ToolResult]:
        """Execute a tool through the authoritative execution pipeline.

        Args:
            request: Authoritative ToolRequest with scope_validated=True and policy_approved=True.
            tool_def: ToolDefinition metadata.
            executor_func: The ToolExecutor instance or callable to invoke.

        Returns:
            tuple of (ExecutionResult, ToolResult)
        """
        execution_id = new_id()
        started_at = utc_now()
        start_mono = time.monotonic()

        # Step 1: Pre-execution validation check
        is_valid, validation_err = self.policy.validate_request(request, tool_def)
        if not is_valid:
            await self.audit.record_action(
                event_type=AuditEventType.EXECUTION_REJECTED,
                actor=request.agent_id,
                action=f"reject_execution:{request.tool_name}",
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                target=request.target,
                result_status="rejected",
                error=validation_err,
                correlation_id=request.request_id,
            )
            exec_result = ExecutionResult(
                execution_id=execution_id,
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                status=ExecutionStatus.REJECTED,
                started_at=started_at,
                completed_at=utc_now(),
                duration_ms=0,
                exit_code=-1,
                stdout="",
                stderr=validation_err or "Execution rejected",
                error=validation_err,
            )
            tool_result = ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=validation_err,
                output={},
                raw_output="",
                execution_time_ms=0,
                evidence_refs=[],
            )
            return exec_result, tool_result

        # Step 2: Derive authoritative limits
        limits = self.policy.derive_limits(tool_def)
        sanitized_env = self.policy.sanitize_environment()
        network_profile = self.policy.resolve_network_profile(NetworkProfile.NO_NETWORK)

        exec_request = ExecutionRequest(
            execution_id=execution_id,
            request_id=request.request_id,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            target=request.target,
            arguments=request.arguments,
            command=[request.tool_name, request.target],
            environment=sanitized_env,
            limits=limits,
            network_profile=network_profile,
            created_at=started_at,
        )

        # Step 3: Record audit events
        await self.audit.record_action(
            event_type=AuditEventType.TOOL_REQUESTED,
            actor=request.agent_id,
            action=f"execute:{request.tool_name}",
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            target=request.target,
            parameters=request.arguments,
            correlation_id=request.request_id,
        )

        await self.audit.record_action(
            event_type=AuditEventType.EXECUTION_REQUESTED,
            actor=request.agent_id,
            action=f"execution_requested:{request.tool_name}",
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            target=request.target,
            parameters=request.arguments,
            correlation_id=request.request_id,
        )

        await self.audit.record_action(
            event_type=AuditEventType.EXECUTION_AUTHORIZED,
            actor="execution_manager",
            action=f"execution_authorized:{request.tool_name}",
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            target=request.target,
            correlation_id=request.request_id,
        )

        # Step 4: Sandbox lifecycle
        sandbox_id = await self.runtime.create(exec_request)
        await self.audit.record_action(
            event_type=AuditEventType.EXECUTION_STARTED,
            actor="execution_manager",
            action=f"execution_started:{request.tool_name}",
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            target=request.target,
            parameters={"sandbox_id": sandbox_id},
            correlation_id=request.request_id,
        )

        try:
            # Step 5: Execute executor within timeout
            timeout = limits.max_execution_time_seconds
            executed_tool_result: ToolResult = await asyncio.wait_for(
                executor_func.execute(request, tool_def),
                timeout=float(timeout),
            )

            duration_ms = int((time.monotonic() - start_mono) * 1000)
            executed_tool_result.execution_time_ms = duration_ms

            # Step 6: Capture cryptographic evidence (three items)
            evidence_refs_list: list[str] = []
            all_evidence_references = []

            # 6a. Record raw tool output (e.g. raw Nmap XML)
            if executed_tool_result.raw_output:
                raw_ref = self.evidence_store.record_evidence(
                    execution_id=execution_id,
                    request_id=request.request_id,
                    engagement_id=request.engagement_id,
                    task_id=request.task_id,
                    content=executed_tool_result.raw_output,
                    evidence_type="raw_stdout",
                    tool_name=request.tool_name,
                    metadata={"target": request.target},
                )
                evidence_refs_list.append(raw_ref.evidence_id)
                all_evidence_references.append(raw_ref)

            # 6b. Record structured result (parsed output dict)
            structured_ref = self.evidence_store.record_evidence(
                execution_id=execution_id,
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                content=executed_tool_result.output,
                evidence_type="structured_result",
                tool_name=request.tool_name,
                metadata={"target": request.target},
            )
            evidence_refs_list.append(structured_ref.evidence_id)
            all_evidence_references.append(structured_ref)

            # 6c. Record stderr if present
            if executed_tool_result.error:
                stderr_ref = self.evidence_store.record_evidence(
                    execution_id=execution_id,
                    request_id=request.request_id,
                    engagement_id=request.engagement_id,
                    task_id=request.task_id,
                    content=executed_tool_result.error,
                    evidence_type="raw_stderr",
                    tool_name=request.tool_name,
                    metadata={"target": request.target},
                )
                evidence_refs_list.append(stderr_ref.evidence_id)
                all_evidence_references.append(stderr_ref)

            # Attach all evidence refs to tool result
            executed_tool_result.evidence_refs.extend(evidence_refs_list)

            # 6d. Audit: evidence recorded
            await self.audit.record_action(
                event_type=AuditEventType.EVIDENCE_RECORDED,
                actor="execution_manager",
                action=f"evidence_recorded:{request.tool_name}",
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                target=request.target,
                parameters={
                    "evidence_count": len(evidence_refs_list),
                    "evidence_ids": evidence_refs_list,
                },
                correlation_id=request.request_id,
            )

            sandbox_meta = await self.runtime.collect_metadata(sandbox_id)

            exec_result = ExecutionResult(
                execution_id=execution_id,
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                status=(
                    ExecutionStatus.COMPLETED
                    if executed_tool_result.success
                    else ExecutionStatus.FAILED
                ),
                started_at=started_at,
                completed_at=utc_now(),
                duration_ms=duration_ms,
                exit_code=0 if executed_tool_result.success else 1,
                stdout=str(executed_tool_result.output),
                stderr=executed_tool_result.error or "",
                structured_output=executed_tool_result.output,
                error=executed_tool_result.error,
                sandbox_id=sandbox_id,
                evidence_references=all_evidence_references,
                resource_usage={"duration_ms": duration_ms},
                metadata=sandbox_meta,
            )

            if executed_tool_result.success:
                await self.audit.record_action(
                    event_type=AuditEventType.TOOL_EXECUTED,
                    actor=request.agent_id,
                    action=f"executed:{request.tool_name}",
                    engagement_id=request.engagement_id,
                    task_id=request.task_id,
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    target=request.target,
                    result_status="success",
                    error=executed_tool_result.error,
                    correlation_id=request.request_id,
                )
                await self.audit.record_action(
                    event_type=AuditEventType.EXECUTION_COMPLETED,
                    actor=request.agent_id,
                    action=f"execution_completed:{request.tool_name}",
                    engagement_id=request.engagement_id,
                    task_id=request.task_id,
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    target=request.target,
                    result_status="completed",
                    error=executed_tool_result.error,
                    evidence_ref=structured_ref.evidence_id,
                    correlation_id=request.request_id,
                )
            else:
                await self.audit.record_action(
                    event_type=AuditEventType.TOOL_FAILED,
                    actor=request.agent_id,
                    action=f"failed:{request.tool_name}",
                    engagement_id=request.engagement_id,
                    task_id=request.task_id,
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    target=request.target,
                    result_status="failed",
                    error=executed_tool_result.error,
                    correlation_id=request.request_id,
                )
                await self.audit.record_action(
                    event_type=AuditEventType.EXECUTION_FAILED,
                    actor=request.agent_id,
                    action=f"execution_failed:{request.tool_name}",
                    engagement_id=request.engagement_id,
                    task_id=request.task_id,
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    target=request.target,
                    result_status="failed",
                    error=executed_tool_result.error,
                    evidence_ref=structured_ref.evidence_id,
                    correlation_id=request.request_id,
                )
            return exec_result, executed_tool_result

        except TimeoutError:
            duration_ms = int((time.monotonic() - start_mono) * 1000)
            await self.runtime.terminate(sandbox_id)

            err_msg = f"Tool execution timed out after {limits.max_execution_time_seconds}s"
            await self.audit.record_action(
                event_type=AuditEventType.TOOL_FAILED,
                actor=request.agent_id,
                action=f"timeout:{request.tool_name}",
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                target=request.target,
                result_status="timeout",
                error=err_msg,
                correlation_id=request.request_id,
            )
            await self.audit.record_action(
                event_type=AuditEventType.EXECUTION_TIMED_OUT,
                actor=request.agent_id,
                action=f"execution_timed_out:{request.tool_name}",
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                target=request.target,
                result_status="timed_out",
                error=err_msg,
                correlation_id=request.request_id,
            )

            exec_result = ExecutionResult(
                execution_id=execution_id,
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                status=ExecutionStatus.TIMED_OUT,
                started_at=started_at,
                completed_at=utc_now(),
                duration_ms=duration_ms,
                exit_code=-1,
                stdout="",
                stderr=err_msg,
                error=err_msg,
                sandbox_id=sandbox_id,
            )
            tool_result = ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=err_msg,
                output={},
                raw_output="",
                execution_time_ms=duration_ms,
                evidence_refs=[],
            )
            return exec_result, tool_result

        except Exception as e:
            duration_ms = int((time.monotonic() - start_mono) * 1000)
            await self.runtime.terminate(sandbox_id)

            err_msg = f"Execution error: {e!s}"
            await self.audit.record_action(
                event_type=AuditEventType.TOOL_FAILED,
                actor=request.agent_id,
                action=f"error:{request.tool_name}",
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                target=request.target,
                result_status="error",
                error=err_msg,
                correlation_id=request.request_id,
            )
            await self.audit.record_action(
                event_type=AuditEventType.EXECUTION_FAILED,
                actor=request.agent_id,
                action=f"execution_failed:{request.tool_name}",
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                target=request.target,
                result_status="failed",
                error=err_msg,
                correlation_id=request.request_id,
            )

            exec_result = ExecutionResult(
                execution_id=execution_id,
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                status=ExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=utc_now(),
                duration_ms=duration_ms,
                exit_code=-1,
                stdout="",
                stderr=err_msg,
                error=err_msg,
                sandbox_id=sandbox_id,
            )
            tool_result = ToolResult(
                request_id=request.request_id,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                tool_name=request.tool_name,
                success=False,
                error=err_msg,
                output={},
                raw_output="",
                execution_time_ms=duration_ms,
                evidence_refs=[],
            )
            return exec_result, tool_result

        finally:
            # Step 7: Guaranteed sandbox resource release
            await self.runtime.destroy(sandbox_id)
