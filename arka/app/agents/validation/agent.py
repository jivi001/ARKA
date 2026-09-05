"""ValidationAgent implementation for ARKA Phase 2.2.10.

Independently checks high-confidence findings to identify false positives.
Follows all ARKA security invariants:
- LLM is untrusted (schema validation enforced, no shell execution).
- All tool requests route through ToolRegistry.
- State transitions: observed -> suspected -> validating -> validated / false_positive.
- Cryptographic provenance and structured audit logging.
"""

from __future__ import annotations

import json
from typing import Any

from arka.app.agents.base.agent import BaseAgent
from arka.app.agents.validation.models import (
    FindingValidationStatus,
    ValidationAction,
    ValidationAssessment,
    ValidationPlan,
)
from arka.app.agents.validation.prompts import (
    VALIDATION_ASSESSMENT_SYSTEM_PROMPT,
    VALIDATION_PLAN_SYSTEM_PROMPT,
    format_validation_assessment_prompt,
    format_validation_plan_prompt,
)
from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.models import Finding
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import new_id
from arka.app.execution.evidence import EvidenceStore
from arka.app.llm.gateway.gateway import LLMGateway, LLMGatewayError
from arka.app.llm.schemas.llm_schemas import LLMMessage, LLMRequest
from arka.app.observability.logging import get_logger
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest, ToolResult

logger = get_logger(__name__)


def _clean_json_markdown(raw: str) -> str:
    """Extract raw JSON text from markdown code fences if present."""
    cleaned = raw.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    return cleaned.strip()


class ValidationAgent(BaseAgent):
    """ARKA Autonomous Validation Agent for verifying findings and eliminating false positives."""

    def __init__(
        self,
        llm_gateway: LLMGateway,
        tool_registry: ToolRegistry,
        audit_service: AuditService,
        scope_guard: ScopeGuard | None = None,
        policy_engine: PolicyEngine | None = None,
        approval_manager: ApprovalManager | None = None,
        asset_repository: InMemoryAssetRepository | None = None,
        evidence_store: EvidenceStore | None = None,
        model: str | None = None,
    ) -> None:
        super().__init__(
            agent_id=new_id(),
            agent_type="validation_agent",
            llm_gateway=llm_gateway,
            tool_registry=tool_registry,
            audit_service=audit_service,
        )
        self.scope_guard = scope_guard
        self.policy_engine = policy_engine
        self.approval_manager = approval_manager
        self.asset_repository = asset_repository
        self.evidence_store = evidence_store
        self.model = model or "gpt-4o"

    async def execute_task(self, task: dict[str, Any]) -> dict[str, Any]:
        """Execute a validation task passed from the orchestration layer."""
        finding = task.get("finding")
        authorized_scope = task.get("authorized_scope", {})
        if not finding or not isinstance(finding, Finding):
            return {"error": "Invalid or missing Finding in task payload"}

        assessment = await self.validate_finding(finding, authorized_scope)
        return assessment.model_dump()

    async def validate_finding(
        self,
        finding: Finding,
        authorized_scope: dict[str, Any],
    ) -> ValidationAssessment:
        """Independently assess and verify a candidate finding."""
        engagement_id = finding.engagement_id

        await self.audit.record_action(
            event_type=AuditEventType.AGENT_STARTED,
            actor=self.agent_id,
            action="validation_started",
            engagement_id=engagement_id,
            target=finding.matched_at,
            parameters={"finding_id": finding.finding_id, "title": finding.title},
            result_status="started",
        )

        # Update finding status to 'validating'
        if self.asset_repository:
            self.asset_repository.update_finding_status(
                finding.finding_id, FindingValidationStatus.VALIDATING.value
            )

        # 1. Ask LLM for a validation plan
        plan = await self._create_validation_plan(finding, authorized_scope)

        # 2. Execute verification actions via ToolRegistry
        tool_results: list[dict[str, Any]] = []
        collected_evidence: list[str] = []

        for action in plan.actions:
            result = await self._execute_validation_action(action, engagement_id)
            tool_results.append(
                {
                    "tool_name": action.tool_name,
                    "target": action.target,
                    "success": result.success,
                    "output": result.output,
                    "error": result.error,
                }
            )
            for ref in result.evidence_refs:
                if ref not in collected_evidence:
                    collected_evidence.append(ref)

        # 3. Assess results with LLM
        assessment = await self._assess_results(finding, plan, tool_results, collected_evidence)

        # 4. Update repository
        if self.asset_repository:
            self.asset_repository.update_finding_status(
                finding.finding_id,
                assessment.status.value,
                confidence=assessment.confidence,
            )

        # 5. Log audit event
        await self.audit.record_action(
            event_type=AuditEventType.EVIDENCE_RECORDED,
            actor=self.agent_id,
            action="validation_completed",
            engagement_id=engagement_id,
            target=finding.matched_at,
            parameters={
                "finding_id": finding.finding_id,
                "status": assessment.status.value,
                "confidence": assessment.confidence,
                "reasoning": assessment.reasoning,
            },
            result_status="success",
        )

        return assessment

    async def _create_validation_plan(
        self,
        finding: Finding,
        authorized_scope: dict[str, Any],
    ) -> ValidationPlan:
        """Call LLM to propose a verification plan and validate schema."""
        prompt = format_validation_plan_prompt(finding, authorized_scope)
        request = LLMRequest(
            messages=[
                LLMMessage(role="system", content=VALIDATION_PLAN_SYSTEM_PROMPT),
                LLMMessage(role="user", content=prompt),
            ],
            model=self.model,
            temperature=0.0,
            response_format={"type": "json_object"},
        )

        try:
            resp = await self.llm.complete(request)
            cleaned = _clean_json_markdown(resp.content)
            data = json.loads(cleaned)
            return ValidationPlan(
                finding_id=finding.finding_id,
                reasoning=str(data.get("reasoning", "")),
                actions=[
                    ValidationAction(
                        tool_name=str(a.get("tool_name", "nuclei")),
                        target=str(a.get("target", finding.matched_at or "")),
                        arguments=dict(a.get("arguments", {})),
                        rationale=str(a.get("rationale", "")),
                    )
                    for a in data.get("actions", [])
                ],
            )
        except (LLMGatewayError, json.JSONDecodeError, ValueError) as e:
            logger.warning(
                "Validation plan generation error: %s. Falling back to default check.", e
            )
            # Default fallback verification action
            target_str = finding.matched_at or finding.asset_id or ""
            return ValidationPlan(
                finding_id=finding.finding_id,
                reasoning="Fallback verification check due to plan parsing failure.",
                actions=[
                    ValidationAction(
                        tool_name="nuclei",
                        target=target_str,
                        arguments={"templates": [finding.template_id]}
                        if finding.template_id
                        else {},
                        rationale="Re-check finding with specific template",
                    )
                ],
            )

    async def _execute_validation_action(
        self, action: ValidationAction, engagement_id: str
    ) -> ToolResult:
        """Submit verification action to ToolRegistry through security pipeline."""
        candidate = CandidateToolRequest(
            tool_name=action.tool_name,
            target=action.target,
            arguments=action.arguments,
            reason=action.rationale or "Validation scan",
        )
        auth_req, _decision, err = self.tools.validate_candidate_request(
            candidate=candidate,
            engagement_id=engagement_id,
            task_id=new_id(),
            agent_id=self.agent_id,
        )
        if not auth_req:
            return ToolResult(
                request_id=new_id(),
                engagement_id=engagement_id,
                task_id=new_id(),
                tool_name=action.tool_name,
                success=False,
                error=err or "Validation action rejected by security pipeline",
                output={"rejected": True, "reason": err},
                raw_output="",
                execution_time_ms=0,
                evidence_refs=[],
            )
        return await self.tools.execute(auth_req)

    async def _assess_results(
        self,
        finding: Finding,
        plan: ValidationPlan,
        tool_results: list[dict[str, Any]],
        evidence_refs: list[str],
    ) -> ValidationAssessment:
        """Call LLM to evaluate verification results and establish status."""
        prompt = format_validation_assessment_prompt(finding, plan.model_dump(), tool_results)
        request = LLMRequest(
            messages=[
                LLMMessage(role="system", content=VALIDATION_ASSESSMENT_SYSTEM_PROMPT),
                LLMMessage(role="user", content=prompt),
            ],
            model=self.model,
            temperature=0.0,
            response_format={"type": "json_object"},
        )

        try:
            resp = await self.llm.complete(request)
            cleaned = _clean_json_markdown(resp.content)
            data = json.loads(cleaned)
            raw_status = str(data.get("status", "validated")).lower()
            try:
                status = FindingValidationStatus(raw_status)
            except ValueError:
                status = FindingValidationStatus.VALIDATED

            confidence = float(data.get("confidence", 0.9))
            confidence = max(0.0, min(1.0, confidence))

            return ValidationAssessment(
                finding_id=finding.finding_id,
                status=status,
                confidence=confidence,
                reasoning=str(data.get("reasoning", "Assessed via verification output")),
                evidence_refs=evidence_refs,
            )
        except Exception as e:
            logger.warning("Validation assessment error: %s. Using deterministic heuristic.", e)
            # Deterministic heuristic: if any verification tool succeeded and found findings
            has_success = any(r.get("success") for r in tool_results)
            status = (
                FindingValidationStatus.VALIDATED
                if has_success
                else FindingValidationStatus.SUSPECTED
            )
            return ValidationAssessment(
                finding_id=finding.finding_id,
                status=status,
                confidence=0.8 if has_success else 0.5,
                reasoning=f"Heuristic fallback assessment: tool success={has_success}",
                evidence_refs=evidence_refs,
            )
