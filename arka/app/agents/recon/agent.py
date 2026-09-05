"""ReconAgent implementation for ARKA Phase 2.2.4.

Orchestrates autonomous reconnaissance planning, candidate tool request generation,
result interpretation, and canonical asset normalization while strictly enforcing:
1. LLM is never trusted (zero direct execution/mutation authority).
2. DISCOVERED != AUTHORIZED (observed assets never expand authorization scope).
3. Authoritative pipeline enforcement:
   ToolRegistry -> ScopeGuard -> PolicyEngine -> ApprovalManager -> ExecutionManager.
4. Idempotency and bounded execution limits.
"""

from __future__ import annotations

import inspect
import json

from arka.app.agents.base.agent import BaseAgent
from arka.app.agents.recon.models import (
    ReconAction,
    ReconAgentConfig,
    ReconAnalysis,
    ReconPlan,
    ReconState,
    ReconTerminationReason,
)
from arka.app.agents.recon.prompts import (
    RECON_ANALYSIS_PROMPT_TEMPLATE,
    RECON_PLAN_PROMPT_TEMPLATE,
    RECON_SYSTEM_PROMPT,
)
from arka.app.audit.schemas import AuditEventType
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.assets.repository import AssetRepository, InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import new_id, utc_now
from arka.app.execution.evidence import EvidenceStore
from arka.app.llm.gateway.gateway import LLMGateway, LLMGatewayError
from arka.app.llm.schemas.llm_schemas import LLMMessage, LLMRequest
from arka.app.observability.logging import get_logger
from arka.app.tools.amass.parser import parse_amass_json
from arka.app.tools.ffuf.parser import parse_ffuf_json
from arka.app.tools.nmap.parser import parse_nmap_xml
from arka.app.tools.nuclei.parser import parse_nuclei_json
from arka.app.tools.registry.registry import ToolRegistry, ToolRegistryError
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest, ToolResult
from arka.app.tools.whatweb.parser import parse_whatweb_json

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


class ReconAgent(BaseAgent):
    """ARKA Autonomous Reconnaissance Planning and Orchestration Agent.

    Plans reconnaissance against authorized engagement targets, submits candidate
    actions through ARKA's authoritative security pipeline, and normalizes observed
    infrastructure into canonical models.
    """

    def __init__(
        self,
        llm_gateway: LLMGateway,
        tool_registry: ToolRegistry,
        audit_service: AuditService,
        scope_guard: ScopeGuard,
        policy_engine: PolicyEngine,
        approval_manager: ApprovalManager | None = None,
        asset_repository: InMemoryAssetRepository | AssetRepository | None = None,
        asset_normalizer: AssetNormalizer | None = None,
        evidence_store: EvidenceStore | None = None,
        config: ReconAgentConfig | None = None,
        agent_id: str = "recon_agent",
    ) -> None:
        super().__init__(
            agent_id=agent_id,
            agent_type="reconnaissance",
            llm_gateway=llm_gateway,
            tool_registry=tool_registry,
            audit_service=audit_service,
        )
        self.scope = scope_guard
        self.policy = policy_engine
        self.approvals = approval_manager or ApprovalManager()
        self.tools.set_approval_manager(self.approvals)

        self.asset_repo = asset_repository or InMemoryAssetRepository()
        self.normalizer = asset_normalizer or AssetNormalizer()
        self.evidence_store = evidence_store or EvidenceStore()
        self.config = config or ReconAgentConfig()

    async def plan_reconnaissance(self, state: ReconState) -> ReconPlan | None:
        """Query the LLM Gateway to generate a structured reconnaissance plan.

        Translates high-level objectives and current state into candidate actions.
        Rejects malformed, ambiguous, or non-JSON LLM output.
        """
        logger.info(
            f"Generating reconnaissance plan for engagement {state.engagement_id} "
            f"(Iteration {state.iteration})"
        )

        user_prompt = RECON_PLAN_PROMPT_TEMPLATE.format(
            engagement_id=state.engagement_id,
            objectives=state.recon_objectives or ["Enumerate open ports and active services"],
            authorized_scope=json.dumps(state.authorized_scope, default=str),
            assets=state.current_assets,
            services=state.current_services,
            completed_actions=[a.get("fingerprint", "") for a in state.completed_actions],
            hypotheses=state.hypotheses,
            errors=state.errors[-5:] if state.errors else [],
        )

        messages = [
            LLMMessage(role="system", content=RECON_SYSTEM_PROMPT),
            LLMMessage(role="user", content=user_prompt),
        ]

        llm_req = LLMRequest(
            engagement_id=state.engagement_id,
            agent_id=self.agent_id,
            messages=messages,
            temperature=self.config.temperature,
        )

        try:
            llm_resp = await self.llm.complete(llm_req)
            cleaned_content = _clean_json_markdown(llm_resp.content)
            data = json.loads(cleaned_content)
            plan = ReconPlan.model_validate(data)

            await self.audit.record_action(
                event_type=AuditEventType.LLM_RESPONSE,
                actor=self.agent_id,
                action="plan_reconnaissance",
                engagement_id=state.engagement_id,
                parameters={
                    "proposed_actions_count": len(plan.candidate_actions),
                    "objective": plan.objective,
                },
                result_status="success",
            )
            return plan

        except (json.JSONDecodeError, Exception) as e:
            err_msg = f"Failed to parse LLM reconnaissance plan: {e}"
            logger.warning(err_msg)
            state.errors.append(err_msg)
            await self.audit.record_action(
                event_type=AuditEventType.LLM_ERROR,
                actor=self.agent_id,
                action="plan_reconnaissance",
                engagement_id=state.engagement_id,
                result_status="rejected",
                error=err_msg,
            )
            return None

    def prioritize_next_action(self, state: ReconState) -> ReconAction | None:
        """Select the next viable candidate action from pending actions.

        Enforces idempotency and bounded repeated action limits using deterministic
        action fingerprints.
        """
        while state.pending_actions:
            action_dict = state.pending_actions.pop(0)
            try:
                action = ReconAction.model_validate(action_dict)
            except Exception as e:
                state.errors.append(f"Invalid candidate action discarded: {e}")
                continue

            fp = action.fingerprint()
            executions = state.executed_fingerprints.get(fp, 0)

            if executions >= self.config.max_repeated_action_attempts:
                msg = (
                    f"Discarding action '{action.tool_name}' on '{action.target}': "
                    f"reached max repeated attempts ({self.config.max_repeated_action_attempts})"
                )
                logger.info(msg)
                state.errors.append(msg)
                continue

            return action

        return None

    async def submit_candidate_action(
        self,
        action: ReconAction,
        state: ReconState,
        task_id: str | None = None,
    ) -> tuple[ToolResult, bool]:
        """Submit an untrusted ReconAction to the authoritative execution pipeline.

        Flow:
        ReconAction -> CandidateToolRequest -> ToolRegistry -> ScopeGuard
        -> PolicyEngine -> ApprovalManager -> Authoritative ToolRequest
        -> ExecutionManager -> ToolResult

        Returns:
            (ToolResult, is_authorized)
        """
        current_task_id = task_id or new_id()
        candidate = CandidateToolRequest(
            tool_name=action.tool_name,
            target=action.target,
            arguments=action.arguments,
            reason=action.rationale or "ReconAgent scheduled scan",
        )
        state.last_candidate_request = candidate.model_dump()

        # Authoritative security validation
        auth_req, _decision, err = self.tools.validate_candidate_request(
            candidate=candidate,
            engagement_id=state.engagement_id,
            task_id=current_task_id,
            agent_id=self.agent_id,
        )

        if not auth_req:
            rejection_reason = err or "Candidate action rejected by security pipeline"
            logger.warning(
                f"Candidate action rejected: tool='{action.tool_name}', "
                f"target='{action.target}': {rejection_reason}"
            )
            state.consecutive_failures += 1
            state.errors.append(rejection_reason)

            rejected_result = ToolResult(
                request_id=new_id(),
                engagement_id=state.engagement_id,
                task_id=current_task_id,
                tool_name=action.tool_name,
                success=False,
                error=rejection_reason,
                output={"rejected": True, "reason": rejection_reason},
                raw_output="",
                execution_time_ms=0,
                evidence_refs=[],
            )
            state.last_tool_result = rejected_result.model_dump()
            return rejected_result, False

        # Execute through authoritative security boundary
        try:
            tool_result = await self.tools.execute(auth_req)
            state.last_tool_result = tool_result.model_dump()

            if tool_result.success:
                state.consecutive_failures = 0
            else:
                state.consecutive_failures += 1
                if tool_result.error:
                    state.errors.append(tool_result.error)

            return tool_result, True

        except (ToolRegistryError, Exception) as e:
            err_msg = f"Tool execution failed: {e}"
            logger.error(err_msg)
            state.consecutive_failures += 1
            state.errors.append(err_msg)

            failed_result = ToolResult(
                request_id=auth_req.request_id,
                engagement_id=state.engagement_id,
                task_id=current_task_id,
                tool_name=auth_req.tool_name,
                success=False,
                error=err_msg,
                output={},
                raw_output="",
                execution_time_ms=0,
                evidence_refs=[],
            )
            state.last_tool_result = failed_result.model_dump()
            return failed_result, True

    async def process_tool_result(
        self,
        result: ToolResult,
        state: ReconState,
        original_action: ReconAction | None = None,
        task_id: str | None = None,
    ) -> None:
        """Process ToolResult: extract evidence, normalize canonical assets, and persist.

        MANDATORY INVARIANT: DISCOVERED != AUTHORIZED.
        Discovered infrastructure is stored in AssetRepository for knowledge and risk assessment,
        but ScopeGuard is NEVER modified.
        """
        # 1. Maintain evidence linkage
        for ref in result.evidence_refs:
            if ref not in state.evidence_refs:
                state.evidence_refs.append(ref)

        # 2. Add to tool results history
        state.tool_results.append(
            {
                "tool_name": result.tool_name,
                "target": original_action.target if original_action else "",
                "success": result.success,
                "error": result.error,
                "evidence_refs": result.evidence_refs,
                "execution_time_ms": result.execution_time_ms,
            }
        )

        # 3. Canonical normalization across tools
        bundle = None
        target_str = original_action.target if original_action else None

        if result.success and result.raw_output:
            if result.tool_name == "nmap":
                nmap_res = parse_nmap_xml(result.raw_output)
                if nmap_res.success:
                    bundle = self.normalizer.normalize_nmap_result(
                        result=nmap_res,
                        engagement_id=state.engagement_id,
                        task_id=task_id,
                        request_id=result.request_id,
                        target=target_str,
                        evidence_refs=result.evidence_refs,
                        source="nmap",
                    )
            elif result.tool_name == "nuclei":
                nuclei_res = parse_nuclei_json(result.raw_output, target=target_str or "")
                if nuclei_res.success:
                    bundle = self.normalizer.normalize_nuclei_result(
                        result=nuclei_res,
                        engagement_id=state.engagement_id,
                        task_id=task_id,
                        request_id=result.request_id,
                        target=target_str,
                        evidence_refs=result.evidence_refs,
                        source="nuclei",
                    )
            elif result.tool_name == "ffuf":
                ffuf_res = parse_ffuf_json(result.raw_output, target_url=target_str or "")
                if ffuf_res.success:
                    bundle = self.normalizer.normalize_ffuf_result(
                        result=ffuf_res,
                        engagement_id=state.engagement_id,
                        task_id=task_id,
                        request_id=result.request_id,
                        target=target_str,
                        evidence_refs=result.evidence_refs,
                        source="ffuf",
                    )
            elif result.tool_name == "whatweb":
                whatweb_res = parse_whatweb_json(result.raw_output, target=target_str or "")
                if whatweb_res.success:
                    bundle = self.normalizer.normalize_whatweb_result(
                        result=whatweb_res,
                        engagement_id=state.engagement_id,
                        task_id=task_id,
                        request_id=result.request_id,
                        target=target_str,
                        evidence_refs=result.evidence_refs,
                        source="whatweb",
                    )
            elif result.tool_name == "amass":
                amass_res = parse_amass_json(result.raw_output, domain=target_str or "")
                if amass_res.success:
                    bundle = self.normalizer.normalize_amass_result(
                        result=amass_res,
                        engagement_id=state.engagement_id,
                        task_id=task_id,
                        request_id=result.request_id,
                        target=target_str,
                        evidence_refs=result.evidence_refs,
                        source="amass",
                    )

        if bundle:
            # Persist canonical bundle
            if inspect.iscoroutinefunction(self.asset_repo.save_bundle):
                await self.asset_repo.save_bundle(bundle)
            else:
                self.asset_repo.save_bundle(bundle)

            # Update state inventory references
            for asset in bundle.assets:
                identifier = asset.address or asset.hostname
                if identifier and identifier not in state.current_assets:
                    state.current_assets.append(identifier)
            for svc in bundle.services:
                svc_desc = f"{svc.port}/{svc.protocol}:{svc.service_name or 'unknown'}"
                if svc_desc not in state.current_services:
                    state.current_services.append(svc_desc)
            for tech in bundle.technologies:
                tech_desc = f"{tech.name}:{tech.version or ''}"
                if tech_desc not in state.current_technologies:
                    state.current_technologies.append(tech_desc)

            await self.audit.record_action(
                event_type=AuditEventType.EVIDENCE_RECORDED,
                actor=self.agent_id,
                action="normalize_recon_assets",
                engagement_id=state.engagement_id,
                task_id=task_id,
                parameters={
                    "tool_name": result.tool_name,
                    "assets_discovered": len(bundle.assets),
                    "services_discovered": len(bundle.services),
                    "evidence_refs_count": len(result.evidence_refs),
                },
                result_status="success",
            )

    async def analyze_tool_result(
        self,
        result: ToolResult,
        state: ReconState,
        original_action: ReconAction | None = None,
    ) -> ReconAnalysis | None:
        """Query LLM Gateway to interpret the execution outcome and extract findings."""
        if not result.success and not result.output:
            return None

        prompt = RECON_ANALYSIS_PROMPT_TEMPLATE.format(
            engagement_id=state.engagement_id,
            objectives=state.recon_objectives or ["Enumerate open ports and active services"],
            tool_name=result.tool_name,
            target=original_action.target if original_action else "",
            success=result.success,
            error=result.error or "",
            output=json.dumps(result.output),
            evidence_refs=result.evidence_refs,
        )

        messages = [
            LLMMessage(role="system", content=RECON_SYSTEM_PROMPT),
            LLMMessage(role="user", content=prompt),
        ]

        llm_req = LLMRequest(
            engagement_id=state.engagement_id,
            agent_id=self.agent_id,
            messages=messages,
            temperature=self.config.temperature,
        )

        try:
            llm_resp = await self.llm.complete(llm_req)
            cleaned = _clean_json_markdown(llm_resp.content)
            data = json.loads(cleaned)
            analysis = ReconAnalysis.model_validate(data)

            # Accumulate observations and hypotheses
            for finding in analysis.findings:
                if finding not in state.observations:
                    state.observations.append(finding)
            for hyp in analysis.hypotheses:
                if hyp not in state.hypotheses:
                    state.hypotheses.append(hyp)

            # Queue recommended actions from analysis (subject to prioritization/scope)
            for next_action in analysis.next_recommended_actions:
                state.pending_actions.append(next_action.model_dump())

            return analysis

        except (LLMGatewayError, json.JSONDecodeError, Exception) as e:
            logger.warning(f"LLM analysis skipped or malformed: {e}")
            return None

    async def step(self, state: ReconState) -> ReconState:
        """Execute a single bounded step of the reconnaissance orchestration loop."""
        state.updated_at = utc_now().isoformat()

        # Check safety limits
        if state.iteration >= self.config.max_iterations:
            state.status = "completed"
            state.termination_reason = ReconTerminationReason.MAX_ITERATIONS_REACHED
            return state

        if state.action_count >= self.config.max_actions:
            state.status = "completed"
            state.termination_reason = ReconTerminationReason.MAX_ACTIONS_REACHED
            return state

        if state.consecutive_failures >= self.config.max_consecutive_failures:
            state.status = "failed"
            state.termination_reason = ReconTerminationReason.REPEATED_FAILURES
            return state

        state.iteration += 1

        # 1. If no pending actions, request reconnaissance plan
        if not state.pending_actions:
            plan = await self.plan_reconnaissance(state)
            if not plan or not plan.candidate_actions:
                state.status = "completed"
                state.termination_reason = (
                    ReconTerminationReason.OBJECTIVES_SATISFIED
                    if plan and plan.stop_condition
                    else ReconTerminationReason.NO_USEFUL_NEXT_ACTION
                )
                return state

            for act in plan.candidate_actions:
                state.pending_actions.append(act.model_dump())

        # 2. Prioritize next action
        action = self.prioritize_next_action(state)
        if not action:
            state.status = "completed"
            state.termination_reason = ReconTerminationReason.NO_USEFUL_NEXT_ACTION
            return state

        fp = action.fingerprint()
        state.executed_fingerprints[fp] = state.executed_fingerprints.get(fp, 0) + 1
        state.action_count += 1
        current_task_id = new_id()

        # 3. Submit candidate action through authoritative security pipeline
        tool_result, is_authorized = await self.submit_candidate_action(
            action, state, task_id=current_task_id
        )

        state.completed_actions.append(
            {
                "tool_name": action.tool_name,
                "target": action.target,
                "operation": action.operation,
                "arguments": action.arguments,
                "fingerprint": fp,
                "authorized": is_authorized,
                "success": tool_result.success,
            }
        )

        # 4. If execution succeeded or generated output, process and analyze
        if is_authorized:
            await self.process_tool_result(
                tool_result, state, original_action=action, task_id=current_task_id
            )
            analysis = await self.analyze_tool_result(tool_result, state, original_action=action)
            if analysis and analysis.should_stop:
                state.status = "completed"
                state.termination_reason = (
                    analysis.stop_reason or ReconTerminationReason.OBJECTIVES_SATISFIED
                )
                return state

        return state

    async def run(self, initial_state: ReconState) -> ReconState:
        """Run the reconnaissance agent loop until a termination condition is reached."""
        state = initial_state
        state.status = "running"

        while state.status == "running":
            state = await self.step(state)

        logger.info(
            f"ReconAgent terminated for engagement {state.engagement_id}. "
            f"Status: {state.status}, Reason: {state.termination_reason}, "
            f"Iterations: {state.iteration}, Actions: {state.action_count}"
        )
        return state
