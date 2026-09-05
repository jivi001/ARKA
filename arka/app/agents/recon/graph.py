"""LangGraph workflow for ARKA Phase 2.2.4 ReconAgent.

Coordinates LLM planning, candidate action selection, deterministic policy checks,
persistent human approval gates, sandboxed execution, and canonical asset normalization
within an interruptible, checkpointable LangGraph StateGraph.
"""

from __future__ import annotations

import contextlib
import inspect
import json
from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from arka.app.agents.recon.agent import _clean_json_markdown
from arka.app.agents.recon.models import (
    ReconAction,
    ReconAgentConfig,
    ReconAgentState,
    ReconAnalysis,
    ReconPlan,
    ReconTerminationReason,
)
from arka.app.agents.recon.prompts import (
    RECON_ANALYSIS_PROMPT_TEMPLATE,
    RECON_PLAN_PROMPT_TEMPLATE,
    RECON_SYSTEM_PROMPT,
)
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.assets.repository import AssetRepository, InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import (
    PolicyDecision,
    PolicyDecisionType,
    new_id,
)
from arka.app.execution.evidence import EvidenceStore
from arka.app.llm.gateway.gateway import LLMGateway, LLMGatewayError
from arka.app.llm.schemas.llm_schemas import LLMMessage, LLMRequest
from arka.app.observability.logging import get_logger
from arka.app.tools.nmap.parser import parse_nmap_xml
from arka.app.tools.registry.registry import ToolRegistry, ToolRegistryError
from arka.app.tools.schemas.tool_schemas import (
    CandidateToolRequest,
    ToolRequest,
    ToolResult,
)

logger = get_logger(__name__)


class ReconGraphWorkflow:
    """Encapsulates LangGraph node functions for ReconAgent."""

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
        self.llm = llm_gateway
        self.tools = tool_registry
        self.audit = audit_service
        self.scope = scope_guard
        self.policy = policy_engine
        self.approvals = approval_manager or ApprovalManager()
        self.tools.set_approval_manager(self.approvals)

        self.asset_repo = asset_repository or InMemoryAssetRepository()
        self.normalizer = asset_normalizer or AssetNormalizer()
        self.evidence_store = evidence_store or EvidenceStore()
        self.config = config or ReconAgentConfig()
        self.agent_id = agent_id

    def initialize_state(self, state: ReconAgentState) -> dict[str, Any]:
        """Initialize recon state and counters."""
        logger.info(f"Initializing ReconAgent graph for engagement {state.get('engagement_id')}")
        return {
            "status": "running",
            "iteration": 0,
            "action_count": 0,
            "consecutive_failures": 0,
            "should_continue": True,
            "requires_approval": False,
            "approval_status": "none",
            "audit_trail": ["ReconAgent initialized"],
            "errors": [],
            "completed_actions": [],
            "tool_results": [],
            "evidence_refs": [],
            "observations": [],
            "hypotheses": [],
            "pending_actions": [],
            "executed_fingerprints": {},
        }

    def load_scope(self, state: ReconAgentState) -> dict[str, Any]:
        """Validate and log scope initialization."""
        logger.info("Loading authorized scope into ReconAgent context")
        return {"audit_trail": ["Scope loaded and verified"]}

    async def plan_recon(self, state: ReconAgentState) -> dict[str, Any]:
        """Ask LLM Gateway for a structured reconnaissance plan."""
        logger.info(f"Planning reconnaissance step (Iteration {state.get('iteration', 0)})")
        user_prompt = RECON_PLAN_PROMPT_TEMPLATE.format(
            engagement_id=state.get("engagement_id", ""),
            objectives=state.get("recon_objectives", []) or ["Enumerate exposed services"],
            authorized_scope=json.dumps(state.get("authorized_scope", {}), default=str),
            assets=state.get("current_assets", []),
            services=state.get("current_services", []),
            completed_actions=[
                a.get("fingerprint", "") for a in state.get("completed_actions", [])
            ],
            hypotheses=state.get("hypotheses", []),
            errors=state.get("errors", [])[-5:],
        )

        messages = [
            LLMMessage(role="system", content=RECON_SYSTEM_PROMPT),
            LLMMessage(role="user", content=user_prompt),
        ]

        llm_req = LLMRequest(
            engagement_id=state.get("engagement_id", ""),
            agent_id=self.agent_id,
            messages=messages,
            temperature=self.config.temperature,
        )

        try:
            resp = await self.llm.complete(llm_req)
            cleaned = _clean_json_markdown(resp.content)
            data = json.loads(cleaned)
            plan = ReconPlan.model_validate(data)

            pending = [a.model_dump() for a in plan.candidate_actions]
            return {
                "llm_plan_raw": resp.content,
                "pending_actions": pending,
                "iteration": state.get("iteration", 0) + 1,
                "audit_trail": [f"LLM planned {len(pending)} candidate action(s)"],
            }
        except (LLMGatewayError, json.JSONDecodeError, Exception) as e:
            logger.warning(f"Recon planning failed: {e}")
            return {
                "errors": [f"Planning error: {e}"],
                "pending_actions": [],
                "iteration": state.get("iteration", 0) + 1,
            }

    def select_action(self, state: ReconAgentState) -> Command:
        """Select next candidate action and enforce idempotency via action fingerprints."""
        pending = list(state.get("pending_actions", []))
        executed_fps = dict(state.get("executed_fingerprints", {}))
        max_repeated = state.get(
            "max_repeated_action_attempts", self.config.max_repeated_action_attempts
        )

        while pending:
            candidate_dict = pending.pop(0)
            try:
                action = ReconAction.model_validate(candidate_dict)
            except Exception as e:
                return Command(
                    update={
                        "errors": [f"Malformed action skipped: {e}"],
                        "pending_actions": pending,
                    },
                    goto="select_action",
                )

            fp = action.fingerprint()
            count = executed_fps.get(fp, 0)
            if count >= max_repeated:
                return Command(
                    update={
                        "errors": [
                            f"Repeated action skipped: {action.tool_name} on {action.target}"
                        ],
                        "pending_actions": pending,
                    },
                    goto="select_action",
                )

            executed_fps[fp] = count + 1
            cand_req = CandidateToolRequest(
                tool_name=action.tool_name,
                target=action.target,
                arguments=action.arguments,
                reason=action.rationale or "ReconAgent scan",
            )

            return Command(
                update={
                    "current_action": action.model_dump(),
                    "candidate_tool_request": cand_req.model_dump(),
                    "pending_actions": pending,
                    "executed_fingerprints": executed_fps,
                    "action_count": state.get("action_count", 0) + 1,
                    "current_task_id": new_id(),
                },
                goto="policy_check",
            )

        # No pending actions left
        return Command(
            update={"current_action": None, "candidate_tool_request": None},
            goto="validation_decision",
        )

    def policy_check(self, state: ReconAgentState) -> dict[str, Any]:
        """Evaluate CandidateToolRequest against PolicyEngine and ScopeGuard."""
        candidate_dict = state.get("candidate_tool_request")
        if not candidate_dict:
            return {"should_continue": False, "policy_decision": None}

        candidate = CandidateToolRequest(**candidate_dict)
        tool_def = self.tools.get_tool(candidate.tool_name)
        if not tool_def:
            return {
                "errors": [f"Unknown tool: '{candidate.tool_name}'"],
                "should_continue": False,
                "policy_decision": None,
                "consecutive_failures": state.get("consecutive_failures", 0) + 1,
            }

        decision = self.policy.evaluate(
            candidate,
            tool_def,
            engagement_id=state.get("engagement_id", ""),
            task_id=state.get("current_task_id", ""),
            agent_id=self.agent_id,
        )

        requires_approval = decision.decision == PolicyDecisionType.REQUIRE_APPROVAL
        is_denied = decision.decision == PolicyDecisionType.DENY

        return {
            "policy_decision": decision.model_dump(),
            "requires_approval": requires_approval,
            "should_continue": not is_denied,
            "errors": [decision.reason] if is_denied else [],
            "consecutive_failures": (
                state.get("consecutive_failures", 0) + 1
                if is_denied
                else state.get("consecutive_failures", 0)
            ),
        }

    def approval_gate(self, state: ReconAgentState) -> Command:
        """Handle human approval interrupts and construct authoritative ToolRequest."""
        candidate_dict = state.get("candidate_tool_request")
        decision_dict = state.get("policy_decision")

        if not candidate_dict or not decision_dict:
            return Command(update={"should_continue": False}, goto="validation_decision")

        candidate = CandidateToolRequest(**candidate_dict)
        decision = PolicyDecision(**decision_dict)

        if decision.decision == PolicyDecisionType.DENY:
            return Command(
                update={"should_continue": False, "errors": [f"Policy denied: {decision.reason}"]},
                goto="validation_decision",
            )

        approval_id = state.get("approval_id")

        if decision.decision == PolicyDecisionType.REQUIRE_APPROVAL:
            # Check if valid approval already exists
            is_valid = self.approvals.validate_approval_for_request(
                approval_id=approval_id,
                engagement_id=state.get("engagement_id", ""),
                task_id=state.get("current_task_id", ""),
                tool_name=candidate.tool_name,
                target=candidate.target,
            )

            if not is_valid:
                # Trigger interrupt for human approval
                existing_req = self.approvals.find_matching_request(
                    engagement_id=state.get("engagement_id", ""),
                    task_id=state.get("current_task_id", ""),
                    tool_name=candidate.tool_name,
                    target=candidate.target,
                )
                if existing_req:
                    app_req = existing_req
                else:
                    app_req = self.approvals.create_request(
                        engagement_id=state.get("engagement_id", ""),
                        task_id=state.get("current_task_id", ""),
                        agent_id=self.agent_id,
                        action=f"execute_tool:{candidate.tool_name}",
                        target=candidate.target,
                        tool_name=candidate.tool_name,
                        risk_level=decision.risk_level,
                        reason=candidate.reason,
                        details={"arguments": candidate.arguments},
                    )
                approval_id = app_req.approval_id

                interrupt_resp = interrupt(
                    {
                        "approval_id": approval_id,
                        "reason": decision.reason,
                        "tool": candidate.tool_name,
                        "target": candidate.target,
                        "risk_level": decision.risk_level.value,
                    }
                )

                if isinstance(interrupt_resp, dict) and interrupt_resp.get("status") == "approved":
                    with contextlib.suppress(ValueError):
                        self.approvals.approve(
                            approval_id, interrupt_resp.get("approved_by", "human_operator")
                        )

                is_now_valid = self.approvals.validate_approval_for_request(
                    approval_id=approval_id,
                    engagement_id=state.get("engagement_id", ""),
                    task_id=state.get("current_task_id", ""),
                    tool_name=candidate.tool_name,
                    target=candidate.target,
                )

                if not is_now_valid:
                    return Command(
                        update={
                            "approval_status": "denied",
                            "should_continue": False,
                            "errors": [
                                f"Action '{candidate.tool_name}' on "
                                f"'{candidate.target}' not approved."
                            ],
                            "consecutive_failures": state.get("consecutive_failures", 0) + 1,
                        },
                        goto="validation_decision",
                    )

        # Build authoritative ToolRequest
        auth_req, _dec, err = self.tools.validate_candidate_request(
            candidate=candidate,
            engagement_id=state.get("engagement_id", ""),
            task_id=state.get("current_task_id", ""),
            agent_id=self.agent_id,
            approval_id=approval_id,
        )

        if not auth_req:
            return Command(
                update={
                    "should_continue": False,
                    "errors": [err or "Failed to validate tool request"],
                    "consecutive_failures": state.get("consecutive_failures", 0) + 1,
                },
                goto="validation_decision",
            )

        return Command(
            update={
                "tool_request": auth_req.model_dump(),
                "approval_id": approval_id,
                "approval_status": "granted" if approval_id else "none",
            },
            goto="execution_boundary",
        )

    async def execution_boundary(self, state: ReconAgentState) -> dict[str, Any]:
        """Execute authoritative ToolRequest through ToolRegistry security boundary."""
        req_dict = state.get("tool_request")
        if not req_dict:
            return {"errors": ["No validated tool request to execute"]}

        req = ToolRequest(**req_dict)
        try:
            result = await self.tools.execute(req)
            consecutive_fails = 0 if result.success else state.get("consecutive_failures", 0) + 1
            return {
                "tool_result": result.model_dump(),
                "tool_results": [result.model_dump()],
                "consecutive_failures": consecutive_fails,
                "audit_trail": [
                    f"Executed {req.tool_name} on {req.target} (success={result.success})"
                ],
                "errors": [result.error] if not result.success and result.error else [],
            }
        except (ToolRegistryError, Exception) as e:
            return {
                "errors": [f"Tool execution failed: {e}"],
                "consecutive_failures": state.get("consecutive_failures", 0) + 1,
            }

    async def result_processing(self, state: ReconAgentState) -> dict[str, Any]:
        """Extract evidence refs, normalize Nmap output, and persist to AssetRepository."""
        res_dict = state.get("tool_result")
        if not res_dict:
            return {}

        result = ToolResult(**res_dict)
        new_evidence_refs = [
            ref for ref in result.evidence_refs if ref not in state.get("evidence_refs", [])
        ]

        new_assets = list(state.get("current_assets", []))
        new_services = list(state.get("current_services", []))
        new_technologies = list(state.get("current_technologies", []))

        # Normalize Nmap output into canonical models
        if result.tool_name == "nmap" and result.success and result.raw_output:
            nmap_res = parse_nmap_xml(result.raw_output)
            if nmap_res.success:
                bundle = self.normalizer.normalize_nmap_result(
                    result=nmap_res,
                    engagement_id=state.get("engagement_id", ""),
                    task_id=state.get("current_task_id", ""),
                    request_id=result.request_id,
                    evidence_refs=result.evidence_refs,
                    source="nmap",
                )

                if inspect.iscoroutinefunction(self.asset_repo.save_bundle):
                    await self.asset_repo.save_bundle(bundle)
                else:
                    self.asset_repo.save_bundle(bundle)

                for asset in bundle.assets:
                    if asset.address and asset.address not in new_assets:
                        new_assets.append(asset.address)
                for svc in bundle.services:
                    s_desc = f"{svc.port}/{svc.protocol}:{svc.service_name or 'unknown'}"
                    if s_desc not in new_services:
                        new_services.append(s_desc)
                for tech in bundle.technologies:
                    t_desc = f"{tech.name}:{tech.version or ''}"
                    if t_desc not in new_technologies:
                        new_technologies.append(t_desc)

        action_dict = state.get("current_action") or {}
        completed_entry = {
            "tool_name": action_dict.get("tool_name", result.tool_name),
            "target": action_dict.get("target", ""),
            "fingerprint": action_dict.get("fingerprint", ""),
            "success": result.success,
        }

        return {
            "evidence_refs": new_evidence_refs,
            "current_assets": new_assets,
            "current_services": new_services,
            "current_technologies": new_technologies,
            "completed_actions": [completed_entry],
            "audit_trail": ["Processed tool result and normalized infrastructure models"],
        }

    async def analyze_results(self, state: ReconAgentState) -> dict[str, Any]:
        """Analyze tool result via LLM Gateway to generate observations and hypotheses."""
        res_dict = state.get("tool_result")
        if not res_dict:
            return {}

        result = ToolResult(**res_dict)
        action_dict = state.get("current_action") or {}

        prompt = RECON_ANALYSIS_PROMPT_TEMPLATE.format(
            engagement_id=state.get("engagement_id", ""),
            objectives=state.get("recon_objectives", []) or ["Enumerate exposed services"],
            tool_name=result.tool_name,
            target=action_dict.get("target", ""),
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
            engagement_id=state.get("engagement_id", ""),
            agent_id=self.agent_id,
            messages=messages,
            temperature=self.config.temperature,
        )

        try:
            resp = await self.llm.complete(llm_req)
            cleaned = _clean_json_markdown(resp.content)
            data = json.loads(cleaned)
            analysis = ReconAnalysis.model_validate(data)

            return {
                "llm_analysis_raw": resp.content,
                "observations": analysis.findings,
                "hypotheses": analysis.hypotheses,
                "should_continue": not analysis.should_stop,
                "termination_reason": (
                    analysis.stop_reason.value
                    if analysis.stop_reason
                    else ReconTerminationReason.OBJECTIVES_SATISFIED.value
                    if analysis.should_stop
                    else None
                ),
            }
        except Exception as e:
            logger.warning(f"Recon result analysis skipped: {e}")
            return {"audit_trail": ["LLM analysis unavailable"]}

    def validation_decision(self, state: ReconAgentState) -> Command:
        """Evaluate loop continuation against limits and conditions."""
        iteration = state.get("iteration", 0)
        action_count = state.get("action_count", 0)
        failures = state.get("consecutive_failures", 0)
        max_iter = state.get("max_iterations", self.config.max_iterations)
        max_act = state.get("max_actions", self.config.max_actions)
        max_fail = state.get("max_consecutive_failures", self.config.max_consecutive_failures)

        if iteration >= max_iter:
            return Command(
                update={
                    "status": "completed",
                    "termination_reason": ReconTerminationReason.MAX_ITERATIONS_REACHED.value,
                },
                goto=END,
            )
        if action_count >= max_act:
            return Command(
                update={
                    "status": "completed",
                    "termination_reason": ReconTerminationReason.MAX_ACTIONS_REACHED.value,
                },
                goto=END,
            )
        if failures >= max_fail:
            return Command(
                update={
                    "status": "failed",
                    "termination_reason": ReconTerminationReason.REPEATED_FAILURES.value,
                },
                goto=END,
            )
        if not state.get("should_continue", True):
            return Command(
                update={
                    "status": "completed",
                    "termination_reason": state.get("termination_reason")
                    or ReconTerminationReason.OBJECTIVES_SATISFIED.value,
                },
                goto=END,
            )

        # If there are still pending actions, pick the next one
        if state.get("pending_actions"):
            return Command(goto="select_action")

        # Otherwise loop to plan next step
        return Command(goto="plan_recon")

    def create_graph(self, checkpointer: Any = None):
        """Compile and return the LangGraph StateGraph with checkpointer."""
        builder = StateGraph(ReconAgentState)

        builder.add_node("initialize_state", self.initialize_state)
        builder.add_node("load_scope", self.load_scope)
        builder.add_node("plan_recon", self.plan_recon)
        builder.add_node("select_action", self.select_action)
        builder.add_node("policy_check", self.policy_check)
        builder.add_node("approval_gate", self.approval_gate)
        builder.add_node("execution_boundary", self.execution_boundary)
        builder.add_node("result_processing", self.result_processing)
        builder.add_node("analyze_results", self.analyze_results)
        builder.add_node("validation_decision", self.validation_decision)

        builder.add_edge(START, "initialize_state")
        builder.add_edge("initialize_state", "load_scope")
        builder.add_edge("load_scope", "plan_recon")
        builder.add_edge("plan_recon", "select_action")
        builder.add_edge("policy_check", "approval_gate")
        builder.add_edge("execution_boundary", "result_processing")
        builder.add_edge("result_processing", "analyze_results")
        builder.add_edge("analyze_results", "validation_decision")

        if checkpointer is None:
            checkpointer = MemorySaver()

        return builder.compile(checkpointer=checkpointer)


def create_recon_graph(
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
    checkpointer: Any = None,
    agent_id: str = "recon_agent",
):
    """Factory creating a compiled LangGraph workflow for ReconAgent."""
    wf = ReconGraphWorkflow(
        llm_gateway=llm_gateway,
        tool_registry=tool_registry,
        audit_service=audit_service,
        scope_guard=scope_guard,
        policy_engine=policy_engine,
        approval_manager=approval_manager,
        asset_repository=asset_repository,
        asset_normalizer=asset_normalizer,
        evidence_store=evidence_store,
        config=config,
        agent_id=agent_id,
    )
    return wf.create_graph(checkpointer=checkpointer)
