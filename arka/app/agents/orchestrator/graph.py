"""ARKA Orchestrator Agent and LangGraph workflow.

The Orchestrator coordinates LLM reasoning, candidate action extraction,
and response processing, but has ZERO authorization authority.
All actions must pass through ScopeGuard, PolicyEngine, ApprovalManager,
and ToolRegistry before execution.
"""

import contextlib
import json
import operator
from typing import Annotated, Any, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from arka.app.agents.orchestrator.prompts import SYSTEM_PROMPT
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import (
    PolicyDecision,
    PolicyDecisionType,
    new_id,
)
from arka.app.llm.gateway.gateway import LLMGateway, LLMGatewayError
from arka.app.llm.schemas.llm_schemas import LLMMessage, LLMRequest
from arka.app.observability.logging import get_logger
from arka.app.tools.registry.registry import ToolRegistry, ToolRegistryError
from arka.app.tools.schemas.tool_schemas import (
    CandidateToolRequest,
    ToolRequest,
)

logger = get_logger(__name__)


class OrchestratorState(TypedDict):
    # Engagement info
    engagement_id: str
    engagement_name: str
    objective: str
    status: str

    # Scope
    scope: dict  # ScopeDefinition as dict

    # Current task
    current_task_id: str
    current_task_name: str
    current_task_status: str

    # LLM interaction
    llm_response: str
    llm_structured_output: dict

    # Tool execution pipeline
    candidate_tool_request: dict | None  # CandidateToolRequest as dict
    policy_decision: dict | None  # PolicyDecision as dict
    tool_request: dict | None  # Authoritative ToolRequest as dict
    tool_result: dict | None  # ToolResult as dict

    # Approval and decision making
    should_continue: bool
    requires_approval: bool
    approval_id: str | None
    approval_status: str

    # Accumulating fields
    tasks_completed: Annotated[list[str], operator.add]
    audit_trail: Annotated[list[str], operator.add]
    errors: Annotated[list[str], operator.add]

    # Iteration control
    iteration_count: int
    max_iterations: int


class OrchestratorAgent:
    """Agent that orchestrates penetration-testing tasks through LangGraph.

    Enforces strict security boundary: LLM proposes actions, but authorization
    is determined solely by ScopeGuard and PolicyEngine.
    """

    def __init__(
        self,
        llm_gateway: LLMGateway,
        tool_registry: ToolRegistry,
        audit_service: AuditService,
        policy_engine: PolicyEngine,
        scope_guard: ScopeGuard,
        approval_manager: ApprovalManager | None = None,
    ):
        self.llm = llm_gateway
        self.tools = tool_registry
        self.audit = audit_service
        self.policy = policy_engine
        self.scope = scope_guard
        self.approvals = approval_manager or ApprovalManager()
        self.tools.set_approval_manager(self.approvals)

    def initialize_engagement(self, state: OrchestratorState) -> dict:
        logger.info(f"Initializing engagement {state.get('engagement_id')}")
        return {
            "status": "in_progress",
            "iteration_count": 0,
            "tasks_completed": [],
            "audit_trail": ["Engagement initialized"],
            "errors": [],
            "should_continue": True,
            "requires_approval": False,
            "approval_status": "none",
        }

    def load_scope(self, state: OrchestratorState) -> dict:
        logger.info("Loading scope into orchestrator context")
        return {"audit_trail": ["Scope loaded"]}

    async def orchestrate(self, state: OrchestratorState) -> dict:
        logger.info(f"Orchestrating next action (Iteration {state.get('iteration_count', 0)})")
        messages = [
            LLMMessage(role="system", content=SYSTEM_PROMPT),
            LLMMessage(
                role="user",
                content=(
                    f"Objective: {state.get('objective', '')}\n"
                    f"Tasks completed: {state.get('tasks_completed', [])}\n"
                    f"Errors: {state.get('errors', [])}\n"
                    f"Last tool result: {json.dumps(state.get('tool_result', {}))}\n"
                    f"Determine next action in JSON format."
                ),
            ),
        ]

        request = LLMRequest(
            engagement_id=state.get("engagement_id"),
            agent_id="orchestrator",
            messages=messages,
            temperature=0.0,
        )

        try:
            response = await self.llm.complete(request)
            raw_content = response.content

            try:
                if raw_content.startswith("```json"):
                    content_to_parse = raw_content[7:-3].strip()
                elif raw_content.startswith("```"):
                    content_to_parse = raw_content[3:-3].strip()
                else:
                    content_to_parse = raw_content.strip()
                parsed_output = json.loads(content_to_parse)
            except json.JSONDecodeError:
                parsed_output = {
                    "action": "error",
                    "reason": "Failed to parse LLM output as JSON",
                }

            # Build candidate tool request if LLM requested a tool
            candidate_dict = None
            if parsed_output.get("action") == "request_tool":
                candidate = CandidateToolRequest(
                    tool_name=parsed_output.get("tool", ""),
                    target=parsed_output.get("target", ""),
                    arguments=parsed_output.get("arguments", {}),
                    reason=parsed_output.get("reason", "Orchestrator requested action"),
                )
                candidate_dict = candidate.model_dump()

            return {
                "llm_response": raw_content,
                "llm_structured_output": parsed_output,
                "candidate_tool_request": candidate_dict,
                "iteration_count": state.get("iteration_count", 0) + 1,
                "audit_trail": ["LLM orchestrated next step"],
            }
        except LLMGatewayError as e:
            logger.error(f"LLM Gateway Error: {e}")
            return {"errors": [str(e)], "should_continue": False}

    def plan_task(self, state: OrchestratorState) -> dict:
        logger.info("Planning task")
        parsed_output = state.get("llm_structured_output", {})
        task_name = parsed_output.get("task_name", "orchestrator_step")
        current_id = state.get("current_task_id") or new_id()
        return {
            "current_task_id": current_id,
            "current_task_name": task_name,
            "current_task_status": "planned",
            "audit_trail": [f"Planned task: {task_name}"],
        }

    async def policy_check(self, state: OrchestratorState) -> dict:
        """Evaluate candidate action against PolicyEngine and ScopeGuard.

        The Orchestrator contains NO independent authorization rules.
        """
        logger.info("Running deterministic policy check")
        candidate_dict = state.get("candidate_tool_request")
        if not candidate_dict:
            action = (state.get("llm_structured_output") or {}).get("action")
            return {
                "should_continue": action != "complete" and action != "error",
                "requires_approval": False,
                "policy_decision": None,
            }

        candidate = CandidateToolRequest(**candidate_dict)
        tool_def = self.tools.get_tool(candidate.tool_name)

        if not tool_def:
            err_msg = f"Unknown tool: '{candidate.tool_name}'"
            logger.warning(err_msg)
            return {
                "should_continue": False,
                "requires_approval": False,
                "errors": [err_msg],
                "policy_decision": None,
            }

        decision = self.policy.evaluate(
            candidate,
            tool_def,
            engagement_id=state.get("engagement_id", ""),
            task_id=state.get("current_task_id", ""),
            agent_id="orchestrator",
        )

        requires_approval = decision.decision == PolicyDecisionType.REQUIRE_APPROVAL
        should_continue = decision.decision != PolicyDecisionType.DENY

        return {
            "policy_decision": decision.model_dump(),
            "requires_approval": requires_approval,
            "should_continue": should_continue,
            "errors": [decision.reason] if decision.decision == PolicyDecisionType.DENY else [],
        }

    def tool_request_node(self, state: OrchestratorState) -> Command:
        """Handle approval interruption gate and authoritative ToolRequest construction."""
        logger.info("Evaluating tool request node")
        candidate_dict = state.get("candidate_tool_request")
        if not candidate_dict:
            action = (state.get("llm_structured_output") or {}).get("action")
            return Command(
                update={"should_continue": action != "complete"},
                goto="validation_decision",
            )

        candidate = CandidateToolRequest(**candidate_dict)
        decision_dict = state.get("policy_decision")
        if not decision_dict:
            return Command(
                update={"should_continue": False, "errors": ["No policy decision"]},
                goto="validation_decision",
            )

        decision = PolicyDecision(**decision_dict)

        # Policy DENY
        if decision.decision == PolicyDecisionType.DENY:
            return Command(
                update={"should_continue": False, "errors": [f"Policy denied: {decision.reason}"]},
                goto="validation_decision",
            )

        # Approval gate
        approval_id = state.get("approval_id")
        if decision.decision == PolicyDecisionType.REQUIRE_APPROVAL:
            # Check if existing approval is already valid and GRANTED
            is_valid = self.approvals.validate_approval_for_request(
                approval_id=approval_id,
                engagement_id=state.get("engagement_id", ""),
                task_id=state.get("current_task_id", ""),
                tool_name=candidate.tool_name,
                target=candidate.target,
            )

            if not is_valid:
                # Check if there is already an active approval for this exact operation
                existing_req = self.approvals.find_matching_request(
                    engagement_id=state.get("engagement_id", ""),
                    task_id=state.get("current_task_id", ""),
                    tool_name=candidate.tool_name,
                    target=candidate.target,
                )

                if existing_req:
                    app_req = existing_req
                else:
                    # Create persistent approval request in REQUIRED state
                    app_req = self.approvals.create_request(
                        engagement_id=state.get("engagement_id", ""),
                        task_id=state.get("current_task_id", ""),
                        agent_id="orchestrator",
                        action=f"execute_tool:{candidate.tool_name}",
                        target=candidate.target,
                        tool_name=candidate.tool_name,
                        risk_level=decision.risk_level,
                        reason=candidate.reason,
                        details={"arguments": candidate.arguments},
                    )
                approval_id = app_req.approval_id

                # Trigger human-in-the-loop interrupt
                interrupt_response = interrupt(
                    {
                        "approval_id": approval_id,
                        "reason": decision.reason,
                        "tool": candidate.tool_name,
                        "target": candidate.target,
                        "risk_level": decision.risk_level.value,
                    }
                )

                # Handle resume response
                if (
                    isinstance(interrupt_response, dict)
                    and interrupt_response.get("status") == "approved"
                ):
                    # Mark approved in manager if decided externally
                    with contextlib.suppress(ValueError):
                        self.approvals.approve(
                            approval_id, interrupt_response.get("approved_by", "human_operator")
                        )

                # Revalidate approval after interrupt
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
                                f"Operation '{candidate.tool_name}' on "
                                f"'{candidate.target}' not approved."
                            ],
                        },
                        goto="validation_decision",
                    )

        # Build authoritative ToolRequest with trusted validation booleans
        auth_req, _pol_dec, err = self.tools.validate_candidate_request(
            candidate=candidate,
            engagement_id=state.get("engagement_id", ""),
            task_id=state.get("current_task_id", ""),
            agent_id="orchestrator",
            approval_id=approval_id,
        )

        if not auth_req:
            return Command(
                update={
                    "should_continue": False,
                    "errors": [err or "Failed to validate tool request"],
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

    async def execution_boundary(self, state: OrchestratorState) -> dict:
        """Execute authoritative ToolRequest through ToolRegistry."""
        logger.info("Executing tool through security boundary")
        req_dict = state.get("tool_request")
        if not req_dict:
            return {"errors": ["No validated tool request to execute"]}

        req = ToolRequest(**req_dict)
        try:
            result = await self.tools.execute(req)
            return {
                "tool_result": result.model_dump(),
                "audit_trail": [f"Executed tool {req.tool_name} (success={result.success})"],
                "errors": [result.error] if not result.success and result.error else [],
            }
        except (ToolRegistryError, Exception) as e:
            return {"errors": [f"Tool execution failed: {e!s}"]}

    def result_processing(self, state: OrchestratorState) -> dict:
        logger.info("Processing execution results")
        return {
            "current_task_status": "completed",
            "tasks_completed": [state.get("current_task_name", "unknown")],
            "audit_trail": ["Processed tool results"],
        }

    def validation_decision(self, state: OrchestratorState) -> Command:
        logger.info("Evaluating validation decision")
        should_continue = state.get("should_continue", True)
        if state.get("iteration_count", 0) >= state.get("max_iterations", 10):
            should_continue = False

        if should_continue:
            return Command(goto="orchestrate")
        else:
            return Command(goto=END)

    def create_graph(self, checkpointer: Any = None):
        """Compile and return the LangGraph state graph with checkpointer."""
        builder = StateGraph(OrchestratorState)

        builder.add_node("initialize_engagement", self.initialize_engagement)
        builder.add_node("load_scope", self.load_scope)
        builder.add_node("orchestrate", self.orchestrate)
        builder.add_node("plan_task", self.plan_task)
        builder.add_node("policy_check", self.policy_check)
        builder.add_node("tool_request", self.tool_request_node)
        builder.add_node("execution_boundary", self.execution_boundary)
        builder.add_node("result_processing", self.result_processing)
        builder.add_node("validation_decision", self.validation_decision)

        builder.add_edge(START, "initialize_engagement")
        builder.add_edge("initialize_engagement", "load_scope")
        builder.add_edge("load_scope", "orchestrate")
        builder.add_edge("orchestrate", "plan_task")
        builder.add_edge("plan_task", "policy_check")
        builder.add_edge("policy_check", "tool_request")
        builder.add_edge("execution_boundary", "result_processing")
        builder.add_edge("result_processing", "validation_decision")

        # Default to memory checkpointer if none specified
        if checkpointer is None:
            checkpointer = MemorySaver()

        return builder.compile(checkpointer=checkpointer)


def create_orchestrator_graph(
    llm_gateway: LLMGateway,
    tool_registry: ToolRegistry,
    audit_service: AuditService,
    policy_engine: PolicyEngine,
    scope_guard: ScopeGuard,
    approval_manager: ApprovalManager | None = None,
    checkpointer: Any = None,
):
    agent = OrchestratorAgent(
        llm_gateway=llm_gateway,
        tool_registry=tool_registry,
        audit_service=audit_service,
        policy_engine=policy_engine,
        scope_guard=scope_guard,
        approval_manager=approval_manager,
    )
    return agent.create_graph(checkpointer=checkpointer)
