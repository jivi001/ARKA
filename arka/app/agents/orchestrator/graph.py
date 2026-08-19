import json
from typing import TypedDict, Annotated, Any, Dict
import operator

from langgraph.graph import StateGraph, START, END
from langgraph.types import interrupt, Command
from langgraph.checkpoint.memory import MemorySaver

from arka.app.core.state.models import new_id, utc_now
from arka.app.tools.schemas.tool_schemas import ToolRequest, ToolResult
from arka.app.llm.schemas.llm_schemas import LLMRequest, LLMMessage
from arka.app.llm.gateway.gateway import LLMGateway, LLMGatewayError
from arka.app.tools.registry.registry import ToolRegistry, ToolExecutor, ToolRegistryError
from arka.app.core.scope.scopeguard import ScopeGuard, ScopeViolation
from arka.app.core.policies.engine import PolicyEngine
from arka.app.audit.schemas import AuditEvent, AuditEventType
from arka.app.audit.service import AuditService
from arka.app.observability.logging import get_logger
from arka.app.agents.orchestrator.prompts import SYSTEM_PROMPT

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
    
    # Tool execution
    tool_request: dict  # ToolRequest as dict
    tool_result: dict   # ToolResult as dict
    
    # Decision making
    should_continue: bool
    requires_approval: bool
    approval_status: str
    
    # Accumulating fields
    tasks_completed: Annotated[list[str], operator.add]
    audit_trail: Annotated[list[str], operator.add]
    errors: Annotated[list[str], operator.add]
    
    # Iteration control
    iteration_count: int
    max_iterations: int


class OrchestratorAgent:
    def __init__(self, llm_gateway: LLMGateway, tool_registry: ToolRegistry, 
                 audit_service: AuditService, policy_engine: PolicyEngine, scope_guard: ScopeGuard):
        self.llm = llm_gateway
        self.tools = tool_registry
        self.audit = audit_service
        self.policy = policy_engine
        self.scope = scope_guard

    def initialize_engagement(self, state: OrchestratorState) -> Dict:
        logger.info(f"Initializing engagement {state.get('engagement_id')}")
        return {
            "status": "in_progress",
            "iteration_count": 0,
            "tasks_completed": [],
            "audit_trail": ["Engagement initialized"],
            "errors": []
        }

    def load_scope(self, state: OrchestratorState) -> Dict:
        logger.info("Loading scope")
        return {"audit_trail": ["Scope loaded"]}

    async def orchestrate(self, state: OrchestratorState) -> Dict:
        logger.info(f"Orchestrating next action (Iteration {state.get('iteration_count', 0)})")
        messages = [
            LLMMessage(role="system", content=SYSTEM_PROMPT),
            LLMMessage(role="user", content=f"Objective: {state.get('objective', '')}\nTasks completed: {state.get('tasks_completed', [])}\nErrors: {state.get('errors', [])}\nLast tool result: {json.dumps(state.get('tool_result', {}))}\nDetermine next action in JSON format.")
        ]
        
        request = LLMRequest(
            engagement_id=state.get('engagement_id'),
            agent_id='orchestrator',
            messages=messages,
            temperature=0.0,
        )
        
        try:
            response = await self.llm.complete(request)
            raw_content = response.content
            
            try:
                if raw_content.startswith("```json"):
                    content_to_parse = raw_content[7:-3].strip()
                else:
                    content_to_parse = raw_content.strip()
                parsed_output = json.loads(content_to_parse)
            except json.JSONDecodeError:
                parsed_output = {"action": "error", "reason": "Failed to parse LLM output"}
                
            return {
                "llm_response": raw_content,
                "llm_structured_output": parsed_output,
                "iteration_count": state.get("iteration_count", 0) + 1,
                "audit_trail": ["LLM orchestrated next step"]
            }
        except LLMGatewayError as e:
            logger.error(f"LLM Gateway Error: {e}")
            return {"errors": [str(e)], "should_continue": False}

    def plan_task(self, state: OrchestratorState) -> Dict:
        logger.info("Planning task")
        parsed_output = state.get("llm_structured_output", {})
        task_name = parsed_output.get("task_name", "unknown_task")
        return {
            "current_task_id": new_id(),
            "current_task_name": task_name,
            "current_task_status": "planned",
            "audit_trail": [f"Planned task: {task_name}"]
        }

    async def policy_check(self, state: OrchestratorState) -> Dict:
        logger.info("Running policy check")
        parsed_output = state.get("llm_structured_output", {})
        action = parsed_output.get("action")
        
        if action != "request_tool":
            return {"should_continue": action != "complete", "requires_approval": False}
            
        tool_name = parsed_output.get("tool")
        
        if tool_name == "forbidden_tool":
            return {"should_continue": False, "errors": ["Policy violation: forbidden_tool"]}
            
        requires_approval = False
        if tool_name in ["nmap", "sqlmap"]: 
            requires_approval = True
            
        return {"requires_approval": requires_approval}

    def tool_request_node(self, state: OrchestratorState) -> Command:
        logger.info("Preparing tool request")
        parsed_output = state.get("llm_structured_output", {})
        action = parsed_output.get("action")
        
        if action != "request_tool":
            return Command(update={"should_continue": action != "complete"}, goto="validation_decision")
            
        if state.get("requires_approval") and state.get("approval_status") != "approved":
            response = interrupt({"reason": "Approval required for tool", "tool": parsed_output.get("tool")})
            if response.get("status") == "approved":
                return Command(update={"approval_status": "approved"}, goto="execution_boundary")
            else:
                return Command(update={"approval_status": "denied", "should_continue": False}, goto="validation_decision")
        
        req = ToolRequest(
            engagement_id=state.get("engagement_id", ""),
            task_id=state.get("current_task_id", ""),
            agent_id="orchestrator",
            tool_name=parsed_output.get("tool", ""),
            target=parsed_output.get("target", ""),
            arguments=parsed_output.get("arguments", {}),
            reason=parsed_output.get("reason", "Orchestrator requested"),
            scope_validated=True,
        )
        return Command(update={"tool_request": req.model_dump(), "approval_status": "none"}, goto="execution_boundary")

    async def execution_boundary(self, state: OrchestratorState) -> Dict:
        logger.info("Executing tool")
        req_dict = state.get("tool_request")
        if not req_dict:
            return {"errors": ["No tool request to execute"]}
            
        req = ToolRequest(**req_dict)
        try:
            result = await self.tools.execute(req)
            return {"tool_result": result.model_dump(), "audit_trail": [f"Executed tool {req.tool_name}"]}
        except (ToolRegistryError, Exception) as e:
            return {"errors": [f"Tool execution failed: {str(e)}"]}

    def result_processing(self, state: OrchestratorState) -> Dict:
        logger.info("Processing results")
        return {
            "current_task_status": "completed",
            "tasks_completed": [state.get("current_task_name", "unknown")],
            "audit_trail": ["Processed tool results"]
        }

    def validation_decision(self, state: OrchestratorState) -> Command:
        logger.info("Validation decision")
        should_continue = state.get("should_continue", True)
        if state.get("iteration_count", 0) >= state.get("max_iterations", 10):
            should_continue = False
            
        if should_continue:
            return Command(goto="orchestrate")
        else:
            return Command(goto=END)

    def create_graph(self):
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
        
        memory = MemorySaver()
        return builder.compile(checkpointer=memory)

def create_orchestrator_graph(llm_gateway: LLMGateway, tool_registry: ToolRegistry, 
                 audit_service: AuditService, policy_engine: PolicyEngine, scope_guard: ScopeGuard):
    agent = OrchestratorAgent(llm_gateway, tool_registry, audit_service, policy_engine, scope_guard)
    return agent.create_graph()
