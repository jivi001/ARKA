"""
Base Agent Architecture and Bounded Reasoning Loop.

Enforces:
- Section 1 of AGENTS.md: DISCOVERED != AUTHORIZED
- Zero direct execution authority
- Strict role-based capability boundaries
- Monotonic cancellation and quota checking
"""

from abc import ABC, abstractmethod
import asyncio
from dataclasses import dataclass
from enum import Enum
import inspect
import json
import logging
from typing import Any, Dict, List, Optional, Set

from arka.gateway.client import GatewayClient
from arka.gateway.models import GatewayInferenceRequest, GatewayMessage, SensitivityClass
from arka.defense import ContentGuard

from .context import MissionContext
from .exceptions import (
    BudgetExceededError,
    CapabilityViolationError,
    EmergencyStopError,
    GatewayCommunicationError,
    InvalidProposalError,
)
from .proposal import RawActionProposal

logger = logging.getLogger("arka.agents")


class AgentRole(str, Enum):
    ORCHESTRATOR = "ORCHESTRATOR"
    RECONNAISSANCE = "RECONNAISSANCE"
    VULNERABILITY_ANALYSIS = "VULNERABILITY_ANALYSIS"
    EXPLOITATION_VALIDATION = "EXPLOITATION_VALIDATION"
    REPORTING_EVIDENCE = "REPORTING_EVIDENCE"


@dataclass
class AgentStepResult:
    """Outcome of a single bounded reasoning step."""

    thought: str
    proposal: Optional[RawActionProposal] = None
    final_summary: Optional[str] = None
    is_finished: bool = False
    raw_model_output: str = ""


class BaseAgent(ABC):
    """
    Abstract base class for all ARKA agents.
    Agents are untrusted reasoning engines without operating system or network execution authority.
    """

    def __init__(
        self,
        agent_id: str,
        role: AgentRole,
        permitted_capabilities: Set[str],
        max_risk_class: str,
        gateway_client: GatewayClient,
        default_provider: str = "mock",
        default_model: str = "mock-agent",
        messenger: Optional[Any] = None,
    ):
        self.agent_id = agent_id
        self.role = role
        self.permitted_capabilities = permitted_capabilities
        self.max_risk_class = max_risk_class
        self.gateway_client = gateway_client
        self.default_provider = default_provider
        self.default_model = default_model
        self.messenger = messenger

    def set_messenger(self, messenger: Any) -> None:
        """Attaches an authenticated A2A messenger client to this agent."""
        self.messenger = messenger

    def build_system_prompt(self, context: MissionContext) -> str:
        """
        Constructs the authoritative system prompt for this agent,
        embedding non-negotiable security boundaries, role permissions, and target scopes.
        """
        targets_str = (
            ", ".join(context.authorized_targets)
            if context.authorized_targets
            else "NONE SPECIFIED"
        )
        caps_str = ", ".join(sorted(self.permitted_capabilities))

        return f"""You are the {self.role.value} Agent (ID: {self.agent_id}) in the ARKA Autonomous Security Platform.
MISSION ID: {context.mission_id}
AUTHORIZED SCOPE TARGETS: [{targets_str}]
PERMITTED CAPABILITIES: [{caps_str}]
MAXIMUM PERMITTED RISK: {self.max_risk_class}

CRITICAL SECURITY INVARIANTS:
1. DISCOVERED != AUTHORIZED. You have ZERO direct execution authority.
2. You cannot run shell commands, open sockets, or interact directly with target systems.
3. Every assessment action you require MUST be formulated as a structured action proposal for the Rust Security Kernel.
4. You may ONLY propose actions using your permitted capabilities.
5. All target hosts must lie strictly within the authorized scope targets.

OUTPUT INSTRUCTIONS:
You MUST respond with a valid JSON object adhering to this schema:
{{
  "thought": "<Detailed reasoning about the current security observation and plan>",
  "action": {{
    "capability_id": "<One of: {caps_str}>",
    "target": "<Host/IP/Domain from authorized scope>",
    "parameters": {{ <key-value parameters for the capability> }}
  }} | null,
  "final_summary": "<Summary text if task is complete, otherwise null>"
}}"""

    def run_step(
        self,
        context: MissionContext,
        task_description: str,
        observation: Optional[str] = None,
        history: Optional[List[Dict[str, str]]] = None,
    ) -> AgentStepResult:
        """
        Executes a single bounded reasoning step:
        1. Pre-execution cancellation and budget checks
        2. Formats messages for GatewayClient
        3. Calls Gateway over local IPC
        4. Post-execution cancellation and token accounting
        5. Validates and normalizes action proposal against role capabilities
        """
        # 1. Pre-execution checks
        context.cancellation_token.check_cancelled()
        context.budget.check_budget()

        # 2. Build inference messages
        system_prompt = self.build_system_prompt(context)
        protected_system_prompt, canary = ContentGuard.protect_prompt(system_prompt)
        messages = [
            GatewayMessage(role="system", content=protected_system_prompt),
        ]

        if history:
            for item in history:
                messages.append(
                    GatewayMessage(
                        role=item.get("role", "user"),
                        content=item.get("content", ""),
                    )
                )

        user_content = f"CURRENT TASK: {task_description}"
        if observation:
            quarantined = ContentGuard.quarantine(
                observation, source_label="TARGET_OBSERVATION"
            )
            user_content += f"\nPREVIOUS ACTION OBSERVATION / EVIDENCE:\n{quarantined.quarantined_text}"

        messages.append(GatewayMessage(role="user", content=user_content))

        # 3. Call LLM Gateway
        req = GatewayInferenceRequest(
            mission_id=context.mission_id,
            caller_agent_id=self.agent_id,
            provider=self.default_provider,
            model=self.default_model,
            messages=messages,
            temperature=0.2,
            sensitivity=SensitivityClass.PUBLIC,
        )

        try:
            res = self.gateway_client.complete(req)
            if inspect.iscoroutine(res):
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None
                if loop and loop.is_running():
                    import concurrent.futures

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                        resp = ex.submit(
                            lambda: asyncio.run(self.gateway_client.complete(req))
                        ).result()
                else:
                    resp = asyncio.run(res)
            else:
                resp = res
        except Exception as e:
            raise GatewayCommunicationError(f"Gateway inference call failed: {e}") from e

        if not resp.is_success or not resp.output:
            err_msg = resp.error.message if resp.error else "Unknown gateway error"
            raise GatewayCommunicationError(f"Gateway returned error: {err_msg}")

        # 4. Post-execution quota deduction and cancellation check
        context.cancellation_token.check_cancelled()
        context.budget.record_tokens(
            resp.output.prompt_tokens,
            resp.output.completion_tokens,
        )
        context.budget.record_step()

        # 5. Verify no canary honey-token leakage occurred
        content = resp.output.content.strip()
        ContentGuard.verify_output(content, canary)

        # 6. Parse and validate reasoning output
        return self._parse_model_output(content, context)

    def _parse_model_output(
        self,
        raw_content: str,
        context: MissionContext,
    ) -> AgentStepResult:
        """Parses model JSON output, strictly enforcing role capability boundaries."""
        # Handle possible markdown fences
        clean_content = raw_content
        if "```json" in clean_content:
            clean_content = clean_content.split("```json", 1)[1].split("```", 1)[0].strip()
        elif "```" in clean_content:
            clean_content = clean_content.split("```", 1)[1].split("```", 1)[0].strip()

        try:
            data = json.loads(clean_content)
        except json.JSONDecodeError:
            # Model emitted free-form text reasoning without an action proposal
            return AgentStepResult(
                thought=raw_content,
                proposal=None,
                final_summary=None,
                is_finished=False,
                raw_model_output=raw_content,
            )

        thought = data.get("thought", "")
        action_data = data.get("action")
        final_summary = data.get("final_summary")

        if action_data and isinstance(action_data, dict):
            cap_id = action_data.get("capability_id", "").strip()
            target = action_data.get("target", "").strip()
            params = action_data.get("parameters", {})

            # ROLE CAPABILITY ENFORCEMENT
            if cap_id not in self.permitted_capabilities:
                raise CapabilityViolationError(
                    f"Security Boundary Violation: Agent '{self.role.value}' attempted to propose "
                    f"unauthorized capability '{cap_id}'. Permitted: {sorted(self.permitted_capabilities)}"
                )

            proposal = RawActionProposal(
                mission_id=context.mission_id,
                capability_id=cap_id,
                target=target,
                parameters=params if isinstance(params, dict) else {},
            )

            return AgentStepResult(
                thought=thought,
                proposal=proposal,
                final_summary=final_summary,
                is_finished=False,
                raw_model_output=raw_content,
            )

        # No action proposed
        return AgentStepResult(
            thought=thought,
            proposal=None,
            final_summary=final_summary,
            is_finished=bool(final_summary),
            raw_model_output=raw_content,
        )
