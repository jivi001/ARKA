"""Deterministic policy engine for ARKA authorization decisions.

Evaluates tool requests against scope, risk levels, and approval requirements.
All decisions are deterministic — no LLM involvement in authorization.
"""

from arka.app.core.scope.scopeguard import ScopeGuard, ScopeViolation
from arka.app.core.state.models import PolicyDecision, PolicyDecisionType, RiskLevel
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest, ToolDefinition, ToolRequest


class PolicyEngine:
    """Deterministic policy engine for authorization decisions.

    Evaluates tool requests against scope, risk levels, and approval requirements.
    The policy engine makes decisions based on:
    1. Scope validation (is the target authorized? Exclusions always take priority.)
    2. Risk classification (what risk level is defined for the tool?)
    3. Approval requirements (does this risk level need human approval?)
    """

    def __init__(self, scope_guard: ScopeGuard) -> None:
        self._scope_guard = scope_guard
        self._risk_approval_thresholds: dict[RiskLevel, bool] = {
            RiskLevel.LOW: False,
            RiskLevel.MEDIUM: False,
            RiskLevel.HIGH: True,
            RiskLevel.CRITICAL: True,
        }

    def evaluate(
        self,
        tool_request: ToolRequest | CandidateToolRequest,
        tool_def: ToolDefinition,
        engagement_id: str = "",
        task_id: str = "",
        agent_id: str = "",
    ) -> PolicyDecision:
        """Evaluate a tool request against policy.

        Returns a PolicyDecision with ALLOW, DENY, or REQUIRE_APPROVAL.
        Scope violations always result in DENY regardless of risk level.
        Risk level is authoritatively derived from ToolDefinition.
        """
        eff_engagement_id = getattr(tool_request, "engagement_id", "") or engagement_id
        eff_task_id = getattr(tool_request, "task_id", "") or task_id
        eff_agent_id = getattr(tool_request, "agent_id", "") or agent_id

        target = tool_request.target

        # 1. Validate target is in scope
        if target:
            try:
                self._scope_guard.validate_target(target)
            except ScopeViolation as e:
                return PolicyDecision(
                    engagement_id=eff_engagement_id,
                    task_id=eff_task_id,
                    agent_id=eff_agent_id,
                    action=f"execute_tool:{tool_def.name}",
                    target=target,
                    tool_name=tool_def.name,
                    decision=PolicyDecisionType.DENY,
                    reason=f"Target out of scope: {e.reason}",
                    risk_level=tool_def.risk_level,
                    requires_approval=False,
                )

        # 2. Check risk level authoritatively from the tool definition
        risk_level = tool_def.risk_level

        # 3. Determine if approval is required based on risk threshold
        requires_approval = self._risk_approval_thresholds.get(risk_level, True)

        # 4. Build decision
        if requires_approval:
            decision_type = PolicyDecisionType.REQUIRE_APPROVAL
            reason = (
                f"Tool '{tool_def.name}' has risk level '{risk_level.value}' "
                f"which requires human approval before execution."
            )
        else:
            decision_type = PolicyDecisionType.ALLOW
            reason = (
                f"Tool '{tool_def.name}' with risk level '{risk_level.value}' "
                f"is authorized for execution. Target '{target}' is in scope."
            )

        return PolicyDecision(
            engagement_id=eff_engagement_id,
            task_id=eff_task_id,
            agent_id=eff_agent_id,
            action=f"execute_tool:{tool_def.name}",
            target=target or "",
            tool_name=tool_def.name,
            decision=decision_type,
            reason=reason,
            risk_level=risk_level,
            requires_approval=requires_approval,
        )

    def set_approval_threshold(self, level: RiskLevel, requires_approval: bool) -> None:
        """Configure whether a given risk level requires human approval."""
        self._risk_approval_thresholds[level] = requires_approval
