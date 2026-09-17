"""Workflow Modeling and State Consistency Analysis for ARKA Phase 3.8.1 & 3.8.2.

Evaluates multi-step workflows to detect:
- Impossible state transitions.
- Operations available without prerequisites (prerequisite bypass).
- Inconsistent authorization responses across workflow stages.
- Enforces strict safety: never executes destructive steps automatically.
"""

from __future__ import annotations

from typing import Any

from arka.app.core.state.models import RiskLevel
from arka.app.observability.logging import get_logger
from arka.app.web.business_logic.models import (
    StateAnomaly,
    StateAnomalyType,
    Workflow,
    WorkflowStep,
)
from arka.app.web.business_logic.safety import (
    BusinessLogicSafetyValidator,
    DestructiveOperationBlocked,
)
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.models.auth import SessionContext
from arka.app.web.models.http import HTTPRequest, HTTPResponse

logger = get_logger(__name__)


class WorkflowEngine:
    """Manages stateful workflow execution and detects business logic state anomalies."""

    def __init__(self, http_client: ControlledHTTPClient) -> None:
        self.http_client = http_client

    def validate_preconditions(
        self,
        step: WorkflowStep,
        current_state: dict[str, Any],
    ) -> tuple[bool, list[str]]:
        """Check whether all declared preconditions are met by current state."""
        unmet: list[str] = []
        for pre in step.preconditions:
            val = current_state.get(pre.required_state_key)
            if val != pre.expected_value:
                unmet.append(
                    f"Precondition '{pre.name}' failed: state['{pre.required_state_key}'] "
                    f"is '{val}', expected '{pre.expected_value}'"
                )
        return len(unmet) == 0, unmet

    async def execute_step(
        self,
        workflow: Workflow,
        step: WorkflowStep,
        session_context: SessionContext | None = None,
        task_id: str = "",
        allow_destructive: bool = False,
    ) -> tuple[HTTPResponse | None, list[StateAnomaly]]:
        """Execute a single workflow step safely and check for state anomalies."""
        anomalies: list[StateAnomaly] = []

        # 1. Safety check under Section 3.8.5: Destructive operation guard
        req = HTTPRequest(
            url=step.endpoint_url,
            method=step.method,
            headers=step.headers,
            body=step.body,
        )
        is_destr, category, reason = BusinessLogicSafetyValidator.classify_request(req)
        if is_destr and not allow_destructive:
            raise DestructiveOperationBlocked(
                category=category or "unknown",  # type: ignore
                url=step.endpoint_url,
                reason=reason,
            )

        # 2. Check preconditions before execution
        preconditions_met, unmet_reasons = self.validate_preconditions(step, workflow.current_state)

        # 3. Execute HTTP transaction
        tx = await self.http_client.execute(
            req,
            engagement_id=workflow.engagement_id,
            task_id=task_id,
            session_context=session_context,
        )

        if not tx.response:
            return None, anomalies

        resp = tx.response
        is_step_successful = resp.status_code in step.expected_status_codes

        # 4. State Anomaly Detection: Prerequisite Bypass
        # If the step succeeded despite unmet preconditions, this reveals a business logic flaw
        if not preconditions_met and is_step_successful:
            anomalies.append(
                StateAnomaly(
                    engagement_id=workflow.engagement_id,
                    workflow_id=workflow.workflow_id,
                    step_name=step.name,
                    anomaly_type=StateAnomalyType.PREREQUISITE_BYPASS,
                    title=f"Workflow Prerequisite Bypass: '{step.name}'",
                    description=(
                        f"Step '{step.name}' succeeded with HTTP {resp.status_code} even though "
                        f"required preconditions were not met: {'; '.join(unmet_reasons)}."
                    ),
                    severity=RiskLevel.HIGH,
                    evidence_data={
                        "endpoint": step.endpoint_url,
                        "status_code": resp.status_code,
                        "unmet_preconditions": unmet_reasons,
                        "state_snapshot": dict(workflow.current_state),
                    },
                )
            )

        # 5. Update workflow state if successful
        if is_step_successful:
            workflow.current_state.update(step.state_updates)
            workflow.current_step_index += 1

        return resp, anomalies
