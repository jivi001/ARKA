"""Unit tests for Validation Agent (Phase 2.2.10)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from arka.app.agents.validation.agent import ValidationAgent
from arka.app.agents.validation.models import FindingValidationStatus
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.models import Finding, FindingStatus
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget, new_id
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.tools.nuclei.definition import register_nuclei_tool
from arka.app.tools.registry.registry import ToolRegistry


@pytest.fixture
def test_environment() -> tuple[ValidationAgent, InMemoryAssetRepository]:
    audit = AuditService()
    scope = ScopeDefinition(
        engagement_id="eng-val",
        includes=ScopeTarget(
            ip_addresses=["192.168.1.100"],
            cidrs=["192.168.1.0/24"],
        ),
    )
    scope_guard = ScopeGuard(scope)
    policy = PolicyEngine(scope_guard)
    approvals = ApprovalManager()
    registry = ToolRegistry(policy, audit, approvals)
    register_nuclei_tool(registry)

    repo = InMemoryAssetRepository()
    gateway = LLMGateway(audit_service=audit)

    agent = ValidationAgent(
        llm_gateway=gateway,
        tool_registry=registry,
        audit_service=audit,
        scope_guard=scope_guard,
        policy_engine=policy,
        approval_manager=approvals,
        asset_repository=repo,
    )
    return agent, repo


@pytest.mark.asyncio
async def test_validation_agent_detects_false_positive(
    test_environment: tuple[ValidationAgent, InMemoryAssetRepository],
) -> None:
    """Test ValidationAgent marks finding as false_positive when verification fails."""
    agent, repo = test_environment
    engagement_id = new_id()

    finding = Finding(
        engagement_id=engagement_id,
        title="False Positive RCE",
        severity="high",
        template_id="cve-2023-9999",
        matched_at="http://192.168.1.100/debug",
        status=FindingStatus.SUSPECTED,
    )
    from arka.app.core.assets.models import NormalizedAssetBundle

    repo.save_bundle(NormalizedAssetBundle(engagement_id=engagement_id, findings=[finding]))

    plan_json = json.dumps(
        {
            "finding_id": finding.finding_id,
            "reasoning": "Re-probe the debug endpoint to verify execution",
            "actions": [
                {
                    "tool_name": "nuclei",
                    "target": "http://192.168.1.100/debug",
                    "arguments": {"templates": ["cves"]},
                    "rationale": "Confirm vulnerability",
                }
            ],
        }
    )

    assessment_json = json.dumps(
        {
            "finding_id": finding.finding_id,
            "status": "false_positive",
            "confidence": 0.95,
            "reasoning": "Target endpoint responded with 404, not vulnerable",
        }
    )

    with patch("litellm.acompletion") as mock_complete:
        mock_complete.side_effect = [
            SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=plan_json))],
                model="gpt-4o",
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            ),
            SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=assessment_json))],
                model="gpt-4o",
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            ),
        ]

        assessment = await agent.validate_finding(finding, authorized_scope={})
        assert assessment.status == FindingValidationStatus.FALSE_POSITIVE
        assert assessment.confidence >= 0.9

        # Verify repository was updated
        updated_finding = repo.get_finding_by_id(finding.finding_id)
        assert updated_finding is not None
        assert updated_finding.status == FindingStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_validation_agent_validates_true_finding(
    test_environment: tuple[ValidationAgent, InMemoryAssetRepository],
) -> None:
    """Test ValidationAgent marks finding as validated when confirmed."""
    agent, _repo = test_environment
    engagement_id = new_id()

    finding = Finding(
        engagement_id=engagement_id,
        title="Confirmed SSL Weakness",
        severity="low",
        template_id="ssl-issuer",
        matched_at="192.168.1.100",
        status=FindingStatus.OBSERVED,
    )

    plan_json = json.dumps(
        {
            "finding_id": finding.finding_id,
            "reasoning": "Check SSL configuration",
            "actions": [
                {
                    "tool_name": "nuclei",
                    "target": "192.168.1.100",
                    "arguments": {"severity": ["info"]},
                    "rationale": "Re-check SSL info",
                }
            ],
        }
    )

    assessment_json = json.dumps(
        {
            "finding_id": finding.finding_id,
            "status": "validated",
            "confidence": 0.99,
            "reasoning": "SSL issuer confirmed via probe",
        }
    )

    with patch("litellm.acompletion") as mock_complete:
        mock_complete.side_effect = [
            SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=plan_json))],
                model="gpt-4o",
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            ),
            SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=assessment_json))],
                model="gpt-4o",
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            ),
        ]

        assessment = await agent.validate_finding(finding, authorized_scope={})
        assert assessment.status == FindingValidationStatus.VALIDATED
        assert assessment.confidence >= 0.9


@pytest.mark.asyncio
async def test_validation_agent_fallback_on_malformed_llm_plan(
    test_environment: tuple[ValidationAgent, InMemoryAssetRepository],
) -> None:
    """Test ValidationAgent recovers cleanly when LLM outputs invalid JSON for plan."""
    agent, _repo = test_environment
    engagement_id = new_id()

    finding = Finding(
        engagement_id=engagement_id,
        title="Inconclusive finding",
        severity="medium",
        template_id="http-missing-headers",
        matched_at="192.168.1.100",
    )

    with patch("litellm.acompletion") as mock_complete:
        mock_complete.side_effect = [
            SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content="NOT VALID JSON"))],
                model="gpt-4o",
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            ),
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=json.dumps(
                                {
                                    "finding_id": finding.finding_id,
                                    "status": "validated",
                                    "confidence": 0.8,
                                    "reasoning": "Re-confirmed via fallback",
                                }
                            )
                        )
                    )
                ],
                model="gpt-4o",
                usage=SimpleNamespace(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            ),
        ]

        assessment = await agent.validate_finding(finding, authorized_scope={})
        assert assessment.status == FindingValidationStatus.VALIDATED
