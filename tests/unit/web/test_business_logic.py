"""Unit tests for Phase 3.8 Business-Logic and Access-Control Analysis."""

import httpx
import pytest

from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import PolicyDecisionType, ScopeDefinition, ScopeTarget
from arka.app.execution.evidence import EvidenceStore
from arka.app.web.analysis.models import FindingValidationStatus
from arka.app.web.business_logic.access_control import AccessControlAnalyzer
from arka.app.web.business_logic.models import (
    AccessControlRole,
    DestructiveActionCategory,
    StateAnomalyType,
    TestIdentity,
    Workflow,
    WorkflowPrecondition,
    WorkflowStep,
)
from arka.app.web.business_logic.safety import (
    BusinessLogicSafetyValidator,
    DestructiveOperationBlocked,
)
from arka.app.web.business_logic.workflow import WorkflowEngine
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.models.auth import SessionContext
from arka.app.web.models.http import HTTPMethod, HTTPRequest


class TestBusinessLogicSafety:
    def test_destructive_operations_classified_and_blocked(self):
        """Section 3.8.5: Verify payments and deletions are classified as destructive."""
        # 1. Purchase/Payment
        req_pay = HTTPRequest(url="http://target.com/api/checkout/pay", method=HTTPMethod.POST)
        is_destr, cat, _ = BusinessLogicSafetyValidator.classify_request(req_pay)
        assert is_destr is True
        assert cat == DestructiveActionCategory.PURCHASE_PAYMENT

        # Policy decision requires approval
        decision = BusinessLogicSafetyValidator.evaluate_safety_policy(
            req_pay, engagement_id="eng-1"
        )
        assert decision is not None
        assert decision.decision == PolicyDecisionType.REQUIRE_APPROVAL
        assert decision.requires_approval is True

        # 2. Account deletion
        req_del = HTTPRequest(url="http://target.com/api/user/delete", method=HTTPMethod.POST)
        is_destr2, cat2, _ = BusinessLogicSafetyValidator.classify_request(req_del)
        assert is_destr2 is True
        assert cat2 == DestructiveActionCategory.DELETE_ACCOUNT

        # 3. Read-only operation is safe
        req_read = HTTPRequest(url="http://target.com/api/products", method=HTTPMethod.GET)
        is_destr3, cat3, _ = BusinessLogicSafetyValidator.classify_request(req_read)
        assert is_destr3 is False
        assert cat3 is None


class TestWorkflowEngine:
    @pytest.mark.asyncio
    async def test_workflow_detects_prerequisite_bypass(self):
        """Section 3.8.2: Detect operations available without expected prerequisites."""
        scope = ScopeDefinition(
            engagement_id="eng-wf-test",
            version=1,
            includes=ScopeTarget(domains=["shop.example.com"], ports=[80, 443]),
        )
        guard = ScopeGuard(scope)

        async def handler(request: httpx.Request) -> httpx.Response:
            # Simulated vulnerable application allowing checkout without adding items
            if request.url.path == "/checkout":
                return httpx.Response(200, text="Checkout completed successfully!")
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        evidence = EvidenceStore()
        client = ControlledHTTPClient(
            scope_guard=guard, evidence_store=evidence, transport=transport
        )
        engine = WorkflowEngine(http_client=client)

        step = WorkflowStep(
            name="Checkout",
            method=HTTPMethod.GET,
            endpoint_url="http://shop.example.com/checkout",
            preconditions=[
                WorkflowPrecondition(
                    name="Has Cart Items",
                    required_state_key="cart_item_count",
                    expected_value=1,
                )
            ],
            expected_status_codes=[200],
        )

        wf = Workflow(
            engagement_id="eng-wf-test",
            name="E-Commerce Purchase Flow",
            steps=[step],
            current_state={"cart_item_count": 0},  # Unmet precondition!
        )

        resp, anomalies = await engine.execute_step(wf, step)
        assert resp is not None
        assert resp.status_code == 200
        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == StateAnomalyType.PREREQUISITE_BYPASS
        assert "Checkout" in anomalies[0].title

    @pytest.mark.asyncio
    async def test_workflow_blocks_destructive_step(self):
        """Section 3.8.5: WorkflowEngine blocks destructive step execution without explicit flag."""
        scope = ScopeDefinition(
            engagement_id="eng-wf-test",
            version=1,
            includes=ScopeTarget(domains=["target.example.com"], ports=[80, 443]),
        )
        guard = ScopeGuard(scope)
        client = ControlledHTTPClient(scope_guard=guard)
        engine = WorkflowEngine(http_client=client)

        destructive_step = WorkflowStep(
            name="Submit Payment",
            method=HTTPMethod.POST,
            endpoint_url="http://target.example.com/api/payment/confirm",
        )
        wf = Workflow(engagement_id="eng-wf-test", name="Payment Flow", steps=[destructive_step])

        with pytest.raises(DestructiveOperationBlocked):
            await engine.execute_step(wf, destructive_step, allow_destructive=False)


class TestAccessControlAnalyzer:
    @pytest.mark.asyncio
    async def test_horizontal_access_control_idor_detection(self):
        """Section 3.8.4: IDOR/BOLA detection using controlled test identities."""
        scope = ScopeDefinition(
            engagement_id="eng-ac-test",
            version=1,
            includes=ScopeTarget(domains=["api.example.com"], ports=[80, 443]),
        )
        guard = ScopeGuard(scope)

        # Alice owns resource /api/orders/order-100
        # Bob should be denied, but vulnerable server returns 200
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"order_id": "order-100", "owner": "alice"})

        transport = httpx.MockTransport(handler)
        evidence = EvidenceStore()
        client = ControlledHTTPClient(
            scope_guard=guard, evidence_store=evidence, transport=transport
        )
        analyzer = AccessControlAnalyzer(http_client=client)

        session_alice = SessionContext(
            engagement_id="eng-ac-test",
            target="http://api.example.com",
            scope_version=1,
        )
        session_bob = SessionContext(
            engagement_id="eng-ac-test",
            target="http://api.example.com",
            scope_version=1,
        )

        alice = TestIdentity(
            engagement_id="eng-ac-test",
            name="Alice",
            role=AccessControlRole.USER,
            session_context=session_alice,
            owned_resource_urls=["http://api.example.com/api/orders/order-100"],
        )
        bob = TestIdentity(
            engagement_id="eng-ac-test",
            name="Bob",
            role=AccessControlRole.USER,
            session_context=session_bob,
        )

        finding = await analyzer.verify_horizontal_isolation(
            owner_identity=alice,
            attacker_identity=bob,
            resource_url="http://api.example.com/api/orders/order-100",
        )

        assert finding is not None
        assert finding.status == FindingValidationStatus.VALIDATED
        assert "BOLA/IDOR" in finding.title
        assert finding.cwe_id == "CWE-639"

    @pytest.mark.asyncio
    async def test_vertical_privilege_escalation(self):
        """Section 3.8.3: Standard user accessing admin endpoint."""
        scope = ScopeDefinition(
            engagement_id="eng-ac-test",
            version=1,
            includes=ScopeTarget(domains=["api.example.com"], ports=[80, 443]),
        )
        guard = ScopeGuard(scope)

        async def handler(request: httpx.Request) -> httpx.Response:
            # Vulnerable admin endpoint accessible by anyone
            return httpx.Response(200, json={"admin_status": "active", "debug_mode": True})

        transport = httpx.MockTransport(handler)
        evidence = EvidenceStore()
        client = ControlledHTTPClient(
            scope_guard=guard, evidence_store=evidence, transport=transport
        )
        analyzer = AccessControlAnalyzer(http_client=client)

        session_user = SessionContext(
            engagement_id="eng-ac-test",
            target="http://api.example.com",
            scope_version=1,
        )
        user = TestIdentity(
            engagement_id="eng-ac-test",
            name="StandardUser",
            role=AccessControlRole.USER,
            session_context=session_user,
        )

        finding = await analyzer.verify_vertical_privilege_escalation(
            standard_user_identity=user,
            admin_endpoint_url="http://api.example.com/api/admin/system",
        )

        assert finding is not None
        assert finding.status == FindingValidationStatus.VALIDATED
        assert "Vertical Privilege Escalation" in finding.title
        assert finding.cwe_id == "CWE-269"

    @pytest.mark.asyncio
    async def test_unauthenticated_access_detection(self):
        """Section 3.8.3: Unauthenticated request accessing protected endpoint."""
        scope = ScopeDefinition(
            engagement_id="eng-ac-test",
            version=1,
            includes=ScopeTarget(domains=["api.example.com"], ports=[80, 443]),
        )
        guard = ScopeGuard(scope)

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": "confidential"})

        transport = httpx.MockTransport(handler)
        evidence = EvidenceStore()
        client = ControlledHTTPClient(
            scope_guard=guard, evidence_store=evidence, transport=transport
        )
        analyzer = AccessControlAnalyzer(http_client=client)

        finding = await analyzer.verify_unauthenticated_access(
            protected_url="http://api.example.com/api/confidential",
            engagement_id="eng-ac-test",
        )

        assert finding is not None
        assert finding.status == FindingValidationStatus.VALIDATED
        assert "Missing Authentication" in finding.title
        assert finding.cwe_id == "CWE-306"
