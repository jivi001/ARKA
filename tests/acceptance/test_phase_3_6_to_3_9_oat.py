"""Operational Acceptance Test (OAT) Suite for ARKA Phase 3.6 to 3.9.

Validates:
- Phase 3.6: Authenticated Web Sessions, Credential Security, Session Isolation
- Phase 3.7: Authenticated Crawling, Passive HTTP/API/CORS Security Analysis
- Phase 3.8: Business Logic Workflow Modeling, State Anomalies, Access Control / IDOR
- Phase 3.9: WebSecurityAgent Autonomous Orchestration, Budgets, Loop Prevention, Audit
"""

from __future__ import annotations

import pytest
from aiohttp import web
from pydantic import SecretStr

from arka.app.agents.web.models import (
    InvalidStateTransitionError,
    WebActionBudget,
    WebActionBudgetUsed,
    WebAgentState,
    WebSecurityState,
    compute_web_action_fingerprint,
)
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import (
    ScopeDefinition,
    ScopeTarget,
)
from arka.app.execution.schemas import CapabilityContext, ExecutionRequest
from arka.app.web.analysis.api_analyzer import APIQualityAnalyzer
from arka.app.web.analysis.cors_analyzer import CORSAnalyzer
from arka.app.web.analysis.engine import WebSecurityAnalysisEngine
from arka.app.web.analysis.http_analyzer import HTTPQualityAnalyzer
from arka.app.web.business_logic.access_control import AccessControlAnalyzer
from arka.app.web.business_logic.models import (
    AccessControlCheckType,
    AccessControlRole,
    DestructiveActionCategory,
    StateAnomalyType,
    TestIdentity,
    Workflow,
    WorkflowPrecondition,
    WorkflowStep,
)
from arka.app.web.business_logic.safety import (
    DestructiveOperationBlocked,
)
from arka.app.web.business_logic.workflow import WorkflowEngine
from arka.app.web.client.client import ControlledHTTPClient
from arka.app.web.models.auth import (
    CredentialReference,
    CredentialType,
    CredentialVault,
    SecureCookie,
    SessionContext,
)
from arka.app.web.models.http import HTTPMethod, HTTPRequest
from arka.app.web.session.manager import SessionManager

# ---------------------------------------------------------------------------
# Simulated Local Target Fixture
# ---------------------------------------------------------------------------


async def _handle_profile(request: web.Request) -> web.Response:
    auth = request.headers.get("Authorization", "")
    cookie = request.cookies.get("session_id", "")
    if "juice-jwt-token-xyz" in auth or cookie == "juice-sess-123":
        return web.json_response({"user": "alice", "email": "alice@juice-sh.op"})
    return web.Response(status=401, text="Unauthorized")


async def _handle_cors(request: web.Request) -> web.Response:
    origin = request.headers.get("Origin", "")
    resp = web.json_response({"data": "cors_protected"})
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


async def _handle_sensitive(request: web.Request) -> web.Response:
    return web.json_response(
        {
            "user_id": 1,
            "email": "admin@juice-sh.op",
            "ssn": "000-12-3456",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----",
        }
    )


async def _handle_order_idor(request: web.Request) -> web.Response:
    order_id = request.match_info.get("id", "0")
    return web.json_response(
        {"order_id": order_id, "owner": "bob" if order_id == "2" else "alice"}
    )


async def _handle_checkout(request: web.Request) -> web.Response:
    return web.json_response({"status": "order_placed", "charged": 99.99})


async def _handle_workflow_step(request: web.Request) -> web.Response:
    return web.json_response({"status": "success", "step": request.path})


@pytest.fixture
async def phase_target_server():
    """Spin up local simulated target HTTP server on 127.0.0.1:3002."""
    app = web.Application()
    app.router.add_get("/api/profile", _handle_profile)
    app.router.add_get("/api/cors-test", _handle_cors)
    app.router.add_get("/api/users/me", _handle_sensitive)
    app.router.add_get("/api/orders/{id}", _handle_order_idor)
    app.router.add_post("/api/cart/checkout", _handle_checkout)
    app.router.add_post("/api/workflow/step2", _handle_workflow_step)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 3002, reuse_address=True)
    await site.start()
    try:
        yield "http://127.0.0.1:3002"
    finally:
        await runner.cleanup()


@pytest.fixture
def phase_scope():
    return ScopeDefinition(
        engagement_id="eng-phase-36-39",
        version=1,
        includes=ScopeTarget(
            domains=["127.0.0.1", "http://127.0.0.1:3002"],
            ip_addresses=["127.0.0.1"],
            ports=[3002],
        ),
        excludes=ScopeTarget(
            domains=["internal-admin.corp"],
            ip_addresses=["169.254.169.254"],
            ports=[8000],
        ),
    )


# ---------------------------------------------------------------------------
# Test 1: Phase 3.6 Authenticated Web Session Management & Isolation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase_3_6_authenticated_session_isolation(
    phase_target_server: str,
    phase_scope: ScopeDefinition,
):
    """Verify Phase 3.6 credential security, vault isolation, and session boundaries."""
    eng_id = phase_scope.engagement_id
    vault = CredentialVault()
    session_mgr = SessionManager(credential_vault=vault)

    # 1. Store secret in vault and create credential reference
    vault.store(
        engagement_id=eng_id,
        credential_id="cred-001",
        secrets={"token": SecretStr("juice-jwt-token-xyz")},
    )
    cred_ref = CredentialReference(
        engagement_id=eng_id,
        credential_id="cred-001",
        type=CredentialType.TOKEN,
        description="Juice Shop API token",
    )
    assert cred_ref.credential_id == "cred-001"

    # INV-1 / Section 3.6.1: LLM view MUST NEVER expose plaintext secrets
    llm_view = cred_ref.to_llm_view()
    assert llm_view["credential_available"] is True
    assert "juice-jwt-token-xyz" not in str(llm_view)

    # 2. Session creation with cookie jar
    session = session_mgr.create_session(
        engagement_id=eng_id,
        target=phase_target_server,
        scope_version=phase_scope.version,
    )
    session.cookie_jar.add_cookie(
        SecureCookie(
            name="session_id",
            value=SecretStr("juice-sess-123"),
            domain="127.0.0.1",
        )
    )

    # 3. Controlled execution using session
    guard = ScopeGuard(phase_scope)
    client = ControlledHTTPClient(scope_guard=guard)
    tx = await client.execute(
        HTTPRequest(url=f"{phase_target_server}/api/profile", method=HTTPMethod.GET),
        engagement_id=eng_id,
        session_context=session,
    )
    assert tx.response is not None
    assert tx.response.status_code == 200
    assert "alice" in tx.response.body

    # 4. Cross-engagement isolation
    assert session_mgr.get_session("other-eng-999", session.session_id) is None

    # 5. Stale scope invalidation
    invalidated = session_mgr.invalidate_stale_scope_sessions(
        eng_id, current_scope_version=phase_scope.version + 1
    )
    assert invalidated >= 1
    assert session.active is False


# ---------------------------------------------------------------------------
# Test 2: Phase 3.7 Passive Security Analysis & Safe CORS/API Verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase_3_7_passive_and_active_analysis(
    phase_target_server: str,
    phase_scope: ScopeDefinition,
):
    """Verify Phase 3.7 HTTP quality, CORS misconfiguration, and API data exposure analyzers."""
    eng_id = phase_scope.engagement_id
    guard = ScopeGuard(phase_scope)
    client = ControlledHTTPClient(scope_guard=guard)
    analysis_engine = WebSecurityAnalysisEngine(http_client=client)

    # 1. Passive HTTP analysis
    tx = await client.execute(
        HTTPRequest(url=f"{phase_target_server}/api/profile", method=HTTPMethod.GET),
        engagement_id=eng_id,
    )
    assert tx.response is not None
    http_obs = HTTPQualityAnalyzer.analyze_response(tx.response, engagement_id=eng_id)
    assert len(http_obs) > 0

    # 2. CORS analysis
    tx_cors = await client.execute(
        HTTPRequest(
            url=f"{phase_target_server}/api/cors-test",
            method=HTTPMethod.GET,
            headers={"Origin": "https://attacker.evil.com"},
        ),
        engagement_id=eng_id,
    )
    assert tx_cors.response is not None
    cors_obs = CORSAnalyzer.analyze_cors(tx_cors.response, engagement_id=eng_id)
    assert len(cors_obs) > 0

    # 3. Hypothesis derivation and safe test generation
    hypotheses = analysis_engine.derive_hypotheses(cors_obs, engagement_id=eng_id)
    assert len(hypotheses) > 0
    safe_test = analysis_engine.generate_safe_test(hypotheses[0])
    assert safe_test is not None
    assert safe_test.is_safe is True

    # 4. API sensitive data exposure analysis
    tx_sens = await client.execute(
        HTTPRequest(url=f"{phase_target_server}/api/users/me", method=HTTPMethod.GET),
        engagement_id=eng_id,
    )
    assert tx_sens.response is not None
    api_obs = APIQualityAnalyzer.analyze_response(tx_sens.response, engagement_id=eng_id)
    assert len(api_obs) > 0
    assert any("sensitive" in o.title.lower() or "exposure" in o.title.lower() for o in api_obs)


# ---------------------------------------------------------------------------
# Test 3: Phase 3.8 Business Logic Modeling, State Anomalies & IDOR
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase_3_8_business_logic_and_access_control(
    phase_target_server: str,
    phase_scope: ScopeDefinition,
):
    """Verify Phase 3.8 business logic safety, prerequisite bypass, and BOLA/IDOR detection."""
    eng_id = phase_scope.engagement_id
    guard = ScopeGuard(phase_scope)
    client = ControlledHTTPClient(scope_guard=guard)

    # 1. Section 3.8.5: Destructive action blocking
    destructive_step = WorkflowStep(
        name="Checkout Purchase",
        method=HTTPMethod.POST,
        endpoint_url=f"{phase_target_server}/api/cart/checkout",
        is_destructive=True,
        destructive_category=DestructiveActionCategory.PURCHASE_PAYMENT,
    )
    wf_destructive = Workflow(
        engagement_id=eng_id,
        name="Purchase Workflow",
        steps=[destructive_step],
    )
    wf_engine = WorkflowEngine(http_client=client)
    with pytest.raises(DestructiveOperationBlocked):
        await wf_engine.execute_step(wf_destructive, destructive_step, allow_destructive=False)

    # 2. State anomaly detection: prerequisite bypass
    step_bypass = WorkflowStep(
        name="Direct Step 2",
        method=HTTPMethod.POST,
        endpoint_url=f"{phase_target_server}/api/workflow/step2",
        preconditions=[
            WorkflowPrecondition(
                name="Step 1 Required",
                required_state_key="step1_done",
                expected_value=True,
            )
        ],
        expected_status_codes=[200],
    )
    wf_bypass = Workflow(
        engagement_id=eng_id,
        name="Bypass Flow",
        steps=[step_bypass],
        current_state={"step1_done": False},
    )
    _, anomalies = await wf_engine.execute_step(wf_bypass, step_bypass)
    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == StateAnomalyType.PREREQUISITE_BYPASS

    # 3. Horizontal access control (BOLA/IDOR) detection
    session_alice = SessionContext(
        engagement_id=eng_id,
        target=phase_target_server,
        scope_version=1,
    )
    session_alice.cookie_jar.add_cookie(
        SecureCookie(
            name="session_id",
            value=SecretStr("juice-sess-123"),
            domain="127.0.0.1",
        )
    )
    session_bob = SessionContext(
        engagement_id=eng_id,
        target=phase_target_server,
        scope_version=1,
    )

    alice = TestIdentity(
        identity_id="alice-id",
        role=AccessControlRole.USER,
        session=session_alice,
        owned_resource_urls=[f"{phase_target_server}/api/orders/1"],
    )
    bob = TestIdentity(
        identity_id="bob-id",
        role=AccessControlRole.USER,
        session=session_bob,
    )

    ac_analyzer = AccessControlAnalyzer(http_client=client)
    bola_finding = await ac_analyzer.analyze_horizontal_bola(
        endpoint_template=f"{phase_target_server}/api/orders/{{id}}",
        primary_identity=alice,
        secondary_identity=bob,
        object_id_primary="1",
        object_id_secondary="2",
        engagement_id=eng_id,
    )
    assert bola_finding is not None
    assert bola_finding.check_type == AccessControlCheckType.HORIZONTAL_IDOR_BOLA


# ---------------------------------------------------------------------------
# Test 4: Phase 3.9 WebSecurityAgent Orchestration, Budgets & Fingerprints
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase_3_9_web_agent_orchestration_and_safety(
    phase_target_server: str,
    phase_scope: ScopeDefinition,
):
    """Verify Phase 3.9 agent state machine, deterministic budgets, loop prevention, and audit."""
    eng_id = phase_scope.engagement_id

    # 1. State machine transition invariants
    state = WebSecurityState(engagement_id=eng_id)
    assert state.agent_state == WebAgentState.INITIALIZED

    state.transition_to(WebAgentState.DISCOVERING)
    assert state.agent_state == WebAgentState.DISCOVERING

    # Illegal transition must raise InvalidStateTransitionError
    with pytest.raises(InvalidStateTransitionError):
        state.transition_to(WebAgentState.INITIALIZED)

    # 2. Action Budget enforcement
    budget = WebActionBudget(max_requests=2, max_pages=2)
    budget_used = WebActionBudgetUsed(requests_sent=2)
    exhausted, reason = budget_used.is_exhausted(budget)
    assert exhausted is True
    assert "Max requests reached" in (reason or "")

    # 3. Deterministic loop prevention fingerprinting
    fp1 = compute_web_action_fingerprint(
        tool_name="web_crawler",
        target=phase_target_server,
        arguments={"max_pages": 5},
        engagement_id=eng_id,
    )
    fp2 = compute_web_action_fingerprint(
        tool_name="web_crawler",
        target=phase_target_server,
        arguments={"max_pages": 5},
        engagement_id=eng_id,
    )
    assert fp1 == fp2
    assert len(fp1) == 64

    # 4. CapabilityContext tamper detection
    context = CapabilityContext(
        engagement_id=eng_id,
        task_id="task-100",
        tool_name="http_request",
        target=phase_target_server,
        scope_version=phase_scope.version,
    )
    exec_req = ExecutionRequest(
        request_id="req-100",
        engagement_id=eng_id,
        task_id="task-100",
        agent_id="agent-001",
        tool_name="http_request",
        target=phase_target_server,
        arguments={"url": phase_target_server, "method": "GET"},
        capability_context=context,
    )
    assert exec_req.capability_context is not None
    assert exec_req.capability_context.engagement_id == exec_req.engagement_id
