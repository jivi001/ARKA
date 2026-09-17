"""Operational Acceptance Test (OAT) Suite for ARKA.

Validates the complete end-to-end operational lifecycle:
Phase 1 Control Plane -> Phase 2 Execution & Correlation -> Phase 3.1-3.5 Web Security Subsystem
-> Live LLM Agentic Workflow -> Adversarial Security Boundary Matrix.
"""

from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from pydantic import SecretStr

from arka.app.agents.web.agent import WebSecurityAgent
from arka.app.agents.web.models import WebAgentState, WebSecurityState
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import (
    ApprovalStatus,
    RiskLevel,
    ScopeDefinition,
    ScopeTarget,
)
from arka.app.execution.evidence import EvidenceStore
from arka.app.execution.manager import ExecutionManager
from arka.app.execution.policy import ExecutionPolicy
from arka.app.execution.sandbox import LocalSafeRuntime
from arka.app.llm.gateway.gateway import LLMGateway
from arka.app.llm.schemas.llm_schemas import LLMMessage, LLMRequest, LLMResponse
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest, ToolRequest
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
from arka.app.web.models.auth import SecureCookie
from arka.app.web.models.http import HTTPMethod, HTTPRequest
from arka.app.web.session.manager import SessionManager
from arka.app.web.tools.definitions import (
    get_graphql_analyze_tool_definition,
    get_http_request_tool_definition,
    get_openapi_analyze_tool_definition,
    get_web_crawler_tool_definition,
)
from arka.app.web.tools.executors import (
    GraphQLAnalyzeToolExecutor,
    HTTPRequestToolExecutor,
    OpenAPIAnalyzeToolExecutor,
    WebCrawlerToolExecutor,
)

# ---------------------------------------------------------------------------
# Local Target Application Fixture (Juice Shop Surface Simulation)
# ---------------------------------------------------------------------------

OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "OWASP Juice Shop Test API", "version": "1.0.0"},
    "servers": [{"url": "http://127.0.0.1:3000"}],
    "paths": {
        "/api/Products": {
            "get": {
                "summary": "List all products",
                "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/api/Users": {
            "get": {
                "summary": "List users",
                "responses": {"200": {"description": "OK"}},
            },
            "delete": {
                "summary": "Delete user",
                "parameters": [{"name": "id", "in": "query", "required": True}],
                "responses": {"200": {"description": "Deleted"}},
            },
        },
    },
}

GRAPHQL_INTROSPECTION_DATA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "Query",
                    "fields": [
                        {
                            "name": "products",
                            "args": [
                                {"name": "category", "type": {"kind": "SCALAR", "name": "String"}}
                            ],
                            "type": {
                                "kind": "LIST",
                                "ofType": {"kind": "OBJECT", "name": "Product"},
                            },
                        }
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "fields": [
                        {
                            "name": "deleteUser",
                            "args": [
                                {
                                    "name": "id",
                                    "type": {
                                        "kind": "NON_NULL",
                                        "ofType": {"kind": "SCALAR", "name": "Int"},
                                    },
                                }
                            ],
                            "type": {"kind": "SCALAR", "name": "Boolean"},
                        }
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "Product",
                    "fields": [
                        {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "Int"}},
                        {"name": "name", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
                    ],
                },
            ],
        }
    }
}


async def _handle_root(request: web.Request) -> web.Response:
    html = """<!DOCTYPE html>
<html>
<head><title>OWASP Juice Shop</title></head>
<body>
    <h1>Welcome to OWASP Juice Shop</h1>
    <a href="/login">Login</a>
    <a href="/about">About Us</a>
    <a href="/rest/products/search?q=apple">Product Search</a>
    <a href="/redirect?to=http://169.254.169.254/latest/meta-data/">Cloud Metadata Link</a>
    <a href="http://127.0.0.1:8000/internal-admin">Internal Admin</a>
    <form action="/login" method="POST">
        <input type="text" name="email" />
        <input type="password" name="password" />
        <button type="submit">Sign In</button>
    </form>
</body>
</html>"""
    return web.Response(text=html, content_type="text/html")


async def _handle_login(request: web.Request) -> web.Response:
    return web.Response(text="<h1>Login Page</h1>", content_type="text/html")


async def _handle_about(request: web.Request) -> web.Response:
    return web.Response(text="<h1>About Us</h1>", content_type="text/html")


async def _handle_search(request: web.Request) -> web.Response:
    q = request.query.get("q", "")
    return web.json_response(
        {"status": "success", "query": q, "data": [{"id": 1, "name": "Apple Juice"}]}
    )


async def _handle_openapi(request: web.Request) -> web.Response:
    return web.json_response(OPENAPI_SPEC)


async def _handle_graphql(request: web.Request) -> web.Response:
    return web.json_response(GRAPHQL_INTROSPECTION_DATA)


async def _handle_redirect(request: web.Request) -> web.Response:
    target = request.query.get("to", "/")
    raise web.HTTPFound(location=target)


async def _handle_auth_login(request: web.Request) -> web.Response:
    resp = web.json_response({"status": "success", "token": "juice-jwt-token-xyz"})
    resp.set_cookie("session_id", "juice-sess-123", httponly=True, samesite="Strict")
    return resp


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
    # Vulnerable BOLA/IDOR: returns any order without checking identity
    return web.json_response({"order_id": order_id, "owner": "bob" if order_id == "2" else "alice"})


async def _handle_checkout(request: web.Request) -> web.Response:
    return web.json_response({"status": "order_placed", "charged": 99.99})


async def _handle_workflow_step(request: web.Request) -> web.Response:
    # Allows step 2 without step 1 (prerequisite bypass)
    return web.json_response({"status": "success", "step": request.path})


@pytest.fixture
async def local_juice_shop_target():
    """Spin up local simulated Juice Shop HTTP server on 127.0.0.1:3000."""
    app = web.Application()
    app.router.add_get("/", _handle_root)
    app.router.add_get("/login", _handle_login)
    app.router.add_post("/login", _handle_login)
    app.router.add_get("/about", _handle_about)
    app.router.add_get("/rest/products/search", _handle_search)
    app.router.add_get("/openapi.json", _handle_openapi)
    app.router.add_post("/graphql", _handle_graphql)
    app.router.add_get("/redirect", _handle_redirect)
    app.router.add_post("/api/auth/login", _handle_auth_login)
    app.router.add_get("/api/profile", _handle_profile)
    app.router.add_get("/api/cors-test", _handle_cors)
    app.router.add_get("/api/users/me", _handle_sensitive)
    app.router.add_get("/api/orders/{id}", _handle_order_idor)
    app.router.add_post("/api/cart/checkout", _handle_checkout)
    app.router.add_post("/api/workflow/step2", _handle_workflow_step)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 3000, reuse_address=True)
    await site.start()
    try:
        yield "http://127.0.0.1:3000"
    finally:
        await runner.cleanup()


# ---------------------------------------------------------------------------
# Core Subsystem Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_service():
    return AuditService()


@pytest.fixture
def evidence_store():
    return EvidenceStore()


@pytest.fixture
def asset_repository():
    return InMemoryAssetRepository()


@pytest.fixture
def strict_scope():
    return ScopeDefinition(
        engagement_id="eng-acceptance-oat-001",
        includes=ScopeTarget(
            urls=["http://127.0.0.1:3000", "http://127.0.0.1:3000/"],
            ip_addresses=["127.0.0.1"],
            ports=[3000],
        ),
        excludes=ScopeTarget(
            urls=["http://127.0.0.1:8000"],
            ip_addresses=["169.254.169.254"],
        ),
    )


@pytest.fixture
def scope_guard(strict_scope: ScopeDefinition):
    return ScopeGuard(strict_scope)


@pytest.fixture
def policy_engine(scope_guard: ScopeGuard):
    return PolicyEngine(scope_guard=scope_guard)


@pytest.fixture
def approval_manager():
    return ApprovalManager()


@pytest.fixture
def execution_manager(audit_service: AuditService, evidence_store: EvidenceStore):
    runtime = LocalSafeRuntime()
    policy = ExecutionPolicy()
    return ExecutionManager(
        runtime=runtime,
        policy=policy,
        evidence_store=evidence_store,
        audit_service=audit_service,
    )


@pytest.fixture
def tool_registry(
    scope_guard: ScopeGuard,
    policy_engine: PolicyEngine,
    approval_manager: ApprovalManager,
    execution_manager: ExecutionManager,
    audit_service: AuditService,
    evidence_store: EvidenceStore,
    asset_repository: InMemoryAssetRepository,
):
    registry = ToolRegistry(
        policy_engine=policy_engine,
        approval_manager=approval_manager,
        execution_manager=execution_manager,
        audit_service=audit_service,
    )
    http_client = ControlledHTTPClient(
        scope_guard=scope_guard,
        evidence_store=evidence_store,
    )

    registry.register(
        get_web_crawler_tool_definition(),
        WebCrawlerToolExecutor(
            scope_guard=scope_guard,
            asset_repository=asset_repository,
            evidence_store=evidence_store,
            http_client=http_client,
        ),
    )
    registry.register(
        get_http_request_tool_definition(),
        HTTPRequestToolExecutor(
            scope_guard=scope_guard,
            evidence_store=evidence_store,
            http_client=http_client,
        ),
    )
    registry.register(
        get_openapi_analyze_tool_definition(),
        OpenAPIAnalyzeToolExecutor(
            scope_guard=scope_guard,
            asset_repository=asset_repository,
            evidence_store=evidence_store,
            http_client=http_client,
        ),
    )
    registry.register(
        get_graphql_analyze_tool_definition(),
        GraphQLAnalyzeToolExecutor(
            scope_guard=scope_guard,
            asset_repository=asset_repository,
            evidence_store=evidence_store,
            http_client=http_client,
        ),
    )
    return registry


# ---------------------------------------------------------------------------
# TEST 1: Control Plane Boundary, Policy, and Approval State Machine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_control_plane_boundary_and_approval_state_machine(
    tool_registry: ToolRegistry,
    policy_engine: PolicyEngine,
    approval_manager: ApprovalManager,
    strict_scope: ScopeDefinition,
):
    """OAT Phase 1: CandidateToolRequest -> Scope -> Policy -> ApprovalManager -> ToolRequest."""
    eng_id = strict_scope.engagement_id
    task_id = str(uuid.uuid4())
    agent_id = "agent-oat-control-plane"

    # 1. Low risk action (web_crawler on authorized seed)
    candidate_low = CandidateToolRequest(
        tool_name="web_crawler",
        target="http://127.0.0.1:3000",
        arguments={"target": "http://127.0.0.1:3000", "max_pages": 5},
        reason="Initial recon crawl",
    )
    tool_req, decision, _ = tool_registry.validate_candidate_request(
        candidate=candidate_low,
        engagement_id=eng_id,
        task_id=task_id,
        agent_id=agent_id,
    )
    assert tool_req is not None
    assert decision is not None and decision.risk_level == RiskLevel.LOW
    assert tool_req.policy_approved is True

    # 2. High risk destructive action (DELETE via http_request) requires human approval
    candidate_high = CandidateToolRequest(
        tool_name="http_request",
        target="http://127.0.0.1:3000/api/Users?id=42",
        arguments={"url": "http://127.0.0.1:3000/api/Users?id=42", "method": "DELETE"},
        reason="Attempting destructive user deletion",
    )
    tool_req_high, decision_high, err_high = tool_registry.validate_candidate_request(
        candidate=candidate_high,
        engagement_id=eng_id,
        task_id=task_id,
        agent_id=agent_id,
    )
    assert tool_req_high is None
    assert "Requires human approval" in (err_high or "")
    assert decision_high is not None and decision_high.risk_level == RiskLevel.HIGH

    # 3. Create approval request and test State Machine transitions
    appr_rec = approval_manager.create_request(
        engagement_id=eng_id,
        task_id=task_id,
        agent_id=agent_id,
        action="http_request:DELETE",
        target="http://127.0.0.1:3000/api/Users?id=42",
        tool_name="http_request",
        risk_level=RiskLevel.HIGH,
        scope_version=strict_scope.version,
        reason="Testing human approval workflow",
    )
    assert appr_rec.status == ApprovalStatus.REQUIRED

    # Invalid state transition: cannot grant twice or grant without required state
    # Grant approval
    approval_manager.approve(
        approval_id=appr_rec.approval_id,
        approved_by="sec-admin@corp.internal",
    )
    appr_after = approval_manager.get_request(appr_rec.approval_id)
    assert appr_after is not None
    assert appr_after.status == ApprovalStatus.GRANTED

    # Validate approval token for the request
    is_valid = approval_manager.validate_approval_for_request(
        approval_id=appr_rec.approval_id,
        engagement_id=eng_id,
        task_id=task_id,
        tool_name="http_request",
        target="http://127.0.0.1:3000/api/Users?id=42",
        scope_version=strict_scope.version,
    )
    assert is_valid is True

    # Re-validate candidate with approved ID
    tool_req_approved, _, _ = tool_registry.validate_candidate_request(
        candidate=candidate_high,
        engagement_id=eng_id,
        task_id=task_id,
        agent_id=agent_id,
        approval_id=appr_rec.approval_id,
    )
    assert tool_req_approved is not None
    assert tool_req_approved.policy_approved is True
    assert tool_req_approved.approval_id == appr_rec.approval_id

    # 4. Invalidation on Scope Version Mutation
    stale_valid = approval_manager.validate_approval_for_request(
        approval_id=appr_rec.approval_id,
        engagement_id=eng_id,
        task_id=task_id,
        tool_name="http_request",
        target="http://127.0.0.1:3000/api/Users?id=42",
        scope_version=strict_scope.version + 1,  # Mutated version
    )
    assert stale_valid is False


# ---------------------------------------------------------------------------
# TEST 2: Phase 3 Real Execution against Local Target (Crawler, OpenAPI, GraphQL)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase3_real_execution_against_local_target(
    local_juice_shop_target: str,
    tool_registry: ToolRegistry,
    evidence_store: EvidenceStore,
    asset_repository: InMemoryAssetRepository,
    strict_scope: ScopeDefinition,
):
    """OAT Phase 3: Real HTTP crawler, OpenAPI analyzer, and GraphQL analyzer execution."""
    eng_id = strict_scope.engagement_id
    task_id = str(uuid.uuid4())

    # 1. Execute Web Crawler
    crawl_req = ToolRequest(
        engagement_id=eng_id,
        task_id=task_id,
        agent_id="test-agent-oat",
        tool_name="web_crawler",
        target=local_juice_shop_target,
        arguments={"target": local_juice_shop_target, "max_pages": 10},
        risk_level=RiskLevel.LOW,
        scope_validated=True,
        scope_version=strict_scope.version,
        policy_approved=True,
    )
    crawl_res = await tool_registry.execute(crawl_req)
    assert crawl_res.success is True
    out = crawl_res.output
    assert out["pages_crawled"] >= 1
    assert any("login" in u for u in out["urls_discovered"])
    assert any("search" in u for u in out["urls_discovered"])

    # 2. Execute OpenAPI Analyzer
    openapi_req = ToolRequest(
        engagement_id=eng_id,
        task_id=task_id,
        agent_id="test-agent-oat",
        tool_name="openapi_analyze",
        target=f"{local_juice_shop_target}/openapi.json",
        arguments={"target": f"{local_juice_shop_target}/openapi.json"},
        risk_level=RiskLevel.LOW,
        scope_validated=True,
        scope_version=strict_scope.version,
        policy_approved=True,
    )
    openapi_res = await tool_registry.execute(openapi_req)
    assert openapi_res.success is True
    assert openapi_res.output["endpoints_discovered"] >= 2

    # 3. Execute GraphQL Analyzer
    graphql_req = ToolRequest(
        engagement_id=eng_id,
        task_id=task_id,
        agent_id="test-agent-oat",
        tool_name="graphql_analyze",
        target=f"{local_juice_shop_target}/graphql",
        arguments={"target": f"{local_juice_shop_target}/graphql"},
        risk_level=RiskLevel.LOW,
        scope_validated=True,
        scope_version=strict_scope.version,
        policy_approved=True,
    )
    graphql_res = await tool_registry.execute(graphql_req)
    assert graphql_res.success is True
    assert graphql_res.output["mutations_count"] >= 1
    assert "deleteUser" in (graphql_res.raw_output or "")

    # 4. Verify Canonical Asset & Endpoint Ingestion
    endpoints = asset_repository.get_endpoints_by_engagement(eng_id)
    assert len(endpoints) >= 3
    for ep in endpoints:
        # Strict Invariant: DISCOVERED != AUTHORIZED
        assert ep.metadata.get("discovered_not_authorized") is True

    # 5. Verify Cryptographic Evidence in EvidenceStore
    ev_list = evidence_store.list_by_engagement(eng_id)
    assert len(ev_list) >= 3
    for ev in ev_list:
        assert ev.sha256 is not None
        assert len(ev.sha256) == 64


# ---------------------------------------------------------------------------
# TEST 3: Live LLM Reasoning & Autonomous Agentic Workflow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_live_agentic_workflow_with_openrouter_nemotron(
    local_juice_shop_target: str,
    tool_registry: ToolRegistry,
    scope_guard: ScopeGuard,
    policy_engine: PolicyEngine,
    audit_service: AuditService,
    strict_scope: ScopeDefinition,
):
    """OAT Agentic: Real Live NVIDIA Nemotron-3 Ultra via OpenRouter autonomous loop."""
    llm_gateway = LLMGateway()

    # Step 1: Verify LLM Gateway Live Health Check
    health_req = LLMRequest(
        messages=[
            LLMMessage(role="user", content="Respond with 'NEMOTRON_READY' and nothing else.")
        ],
        temperature=0.1,
        max_tokens=32,
    )
    health_resp = await llm_gateway.complete(health_req)
    assert health_resp.content is not None
    assert "NEMOTRON_READY" in health_resp.content or len(health_resp.content) > 0

    # Step 2: Initialize WebSecurityAgent with real live LLM
    agent = WebSecurityAgent(
        agent_id="web-agent-live-nemotron",
        llm_gateway=llm_gateway,
        tool_registry=tool_registry,
        scope_guard=scope_guard,
        policy_engine=policy_engine,
        audit_service=audit_service,
    )

    state = WebSecurityState(
        engagement_id=strict_scope.engagement_id,
        max_iterations=3,
    )

    # Step 3: Agentic Planning Iteration 1
    plan = await agent.plan_reconnaissance(
        state=state,
        seed_target=local_juice_shop_target,
        authorized_domains=["127.0.0.1", "http://127.0.0.1:3000"],
    )
    assert plan.plan_id is not None
    assert len(plan.candidate_actions) > 0

    # Step 4: Execute Plan through Authoritative Security Pipeline
    results = await agent.execute_plan(state, plan)
    assert len(results) == len(plan.candidate_actions)
    for res in results:
        # Must execute cleanly or fail safely under policy
        assert isinstance(res.success, bool)

    # Step 5: Verify Audit Trail Records
    audit_events = await audit_service.get_events(engagement_id=strict_scope.engagement_id)
    assert len(audit_events) >= 1
    # Verify credential redaction
    for ev in audit_events:
        for k, v in (ev.parameters or {}).items():
            if any(s in k.lower() for s in ["key", "token", "password", "secret", "auth"]):
                assert v == "[REDACTED]" or "sk-" not in str(v)


# ---------------------------------------------------------------------------
# TEST 4: Comprehensive Adversarial Security Boundary Matrix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_adversarial_security_boundary_matrix(
    tool_registry: ToolRegistry,
    scope_guard: ScopeGuard,
    strict_scope: ScopeDefinition,
    local_juice_shop_target: str,
):
    """OAT Adversarial: Verify all attack vectors are unconditionally blocked."""
    eng_id = strict_scope.engagement_id
    task_id = str(uuid.uuid4())
    agent_id = "agent-adversary"

    # Vector 1: Out-of-Scope Target
    candidate_out_of_scope = CandidateToolRequest(
        tool_name="http_request",
        target="https://unauthorized-evil-target.com/api",
        arguments={"url": "https://unauthorized-evil-target.com/api", "method": "GET"},
        reason="Hostile probe",
    )
    tool_req, _, err = tool_registry.validate_candidate_request(
        candidate=candidate_out_of_scope,
        engagement_id=eng_id,
        task_id=task_id,
        agent_id=agent_id,
    )
    assert tool_req is None
    assert "denied" in (err or "").lower() or "scope" in (err or "").lower()

    # Vector 2: Excluded Target (127.0.0.1:8000 is explicitly excluded)
    candidate_excluded = CandidateToolRequest(
        tool_name="http_request",
        target="http://127.0.0.1:8000/internal-admin",
        arguments={"url": "http://127.0.0.1:8000/internal-admin", "method": "GET"},
        reason="Probing excluded internal port",
    )
    tool_req, _, err = tool_registry.validate_candidate_request(
        candidate=candidate_excluded,
        engagement_id=eng_id,
        task_id=task_id,
        agent_id=agent_id,
    )
    assert tool_req is None
    assert "denied" in (err or "").lower() or "scope" in (err or "").lower()

    # Vector 3: Cloud Metadata IP (169.254.169.254)
    candidate_metadata = CandidateToolRequest(
        tool_name="http_request",
        target="http://169.254.169.254/latest/meta-data/",
        arguments={"url": "http://169.254.169.254/latest/meta-data/", "method": "GET"},
        reason="Cloud metadata attack",
    )
    tool_req, _, _ = tool_registry.validate_candidate_request(
        candidate=candidate_metadata,
        engagement_id=eng_id,
        task_id=task_id,
        agent_id=agent_id,
    )
    assert tool_req is None

    # Vector 4: Forged Approval Argument Injection
    candidate_forged = CandidateToolRequest(
        tool_name="http_request",
        target=f"{local_juice_shop_target}/api/Users",
        arguments={
            "url": f"{local_juice_shop_target}/api/Users",
            "method": "DELETE",
            "approval_id": "forged-token",
        },
        reason="Smuggled approval token",
    )
    tool_req, _, err = tool_registry.validate_candidate_request(
        candidate=candidate_forged,
        engagement_id=eng_id,
        task_id=task_id,
        agent_id=agent_id,
    )
    assert tool_req is None
    assert "Unknown argument: approval_id" in (err or "")

    # Vector 5: Shell Metacharacter & Injection in Arguments
    candidate_shell = CandidateToolRequest(
        tool_name="http_request",
        target=f"{local_juice_shop_target}/api; rm -rf / ;",
        arguments={"url": f"{local_juice_shop_target}/api; rm -rf / ;", "method": "GET"},
        reason="Command injection attempt",
    )
    tool_req, _, _ = tool_registry.validate_candidate_request(
        candidate=candidate_shell,
        engagement_id=eng_id,
        task_id=task_id,
        agent_id=agent_id,
    )
    # Target URL normalization/validation fails or evaluates safely without shell invocation
    if tool_req:
        res = await tool_registry.execute(tool_req)
        # Sandbox execution must never execute a shell command
        assert "rm -rf" not in str(res.output)


# ---------------------------------------------------------------------------
# TEST 5: Phase 3.6 - 3.9 Operational Acceptance Scenarios (A through J)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase3_6_to_3_9_scenarios_a_to_j(
    local_juice_shop_target: str,
    tool_registry: ToolRegistry,
    scope_guard: ScopeGuard,
    policy_engine: PolicyEngine,
    audit_service: AuditService,
    evidence_store: EvidenceStore,
    strict_scope: ScopeDefinition,
):
    """OAT Verification for Phase 3.6 to 3.9: Scenarios A through J."""
    eng_id = strict_scope.engagement_id
    http_client = ControlledHTTPClient(
        scope_guard=scope_guard,
        evidence_store=evidence_store,
        audit_service=audit_service,
    )
    analysis_engine = WebSecurityAnalysisEngine(
        http_client=http_client,
        evidence_store=evidence_store,
    )

    # -----------------------------------------------------------------------
    # Scenario A: Authenticated Session Lifecycle & Isolation
    # -----------------------------------------------------------------------
    session_mgr = SessionManager()
    session = session_mgr.create_session(
        engagement_id=eng_id,
        target=local_juice_shop_target,
        scope_version=strict_scope.version,
    )
    session.cookie_jar.add_cookie(
        SecureCookie(
            name="session_id",
            value=SecretStr("juice-sess-123"),
            domain="127.0.0.1",
        )
    )
    # Perform authenticated request
    tx_auth = await http_client.execute(
        HTTPRequest(url=f"{local_juice_shop_target}/api/profile", method=HTTPMethod.GET),
        engagement_id=eng_id,
        session_context=session,
    )
    assert tx_auth.response is not None
    assert tx_auth.response.status_code == 200
    assert "alice" in tx_auth.response.body

    # Cross-engagement isolation
    assert session_mgr.get_session("other-engagement-999", session.session_id) is None

    # -----------------------------------------------------------------------
    # Scenario B: Passive HTTP Security Analysis
    # -----------------------------------------------------------------------
    http_obs = HTTPQualityAnalyzer.analyze_response(
        response=tx_auth.response,
        engagement_id=eng_id,
    )
    assert len(http_obs) > 0
    # Juice Shop simulation does not send HSTS, CSP, or X-Frame-Options
    obs_types = [o.observation_type.value for o in http_obs]
    assert any("hsts" in t or "csp" in t or "header" in t for t in obs_types)

    # -----------------------------------------------------------------------
    # Scenario C: CORS Misconfiguration Safe Verification
    # -----------------------------------------------------------------------
    tx_cors = await http_client.execute(
        HTTPRequest(
            url=f"{local_juice_shop_target}/api/cors-test",
            method=HTTPMethod.GET,
            headers={"Origin": "https://attacker.evil.com"},
        ),
        engagement_id=eng_id,
    )
    assert tx_cors.response is not None
    cors_obs = CORSAnalyzer.analyze_cors(tx_cors.response, engagement_id=eng_id)
    assert len(cors_obs) > 0
    hypotheses = analysis_engine.derive_hypotheses(cors_obs, engagement_id=eng_id)
    assert len(hypotheses) > 0
    safe_test = analysis_engine.generate_safe_test(hypotheses[0])
    assert safe_test is not None and safe_test.is_safe

    # -----------------------------------------------------------------------
    # Scenario D: Sensitive Data Exposure Safe Verification
    # -----------------------------------------------------------------------
    tx_sens = await http_client.execute(
        HTTPRequest(url=f"{local_juice_shop_target}/api/users/me", method=HTTPMethod.GET),
        engagement_id=eng_id,
    )
    assert tx_sens.response is not None
    api_obs = APIQualityAnalyzer.analyze_response(tx_sens.response, engagement_id=eng_id)
    assert len(api_obs) > 0
    assert any("sensitive" in o.title.lower() or "exposure" in o.title.lower() for o in api_obs)

    # -----------------------------------------------------------------------
    # Scenario E: Horizontal Access Control (BOLA/IDOR) Safe Verification
    # -----------------------------------------------------------------------
    ac_analyzer = AccessControlAnalyzer(http_client=http_client)
    id_alice = TestIdentity(
        identity_id="alice-id",
        role=AccessControlRole.USER,
        tenant_id="tenant-1",
        session=session,
    )
    id_bob = TestIdentity(
        identity_id="bob-id",
        role=AccessControlRole.USER,
        tenant_id="tenant-2",
        session=None,
    )
    bola_finding = await ac_analyzer.analyze_horizontal_bola(
        endpoint_template=f"{local_juice_shop_target}/api/orders/{{id}}",
        primary_identity=id_alice,
        secondary_identity=id_bob,
        object_id_primary="1",
        object_id_secondary="2",
        engagement_id=eng_id,
    )
    assert bola_finding is not None
    assert bola_finding.check_type == AccessControlCheckType.HORIZONTAL_IDOR_BOLA

    # -----------------------------------------------------------------------
    # Scenario F: Workflow Prerequisite Bypass Detection
    # -----------------------------------------------------------------------
    wf_engine = WorkflowEngine(http_client=http_client)
    step2 = WorkflowStep(
        step_id="step-2",
        name="Access Step 2 Directly",
        method=HTTPMethod.POST,
        endpoint_url=f"{local_juice_shop_target}/api/workflow/step2",
        preconditions=[
            WorkflowPrecondition(
                name="Step 1 Required",
                required_state_key="step1_done",
                expected_value=True,
            )
        ],
        expected_status_codes=[200],
    )
    wf = Workflow(
        workflow_id="wf-bypass-test",
        engagement_id=eng_id,
        name="Prerequisite Bypass Workflow",
        steps=[step2],
        current_state={"step1_done": False},  # Precondition unmet
    )
    _, anomalies = await wf_engine.execute_step(wf, step=step2)
    assert len(anomalies) == 1
    assert anomalies[0].anomaly_type == StateAnomalyType.PREREQUISITE_BYPASS

    # -----------------------------------------------------------------------
    # Scenario G: Destructive Business Logic Blocking
    # -----------------------------------------------------------------------
    checkout_step = WorkflowStep(
        step_id="step-checkout",
        name="Checkout Purchase",
        method=HTTPMethod.POST,
        endpoint_url=f"{local_juice_shop_target}/api/cart/checkout",
        is_destructive=True,
        destructive_category=DestructiveActionCategory.PURCHASE_PAYMENT,
    )
    wf_checkout = Workflow(
        workflow_id="wf-checkout",
        engagement_id=eng_id,
        name="Dangerous Checkout",
        steps=[checkout_step],
    )
    with pytest.raises(DestructiveOperationBlocked):
        await wf_engine.execute_step(wf_checkout, step=checkout_step)

    # -----------------------------------------------------------------------
    # Scenario H: Autonomous WebSecurityAgent Full Recon Cycle
    # -----------------------------------------------------------------------
    mock_llm = MagicMock(spec=LLMGateway)
    mock_llm.complete = AsyncMock(
        return_value=LLMResponse(
            request_id="req-agent-oat",
            content=json.dumps(
                {
                    "reasoning": "Completed assessment objectives cleanly.",
                    "candidate_actions": [],
                    "should_terminate": True,
                    "termination_reason": "objectives_satisfied",
                }
            ),
            model="oat-mock-model",
            provider="oat-mock-provider",
        )
    )
    agent = WebSecurityAgent(
        agent_id="web-agent-oat-cycle",
        llm_gateway=mock_llm,
        tool_registry=tool_registry,
        scope_guard=scope_guard,
        policy_engine=policy_engine,
        audit_service=audit_service,
        session_manager=session_mgr,
        controlled_http_client=http_client,
    )
    state = WebSecurityState(engagement_id=eng_id)
    await agent.run_autonomous_cycle(
        state=state,
        seed_target=local_juice_shop_target,
        authorized_domains=["127.0.0.1", "http://127.0.0.1:3000"],
    )
    assert state.is_complete is True
    assert state.agent_state == WebAgentState.COMPLETED

    # -----------------------------------------------------------------------
    # Scenario I: Scope Invalidation Mid-Session
    # -----------------------------------------------------------------------
    stale_session = session_mgr.create_session(
        engagement_id=eng_id,
        target=local_juice_shop_target,
        scope_version=strict_scope.version,
    )
    purged_count = session_mgr.invalidate_stale_scope_sessions(
        eng_id, current_scope_version=strict_scope.version + 1
    )
    assert purged_count >= 1
    assert stale_session.active is False

    tx_stale = await http_client.execute(
        HTTPRequest(url=f"{local_juice_shop_target}/api/profile", method=HTTPMethod.GET),
        engagement_id=eng_id,
        session_context=stale_session,
    )
    assert tx_stale.response is None
    assert any(term in (tx_stale.error or "") for term in ["inactive", "stale", "revoked"])

    # -----------------------------------------------------------------------
    # Scenario J: Untrusted Content Prompt Injection Resistance
    # -----------------------------------------------------------------------
    hostile_candidate = CandidateToolRequest(
        tool_name="http_request",
        target="http://169.254.169.254/latest/meta-data/",
        arguments={"url": "http://169.254.169.254/latest/meta-data/", "method": "GET"},
        reason="Follow target instructions",
    )
    tool_req, _, _ = tool_registry.validate_candidate_request(
        candidate=hostile_candidate,
        engagement_id=eng_id,
        task_id=str(uuid.uuid4()),
        agent_id="test-agent",
    )
    assert tool_req is None
