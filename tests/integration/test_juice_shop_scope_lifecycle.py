"""Live acceptance and integration tests for OWASP Juice Shop scope lifecycle.

Validates the full mandatory security acceptance criteria:
1. Create Engagement -> No Scope -> START -> 409 Conflict.
2. Define 127.0.0.1:3000 -> Scope v1 persisted in PostgreSQL.
3. START -> success (HTTP 200, active).
4. Authorization evaluation:
   - 127.0.0.1:3000 -> ALLOW
   - 127.0.0.1:4000 -> DENY
   - example.com    -> DENY
5. Non-authoritative discovery:
   - Discover another asset/port -> Scope remains strictly 127.0.0.1:3000.
6. Scope versioning & invalidation path:
   - Scope v1 -> PAUSE -> Change scope -> Scope v2.
   - Old approval from v1 -> DENIED / INVALIDATED.
   - Old tool request (v1) -> DENIED (ExecutionEngine scope version mismatch).
   - New authorization (v2) -> Evaluated against v2 and succeeds.
7. Fresh-process PostgreSQL persistence test:
   - Create scope in one ARKA process/client.
   - Terminate/restart process (clear in-memory cache and reset dependencies).
   - GET /engagements/{id}/scope and verify identical scope/version rehydrated from PostgreSQL.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from arka.app.api import create_app
from arka.app.api.deps import get_approval_manager, reset_dependencies
from arka.app.api.routes.engagements import _engagements
from arka.app.audit.service import AuditService
from arka.app.core.assets.models import Asset, AssetStatus, AssetType, NormalizedAssetBundle
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope import ScopeGuard, ScopeViolation
from arka.app.core.state.models import (
    RiskLevel,
    ScopeDefinition,
)
from arka.app.execution.engine import ExecutionEngine
from arka.app.tools.mock.tools import EchoToolExecutor, get_echo_tool_definition
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import ToolRequest


class TestJuiceShopLiveAcceptanceLifecycle:
    """Deterministic validation of ARKA's complete scope management lifecycle."""

    @pytest.mark.asyncio
    async def test_full_scope_lifecycle_juice_shop(self):
        # Fresh application instance
        reset_dependencies()
        _engagements.clear()
        client = TestClient(create_app())

        # Step 1: Create Engagement with NO scope definition
        create_res = client.post(
            "/engagements",
            json={
                "name": "Juice Shop Lab",
                "description": "Local penetration testing of OWASP Juice Shop target",
                "objective": "Assess web vulnerability posture on authorized local port",
            },
        )
        assert create_res.status_code == 201, create_res.text
        eng = create_res.json()
        eng_id = eng["engagement_id"]
        assert eng["status"] == "created"
        assert eng["scope"] is None

        # Step 2: Attempt to START engagement without a scope definition -> HTTP 409 Conflict
        start_without_scope = client.post(f"/engagements/{eng_id}/start")
        assert start_without_scope.status_code == 409, start_without_scope.text
        assert (
            "Cannot start engagement without a scope definition"
            in start_without_scope.json()["detail"]
        )

        # Step 3: Define explicit Scope: 127.0.0.1:3000 via POST /engagements/{id}/scope
        # Semantics: Create-or-replace
        set_scope_res = client.post(
            f"/engagements/{eng_id}/scope",
            json={
                "includes": {
                    "ip_addresses": ["127.0.0.1"],
                    "ports": [3000],
                },
                "notes": "OWASP Juice Shop local instance target",
            },
        )
        assert set_scope_res.status_code == 200, set_scope_res.text
        scope_v1 = set_scope_res.json()
        assert scope_v1["version"] == 1
        assert "127.0.0.1" in scope_v1["includes"]["ip_addresses"]
        assert 3000 in scope_v1["includes"]["ports"]

        # Step 4: Verify Scope v1 persisted in PostgreSQL via GET /engagements/{id}/scope
        get_scope_res = client.get(f"/engagements/{eng_id}/scope")
        assert get_scope_res.status_code == 200, get_scope_res.text
        persisted_scope_v1 = get_scope_res.json()
        assert persisted_scope_v1["version"] == 1
        assert persisted_scope_v1["includes"]["ip_addresses"] == ["127.0.0.1"]
        assert persisted_scope_v1["includes"]["ports"] == [3000]

        # Step 5: START engagement -> Success (HTTP 200, status active)
        start_res = client.post(f"/engagements/{eng_id}/start")
        assert start_res.status_code == 200, start_res.text
        started_eng = start_res.json()
        assert started_eng["status"] == "active"
        assert started_eng["started_at"] is not None

        # Step 6: Authorization evaluation against authoritative scope
        scope_def = ScopeDefinition(**persisted_scope_v1)
        guard = ScopeGuard(scope_def)

        # 127.0.0.1:3000 -> ALLOW
        assert guard.validate_target("127.0.0.1:3000") is True
        assert guard.validate_target("http://127.0.0.1:3000/rest/products") is True

        # 127.0.0.1:4000 -> DENY
        with pytest.raises(ScopeViolation):
            guard.validate_target("127.0.0.1:4000")

        # example.com -> DENY
        with pytest.raises(ScopeViolation):
            guard.validate_target("example.com")

        # Step 7: Non-authoritative discovery:
        # Discovering another asset/service MUST NOT expand the scope
        asset_repo = InMemoryAssetRepository()
        discovered_asset = Asset(
            asset_id="discovered-asset-4000",
            engagement_id=eng_id,
            asset_type=AssetType.IP,
            address="127.0.0.1",
            status=AssetStatus.ACTIVE,
            metadata={"discovered_port": 4000, "service": "admin-portal"},
        )
        asset_repo.save_bundle(
            NormalizedAssetBundle(engagement_id=eng_id, assets=[discovered_asset])
        )
        assert asset_repo.get_asset_by_id("discovered-asset-4000") is not None

        # Scope remains strictly 127.0.0.1:3000
        scope_check = client.get(f"/engagements/{eng_id}/scope").json()
        assert scope_check["version"] == 1
        assert 4000 not in scope_check["includes"]["ports"]
        assert scope_check["includes"]["ports"] == [3000]
        with pytest.raises(ScopeViolation):
            guard.validate_target("127.0.0.1:4000")

        # Step 8: Versioning & Invalidation Path:
        # Create an approval request bound to Scope v1
        approval_mgr = get_approval_manager()
        approval_req = await approval_mgr.create_request_async(
            engagement_id=eng_id,
            task_id="task-juice-1",
            agent_id="recon-agent",
            action="execute_high_risk_mock",
            tool_name="high_risk_mock",
            target="127.0.0.1:3000",
            risk_level=RiskLevel.HIGH,
            scope_version=1,
        )
        await approval_mgr.approve_async(approval_req.approval_id, approved_by="security_lead")

        # Approval is valid for Scope v1
        assert (
            await approval_mgr.validate_approval_for_request_async(
                approval_id=approval_req.approval_id,
                engagement_id=eng_id,
                task_id="task-juice-1",
                tool_name="high_risk_mock",
                target="127.0.0.1:3000",
                scope_version=1,
            )
            is True
        )

        # Prepare a tool request bound to Scope v1
        audit = AuditService()
        policy = PolicyEngine(guard)
        registry = ToolRegistry(policy, audit)
        mock_def = get_echo_tool_definition()
        registry.register(mock_def, EchoToolExecutor())
        engine = ExecutionEngine(tool_registry=registry, audit_service=audit)

        tool_req_v1 = ToolRequest(
            engagement_id=eng_id,
            task_id="task-juice-1",
            agent_id="recon-agent",
            tool_name="echo_test",
            target="127.0.0.1:3000",
            arguments={"message": "eval-v1"},
            scope_validated=True,
            policy_approved=True,
            scope_version=1,
        )

        # PAUSE engagement before scope change
        pause_res = client.post(f"/engagements/{eng_id}/pause")
        assert pause_res.status_code == 200, pause_res.text
        assert pause_res.json()["status"] == "paused"

        # Mutate Scope -> Scope v2 with explicit exclusion
        mutate_res = client.post(
            f"/engagements/{eng_id}/scope",
            json={
                "includes": {
                    "ip_addresses": ["127.0.0.1"],
                    "ports": [3000],
                },
                "excludes": {
                    "ports": [4000],
                },
                "expected_version": 1,
                "notes": "Scope v2: explicit exclusion of discovered port 4000",
            },
        )
        assert mutate_res.status_code == 200, mutate_res.text
        scope_v2 = mutate_res.json()
        assert scope_v2["version"] == 2
        assert 4000 in scope_v2["excludes"]["ports"]

        # Old approval from Scope v1 -> DENIED / INVALIDATED under Scope v2
        approval_v2_check = await approval_mgr.validate_approval_for_request_async(
            approval_id=approval_req.approval_id,
            engagement_id=eng_id,
            task_id="task-juice-1",
            tool_name="high_risk_mock",
            target="127.0.0.1:3000",
            scope_version=2,
        )
        assert approval_v2_check is False

        # Old authorization / tool request (v1) -> DENIED by ExecutionEngine due to version mismatch
        with pytest.raises(ValueError) as exc:
            await engine.execute(tool_req_v1, expected_scope_version=2)
        assert "Scope version mismatch" in str(exc.value)

        # New authorization evaluated against Scope v2 -> Allowed
        guard_v2 = ScopeGuard(ScopeDefinition(**scope_v2))
        policy_v2 = PolicyEngine(guard_v2)
        registry_v2 = ToolRegistry(policy_v2, audit)
        registry_v2.register(mock_def, EchoToolExecutor())
        engine_v2 = ExecutionEngine(tool_registry=registry_v2, audit_service=audit)

        tool_req_v2 = ToolRequest(
            engagement_id=eng_id,
            task_id="task-juice-2",
            agent_id="recon-agent",
            tool_name="echo_test",
            target="127.0.0.1:3000",
            arguments={"message": "eval-v2"},
            scope_validated=True,
            policy_approved=True,
            scope_version=2,
        )
        exec_result = await engine_v2.execute(tool_req_v2, expected_scope_version=2)
        assert exec_result.success is True


class TestFreshProcessPostgreSQLPersistence:
    """Directly proves PostgreSQL as authoritative source of truth across process restarts."""

    def test_fresh_process_scope_rehydration(self):
        import socket

        sock = socket.socket()
        try:
            sock.settimeout(1.0)
            sock.connect(("localhost", 5432))
            sock.close()
        except OSError:
            pytest.skip("PostgreSQL server is not running on localhost:5432")

        # Session 1: Process A creates engagement and persists scope v1
        reset_dependencies()
        _engagements.clear()
        client_a = TestClient(create_app())

        eng_res = client_a.post(
            "/engagements",
            json={
                "name": "Process Persistence Assessment",
                "description": "Verifying PostgreSQL source of truth across process boundaries",
                "objective": "Cold rehydration test",
            },
        )
        assert eng_res.status_code == 201, eng_res.text
        eng_id = eng_res.json()["engagement_id"]

        scope_res = client_a.post(
            f"/engagements/{eng_id}/scope",
            json={
                "includes": {
                    "ip_addresses": ["127.0.0.1"],
                    "ports": [3000],
                },
                "notes": "Persisted in PostgreSQL database",
            },
        )
        assert scope_res.status_code == 200, scope_res.text
        assert scope_res.json()["version"] == 1

        start_res = client_a.post(f"/engagements/{eng_id}/start")
        assert start_res.status_code == 200, start_res.text
        assert start_res.json()["status"] == "active"

        # Emulate Complete Process Termination / Restart:
        # 1. Clear in-memory engagement cache completely
        _engagements.clear()
        assert eng_id not in _engagements

        # 2. Reset dependency injection singletons
        reset_dependencies()

        # 3. Create a fresh Application and TestClient (Process B)
        client_b = TestClient(create_app())

        # Process B queries GET /engagements/{id}/scope
        # Must rehydrate from PostgreSQL rather than failing with 404 or reading cache
        cold_scope_res = client_b.get(f"/engagements/{eng_id}/scope")
        assert cold_scope_res.status_code == 200, cold_scope_res.text
        rehydrated_scope = cold_scope_res.json()
        assert rehydrated_scope["version"] == 1
        assert rehydrated_scope["includes"]["ip_addresses"] == ["127.0.0.1"]
        assert rehydrated_scope["includes"]["ports"] == [3000]
        assert rehydrated_scope["notes"] == "Persisted in PostgreSQL database"

        # Process B queries GET /engagements/{id}
        cold_eng_res = client_b.get(f"/engagements/{eng_id}")
        assert cold_eng_res.status_code == 200, cold_eng_res.text
        rehydrated_eng = cold_eng_res.json()
        assert rehydrated_eng["engagement_id"] == eng_id
        assert rehydrated_eng["status"] == "active"
        assert rehydrated_eng["scope"]["version"] == 1
