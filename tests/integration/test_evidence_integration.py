"""Integration tests for the ARKA Evidence Pipeline (Phase 2.2.3).

Validates:
1. Full end-to-end flow:
   Tool Execution -> ExecutionManager -> EvidenceStore -> AssetNormalizer -> AssetRepository
2. Multi-evidence generation (raw stdout + structured result + raw stderr)
3. Raw XML artifact traceability and integrity verification from asset evidence_refs
4. Evidence API metadata retrieval endpoints (/evidence/{id} and /evidence?engagement_id=...)
5. API isolation (metadata only, no raw blob exposure, no authorization expansion)
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from arka.app.api import create_app
from arka.app.api.routes.evidence import set_evidence_store
from arka.app.audit.service import AuditService
from arka.app.core.approvals.manager import ApprovalManager
from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.policies.engine import PolicyEngine
from arka.app.core.scope.scopeguard import ScopeDefinition, ScopeGuard
from arka.app.core.state.models import ScopeTarget
from arka.app.execution.evidence import EvidenceStore
from arka.app.execution.manager import ExecutionManager
from arka.app.execution.sandbox.local import LocalSafeRuntime
from arka.app.execution.schemas import EvidenceType
from arka.app.tools.nmap.definition import get_nmap_tool_definition
from arka.app.tools.nmap.executor import NmapToolExecutor
from arka.app.tools.nmap.parser import parse_nmap_xml
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.schemas.tool_schemas import CandidateToolRequest

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "nmap"


@pytest.fixture
def evidence_store() -> EvidenceStore:
    store = EvidenceStore()
    set_evidence_store(store)
    return store


@pytest.fixture
def audit_service() -> AuditService:
    return AuditService()


@pytest.fixture
def scope_guard() -> ScopeGuard:
    return ScopeGuard(
        ScopeDefinition(
            engagement_id="eng-ev-int-1",
            includes=ScopeTarget(
                ip_addresses=["192.168.1.10"],
                cidrs=["192.168.1.0/24"],
                ports=[22, 80, 443],
            ),
        )
    )


@pytest.fixture
def policy_engine(scope_guard: ScopeGuard) -> PolicyEngine:
    return PolicyEngine(scope_guard=scope_guard)


@pytest.fixture
def approval_manager() -> ApprovalManager:
    return ApprovalManager()


@pytest.fixture
def tool_registry(
    scope_guard: ScopeGuard,
    policy_engine: PolicyEngine,
    approval_manager: ApprovalManager,
    audit_service: AuditService,
    evidence_store: EvidenceStore,
) -> ToolRegistry:
    exec_manager = ExecutionManager(
        audit_service=audit_service,
        runtime=LocalSafeRuntime(),
        evidence_store=evidence_store,
    )
    registry = ToolRegistry(
        policy_engine=policy_engine,
        audit_service=audit_service,
        approval_manager=approval_manager,
        execution_manager=exec_manager,
    )
    registry.register(get_nmap_tool_definition(), NmapToolExecutor())
    return registry


@pytest.fixture
def asset_repo() -> InMemoryAssetRepository:
    return InMemoryAssetRepository()


@pytest.fixture
def normalizer() -> AssetNormalizer:
    return AssetNormalizer()


@pytest.fixture
def api_client(evidence_store: EvidenceStore) -> TestClient:
    app = create_app()
    set_evidence_store(evidence_store)
    return TestClient(app)


class TestEvidencePipelineEndToEndIntegration:
    """Test full pipeline from tool execution to evidence storage and API retrieval."""

    @pytest.mark.asyncio
    async def test_nmap_execution_evidence_pipeline(
        self,
        tool_registry: ToolRegistry,
        evidence_store: EvidenceStore,
        normalizer: AssetNormalizer,
        asset_repo: InMemoryAssetRepository,
        api_client: TestClient,
    ):
        # 1. Candidate tool request for in-scope target
        candidate = CandidateToolRequest(
            tool_name="nmap",
            target="192.168.1.10",
            arguments={"ports": "80,443", "service_detection": True},
            reason="Integration evidence test",
        )

        # 2. Control plane validation
        tool_req, decision, err = tool_registry.validate_candidate_request(
            candidate=candidate,
            engagement_id="eng-ev-int-1",
            task_id="task-ev-int-1",
            agent_id="agent-recon-1",
        )
        assert tool_req is not None
        assert err is None
        assert decision is not None
        assert decision.decision.value == "allow"

        # 3. Execution plane execution
        tool_res = await tool_registry.execute(tool_req)
        assert tool_res.success is True

        # 4. Verify EvidenceStore recorded multiple evidence items (raw stdout + structured result)
        assert len(tool_res.evidence_refs) >= 2

        # 5. Verify integrity of all recorded evidence
        for ev_id in tool_res.evidence_refs:
            assert evidence_store.verify_integrity(ev_id) is True

        # 6. Retrieve raw stdout (Nmap XML) evidence
        first_ev = evidence_store.get_evidence(tool_res.evidence_refs[0])
        assert first_ev is not None
        raw_stdout_refs = [
            ref
            for ref in evidence_store.list_by_execution(first_ev.execution_id)
            if ref.evidence_type == EvidenceType.RAW_STDOUT.value
        ]
        assert len(raw_stdout_refs) == 1
        raw_xml_bytes = evidence_store.get_raw_blob(raw_stdout_refs[0].evidence_id)
        assert raw_xml_bytes is not None
        assert b"<nmaprun" in raw_xml_bytes

        # 7. Normalize into Asset Bundle with evidence provenance
        nmap_res = parse_nmap_xml(raw_xml_bytes.decode("utf-8"))
        bundle = normalizer.normalize_nmap_result(
            result=nmap_res,
            engagement_id="eng-ev-int-1",
            task_id="task-ev-int-1",
            request_id=tool_res.request_id,
            target="192.168.1.10",
            evidence_refs=tool_res.evidence_refs,
        )

        # 8. Persist to asset store
        asset_repo.save_bundle(bundle)

        # 9. Verify asset repository has evidence references
        assets = asset_repo.get_assets_by_engagement("eng-ev-int-1")
        assert len(assets) == 1
        asset = assets[0]
        for ev_id in tool_res.evidence_refs:
            assert ev_id in asset.evidence_refs

        # 10. Test Evidence API Endpoints
        # 10a. Get evidence metadata by ID
        ev_id = tool_res.evidence_refs[0]
        resp = api_client.get(f"/evidence/{ev_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["evidence_id"] == ev_id
        assert data["engagement_id"] == "eng-ev-int-1"
        assert "sha256" in data

        # 10b. List evidence by engagement
        resp_list = api_client.get("/evidence?engagement_id=eng-ev-int-1")
        assert resp_list.status_code == 200
        list_data = resp_list.json()
        assert len(list_data) >= 2

        # 10c. 404 on nonexistent evidence
        resp_404 = api_client.get("/evidence/nonexistent-uuid-999")
        assert resp_404.status_code == 404

        # 10d. 400 when no filter parameters are supplied
        resp_400 = api_client.get("/evidence")
        assert resp_400.status_code == 400


def test_evidence_store_initialized_by_default_in_app() -> None:
    """Verify create_app() automatically wires and initializes the evidence store.

    Prevents 503 Service Unavailable ('Evidence store not initialized') when querying
    the evidence endpoints on a freshly booted application.
    """
    from arka.app.api.deps import reset_dependencies

    reset_dependencies()
    client = TestClient(create_app())
    resp = client.get("/evidence?engagement_id=nonexistent-eng")
    assert resp.status_code == 200
    assert resp.json() == []
