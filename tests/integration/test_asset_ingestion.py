"""Integration tests for the ARKA asset ingestion and evidence provenance pipeline.

Validates the full flow:
Tool Execution / EvidenceStore -> NmapParser -> AssetNormalizer -> AssetRepository
"""

from pathlib import Path

import pytest

from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.execution.evidence import EvidenceStore
from arka.app.tools.nmap.parser import parse_nmap_xml

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "nmap"


@pytest.fixture
def evidence_store() -> EvidenceStore:
    return EvidenceStore()


@pytest.fixture
def normalizer() -> AssetNormalizer:
    return AssetNormalizer()


@pytest.fixture
def asset_repo() -> InMemoryAssetRepository:
    return InMemoryAssetRepository()


class TestAssetIngestionPipeline:
    """Test full integration from raw evidence to canonical asset store."""

    def test_full_pipeline_with_evidence_verification(self, evidence_store, normalizer, asset_repo):
        # 1. Read fixture XML (simulating tool output)
        xml_content = (FIXTURES_DIR / "basic_scan.xml").read_text(encoding="utf-8")

        # 2. Record raw evidence in EvidenceStore
        ev_ref = evidence_store.record_evidence(
            execution_id="exec-e2e-1",
            request_id="req-e2e-1",
            engagement_id="eng-e2e-1",
            task_id="task-e2e-1",
            content=xml_content,
            evidence_type="raw_tool_output",
        )
        assert ev_ref.sha256 is not None
        assert evidence_store.verify_integrity(ev_ref.evidence_id) is True

        # 3. Parse XML
        nmap_res = parse_nmap_xml(xml_content)
        assert nmap_res.success is True

        # 4. Normalize into canonical bundle
        bundle = normalizer.normalize_nmap_result(
            result=nmap_res,
            engagement_id="eng-e2e-1",
            task_id="task-e2e-1",
            execution_id="exec-e2e-1",
            request_id="req-e2e-1",
            target="192.168.1.10",
            evidence_refs=[ev_ref.evidence_id],
        )

        # 5. Persist to repository
        asset_repo.save_bundle(bundle)

        # 6. Verify Asset Store & Provenance Linkage
        assets = asset_repo.get_assets_by_engagement("eng-e2e-1")
        assert len(assets) == 1
        asset = assets[0]
        assert asset.address == "192.168.1.10"
        assert ev_ref.evidence_id in asset.evidence_refs

        # Verify that we can retrieve and verify raw evidence from the asset's evidence ref
        stored_ev = evidence_store.get_evidence(asset.evidence_refs[0])
        assert stored_ev is not None
        assert stored_ev.sha256 == ev_ref.sha256
        assert stored_ev.execution_id == "exec-e2e-1"

        # Verify services
        services = asset_repo.get_services_by_asset(asset.asset_id)
        assert len(services) == 3
        ports = {s.port for s in services}
        assert ports == {22, 80, 443}

    def test_multi_scan_incremental_enrichment(self, normalizer, asset_repo):
        """Sequential scans against the same target enrich services and merge evidence."""
        # Scan 1: Basic scan (ports 22, 80, 443)
        xml1 = (FIXTURES_DIR / "basic_scan.xml").read_text(encoding="utf-8")
        res1 = parse_nmap_xml(xml1)
        bundle1 = normalizer.normalize_nmap_result(
            result=res1,
            engagement_id="eng-multi-scan",
            evidence_refs=["ev-scan-1"],
        )
        asset_repo.save_bundle(bundle1)

        assets_initial = asset_repo.get_assets_by_engagement("eng-multi-scan")
        assert len(assets_initial) == 1
        asset_id = assets_initial[0].asset_id

        # Scan 2: Script output scan (ports 80, 443 with NSE scripts)
        xml2 = (FIXTURES_DIR / "script_output.xml").read_text(encoding="utf-8")
        res2 = parse_nmap_xml(xml2)
        bundle2 = normalizer.normalize_nmap_result(
            result=res2,
            engagement_id="eng-multi-scan",
            evidence_refs=["ev-scan-2"],
        )
        asset_repo.save_bundle(bundle2)

        # Assets should remain 1 (deduplicated), with merged evidence refs
        assets_after = asset_repo.get_assets_by_engagement("eng-multi-scan")
        assert len(assets_after) == 1
        assert set(assets_after[0].evidence_refs) == {"ev-scan-1", "ev-scan-2"}

        # Services for port 443 should now have script banners from scan 2
        services_after = asset_repo.get_services_by_asset(asset_id)
        svc_443 = next(s for s in services_after if s.port == 443)
        assert svc_443.banner is not None
        assert "ssl-cert" in svc_443.banner or "nginx" in svc_443.banner
