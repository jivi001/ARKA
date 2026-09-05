"""Unit tests for Recon Correlation Engine (Phase 2.2.9)."""

from __future__ import annotations

from arka.app.core.assets.identity import (
    generate_asset_id,
    generate_endpoint_id,
    generate_service_id,
    generate_technology_id,
)
from arka.app.core.assets.models import (
    Asset,
    AssetType,
    Endpoint,
    Finding,
    NormalizedAssetBundle,
    Service,
    Technology,
)
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.correlation import CorrelationEngine
from arka.app.core.state.models import new_id


def test_correlation_engine_asset_merging() -> None:
    """Test correlation engine merges duplicate assets and combines evidence."""
    engine = CorrelationEngine()
    engagement_id = new_id()

    asset_id = generate_asset_id(engagement_id, AssetType.IP.value, "192.168.1.10")
    b1 = NormalizedAssetBundle(
        engagement_id=engagement_id,
        assets=[
            Asset(
                asset_id=asset_id,
                engagement_id=engagement_id,
                asset_type=AssetType.IP,
                address="192.168.1.10",
                status="discovered",
                source="amass",
                evidence_refs=["sha256:ref1"],
            )
        ],
    )
    b2 = NormalizedAssetBundle(
        engagement_id=engagement_id,
        assets=[
            Asset(
                asset_id=asset_id,
                engagement_id=engagement_id,
                asset_type=AssetType.IP,
                address="192.168.1.10",
                status="active",
                source="nmap",
                evidence_refs=["sha256:ref2"],
            )
        ],
    )

    merged = engine.correlate_bundle(b1, b2)
    assert len(merged.assets) == 1
    m_asset = merged.assets[0]
    assert m_asset.status == "active"  # updated from active confirmation
    assert "sha256:ref1" in m_asset.evidence_refs
    assert "sha256:ref2" in m_asset.evidence_refs


def test_correlation_engine_service_conflict_detection() -> None:
    """Test correlation engine detects conflicts in service versions without dropping history."""
    engine = CorrelationEngine()
    engagement_id = new_id()
    asset_id = generate_asset_id(engagement_id, AssetType.IP.value, "192.168.1.10")
    svc_id = generate_service_id(engagement_id, asset_id, "tcp", 80)

    b1 = NormalizedAssetBundle(
        engagement_id=engagement_id,
        services=[
            Service(
                service_id=svc_id,
                asset_id=asset_id,
                engagement_id=engagement_id,
                port=80,
                protocol="tcp",
                product="Apache",
                version="2.4.41",
                source="nmap",
                evidence_refs=["sha256:nmap1"],
            )
        ],
    )
    b2 = NormalizedAssetBundle(
        engagement_id=engagement_id,
        services=[
            Service(
                service_id=svc_id,
                asset_id=asset_id,
                engagement_id=engagement_id,
                port=80,
                protocol="tcp",
                product="nginx",
                version="1.18.0",
                source="whatweb",
                evidence_refs=["sha256:whatweb1"],
            )
        ],
    )

    merged = engine.correlate_bundle(b1, b2)
    assert len(merged.services) == 1
    # Both product conflict and version conflict should be detected
    assert len(merged.conflicts) == 2
    c_fields = {c.field_name for c in merged.conflicts}
    assert "product" in c_fields
    assert "version" in c_fields
    assert merged.conflicts[0].entity_id == svc_id


def test_correlation_engine_technology_and_endpoint_merging() -> None:
    """Test merging of technologies and endpoints."""
    engine = CorrelationEngine()
    engagement_id = new_id()
    asset_id = generate_asset_id(engagement_id, AssetType.HOST.value, "example.com")

    t_id = generate_technology_id(engagement_id, asset_id, None, "WordPress", "6.2")
    ep_id = generate_endpoint_id(engagement_id, asset_id, "http", "example.com", 80, "/admin")

    b1 = NormalizedAssetBundle(
        engagement_id=engagement_id,
        technologies=[
            Technology(
                technology_id=t_id,
                engagement_id=engagement_id,
                asset_id=asset_id,
                name="WordPress",
                version="6.2",
                source="whatweb",
                evidence_refs=["sha256:ww1"],
            )
        ],
        endpoints=[
            Endpoint(
                endpoint_id=ep_id,
                engagement_id=engagement_id,
                asset_id=asset_id,
                scheme="http",
                host="example.com",
                port=80,
                path="/admin",
                source="ffuf",
                evidence_refs=["sha256:ffuf1"],
            )
        ],
    )

    b2 = NormalizedAssetBundle(
        engagement_id=engagement_id,
        technologies=[
            Technology(
                technology_id=t_id,
                engagement_id=engagement_id,
                asset_id=asset_id,
                name="WordPress",
                version="6.2",
                source="nuclei",
                evidence_refs=["sha256:nuc1"],
            )
        ],
        endpoints=[
            Endpoint(
                endpoint_id=ep_id,
                engagement_id=engagement_id,
                asset_id=asset_id,
                scheme="http",
                host="example.com",
                port=80,
                path="/admin",
                source="ffuf",
                evidence_refs=["sha256:ffuf2"],
            )
        ],
    )

    merged = engine.correlate_bundle(b1, b2)
    assert len(merged.technologies) == 1
    assert len(merged.technologies[0].evidence_refs) == 2
    assert len(merged.endpoints) == 1
    assert len(merged.endpoints[0].evidence_refs) == 2


def test_correlation_engine_correlate_repository() -> None:
    """Test correlate_repository generates accurate summary statistics."""
    engine = CorrelationEngine()
    repo = InMemoryAssetRepository()
    engagement_id = new_id()

    asset_id = generate_asset_id(engagement_id, AssetType.IP.value, "10.0.0.1")
    repo.save_bundle(
        NormalizedAssetBundle(
            engagement_id=engagement_id,
            assets=[
                Asset(
                    asset_id=asset_id,
                    engagement_id=engagement_id,
                    asset_type=AssetType.IP,
                    address="10.0.0.1",
                    source="nmap",
                )
            ],
            services=[
                Service(
                    service_id=generate_service_id(engagement_id, asset_id, "tcp", 22),
                    asset_id=asset_id,
                    engagement_id=engagement_id,
                    port=22,
                    protocol="tcp",
                    source="nmap",
                )
            ],
            findings=[
                Finding(
                    engagement_id=engagement_id,
                    asset_id=asset_id,
                    title="OpenSSH Vulnerability",
                    severity="high",
                    source="nuclei",
                )
            ],
        )
    )

    report = engine.correlate_repository(repo, engagement_id)
    assert report.summary.total_assets == 1
    assert report.summary.total_services == 1
    assert report.summary.total_findings == 1
    assert "nmap" in report.summary.sources
    assert "nuclei" in report.summary.sources
