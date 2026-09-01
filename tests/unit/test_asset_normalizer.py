"""Unit tests for AssetNormalizer and InMemoryAssetRepository."""

from pathlib import Path

import pytest

from arka.app.core.assets.models import AssetStatus
from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.tools.nmap.parser import parse_nmap_xml

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "nmap"


@pytest.fixture
def normalizer() -> AssetNormalizer:
    return AssetNormalizer()


class TestAssetNormalizer:
    """Test normalization of NmapResult outputs."""

    def test_normalize_basic_scan(self, normalizer):
        xml_content = (FIXTURES_DIR / "basic_scan.xml").read_text(encoding="utf-8")
        nmap_res = parse_nmap_xml(xml_content)

        bundle = normalizer.normalize_nmap_result(
            result=nmap_res,
            engagement_id="eng-100",
            task_id="task-100",
            execution_id="exec-100",
            request_id="req-100",
            target="192.168.1.10",
            evidence_refs=["sha256-ev-1"],
        )

        assert bundle.engagement_id == "eng-100"
        assert len(bundle.assets) == 1
        asset = bundle.assets[0]
        assert asset.address == "192.168.1.10"
        assert asset.address_type == "ipv4"
        assert asset.hostname == "webserver.example.com"
        assert asset.domain == "example.com"
        assert asset.status == AssetStatus.ACTIVE.value
        assert asset.source == "nmap"
        assert asset.evidence_refs == ["sha256-ev-1"]
        assert asset.metadata["task_id"] == "task-100"

        # Ports: 22 (open, ssh), 80 (open, http/nginx), 443 (closed)
        assert len(bundle.services) == 3
        svc_ports = {s.port: s for s in bundle.services}
        assert 22 in svc_ports
        assert svc_ports[22].service_name == "ssh"
        assert svc_ports[22].product == "OpenSSH"
        assert svc_ports[22].version == "9.6"
        assert "cpe:/a:openbsd:openssh:9.6" in svc_ports[22].cpe

        assert 80 in svc_ports
        assert svc_ports[80].service_name == "http"
        assert svc_ports[80].product == "nginx"
        assert svc_ports[80].version == "1.24.0"

        assert 443 in svc_ports
        assert svc_ports[443].state == "closed"

        # Technologies extracted from OpenSSH, nginx, and CPEs
        tech_names = {t.name for t in bundle.technologies}
        assert "OpenSSH" in tech_names
        assert "nginx" in tech_names

    def test_normalize_multi_host_scan(self, normalizer):
        xml_content = (FIXTURES_DIR / "multi_host.xml").read_text(encoding="utf-8")
        nmap_res = parse_nmap_xml(xml_content)

        bundle = normalizer.normalize_nmap_result(
            result=nmap_res,
            engagement_id="eng-multi",
            evidence_refs=["ev-multi"],
        )

        assert len(bundle.assets) == 3
        addresses = {a.address for a in bundle.assets}
        assert "192.168.1.1" in addresses
        assert "192.168.1.10" in addresses
        assert "192.168.1.20" in addresses

    def test_normalize_script_output_scan(self, normalizer):
        xml_content = (FIXTURES_DIR / "script_output.xml").read_text(encoding="utf-8")
        nmap_res = parse_nmap_xml(xml_content)

        bundle = normalizer.normalize_nmap_result(
            result=nmap_res,
            engagement_id="eng-script",
            evidence_refs=["ev-script"],
        )

        assert len(bundle.assets) == 1
        assert len(bundle.services) == 2
        svc_443 = next(s for s in bundle.services if s.port == 443)
        assert svc_443.banner is not None
        assert "ssl-cert" in svc_443.banner or "nginx" in svc_443.banner
        # Linux kernel CPE technology extracted
        tech_cpes = [cpe for t in bundle.technologies for cpe in t.cpe]
        assert "cpe:/o:linux:linux_kernel" in tech_cpes

    def test_normalize_empty_scan(self, normalizer):
        xml_content = (FIXTURES_DIR / "empty_result.xml").read_text(encoding="utf-8")
        nmap_res = parse_nmap_xml(xml_content)

        bundle = normalizer.normalize_nmap_result(
            result=nmap_res,
            engagement_id="eng-empty",
        )
        assert len(bundle.assets) == 0
        assert len(bundle.services) == 0
        assert len(bundle.technologies) == 0

    def test_deduplication_of_duplicate_hosts_in_single_scan(self, normalizer):
        from arka.app.tools.nmap.schemas import NmapHost, NmapPort, NmapResult

        host1 = NmapHost(
            address="10.0.0.1",
            hostnames=["web.corp"],
            status="up",
            ports=[NmapPort(port=80, protocol="tcp", state="open")],
        )
        host2 = NmapHost(
            address="10.0.0.1",
            hostnames=["web.corp", "web-alias.corp"],
            status="up",
            ports=[NmapPort(port=443, protocol="tcp", state="open")],
        )
        res = NmapResult(hosts=[host1, host2])

        bundle = normalizer.normalize_nmap_result(
            result=res,
            engagement_id="eng-dedup",
            evidence_refs=["ev-1", "ev-2"],
        )

        assert len(bundle.assets) == 1
        assert len(bundle.services) == 2
        assert set(bundle.assets[0].evidence_refs) == {"ev-1", "ev-2"}

    def test_conflict_recording_on_differing_service_versions(self, normalizer):
        from arka.app.tools.nmap.schemas import (
            NmapHost,
            NmapPort,
            NmapResult,
            NmapService,
        )

        host1 = NmapHost(
            address="10.0.0.1",
            status="up",
            ports=[
                NmapPort(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service=NmapService(name="http", product="Apache", version="2.4.41"),
                )
            ],
        )
        host2 = NmapHost(
            address="10.0.0.1",
            status="up",
            ports=[
                NmapPort(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service=NmapService(name="http", product="Nginx", version="1.24.0"),
                )
            ],
        )
        res = NmapResult(hosts=[host1, host2])

        bundle = normalizer.normalize_nmap_result(
            result=res,
            engagement_id="eng-conflict",
            evidence_refs=["ev-conflict"],
        )

        assert len(bundle.assets) == 1
        assert len(bundle.services) == 1
        assert len(bundle.conflicts) >= 1
        field_names = {c.field_name for c in bundle.conflicts}
        assert "product" in field_names or "version" in field_names


class TestInMemoryAssetRepository:
    """Test InMemoryAssetRepository persistence and querying."""

    def test_repository_save_and_retrieve(self, normalizer):
        repo = InMemoryAssetRepository()
        xml_content = (FIXTURES_DIR / "basic_scan.xml").read_text(encoding="utf-8")
        nmap_res = parse_nmap_xml(xml_content)

        bundle = normalizer.normalize_nmap_result(
            result=nmap_res,
            engagement_id="eng-repo",
            evidence_refs=["ev-repo-1"],
        )
        repo.save_bundle(bundle)

        assets = repo.get_assets_by_engagement("eng-repo")
        assert len(assets) == 1
        asset_id = assets[0].asset_id

        services = repo.get_services_by_asset(asset_id)
        assert len(services) == 3

        technologies = repo.get_technologies_by_asset(asset_id)
        assert len(technologies) >= 2

        # Engagement isolation check
        other_assets = repo.get_assets_by_engagement("eng-other")
        assert len(other_assets) == 0
