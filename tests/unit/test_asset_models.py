"""Unit tests for ARKA canonical asset models and deterministic identity."""

import uuid

import pytest

from arka.app.core.assets.identity import (
    extract_domain_from_hostname,
    generate_asset_id,
    generate_endpoint_id,
    generate_service_id,
    generate_technology_id,
    normalize_domain,
    normalize_hostname,
    normalize_ip,
    normalize_protocol,
    normalize_url,
)
from arka.app.core.assets.models import (
    Asset,
    AssetStatus,
    AssetType,
    Endpoint,
    NormalizedAssetBundle,
    ObservationConflict,
    Service,
    Technology,
)


class TestNormalizationHelpers:
    """Test target property normalization functions."""

    def test_normalize_ipv4_standard(self):
        norm, addr_type = normalize_ip("192.168.1.1")
        assert norm == "192.168.1.1"
        assert addr_type == "ipv4"

    def test_normalize_ipv4_leading_zeros(self):
        norm, addr_type = normalize_ip("192.168.001.010")
        assert norm == "192.168.1.10"
        assert addr_type == "ipv4"

    def test_normalize_ipv6_full(self):
        norm, addr_type = normalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert norm == "2001:db8:85a3::8a2e:370:7334"
        assert addr_type == "ipv6"

    def test_normalize_ipv6_bracketed(self):
        norm, addr_type = normalize_ip("[fe80::1]")
        assert norm == "fe80::1"
        assert addr_type == "ipv6"

    def test_normalize_invalid_ip_raises_value_error(self):
        with pytest.raises(ValueError):
            normalize_ip("999.999.999.999")
        with pytest.raises(ValueError):
            normalize_ip("example.com")

    def test_normalize_domain_and_hostname(self):
        assert normalize_domain("  EXAMPLE.COM.  ") == "example.com"
        assert normalize_hostname("Web-01.Internal.Corp.  ") == "web-01.internal.corp"

    def test_extract_domain_from_hostname(self):
        assert extract_domain_from_hostname("web.sub.example.com") == "example.com"
        assert extract_domain_from_hostname("example.com") == "example.com"
        assert extract_domain_from_hostname("localhost") is None
        assert extract_domain_from_hostname("192.168.1.1") is None

    def test_normalize_url(self):
        scheme, host, port, path = normalize_url("HTTPS://Example.COM:8443/api/v1//users?query=1")
        assert scheme == "https"
        assert host == "example.com"
        assert port == 8443
        assert path == "/api/v1/users"

        # Default http/https port inference
        scheme, host, port, path = normalize_url("http://api.example.com")
        assert scheme == "http"
        assert port == 80
        assert path == "/"

    def test_normalize_protocol(self):
        assert normalize_protocol("  TCP ") == "tcp"
        assert normalize_protocol("UDP") == "udp"


class TestDeterministicIdentity:
    """Test deterministic UUID generation rules."""

    def test_asset_id_is_deterministic_and_uuid(self):
        id1 = generate_asset_id("eng-1", "ip", "192.168.1.1")
        id2 = generate_asset_id("eng-1", "ip", "192.168.1.1")
        assert id1 == id2
        # Must parse as valid UUID
        parsed_uuid = uuid.UUID(id1)
        assert parsed_uuid.version == 5

    def test_asset_id_isolated_by_engagement(self):
        id_eng1 = generate_asset_id("eng-1", "ip", "192.168.1.1")
        id_eng2 = generate_asset_id("eng-2", "ip", "192.168.1.1")
        assert id_eng1 != id_eng2

    def test_asset_id_case_insensitive(self):
        id1 = generate_asset_id("eng-1", "domain", "EXAMPLE.COM")
        id2 = generate_asset_id("eng-1", "domain", "example.com")
        assert id1 == id2

    def test_service_id_deterministic(self):
        asset_id = generate_asset_id("eng-1", "ip", "10.0.0.1")
        svc1 = generate_service_id("eng-1", asset_id, "TCP", 80)
        svc2 = generate_service_id("eng-1", asset_id, "tcp", 80)
        assert svc1 == svc2
        assert uuid.UUID(svc1).version == 5

    def test_technology_id_deterministic(self):
        asset_id = generate_asset_id("eng-1", "ip", "10.0.0.1")
        svc_id = generate_service_id("eng-1", asset_id, "tcp", 80)
        t1 = generate_technology_id("eng-1", asset_id, svc_id, "Nginx", "1.24.0")
        t2 = generate_technology_id("eng-1", asset_id, svc_id, "nginx", "1.24.0")
        assert t1 == t2

    def test_endpoint_id_deterministic(self):
        asset_id = generate_asset_id("eng-1", "ip", "10.0.0.1")
        ep1 = generate_endpoint_id("eng-1", asset_id, "https", "example.com", 443, "/api/login")
        ep2 = generate_endpoint_id("eng-1", asset_id, "HTTPS", "EXAMPLE.COM", 443, "/api/login")
        assert ep1 == ep2


class TestCanonicalDomainModels:
    """Test Pydantic model instantiations, constraints, and bundling."""

    def test_asset_model_instantiation(self):
        asset_id = generate_asset_id("eng-1", "ip", "192.168.1.10")
        asset = Asset(
            asset_id=asset_id,
            engagement_id="eng-1",
            asset_type=AssetType.IP,
            address="192.168.1.10",
            address_type="ipv4",
            hostname="web.example.com",
            domain="example.com",
            status=AssetStatus.ACTIVE.value,
            source="nmap",
            confidence=1.0,
            evidence_refs=["ev-123"],
            metadata={"os": "Linux"},
        )
        assert asset.asset_id == asset_id
        assert asset.asset_type == AssetType.IP
        assert asset.confidence == 1.0
        assert "ev-123" in asset.evidence_refs

    def test_service_model_instantiation(self):
        asset_id = generate_asset_id("eng-1", "ip", "192.168.1.10")
        service_id = generate_service_id("eng-1", asset_id, "tcp", 443)
        service = Service(
            service_id=service_id,
            asset_id=asset_id,
            engagement_id="eng-1",
            port=443,
            protocol="tcp",
            state="open",
            service_name="https",
            product="nginx",
            version="1.24.0",
            cpe=["cpe:/a:nginx:nginx:1.24.0"],
            banner="nginx/1.24.0",
            source="nmap",
            confidence=1.0,
            evidence_refs=["ev-123"],
            metadata={},
        )
        assert service.service_id == service_id
        assert service.port == 443
        assert service.cpe == ["cpe:/a:nginx:nginx:1.24.0"]

    def test_technology_model_instantiation(self):
        asset_id = generate_asset_id("eng-1", "ip", "192.168.1.10")
        tech_id = generate_technology_id("eng-1", asset_id, None, "Linux Kernel", None)
        tech = Technology(
            technology_id=tech_id,
            engagement_id="eng-1",
            asset_id=asset_id,
            name="Linux Kernel",
            cpe=["cpe:/o:linux:linux_kernel"],
            source="nmap",
            confidence=0.9,
            evidence_refs=["ev-123"],
        )
        assert tech.technology_id == tech_id
        assert tech.name == "Linux Kernel"
        assert tech.confidence == 0.9

    def test_endpoint_model_instantiation(self):
        asset_id = generate_asset_id("eng-1", "ip", "192.168.1.10")
        ep_id = generate_endpoint_id("eng-1", asset_id, "http", "example.com", 80, "/admin")
        ep = Endpoint(
            endpoint_id=ep_id,
            engagement_id="eng-1",
            asset_id=asset_id,
            scheme="http",
            host="example.com",
            port=80,
            path="/admin",
            query_metadata={"auth_required": True},
            source="ffuf",
            confidence=1.0,
            evidence_refs=["ev-456"],
        )
        assert ep.endpoint_id == ep_id
        assert ep.path == "/admin"

    def test_observation_conflict_and_bundle(self):
        conflict = ObservationConflict(
            engagement_id="eng-1",
            entity_type="service",
            entity_id="svc-1",
            field_name="version",
            existing_value="1.20",
            observed_value="1.24",
            source="nmap",
            evidence_refs=["ev-789"],
        )
        bundle = NormalizedAssetBundle(
            engagement_id="eng-1",
            assets=[],
            services=[],
            technologies=[],
            endpoints=[],
            conflicts=[conflict],
        )
        assert len(bundle.conflicts) == 1
        assert bundle.conflicts[0].field_name == "version"
