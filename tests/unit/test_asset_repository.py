"""Unit tests for AssetRepository and InMemoryAssetRepository."""

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from arka.app.core.assets.models import (
    Asset,
    AssetStatus,
    AssetType,
    Endpoint,
    NormalizedAssetBundle,
    Service,
    Technology,
    utc_now,
)
from arka.app.core.assets.repository import AssetRepository, InMemoryAssetRepository
from arka.app.database.models import (
    AssetDB,
    EndpointDB,
    ServiceDB,
    TechnologyDB,
)


@pytest.fixture
def sample_bundle() -> NormalizedAssetBundle:
    asset_id = str(uuid.uuid4())
    svc_id = str(uuid.uuid4())
    tech_id = str(uuid.uuid4())
    ep_id = str(uuid.uuid4())
    eng_id = str(uuid.uuid4())

    asset = Asset(
        asset_id=asset_id,
        engagement_id=eng_id,
        first_seen=utc_now(),
        last_seen=utc_now(),
        asset_type=AssetType.IP,
        address="192.168.1.100",
        address_type="ipv4",
        hostname="server.corp",
        domain="corp",
        status=AssetStatus.ACTIVE.value,
        source="nmap",
        confidence=1.0,
        evidence_refs=["ev-1"],
        metadata={"note": "primary"},
    )
    svc = Service(
        service_id=svc_id,
        asset_id=asset_id,
        engagement_id=eng_id,
        port=80,
        protocol="tcp",
        state="open",
        service_name="http",
        product="nginx",
        version="1.24.0",
        cpe=["cpe:/a:nginx:nginx:1.24.0"],
        banner="nginx 1.24",
        source="nmap",
        confidence=1.0,
        evidence_refs=["ev-1"],
    )
    tech = Technology(
        technology_id=tech_id,
        engagement_id=eng_id,
        asset_id=asset_id,
        service_id=svc_id,
        name="nginx",
        version="1.24.0",
        cpe=["cpe:/a:nginx:nginx:1.24.0"],
        source="nmap",
        confidence=1.0,
        evidence_refs=["ev-1"],
    )
    ep = Endpoint(
        endpoint_id=ep_id,
        engagement_id=eng_id,
        asset_id=asset_id,
        scheme="http",
        host="server.corp",
        port=80,
        path="/api/status",
        query_metadata={},
        source="ffuf",
        confidence=1.0,
        evidence_refs=["ev-2"],
    )

    return NormalizedAssetBundle(
        engagement_id=eng_id,
        assets=[asset],
        services=[svc],
        technologies=[tech],
        endpoints=[ep],
        conflicts=[],
    )


class TestInMemoryAssetRepositoryMethods:
    def test_crud_and_lookups(self, sample_bundle):
        repo = InMemoryAssetRepository()
        repo.save_bundle(sample_bundle)

        eng_id = sample_bundle.engagement_id
        asset = sample_bundle.assets[0]

        # Lookups
        assets = repo.get_assets_by_engagement(eng_id)
        assert len(assets) == 1
        assert assets[0].asset_id == asset.asset_id

        found_asset = repo.get_asset_by_id(asset.asset_id)
        assert found_asset is not None
        assert found_asset.address == "192.168.1.100"

        services = repo.get_services_by_asset(asset.asset_id)
        assert len(services) == 1
        assert services[0].port == 80

        technologies = repo.get_technologies_by_asset(asset.asset_id)
        assert len(technologies) == 1
        assert technologies[0].name == "nginx"

        endpoints = repo.get_endpoints_by_asset(asset.asset_id)
        assert len(endpoints) == 1
        assert endpoints[0].path == "/api/status"

        # Nonexistent lookup
        assert repo.get_asset_by_id("nonexistent") is None


class TestSQLAlchemyAssetRepository:
    """Test AssetRepository queries and execution with mocked AsyncSession."""

    @pytest.mark.asyncio
    async def test_save_bundle_executes_upserts(self, sample_bundle):
        session = AsyncMock()
        repo = AssetRepository(session)

        await repo.save_bundle(sample_bundle)

        # 4 statements executed: asset, service, technology, endpoint + 1 flush
        assert session.execute.call_count == 4
        assert session.flush.call_count == 1

    @pytest.mark.asyncio
    async def test_get_assets_by_engagement(self, sample_bundle):
        session = AsyncMock()
        repo = AssetRepository(session)

        mock_row = MagicMock(spec=AssetDB)
        mock_row.id = uuid.UUID(sample_bundle.assets[0].asset_id)
        mock_row.engagement_id = uuid.UUID(sample_bundle.engagement_id)
        mock_row.first_seen = utc_now()
        mock_row.last_seen = utc_now()
        mock_row.asset_type = "ip"
        mock_row.address = "192.168.1.100"
        mock_row.address_type = "ipv4"
        mock_row.hostname = "server.corp"
        mock_row.domain = "corp"
        mock_row.status = "active"
        mock_row.source = "nmap"
        mock_row.confidence = 1.0
        mock_row.evidence_refs = ["ev-1"]
        mock_row.metadata_ = {}

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_row]
        session.execute.return_value = mock_result

        assets = await repo.get_assets_by_engagement(sample_bundle.engagement_id)
        assert len(assets) == 1
        assert assets[0].address == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_get_asset_by_id(self, sample_bundle):
        session = AsyncMock()
        repo = AssetRepository(session)

        mock_row = MagicMock(spec=AssetDB)
        mock_row.id = uuid.UUID(sample_bundle.assets[0].asset_id)
        mock_row.engagement_id = uuid.UUID(sample_bundle.engagement_id)
        mock_row.first_seen = utc_now()
        mock_row.last_seen = utc_now()
        mock_row.asset_type = "ip"
        mock_row.address = "192.168.1.100"
        mock_row.address_type = "ipv4"
        mock_row.hostname = "server.corp"
        mock_row.domain = "corp"
        mock_row.status = "active"
        mock_row.source = "nmap"
        mock_row.confidence = 1.0
        mock_row.evidence_refs = ["ev-1"]
        mock_row.metadata_ = {}

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_row
        session.execute.return_value = mock_result

        asset = await repo.get_asset_by_id(sample_bundle.assets[0].asset_id)
        assert asset is not None
        assert asset.address == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_get_services_by_asset(self, sample_bundle):
        session = AsyncMock()
        repo = AssetRepository(session)

        mock_row = MagicMock(spec=ServiceDB)
        mock_row.id = uuid.UUID(sample_bundle.services[0].service_id)
        mock_row.asset_id = uuid.UUID(sample_bundle.assets[0].asset_id)
        mock_row.engagement_id = uuid.UUID(sample_bundle.engagement_id)
        mock_row.port = 80
        mock_row.protocol = "tcp"
        mock_row.state = "open"
        mock_row.service_name = "http"
        mock_row.product = "nginx"
        mock_row.version = "1.24.0"
        mock_row.cpe = []
        mock_row.banner = "nginx"
        mock_row.source = "nmap"
        mock_row.confidence = 1.0
        mock_row.first_seen = utc_now()
        mock_row.last_seen = utc_now()
        mock_row.evidence_refs = []
        mock_row.metadata_ = {}

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_row]
        session.execute.return_value = mock_result

        services = await repo.get_services_by_asset(sample_bundle.assets[0].asset_id)
        assert len(services) == 1
        assert services[0].port == 80

    @pytest.mark.asyncio
    async def test_get_technologies_by_asset(self, sample_bundle):
        session = AsyncMock()
        repo = AssetRepository(session)

        mock_row = MagicMock(spec=TechnologyDB)
        mock_row.id = uuid.UUID(sample_bundle.technologies[0].technology_id)
        mock_row.engagement_id = uuid.UUID(sample_bundle.engagement_id)
        mock_row.asset_id = uuid.UUID(sample_bundle.assets[0].asset_id)
        mock_row.service_id = None
        mock_row.name = "nginx"
        mock_row.version = "1.24.0"
        mock_row.cpe = []
        mock_row.source = "nmap"
        mock_row.confidence = 1.0
        mock_row.first_seen = utc_now()
        mock_row.last_seen = utc_now()
        mock_row.evidence_refs = []
        mock_row.metadata_ = {}

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_row]
        session.execute.return_value = mock_result

        techs = await repo.get_technologies_by_asset(sample_bundle.assets[0].asset_id)
        assert len(techs) == 1
        assert techs[0].name == "nginx"

    @pytest.mark.asyncio
    async def test_get_endpoints_by_asset(self, sample_bundle):
        session = AsyncMock()
        repo = AssetRepository(session)

        mock_row = MagicMock(spec=EndpointDB)
        mock_row.id = uuid.UUID(sample_bundle.endpoints[0].endpoint_id)
        mock_row.engagement_id = uuid.UUID(sample_bundle.engagement_id)
        mock_row.asset_id = uuid.UUID(sample_bundle.assets[0].asset_id)
        mock_row.scheme = "http"
        mock_row.host = "server.corp"
        mock_row.port = 80
        mock_row.path = "/api/status"
        mock_row.query_metadata = {}
        mock_row.source = "ffuf"
        mock_row.confidence = 1.0
        mock_row.first_seen = utc_now()
        mock_row.last_seen = utc_now()
        mock_row.evidence_refs = []
        mock_row.metadata_ = {}

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_row]
        session.execute.return_value = mock_result

        eps = await repo.get_endpoints_by_asset(sample_bundle.assets[0].asset_id)
        assert len(eps) == 1
        assert eps[0].path == "/api/status"
