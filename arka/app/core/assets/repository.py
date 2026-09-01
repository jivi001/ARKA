"""Asset Repository for persisting and querying canonical ARKA infrastructure models.

Provides both an asynchronous SQLAlchemy PostgreSQL repository (AssetRepository)
and an in-memory repository (InMemoryAssetRepository) for testing and isolated sandboxes.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from arka.app.core.assets.models import (
    Asset,
    AssetType,
    Endpoint,
    NormalizedAssetBundle,
    Service,
    Technology,
    utc_now,
)
from arka.app.database.models import (
    AssetDB,
    EndpointDB,
    ServiceDB,
    TechnologyDB,
)


class InMemoryAssetRepository:
    """In-memory asset repository for unit testing and offline sandboxes."""

    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}
        self._services: dict[str, Service] = {}
        self._technologies: dict[str, Technology] = {}
        self._endpoints: dict[str, Endpoint] = {}

    def save_bundle(self, bundle: NormalizedAssetBundle) -> None:
        """Persist a NormalizedAssetBundle in-memory with upsert logic."""
        now = utc_now()
        for asset in bundle.assets:
            if asset.asset_id in self._assets:
                existing = self._assets[asset.asset_id]
                existing.last_seen = now
                existing.status = asset.status
                if asset.hostname:
                    existing.hostname = asset.hostname
                if asset.domain:
                    existing.domain = asset.domain
                for ref in asset.evidence_refs:
                    if ref not in existing.evidence_refs:
                        existing.evidence_refs.append(ref)
                existing.metadata.update(asset.metadata)
            else:
                self._assets[asset.asset_id] = asset.model_copy(deep=True)

        for svc in bundle.services:
            if svc.service_id in self._services:
                existing_svc = self._services[svc.service_id]
                existing_svc.last_seen = now
                existing_svc.state = svc.state
                if svc.service_name:
                    existing_svc.service_name = svc.service_name
                if svc.product:
                    existing_svc.product = svc.product
                if svc.version:
                    existing_svc.version = svc.version
                if svc.banner:
                    existing_svc.banner = svc.banner
                for cpe_item in svc.cpe:
                    if cpe_item not in existing_svc.cpe:
                        existing_svc.cpe.append(cpe_item)
                for ref in svc.evidence_refs:
                    if ref not in existing_svc.evidence_refs:
                        existing_svc.evidence_refs.append(ref)
                existing_svc.metadata.update(svc.metadata)
            else:
                self._services[svc.service_id] = svc.model_copy(deep=True)

        for tech in bundle.technologies:
            if tech.technology_id in self._technologies:
                existing_tech = self._technologies[tech.technology_id]
                existing_tech.last_seen = now
                if tech.version:
                    existing_tech.version = tech.version
                for cpe_item in tech.cpe:
                    if cpe_item not in existing_tech.cpe:
                        existing_tech.cpe.append(cpe_item)
                for ref in tech.evidence_refs:
                    if ref not in existing_tech.evidence_refs:
                        existing_tech.evidence_refs.append(ref)
                existing_tech.metadata.update(tech.metadata)
            else:
                self._technologies[tech.technology_id] = tech.model_copy(deep=True)

        for ep in bundle.endpoints:
            if ep.endpoint_id in self._endpoints:
                existing_ep = self._endpoints[ep.endpoint_id]
                existing_ep.last_seen = now
                for ref in ep.evidence_refs:
                    if ref not in existing_ep.evidence_refs:
                        existing_ep.evidence_refs.append(ref)
                existing_ep.metadata.update(ep.metadata)
            else:
                self._endpoints[ep.endpoint_id] = ep.model_copy(deep=True)

    def get_assets_by_engagement(self, engagement_id: str) -> list[Asset]:
        """Retrieve all assets associated with an engagement."""
        return [
            a.model_copy(deep=True)
            for a in self._assets.values()
            if a.engagement_id == engagement_id
        ]

    def get_asset_by_id(self, asset_id: str) -> Asset | None:
        """Retrieve an asset by ID."""
        asset = self._assets.get(asset_id)
        return asset.model_copy(deep=True) if asset else None

    def get_services_by_asset(self, asset_id: str) -> list[Service]:
        """Retrieve all services associated with an asset."""
        return [s.model_copy(deep=True) for s in self._services.values() if s.asset_id == asset_id]

    def get_technologies_by_asset(self, asset_id: str) -> list[Technology]:
        """Retrieve all technologies associated with an asset."""
        return [
            t.model_copy(deep=True) for t in self._technologies.values() if t.asset_id == asset_id
        ]

    def get_endpoints_by_asset(self, asset_id: str) -> list[Endpoint]:
        """Retrieve all endpoints associated with an asset."""
        return [e.model_copy(deep=True) for e in self._endpoints.values() if e.asset_id == asset_id]


class AssetRepository:
    """Production asynchronous SQLAlchemy repository for PostgreSQL."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def save_bundle(self, bundle: NormalizedAssetBundle) -> None:
        """Persist a NormalizedAssetBundle to PostgreSQL using idempotent upserts."""
        now = utc_now()

        # 1. Upsert Assets
        for asset in bundle.assets:
            asset_uuid = uuid.UUID(asset.asset_id)
            eng_uuid = uuid.UUID(bundle.engagement_id)
            stmt = pg_insert(AssetDB).values(
                id=asset_uuid,
                engagement_id=eng_uuid,
                asset_type=asset.asset_type.value,
                address=asset.address,
                address_type=asset.address_type,
                hostname=asset.hostname,
                domain=asset.domain,
                status=asset.status,
                source=asset.source,
                confidence=asset.confidence,
                first_seen=asset.first_seen,
                last_seen=now,
                evidence_refs=asset.evidence_refs,
                metadata_=asset.metadata,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=[AssetDB.id],
                set_={
                    "last_seen": now,
                    "status": stmt.excluded.status,
                    "hostname": stmt.excluded.hostname,
                    "domain": stmt.excluded.domain,
                    "evidence_refs": stmt.excluded.evidence_refs,
                    "metadata": stmt.excluded["metadata"],
                },
            )
            await self.session.execute(stmt)

        # 2. Upsert Services
        for svc in bundle.services:
            svc_uuid = uuid.UUID(svc.service_id)
            asset_uuid = uuid.UUID(svc.asset_id)
            eng_uuid = uuid.UUID(bundle.engagement_id)
            stmt = pg_insert(ServiceDB).values(
                id=svc_uuid,
                engagement_id=eng_uuid,
                asset_id=asset_uuid,
                port=svc.port,
                protocol=svc.protocol,
                state=svc.state,
                service_name=svc.service_name,
                product=svc.product,
                version=svc.version,
                cpe=svc.cpe,
                banner=svc.banner,
                source=svc.source,
                confidence=svc.confidence,
                first_seen=svc.first_seen,
                last_seen=now,
                evidence_refs=svc.evidence_refs,
                metadata_=svc.metadata,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=[ServiceDB.id],
                set_={
                    "last_seen": now,
                    "state": stmt.excluded.state,
                    "service_name": stmt.excluded.service_name,
                    "product": stmt.excluded.product,
                    "version": stmt.excluded.version,
                    "cpe": stmt.excluded.cpe,
                    "banner": stmt.excluded.banner,
                    "evidence_refs": stmt.excluded.evidence_refs,
                    "metadata": stmt.excluded["metadata"],
                },
            )
            await self.session.execute(stmt)

        # 3. Upsert Technologies
        for tech in bundle.technologies:
            tech_uuid = uuid.UUID(tech.technology_id)
            asset_uuid = uuid.UUID(tech.asset_id)
            tech_svc_uuid: uuid.UUID | None = (
                uuid.UUID(tech.service_id) if tech.service_id else None
            )
            eng_uuid = uuid.UUID(bundle.engagement_id)
            stmt = pg_insert(TechnologyDB).values(
                id=tech_uuid,
                engagement_id=eng_uuid,
                asset_id=asset_uuid,
                service_id=tech_svc_uuid,
                name=tech.name,
                version=tech.version,
                cpe=tech.cpe,
                source=tech.source,
                confidence=tech.confidence,
                first_seen=tech.first_seen,
                last_seen=now,
                evidence_refs=tech.evidence_refs,
                metadata_=tech.metadata,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=[TechnologyDB.id],
                set_={
                    "last_seen": now,
                    "version": stmt.excluded.version,
                    "cpe": stmt.excluded.cpe,
                    "evidence_refs": stmt.excluded.evidence_refs,
                    "metadata": stmt.excluded["metadata"],
                },
            )
            await self.session.execute(stmt)

        # 4. Upsert Endpoints
        for ep in bundle.endpoints:
            ep_uuid = uuid.UUID(ep.endpoint_id)
            asset_uuid = uuid.UUID(ep.asset_id)
            eng_uuid = uuid.UUID(bundle.engagement_id)
            stmt = pg_insert(EndpointDB).values(
                id=ep_uuid,
                engagement_id=eng_uuid,
                asset_id=asset_uuid,
                scheme=ep.scheme,
                host=ep.host,
                port=ep.port,
                path=ep.path,
                query_metadata=ep.query_metadata,
                source=ep.source,
                confidence=ep.confidence,
                first_seen=ep.first_seen,
                last_seen=now,
                evidence_refs=ep.evidence_refs,
                metadata_=ep.metadata,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=[EndpointDB.id],
                set_={
                    "last_seen": now,
                    "query_metadata": stmt.excluded.query_metadata,
                    "evidence_refs": stmt.excluded.evidence_refs,
                    "metadata": stmt.excluded["metadata"],
                },
            )
            await self.session.execute(stmt)

        await self.session.flush()

    async def get_assets_by_engagement(self, engagement_id: str) -> list[Asset]:
        """Query all assets for an engagement."""
        eng_uuid = uuid.UUID(engagement_id)
        stmt = select(AssetDB).where(AssetDB.engagement_id == eng_uuid)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [
            Asset(
                asset_id=str(row.id),
                engagement_id=str(row.engagement_id),
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                asset_type=AssetType(row.asset_type),
                address=row.address,
                address_type=row.address_type,
                hostname=row.hostname,
                domain=row.domain,
                status=row.status,
                source=row.source,
                confidence=row.confidence,
                evidence_refs=row.evidence_refs or [],
                metadata=row.metadata_ or {},
            )
            for row in rows
        ]

    async def get_asset_by_id(self, asset_id: str) -> Asset | None:
        """Query a single asset by UUID."""
        asset_uuid = uuid.UUID(asset_id)
        stmt = select(AssetDB).where(AssetDB.id == asset_uuid)
        result = await self.session.execute(stmt)
        row = result.scalar_one_or_none()
        if not row:
            return None
        return Asset(
            asset_id=str(row.id),
            engagement_id=str(row.engagement_id),
            first_seen=row.first_seen,
            last_seen=row.last_seen,
            asset_type=AssetType(row.asset_type),
            address=row.address,
            address_type=row.address_type,
            hostname=row.hostname,
            domain=row.domain,
            status=row.status,
            source=row.source,
            confidence=row.confidence,
            evidence_refs=row.evidence_refs or [],
            metadata=row.metadata_ or {},
        )

    async def get_services_by_asset(self, asset_id: str) -> list[Service]:
        """Query all services for an asset."""
        asset_uuid = uuid.UUID(asset_id)
        stmt = select(ServiceDB).where(ServiceDB.asset_id == asset_uuid)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [
            Service(
                service_id=str(row.id),
                asset_id=str(row.asset_id),
                engagement_id=str(row.engagement_id),
                port=row.port,
                protocol=row.protocol,
                state=row.state,
                service_name=row.service_name,
                product=row.product,
                version=row.version,
                cpe=row.cpe or [],
                banner=row.banner,
                source=row.source,
                confidence=row.confidence,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                evidence_refs=row.evidence_refs or [],
                metadata=row.metadata_ or {},
            )
            for row in rows
        ]

    async def get_technologies_by_asset(self, asset_id: str) -> list[Technology]:
        """Query all technologies for an asset."""
        asset_uuid = uuid.UUID(asset_id)
        stmt = select(TechnologyDB).where(TechnologyDB.asset_id == asset_uuid)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [
            Technology(
                technology_id=str(row.id),
                engagement_id=str(row.engagement_id),
                asset_id=str(row.asset_id),
                service_id=str(row.service_id) if row.service_id else None,
                name=row.name,
                version=row.version,
                cpe=row.cpe or [],
                source=row.source,
                confidence=row.confidence,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                evidence_refs=row.evidence_refs or [],
                metadata=row.metadata_ or {},
            )
            for row in rows
        ]

    async def get_endpoints_by_asset(self, asset_id: str) -> list[Endpoint]:
        """Query all endpoints for an asset."""
        asset_uuid = uuid.UUID(asset_id)
        stmt = select(EndpointDB).where(EndpointDB.asset_id == asset_uuid)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()
        return [
            Endpoint(
                endpoint_id=str(row.id),
                engagement_id=str(row.engagement_id),
                asset_id=str(row.asset_id),
                scheme=row.scheme,
                host=row.host,
                port=row.port,
                path=row.path,
                query_metadata=row.query_metadata or {},
                source=row.source,
                confidence=row.confidence,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                evidence_refs=row.evidence_refs or [],
                metadata=row.metadata_ or {},
            )
            for row in rows
        ]
