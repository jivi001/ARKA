"""Attack Surface API endpoints for Assets, Endpoints, and Services.

Explicitly enforces the invariant: DISCOVERED != AUTHORIZED.
Every discovered asset is strictly tagged with its authorization status.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select

from arka.app.api.deps import get_scope_repository
from arka.app.core.scope.repository import ScopeRepository
from arka.app.database.models import AssetDB, EndpointDB, ServiceDB
from arka.app.database.session import get_session_factory

logger = logging.getLogger(__name__)

router = APIRouter(tags=["attack-surface"])


class AssetResponse(BaseModel):
    """Infrastructure asset with deterministic authorization status."""

    asset_id: str
    engagement_id: str
    asset_type: str
    address: str | None = None
    hostname: str | None = None
    domain: str | None = None
    status: str
    source: str
    confidence: float
    authorization_status: str = Field(
        ..., description="'AUTHORIZED' or 'DISCOVERED — NOT AUTHORIZED'"
    )
    first_seen: str
    last_seen: str
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EndpointResponse(BaseModel):
    """HTTP Endpoint representation with authorization state."""

    endpoint_id: str
    engagement_id: str
    asset_id: str
    scheme: str
    host: str
    port: int | None = None
    path: str
    url: str
    source: str
    confidence: float
    authorization_status: str
    first_seen: str
    last_seen: str
    evidence_refs: list[str] = Field(default_factory=list)
    query_metadata: dict[str, Any] = Field(default_factory=dict)


class ServiceResponse(BaseModel):
    """Network service representation."""

    service_id: str
    engagement_id: str
    asset_id: str
    port: int
    protocol: str
    state: str
    service_name: str
    product: str | None = None
    version: str | None = None
    source: str
    confidence: float
    first_seen: str
    last_seen: str


@router.get("/engagements/{engagement_id}/assets", response_model=list[AssetResponse])
async def list_engagement_assets(
    engagement_id: str,
    scope_repo: ScopeRepository = Depends(get_scope_repository),
) -> list[AssetResponse]:
    """List assets discovered for an engagement with deterministic authorization check."""
    # Retrieve authoritative scope to evaluate authorization
    scope_def = await scope_repo.get_scope(engagement_id)

    results: list[AssetResponse] = []
    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            eng_uuid = uuid.UUID(engagement_id)
            rows = (
                (await session.execute(select(AssetDB).where(AssetDB.engagement_id == eng_uuid)))
                .scalars()
                .all()
            )

            for r in rows:
                target_check = r.hostname or r.domain or r.address or ""
                # Evaluate against scope
                is_authorized = False
                if scope_def and target_check:
                    try:
                        from arka.app.core.scope import ScopeGuard

                        guard = ScopeGuard(scope_def)
                        is_authorized = guard.is_in_scope(target_check)
                    except Exception:
                        is_authorized = False

                auth_status = "AUTHORIZED" if is_authorized else "DISCOVERED — NOT AUTHORIZED"

                results.append(
                    AssetResponse(
                        asset_id=str(r.id),
                        engagement_id=str(r.engagement_id),
                        asset_type=r.asset_type,
                        address=r.address,
                        hostname=r.hostname,
                        domain=r.domain,
                        status=r.status,
                        source=r.source,
                        confidence=r.confidence,
                        authorization_status=auth_status,
                        first_seen=r.first_seen.isoformat() if r.first_seen else "",
                        last_seen=r.last_seen.isoformat() if r.last_seen else "",
                        evidence_refs=r.evidence_refs or [],
                        metadata=r.metadata_ or {},
                    )
                )
    except Exception:
        pass

    return results


@router.get("/engagements/{engagement_id}/endpoints", response_model=list[EndpointResponse])
async def list_engagement_endpoints(
    engagement_id: str,
    scope_repo: ScopeRepository = Depends(get_scope_repository),
) -> list[EndpointResponse]:
    """List discovered web endpoints for an engagement."""
    scope_def = await scope_repo.get_scope(engagement_id)
    results: list[EndpointResponse] = []

    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            eng_uuid = uuid.UUID(engagement_id)
            rows = (
                (
                    await session.execute(
                        select(EndpointDB).where(EndpointDB.engagement_id == eng_uuid)
                    )
                )
                .scalars()
                .all()
            )

            for ep in rows:
                port_str = f":{ep.port}" if ep.port and ep.port not in (80, 443) else ""
                full_url = f"{ep.scheme}://{ep.host}{port_str}{ep.path}"

                is_authorized = False
                if scope_def:
                    try:
                        from arka.app.core.scope import ScopeGuard

                        guard = ScopeGuard(scope_def)
                        is_authorized = guard.is_in_scope(full_url)
                    except Exception:
                        is_authorized = False

                auth_status = "AUTHORIZED" if is_authorized else "DISCOVERED — NOT AUTHORIZED"

                results.append(
                    EndpointResponse(
                        endpoint_id=str(ep.id),
                        engagement_id=str(ep.engagement_id),
                        asset_id=str(ep.asset_id),
                        scheme=ep.scheme,
                        host=ep.host,
                        port=ep.port,
                        path=ep.path,
                        url=full_url,
                        source=ep.source,
                        confidence=ep.confidence,
                        authorization_status=auth_status,
                        first_seen=ep.first_seen.isoformat() if ep.first_seen else "",
                        last_seen=ep.last_seen.isoformat() if ep.last_seen else "",
                        evidence_refs=ep.evidence_refs or [],
                        query_metadata=ep.query_metadata or {},
                    )
                )
    except Exception:
        pass

    return results


@router.get("/engagements/{engagement_id}/services", response_model=list[ServiceResponse])
async def list_engagement_services(engagement_id: str) -> list[ServiceResponse]:
    """List discovered network services for an engagement."""
    results: list[ServiceResponse] = []

    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            eng_uuid = uuid.UUID(engagement_id)
            rows = (
                (
                    await session.execute(
                        select(ServiceDB).where(ServiceDB.engagement_id == eng_uuid)
                    )
                )
                .scalars()
                .all()
            )

            for s in rows:
                results.append(
                    ServiceResponse(
                        service_id=str(s.id),
                        engagement_id=str(s.engagement_id),
                        asset_id=str(s.asset_id),
                        port=s.port,
                        protocol=s.protocol,
                        state=s.state,
                        service_name=s.service_name,
                        product=s.product,
                        version=s.version,
                        source=s.source,
                        confidence=s.confidence,
                        first_seen=s.first_seen.isoformat() if s.first_seen else "",
                        last_seen=s.last_seen.isoformat() if s.last_seen else "",
                    )
                )
    except Exception:
        pass

    return results
