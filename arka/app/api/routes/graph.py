"""Graphify / Attack Graph export endpoint for React Flow visualizer."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select

from arka.app.api.deps import get_scope_repository
from arka.app.core.scope.repository import ScopeRepository
from arka.app.database.models import AssetDB, EndpointDB, FindingDB, ServiceDB
from arka.app.database.session import get_session_factory

logger = logging.getLogger(__name__)

router = APIRouter(tags=["graph"])


class GraphNode(BaseModel):
    """React Flow compatible node."""

    id: str
    type: str  # "asset", "service", "endpoint", "finding"
    position: dict[str, float] = Field(default_factory=lambda: {"x": 0.0, "y": 0.0})
    data: dict[str, Any]


class GraphEdge(BaseModel):
    """React Flow compatible edge."""

    id: str
    source: str
    target: str
    label: str | None = None
    animated: bool = False
    style: dict[str, Any] = Field(default_factory=dict)


class GraphResponse(BaseModel):
    """Full graph structure for React Flow."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]
    stats: dict[str, int]


@router.get("/engagements/{engagement_id}/graph", response_model=GraphResponse)
async def get_engagement_graph(
    engagement_id: str,
    scope_repo: ScopeRepository = Depends(get_scope_repository),
) -> GraphResponse:
    """Generate React Flow compatible node and edge graph of the engagement attack surface."""
    scope_def = await scope_repo.get_scope(engagement_id)

    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []

    try:
        session_factory = get_session_factory()
        async with session_factory() as session:
            eng_uuid = uuid.UUID(engagement_id)

            # 1. Assets
            assets = (
                (await session.execute(select(AssetDB).where(AssetDB.engagement_id == eng_uuid)))
                .scalars()
                .all()
            )

            for asset_col, a in enumerate(assets):
                target_check = a.hostname or a.domain or a.address or ""
                is_auth = False
                if scope_def and target_check:
                    try:
                        from arka.app.core.scope import ScopeGuard

                        guard = ScopeGuard(scope_def)
                        is_auth = guard.is_in_scope(target_check)
                    except Exception:
                        is_auth = False

                nodes.append(
                    GraphNode(
                        id=f"asset_{a.id}",
                        type="asset",
                        position={"x": 50.0, "y": 100.0 + (asset_col * 150.0)},
                        data={
                            "label": target_check or f"Asset {str(a.id)[:8]}",
                            "asset_id": str(a.id),
                            "asset_type": a.asset_type,
                            "address": a.address,
                            "hostname": a.hostname,
                            "authorization": "AUTHORIZED"
                            if is_auth
                            else "DISCOVERED — NOT AUTHORIZED",
                            "status": a.status,
                        },
                    )
                )

            # 2. Services
            services = (
                (
                    await session.execute(
                        select(ServiceDB).where(ServiceDB.engagement_id == eng_uuid)
                    )
                )
                .scalars()
                .all()
            )

            for svc_col, s in enumerate(services):
                nodes.append(
                    GraphNode(
                        id=f"svc_{s.id}",
                        type="service",
                        position={"x": 350.0, "y": 100.0 + (svc_col * 120.0)},
                        data={
                            "label": f"{s.service_name or 'port'} :{s.port}",
                            "service_id": str(s.id),
                            "port": s.port,
                            "protocol": s.protocol,
                            "product": s.product,
                            "version": s.version,
                            "state": s.state,
                        },
                    )
                )
                edges.append(
                    GraphEdge(
                        id=f"edge_asset_svc_{s.id}",
                        source=f"asset_{s.asset_id}",
                        target=f"svc_{s.id}",
                        label="runs_on",
                    )
                )

            # 3. Endpoints
            endpoints = (
                (
                    await session.execute(
                        select(EndpointDB).where(EndpointDB.engagement_id == eng_uuid)
                    )
                )
                .scalars()
                .all()
            )

            for ep_col, ep in enumerate(endpoints):
                nodes.append(
                    GraphNode(
                        id=f"ep_{ep.id}",
                        type="endpoint",
                        position={"x": 650.0, "y": 80.0 + (ep_col * 100.0)},
                        data={
                            "label": ep.path,
                            "endpoint_id": str(ep.id),
                            "host": ep.host,
                            "path": ep.path,
                            "scheme": ep.scheme,
                        },
                    )
                )
                edges.append(
                    GraphEdge(
                        id=f"edge_asset_ep_{ep.id}",
                        source=f"asset_{ep.asset_id}",
                        target=f"ep_{ep.id}",
                        label="exposes",
                    )
                )

            # 4. Findings
            findings = (
                (
                    await session.execute(
                        select(FindingDB).where(FindingDB.engagement_id == eng_uuid)
                    )
                )
                .scalars()
                .all()
            )

            for f_col, f in enumerate(findings):
                nodes.append(
                    GraphNode(
                        id=f"finding_{f.id}",
                        type="finding",
                        position={"x": 950.0, "y": 80.0 + (f_col * 140.0)},
                        data={
                            "label": f.title,
                            "finding_id": str(f.id),
                            "severity": f.severity,
                            "lifecycle_stage": f.lifecycle_stage,
                            "target": f.target,
                            "confidence": f.confidence,
                        },
                    )
                )
                if f.endpoint_id:
                    edges.append(
                        GraphEdge(
                            id=f"edge_ep_f_{f.id}",
                            source=f"ep_{f.endpoint_id}",
                            target=f"finding_{f.id}",
                            label="affects",
                            animated=True,
                            style={"stroke": "#ff716c"},
                        )
                    )
                elif f.asset_id:
                    edges.append(
                        GraphEdge(
                            id=f"edge_asset_f_{f.id}",
                            source=f"asset_{f.asset_id}",
                            target=f"finding_{f.id}",
                            label="affects",
                            animated=True,
                            style={"stroke": "#ff716c"},
                        )
                    )
    except Exception:
        pass

    return GraphResponse(
        nodes=nodes,
        edges=edges,
        stats={
            "assets": len([n for n in nodes if n.type == "asset"]),
            "services": len([n for n in nodes if n.type == "service"]),
            "endpoints": len([n for n in nodes if n.type == "endpoint"]),
            "findings": len([n for n in nodes if n.type == "finding"]),
        },
    )
