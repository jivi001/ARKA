"""Recon Correlation Engine for ARKA.

Merges, deduplicates, and correlates observations (Assets, Services, Technologies,
Endpoints, Findings) across diverse reconnaissance tools (Nmap, Nuclei, ffuf, WhatWeb, Amass).
Detects conflicts and creates ObservationConflict records without overwriting historical provenance.
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from arka.app.core.assets.models import (
    Asset,
    Endpoint,
    Finding,
    NormalizedAssetBundle,
    ObservationConflict,
    Service,
    Technology,
    utc_now,
)
from arka.app.core.assets.repository import InMemoryAssetRepository

logger = logging.getLogger(__name__)


class CorrelationSummary(BaseModel):
    """Summary statistics from a correlation run."""

    engagement_id: str
    total_assets: int = 0
    total_services: int = 0
    total_technologies: int = 0
    total_endpoints: int = 0
    total_findings: int = 0
    total_conflicts: int = 0
    sources: list[str] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: utc_now().isoformat())


class CorrelationReport(BaseModel):
    """Result of multi-source correlation."""

    bundle: NormalizedAssetBundle
    summary: CorrelationSummary


class CorrelationEngine:
    """Core correlation engine merging multi-source reconnaissance findings."""

    def correlate_bundle(
        self,
        base_bundle: NormalizedAssetBundle,
        new_bundle: NormalizedAssetBundle,
    ) -> NormalizedAssetBundle:
        """Merge a new observation bundle into a base bundle with conflict detection."""
        engagement_id = base_bundle.engagement_id or new_bundle.engagement_id

        # 1. Assets
        asset_map: dict[str, Asset] = {
            a.asset_id: a.model_copy(deep=True) for a in base_bundle.assets
        }
        conflicts: list[ObservationConflict] = list(base_bundle.conflicts) + list(
            new_bundle.conflicts
        )

        for new_asset in new_bundle.assets:
            if new_asset.asset_id in asset_map:
                existing = asset_map[new_asset.asset_id]
                existing.last_seen = max(existing.last_seen, new_asset.last_seen)
                # Combine evidence
                for ref in new_asset.evidence_refs:
                    if ref not in existing.evidence_refs:
                        existing.evidence_refs.append(ref)
                # If existing status was 'discovered' but new tool actively confirmed it, update
                if existing.status == "discovered" and new_asset.status == "active":
                    existing.status = "active"
                if new_asset.hostname and not existing.hostname:
                    existing.hostname = new_asset.hostname
                if new_asset.domain and not existing.domain:
                    existing.domain = new_asset.domain
                existing.metadata.update(new_asset.metadata)
            else:
                asset_map[new_asset.asset_id] = new_asset.model_copy(deep=True)

        # 2. Services
        service_map: dict[str, Service] = {
            s.service_id: s.model_copy(deep=True) for s in base_bundle.services
        }
        for new_svc in new_bundle.services:
            if new_svc.service_id in service_map:
                existing_svc = service_map[new_svc.service_id]
                existing_svc.last_seen = max(existing_svc.last_seen, new_svc.last_seen)
                for ref in new_svc.evidence_refs:
                    if ref not in existing_svc.evidence_refs:
                        existing_svc.evidence_refs.append(ref)
                for cpe in new_svc.cpe:
                    if cpe not in existing_svc.cpe:
                        existing_svc.cpe.append(cpe)

                # Conflict detection on product and version
                if (
                    existing_svc.product
                    and new_svc.product
                    and existing_svc.product.lower() != new_svc.product.lower()
                ):
                    conflicts.append(
                        ObservationConflict(
                            engagement_id=engagement_id,
                            entity_type="service",
                            entity_id=existing_svc.service_id,
                            field_name="product",
                            existing_value=existing_svc.product,
                            observed_value=new_svc.product,
                            source=new_svc.source,
                            evidence_refs=list(new_svc.evidence_refs),
                            metadata={"port": existing_svc.port, "protocol": existing_svc.protocol},
                        )
                    )

                if (
                    existing_svc.version
                    and new_svc.version
                    and existing_svc.version != new_svc.version
                ):
                    conflicts.append(
                        ObservationConflict(
                            engagement_id=engagement_id,
                            entity_type="service",
                            entity_id=existing_svc.service_id,
                            field_name="version",
                            existing_value=existing_svc.version,
                            observed_value=new_svc.version,
                            source=new_svc.source,
                            evidence_refs=list(new_svc.evidence_refs),
                            metadata={"port": existing_svc.port, "protocol": existing_svc.protocol},
                        )
                    )

                if new_svc.product and not existing_svc.product:
                    existing_svc.product = new_svc.product
                if new_svc.version and not existing_svc.version:
                    existing_svc.version = new_svc.version
                existing_svc.metadata.update(new_svc.metadata)
            else:
                service_map[new_svc.service_id] = new_svc.model_copy(deep=True)

        # 3. Technologies
        tech_map: dict[str, Technology] = {
            t.technology_id: t.model_copy(deep=True) for t in base_bundle.technologies
        }
        for new_tech in new_bundle.technologies:
            if new_tech.technology_id in tech_map:
                existing_tech = tech_map[new_tech.technology_id]
                existing_tech.last_seen = max(existing_tech.last_seen, new_tech.last_seen)
                for ref in new_tech.evidence_refs:
                    if ref not in existing_tech.evidence_refs:
                        existing_tech.evidence_refs.append(ref)
                for cpe in new_tech.cpe:
                    if cpe not in existing_tech.cpe:
                        existing_tech.cpe.append(cpe)
                if new_tech.version and not existing_tech.version:
                    existing_tech.version = new_tech.version
                existing_tech.metadata.update(new_tech.metadata)
            else:
                tech_map[new_tech.technology_id] = new_tech.model_copy(deep=True)

        # 4. Endpoints
        endpoint_map: dict[str, Endpoint] = {
            e.endpoint_id: e.model_copy(deep=True) for e in base_bundle.endpoints
        }
        for new_ep in new_bundle.endpoints:
            if new_ep.endpoint_id in endpoint_map:
                existing_ep = endpoint_map[new_ep.endpoint_id]
                existing_ep.last_seen = max(existing_ep.last_seen, new_ep.last_seen)
                for ref in new_ep.evidence_refs:
                    if ref not in existing_ep.evidence_refs:
                        existing_ep.evidence_refs.append(ref)
                existing_ep.query_metadata.update(new_ep.query_metadata)
                existing_ep.metadata.update(new_ep.metadata)
            else:
                endpoint_map[new_ep.endpoint_id] = new_ep.model_copy(deep=True)

        # 5. Findings
        finding_map: dict[str, Finding] = {
            f.finding_id: f.model_copy(deep=True) for f in base_bundle.findings
        }
        for new_f in new_bundle.findings:
            if new_f.finding_id in finding_map:
                existing_f = finding_map[new_f.finding_id]
                existing_f.last_seen = max(existing_f.last_seen, new_f.last_seen)
                for ref in new_f.evidence_refs:
                    if ref not in existing_f.evidence_refs:
                        existing_f.evidence_refs.append(ref)
                existing_f.metadata.update(new_f.metadata)
            else:
                # Deduplicate matching template on matching host/port
                duplicate = False
                for existing_f in finding_map.values():
                    if (
                        existing_f.template_id == new_f.template_id
                        and existing_f.asset_id == new_f.asset_id
                        and existing_f.matched_at == new_f.matched_at
                    ):
                        existing_f.last_seen = max(existing_f.last_seen, new_f.last_seen)
                        for ref in new_f.evidence_refs:
                            if ref not in existing_f.evidence_refs:
                                existing_f.evidence_refs.append(ref)
                        duplicate = True
                        break
                if not duplicate:
                    finding_map[new_f.finding_id] = new_f.model_copy(deep=True)

        return NormalizedAssetBundle(
            engagement_id=engagement_id,
            assets=list(asset_map.values()),
            services=list(service_map.values()),
            technologies=list(tech_map.values()),
            endpoints=list(endpoint_map.values()),
            findings=list(finding_map.values()),
            conflicts=conflicts,
        )

    def correlate_repository(
        self,
        repository: InMemoryAssetRepository,
        engagement_id: str,
    ) -> CorrelationReport:
        """Analyze and correlate all assets for an engagement in an InMemoryAssetRepository."""
        assets = repository.get_assets_by_engagement(engagement_id)
        services: list[Service] = []
        technologies: list[Technology] = []
        endpoints: list[Endpoint] = []
        for a in assets:
            services.extend(repository.get_services_by_asset(a.asset_id))
            technologies.extend(repository.get_technologies_by_asset(a.asset_id))
            endpoints.extend(repository.get_endpoints_by_asset(a.asset_id))
        findings = repository.get_findings_by_engagement(engagement_id)

        sources: set[str] = set()
        for a in assets:
            sources.add(a.source)
        for s in services:
            sources.add(s.source)
        for t in technologies:
            sources.add(t.source)
        for ep in endpoints:
            sources.add(ep.source)
        for f in findings:
            sources.add(f.source)

        bundle = NormalizedAssetBundle(
            engagement_id=engagement_id,
            assets=assets,
            services=services,
            technologies=technologies,
            endpoints=endpoints,
            findings=findings,
            conflicts=[],
        )

        summary = CorrelationSummary(
            engagement_id=engagement_id,
            total_assets=len(assets),
            total_services=len(services),
            total_technologies=len(technologies),
            total_endpoints=len(endpoints),
            total_findings=len(findings),
            total_conflicts=0,
            sources=sorted(sources),
        )

        return CorrelationReport(bundle=bundle, summary=summary)
