"""AssetNormalizer for converting raw tool results into canonical ARKA models.

Normalizes NmapResult (and future tool outputs) into canonical Asset, Service,
Technology, and Endpoint models with deterministic identity, deduplication,
conflict preservation, and cryptographic evidence provenance.
"""

from __future__ import annotations

import logging
from typing import Any

from arka.app.core.assets.identity import (
    extract_domain_from_hostname,
    generate_asset_id,
    generate_service_id,
    generate_technology_id,
    normalize_hostname,
    normalize_ip,
    normalize_protocol,
)
from arka.app.core.assets.models import (
    Asset,
    AssetStatus,
    AssetType,
    NormalizedAssetBundle,
    ObservationConflict,
    Service,
    Technology,
    utc_now,
)
from arka.app.tools.nmap.schemas import NmapHost, NmapPort, NmapResult

logger = logging.getLogger(__name__)


class AssetNormalizer:
    """Normalizes tool observation models into canonical ARKA asset entities."""

    def normalize_nmap_result(
        self,
        result: NmapResult,
        engagement_id: str,
        task_id: str | None = None,
        execution_id: str | None = None,
        request_id: str | None = None,
        target: str | None = None,
        evidence_refs: list[str] | None = None,
        source: str = "nmap",
    ) -> NormalizedAssetBundle:
        """Normalize an NmapResult into a NormalizedAssetBundle.

        Args:
            result: Parsed Nmap XML result.
            engagement_id: Active engagement UUID string.
            task_id: Associated task UUID string.
            execution_id: Execution run UUID string.
            request_id: Authoritative tool request UUID string.
            target: Original target string for the scan.
            evidence_refs: SHA-256 evidence reference IDs.
            source: Tool identifier producing the observation (default "nmap").

        Returns:
            NormalizedAssetBundle with deduplicated assets, services, technologies,
            and any detected observation conflicts.
        """
        evidence_list = list(evidence_refs) if evidence_refs else []
        provenance_metadata: dict[str, Any] = {
            "task_id": task_id,
            "execution_id": execution_id,
            "request_id": request_id,
            "target": target,
            "normalized_at": utc_now().isoformat(),
        }

        asset_map: dict[str, Asset] = {}
        service_map: dict[str, Service] = {}
        technology_map: dict[str, Technology] = {}
        conflicts: list[ObservationConflict] = []

        for host in result.hosts:
            self._process_nmap_host(
                host=host,
                engagement_id=engagement_id,
                source=source,
                evidence_list=evidence_list,
                provenance_metadata=provenance_metadata,
                asset_map=asset_map,
                service_map=service_map,
                technology_map=technology_map,
                conflicts=conflicts,
            )

        return NormalizedAssetBundle(
            engagement_id=engagement_id,
            assets=list(asset_map.values()),
            services=list(service_map.values()),
            technologies=list(technology_map.values()),
            endpoints=[],  # Populated by endpoint discovery tools like ffuf in subsequent phases
            conflicts=conflicts,
        )

    def _process_nmap_host(
        self,
        host: NmapHost,
        engagement_id: str,
        source: str,
        evidence_list: list[str],
        provenance_metadata: dict[str, Any],
        asset_map: dict[str, Asset],
        service_map: dict[str, Service],
        technology_map: dict[str, Technology],
        conflicts: list[ObservationConflict],
    ) -> None:
        """Process a single NmapHost into Asset, Service, and Technology observations."""
        raw_address = (host.address or "").strip()
        if not raw_address:
            return

        # 1. Address & Hostname normalization
        normalized_ip: str | None = None
        addr_type: str | None = None
        try:
            normalized_ip, addr_type = normalize_ip(raw_address)
        except ValueError:
            # Not a valid IP address; may be a hostname/domain or malformed
            normalized_ip = None
            addr_type = host.address_type or "unknown"

        # Hostnames & domain
        valid_hostnames: list[str] = []
        primary_hostname: str | None = None
        domain: str | None = None

        for hn in host.hostnames:
            clean_hn = normalize_hostname(hn)
            if clean_hn and clean_hn not in valid_hostnames:
                valid_hostnames.append(clean_hn)

        if valid_hostnames:
            primary_hostname = valid_hostnames[0]
            domain = extract_domain_from_hostname(primary_hostname)

        # Asset Type & Deterministic Asset ID
        if normalized_ip is not None:
            asset_type = AssetType.IP
            identifier = normalized_ip
            display_address = normalized_ip
        elif primary_hostname is not None:
            asset_type = AssetType.HOST
            identifier = primary_hostname
            display_address = primary_hostname
        else:
            asset_type = AssetType.IP
            identifier = raw_address.lower()
            display_address = raw_address

        asset_id = generate_asset_id(engagement_id, asset_type.value, identifier)

        # Map host status to canonical AssetStatus
        status_val = host.status.lower() if host.status else "unknown"
        if status_val == "up":
            canonical_status = AssetStatus.ACTIVE.value
        elif status_val == "down":
            canonical_status = AssetStatus.DOWN.value
        else:
            canonical_status = AssetStatus.UNKNOWN.value

        # Asset metadata
        asset_meta = {
            **provenance_metadata,
            "hostnames": valid_hostnames,
            "raw_address": raw_address,
            "raw_status": host.status,
        }

        # Deduplicate or merge Asset
        if asset_id in asset_map:
            existing_asset = asset_map[asset_id]
            existing_asset.last_seen = utc_now()
            # Merge evidence refs
            for ref in evidence_list:
                if ref not in existing_asset.evidence_refs:
                    existing_asset.evidence_refs.append(ref)
            # Update hostname/domain if previously empty
            if not existing_asset.hostname and primary_hostname:
                existing_asset.hostname = primary_hostname
            if not existing_asset.domain and domain:
                existing_asset.domain = domain
        else:
            asset_map[asset_id] = Asset(
                asset_id=asset_id,
                engagement_id=engagement_id,
                first_seen=utc_now(),
                last_seen=utc_now(),
                asset_type=asset_type,
                address=display_address,
                address_type=addr_type,
                hostname=primary_hostname,
                domain=domain,
                status=canonical_status,
                source=source,
                confidence=1.0,
                evidence_refs=list(evidence_list),
                metadata=asset_meta,
            )

        # 2. Process Ports and Services
        for port in host.ports:
            self._process_nmap_port(
                port=port,
                asset_id=asset_id,
                engagement_id=engagement_id,
                source=source,
                evidence_list=evidence_list,
                provenance_metadata=provenance_metadata,
                service_map=service_map,
                technology_map=technology_map,
                conflicts=conflicts,
            )

    def _process_nmap_port(
        self,
        port: NmapPort,
        asset_id: str,
        engagement_id: str,
        source: str,
        evidence_list: list[str],
        provenance_metadata: dict[str, Any],
        service_map: dict[str, Service],
        technology_map: dict[str, Technology],
        conflicts: list[ObservationConflict],
    ) -> None:
        """Process an individual NmapPort into Service and Technology observations."""
        protocol = normalize_protocol(port.protocol or "tcp")
        port_num = port.port
        service_id = generate_service_id(engagement_id, asset_id, protocol, port_num)

        # Extract service details
        svc_name = ""
        product: str | None = None
        version: str | None = None
        cpe_list: list[str] = []
        banner_parts: list[str] = []

        if port.service:
            svc_name = port.service.name or ""
            product = port.service.product or None
            version = port.service.version or None
            cpe_list = list(port.service.cpe) if port.service.cpe else []
            if port.service.extra_info:
                banner_parts.append(port.service.extra_info)

        # Extract banners/headers from NSE scripts
        scripts_data: list[dict[str, str]] = []
        for script in port.scripts:
            scripts_data.append({"id": script.script_id, "output": script.output})
            if script.script_id in (
                "http-server-header",
                "http-title",
                "banner",
                "ssl-cert",
            ):
                banner_parts.append(f"{script.script_id}: {script.output.strip()}")

        banner = " | ".join(banner_parts) if banner_parts else None

        service_meta = {
            **provenance_metadata,
            "scripts": scripts_data,
        }

        # Deduplicate or record conflict for Service
        if service_id in service_map:
            existing_svc = service_map[service_id]
            existing_svc.last_seen = utc_now()
            # Check for version / product conflicts
            if product and existing_svc.product and product != existing_svc.product:
                conflicts.append(
                    ObservationConflict(
                        engagement_id=engagement_id,
                        entity_type="service",
                        entity_id=service_id,
                        field_name="product",
                        existing_value=existing_svc.product,
                        observed_value=product,
                        source=source,
                        evidence_refs=list(evidence_list),
                        metadata={"port": port_num, "protocol": protocol},
                    )
                )
            if version and existing_svc.version and version != existing_svc.version:
                conflicts.append(
                    ObservationConflict(
                        engagement_id=engagement_id,
                        entity_type="service",
                        entity_id=service_id,
                        field_name="version",
                        existing_value=existing_svc.version,
                        observed_value=version,
                        source=source,
                        evidence_refs=list(evidence_list),
                        metadata={"port": port_num, "protocol": protocol},
                    )
                )

            # Merge CPEs and evidence
            for cpe_item in cpe_list:
                if cpe_item not in existing_svc.cpe:
                    existing_svc.cpe.append(cpe_item)
            for ref in evidence_list:
                if ref not in existing_svc.evidence_refs:
                    existing_svc.evidence_refs.append(ref)
        else:
            service_map[service_id] = Service(
                service_id=service_id,
                asset_id=asset_id,
                engagement_id=engagement_id,
                port=port_num,
                protocol=protocol,
                state=port.state or "unknown",
                service_name=svc_name,
                product=product,
                version=version,
                cpe=cpe_list,
                banner=banner,
                source=source,
                confidence=1.0,
                first_seen=utc_now(),
                last_seen=utc_now(),
                evidence_refs=list(evidence_list),
                metadata=service_meta,
            )

        # 3. Extract Technologies
        # A. Product/Version technology on service
        if product:
            tech_id = generate_technology_id(
                engagement_id=engagement_id,
                asset_id=asset_id,
                service_id=service_id,
                name=product,
                version=version,
            )
            if tech_id not in technology_map:
                technology_map[tech_id] = Technology(
                    technology_id=tech_id,
                    engagement_id=engagement_id,
                    asset_id=asset_id,
                    service_id=service_id,
                    name=product,
                    version=version,
                    cpe=cpe_list,
                    source=source,
                    confidence=1.0,
                    first_seen=utc_now(),
                    last_seen=utc_now(),
                    evidence_refs=list(evidence_list),
                    metadata=provenance_metadata,
                )

        # B. CPE-based technologies (e.g. Operating System, Application)
        for cpe_str in cpe_list:
            cpe_tech = self._parse_cpe_technology(
                cpe_str=cpe_str,
                engagement_id=engagement_id,
                asset_id=asset_id,
                service_id=service_id,
                source=source,
                evidence_list=evidence_list,
                provenance_metadata=provenance_metadata,
            )
            if cpe_tech and cpe_tech.technology_id not in technology_map:
                technology_map[cpe_tech.technology_id] = cpe_tech

    def _parse_cpe_technology(
        self,
        cpe_str: str,
        engagement_id: str,
        asset_id: str,
        service_id: str | None,
        source: str,
        evidence_list: list[str],
        provenance_metadata: dict[str, Any],
    ) -> Technology | None:
        """Extract a structured Technology entity from a CPE 2.3 or 2.2 URI."""
        # e.g., cpe:/a:nginx:nginx:1.24.0 or cpe:/o:linux:linux_kernel
        parts = cpe_str.split(":")
        if len(parts) < 4:
            return None

        part_type = parts[1].replace("/", "")  # 'a' (app), 'o' (os), 'h' (hardware)
        vendor = parts[2] if len(parts) > 2 else ""
        product_name = parts[3] if len(parts) > 3 else vendor
        version = parts[4] if len(parts) > 4 and parts[4] not in ("*", "-") else None

        # Clean name for presentation
        display_name = f"{vendor.capitalize()} {product_name.capitalize()}".strip()
        if not display_name:
            display_name = cpe_str

        tech_id = generate_technology_id(
            engagement_id=engagement_id,
            asset_id=asset_id,
            service_id=service_id if part_type == "a" else None,
            name=display_name,
            version=version,
        )

        return Technology(
            technology_id=tech_id,
            engagement_id=engagement_id,
            asset_id=asset_id,
            service_id=service_id if part_type == "a" else None,
            name=display_name,
            version=version,
            cpe=[cpe_str],
            source=source,
            confidence=0.9 if part_type == "o" else 1.0,
            first_seen=utc_now(),
            last_seen=utc_now(),
            evidence_refs=list(evidence_list),
            metadata={
                **provenance_metadata,
                "cpe_part": part_type,
                "vendor": vendor,
                "product": product_name,
            },
        )
