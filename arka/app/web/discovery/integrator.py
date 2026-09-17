"""Web Discovery Integrator for Phase 3.3.

Integrates web crawler, OpenAPI, and GraphQL endpoint discoveries into ARKA's
canonical Phase 2 Asset, Service, and Endpoint models.

Enforces the absolute invariant:
    DISCOVERED != AUTHORIZED
Discovered endpoints and assets are recorded as observations and are NOT
automatically added to authorized scope.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import urllib.parse
import uuid
from datetime import datetime, timezone

from arka.app.core.assets.identity import (
    extract_domain_from_hostname,
    generate_asset_id,
    generate_endpoint_id,
    generate_service_id,
    normalize_hostname,
    normalize_ip,
    normalize_url,
)
from arka.app.core.assets.models import (
    Asset,
    AssetStatus,
    AssetType,
    Endpoint,
    NormalizedAssetBundle,
    Service,
)
from arka.app.core.assets.repository import AssetRepository, InMemoryAssetRepository
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.execution.evidence import EvidenceStore, EvidenceType
from arka.app.web.crawler.crawler import CrawlResult
from arka.app.web.models.endpoint import DiscoveredWebEndpoint
from arka.app.web.models.parameters import Parameter, ParameterLocation


def utc_now() -> datetime:
    """Return UTC timestamp for database compatibility."""
    return datetime.now(timezone.utc)


# Path parameter regex: e.g. {id}, :id, <id>
_PATH_PARAM_REGEX = re.compile(r"\{([a-zA-Z0-9_-]+)\}|:([a-zA-Z0-9_-]+)|<([a-zA-Z0-9_-]+)>")


class WebDiscoveryIntegrator:
    """Integrates web/API security discoveries into ARKA's canonical asset repository.

    Correlates observations to prevent duplicate endpoints, extracts and canonicalizes
    parameters across query strings, form fields, headers, and JSON bodies, and
    attaches cryptographic evidence provenance.
    """

    def __init__(
        self,
        engagement_id: str,
        asset_repository: AssetRepository | InMemoryAssetRepository | None = None,
        evidence_store: EvidenceStore | None = None,
        scope_guard: ScopeGuard | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        self.repository = asset_repository
        self.evidence_store = evidence_store
        self.scope_guard = scope_guard

    def extract_parameters_from_url(self, url: str) -> list[Parameter]:
        """Extract query and path parameters from a URL."""
        params: list[Parameter] = []
        parsed = urllib.parse.urlparse(url)

        # 1. Query parameters
        if parsed.query:
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for name, values in qs.items():
                params.append(
                    Parameter(
                        name=name,
                        location=ParameterLocation.QUERY,
                        sample_value=values[0] if values else None,
                        description=f"Extracted query parameter from {parsed.path}",
                    )
                )

        # 2. Path parameters
        for match in _PATH_PARAM_REGEX.finditer(parsed.path):
            name = match.group(1) or match.group(2) or match.group(3)
            if name:
                params.append(
                    Parameter(
                        name=name,
                        location=ParameterLocation.PATH,
                        required=True,
                        description=f"Path parameter in template {parsed.path}",
                    )
                )

        return params

    def build_bundle_from_discovered_endpoints(
        self,
        endpoints: list[DiscoveredWebEndpoint],
        source: str = "web_crawler",
        default_evidence_refs: list[str] | None = None,
    ) -> NormalizedAssetBundle:
        """Transform discovered web endpoints into a canonical NormalizedAssetBundle.

        Deduplicates endpoints using deterministic UUIDs, aggregates parameters,
        and links them to parent Assets and Services.
        """
        now = utc_now()
        base_evidence = list(default_evidence_refs or [])

        asset_map: dict[str, Asset] = {}
        service_map: dict[str, Service] = {}
        endpoint_map: dict[str, Endpoint] = {}

        for dep in endpoints:
            scheme, host, port, path = normalize_url(dep.url)

            # Determine Asset type (IP vs Domain/Hostname)
            is_ip = False
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                pass

            if is_ip:
                norm_ip, addr_type = normalize_ip(host)
                asset_id = generate_asset_id(self.engagement_id, addr_type, norm_ip)
                if asset_id not in asset_map:
                    asset_map[asset_id] = Asset(
                        asset_id=asset_id,
                        engagement_id=self.engagement_id,
                        asset_type=AssetType.IP,
                        address=norm_ip,
                        address_type=addr_type,
                        status=AssetStatus.ACTIVE.value,
                        source=source,
                        first_seen=now,
                        last_seen=now,
                        evidence_refs=list(base_evidence),
                        metadata={"discovered_not_authorized": True},
                    )
            else:
                norm_host = normalize_hostname(host)
                norm_domain = extract_domain_from_hostname(norm_host)
                is_domain = norm_domain is not None and norm_host == norm_domain
                asset_type = AssetType.DOMAIN if is_domain else AssetType.HOST
                asset_id = generate_asset_id(self.engagement_id, asset_type.value, norm_host)
                if asset_id not in asset_map:
                    asset_map[asset_id] = Asset(
                        asset_id=asset_id,
                        engagement_id=self.engagement_id,
                        asset_type=asset_type,
                        hostname=norm_host,
                        domain=norm_domain,
                        status=AssetStatus.ACTIVE.value,
                        source=source,
                        first_seen=now,
                        last_seen=now,
                        evidence_refs=list(base_evidence),
                        metadata={"discovered_not_authorized": True},
                    )

            # Create or identify corresponding Service (HTTP/HTTPS)
            effective_port = port or (443 if scheme == "https" else 80)
            service_id = generate_service_id(self.engagement_id, asset_id, "tcp", effective_port)
            if service_id not in service_map:
                service_map[service_id] = Service(
                    service_id=service_id,
                    asset_id=asset_id,
                    engagement_id=self.engagement_id,
                    port=effective_port,
                    protocol="tcp",
                    state="open",
                    service_name=scheme,
                    product=f"{scheme.upper()} Service",
                    source=source,
                    first_seen=now,
                    last_seen=now,
                    evidence_refs=list(base_evidence),
                    metadata={"discovered_not_authorized": True},
                )

            # Generate canonical Endpoint ID
            ep_id = generate_endpoint_id(self.engagement_id, asset_id, scheme, host, port, path)

            # Aggregate parameters: combine from URL + discovered forms + dep.parameters
            all_params_dict: dict[str, Parameter] = {}
            for p in self.extract_parameters_from_url(dep.url):
                all_params_dict[f"{p.location.value}:{p.name}"] = p
            for p in dep.parameters:
                all_params_dict[f"{p.location.value}:{p.name}"] = p
            for form in dep.forms:
                for fld in form.fields:
                    p = Parameter(
                        name=fld.name,
                        location=ParameterLocation.FORM,
                        param_type=fld.field_type,
                        sample_value=fld.default_value,
                        required=fld.required,
                        description=f"Field in form {form.action}",
                    )
                    all_params_dict[f"{p.location.value}:{p.name}"] = p

            methods = {dep.method.value} if dep.method else {"GET"}

            # Check authorization status against ScopeGuard if available
            is_authorized = False
            if self.scope_guard:
                is_authorized = self.scope_guard.validate_url(dep.url)

            combined_evidence = list(set(base_evidence + (dep.evidence_refs or [])))

            if ep_id in endpoint_map:
                existing_ep = endpoint_map[ep_id]
                existing_ep.last_seen = now
                existing_methods = set(existing_ep.metadata.get("methods", []))
                existing_methods.update(methods)
                existing_ep.metadata["methods"] = sorted(existing_methods)

                # Merge parameters
                existing_params = {
                    f"{p['location']}:{p['name']}": p
                    for p in existing_ep.metadata.get("parameters", [])
                }
                for k, p in all_params_dict.items():
                    existing_params[k] = p.model_dump()
                existing_ep.metadata["parameters"] = list(existing_params.values())

                # Merge evidence refs
                merged_refs = list(set(existing_ep.evidence_refs + combined_evidence))
                existing_ep.evidence_refs = merged_refs
            else:
                endpoint_map[ep_id] = Endpoint(
                    endpoint_id=ep_id,
                    engagement_id=self.engagement_id,
                    asset_id=asset_id,
                    scheme=scheme,
                    host=host,
                    port=port,
                    path=path,
                    query_metadata={
                        "depth": dep.depth,
                        "status_code": dep.status_code,
                        "content_type": dep.content_type,
                    },
                    source=source,
                    confidence=1.0,
                    first_seen=now,
                    last_seen=now,
                    evidence_refs=combined_evidence,
                    metadata={
                        "discovered_not_authorized": True,
                        "in_authorized_scope": is_authorized,
                        "methods": sorted(methods),
                        "parameters": [p.model_dump() for p in all_params_dict.values()],
                        "forms": [f.model_dump() for f in dep.forms],
                        "source": source,
                    },
                )

        return NormalizedAssetBundle(
            engagement_id=self.engagement_id,
            assets=list(asset_map.values()),
            services=list(service_map.values()),
            endpoints=list(endpoint_map.values()),
        )

    def integrate_crawl_result(
        self,
        crawl_result: CrawlResult,
        evidence_content: str | bytes | None = None,
        execution_id: str | None = None,
        task_id: str | None = None,
    ) -> NormalizedAssetBundle:
        """Process results of a WebCrawler execution and optionally store evidence."""
        evidence_refs: list[str] = []

        if self.evidence_store and evidence_content is not None:
            raw_bytes = (
                evidence_content.encode("utf-8")
                if isinstance(evidence_content, str)
                else evidence_content
            )
            item = self.evidence_store.record_evidence(
                execution_id=execution_id or str(uuid.uuid4()),
                request_id=str(uuid.uuid4()),
                engagement_id=self.engagement_id,
                task_id=task_id or str(uuid.uuid4()),
                content=raw_bytes,
                evidence_type=EvidenceType.STRUCTURED_RESULT.value,
                tool_name="web_crawler",
                metadata={"target_url": crawl_result.target_url},
            )
            evidence_refs.append(item.evidence_id)

        endpoints = (
            list(crawl_result.endpoints.values())
            if isinstance(crawl_result.endpoints, dict)
            else list(crawl_result.endpoints)
        )
        return self.build_bundle_from_discovered_endpoints(
            endpoints=endpoints,
            source="web_crawler",
            default_evidence_refs=evidence_refs,
        )

    async def persist_bundle(self, bundle: NormalizedAssetBundle) -> None:
        """Persist bundle to the configured AssetRepository."""
        if self.repository is None:
            raise ValueError("No asset repository configured on WebDiscoveryIntegrator.")
        res = self.repository.save_bundle(bundle)
        if asyncio.iscoroutine(res):
            await res
