"""Unit tests for Phase 3.3: Web Discovery Integration and Canonicalization."""

import pytest

from arka.app.core.assets.repository import InMemoryAssetRepository
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.execution.evidence import EvidenceStore
from arka.app.web.crawler.crawler import CrawlResult
from arka.app.web.discovery.integrator import WebDiscoveryIntegrator
from arka.app.web.models.endpoint import DiscoveredForm, DiscoveredWebEndpoint, FormField
from arka.app.web.models.http import HTTPMethod


@pytest.fixture
def engagement_id() -> str:
    return "11111111-1111-1111-1111-111111111111"


@pytest.fixture
def scope_guard() -> ScopeGuard:
    scope = ScopeDefinition(
        engagement_id="11111111-1111-1111-1111-111111111111",
        includes=ScopeTarget(
            domains=["app.example.com"],
            ports=[80, 443],
        ),
    )
    return ScopeGuard(scope)


@pytest.fixture
def memory_repo() -> InMemoryAssetRepository:
    return InMemoryAssetRepository()


@pytest.fixture
def temp_evidence_store() -> EvidenceStore:
    return EvidenceStore()


def test_extract_parameters_from_url(engagement_id: str) -> None:
    integrator = WebDiscoveryIntegrator(engagement_id=engagement_id)
    url = (
        "https://app.example.com/api/v1/users/{user_id}/items/:item_id?search=test&page=2&limit=50"
    )
    params = integrator.extract_parameters_from_url(url)

    param_dict = {f"{p.location.value}:{p.name}": p for p in params}

    # Verify query params
    assert "query:search" in param_dict
    assert param_dict["query:search"].sample_value == "test"
    assert "query:page" in param_dict
    assert param_dict["query:page"].sample_value == "2"
    assert "query:limit" in param_dict

    # Verify path params
    assert "path:user_id" in param_dict
    assert param_dict["path:user_id"].required is True
    assert "path:item_id" in param_dict
    assert param_dict["path:item_id"].required is True


@pytest.mark.asyncio
async def test_build_bundle_and_deduplication(
    engagement_id: str,
    memory_repo: InMemoryAssetRepository,
    scope_guard: ScopeGuard,
) -> None:
    integrator = WebDiscoveryIntegrator(
        engagement_id=engagement_id,
        asset_repository=memory_repo,
        scope_guard=scope_guard,
    )

    # Two observations of the same endpoint: one GET with query, one POST with form
    dep1 = DiscoveredWebEndpoint(
        url="https://app.example.com/login?redirect=/dashboard",
        method=HTTPMethod.GET,
        depth=1,
        status_code=200,
    )
    dep2 = DiscoveredWebEndpoint(
        url="https://app.example.com/login",
        method=HTTPMethod.POST,
        depth=1,
        forms=[
            DiscoveredForm(
                action="/login",
                method=HTTPMethod.POST,
                page_url="https://app.example.com/login",
                fields=[
                    FormField(name="username", field_type="text", required=True),
                    FormField(name="password", field_type="password", required=True),
                ],
            )
        ],
    )

    bundle = integrator.build_bundle_from_discovered_endpoints([dep1, dep2])

    # Endpoints should correlate into ONE canonical Endpoint
    assert len(bundle.endpoints) == 1
    ep = bundle.endpoints[0]
    assert ep.path == "/login"
    assert ep.host == "app.example.com"
    assert ep.scheme == "https"
    assert ep.metadata["discovered_not_authorized"] is True
    assert ep.metadata["in_authorized_scope"] is True

    # Both methods should be present
    assert sorted(ep.metadata["methods"]) == ["GET", "POST"]

    # Parameters should have merged: redirect (query) + username (form) + password (form)
    param_names = {p["name"] for p in ep.metadata["parameters"]}
    assert "redirect" in param_names
    assert "username" in param_names
    assert "password" in param_names

    # Persist and verify in repository
    await integrator.persist_bundle(bundle)
    stored = memory_repo.get_endpoints_by_engagement(engagement_id)
    assert len(stored) == 1
    assert stored[0].endpoint_id == ep.endpoint_id


def test_discovered_not_authorized_invariant(
    engagement_id: str,
    scope_guard: ScopeGuard,
) -> None:
    integrator = WebDiscoveryIntegrator(
        engagement_id=engagement_id,
        scope_guard=scope_guard,
    )

    # Discovered URL pointing to an unauthorized external target or admin
    dep_unauthorized = DiscoveredWebEndpoint(
        url="https://unauthorized-evil.com/admin",
        method=HTTPMethod.GET,
    )
    bundle = integrator.build_bundle_from_discovered_endpoints([dep_unauthorized])

    assert len(bundle.endpoints) == 1
    ep = bundle.endpoints[0]
    # DISCOVERED != AUTHORIZED:
    # It must be recorded with discovered_not_authorized=True and in_authorized_scope=False
    assert ep.metadata["discovered_not_authorized"] is True
    assert ep.metadata["in_authorized_scope"] is False
    # ScopeGuard boundary must NOT have changed!
    assert scope_guard.validate_url("https://unauthorized-evil.com/admin") is False


@pytest.mark.asyncio
async def test_integrate_crawl_result_with_evidence(
    engagement_id: str,
    memory_repo: InMemoryAssetRepository,
    temp_evidence_store: EvidenceStore,
) -> None:
    integrator = WebDiscoveryIntegrator(
        engagement_id=engagement_id,
        asset_repository=memory_repo,
        evidence_store=temp_evidence_store,
    )

    crawl_result = CrawlResult(
        target_url="https://app.example.com/",
        pages_crawled=2,
        urls_discovered=["https://app.example.com/", "https://app.example.com/about"],
        endpoints=[
            DiscoveredWebEndpoint(
                url="https://app.example.com/",
                method=HTTPMethod.GET,
                status_code=200,
            ),
            DiscoveredWebEndpoint(
                url="https://app.example.com/about",
                method=HTTPMethod.GET,
                status_code=200,
            ),
        ],
    )

    raw_evidence = b"<html>Crawler execution log mock evidence</html>"
    bundle = integrator.integrate_crawl_result(crawl_result, evidence_content=raw_evidence)

    assert len(bundle.endpoints) == 2
    assert len(bundle.assets) == 1
    assert len(bundle.services) == 1

    # Check evidence provenance
    for ep in bundle.endpoints:
        assert len(ep.evidence_refs) == 1
        ev_id = ep.evidence_refs[0]
        # Verify evidence is retrievable in evidence store
        assert temp_evidence_store.verify_integrity(ev_id) is True

    await integrator.persist_bundle(bundle)
    stored = memory_repo.get_endpoints_by_engagement(engagement_id)
    assert len(stored) == 2
