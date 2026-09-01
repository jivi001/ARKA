"""Canonical ARKA Asset, Service, Technology, and Endpoint Models."""

from arka.app.core.assets.identity import (
    ARKA_ASSET_NAMESPACE,
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
from arka.app.core.assets.normalizer import AssetNormalizer
from arka.app.core.assets.repository import AssetRepository, InMemoryAssetRepository

__all__ = [
    "ARKA_ASSET_NAMESPACE",
    "Asset",
    "AssetNormalizer",
    "AssetRepository",
    "AssetStatus",
    "AssetType",
    "Endpoint",
    "InMemoryAssetRepository",
    "NormalizedAssetBundle",
    "ObservationConflict",
    "Service",
    "Technology",
    "extract_domain_from_hostname",
    "generate_asset_id",
    "generate_endpoint_id",
    "generate_service_id",
    "generate_technology_id",
    "normalize_domain",
    "normalize_hostname",
    "normalize_ip",
    "normalize_protocol",
    "normalize_url",
]
