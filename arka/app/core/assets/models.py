"""Canonical Asset, Service, Technology, and Endpoint domain models for ARKA.

These models represent normalized, tool-independent observations of target
infrastructure. Tool observations NEVER automatically expand authorization scope.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from arka.app.core.state.models import new_id


def utc_now() -> datetime:
    return datetime.now(UTC)


class AssetType(str, Enum):
    """Supported canonical asset types."""

    IP = "ip"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    HOST = "host"
    URL = "url"


class AssetStatus(str, Enum):
    """Operational status of a discovered asset."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    DOWN = "down"


class Asset(BaseModel):
    """Canonical representation of an infrastructure asset."""

    asset_id: str
    engagement_id: str
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    asset_type: AssetType = AssetType.IP
    address: str | None = None
    address_type: str | None = None  # "ipv4", "ipv6", etc.
    hostname: str | None = None
    domain: str | None = None
    status: str = "active"
    source: str = "nmap"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Service(BaseModel):
    """Canonical representation of a network service running on an Asset."""

    service_id: str
    asset_id: str
    engagement_id: str
    port: int
    protocol: str = "tcp"
    state: str = "open"  # "open", "filtered", "closed", "unknown"
    service_name: str = ""
    product: str | None = None
    version: str | None = None
    cpe: list[str] = Field(default_factory=list)
    banner: str | None = None
    source: str = "nmap"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Technology(BaseModel):
    """Canonical representation of software/technology detected on an asset/service."""

    technology_id: str
    engagement_id: str
    asset_id: str
    service_id: str | None = None
    name: str
    version: str | None = None
    cpe: list[str] = Field(default_factory=list)
    source: str = "nmap"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Endpoint(BaseModel):
    """Canonical representation of an HTTP endpoint discovered on an asset/service."""

    endpoint_id: str
    engagement_id: str
    asset_id: str
    scheme: str = "http"
    host: str
    port: int | None = None
    path: str = "/"
    query_metadata: dict[str, Any] = Field(default_factory=dict)
    source: str = "ffuf"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ObservationConflict(BaseModel):
    """Captures conflicting observations across tools or time without overwriting history."""

    conflict_id: str = Field(default_factory=new_id)
    engagement_id: str
    entity_type: str  # "asset", "service", "technology", "endpoint"
    entity_id: str
    field_name: str
    existing_value: Any
    observed_value: Any
    source: str
    observed_at: datetime = Field(default_factory=utc_now)
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalizedAssetBundle(BaseModel):
    """Complete bundle of normalized observations produced by an AssetNormalizer."""

    engagement_id: str
    assets: list[Asset] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    technologies: list[Technology] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    conflicts: list[ObservationConflict] = Field(default_factory=list)
