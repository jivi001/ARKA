"""Domain models for OpenAPI and Swagger schema analysis."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from arka.app.web.models.http import HTTPMethod
from arka.app.web.models.parameters import Parameter


class OpenAPIServer(BaseModel):
    """Normalized API server definition declared in the OpenAPI specification."""

    model_config = ConfigDict(frozen=True)

    url: str = Field(..., description="Server URL specified in document")
    description: str | None = Field(default=None)
    in_authorized_scope: bool = Field(
        default=False,
        description="Whether server target is verified within ARKA's authorized scope",
    )


class OpenAPISecurityScheme(BaseModel):
    """Normalized security scheme definition (e.g. bearer, apiKey, oauth2)."""

    model_config = ConfigDict(frozen=True)

    scheme_name: str = Field(..., description="Name of the security scheme in components")
    scheme_type: str = Field(..., description="apiKey, http, oauth2, openIdConnect")
    location: str | None = Field(default=None, description="header, query, or cookie for apiKey")
    param_name: str | None = Field(default=None, description="Header or parameter name")
    http_scheme: str | None = Field(default=None, description="bearer, basic for http")
    bearer_format: str | None = Field(default=None, description="JWT, etc.")
    description: str | None = Field(default=None)


class OpenAPIOperation(BaseModel):
    """Normalized API operation for a specific path and HTTP method."""

    model_config = ConfigDict(frozen=True)

    path: str = Field(..., description="Path template, e.g. /users/{id}")
    method: HTTPMethod = Field(..., description="HTTP method (GET, POST, etc.)")
    operation_id: str | None = Field(default=None)
    summary: str | None = Field(default=None)
    description: str | None = Field(default=None)
    tags: list[str] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)
    request_body_content_types: list[str] = Field(default_factory=list)
    security_requirements: list[str] = Field(default_factory=list)
    is_destructive: bool = Field(
        default=False,
        description="Flag indicating destructive action requiring policy validation",
    )


class OpenAPISchema(BaseModel):
    """Normalized representation of an analyzed OpenAPI/Swagger specification."""

    model_config = ConfigDict(frozen=True)

    title: str = Field(default="Untitled API")
    version: str = Field(default="1.0.0")
    spec_version: str = Field(
        default="3.0.0", description="OpenAPI version (e.g. 3.0.0) or Swagger (2.0)"
    )
    description: str | None = Field(default=None)
    source_url: str = Field(..., description="URL where the OpenAPI document was retrieved")
    servers: list[OpenAPIServer] = Field(default_factory=list)
    operations: list[OpenAPIOperation] = Field(default_factory=list)
    security_schemes: dict[str, OpenAPISecurityScheme] = Field(default_factory=dict)
    raw_size_bytes: int = Field(default=0)
    document_hash: str = Field(default="", description="SHA-256 digest of document")
    metadata: dict[str, Any] = Field(default_factory=dict)
