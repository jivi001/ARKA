"""Parameter models for ARKA Web and API Security Subsystem.

Defines canonical representation for parameters discovered across query strings,
path templates, headers, cookies, request bodies, forms, JSON, and GraphQL.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ParameterLocation(str, Enum):
    """Canonical locations where parameters can be supplied in web requests."""

    QUERY = "query"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"
    FORM = "form"
    JSON = "json"
    GRAPHQL = "graphql"


class Parameter(BaseModel):
    """Canonical representation of a discovered input parameter."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., min_length=1, description="Parameter name or identifier")
    location: ParameterLocation = Field(default=ParameterLocation.QUERY)
    param_type: str | None = Field(
        default=None, description="Inferred or declared type, e.g. 'string', 'integer'"
    )
    sample_value: str | None = Field(
        default=None, description="Observed sample value for discovery context"
    )
    required: bool = Field(
        default=False, description="Whether parameter is required by the API/endpoint"
    )
    description: str | None = Field(default=None, description="Parameter description if declared")
    schema_info: dict[str, Any] = Field(
        default_factory=dict, description="Additional schema metadata"
    )
