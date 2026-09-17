"""Web endpoint and form discovery models for ARKA Web Security.

Defines rich representation of endpoints, forms, and parameter interactions
discovered during reconnaissance before normalization into canonical models.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from arka.app.web.models.http import HTTPMethod
from arka.app.web.models.parameters import Parameter


class FormField(BaseModel):
    """An input field discovered inside an HTML form."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., min_length=1, description="Field name attribute")
    field_type: str = Field(
        default="text", description="Input type (text, password, hidden, email, etc.)"
    )
    default_value: str | None = Field(default=None, description="Preset value attribute if present")
    required: bool = Field(default=False, description="Whether the required attribute was present")


class DiscoveredForm(BaseModel):
    """An HTML form discovered on a web page."""

    model_config = ConfigDict(frozen=True)

    action: str = Field(..., description="Target action URL or relative path")
    method: HTTPMethod = Field(default=HTTPMethod.GET, description="Form submission HTTP method")
    fields: list[FormField] = Field(default_factory=list, description="Extracted input fields")
    form_id: str | None = Field(default=None, description="Form id attribute")
    form_name: str | None = Field(default=None, description="Form name attribute")
    page_url: str = Field(..., description="URL of the page containing the form")


class DiscoveredWebEndpoint(BaseModel):
    """An HTTP endpoint discovered during crawling or API analysis.

    CRITICAL INVARIANT: DISCOVERED != AUTHORIZED.
    Discovery of an endpoint does not grant execution or scanning authority.
    """

    model_config = ConfigDict(frozen=True)

    url: str = Field(..., description="Full canonical URL of the discovered endpoint")
    scheme: str = Field(default="http")
    host: str = Field(default="")
    port: int = Field(default=80)
    path: str = Field(default="/")
    method: HTTPMethod = Field(default=HTTPMethod.GET)
    parameters: list[Parameter] = Field(default_factory=list)
    forms: list[DiscoveredForm] = Field(default_factory=list)
    status_code: int | None = Field(default=None)
    content_type: str | None = Field(default=None)
    auth_required: bool = Field(default=False)
    source: str = Field(default="crawler")
    title: str | None = Field(default=None)
    depth: int = Field(default=0, ge=0)
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def populate_url_parts(cls, data: Any) -> Any:
        if isinstance(data, dict) and "url" in data:
            url_str = str(data["url"])
            parsed = urllib.parse.urlparse(url_str)
            if "scheme" not in data or not data["scheme"]:
                data["scheme"] = (parsed.scheme or "http").lower()
            if "host" not in data or not data["host"]:
                data["host"] = (parsed.hostname or "").lower()
            if "port" not in data or data["port"] is None:
                if parsed.port:
                    data["port"] = parsed.port
                else:
                    data["port"] = 443 if data["scheme"] == "https" else 80
            if "path" not in data or not data["path"]:
                data["path"] = parsed.path or "/"
        return data
