"""Nuclei domain models and safe argument construction for ARKA.

All models are Pydantic v2 BaseModels. NucleiScanConfig enforces an explicit
argument allowlist — only typed, validated fields can appear in the generated argv.
The LLM has zero access to raw Nuclei CLI flags.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

_SAFE_TAG_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")
_SAFE_TEMPLATE_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\/]+$")
_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class NucleiScanConfig(BaseModel):
    """Safe, strongly-typed Nuclei scan configuration.

    Exposes ONLY explicitly allowed scan parameters.
    No raw flag passthrough or shell execution.
    """

    templates: list[str] | None = Field(
        default=None,
        description="Allowed template names/categories (e.g. ['cves', 'misconfiguration']).",
    )
    tags: list[str] | None = Field(
        default=None,
        description="Allowed tags (e.g. ['cve', 'tech']).",
    )
    severity: list[str] | None = Field(
        default=None,
        description="Severities to include: 'info', 'low', 'medium', 'high', 'critical'.",
    )
    rate_limit: int = Field(
        default=50,
        ge=1,
        le=150,
        description="Rate limit (requests per second). Values > 100 escalate risk to HIGH.",
    )
    timeout: int = Field(
        default=5,
        ge=1,
        le=30,
        description="Request timeout in seconds.",
    )

    @field_validator("templates")
    @classmethod
    def validate_templates(cls, v: list[str] | None) -> list[str] | None:
        if not v:
            return None
        clean: list[str] = []
        for t in v:
            item = t.strip()
            if not item:
                continue
            if ".." in item or item.startswith("/") or not _SAFE_TEMPLATE_PATTERN.match(item):
                raise ValueError(
                    f"Invalid template path '{t}': only alphanumeric relative paths allowed"
                )
            clean.append(item)
        return clean or None

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: list[str] | None) -> list[str] | None:
        if not v:
            return None
        clean: list[str] = []
        for t in v:
            item = t.strip().lower()
            if not item:
                continue
            if not _SAFE_TAG_PATTERN.match(item):
                raise ValueError(
                    f"Invalid tag '{t}': only alphanumeric characters and hyphens allowed"
                )
            clean.append(item)
        return clean or None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: list[str] | None) -> list[str] | None:
        if not v:
            return None
        clean: list[str] = []
        for s in v:
            item = s.strip().lower()
            if not item:
                continue
            if item not in _ALLOWED_SEVERITIES:
                raise ValueError(
                    f"Invalid severity '{s}': must be one of {sorted(_ALLOWED_SEVERITIES)}"
                )
            clean.append(item)
        return clean or None

    def requires_escalation(self) -> bool:
        """Derive whether the scan requires HIGH risk escalation.

        Triggers HIGH risk if:
        - High or Critical severity findings are actively targeted
        - High rate limit (>100 rps)
        """
        return self.rate_limit > 100 or bool(
            self.severity and any(s in ("high", "critical") for s in self.severity)
        )

    def to_argv(self, target: str) -> list[str]:
        """Construct safe Nuclei argument list from typed fields only."""
        argv: list[str] = [
            "nuclei",
            "-target",
            target,
            "-json-export",
            "-",
            "-rate-limit",
            str(self.rate_limit),
            "-timeout",
            str(self.timeout),
            "-no-color",
            "-silent",
        ]
        if self.templates:
            argv.extend(["-t", ",".join(self.templates)])
        if self.tags:
            argv.extend(["-tags", ",".join(self.tags)])
        if self.severity:
            argv.extend(["-severity", ",".join(self.severity)])

        return argv


class NucleiFinding(BaseModel):
    """Parsed single vulnerability finding from Nuclei output."""

    template_id: str
    name: str
    severity: str = "low"
    type: str = "http"
    host: str = ""
    matched_at: str = ""
    description: str = ""
    reference: list[str] = Field(default_factory=list)
    cve_id: str | None = None
    cvss_score: float | None = None
    curl_command: str | None = None
    extracted_results: list[str] = Field(default_factory=list)
    timestamp: str = ""


class NucleiResult(BaseModel):
    """Structured result from Nuclei scan."""

    success: bool = True
    error: str | None = None
    findings: list[NucleiFinding] = Field(default_factory=list)
    target: str = ""
    raw_json: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
