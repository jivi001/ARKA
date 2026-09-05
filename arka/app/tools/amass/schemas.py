"""Amass domain models and safe argument construction for ARKA.

Enforces strict options for Amass subdomain/DNS enumeration tool.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class AmassScanConfig(BaseModel):
    """Safe, strongly-typed Amass scan configuration.

    Allowed options:
    - mode: 'passive' (default, safe OSINT) or 'active' (active DNS resolution/probing).
            'active' escalates risk to HIGH.
    - timeout_minutes: max scan duration in minutes (1-30).
    """

    mode: str = Field(
        default="passive",
        description="Enumeration mode: 'passive' (safe OSINT) or 'active' (DNS probing).",
    )
    timeout_minutes: int = Field(
        default=5,
        ge=1,
        le=30,
        description="Timeout in minutes (1-30).",
    )

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean not in ("passive", "active"):
            raise ValueError(f"Invalid Amass mode '{v}': must be 'passive' or 'active'")
        return clean

    def requires_escalation(self) -> bool:
        """Derive whether the scan requires HIGH risk escalation."""
        return self.mode == "active"

    def to_argv(self, domain: str) -> list[str]:
        """Construct safe Amass argument list."""
        argv: list[str] = [
            "amass",
            "enum",
            "-d",
            domain.strip().lower(),
            "-json",
            "-",
            "-timeout",
            str(self.timeout_minutes),
        ]
        if self.mode == "passive":
            argv.append("-passive")
        else:
            argv.append("-active")

        return argv


class AmassAddress(BaseModel):
    """IP address information associated with an Amass DNS record."""

    ip: str
    cidr: str | None = None
    asn: int | None = None
    desc: str | None = None


class AmassRecord(BaseModel):
    """A single subdomain/DNS observation from Amass."""

    name: str
    domain: str
    addresses: list[AmassAddress] = Field(default_factory=list)
    tag: str = "dns"
    sources: list[str] = Field(default_factory=list)


class AmassResult(BaseModel):
    """Structured result from Amass subdomain enumeration."""

    success: bool = True
    error: str | None = None
    domain: str = ""
    records: list[AmassRecord] = Field(default_factory=list)
    raw_json: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
