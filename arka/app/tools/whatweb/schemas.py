"""WhatWeb domain models and safe argument construction for ARKA.

Enforces strict typed options for WhatWeb web technology fingerprinter.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class WhatWebScanConfig(BaseModel):
    """Safe, strongly-typed WhatWeb scan configuration.

    Allowed options:
    - aggression: 1 (stealthy) or 3 (aggressive). Values >= 3 escalate risk to HIGH.
    - no_errors: suppress error output.
    """

    aggression: int = Field(
        default=1,
        ge=1,
        le=3,
        description="Aggression level (1=stealthy, 3=aggressive). Value 3 escalates to HIGH.",
    )
    no_errors: bool = Field(
        default=True,
        description="Suppress error messages in WhatWeb output.",
    )

    def requires_escalation(self) -> bool:
        """Derive if aggression level requires human approval."""
        return self.aggression >= 3

    def to_argv(self, target: str) -> list[str]:
        """Construct safe WhatWeb argument list."""
        argv: list[str] = [
            "whatweb",
            f"-a{self.aggression}",
            "--color=never",
            "--log-json=-",
        ]
        if self.no_errors:
            argv.append("--no-errors")
        argv.append(target.strip())
        return argv


class WhatWebPlugin(BaseModel):
    """A detected technology plugin from WhatWeb."""

    name: str
    version: list[str] = Field(default_factory=list)
    string: list[str] = Field(default_factory=list)
    cpe: list[str] = Field(default_factory=list)
    confidence: float = 1.0


class WhatWebTarget(BaseModel):
    """Parsed WhatWeb observation for a single target."""

    target: str
    http_status: int = 200
    plugins: dict[str, WhatWebPlugin] = Field(default_factory=dict)


class WhatWebResult(BaseModel):
    """Structured result from WhatWeb scanning."""

    success: bool = True
    error: str | None = None
    targets: list[WhatWebTarget] = Field(default_factory=list)
    raw_json: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
