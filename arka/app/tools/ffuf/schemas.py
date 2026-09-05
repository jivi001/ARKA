"""ffuf domain models and safe argument construction for ARKA.

Enforces an explicit argument allowlist and wordlist whitelist.
Arbitrary flags, wordlist paths, or injection characters are strictly rejected.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

_ALLOWED_WORDLISTS = {
    "common.txt",
    "directory-list-2.3-small.txt",
    "quickhits.txt",
    "raft-small-words.txt",
    "api-endpoints.txt",
    "subdomains.txt",
}

_NUM_COMMA_PATTERN = re.compile(r"^[0-9]+(,[0-9]+)*$")


class FfufScanConfig(BaseModel):
    """Safe, strongly-typed ffuf scan configuration.

    The LLM sees only safe structured parameters. CLI flags,
    arbitrary filesystem paths, and shell characters are strictly rejected.
    """

    wordlist: str = Field(
        default="common.txt",
        description="Approved wordlist name (e.g. 'common.txt', 'api-endpoints.txt').",
    )
    rate: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Max requests per second. Values > 50 escalate risk to HIGH.",
    )
    recursion: bool = Field(
        default=False,
        description="Enable directory recursion.",
    )
    recursion_depth: int = Field(
        default=1,
        ge=1,
        le=3,
        description="Recursion depth (1-3). Depth > 2 escalates risk to HIGH.",
    )
    match_codes: str = Field(
        default="200,204,301,302,307,401,403",
        description="Comma-separated HTTP status codes to match (e.g. '200,301').",
    )
    filter_codes: str = Field(
        default="404",
        description="Comma-separated HTTP status codes to filter out (e.g. '404').",
    )

    @field_validator("wordlist")
    @classmethod
    def validate_wordlist(cls, v: str) -> str:
        clean = v.strip().lower()
        # Extract base filename if path was provided
        base_name = clean.split("/")[-1].split("\\")[-1]
        if base_name not in _ALLOWED_WORDLISTS:
            raise ValueError(
                f"Wordlist '{v}' is not in approved allowlist: {sorted(_ALLOWED_WORDLISTS)}"
            )
        return base_name

    @field_validator("match_codes", "filter_codes")
    @classmethod
    def validate_codes(cls, v: str) -> str:
        clean = v.strip()
        if not _NUM_COMMA_PATTERN.match(clean):
            raise ValueError(f"Invalid status codes '{v}': only digits and commas allowed")
        return clean

    def requires_escalation(self) -> bool:
        """Check if this configuration requires risk escalation to HIGH."""
        return self.rate > 50 or self.recursion_depth > 2

    def to_argv(self, target_url: str) -> list[str]:
        """Construct safe ffuf argument list from typed fields only."""
        # Ensure target_url contains FUZZ keyword
        url = target_url.strip()
        if "FUZZ" not in url:
            url = f"{url}FUZZ" if url.endswith("/") else f"{url}/FUZZ"

        argv: list[str] = [
            "ffuf",
            "-u",
            url,
            "-w",
            f"wordlists/{self.wordlist}",
            "-mc",
            self.match_codes,
            "-fc",
            self.filter_codes,
            "-rate",
            str(self.rate),
            "-o",
            "-",
            "-of",
            "json",
            "-s",
        ]
        if self.recursion:
            argv.extend(["-recursion", "-recursion-depth", str(self.recursion_depth)])

        return argv


class FfufMatch(BaseModel):
    """A discovered endpoint match from ffuf."""

    url: str
    path: str
    status: int
    length: int = 0
    words: int = 0
    lines: int = 0
    redirect_location: str | None = None


class FfufResult(BaseModel):
    """Structured result from ffuf directory/endpoint fuzzing."""

    success: bool = True
    error: str | None = None
    matches: list[FfufMatch] = Field(default_factory=list)
    target_url: str = ""
    raw_json: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
