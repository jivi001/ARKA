"""ffuf output parser for ARKA.

Parses ffuf JSON output into structured FfufResult and FfufMatch models.
"""

from __future__ import annotations

import json
import logging

from arka.app.tools.ffuf.schemas import FfufMatch, FfufResult

logger = logging.getLogger(__name__)


def parse_ffuf_json(raw_output: str, target_url: str = "") -> FfufResult:
    """Parse ffuf JSON output into FfufResult."""
    clean_text = raw_output.strip()
    if not clean_text:
        return FfufResult(success=True, matches=[], target_url=target_url, raw_json="")

    try:
        data = json.loads(clean_text)
    except json.JSONDecodeError as e:
        return FfufResult(
            success=False,
            error=f"ffuf JSON decode error: {e}",
            matches=[],
            target_url=target_url,
            raw_json=clean_text,
        )

    results = data.get("results", [])
    if not isinstance(results, list):
        results = []

    matches: list[FfufMatch] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        url = str(r.get("url") or "")
        fuzz_input = r.get("input", {})
        path = ""
        if isinstance(fuzz_input, dict):
            path = str(fuzz_input.get("FUZZ") or "")
        elif isinstance(fuzz_input, str):
            path = fuzz_input

        if not path and url:
            # Extract path from URL
            try:
                import urllib.parse

                parsed = urllib.parse.urlparse(url)
                path = parsed.path
            except Exception:
                path = url

        status = int(r.get("status", 200))
        length = int(r.get("length", 0))
        words = int(r.get("words", 0))
        lines = int(r.get("lines", 0))
        redirect = r.get("redirectlocation")

        matches.append(
            FfufMatch(
                url=url,
                path=path if path.startswith("/") else f"/{path}",
                status=status,
                length=length,
                words=words,
                lines=lines,
                redirect_location=str(redirect) if redirect else None,
            )
        )

    config = data.get("config", {})
    return FfufResult(
        success=True,
        matches=matches,
        target_url=target_url or str(config.get("url", "")),
        raw_json=clean_text,
        metadata={"total_matches": len(matches), "commandline": str(data.get("commandline", ""))},
    )
