"""Nuclei output parser for ARKA.

Parses Nuclei JSON or JSONL stdout into structured NucleiResult and NucleiFinding models.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from arka.app.tools.nuclei.schemas import NucleiFinding, NucleiResult

logger = logging.getLogger(__name__)


def parse_nuclei_json(raw_output: str, target: str = "") -> NucleiResult:
    """Parse Nuclei JSON/JSONL output into a strongly typed NucleiResult.

    Supports both JSON array syntax and newline-delimited JSON (JSONL).
    """
    clean_text = raw_output.strip()
    if not clean_text:
        return NucleiResult(success=True, findings=[], target=target, raw_json="")

    findings: list[NucleiFinding] = []

    # 1. Try parsing as full JSON array or single object
    try:
        parsed_data = json.loads(clean_text)
        if isinstance(parsed_data, list):
            for item in parsed_data:
                if isinstance(item, dict):
                    finding = _parse_single_finding(item)
                    if finding:
                        findings.append(finding)
            return NucleiResult(success=True, findings=findings, target=target, raw_json=clean_text)
        elif isinstance(parsed_data, dict):
            finding = _parse_single_finding(parsed_data)
            if finding:
                findings.append(finding)
            return NucleiResult(success=True, findings=findings, target=target, raw_json=clean_text)
    except json.JSONDecodeError:
        pass

    # 2. Try parsing line by line (JSONL format, standard for Nuclei CLI)
    lines = clean_text.splitlines()
    parse_errors = 0
    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            item = json.loads(line_str)
            if isinstance(item, dict):
                finding = _parse_single_finding(item)
                if finding:
                    findings.append(finding)
        except json.JSONDecodeError:
            parse_errors += 1
            logger.debug("Skipping unparseable nuclei line: %s", line_str[:100])

    return NucleiResult(
        success=True,
        findings=findings,
        target=target,
        raw_json=clean_text,
        metadata={"parsed_lines": len(lines), "parse_errors": parse_errors},
    )


def _parse_single_finding(item: dict[str, Any]) -> NucleiFinding | None:
    """Extract a NucleiFinding from a raw nuclei dictionary."""
    template_id = item.get("template-id") or item.get("template_id") or item.get("id")
    if not template_id:
        return None

    info = item.get("info", {})
    if not isinstance(info, dict):
        info = {}

    name = info.get("name") or template_id
    severity = str(info.get("severity") or "low").lower()
    description = info.get("description") or ""

    # References
    refs = info.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]
    elif not isinstance(refs, list):
        refs = []

    # Classification: CVE / CVSS
    classification = info.get("classification", {})
    cve_id: str | None = None
    cvss_score: float | None = None
    if isinstance(classification, dict):
        raw_cve = classification.get("cve-id")
        if isinstance(raw_cve, list) and raw_cve:
            cve_id = str(raw_cve[0])
        elif isinstance(raw_cve, str):
            cve_id = raw_cve

        raw_cvss = classification.get("cvss-score")
        if raw_cvss is not None:
            import contextlib

            with contextlib.suppress(ValueError, TypeError):
                cvss_score = float(raw_cvss)

    # Extraction
    extracted_raw = item.get("extracted-results") or item.get("extracted_results") or []
    if isinstance(extracted_raw, list):
        extracted_results = [str(x) for x in extracted_raw]
    elif isinstance(extracted_raw, str):
        extracted_results = [extracted_raw]
    else:
        extracted_results = []

    host = str(item.get("host") or "")
    matched_at = str(item.get("matched-at") or item.get("matched_at") or host)
    curl_command = item.get("curl-command") or item.get("curl_command")

    return NucleiFinding(
        template_id=str(template_id),
        name=str(name),
        severity=severity,
        type=str(item.get("type") or "http"),
        host=host,
        matched_at=matched_at,
        description=str(description),
        reference=[str(r) for r in refs],
        cve_id=cve_id,
        cvss_score=cvss_score,
        curl_command=str(curl_command) if curl_command else None,
        extracted_results=extracted_results,
        timestamp=str(item.get("timestamp") or ""),
    )
