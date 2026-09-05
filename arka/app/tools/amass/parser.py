"""Amass output parser for ARKA.

Parses Amass JSON/JSONL output into structured AmassResult models.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from arka.app.tools.amass.schemas import AmassAddress, AmassRecord, AmassResult

logger = logging.getLogger(__name__)


def parse_amass_json(raw_output: str, domain: str = "") -> AmassResult:
    """Parse Amass JSON/JSONL output into AmassResult."""
    clean_text = raw_output.strip()
    if not clean_text:
        return AmassResult(success=True, domain=domain, records=[], raw_json="")

    records: list[AmassRecord] = []

    # 1. Try parsing full JSON array
    try:
        data = json.loads(clean_text)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    rec = _parse_single_record(item, domain)
                    if rec:
                        records.append(rec)
            return AmassResult(success=True, domain=domain, records=records, raw_json=clean_text)
        elif isinstance(data, dict):
            rec = _parse_single_record(data, domain)
            if rec:
                records.append(rec)
            return AmassResult(success=True, domain=domain, records=records, raw_json=clean_text)
    except json.JSONDecodeError:
        pass

    # 2. Try parsing line-by-line JSONL
    for line in clean_text.splitlines():
        line_str = line.strip()
        if not line_str:
            continue
        try:
            item = json.loads(line_str)
            if isinstance(item, dict):
                rec = _parse_single_record(item, domain)
                if rec:
                    records.append(rec)
        except json.JSONDecodeError:
            pass

    return AmassResult(
        success=True,
        domain=domain,
        records=records,
        raw_json=clean_text,
        metadata={"record_count": len(records)},
    )


def _parse_single_record(item: dict[str, Any], default_domain: str) -> AmassRecord | None:
    """Parse a single Amass JSON record."""
    name = item.get("name")
    if not name:
        return None

    domain = item.get("domain") or default_domain
    tag = item.get("tag") or "dns"

    sources_raw = item.get("sources") or []
    sources = (
        [str(s) for s in sources_raw]
        if isinstance(sources_raw, list)
        else [str(sources_raw)]
        if sources_raw
        else []
    )

    addresses_raw = item.get("addresses") or []
    addresses: list[AmassAddress] = []
    if isinstance(addresses_raw, list):
        for addr_item in addresses_raw:
            if isinstance(addr_item, dict) and "ip" in addr_item:
                addresses.append(
                    AmassAddress(
                        ip=str(addr_item["ip"]),
                        cidr=str(addr_item.get("cidr")) if addr_item.get("cidr") else None,
                        asn=int(addr_item["asn"]) if addr_item.get("asn") is not None else None,
                        desc=str(addr_item.get("desc")) if addr_item.get("desc") else None,
                    )
                )

    return AmassRecord(
        name=str(name).strip().lower(),
        domain=str(domain).strip().lower(),
        addresses=addresses,
        tag=str(tag),
        sources=sources,
    )
