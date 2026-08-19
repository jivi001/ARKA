"""Nmap XML parser for ARKA Phase 2.2.1.

Uses defusedxml exclusively (mandatory, not optional) to prevent XML entity
expansion attacks, billion-laughs, and external entity injection.

All XML content is treated as untrusted, target-controlled data.
Malformed XML returns a controlled NmapResult with error metadata — never crashes.
"""

from __future__ import annotations

from typing import Any

import defusedxml.ElementTree as ET

from arka.app.tools.nmap.schemas import (
    NmapHost,
    NmapPort,
    NmapResult,
    NmapScript,
    NmapService,
)


def parse_nmap_xml(xml_content: str | bytes) -> NmapResult:
    """Parse Nmap XML output into a structured NmapResult.

    Args:
        xml_content: Raw Nmap XML output (string or bytes).

    Returns:
        NmapResult with parsed hosts, ports, services, and scripts.
        On malformed XML, returns NmapResult(success=False, error=...).
    """
    if isinstance(xml_content, str):
        raw_xml = xml_content
    else:
        raw_xml = xml_content.decode("utf-8", errors="replace")

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        return NmapResult(
            success=False,
            error=f"Malformed XML: {e}",
            raw_xml=raw_xml[:10_000],  # Truncate for safety
        )

    # Extract scan metadata from <nmaprun> attributes
    scan_metadata = _extract_scan_metadata(root)

    # Extract hosts
    hosts: list[NmapHost] = []
    for host_elem in root.findall("host"):
        host = _parse_host(host_elem)
        if host is not None:
            hosts.append(host)

    return NmapResult(
        success=True,
        scan_metadata=scan_metadata,
        hosts=hosts,
        raw_xml=raw_xml,
    )


def _extract_scan_metadata(root: ET.Element) -> dict[str, Any]:
    """Extract scan-level metadata from the <nmaprun> root element."""
    meta: dict[str, Any] = {}
    for attr in ("scanner", "args", "start", "startstr", "version", "xmloutputversion"):
        val = root.get(attr)
        if val is not None:
            meta[attr] = val

    # Extract runstats if present
    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            meta["end_time"] = finished.get("time", "")
            meta["elapsed"] = finished.get("elapsed", "")
            meta["exit_status"] = finished.get("exit", "")
        hosts_stat = runstats.find("hosts")
        if hosts_stat is not None:
            meta["hosts_up"] = hosts_stat.get("up", "0")
            meta["hosts_down"] = hosts_stat.get("down", "0")
            meta["hosts_total"] = hosts_stat.get("total", "0")

    return meta


def _parse_host(host_elem: ET.Element) -> NmapHost | None:
    """Parse a single <host> element into an NmapHost."""
    # Address
    address = ""
    address_type = "ipv4"
    for addr_elem in host_elem.findall("address"):
        addr_type = addr_elem.get("addrtype", "ipv4")
        addr_val = addr_elem.get("addr", "")
        if addr_type in ("ipv4", "ipv6"):
            address = addr_val
            address_type = addr_type
            break

    if not address:
        return None

    # Hostnames
    hostnames: list[str] = []
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is not None:
        for hn in hostnames_elem.findall("hostname"):
            name = hn.get("name", "")
            if name:
                hostnames.append(name)

    # Status
    status_elem = host_elem.find("status")
    status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

    # Ports
    ports: list[NmapPort] = []
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            port = _parse_port(port_elem)
            if port is not None:
                ports.append(port)

    return NmapHost(
        address=address,
        address_type=address_type,
        hostnames=hostnames,
        status=status,
        ports=ports,
    )


def _parse_port(port_elem: ET.Element) -> NmapPort | None:
    """Parse a single <port> element into an NmapPort."""
    port_id_str = port_elem.get("portid", "")
    protocol = port_elem.get("protocol", "tcp")

    try:
        port_id = int(port_id_str)
    except (ValueError, TypeError):
        return None

    # State
    state_elem = port_elem.find("state")
    state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

    # Service
    service: NmapService | None = None
    service_elem = port_elem.find("service")
    if service_elem is not None:
        cpe_list: list[str] = []
        for cpe_elem in service_elem.findall("cpe"):
            if cpe_elem.text:
                cpe_list.append(cpe_elem.text)

        service = NmapService(
            name=service_elem.get("name", ""),
            product=service_elem.get("product", ""),
            version=service_elem.get("version", ""),
            extra_info=service_elem.get("extrainfo", ""),
            cpe=cpe_list,
        )

    # Scripts
    scripts: list[NmapScript] = []
    for script_elem in port_elem.findall("script"):
        script_id = script_elem.get("id", "")
        script_output = script_elem.get("output", "")
        if script_id:
            scripts.append(NmapScript(script_id=script_id, output=script_output))

    return NmapPort(
        port=port_id,
        protocol=protocol,
        state=state,
        service=service,
        scripts=scripts,
    )
