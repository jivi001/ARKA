"""Deterministic identity and normalization rules for canonical assets.

Provides deterministic UUID5 generation based on canonical namespace and
normalized target properties (IP, hostname, domain, URL, service, technology, endpoint).
Asset identities are stable across scans, timestamps, ordering, and tool implementations.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
import uuid

# Fixed ARKA Asset Namespace UUID for deterministic UUID5 generation
ARKA_ASSET_NAMESPACE = uuid.UUID("a7e6b8c0-5f21-4d32-9c1a-8e7d6b5c4a3f")

# Regex for basic domain validation
_DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def normalize_ip(ip_str: str) -> tuple[str, str]:
    """Normalize an IPv4 or IPv6 address.

    Returns:
        tuple[str, str]: (normalized_address, address_type) where address_type
        is 'ipv4' or 'ipv6'.

    Raises:
        ValueError: If ip_str is not a valid IP address.
    """
    clean_ip = ip_str.strip()
    # Handle optional brackets around IPv6 addresses like [::1]
    if clean_ip.startswith("[") and clean_ip.endswith("]"):
        clean_ip = clean_ip[1:-1]

    # Handle leading zeros in IPv4 octets (e.g. 192.168.001.010 -> 192.168.1.10)
    if "." in clean_ip and ":" not in clean_ip:
        parts = clean_ip.split(".")
        if len(parts) == 4:
            clean_parts = []
            for p in parts:
                if p.isdigit():
                    clean_parts.append(str(int(p)))
                else:
                    clean_parts.append(p)
            clean_ip = ".".join(clean_parts)

    ip_obj = ipaddress.ip_address(clean_ip)
    addr_type = "ipv4" if isinstance(ip_obj, ipaddress.IPv4Address) else "ipv6"
    return ip_obj.compressed, addr_type


def normalize_domain(domain_str: str) -> str:
    """Normalize a domain name to lowercase, stripped, without trailing dots."""
    clean = domain_str.strip().lower()
    if clean.endswith("."):
        clean = clean[:-1]
    return clean


def normalize_hostname(hostname_str: str) -> str:
    """Normalize a hostname to lowercase, stripped, without trailing dots."""
    return normalize_domain(hostname_str)


def extract_domain_from_hostname(hostname: str) -> str | None:
    """Extract registered domain from a fully-qualified hostname if possible.

    For example, 'web.sub.example.com' -> 'example.com'.
    """
    clean = normalize_hostname(hostname)
    # If it's an IP address, return None
    try:
        ipaddress.ip_address(clean)
        return None
    except ValueError:
        pass

    parts = clean.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return None


def normalize_url(url_str: str) -> tuple[str, str, int | None, str]:
    """Normalize a URL.

    Returns:
        tuple[str, str, int | None, str]: (scheme, host, port, path)
    """
    parsed = urllib.parse.urlparse(url_str.strip())
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port is None:
        if scheme == "http":
            port = 80
        elif scheme == "https":
            port = 443

    path = parsed.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    # Remove duplicate slashes
    path = re.sub(r"/+", "/", path)

    return scheme, host, port, path


def normalize_protocol(protocol: str) -> str:
    """Normalize network protocol string to lowercase ('tcp', 'udp', etc.)."""
    return protocol.strip().lower()


def generate_asset_id(
    engagement_id: str,
    asset_type: str,
    identifier: str,
) -> str:
    """Generate a deterministic UUID string for an Asset.

    Identity key format: engagement:{engagement_id}:{asset_type.lower()}:{normalized_identifier}
    """
    key = f"engagement:{engagement_id}:{asset_type.lower()}:{identifier.strip().lower()}"
    return str(uuid.uuid5(ARKA_ASSET_NAMESPACE, key))


def generate_service_id(
    engagement_id: str,
    asset_id: str,
    protocol: str,
    port: int,
) -> str:
    """Generate a deterministic UUID string for a Service.

    Identity key format: engagement:{engagement_id}:service:{asset_id}:{protocol.lower()}:{port}
    """
    proto = normalize_protocol(protocol)
    key = f"engagement:{engagement_id}:service:{asset_id}:{proto}:{port}"
    return str(uuid.uuid5(ARKA_ASSET_NAMESPACE, key))


def generate_technology_id(
    engagement_id: str,
    asset_id: str,
    service_id: str | None,
    name: str,
    version: str | None = None,
) -> str:
    """Generate a deterministic UUID string for a Technology observation.

    Identity key format:
    engagement:{engagement_id}:tech:{asset_id}:{service_id}:{name}:{version}
    """
    svc_part = service_id or ""
    ver_part = (version or "").strip().lower()
    name_part = name.strip().lower()
    key = f"engagement:{engagement_id}:tech:{asset_id}:{svc_part}:{name_part}:{ver_part}"
    return str(uuid.uuid5(ARKA_ASSET_NAMESPACE, key))


def generate_endpoint_id(
    engagement_id: str,
    asset_id: str,
    scheme: str,
    host: str,
    port: int | None,
    path: str,
) -> str:
    """Generate a deterministic UUID string for an Endpoint.

    Identity key format:
    engagement:{engagement_id}:endpoint:{asset_id}:{scheme}:{host}:{port}:{path}
    """
    scheme_norm = (scheme or "http").strip().lower()
    host_norm = (host or "").strip().lower()
    port_norm = str(port) if port is not None else ""
    path_norm = path if path.startswith("/") else f"/{path}"
    path_norm = re.sub(r"/+", "/", path_norm)
    key = (
        f"engagement:{engagement_id}:endpoint:{asset_id}:"
        f"{scheme_norm}:{host_norm}:{port_norm}:{path_norm}"
    )
    return str(uuid.uuid5(ARKA_ASSET_NAMESPACE, key))
