"""Validation and normalization routines for ARKA scope definitions.

Enforces strict syntax, bounds, and security boundaries on scope targets
before persistence or authorization evaluation.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
from urllib.parse import urlparse

from arka.app.core.state.models import ScopeDefinition, ScopeTarget

# RFC 1123 compliant domain label regex
_DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
# Dangerous shell or injection characters
_DISALLOWED_CHARS = re.compile(r"[\s/\\?#;\"'&|`$<>{}\[\]()!*]")


class ScopeValidationError(ValueError):
    """Raised when a scope definition fails structural, syntactic, or boundary validation."""

    def __init__(self, message: str, field: str | None = None) -> None:
        self.field = field
        super().__init__(
            f"Scope validation error: {message}"
            if not field
            else f"Scope validation error [{field}]: {message}"
        )


def validate_domain_name(domain: str) -> str:
    """Validate and normalize a domain name.

    Returns the normalized lowercase domain.
    Raises ScopeValidationError on syntax, injection, or formatting violations.
    """
    cleaned = domain.strip().lower()
    if not cleaned:
        raise ScopeValidationError("Domain name cannot be empty", field="domains")

    # Handle optional leading wildcard e.g. *.example.com -> example.com
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]

    if not cleaned:
        raise ScopeValidationError(
            "Wildcard domain must specify a valid base domain", field="domains"
        )

    # Reject disallowed characters (spaces, slashes, shell injection metacharacters)
    if _DISALLOWED_CHARS.search(cleaned):
        raise ScopeValidationError(
            f"Domain '{domain}' contains invalid characters or potential injection syntax",
            field="domains",
        )

    labels = cleaned.split(".")
    for label in labels:
        if not label:
            raise ScopeValidationError(
                f"Domain '{domain}' has empty label (consecutive dots)", field="domains"
            )
        if not _DOMAIN_LABEL_REGEX.match(label):
            raise ScopeValidationError(
                f"Domain '{domain}' label '{label}' is not RFC 1123 compliant",
                field="domains",
            )

    return cleaned


def validate_ip_address(ip_str: str) -> str:
    """Validate and normalize an IPv4 or IPv6 address."""
    cleaned = ip_str.strip()
    if not cleaned:
        raise ScopeValidationError("IP address cannot be empty", field="ip_addresses")
    try:
        obj = ipaddress.ip_address(cleaned)
        return str(obj)
    except ValueError as e:
        raise ScopeValidationError(
            f"Invalid IP address '{ip_str}': {e}", field="ip_addresses"
        ) from e


def validate_cidr_network(cidr_str: str) -> str:
    """Validate and normalize an IPv4 or IPv6 CIDR network."""
    cleaned = cidr_str.strip()
    if not cleaned:
        raise ScopeValidationError("CIDR cannot be empty", field="cidrs")
    try:
        net = ipaddress.ip_network(cleaned, strict=False)
        return str(net)
    except ValueError as e:
        raise ScopeValidationError(f"Invalid CIDR '{cidr_str}': {e}", field="cidrs") from e


def validate_port_number(port: int) -> int:
    """Validate port number is in valid network range 1-65535 (port 0 reserved)."""
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ScopeValidationError(
            f"Invalid port number {port}; must be an integer between 1 and 65535", field="ports"
        )
    return port


def validate_port_range(port_range_str: str) -> str:
    """Validate and normalize port range in 'start-end' format within 1-65535."""
    cleaned = port_range_str.strip()
    parts = cleaned.split("-")
    if len(parts) != 2:
        raise ScopeValidationError(
            f"Invalid port range '{port_range_str}'; format must be 'start-end' (e.g. '80-443')",
            field="port_ranges",
        )
    try:
        start = int(parts[0].strip())
        end = int(parts[1].strip())
    except ValueError as e:
        raise ScopeValidationError(
            f"Invalid port range values '{port_range_str}'; start and end must be integers",
            field="port_ranges",
        ) from e

    if start < 1 or start > 65535 or end < 1 or end > 65535:
        raise ScopeValidationError(
            f"Port range values {start}-{end} out of bounds (1-65535)",
            field="port_ranges",
        )
    if start > end:
        raise ScopeValidationError(
            f"Invalid port range '{port_range_str}'; "
            f"start port ({start}) cannot exceed end port ({end})",
            field="port_ranges",
        )
    return f"{start}-{end}"


def validate_url_target(url_str: str) -> str:
    """Validate and normalize a URL target.

    Must use http or https, and have a valid extractable host.
    """
    cleaned = url_str.strip()
    if not cleaned:
        raise ScopeValidationError("URL cannot be empty", field="urls")

    if not cleaned.startswith(("http://", "https://")):
        raise ScopeValidationError(
            f"URL '{url_str}' must specify scheme 'http://' or 'https://'",
            field="urls",
        )

    try:
        parsed = urlparse(cleaned)
    except Exception as e:
        raise ScopeValidationError(f"Malformed URL '{url_str}': {e}", field="urls") from e

    host = parsed.hostname
    if not host:
        raise ScopeValidationError(f"Could not extract hostname from URL '{url_str}'", field="urls")

    # Validate host is either valid IP or valid domain
    try:
        ipaddress.ip_address(host)
    except ValueError:
        with contextlib.suppress(ScopeValidationError):
            validate_domain_name(host)

    try:
        if parsed.port is not None:
            validate_port_number(parsed.port)
    except ValueError as e:
        raise ScopeValidationError(f"Invalid URL port in '{url_str}': {e}", field="urls") from e

    return cleaned


def validate_scope_target(target: ScopeTarget, is_inclusion: bool = False) -> ScopeTarget:
    """Validate and normalize a ScopeTarget.

    If is_inclusion=True, ensures at least one host/network target
    (domain, IP, CIDR, or URL) is explicitly defined.
    """
    normalized_domains = [validate_domain_name(d) for d in target.domains if d.strip()]
    normalized_ips = [validate_ip_address(ip) for ip in target.ip_addresses if ip.strip()]
    normalized_cidrs = [validate_cidr_network(c) for c in target.cidrs if c.strip()]
    normalized_urls = [validate_url_target(u) for u in target.urls if u.strip()]
    normalized_ports = sorted({validate_port_number(p) for p in target.ports})
    normalized_ranges = [validate_port_range(r) for r in target.port_ranges if r.strip()]

    # If user provided *.domain in domain list, ensure subdomains_allowed is enabled
    subdomains_allowed = target.subdomains_allowed
    for d in target.domains:
        if d.strip().startswith("*."):
            subdomains_allowed = True
            break

    if is_inclusion:
        total_targets = (
            len(normalized_domains)
            + len(normalized_ips)
            + len(normalized_cidrs)
            + len(normalized_urls)
        )
        if total_targets == 0:
            raise ScopeValidationError(
                "Scope inclusion must specify at least one target "
                "(domain, IP address, CIDR, or URL).",
                field="includes",
            )

    return ScopeTarget(
        domains=normalized_domains,
        subdomains_allowed=subdomains_allowed,
        ip_addresses=normalized_ips,
        cidrs=normalized_cidrs,
        urls=normalized_urls,
        ports=normalized_ports,
        port_ranges=normalized_ranges,
    )


def validate_scope_definition(scope: ScopeDefinition) -> ScopeDefinition:
    """Validate and normalize a full ScopeDefinition."""
    if not scope.engagement_id or not scope.engagement_id.strip():
        raise ScopeValidationError(
            "Scope must be associated with an engagement_id", field="engagement_id"
        )

    if scope.version < 1:
        raise ScopeValidationError("Scope version must be >= 1", field="version")

    validated_includes = validate_scope_target(scope.includes, is_inclusion=True)
    validated_excludes = validate_scope_target(scope.excludes, is_inclusion=False)

    return ScopeDefinition(
        scope_id=scope.scope_id,
        engagement_id=scope.engagement_id.strip(),
        version=scope.version,
        includes=validated_includes,
        excludes=validated_excludes,
        notes=scope.notes.strip(),
        created_at=scope.created_at,
        updated_at=scope.updated_at,
    )
