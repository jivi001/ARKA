"""SSRF detection and endpoint validation for ARKA Web Security.

Defends against Server-Side Request Forgery (SSRF), metadata exfiltration,
cloud credential access, and unauthorized internal network pivoting.
"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from arka.app.core.scope.scopeguard import ScopeGuard


class WebSSRFError(Exception):
    """Raised when an outbound HTTP request targets a blocked or unauthorized destination."""

    def __init__(self, message: str, url: str = "", target_ip: str = ""):
        self.url = url
        self.target_ip = target_ip
        super().__init__(f"Web SSRF violation: {message}")


# Blocked cloud metadata endpoints (unconditionally blocked even if attempted in scope)
BLOCKED_METADATA_IPS: frozenset[str] = frozenset(
    {
        "169.254.169.254",  # AWS / Azure / GCP / OpenStack link-local metadata
        "169.254.169.253",  # AWS DNS responder
        "169.254.170.2",  # AWS ECS task metadata
        "100.100.100.200",  # Alibaba Cloud metadata
    }
)

BLOCKED_METADATA_HOSTS: frozenset[str] = frozenset(
    {
        "metadata.google.internal",
        "metadata.internal",
        "metadata",
        "instance-data",
    }
)

# Standard restricted subnets for SSRF validation
_LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
_LINK_LOCAL_V4 = ipaddress.ip_network("169.254.0.0/16")
_PRIVATE_10 = ipaddress.ip_network("10.0.0.0/8")
_PRIVATE_172 = ipaddress.ip_network("172.16.0.0/12")
_PRIVATE_192 = ipaddress.ip_network("192.168.0.0/16")
_CURRENT_NET_V4 = ipaddress.ip_network("0.0.0.0/8")
_BROADCAST_V4 = ipaddress.ip_network("255.255.255.255/32")
_MULTICAST_V4 = ipaddress.ip_network("224.0.0.0/4")
_RESERVED_V4 = ipaddress.ip_network("240.0.0.0/4")

_LOOPBACK_V6 = ipaddress.ip_network("::1/128")
_LINK_LOCAL_V6 = ipaddress.ip_network("fe80::/10")
_UNIQUE_LOCAL_V6 = ipaddress.ip_network("fc00::/7")
_UNSPECIFIED_V6 = ipaddress.ip_network("::/128")
_MULTICAST_V6 = ipaddress.ip_network("ff00::/8")


class WebSSRFValidator:
    """Validates outbound HTTP target URLs against SSRF policies and engagement scope."""

    @classmethod
    def is_cloud_metadata(
        cls, hostname: str, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    ) -> bool:
        """Check if target matches known cloud metadata services."""
        norm_host = hostname.strip().lower()
        if norm_host in BLOCKED_METADATA_HOSTS or any(
            norm_host.endswith("." + h) for h in BLOCKED_METADATA_HOSTS
        ):
            return True
        if ip_obj and ip_obj.compressed in BLOCKED_METADATA_IPS:
            return True
        return norm_host in BLOCKED_METADATA_IPS

    @classmethod
    def resolve_ip(cls, hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Resolve a hostname to IP addresses safely."""
        clean_host = hostname.strip()
        # Direct IP check
        with contextlib.suppress(ValueError):
            # Handle brackets around IPv6
            if clean_host.startswith("[") and clean_host.endswith("]"):
                clean_host = clean_host[1:-1]
            return [ipaddress.ip_address(clean_host)]

        resolved: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        try:
            addr_info = socket.getaddrinfo(clean_host, None, proto=socket.IPPROTO_TCP)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                with contextlib.suppress(ValueError):
                    resolved.append(ipaddress.ip_address(ip_str))
        except socket.gaierror:
            pass
        return resolved

    @classmethod
    def is_restricted_ip(cls, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Check if an IP address belongs to loopback, link-local, private, or metadata networks."""
        # Unmap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped

        if isinstance(ip_obj, ipaddress.IPv4Address):
            if ip_obj.compressed in BLOCKED_METADATA_IPS:
                return True
            return (
                ip_obj in _LOOPBACK_V4
                or ip_obj in _LINK_LOCAL_V4
                or ip_obj in _PRIVATE_10
                or ip_obj in _PRIVATE_172
                or ip_obj in _PRIVATE_192
                or ip_obj in _CURRENT_NET_V4
                or ip_obj in _BROADCAST_V4
                or ip_obj in _MULTICAST_V4
                or ip_obj in _RESERVED_V4
            )

        if isinstance(ip_obj, ipaddress.IPv6Address):
            return (
                ip_obj in _LOOPBACK_V6
                or ip_obj in _LINK_LOCAL_V6
                or ip_obj in _UNIQUE_LOCAL_V6
                or ip_obj in _UNSPECIFIED_V6
                or ip_obj in _MULTICAST_V6
            )

        return False

    @classmethod
    def validate_url(
        cls,
        url: str,
        scope_guard: ScopeGuard | None = None,
        allow_private_if_scoped: bool = True,
    ) -> None:
        """Validate target URL against SSRF policy and engagement scope.

        Raises:
            WebSSRFError: If the target violates SSRF defenses or is outside scope.
        """
        clean_url = url.strip()
        parsed = urllib.parse.urlparse(clean_url)
        scheme = (parsed.scheme or "").lower()

        # 1. Enforce safe schemes
        if scheme not in ("http", "https"):
            raise WebSSRFError(
                f"Prohibited URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.", url=url
            )

        host = (parsed.hostname or "").lower()
        if not host:
            raise WebSSRFError("URL has no valid hostname", url=url)

        # 2. Block cloud metadata hostname directly
        if cls.is_cloud_metadata(host):
            raise WebSSRFError(
                f"Access to cloud metadata service '{host}' is strictly prohibited.", url=url
            )

        # 3. Resolve IP and evaluate metadata and restricted networks
        ips = cls.resolve_ip(host)
        for ip_obj in ips:
            if cls.is_cloud_metadata(host, ip_obj):
                raise WebSSRFError(
                    f"Resolved target '{ip_obj.compressed}' is a prohibited cloud "
                    "metadata endpoint.",
                    url=url,
                    target_ip=ip_obj.compressed,
                )

        # 4. Evaluate against ScopeGuard if provided
        if scope_guard is not None:
            # Check if URL passes ScopeGuard
            if not scope_guard.validate_url(clean_url):
                raise WebSSRFError(
                    f"Target URL '{clean_url}' is outside authorized engagement scope.", url=url
                )

            # If target resolves to private/loopback, verify it is explicitly in scope
            for ip_obj in ips:
                if cls.is_restricted_ip(ip_obj):
                    if not allow_private_if_scoped:
                        raise WebSSRFError(
                            f"Target resolved to restricted network IP '{ip_obj.compressed}'.",
                            url=url,
                            target_ip=ip_obj.compressed,
                        )
                    # Verify the resolved IP itself is in scope
                    if not scope_guard.validate_ip(ip_obj.compressed):
                        raise WebSSRFError(
                            f"Target resolved to out-of-scope internal IP '{ip_obj.compressed}'.",
                            url=url,
                            target_ip=ip_obj.compressed,
                        )
        else:
            # Without ScopeGuard, default to blocking ALL restricted IPs
            for ip_obj in ips:
                if cls.is_restricted_ip(ip_obj):
                    raise WebSSRFError(
                        f"Target resolved to restricted IP '{ip_obj.compressed}' "
                        "without explicit authorization.",
                        url=url,
                        target_ip=ip_obj.compressed,
                    )
