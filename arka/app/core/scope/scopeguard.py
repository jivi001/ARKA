import contextlib
import ipaddress
from urllib.parse import urlparse

from arka.app.core.state.models import ScopeDefinition, ScopeTarget


class ScopeViolation(Exception):
    """Raised when a target is outside the authorized scope."""

    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        super().__init__(f"Scope violation: {target} - {reason}")


class ScopeGuard:
    """Deterministic scope enforcement engine.

    Never relies on LLM decisions for scope validation.
    All checks are based on explicit scope definitions with deterministic logic.
    Exclusions ALWAYS take precedence over inclusions.
    """

    def __init__(self, scope: ScopeDefinition):
        self._scope = scope
        self._included_networks = self._parse_networks(scope.includes)
        self._excluded_networks = self._parse_networks(scope.excludes)
        self._included_domains = {d.strip().lower() for d in scope.includes.domains if d.strip()}
        self._excluded_domains = {d.strip().lower() for d in scope.excludes.domains if d.strip()}
        self._included_ips = self._parse_ip_set(scope.includes.ip_addresses)
        self._excluded_ips = self._parse_ip_set(scope.excludes.ip_addresses)
        self._included_ports = {p for p in scope.includes.ports if 1 <= p <= 65535}
        self._allowed_port_ranges = self._parse_port_ranges(scope.includes.port_ranges)
        self._subdomains_allowed = scope.includes.subdomains_allowed

        # Parse URLs and integrate their hosts/ports
        self._included_urls = self._parse_urls(scope.includes.urls)
        self._excluded_urls = self._parse_urls(scope.excludes.urls)

        has_explicit_ports = bool(self._included_ports or self._allowed_port_ranges)
        for u in self._included_urls:
            host = u["host"]
            try:
                self._included_ips.add(ipaddress.ip_address(host))
            except ValueError:
                self._included_domains.add(host)
            # If ports were not explicitly given, include URL's port
            if not has_explicit_ports:
                self._included_ports.add(u["port"])

    @property
    def scope_version(self) -> int:
        """Return the authoritative scope version."""
        return self._scope.version

    def _parse_urls(self, urls: list[str]) -> list[dict]:
        parsed_list = []
        for u in urls:
            u_clean = u.strip()
            if not u_clean:
                continue
            if not u_clean.startswith(("http://", "https://")):
                u_clean = "http://" + u_clean
            with contextlib.suppress(Exception):
                parsed = urlparse(u_clean)
                host = parsed.hostname
                if not host:
                    continue
                scheme = parsed.scheme.lower()
                port = (
                    parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
                )
                path = parsed.path.rstrip("/")
                parsed_list.append(
                    {
                        "raw": u,
                        "scheme": scheme,
                        "host": host.lower(),
                        "port": port,
                        "path": path,
                    }
                )
        return parsed_list

    def _parse_networks(
        self, target: ScopeTarget
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        networks = []
        for cidr in target.cidrs:
            cidr_clean = cidr.strip()
            if not cidr_clean:
                continue
            with contextlib.suppress(ValueError):
                networks.append(ipaddress.ip_network(cidr_clean, strict=False))
        return networks

    def _parse_ip_set(
        self, ip_strings: list[str]
    ) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        ips = set()
        for s in ip_strings:
            s_clean = s.strip()
            if not s_clean:
                continue
            with contextlib.suppress(ValueError):
                ips.add(ipaddress.ip_address(s_clean))
        return ips

    def _parse_port_ranges(self, ranges: list[str]) -> list[tuple[int, int]]:
        parsed = []
        for prange in ranges:
            parts = prange.strip().split("-")
            if len(parts) == 2:
                with contextlib.suppress(ValueError):
                    start = int(parts[0].strip())
                    end = int(parts[1].strip())
                    if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                        parsed.append((start, end))
        return parsed

    def _is_subdomain_of(self, domain: str, parent: str) -> bool:
        """Strict domain/subdomain check.

        Matches exact domain or strict subdomains (with leading dot delimiter).
        Prevents suffix/prefix attacks like evil-example.com or notexample.com.
        """
        domain = domain.lower().strip()
        parent = parent.lower().strip()
        if not domain or not parent:
            return False
        return domain == parent or domain.endswith("." + parent)

    def validate_port(self, port: int) -> bool:
        """Check if a port is within allowed scope (valid network ports 1-65535)."""
        if not isinstance(port, int) or port < 1 or port > 65535:
            return False
        if not self._included_ports and not self._allowed_port_ranges:
            return True
        if port in self._included_ports:
            return True
        return any(start <= port <= end for start, end in self._allowed_port_ranges)

    @staticmethod
    def _ip_in_net(
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
        net: ipaddress.IPv4Network | ipaddress.IPv6Network,
    ) -> bool:
        if isinstance(ip_obj, ipaddress.IPv4Address) and isinstance(net, ipaddress.IPv4Network):
            return ip_obj in net
        if isinstance(ip_obj, ipaddress.IPv6Address) and isinstance(net, ipaddress.IPv6Network):
            return ip_obj in net
        return False

    @staticmethod
    def _net_overlaps(
        net1: ipaddress.IPv4Network | ipaddress.IPv6Network,
        net2: ipaddress.IPv4Network | ipaddress.IPv6Network,
    ) -> bool:
        if isinstance(net1, ipaddress.IPv4Network) and isinstance(net2, ipaddress.IPv4Network):
            return net1.overlaps(net2)
        if isinstance(net1, ipaddress.IPv6Network) and isinstance(net2, ipaddress.IPv6Network):
            return net1.overlaps(net2)
        return False

    @staticmethod
    def _net_subnet_of(
        child: ipaddress.IPv4Network | ipaddress.IPv6Network,
        parent: ipaddress.IPv4Network | ipaddress.IPv6Network,
    ) -> bool:
        if isinstance(child, ipaddress.IPv4Network) and isinstance(parent, ipaddress.IPv4Network):
            return child.subnet_of(parent)
        if isinstance(child, ipaddress.IPv6Network) and isinstance(parent, ipaddress.IPv6Network):
            return child.subnet_of(parent)
        return False

    def validate_ip(self, ip: str) -> bool:
        """Check if an IPv4 or IPv6 address is in scope."""
        ip_clean = ip.strip()
        try:
            ip_obj = ipaddress.ip_address(ip_clean)
        except ValueError as e:
            raise ScopeViolation(ip, "Invalid IP address format.") from e

        # Check exclusions first (exclusions always take priority)
        if ip_obj in self._excluded_ips:
            return False
        for net in self._excluded_networks:
            if self._ip_in_net(ip_obj, net):
                return False

        # Check inclusions
        if ip_obj in self._included_ips:
            return True
        return any(self._ip_in_net(ip_obj, net) for net in self._included_networks)

    def validate_domain(self, domain: str) -> bool:
        """Check if domain is in scope. Handles subdomain and exclusion logic."""
        domain_clean = domain.strip().lower()
        if not domain_clean or "/" in domain_clean or "\\" in domain_clean or " " in domain_clean:
            return False

        # Check exclusions first (exclusions always take priority)
        for ex in self._excluded_domains:
            if self._is_subdomain_of(domain_clean, ex):
                return False

        # Check inclusions
        if domain_clean in self._included_domains:
            return True
        if self._subdomains_allowed:
            for inc in self._included_domains:
                if self._is_subdomain_of(domain_clean, inc):
                    return True
        return False

    def validate_cidr(self, cidr: str) -> bool:
        """Check if a CIDR range is entirely within scope."""
        cidr_clean = cidr.strip()
        try:
            net_obj = ipaddress.ip_network(cidr_clean, strict=False)
        except ValueError as e:
            raise ScopeViolation(cidr, "Invalid CIDR format.") from e

        # If it intersects any excluded network of the same version, it's invalid
        for ex_net in self._excluded_networks:
            if self._net_overlaps(net_obj, ex_net):
                return False

        # If any excluded IP of the same version falls within this CIDR, it's invalid
        for ex_ip in self._excluded_ips:
            if self._ip_in_net(ex_ip, net_obj):
                return False

        # It must be entirely within at least one included network of the same version
        return any(self._net_subnet_of(net_obj, inc_net) for inc_net in self._included_networks)

    def validate_url(self, url: str) -> bool:
        """Validate URL host, port, and path against scope."""
        url_clean = url.strip()
        if not url_clean.startswith(("http://", "https://")):
            url_clean = "http://" + url_clean
        try:
            parsed = urlparse(url_clean)
        except Exception as e:
            raise ScopeViolation(url, "Invalid URL format.") from e

        host = parsed.hostname
        if not host:
            raise ScopeViolation(url, "Could not extract host from URL.")

        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme.lower() == "https" else 80
        if not self.validate_port(port):
            return False

        url_path = parsed.path.rstrip("/")
        if not url_path:
            url_path = "/"

        # Check URL exclusions with path prefixes
        for ex_u in self._excluded_urls:
            if ex_u["host"] == host.lower() and ex_u["port"] == port:
                ex_path = ex_u["path"]
                if (
                    not ex_path
                    or ex_path == "/"
                    or url_path == ex_path
                    or url_path.startswith(ex_path + "/")
                ):
                    return False

        # If scope contains explicit URL path constraints for this host:port, enforce path prefix
        matching_included_urls = [
            inc
            for inc in self._included_urls
            if inc["host"] == host.lower()
            and inc["port"] == port
            and inc["path"]
            and inc["path"] != "/"
        ]
        if matching_included_urls:
            path_allowed = any(
                url_path == inc["path"] or url_path.startswith(inc["path"] + "/")
                for inc in matching_included_urls
            )
            if not path_allowed:
                return False

        try:
            # Check if host is IP
            ipaddress.ip_address(host)
            return self.validate_ip(host)
        except ValueError:
            return self.validate_domain(host)

    def validate_target(self, target: str, port: int | None = None) -> bool:
        """Validate whether a target is within scope.

        Returns True if valid, raises ScopeViolation otherwise.
        """
        if not target or not isinstance(target, str) or not target.strip():
            raise ScopeViolation(str(target), "Empty target specified.")

        target_clean = target.strip()

        # If port provided separately, validate it
        if port is not None and not self.validate_port(port):
            raise ScopeViolation(f"{target_clean}:{port}", f"Port {port} not in scope.")

        # URL validation
        if target_clean.startswith(("http://", "https://")):
            if not self.validate_url(target_clean):
                raise ScopeViolation(target_clean, "URL not in scope.")
            return True

        # Check for host:port format if not a CIDR and not an IPv6 address
        if ":" in target_clean and not target_clean.startswith("[") and "/" not in target_clean:
            parts = target_clean.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                host_part = parts[0]
                port_part = int(parts[1])
                if not self.validate_port(port_part):
                    raise ScopeViolation(target_clean, f"Port {port_part} not in scope.")
                return self.validate_target(host_part)

        # CIDR notation
        if "/" in target_clean:
            if not self.validate_cidr(target_clean):
                raise ScopeViolation(target_clean, "CIDR not in scope.")
            return True

        # IP Address check
        try:
            ipaddress.ip_address(target_clean)
            if not self.validate_ip(target_clean):
                raise ScopeViolation(target_clean, "IP not in scope.")
            return True
        except ValueError:
            pass

        # Domain check
        if not self.validate_domain(target_clean):
            raise ScopeViolation(target_clean, "Domain not in scope.")
        return True
