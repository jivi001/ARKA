import ipaddress
from urllib.parse import urlparse
from typing import List, Tuple, Optional

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
    All checks are based on explicit scope definitions.
    """

    def __init__(self, scope: ScopeDefinition):
        self._scope = scope
        self._included_networks = self._parse_networks(scope.includes)
        self._excluded_networks = self._parse_networks(scope.excludes)
        self._included_domains = set(d.lower() for d in scope.includes.domains)
        self._excluded_domains = set(d.lower() for d in scope.excludes.domains)
        self._included_ips = set(scope.includes.ip_addresses)
        self._excluded_ips = set(scope.excludes.ip_addresses)
        self._included_ports = set(scope.includes.ports)
        self._allowed_port_ranges = self._parse_port_ranges(scope.includes.port_ranges)
        self._subdomains_allowed = scope.includes.subdomains_allowed

    def _parse_networks(self, target: ScopeTarget) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        networks = []
        for cidr in target.cidrs:
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
        return networks

    def _parse_port_ranges(self, ranges: list[str]) -> list[tuple[int, int]]:
        parsed = []
        for prange in ranges:
            parts = prange.split('-')
            if len(parts) == 2:
                try:
                    start = int(parts[0])
                    end = int(parts[1])
                    if 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end:
                        parsed.append((start, end))
                except ValueError:
                    pass
        return parsed

    def _is_subdomain_of(self, domain: str, parent: str) -> bool:
        return domain == parent or domain.endswith('.' + parent)

    def validate_port(self, port: int) -> bool:
        """Check if a port is within allowed scope."""
        if not self._included_ports and not self._allowed_port_ranges:
            return True
        if port in self._included_ports:
            return True
        for start, end in self._allowed_port_ranges:
            if start <= port <= end:
                return True
        return False

    def validate_ip(self, ip: str) -> bool:
        """Check if IP address is in scope."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            raise ScopeViolation(ip, "Invalid IP address format.")

        # Check exclusions first (exclusions always take priority)
        if ip in self._excluded_ips:
            return False
        for net in self._excluded_networks:
            if ip_obj in net:
                return False

        # Check inclusions
        if ip in self._included_ips:
            return True
        for net in self._included_networks:
            if ip_obj in net:
                return True

        return False

    def validate_domain(self, domain: str) -> bool:
        """Check if domain is in scope. Handles subdomain logic."""
        domain = domain.lower()
        
        # Check exclusions first (exclusions always take priority)
        if domain in self._excluded_domains:
            return False
        for ex in self._excluded_domains:
            if self._is_subdomain_of(domain, ex):
                return False

        # Check inclusions
        if domain in self._included_domains:
            return True
        if self._subdomains_allowed:
            for inc in self._included_domains:
                if self._is_subdomain_of(domain, inc):
                    return True
        return False

    def validate_cidr(self, cidr: str) -> bool:
        """Check if a CIDR range is entirely within scope."""
        try:
            net_obj = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise ScopeViolation(cidr, "Invalid CIDR format.")

        # If it intersects any excluded network, it's invalid
        for ex_net in self._excluded_networks:
            if net_obj.overlaps(ex_net):
                return False

        # It must be entirely within at least one included network
        for inc_net in self._included_networks:
            if net_obj.subnet_of(inc_net):
                return True
                
        return False

    def validate_url(self, url: str) -> bool:
        """Validate a URL's host and port are in scope."""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        try:
            parsed = urlparse(url)
        except Exception:
            raise ScopeViolation(url, "Invalid URL format.")
            
        host = parsed.hostname
        if not host:
            raise ScopeViolation(url, "Could not extract host from URL.")
            
        port = parsed.port
        if port is not None:
            if not self.validate_port(port):
                return False

        try:
            # Check if host is IP
            ipaddress.ip_address(host)
            return self.validate_ip(host)
        except ValueError:
            return self.validate_domain(host)

    def validate_target(self, target: str, port: Optional[int] = None) -> bool:
        """Validate whether a target is within scope. Returns True if valid, raises ScopeViolation otherwise."""
        if port is not None:
            if not self.validate_port(port):
                raise ScopeViolation(f"{target}:{port}", f"Port {port} not in scope.")

        if target.startswith('http://') or target.startswith('https://'):
            if not self.validate_url(target):
                raise ScopeViolation(target, "URL not in scope.")
            return True

        if '/' in target:
            if not self.validate_cidr(target):
                raise ScopeViolation(target, "CIDR not in scope.")
            return True

        try:
            ipaddress.ip_address(target)
            if not self.validate_ip(target):
                raise ScopeViolation(target, "IP not in scope.")
            return True
        except ValueError:
            pass

        if not self.validate_domain(target):
            raise ScopeViolation(target, "Domain not in scope.")
            
        return True
