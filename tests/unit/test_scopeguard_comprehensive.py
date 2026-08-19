"""Comprehensive security test suite for ScopeGuard.

Tests deterministic scoping:
- IPv4 & IPv6 addresses
- CIDR ranges & subnet containment
- Domain & strict subdomain logic (including suffix collision attacks)
- URL schemes, hosts, and ports
- Port ranges & single ports
- Priority of exclusions over inclusions
- Malformed inputs failing safely
"""

import pytest

from arka.app.core.scope.scopeguard import ScopeGuard, ScopeViolation
from arka.app.core.state.models import ScopeDefinition, ScopeTarget


@pytest.fixture
def comprehensive_scope() -> ScopeDefinition:
    return ScopeDefinition(
        engagement_id="eng-comprehensive-1",
        includes=ScopeTarget(
            domains=["example.com", "target.org"],
            subdomains_allowed=True,
            ip_addresses=["192.168.1.5", "10.0.0.1", "2001:db8::1"],
            cidrs=["192.168.1.0/24", "10.10.0.0/16", "2001:db8:abcd::/48"],
            ports=[80, 443, 8080],
            port_ranges=["8000-9000", "3000-3005"],
        ),
        excludes=ScopeTarget(
            domains=["admin.example.com", "forbidden.target.org"],
            ip_addresses=["192.168.1.100", "10.10.5.5", "2001:db8::99"],
            cidrs=["192.168.1.128/26", "10.10.99.0/24"],
        ),
    )


@pytest.fixture
def guard(comprehensive_scope) -> ScopeGuard:
    return ScopeGuard(comprehensive_scope)


class TestScopeGuardIPs:
    def test_ipv4_exact_inclusion(self, guard: ScopeGuard):
        assert guard.validate_ip("192.168.1.5") is True
        assert guard.validate_ip("10.0.0.1") is True

    def test_ipv4_cidr_inclusion(self, guard: ScopeGuard):
        assert guard.validate_ip("192.168.1.20") is True
        assert guard.validate_ip("10.10.1.1") is True

    def test_ipv4_exact_exclusion_overrides(self, guard: ScopeGuard):
        # In included CIDR, but explicitly excluded
        assert guard.validate_ip("192.168.1.100") is False
        assert guard.validate_ip("10.10.5.5") is False

    def test_ipv4_cidr_exclusion_overrides(self, guard: ScopeGuard):
        # In included 192.168.1.0/24, but inside excluded 192.168.1.128/26 (192.168.1.128 - 191)
        assert guard.validate_ip("192.168.1.130") is False
        assert guard.validate_ip("192.168.1.150") is False
        # Outside excluded 192.168.1.128/26 but inside included 192.168.1.0/24
        assert guard.validate_ip("192.168.1.10") is True

    def test_ipv6_exact_inclusion(self, guard: ScopeGuard):
        assert guard.validate_ip("2001:db8::1") is True

    def test_ipv6_cidr_inclusion(self, guard: ScopeGuard):
        assert guard.validate_ip("2001:db8:abcd:1234::1") is True

    def test_ipv6_exclusion_overrides(self, guard: ScopeGuard):
        assert guard.validate_ip("2001:db8::99") is False

    def test_ip_out_of_scope(self, guard: ScopeGuard):
        assert guard.validate_ip("8.8.8.8") is False
        assert guard.validate_ip("172.16.0.1") is False
        assert guard.validate_ip("fe80::1") is False

    def test_malformed_ip_raises_scope_violation(self, guard: ScopeGuard):
        with pytest.raises(ScopeViolation):
            guard.validate_ip("999.999.999.999")
        with pytest.raises(ScopeViolation):
            guard.validate_ip("192.168.1.1.1")
        with pytest.raises(ScopeViolation):
            guard.validate_ip("not-an-ip")


class TestScopeGuardDomains:
    def test_exact_domain_inclusion(self, guard: ScopeGuard):
        assert guard.validate_domain("example.com") is True
        assert guard.validate_domain("target.org") is True

    def test_allowed_subdomain_inclusion(self, guard: ScopeGuard):
        assert guard.validate_domain("api.example.com") is True
        assert guard.validate_domain("dev.api.example.com") is True
        assert guard.validate_domain("staging.target.org") is True

    def test_excluded_subdomain_overrides(self, guard: ScopeGuard):
        assert guard.validate_domain("admin.example.com") is False
        assert guard.validate_domain("sub.admin.example.com") is False
        assert guard.validate_domain("forbidden.target.org") is False

    def test_suffix_collision_attack_prevention(self, guard: ScopeGuard):
        # attacker attempts suffix matches without dot
        assert guard.validate_domain("evil-example.com") is False
        assert guard.validate_domain("notexample.com") is False
        assert guard.validate_domain("example.com.evil.com") is False
        assert guard.validate_domain("target.org.attacker.com") is False

    def test_subdomains_disabled_mode(self):
        scope = ScopeDefinition(
            engagement_id="eng-strict",
            includes=ScopeTarget(domains=["strict.com"], subdomains_allowed=False),
        )
        strict_guard = ScopeGuard(scope)
        assert strict_guard.validate_domain("strict.com") is True
        assert strict_guard.validate_domain("api.strict.com") is False
        assert strict_guard.validate_domain("sub.strict.com") is False

    def test_case_insensitivity(self, guard: ScopeGuard):
        assert guard.validate_domain("API.EXAMPLE.COM") is True
        assert guard.validate_domain("Admin.Example.COM") is False

    def test_malformed_domain_handling(self, guard: ScopeGuard):
        assert guard.validate_domain("") is False
        assert guard.validate_domain("   ") is False
        assert guard.validate_domain("domain with spaces.com") is False
        assert guard.validate_domain("domain/with/path") is False


class TestScopeGuardCIDR:
    def test_valid_cidr_contained(self, guard: ScopeGuard):
        assert guard.validate_cidr("192.168.1.0/28") is True
        assert guard.validate_cidr("10.10.1.0/24") is True
        assert guard.validate_cidr("2001:db8:abcd:1::/64") is True

    def test_cidr_overlapping_with_exclusion_is_denied(self, guard: ScopeGuard):
        # 192.168.1.128/25 contains excluded 192.168.1.128/26
        assert guard.validate_cidr("192.168.1.128/25") is False
        # 10.10.99.0/24 is excluded
        assert guard.validate_cidr("10.10.99.0/24") is False
        assert guard.validate_cidr("10.10.99.0/28") is False

    def test_cidr_containing_excluded_ip_is_denied(self, guard: ScopeGuard):
        # 192.168.1.96/28 contains 192.168.1.100 which is excluded
        assert guard.validate_cidr("192.168.1.96/28") is False

    def test_cidr_out_of_scope(self, guard: ScopeGuard):
        assert guard.validate_cidr("172.16.0.0/16") is False
        assert guard.validate_cidr("192.168.2.0/24") is False

    def test_malformed_cidr_raises(self, guard: ScopeGuard):
        with pytest.raises(ScopeViolation):
            guard.validate_cidr("192.168.1.0/35")
        with pytest.raises(ScopeViolation):
            guard.validate_cidr("not-a-cidr")


class TestScopeGuardPorts:
    def test_exact_ports(self, guard: ScopeGuard):
        assert guard.validate_port(80) is True
        assert guard.validate_port(443) is True
        assert guard.validate_port(8080) is True

    def test_port_ranges(self, guard: ScopeGuard):
        assert guard.validate_port(8000) is True
        assert guard.validate_port(8500) is True
        assert guard.validate_port(9000) is True
        assert guard.validate_port(3002) is True

    def test_disallowed_ports(self, guard: ScopeGuard):
        assert guard.validate_port(22) is False
        assert guard.validate_port(25) is False
        assert guard.validate_port(3389) is False
        assert guard.validate_port(7999) is False
        assert guard.validate_port(9001) is False

    def test_invalid_port_numbers(self, guard: ScopeGuard):
        assert guard.validate_port(-1) is False
        assert guard.validate_port(65536) is False
        assert guard.validate_port(100000) is False


class TestScopeGuardURLs:
    def test_valid_http_and_https_urls(self, guard: ScopeGuard):
        assert guard.validate_url("https://example.com/api/v1/test") is True
        assert guard.validate_url("http://api.example.com:8080/graphql") is True
        assert guard.validate_url("http://192.168.1.5:8000/app") is True

    def test_url_with_disallowed_port(self, guard: ScopeGuard):
        assert guard.validate_url("http://example.com:22/ssh") is False
        assert guard.validate_url("http://example.com:9999/") is False

    def test_url_with_excluded_domain(self, guard: ScopeGuard):
        assert guard.validate_url("https://admin.example.com/login") is False

    def test_url_with_out_of_scope_host(self, guard: ScopeGuard):
        assert guard.validate_url("https://evil.com/payload") is False

    def test_malformed_url_raises(self, guard: ScopeGuard):
        with pytest.raises(ScopeViolation):
            guard.validate_url("http://")


class TestScopeGuardValidateTarget:
    def test_validate_target_dispatch(self, guard: ScopeGuard):
        assert guard.validate_target("192.168.1.5") is True
        assert guard.validate_target("example.com") is True
        assert guard.validate_target("https://api.example.com:8080/test") is True
        assert guard.validate_target("192.168.1.0/28") is True
        assert guard.validate_target("example.com:8080") is True

    def test_validate_target_with_port(self, guard: ScopeGuard):
        assert guard.validate_target("example.com", port=443) is True
        with pytest.raises(ScopeViolation):
            guard.validate_target("example.com", port=22)

    def test_empty_or_whitespace_target_raises(self, guard: ScopeGuard):
        with pytest.raises(ScopeViolation):
            guard.validate_target("")
        with pytest.raises(ScopeViolation):
            guard.validate_target("   ")

    def test_excluded_target_raises(self, guard: ScopeGuard):
        with pytest.raises(ScopeViolation) as exc:
            guard.validate_target("admin.example.com")
        assert "Domain not in scope" in str(exc.value)

    def test_out_of_scope_target_raises(self, guard: ScopeGuard):
        with pytest.raises(ScopeViolation):
            guard.validate_target("unauthorized.com")
