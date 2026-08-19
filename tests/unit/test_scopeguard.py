import pytest
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.core.scope.scopeguard import ScopeGuard, ScopeViolation

class TestScopeGuardIP:
    def test_valid_ip_in_scope(self, scope_guard):
        assert scope_guard.validate_ip("192.168.1.1") is True
    
    def test_ip_in_cidr_scope(self, scope_guard):
        assert scope_guard.validate_ip("192.168.1.50") is True
    
    def test_ip_out_of_scope(self, scope_guard):
        assert scope_guard.validate_ip("10.0.0.2") is False  # Not in CIDR
    
    def test_excluded_ip(self, scope_guard):
        # 192.168.1.100 is in the CIDR but explicitly excluded
        assert scope_guard.validate_ip("192.168.1.100") is False
    
    def test_invalid_ip_raises(self, scope_guard):
        with pytest.raises(ScopeViolation):
            scope_guard.validate_ip("not-an-ip")

class TestScopeGuardDomain:
    def test_valid_domain(self, scope_guard):
        assert scope_guard.validate_domain("example.com") is True
    
    def test_subdomain_allowed(self, scope_guard):
        assert scope_guard.validate_domain("api.example.com") is True
    
    def test_excluded_subdomain(self, scope_guard):
        assert scope_guard.validate_domain("admin.example.com") is False
    
    def test_out_of_scope_domain(self, scope_guard):
        assert scope_guard.validate_domain("evil.com") is False
    
    def test_case_insensitive(self, scope_guard):
        assert scope_guard.validate_domain("Example.COM") is True
    
    def test_subdomains_not_allowed(self):
        # Create a scope with subdomains_allowed=False
        scope = ScopeDefinition(
            engagement_id="test",
            includes=ScopeTarget(domains=["exact.com"], subdomains_allowed=False),
        )
        guard = ScopeGuard(scope)
        assert guard.validate_domain("exact.com") is True
        assert guard.validate_domain("sub.exact.com") is False

class TestScopeGuardCIDR:
    def test_valid_cidr_within_scope(self, scope_guard):
        assert scope_guard.validate_cidr("192.168.1.0/28") is True
    
    def test_cidr_outside_scope(self, scope_guard):
        assert scope_guard.validate_cidr("10.10.0.0/16") is False
    
    def test_invalid_cidr_raises(self, scope_guard):
        with pytest.raises(ScopeViolation):
            scope_guard.validate_cidr("invalid-cidr")

class TestScopeGuardPort:
    def test_allowed_port(self, scope_guard):
        assert scope_guard.validate_port(80) is True
    
    def test_port_in_range(self, scope_guard):
        assert scope_guard.validate_port(8500) is True
    
    def test_port_out_of_scope(self, scope_guard):
        assert scope_guard.validate_port(22) is False

class TestScopeGuardURL:
    def test_valid_url(self, scope_guard):
        assert scope_guard.validate_url("https://example.com:443/path") is True
    
    def test_url_out_of_scope(self, scope_guard):
        assert scope_guard.validate_url("https://evil.com/path") is False
    
    def test_url_excluded_domain(self, scope_guard):
        assert scope_guard.validate_url("https://admin.example.com") is False

class TestScopeGuardTarget:
    def test_validate_ip_target(self, scope_guard):
        assert scope_guard.validate_target("192.168.1.1") is True
    
    def test_validate_domain_target(self, scope_guard):
        assert scope_guard.validate_target("example.com") is True
    
    def test_validate_url_target(self, scope_guard):
        assert scope_guard.validate_target("https://example.com") is True
    
    def test_out_of_scope_raises(self, scope_guard):
        with pytest.raises(ScopeViolation):
            scope_guard.validate_target("evil.com")
    
    def test_validate_with_port(self, scope_guard):
        assert scope_guard.validate_target("192.168.1.1", port=80) is True
    
    def test_validate_with_bad_port(self, scope_guard):
        with pytest.raises(ScopeViolation):
            scope_guard.validate_target("192.168.1.1", port=22)

    def test_empty_scope_denies_all(self):
        scope = ScopeDefinition(engagement_id="test")
        guard = ScopeGuard(scope)
        assert guard.validate_ip("1.1.1.1") is False
        assert guard.validate_domain("anything.com") is False
