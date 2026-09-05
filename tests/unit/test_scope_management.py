"""Unit tests for ARKA scope management, validation, repository, and API routes."""

import pytest
from fastapi.testclient import TestClient

from arka.app.api import create_app
from arka.app.api.deps import reset_dependencies
from arka.app.core.scope import (
    ScopeValidationError,
    validate_cidr_network,
    validate_domain_name,
    validate_ip_address,
    validate_port_number,
    validate_port_range,
    validate_scope_target,
    validate_url_target,
)
from arka.app.core.state.models import ScopeTarget


@pytest.fixture(autouse=True)
def clean_deps():
    reset_dependencies()
    yield
    reset_dependencies()


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


# --- 1. Syntactic and Semantic Validation Tests ---


class TestScopeTargetValidation:
    """Test validation of individual target types."""

    def test_valid_domain_names(self):
        assert validate_domain_name("example.com") == "example.com"
        assert validate_domain_name("SUB.Example.COM ") == "sub.example.com"
        assert validate_domain_name("juice-shop.local") == "juice-shop.local"
        assert validate_domain_name("*.target.com") == "target.com"

    def test_invalid_domain_names(self):
        with pytest.raises(ScopeValidationError):
            validate_domain_name("")
        with pytest.raises(ScopeValidationError):
            validate_domain_name("   ")
        with pytest.raises(ScopeValidationError):
            validate_domain_name("*. ")
        with pytest.raises(ScopeValidationError):
            validate_domain_name("example..com")
        with pytest.raises(ScopeValidationError):
            validate_domain_name("example.com/path")
        with pytest.raises(ScopeValidationError):
            validate_domain_name("example.com; rm -rf /")
        with pytest.raises(ScopeValidationError):
            validate_domain_name("example.com|cat /etc/passwd")

    def test_valid_ip_addresses(self):
        assert validate_ip_address("127.0.0.1") == "127.0.0.1"
        assert validate_ip_address("192.168.1.100 ") == "192.168.1.100"
        assert validate_ip_address("::1") == "::1"
        assert validate_ip_address("2001:db8::1") == "2001:db8::1"

    def test_invalid_ip_addresses(self):
        with pytest.raises(ScopeValidationError):
            validate_ip_address("999.999.999.999")
        with pytest.raises(ScopeValidationError):
            validate_ip_address("127.0.0.1.1")
        with pytest.raises(ScopeValidationError):
            validate_ip_address("not-an-ip")
        with pytest.raises(ScopeValidationError):
            validate_ip_address("")

    def test_valid_cidrs(self):
        assert validate_cidr_network("192.168.1.0/24") == "192.168.1.0/24"
        assert validate_cidr_network("10.0.0.0/8 ") == "10.0.0.0/8"
        assert validate_cidr_network("2001:db8::/32") == "2001:db8::/32"

    def test_invalid_cidrs(self):
        with pytest.raises(ScopeValidationError):
            validate_cidr_network("192.168.1.0/99")
        with pytest.raises(ScopeValidationError):
            validate_cidr_network("not-a-cidr")
        with pytest.raises(ScopeValidationError):
            validate_cidr_network("")

    def test_valid_ports(self):
        assert validate_port_number(1) == 1
        assert validate_port_number(80) == 80
        assert validate_port_number(443) == 443
        assert validate_port_number(3000) == 3000
        assert validate_port_number(65535) == 65535

    def test_invalid_ports(self):
        # Port 0 is reserved and invalid for network penetration testing
        with pytest.raises(ScopeValidationError):
            validate_port_number(0)
        with pytest.raises(ScopeValidationError):
            validate_port_number(-1)
        with pytest.raises(ScopeValidationError):
            validate_port_number(65536)
        with pytest.raises(ScopeValidationError):
            validate_port_number(70000)

    def test_valid_port_ranges(self):
        assert validate_port_range("80-443") == "80-443"
        assert validate_port_range("1-65535") == "1-65535"
        assert validate_port_range(" 3000 - 3050 ") == "3000-3050"

    def test_invalid_port_ranges(self):
        with pytest.raises(ScopeValidationError):
            validate_port_range("443-80")  # reversed
        with pytest.raises(ScopeValidationError):
            validate_port_range("0-100")  # port 0 invalid
        with pytest.raises(ScopeValidationError):
            validate_port_range("80-70000")  # out of bounds
        with pytest.raises(ScopeValidationError):
            validate_port_range("80")  # missing dash
        with pytest.raises(ScopeValidationError):
            validate_port_range("http-https")  # non-integers

    def test_valid_urls(self):
        assert validate_url_target("http://127.0.0.1:3000") == "http://127.0.0.1:3000"
        assert (
            validate_url_target("https://juice-shop.local/api/v1")
            == "https://juice-shop.local/api/v1"
        )

    def test_invalid_urls(self):
        with pytest.raises(ScopeValidationError):
            validate_url_target("ftp://127.0.0.1:21")  # non-http/https
        with pytest.raises(ScopeValidationError):
            validate_url_target("file:///etc/passwd")
        with pytest.raises(ScopeValidationError):
            validate_url_target("http://127.0.0.1:70000")  # invalid port

    def test_inclusion_must_have_at_least_one_target(self):
        empty_target = ScopeTarget()
        with pytest.raises(ScopeValidationError) as exc:
            validate_scope_target(empty_target, is_inclusion=True)
        assert "must specify at least one target" in str(exc.value)

        ports_only = ScopeTarget(ports=[80, 443])
        with pytest.raises(ScopeValidationError) as exc:
            validate_scope_target(ports_only, is_inclusion=True)
        assert "must specify at least one target" in str(exc.value)

    def test_exclusion_can_be_empty(self):
        empty_target = ScopeTarget()
        validated = validate_scope_target(empty_target, is_inclusion=False)
        assert validated.domains == []


# --- 2. API Scope Management Lifecycle Tests ---


class TestScopeAPILifecycle:
    """Test API scope endpoints, create-or-replace semantics, and status transitions."""

    def test_start_without_scope_fails_with_409(self, client):
        # 1. Create engagement
        res = client.post("/engagements", json={"name": "Test Lab", "objective": "Testing"})
        assert res.status_code == 201
        eng_id = res.json()["engagement_id"]
        assert res.json()["status"] == "created"
        assert res.json()["scope"] is None

        # 2. Attempt to start without scope -> 409 Conflict
        start_res = client.post(f"/engagements/{eng_id}/start")
        assert start_res.status_code == 409
        assert "without a scope definition" in start_res.json()["detail"]

    def test_create_and_retrieve_scope(self, client):
        res = client.post("/engagements", json={"name": "Juice Shop", "objective": "Recon"})
        eng_id = res.json()["engagement_id"]

        # Scope not found initially
        get_res = client.get(f"/engagements/{eng_id}/scope")
        assert get_res.status_code == 404

        # Set valid scope
        scope_payload = {
            "includes": {
                "ip_addresses": ["127.0.0.1"],
                "ports": [3000],
                "urls": ["http://127.0.0.1:3000"],
            },
            "excludes": {
                "ports": [4000],
            },
            "notes": "Local OWASP Juice Shop Lab",
        }
        post_res = client.post(f"/engagements/{eng_id}/scope", json=scope_payload)
        assert post_res.status_code == 200
        scope_data = post_res.json()
        assert scope_data["engagement_id"] == eng_id
        assert scope_data["version"] == 1
        assert "127.0.0.1" in scope_data["includes"]["ip_addresses"]
        assert 3000 in scope_data["includes"]["ports"]

        # GET scope
        get_res = client.get(f"/engagements/{eng_id}/scope")
        assert get_res.status_code == 200
        assert get_res.json()["version"] == 1
        assert get_res.json()["notes"] == "Local OWASP Juice Shop Lab"

    def test_create_or_replace_semantics_and_version_increment(self, client):
        res = client.post("/engagements", json={"name": "Replace Test", "objective": "Testing"})
        eng_id = res.json()["engagement_id"]

        # Initial scope v1
        v1_payload = {
            "includes": {"domains": ["old-target.com"]},
            "notes": "Version 1",
        }
        res_v1 = client.post(f"/engagements/{eng_id}/scope", json=v1_payload)
        assert res_v1.status_code == 200
        assert res_v1.json()["version"] == 1
        assert res_v1.json()["includes"]["domains"] == ["old-target.com"]

        # Replace scope v2 (create-or-replace, NOT merge)
        v2_payload = {
            "includes": {"ip_addresses": ["127.0.0.1"], "ports": [3000]},
            "notes": "Version 2 replaced",
        }
        res_v2 = client.post(f"/engagements/{eng_id}/scope", json=v2_payload)
        assert res_v2.status_code == 200
        data_v2 = res_v2.json()
        assert data_v2["version"] == 2
        # Verify old domain is gone (not merged)
        assert data_v2["includes"]["domains"] == []
        assert data_v2["includes"]["ip_addresses"] == ["127.0.0.1"]
        assert data_v2["notes"] == "Version 2 replaced"

    def test_optimistic_concurrency_locking(self, client):
        res = client.post("/engagements", json={"name": "Concurrency Test", "objective": "Testing"})
        eng_id = res.json()["engagement_id"]

        # Initial scope v1
        client.post(f"/engagements/{eng_id}/scope", json={"includes": {"domains": ["target.com"]}})

        # Try to update expecting version 2 when current is 1 -> 409 Conflict
        conflict_payload = {
            "includes": {"domains": ["new-target.com"]},
            "expected_version": 2,
        }
        res_conflict = client.post(f"/engagements/{eng_id}/scope", json=conflict_payload)
        assert res_conflict.status_code == 409
        assert "version conflict" in res_conflict.json()["detail"]

        # Update expecting version 1 -> succeeds, becomes v2
        valid_payload = {
            "includes": {"domains": ["new-target.com"]},
            "expected_version": 1,
        }
        res_ok = client.post(f"/engagements/{eng_id}/scope", json=valid_payload)
        assert res_ok.status_code == 200
        assert res_ok.json()["version"] == 2

    def test_scope_mutation_state_boundaries(self, client):
        res = client.post(
            "/engagements", json={"name": "State Boundary Test", "objective": "Testing"}
        )
        eng_id = res.json()["engagement_id"]

        # 1. State: CREATED -> Scope editable
        res1 = client.post(
            f"/engagements/{eng_id}/scope", json={"includes": {"ip_addresses": ["127.0.0.1"]}}
        )
        assert res1.status_code == 200

        # 2. Start engagement -> ACTIVE
        start_res = client.post(f"/engagements/{eng_id}/start")
        assert start_res.status_code == 200
        assert start_res.json()["status"] == "active"

        # 3. State: ACTIVE -> Scope mutation forbidden (409)
        res_active = client.post(
            f"/engagements/{eng_id}/scope", json={"includes": {"ip_addresses": ["10.0.0.1"]}}
        )
        assert res_active.status_code == 409
        assert "Cannot modify scope of an active engagement" in res_active.json()["detail"]

        # 4. Pause engagement -> PAUSED
        pause_res = client.post(f"/engagements/{eng_id}/pause")
        assert pause_res.status_code == 200
        assert pause_res.json()["status"] == "paused"

        # 5. State: PAUSED -> Scope editable
        res_paused = client.post(
            f"/engagements/{eng_id}/scope", json={"includes": {"ip_addresses": ["10.0.0.1"]}}
        )
        assert res_paused.status_code == 200
        assert res_paused.json()["version"] == 2

        # 6. Stop engagement -> STOPPED
        stop_res = client.post(f"/engagements/{eng_id}/stop")
        assert stop_res.status_code == 200
        assert stop_res.json()["status"] == "stopped"

        # 7. State: STOPPED -> Scope mutation forbidden (409)
        res_stopped = client.post(
            f"/engagements/{eng_id}/scope", json={"includes": {"ip_addresses": ["10.0.0.1"]}}
        )
        assert res_stopped.status_code == 409
        assert "terminal state" in res_stopped.json()["detail"]
