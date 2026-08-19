import pytest
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.policies.engine import PolicyEngine
from arka.app.audit.service import AuditService
from arka.app.tools.registry.registry import ToolRegistry
from arka.app.tools.mock.tools import register_mock_tools

@pytest.fixture
def sample_scope() -> ScopeDefinition:
    return ScopeDefinition(
        engagement_id="test-engagement-1",
        includes=ScopeTarget(
            domains=["example.com"],
            subdomains_allowed=True,
            ip_addresses=["192.168.1.1", "10.0.0.1"],
            cidrs=["192.168.1.0/24"],
            ports=[80, 443, 8080],
            port_ranges=["8000-9000"],
        ),
        excludes=ScopeTarget(
            ip_addresses=["192.168.1.100"],
            domains=["admin.example.com"],
        ),
    )

@pytest.fixture
def scope_guard(sample_scope) -> ScopeGuard:
    return ScopeGuard(sample_scope)

@pytest.fixture
def audit_service() -> AuditService:
    return AuditService()

@pytest.fixture
def policy_engine(scope_guard) -> PolicyEngine:
    return PolicyEngine(scope_guard)

@pytest.fixture
def tool_registry(policy_engine, audit_service, scope_guard) -> ToolRegistry:
    registry = ToolRegistry(policy_engine, audit_service)
    register_mock_tools(registry, scope_guard)
    return registry


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from arka.app.api import create_app
    app = create_app()
    return TestClient(app)

