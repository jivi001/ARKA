import pytest
from arka.app.core.scope.scopeguard import ScopeGuard
from arka.app.core.state.models import ScopeDefinition, ScopeTarget
from arka.app.tools.schemas.tool_schemas import ToolRequest

class TestScopeBypass:
    def test_no_scope_bypass_via_subdomain(self):
        scope = ScopeDefinition(
            engagement_id="test",
            includes=ScopeTarget(domains=["example.com"], subdomains_allowed=True),
            excludes=ScopeTarget(domains=["admin.example.com"])
        )
        guard = ScopeGuard(scope)
        assert guard.validate_domain("admin.example.com") is False
        assert guard.validate_domain("hidden.admin.example.com") is False

    def test_no_scope_bypass_via_cidr_overlap(self):
        scope = ScopeDefinition(
            engagement_id="test",
            includes=ScopeTarget(cidrs=["192.168.1.0/24"]),
            excludes=ScopeTarget(ip_addresses=["192.168.1.50"])
        )
        guard = ScopeGuard(scope)
        assert guard.validate_ip("192.168.1.1") is True
        assert guard.validate_ip("192.168.1.50") is False

class TestInjection:
    def test_sql_injection_in_engagement_name(self, client):
        response = client.post("/engagements", json={"name": "'; DROP TABLE engagements; --"})
        assert response.status_code == 201
        assert response.json()["name"] == "'; DROP TABLE engagements; --"

    def test_path_traversal_in_engagement_id(self, client):
        response = client.get("/engagements/../../etc/passwd")
        assert response.status_code in (404, 405)

class TestToolExecution:
    @pytest.mark.asyncio
    async def test_no_direct_shell_execution(self, tool_registry):
        request = ToolRequest(
            engagement_id="eng-1",
            task_id="task-1",
            agent_id="agent-1",
            tool_name="echo_test",
            target="example.com",
            arguments={"message": "; cat /etc/passwd"},
            reason="security_test"
        )
        result = await tool_registry.execute(request)
        assert result.success is True
        assert "; cat /etc/passwd" in str(result.output)
