"""Unit tests for the ARKA Security Operations Console API endpoints."""

import pytest
from fastapi.testclient import TestClient

from arka.app.api import create_app
from arka.app.api.deps import get_approval_manager
from arka.app.core.state.models import RiskLevel


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_get_configuration(client):
    """Verify configuration center endpoint returns active providers, agents,
    tools, and invariants.
    """
    resp = client.get("/configuration")
    assert resp.status_code == 200
    data = resp.json()
    assert "providers" in data
    assert "agents" in data
    assert "tools" in data
    assert "policy_matrix" in data
    assert "resource_budgets" in data
    assert len(data["security_invariants"]) >= 4

    # Also test /api/configuration prefix
    resp_api = client.get("/api/configuration")
    assert resp_api.status_code == 200


def test_approvals_api_lifecycle(client):
    """Verify listing, inspecting, and deciding approvals via API."""
    mgr = get_approval_manager()
    req = mgr.create_request(
        engagement_id="eng-console-1",
        task_id="task-101",
        agent_id="web_agent",
        action="nuclei_scan",
        target="http://test.local",
        tool_name="nuclei",
        risk_level=RiskLevel.HIGH,
        arguments={"target": "http://test.local", "templates": ["cve"]},
        scope_version=1,
    )

    # 1. List approvals
    resp = client.get("/approvals")
    assert resp.status_code == 200
    approvals = resp.json()
    found = [a for a in approvals if a["approval_id"] == req.approval_id]
    assert len(found) == 1
    assert found[0]["risk_level"] == "high"
    assert found[0]["arguments_hash"] is not None

    # 2. Get single approval
    resp_single = client.get(f"/approvals/{req.approval_id}")
    assert resp_single.status_code == 200
    assert resp_single.json()["approval_id"] == req.approval_id

    # 3. Decide approval: GRANTED
    decide_resp = client.post(
        f"/approvals/{req.approval_id}/decide",
        json={"decision": "GRANTED", "decided_by": "sec_lead", "reason": "Authorized test"},
    )
    assert decide_resp.status_code == 200
    assert decide_resp.json()["status"] == "granted"
    assert decide_resp.json()["decided_by"] == "sec_lead"


def test_findings_lifecycle_and_human_confirmation(client):
    """Verify creating a candidate finding and promoting it to HUMAN_CONFIRMED."""
    eng_id = "eng-findings-1"

    # 1. Create candidate finding
    create_resp = client.post(
        f"/engagements/{eng_id}/findings",
        json={
            "title": "SQL Injection in Login Form",
            "description": "Unescaped parameter 'username' allows auth bypass",
            "severity": "high",
            "target": "http://target.local/login",
            "check_type": "sqli",
        },
    )
    assert create_resp.status_code == 201
    finding = create_resp.json()
    assert finding["title"] == "SQL Injection in Login Form"
    assert finding["lifecycle_stage"] in ("OBSERVED", "CANDIDATE")
    finding_id = finding["finding_id"]

    # 2. List findings
    list_resp = client.get(f"/engagements/{eng_id}/findings")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert any(item["finding_id"] == finding_id for item in items)

    # 3. Confirm finding as human operator
    confirm_resp = client.post(
        f"/findings/{finding_id}/confirm",
        json={"confirmed_by": "lead_auditor", "notes": "Verified manually with sqlmap PoC"},
    )
    assert confirm_resp.status_code == 200
    confirmed = confirm_resp.json()
    assert confirmed["lifecycle_stage"] == "HUMAN_CONFIRMED"
    assert confirmed["human_confirmed_by"] == "lead_auditor"


def test_generate_report(client):
    """Verify report generation endpoint."""
    resp = client.post(
        "/reports/generate",
        json={"engagement_id": "eng-rep-1", "report_type": "technical", "title": "Audit Report"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "Audit Report" in data["content"]
    assert data["format"] == "markdown"


def test_graph_export(client):
    """Verify React Flow graph generation endpoint."""
    resp = client.get("/engagements/eng-graph-1/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
    assert "stats" in data
