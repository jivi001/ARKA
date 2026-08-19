import pytest
from fastapi.testclient import TestClient

from arka.app.api import create_app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


class TestHealthEndpoints:
    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_ready(self, client):
        response = client.get("/ready")
        assert response.status_code == 200


class TestEngagementAPI:
    def test_create_engagement(self, client):
        response = client.post(
            "/engagements",
            json={
                "name": "Test Engagement",
                "description": "Test",
                "scope": {"includes": {"domains": ["example.com"]}},
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Test Engagement"
        assert data["status"] == "created"

    def test_get_engagement(self, client):
        response = client.post("/engagements", json={"name": "Test Get"})
        engagement_id = response.json()["engagement_id"]

        response2 = client.get(f"/engagements/{engagement_id}")
        assert response2.status_code == 200
        assert response2.json()["engagement_id"] == engagement_id

    def test_get_nonexistent_engagement(self, client):
        response = client.get("/engagements/nonexistent-id")
        assert response.status_code == 404

    def test_engagement_lifecycle(self, client):
        # Create with scope
        response = client.post(
            "/engagements",
            json={"name": "Lifecycle", "scope": {"includes": {"domains": ["example.com"]}}},
        )
        eng_id = response.json()["engagement_id"]

        # Start
        start_res = client.post(f"/engagements/{eng_id}/start")
        assert start_res.status_code == 200
        assert start_res.json()["status"] == "active"

        # Pause
        pause_res = client.post(f"/engagements/{eng_id}/pause")
        assert pause_res.status_code == 200
        assert pause_res.json()["status"] == "paused"

        # Stop
        stop_res = client.post(f"/engagements/{eng_id}/stop")
        assert stop_res.status_code == 200
        assert stop_res.json()["status"] == "stopped"

    def test_invalid_state_transition(self, client):
        response = client.post("/engagements", json={"name": "Invalid Transition"})
        eng_id = response.json()["engagement_id"]

        pause_res = client.post(f"/engagements/{eng_id}/pause")
        assert pause_res.status_code == 409  # Conflict error

    def test_engagement_audit_trail(self, client):
        response = client.post("/engagements", json={"name": "Audit Test"})
        eng_id = response.json()["engagement_id"]

        audit_res = client.get(f"/engagements/{eng_id}/audit")
        assert audit_res.status_code == 200
        data = audit_res.json()
        assert "events" in data
        assert isinstance(data["events"], list)
