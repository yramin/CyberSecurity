"""Tests for API endpoints."""

import pytest
from fastapi.testclient import TestClient
from api.main import app
from api.database import init_db, get_db
import os

# Initialize test database
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
init_db()

client = TestClient(app)


@pytest.fixture
def auth_headers():
    """Get authentication headers."""
    credentials = "admin:admin123"
    import base64
    encoded = base64.b64encode(credentials.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def test_health_check():
    """Test health check endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_get_incidents(auth_headers):
    """Test getting incidents."""
    response = client.get("/api/v1/incidents", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_create_incident(auth_headers):
    """Test creating an incident."""
    incident_data = {
        "title": "Test Incident",
        "description": "This is a test incident",
        "severity": "medium",
    }
    response = client.post("/api/v1/incidents", json=incident_data, headers=auth_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "Test Incident"


def test_get_alerts(auth_headers):
    """Test getting alerts."""
    response = client.get("/api/v1/alerts", headers=auth_headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_unauthorized_access():
    """Test that unauthorized access is blocked."""
    response = client.get("/api/v1/incidents")
    assert response.status_code == 401

