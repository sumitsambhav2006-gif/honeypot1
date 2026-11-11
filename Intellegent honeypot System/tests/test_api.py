import pytest
from backend.app import create_app

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

def test_api_dashboard_stats(client):
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert "kpis" in data
    assert "trends" in data
    assert "top_usernames" in data

def test_api_attacks_list(client):
    res = client.get("/api/attacks?limit=5")
    assert res.status_code == 200
    data = res.get_json()
    assert "attacks" in data
    assert isinstance(data["attacks"], list)

def test_api_attackers_list(client):
    res = client.get("/api/attackers?limit=5")
    assert res.status_code == 200
    data = res.get_json()
    assert "attackers" in data

def test_api_sessions_list(client):
    res = client.get("/api/sessions?limit=5")
    assert res.status_code == 200
    data = res.get_json()
    assert "sessions" in data

def test_api_alerts_list(client):
    res = client.get("/api/alerts")
    assert res.status_code == 200
    data = res.get_json()
    assert "alerts" in data

def test_api_reports_export_csv(client):
    res = client.get("/api/reports/export?format=csv&type=attacks")
    assert res.status_code == 200
    assert "text/csv" in res.headers["Content-Type"]

def test_api_reports_export_pdf(client):
    res = client.get("/api/reports/export?format=pdf")
    assert res.status_code == 200
    assert "application/pdf" in res.headers["Content-Type"]

