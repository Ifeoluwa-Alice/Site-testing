from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from soc import create_app, timestamp_text


@pytest.fixture()
def client(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "test-soc.sqlite"),
        }
    )
    return app.test_client()


def sample_event(**overrides):
    event = {
        "source": "test-host",
        "source_ip": "192.0.2.20",
        "event_type": "failed_login",
        "username": "test-user",
        "message": "Invalid password",
        "severity": "medium",
    }
    event.update(overrides)
    return event


def test_dashboard_and_security_headers(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"Cyberdev" in response.data
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_database_seeds_demo_telemetry_and_detections(client):
    summary = client.get("/api/summary").get_json()
    alerts = client.get("/api/alerts").get_json()["alerts"]

    assert summary["events_last_24h"] >= 10
    assert summary["open_alerts"] >= 3
    assert any(alert["rule_id"] == "AUTH-001" for alert in alerts)
    assert any(alert["rule_id"] == "ENDPOINT-001" for alert in alerts)
    assert any(alert["rule_id"] == "IDENTITY-001" for alert in alerts)


def test_fifth_failed_login_creates_correlated_alert(client):
    event_time = datetime.now(UTC) - timedelta(minutes=1)
    response = None
    for attempt in range(5):
        response = client.post(
            "/api/events",
            json=sample_event(
                timestamp=timestamp_text(event_time + timedelta(seconds=attempt)),
                source_ip="192.0.2.200",
            ),
        )
        assert response.status_code == 201

    assert response is not None
    assert response.get_json()["alert_ids"]
    alerts = client.get("/api/alerts").get_json()["alerts"]
    alert = next(
        item
        for item in alerts
        if item["rule_id"] == "AUTH-001" and item["source_ip"] == "192.0.2.200"
    )
    assert alert["occurrence_count"] == 1


def test_suspicious_command_detection(client):
    response = client.post(
        "/api/events",
        json=sample_event(
            event_type="process_start",
            message="powershell.exe -EncodedCommand SQBFAFgA",
        ),
    )

    assert response.status_code == 201
    alert = client.get("/api/alerts").get_json()["alerts"]
    assert any(item["rule_id"] == "ENDPOINT-001" for item in alert)


@pytest.mark.parametrize(
    ("payload", "expected_error"),
    [
        (
            {"source": "x", "event_type": "test", "message": "x", "source_ip": "999.1.1.1"},
            "valid IPv4",
        ),
        (
            {"source": "x", "event_type": "test", "message": "x", "severity": "urgent"},
            "severity must",
        ),
        ([], "JSON object"),
    ],
)
def test_invalid_event_payload_is_rejected(client, payload, expected_error):
    response = client.post("/api/events", json=payload)

    assert response.status_code == 400
    assert expected_error in response.get_json()["error"]


def test_alert_workflow_promotes_alert_and_updates_incident(client):
    alert_id = client.get("/api/alerts").get_json()["alerts"][0]["id"]
    created = client.post(f"/api/alerts/{alert_id}/incident")

    assert created.status_code == 201
    incident_id = created.get_json()["id"]
    assert client.post(f"/api/alerts/{alert_id}/incident").status_code == 200
    assert client.get("/api/incidents").get_json()["incidents"][0]["status"] == "open"

    updated = client.patch(f"/api/incidents/{incident_id}", json={"status": "in_progress"})
    assert updated.status_code == 200
    assert updated.get_json()["status"] == "in_progress"

    invalid = client.patch(f"/api/incidents/{incident_id}", json={"status": "closed"})
    assert invalid.status_code == 400


def test_alert_status_validation_and_not_found(client):
    invalid = client.patch("/api/alerts/1", json={"status": "closed"})
    missing = client.patch("/api/alerts/99999", json={"status": "resolved"})

    assert invalid.status_code == 400
    assert missing.status_code == 404
