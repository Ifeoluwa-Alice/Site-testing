"""Local-first Security Operations Center dashboard."""

from __future__ import annotations

import ipaddress
import os
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from flask import Flask, current_app, g, jsonify, render_template, request

SEVERITIES = ("info", "low", "medium", "high", "critical")
ALERT_STATUSES = ("new", "acknowledged", "investigating", "resolved")
INCIDENT_STATUSES = ("open", "in_progress", "resolved")
SUSPICIOUS_COMMAND = re.compile(
    r"-encodedcommand|downloadstring|invoke-expression|frombase64string|"
    r"\bcertutil\b.*-urlcache",
    re.IGNORECASE,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,
    source_ip TEXT,
    event_type TEXT NOT NULL,
    username TEXT,
    message TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_type_ip ON events(event_type, source_ip, timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedupe_key TEXT NOT NULL UNIQUE,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'acknowledged', 'investigating', 'resolved')),
    event_id INTEGER NOT NULL REFERENCES events(id),
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status, created_at DESC);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL UNIQUE REFERENCES alerts(id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'in_progress', 'resolved')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def utc_now() -> datetime:
    return datetime.now(UTC)


def timestamp_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        connection = sqlite3.connect(current_app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def close_db(_error: BaseException | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def parse_timestamp(value: Any) -> str:
    if value is None or value == "":
        return timestamp_text(utc_now())
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be a valid ISO-8601 date and time") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return timestamp_text(parsed)


def required_text(payload: dict[str, Any], field: str, max_length: int) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    value = value.strip()
    if len(value) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")
    return value


def optional_text(payload: dict[str, Any], field: str, max_length: int) -> str | None:
    value = payload.get(field)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    value = value.strip()
    if len(value) > max_length:
        raise ValueError(f"{field} must be at most {max_length} characters")
    return value or None


def validate_event(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object")
    event_type = required_text(payload, "event_type", 64).lower()
    severity = payload.get("severity", "info")
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of: {', '.join(SEVERITIES)}")
    source_ip = optional_text(payload, "source_ip", 45)
    if source_ip:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError as exc:
            raise ValueError("source_ip must be a valid IPv4 or IPv6 address") from exc
    return {
        "timestamp": parse_timestamp(payload.get("timestamp")),
        "source": required_text(payload, "source", 80),
        "source_ip": source_ip,
        "event_type": event_type,
        "username": optional_text(payload, "username", 120),
        "message": required_text(payload, "message", 2000),
        "severity": severity,
    }


def upsert_alert(
    connection: sqlite3.Connection,
    *,
    dedupe_key: str,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    event_id: int,
    seen_at: str,
) -> None:
    existing = connection.execute(
        "SELECT id FROM alerts WHERE dedupe_key = ?", (dedupe_key,)
    ).fetchone()
    if existing:
        connection.execute(
            """UPDATE alerts
               SET occurrence_count = occurrence_count + 1, last_seen = ?, event_id = ?
               WHERE id = ?""",
            (seen_at, event_id, existing["id"]),
        )
        return
    connection.execute(
        """INSERT INTO alerts
           (dedupe_key, rule_id, title, description, severity, event_id, created_at, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (dedupe_key, rule_id, title, description, severity, event_id, seen_at, seen_at),
    )


def detect_event(connection: sqlite3.Connection, event: dict[str, Any], event_id: int) -> None:
    if event["event_type"] == "failed_login" and event["source_ip"]:
        event_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        window_start = timestamp_text(event_time - timedelta(minutes=15))
        failures = connection.execute(
            """SELECT COUNT(*) AS total FROM events
               WHERE event_type = 'failed_login' AND source_ip = ?
                 AND timestamp >= ? AND timestamp <= ?""",
            (event["source_ip"], window_start, event["timestamp"]),
        ).fetchone()["total"]
        if failures >= 5:
            upsert_alert(
                connection,
                dedupe_key=f"brute-force:{event['source_ip']}",
                rule_id="AUTH-001",
                title="Repeated authentication failures",
                description=(
                    f"{failures} failed login attempts from {event['source_ip']} "
                    "were observed within 15 minutes."
                ),
                severity="high",
                event_id=event_id,
                seen_at=event["timestamp"],
            )

    if SUSPICIOUS_COMMAND.search(event["message"]):
        upsert_alert(
            connection,
            dedupe_key=f"suspicious-command:{event_id}",
            rule_id="ENDPOINT-001",
            title="Suspicious command pattern",
            description=f"Potentially suspicious command activity on {event['source']}.",
            severity="high",
            event_id=event_id,
            seen_at=event["timestamp"],
        )

    if event["event_type"] == "privilege_escalation":
        upsert_alert(
            connection,
            dedupe_key=f"privilege-escalation:{event_id}",
            rule_id="IDENTITY-001",
            title="Privilege escalation event",
            description=f"Privilege escalation activity was reported by {event['source']}.",
            severity="critical",
            event_id=event_id,
            seen_at=event["timestamp"],
        )


def store_event(payload: Any) -> tuple[int, list[int]]:
    event = validate_event(payload)
    connection = get_db()
    cursor = connection.execute(
        """INSERT INTO events
           (timestamp, source, source_ip, event_type, username, message, severity)
           VALUES (:timestamp, :source, :source_ip, :event_type, :username,
                   :message, :severity)""",
        event,
    )
    event_id = cursor.lastrowid
    detect_event(connection, event, event_id)
    connection.commit()
    alert_ids = [
        row["id"]
        for row in connection.execute(
            "SELECT id FROM alerts WHERE event_id = ? ORDER BY id", (event_id,)
        ).fetchall()
    ]
    return event_id, alert_ids


def seed_demo_data(connection: sqlite3.Connection) -> None:
    if connection.execute("SELECT 1 FROM events LIMIT 1").fetchone():
        return
    now = utc_now()
    examples = [
        {
            "timestamp": timestamp_text(now - timedelta(minutes=20)),
            "source": "vpn-gateway-01",
            "source_ip": "203.0.113.44",
            "event_type": "vpn_login",
            "username": "j.smith",
            "message": "VPN login successful",
            "severity": "info",
        },
        {
            "timestamp": timestamp_text(now - timedelta(minutes=12)),
            "source": "workstation-17",
            "source_ip": "10.0.4.17",
            "event_type": "process_start",
            "username": "a.jones",
            "message": "Microsoft Word started",
            "severity": "info",
        },
        {
            "timestamp": timestamp_text(now - timedelta(minutes=8)),
            "source": "web-server-02",
            "source_ip": "198.51.100.92",
            "event_type": "http_access",
            "username": None,
            "message": "HTTP 200 GET /health",
            "severity": "info",
        },
        {
            "timestamp": timestamp_text(now - timedelta(minutes=5)),
            "source": "workstation-22",
            "source_ip": "10.0.4.22",
            "event_type": "process_start",
            "username": "m.ade",
            "message": "powershell.exe -EncodedCommand SQBFAFgA",
            "severity": "high",
        },
        {
            "timestamp": timestamp_text(now - timedelta(minutes=2)),
            "source": "identity-provider",
            "source_ip": "192.0.2.88",
            "event_type": "privilege_escalation",
            "username": "svc-backup",
            "message": "Service account granted elevated privileges",
            "severity": "critical",
        },
    ]
    for minutes_ago in (4, 3, 2, 1, 0):
        examples.append(
            {
                "timestamp": timestamp_text(now - timedelta(minutes=minutes_ago)),
                "source": "vpn-gateway-01",
                "source_ip": "198.51.100.23",
                "event_type": "failed_login",
                "username": "admin",
                "message": "Invalid password during VPN authentication",
                "severity": "medium",
            }
        )
    for example in examples:
        event = validate_event(example)
        cursor = connection.execute(
            """INSERT INTO events
               (timestamp, source, source_ip, event_type, username, message, severity)
               VALUES (:timestamp, :source, :source_ip, :event_type, :username,
                       :message, :severity)""",
            event,
        )
        detect_event(connection, event, cursor.lastrowid)
    connection.commit()


def init_db() -> None:
    database = Path(current_app.config["DATABASE"])
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(SCHEMA)
    seed_demo_data(connection)
    connection.close()


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE=os.environ.get("SOC_DATABASE", str(Path(app.instance_path) / "soc.db")),
        JSON_SORT_KEYS=False,
    )
    if test_config:
        app.config.update(test_config)
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        return response

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/api/summary")
    def api_summary():
        connection = get_db()
        since = timestamp_text(utc_now() - timedelta(hours=24))
        event_total = connection.execute(
            "SELECT COUNT(*) AS total FROM events WHERE timestamp >= ?", (since,)
        ).fetchone()["total"]
        alert_total = connection.execute(
            "SELECT COUNT(*) AS total FROM alerts WHERE status != 'resolved'"
        ).fetchone()["total"]
        incident_total = connection.execute(
            "SELECT COUNT(*) AS total FROM incidents WHERE status != 'resolved'"
        ).fetchone()["total"]
        by_severity = {
            row["severity"]: row["total"]
            for row in connection.execute(
                """SELECT severity, COUNT(*) AS total FROM alerts
                   WHERE status != 'resolved' GROUP BY severity"""
            ).fetchall()
        }
        return jsonify(
            events_last_24h=event_total,
            open_alerts=alert_total,
            active_incidents=incident_total,
            alerts_by_severity={severity: by_severity.get(severity, 0) for severity in SEVERITIES},
        )

    @app.get("/api/events")
    def api_events():
        limit = min(max(request.args.get("limit", 50, type=int), 1), 100)
        rows = get_db().execute(
            """SELECT id, timestamp, source, source_ip, event_type, username, message, severity
               FROM events ORDER BY timestamp DESC, id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return jsonify(events=[dict(row) for row in rows])

    @app.post("/api/events")
    def api_ingest_event():
        try:
            event_id, alert_ids = store_event(request.get_json(silent=True))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(event_id=event_id, alert_ids=alert_ids), 201

    @app.get("/api/alerts")
    def api_alerts():
        status = request.args.get("status")
        if status and status not in ALERT_STATUSES:
            return jsonify(error=f"status must be one of: {', '.join(ALERT_STATUSES)}"), 400
        query = """SELECT a.id, a.rule_id, a.title, a.description, a.severity, a.status,
                          a.occurrence_count, a.created_at, a.last_seen, e.source_ip, e.source
                   FROM alerts a JOIN events e ON e.id = a.event_id"""
        params: list[Any] = []
        if status:
            query += " WHERE a.status = ?"
            params.append(status)
        query += " ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        query += "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, a.last_seen DESC LIMIT 100"
        return jsonify(alerts=[dict(row) for row in get_db().execute(query, params).fetchall()])

    @app.patch("/api/alerts/<int:alert_id>")
    def api_update_alert(alert_id: int):
        payload = request.get_json(silent=True)
        status = payload.get("status") if isinstance(payload, dict) else None
        if status not in ALERT_STATUSES:
            return jsonify(error=f"status must be one of: {', '.join(ALERT_STATUSES)}"), 400
        connection = get_db()
        cursor = connection.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        if cursor.rowcount == 0:
            return jsonify(error="Alert not found"), 404
        connection.commit()
        return jsonify(id=alert_id, status=status)

    @app.post("/api/alerts/<int:alert_id>/incident")
    def api_create_incident(alert_id: int):
        connection = get_db()
        alert = connection.execute(
            "SELECT id, title, severity FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        if alert is None:
            return jsonify(error="Alert not found"), 404
        existing = connection.execute(
            "SELECT id, status FROM incidents WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        if existing:
            return jsonify(id=existing["id"], status=existing["status"]), 200
        now = timestamp_text(utc_now())
        cursor = connection.execute(
            """INSERT INTO incidents (alert_id, title, severity, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)""",
            (alert_id, alert["title"], alert["severity"], now, now),
        )
        connection.execute(
            "UPDATE alerts SET status = 'investigating' WHERE id = ? AND status != 'resolved'",
            (alert_id,),
        )
        connection.commit()
        return jsonify(id=cursor.lastrowid, status="open"), 201

    @app.get("/api/incidents")
    def api_incidents():
        rows = get_db().execute(
            """SELECT i.id, i.alert_id, i.title, i.severity, i.status, i.created_at,
                      i.updated_at, a.rule_id
               FROM incidents i JOIN alerts a ON a.id = i.alert_id
               ORDER BY CASE i.status WHEN 'open' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,
                        i.updated_at DESC LIMIT 100"""
        ).fetchall()
        return jsonify(incidents=[dict(row) for row in rows])

    @app.patch("/api/incidents/<int:incident_id>")
    def api_update_incident(incident_id: int):
        payload = request.get_json(silent=True)
        status = payload.get("status") if isinstance(payload, dict) else None
        if status not in INCIDENT_STATUSES:
            return jsonify(error=f"status must be one of: {', '.join(INCIDENT_STATUSES)}"), 400
        connection = get_db()
        cursor = connection.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
            (status, timestamp_text(utc_now()), incident_id),
        )
        if cursor.rowcount == 0:
            return jsonify(error="Incident not found"), 404
        connection.commit()
        return jsonify(id=incident_id, status=status)

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
