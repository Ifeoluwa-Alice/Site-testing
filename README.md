# Cyberdev SOC

A defensive, local-first Security Operations Center (SOC) dashboard built with Python, Flask, and SQLite. It ingests normalized security events, evaluates lightweight detections, and provides an analyst workflow for triaging alerts and tracking incidents.

> **Demo project:** The bundled telemetry is synthetic. The app has no authentication and is intended to run on localhost for learning and portfolio demonstrations. Do not expose it to the internet or send it sensitive production logs.

## Features

- Dark, responsive analyst dashboard with event, alert, and incident queues.
- SQLite persistence with indexes and foreign-key constraints.
- JSON event-ingestion endpoint with field, length, severity, timestamp, and IP validation.
- Three starter detections:
  - **AUTH-001:** five or more failed logins from one IP within 15 minutes.
  - **ENDPOINT-001:** command strings containing selected suspicious PowerShell or `certutil` patterns.
  - **IDENTITY-001:** privilege-escalation event types.
- Duplicate suppression for repeated brute-force alerts, with occurrence counts and last-seen time.
- Alert triage, incident creation, and incident status updates.
- Sample events and detections seeded into a new database.
- Security response headers, parameterized SQL queries, and safe text rendering in the browser.
- Pytest coverage and a GitHub Actions CI workflow.

## Quick start

Requires Python 3.11 or newer.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python soc.py
```

Open <http://127.0.0.1:5000>. The app binds to loopback by default and creates its SQLite database in `instance/soc.db`. Set `SOC_DATABASE` to use a different database path.

## API

All endpoints are served locally by the Flask app. JSON errors use an `error` field and an appropriate HTTP status.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/summary` | Event, unresolved alert, and active incident totals |
| `GET` | `/api/events?limit=50` | Latest normalized events (limit is capped at 100) |
| `POST` | `/api/events` | Validate, store, and detect on an event |
| `GET` | `/api/alerts` | List alerts, ordered by severity and last seen |
| `PATCH` | `/api/alerts/<id>` | Set alert status to `new`, `acknowledged`, `investigating`, or `resolved` |
| `POST` | `/api/alerts/<id>/incident` | Create (or return the existing) incident for an alert |
| `GET` | `/api/incidents` | List incident queue |
| `PATCH` | `/api/incidents/<id>` | Set incident status to `open`, `in_progress`, or `resolved` |

Example event:

```powershell
$event = @{
  source = "vpn-gateway-01"
  source_ip = "192.0.2.50"
  event_type = "failed_login"
  username = "analyst-test"
  message = "Invalid password during VPN authentication"
  severity = "medium"
} | ConvertTo-Json

Invoke-RestMethod -Uri http://127.0.0.1:5000/api/events -Method Post `
  -ContentType "application/json" -Body $event
```

## Development and tests

```powershell
python -m pip install pytest ruff
ruff check .
pytest
```

The tests use a temporary SQLite database and do not modify the demo database.

## Project layout

```text
soc.py                    Flask application, API, SQLite schema, and detection rules
templates/dashboard.html  Dashboard structure
static/dashboard.js       Dashboard rendering and analyst actions
static/style.css          Responsive dark theme
tests/test_soc.py         API, detection, validation, and workflow tests
.github/workflows/ci.yml  GitHub Actions lint and test checks
```

## Responsible-use notes

This project demonstrates blue-team event triage. Detection patterns are illustrative and can produce false positives or miss activity. Before adapting it for real use, add authentication and authorization, CSRF protections for browser-driven changes, secrets management, audit logging, retention controls, hardened deployment behind HTTPS, and reviewed detection rules. Avoid collecting or storing sensitive personal data in the demo.
