const severityOrder = ["critical", "high", "medium", "low", "info"];

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function badge(value, prefix) {
  return element("span", `${prefix} ${value}`, value.replaceAll("_", " "));
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", ...options.headers },
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function setRows(targetId, rows, columns, emptyMessage) {
  const body = document.getElementById(targetId);
  body.replaceChildren();
  if (!rows.length) {
    const row = element("tr");
    const cell = element("td", "empty-cell", emptyMessage);
    cell.colSpan = columns;
    row.append(cell);
    body.append(row);
    return;
  }
  rows.forEach((row) => body.append(row));
}

async function loadSummary() {
  const data = await api("/api/summary");
  document.getElementById("metric-events").textContent = data.events_last_24h.toLocaleString();
  document.getElementById("metric-alerts").textContent = data.open_alerts.toLocaleString();
  document.getElementById("metric-incidents").textContent = data.active_incidents.toLocaleString();
  document.getElementById("nav-alert-count").textContent = data.open_alerts;

  const chart = document.getElementById("severity-chart");
  chart.replaceChildren();
  const max = Math.max(1, ...severityOrder.map((severity) => data.alerts_by_severity[severity]));
  severityOrder.forEach((severity) => {
    const line = element("div", "severity-line");
    const label = element("span", `severity-label ${severity}`, severity);
    const track = element("div", "severity-track");
    const bar = element("span", `severity-bar ${severity}`);
    bar.style.width = `${Math.max(0, (data.alerts_by_severity[severity] / max) * 100)}%`;
    track.append(bar);
    line.append(label, track, element("strong", "severity-count", data.alerts_by_severity[severity]));
    chart.append(line);
  });
}

async function loadAlerts() {
  const { alerts } = await api("/api/alerts");
  const rows = alerts.map((alert) => {
    const row = element("tr");
    const title = element("td", "alert-title");
    title.append(element("strong", "", alert.title), element("small", "", `${alert.source} · ${alert.source_ip || "no IP"} · ${alert.occurrence_count} occurrence(s)`));
    const severity = element("td");
    severity.append(badge(alert.severity, "severity-badge"));
    const detection = element("td", "mono-cell", alert.rule_id);
    const lastSeen = element("td", "muted-cell", formatDate(alert.last_seen));
    const status = element("td");
    status.append(badge(alert.status, "status-badge"));
    const actions = element("td");
    actions.className = "actions-cell";
    if (alert.status === "new") {
      const acknowledge = element("button", "mini-button", "Acknowledge");
      acknowledge.type = "button";
      acknowledge.addEventListener("click", () => updateAlert(alert.id, "acknowledged"));
      actions.append(acknowledge);
    }
    if (alert.status !== "resolved") {
      const incident = element("button", "mini-button", "Create incident");
      incident.type = "button";
      incident.addEventListener("click", () => createIncident(alert.id));
      actions.append(incident);
      const resolve = element("button", "mini-button muted-button", "Resolve");
      resolve.type = "button";
      resolve.addEventListener("click", () => updateAlert(alert.id, "resolved"));
      actions.append(resolve);
    }
    row.append(title, severity, detection, lastSeen, status, actions);
    return row;
  });
  setRows("alerts-table", rows, 6, "No alerts match the current view.");
}

async function loadIncidents() {
  const { incidents } = await api("/api/incidents");
  const rows = incidents.map((incident) => {
    const row = element("tr");
    row.append(
      element("td", "mono-cell", `INC-${String(incident.id).padStart(4, "0")}`),
    );
    const severity = element("td");
    severity.append(badge(incident.severity, "severity-badge"));
    row.append(
      severity,
      element("td", "", `${incident.title} · ${incident.rule_id}`),
      element("td", "muted-cell", formatDate(incident.created_at)),
    );
    const statusCell = element("td");
    statusCell.append(badge(incident.status, "status-badge"));
    row.append(statusCell);
    const actionCell = element("td", "actions-cell");
    if (incident.status !== "resolved") {
      const button = element("button", "mini-button", incident.status === "open" ? "Start investigation" : "Resolve");
      button.type = "button";
      button.addEventListener("click", () => {
        updateIncident(incident.id, incident.status === "open" ? "in_progress" : "resolved");
      });
      actionCell.append(button);
    }
    row.append(actionCell);
    return row;
  });
  setRows("incidents-table", rows, 6, "No incidents yet. Promote an alert to start an investigation.");
}

async function loadEvents() {
  const { events } = await api("/api/events?limit=50");
  const rows = events.map((event) => {
    const row = element("tr");
    row.append(
      element("td", "muted-cell nowrap", formatDate(event.timestamp)),
      element("td", "mono-cell", event.source),
      element("td", "", event.event_type.replaceAll("_", " ")),
      element("td", "", event.username || "—"),
      element("td", "event-message", event.message),
    );
    const severityCell = element("td");
    severityCell.append(badge(event.severity, "severity-badge"));
    row.append(severityCell);
    return row;
  });
  setRows("events-table", rows, 6, "No events received.");
}

async function refreshDashboard() {
  const results = await Promise.allSettled([loadSummary(), loadAlerts(), loadIncidents(), loadEvents()]);
  const failures = results.filter((result) => result.status === "rejected");
  if (failures.length) showMessage(failures[0].reason.message, true);
}

function showMessage(message, isError = false) {
  const target = document.getElementById("ingest-message");
  target.textContent = message;
  target.classList.toggle("error-message", isError);
}

async function updateAlert(id, status) {
  try {
    await api(`/api/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status }) });
    await refreshDashboard();
  } catch (error) {
    showMessage(error.message, true);
  }
}

async function createIncident(id) {
  try {
    await api(`/api/alerts/${id}/incident`, { method: "POST", body: "{}" });
    await refreshDashboard();
  } catch (error) {
    showMessage(error.message, true);
  }
}

async function updateIncident(id, status) {
  try {
    await api(`/api/incidents/${id}`, { method: "PATCH", body: JSON.stringify({ status }) });
    await refreshDashboard();
  } catch (error) {
    showMessage(error.message, true);
  }
}

document.getElementById("refresh-button").addEventListener("click", refreshDashboard);
document.getElementById("ingest-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = Object.fromEntries(form.entries());
  payload.username = "analyst";
  payload.severity = payload.event_type === "privilege_escalation" ? "critical" : "medium";
  try {
    const result = await api("/api/events", { method: "POST", body: JSON.stringify(payload) });
    showMessage(`Event #${result.event_id} ingested · ${result.alert_ids.length} alert(s) generated.`);
    event.currentTarget.reset();
    event.currentTarget.elements.source.value = "analyst-workstation";
    await refreshDashboard();
  } catch (error) {
    showMessage(error.message, true);
  }
});

refreshDashboard();
