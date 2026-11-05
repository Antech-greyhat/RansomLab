/* No external assets or HTML injection. The dashboard never issues lab mutations. */
"use strict";

(() => {
  const body = document.body;
  const tones = new Map([
    ["critical", "danger"], ["high", "danger"], ["failed", "danger"],
    ["recovery_failed", "danger"], ["verification_lost", "danger"], ["missing", "danger"], ["interrupted", "warning"],
    ["warning", "warning"], ["changed", "warning"], ["running", "warning"],
    ["contained", "warning"], ["verified", "success"], ["unchanged", "success"], ["intact", "success"],
    ["prepared", "success"], ["success", "success"], ["completed", "success"],
  ]);
  const tone = value => tones.get(String(value).toLowerCase()) || "neutral";
  const label = value => String(value ?? "not recorded").replaceAll("_", " ").replaceAll(".", " · ");
  const text = (id, value) => { const element = document.getElementById(id); if (element) element.textContent = value; };
  const node = (tag, className, value) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (value !== undefined) element.textContent = value;
    return element;
  };
  const bytes = value => {
    if (!Number.isInteger(value) || value < 0) return "—";
    for (const [size, unit] of [[1073741824, "GiB"], [1048576, "MiB"], [1024, "KiB"]]) {
      if (value >= size) return `${(value / size).toFixed(1)} ${unit}`;
    }
    return `${value.toLocaleString()} B`;
  };
  const timestamp = value => {
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? "Unknown time" : `${date.toISOString().slice(11, 19)} UTC`;
  };

  async function bootstrapSession() {
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    if (!fragment.has("token")) return false;
    let token = fragment.get("token");
    // Remove the fragment before any request, navigation, or status rendering.
    window.history.replaceState(null, "", window.location.pathname);
    text("session-status", "Opening the local session…");
    try {
      if (!token || token.length < 32 || token.length > 256) throw new Error("invalid token");
      const response = await fetch("/session", {
        method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error",
        headers: {Authorization: `Bearer ${token}`},
      });
      token = null;
      if (!response.ok) throw new Error("session rejected");
      window.location.replace(window.location.pathname);
      return true;
    } catch (_error) {
      token = null;
      text("session-status", "Session unavailable. Open a fresh link from the dashboard command.");
      return false;
    }
  }

  // Pasting the launch fragment into an already open locked page is a
  // same-document navigation: the browser does not rerun this script.
  window.addEventListener("hashchange", () => {
    if (new URLSearchParams(window.location.hash.slice(1)).has("token")) bootstrapSession();
  });

  function drawEvents(events) {
    const container = document.getElementById("event-timeline");
    if (!container) return;
    const fragment = document.createDocumentFragment();
    for (const event of events.slice(-40).reverse()) {
      const item = node("article", `timeline-event ${tone(event.severity)}`);
      const track = node("div", "timeline-track");
      track.append(node("span", "timeline-dot"));
      const content = node("div", "timeline-content");
      const top = node("div", "event-topline");
      top.append(node("h3", "", label(event.kind)), node("span", "event-sequence", `#${event.sequence}`));
      const reason = event.details?.reason || (event.fixture_id ? `Fixture ${event.fixture_id.slice(0, 8)}` : label(event.outcome));
      const meta = node("div", "event-meta");
      const time = node("time", "", timestamp(event.created_at));
      time.dateTime = event.created_at;
      meta.append(time, node("span", "source-tag", event.source), node("span", "", label(event.outcome)));
      content.append(top, node("p", "event-detail", reason), meta);
      item.append(track, content);
      fragment.append(item);
    }
    if (!events.length) {
      const empty = node("div", "empty-panel");
      empty.append(node("h3", "", "No recorded events yet."), node("p", "", "Committed application events will appear here."));
      fragment.append(empty);
    }
    container.replaceChildren(fragment);
    text("event-count", `${events.length} recent events`);
  }

  function drawAlerts(alerts) {
    const container = document.getElementById("alert-list");
    if (!container) return;
    const fragment = document.createDocumentFragment();
    for (const alert of alerts) {
      const item = node("article", "alert-item");
      const copy = node("div");
      copy.append(node("h3", "", label(alert.rule || alert.kind || "Detection finding")),
        node("p", "", alert.reason || alert.message || alert.status || "Review supporting events"));
      item.append(node("span", `alert-marker ${tone(alert.severity || "warning")}`, "△"), copy);
      fragment.append(item);
    }
    if (!alerts.length) {
      const empty = node("div", "quiet-state");
      empty.append(node("span", "", "◇"), node("h3", "", "No detection findings"),
        node("p", "", "No alerts are recorded in this snapshot. This is not proof that every change was observed."));
      fragment.append(empty);
    }
    container.replaceChildren(fragment);
    text("finding-count", alerts.length);
  }

  function drawFixtures(fixtures) {
    const container = document.getElementById("fixture-rows");
    if (!container) return;
    const fragment = document.createDocumentFragment();
    for (const fixture of fixtures) {
      const row = node("tr");
      const name = node("td");
      name.append(node("span", "file-icon", "▤"), node("span", "", fixture.name));
      const baseline = node("td");
      const baselineHash = node("code", "", `${fixture.sha256.slice(0, 16)}…`);
      baselineHash.title = fixture.sha256;
      baseline.append(baselineHash);
      const current = node("td");
      const currentHash = node("code", "", fixture.current_sha256 ? `${fixture.current_sha256.slice(0, 16)}…` : "Not observed");
      currentHash.title = fixture.current_sha256 || "";
      current.append(currentHash);
      const state = node("td");
      state.append(node("span", `badge ${tone(fixture.status)}`, label(fixture.status)));
      row.append(name, node("td", "mono", bytes(fixture.size)), baseline, current, state);
      fragment.append(row);
    }
    if (!fixtures.length) {
      const row = node("tr");
      const cell = node("td", "empty-table", "No registered fixture inventory is available.");
      cell.colSpan = 5;
      row.append(cell);
      fragment.append(row);
    }
    container.replaceChildren(fragment);
  }

  function update(snapshot) {
    text("metric-files", snapshot.fixture_count);
    text("metric-bytes", bytes(snapshot.bytes_total));
    text("metric-alerts", snapshot.alerts.length);
    const recoveryState = snapshot.recovery?.state || snapshot.recovery?.status || "Not run";
    text("metric-recovery", label(recoveryState));
    const state = document.getElementById("lab-state");
    if (state) { state.textContent = label(snapshot.state); state.className = `badge large ${tone(snapshot.state)}`; }
    for (const link of document.querySelectorAll(".lab-link[data-lab-id]")) {
      if (link.dataset.labId === snapshot.lab_id) {
        link.querySelector("small").textContent = label(snapshot.state);
        link.querySelector(".mini-indicator").className = `mini-indicator ${tone(snapshot.state)}`;
      }
    }
    text("recovery-summary", snapshot.recovery
      ? `Recovery status: ${label(recoveryState)}. Inspect the report for per-file verification results and evidence references.`
      : "No recovery result is recorded. Preserve the exercise evidence before restoring clean fixture copies.");
    drawEvents(snapshot.events);
    drawAlerts(snapshot.alerts);
    drawFixtures(snapshot.fixtures);
  }

  async function start() {
    if (await bootstrapSession()) return;
    if (body.dataset.locked === "true" || !body.dataset.statusUrl) return;
    let active = true;
    let controller;
    window.addEventListener("pagehide", () => { active = false; controller?.abort(); });
    async function refresh() {
      if (!active) return;
      if (!document.hidden) {
        controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 5000);
        try {
          const response = await fetch(body.dataset.statusUrl, {
            credentials: "same-origin", cache: "no-store", redirect: "error", signal: controller.signal,
          });
          if (response.status === 401) {
            active = false;
            text("refresh-status", "Session expired · open a fresh dashboard session link");
            return;
          }
          if (!response.ok) throw new Error("snapshot unavailable");
          update(await response.json());
          text("refresh-status", `Updated ${timestamp(new Date().toISOString())} · refreshes every 3 seconds`);
        } catch (_error) {
          text("refresh-status", "Snapshot is stale · reconnecting to the local service");
        } finally {
          window.clearTimeout(timeout);
        }
      }
      if (active) window.setTimeout(refresh, 3000);
    }
    window.setTimeout(refresh, 3000);
  }
  start();
})();
