import test, { after, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createServer, MAX_REQUEST_BYTES } from "../server.js";
import { MemoryStore } from "../src/memory-store.js";

const appState = { scanRunning: false };
const store = new MemoryStore();
let scanImplementation;
const sampleResult = (overrides = {}) => ({
  generated_at: new Date().toISOString(),
  duration_seconds: 0.2,
  target: "192.168.1.0/24",
  host: { hostname: "test-host", interfaces: [], ipv6_interfaces: [], suggested_targets: [], target_options: [] },
  network: { cidr: "192.168.1.0/24", network_address: "192.168.1.0", broadcast_address: "192.168.1.255", prefix: 24, interface: "eth0", interface_kind: "ethernet", local_address: "192.168.1.2", local_mac: "aa:bb:cc:dd:ee:ff", gateway: "192.168.1.1", gateway_metric: 10, dns_servers: ["192.168.1.1"], route_count: 2 },
  ipv6: { mode: "passive", interfaces: [], neighbors: [] },
  devices: [{ ip: "192.168.1.2", hostname: "test-host", mac: "aa:bb:cc:dd:ee:ff", state: "up", latency_ms: 1.2, open_ports: [{ port: 80, service: "HTTP" }], is_host: true, is_gateway: false, evidence: ["local", "icmp", "tcp"], role: { key: "host", label: "This PC", category: "endpoints", reason: "Local address" } }],
  warnings: [],
  scan_options: { ports: [80], port_mode: "selected", address_mode: "standard", usable_address_count: 254, scanned_address_count: 254, excluded_address_count: 0, ping_timeout_ms: 500, port_timeout_ms: 260, full_port_timeout_ms: null },
  summary: { device_count: 1, responsive_count: 1, tcp_evidence_count: 1, tcp_discovered_count: 0, neighbor_only_count: 0, open_service_count: 1, gateway_count: 0, ipv6_interface_count: 0, ipv6_neighbor_count: 0 },
  changes: { comparable: false, baseline_generated_at: null, new_devices: [], missing_devices: [], changed_services: [], counts: { new: 0, missing: 0, changed: 0 } },
  topology: { kind: "observed-logical", disclaimer: "Logical only", nodes: [], edges: [] },
  ...overrides,
});

const scanner = {
  DEFAULT_PORTS: [22, 80],
  PORT_NAMES: { 22: "SSH", 80: "HTTP" },
  interfaceInventory: () => [],
  targetOptions: () => [{ cidr: "192.168.1.0/24", interface: "eth0", kind: "ethernet", address_count: 256, usable_address_count: 254, scope: "local-segment", extended: false }],
  hostInventory: () => ({ hostname: "test-host", interfaces: [], ipv6_interfaces: [], suggested_targets: ["192.168.1.0/24"], target_options: [{ cidr: "192.168.1.0/24", scope: "local-segment", extended: false }] }),
  scanNetwork: (...args) => scanImplementation(...args),
};
const logger = { error() {}, warn() {} };
const server = createServer({ scanner, store, state: appState, logger, wakeFn: async (mac) => ({ sent: true, mac }) });
let baseUrl;

before(async () => {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { await new Promise((resolve) => server.close(resolve)); });
beforeEach(() => {
  appState.scanRunning = false;
  appState.scanSource = null;
  appState.progress = null;
  appState.abortController = null;
  store.scans.length = 0;
  store.devices.length = 0;
  store.alerts.length = 0;
  store.notificationEvents.length = 0;
  store.schedules.length = 0;
  store.exclusions.length = 0;
  store.settings.clear();
  scanImplementation = async () => sampleResult();
});

const request = (pathname, options = {}) => fetch(`${baseUrl}${pathname}`, options);
const jsonPost = (pathname, payload, method = "POST") => request(pathname, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });

function requestWithHost(pathname, host) {
  return new Promise((resolve, reject) => {
    const outgoing = http.request({ host: "127.0.0.1", port: server.address().port, path: pathname, headers: { Host: host } }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({ response, body: Buffer.concat(chunks).toString("utf8") }));
    });
    outgoing.on("error", reject);
    outgoing.end();
  });
}

test("health, dashboard, and static files have security headers", async () => {
  for (const pathname of ["/healthz", "/", "/static/app.css", "/static/favicon.svg", "/static/%2e%2e/server.js", "/missing"]) {
    const response = await request(pathname);
    assert.ok([200, 404].includes(response.status), `${pathname} returned ${response.status}`);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.match(response.headers.get("content-security-policy"), /default-src 'self'/);
  }
});

test("HEAD requests return GET metadata without bodies", async () => {
  for (const pathname of ["/healthz", "/", "/static/app.css", "/static/favicon.svg"]) {
    const response = await request(pathname, { method: "HEAD" });
    assert.equal(response.status, 200);
    assert.ok(Number(response.headers.get("content-length")) > 0);
    assert.equal(await response.text(), "");
  }
});

test("dashboard exposes release-ready monitoring controls and removes redundant shortcut help", async () => {
  const html = await (await request("/")).text();
  for (const expected of [
    "History",
    "Alerts",
    "Automation",
    "Custom",
    "All TCP ports",
    "favicon.svg",
    "profile-select",
    "scan-all-targets",
    "notification-history-list",
    "exclusion-manager",
    "Keyboard shortcuts",
  ]) assert.match(html, new RegExp(expected, "i"));
  for (const removed of ["shortcut-dialog", "shortcut-help-button", "Show shortcut help"]) assert.doesNotMatch(html, new RegExp(removed, "i"));
  assert.doesNotMatch(html, /NetScope Lite\s+v?\d/i);
});

test("invalid Host headers are rejected", async () => {
  const { response, body } = await requestWithHost("/healthz", "attacker.example");
  assert.equal(response.statusCode, 400);
  assert.match(JSON.parse(body).error, /Invalid Host/);
});

test("status and scan-state payloads are coherent", async () => {
  appState.scanRunning = true;
  const scanState = await (await request("/api/scan-state")).json();
  assert.equal(scanState.scan_running, true);
  assert.equal(scanState.progress, null);
  const response = await request("/api/status");
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(payload.default_ports, [22, 80]);
  assert.equal(payload.profiles.length, 4);
  assert.equal(payload.target_options.length, 1);
  assert.ok(payload.monitor);
});

test("scan validation and request limits return client errors", async () => {
  const cases = [
    [request("/api/scan", { method: "POST", headers: { "Content-Type": "text/plain" }, body: "{}" }), 415],
    [request("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{" }), 400],
    [jsonPost("/api/scan", { target: "192.168.1.0/24", ports: null }), 400],
    [jsonPost("/api/scan", { target: "192.168.1.0/24", ports: [], port_mode: "all" }), 400],
  ];
  for (const [promise, status] of cases) assert.equal((await promise).status, status);
  const oversized = await request("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target: "192.168.1.0/24", ports: [], padding: "x".repeat(MAX_REQUEST_BYTES + 1024) }) });
  assert.equal(oversized.status, 413);
});

test("successful scans persist history, devices, exports, and comparison data", async () => {
  const first = await jsonPost("/api/scan", { target: "192.168.1.0/24", ports: [80] });
  const firstPayload = await first.json();
  assert.equal(first.status, 200);
  assert.equal(firstPayload.saved, true);
  assert.ok(firstPayload.scan_id);
  scanImplementation = async () => sampleResult({
    generated_at: new Date(Date.now() + 1000).toISOString(),
    devices: [...sampleResult().devices, { ip: "192.168.1.10", hostname: "printer", mac: "00:1a:11:11:22:33", state: "service", latency_ms: null, open_ports: [{ port: 9100, service: "JetDirect" }], is_host: false, is_gateway: false, evidence: ["tcp"], role: { key: "printer", label: "Printer", category: "peripherals", reason: "Printing service" } }],
    summary: { ...sampleResult().summary, device_count: 2, tcp_evidence_count: 2, open_service_count: 2 },
  });
  const secondPayload = await (await jsonPost("/api/scan", { target: "192.168.1.0/24", ports: [80, 9100] })).json();
  const history = await (await request("/api/history")).json();
  assert.equal(history.scans.length, 2);
  const compare = await request(`/api/history/compare?left=${firstPayload.scan_id}&right=${secondPayload.scan_id}`);
  assert.equal(compare.status, 200);
  assert.equal((await compare.json()).changes.counts.new, 1);
  const exportResponse = await request("/api/export?format=csv");
  assert.equal(exportResponse.status, 200);
  assert.match(exportResponse.headers.get("content-type"), /text\/csv/);
  assert.match(await exportResponse.text(), /printer/);
});

test("device records support names, trust, tags, notes, ignored alerts, and Wake-on-LAN", async () => {
  const payload = await (await jsonPost("/api/scan", { target: "192.168.1.0/24", ports: [80] })).json();
  const deviceId = payload.devices[0].device_id;
  const updatedResponse = await jsonPost(`/api/devices/${deviceId}`, { custom_name: "Lab workstation", trust_state: "trusted", tags: ["lab", "managed"], notes: "Primary test system", ignored: true }, "PATCH");
  assert.equal(updatedResponse.status, 200);
  const updated = await updatedResponse.json();
  assert.equal(updated.custom_name, "Lab workstation");
  assert.deepEqual(updated.tags, ["lab", "managed"]);
  assert.ok(updated.observations.length);
  const wake = await jsonPost(`/api/devices/${deviceId}/wake`, {});
  assert.equal(wake.status, 202);
});

test("profiles, schedules, exclusions, and settings validate and persist", async () => {
  const profileResponse = await jsonPost("/api/profiles", { name: "Office", address_mode: "standard", port_mode: "selected", ports: [22, 443], timeout_ms: 250 });
  assert.equal(profileResponse.status, 201);
  const profile = await profileResponse.json();
  const scheduleResponse = await jsonPost("/api/schedules", { name: "Hourly", targets: ["192.168.1.0/24"], profile_id: profile.id, interval_minutes: 60 });
  assert.equal(scheduleResponse.status, 201);
  assert.equal((await request("/api/schedules").then((response) => response.json())).schedules.length, 1);
  const exclusion = await jsonPost("/api/exclusions", { kind: "mac", value: "AA-BB-CC-DD-EE-01", label: "Excluded" });
  assert.equal(exclusion.status, 201);
  assert.equal((await exclusion.json()).value, "aa:bb:cc:dd:ee:01");
  const settings = await request("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ preferences: { theme_schedule: { enabled: true } }, alert_preferences: { browser_notifications: true } }) });
  assert.equal(settings.status, 200);
  assert.equal((await request("/api/settings").then((response) => response.json())).alert_preferences.browser_notifications, true);
});

test("scheduled all-port profiles require explicit authorization on create and update", async () => {
  const profile = store.listProfiles().find((entry) => entry.port_mode === "all");
  const rejected = await jsonPost("/api/schedules", { name: "Deep", targets: ["192.168.1.0/24"], profile_id: profile.id, interval_minutes: 60 });
  assert.equal(rejected.status, 400);
  const allowed = await jsonPost("/api/schedules", { name: "Deep", targets: ["192.168.1.0/24"], profile_id: profile.id, interval_minutes: 60, allow_intensive: true });
  assert.equal(allowed.status, 201);
  const schedule = await allowed.json();
  const patchRejected = await jsonPost(`/api/schedules/${schedule.id}`, { allow_intensive: false }, "PATCH");
  assert.equal(patchRejected.status, 400);
});

test("alerts are generated after baseline and can be acknowledged", async () => {
  await jsonPost("/api/scan", { target: "192.168.1.0/24", ports: [80] });
  scanImplementation = async () => sampleResult({ generated_at: new Date(Date.now() + 1000).toISOString(), devices: [...sampleResult().devices, { ip: "192.168.1.5", hostname: "new-host", mac: "00:1a:11:22:33:44", state: "service", latency_ms: null, open_ports: [{ port: 23, service: "Telnet" }], is_host: false, is_gateway: false, evidence: ["tcp"], role: { key: "server", label: "Server", category: "servers", reason: "TCP service" } }], summary: { ...sampleResult().summary, device_count: 2, open_service_count: 2 } });
  await jsonPost("/api/scan", { target: "192.168.1.0/24", ports: [23, 80] });
  const alertsPayload = await (await request("/api/alerts?acknowledged=false")).json();
  assert.ok(alertsPayload.alerts.some((alert) => alert.kind === "new-device"));
  const acknowledged = await request("/api/alerts/acknowledge-all", { method: "POST" });
  assert.equal(acknowledged.status, 200);
  assert.equal((await request("/api/alerts?acknowledged=false").then((response) => response.json())).alerts.length, 0);
});

test("notification history records, lists, validates, and clears local delivery attempts", async () => {
  const created = await jsonPost("/api/notifications/history", {
    alert_id: 7,
    status: "shown",
    title: "NetScope Lite",
    message: "Two network alerts need review.",
    details: { unacknowledged_count: 2 },
  });
  assert.equal(created.status, 201);
  const event = await created.json();
  assert.equal(event.status, "shown");
  assert.equal(event.alert_id, 7);

  const history = await (await request("/api/notifications/history")).json();
  assert.equal(history.notifications.length, 1);
  assert.equal(history.notifications[0].message, "Two network alerts need review.");

  const invalid = await jsonPost("/api/notifications/history", { status: "sent-to-cloud", title: "Bad", message: "Bad" });
  assert.equal(invalid.status, 400);
  const cleared = await request("/api/notifications/history", { method: "DELETE" });
  assert.equal(cleared.status, 200);
  assert.equal((await cleared.json()).deleted, 1);
  assert.equal((await request("/api/notifications/history").then((response) => response.json())).notifications.length, 0);
});

test("running scans can be cancelled and concurrent scans conflict", async () => {
  scanImplementation = async (_target, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => { const error = new Error("Scan cancelled."); error.name = "AbortError"; reject(error); }, { once: true });
  });
  const pending = jsonPost("/api/scan", { target: "192.168.1.0/24", ports: [80] });
  for (let attempts = 0; attempts < 100 && !appState.scanRunning; attempts += 1) await new Promise((resolve) => setTimeout(resolve, 2));
  assert.equal((await jsonPost("/api/scan", { target: "192.168.1.0/24", ports: [80] })).status, 409);
  assert.equal((await request("/api/scan/cancel", { method: "POST" })).status, 202);
  assert.equal((await pending).status, 409);
});

test("optional password protection gates private API routes", async () => {
  const set = await jsonPost("/api/auth/password", { current_password: "", new_password: "correct horse battery" });
  assert.equal(set.status, 200);
  const protectedResponse = await request("/api/status");
  assert.equal(protectedResponse.status, 401);
  const login = await jsonPost("/api/auth/login", { password: "correct horse battery" });
  assert.equal(login.status, 200);
  const cookie = login.headers.get("set-cookie").split(";", 1)[0];
  assert.equal((await request("/api/status", { headers: { Cookie: cookie } })).status, 200);
  await request("/api/auth/password", { method: "POST", headers: { "Content-Type": "application/json", Cookie: cookie }, body: JSON.stringify({ current_password: "correct horse battery", new_password: "" }) });
});

test("decorated JSON exports can be imported again safely", async () => {
  const scan = await jsonPost("/api/scan", { target: "192.168.1.0/24", ports: [80] });
  assert.equal(scan.status, 200);
  const exported = await (await request("/api/export?format=json")).json();
  assert.ok(exported.devices[0].device_id);
  exported.devices[0].custom_name = "Imported workstation";
  const imported = await jsonPost("/api/history/import", exported);
  assert.equal(imported.status, 201);
  assert.equal((await request("/api/history").then((response) => response.json())).scans.length, 2);
});

test("CSV exports neutralize spreadsheet formulas in user-managed names", async () => {
  const payload = await (await jsonPost("/api/scan", { target: "192.168.1.0/24", ports: [80] })).json();
  await jsonPost(`/api/devices/${payload.devices[0].device_id}`, { custom_name: "=HYPERLINK(\"https://example.invalid\",\"click\")" }, "PATCH");
  const csv = await (await request("/api/export?format=csv")).text();
  assert.match(csv, /'=HYPERLINK/);
  assert.doesNotMatch(csv, /,=HYPERLINK/);
});

test("schedules and exclusions reject public or unattached networks", async () => {
  const profile = store.listProfiles().find((entry) => entry.port_mode === "selected");
  assert.equal((await jsonPost("/api/schedules", { name: "Wrong network", targets: ["192.168.55.0/24"], profile_id: profile.id, interval_minutes: 60 })).status, 400);
  assert.equal((await jsonPost("/api/schedules", { name: "Public", targets: ["8.8.8.8/32"], profile_id: profile.id, interval_minutes: 60 })).status, 400);
  assert.equal((await jsonPost("/api/exclusions", { kind: "ip", value: "8.8.8.8" })).status, 400);
});

test("monitor endpoint and status include lightweight persistent preferences", async () => {
  await request("/api/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      preferences: { theme_schedule: { enabled: true, day: "light", night: "purple", day_start: "06:30", night_start: "20:15" } },
      alert_preferences: { browser_notifications: true },
    }),
  });
  const status = await (await request("/api/status")).json();
  assert.equal(status.settings.preferences.theme_schedule.day_start, "06:30");
  assert.equal(status.settings.alert_preferences.browser_notifications, true);
  const monitor = await request("/api/monitor");
  assert.equal(monitor.status, 200);
  assert.ok((await monitor.json()).monitor);
});

test("settings reject malformed preference payloads", async () => {
  assert.equal((await request("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ preferences: [] }) })).status, 400);
  assert.equal((await request("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ alert_preferences: "yes" }) })).status, 400);
});

test("malformed session cookies fail closed instead of causing server errors", async () => {
  assert.equal((await jsonPost("/api/auth/password", { current_password: "", new_password: "correct horse battery" })).status, 200);
  const malformed = await request("/api/status", { headers: { Cookie: "netscope_session=%E0%A4%A" } });
  assert.equal(malformed.status, 401);
  const login = await jsonPost("/api/auth/login", { password: "correct horse battery" });
  const cookie = login.headers.get("set-cookie").split(";", 1)[0];
  await request("/api/auth/password", { method: "POST", headers: { "Content-Type": "application/json", Cookie: cookie }, body: JSON.stringify({ current_password: "correct horse battery", new_password: "" }) });
});

test("detached schedules can be paused but cannot be resumed", async () => {
  const profile = store.listProfiles().find((entry) => entry.port_mode === "selected");
  const detached = store.saveSchedule({ name: "Detached", targets: ["192.168.55.0/24"], profile_id: profile.id, interval_minutes: 60, enabled: true, allow_intensive: false });
  const paused = await jsonPost(`/api/schedules/${detached.id}`, { enabled: false }, "PATCH");
  assert.equal(paused.status, 200);
  const resumed = await jsonPost(`/api/schedules/${detached.id}`, { enabled: true }, "PATCH");
  assert.equal(resumed.status, 400);
});

test("history and status results retain their scan identifiers", async () => {
  const scanPayload = await (await jsonPost("/api/scan", { target: "192.168.1.0/24", ports: [80] })).json();
  const status = await (await request("/api/status")).json();
  assert.equal(status.latest.scan_id, scanPayload.scan_id);
  const history = await (await request(`/api/history/${scanPayload.scan_id}`)).json();
  assert.equal(history.result.scan_id, scanPayload.scan_id);
});

test("exclusion updates reject empty, unknown, and incorrectly typed patches", async () => {
  const created = await jsonPost("/api/exclusions", { kind: "ip", value: "192.168.1.50", label: "Temporary" });
  assert.equal(created.status, 201);
  const exclusion = await created.json();
  for (const payload of [{}, { value: "192.168.1.60" }, { enabled: "yes" }]) {
    const response = await jsonPost(`/api/exclusions/${exclusion.id}`, payload, "PATCH");
    assert.equal(response.status, 400);
  }
  const updated = await jsonPost(`/api/exclusions/${exclusion.id}`, { enabled: false, label: "Paused" }, "PATCH");
  assert.equal(updated.status, 200);
  assert.equal((await updated.json()).enabled, false);
});
