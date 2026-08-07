import { execFile } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { AuthManager } from "./src/auth.js";
import { identityKeyForDevice, normalizeMac } from "./src/identity.js";
import { MemoryStore } from "./src/memory-store.js";
import { ScanManager, ScanScheduler } from "./src/scan-manager.js";
import * as scannerModule from "./src/scanner.js";
import { TargetRejected, isAllowedLocalNetwork, normalizePorts, parseIPv4, parseIPv4Network } from "./src/safety.js";
import { sendWakeOnLan } from "./src/wol.js";

export const MAX_REQUEST_BYTES = 256 * 1024;
export const MAX_IMPORT_BYTES = 64 * 1024 * 1024;
const ROOT = path.dirname(fileURLToPath(import.meta.url));
const STATIC_ROOT = path.join(ROOT, "static");
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);

export function defaultDataDirectory() {
  if (process.env.NETSCOPE_DATA_DIR) return process.env.NETSCOPE_DATA_DIR;
  if (process.platform === "win32") {
    const base = process.env.LOCALAPPDATA ?? path.join(os.homedir(), "AppData", "Local");
    return path.join(base, "NetScopeLite");
  }
  if (process.platform === "darwin") return path.join(os.homedir(), "Library", "Application Support", "NetScope Lite");
  const base = process.env.XDG_STATE_HOME ?? path.join(os.homedir(), ".local", "state");
  return path.join(base, "netscope-lite");
}

export function defaultDatabasePath() {
  return path.join(defaultDataDirectory(), "netscope.sqlite");
}

export function defaultLegacyDataPath() {
  return path.join(defaultDataDirectory(), "latest_scan.json");
}

const MIME_TYPES = new Map([
  [".html", "text/html; charset=utf-8"], [".css", "text/css; charset=utf-8"], [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"], [".svg", "image/svg+xml"], [".png", "image/png"], [".ico", "image/x-icon"],
]);

function applySecurityHeaders(response) {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
}

function sendJson(response, payload, status = 200, options = {}) {
  const body = Buffer.from(JSON.stringify(payload, null, options.pretty ? 2 : 0), "utf8");
  response.statusCode = status;
  response.setHeader("Cache-Control", options.cacheControl ?? "no-store");
  response.setHeader("Content-Type", options.contentType ?? "application/json; charset=utf-8");
  response.setHeader("Content-Length", body.length);
  if (options.contentDisposition) response.setHeader("Content-Disposition", options.contentDisposition);
  if (options.cookie) response.setHeader("Set-Cookie", options.cookie);
  response.end(response.req?.method === "HEAD" ? undefined : body);
}

function sendBuffer(response, body, { status = 200, contentType = "application/octet-stream", contentDisposition = null, cacheControl = "no-store" } = {}) {
  response.statusCode = status;
  response.setHeader("Cache-Control", cacheControl);
  response.setHeader("Content-Type", contentType);
  response.setHeader("Content-Length", body.length);
  if (contentDisposition) response.setHeader("Content-Disposition", contentDisposition);
  response.end(response.req?.method === "HEAD" ? undefined : body);
}

function sendText(response, message, status = 404) {
  return sendBuffer(response, Buffer.from(message, "utf8"), { status, contentType: "text/plain; charset=utf-8" });
}

function requestHost(request) {
  const raw = String(request.headers.host ?? "").trim().toLowerCase();
  if (raw.startsWith("[")) {
    const closingBracket = raw.indexOf("]");
    return closingBracket > 1 ? raw.slice(1, closingBracket) : "";
  }
  return raw.split(":", 1)[0];
}

export function requestAllowedHosts(value = process.env.NETSCOPE_ALLOWED_HOSTS) {
  const hosts = new Set(LOOPBACK_HOSTS);
  for (const entry of String(value ?? "").split(",")) {
    const host = entry.trim().toLowerCase();
    if (host) hosts.add(host);
  }
  return hosts;
}

function hostIsAllowed(request, allowedHosts) {
  return allowedHosts.has(requestHost(request));
}

function staticFilePath(urlPath) {
  let relative;
  try {
    relative = decodeURIComponent(urlPath.replace(/^\/static\//, ""));
  } catch {
    return null;
  }
  if (!relative || relative.includes("\0")) return null;
  const candidate = path.resolve(STATIC_ROOT, relative);
  const prefix = `${path.resolve(STATIC_ROOT)}${path.sep}`;
  return candidate.startsWith(prefix) ? candidate : null;
}

function sendFile(response, filePath, cacheControl = "no-cache") {
  if (!filePath) return sendText(response, "Not found", 404);
  let stats;
  try {
    stats = fs.statSync(filePath);
  } catch {
    return sendText(response, "Not found", 404);
  }
  if (!stats.isFile()) return sendText(response, "Not found", 404);
  response.statusCode = 200;
  response.setHeader("Cache-Control", cacheControl);
  response.setHeader("Content-Type", MIME_TYPES.get(path.extname(filePath).toLowerCase()) ?? "application/octet-stream");
  response.setHeader("Content-Length", stats.size);
  if (response.req?.method === "HEAD") return response.end();
  fs.createReadStream(filePath).on("error", () => response.headersSent ? response.destroy() : sendText(response, "Unable to read file", 500)).pipe(response);
}

async function readJsonBody(request, maxBytes = MAX_REQUEST_BYTES) {
  const contentLengthHeader = request.headers["content-length"];
  if (contentLengthHeader != null && !/^\d+$/.test(String(contentLengthHeader))) throw Object.assign(new Error("Invalid Content-Length."), { status: 400 });
  if (Number(contentLengthHeader ?? 0) > maxBytes) throw Object.assign(new Error("Request body is too large."), { status: 413 });
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) throw Object.assign(new Error("Request body is too large."), { status: 413 });
    chunks.push(chunk);
  }
  if (!size) throw Object.assign(new Error("Invalid request size."), { status: 400 });
  let payload;
  try {
    payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw Object.assign(new Error("Invalid JSON body."), { status: 400 });
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw Object.assign(new Error("JSON body must be an object."), { status: 400 });
  return payload;
}

function contentTypeIsJson(request) {
  return String(request.headers["content-type"] ?? "").split(";", 1)[0].trim().toLowerCase() === "application/json";
}

function requireJson(request, response) {
  if (contentTypeIsJson(request)) return true;
  sendJson(response, { error: "Content-Type must be application/json." }, 415);
  return false;
}

function parsePositiveId(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function csvCell(value) {
  const text = String(value ?? "");
  const safeText = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return /[",\n\r]/.test(safeText) ? `"${safeText.replaceAll('"', '""')}"` : safeText;
}

function resultToCsv(result) {
  const rows = [["IP address", "Name", "MAC address", "Vendor", "Role", "State", "Evidence", "Open TCP ports", "Host", "Gateway"]];
  for (const device of result?.devices ?? []) {
    rows.push([
      device.ip, device.custom_name || device.hostname || "", device.mac || "", device.vendor || "", device.role?.label || "",
      device.state || "", (device.evidence || []).join("; "), (device.open_ports || []).map((entry) => `${entry.port}/${entry.service || "TCP"}`).join("; "),
      device.is_host ? "yes" : "no", device.is_gateway ? "yes" : "no",
    ]);
  }
  return `${rows.map((row) => row.map(csvCell).join(",")).join("\r\n")}\r\n`;
}

function decorateResult(result, store) {
  if (!result) return null;
  const output = structuredClone(result);
  const profiles = store.listDevices({ limit: 5000 });
  const byIdentity = new Map(profiles.map((device) => [device.identity_key, device]));
  for (const device of output.devices ?? []) {
    const profile = byIdentity.get(identityKeyForDevice(device, output.target));
    if (!profile) continue;
    device.device_id = profile.id;
    device.custom_name = profile.custom_name;
    device.vendor = profile.vendor;
    device.trust_state = profile.trust_state;
    device.tags = profile.tags;
    device.ignored = profile.ignored;
  }
  return output;
}

function sanitizeImportedResult(payload) {
  const candidate = payload?.scan ?? payload?.result ?? payload;
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return candidate;
  const result = structuredClone(candidate);
  for (const key of ["scan_id", "alert_count", "saved", "source", "profile_name", "created_at"]) delete result[key];
  if (Array.isArray(result.devices)) {
    for (const device of result.devices) {
      if (!device || typeof device !== "object" || Array.isArray(device)) continue;
      for (const key of ["device_id", "custom_name", "vendor", "trust_state", "tags", "ignored", "notes"]) delete device[key];
    }
  }
  return result;
}

function availableTargetCidrs(scanner) {
  try {
    const interfaces = typeof scanner.interfaceInventory === "function" ? scanner.interfaceInventory() : [];
    const options = typeof scanner.targetOptions === "function"
      ? scanner.targetOptions(interfaces)
      : typeof scanner.hostInventory === "function" ? scanner.hostInventory(interfaces)?.target_options ?? [] : [];
    return new Set(options.map((option) => option?.cidr).filter(Boolean));
  } catch {
    return new Set();
  }
}


function validationError(message) {
  return Object.assign(new Error(message), { status: 400 });
}

function normalizeProfilePayload(payload) {
  const name = String(payload.name ?? "").trim().slice(0, 60);
  if (!name) throw validationError("Profile name is required.");
  const addressMode = String(payload.address_mode ?? "standard");
  const portMode = String(payload.port_mode ?? "selected");
  if (!["standard", "extended"].includes(addressMode)) throw validationError("Address mode must be standard or extended.");
  if (!["selected", "all"].includes(portMode)) throw validationError("Port mode must be selected or all.");
  let ports;
  try { ports = normalizePorts(Array.isArray(payload.ports) ? payload.ports : [], { limit: 1024 }); }
  catch (error) { throw validationError(error.message); }
  if (portMode === "selected" && !ports.length) throw validationError("Selected-port profiles require at least one TCP port.");
  const timeout = Number(payload.timeout_ms ?? 260);
  if (!Number.isInteger(timeout) || timeout < 50 || timeout > 5000) throw validationError("Timeout must be between 50 and 5000 milliseconds.");
  return { name, address_mode: addressMode, port_mode: portMode, ports, timeout_ms: timeout };
}

function normalizeExclusionPatch(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw validationError("Exclusion update must be an object.");
  const allowed = new Set(["label", "enabled"]);
  for (const key of Object.keys(payload)) if (!allowed.has(key)) throw validationError(`Unsupported exclusion field: ${key}.`);
  const output = {};
  if (Object.hasOwn(payload, "label")) output.label = String(payload.label ?? "").trim().slice(0, 100);
  if (Object.hasOwn(payload, "enabled")) {
    if (typeof payload.enabled !== "boolean") throw validationError("Exclusion enabled must be true or false.");
    output.enabled = payload.enabled;
  }
  if (!Object.keys(output).length) throw validationError("Provide a label or enabled state to update.");
  return output;
}

function normalizeExclusionPayload(payload) {
  const kind = String(payload.kind ?? "");
  let value = String(payload.value ?? "").trim();
  if (kind === "ip") {
    parseIPv4(value);
    if (!isAllowedLocalNetwork(parseIPv4Network(`${value}/32`))) throw validationError("IP exclusions must be private or link-local addresses.");
  } else if (kind === "cidr") {
    const network = parseIPv4Network(value);
    if (!isAllowedLocalNetwork(network)) throw validationError("CIDR exclusions must be private or link-local networks.");
    value = network.cidr;
  } else if (kind === "mac") {
    value = normalizeMac(value);
    if (!value) throw validationError("Enter a valid MAC address.");
  } else throw validationError("Exclusion type must be ip, cidr, or mac.");
  return { kind, value, label: String(payload.label ?? "").trim().slice(0, 100), enabled: payload.enabled !== false };
}

const THEME_NAMES = new Set(["purple", "midnight", "light", "contrast", "custom"]);

function normalizeClockTime(value, fallback) {
  const text = String(value ?? fallback);
  return /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(text) ? text : fallback;
}

function normalizePreferences(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw validationError("Preferences must be an object.");
  const rawSchedule = value.theme_schedule;
  if (rawSchedule == null) return {};
  if (!rawSchedule || typeof rawSchedule !== "object" || Array.isArray(rawSchedule)) throw validationError("Theme schedule must be an object.");
  const day = THEME_NAMES.has(String(rawSchedule.day)) ? String(rawSchedule.day) : "light";
  const night = THEME_NAMES.has(String(rawSchedule.night)) ? String(rawSchedule.night) : "purple";
  return {
    theme_schedule: {
      enabled: rawSchedule.enabled === true,
      day,
      night,
      day_start: normalizeClockTime(rawSchedule.day_start, "07:00"),
      night_start: normalizeClockTime(rawSchedule.night_start, "19:00"),
    },
  };
}

function normalizeAlertPreferences(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw validationError("Alert preferences must be an object.");
  return { browser_notifications: value.browser_notifications === true };
}


const NOTIFICATION_EVENT_STATUSES = new Set(["shown", "permission-granted", "permission-denied", "permission-default", "unsupported", "disabled", "error"]);

function normalizeNotificationEvent(payload) {
  const status = String(payload.status ?? "").trim();
  if (!NOTIFICATION_EVENT_STATUSES.has(status)) throw validationError("Invalid notification history status.");
  const title = String(payload.title ?? "NetScope Lite").trim().slice(0, 120) || "NetScope Lite";
  const message = String(payload.message ?? "").trim().slice(0, 500);
  if (!message) throw validationError("Notification history message is required.");
  const alertId = payload.alert_id == null ? null : parsePositiveId(payload.alert_id);
  if (payload.alert_id != null && !alertId) throw validationError("Notification alert ID must be a positive integer.");
  const rawDetails = payload.details;
  const details = rawDetails && typeof rawDetails === "object" && !Array.isArray(rawDetails) ? rawDetails : {};
  const serializedDetails = JSON.stringify(details);
  if (Buffer.byteLength(serializedDetails, "utf8") > 4096) throw Object.assign(new Error("Notification details are too large."), { status: 413 });
  return { alert_id: alertId, status, title, message, details };
}

function resultWithScanMetadata(scan, store) {
  if (!scan?.result) return null;
  return Object.assign(decorateResult(scan.result, store), {
    scan_id: scan.id,
    source: scan.source ?? null,
    profile_name: scan.profile_name ?? null,
    created_at: scan.created_at ?? null,
  });
}

function normalizeSchedulePayload(payload, store, existing = null, allowedTargets = new Set()) {
  const merged = { ...(existing ?? {}), ...payload };
  const profile = store.getProfile(merged.profile_id);
  if (!profile) throw validationError("Choose a valid scan profile.");
  const name = String(merged.name ?? "").trim().slice(0, 80);
  if (!name) throw validationError("Schedule name is required.");
  const targets = [];
  const seen = new Set();
  for (const value of Array.isArray(merged.targets) ? merged.targets : []) {
    const parsed = parseIPv4Network(String(value).trim());
    if (!isAllowedLocalNetwork(parsed)) throw validationError("Scheduled targets must be private or link-local networks.");
    if (seen.has(parsed.cidr)) continue;
    seen.add(parsed.cidr);
    targets.push(parsed.cidr);
  }
  if (!targets.length || targets.length > 8) throw validationError("Choose between one and eight attached targets.");
  const enabled = merged.enabled !== false;
  const priorTargets = new Set((existing?.targets ?? []).map((value) => {
    try { return parseIPv4Network(value).cidr; } catch { return null; }
  }).filter(Boolean));
  for (const target of targets) {
    const mayPauseDetachedExistingTarget = Boolean(existing) && !enabled && priorTargets.has(target);
    if (!allowedTargets.has(target) && !mayPauseDetachedExistingTarget) throw validationError("Scheduled targets must be attached to this host.");
  }
  const interval = Number(merged.interval_minutes);
  if (!Number.isInteger(interval) || interval < 5 || interval > 10080) throw validationError("Schedule interval must be between 5 minutes and 7 days.");
  const allowIntensive = merged.allow_intensive === true;
  if (profile.port_mode === "all" && enabled && !allowIntensive) throw validationError("Scheduled all-port scans require explicit intensive-scan authorization.");
  return { name, targets, profile_id: profile.id, interval_minutes: interval, enabled, allow_intensive: allowIntensive };
}

function routeMatch(route, pattern) {
  const match = pattern.exec(route);
  return match ? match.slice(1) : null;
}

export function createRequestHandler({
  scanner = scannerModule,
  store = new MemoryStore(),
  state = { scanRunning: false },
  logger = console,
  scanManager = new ScanManager({ scanner, store, state, logger }),
  authManager = new AuthManager({ store }),
  wakeFn = sendWakeOnLan,
  allowedHosts = requestAllowedHosts(),
} = {}) {
  return async function handleRequest(request, response) {
    applySecurityHeaders(response);
    if (!hostIsAllowed(request, allowedHosts)) return sendJson(response, { error: "Invalid Host header." }, 400);
    try {
      let requestUrl;
      try {
        requestUrl = new URL(request.url ?? "/", "http://localhost");
      } catch {
        return sendJson(response, { error: "Invalid request URL." }, 400);
      }
      const route = requestUrl.pathname;
      const method = request.method === "HEAD" ? "GET" : request.method;

      if (method === "GET" && route === "/") return sendFile(response, path.join(STATIC_ROOT, "index.html"));
      if (method === "GET" && route === "/healthz") return sendJson(response, { status: "ok" });
      if (method === "GET" && route.startsWith("/static/")) return sendFile(response, staticFilePath(route));

      if (method === "GET" && route === "/api/auth/status") return sendJson(response, authManager.status(request));
      if (method === "POST" && route === "/api/auth/login") {
        if (!requireJson(request, response)) return;
        const payload = await readJsonBody(request);
        const result = await authManager.login(payload.password);
        return sendJson(response, { authenticated: true }, 200, { cookie: result.cookie });
      }
      if (method === "POST" && route === "/api/auth/logout") {
        const result = authManager.logout(request);
        return sendJson(response, { authenticated: false }, 200, { cookie: result.cookie });
      }

      if (!authManager.sessionFor(request).authenticated) return sendJson(response, { error: "Authentication required.", authentication_required: true }, 401);

      if (method === "POST" && route === "/api/auth/password") {
        if (!requireJson(request, response)) return;
        const payload = await readJsonBody(request);
        const result = await authManager.setPassword({ currentPassword: payload.current_password, newPassword: payload.new_password });
        return sendJson(response, result, 200, { cookie: authManager.clearCookie() });
      }

      if (method === "GET" && route === "/api/scan-state") return sendJson(response, scanManager.getState());
      if (method === "GET" && route === "/api/monitor") return sendJson(response, { monitor: store.dashboardSummary() });
      if (method === "GET" && route === "/api/status") {
        const interfaces = scanner.interfaceInventory();
        const latestScan = store.getLatestScan();
        return sendJson(response, {
          host: scanner.hostInventory(interfaces),
          latest: resultWithScanMetadata(latestScan, store),
          default_ports: scanner.DEFAULT_PORTS,
          port_names: scanner.PORT_NAMES,
          target_options: typeof scanner.targetOptions === "function" ? scanner.targetOptions(interfaces) : scanner.hostInventory(interfaces)?.target_options ?? [],
          scan_running: scanManager.getState().scan_running,
          progress: scanManager.getState().progress,
          profiles: store.listProfiles(),
          monitor: store.dashboardSummary(),
          settings: {
            preferences: store.getSetting("ui.preferences", {}),
            alert_preferences: store.getSetting("alerts.preferences", { browser_notifications: false }),
          },
          auth: authManager.status(request),
        });
      }

      if (method === "POST" && route === "/api/scan/cancel") return sendJson(response, scanManager.cancel(), 202);
      if (method === "POST" && route === "/api/scan") {
        if (!requireJson(request, response)) return;
        const payload = await readJsonBody(request);
        const result = await scanManager.run(payload, { source: "live" });
        if (result.batch) result.results = result.results.map((entry) => decorateResult(entry, store));
        else Object.assign(result, decorateResult(result, store));
        return sendJson(response, result);
      }

      if (method === "GET" && route === "/api/export") {
        const format = String(requestUrl.searchParams.get("format") ?? "json").toLowerCase();
        const scanId = parsePositiveId(requestUrl.searchParams.get("scan_id"));
        const scan = scanId ? store.getScan(scanId) : store.getLatestScan();
        if (!scan?.result) return sendJson(response, { error: "No completed scan is available." }, 404);
        const result = decorateResult(scan.result, store);
        if (format === "csv") {
          return sendBuffer(response, Buffer.from(resultToCsv(result), "utf8"), { contentType: "text/csv; charset=utf-8", contentDisposition: `attachment; filename="netscope-${scan.id}.csv"` });
        }
        if (format !== "json") return sendJson(response, { error: "Export format must be json or csv." }, 400);
        return sendJson(response, result, 200, { pretty: true, contentDisposition: `attachment; filename="netscope-${scan.id}.json"` });
      }

      if (method === "GET" && route === "/api/history") {
        return sendJson(response, { scans: store.listHistory({ limit: requestUrl.searchParams.get("limit"), target: requestUrl.searchParams.get("target") }) });
      }
      if (method === "POST" && route === "/api/history/import") {
        if (!requireJson(request, response)) return;
        const payload = await readJsonBody(request, MAX_IMPORT_BYTES);
        const result = sanitizeImportedResult(payload);
        const validateResult = typeof scanner.isValidResult === "function" ? scanner.isValidResult : scannerModule.isValidResult;
        if (!validateResult(result)) return sendJson(response, { error: "The imported file is not a valid NetScope scan result." }, 400);
        const stored = store.importScan(result);
        return sendJson(response, { imported: true, scan_id: stored.scan_id }, 201);
      }
      if (method === "GET" && route === "/api/history/compare") {
        const left = parsePositiveId(requestUrl.searchParams.get("left"));
        const right = parsePositiveId(requestUrl.searchParams.get("right"));
        if (!left || !right || left === right) return sendJson(response, { error: "Choose two different history entries." }, 400);
        const comparison = store.compareScans(left, right);
        return comparison ? sendJson(response, comparison) : sendJson(response, { error: "History entry not found." }, 404);
      }
      const historyMatch = routeMatch(route, /^\/api\/history\/(\d+)$/);
      if (historyMatch && method === "GET") {
        const scan = store.getScan(historyMatch[0]);
        return scan ? sendJson(response, { ...scan, result: resultWithScanMetadata(scan, store) }) : sendJson(response, { error: "History entry not found." }, 404);
      }
      if (historyMatch && method === "DELETE") return store.deleteScan(historyMatch[0]) ? sendJson(response, { deleted: true }) : sendJson(response, { error: "History entry not found." }, 404);

      if (method === "GET" && route === "/api/devices") {
        return sendJson(response, { devices: store.listDevices({ query: requestUrl.searchParams.get("query") ?? "", trustState: requestUrl.searchParams.get("trust") ?? "", limit: requestUrl.searchParams.get("limit") }) });
      }
      const deviceWakeMatch = routeMatch(route, /^\/api\/devices\/(\d+)\/wake$/);
      if (deviceWakeMatch && method === "POST") {
        const device = store.getDevice(deviceWakeMatch[0]);
        if (!device) return sendJson(response, { error: "Device not found." }, 404);
        const interfaces = scanner.interfaceInventory();
        return sendJson(response, await wakeFn(device.mac, { interfaces }), 202);
      }
      const deviceMatch = routeMatch(route, /^\/api\/devices\/(\d+)$/);
      if (deviceMatch && method === "GET") {
        const device = store.getDevice(deviceMatch[0]);
        return device ? sendJson(response, device) : sendJson(response, { error: "Device not found." }, 404);
      }
      if (deviceMatch && method === "PATCH") {
        if (!requireJson(request, response)) return;
        const device = store.updateDevice(deviceMatch[0], await readJsonBody(request));
        return device ? sendJson(response, device) : sendJson(response, { error: "Device not found." }, 404);
      }

      if (method === "GET" && route === "/api/alerts") {
        const unacknowledged = requestUrl.searchParams.get("acknowledged");
        const acknowledged = unacknowledged == null ? null : unacknowledged === "true";
        return sendJson(response, { alerts: store.listAlerts({ acknowledged, limit: requestUrl.searchParams.get("limit") }) });
      }
      if (method === "POST" && route === "/api/alerts/acknowledge-all") return sendJson(response, { acknowledged: store.acknowledgeAllAlerts() });
      const alertMatch = routeMatch(route, /^\/api\/alerts\/(\d+)\/acknowledge$/);
      if (alertMatch && method === "POST") {
        if (!requireJson(request, response)) return;
        const payload = await readJsonBody(request);
        return store.acknowledgeAlert(alertMatch[0], payload.acknowledged !== false) ? sendJson(response, { updated: true }) : sendJson(response, { error: "Alert not found." }, 404);
      }


      if (method === "GET" && route === "/api/notifications/history") {
        return sendJson(response, { notifications: store.listNotificationEvents({ limit: requestUrl.searchParams.get("limit") }) });
      }
      if (method === "POST" && route === "/api/notifications/history") {
        if (!requireJson(request, response)) return;
        return sendJson(response, store.addNotificationEvent(normalizeNotificationEvent(await readJsonBody(request))), 201);
      }
      if (method === "DELETE" && route === "/api/notifications/history") {
        return sendJson(response, { deleted: store.clearNotificationEvents() });
      }

      if (method === "GET" && route === "/api/profiles") return sendJson(response, { profiles: store.listProfiles() });
      if (method === "POST" && route === "/api/profiles") {
        if (!requireJson(request, response)) return;
        return sendJson(response, store.saveProfile(normalizeProfilePayload(await readJsonBody(request))), 201);
      }
      const profileMatch = routeMatch(route, /^\/api\/profiles\/(\d+)$/);
      if (profileMatch && method === "PATCH") {
        if (!requireJson(request, response)) return;
        const profile = store.saveProfile(normalizeProfilePayload(await readJsonBody(request)), profileMatch[0]);
        return profile ? sendJson(response, profile) : sendJson(response, { error: "Profile not found." }, 404);
      }
      if (profileMatch && method === "DELETE") return store.deleteProfile(profileMatch[0]) ? sendJson(response, { deleted: true }) : sendJson(response, { error: "Profile not found." }, 404);

      if (method === "GET" && route === "/api/schedules") return sendJson(response, { schedules: store.listSchedules() });
      if (method === "POST" && route === "/api/schedules") {
        if (!requireJson(request, response)) return;
        const payload = normalizeSchedulePayload(await readJsonBody(request), store, null, availableTargetCidrs(scanner));
        return sendJson(response, store.saveSchedule(payload), 201);
      }
      const scheduleMatch = routeMatch(route, /^\/api\/schedules\/(\d+)$/);
      if (scheduleMatch && method === "PATCH") {
        if (!requireJson(request, response)) return;
        const existing = store.getSchedule(scheduleMatch[0]);
        if (!existing) return sendJson(response, { error: "Schedule not found." }, 404);
        const schedule = store.saveSchedule(normalizeSchedulePayload(await readJsonBody(request), store, existing, availableTargetCidrs(scanner)), scheduleMatch[0]);
        return schedule ? sendJson(response, schedule) : sendJson(response, { error: "Schedule not found." }, 404);
      }
      if (scheduleMatch && method === "DELETE") return store.deleteSchedule(scheduleMatch[0]) ? sendJson(response, { deleted: true }) : sendJson(response, { error: "Schedule not found." }, 404);

      if (method === "GET" && route === "/api/exclusions") return sendJson(response, { exclusions: store.listExclusions() });
      if (method === "POST" && route === "/api/exclusions") {
        if (!requireJson(request, response)) return;
        return sendJson(response, store.saveExclusion(normalizeExclusionPayload(await readJsonBody(request))), 201);
      }
      const exclusionMatch = routeMatch(route, /^\/api\/exclusions\/(\d+)$/);
      if (exclusionMatch && method === "PATCH") {
        if (!requireJson(request, response)) return;
        const exclusion = store.updateExclusion(exclusionMatch[0], normalizeExclusionPatch(await readJsonBody(request)));
        return exclusion ? sendJson(response, exclusion) : sendJson(response, { error: "Exclusion not found." }, 404);
      }
      if (exclusionMatch && method === "DELETE") return store.deleteExclusion(exclusionMatch[0]) ? sendJson(response, { deleted: true }) : sendJson(response, { error: "Exclusion not found." }, 404);

      if (method === "GET" && route === "/api/settings") {
        return sendJson(response, { preferences: store.getSetting("ui.preferences", {}), alert_preferences: store.getSetting("alerts.preferences", { browser_notifications: false }) });
      }
      if (method === "PUT" && route === "/api/settings") {
        if (!requireJson(request, response)) return;
        const payload = await readJsonBody(request);
        if (Object.hasOwn(payload, "preferences")) store.setSetting("ui.preferences", normalizePreferences(payload.preferences));
        if (Object.hasOwn(payload, "alert_preferences")) store.setSetting("alerts.preferences", normalizeAlertPreferences(payload.alert_preferences));
        return sendJson(response, { saved: true });
      }

      return sendText(response, "Not found", 404);
    } catch (error) {
      if (error?.name === "AbortError") return sendJson(response, { error: error.message || "Scan cancelled." }, 409);
      if (error instanceof TargetRejected) return sendJson(response, { error: error.message }, 400);
      if (Number.isInteger(error?.status) && error.status >= 400 && error.status < 500) return sendJson(response, { error: error.message }, error.status);
      logger.error?.(error);
      return sendJson(response, { error: "The request failed because of an unexpected local system error." }, 500);
    }
  };
}

export function createServer(options = {}) {
  const handler = createRequestHandler(options);
  const server = http.createServer((request, response) => {
    Promise.resolve(handler(request, response)).catch((error) => {
      options.logger?.error?.(error);
      if (!response.headersSent) {
        applySecurityHeaders(response);
        sendJson(response, { error: "Unexpected server error." }, 500);
      } else response.destroy();
    });
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 64;
  return server;
}

function parseArguments(argv) {
  const result = { host: process.env.NETSCOPE_HOST ?? "127.0.0.1", port: Number(process.env.NETSCOPE_PORT ?? 8787), open: false };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--host") {
      if (index + 1 >= argv.length) throw new Error("--host requires a value.");
      result.host = argv[++index];
    } else if (argv[index] === "--port") {
      if (index + 1 >= argv.length) throw new Error("--port requires a value.");
      result.port = Number(argv[++index]);
    } else if (argv[index] === "--open") result.open = true;
    else if (argv[index] === "--help" || argv[index] === "-h") result.help = true;
    else throw new Error(`Unknown argument: ${argv[index]}`);
  }
  result.host = String(result.host).trim().toLowerCase();
  if (result.host === "localhost") result.host = "127.0.0.1";
  if (!Number.isInteger(result.port) || result.port < 0 || result.port > 65535) throw new Error("Port must be between 0 and 65535.");
  const explicitlyAllowedNonLoopbackBind = result.host === "0.0.0.0" && process.env.NETSCOPE_ALLOW_NON_LOOPBACK === "1";
  if (!LOOPBACK_HOSTS.has(result.host) && !explicitlyAllowedNonLoopbackBind) {
    throw new Error("NetScope Lite only binds to loopback unless NETSCOPE_ALLOW_NON_LOOPBACK=1 explicitly permits a 0.0.0.0 bind.");
  }
  return result;
}

function openBrowser(url) {
  const command = process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : process.platform === "darwin" ? ["open", [url]] : ["xdg-open", [url]];
  execFile(command[0], command[1], { windowsHide: true }, () => {});
}

async function main() {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 2;
    return;
  }
  if (options.help) {
    console.log("Usage: node server.js [--host 127.0.0.1] [--port 8787] [--open]\nContainer LAN bind: NETSCOPE_ALLOW_NON_LOOPBACK=1 node server.js --host 0.0.0.0");
    return;
  }
  let store;
  try {
    const { SqliteStore } = await import("./src/db/store.js");
    store = new SqliteStore({ databasePath: defaultDatabasePath(), legacyDataPath: defaultLegacyDataPath() });
  } catch (error) {
    console.error("Unable to start the SQLite data store. Run npm install and verify that better-sqlite3 can load on this Node.js installation.");
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
    return;
  }
  const state = { scanRunning: false };
  const scanManager = new ScanManager({ scanner: scannerModule, store, state });
  const authManager = new AuthManager({ store });
  const scheduler = new ScanScheduler({ store, scanManager });
  const server = createServer({ scanner: scannerModule, store, state, scanManager, authManager });
  server.on("close", () => {
    scheduler.stop();
    store.close();
  });
  server.listen(options.port, options.host, () => {
    scheduler.start();
    const address = server.address();
    const host = options.host === "::1" ? "[::1]" : options.host;
    const url = `http://${host}:${address.port}`;
    console.log(`NetScope Lite is running at ${url}`);
    console.log("Press Ctrl+C to stop.");
    if (options.open) openBrowser(url);
  });
  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    scheduler.stop();
    if (scanManager.getState().scan_running) {
      try { scanManager.cancel(); } catch { /* Scan already settled. */ }
    }
    const forceTimer = setTimeout(() => {
      server.closeAllConnections?.();
      process.exit(0);
    }, 2_000);
    forceTimer.unref?.();
    server.close(() => {
      clearTimeout(forceTimer);
      process.exit(0);
    });
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
