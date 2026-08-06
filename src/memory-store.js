import { compareResults, MAX_SAVED_RESULT_BYTES } from "./scanner.js";
import { identityKeyForDevice, vendorFromMac } from "./identity.js";
import { builtInProfilesForApi } from "./profiles.js";

function clone(value) {
  return value == null ? value : structuredClone(value);
}

const SENSITIVE_PORTS = new Map([
  [21, "FTP"], [23, "Telnet"], [25, "SMTP"], [110, "POP3"], [139, "NetBIOS"], [445, "SMB"],
  [1433, "SQL Server"], [1521, "Oracle"], [2375, "Docker API"], [3306, "MySQL"], [3389, "RDP"],
  [5432, "PostgreSQL"], [5900, "VNC"], [6379, "Redis"], [9200, "Elasticsearch"], [27017, "MongoDB"],
]);

function alertsForResult(result, previous, devicesByIp, nextId) {
  if (!previous) return [];
  const changes = compareResults(result, previous);
  const generated = [];
  const add = (ip, kind, severity, title, message, details = {}) => {
    const persistent = ip ? devicesByIp.get(ip) : null;
    if (persistent?.ignored) return;
    generated.push({ id: nextId(), scan_id: null, device_id: persistent?.id ?? null, kind, severity, title, message, details, acknowledged: false, created_at: result.generated_at });
  };
  for (const item of changes.new_devices ?? []) add(item.ip, "new-device", "medium", "New device observed", `${item.hostname || item.ip} appeared on ${result.target}.`, item);
  for (const item of changes.missing_devices ?? []) add(item.ip, "missing-device", "low", "Device no longer observed", `${item.hostname || item.ip} was not observed on the latest scan.`, item);
  for (const item of changes.changed_services ?? []) add(item.ip, "service-change", "medium", "Service exposure changed", `${item.hostname || item.ip} changed its observed TCP services.`, item);
  const before = new Map((previous.devices ?? []).map((device) => [device.ip, new Set((device.open_ports ?? []).map((entry) => entry.port))]));
  for (const device of result.devices ?? []) for (const entry of device.open_ports ?? []) {
    if (SENSITIVE_PORTS.has(entry.port) && !before.get(device.ip)?.has(entry.port)) add(device.ip, "sensitive-port", [23, 2375, 6379, 9200, 27017].includes(entry.port) ? "high" : "medium", `${SENSITIVE_PORTS.get(entry.port)} became visible`, `${device.hostname || device.ip} now exposes TCP port ${entry.port}.`, entry);
  }
  if (previous.network?.gateway !== result.network?.gateway) add(null, "gateway-change", "high", "Default gateway changed", `Gateway changed from ${previous.network?.gateway || "none"} to ${result.network?.gateway || "none"}.`);
  if (JSON.stringify([...(previous.network?.dns_servers ?? [])].sort()) !== JSON.stringify([...(result.network?.dns_servers ?? [])].sort())) add(null, "dns-change", "high", "DNS resolvers changed", "The host is using a different DNS resolver set.");
  return generated;
}

function newestFirst(scans) {
  return [...scans].sort((left, right) => Date.parse(right.generated_at) - Date.parse(left.generated_at) || right.id - left.id);
}

export class MemoryStore {
  constructor() {
    this.scans = [];
    this.devices = [];
    this.alerts = [];
    this.notificationEvents = [];
    this.profiles = builtInProfilesForApi();
    this.schedules = [];
    this.exclusions = [];
    this.settings = new Map();
    this.nextIds = { scan: 1, device: 1, alert: 1, notification: 1, profile: 5, schedule: 1, exclusion: 1 };
  }

  close() {}

  getLatestResult(target = null) {
    return clone(newestFirst(this.scans.filter((scan) => !target || scan.target === target))[0]?.result ?? null);
  }

  getLatestScan(target = null) {
    return clone(newestFirst(this.scans.filter((scan) => !target || scan.target === target))[0] ?? null);
  }

  getScan(id) {
    return clone(this.scans.find((scan) => scan.id === Number(id)) ?? null);
  }

  listHistory({ limit = 50, target = null } = {}) {
    const safeLimit = Math.max(1, Math.min(250, Number(limit) || 50));
    return clone(newestFirst(this.scans.filter((scan) => !target || scan.target === target)).slice(0, safeLimit).map(({ result, ...scan }) => scan));
  }

  deleteScan(id) {
    const index = this.scans.findIndex((scan) => scan.id === Number(id));
    if (index < 0) return false;
    this.scans.splice(index, 1);
    return true;
  }

  saveScan(result, { source = "live", profileName = null, skipAlerts = false } = {}) {
    if (!result || typeof result !== "object" || !Array.isArray(result.devices)) throw Object.assign(new Error("Refusing to store an invalid scan result."), { status: 400 });
    if (Buffer.byteLength(JSON.stringify(result), "utf8") > MAX_SAVED_RESULT_BYTES) throw Object.assign(new Error("Scan result is too large to save."), { status: 413 });
    const previous = this.getLatestResult(result.target);
    const scan = {
      id: this.nextIds.scan++,
      generated_at: result.generated_at,
      target: result.target,
      source,
      profile_name: profileName,
      duration_seconds: result.duration_seconds || 0,
      device_count: result.summary?.device_count ?? result.devices?.length ?? 0,
      summary: clone(result.summary ?? {}),
      result: clone(result),
      created_at: new Date().toISOString(),
    };
    this.scans.unshift(scan);
    const deviceIds = {};
    for (const observed of result.devices ?? []) {
      const key = identityKeyForDevice(observed, result.target);
      let device = this.devices.find((entry) => entry.identity_key === key);
      if (!device) {
        device = {
          id: this.nextIds.device++, identity_key: key, mac: observed.mac || null, last_ip: observed.ip,
          hostname: observed.hostname || null, vendor: vendorFromMac(observed.mac), role_key: observed.role?.key || null,
          role_label: observed.role?.label || null, custom_name: null, notes: "", trust_state: observed.is_gateway ? "infrastructure" : "unknown",
          tags: [], ignored: false, first_seen_at: result.generated_at, last_seen_at: result.generated_at,
          created_at: scan.created_at, updated_at: scan.created_at, observations: [],
        };
        this.devices.push(device);
      }
      device.last_ip = observed.ip;
      device.hostname = observed.hostname || device.hostname;
      device.last_seen_at = result.generated_at;
      device.observations.unshift({ ...clone(observed), scan_id: scan.id, created_at: result.generated_at });
      deviceIds[observed.ip] = device.id;
    }
    const devicesByIp = new Map((result.devices ?? []).map((entry) => [entry.ip, this.devices.find((device) => device.id === deviceIds[entry.ip])]));
    for (const previousDevice of previous?.devices ?? []) {
      if (devicesByIp.has(previousDevice.ip)) continue;
      const identityKey = identityKeyForDevice(previousDevice, result.target);
      const persistent = this.devices.find((device) => device.identity_key === identityKey);
      if (persistent) devicesByIp.set(previousDevice.ip, persistent);
    }
    const generated = skipAlerts ? [] : alertsForResult(result, previous, devicesByIp, () => this.nextIds.alert++);
    for (const alert of generated) { alert.scan_id = scan.id; this.alerts.unshift(alert); }
    return { scan_id: scan.id, alert_count: generated.length, device_ids: deviceIds };
  }

  importScan(result) {
    return this.saveScan(result, { source: "imported", skipAlerts: true });
  }

  compareScans(leftId, rightId) {
    const left = this.getScan(leftId);
    const right = this.getScan(rightId);
    if (!left || !right) return null;
    const [before, after] = Date.parse(left.generated_at) <= Date.parse(right.generated_at) ? [left, right] : [right, left];
    return { left: before, right: after, changes: compareResults(after.result, before.result) };
  }

  listDevices({ query = "", trustState = "", limit = 250 } = {}) {
    const safeLimit = Math.max(1, Math.min(5000, Number(limit) || 250));
    const needle = String(query || "").toLowerCase();
    return clone(this.devices.filter((device) => {
      if (trustState && device.trust_state !== trustState) return false;
      if (!needle) return true;
      return [device.custom_name, device.hostname, device.last_ip, device.mac, device.vendor, ...device.tags].some((value) => String(value ?? "").toLowerCase().includes(needle));
    }).slice(0, safeLimit).map(({ observations, ...device }) => device));
  }

  getDevice(id) {
    return clone(this.devices.find((device) => device.id === Number(id)) ?? null);
  }

  updateDevice(id, patch) {
    const device = this.devices.find((entry) => entry.id === Number(id));
    if (!device) return null;
    if (Object.hasOwn(patch, "custom_name")) device.custom_name = String(patch.custom_name || "").trim().slice(0, 80) || null;
    if (Object.hasOwn(patch, "notes")) device.notes = String(patch.notes || "").slice(0, 4000);
    if (Object.hasOwn(patch, "trust_state")) {
      const value = String(patch.trust_state);
      if (!["unknown", "trusted", "guest", "infrastructure", "review"].includes(value)) throw Object.assign(new Error("Invalid device trust state."), { status: 400 });
      device.trust_state = value;
    }
    if (Object.hasOwn(patch, "tags")) {
      if (!Array.isArray(patch.tags)) throw Object.assign(new Error("Tags must be a list."), { status: 400 });
      device.tags = [...new Set(patch.tags.map((tag) => String(tag).trim().slice(0, 32)).filter(Boolean))].slice(0, 12);
    }
    if (Object.hasOwn(patch, "ignored")) device.ignored = patch.ignored === true;
    device.updated_at = new Date().toISOString();
    return clone(device);
  }

  listAlerts({ limit = 100, acknowledged = null } = {}) {
    const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));
    return clone(this.alerts.filter((alert) => acknowledged == null || alert.acknowledged === acknowledged).slice(0, safeLimit));
  }

  acknowledgeAlert(id, acknowledged = true) {
    const alert = this.alerts.find((entry) => entry.id === Number(id));
    if (!alert) return false;
    alert.acknowledged = acknowledged;
    return true;
  }

  acknowledgeAllAlerts() {
    let count = 0;
    for (const alert of this.alerts) if (!alert.acknowledged) { alert.acknowledged = true; count += 1; }
    return count;
  }


  listNotificationEvents({ limit = 100 } = {}) {
    const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));
    return clone(this.notificationEvents.slice(0, safeLimit));
  }

  addNotificationEvent(payload) {
    const event = {
      id: this.nextIds.notification++,
      alert_id: payload.alert_id ?? null,
      status: payload.status,
      title: payload.title,
      message: payload.message,
      details: clone(payload.details ?? {}),
      created_at: payload.created_at ?? new Date().toISOString(),
    };
    this.notificationEvents.unshift(event);
    return clone(event);
  }

  clearNotificationEvents() {
    const count = this.notificationEvents.length;
    this.notificationEvents = [];
    return count;
  }

  listProfiles() { return clone(this.profiles); }
  getProfile(id) { return clone(this.profiles.find((profile) => profile.id === Number(id)) ?? null); }
  saveProfile(payload, id = null) {
    const duplicate = this.profiles.find((entry) => entry.name.toLowerCase() === String(payload.name ?? "").toLowerCase() && entry.id !== Number(id));
    if (duplicate) throw Object.assign(new Error("A scan profile with this name already exists."), { status: 409 });
    if (id != null) {
      const profile = this.profiles.find((entry) => entry.id === Number(id));
      if (!profile) return null;
      if (profile.built_in) throw Object.assign(new Error("Built-in profiles cannot be modified."), { status: 409 });
      Object.assign(profile, payload);
      return clone(profile);
    }
    const profile = { id: this.nextIds.profile++, built_in: false, ...clone(payload) };
    this.profiles.push(profile);
    return clone(profile);
  }
  deleteProfile(id) {
    const index = this.profiles.findIndex((profile) => profile.id === Number(id) && !profile.built_in);
    if (index < 0) return false;
    if (this.schedules.some((schedule) => schedule.profile_id === Number(id))) throw Object.assign(new Error("Delete or change schedules that use this profile first."), { status: 409 });
    this.profiles.splice(index, 1);
    return true;
  }

  listSchedules() { return clone(this.schedules); }
  getSchedule(id) { return clone(this.schedules.find((schedule) => schedule.id === Number(id)) ?? null); }
  saveSchedule(payload, id = null) {
    if (id != null) {
      const schedule = this.schedules.find((entry) => entry.id === Number(id));
      if (!schedule) return null;
      Object.assign(schedule, clone(payload));
      return clone(schedule);
    }
    const schedule = { id: this.nextIds.schedule++, enabled: true, next_run_at: new Date(Date.now() + payload.interval_minutes * 60000).toISOString(), ...clone(payload) };
    this.schedules.push(schedule);
    return clone(schedule);
  }
  deleteSchedule(id) {
    const index = this.schedules.findIndex((schedule) => schedule.id === Number(id));
    if (index < 0) return false;
    this.schedules.splice(index, 1);
    return true;
  }
  dueSchedules(at = new Date().toISOString()) { return clone(this.schedules.filter((schedule) => schedule.enabled && schedule.next_run_at <= at)); }
  markScheduleRun(id, { status = "complete", ranAt = new Date().toISOString() } = {}) {
    const schedule = this.schedules.find((entry) => entry.id === Number(id));
    if (!schedule) return null;
    schedule.last_run_at = ranAt;
    schedule.last_status = status;
    schedule.next_run_at = new Date(Date.parse(ranAt) + schedule.interval_minutes * 60000).toISOString();
    return clone(schedule);
  }

  listExclusions() { return clone(this.exclusions); }
  saveExclusion(payload) { if (this.exclusions.some((entry) => entry.kind === payload.kind && entry.value === payload.value)) throw Object.assign(new Error("This exclusion already exists."), { status: 409 }); const entry = { id: this.nextIds.exclusion++, enabled: true, ...clone(payload) }; this.exclusions.push(entry); return clone(entry); }
  updateExclusion(id, payload) { const entry = this.exclusions.find((item) => item.id === Number(id)); if (!entry) return null; Object.assign(entry, clone(payload)); return clone(entry); }
  deleteExclusion(id) { const index = this.exclusions.findIndex((entry) => entry.id === Number(id)); if (index < 0) return false; this.exclusions.splice(index, 1); return true; }

  getSetting(key, fallback = null) { return clone(this.settings.has(key) ? this.settings.get(key) : fallback); }
  setSetting(key, value) { this.settings.set(key, clone(value)); return clone(value); }

  dashboardSummary() {
    const unacknowledged = this.alerts.filter((alert) => !alert.acknowledged);
    return { history_count: this.scans.length, known_device_count: this.devices.length, unacknowledged_alert_count: unacknowledged.length, latest_unacknowledged_alert_id: unacknowledged.reduce((latest, alert) => Math.max(latest, Number(alert.id) || 0), 0) || null, active_schedule_count: this.schedules.filter((schedule) => schedule.enabled).length };
  }
}
