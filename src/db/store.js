import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { and, desc, eq, inArray, like, lte, or, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { compareResults, isValidResult, MAX_SAVED_RESULT_BYTES } from "../scanner.js";
import { identityKeyForDevice, normalizeMac, vendorFromMac } from "../identity.js";
import { BUILT_IN_PROFILES } from "../profiles.js";
import { applyMigrations } from "./migrations.js";
import { alerts, devices, exclusions, notificationEvents, observations, scanProfiles, scans, schedules, settings } from "./schema.js";

const SENSITIVE_PORTS = new Map([
  [21, "FTP"], [23, "Telnet"], [25, "SMTP"], [110, "POP3"], [139, "NetBIOS"], [445, "SMB"],
  [1433, "SQL Server"], [1521, "Oracle"], [2375, "Docker API"], [3306, "MySQL"], [3389, "RDP"],
  [5432, "PostgreSQL"], [5900, "VNC"], [6379, "Redis"], [9200, "Elasticsearch"], [27017, "MongoDB"],
]);

function nowIso() {
  return new Date().toISOString();
}

function parseJson(value, fallback) {
  try {
    const parsed = JSON.parse(value);
    return parsed == null ? fallback : parsed;
  } catch {
    return fallback;
  }
}

function json(value) {
  return JSON.stringify(value ?? null);
}

function sqliteConflict(error, message) {
  if (String(error?.code ?? "").startsWith("SQLITE_CONSTRAINT")) {
    return Object.assign(new Error(message), { status: 409 });
  }
  return error;
}

function rowToScan(row, { includeResult = true } = {}) {
  if (!row) return null;
  const base = {
    id: row.id,
    generated_at: row.generatedAt,
    target: row.target,
    source: row.source,
    profile_name: row.profileName,
    duration_seconds: row.durationSeconds,
    device_count: row.deviceCount,
    summary: parseJson(row.summaryJson, {}),
    created_at: row.createdAt,
  };
  if (includeResult) base.result = parseJson(row.resultJson, null);
  return base;
}

function rowToDevice(row) {
  if (!row) return null;
  return {
    id: row.id,
    identity_key: row.identityKey,
    mac: row.mac,
    last_ip: row.lastIp,
    hostname: row.hostname,
    vendor: row.vendor,
    role_key: row.roleKey,
    role_label: row.roleLabel,
    custom_name: row.customName,
    notes: row.notes,
    trust_state: row.trustState,
    tags: parseJson(row.tagsJson, []),
    ignored: Boolean(row.ignored),
    first_seen_at: row.firstSeenAt,
    last_seen_at: row.lastSeenAt,
    created_at: row.createdAt,
    updated_at: row.updatedAt,
  };
}

function rowToAlert(row) {
  return {
    id: row.id,
    scan_id: row.scanId,
    device_id: row.deviceId,
    kind: row.kind,
    severity: row.severity,
    title: row.title,
    message: row.message,
    details: parseJson(row.detailsJson, {}),
    acknowledged: Boolean(row.acknowledged),
    created_at: row.createdAt,
  };
}


function rowToNotificationEvent(row) {
  return {
    id: row.id,
    alert_id: row.alertId,
    status: row.status,
    title: row.title,
    message: row.message,
    details: parseJson(row.detailsJson, {}),
    created_at: row.createdAt,
  };
}

function rowToProfile(row) {
  return {
    id: row.id,
    name: row.name,
    built_in: Boolean(row.builtIn),
    address_mode: row.addressMode,
    port_mode: row.portMode,
    ports: parseJson(row.portsJson, []),
    timeout_ms: row.timeoutMs,
    created_at: row.createdAt,
    updated_at: row.updatedAt,
  };
}

function rowToSchedule(row) {
  return {
    id: row.id,
    name: row.name,
    enabled: Boolean(row.enabled),
    targets: parseJson(row.targetsJson, []),
    profile_id: row.profileId,
    allow_intensive: Boolean(row.allowIntensive),
    interval_minutes: row.intervalMinutes,
    next_run_at: row.nextRunAt,
    last_run_at: row.lastRunAt,
    last_status: row.lastStatus,
    created_at: row.createdAt,
    updated_at: row.updatedAt,
  };
}

function validateTrustState(value) {
  const trustState = String(value ?? "unknown");
  if (!["unknown", "trusted", "guest", "infrastructure", "review"].includes(trustState)) {
    throw Object.assign(new Error("Invalid device trust state."), { status: 400 });
  }
  return trustState;
}

function normalizeTags(value) {
  if (!Array.isArray(value)) throw Object.assign(new Error("Tags must be a list."), { status: 400 });
  const result = [];
  const seen = new Set();
  for (const item of value) {
    const tag = String(item ?? "").trim().slice(0, 32);
    if (!tag || seen.has(tag.toLowerCase())) continue;
    seen.add(tag.toLowerCase());
    result.push(tag);
    if (result.length >= 12) break;
  }
  return result;
}

function scanDeviceByIp(result, ip) {
  return result?.devices?.find((device) => device.ip === ip) ?? null;
}

function openPortSet(device) {
  return new Set((device?.open_ports ?? []).map((entry) => Number(entry.port)).filter(Number.isInteger));
}

function alertsForScan(result, previous, deviceMap) {
  if (!previous) return [];
  const generatedAt = result.generated_at || nowIso();
  const output = [];
  const changes = compareResults(result, previous);
  const add = ({ ip = null, kind, severity, title, message, details = {} }) => {
    const persistent = ip ? deviceMap.get(ip) : null;
    if (persistent?.ignored) return;
    output.push({
      scanId: null,
      deviceId: persistent?.id ?? null,
      kind,
      severity,
      title,
      message,
      detailsJson: json(details),
      acknowledged: false,
      createdAt: generatedAt,
    });
  };

  if (changes.comparable) {
    for (const item of changes.new_devices ?? []) {
      add({ ip: item.ip, kind: "new-device", severity: "medium", title: "New device observed", message: `${item.hostname || item.ip} appeared on ${result.target}.`, details: item });
    }
    for (const item of changes.missing_devices ?? []) {
      add({ ip: item.ip, kind: "missing-device", severity: "low", title: "Device no longer observed", message: `${item.hostname || item.ip} was not observed on the latest scan.`, details: item });
    }
    for (const item of changes.changed_services ?? []) {
      add({ ip: item.ip, kind: "service-change", severity: "medium", title: "Service exposure changed", message: `${item.hostname || item.ip} changed its observed TCP services.`, details: item });
    }
  }

  const previousByIp = new Map((previous?.devices ?? []).map((device) => [device.ip, device]));
  for (const device of result.devices ?? []) {
    const before = openPortSet(previousByIp.get(device.ip));
    for (const port of openPortSet(device)) {
      if (!SENSITIVE_PORTS.has(port) || before.has(port)) continue;
      add({
        ip: device.ip,
        kind: "sensitive-port",
        severity: [23, 2375, 6379, 9200, 27017].includes(port) ? "high" : "medium",
        title: `${SENSITIVE_PORTS.get(port)} became visible`,
        message: `${device.hostname || device.ip} now exposes TCP port ${port}.`,
        details: { ip: device.ip, port, service: SENSITIVE_PORTS.get(port) },
      });
    }
  }

  if (previous?.network && result.network) {
    if (previous.network.gateway !== result.network.gateway) {
      add({ kind: "gateway-change", severity: "high", title: "Default gateway changed", message: `Gateway changed from ${previous.network.gateway || "none"} to ${result.network.gateway || "none"}.`, details: { before: previous.network.gateway, after: result.network.gateway } });
    }
    const beforeDns = json([...(previous.network.dns_servers ?? [])].sort());
    const afterDns = json([...(result.network.dns_servers ?? [])].sort());
    if (beforeDns !== afterDns) {
      add({ kind: "dns-change", severity: "high", title: "DNS resolvers changed", message: "The host is using a different DNS resolver set.", details: { before: previous.network.dns_servers ?? [], after: result.network.dns_servers ?? [] } });
    }
  }

  return output;
}

function chunks(values, size = 400) {
  const output = [];
  for (let index = 0; index < values.length; index += size) output.push(values.slice(index, index + size));
  return output;
}

export class SqliteStore {
  constructor({ databasePath, legacyDataPath = null, logger = console } = {}) {
    if (!databasePath) throw new Error("databasePath is required.");
    const dataDirectory = path.dirname(databasePath);
    fs.mkdirSync(dataDirectory, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(dataDirectory, 0o700); } catch {}
    this.sqlite = new Database(databasePath);
    try { fs.chmodSync(databasePath, 0o600); } catch {}
    this.sqlite.pragma("temp_store = MEMORY");
    this.sqlite.pragma("cache_size = -32000");
    applyMigrations(this.sqlite);
    this.db = drizzle({ client: this.sqlite });
    this.logger = logger;
    this.seedProfiles();
    this.migrateLegacyResult(legacyDataPath);
  }

  close() {
    this.sqlite.close();
  }

  seedProfiles() {
    const timestamp = nowIso();
    for (const profile of BUILT_IN_PROFILES) {
      this.db.insert(scanProfiles).values({
        name: profile.name,
        builtIn: true,
        addressMode: profile.addressMode,
        portMode: profile.portMode,
        portsJson: json(profile.ports),
        timeoutMs: profile.timeoutMs,
        createdAt: timestamp,
        updatedAt: timestamp,
      }).onConflictDoUpdate({
        target: scanProfiles.name,
        set: {
          builtIn: true,
          addressMode: profile.addressMode,
          portMode: profile.portMode,
          portsJson: json(profile.ports),
          timeoutMs: profile.timeoutMs,
          updatedAt: timestamp,
        },
      }).run();
    }
  }

  migrateLegacyResult(legacyDataPath) {
    if (!legacyDataPath || !fs.existsSync(legacyDataPath)) return;
    const existing = this.db.select({ count: sql`count(*)` }).from(scans).get();
    if (Number(existing?.count ?? 0) > 0) return;
    try {
      const raw = fs.readFileSync(legacyDataPath, "utf8");
      const result = JSON.parse(raw);
      if (!isValidResult(result)) return;
      this.saveScan(result, { source: "migrated", skipAlerts: true });
      fs.renameSync(legacyDataPath, `${legacyDataPath}.migrated`);
    } catch (error) {
      this.logger.warn?.("Unable to migrate the previous latest-scan file.", error);
    }
  }

  getLatestResult(target = null) {
    const query = this.db.select().from(scans)
      .where(target ? eq(scans.target, target) : undefined)
      .orderBy(desc(scans.generatedAt), desc(scans.id)).limit(1);
    const row = query.get();
    return row ? parseJson(row.resultJson, null) : null;
  }

  getLatestScan(target = null) {
    const query = this.db.select().from(scans)
      .where(target ? eq(scans.target, target) : undefined)
      .orderBy(desc(scans.generatedAt), desc(scans.id)).limit(1);
    return rowToScan(query.get());
  }

  getScan(id) {
    const row = this.db.select().from(scans).where(eq(scans.id, Number(id))).limit(1).get();
    return rowToScan(row);
  }

  listHistory({ limit = 50, target = null } = {}) {
    const safeLimit = Math.max(1, Math.min(250, Number(limit) || 50));
    const rows = this.db.select().from(scans)
      .where(target ? eq(scans.target, target) : undefined)
      .orderBy(desc(scans.generatedAt), desc(scans.id)).limit(safeLimit).all();
    return rows.map((row) => rowToScan(row, { includeResult: false }));
  }

  deleteScan(id) {
    return this.db.delete(scans).where(eq(scans.id, Number(id))).run().changes > 0;
  }

  saveScan(result, { source = "live", profileName = null, skipAlerts = false } = {}) {
    if (!isValidResult(result)) throw Object.assign(new Error("Refusing to store an invalid scan result."), { status: 400 });
    const serializedResult = json(result);
    if (Buffer.byteLength(serializedResult, "utf8") > MAX_SAVED_RESULT_BYTES) {
      throw Object.assign(new Error("Scan result is too large to save."), { status: 413 });
    }
    const generatedAt = new Date(result.generated_at).toISOString();
    const previous = this.getLatestResult(result.target);
    const createdAt = nowIso();
    return this.db.transaction((tx) => {
      const inserted = tx.insert(scans).values({
        generatedAt,
        target: result.target,
        source,
        profileName,
        durationSeconds: Number(result.duration_seconds || 0),
        deviceCount: Number(result.summary?.device_count ?? result.devices.length),
        summaryJson: json(result.summary ?? {}),
        resultJson: serializedResult,
        createdAt,
      }).returning({ id: scans.id }).get();
      const scanId = inserted.id;
      const deviceMap = new Map();
      const observedDeviceIds = {};
      const observationRows = [];
      const identityKeys = [...new Set([
        ...(result.devices ?? []).map((device) => identityKeyForDevice(device, result.target)),
        ...(previous?.devices ?? []).map((device) => identityKeyForDevice(device, result.target)),
      ])];
      const existingByIdentity = new Map();
      for (const batch of chunks(identityKeys)) {
        if (!batch.length) continue;
        for (const row of tx.select().from(devices).where(inArray(devices.identityKey, batch)).all()) existingByIdentity.set(row.identityKey, row);
      }

      for (const device of result.devices ?? []) {
        const identityKey = identityKeyForDevice(device, result.target);
        const existing = existingByIdentity.get(identityKey);
        const role = device.role ?? {};
        const vendor = existing?.vendor || vendorFromMac(device.mac);
        let persistent;
        if (existing) {
          tx.update(devices).set({
            mac: normalizeMac(device.mac) ?? existing.mac,
            lastIp: device.ip,
            hostname: device.hostname || existing.hostname,
            vendor,
            roleKey: role.key || existing.roleKey,
            roleLabel: role.label || existing.roleLabel,
            lastSeenAt: generatedAt,
            updatedAt: createdAt,
          }).where(eq(devices.id, existing.id)).run();
          persistent = { ...existing, lastIp: device.ip, hostname: device.hostname || existing.hostname, vendor };
        } else {
          const insertedDevice = tx.insert(devices).values({
            identityKey,
            mac: normalizeMac(device.mac),
            lastIp: device.ip,
            hostname: device.hostname || null,
            vendor,
            roleKey: role.key || null,
            roleLabel: role.label || null,
            customName: null,
            notes: "",
            trustState: device.is_gateway ? "infrastructure" : "unknown",
            tagsJson: "[]",
            ignored: false,
            firstSeenAt: result.generated_at,
            lastSeenAt: generatedAt,
            createdAt,
            updatedAt: createdAt,
          }).returning({ id: devices.id }).get();
          persistent = {
            id: insertedDevice.id,
            identityKey,
            mac: normalizeMac(device.mac),
            lastIp: device.ip,
            hostname: device.hostname || null,
            vendor,
            roleKey: role.key || null,
            roleLabel: role.label || null,
            customName: null,
            notes: "",
            trustState: device.is_gateway ? "infrastructure" : "unknown",
            tagsJson: "[]",
            ignored: false,
            firstSeenAt: generatedAt,
            lastSeenAt: generatedAt,
            createdAt,
            updatedAt: createdAt,
          };
          existingByIdentity.set(identityKey, persistent);
        }
        deviceMap.set(device.ip, rowToDevice(persistent));
        observedDeviceIds[device.ip] = persistent.id;
        observationRows.push({
          scanId,
          deviceId: persistent.id,
          ip: device.ip,
          hostname: device.hostname || null,
          mac: normalizeMac(device.mac),
          state: device.state || "unknown",
          latencyMs: Number.isFinite(device.latency_ms) ? device.latency_ms : null,
          openPortsJson: json(device.open_ports ?? []),
          evidenceJson: json(device.evidence ?? []),
          roleJson: json(role),
          isHost: Boolean(device.is_host),
          isGateway: Boolean(device.is_gateway),
          createdAt: generatedAt,
        });
      }
      for (const batch of chunks(observationRows, 50)) tx.insert(observations).values(batch).run();

      for (const previousDevice of previous?.devices ?? []) {
        if (deviceMap.has(previousDevice.ip)) continue;
        const identityKey = identityKeyForDevice(previousDevice, result.target);
        const persistent = existingByIdentity.get(identityKey);
        if (persistent) deviceMap.set(previousDevice.ip, rowToDevice(persistent));
      }

      const generatedAlerts = skipAlerts ? [] : alertsForScan(result, previous, deviceMap);
      for (const alert of generatedAlerts) tx.insert(alerts).values({ ...alert, scanId }).run();
      return {
        scan_id: scanId,
        alert_count: generatedAlerts.length,
        device_ids: observedDeviceIds,
      };
    });
  }

  importScan(result) {
    return this.saveScan(result, { source: "imported", skipAlerts: true });
  }

  compareScans(leftId, rightId) {
    const left = this.getScan(leftId);
    const right = this.getScan(rightId);
    if (!left || !right) return null;
    const [before, after] = Date.parse(left.generated_at) <= Date.parse(right.generated_at) ? [left, right] : [right, left];
    return {
      left: { id: before.id, generated_at: before.generated_at, target: before.target },
      right: { id: after.id, generated_at: after.generated_at, target: after.target },
      changes: compareResults(after.result, before.result),
    };
  }

  listDevices({ query = "", trustState = "", limit = 250 } = {}) {
    const safeLimit = Math.max(1, Math.min(5000, Number(limit) || 250));
    const conditions = [];
    if (query) {
      const pattern = `%${String(query).slice(0, 100)}%`;
      conditions.push(or(like(devices.customName, pattern), like(devices.hostname, pattern), like(devices.lastIp, pattern), like(devices.mac, pattern), like(devices.vendor, pattern), like(devices.tagsJson, pattern)));
    }
    if (trustState) conditions.push(eq(devices.trustState, validateTrustState(trustState)));
    const where = conditions.length > 1 ? and(...conditions) : conditions[0];
    return this.db.select().from(devices).where(where).orderBy(desc(devices.lastSeenAt)).limit(safeLimit).all().map(rowToDevice);
  }

  getDevice(id) {
    const device = this.db.select().from(devices).where(eq(devices.id, Number(id))).limit(1).get();
    if (!device) return null;
    const history = this.db.select({
      id: observations.id,
      scanId: observations.scanId,
      ip: observations.ip,
      hostname: observations.hostname,
      mac: observations.mac,
      state: observations.state,
      latencyMs: observations.latencyMs,
      openPortsJson: observations.openPortsJson,
      evidenceJson: observations.evidenceJson,
      roleJson: observations.roleJson,
      isHost: observations.isHost,
      isGateway: observations.isGateway,
      createdAt: observations.createdAt,
    }).from(observations).where(eq(observations.deviceId, device.id)).orderBy(desc(observations.createdAt)).limit(100).all().map((row) => ({
      id: row.id,
      scan_id: row.scanId,
      ip: row.ip,
      hostname: row.hostname,
      mac: row.mac,
      state: row.state,
      latency_ms: row.latencyMs,
      open_ports: parseJson(row.openPortsJson, []),
      evidence: parseJson(row.evidenceJson, []),
      role: parseJson(row.roleJson, {}),
      is_host: Boolean(row.isHost),
      is_gateway: Boolean(row.isGateway),
      created_at: row.createdAt,
    }));
    return { ...rowToDevice(device), observations: history };
  }

  updateDevice(id, patch) {
    const existing = this.db.select().from(devices).where(eq(devices.id, Number(id))).limit(1).get();
    if (!existing) return null;
    const updates = { updatedAt: nowIso() };
    if (Object.hasOwn(patch, "custom_name")) updates.customName = String(patch.custom_name ?? "").trim().slice(0, 80) || null;
    if (Object.hasOwn(patch, "notes")) updates.notes = String(patch.notes ?? "").slice(0, 4000);
    if (Object.hasOwn(patch, "trust_state")) updates.trustState = validateTrustState(patch.trust_state);
    if (Object.hasOwn(patch, "tags")) updates.tagsJson = json(normalizeTags(patch.tags));
    if (Object.hasOwn(patch, "ignored")) updates.ignored = patch.ignored === true;
    this.db.update(devices).set(updates).where(eq(devices.id, existing.id)).run();
    return this.getDevice(existing.id);
  }

  listAlerts({ limit = 100, acknowledged = null } = {}) {
    const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));
    const where = acknowledged == null ? undefined : eq(alerts.acknowledged, Boolean(acknowledged));
    return this.db.select().from(alerts).where(where).orderBy(desc(alerts.createdAt), desc(alerts.id)).limit(safeLimit).all().map(rowToAlert);
  }

  acknowledgeAlert(id, acknowledged = true) {
    const result = this.db.update(alerts).set({ acknowledged: Boolean(acknowledged) }).where(eq(alerts.id, Number(id))).run();
    return result.changes > 0;
  }

  acknowledgeAllAlerts() {
    return this.db.update(alerts).set({ acknowledged: true }).where(eq(alerts.acknowledged, false)).run().changes;
  }


  listNotificationEvents({ limit = 100 } = {}) {
    const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));
    return this.db.select().from(notificationEvents).orderBy(desc(notificationEvents.createdAt), desc(notificationEvents.id)).limit(safeLimit).all().map(rowToNotificationEvent);
  }

  addNotificationEvent(payload) {
    const inserted = this.db.insert(notificationEvents).values({
      alertId: payload.alert_id ?? null,
      status: payload.status,
      title: payload.title,
      message: payload.message,
      detailsJson: json(payload.details ?? {}),
      createdAt: payload.created_at ?? nowIso(),
    }).returning({ id: notificationEvents.id }).get();
    return rowToNotificationEvent(this.db.select().from(notificationEvents).where(eq(notificationEvents.id, inserted.id)).limit(1).get());
  }

  clearNotificationEvents() {
    return this.db.delete(notificationEvents).run().changes;
  }

  listProfiles() {
    return this.db.select().from(scanProfiles).orderBy(desc(scanProfiles.builtIn), scanProfiles.name).all().map(rowToProfile);
  }

  getProfile(id) {
    return rowToProfile(this.db.select().from(scanProfiles).where(eq(scanProfiles.id, Number(id))).limit(1).get());
  }

  saveProfile(payload, id = null) {
    const name = String(payload.name ?? "").trim().slice(0, 60);
    if (!name) throw Object.assign(new Error("Profile name is required."), { status: 400 });
    const addressMode = String(payload.address_mode ?? "standard");
    const portMode = String(payload.port_mode ?? "selected");
    if (!["standard", "extended"].includes(addressMode) || !["selected", "all"].includes(portMode)) {
      throw Object.assign(new Error("Invalid scan profile mode."), { status: 400 });
    }
    const ports = Array.isArray(payload.ports) ? payload.ports : [];
    const timestamp = nowIso();
    const duplicateCondition = id == null
      ? sql`lower(${scanProfiles.name}) = lower(${name})`
      : and(sql`lower(${scanProfiles.name}) = lower(${name})`, sql`${scanProfiles.id} <> ${Number(id)}`);
    if (this.db.select({ id: scanProfiles.id }).from(scanProfiles).where(duplicateCondition).limit(1).get()) {
      throw Object.assign(new Error("A scan profile with this name already exists."), { status: 409 });
    }
    try {
      if (id != null) {
        const existing = this.db.select().from(scanProfiles).where(eq(scanProfiles.id, Number(id))).limit(1).get();
        if (!existing) return null;
        if (existing.builtIn) throw Object.assign(new Error("Built-in profiles cannot be modified."), { status: 409 });
        this.db.update(scanProfiles).set({ name, addressMode, portMode, portsJson: json(ports), timeoutMs: payload.timeout_ms ?? null, updatedAt: timestamp }).where(eq(scanProfiles.id, existing.id)).run();
        return this.getProfile(existing.id);
      }
      const inserted = this.db.insert(scanProfiles).values({ name, builtIn: false, addressMode, portMode, portsJson: json(ports), timeoutMs: payload.timeout_ms ?? null, createdAt: timestamp, updatedAt: timestamp }).returning({ id: scanProfiles.id }).get();
      return this.getProfile(inserted.id);
    } catch (error) {
      if (Number.isInteger(error?.status)) throw error;
      throw sqliteConflict(error, "A scan profile with this name already exists.");
    }
  }

  deleteProfile(id) {
    const existing = this.db.select().from(scanProfiles).where(eq(scanProfiles.id, Number(id))).limit(1).get();
    if (!existing) return false;
    if (existing.builtIn) throw Object.assign(new Error("Built-in profiles cannot be deleted."), { status: 409 });
    const scheduleCount = Number(this.db.select({ count: sql`count(*)` }).from(schedules).where(eq(schedules.profileId, existing.id)).get()?.count ?? 0);
    if (scheduleCount) throw Object.assign(new Error("Delete or change schedules that use this profile first."), { status: 409 });
    return this.db.delete(scanProfiles).where(eq(scanProfiles.id, existing.id)).run().changes > 0;
  }

  listSchedules() {
    return this.db.select().from(schedules).orderBy(desc(schedules.enabled), schedules.nextRunAt).all().map(rowToSchedule);
  }

  getSchedule(id) {
    return rowToSchedule(this.db.select().from(schedules).where(eq(schedules.id, Number(id))).limit(1).get());
  }

  saveSchedule(payload, id = null) {
    const name = String(payload.name ?? "").trim().slice(0, 80);
    const targets = Array.isArray(payload.targets) ? [...new Set(payload.targets.map(String).map((value) => value.trim()).filter(Boolean))] : [];
    const intervalMinutes = Number(payload.interval_minutes);
    if (!name || !targets.length) throw Object.assign(new Error("Schedule name and at least one target are required."), { status: 400 });
    if (!Number.isInteger(intervalMinutes) || intervalMinutes < 5 || intervalMinutes > 10080) throw Object.assign(new Error("Schedule interval must be between 5 minutes and 7 days."), { status: 400 });
    const profileId = Number(payload.profile_id);
    if (!this.getProfile(profileId)) throw Object.assign(new Error("Choose a valid scan profile."), { status: 400 });
    const timestamp = nowIso();
    const nextRunAt = payload.next_run_at && Number.isFinite(Date.parse(payload.next_run_at)) ? new Date(payload.next_run_at).toISOString() : new Date(Date.now() + intervalMinutes * 60_000).toISOString();
    const values = { name, enabled: payload.enabled !== false, targetsJson: json(targets.slice(0, 8)), profileId, allowIntensive: payload.allow_intensive === true, intervalMinutes, nextRunAt, updatedAt: timestamp };
    if (id != null) {
      const existing = this.getSchedule(id);
      if (!existing) return null;
      this.db.update(schedules).set(values).where(eq(schedules.id, Number(id))).run();
      return this.getSchedule(id);
    }
    const inserted = this.db.insert(schedules).values({ ...values, lastRunAt: null, lastStatus: null, createdAt: timestamp }).returning({ id: schedules.id }).get();
    return this.getSchedule(inserted.id);
  }

  deleteSchedule(id) {
    return this.db.delete(schedules).where(eq(schedules.id, Number(id))).run().changes > 0;
  }

  dueSchedules(at = nowIso()) {
    return this.db.select().from(schedules).where(and(eq(schedules.enabled, true), lte(schedules.nextRunAt, at))).orderBy(schedules.nextRunAt).all().map(rowToSchedule);
  }

  markScheduleRun(id, { status = "complete", ranAt = nowIso() } = {}) {
    const schedule = this.getSchedule(id);
    if (!schedule) return null;
    const nextRunAt = new Date(Date.parse(ranAt) + schedule.interval_minutes * 60_000).toISOString();
    this.db.update(schedules).set({ lastRunAt: ranAt, lastStatus: status, nextRunAt, updatedAt: nowIso() }).where(eq(schedules.id, Number(id))).run();
    return this.getSchedule(id);
  }

  listExclusions() {
    return this.db.select().from(exclusions).orderBy(exclusions.kind, exclusions.value).all().map((row) => ({ id: row.id, kind: row.kind, value: row.value, label: row.label, enabled: Boolean(row.enabled), created_at: row.createdAt }));
  }

  saveExclusion(payload) {
    const kind = String(payload.kind ?? "");
    const value = String(payload.value ?? "").trim();
    if (!["ip", "cidr", "mac"].includes(kind) || !value) throw Object.assign(new Error("Invalid exclusion."), { status: 400 });
    try {
      const inserted = this.db.insert(exclusions).values({ kind, value, label: String(payload.label ?? "").trim().slice(0, 100), enabled: payload.enabled !== false, createdAt: nowIso() }).returning({ id: exclusions.id }).get();
      return this.listExclusions().find((entry) => entry.id === inserted.id);
    } catch (error) {
      throw sqliteConflict(error, "This exclusion already exists.");
    }
  }

  updateExclusion(id, payload) {
    const existing = this.db.select().from(exclusions).where(eq(exclusions.id, Number(id))).limit(1).get();
    if (!existing) return null;
    const updates = {};
    if (Object.hasOwn(payload, "label")) updates.label = String(payload.label ?? "").trim().slice(0, 100);
    if (Object.hasOwn(payload, "enabled")) updates.enabled = payload.enabled === true;
    this.db.update(exclusions).set(updates).where(eq(exclusions.id, existing.id)).run();
    return this.listExclusions().find((entry) => entry.id === existing.id);
  }

  deleteExclusion(id) {
    return this.db.delete(exclusions).where(eq(exclusions.id, Number(id))).run().changes > 0;
  }

  getSetting(key, fallback = null) {
    const row = this.db.select().from(settings).where(eq(settings.key, String(key))).limit(1).get();
    return row ? parseJson(row.valueJson, fallback) : fallback;
  }

  setSetting(key, value) {
    const timestamp = nowIso();
    this.db.insert(settings).values({ key: String(key), valueJson: json(value), updatedAt: timestamp }).onConflictDoUpdate({ target: settings.key, set: { valueJson: json(value), updatedAt: timestamp } }).run();
    return value;
  }

  dashboardSummary() {
    const historyCount = Number(this.db.select({ count: sql`count(*)` }).from(scans).get()?.count ?? 0);
    const deviceCount = Number(this.db.select({ count: sql`count(*)` }).from(devices).get()?.count ?? 0);
    const alertSummary = this.db.select({ count: sql`count(*)`, latestId: sql`max(${alerts.id})` }).from(alerts).where(eq(alerts.acknowledged, false)).get();
    const alertCount = Number(alertSummary?.count ?? 0);
    const latestAlertId = alertSummary?.latestId == null ? null : Number(alertSummary.latestId);
    const scheduleCount = Number(this.db.select({ count: sql`count(*)` }).from(schedules).where(eq(schedules.enabled, true)).get()?.count ?? 0);
    return { history_count: historyCount, known_device_count: deviceCount, unacknowledged_alert_count: alertCount, latest_unacknowledged_alert_id: latestAlertId, active_schedule_count: scheduleCount };
  }
}
