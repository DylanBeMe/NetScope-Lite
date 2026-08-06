import { index, integer, real, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const scans = sqliteTable("scans", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  generatedAt: text("generated_at").notNull(),
  target: text("target").notNull(),
  source: text("source").notNull().default("live"),
  profileName: text("profile_name"),
  durationSeconds: real("duration_seconds").notNull().default(0),
  deviceCount: integer("device_count").notNull().default(0),
  summaryJson: text("summary_json").notNull().default("{}"),
  resultJson: text("result_json").notNull(),
  createdAt: text("created_at").notNull(),
}, (table) => ({
  targetGeneratedIndex: index("scans_target_generated_idx").on(table.target, table.generatedAt),
  generatedIndex: index("scans_generated_idx").on(table.generatedAt),
}));

export const devices = sqliteTable("devices", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  identityKey: text("identity_key").notNull(),
  mac: text("mac"),
  lastIp: text("last_ip").notNull(),
  hostname: text("hostname"),
  vendor: text("vendor"),
  roleKey: text("role_key"),
  roleLabel: text("role_label"),
  customName: text("custom_name"),
  notes: text("notes").notNull().default(""),
  trustState: text("trust_state").notNull().default("unknown"),
  tagsJson: text("tags_json").notNull().default("[]"),
  ignored: integer("ignored", { mode: "boolean" }).notNull().default(false),
  firstSeenAt: text("first_seen_at").notNull(),
  lastSeenAt: text("last_seen_at").notNull(),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
}, (table) => ({
  identityIndex: uniqueIndex("devices_identity_key_idx").on(table.identityKey),
  macIndex: index("devices_mac_idx").on(table.mac),
  ipIndex: index("devices_last_ip_idx").on(table.lastIp),
  lastSeenIndex: index("devices_last_seen_idx").on(table.lastSeenAt),
}));

export const observations = sqliteTable("observations", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  scanId: integer("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  deviceId: integer("device_id").notNull().references(() => devices.id, { onDelete: "cascade" }),
  ip: text("ip").notNull(),
  hostname: text("hostname"),
  mac: text("mac"),
  state: text("state").notNull(),
  latencyMs: real("latency_ms"),
  openPortsJson: text("open_ports_json").notNull().default("[]"),
  evidenceJson: text("evidence_json").notNull().default("[]"),
  roleJson: text("role_json").notNull().default("{}"),
  isHost: integer("is_host", { mode: "boolean" }).notNull().default(false),
  isGateway: integer("is_gateway", { mode: "boolean" }).notNull().default(false),
  createdAt: text("created_at").notNull(),
}, (table) => ({
  scanIndex: index("observations_scan_idx").on(table.scanId),
  deviceCreatedIndex: index("observations_device_created_idx").on(table.deviceId, table.createdAt),
}));

export const alerts = sqliteTable("alerts", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  scanId: integer("scan_id").references(() => scans.id, { onDelete: "set null" }),
  deviceId: integer("device_id").references(() => devices.id, { onDelete: "set null" }),
  kind: text("kind").notNull(),
  severity: text("severity").notNull(),
  title: text("title").notNull(),
  message: text("message").notNull(),
  detailsJson: text("details_json").notNull().default("{}"),
  acknowledged: integer("acknowledged", { mode: "boolean" }).notNull().default(false),
  createdAt: text("created_at").notNull(),
}, (table) => ({
  acknowledgedIndex: index("alerts_acknowledged_created_idx").on(table.acknowledged, table.createdAt),
  scanIndex: index("alerts_scan_idx").on(table.scanId),
}));


export const notificationEvents = sqliteTable("notification_events", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  alertId: integer("alert_id").references(() => alerts.id, { onDelete: "set null" }),
  status: text("status").notNull(),
  title: text("title").notNull(),
  message: text("message").notNull(),
  detailsJson: text("details_json").notNull().default("{}"),
  createdAt: text("created_at").notNull(),
}, (table) => ({
  createdIndex: index("notification_events_created_idx").on(table.createdAt),
  alertIndex: index("notification_events_alert_idx").on(table.alertId),
}));

export const schedules = sqliteTable("schedules", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  name: text("name").notNull(),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  targetsJson: text("targets_json").notNull(),
  profileId: integer("profile_id"),
  allowIntensive: integer("allow_intensive", { mode: "boolean" }).notNull().default(false),
  intervalMinutes: integer("interval_minutes").notNull(),
  nextRunAt: text("next_run_at").notNull(),
  lastRunAt: text("last_run_at"),
  lastStatus: text("last_status"),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
}, (table) => ({
  dueIndex: index("schedules_enabled_next_idx").on(table.enabled, table.nextRunAt),
}));

export const scanProfiles = sqliteTable("scan_profiles", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  name: text("name").notNull(),
  builtIn: integer("built_in", { mode: "boolean" }).notNull().default(false),
  addressMode: text("address_mode").notNull().default("standard"),
  portMode: text("port_mode").notNull().default("selected"),
  portsJson: text("ports_json").notNull().default("[]"),
  timeoutMs: integer("timeout_ms"),
  createdAt: text("created_at").notNull(),
  updatedAt: text("updated_at").notNull(),
}, (table) => ({
  nameIndex: uniqueIndex("scan_profiles_name_idx").on(table.name),
}));

export const exclusions = sqliteTable("exclusions", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  kind: text("kind").notNull(),
  value: text("value").notNull(),
  label: text("label").notNull().default(""),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  createdAt: text("created_at").notNull(),
}, (table) => ({
  kindValueIndex: uniqueIndex("exclusions_kind_value_idx").on(table.kind, table.value),
}));

export const settings = sqliteTable("settings", {
  key: text("key").primaryKey(),
  valueJson: text("value_json").notNull(),
  updatedAt: text("updated_at").notNull(),
});
