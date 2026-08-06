export function applyMigrations(sqlite) {
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  sqlite.pragma("synchronous = NORMAL");
  sqlite.pragma("busy_timeout = 5000");
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      generated_at TEXT NOT NULL,
      target TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'live',
      profile_name TEXT,
      duration_seconds REAL NOT NULL DEFAULT 0,
      device_count INTEGER NOT NULL DEFAULT 0,
      summary_json TEXT NOT NULL DEFAULT '{}',
      result_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS scans_target_generated_idx ON scans(target, generated_at);
    CREATE INDEX IF NOT EXISTS scans_generated_idx ON scans(generated_at);

    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      identity_key TEXT NOT NULL UNIQUE,
      mac TEXT,
      last_ip TEXT NOT NULL,
      hostname TEXT,
      vendor TEXT,
      role_key TEXT,
      role_label TEXT,
      custom_name TEXT,
      notes TEXT NOT NULL DEFAULT '',
      trust_state TEXT NOT NULL DEFAULT 'unknown',
      tags_json TEXT NOT NULL DEFAULT '[]',
      ignored INTEGER NOT NULL DEFAULT 0,
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS devices_mac_idx ON devices(mac);
    CREATE INDEX IF NOT EXISTS devices_last_ip_idx ON devices(last_ip);
    CREATE INDEX IF NOT EXISTS devices_last_seen_idx ON devices(last_seen_at);

    CREATE TABLE IF NOT EXISTS observations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      ip TEXT NOT NULL,
      hostname TEXT,
      mac TEXT,
      state TEXT NOT NULL,
      latency_ms REAL,
      open_ports_json TEXT NOT NULL DEFAULT '[]',
      evidence_json TEXT NOT NULL DEFAULT '[]',
      role_json TEXT NOT NULL DEFAULT '{}',
      is_host INTEGER NOT NULL DEFAULT 0,
      is_gateway INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS observations_scan_idx ON observations(scan_id);
    CREATE INDEX IF NOT EXISTS observations_device_created_idx ON observations(device_id, created_at);

    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
      device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
      kind TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      details_json TEXT NOT NULL DEFAULT '{}',
      acknowledged INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS alerts_acknowledged_created_idx ON alerts(acknowledged, created_at);
    CREATE INDEX IF NOT EXISTS alerts_scan_idx ON alerts(scan_id);

    CREATE TABLE IF NOT EXISTS notification_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      alert_id INTEGER REFERENCES alerts(id) ON DELETE SET NULL,
      status TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      details_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS notification_events_created_idx ON notification_events(created_at);
    CREATE INDEX IF NOT EXISTS notification_events_alert_idx ON notification_events(alert_id);

    CREATE TABLE IF NOT EXISTS schedules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      targets_json TEXT NOT NULL,
      profile_id INTEGER,
      allow_intensive INTEGER NOT NULL DEFAULT 0,
      interval_minutes INTEGER NOT NULL,
      next_run_at TEXT NOT NULL,
      last_run_at TEXT,
      last_status TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS schedules_enabled_next_idx ON schedules(enabled, next_run_at);

    CREATE TABLE IF NOT EXISTS scan_profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      built_in INTEGER NOT NULL DEFAULT 0,
      address_mode TEXT NOT NULL DEFAULT 'standard',
      port_mode TEXT NOT NULL DEFAULT 'selected',
      ports_json TEXT NOT NULL DEFAULT '[]',
      timeout_ms INTEGER,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS exclusions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kind TEXT NOT NULL,
      value TEXT NOT NULL,
      label TEXT NOT NULL DEFAULT '',
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      UNIQUE(kind, value)
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
  const scheduleColumns = sqlite.prepare("PRAGMA table_info(schedules)").all().map((row) => row.name);
  if (!scheduleColumns.includes("allow_intensive")) sqlite.exec("ALTER TABLE schedules ADD COLUMN allow_intensive INTEGER NOT NULL DEFAULT 0");
}
