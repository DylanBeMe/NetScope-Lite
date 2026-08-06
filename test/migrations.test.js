import assert from "node:assert/strict";
import test from "node:test";
import { applyMigrations } from "../src/db/migrations.js";

let DatabaseSync;
try {
  ({ DatabaseSync } = await import("node:sqlite"));
} catch {
  DatabaseSync = null;
}

test("SQLite migrations create the monitoring schema and remain idempotent", { skip: !DatabaseSync }, () => {
  const database = new DatabaseSync(":memory:");
  const adapter = {
    pragma(statement) { database.exec(`PRAGMA ${statement}`); },
    exec(sql) { database.exec(sql); },
    prepare(sql) {
      const statement = database.prepare(sql);
      return { all: (...params) => statement.all(...params) };
    }
  };

  applyMigrations(adapter);
  applyMigrations(adapter);

  const tableRows = database.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all();
  const tableNames = new Set(tableRows.map((row) => row.name));
  for (const expected of ["scans", "devices", "observations", "alerts", "notification_events", "schedules", "scan_profiles", "exclusions", "settings"]) {
    assert.equal(tableNames.has(expected), true, `missing table ${expected}`);
  }

  const scheduleColumns = database.prepare("PRAGMA table_info(schedules)").all().map((row) => row.name);
  assert.equal(scheduleColumns.includes("allow_intensive"), true);
  assert.equal(database.prepare("PRAGMA foreign_keys").get().foreign_keys, 1);
  assert.equal(database.prepare("PRAGMA busy_timeout").get().timeout, 5000);
  database.close();
});
