import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { BUILT_IN_PROFILES } from "../src/profiles.js";

let SqliteStore = null;
try {
  ({ SqliteStore } = await import("../src/db/store.js"));
} catch (error) {
  if (error?.code !== "ERR_MODULE_NOT_FOUND") throw error;
}

test("production SQLite store matches shared profiles and rejects case-only duplicates", { skip: !SqliteStore }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "netscope-sqlite-test-"));
  const store = new SqliteStore({ databasePath: path.join(directory, "netscope.sqlite") });
  try {
    assert.deepEqual(store.listProfiles().filter((profile) => profile.built_in).map((profile) => ({
      name: profile.name,
      addressMode: profile.address_mode,
      portMode: profile.port_mode,
      ports: profile.ports,
      timeoutMs: profile.timeout_ms,
    })), BUILT_IN_PROFILES.map((profile) => ({ ...profile, ports: [...profile.ports] })).sort((left, right) => left.name.localeCompare(right.name)));
    assert.throws(() => store.saveProfile({ name: "quick", address_mode: "standard", port_mode: "selected", ports: [80], timeout_ms: 200 }), (error) => error.status === 409);
  } finally {
    store.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
