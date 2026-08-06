import test from "node:test";
import assert from "node:assert/strict";
import { MemoryStore } from "../src/memory-store.js";
import { ScanManager } from "../src/scan-manager.js";
import { isValidResult } from "../src/scanner.js";

function resultAt(generatedAt, devices = []) {
  return {
    generated_at: generatedAt,
    duration_seconds: 0.1,
    target: "192.168.50.0/24",
    host: {
      hostname: "host",
      interfaces: [{ interface: "eth0", kind: "ethernet", address: "192.168.50.2", netmask: "255.255.255.0", network: "192.168.50.0/24", mac: "aa:bb:cc:dd:ee:ff" }],
      ipv6_interfaces: [{ interface: "eth0", kind: "ethernet", address: "fe80::1", cidr: "fe80::1/64" }],
      suggested_targets: ["192.168.50.0/24"],
      target_options: [],
    },
    network: {
      cidr: "192.168.50.0/24", network_address: "192.168.50.0", broadcast_address: "192.168.50.255", prefix: 24,
      interface: "eth0", interface_kind: "ethernet", local_address: "192.168.50.2", local_mac: "aa:bb:cc:dd:ee:ff",
      gateway: "192.168.50.1", gateway_metric: 10, dns_servers: ["192.168.50.1"], route_count: 2,
    },
    ipv6: { mode: "passive", interfaces: [{ interface: "eth0", address: "fe80::1", cidr: "fe80::1/64" }], neighbors: [{ interface: "eth0", address: "fe80::2", mac: "00:11:22:33:44:55", state: "reachable" }] },
    devices,
    warnings: [],
    scan_options: { ports: [22, 80], port_mode: "selected", address_mode: "standard", usable_address_count: 254, scanned_address_count: 254, excluded_address_count: 0, ping_timeout_ms: 500, port_timeout_ms: 260, full_port_timeout_ms: null },
    summary: { device_count: devices.length, responsive_count: devices.length, tcp_evidence_count: 0, tcp_discovered_count: 0, neighbor_only_count: 0, open_service_count: 0, gateway_count: 0, ipv6_interface_count: 1, ipv6_neighbor_count: 1 },
    changes: { comparable: false, baseline_generated_at: null, new_devices: [], missing_devices: [], changed_services: [], counts: { new: 0, missing: 0, changed: 0 } },
    topology: { kind: "observed-logical", disclaimer: "Logical only", nodes: [], edges: [] },
  };
}

const hostDevice = { ip: "192.168.50.2", hostname: "host", mac: "aa:bb:cc:dd:ee:ff", state: "up", latency_ms: 1, open_ports: [], is_host: true, is_gateway: false, evidence: ["local", "icmp"], role: { key: "host", label: "This PC", category: "endpoints", reason: "Local" } };
const ignoredDevice = { ip: "192.168.50.10", hostname: "camera", mac: "00:11:22:33:44:55", state: "service", latency_ms: null, open_ports: [{ port: 23, service: "Telnet" }], is_host: false, is_gateway: false, evidence: ["tcp"], role: { key: "iot", label: "IoT", category: "peripherals", reason: "Service" } };

test("result validation accepts passive IPv6 context and summary counts", () => {
  assert.equal(isValidResult(resultAt("2026-08-06T10:00:00.000Z", [hostDevice])), true);
});

test("all-port profiles seed discovery ports when a custom profile has no selected ports", async () => {
  const store = new MemoryStore();
  const profile = store.saveProfile({ name: "Everything", address_mode: "extended", port_mode: "all", ports: [], timeout_ms: 250 });
  let received;
  const scanner = {
    DEFAULT_PORTS: [22, 80, 443],
    scanNetwork: async (_target, options) => {
      received = options;
      return resultAt("2026-08-06T10:00:00.000Z", [hostDevice]);
    },
  };
  const manager = new ScanManager({ scanner, store, state: {} });
  await manager.run({ target: "192.168.50.0/24", profile_id: profile.id, authorized: true });
  assert.deepEqual(received.ports, [22, 80, 443]);
  assert.equal(received.portMode, "all");
});

test("the first baseline does not generate sensitive-port alerts", () => {
  const store = new MemoryStore();
  const stored = store.saveScan(resultAt("2026-08-06T10:00:00.000Z", [hostDevice, ignoredDevice]));
  assert.equal(stored.alert_count, 0);
  assert.equal(store.listAlerts().length, 0);
});

test("ignored devices suppress missing-device alerts", () => {
  const store = new MemoryStore();
  const first = store.saveScan(resultAt("2026-08-06T10:00:00.000Z", [hostDevice, ignoredDevice]));
  store.updateDevice(first.device_ids[ignoredDevice.ip], { ignored: true });
  store.saveScan(resultAt("2026-08-06T11:00:00.000Z", [hostDevice]));
  assert.equal(store.listAlerts().some((alert) => alert.kind === "missing-device"), false);
});

test("history comparison is chronological regardless of argument order", () => {
  const store = new MemoryStore();
  const older = store.saveScan(resultAt("2026-08-06T10:00:00.000Z", [hostDevice]));
  const newer = store.saveScan(resultAt("2026-08-06T11:00:00.000Z", [hostDevice, ignoredDevice]));
  const comparison = store.compareScans(newer.scan_id, older.scan_id);
  assert.equal(comparison.left.id, older.scan_id);
  assert.equal(comparison.right.id, newer.scan_id);
  assert.equal(comparison.changes.counts.new, 1);
});

test("equivalent DNS resolver sets do not create order-only alerts", () => {
  const store = new MemoryStore();
  const first = resultAt("2026-08-06T10:00:00.000Z", [hostDevice]);
  first.network.dns_servers = ["192.168.50.1", "1.1.1.1"];
  store.saveScan(first);
  const second = resultAt("2026-08-06T11:00:00.000Z", [hostDevice]);
  second.network.dns_servers = ["1.1.1.1", "192.168.50.1"];
  store.saveScan(second);
  assert.equal(store.listAlerts().some((alert) => alert.kind === "dns-change"), false);
});

test("equivalent CIDR targets are canonicalized and scanned once", async () => {
  const store = new MemoryStore();
  const calls = [];
  const scanner = {
    DEFAULT_PORTS: [80],
    scanNetwork: async (target) => {
      calls.push(target);
      return resultAt("2026-08-06T12:00:00.000Z", [hostDevice]);
    },
  };
  const manager = new ScanManager({ scanner, store, state: {} });
  const result = await manager.run({ targets: ["192.168.50.1/24", "192.168.50.0/24"], ports: [80] });
  assert.equal(result.batch, undefined);
  assert.deepEqual(calls, ["192.168.50.0/24"]);
});

test("monitor summary exposes the newest unacknowledged alert identity", () => {
  const store = new MemoryStore();
  store.alerts.push(
    { id: 4, acknowledged: false },
    { id: 8, acknowledged: true },
    { id: 7, acknowledged: false },
  );
  assert.equal(store.dashboardSummary().latest_unacknowledged_alert_id, 7);
  store.acknowledgeAllAlerts();
  assert.equal(store.dashboardSummary().latest_unacknowledged_alert_id, null);
});

test("in-memory tests use the same built-in profile definitions as production", async () => {
  const { BUILT_IN_PROFILES } = await import("../src/profiles.js");
  const store = new MemoryStore();
  assert.deepEqual(store.listProfiles().map((profile) => ({
    name: profile.name,
    addressMode: profile.address_mode,
    portMode: profile.port_mode,
    ports: profile.ports,
    timeoutMs: profile.timeout_ms,
  })), BUILT_IN_PROFILES.map((profile) => ({ ...profile, ports: [...profile.ports] })));
});
