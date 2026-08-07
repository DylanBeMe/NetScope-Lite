import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildNetworkContext,
  classifyDevice,
  compareResults,
  interfaceInventory,
  loadResult,
  parseDarwinRoutes,
  parseLegacyLinuxRoutes,
  parseLinuxRoutes,
  parsePingLatency,
  parseWindowsRoutes,
  resolveHostnames,
  routeInventory,
  saveResult,
  scanNetwork,
  suggestedTargets,
  targetOptions,
} from "../src/scanner.js";
import { parseIPv4Network } from "../src/safety.js";

const interfaceRecord = {
  interface: "eth0",
  kind: "ethernet",
  address: "192.168.1.2",
  netmask: "255.255.255.0",
  network: "192.168.1.0/24",
  mac: "aa:bb:cc:dd:ee:ff",
};

const noNames = async (ips) => ({ names: Object.fromEntries(ips.map((ip) => [ip, null])), timedOut: 0 });

test("large attached networks are suggested as bounded local /24 targets", () => {
  assert.deepEqual(suggestedTargets([{ ...interfaceRecord, address: "10.20.33.44", network: "10.20.0.0/16", netmask: "255.255.0.0" }]), ["10.20.33.0/24"]);
});


test("eligible attached networks expose both local-segment and full-subnet choices", () => {
  const options = targetOptions([{ ...interfaceRecord, address: "10.20.17.44", network: "10.20.16.0/20", netmask: "255.255.240.0" }]);
  assert.deepEqual(options.map((option) => [option.cidr, option.scope, option.extended]), [
    ["10.20.17.0/24", "local-segment", false],
    ["10.20.16.0/20", "full-subnet", true],
  ]);
});

test("interface inventory converts OS records and classifies the link", () => {
  const inventory = interfaceInventory({
    eth0: [{ family: "IPv4", internal: false, address: "192.168.5.9", netmask: "255.255.255.0", mac: "AA:BB:CC:DD:EE:FF" }],
    lo: [{ family: "IPv4", internal: true, address: "127.0.0.1", netmask: "255.0.0.0", mac: "00:00:00:00:00:00" }],
  });
  assert.deepEqual(inventory, [{
    interface: "eth0",
    kind: "ethernet",
    address: "192.168.5.9",
    netmask: "255.255.255.0",
    network: "192.168.5.0/24",
    mac: "aa:bb:cc:dd:ee:ff",
  }]);
});

test("ping latency parsing supports Unix and Windows output", () => {
  assert.equal(parsePingLatency("64 bytes time=2.43 ms"), 2.43);
  assert.equal(parsePingLatency("Minimum = 1ms, Maximum = 3ms, Average = 2ms"), 2);
  assert.equal(parsePingLatency("round-trip min/avg/max/stddev = 1.0/2.5/4.0/1.0 ms"), 2.5);
});

test("route parsers normalize Linux, Windows, and macOS route evidence", () => {
  assert.deepEqual(parseLinuxRoutes("default via 192.168.1.1 dev eth0 metric 100\n192.168.1.0/24 dev eth0 src 192.168.1.2"), [
    { destination: "0.0.0.0/0", gateway: "192.168.1.1", interface: "eth0", source: null, metric: 100, is_default: true },
    { destination: "192.168.1.0/24", gateway: null, interface: "eth0", source: "192.168.1.2", metric: null, is_default: false },
  ]);
  assert.equal(parseWindowsRoutes("0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.2     25")[0].gateway, "192.168.1.1");
  const darwinRoutes = parseDarwinRoutes(`Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
192.168.1/24       link#4             UCS                   en0`);
  assert.equal(darwinRoutes[0].interface, "en0");
  assert.equal(darwinRoutes[1].destination, "192.168.1.0/24");
  assert.deepEqual(parseLegacyLinuxRoutes(`Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 eth0
192.168.1.0     0.0.0.0         255.255.255.0   U     100    0        0 eth0`), [
    { destination: "0.0.0.0/0", gateway: "192.168.1.1", interface: "eth0", source: null, metric: 100, is_default: true },
    { destination: "192.168.1.0/24", gateway: null, interface: "eth0", source: null, metric: 100, is_default: false },
  ]);
});

test("route inventory falls back when the preferred command returns unparseable output", async () => {
  const calls = [];
  const routes = await routeInventory({
    platform: "linux",
    execFn: async (command) => {
      calls.push(command);
      if (command === "ip") return { error: null, stdout: "unparseable but non-empty output" };
      return {
        error: null,
        stdout: "Destination Gateway Genmask Flags Metric Ref Use Iface\n0.0.0.0 192.168.1.1 0.0.0.0 UG 100 0 0 eth0\n",
      };
    },
  });
  assert.deepEqual(calls, ["ip", "route"]);
  assert.equal(routes[0].gateway, "192.168.1.1");
});

test("network context selects matching interface, gateway, and IPv4 DNS", () => {
  const context = buildNetworkContext(parseIPv4Network("192.168.1.0/24"), [interfaceRecord], [
    { destination: "0.0.0.0/0", gateway: "192.168.1.1", interface: "eth0", source: null, metric: 10, is_default: true },
  ], ["192.168.1.1", "2001:4860:4860::8888"]);
  assert.equal(context.interface, "eth0");
  assert.equal(context.gateway, "192.168.1.1");
  assert.deepEqual(context.dns_servers, ["192.168.1.1"]);
});

test("network context follows route evidence when multiple interfaces cover the target", () => {
  const interfaces = [
    { ...interfaceRecord, interface: "eth0", address: "192.168.1.2" },
    { ...interfaceRecord, interface: "wlan0", kind: "wireless", address: "192.168.1.20", mac: "aa:bb:cc:dd:ee:20" },
  ];
  const context = buildNetworkContext(parseIPv4Network("192.168.1.0/24"), interfaces, [
    { destination: "0.0.0.0/0", gateway: "192.168.1.1", interface: "wlan0", source: "192.168.1.20", metric: 5, is_default: true },
  ]);
  assert.equal(context.interface, "wlan0");
  assert.equal(context.local_address, "192.168.1.20");
});

test("network context uses a connected route to disambiguate overlapping interfaces", () => {
  const interfaces = [
    { ...interfaceRecord, interface: "eth0", address: "192.168.1.2" },
    { ...interfaceRecord, interface: "wlan0", kind: "wireless", address: "192.168.1.20", mac: "aa:bb:cc:dd:ee:20" },
  ];
  const context = buildNetworkContext(parseIPv4Network("192.168.1.128/25"), interfaces, [
    { destination: "192.168.1.128/25", gateway: null, interface: "wlan0", source: "192.168.1.20", metric: 5, is_default: false },
  ]);
  assert.equal(context.interface, "wlan0");
  assert.equal(context.local_address, "192.168.1.20");
});

test("hostname resolution rejects invalid time budgets", async () => {
  await assert.rejects(() => resolveHostnames([], { totalTimeoutMs: Number.NaN }), /totalTimeoutMs/);
  await assert.rejects(() => resolveHostnames([], { totalTimeoutMs: -1 }), /totalTimeoutMs/);
});

test("hostname resolution returns completed results", async () => {
  const result = await resolveHostnames(["192.168.1.2", "192.168.1.3"], {
    totalTimeoutMs: 1000,
    reverseFn: async (ip) => [`host-${ip}`],
  });
  assert.equal(result.timedOut, 0);
  assert.equal(result.names["192.168.1.2"], "host-192.168.1.2");
});

test("hostname resolution responds promptly to cancellation", async () => {
  const controller = new AbortController();
  const pending = resolveHostnames(["192.168.1.2"], {
    signal: controller.signal,
    totalTimeoutMs: 10_000,
    reverseFn: () => new Promise(() => {}),
  });
  controller.abort();
  await assert.rejects(pending, (error) => error?.name === "AbortError");
});

test("scan remains usable when the reverse-DNS stage fails wholesale", async () => {
  const result = await scanNetwork("192.168.1.2/32", {
    interfaces: [interfaceRecord],
    ports: [],
    pingAvailable: true,
    pingFn: async () => ({ responded: true, latencyMs: 1 }),
    neighborTableFn: async () => ({}),
    resolveHostnamesFn: async () => { throw new Error("resolver unavailable"); },
    routeInventoryFn: async () => [],
    dnsServersFn: () => [],
    hostInventoryFn: () => ({ hostname: "host", interfaces: [interfaceRecord], suggested_targets: [] }),
  });
  assert.equal(result.devices[0].ip, "192.168.1.2");
  assert.match(result.warnings.join(" "), /Reverse-DNS lookup failed/);
});

test("ICMP and TCP discovery queues begin concurrently", async () => {
  const started = new Set();
  let release;
  const bothStarted = new Promise((resolve) => { release = resolve; });
  const markStarted = (kind) => {
    started.add(kind);
    if (started.size === 2) release();
  };
  const scan = scanNetwork("192.168.1.2/32", {
    interfaces: [interfaceRecord],
    ports: [80],
    pingAvailable: true,
    pingFn: async () => {
      markStarted("icmp");
      await bothStarted;
      return { responded: true, latencyMs: 1 };
    },
    checkPortFn: async () => {
      markStarted("tcp");
      await bothStarted;
      return false;
    },
    neighborTableFn: async () => ({}),
    resolveHostnamesFn: noNames,
    routeInventoryFn: async () => [],
    dnsServersFn: () => [],
    hostInventoryFn: () => ({ hostname: "host", interfaces: [interfaceRecord], suggested_targets: [] }),
  });
  await Promise.race([
    bothStarted,
    new Promise((_, reject) => setImmediate(() => reject(new Error("Discovery queues did not overlap.")))),
  ]);
  const result = await scan;
  assert.deepEqual([...started].sort(), ["icmp", "tcp"]);
  assert.equal(result.devices[0].is_host, true);
});

test("scan reuses a supplied interface snapshot and marks the host", async () => {
  let hostInventoryCalls = 0;
  const result = await scanNetwork("192.168.1.2/32", {
    ports: [],
    interfaces: [interfaceRecord],
    pingAvailable: false,
    neighborTableFn: async () => ({}),
    routeInventoryFn: async () => [],
    dnsServersFn: () => [],
    resolveHostnamesFn: noNames,
    hostInventoryFn: (interfaces) => {
      hostInventoryCalls += 1;
      assert.equal(interfaces[0], interfaceRecord);
      return { hostname: "host", interfaces, suggested_targets: ["192.168.1.0/24"] };
    },
  });
  assert.equal(hostInventoryCalls, 1);
  assert.equal(result.devices[0].is_host, true);
  assert.deepEqual(result.devices[0].evidence, ["local"]);
  assert.match(result.warnings.join(" "), /ping command was not found/);
});

test("scan discovers ICMP, neighbor, and TCP-only devices across the subnet", async () => {
  const result = await scanNetwork("192.168.1.0/30", {
    ports: [80, 443],
    interfaces: [interfaceRecord],
    pingAvailable: true,
    pingFn: async (ip) => ({ responded: ip === "192.168.1.1", latencyMs: ip === "192.168.1.1" ? 2.4 : null }),
    neighborTableFn: async () => ({ "192.168.1.2": "aa:bb:cc:dd:ee:ff" }),
    routeInventoryFn: async () => [{ destination: "0.0.0.0/0", gateway: "192.168.1.1", interface: "eth0", source: null, metric: 10, is_default: true }],
    dnsServersFn: () => ["192.168.1.1"],
    resolveHostnamesFn: async (ips) => ({ names: Object.fromEntries(ips.map((ip) => [ip, ip.endsWith(".1") ? "router.local" : null])), timedOut: 0 }),
    checkPortFn: async (ip, port) => ip === "192.168.1.1" && port === 80,
    hostInventoryFn: () => ({ hostname: "host", interfaces: [interfaceRecord], suggested_targets: [] }),
  });
  assert.equal(result.summary.device_count, 2);
  assert.equal(result.summary.open_service_count, 1);
  const gateway = result.devices.find((device) => device.ip === "192.168.1.1");
  assert.equal(gateway.open_ports[0].service, "HTTP");
  assert.equal(gateway.is_gateway, true);
  assert.deepEqual(gateway.evidence, ["icmp", "tcp"]);
  assert.equal(result.devices.find((device) => device.ip === "192.168.1.2").is_host, true);
  assert.equal(result.topology.kind, "logical-observed");
});

test("TCP evidence discovers a device that blocks ICMP and is absent from the neighbor table", async () => {
  const result = await scanNetwork("192.168.1.0/30", {
    ports: [443],
    interfaces: [interfaceRecord],
    pingAvailable: true,
    pingFn: async () => ({ responded: false, latencyMs: null }),
    neighborTableFn: async () => ({}),
    routeInventoryFn: async () => [],
    dnsServersFn: () => [],
    resolveHostnamesFn: noNames,
    checkPortFn: async (ip, port) => ip === "192.168.1.1" && port === 443,
    hostInventoryFn: () => ({ hostname: "host", interfaces: [interfaceRecord], suggested_targets: [] }),
  });
  const tcpOnly = result.devices.find((device) => device.ip === "192.168.1.1");
  assert.equal(tcpOnly.state, "service");
  assert.deepEqual(tcpOnly.evidence, ["tcp"]);
  assert.equal(result.summary.tcp_discovered_count, 1);
});

test("scan summary counts only actual ICMP responses and reports TCP-evidenced devices", async () => {
  const result = await scanNetwork("192.168.1.0/30", {
    ports: [80],
    interfaces: [interfaceRecord],
    pingAvailable: false,
    neighborTableFn: async () => ({ "192.168.1.1": "aa:bb:cc:dd:ee:01" }),
    routeInventoryFn: async () => [],
    dnsServersFn: () => [],
    resolveHostnamesFn: noNames,
    checkPortFn: async (ip) => ip === "192.168.1.1",
    hostInventoryFn: () => ({ hostname: "host", interfaces: [interfaceRecord], suggested_targets: [] }),
  });
  assert.equal(result.summary.responsive_count, 0);
  assert.equal(result.summary.tcp_evidence_count, 1);
  assert.equal(result.summary.tcp_discovered_count, 1);
});

test("device classification uses conservative service evidence", () => {
  assert.equal(classifyDevice({ open_ports: [{ port: 9100 }], hostname: null, evidence: [] }).key, "printer");
  assert.equal(classifyDevice({ open_ports: [{ port: 445 }, { port: 443 }], hostname: null, evidence: ["tcp"] }).key, "nas");
  assert.equal(classifyDevice({ open_ports: [], hostname: null, evidence: [] }).key, "device");
});

test("change tracking reports new, missing, and changed services only for the same target", () => {
  const previous = {
    target: "192.168.1.0/24",
    generated_at: "2026-01-01T00:00:00.000Z",
    devices: [
      { ip: "192.168.1.2", is_host: true, open_ports: [] },
      { ip: "192.168.1.3", open_ports: [{ port: 80 }] },
      { ip: "192.168.1.4", open_ports: [] },
    ],
  };
  const current = {
    target: previous.target,
    devices: [
      { ip: "192.168.1.2", is_host: true, open_ports: [] },
      { ip: "192.168.1.3", open_ports: [{ port: 443 }] },
      { ip: "192.168.1.5", open_ports: [] },
    ],
  };
  const changes = compareResults(current, previous);
  assert.deepEqual(changes.counts, { new: 1, missing: 1, changed: 1 });
});


test("all-port mode checks ports 1 through 65535 on every observed device", async () => {
  let checks = 0;
  const phases = new Set();
  let portProgressUpdates = 0;
  const result = await scanNetwork("192.168.1.2/32", {
    ports: [],
    portMode: "all",
    interfaces: [interfaceRecord],
    pingAvailable: false,
    checkPortFn: async (_ip, port) => {
      checks += 1;
      return port === 12345;
    },
    neighborTableFn: async () => ({}),
    routeInventoryFn: async () => [],
    dnsServersFn: () => [],
    resolveHostnamesFn: noNames,
    hostInventoryFn: () => ({ hostname: "host", interfaces: [interfaceRecord], suggested_targets: [] }),
    onProgress: (progress) => {
      phases.add(progress.phase);
      if (progress.phase === "ports") portProgressUpdates += 1;
    },
  });
  assert.equal(checks, 65535);
  assert.deepEqual(result.devices[0].open_ports, [{ port: 12345, service: "TCP" }]);
  assert.equal(result.scan_options.port_mode, "all");
  assert.ok(phases.has("ports"));
  assert.ok(phases.has("complete"));
  assert.ok(portProgressUpdates <= 505, `expected bounded progress updates, received ${portProgressUpdates}`);
});

test("all-port mode responds to cancellation", async () => {
  const controller = new AbortController();
  await assert.rejects(() => scanNetwork("192.168.1.2/32", {
    ports: [],
    portMode: "all",
    interfaces: [interfaceRecord],
    pingAvailable: false,
    checkPortFn: async () => false,
    neighborTableFn: async () => ({}),
    routeInventoryFn: async () => [],
    dnsServersFn: () => [],
    resolveHostnamesFn: noNames,
    hostInventoryFn: () => ({ hostname: "host", interfaces: [interfaceRecord], suggested_targets: [] }),
    signal: controller.signal,
    onProgress: (progress) => {
      if (progress.phase === "ports") controller.abort();
    },
  }), (error) => error?.name === "AbortError");
});

test("result persistence is atomic and rejects malformed or out-of-target data", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "netscope-test-"));
  const filePath = path.join(directory, "scan.json");
  const result = {
    generated_at: "2026-08-06T00:00:00.000Z",
    target: "192.168.1.0/24",
    host: { hostname: "test" },
    devices: [{ ip: "192.168.1.2", open_ports: [] }],
    warnings: [],
    summary: {},
  };
  saveResult(result, filePath);
  assert.deepEqual(loadResult(filePath), result);

  const hostOnlyResult = {
    generated_at: result.generated_at,
    target: "192.168.1.20/32",
    host: {
      hostname: "test",
      interfaces: [{
        interface: "eth0",
        kind: "ethernet",
        address: "192.168.1.20",
        netmask: "255.255.255.0",
        network: "192.168.1.0/24",
        mac: "aa:bb:cc:dd:ee:ff",
      }],
    },
    network: {
      cidr: "192.168.1.20/32",
      network_address: "192.168.1.20",
      broadcast_address: "192.168.1.20",
      prefix: 32,
      interface: "eth0",
      interface_kind: "ethernet",
      local_address: "192.168.1.20",
      local_mac: "aa:bb:cc:dd:ee:ff",
      gateway: "192.168.1.1",
      gateway_metric: null,
      dns_servers: [],
      route_count: 2,
    },
    devices: [{ ip: "192.168.1.20", state: "up", open_ports: [], is_host: true, evidence: ["local", "icmp"] }],
    warnings: [],
    summary: { device_count: 1 },
  };
  saveResult(hostOnlyResult, filePath);
  assert.deepEqual(loadResult(filePath), hostOnlyResult);
  for (const payload of [
    [],
    { host: {}, devices: {} },
    { generated_at: result.generated_at, target: result.target, host: {}, devices: [{ ip: "10.0.0.1", open_ports: [] }] },
    { generated_at: "invalid", target: result.target, host: {}, devices: [] },
    { generated_at: result.generated_at, target: "8.8.8.8/32", host: {}, devices: [{ ip: "8.8.8.8", open_ports: [] }] },
    { generated_at: result.generated_at, target: "10.0.0.0/8", host: {}, devices: [] },
    { generated_at: result.generated_at, target: result.target, host: {}, devices: [{ ip: "192.168.1.2", open_ports: [{ port: 80 }, { port: 80 }] }] },
    { generated_at: result.generated_at, target: result.target, host: {}, devices: [{ ip: "192.168.1.2", state: "invented", open_ports: [] }] },
    { generated_at: result.generated_at, target: result.target, host: { unexpected: { deeply: "nested" } }, devices: [] },
    { generated_at: result.generated_at, target: result.target, host: {}, devices: [{ ip: "192.168.001.002", open_ports: [] }] },
    { generated_at: result.generated_at, target: result.target, host: {}, devices: [{ ip: "192.168.1.2", role: { key: "x".repeat(100) }, open_ports: [] }] },
    { ...result, unexpected: "field" },
  ]) {
    fs.writeFileSync(filePath, JSON.stringify(payload));
    assert.equal(loadResult(filePath), null);
  }
  fs.rmSync(directory, { recursive: true, force: true });
});
