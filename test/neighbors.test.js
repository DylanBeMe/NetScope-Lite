import test from "node:test";
import assert from "node:assert/strict";
import { parseNeighborTable } from "../src/scanner.js";

test("parses Linux ip neigh output", () => {
  const raw = `
192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.1.50 dev eth0 FAILED
`;
  assert.deepEqual(parseNeighborTable(raw), { "192.168.1.1": "aa:bb:cc:dd:ee:ff" });
});

test("parses Windows ARP output and normalizes MAC addresses", () => {
  const raw = `
  192.168.1.1          00-11-22-33-44-55     dynamic
  192.168.1.20         aa-bb-cc-dd-ee-ff     dynamic
`;
  assert.deepEqual(parseNeighborTable(raw), {
    "192.168.1.1": "00:11:22:33:44:55",
    "192.168.1.20": "aa:bb:cc:dd:ee:ff",
  });
});

test("ignores invalid IPs and placeholder MAC addresses", () => {
  const raw = `
999.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.1.2 dev eth0 lladdr 00:00:00:00:00:00 STALE
192.168.1.3 dev eth0 lladdr ff:ff:ff:ff:ff:ff STALE
`;
  assert.deepEqual(parseNeighborTable(raw), {});
});
