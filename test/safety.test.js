import test from "node:test";
import assert from "node:assert/strict";
import {
  MAX_EXTENDED_TARGET_ADDRESSES,
  TargetRejected,
  hostsInNetwork,
  netmaskToPrefix,
  normalizePorts,
  parseIPv4Network,
  validateLocalTarget,
} from "../src/safety.js";

test("accepts a small attached private subnet and canonicalizes CIDR", () => {
  const target = parseIPv4Network("192.168.10.42/24");
  assert.equal(validateLocalTarget(target, [parseIPv4Network("192.168.10.0/24")]).cidr, "192.168.10.0/24");
});

test("accepts an attached IPv4 link-local subnet", () => {
  const target = parseIPv4Network("169.254.10.0/24");
  assert.equal(validateLocalTarget(target, [target]).cidr, target.cidr);
});

test("rejects public and reserved ranges even when attached", () => {
  for (const cidr of ["8.8.8.0/24", "192.0.2.0/24"]) {
    assert.throws(
      () => validateLocalTarget(parseIPv4Network(cidr), [parseIPv4Network(cidr)]),
      TargetRejected,
    );
  }
});

test("rejects an unattached private range", () => {
  assert.throws(
    () => validateLocalTarget(parseIPv4Network("10.20.30.0/24"), [parseIPv4Network("192.168.1.0/24")]),
    /directly attached/,
  );
});

test("rejects ranges larger than 256 addresses", () => {
  assert.throws(
    () => validateLocalTarget(parseIPv4Network("10.0.0.0/16"), [parseIPv4Network("10.0.0.0/16")]),
    /too large/,
  );
});


test("accepts an explicitly extended attached subnet up to the extended cap", () => {
  const target = parseIPv4Network("10.20.16.0/20");
  assert.equal(
    validateLocalTarget(target, [target], { maxAddresses: MAX_EXTENDED_TARGET_ADDRESSES }).cidr,
    "10.20.16.0/20",
  );
});

test("normalizes, deduplicates, and validates ports", () => {
  assert.deepEqual(normalizePorts([80, "443", 80]), [80, 443]);
  for (const invalid of [[0], null, "80,443", [true], [80.5], [65536]]) {
    assert.throws(() => normalizePorts(invalid));
  }
  assert.throws(() => normalizePorts([22, 80, 443], { limit: 2 }), /At most 2/);
});

test("validates contiguous netmasks", () => {
  assert.equal(netmaskToPrefix("255.255.255.0"), 24);
  assert.equal(netmaskToPrefix("255.255.255.255"), 32);
  assert.throws(() => netmaskToPrefix("255.0.255.0"), /Invalid IPv4 netmask/);
});

test("enumerates /30, /31, and /32 hosts correctly", () => {
  assert.deepEqual(hostsInNetwork(parseIPv4Network("192.168.1.0/30")), ["192.168.1.1", "192.168.1.2"]);
  assert.deepEqual(hostsInNetwork(parseIPv4Network("192.168.1.0/31")), ["192.168.1.0", "192.168.1.1"]);
  assert.deepEqual(hostsInNetwork(parseIPv4Network("192.168.1.7/32")), ["192.168.1.7"]);
});
