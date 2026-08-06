export const MAX_TARGET_ADDRESSES = 256;
export const MAX_EXTENDED_TARGET_ADDRESSES = 4096;

export class TargetRejected extends Error {
  constructor(message) {
    super(message);
    this.name = "TargetRejected";
  }
}

export function parseIPv4(value) {
  if (typeof value !== "string") throw new TargetRejected("IPv4 address must be text.");
  const parts = value.trim().split(".");
  if (parts.length !== 4) throw new TargetRejected(`Invalid IPv4 address: ${JSON.stringify(value)}`);
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) throw new TargetRejected(`Invalid IPv4 address: ${JSON.stringify(value)}`);
    const octet = Number(part);
    if (octet > 255) throw new TargetRejected(`Invalid IPv4 address: ${JSON.stringify(value)}`);
    result = result * 256 + octet;
  }
  return result;
}

export function intToIPv4(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError("IPv4 integer must be between 0 and 2^32 - 1.");
  }
  return [24, 16, 8, 0].map((shift) => Math.floor(value / (2 ** shift)) % 256).join(".");
}

export function prefixMask(prefix) {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new TargetRejected("IPv4 prefix length must be between 0 and 32.");
  }
  if (prefix === 0) return 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

export function netmaskToPrefix(netmask) {
  const mask = parseIPv4(netmask);
  const binary = mask.toString(2).padStart(32, "0");
  if (!/^1*0*$/.test(binary)) throw new TargetRejected(`Invalid IPv4 netmask: ${JSON.stringify(netmask)}`);
  return binary.indexOf("0") === -1 ? 32 : binary.indexOf("0");
}

export function parseIPv4Network(value) {
  if (typeof value !== "string" || !value.trim()) {
    throw new TargetRejected("Target must be an IPv4 network in CIDR notation.");
  }
  const match = /^\s*([^/]+)\/(\d{1,2})\s*$/.exec(value);
  if (!match) throw new TargetRejected(`Invalid CIDR: ${JSON.stringify(value)}`);
  const address = parseIPv4(match[1]);
  const prefix = Number(match[2]);
  const mask = prefixMask(prefix);
  const networkInt = (address & mask) >>> 0;
  const broadcastInt = (networkInt | (~mask >>> 0)) >>> 0;
  return {
    prefix,
    networkInt,
    broadcastInt,
    numAddresses: 2 ** (32 - prefix),
    cidr: `${intToIPv4(networkInt)}/${prefix}`,
  };
}

export function networkFromAddressAndNetmask(address, netmask) {
  const prefix = netmaskToPrefix(netmask);
  return parseIPv4Network(`${address}/${prefix}`);
}

export function networkContainsIPv4(network, address) {
  const value = typeof address === "number" ? address : parseIPv4(address);
  return value >= network.networkInt && value <= network.broadcastInt;
}

export function networkIsSubnetOf(target, parent) {
  return target.networkInt >= parent.networkInt && target.broadcastInt <= parent.broadcastInt;
}

const ALLOWED_LOCAL_RANGES = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "169.254.0.0/16",
].map(parseIPv4Network);

export function isAllowedLocalNetwork(target) {
  return ALLOWED_LOCAL_RANGES.some((allowed) => networkIsSubnetOf(target, allowed));
}

export function validateLocalTarget(target, attachedNetworks, { maxAddresses = MAX_TARGET_ADDRESSES } = {}) {
  if (!Number.isInteger(maxAddresses) || maxAddresses < 1) {
    throw new RangeError("maxAddresses must be at least 1.");
  }
  if (!isAllowedLocalNetwork(target)) {
    throw new TargetRejected("Only RFC1918 private or IPv4 link-local ranges are allowed.");
  }
  if (target.numAddresses > maxAddresses) {
    throw new TargetRejected(
      `Target is too large (${target.numAddresses} addresses); maximum is ${maxAddresses}.`,
    );
  }
  const attached = [...attachedNetworks].map((network) =>
    typeof network === "string" ? parseIPv4Network(network) : network,
  );
  if (!attached.some((network) => networkIsSubnetOf(target, network))) {
    const pretty = attached.map((network) => network.cidr).join(", ") || "none detected";
    throw new TargetRejected(
      `Target must be inside a network directly attached to this host. Attached networks: ${pretty}.`,
    );
  }
  return target;
}

export function hostsInNetwork(network) {
  const first = network.numAddresses <= 2 ? network.networkInt : network.networkInt + 1;
  const last = network.numAddresses <= 2 ? network.broadcastInt : network.broadcastInt - 1;
  const hosts = [];
  for (let current = first; current <= last; current += 1) hosts.push(intToIPv4(current));
  return hosts;
}

export function normalizePorts(values, { limit = 1024 } = {}) {
  if (!Number.isInteger(limit) || limit < 0) throw new RangeError("Port limit cannot be negative.");
  if (!Array.isArray(values)) throw new TypeError("Ports must be provided as a list of numbers.");
  const result = [];
  const seen = new Set();
  for (const value of values) {
    if (typeof value === "boolean" || value === null || value === "") {
      throw new TypeError(`Invalid port: ${JSON.stringify(value)}`);
    }
    const port = Number(value);
    if (!Number.isInteger(port)) throw new TypeError(`Invalid port: ${JSON.stringify(value)}`);
    if (port < 1 || port > 65535) throw new RangeError(`Port out of range: ${port}`);
    if (!seen.has(port)) {
      seen.add(port);
      result.push(port);
    }
    if (result.length > limit) throw new RangeError(`At most ${limit} ports may be checked per scan.`);
  }
  return result;
}
