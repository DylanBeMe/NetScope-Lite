import { execFile } from "node:child_process";
import dns from "node:dns/promises";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import {
  hostsInNetwork,
  MAX_EXTENDED_TARGET_ADDRESSES,
  MAX_TARGET_ADDRESSES,
  intToIPv4,
  isAllowedLocalNetwork,
  networkContainsIPv4,
  networkFromAddressAndNetmask,
  networkIsSubnetOf,
  netmaskToPrefix,
  normalizePorts,
  parseIPv4,
  parseIPv4Network,
  validateLocalTarget,
} from "./safety.js";

export const DEFAULT_PORTS = [22, 53, 80, 443, 445, 631, 3389, 8080, 8443, 9100];
export const PORT_NAMES = Object.freeze({
  20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
  80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP",
  443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD", 587: "SMTP submission",
  631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "SQL Server", 1521: "Oracle",
  1883: "MQTT", 2049: "NFS", 2375: "Docker API", 3000: "HTTP dev", 3306: "MySQL",
  3389: "RDP", 5000: "HTTP-alt", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
  5986: "WinRM TLS", 6379: "Redis", 8000: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt",
  8883: "MQTT TLS", 9000: "Application", 9100: "JetDirect", 9200: "Elasticsearch", 27017: "MongoDB",
});
export const MAX_COMMAND_WORKERS = 24;
export const MAX_SOCKET_WORKERS = 96;
export const DNS_LOOKUP_BUDGET_MS = 3000;
export const MAX_SAVED_RESULT_BYTES = 64 * 1024 * 1024;
export const MAX_DEEP_SCAN_HOSTS = 256;
export const FULL_TCP_PORT_COUNT = 65535;

function round(value, digits = 2) {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function normalizedMac(value) {
  if (typeof value !== "string") return null;
  const hex = value.replace(/[^0-9a-f]/gi, "").toLowerCase();
  if (!/^[0-9a-f]{12}$/.test(hex) || hex === "000000000000" || hex === "ffffffffffff") return null;
  return hex.match(/.{2}/g)?.join(":") ?? null;
}

export function interfaceKind(interfaceName) {
  const name = String(interfaceName ?? "").toLowerCase();
  if (/^(docker|br-|veth|virbr|vmnet|vbox|vethernet|utun|tun|tap|wg|tailscale|zt|cni|flannel|cilium|kube|podman|lxc|lxd|incus)/.test(name)) return "virtual";
  if (/(wi-?fi|wireless|wlan|airport)|^wl/.test(name)) return "wireless";
  if (/^(eth|enp|eno|ens|em\d|lan)|ethernet/.test(name)) return "ethernet";
  if (/^(ppp|wwan|cellular)/.test(name)) return "wide-area";
  return "network";
}

export function interfaceInventory(networkInterfaces = os.networkInterfaces()) {
  const inventory = [];
  for (const [interfaceName, addresses] of Object.entries(networkInterfaces)) {
    for (const address of addresses ?? []) {
      const isIPv4 = address.family === "IPv4" || address.family === 4;
      if (!isIPv4 || address.internal || !address.address || !address.netmask) continue;
      try {
        const network = networkFromAddressAndNetmask(address.address, address.netmask);
        inventory.push({
          interface: interfaceName,
          kind: interfaceKind(interfaceName),
          address: address.address,
          netmask: address.netmask,
          network: network.cidr,
          mac: normalizedMac(address.mac),
        });
      } catch {
        // Ignore incomplete or malformed interface records supplied by the OS.
      }
    }
  }
  return inventory.sort((left, right) => left.interface.localeCompare(right.interface) || parseIPv4(left.address) - parseIPv4(right.address));
}

export function attachedNetworks(interfaces = interfaceInventory()) {
  const seen = new Set();
  const networks = [];
  for (const item of interfaces) {
    try {
      const network = parseIPv4Network(item.network);
      if (!seen.has(network.cidr)) {
        seen.add(network.cidr);
        networks.push(network);
      }
    } catch {
      // Ignore malformed interface snapshots.
    }
  }
  return networks;
}

export function targetOptions(interfaces = interfaceInventory(), { includeVirtual = process.env.NETSCOPE_INCLUDE_VIRTUAL_TARGETS === "1" } = {}) {
  const options = [];
  const seen = new Set();
  const add = (network, item, scope) => {
    const key = `${network.cidr}:${scope}`;
    if (seen.has(key)) return;
    seen.add(key);
    options.push({
      cidr: network.cidr,
      interface: item.interface,
      kind: item.kind,
      address_count: network.numAddresses,
      usable_address_count: network.numAddresses <= 2 ? network.numAddresses : network.numAddresses - 2,
      scope,
      extended: network.numAddresses > MAX_TARGET_ADDRESSES,
    });
  };

  for (const item of interfaces) {
    // Host-network containers can see Docker/Podman/CNI bridge interfaces in
    // addition to the host's real LAN interfaces. Do not offer those virtual
    // networks as normal scan targets unless the operator explicitly opts in.
    if (item.kind === "virtual" && !includeVirtual) continue;
    try {
      const attached = parseIPv4Network(item.network);
      if (!isAllowedLocalNetwork(attached)) continue;
      if (attached.numAddresses > MAX_TARGET_ADDRESSES) {
        add(parseIPv4Network(`${item.address}/24`), item, "local-segment");
      }
      if (attached.numAddresses <= MAX_EXTENDED_TARGET_ADDRESSES) add(attached, item, "full-subnet");
    } catch {
      // Ignore malformed interface snapshots.
    }
  }
  return options;
}

export function suggestedTargets(interfaces = interfaceInventory(), options) {
  return targetOptions(interfaces, options).map((option) => option.cidr);
}

function diskInventory() {
  try {
    const root = path.parse(process.cwd()).root;
    const stats = fs.statfsSync(root);
    const blockSize = Number(stats.bsize);
    const totalBytes = blockSize * Number(stats.blocks);
    const availableBytes = blockSize * Number(stats.bavail);
    const usedBytes = Math.max(0, totalBytes - availableBytes);
    return {
      disk_total_gb: round(totalBytes / 1024 ** 3),
      disk_used_percent: totalBytes ? round((usedBytes / totalBytes) * 100, 1) : null,
    };
  } catch {
    return { disk_total_gb: null, disk_used_percent: null };
  }
}

export function hostInventory(interfaces = interfaceInventory(), ipv6Interfaces = ipv6InterfaceInventory()) {
  const cpuList = os.cpus();
  const totalMemory = os.totalmem();
  const freeMemory = os.freemem();
  const disk = diskInventory();
  return {
    hostname: os.hostname(),
    fqdn: os.hostname(),
    os: `${os.type()} ${os.release()}`,
    system: os.platform(),
    release: os.release(),
    architecture: os.arch(),
    processor: cpuList[0]?.model ?? null,
    boot_time: new Date(Date.now() - os.uptime() * 1000).toISOString(),
    cpu_logical: cpuList.length || null,
    cpu_physical: null,
    memory_total_gb: round(totalMemory / 1024 ** 3),
    memory_used_percent: totalMemory ? round(((totalMemory - freeMemory) / totalMemory) * 100, 1) : null,
    ...disk,
    interfaces: interfaces.map((item) => ({ ...item })),
    ipv6_interfaces: ipv6Interfaces.map((item) => ({ ...item })),
    suggested_targets: suggestedTargets(interfaces),
    target_options: targetOptions(interfaces),
  };
}

function executableCandidates(command) {
  const pathEntries = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
  const extensions = process.platform === "win32"
    ? (process.env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";")
    : [""];
  return pathEntries.flatMap((entry) => extensions.map((extension) => path.join(entry, `${command}${extension}`)));
}

export function commandExists(command) {
  return executableCandidates(command).some((candidate) => {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
}

function pingCommand(ip, timeoutMs) {
  if (process.platform === "win32") return ["ping", ["-n", "1", "-w", String(Math.max(1, timeoutMs)), ip]];
  if (process.platform === "darwin") return ["ping", ["-c", "1", "-W", String(Math.max(1, timeoutMs)), ip]];
  return ["ping", ["-c", "1", "-W", String(Math.max(1, Math.ceil(timeoutMs / 1000))), ip]];
}

function execFileResult(command, args, options = {}) {
  return new Promise((resolve) => {
    execFile(command, args, { windowsHide: true, ...options }, (error, stdout = "", stderr = "") => {
      resolve({ error, stdout, stderr });
    });
  });
}

export function parsePingLatency(raw) {
  const text = String(raw ?? "");
  const direct = /time\s*[=<]\s*(\d+(?:\.\d+)?)\s*ms/i.exec(text);
  if (direct) return Number(direct[1]);
  const windows = /average\s*=\s*(\d+(?:\.\d+)?)\s*ms/i.exec(text);
  if (windows) return Number(windows[1]);
  const summary = /=\s*[\d.]+\/([\d.]+)\/[\d.]+\/[\d.]+\s*ms/i.exec(text);
  return summary ? Number(summary[1]) : null;
}

export async function ping(ip, timeoutMs = 800) {
  const [command, args] = pingCommand(ip, timeoutMs);
  const started = performance.now();
  const { error, stdout, stderr } = await execFileResult(command, args, {
    timeout: Math.max(100, timeoutMs) + 700,
    maxBuffer: 128 * 1024,
  });
  const responded = !error;
  const reportedLatency = parsePingLatency(`${stdout}\n${stderr}`);
  return {
    responded,
    latencyMs: responded ? round(reportedLatency ?? performance.now() - started, 1) : null,
  };
}

export function parseNeighborTable(raw) {
  const neighbors = {};
  const ipPattern = /(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])/;
  const macPattern = /\b([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\b/;
  for (const line of String(raw ?? "").split(/\r?\n/)) {
    const ipMatch = ipPattern.exec(line);
    const macMatch = macPattern.exec(line);
    if (!ipMatch || !macMatch) continue;
    try {
      parseIPv4(ipMatch[1]);
    } catch {
      continue;
    }
    const mac = normalizedMac(macMatch[1]);
    if (mac) neighbors[ipMatch[1]] = mac;
  }
  return neighbors;
}

async function runNeighborCommand() {
  const candidates = process.platform === "win32"
    ? [["arp", ["-a"]]]
    : process.platform === "darwin"
      ? [["arp", ["-an"]]]
      : [["ip", ["neigh", "show"]], ["arp", ["-an"]]];
  for (const [command, args] of candidates) {
    const { error, stdout } = await execFileResult(command, args, { timeout: 3000, maxBuffer: 1024 * 1024 });
    if (!error && stdout) return stdout;
  }
  return "";
}

export async function neighborTable() {
  return parseNeighborTable(await runNeighborCommand());
}

export function ipv6InterfaceInventory(networkInterfaces = os.networkInterfaces()) {
  const inventory = [];
  for (const [interfaceName, addresses] of Object.entries(networkInterfaces)) {
    for (const address of addresses ?? []) {
      const isIPv6 = address.family === "IPv6" || address.family === 6;
      if (!isIPv6 || address.internal || !address.address) continue;
      const cleanAddress = String(address.address).split("%")[0];
      if (net.isIP(cleanAddress) !== 6) continue;
      inventory.push({
        interface: interfaceName,
        kind: interfaceKind(interfaceName),
        address: cleanAddress,
        cidr: address.cidr || `${cleanAddress}/128`,
        scope_id: Number.isInteger(address.scopeid) ? address.scopeid : null,
        mac: normalizedMac(address.mac),
      });
    }
  }
  return inventory.sort((left, right) => left.interface.localeCompare(right.interface) || left.address.localeCompare(right.address));
}

export function parseIPv6NeighborTable(raw) {
  const entries = [];
  const seen = new Set();
  const macPattern = /\b([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\b/;
  for (const line of String(raw ?? "").split(/\r?\n/)) {
    const tokens = line.trim().split(/\s+/).filter(Boolean);
    let address = null;
    for (const token of tokens) {
      const clean = token.replace(/^\[|\]$/g, "").split("%")[0];
      if (net.isIP(clean) === 6) {
        address = clean;
        break;
      }
    }
    if (!address || seen.has(address)) continue;
    const mac = normalizedMac(macPattern.exec(line)?.[1] ?? null);
    const interfaceMatch = /\b(?:dev|interface)\s+([^\s]+)/i.exec(line);
    const stateMatch = /\b(REACHABLE|STALE|DELAY|PROBE|PERMANENT|NOARP|INCOMPLETE|FAILED)\b/i.exec(line);
    entries.push({
      address,
      mac,
      interface: interfaceMatch?.[1] ?? null,
      state: stateMatch?.[1]?.toLowerCase() ?? null,
    });
    seen.add(address);
  }
  return entries;
}

async function runIpv6NeighborCommand() {
  const candidates = process.platform === "win32"
    ? [["netsh", ["interface", "ipv6", "show", "neighbors"]]]
    : process.platform === "darwin"
      ? [["ndp", ["-an"]]]
      : [["ip", ["-6", "neigh", "show"]]];
  for (const [command, args] of candidates) {
    const { error, stdout } = await execFileResult(command, args, { timeout: 3000, maxBuffer: 1024 * 1024 });
    if (!error && stdout) return stdout;
  }
  return "";
}

export async function ipv6NeighborTable() {
  return parseIPv6NeighborTable(await runIpv6NeighborCommand());
}

function normalizeRoute({ destination, gateway = null, interface: interfaceName = null, source = null, metric = null }) {
  let normalizedDestination;
  try {
    normalizedDestination = parseIPv4Network(destination).cidr;
  } catch {
    return null;
  }
  let normalizedGateway = null;
  if (gateway && gateway !== "0.0.0.0" && !/^on-link$/i.test(gateway)) {
    try {
      normalizedGateway = intToIPv4(parseIPv4(gateway));
    } catch {
      normalizedGateway = null;
    }
  }
  let normalizedSource = null;
  if (source) {
    try {
      normalizedSource = intToIPv4(parseIPv4(source));
    } catch {
      normalizedSource = null;
    }
  }
  return {
    destination: normalizedDestination,
    gateway: normalizedGateway,
    interface: interfaceName || null,
    source: normalizedSource,
    metric: metric != null && metric !== "" && Number.isFinite(Number(metric)) ? Number(metric) : null,
    is_default: normalizedDestination === "0.0.0.0/0",
  };
}

export function parseLinuxRoutes(raw) {
  const routes = [];
  for (const line of String(raw ?? "").split(/\r?\n/)) {
    const fields = line.trim().split(/\s+/);
    if (!fields[0]) continue;
    const destination = fields[0] === "default" ? "0.0.0.0/0" : fields[0];
    const valueAfter = (token) => {
      const index = fields.indexOf(token);
      return index >= 0 ? fields[index + 1] : null;
    };
    const route = normalizeRoute({
      destination,
      gateway: valueAfter("via"),
      interface: valueAfter("dev"),
      source: valueAfter("src"),
      metric: valueAfter("metric"),
    });
    if (route) routes.push(route);
  }
  return routes;
}

export function parseLegacyLinuxRoutes(raw) {
  const routes = [];
  const lines = String(raw ?? "").split(/\r?\n/);
  const headerIndex = lines.findIndex((line) => /^\s*Destination\s+Gateway\s+Genmask\b/i.test(line));
  if (headerIndex < 0) return routes;
  const header = lines[headerIndex].trim().split(/\s+/);
  const destinationIndex = header.findIndex((value) => /^Destination$/i.test(value));
  const gatewayIndex = header.findIndex((value) => /^Gateway$/i.test(value));
  const netmaskIndex = header.findIndex((value) => /^Genmask$/i.test(value));
  const metricIndex = header.findIndex((value) => /^Metric$/i.test(value));
  const interfaceIndex = header.findIndex((value) => /^(Iface|If)$/i.test(value));
  if ([destinationIndex, gatewayIndex, netmaskIndex].some((index) => index < 0)) return routes;

  for (const line of lines.slice(headerIndex + 1)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < header.length || !fields[destinationIndex]) continue;
    try {
      const destination = networkFromAddressAndNetmask(fields[destinationIndex], fields[netmaskIndex]).cidr;
      const route = normalizeRoute({
        destination,
        gateway: fields[gatewayIndex],
        interface: interfaceIndex >= 0 ? fields[interfaceIndex] : null,
        metric: metricIndex >= 0 ? fields[metricIndex] : null,
      });
      if (route) routes.push(route);
    } catch {
      // Skip malformed legacy route rows.
    }
  }
  return routes;
}

export function parseWindowsRoutes(raw) {
  const routes = [];
  const pattern = /^\s*((?:\d{1,3}\.){3}\d{1,3})\s+((?:\d{1,3}\.){3}\d{1,3})\s+(\S+)\s+((?:\d{1,3}\.){3}\d{1,3})\s+(\d+)\s*$/;
  for (const line of String(raw ?? "").split(/\r?\n/)) {
    const match = pattern.exec(line);
    if (!match) continue;
    try {
      const destination = networkFromAddressAndNetmask(match[1], match[2]).cidr;
      const route = normalizeRoute({
        destination,
        gateway: match[3],
        source: match[4],
        metric: match[5],
      });
      if (route) routes.push(route);
    } catch {
      // Skip malformed route rows.
    }
  }
  return routes;
}

function normalizeDarwinDestination(value) {
  if (value === "default") return "0.0.0.0/0";
  const match = /^((?:\d{1,3}\.){0,3}\d{1,3})(?:\/(\d{1,2}))?$/.exec(value);
  if (!match) return value;
  const octets = match[1].split(".");
  const expanded = `${match[1]}${".0".repeat(4 - octets.length)}`;
  const prefix = match[2] ?? (octets.length < 4 ? String(octets.length * 8) : "32");
  return `${expanded}/${prefix}`;
}

export function parseDarwinRoutes(raw) {
  const routes = [];
  const lines = String(raw ?? "").split(/\r?\n/);
  const headerLine = lines.find((line) => /^\s*Destination\s+Gateway\b/.test(line));
  const header = headerLine?.trim().split(/\s+/) ?? [];
  const interfaceIndex = header.findIndex((value) => value === "Netif");
  for (const line of lines) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 4 || fields[0] === "Destination" || fields[0] === "Routing") continue;
    const destination = normalizeDarwinDestination(fields[0]);
    const gateway = fields[1].startsWith("link#") ? null : fields[1];
    const interfaceName = interfaceIndex >= 0 && fields[interfaceIndex]
      ? fields[interfaceIndex]
      : fields.findLast((field) => /^(?:en|bridge|utun|awdl|llw|lo|gif|stf|pdp_ip|ap)\d+$/.test(field)) ?? null;
    const route = normalizeRoute({ destination, gateway, interface: interfaceName });
    if (route) routes.push(route);
  }
  return routes;
}

export async function routeInventory({ platform = process.platform, execFn = execFileResult } = {}) {
  const candidates = platform === "win32"
    ? [["route", ["print", "-4"], parseWindowsRoutes]]
    : platform === "darwin"
      ? [["netstat", ["-rn", "-f", "inet"], parseDarwinRoutes]]
      : [["ip", ["-4", "route", "show"], parseLinuxRoutes], ["route", ["-n"], parseLegacyLinuxRoutes]];
  for (const [command, args, parser] of candidates) {
    const { error, stdout } = await execFn(command, args, { timeout: 3000, maxBuffer: 1024 * 1024 });
    if (!error && stdout) {
      const parsed = parser(stdout);
      if (parsed.length) return parsed;
    }
  }
  return [];
}

function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const error = new Error("Operation timed out.");
    error.code = "ETIMEDOUT";
    const timer = setTimeout(() => reject(error), Math.max(1, ms));
    timer.unref?.();
    Promise.resolve(promise).then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (reason) => {
        clearTimeout(timer);
        reject(reason);
      },
    );
  });
}

function withAbort(promise, signal) {
  if (!signal) return Promise.resolve(promise);
  if (signal.aborted) return Promise.reject(abortError());
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(abortError());
    signal.addEventListener("abort", onAbort, { once: true });
    Promise.resolve(promise).then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

function abortError() {
  const error = new Error("Scan cancelled.");
  error.name = "AbortError";
  return error;
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw abortError();
}

async function mapLimit(items, requestedLimit, cap, worker, { signal } = {}) {
  if (!Number.isInteger(requestedLimit) || requestedLimit < 1) throw new RangeError("workers must be at least 1.");
  const limit = Math.max(1, Math.min(requestedLimit, cap, Math.max(1, items.length)));
  let nextIndex = 0;
  const runners = Array.from({ length: limit }, async () => {
    while (true) {
      throwIfAborted(signal);
      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) return;
      await worker(items[index], index);
    }
  });
  await Promise.all(runners);
}

async function mapIndex(total, requestedLimit, cap, worker, { signal } = {}) {
  if (!Number.isSafeInteger(total) || total < 0) throw new RangeError("total work must be a non-negative safe integer.");
  if (!total) return;
  if (!Number.isInteger(requestedLimit) || requestedLimit < 1) throw new RangeError("workers must be at least 1.");
  const limit = Math.max(1, Math.min(requestedLimit, cap, total));
  let nextIndex = 0;
  const runners = Array.from({ length: limit }, async () => {
    while (true) {
      throwIfAborted(signal);
      const index = nextIndex;
      nextIndex += 1;
      if (index >= total) return;
      await worker(index);
    }
  });
  await Promise.all(runners);
}

function createProgressReporter(callback) {
  if (typeof callback !== "function") return () => {};
  let lastTime = 0;
  let lastCompleted = -1;
  return (phase, completed, total, message, force = false) => {
    const now = performance.now();
    const stride = Math.max(1, Math.floor(Math.max(1, total) / 500));
    if (!force && completed !== total && completed - lastCompleted < stride && now - lastTime < 200) return;
    lastTime = now;
    lastCompleted = completed;
    try {
      callback({ phase, completed, total, percent: total ? Math.min(100, round(completed / total * 100, 1)) : 0, message });
    } catch {
      // Progress reporting must never interrupt a scan.
    }
  };
}

export async function resolveHostnames(
  ips,
  { workers = 12, totalTimeoutMs = DNS_LOOKUP_BUDGET_MS, reverseFn = (ip) => dns.reverse(ip), signal } = {},
) {
  if (!Array.isArray(ips)) throw new TypeError("IP addresses must be provided as a list.");
  if (!Number.isFinite(totalTimeoutMs) || totalTimeoutMs < 0) {
    throw new RangeError("totalTimeoutMs cannot be negative.");
  }
  const names = Object.fromEntries(ips.map((ip) => [ip, null]));
  let timedOut = 0;
  const deadline = performance.now() + totalTimeoutMs;
  await mapLimit(ips, workers, MAX_COMMAND_WORKERS, async (ip) => {
    const remaining = deadline - performance.now();
    if (remaining <= 0) {
      timedOut += 1;
      return;
    }
    try {
      const result = await withTimeout(withAbort(Promise.resolve(reverseFn(ip)), signal), Math.min(1000, remaining));
      names[ip] = Array.isArray(result) && result.length ? result[0] : null;
    } catch (error) {
      if (error?.name === "AbortError") throw error;
      if (error?.code === "ETIMEDOUT") timedOut += 1;
    }
  }, { signal });
  return { names, timedOut };
}

export function checkPort(ip, port, timeoutMs = 260, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError());
      return;
    }
    const socket = net.createConnection({ host: ip, port });
    let settled = false;
    const onAbort = () => finish(null, abortError());
    const finish = (isOpen, error = null) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", onAbort);
      socket.destroy();
      if (error) reject(error);
      else resolve(isOpen);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    socket.setTimeout(Math.max(50, timeoutMs));
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
  });
}

function interfacesForTarget(target, interfaces) {
  return interfaces.filter((item) => {
    try {
      return networkIsSubnetOf(target, parseIPv4Network(item.network));
    } catch {
      return false;
    }
  });
}

export function buildNetworkContext(target, interfaces, routes = [], dnsServers = []) {
  const candidateInterfaces = interfacesForTarget(target, interfaces);
  const defaultRoutes = routes
    .filter((route) => route?.is_default && route.gateway)
    .sort((left, right) => (left.metric ?? Number.MAX_SAFE_INTEGER) - (right.metric ?? Number.MAX_SAFE_INTEGER));
  const targetRoutes = routes
    .filter((route) => {
      if (!route || route.is_default || !route.destination) return false;
      try {
        return networkIsSubnetOf(target, parseIPv4Network(route.destination));
      } catch {
        return false;
      }
    })
    .sort((left, right) => {
      const prefixDifference = parseIPv4Network(right.destination).prefix - parseIPv4Network(left.destination).prefix;
      return prefixDifference || (left.metric ?? Number.MAX_SAFE_INTEGER) - (right.metric ?? Number.MAX_SAFE_INTEGER);
    });
  const routeInsideTarget = defaultRoutes.find((route) => {
    try {
      return networkContainsIPv4(target, route.gateway);
    } catch {
      return false;
    }
  });
  const routeForTarget = targetRoutes.find((route) => candidateInterfaces.some((item) =>
    route.source === item.address || route.interface === item.interface
  ));
  const interfaceRoute = routeForTarget ?? routeInsideTarget;
  const selectedInterface = candidateInterfaces.find((item) =>
    interfaceRoute?.source === item.address || interfaceRoute?.interface === item.interface
  ) ?? candidateInterfaces[0] ?? null;
  const matchingDefault = defaultRoutes.find((route) =>
    selectedInterface && (route.interface === selectedInterface.interface || route.source === selectedInterface.address)
  ) ?? routeInsideTarget ?? null;

  const normalizedDns = [];
  for (const server of dnsServers ?? []) {
    try {
      normalizedDns.push(intToIPv4(parseIPv4(server)));
    } catch {
      // The dashboard is IPv4-only, so omit IPv6 resolver addresses.
    }
  }

  return {
    cidr: target.cidr,
    network_address: intToIPv4(target.networkInt),
    broadcast_address: intToIPv4(target.broadcastInt),
    prefix: target.prefix,
    interface: selectedInterface?.interface ?? null,
    interface_kind: selectedInterface?.kind ?? null,
    local_address: selectedInterface?.address ?? null,
    local_mac: selectedInterface?.mac ?? null,
    gateway: matchingDefault?.gateway ?? null,
    gateway_metric: matchingDefault?.metric ?? null,
    dns_servers: [...new Set(normalizedDns)],
    route_count: routes.length,
  };
}

function hasAnyPort(openPorts, values) {
  const set = new Set(openPorts.map((item) => item.port));
  return values.some((port) => set.has(port));
}

export function classifyDevice(device) {
  const ports = Array.isArray(device.open_ports) ? device.open_ports : [];
  const hostname = String(device.hostname ?? "").toLowerCase();
  const role = (key, label, category, reason) => ({ key, label, category, reason });

  if (device.is_host) return role("host", "Host PC", "infrastructure", "Local interface address");
  if (device.is_gateway) return role("gateway", "Gateway", "infrastructure", "Default route next hop");
  if (hasAnyPort(ports, [631, 9100]) || /(printer|laserjet|officejet|epson|brother)/.test(hostname)) {
    return role("printer", "Printer", "peripherals", "Printing service or hostname");
  }
  if (hasAnyPort(ports, [445]) && hasAnyPort(ports, [80, 443, 8080, 8443])) {
    return role("nas", "NAS / file server", "servers", "File sharing and web management services");
  }
  if (hasAnyPort(ports, [53]) && hasAnyPort(ports, [80, 443, 8080, 8443])) {
    return role("network-appliance", "Network appliance", "infrastructure", "DNS and web management services");
  }
  if (/(router|gateway|firewall|switch|access[- ]?point|\bap\b)/.test(hostname)) {
    return role("network-appliance", "Network appliance", "infrastructure", "Infrastructure-style hostname");
  }
  if (hasAnyPort(ports, [3389])) return role("windows", "Windows endpoint", "endpoints", "Remote Desktop service");
  if (hasAnyPort(ports, [22]) && hasAnyPort(ports, [80, 443, 8080, 8443])) {
    return role("server", "Server", "servers", "SSH and web services");
  }
  if (hasAnyPort(ports, [22])) return role("ssh-host", "SSH host", "servers", "SSH service");
  if (hasAnyPort(ports, [80, 443, 8080, 8443])) return role("web-device", "Web device", "servers", "Web service");
  if (hasAnyPort(ports, [445])) return role("file-host", "File-sharing host", "servers", "SMB service");
  if (/(camera|cam\b|doorbell|thermostat|sensor|iot)/.test(hostname)) {
    return role("iot", "IoT device", "peripherals", "Device-style hostname");
  }
  if (/(iphone|ipad|android|phone|tablet|laptop|desktop|workstation)/.test(hostname)) {
    return role("endpoint", "Endpoint", "endpoints", "Endpoint-style hostname");
  }
  if (device.evidence?.includes("tcp")) return role("service-host", "Service host", "servers", "Reachable selected TCP service");
  return role("device", "Network device", "unknown", "Insufficient evidence for a narrower role");
}

function comparePortSets(left, right) {
  const normalize = (items) => new Set((items ?? []).map((item) => Number(item.port)).filter(Number.isInteger));
  const leftSet = normalize(left);
  const rightSet = normalize(right);
  return leftSet.size === rightSet.size && [...leftSet].every((port) => rightSet.has(port));
}

export function compareResults(current, previous) {
  if (!previous || previous.target !== current.target || !Array.isArray(previous.devices)) {
    return {
      comparable: false,
      new_devices: [],
      missing_devices: [],
      changed_services: [],
      counts: { new: 0, missing: 0, changed: 0 },
    };
  }
  const currentByIp = new Map(current.devices.map((device) => [device.ip, device]));
  const previousByIp = new Map(previous.devices.map((device) => [device.ip, device]));
  const newDevices = current.devices.filter((device) => !previousByIp.has(device.ip)).map((device) => ({
    ip: device.ip,
    hostname: device.hostname,
    role: device.role,
  }));
  const missingDevices = previous.devices.filter((device) => !device.is_host && !currentByIp.has(device.ip)).map((device) => ({
    ip: device.ip,
    hostname: device.hostname,
    role: device.role,
  }));
  const changedServices = [];
  for (const device of current.devices) {
    const oldDevice = previousByIp.get(device.ip);
    if (!oldDevice || comparePortSets(device.open_ports, oldDevice.open_ports)) continue;
    changedServices.push({
      ip: device.ip,
      hostname: device.hostname,
      before: oldDevice.open_ports ?? [],
      after: device.open_ports ?? [],
    });
  }
  return {
    comparable: true,
    baseline_generated_at: previous.generated_at ?? null,
    new_devices: newDevices,
    missing_devices: missingDevices,
    changed_services: changedServices,
    counts: { new: newDevices.length, missing: missingDevices.length, changed: changedServices.length },
  };
}

export function buildTopology(network, devices) {
  const nodes = [];
  const edges = [];
  const networkId = `network:${network.cidr}`;
  const gatewayDevice = network.gateway ? devices.find((device) => device.ip === network.gateway) : null;

  if (network.gateway) {
    nodes.push({ id: "internet", type: "internet", label: "Internet", subtitle: "Default route" });
    const gatewayId = `device:${network.gateway}`;
    nodes.push({
      id: gatewayId,
      type: "gateway",
      label: gatewayDevice?.hostname || "Gateway",
      subtitle: network.gateway,
      observed: Boolean(gatewayDevice),
      device_ip: network.gateway,
      role: gatewayDevice?.role ?? { key: "gateway", label: "Gateway", category: "infrastructure" },
    });
    edges.push({ source: "internet", target: gatewayId, type: "route", label: "default route" });
    edges.push({ source: gatewayId, target: networkId, type: "gateway", label: "routes to" });
  }

  nodes.push({
    id: networkId,
    type: "network",
    label: network.cidr,
    subtitle: [network.interface, `${devices.length} observed`].filter(Boolean).join(" · "),
  });

  for (const device of devices) {
    if (network.gateway && device.ip === network.gateway) continue;
    const deviceId = `device:${device.ip}`;
    nodes.push({
      id: deviceId,
      type: "device",
      label: device.hostname || device.ip,
      subtitle: device.ip,
      device_ip: device.ip,
      role: device.role,
      state: device.state,
      is_host: device.is_host,
      evidence: device.evidence,
    });
    edges.push({ source: networkId, target: deviceId, type: "membership", label: "on subnet" });
  }

  return {
    kind: "logical-observed",
    disclaimer: "Logical topology derived from local interfaces, the default route, neighbor entries, ICMP responses, and selected TCP services. It does not claim physical switch-port relationships.",
    nodes,
    edges,
  };
}

function summarize(result) {
  return {
    device_count: result.devices.length,
    responsive_count: result.devices.filter((device) => device.evidence.includes("icmp")).length,
    tcp_evidence_count: result.devices.filter((device) => device.evidence.includes("tcp")).length,
    tcp_discovered_count: result.devices.filter((device) => device.state === "service").length,
    neighbor_only_count: result.devices.filter((device) => device.state === "neighbor").length,
    open_service_count: result.devices.reduce((sum, device) => sum + device.open_ports.length, 0),
    gateway_count: result.devices.filter((device) => device.is_gateway).length,
    ipv6_interface_count: result.ipv6?.interfaces?.length ?? 0,
    ipv6_neighbor_count: result.ipv6?.neighbors?.length ?? 0,
  };
}

export async function scanNetwork(targetValue, options = {}) {
  const {
    ports = DEFAULT_PORTS,
    portMode = "selected",
    extendedAddressScan = false,
    workers,
    pingWorkers = workers ?? Math.max(4, Math.min(16, (os.availableParallelism?.() ?? 4) * 2)),
    socketWorkers = workers ?? 64,
    fullPortWorkers = workers ?? 128,
    pingTimeoutMs = 700,
    portTimeoutMs = 260,
    fullPortTimeoutMs = 220,
    interfaces: suppliedInterfaces,
    ipv6Interfaces: suppliedIpv6Interfaces,
    excludedCidrs = [],
    excludedIps = [],
    excludedMacs = [],
    pingFn = ping,
    neighborTableFn = neighborTable,
    ipv6NeighborTableFn = ipv6NeighborTable,
    resolveHostnamesFn = resolveHostnames,
    checkPortFn = checkPort,
    routeInventoryFn = routeInventory,
    dnsServersFn = () => dns.getServers(),
    hostInventoryFn = hostInventory,
    pingAvailable = commandExists("ping"),
    previousResult = null,
    signal,
    onProgress,
  } = options;
  if (!["selected", "all"].includes(portMode)) throw new RangeError("portMode must be selected or all.");
  if (!Number.isFinite(pingTimeoutMs) || pingTimeoutMs <= 0) throw new RangeError("pingTimeoutMs must be greater than zero.");
  if (!Number.isFinite(portTimeoutMs) || portTimeoutMs <= 0) throw new RangeError("portTimeoutMs must be greater than zero.");
  if (!Number.isFinite(fullPortTimeoutMs) || fullPortTimeoutMs <= 0) throw new RangeError("fullPortTimeoutMs must be greater than zero.");

  throwIfAborted(signal);
  const report = createProgressReporter(onProgress);
  const started = performance.now();
  const warnings = [];
  const interfaces = suppliedInterfaces ?? interfaceInventory();
  const ipv6Interfaces = suppliedIpv6Interfaces ?? ipv6InterfaceInventory();
  const maxAddresses = extendedAddressScan ? MAX_EXTENDED_TARGET_ADDRESSES : MAX_TARGET_ADDRESSES;
  const target = validateLocalTarget(parseIPv4Network(targetValue), attachedNetworks(interfaces), { maxAddresses });
  const selectedPorts = normalizePorts(ports);
  const ownIps = new Set(interfaces.map((item) => item.address));
  const exclusionNetworks = [];
  for (const value of excludedCidrs) exclusionNetworks.push(parseIPv4Network(String(value)));
  for (const value of excludedIps) exclusionNetworks.push(parseIPv4Network(`${String(value)}/32`));
  const excludedMacSet = new Set(excludedMacs.map(normalizedMac).filter(Boolean));
  const allHosts = hostsInNetwork(target);
  const hosts = allHosts.filter((ip) => !exclusionNetworks.some((network) => networkContainsIPv4(network, ip)));
  const candidateSet = new Set(hosts);
  const pingResults = Object.fromEntries(hosts.map((ip) => [ip, { responded: false, latencyMs: null }]));
  const openPorts = Object.fromEntries(hosts.map((ip) => [ip, []]));
  const openPortSets = Object.fromEntries(hosts.map((ip) => [ip, new Set()]));

  if (allHosts.length !== hosts.length) warnings.push(`Skipped ${allHosts.length - hosts.length} excluded IPv4 address${allHosts.length - hosts.length === 1 ? "" : "es"}.`);
  const discoveryTotal = (pingAvailable ? hosts.length : 0) + hosts.length * selectedPorts.length;
  let discoveryCompleted = 0;
  report("discovery", 0, discoveryTotal, `Discovering ${hosts.length} usable address${hosts.length === 1 ? "" : "es"}.`, true);
  const markDiscovery = () => {
    discoveryCompleted += 1;
    report("discovery", discoveryCompleted, discoveryTotal, `Discovering devices across ${target.cidr}.`);
  };

  const routePromise = Promise.resolve().then(() => routeInventoryFn()).catch(() => []);
  const ipv6Promise = Promise.resolve().then(() => ipv6NeighborTableFn()).catch(() => []);
  const pingPromise = !pingAvailable ? Promise.resolve() : mapLimit(hosts, pingWorkers, MAX_COMMAND_WORKERS, async (ip) => {
    try {
      pingResults[ip] = await pingFn(ip, pingTimeoutMs);
    } catch (error) {
      if (error?.name === "AbortError") throw error;
      pingResults[ip] = { responded: false, latencyMs: null };
    } finally {
      markDiscovery();
    }
  }, { signal });
  if (!pingAvailable) warnings.push("The system ping command was not found; discovery used neighbor and TCP evidence instead.");

  let portPromise = Promise.resolve();
  if (selectedPorts.length) {
    const taskCount = hosts.length * selectedPorts.length;
    portPromise = mapIndex(taskCount, socketWorkers, MAX_SOCKET_WORKERS, async (index) => {
      const ip = hosts[Math.floor(index / selectedPorts.length)];
      const port = selectedPorts[index % selectedPorts.length];
      try {
        if (await checkPortFn(ip, port, portTimeoutMs, signal)) {
          openPortSets[ip].add(port);
        }
      } catch (error) {
        if (error?.name === "AbortError") throw error;
        // A failed service check is treated as closed or unreachable.
      } finally {
        markDiscovery();
      }
    }, { signal });
  } else {
    warnings.push("No TCP discovery services were selected, so devices that block ICMP may remain hidden unless they appear in the neighbor table.");
  }

  await Promise.all([pingPromise, portPromise]);
  report("discovery", discoveryTotal, discoveryTotal, "Initial discovery complete.", true);
  throwIfAborted(signal);

  const [neighbors, routes, ipv6Neighbors] = await Promise.all([
    Promise.resolve(neighborTableFn()).catch(() => ({})),
    routePromise,
    ipv6Promise,
  ]);
  let dnsServers = [];
  try {
    dnsServers = dnsServersFn();
  } catch {
    dnsServers = [];
  }
  const network = buildNetworkContext(target, interfaces, Array.isArray(routes) ? routes : [], dnsServers);
  if (!network.gateway) warnings.push("The default gateway could not be identified from the local IPv4 route table.");

  const discovered = new Set();
  for (const [ip, result] of Object.entries(pingResults)) if (result.responded) discovered.add(ip);
  for (const ip of Object.keys(neighbors ?? {})) if (candidateSet.has(ip)) discovered.add(ip);
  for (const [ip, portsForIp] of Object.entries(openPortSets)) if (portsForIp.size) discovered.add(ip);
  for (const ip of ownIps) if (networkContainsIPv4(target, ip)) discovered.add(ip);
  const sortedIps = [...discovered]
    .filter((ip) => !excludedMacSet.has(normalizedMac(neighbors?.[ip])))
    .sort((left, right) => parseIPv4(left) - parseIPv4(right));

  if (portMode === "all" && sortedIps.length) {
    if (sortedIps.length > MAX_DEEP_SCAN_HOSTS) {
      throw new TargetRejected(`All-port mode found ${sortedIps.length} devices; reduce the target so no more than ${MAX_DEEP_SCAN_HOSTS} observed devices are scanned deeply.`);
    }
    const deepTotal = sortedIps.length * FULL_TCP_PORT_COUNT;
    let deepCompleted = 0;
    const deepProgressStride = Math.max(1, Math.floor(deepTotal / 500));
    report("ports", 0, deepTotal, `Checking all TCP ports on ${sortedIps.length} observed device${sortedIps.length === 1 ? "" : "s"}.`, true);
    await mapIndex(deepTotal, fullPortWorkers, 256, async (index) => {
      const ip = sortedIps[Math.floor(index / FULL_TCP_PORT_COUNT)];
      const port = index % FULL_TCP_PORT_COUNT + 1;
      try {
        if (!openPortSets[ip].has(port) && await checkPortFn(ip, port, fullPortTimeoutMs, signal)) {
          openPortSets[ip].add(port);
        }
      } catch (error) {
        if (error?.name === "AbortError") throw error;
      } finally {
        deepCompleted += 1;
        if (deepCompleted === deepTotal || deepCompleted % deepProgressStride === 0) {
          report("ports", deepCompleted, deepTotal, `Checking ports 1–65,535 on observed devices.`);
        }
      }
    }, { signal });
    report("ports", deepTotal, deepTotal, "Full TCP port scan complete.", true);
  }

  for (const ip of hosts) {
    openPorts[ip] = [...openPortSets[ip]].sort((left, right) => left - right).map((port) => ({
      port,
      service: PORT_NAMES[port] ?? "TCP",
    }));
  }

  throwIfAborted(signal);
  report("names", 0, sortedIps.length, "Resolving device names.", true);
  let names = Object.fromEntries(sortedIps.map((ip) => [ip, null]));
  let timedOut = 0;
  try {
    const resolved = await resolveHostnamesFn(sortedIps, { signal });
    if (resolved?.names && typeof resolved.names === "object") names = resolved.names;
    if (Number.isInteger(resolved?.timedOut) && resolved.timedOut > 0) timedOut = resolved.timedOut;
  } catch (error) {
    if (error?.name === "AbortError") throw error;
    warnings.push("Reverse-DNS lookup failed; IP and service evidence are still available.");
  }
  if (timedOut) warnings.push(`Skipped ${timedOut} slow reverse-DNS lookup${timedOut === 1 ? "" : "s"} to keep the scan responsive.`);
  report("names", sortedIps.length, sortedIps.length, "Device names resolved.", true);
  throwIfAborted(signal);

  const devices = sortedIps.map((ip) => {
    const isHost = ownIps.has(ip);
    const isGateway = ip === network.gateway;
    const evidence = [];
    if (isHost) evidence.push("local");
    if (pingResults[ip]?.responded) evidence.push("icmp");
    if (neighbors?.[ip]) evidence.push("neighbor");
    if (openPorts[ip]?.length) evidence.push("tcp");
    const state = isHost || pingResults[ip]?.responded ? "up" : openPorts[ip]?.length ? "service" : "neighbor";
    const device = {
      ip,
      hostname: names[ip] ?? null,
      mac: neighbors?.[ip] ?? null,
      state,
      latency_ms: pingResults[ip]?.latencyMs ?? null,
      open_ports: openPorts[ip] ?? [],
      is_host: isHost,
      is_gateway: isGateway,
      evidence,
    };
    device.role = classifyDevice(device);
    return device;
  });

  if (!devices.length) warnings.push("No devices produced ICMP, neighbor, or selected TCP evidence. Some managed networks suppress all three forms of local observation.");

  const result = {
    generated_at: new Date().toISOString(),
    duration_seconds: round((performance.now() - started) / 1000),
    target: target.cidr,
    host: hostInventoryFn(interfaces, ipv6Interfaces),
    network,
    ipv6: {
      mode: "passive",
      interfaces: ipv6Interfaces,
      neighbors: Array.isArray(ipv6Neighbors) ? ipv6Neighbors : [],
    },
    devices,
    warnings,
    scan_options: {
      ports: selectedPorts,
      port_mode: portMode,
      address_mode: extendedAddressScan ? "extended" : "standard",
      usable_address_count: allHosts.length,
      scanned_address_count: hosts.length,
      excluded_address_count: allHosts.length - hosts.length,
      ping_timeout_ms: pingTimeoutMs,
      port_timeout_ms: portTimeoutMs,
      full_port_timeout_ms: portMode === "all" ? fullPortTimeoutMs : null,
    },
  };
  result.summary = summarize(result);
  result.changes = compareResults(result, previousResult);
  result.topology = buildTopology(network, devices);
  report("complete", 1, 1, `Observed ${devices.length} device${devices.length === 1 ? "" : "s"}.`, true);
  return result;
}

function validOpenPorts(value) {
  if (!Array.isArray(value) || value.length > FULL_TCP_PORT_COUNT) return false;
  const seen = new Set();
  return value.every((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return false;
    if (!Number.isInteger(item.port) || item.port < 1 || item.port > 65535 || seen.has(item.port)) return false;
    if (item.service != null && (typeof item.service !== "string" || item.service.length > 64)) return false;
    seen.add(item.port);
    return true;
  });
}

function validOptionalText(value, limit) {
  return value == null || typeof value === "string" && value.length <= limit;
}

function hasOnlyKeys(value, allowedKeys) {
  return Object.keys(value).every((key) => allowedKeys.has(key));
}

function validOptionalNumber(value, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER, integer = false } = {}) {
  if (value == null) return true;
  return Number.isFinite(value) && value >= minimum && value <= maximum && (!integer || Number.isInteger(value));
}

function validCanonicalIPv4(value) {
  if (typeof value !== "string") return false;
  try {
    return intToIPv4(parseIPv4(value)) === value;
  } catch {
    return false;
  }
}

function validStringList(value, { maximumItems, maximumLength, allowedValues } = {}) {
  if (!Array.isArray(value) || value.length > maximumItems) return false;
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== "string" || item.length > maximumLength || seen.has(item)) return false;
    if (allowedValues && !allowedValues.has(item)) return false;
    seen.add(item);
  }
  return true;
}

function validRole(value) {
  if (value == null) return true;
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!hasOnlyKeys(value, new Set(["key", "label", "category", "reason"]))) return false;
  if (!validOptionalText(value.key, 64) || !validOptionalText(value.label, 128) || !validOptionalText(value.reason, 256)) return false;
  return value.category == null || ["infrastructure", "servers", "endpoints", "peripherals", "unknown"].includes(value.category);
}


function validIpv6Address(value) {
  return typeof value === "string" && net.isIP(String(value).split("%")[0]) === 6 && value.length <= 128;
}

function validIpv6Interface(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!hasOnlyKeys(value, new Set(["interface", "kind", "address", "cidr", "scope_id", "mac"]))) return false;
  if (!validOptionalText(value.interface, 128) || !validOptionalText(value.kind, 64) || !validIpv6Address(value.address)) return false;
  if (typeof value.cidr !== "string" || value.cidr.length > 160 || !/^.+\/(?:12[0-8]|1[01]\d|\d?\d)$/.test(value.cidr) || net.isIP(value.cidr.split("/")[0].split("%")[0]) !== 6) return false;
  if (!validOptionalNumber(value.scope_id, { minimum: 0, maximum: 0xffffffff, integer: true })) return false;
  return value.mac == null || normalizedMac(value.mac) === value.mac;
}

function validIpv6Context(value) {
  if (value == null) return true;
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!hasOnlyKeys(value, new Set(["mode", "interfaces", "neighbors"]))) return false;
  if (value.mode !== "passive") return false;
  if (!Array.isArray(value.interfaces) || value.interfaces.length > 256 || !value.interfaces.every(validIpv6Interface)) return false;
  if (!Array.isArray(value.neighbors) || value.neighbors.length > 4096) return false;
  const seen = new Set();
  return value.neighbors.every((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry) || !hasOnlyKeys(entry, new Set(["address", "mac", "interface", "state"]))) return false;
    if (!validIpv6Address(entry.address) || seen.has(entry.address)) return false;
    seen.add(entry.address);
    if (entry.mac != null && normalizedMac(entry.mac) !== entry.mac) return false;
    return validOptionalText(entry.interface, 128) && validOptionalText(entry.state, 64);
  });
}

function validHostInterface(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!hasOnlyKeys(value, new Set(["interface", "kind", "address", "netmask", "network", "mac"]))) return false;
  if (!validOptionalText(value.interface, 128) || !validOptionalText(value.kind, 64)) return false;
  if (value.address != null && !validCanonicalIPv4(value.address)) return false;
  if (value.netmask != null) {
    try {
      netmaskToPrefix(value.netmask);
    } catch {
      return false;
    }
  }
  if (value.network != null) {
    try {
      if (parseIPv4Network(value.network).cidr !== value.network) return false;
    } catch {
      return false;
    }
  }
  return value.mac == null || normalizedMac(value.mac) === value.mac;
}

function validTargetOption(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!hasOnlyKeys(value, new Set(["cidr", "interface", "kind", "address_count", "usable_address_count", "scope", "extended"]))) return false;
  try {
    if (parseIPv4Network(value.cidr).cidr !== value.cidr) return false;
  } catch {
    return false;
  }
  return validOptionalText(value.interface, 128) && validOptionalText(value.kind, 64) &&
    validOptionalNumber(value.address_count, { minimum: 1, maximum: 2 ** 32, integer: true }) &&
    validOptionalNumber(value.usable_address_count, { minimum: 0, maximum: 2 ** 32, integer: true }) &&
    (value.scope == null || ["local-segment", "full-subnet"].includes(value.scope)) &&
    (value.extended == null || typeof value.extended === "boolean");
}

function validHost(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const allowedKeys = new Set([
    "hostname", "fqdn", "os", "system", "release", "architecture", "processor", "boot_time",
    "cpu_logical", "cpu_physical", "memory_total_gb", "memory_used_percent", "disk_total_gb", "disk_used_percent",
    "interfaces", "ipv6_interfaces", "suggested_targets", "target_options",
  ]);
  if (!hasOnlyKeys(value, allowedKeys)) return false;
  for (const key of ["hostname", "fqdn", "os", "system", "release", "architecture", "processor"]) {
    if (!validOptionalText(value[key], key === "processor" ? 512 : 255)) return false;
  }
  if (value.boot_time != null && (typeof value.boot_time !== "string" || Number.isNaN(new Date(value.boot_time).getTime()))) return false;
  if (!validOptionalNumber(value.cpu_logical, { minimum: 0, maximum: 65536, integer: true }) ||
      !validOptionalNumber(value.cpu_physical, { minimum: 0, maximum: 65536, integer: true }) ||
      !validOptionalNumber(value.memory_total_gb, { maximum: 1_000_000 }) ||
      !validOptionalNumber(value.memory_used_percent, { maximum: 100 }) ||
      !validOptionalNumber(value.disk_total_gb, { maximum: 1_000_000_000 }) ||
      !validOptionalNumber(value.disk_used_percent, { maximum: 100 })) return false;
  if (value.interfaces != null && (!Array.isArray(value.interfaces) || value.interfaces.length > 256 || !value.interfaces.every(validHostInterface))) return false;
  if (value.ipv6_interfaces != null && (!Array.isArray(value.ipv6_interfaces) || value.ipv6_interfaces.length > 256 || !value.ipv6_interfaces.every(validIpv6Interface))) return false;
  if (value.suggested_targets != null) {
    if (!Array.isArray(value.suggested_targets) || value.suggested_targets.length > 256) return false;
    for (const cidr of value.suggested_targets) {
      try {
        if (parseIPv4Network(cidr).cidr !== cidr) return false;
      } catch {
        return false;
      }
    }
  }
  return value.target_options == null || Array.isArray(value.target_options) && value.target_options.length <= 256 && value.target_options.every(validTargetOption);
}

function validNetworkContext(value, target, host) {
  if (value == null) return true;
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!hasOnlyKeys(value, new Set([
    "cidr", "network_address", "broadcast_address", "prefix", "interface", "interface_kind", "local_address",
    "local_mac", "gateway", "gateway_metric", "dns_servers", "route_count",
  ]))) return false;
  if (value.cidr !== target.cidr || value.network_address !== intToIPv4(target.networkInt) || value.broadcast_address !== intToIPv4(target.broadcastInt) || value.prefix !== target.prefix) return false;
  if (!validOptionalText(value.interface, 128) || !validOptionalText(value.interface_kind, 64)) return false;
  if (value.local_address != null && (!validCanonicalIPv4(value.local_address) || !networkContainsIPv4(target, value.local_address))) return false;
  if (value.local_mac != null && normalizedMac(value.local_mac) !== value.local_mac) return false;
  if (value.gateway != null) {
    if (!validCanonicalIPv4(value.gateway)) return false;
    const insideTarget = networkContainsIPv4(target, value.gateway);
    const insideAttachedInterface = Array.isArray(host?.interfaces) && host.interfaces.some((item) => {
      try {
        return typeof item?.network === "string" && networkContainsIPv4(parseIPv4Network(item.network), value.gateway);
      } catch {
        return false;
      }
    });
    if (!insideTarget && !insideAttachedInterface) return false;
  }
  if (!validOptionalNumber(value.gateway_metric, { maximum: 1_000_000_000, integer: true }) || !validOptionalNumber(value.route_count, { maximum: 1_000_000, integer: true })) return false;
  return value.dns_servers == null || Array.isArray(value.dns_servers) && value.dns_servers.length <= 64 && value.dns_servers.every(validCanonicalIPv4);
}

function validSummary(value, deviceCount) {
  if (value == null) return true;
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = new Set([
    "device_count", "responsive_count", "tcp_evidence_count", "tcp_discovered_count", "neighbor_only_count",
    "open_service_count", "gateway_count", "ipv6_interface_count", "ipv6_neighbor_count",
  ]);
  if (!hasOnlyKeys(value, keys)) return false;
  for (const [key, number] of Object.entries(value)) {
    let maximum = deviceCount;
    if (key === "open_service_count") maximum = deviceCount * FULL_TCP_PORT_COUNT;
    else if (key === "ipv6_interface_count") maximum = 4096;
    else if (key === "ipv6_neighbor_count") maximum = MAX_EXTENDED_TARGET_ADDRESSES;
    if (!validOptionalNumber(number, { maximum, integer: true })) return false;
  }
  return value.device_count == null || value.device_count === deviceCount;
}

function validChanges(value, maximumDevices) {
  if (value == null) return true;
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!hasOnlyKeys(value, new Set(["comparable", "baseline_generated_at", "new_devices", "missing_devices", "changed_services", "counts"]))) return false;
  if (typeof value.comparable !== "boolean") return false;
  if (value.baseline_generated_at != null && (typeof value.baseline_generated_at !== "string" || Number.isNaN(new Date(value.baseline_generated_at).getTime()))) return false;
  for (const key of ["new_devices", "missing_devices", "changed_services"]) {
    if (!Array.isArray(value[key]) || value[key].length > maximumDevices) return false;
  }
  const identityValid = (item) => item && typeof item === "object" && !Array.isArray(item) &&
    validCanonicalIPv4(item.ip) && validOptionalText(item.hostname, 255) && validRole(item.role);
  if (!value.new_devices.every(identityValid) || !value.missing_devices.every(identityValid)) return false;
  if (!value.changed_services.every((item) => identityValid(item) && validOpenPorts(item.before ?? []) && validOpenPorts(item.after ?? []))) return false;
  if (!value.counts || typeof value.counts !== "object" || Array.isArray(value.counts) || !hasOnlyKeys(value.counts, new Set(["new", "missing", "changed"]))) return false;
  return ["new", "missing", "changed"].every((key) => validOptionalNumber(value.counts[key], { maximum: maximumDevices, integer: true }));
}

function validTopology(value, maximumDevices) {
  if (value == null) return true;
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!hasOnlyKeys(value, new Set(["kind", "disclaimer", "nodes", "edges"]))) return false;
  if (!validOptionalText(value.kind, 64) || !validOptionalText(value.disclaimer, 1000)) return false;
  if (!Array.isArray(value.nodes) || value.nodes.length > maximumDevices + 3 || !Array.isArray(value.edges) || value.edges.length > maximumDevices + 2) return false;
  const nodeKeys = new Set(["id", "type", "label", "subtitle", "observed", "device_ip", "role", "state", "is_host", "evidence"]);
  for (const node of value.nodes) {
    if (!node || typeof node !== "object" || Array.isArray(node) || !hasOnlyKeys(node, nodeKeys)) return false;
    if (!validOptionalText(node.id, 320) || !validOptionalText(node.type, 64) || !validOptionalText(node.label, 255) || !validOptionalText(node.subtitle, 512)) return false;
    if (node.observed != null && typeof node.observed !== "boolean" || node.is_host != null && typeof node.is_host !== "boolean") return false;
    if (node.device_ip != null && !validCanonicalIPv4(node.device_ip) || !validRole(node.role)) return false;
    if (node.evidence != null && !validStringList(node.evidence, { maximumItems: 4, maximumLength: 16, allowedValues: new Set(["local", "icmp", "neighbor", "tcp"]) })) return false;
  }
  const edgeKeys = new Set(["source", "target", "type", "label"]);
  return value.edges.every((edge) => edge && typeof edge === "object" && !Array.isArray(edge) && hasOnlyKeys(edge, edgeKeys) &&
    validOptionalText(edge.source, 320) && validOptionalText(edge.target, 320) && validOptionalText(edge.type, 64) && validOptionalText(edge.label, 128));
}

function validScanOptions(value) {
  if (value == null) return true;
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!hasOnlyKeys(value, new Set(["ports", "port_mode", "address_mode", "usable_address_count", "scanned_address_count", "excluded_address_count", "ping_timeout_ms", "port_timeout_ms", "full_port_timeout_ms"]))) return false;
  try {
    if (normalizePorts(value.ports ?? []).length !== (value.ports ?? []).length) return false;
  } catch {
    return false;
  }
  return ["selected", "all"].includes(value.port_mode) && ["standard", "extended"].includes(value.address_mode) &&
    validOptionalNumber(value.usable_address_count, { maximum: MAX_EXTENDED_TARGET_ADDRESSES, integer: true }) &&
    validOptionalNumber(value.scanned_address_count, { maximum: MAX_EXTENDED_TARGET_ADDRESSES, integer: true }) &&
    validOptionalNumber(value.excluded_address_count, { maximum: MAX_EXTENDED_TARGET_ADDRESSES, integer: true }) &&
    validOptionalNumber(value.ping_timeout_ms, { minimum: 1, maximum: 60_000 }) &&
    validOptionalNumber(value.port_timeout_ms, { minimum: 1, maximum: 60_000 }) &&
    validOptionalNumber(value.full_port_timeout_ms, { minimum: 1, maximum: 60_000 });
}

export function isValidResult(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return false;
  if (!hasOnlyKeys(payload, new Set(["generated_at", "duration_seconds", "target", "host", "network", "ipv6", "devices", "warnings", "scan_options", "summary", "changes", "topology"]))) return false;
  if (typeof payload.target !== "string" || typeof payload.generated_at !== "string") return false;
  if (!validHost(payload.host)) return false;
  if (!Array.isArray(payload.devices) || payload.devices.length > MAX_EXTENDED_TARGET_ADDRESSES) return false;
  let target;
  try {
    target = parseIPv4Network(payload.target);
    if (!isAllowedLocalNetwork(target) || target.numAddresses > MAX_EXTENDED_TARGET_ADDRESSES) return false;
    if (Number.isNaN(new Date(payload.generated_at).getTime())) return false;
  } catch {
    return false;
  }
  const seen = new Set();
  const allowedStates = new Set(["up", "service", "neighbor"]);
  const allowedEvidence = new Set(["local", "icmp", "neighbor", "tcp"]);
  if (!validOptionalNumber(payload.duration_seconds, { maximum: 31_536_000 })) return false;
  if (!validNetworkContext(payload.network, target, payload.host) || !validIpv6Context(payload.ipv6)) return false;
  if (payload.warnings != null && !validStringList(payload.warnings, { maximumItems: 100, maximumLength: 1000 })) return false;
  if (!validScanOptions(payload.scan_options) || !validSummary(payload.summary, payload.devices.length) ||
      !validChanges(payload.changes, payload.devices.length) || !validTopology(payload.topology, payload.devices.length)) return false;
  return payload.devices.every((device) => {
    if (!device || typeof device !== "object" || Array.isArray(device)) return false;
    if (!hasOnlyKeys(device, new Set(["ip", "hostname", "mac", "state", "latency_ms", "open_ports", "is_host", "is_gateway", "evidence", "role"]))) return false;
    try {
      if (!validCanonicalIPv4(device.ip) || !networkContainsIPv4(target, device.ip) || seen.has(device.ip)) return false;
      seen.add(device.ip);
    } catch {
      return false;
    }
    if (!validOptionalText(device.hostname, 255) || device.mac != null && normalizedMac(device.mac) !== device.mac) return false;
    if (device.state != null && !allowedStates.has(device.state)) return false;
    if (device.latency_ms != null && (!Number.isFinite(device.latency_ms) || device.latency_ms < 0)) return false;
    if (device.is_host != null && typeof device.is_host !== "boolean") return false;
    if (device.is_gateway != null && typeof device.is_gateway !== "boolean") return false;
    if (device.evidence != null && (!Array.isArray(device.evidence) || device.evidence.length > 4 ||
      new Set(device.evidence).size !== device.evidence.length || device.evidence.some((item) => !allowedEvidence.has(item)))) return false;
    return validRole(device.role) && validOpenPorts(device.open_ports ?? []);
  });
}

export function saveResult(result, filePath) {
  if (!isValidResult(result)) throw new TypeError("Refusing to save an invalid scan result.");
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temporary = `${filePath}.${process.pid}.tmp`;
  const serialized = `${JSON.stringify(result, null, 2)}\n`;
  if (Buffer.byteLength(serialized) > MAX_SAVED_RESULT_BYTES) throw new RangeError("Scan result is too large to save.");
  try {
    fs.writeFileSync(temporary, serialized, { encoding: "utf8", mode: 0o600, flag: "w" });
    try {
      fs.renameSync(temporary, filePath);
    } catch (error) {
      if (process.platform !== "win32") throw error;
      fs.rmSync(filePath, { force: true });
      fs.renameSync(temporary, filePath);
    }
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

export function loadResult(filePath) {
  try {
    const stats = fs.statSync(filePath);
    if (!stats.isFile() || stats.size <= 0 || stats.size > MAX_SAVED_RESULT_BYTES) return null;
    const payload = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return isValidResult(payload) ? payload : null;
  } catch {
    return null;
  }
}
