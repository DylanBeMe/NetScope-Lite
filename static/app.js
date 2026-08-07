const state = {
  host: null,
  latest: null,
  devices: [],
  defaultPorts: [],
  portNames: {},
  scanning: false,
  selectedDeviceIp: null,
  mapScale: 1,
  mapBaseWidth: 1200,
  mapBaseHeight: 760,
  pollTimer: null,
  mapAvailable: false,
  inventoryLimit: 60,
  scanProgress: null,
  pollFailures: 0,
  profiles: [],
  targetOptions: [],
  monitor: {},
  auth: { enabled: false, authenticated: true },
  schedules: [],
  exclusions: [],
  alerts: [],
  notificationHistory: [],
  history: [],
  selectedDeviceId: null,
  settings: {},
};

const $ = (selector) => document.querySelector(selector);
const INVENTORY_PAGE_SIZE = 60;
const MAX_TOPOLOGY_DEVICE_NODES = 480;
const DEFAULT_MAP_NOTE = "The map shows logical relationships inferred from local interfaces, routes, neighbor entries, ICMP, and selected TCP services. It does not claim physical switch-port connections.";
const STORAGE_PORTS = "netscope-selected-ports";
const STORAGE_TARGET = "netscope-selected-target";
const STORAGE_THEME = "netscope-theme";
const STORAGE_CUSTOM_THEME = "netscope-custom-theme";
const STORAGE_PORT_MODE = "netscope-port-mode";
const STORAGE_PROFILE = "netscope-profile";
const STORAGE_CUSTOM_PORTS = "netscope-custom-ports";
const STORAGE_SCAN_ALL = "netscope-scan-all-targets";
const STORAGE_THEME_SCHEDULE = "netscope-theme-schedule";
const STORAGE_NOTIFIED_ALERT_ID = "netscope-notified-alert-id";
const DEFAULT_CUSTOM_THEME = Object.freeze({ primary: "#8b5cf6", accent: "#c084fc", background: "#0d0718", surface: "#181126", text: "#f8f5ff" });
let customThemeMemory = { ...DEFAULT_CUSTOM_THEME };

function storageGet(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function storageSet(key, value) {
  try {
    window.localStorage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

function validHex(value) {
  return typeof value === "string" && /^#[0-9a-f]{6}$/i.test(value);
}

function hexRgb(value) {
  const hex = validHex(value) ? value.slice(1) : "000000";
  return [0, 2, 4].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16) / 255);
}

function relativeLuminance(value) {
  const channels = hexRgb(value).map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}

function contrastRatio(left, right) {
  const [lighter, darker] = [relativeLuminance(left), relativeLuminance(right)].sort((a, b) => b - a);
  return (lighter + 0.05) / (darker + 0.05);
}

function readableForeground(background) {
  return contrastRatio(background, "#ffffff") >= contrastRatio(background, "#000000") ? "#ffffff" : "#000000";
}

function normalizeCustomTheme(theme) {
  return Object.fromEntries(Object.entries(DEFAULT_CUSTOM_THEME).map(([key, fallback]) => [key, validHex(theme?.[key]) ? theme[key] : fallback]));
}

function readCustomTheme() {
  try {
    const stored = storageGet(STORAGE_CUSTOM_THEME);
    if (stored) customThemeMemory = normalizeCustomTheme(JSON.parse(stored));
  } catch {
    // Keep the in-memory palette when browser storage is blocked or malformed.
  }
  return { ...customThemeMemory };
}

function writeCustomTheme(theme) {
  customThemeMemory = normalizeCustomTheme(theme);
  storageSet(STORAGE_CUSTOM_THEME, JSON.stringify(customThemeMemory));
}

function clearCustomProperties() {
  for (const property of ["--bg", "--bg-deep", "--surface", "--surface-2", "--surface-3", "--panel", "--panel-soft", "--line", "--line-strong", "--text", "--muted", "--primary", "--primary-strong", "--accent", "--accent-2", "--success", "--warning", "--danger", "--focus", "--on-primary", "--glow-a", "--glow-b", "--grid-dot"]) {
    document.documentElement.style.removeProperty(property);
  }
  document.documentElement.style.removeProperty("color-scheme");
}

function updateCustomContrastStatus(theme) {
  const status = $("#custom-contrast");
  if (!status) return;
  const backgroundRatio = contrastRatio(theme.text, theme.background);
  const surfaceRatio = contrastRatio(theme.text, theme.surface);
  const lowest = Math.min(backgroundRatio, surfaceRatio);
  const good = lowest >= 4.5;
  status.className = `custom-contrast ${good ? "good" : "warning"}`;
  status.textContent = good
    ? `Text contrast is readable (${lowest.toFixed(1)}:1 minimum). Button text is adjusted automatically.`
    : `Low text contrast (${lowest.toFixed(1)}:1 minimum). Aim for at least 4.5:1 by changing Text, Background, or Surface.`;
}

function applyCustomTheme(theme) {
  const root = document.documentElement.style;
  root.setProperty("--bg", theme.background);
  root.setProperty("--bg-deep", `color-mix(in srgb, ${theme.background} 72%, black)`);
  root.setProperty("--surface", theme.surface);
  root.setProperty("--surface-2", `color-mix(in srgb, ${theme.surface} 86%, ${theme.background})`);
  root.setProperty("--surface-3", `color-mix(in srgb, ${theme.surface} 82%, ${theme.primary})`);
  root.setProperty("--panel", `color-mix(in srgb, ${theme.surface} 92%, transparent)`);
  root.setProperty("--panel-soft", `color-mix(in srgb, ${theme.surface} 72%, transparent)`);
  root.setProperty("--line", `color-mix(in srgb, ${theme.accent} 25%, transparent)`);
  root.setProperty("--line-strong", `color-mix(in srgb, ${theme.accent} 48%, transparent)`);
  root.setProperty("--text", theme.text);
  root.setProperty("--muted", `color-mix(in srgb, ${theme.text} 68%, ${theme.background})`);
  root.setProperty("--primary", theme.primary);
  root.setProperty("--primary-strong", `color-mix(in srgb, ${theme.primary} 78%, black)`);
  root.setProperty("--accent", theme.accent);
  root.setProperty("--accent-2", `color-mix(in srgb, ${theme.accent} 65%, ${theme.text})`);
  root.setProperty("--success", "#6ee7b7");
  root.setProperty("--warning", "#fcd34d");
  root.setProperty("--danger", "#fb7185");
  root.setProperty("--focus", theme.text);
  root.setProperty("--on-primary", readableForeground(theme.primary));
  root.setProperty("--glow-a", `color-mix(in srgb, ${theme.primary} 22%, transparent)`);
  root.setProperty("--glow-b", `color-mix(in srgb, ${theme.accent} 13%, transparent)`);
  root.setProperty("--grid-dot", `color-mix(in srgb, ${theme.accent} 12%, transparent)`);
  root.setProperty("color-scheme", relativeLuminance(theme.background) > 0.45 ? "light" : "dark");
  updateCustomContrastStatus(theme);
}

function applyTheme(themeName, { persist = true } = {}) {
  const allowed = new Set(["purple", "midnight", "light", "contrast", "custom"]);
  const theme = allowed.has(themeName) ? themeName : "purple";
  clearCustomProperties();
  document.documentElement.dataset.theme = theme;
  if (theme === "custom") applyCustomTheme(readCustomTheme());
  const themeColor = theme === "light" ? "#f5f3ff" : theme === "midnight" ? "#06111d" : theme === "contrast" ? "#000000" : theme === "custom" ? readCustomTheme().background : "#0d0718";
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", themeColor);
  if (persist) storageSet(STORAGE_THEME, theme);
  const selected = document.querySelector(`input[name="theme"][value="${theme}"]`);
  if (selected) selected.checked = true;
  const customFields = $("#custom-theme-fields");
  if (customFields) customFields.disabled = theme !== "custom";
  const resetButton = $("#theme-reset");
  if (resetButton) resetButton.disabled = theme !== "custom";
}

function syncCustomThemeFields(theme = readCustomTheme()) {
  for (const [key, value] of Object.entries(theme)) {
    const input = $(`#theme-${key}`);
    if (input) input.value = value;
  }
  updateCustomContrastStatus(theme);
}

function initializeTheme() {
  syncCustomThemeFields();
  applyTheme(storageGet(STORAGE_THEME) || "purple", { persist: false });
}

function setStatus(text, kind = "") {
  const element = $("#app-status");
  element.textContent = text;
  element.className = `status-pill ${kind}`.trim();
}

function showMessage(text, kind = "") {
  const element = $("#message");
  element.textContent = text;
  element.className = `message ${kind}`.trim();
}

function reportUiError(error) {
  if (error?.authenticationRequired) return;
  showMessage(error?.message || "The requested action could not be completed.", "error");
}

function formatUsage(total, usedPercent) {
  if (total == null && usedPercent == null) return "Unavailable";
  if (total == null) return `${usedPercent}% used`;
  if (usedPercent == null) return `${total} GB`;
  return `${total} GB · ${usedPercent}% used`;
}

function formatCpu(host) {
  const logical = host.cpu_logical;
  const physical = host.cpu_physical;
  if (physical != null && logical != null) return `${physical} physical / ${logical} logical`;
  if (logical != null) return `${logical} logical cores`;
  return host.processor || "Unavailable";
}

function formatDate(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString();
}

function textBlock(label, value, size = "") {
  const block = document.createElement("div");
  block.className = `info-block ${size}`.trim();
  const key = document.createElement("span");
  const content = document.createElement("strong");
  key.textContent = label;
  content.textContent = value ?? "—";
  block.append(key, content);
  return block;
}

function selectedPortMode() {
  return document.querySelector('input[name="port-mode"]:checked')?.value || "selected";
}

function selectedTargetOption() {
  return $("#target-select").selectedOptions[0] || null;
}

function updateScanSummary() {
  const option = selectedTargetOption();
  const mode = selectedPortMode();
  const addresses = option?.dataset.usableAddresses || "the selected";
  let selectedServices = document.querySelectorAll("#ports input:checked").length;
  try { selectedServices = new Set(currentSelectedPorts()).size; } catch { /* Validation feedback is shown when scanning. */ }
  $("#deep-scan-warning").hidden = mode !== "all";
  $("#scan-summary").textContent = mode === "all"
    ? `Discover ${addresses} addresses, then scan all TCP ports on observed devices.`
    : selectedServices
      ? `Discover ${addresses} addresses using ${selectedServices} selected service check${selectedServices === 1 ? "" : "s"}.`
      : `Discover ${addresses} addresses using ICMP and neighbor evidence only.`;
}

function setScanAvailability() {
  const button = $("#scan-button");
  const select = $("#target-select");
  const hasTarget = Boolean(select.value);
  const deepModeReady = selectedPortMode() !== "all" || $("#deep-scan-confirm").checked;
  button.disabled = state.scanning || !hasTarget || !deepModeReady;
  select.disabled = state.scanning || select.options.length <= 1 && !hasTarget;
  for (const input of document.querySelectorAll('#ports input, input[name="port-mode"], #deep-scan-confirm, #custom-ports, #profile-select, #scan-all-targets')) input.disabled = state.scanning;
  $("#select-all-ports").disabled = state.scanning;
  $("#clear-ports").disabled = state.scanning;
  for (const button of document.querySelectorAll("#port-groups button")) button.disabled = state.scanning;
  $("#cancel-button").hidden = !state.scanning;
  updateScanSummary();
}

function updateScanProgress(progress) {
  state.scanProgress = progress || null;
  const percent = Number.isFinite(Number(progress?.percent)) ? Math.max(0, Math.min(100, Number(progress.percent))) : 0;
  $("#scan-progress-bar").style.width = `${percent}%`;
  $("#scan-progress-percent").textContent = `${Math.round(percent)}%`;
  $("#scan-progress-label").textContent = progress?.message || "Preparing scan…";
}

function setScanning(scanning) {
  state.scanning = scanning;
  const main = $("#main-content");
  const button = $("#scan-button");
  const progress = $("#scan-progress");
  const progressMeta = $("#scan-progress-meta");
  main.setAttribute("aria-busy", String(scanning));
  button.classList.toggle("is-loading", scanning);
  button.querySelector(".button-label").textContent = scanning ? "Mapping…" : "Map network";
  progress.hidden = !scanning;
  progressMeta.hidden = !scanning;
  progress.setAttribute("aria-hidden", String(!scanning));
  if (scanning && !state.scanProgress) updateScanProgress({ percent: 0, message: "Preparing scan…" });
  if (!scanning) {
    state.scanProgress = null;
    state.pollFailures = 0;
  }
  setScanAvailability();
}

function updateExportAvailability(hasResult) {
  for (const exportButton of [$("#export-button"), $("#export-csv-button")]) {
    exportButton.classList.toggle("is-disabled", !hasResult);
    exportButton.setAttribute("aria-disabled", String(!hasResult));
    exportButton.tabIndex = hasResult ? 0 : -1;
  }
}

function updateExportTargets(scanId = null) {
  const suffix = scanId ? `&scan_id=${encodeURIComponent(scanId)}` : "";
  $("#export-button").href = scanId ? `/api/export?scan_id=${encodeURIComponent(scanId)}` : "/api/export";
  $("#export-csv-button").href = `/api/export?format=csv${suffix}`;
}

function setMapAvailability(available) {
  state.mapAvailable = Boolean(available);
  for (const button of document.querySelectorAll("#map-zoom-out, #map-fit, #map-zoom-in")) {
    button.disabled = !state.mapAvailable;
  }
}

function targetAddressModes(target) {
  if (target?.scope === "full-subnet" && target.extended !== true) return ["standard", "extended"];
  return [target?.extended === true ? "extended" : "standard"];
}

function optionSupportsAddressMode(option, mode) {
  return String(option?.dataset.addressModes || option?.dataset.addressMode || "standard").split(/\s+/).includes(mode);
}

function targetSupportsAddressMode(target, mode) {
  return targetAddressModes(target).includes(mode);
}

function renderHost(host) {
  state.host = host;
  $("#host-name").textContent = host.hostname || "This computer";
  const container = $("#host-details");
  container.replaceChildren();
  container.append(
    textBlock("Operating system", host.os, "wide"),
    textBlock("Architecture", host.architecture),
    textBlock("CPU", formatCpu(host)),
    textBlock("Memory", formatUsage(host.memory_total_gb, host.memory_used_percent)),
    textBlock("Disk", formatUsage(host.disk_total_gb, host.disk_used_percent)),
  );

  const interfaces = Array.isArray(host.interfaces) ? host.interfaces : [];
  for (const item of interfaces) {
    const details = [item.address, item.network, item.mac].filter(Boolean).join(" · ");
    const kind = item.kind ? ` · ${item.kind}` : "";
    container.append(textBlock(`${item.interface}${kind}`, details, "wide"));
  }
  if (!interfaces.length) container.append(textBlock("Network interfaces", "No active IPv4 interfaces detected", "full"));

  const select = $("#target-select");
  const selected = select.value || storageGet(STORAGE_TARGET) || "";
  select.replaceChildren();
  const targets = Array.isArray(host.target_options) && host.target_options.length
    ? host.target_options
    : (Array.isArray(host.suggested_targets) ? host.suggested_targets.map((cidr) => ({ cidr, scope: "local-segment", extended: false })) : []);
  for (const target of targets) {
    const option = document.createElement("option");
    option.value = target.cidr;
    const addressModes = targetAddressModes(target);
    option.dataset.addressModes = addressModes.join(" ");
    option.dataset.addressMode = addressModes[0];
    option.dataset.interface = target.interface || "";
    option.dataset.usableAddresses = String(target.usable_address_count ?? target.address_count ?? "selected");
    const scope = target.scope === "full-subnet" ? "full attached subnet" : "local segment";
    const count = target.usable_address_count == null ? "" : ` · ${target.usable_address_count} usable`;
    const link = target.interface ? ` · ${target.interface}${target.kind ? ` (${target.kind})` : ""}` : "";
    option.textContent = `${target.cidr}${link} · ${scope}${count}`;
    select.append(option);
  }
  if (selected && [...select.options].some((option) => option.value === selected)) select.value = selected;
  if (!select.options.length) {
    const option = document.createElement("option");
    option.textContent = "No private IPv4 network detected";
    option.value = "";
    select.append(option);
  }
  if (select.value) storageSet(STORAGE_TARGET, select.value);
  updateScanSummary();
  setScanAvailability();
}

function storedPortSelection() {
  try {
    const parsed = JSON.parse(storageGet(STORAGE_PORTS) || "null");
    return Array.isArray(parsed) ? new Set(parsed.map(String)) : null;
  } catch {
    return null;
  }
}

function savePortSelection() {
  const selected = [...document.querySelectorAll("#ports input:checked")].map((input) => Number(input.value));
  storageSet(STORAGE_PORTS, JSON.stringify(selected));
}

function renderPorts(ports) {
  const container = $("#ports");
  const existingInputs = [...container.querySelectorAll("input")];
  const current = existingInputs.length
    ? new Set(existingInputs.filter((input) => input.checked).map((input) => input.value))
    : storedPortSelection();
  container.replaceChildren();
  for (const port of ports) {
    const label = document.createElement("label");
    label.className = "port-check";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.value = String(port);
    checkbox.checked = current ? current.has(String(port)) : true;
    checkbox.addEventListener("change", () => {
      savePortSelection();
      updateScanSummary();
    });
    const text = document.createElement("span");
    const number = document.createElement("b");
    number.className = "port-number";
    number.textContent = String(port);
    const service = document.createElement("span");
    service.className = "port-service";
    service.textContent = state.portNames[String(port)] || "TCP";
    text.append(number, service);
    label.append(checkbox, text);
    container.append(label);
  }
}

function svgElement(name, attributes = {}) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
  return node;
}

function deviceLabel(device) {
  if (device?.custom_name) return device.custom_name;
  if (device?.is_host) return "This PC";
  if (device?.hostname) return device.hostname.split(".")[0];
  return device?.ip || "Unknown device";
}

function roleFor(device) {
  return device?.role && typeof device.role === "object"
    ? device.role
    : { key: "device", label: "Network device", category: "unknown", reason: "Unclassified" };
}

function servicesFor(device) {
  return Array.isArray(device?.open_ports) ? device.open_ports : [];
}

function evidenceFor(device) {
  return Array.isArray(device?.evidence) ? device.evidence : [];
}

function humanEvidence(value) {
  return ({ local: "Local address", icmp: "ICMP response", neighbor: "Neighbor table", tcp: "TCP service" })[value] || value;
}

function renderNetworkContext(result) {
  const container = $("#network-details");
  const evidence = $("#evidence-summary");
  container.replaceChildren();
  evidence.replaceChildren();
  const network = result?.network;
  if (!network) {
    $("#network-heading").textContent = "Waiting for a scan";
    $("#network-interface-badge").textContent = "NO BASELINE";
    container.append(
      textBlock("Network", "Run a scan to identify route and gateway context", "full"),
      textBlock("Attached interfaces", String(state.host?.interfaces?.length ?? 0)),
      textBlock("Suggested targets", String(state.host?.suggested_targets?.length ?? 0)),
    );
    return;
  }

  $("#network-heading").textContent = network.cidr || result.target || "Network context";
  $("#network-interface-badge").textContent = network.interface
    ? `${network.interface}${network.interface_kind ? ` · ${network.interface_kind}` : ""}`
    : "INTERFACE UNKNOWN";
  container.append(
    textBlock("Local address", network.local_address || "Unavailable"),
    textBlock("Default gateway", network.gateway || "Not detected"),
    textBlock("Broadcast", network.broadcast_address || "Unavailable"),
    textBlock("DNS resolvers", network.dns_servers?.length ? network.dns_servers.join(", ") : "Not detected", "wide"),
    textBlock("Route evidence", `${network.route_count ?? 0} IPv4 route${network.route_count === 1 ? "" : "s"}`),
    textBlock("IPv6 context", `${result.ipv6?.interfaces?.length ?? 0} interface address${result.ipv6?.interfaces?.length === 1 ? "" : "es"} · ${result.ipv6?.neighbors?.length ?? 0} passive neighbor${result.ipv6?.neighbors?.length === 1 ? "" : "s"}`, "wide"),
  );

  const devices = Array.isArray(result.devices) ? result.devices : [];
  const evidenceCounts = [
    ["ICMP", devices.filter((device) => evidenceFor(device).includes("icmp")).length, "active"],
    ["Neighbor", devices.filter((device) => evidenceFor(device).includes("neighbor")).length, "neighbor"],
    ["TCP", devices.filter((device) => evidenceFor(device).includes("tcp")).length, "service"],
    ["Local", devices.filter((device) => evidenceFor(device).includes("local")).length, "host"],
  ];
  for (const [label, count, kind] of evidenceCounts) {
    const item = document.createElement("div");
    item.className = `evidence-card ${kind}`;
    const name = document.createElement("span");
    name.textContent = label;
    const value = document.createElement("strong");
    value.textContent = String(count);
    item.append(name, value);
    evidence.append(item);
  }
}

function changeTotal(changes) {
  const counts = changes?.counts;
  return counts ? Number(counts.new || 0) + Number(counts.missing || 0) + Number(counts.changed || 0) : 0;
}

function changeIdentity(item) {
  return item.hostname ? `${item.hostname} · ${item.ip}` : item.ip;
}

function changeGroup(title, items, kind, formatter) {
  const group = document.createElement("section");
  group.className = `change-group ${kind}`;
  const header = document.createElement("div");
  header.className = "change-group-heading";
  const heading = document.createElement("h3");
  heading.textContent = title;
  const count = document.createElement("span");
  count.textContent = String(items.length);
  header.append(heading, count);
  group.append(header);
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "None";
    group.append(empty);
    return group;
  }
  const list = document.createElement("ul");
  for (const item of items.slice(0, 8)) {
    const entry = document.createElement("li");
    entry.textContent = formatter(item);
    list.append(entry);
  }
  if (items.length > 8) {
    const entry = document.createElement("li");
    entry.textContent = `And ${items.length - 8} more`;
    list.append(entry);
  }
  group.append(list);
  return group;
}

function renderChanges(changes) {
  const content = $("#change-content");
  content.replaceChildren();
  if (!changes?.comparable) {
    $("#baseline-badge").textContent = "FIRST BASELINE";
    const message = document.createElement("div");
    message.className = "baseline-empty";
    const title = document.createElement("strong");
    title.textContent = "This scan establishes the baseline.";
    const text = document.createElement("span");
    text.textContent = "Scan the same network again to see new, missing, and service-changed devices.";
    message.append(title, text);
    content.append(message);
    return;
  }

  const baselineDate = formatDate(changes.baseline_generated_at);
  $("#baseline-badge").textContent = baselineDate ? `SINCE ${baselineDate}` : "PREVIOUS SCAN";
  const total = changeTotal(changes);
  if (!total) {
    const message = document.createElement("div");
    message.className = "baseline-empty success-state";
    const title = document.createElement("strong");
    title.textContent = "No observed topology changes.";
    const text = document.createElement("span");
    text.textContent = "The same devices and selected open services were observed as in the previous scan.";
    message.append(title, text);
    content.append(message);
    return;
  }

  content.append(
    changeGroup("New devices", changes.new_devices || [], "new", changeIdentity),
    changeGroup("No longer observed", changes.missing_devices || [], "missing", changeIdentity),
    changeGroup("Service changes", changes.changed_services || [], "changed", changeIdentity),
  );
}

function topologyCategory(device) {
  const category = roleFor(device).category;
  return ["infrastructure", "servers", "endpoints", "peripherals", "unknown"].includes(category) ? category : "unknown";
}

const CATEGORY_LABELS = {
  infrastructure: "Infrastructure",
  servers: "Servers and services",
  endpoints: "Endpoints",
  peripherals: "Peripherals and IoT",
  unknown: "Other observed devices",
};

function truncate(value, limit) {
  const text = String(value ?? "");
  return text.length > limit ? `${text.slice(0, Math.max(1, limit - 1))}…` : text;
}

function laneLayout(devices) {
  const groups = new Map();
  for (const device of devices) {
    const category = topologyCategory(device);
    if (!groups.has(category)) groups.set(category, []);
    groups.get(category).push(device);
  }
  const categories = Object.keys(CATEGORY_LABELS).filter((category) => groups.has(category));
  const total = devices.length;
  const dense = total > 72;
  const lanes = [];
  const startY = 410;
  const gapY = 26;

  if (dense) {
    let y = startY;
    for (const category of categories) {
      const items = groups.get(category);
      const columns = total > 160 ? 8 : total > 100 ? 7 : 6;
      const width = 1100;
      const nodeGap = 12;
      const nodeWidth = (width - 40 - nodeGap * (columns - 1)) / columns;
      const nodeHeight = 64;
      const rows = Math.ceil(items.length / columns);
      const height = 64 + rows * (nodeHeight + nodeGap) + 18;
      lanes.push({ category, items, x: 50, y, width, height, columns, nodeWidth, nodeHeight, nodeGap });
      y += height + gapY;
    }
    return { lanes, height: Math.max(760, y + 30) };
  }

  const columnX = [50, 620];
  const columnY = [startY, startY];
  for (const category of categories) {
    const items = groups.get(category);
    const columns = items.length === 1 ? 1 : 3;
    const width = 530;
    const nodeGap = 12;
    const nodeWidth = (width - 36 - nodeGap * (columns - 1)) / columns;
    const nodeHeight = 72;
    const rows = Math.ceil(items.length / columns);
    const height = 64 + rows * (nodeHeight + nodeGap) + 18;
    const column = columnY[0] <= columnY[1] ? 0 : 1;
    lanes.push({ category, items, x: columnX[column], y: columnY[column], width, height, columns, nodeWidth, nodeHeight, nodeGap });
    columnY[column] += height + gapY;
  }
  return { lanes, height: Math.max(760, Math.max(...columnY) + 20) };
}

function topologyDeviceSelection(devices) {
  if (devices.length <= MAX_TOPOLOGY_DEVICE_NODES) return { devices, omitted: 0, omittedByCategory: new Map() };
  const pinned = devices.filter((device) => device.is_host);
  const pinnedIps = new Set(pinned.map((device) => device.ip));
  const groups = new Map(Object.keys(CATEGORY_LABELS).map((category) => [category, []]));
  for (const device of devices) {
    if (!pinnedIps.has(device.ip)) groups.get(topologyCategory(device)).push(device);
  }
  const selected = pinned.slice(0, MAX_TOPOLOGY_DEVICE_NODES);
  let index = 0;
  while (selected.length < MAX_TOPOLOGY_DEVICE_NODES) {
    let added = false;
    for (const category of Object.keys(CATEGORY_LABELS)) {
      const device = groups.get(category)[index];
      if (!device) continue;
      selected.push(device);
      added = true;
      if (selected.length >= MAX_TOPOLOGY_DEVICE_NODES) break;
    }
    if (!added) break;
    index += 1;
  }
  const selectedSet = new Set(selected.map((device) => device.ip));
  const omittedByCategory = new Map();
  for (const device of devices) {
    if (selectedSet.has(device.ip)) continue;
    const category = topologyCategory(device);
    omittedByCategory.set(category, (omittedByCategory.get(category) || 0) + 1);
  }
  return { devices: selected, omitted: devices.length - selected.length, omittedByCategory };
}

function mapNodeGroup({ x, y, width, height, className, title, subtitle, ip, accessibleLabel }) {
  const attributes = {
    class: `map-node ${className}`.trim(),
    transform: `translate(${x} ${y})`,
    role: ip ? "button" : "group",
    "aria-label": accessibleLabel || `${title}, ${subtitle}`,
  };
  if (ip) {
    attributes.tabindex = "0";
    attributes["aria-pressed"] = "false";
  }
  const group = svgElement("g", attributes);
  if (ip) group.dataset.ip = ip;
  group.append(svgElement("rect", { x: -width / 2, y: -height / 2, width, height, rx: 14 }));
  const primary = svgElement("text", { y: -3, class: "node-title" });
  primary.textContent = truncate(title, width < 140 ? 15 : 22);
  const secondary = svgElement("text", { y: 17, class: "node-subtitle" });
  secondary.textContent = truncate(subtitle, width < 140 ? 18 : 26);
  group.append(primary, secondary);
  return group;
}

function nodeStateClass(device) {
  if (device.is_host) return "host";
  if (device.is_gateway) return "gateway";
  if (device.state === "service") return "service";
  if (device.state === "neighbor") return "neighbor";
  return "active";
}

function bindMapNode(group) {
  const activate = () => {
    const ip = group.dataset.ip;
    if (ip) selectDevice(ip);
  };
  group.addEventListener("click", activate);
  group.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      activate();
    }
  });
}

function renderTopology(result) {
  const svg = $("#topology");
  svg.replaceChildren();
  const devices = Array.isArray(result.devices) ? result.devices : [];
  $("#empty-map").hidden = true;
  setMapAvailability(true);
  const network = result.network || { cidr: result.target };
  const gatewayDevice = network.gateway ? devices.find((device) => device.ip === network.gateway) : null;
  const laneCandidates = devices.filter((device) => !network.gateway || device.ip !== network.gateway);
  const selection = topologyDeviceSelection(laneCandidates);
  const laneDevices = selection.devices;
  const layout = laneLayout(laneDevices);
  state.mapBaseWidth = 1200;
  state.mapBaseHeight = layout.height + (selection.omitted ? 105 : 0);
  svg.setAttribute("viewBox", `0 0 ${state.mapBaseWidth} ${state.mapBaseHeight}`);
  svg.setAttribute(
    "aria-label",
    selection.omitted
      ? `Logical topology showing ${laneDevices.length} representative devices of ${devices.length} observed devices`
      : devices.length
        ? `Logical topology with ${devices.length} observed devices`
        : "Logical topology with network and route context but no directly observed devices",
  );

  const defs = svgElement("defs");
  const marker = svgElement("marker", { id: "arrow", viewBox: "0 0 10 10", refX: 8, refY: 5, markerWidth: 5, markerHeight: 5, orient: "auto-start-reverse" });
  marker.append(svgElement("path", { d: "M 0 0 L 10 5 L 0 10 z", class: "arrow-head" }));
  defs.append(marker);
  svg.append(defs);

  const routeLayer = svgElement("g", { class: "route-layer" });
  const laneLayer = svgElement("g", { class: "lane-layer" });
  const nodeLayer = svgElement("g", { class: "node-layer" });
  svg.append(routeLayer, laneLayer, nodeLayer);

  let networkY = 240;
  if (network.gateway) {
    routeLayer.append(svgElement("path", { d: "M600 92 C600 110 600 118 600 132", class: "route-line", "marker-end": "url(#arrow)" }));
    routeLayer.append(svgElement("path", { d: "M600 198 C600 212 600 220 600 230", class: "route-line", "marker-end": "url(#arrow)" }));
    nodeLayer.append(mapNodeGroup({ x: 600, y: 60, width: 180, height: 58, className: "internet", title: "Internet", subtitle: "Default route", accessibleLabel: "Internet, default route" }));
    const gateway = mapNodeGroup({
      x: 600,
      y: 165,
      width: 220,
      height: 66,
      className: `gateway ${gatewayDevice ? nodeStateClass(gatewayDevice) : "unobserved"}`,
      title: gatewayDevice?.hostname || "Gateway",
      subtitle: `${network.gateway}${gatewayDevice ? " · observed" : " · route evidence only"}`,
      ip: network.gateway,
      accessibleLabel: `Gateway ${network.gateway}, ${gatewayDevice ? "observed" : "identified from route table only"}`,
    });
    bindMapNode(gateway);
    nodeLayer.append(gateway);
  } else {
    networkY = 135;
  }

  const networkNode = mapNodeGroup({
    x: 600,
    y: networkY,
    width: 300,
    height: 76,
    className: "network",
    title: network.cidr || result.target,
    subtitle: [network.interface, `${devices.length} observed`].filter(Boolean).join(" · "),
    accessibleLabel: `Network ${network.cidr || result.target}, ${devices.length} observed devices`,
  });
  nodeLayer.append(networkNode);

  for (const lane of layout.lanes) {
    const anchorX = lane.x + lane.width / 2;
    const anchorY = lane.y;
    const networkBottom = networkY + 38;
    routeLayer.append(svgElement("path", {
      d: `M600 ${networkBottom} C600 ${networkBottom + 70} ${anchorX} ${anchorY - 60} ${anchorX} ${anchorY - 8}`,
      class: "membership-line",
    }));

    laneLayer.append(svgElement("rect", {
      x: lane.x,
      y: lane.y,
      width: lane.width,
      height: lane.height,
      rx: 20,
      class: `topology-lane lane-${lane.category}`,
    }));
    const laneTitle = svgElement("text", { x: lane.x + 20, y: lane.y + 31, class: "lane-title" });
    laneTitle.textContent = CATEGORY_LABELS[lane.category];
    const laneCount = svgElement("text", { x: lane.x + lane.width - 20, y: lane.y + 31, class: "lane-count" });
    laneCount.textContent = `${lane.items.length} device${lane.items.length === 1 ? "" : "s"}`;
    laneLayer.append(laneTitle, laneCount);

    for (let index = 0; index < lane.items.length; index += 1) {
      const device = lane.items[index];
      const column = index % lane.columns;
      const row = Math.floor(index / lane.columns);
      const x = lane.x + 18 + lane.nodeWidth / 2 + column * (lane.nodeWidth + lane.nodeGap);
      const y = lane.y + 58 + lane.nodeHeight / 2 + row * (lane.nodeHeight + lane.nodeGap);
      const role = roleFor(device);
      const services = servicesFor(device);
      const node = mapNodeGroup({
        x,
        y,
        width: lane.nodeWidth,
        height: lane.nodeHeight,
        className: `device ${nodeStateClass(device)} role-${topologyCategory(device)}${state.selectedDeviceIp === device.ip ? " selected" : ""}`,
        title: deviceLabel(device),
        subtitle: `${device.ip} · ${services.length} svc`,
        ip: device.ip,
        accessibleLabel: `${deviceLabel(device)}, ${device.ip}, ${role.label}, evidence ${evidenceFor(device).map(humanEvidence).join(", ") || "none"}`,
      });
      const title = svgElement("title");
      const servicePreview = services.slice(0, 40).map((item) => `${item.port}/${item.service}`).join(", ");
      const serviceSummary = services.length > 40 ? `${servicePreview}, and ${services.length - 40} more` : servicePreview || "none detected";
      title.textContent = `${device.hostname || device.ip}\nRole: ${role.label}\nIP: ${device.ip}\nMAC: ${device.mac || "unknown"}\nEvidence: ${evidenceFor(device).map(humanEvidence).join(", ") || "none"}\nServices: ${serviceSummary}`;
      node.prepend(title);
      const dot = svgElement("circle", { cx: -lane.nodeWidth / 2 + 13, cy: -lane.nodeHeight / 2 + 13, r: 4, class: "node-status" });
      node.append(dot);
      bindMapNode(node);
      nodeLayer.append(node);
    }
  }

  if (selection.omitted) {
    const summaryY = layout.height + 18;
    laneLayer.append(svgElement("rect", { x: 50, y: summaryY, width: 1100, height: 68, rx: 18, class: "topology-lane lane-overflow" }));
    const summaryTitle = svgElement("text", { x: 75, y: summaryY + 28, class: "lane-title" });
    summaryTitle.textContent = `${selection.omitted} additional observed device${selection.omitted === 1 ? "" : "s"} available in Inventory`;
    const breakdown = [...selection.omittedByCategory.entries()]
      .map(([category, count]) => `${CATEGORY_LABELS[category]} ${count}`)
      .join(" · ");
    const summaryDetail = svgElement("text", { x: 75, y: summaryY + 49, class: "node-subtitle overflow-detail", "text-anchor": "start" });
    summaryDetail.textContent = truncate(breakdown, 130);
    laneLayer.append(summaryTitle, summaryDetail);
  }

  const disclaimer = result.topology?.disclaimer || "The map shows logical relationships inferred from local evidence; it does not claim physical switch-port connections.";
  $("#map-note").textContent = devices.length
    ? selection.omitted
      ? `For browser performance, the map shows ${laneDevices.length} representative device nodes; all ${devices.length} devices remain searchable in Inventory. ${disclaimer}`
      : disclaimer
    : `No devices answered the selected checks. Network and route context are still shown. ${disclaimer}`;
  window.requestAnimationFrame(fitMap);
}

function applyMapScale(nextScale, preserveCenter = true) {
  const scroll = $("#topology-scroll");
  const svg = $("#topology");
  const oldWidth = svg.getBoundingClientRect().width || state.mapBaseWidth * state.mapScale;
  const oldHeight = svg.getBoundingClientRect().height || state.mapBaseHeight * state.mapScale;
  const centerX = oldWidth ? (scroll.scrollLeft + scroll.clientWidth / 2) / oldWidth : 0.5;
  const centerY = oldHeight ? (scroll.scrollTop + scroll.clientHeight / 2) / oldHeight : 0.5;
  state.mapScale = Math.max(0.45, Math.min(1.8, nextScale));
  svg.style.width = `${Math.round(state.mapBaseWidth * state.mapScale)}px`;
  svg.style.height = `${Math.round(state.mapBaseHeight * state.mapScale)}px`;
  if (preserveCenter) {
    window.requestAnimationFrame(() => {
      scroll.scrollLeft = centerX * svg.getBoundingClientRect().width - scroll.clientWidth / 2;
      scroll.scrollTop = centerY * svg.getBoundingClientRect().height - scroll.clientHeight / 2;
    });
  }
}

function fitMap() {
  const scroll = $("#topology-scroll");
  if (!scroll.clientWidth) return;
  applyMapScale(Math.max(0.55, Math.min(1, (scroll.clientWidth - 18) / state.mapBaseWidth)), false);
  scroll.scrollTo({ top: 0, left: 0 });
}

function tag(text, className = "") {
  const element = document.createElement("span");
  element.className = `tag ${className}`.trim();
  element.textContent = text;
  return element;
}

function statusLabel(device) {
  if (device.is_host) return ["This PC", "host"];
  if (device.is_gateway) return ["Gateway", "gateway"];
  if (device.state === "service") return ["TCP evidence", "service"];
  if (device.state === "neighbor") return ["Neighbor only", "neighbor"];
  return ["Responsive", "active"];
}

function deviceSearchText(device) {
  const role = roleFor(device);
  return [
    device.custom_name,
    device.hostname,
    device.vendor,
    device.trust_state,
    ...(Array.isArray(device.tags) ? device.tags : []),
    device.ip,
    device.mac,
    device.state,
    role.key,
    role.label,
    role.category,
    ...evidenceFor(device),
    ...servicesFor(device).slice(0, 200).flatMap((service) => [service.port, service.service]),
  ].filter(Boolean).join(" ").toLowerCase();
}

function filteredDevices() {
  const query = $("#device-search").value.trim().toLowerCase();
  const filter = $("#device-filter").value;
  return state.devices.filter((device) => {
    if (query && !deviceSearchText(device).includes(query) && !servicesFor(device).some((service) => String(service.port) === query || String(service.service || "").toLowerCase().includes(query))) return false;
    if (filter === "host" && !device.is_host) return false;
    if (filter === "gateway" && !device.is_gateway) return false;
    if (filter === "trusted" && device.trust_state !== "trusted") return false;
    if (filter === "review" && device.trust_state !== "review") return false;
    if (filter === "up" && !evidenceFor(device).includes("icmp")) return false;
    if (filter === "service" && !evidenceFor(device).includes("tcp")) return false;
    if (filter === "neighbor" && device.state !== "neighbor") return false;
    if (filter === "services" && !servicesFor(device).length) return false;
    return true;
  });
}

function renderDevices({ resetLimit = false } = {}) {
  const list = $("#device-list");
  list.replaceChildren();
  if (resetLimit) state.inventoryLimit = INVENTORY_PAGE_SIZE;
  const devices = filteredDevices();
  const visibleDevices = devices.slice(0, state.inventoryLimit);
  const total = state.devices.length;
  $("#inventory-count").textContent = total
    ? `Showing ${visibleDevices.length} of ${devices.length}${devices.length === total ? "" : ` matching · ${total} total`}`
    : "No scan data";

  if (!devices.length) {
    const placeholder = document.createElement("p");
    placeholder.className = "list-empty";
    placeholder.textContent = total ? "No devices match the current search and filter." : "No devices observed yet.";
    list.append(placeholder);
    return;
  }

  for (const device of visibleDevices) {
    const card = document.createElement("article");
    card.className = `device-card${device.is_host ? " host-card" : ""}${state.selectedDeviceIp === device.ip ? " selected" : ""}`;
    card.tabIndex = 0;
    card.setAttribute("role", "button");
    card.setAttribute("aria-pressed", String(state.selectedDeviceIp === device.ip));
    card.setAttribute("aria-label", `Inspect ${deviceLabel(device)} at ${device.ip}`);
    card.dataset.ip = device.ip;
    card.addEventListener("click", () => selectDevice(device.ip));
    card.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectDevice(device.ip);
      }
    });

    const top = document.createElement("div");
    top.className = "device-card-top";
    const titleBox = document.createElement("div");
    const eyebrow = document.createElement("span");
    eyebrow.className = "device-role";
    eyebrow.textContent = [roleFor(device).label, device.vendor].filter(Boolean).join(" · ");
    const title = document.createElement("h3");
    title.textContent = deviceLabel(device);
    const subtitle = document.createElement("p");
    subtitle.textContent = [device.ip, device.mac].filter(Boolean).join(" · ");
    titleBox.append(eyebrow, title, subtitle);
    const [label, className] = statusLabel(device);
    top.append(titleBox, tag(label, className));

    const meta = document.createElement("div");
    meta.className = "device-meta";
    if (device.trust_state && device.trust_state !== "unknown") meta.append(tag(device.trust_state.replaceAll("-", " "), `trust-${device.trust_state}`));
    for (const item of Array.isArray(device.tags) ? device.tags.slice(0, 4) : []) meta.append(tag(item, "device-tag"));
    for (const evidence of evidenceFor(device)) meta.append(tag(humanEvidence(evidence), `evidence-${evidence}`));
    if (device.latency_ms != null) meta.append(tag(`${device.latency_ms} ms`));
    const deviceServices = servicesFor(device);
    for (const service of deviceServices.slice(0, 8)) meta.append(tag(`${service.port} ${service.service}`, "open"));
    if (deviceServices.length > 8) meta.append(tag(`+${deviceServices.length - 8} more`, "service"));
    if (!deviceServices.length) meta.append(tag("No scanned TCP ports open"));
    card.append(top, meta);
    list.append(card);
  }

  if (visibleDevices.length < devices.length) {
    const remaining = devices.length - visibleDevices.length;
    const more = document.createElement("button");
    more.className = "button button-secondary list-more";
    more.type = "button";
    more.textContent = `Show ${Math.min(INVENTORY_PAGE_SIZE, remaining)} more`;
    more.addEventListener("click", () => {
      state.inventoryLimit += INVENTORY_PAGE_SIZE;
      renderDevices();
    });
    list.append(more);
  }
}

function inspectorRow(label, value) {
  const row = document.createElement("div");
  row.className = "inspector-row";
  const key = document.createElement("span");
  key.textContent = label;
  const content = document.createElement("strong");
  content.textContent = value ?? "—";
  row.append(key, content);
  return row;
}

function renderInspector(device = null) {
  const heading = $("#inspector-heading");
  const content = $("#inspector-content");
  const openButton = $("#open-device-button");
  content.replaceChildren();
  openButton.hidden = true;
  openButton.dataset.deviceId = "";
  if (!state.latest) {
    heading.textContent = "Network overview";
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "Run a scan to inspect observed devices and network evidence.";
    content.append(empty);
    return;
  }

  if (!device && state.selectedDeviceIp && state.latest.network?.gateway === state.selectedDeviceIp) {
    heading.textContent = "Default gateway";
    content.append(
      inspectorRow("IP address", state.selectedDeviceIp),
      inspectorRow("Evidence", "IPv4 default route"),
      inspectorRow("Observation", "No direct device evidence was returned"),
    );
    return;
  }

  if (!device) {
    const network = state.latest.network || {};
    heading.textContent = network.cidr || state.latest.target || "Network overview";
    content.append(
      inspectorRow("Interface", [network.interface, network.interface_kind].filter(Boolean).join(" · ")),
      inspectorRow("Local address", network.local_address),
      inspectorRow("Gateway", network.gateway),
      inspectorRow("Observed devices", String(state.devices.length)),
      inspectorRow("Port depth", state.latest.scan_options?.port_mode === "all" ? "All TCP ports on observed devices" : `${state.latest.scan_options?.ports?.length ?? state.defaultPorts.length} selected services`),
    );
    return;
  }

  heading.textContent = deviceLabel(device);
  if (device.device_id) {
    openButton.hidden = false;
    openButton.dataset.deviceId = String(device.device_id);
  }
  content.append(
    inspectorRow("Role", roleFor(device).label),
    inspectorRow("IP address", device.ip),
    inspectorRow("MAC address", device.mac || "Not observed"),
    inspectorRow("Vendor", device.vendor || "Unknown"),
    inspectorRow("Trust", device.trust_state || "unknown"),
    inspectorRow("Hostname", device.hostname || "Not resolved"),
    inspectorRow("Evidence", evidenceFor(device).map(humanEvidence).join(", ") || "None"),
    inspectorRow("Latency", device.latency_ms == null ? "Not available" : `${device.latency_ms} ms`),
  );
  const serviceSection = document.createElement("section");
  serviceSection.className = "inspector-services";
  const title = document.createElement("h4");
  title.textContent = "Open TCP ports";
  serviceSection.append(title);
  const services = servicesFor(device);
  if (!services.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "None detected.";
    serviceSection.append(empty);
  } else {
    const tags = document.createElement("div");
    tags.className = "device-meta";
    for (const service of services.slice(0, 100)) tags.append(tag(`${service.port} ${service.service}`, "open"));
    if (services.length > 100) tags.append(tag(`+${services.length - 100} additional open ports`, "service"));
    serviceSection.append(tags);
  }
  const reason = document.createElement("p");
  reason.className = "role-reason";
  reason.textContent = `Classification: ${roleFor(device).reason || "available evidence"}.`;
  serviceSection.append(reason);
  content.append(serviceSection);
}

function refreshSelectionClasses() {
  for (const node of document.querySelectorAll("#topology [data-ip]")) {
    const selected = node.dataset.ip === state.selectedDeviceIp;
    node.classList.toggle("selected", selected);
    node.setAttribute("aria-pressed", String(selected));
  }
  for (const card of document.querySelectorAll(".device-card[data-ip]")) {
    const selected = card.dataset.ip === state.selectedDeviceIp;
    card.classList.toggle("selected", selected);
    card.setAttribute("aria-pressed", String(selected));
  }
}

function selectDevice(ip) {
  state.selectedDeviceIp = ip;
  const device = state.devices.find((item) => item.ip === ip) || null;
  state.selectedDeviceId = device?.device_id ?? null;
  renderInspector(device);
  refreshSelectionClasses();
}

function renderNoResult() {
  state.latest = null;
  state.devices = [];
  state.selectedDeviceIp = null;
  state.inventoryLimit = INVENTORY_PAGE_SIZE;
  for (const id of ["device-count", "responsive-count", "tcp-count", "service-count", "change-count", "duration"]) {
    $(`#${id}`).textContent = "—";
  }
  $("#map-title").textContent = "No scan yet";
  $("#generated-at").textContent = "";
  $("#map-note").textContent = DEFAULT_MAP_NOTE;
  const svg = $("#topology");
  svg.replaceChildren();
  svg.setAttribute("viewBox", "0 0 1200 760");
  svg.setAttribute("aria-label", "Interactive logical network topology");
  state.mapBaseWidth = 1200;
  state.mapBaseHeight = 760;
  applyMapScale(1, false);
  $("#empty-map").hidden = false;
  renderNetworkContext(null);
  renderChanges(null);
  renderDevices();
  renderInspector();
  updateExportTargets(null);
  updateExportAvailability(false);
  setMapAvailability(false);
}

function renderResult(result) {
  state.latest = result;
  const resultDevices = Array.isArray(result.devices) ? result.devices : [];
  const categoryRank = { infrastructure: 0, servers: 1, endpoints: 2, peripherals: 3, unknown: 4 };
  state.devices = [...resultDevices].sort((left, right) => {
    if (left.is_host !== right.is_host) return left.is_host ? -1 : 1;
    if (left.is_gateway !== right.is_gateway) return left.is_gateway ? -1 : 1;
    const categoryDifference = (categoryRank[topologyCategory(left)] ?? 9) - (categoryRank[topologyCategory(right)] ?? 9);
    if (categoryDifference) return categoryDifference;
    return left.ip.localeCompare(right.ip, undefined, { numeric: true });
  });
  state.inventoryLimit = INVENTORY_PAGE_SIZE;
  const changes = result.changes;
  $("#device-count").textContent = result.summary?.device_count ?? state.devices.length;
  $("#responsive-count").textContent = result.summary?.responsive_count ?? "—";
  $("#tcp-count").textContent = result.summary?.tcp_evidence_count ?? result.summary?.tcp_discovered_count ?? "—";
  $("#service-count").textContent = result.summary?.open_service_count ?? "—";
  $("#change-count").textContent = changes?.comparable ? changeTotal(changes) : "NEW";
  $("#duration").textContent = result.duration_seconds == null ? "—" : `${result.duration_seconds}s`;
  $("#map-title").textContent = result.target || "Network map";
  const generatedAt = formatDate(result.generated_at);
  $("#generated-at").textContent = generatedAt ? `Scanned ${generatedAt}` : "";
  renderNetworkContext(result);
  renderChanges(changes);
  renderTopology(result);
  renderDevices();
  updateExportTargets(result.scan_id ?? null);
  updateExportAvailability(result.saved !== false);

  if (state.selectedDeviceIp && !state.devices.some((device) => device.ip === state.selectedDeviceIp) && result.network?.gateway !== state.selectedDeviceIp) {
    state.selectedDeviceIp = null;
  }
  renderInspector(state.devices.find((device) => device.ip === state.selectedDeviceIp) || null);
  refreshSelectionClasses();

  const warnings = Array.isArray(result.warnings) ? result.warnings : [];
  if (warnings.length) showMessage(warnings.join(" "), "warning");
  else showMessage(`Map complete. Observed ${state.devices.length} device${state.devices.length === 1 ? "" : "s"}.`, "success");
}

async function readJsonResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) throw new Error(`The server returned an unexpected response (${response.status}).`);
  try {
    return await response.json();
  } catch {
    throw new Error("The server returned invalid JSON.");
  }
}

function showLogin(message = "") {
  const dialog = $("#login-dialog");
  const feedback = $("#login-message");
  feedback.hidden = !message;
  feedback.textContent = message;
  if (!dialog.open) dialog.showModal();
  queueMicrotask(() => $("#login-password").focus());
}

async function apiFetch(path, options = {}) {
  const response = await fetch(path, { cache: "no-store", ...options });
  const payload = await readJsonResponse(response);
  if (response.status === 401 && payload.authentication_required) {
    state.auth = { enabled: true, authenticated: false };
    showLogin();
    throw Object.assign(new Error("Authentication required."), { authenticationRequired: true });
  }
  if (!response.ok) throw Object.assign(new Error(payload.error || `Request failed (${response.status}).`), { status: response.status, payload });
  return payload;
}

function scheduleStatusPoll(delay = 1500) {
  window.clearTimeout(state.pollTimer);
  state.pollTimer = window.setTimeout(pollScanState, delay);
}

async function pollScanState() {
  try {
    const payload = await apiFetch("/api/scan-state");
    state.pollFailures = 0;
    if (payload.progress) updateScanProgress(payload.progress);
    if (payload.scan_running) {
      setScanning(true);
      setStatus(payload.progress?.phase === "ports" ? "Deep port scan" : "Mapping network", "busy");
      if (payload.progress?.message) showMessage(payload.progress.message);
      scheduleStatusPoll();
      return;
    }
    await loadStatus(true);
  } catch (error) {
    if (error.authenticationRequired) return;
    if (state.scanning && state.pollFailures < 3) {
      state.pollFailures += 1;
      setStatus("Reconnecting", "busy");
      showMessage("Scan progress is temporarily unavailable. The active scan request is still running.", "warning");
      scheduleStatusPoll(2500);
      return;
    }
    setScanning(false);
    setStatus("Unavailable", "bad");
    showMessage(error.message || "Unable to check scan progress.", "error");
  }
}

function renderMonitor(monitor = {}) {
  state.monitor = monitor;
  const values = {
    "history-count": monitor.history_count ?? 0,
    "alert-count": monitor.unacknowledged_alert_count ?? 0,
    "monitor-history": monitor.history_count ?? 0,
    "monitor-devices": monitor.known_device_count ?? 0,
    "monitor-alerts": monitor.unacknowledged_alert_count ?? 0,
    "monitor-schedules": monitor.active_schedule_count ?? 0,
  };
  for (const [id, value] of Object.entries(values)) if ($(`#${id}`)) $(`#${id}`).textContent = String(value);
  $("#alerts-button").classList.toggle("has-alerts", Number(monitor.unacknowledged_alert_count) > 0);
}

function populateProfiles(profiles = [], { applyScan = true } = {}) {
  state.profiles = profiles;
  const scanSelect = $("#profile-select");
  const scheduleSelect = $("#schedule-profile");
  const selected = scanSelect.value || storageGet(STORAGE_PROFILE) || String(profiles.find((profile) => profile.name === "Standard")?.id ?? profiles[0]?.id ?? "");
  const scheduleSelected = scheduleSelect.value;
  for (const select of [scanSelect, scheduleSelect]) {
    select.replaceChildren();
    for (const profile of profiles) {
      const option = document.createElement("option");
      option.value = String(profile.id);
      option.textContent = `${profile.name}${profile.built_in ? "" : " · custom"}`;
      option.dataset.portMode = profile.port_mode;
      option.dataset.addressMode = profile.address_mode;
      select.append(option);
    }
  }
  if ([...scanSelect.options].some((option) => option.value === selected)) scanSelect.value = selected;
  else if (scanSelect.options.length) scanSelect.selectedIndex = 0;
  if ([...scheduleSelect.options].some((option) => option.value === scheduleSelected)) scheduleSelect.value = scheduleSelected;
  if (applyScan) applySelectedProfile({ preservePorts: true });
}

function selectedProfile() {
  return state.profiles.find((profile) => String(profile.id) === $("#profile-select").value) || null;
}

function parsePortExpression(value, { allowEmpty = true } = {}) {
  const text = String(value ?? "").trim();
  if (!text) {
    if (allowEmpty) return [];
    throw new Error("Enter at least one TCP port.");
  }
  const ports = new Set();
  for (const token of text.split(/[\s,]+/).filter(Boolean)) {
    const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(token);
    if (!match) throw new Error(`Invalid port expression: ${token}`);
    const start = Number(match[1]);
    const end = Number(match[2] || match[1]);
    if (start < 1 || end > 65535 || end < start) throw new Error(`Port range is invalid: ${token}`);
    if (end - start > 1023) throw new Error("A single custom range may contain at most 1,024 ports.");
    for (let port = start; port <= end; port += 1) {
      ports.add(port);
      if (ports.size > 1024) throw new Error("At most 1,024 selected ports may be configured.");
    }
  }
  return [...ports].sort((left, right) => left - right);
}

function currentSelectedPorts() {
  const ports = new Set([...document.querySelectorAll("#ports input:checked")].map((input) => Number(input.value)));
  for (const port of parsePortExpression($("#custom-ports").value)) ports.add(port);
  return [...ports].sort((left, right) => left - right);
}

function applyPorts(ports) {
  const selected = new Set((ports || []).map(Number));
  for (const input of document.querySelectorAll("#ports input")) input.checked = selected.has(Number(input.value));
  const custom = [...selected].filter((port) => !state.defaultPorts.includes(port));
  $("#custom-ports").value = custom.join(", ");
  storageSet(STORAGE_CUSTOM_PORTS, $("#custom-ports").value);
  savePortSelection();
  updateScanSummary();
}

function applySelectedProfile({ preservePorts = false } = {}) {
  const profile = selectedProfile();
  if (!profile) return;
  storageSet(STORAGE_PROFILE, String(profile.id));
  const modeInput = document.querySelector(`input[name="port-mode"][value="${profile.port_mode}"]`);
  if (modeInput) modeInput.checked = true;
  if (!preservePorts) applyPorts(profile.ports || []);
  const help = $("#profile-help");
  help.textContent = `${profile.address_mode === "extended" ? "Full attached subnet" : "Local segment"} · ${profile.port_mode === "all" ? "all TCP ports on observed devices" : `${profile.ports.length} selected ports`} · ${profile.timeout_ms || 260} ms timeout.`;
  const desiredAddressMode = profile.address_mode;
  const matching = [...$("#target-select").options].find((option) => optionSupportsAddressMode(option, desiredAddressMode));
  if (matching) $("#target-select").value = matching.value;
  if (profile.port_mode !== "all") $("#deep-scan-confirm").checked = false;
  updateScanSummary();
  setScanAvailability();
}

function selectedTargets() {
  if (!$("#scan-all-targets").checked) return $("#target-select").value ? [$("#target-select").value] : [];
  const desiredMode = selectedProfile()?.address_mode || "standard";
  let options = [...$("#target-select").options].filter((option) => option.value && optionSupportsAddressMode(option, desiredMode));
  if (!options.length) options = [...$("#target-select").options].filter((option) => option.value);
  const seen = new Set();
  const targets = [];
  for (const option of options) {
    const key = option.dataset.interface || option.value;
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push(option.value);
  }
  return targets;
}

async function loadStatus(quiet = false) {
  if (!quiet) {
    setStatus("Loading", "busy");
    showMessage("Loading host, history, and interface details.");
  }
  try {
    const payload = await apiFetch("/api/status");
    state.auth = payload.auth || state.auth;
    state.defaultPorts = Array.isArray(payload.default_ports) ? payload.default_ports : [];
    state.portNames = payload.port_names && typeof payload.port_names === "object" ? payload.port_names : {};
    state.targetOptions = Array.isArray(payload.target_options) ? payload.target_options : [];
    state.settings = payload.settings && typeof payload.settings === "object" ? payload.settings : state.settings;
    renderPorts(state.defaultPorts);
    if (!$("#custom-ports").value) $("#custom-ports").value = storageGet(STORAGE_CUSTOM_PORTS) || "";
    const host = { ...(payload.host || {}), target_options: state.targetOptions };
    renderHost(host);
    populateProfiles(payload.profiles || []);
    renderMonitor(payload.monitor || {});
    applyAutomaticTheme();
    syncNotificationUi();
    if (payload.latest) renderResult(payload.latest);
    else {
      renderNoResult();
      showMessage("Ready to map an attached network.");
    }
    if (payload.scan_running) {
      if (payload.progress) updateScanProgress(payload.progress);
      setScanning(true);
      setStatus(payload.progress?.phase === "ports" ? "Deep port scan" : "Mapping network", "busy");
      showMessage(payload.progress?.message || "A scan is running. This view will update when it completes.", "warning");
      scheduleStatusPoll();
    } else {
      window.clearTimeout(state.pollTimer);
      setScanning(false);
      setStatus("Ready", "good");
    }
    await maybeNotifyAlerts(payload.monitor || {});
  } catch (error) {
    if (error.authenticationRequired) return;
    setScanning(false);
    setStatus("Unavailable", "bad");
    showMessage(error.message || "Unable to load the dashboard.", "error");
  }
}

async function runScan() {
  const targets = selectedTargets();
  if (!targets.length || state.scanning) return;
  const portMode = selectedPortMode();
  if (portMode === "all" && !$("#deep-scan-confirm").checked) {
    showMessage("Confirm authorization before starting an all-port scan.", "warning");
    setScanAvailability();
    return;
  }
  let ports;
  try { ports = currentSelectedPorts(); }
  catch (error) { showMessage(error.message, "error"); return; }
  if (portMode === "selected" && !ports.length) showMessage("No TCP services are selected; discovery will use ICMP and neighbor evidence only.", "warning");
  storageSet(STORAGE_TARGET, targets[0]);
  storageSet(STORAGE_PORT_MODE, portMode);
  storageSet(STORAGE_SCAN_ALL, String($("#scan-all-targets").checked));
  const profile = selectedProfile();
  const addressMode = profile?.address_mode || selectedTargetOption()?.dataset.addressMode || "standard";
  setScanning(true);
  updateScanProgress({ percent: 0, message: "Preparing local scan…" });
  setStatus(portMode === "all" ? "Deep port scan" : "Mapping network", "busy");
  showMessage(targets.length > 1 ? `Scanning ${targets.length} attached networks sequentially.` : `Mapping ${targets[0]}.`);
  scheduleStatusPoll();
  let externalScan = false;
  try {
    const payload = await apiFetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        targets,
        profile_id: profile?.id,
        ports,
        port_mode: portMode,
        address_mode: addressMode,
        authorized: portMode === "all" && $("#deep-scan-confirm").checked,
      }),
    });
    window.clearTimeout(state.pollTimer);
    const result = payload.batch ? payload.latest : payload;
    renderResult(result);
    setStatus("Map updated", "good");
    if (payload.batch) showMessage(`Completed ${payload.summary.network_count} network scans and stored each snapshot.`, "success");
    await refreshMonitorOnly();
  } catch (error) {
    if (error.status === 409 && /already running/i.test(error.message)) {
      externalScan = true;
      setStatus("Mapping network", "busy");
      showMessage("Another dashboard tab started a scan. This view will update when it completes.", "warning");
      scheduleStatusPoll();
      return;
    }
    if (error.authenticationRequired) return;
    window.clearTimeout(state.pollTimer);
    const cancelled = error.message === "Scan cancelled.";
    setStatus(cancelled ? "Ready" : "Scan failed", cancelled ? "good" : "bad");
    showMessage(cancelled ? "Scan cancelled. The previous completed map is still available." : error.message || "The scan failed.", cancelled ? "warning" : "error");
  } finally {
    if (!externalScan) setScanning(false);
  }
}

async function cancelScan() {
  if (!state.scanning) return;
  $("#cancel-button").disabled = true;
  updateScanProgress({ ...(state.scanProgress || {}), message: "Cancelling scan…" });
  try { await apiFetch("/api/scan/cancel", { method: "POST" }); }
  catch (error) { if (!error.authenticationRequired) showMessage(error.message || "Unable to cancel the scan.", "error"); }
  finally { $("#cancel-button").disabled = false; }
}

function setAllPorts(checked) {
  for (const input of document.querySelectorAll("#ports input")) input.checked = checked;
  savePortSelection();
  updateScanSummary();
}

const PORT_GROUPS = {
  common: [22, 53, 80, 443, 445, 3389, 8080],
  web: [80, 443, 8000, 8080, 8443, 8888],
  remote: [22, 23, 3389, 5900, 5985, 5986],
  files: [139, 445, 2049, 548],
  databases: [1433, 3306, 5432, 6379, 9200, 27017],
  printers: [515, 631, 9100],
};

function openDialog(selector) {
  const dialog = $(selector);
  if (dialog && !dialog.open) dialog.showModal();
}

function closeDialog(button) {
  button.closest("dialog")?.close();
}

function actionButton(label, handler, className = "button button-secondary compact-button") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", async (event) => {
    if (button.disabled) return;
    button.disabled = true;
    try {
      await handler(event);
    } catch (error) {
      reportUiError(error);
    } finally {
      if (button.isConnected) button.disabled = false;
    }
  });
  return button;
}

async function refreshMonitorOnly() {
  try {
    const payload = await apiFetch("/api/monitor");
    renderMonitor(payload.monitor || {});
    await maybeNotifyAlerts(payload.monitor || {});
  } catch {
    // The next normal status refresh will reconcile counters.
  }
}

async function loadHistory() {
  const body = $("#history-list");
  body.innerHTML = '<tr><td colspan="6" class="table-empty">Loading history…</td></tr>';
  try {
    const payload = await apiFetch("/api/history?limit=250");
    state.history = payload.scans || [];
    body.replaceChildren();
    if (!state.history.length) body.innerHTML = '<tr><td colspan="6" class="table-empty">No saved scans yet.</td></tr>';
    for (const scan of state.history) {
      const row = document.createElement("tr");
      const compare = document.createElement("input");
      compare.type = "checkbox";
      compare.value = String(scan.id);
      compare.setAttribute("aria-label", `Select scan ${scan.id} for comparison`);
      compare.addEventListener("change", updateHistoryActions);
      const actions = document.createElement("div");
      actions.className = "row-actions";
      actions.append(
        actionButton("View", async () => {
          const entry = await apiFetch(`/api/history/${scan.id}`);
          renderResult(entry.result);
          $("#history-dialog").close();
          document.querySelector("#topology-panel")?.scrollIntoView({ behavior: "smooth" });
        }),
        actionButton("JSON", () => { window.location.href = `/api/export?scan_id=${scan.id}`; }),
        actionButton("CSV", () => { window.location.href = `/api/export?format=csv&scan_id=${scan.id}`; }),
        actionButton("Delete", async () => {
          if (!window.confirm(`Delete the saved scan from ${formatDate(scan.generated_at)}?`)) return;
          await apiFetch(`/api/history/${scan.id}`, { method: "DELETE" });
          await loadHistory();
          await loadStatus(true);
        }, "button button-danger compact-button"),
      );
      const cells = [compare, formatDate(scan.generated_at), scan.target, scan.source || "live", String(scan.device_count ?? 0), actions];
      for (const item of cells) {
        const cell = document.createElement("td");
        if (item instanceof Node) cell.append(item); else cell.textContent = item;
        row.append(cell);
      }
      body.append(row);
    }
    updateHistoryActions();
  } catch (error) {
    body.replaceChildren();
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.className = "table-empty";
    cell.textContent = error.message || "Unable to load history.";
    row.append(cell);
    body.append(row);
  }
}

function selectedHistoryIds() {
  return [...document.querySelectorAll("#history-list input[type=checkbox]:checked")].map((input) => Number(input.value));
}

function updateHistoryActions() {
  const count = selectedHistoryIds().length;
  $("#compare-history").disabled = count !== 2;
  $("#print-history").disabled = count !== 1;
}

async function compareHistory() {
  const [left, right] = selectedHistoryIds();
  if (!left || !right) return;
  const payload = await apiFetch(`/api/history/compare?left=${left}&right=${right}`);
  const changes = payload.changes || {};
  const panel = $("#history-comparison");
  panel.hidden = false;
  panel.innerHTML = `<h3>Comparison</h3><div class="comparison-summary"><span><strong>${changes.counts?.new ?? 0}</strong> new</span><span><strong>${changes.counts?.missing ?? 0}</strong> missing</span><span><strong>${changes.counts?.changed ?? 0}</strong> service changes</span></div><p>${formatDate(payload.left.generated_at)} → ${formatDate(payload.right.generated_at)}</p>`;
}

async function importHistory(file) {
  if (!file) return;
  if (file.size > 64 * 1024 * 1024) throw new Error("Import files may not exceed 64 MB.");
  const text = await file.text();
  let data;
  try { data = JSON.parse(text); } catch { throw new Error("The selected file is not valid JSON."); }
  await apiFetch("/api/history/import", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
  await loadHistory();
  await loadStatus(true);
}

async function loadAlerts() {
  const list = $("#alert-list");
  list.textContent = "Loading alerts…";
  try {
    const acknowledged = $("#alert-filter").value === "all" ? "" : "&acknowledged=false";
    const payload = await apiFetch(`/api/alerts?limit=500${acknowledged}`);
    state.alerts = payload.alerts || [];
    list.replaceChildren();
    if (!state.alerts.length) {
      const empty = document.createElement("p"); empty.className = "list-empty"; empty.textContent = "No alerts match this view."; list.append(empty);
    }
    for (const alert of state.alerts) {
      const card = document.createElement("article");
      card.className = `alert-card ${alert.severity}${alert.acknowledged ? " acknowledged" : ""}`;
      const severity = document.createElement("span");
      severity.className = "alert-severity";
      severity.setAttribute("aria-hidden", "true");
      const copy = document.createElement("div");
      const title = document.createElement("h3"); title.textContent = alert.title;
      const message = document.createElement("p"); message.textContent = alert.message;
      const meta = document.createElement("small"); meta.textContent = `${alert.severity.toUpperCase()} · ${formatDate(alert.created_at)}`;
      copy.append(title, message, meta);
      const button = actionButton(alert.acknowledged ? "Reopen" : "Acknowledge", async () => {
        await apiFetch(`/api/alerts/${alert.id}/acknowledge`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ acknowledged: !alert.acknowledged }) });
        await loadAlerts();
        await refreshMonitorOnly();
      });
      card.append(severity, copy, button);
      list.append(card);
    }
  } catch (error) { list.textContent = error.message; }
}

function notificationPermissionState() {
  if (!("Notification" in window)) return "unsupported";
  return Notification.permission || "default";
}

function syncNotificationUi() {
  const preferenceEnabled = Boolean(state.settings.alert_preferences?.browser_notifications);
  const permission = notificationPermissionState();
  const enabled = preferenceEnabled && permission === "granted";
  const mainButton = $("#notification-button");
  const dialogButton = $("#notification-dialog-button");
  const status = $("#notification-permission-status");
  const label = enabled ? "Notifications on" : permission === "denied" ? "Notifications blocked" : permission === "unsupported" ? "Notifications unavailable" : "Enable notifications";
  if (mainButton) {
    mainButton.textContent = label;
    mainButton.disabled = permission === "unsupported" || permission === "denied";
  }
  if (dialogButton) {
    dialogButton.textContent = enabled ? "Disable browser notifications" : permission === "denied" ? "Blocked in browser settings" : permission === "unsupported" ? "Not supported" : "Enable browser notifications";
    dialogButton.disabled = permission === "unsupported" || permission === "denied";
  }
  if (status) {
    status.className = `badge ${enabled ? "is-enabled" : permission === "denied" ? "is-blocked" : permission === "unsupported" ? "is-unavailable" : ""}`.trim();
    status.textContent = enabled ? "Permission granted" : permission === "denied" ? "Permission blocked" : permission === "unsupported" ? "Not supported" : preferenceEnabled ? "Permission required" : "Disabled";
  }
}

async function recordNotificationEvent(payload) {
  try {
    await apiFetch("/api/notifications/history", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    if ($("#alerts-dialog")?.open) await loadNotificationHistory();
  } catch {
    // Notification delivery must never interrupt dashboard polling or alert handling.
  }
}

function notificationStatusLabel(status) {
  return ({
    shown: "Shown",
    "permission-granted": "Permission granted",
    "permission-denied": "Permission denied",
    "permission-default": "Permission dismissed",
    unsupported: "Unsupported",
    disabled: "Notifications disabled",
    error: "Delivery error",
  })[status] || "Notification event";
}

async function loadNotificationHistory() {
  const list = $("#notification-history-list");
  if (!list) return;
  list.textContent = "Loading notification history…";
  try {
    const payload = await apiFetch("/api/notifications/history?limit=200");
    state.notificationHistory = payload.notifications || [];
    list.replaceChildren();
    if (!state.notificationHistory.length) {
      const empty = document.createElement("p");
      empty.className = "list-empty";
      empty.textContent = "No browser notification attempts have been recorded yet.";
      list.append(empty);
      return;
    }
    for (const event of state.notificationHistory) {
      const card = document.createElement("article");
      card.className = `notification-event ${event.status}`;
      const icon = document.createElement("span");
      icon.className = "notification-event-icon";
      icon.setAttribute("aria-hidden", "true");
      icon.textContent = event.status === "shown" || event.status === "permission-granted" ? "✓" : event.status === "error" || event.status === "permission-denied" ? "!" : "i";
      const copy = document.createElement("div");
      const title = document.createElement("h4");
      title.textContent = `${notificationStatusLabel(event.status)} · ${event.title}`;
      const message = document.createElement("p");
      message.textContent = event.message;
      const time = document.createElement("time");
      time.dateTime = event.created_at;
      time.textContent = formatDate(event.created_at);
      copy.append(title, message, time);
      card.append(icon, copy);
      list.append(card);
    }
  } catch (error) {
    list.textContent = error.message;
  }
}

async function loadAlertCenter() {
  syncNotificationUi();
  await Promise.all([loadAlerts(), loadNotificationHistory()]);
}

async function maybeNotifyAlerts(monitor = {}) {
  const preferences = state.settings.alert_preferences || {};
  const count = Number(monitor.unacknowledged_alert_count || 0);
  const latestId = Number(monitor.latest_unacknowledged_alert_id || 0);
  if (!preferences.browser_notifications || !count || !latestId || notificationPermissionState() !== "granted") return;
  const previousId = Number(storageGet(STORAGE_NOTIFIED_ALERT_ID) || 0);
  if (latestId <= previousId) return;
  const body = `${count} network alert${count === 1 ? " needs" : "s need"} review.`;
  try {
    new Notification("NetScope Lite", { body, icon: "/static/favicon.svg", tag: `netscope-alert-${latestId}` });
    storageSet(STORAGE_NOTIFIED_ALERT_ID, String(latestId));
    await recordNotificationEvent({ alert_id: latestId, status: "shown", title: "NetScope Lite", message: body, details: { unacknowledged_count: count } });
  } catch (error) {
    await recordNotificationEvent({ alert_id: latestId, status: "error", title: "NetScope Lite", message: error?.message || "The browser rejected the notification request." });
  }
}

async function requestNotifications() {
  const currentlyEnabled = Boolean(state.settings.alert_preferences?.browser_notifications) && notificationPermissionState() === "granted";
  if (currentlyEnabled) {
    state.settings.alert_preferences = { ...(state.settings.alert_preferences || {}), browser_notifications: false };
    await apiFetch("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ alert_preferences: state.settings.alert_preferences }) });
    await recordNotificationEvent({ status: "disabled", title: "Browser notifications", message: "NetScope Lite browser notifications were disabled for this dashboard." });
    syncNotificationUi();
    showMessage("Browser alert notifications disabled.", "success");
    return;
  }
  if (!("Notification" in window)) {
    await recordNotificationEvent({ status: "unsupported", title: "Browser notifications", message: "This browser does not expose the Notification API." });
    syncNotificationUi();
    return showMessage("Browser notifications are not available in this browser.", "warning");
  }
  const permission = await Notification.requestPermission();
  const enabled = permission === "granted";
  state.settings.alert_preferences = { ...(state.settings.alert_preferences || {}), browser_notifications: enabled };
  await apiFetch("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ alert_preferences: state.settings.alert_preferences }) });
  await recordNotificationEvent({
    status: enabled ? "permission-granted" : permission === "denied" ? "permission-denied" : "permission-default",
    title: "Browser notification permission",
    message: enabled ? "This browser can display local NetScope Lite notifications while the dashboard is open." : permission === "denied" ? "Notification permission is blocked. Change the site permission in the browser to enable it." : "The permission request was dismissed without enabling notifications.",
    details: { permission },
  });
  syncNotificationUi();
  showMessage(enabled ? "Browser alert notifications enabled." : permission === "denied" ? "Notification permission is blocked in the browser." : "Notification permission was not granted.", enabled ? "success" : "warning");
}

function renderProfilesList() {
  const list = $("#profile-list");
  list.replaceChildren();
  for (const profile of state.profiles) {
    const row = document.createElement("article"); row.className = "stack-item";
    const copy = document.createElement("div");
    const title = document.createElement("strong"); title.textContent = profile.name;
    const detail = document.createElement("small"); detail.textContent = `${profile.address_mode} · ${profile.port_mode === "all" ? "all TCP ports" : `${profile.ports.length} ports`} · ${profile.timeout_ms || 260} ms`;
    copy.append(title, detail); row.append(copy);
    if (!profile.built_in) row.append(actionButton("Delete", async () => {
      await apiFetch(`/api/profiles/${profile.id}`, { method: "DELETE" });
      await loadAutomation();
      await loadStatus(true);
    }, "button button-danger compact-button"));
    list.append(row);
  }
}

function renderSchedules() {
  const list = $("#schedule-list"); list.replaceChildren();
  if (!state.schedules.length) { const empty = document.createElement("p"); empty.className = "list-empty"; empty.textContent = "No scheduled scans."; list.append(empty); }
  for (const schedule of state.schedules) {
    const row = document.createElement("article"); row.className = "stack-item";
    const copy = document.createElement("div");
    const title = document.createElement("strong"); title.textContent = schedule.name;
    const profile = state.profiles.find((item) => item.id === schedule.profile_id);
    const detail = document.createElement("small"); detail.textContent = `${profile?.name || "Unknown profile"} · every ${schedule.interval_minutes} min · next ${formatDate(schedule.next_run_at)}`;
    copy.append(title, detail);
    const controls = document.createElement("div"); controls.className = "row-actions";
    controls.append(
      actionButton(schedule.enabled ? "Pause" : "Resume", async () => {
        await apiFetch(`/api/schedules/${schedule.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: !schedule.enabled }) });
        await loadAutomation(); await refreshMonitorOnly();
      }),
      actionButton("Delete", async () => { await apiFetch(`/api/schedules/${schedule.id}`, { method: "DELETE" }); await loadAutomation(); await refreshMonitorOnly(); }, "button button-danger compact-button"),
    );
    row.append(copy, controls); list.append(row);
  }
}

async function loadAutomation() {
  const [profilesPayload, schedulesPayload] = await Promise.all([apiFetch("/api/profiles"), apiFetch("/api/schedules")]);
  state.profiles = profilesPayload.profiles || [];
  state.schedules = schedulesPayload.schedules || [];
  populateProfiles(state.profiles, { applyScan: false });
  renderProfilesList();
  renderSchedules();
  populateScheduleTargets();
  updateScheduleAuthorization();
}

function populateScheduleTargets() {
  const select = $("#schedule-targets");
  const previous = new Set([...select.selectedOptions].map((option) => option.value));
  const profile = state.profiles.find((entry) => String(entry.id) === $("#schedule-profile").value);
  const desiredMode = profile?.address_mode || "standard";
  const targets = state.targetOptions.filter((target) => targetSupportsAddressMode(target, desiredMode));
  select.replaceChildren();
  for (const target of targets) {
    const option = document.createElement("option");
    option.value = target.cidr;
    const link = target.interface ? ` · ${target.interface}${target.kind ? ` (${target.kind})` : ""}` : "";
    option.textContent = `${target.cidr}${link} · ${target.scope === "full-subnet" ? "full subnet" : "local segment"}`;
    option.selected = previous.has(option.value);
    select.append(option);
  }
  if (!select.selectedOptions.length && select.options.length) select.options[0].selected = true;
}

function updateScheduleAuthorization() {
  const profile = state.profiles.find((entry) => String(entry.id) === $("#schedule-profile").value);
  $("#schedule-intensive-wrap").hidden = profile?.port_mode !== "all";
  if (profile?.port_mode !== "all") $("#schedule-intensive").checked = false;
}

async function loadSettings() {
  const [settingsPayload, exclusionsPayload] = await Promise.all([apiFetch("/api/settings"), apiFetch("/api/exclusions")]);
  state.settings = settingsPayload;
  state.exclusions = exclusionsPayload.exclusions || [];
  renderExclusions();
  loadThemeScheduleFields();
  syncNotificationUi();
}

function updateExclusionInputHelp() {
  const kind = $("#exclusion-kind")?.value || "ip";
  const input = $("#exclusion-value");
  const help = $("#exclusion-kind-help");
  if (!input || !help) return;
  const guidance = {
    ip: { placeholder: "192.168.1.50", message: "Enter one private or link-local IPv4 address." },
    cidr: { placeholder: "192.168.1.0/24", message: "Enter a private or link-local IPv4 CIDR that overlaps an attached network." },
    mac: { placeholder: "AA:BB:CC:DD:EE:FF", message: "Enter a six-byte MAC address. Separators may use colons or hyphens." },
  }[kind];
  input.placeholder = guidance.placeholder;
  help.textContent = guidance.message;
}

function renderExclusions() {
  const list = $("#exclusion-list");
  list.replaceChildren();
  const active = state.exclusions.filter((entry) => entry.enabled).length;
  const count = $("#exclusion-count");
  if (count) count.textContent = `${active} active${state.exclusions.length !== active ? ` · ${state.exclusions.length - active} paused` : ""}`;
  if (!state.exclusions.length) {
    const empty = document.createElement("p");
    empty.className = "exclusion-empty";
    empty.textContent = "No exclusions yet. Every eligible address and device in the selected scope can be considered for scanning.";
    list.append(empty);
    return;
  }
  const kindLabels = { ip: "IP", cidr: "CIDR", mac: "MAC" };
  for (const exclusion of state.exclusions) {
    const row = document.createElement("article");
    row.className = `exclusion-card${exclusion.enabled ? "" : " is-paused"}`;
    const kind = document.createElement("span");
    kind.className = "exclusion-kind";
    kind.textContent = kindLabels[exclusion.kind] || exclusion.kind;
    const copy = document.createElement("div");
    copy.className = "exclusion-copy";
    const title = document.createElement("strong");
    title.textContent = exclusion.value;
    title.title = exclusion.value;
    const detail = document.createElement("small");
    detail.textContent = `${exclusion.enabled ? "Applied to scans" : "Paused"}${exclusion.label ? ` · ${exclusion.label}` : ""}`;
    copy.append(title, detail);
    const actions = document.createElement("div");
    actions.className = "exclusion-actions";
    actions.append(
      actionButton(exclusion.enabled ? "Pause" : "Enable", async () => { await apiFetch(`/api/exclusions/${exclusion.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled: !exclusion.enabled }) }); await loadSettings(); }, "button button-secondary compact-button"),
      actionButton("Delete", async () => { await apiFetch(`/api/exclusions/${exclusion.id}`, { method: "DELETE" }); await loadSettings(); }, "button button-danger compact-button"),
    );
    row.append(kind, copy, actions);
    list.append(row);
  }
}

function readThemeSchedule() {
  try { return JSON.parse(storageGet(STORAGE_THEME_SCHEDULE) || "null") || {}; } catch { return {}; }
}

function loadThemeScheduleFields() {
  const settings = state.settings.preferences?.theme_schedule || readThemeSchedule();
  $("#theme-auto").checked = Boolean(settings.enabled);
  $("#theme-day").value = settings.day || "light";
  $("#theme-night").value = settings.night || "purple";
  $("#theme-night-start").value = settings.night_start || "19:00";
  $("#theme-day-start").value = settings.day_start || "07:00";
  applyAutomaticTheme();
}

function minutesForTime(value, fallback) {
  const match = /^(\d{2}):(\d{2})$/.exec(value || "");
  if (!match) return fallback;
  return Number(match[1]) * 60 + Number(match[2]);
}

function applyAutomaticTheme() {
  const settings = state.settings.preferences?.theme_schedule || readThemeSchedule();
  if (!settings.enabled) {
    applyTheme(storageGet(STORAGE_THEME) || "purple", { persist: false });
    return;
  }
  const now = new Date();
  const current = now.getHours() * 60 + now.getMinutes();
  const day = minutesForTime(settings.day_start, 420);
  const night = minutesForTime(settings.night_start, 1140);
  const isNight = night > day ? current >= night || current < day : current >= night && current < day;
  applyTheme(isNight ? settings.night || "purple" : settings.day || "light", { persist: false });
}

async function saveThemeSchedule() {
  const schedule = { enabled: $("#theme-auto").checked, day: $("#theme-day").value, night: $("#theme-night").value, day_start: $("#theme-day-start").value, night_start: $("#theme-night-start").value };
  storageSet(STORAGE_THEME_SCHEDULE, JSON.stringify(schedule));
  state.settings.preferences = { ...(state.settings.preferences || {}), theme_schedule: schedule };
  await apiFetch("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ preferences: state.settings.preferences }) });
  applyAutomaticTheme();
  showMessage("Theme schedule saved.", "success");
}

function observationSummary(observation) {
  const ports = (observation.open_ports || []).slice(0, 8).map((entry) => entry.port).join(", ");
  return `${formatDate(observation.created_at)} · ${observation.ip}${ports ? ` · ports ${ports}` : ""}`;
}

async function openDeviceRecord(deviceId) {
  if (!deviceId) return;
  const device = await apiFetch(`/api/devices/${deviceId}`);
  state.selectedDeviceId = device.id;
  $("#device-dialog-title").textContent = device.custom_name || device.hostname || device.last_ip || "Device details";
  const content = $("#device-dialog-content");
  content.replaceChildren();
  const form = document.createElement("form"); form.className = "device-editor stack-form";
  form.innerHTML = `
    <div class="device-record-summary"><span><strong>${escapeHtml(device.last_ip || "Unknown IP")}</strong><small>${escapeHtml(device.mac || "MAC not observed")}</small></span><span><strong>${escapeHtml(device.vendor || "Unknown vendor")}</strong><small>First seen ${escapeHtml(formatDate(device.first_seen_at))}</small></span></div>
    <label>Custom name<input name="custom_name" maxlength="80" value="${escapeAttribute(device.custom_name || "")}" placeholder="Office printer"></label>
    <label>Trust state<select name="trust_state"><option value="unknown">Unknown</option><option value="trusted">Trusted</option><option value="guest">Guest</option><option value="infrastructure">Infrastructure</option><option value="review">Needs review</option></select></label>
    <label>Tags<input name="tags" maxlength="400" value="${escapeAttribute((device.tags || []).join(", "))}" placeholder="office, printer, managed"></label>
    <label>Notes<textarea name="notes" maxlength="4000" rows="5" placeholder="Ownership, location, maintenance details…">${escapeHtml(device.notes || "")}</textarea></label>
    <label class="switch-row"><input name="ignored" type="checkbox"><span><strong>Ignore alerts for this device</strong><small>The device remains in history and inventory.</small></span></label>
    <div class="inline-actions"><button class="button button-primary" type="submit">Save device</button><button class="button button-secondary" type="button" data-wake>Wake on LAN</button></div>`;
  form.elements.trust_state.value = device.trust_state || "unknown";
  form.elements.ignored.checked = Boolean(device.ignored);
  form.querySelector("[data-wake]").disabled = !device.mac;
  form.querySelector("[data-wake]").addEventListener("click", async () => {
    const result = await apiFetch(`/api/devices/${device.id}/wake`, { method: "POST" });
    showMessage(`Wake packet sent to ${result.mac}.`, "success");
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const updated = await apiFetch(`/api/devices/${device.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ custom_name: data.get("custom_name"), trust_state: data.get("trust_state"), tags: String(data.get("tags") || "").split(",").map((item) => item.trim()).filter(Boolean), notes: data.get("notes"), ignored: data.get("ignored") === "on" }) });
    for (const observed of state.devices.filter((entry) => entry.device_id === updated.id)) Object.assign(observed, { custom_name: updated.custom_name, vendor: updated.vendor, trust_state: updated.trust_state, tags: updated.tags, ignored: updated.ignored });
    renderDevices(); renderInspector(state.devices.find((entry) => entry.ip === state.selectedDeviceIp) || null);
    showMessage("Device record saved.", "success");
    await openDeviceRecord(device.id);
  });
  const history = document.createElement("section"); history.className = "device-history";
  const heading = document.createElement("h3"); heading.textContent = "Observation history"; history.append(heading);
  for (const observation of device.observations || []) { const row = document.createElement("p"); row.textContent = observationSummary(observation); history.append(row); }
  if (!device.observations?.length) { const empty = document.createElement("p"); empty.className = "muted"; empty.textContent = "No observations are stored."; history.append(empty); }
  content.append(form, history);
  openDialog("#device-dialog");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}
function escapeAttribute(value) { return escapeHtml(value).replace(/`/g, "&#96;"); }

async function bootstrapAuth() {
  try {
    const response = await fetch("/api/auth/status", { cache: "no-store" });
    state.auth = await readJsonResponse(response);
    if (state.auth.enabled && !state.auth.authenticated) { showLogin(); return false; }
    return true;
  } catch (error) {
    setStatus("Unavailable", "bad"); showMessage(error.message, "error"); return false;
  }
}

function installDialogHandlers() {
  for (const button of document.querySelectorAll(".dialog-close")) button.addEventListener("click", () => closeDialog(button));
  for (const dialog of document.querySelectorAll("dialog")) dialog.addEventListener("click", (event) => { if (event.target === dialog && dialog.id !== "login-dialog") dialog.close(); });
}

function installKeyboardShortcuts() {
  document.addEventListener("keydown", (event) => {
    if (event.defaultPrevented || event.ctrlKey || event.metaKey || event.altKey) return;
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "");
    if (event.key === "Escape") return;
    if (document.querySelector("dialog[open]") || typing) return;
    const key = event.key.toLowerCase();
    if (key === "s") { event.preventDefault(); runScan(); }
    if (key === "/") { event.preventDefault(); $("#device-search").focus(); }
    if (key === "h") { event.preventDefault(); openDialog("#history-dialog"); loadHistory(); }
    if (key === "a") { event.preventDefault(); openDialog("#alerts-dialog"); loadAlertCenter(); }
    if (key === "t") { event.preventDefault(); openDialog("#theme-dialog"); }
  });
}

function installListeners() {
  $("#scan-button").addEventListener("click", runScan);
  $("#cancel-button").addEventListener("click", cancelScan);
  $("#target-select").addEventListener("change", () => { if ($("#target-select").value) storageSet(STORAGE_TARGET, $("#target-select").value); updateScanSummary(); setScanAvailability(); });
  $("#scan-all-targets").checked = storageGet(STORAGE_SCAN_ALL) === "true";
  $("#scan-all-targets").addEventListener("change", () => { storageSet(STORAGE_SCAN_ALL, String($("#scan-all-targets").checked)); updateScanSummary(); });
  $("#profile-select").addEventListener("change", () => applySelectedProfile());
  for (const input of document.querySelectorAll('input[name="port-mode"]')) input.addEventListener("change", () => { storageSet(STORAGE_PORT_MODE, selectedPortMode()); if (selectedPortMode() !== "all") $("#deep-scan-confirm").checked = false; updateScanSummary(); setScanAvailability(); });
  $("#custom-ports").addEventListener("change", () => { storageSet(STORAGE_CUSTOM_PORTS, $("#custom-ports").value); try { parsePortExpression($("#custom-ports").value); showMessage("Custom port selection updated.", "success"); } catch (error) { showMessage(error.message, "error"); } updateScanSummary(); });
  $("#deep-scan-confirm").addEventListener("change", setScanAvailability);
  $("#select-all-ports").addEventListener("click", () => setAllPorts(true));
  $("#clear-ports").addEventListener("click", () => setAllPorts(false));
  $("#port-groups").addEventListener("click", (event) => { const group = event.target.closest("[data-port-group]")?.dataset.portGroup; if (group && PORT_GROUPS[group]) applyPorts(PORT_GROUPS[group]); });
  $("#map-zoom-in").addEventListener("click", () => applyMapScale(state.mapScale + 0.15));
  $("#map-zoom-out").addEventListener("click", () => applyMapScale(state.mapScale - 0.15));
  $("#map-fit").addEventListener("click", fitMap);
  let searchTimer;
  $("#device-search").addEventListener("input", () => { window.clearTimeout(searchTimer); searchTimer = window.setTimeout(() => renderDevices({ resetLimit: true }), 100); });
  $("#device-filter").addEventListener("change", () => renderDevices({ resetLimit: true }));
  for (const button of [$("#export-button"), $("#export-csv-button")]) button.addEventListener("click", (event) => { if (event.currentTarget.getAttribute("aria-disabled") === "true") event.preventDefault(); });
  window.addEventListener("resize", () => { window.clearTimeout(state.resizeTimer); state.resizeTimer = window.setTimeout(fitMap, 120); });
  $("#theme-button").addEventListener("click", () => openDialog("#theme-dialog"));
  for (const input of document.querySelectorAll('input[name="theme"]')) input.addEventListener("change", () => applyTheme(input.value));
  for (const key of Object.keys(DEFAULT_CUSTOM_THEME)) $("#theme-" + key).addEventListener("input", () => { const theme = Object.fromEntries(Object.keys(DEFAULT_CUSTOM_THEME).map((name) => [name, $("#theme-" + name).value])); writeCustomTheme(theme); applyTheme("custom"); });
  $("#theme-reset").addEventListener("click", () => { writeCustomTheme(DEFAULT_CUSTOM_THEME); syncCustomThemeFields(DEFAULT_CUSTOM_THEME); applyTheme("custom"); });
  $("#history-button").addEventListener("click", () => { openDialog("#history-dialog"); loadHistory(); });
  $("#refresh-history").addEventListener("click", loadHistory);
  $("#compare-history").addEventListener("click", () => compareHistory().catch(reportUiError));
  $("#print-history").addEventListener("click", () => (async () => { const [id] = selectedHistoryIds(); if (!id) return; const entry = await apiFetch(`/api/history/${id}`); renderResult(entry.result); $("#history-dialog").close(); window.print(); })().catch(reportUiError));
  $("#history-import").addEventListener("change", async (event) => { try { await importHistory(event.target.files?.[0]); showMessage("Scan history imported.", "success"); } catch (error) { showMessage(error.message, "error"); } finally { event.target.value = ""; } });
  $("#alerts-button").addEventListener("click", () => { openDialog("#alerts-dialog"); loadAlertCenter(); });
  $("#refresh-alerts").addEventListener("click", loadAlerts);
  $("#alert-filter").addEventListener("change", loadAlerts);
  $("#acknowledge-all-alerts").addEventListener("click", () => (async () => { await apiFetch("/api/alerts/acknowledge-all", { method: "POST" }); await loadAlerts(); await refreshMonitorOnly(); })().catch(reportUiError));
  $("#notification-button").addEventListener("click", () => requestNotifications().catch(reportUiError));
  $("#notification-dialog-button").addEventListener("click", () => requestNotifications().catch(reportUiError));
  $("#refresh-notification-history").addEventListener("click", loadNotificationHistory);
  $("#clear-notification-history").addEventListener("click", () => (async () => { await apiFetch("/api/notifications/history", { method: "DELETE" }); await loadNotificationHistory(); showMessage("Notification history cleared.", "success"); })().catch(reportUiError));
  $("#automation-button").addEventListener("click", async () => { openDialog("#automation-dialog"); try { await loadAutomation(); } catch (error) { showMessage(error.message, "error"); } });
  $("#schedule-profile").addEventListener("change", () => { updateScheduleAuthorization(); populateScheduleTargets(); });
  $("#schedule-form").addEventListener("submit", async (event) => { event.preventDefault(); const targets = [...$("#schedule-targets").selectedOptions].map((option) => option.value); try { await apiFetch("/api/schedules", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: $("#schedule-name").value, targets, profile_id: Number($("#schedule-profile").value), interval_minutes: Number($("#schedule-interval").value), allow_intensive: $("#schedule-intensive").checked }) }); event.target.reset(); await loadAutomation(); await refreshMonitorOnly(); } catch (error) { showMessage(error.message, "error"); } });
  $("#profile-port-mode").addEventListener("change", () => { $("#profile-ports").disabled = $("#profile-port-mode").value === "all"; });
  $("#profile-form").addEventListener("submit", async (event) => { event.preventDefault(); try { const portMode = $("#profile-port-mode").value; const ports = portMode === "all" ? [] : parsePortExpression($("#profile-ports").value, { allowEmpty: false }); await apiFetch("/api/profiles", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: $("#profile-name").value, address_mode: $("#profile-address-mode").value, port_mode: portMode, ports, timeout_ms: Number($("#profile-timeout").value) }) }); event.target.reset(); $("#profile-timeout").value = "260"; await loadAutomation(); } catch (error) { showMessage(error.message, "error"); } });
  $("#settings-button").addEventListener("click", async () => { openDialog("#settings-dialog"); try { await loadSettings(); } catch (error) { showMessage(error.message, "error"); } });
  $("#exclusion-kind").addEventListener("change", updateExclusionInputHelp);
  $("#exclusion-form").addEventListener("submit", async (event) => { event.preventDefault(); try { await apiFetch("/api/exclusions", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ kind: $("#exclusion-kind").value, value: $("#exclusion-value").value, label: $("#exclusion-label").value }) }); event.target.reset(); updateExclusionInputHelp(); await loadSettings(); } catch (error) { showMessage(error.message, "error"); } });
  $("#save-theme-schedule").addEventListener("click", () => saveThemeSchedule().catch((error) => showMessage(error.message, "error")));
  $("#password-form").addEventListener("submit", async (event) => { event.preventDefault(); try { const payload = await apiFetch("/api/auth/password", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ current_password: $("#current-password").value, new_password: $("#new-password").value }) }); event.target.reset(); showMessage(payload.enabled ? "Password protection enabled. Sign in to continue." : "Password protection disabled.", "success"); $("#settings-dialog").close(); if (payload.enabled) showLogin(); } catch (error) { showMessage(error.message, "error"); } });
  $("#open-device-button").addEventListener("click", () => openDeviceRecord(Number($("#open-device-button").dataset.deviceId)).catch((error) => showMessage(error.message, "error")));
  $("#login-form").addEventListener("submit", async (event) => { event.preventDefault(); const feedback = $("#login-message"); try { const response = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: $("#login-password").value }) }); const payload = await readJsonResponse(response); if (!response.ok) throw new Error(payload.error || "Unable to sign in."); feedback.hidden = true; $("#login-password").value = ""; $("#login-dialog").close(); state.auth = { enabled: true, authenticated: true }; await loadStatus(); } catch (error) { feedback.hidden = false; feedback.textContent = error.message; } });
  installDialogHandlers();
  installKeyboardShortcuts();
}

window.addEventListener("unhandledrejection", (event) => {
  event.preventDefault();
  reportUiError(event.reason);
});
window.addEventListener("focus", syncNotificationUi);

initializeTheme();
const storedMode = storageGet(STORAGE_PORT_MODE);
const storedModeInput = document.querySelector(`input[name="port-mode"][value="${storedMode}"]`);
if (storedModeInput) storedModeInput.checked = true;
$("#custom-ports").value = storageGet(STORAGE_CUSTOM_PORTS) || "";
installListeners();
updateExclusionInputHelp();
syncNotificationUi();
updateScanSummary();
window.setInterval(applyAutomaticTheme, 60_000);
bootstrapAuth().then((ready) => { if (ready) loadStatus(); });
