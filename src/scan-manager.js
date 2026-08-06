import { normalizePorts, parseIPv4Network } from "./safety.js";

function conflict(message) {
  return Object.assign(new Error(message), { status: 409 });
}

function validation(message) {
  return Object.assign(new Error(message), { status: 400 });
}

function normalizeTargets(payload) {
  const raw = Array.isArray(payload.targets) ? payload.targets : [payload.target];
  const targets = [];
  const seen = new Set();
  for (const value of raw) {
    const text = String(value ?? "").trim();
    if (!text) continue;
    let cidr;
    try {
      cidr = parseIPv4Network(text).cidr;
    } catch (error) {
      throw validation(error.message || "Enter a valid IPv4 network.");
    }
    if (seen.has(cidr)) continue;
    seen.add(cidr);
    targets.push(cidr);
  }
  if (!targets.length) throw validation("Choose at least one target network.");
  if (targets.length > 8) throw validation("At most eight attached networks may be scanned in one batch.");
  return targets;
}

function exclusionsForScanner(entries) {
  const enabled = entries.filter((entry) => entry.enabled !== false);
  return {
    excludedIps: enabled.filter((entry) => entry.kind === "ip").map((entry) => entry.value),
    excludedCidrs: enabled.filter((entry) => entry.kind === "cidr").map((entry) => entry.value),
    excludedMacs: enabled.filter((entry) => entry.kind === "mac").map((entry) => entry.value),
  };
}

export class ScanManager {
  constructor({ scanner, store, state = {}, logger = console } = {}) {
    if (!scanner || !store) throw new Error("scanner and store are required.");
    this.scanner = scanner;
    this.store = store;
    this.state = state;
    this.logger = logger;
    this.state.scanRunning = Boolean(this.state.scanRunning);
  }

  getState() {
    return { scan_running: this.state.scanRunning, progress: this.state.progress ?? null, source: this.state.scanSource ?? null };
  }

  cancel() {
    if (!this.state.scanRunning || !this.state.abortController) throw conflict("No scan is currently running.");
    this.state.progress = { ...(this.state.progress ?? {}), phase: "cancelling", message: "Cancelling scan…" };
    this.state.abortController.abort();
    return { status: "cancelling" };
  }

  resolveProfile(payload) {
    if (payload.profile_id == null) return null;
    const profile = this.store.getProfile(Number(payload.profile_id));
    if (!profile) throw validation("Choose a valid scan profile.");
    return profile;
  }

  normalizeRequest(payload, { scheduled = false } = {}) {
    const profile = this.resolveProfile(payload);
    const targets = normalizeTargets(payload);
    const portMode = String(payload.port_mode ?? profile?.port_mode ?? "selected");
    const addressMode = String(payload.address_mode ?? profile?.address_mode ?? "standard");
    if (!["selected", "all"].includes(portMode)) throw validation("Port mode must be selected or all.");
    if (!["standard", "extended"].includes(addressMode)) throw validation("Address mode must be standard or extended.");
    const rawPorts = Object.hasOwn(payload, "ports") ? payload.ports : profile?.ports ?? this.scanner.DEFAULT_PORTS;
    let ports;
    try {
      ports = normalizePorts(rawPorts, { limit: 1024 });
      if (portMode === "all" && ports.length === 0) {
        ports = normalizePorts(this.scanner.DEFAULT_PORTS ?? [22, 53, 80, 443, 445, 3389, 8080], { limit: 1024 });
      }
    } catch (error) {
      if (error instanceof TypeError || error instanceof RangeError) throw validation(error.message);
      throw error;
    }
    const authorized = payload.authorized === true || (scheduled && payload.allow_intensive === true);
    if (portMode === "all" && !authorized) throw validation("All-port scans require explicit authorization acknowledgement.");
    const timeoutMs = Number(payload.timeout_ms ?? profile?.timeout_ms ?? 0);
    if (timeoutMs && (!Number.isFinite(timeoutMs) || timeoutMs < 50 || timeoutMs > 5000)) throw validation("Timeout must be between 50 and 5000 milliseconds.");
    return { targets, profile, portMode, addressMode, ports, timeoutMs: timeoutMs || null, authorized };
  }

  async run(payload, { source = "live", scheduled = false } = {}) {
    if (this.state.scanRunning) throw conflict("A scan is already running.");
    const request = this.normalizeRequest(payload, { scheduled });
    if (this.state.scanRunning) throw conflict("A scan is already running.");
    this.state.scanRunning = true;
    this.state.scanSource = source;
    this.state.abortController = new AbortController();
    this.state.progress = { phase: "starting", completed: 0, total: 0, percent: 0, message: "Preparing local scan." };
    const results = [];
    try {
      const exclusions = exclusionsForScanner(this.store.listExclusions());
      for (let index = 0; index < request.targets.length; index += 1) {
        const target = request.targets[index];
        const previousResult = this.store.getLatestResult(target);
        const result = await this.scanner.scanNetwork(target, {
          ports: request.ports,
          portMode: request.portMode,
          extendedAddressScan: request.addressMode === "extended",
          previousResult,
          signal: this.state.abortController.signal,
          portTimeoutMs: request.timeoutMs ?? undefined,
          fullPortTimeoutMs: request.timeoutMs ?? undefined,
          ...exclusions,
          onProgress: (progress) => {
            const completedTargets = index;
            const localPercent = Number(progress.percent || 0);
            const overallPercent = ((completedTargets + localPercent / 100) / request.targets.length) * 100;
            this.state.progress = {
              ...progress,
              target,
              target_index: index + 1,
              target_count: request.targets.length,
              percent: Math.round(overallPercent * 10) / 10,
              message: request.targets.length > 1 ? `[${index + 1}/${request.targets.length}] ${progress.message}` : progress.message,
              updated_at: new Date().toISOString(),
            };
          },
        });
        const stored = this.store.saveScan(result, { source, profileName: request.profile?.name ?? null });
        result.scan_id = stored.scan_id;
        result.alert_count = stored.alert_count;
        result.saved = true;
        for (const device of result.devices ?? []) {
          if (stored.device_ids?.[device.ip]) device.device_id = stored.device_ids[device.ip];
        }
        results.push(result);
      }
      this.state.progress = { phase: "complete", completed: 1, total: 1, percent: 100, message: request.targets.length > 1 ? `Completed ${request.targets.length} network scans.` : "Scan complete." };
      return request.targets.length === 1 ? results[0] : {
        batch: true,
        generated_at: new Date().toISOString(),
        targets: request.targets,
        results,
        latest: results.at(-1),
        summary: {
          network_count: results.length,
          device_count: results.reduce((sum, result) => sum + Number(result.summary?.device_count ?? 0), 0),
          alert_count: results.reduce((sum, result) => sum + Number(result.alert_count ?? 0), 0),
        },
      };
    } catch (error) {
      if (error?.name === "AbortError") {
        this.state.progress = { phase: "cancelled", completed: 0, total: 0, percent: 0, message: "Scan cancelled." };
      }
      throw error;
    } finally {
      this.state.scanRunning = false;
      this.state.scanSource = null;
      this.state.abortController = null;
    }
  }
}

export class ScanScheduler {
  constructor({ store, scanManager, logger = console, intervalMs = 30_000 } = {}) {
    this.store = store;
    this.scanManager = scanManager;
    this.logger = logger;
    this.intervalMs = Math.max(5_000, intervalMs);
    this.timer = null;
    this.running = false;
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => this.tick(), this.intervalMs);
    this.timer.unref?.();
    queueMicrotask(() => this.tick());
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async tick() {
    if (this.running || this.scanManager.getState().scan_running) return;
    const due = this.store.dueSchedules();
    if (!due.length) return;
    this.running = true;
    try {
      for (const schedule of due) {
        if (this.scanManager.getState().scan_running) break;
        const profile = this.store.getProfile(schedule.profile_id);
        if (!profile) {
          this.store.markScheduleRun(schedule.id, { status: "profile-missing" });
          continue;
        }
        try {
          await this.scanManager.run({
            targets: schedule.targets,
            profile_id: profile.id,
            allow_intensive: schedule.allow_intensive,
          }, { source: "scheduled", scheduled: true });
          this.store.markScheduleRun(schedule.id, { status: "complete" });
        } catch (error) {
          this.logger.error?.("Scheduled scan failed.", error);
          this.store.markScheduleRun(schedule.id, { status: error?.name === "AbortError" ? "cancelled" : "failed" });
        }
      }
    } finally {
      this.running = false;
    }
  }
}
