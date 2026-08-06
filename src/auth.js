import crypto from "node:crypto";
import process from "node:process";

const PASSWORD_SETTING = "auth.password";
const SESSION_COOKIE = "netscope_session";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_SESSIONS = 128;
const MAX_PASSWORD_LENGTH = 200;
const FAILED_LOGIN_WINDOW_MS = 60_000;
const MAX_FAILED_LOGINS = 8;

function hashPassword(password, salt = crypto.randomBytes(16)) {
  const derived = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return { salt: salt.toString("base64"), hash: derived.toString("base64"), algorithm: "scrypt" };
}

function verifyPassword(password, record) {
  if (!record?.salt || !record?.hash) return false;
  try {
    const salt = Buffer.from(record.salt, "base64");
    const expected = Buffer.from(record.hash, "base64");
    const actual = crypto.scryptSync(password, salt, expected.length, { N: 16384, r: 8, p: 1 });
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}


function derivePassword(password, salt, length) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, length, { N: 16384, r: 8, p: 1 }, (error, derived) => {
      if (error) reject(error);
      else resolve(derived);
    });
  });
}

async function hashPasswordAsync(password, salt = crypto.randomBytes(16)) {
  const derived = await derivePassword(password, salt, 64);
  return { salt: salt.toString("base64"), hash: derived.toString("base64"), algorithm: "scrypt" };
}

async function verifyPasswordAsync(password, record) {
  if (!record?.salt || !record?.hash) return false;
  try {
    const salt = Buffer.from(record.salt, "base64");
    const expected = Buffer.from(record.hash, "base64");
    const actual = await derivePassword(password, salt, expected.length);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

function cookieValue(request, name) {
  const header = String(request.headers.cookie ?? "");
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) {
      try {
        return decodeURIComponent(rest.join("="));
      } catch {
        return null;
      }
    }
  }
  return null;
}

export class AuthManager {
  constructor({ store, environmentPassword = process.env.NETSCOPE_PASSWORD, maxSessions = MAX_SESSIONS, maxFailedLogins = MAX_FAILED_LOGINS } = {}) {
    this.store = store;
    this.sessions = new Map();
    this.failedLogins = [];
    this.maxSessions = Math.max(1, Number(maxSessions) || MAX_SESSIONS);
    this.maxFailedLogins = Math.max(1, Number(maxFailedLogins) || MAX_FAILED_LOGINS);
    if (!this.store.getSetting(PASSWORD_SETTING) && environmentPassword) {
      this.setInitialPassword(environmentPassword);
    }
  }

  setInitialPassword(password) {
    const normalized = String(password ?? "");
    if (normalized.length < 8 || normalized.length > MAX_PASSWORD_LENGTH) throw new Error(`NETSCOPE_PASSWORD must contain between 8 and ${MAX_PASSWORD_LENGTH} characters.`);
    this.store.setSetting(PASSWORD_SETTING, hashPassword(normalized));
  }

  enabled() {
    return Boolean(this.store.getSetting(PASSWORD_SETTING));
  }

  purgeSessions() {
    const now = Date.now();
    for (const [token, session] of this.sessions) if (session.expiresAt <= now) this.sessions.delete(token);
  }

  sessionFor(request) {
    if (!this.enabled()) return { authenticated: true, token: null };
    this.purgeSessions();
    const token = cookieValue(request, SESSION_COOKIE);
    const session = token ? this.sessions.get(token) : null;
    if (!session || session.expiresAt <= Date.now()) return { authenticated: false, token: null };
    session.expiresAt = Date.now() + SESSION_TTL_MS;
    return { authenticated: true, token };
  }

  status(request) {
    const session = this.sessionFor(request);
    return { enabled: this.enabled(), authenticated: session.authenticated };
  }

  async login(password) {
    const record = this.store.getSetting(PASSWORD_SETTING);
    if (!record) return { authenticated: true, cookie: this.clearCookie() };
    const now = Date.now();
    this.failedLogins = this.failedLogins.filter((timestamp) => now - timestamp < FAILED_LOGIN_WINDOW_MS);
    if (this.failedLogins.length >= this.maxFailedLogins) {
      throw Object.assign(new Error("Too many failed sign-in attempts. Try again in a minute."), { status: 429 });
    }
    const normalized = String(password ?? "");
    if (normalized.length > MAX_PASSWORD_LENGTH || !await verifyPasswordAsync(normalized, record)) {
      this.failedLogins.push(now);
      throw Object.assign(new Error("Incorrect password."), { status: 401 });
    }
    this.failedLogins = [];
    this.purgeSessions();
    while (this.sessions.size >= this.maxSessions) this.sessions.delete(this.sessions.keys().next().value);
    const token = crypto.randomBytes(32).toString("base64url");
    this.sessions.set(token, { expiresAt: now + SESSION_TTL_MS });
    return { authenticated: true, cookie: `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}` };
  }

  logout(request) {
    const token = cookieValue(request, SESSION_COOKIE);
    if (token) this.sessions.delete(token);
    return { authenticated: false, cookie: this.clearCookie() };
  }

  clearCookie() {
    return `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`;
  }

  async setPassword({ currentPassword = "", newPassword = "" } = {}) {
    const existing = this.store.getSetting(PASSWORD_SETTING);
    if (existing && !await verifyPasswordAsync(String(currentPassword), existing)) throw Object.assign(new Error("Current password is incorrect."), { status: 401 });
    const normalized = String(newPassword ?? "");
    if (!normalized) {
      this.store.setSetting(PASSWORD_SETTING, null);
      this.sessions.clear();
      return { enabled: false };
    }
    if (normalized.length < 8 || normalized.length > MAX_PASSWORD_LENGTH) throw Object.assign(new Error("Password must contain between 8 and 200 characters."), { status: 400 });
    this.store.setSetting(PASSWORD_SETTING, await hashPasswordAsync(normalized));
    this.sessions.clear();
    return { enabled: true };
  }
}
