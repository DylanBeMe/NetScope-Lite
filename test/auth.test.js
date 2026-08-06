import assert from "node:assert/strict";
import test from "node:test";
import { AuthManager } from "../src/auth.js";
import { MemoryStore } from "../src/memory-store.js";

test("authentication bounds password length, failed attempts, and active sessions", async () => {
  const store = new MemoryStore();
  assert.throws(() => new AuthManager({ store, environmentPassword: "x".repeat(201) }), /between 8 and 200/);
  const auth = new AuthManager({ store, environmentPassword: "correct horse battery staple", maxFailedLogins: 1 });
  for (let attempt = 0; attempt < 1; attempt += 1) {
    await assert.rejects(() => auth.login("wrong password"), (error) => error.status === 401);
  }
  await assert.rejects(() => auth.login("wrong password"), (error) => error.status === 429);

  const fresh = new AuthManager({ store, maxSessions: 3 });
  const order = [];
  const firstLogin = fresh.login("correct horse battery staple").then(() => order.push("login"));
  await new Promise((resolve) => setImmediate(() => { order.push("event-loop"); resolve(); }));
  await firstLogin;
  assert.equal(order[0], "event-loop", "password verification should not block the event loop");
  for (let index = 0; index < 4; index += 1) await fresh.login("correct horse battery staple");
  assert.equal(fresh.sessions.size, 3);
});
