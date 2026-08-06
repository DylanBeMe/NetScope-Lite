import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";
import { broadcastAddresses, magicPacket, sendWakeOnLan } from "../src/wol.js";

test("Wake-on-LAN packets contain the synchronization stream and sixteen MAC repetitions", () => {
  const packet = magicPacket("00-11-22-33-44-55");
  assert.equal(packet.length, 102);
  assert.deepEqual([...packet.subarray(0, 6)], [255, 255, 255, 255, 255, 255]);
  for (let offset = 6; offset < packet.length; offset += 6) {
    assert.deepEqual([...packet.subarray(offset, offset + 6)], [0, 17, 34, 51, 68, 85]);
  }
  assert.throws(() => magicPacket("not-a-mac"), /valid device MAC address/i);
});

test("Wake-on-LAN broadcast destinations include global and attached interface broadcasts", () => {
  assert.deepEqual(
    broadcastAddresses([
      { network: "192.168.10.0/24" },
      { network: "10.5.0.0/16" },
      { network: "bad-network" },
      { network: "192.168.10.0/24" }
    ]).sort(),
    ["10.5.255.255", "192.168.10.255", "255.255.255.255"].sort()
  );
});

test("Wake-on-LAN sends once per broadcast and always closes its socket", async () => {
  const sent = [];
  class FakeSocket extends EventEmitter {
    bind(_port, _host, callback) { queueMicrotask(callback); }
    setBroadcast(value) { this.broadcast = value; }
    send(packet, port, address, callback) {
      sent.push({ length: packet.length, port, address });
      queueMicrotask(() => callback(null));
    }
    close() { this.closed = true; }
  }
  const socket = new FakeSocket();
  const result = await sendWakeOnLan("00:11:22:33:44:55", {
    interfaces: [{ network: "192.168.1.0/24" }],
    port: 7,
    createSocket: () => socket
  });
  assert.equal(socket.broadcast, true);
  assert.equal(socket.closed, true);
  assert.deepEqual(sent, [
    { length: 102, port: 7, address: "255.255.255.255" },
    { length: 102, port: 7, address: "192.168.1.255" }
  ]);
  assert.deepEqual(result, {
    sent: true,
    destinations: ["255.255.255.255", "192.168.1.255"],
    port: 7
  });
});

test("Wake-on-LAN closes the socket when a send fails", async () => {
  class FakeSocket extends EventEmitter {
    bind(_port, _host, callback) { queueMicrotask(callback); }
    setBroadcast() {}
    send(_packet, _port, _address, callback) { queueMicrotask(() => callback(new Error("send failed"))); }
    close() { this.closed = true; }
  }
  const socket = new FakeSocket();
  await assert.rejects(
    sendWakeOnLan("00:11:22:33:44:55", { createSocket: () => socket }),
    /send failed/
  );
  assert.equal(socket.closed, true);
});

test("Wake-on-LAN rejects asynchronous socket errors during a send", async () => {
  class FakeSocket extends EventEmitter {
    bind(_port, _host, callback) { queueMicrotask(callback); }
    setBroadcast() {}
    send() { queueMicrotask(() => this.emit("error", new Error("socket failed"))); }
    close() { this.closed = true; }
  }
  const socket = new FakeSocket();
  await assert.rejects(
    sendWakeOnLan("00:11:22:33:44:55", { createSocket: () => socket }),
    /socket failed/
  );
  assert.equal(socket.closed, true);
});
