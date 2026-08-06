import dgram from "node:dgram";
import { normalizeMac } from "./identity.js";
import { parseIPv4Network } from "./safety.js";

export function magicPacket(macValue) {
  const mac = normalizeMac(macValue);
  if (!mac) throw Object.assign(new Error("A valid device MAC address is required for Wake-on-LAN."), { status: 400 });
  const bytes = Buffer.from(mac.replaceAll(":", ""), "hex");
  return Buffer.concat([Buffer.alloc(6, 0xff), ...Array.from({ length: 16 }, () => bytes)]);
}

export function broadcastAddresses(interfaces = []) {
  const addresses = new Set(["255.255.255.255"]);
  for (const item of interfaces) {
    try {
      const network = parseIPv4Network(item.network);
      const value = network.broadcastInt;
      addresses.add([24, 16, 8, 0].map((shift) => Math.floor(value / (2 ** shift)) % 256).join("."));
    } catch {
      // Ignore malformed interface snapshots.
    }
  }
  return [...addresses];
}

export async function sendWakeOnLan(mac, { interfaces = [], port = 9, createSocket = () => dgram.createSocket("udp4") } = {}) {
  const packet = magicPacket(mac);
  const destinations = broadcastAddresses(interfaces);
  const socket = createSocket();
  let activeReject = null;
  let closed = false;

  const closeSocket = () => {
    if (closed) return;
    closed = true;
    socket.removeListener("error", onSocketError);
    socket.close();
  };
  const onSocketError = (error) => {
    const reject = activeReject;
    activeReject = null;
    if (reject) reject(error);
  };
  const operation = (start) => new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (activeReject === fail) activeReject = null;
      if (error) reject(error);
      else resolve(value);
    };
    const fail = (error) => finish(error);
    activeReject = fail;
    try {
      start(finish);
    } catch (error) {
      finish(error);
    }
  });

  socket.on("error", onSocketError);
  try {
    await operation((finish) => {
      socket.bind(0, "0.0.0.0", () => {
        try {
          socket.setBroadcast(true);
          finish();
        } catch (error) {
          finish(error);
        }
      });
    });
    for (const address of destinations) {
      await operation((finish) => {
        socket.send(packet, port, address, (error) => finish(error || null));
      });
    }
  } finally {
    closeSocket();
  }
  return { sent: true, destinations, port };
}
