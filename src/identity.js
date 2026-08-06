const COMMON_OUIS = new Map([
  ["001A11", "Google"], ["3C5AB4", "Google"], ["F4F5D8", "Google"],
  ["000C29", "VMware"], ["005056", "VMware"], ["001C14", "VMware"],
  ["080027", "VirtualBox"], ["00163E", "Xen"], ["525400", "QEMU / KVM"],
  ["001B21", "Intel"], ["3C970E", "Intel"], ["F8F21E", "Intel"],
  ["D850E6", "ASUS"], ["2CFDA1", "ASUS"], ["AC220B", "ASUS"],
  ["001E58", "D-Link"], ["1C7EE5", "D-Link"], ["C4A81D", "D-Link"],
  ["001D0F", "TP-Link"], ["50C7BF", "TP-Link"], ["B0487A", "TP-Link"], ["E848B8", "TP-Link"],
  ["00146C", "NETGEAR"], ["204E7F", "NETGEAR"], ["A42B8C", "NETGEAR"],
  ["001A2B", "Cisco"], ["001B54", "Cisco"], ["F4CFD2", "Cisco"],
  ["00155D", "Microsoft Hyper-V"], ["7C1E52", "Microsoft"], ["281878", "Microsoft"],
  ["0016CB", "Apple"], ["3C0754", "Apple"], ["F0D1A9", "Apple"], ["A4D1D2", "Apple"],
  ["B827EB", "Raspberry Pi"], ["DCA632", "Raspberry Pi"], ["E45F01", "Raspberry Pi"],
  ["001788", "Philips"], ["ECB5FA", "Philips Hue"],
  ["18B430", "Nest"], ["641666", "Nest"],
  ["44D9E7", "Ubiquiti"], ["802AA8", "Ubiquiti"], ["F09FC2", "Ubiquiti"],
  ["001132", "Synology"], ["0011D8", "Synology"],
  ["001F33", "QNAP"], ["245EBE", "QNAP"],
  ["00055D", "D-Link"], ["0018E7", "Cameo / embedded"],
  ["B0BE76", "TP-Link / Tapo"], ["54AF97", "TP-Link / Tapo"],
  ["ACCC8E", "Axis Communications"], ["00408C", "Axis Communications"],
  ["001788", "Philips Lighting"], ["68A40E", "BSH Home Appliances"],
  ["F0272D", "Amazon"], ["FC65DE", "Amazon"], ["B47C9C", "Amazon"],
  ["CC50E3", "Espressif"], ["24A160", "Espressif"], ["A4CF12", "Espressif"],
  ["001A79", "Zyxel"], ["5C6A80", "Zyxel"],
]);

export function normalizeMac(value) {
  if (typeof value !== "string") return null;
  const compact = value.replace(/[^0-9a-f]/gi, "").toUpperCase();
  if (!/^[0-9A-F]{12}$/.test(compact) || compact === "000000000000" || compact === "FFFFFFFFFFFF") return null;
  return compact.match(/.{2}/g).join(":").toLowerCase();
}

export function isLocallyAdministeredMac(value) {
  const mac = normalizeMac(value);
  if (!mac) return false;
  return (Number.parseInt(mac.slice(0, 2), 16) & 0x02) !== 0;
}

export function vendorFromMac(value) {
  const mac = normalizeMac(value);
  if (!mac) return null;
  if (isLocallyAdministeredMac(mac)) return "Locally administered";
  const key = mac.replaceAll(":", "").slice(0, 6).toUpperCase();
  return COMMON_OUIS.get(key) ?? null;
}

export function identityKeyForDevice(device, target = "") {
  const mac = normalizeMac(device?.mac);
  if (mac) return `mac:${mac}`;
  const hostname = String(device?.hostname ?? "").trim().toLowerCase();
  if (hostname && !/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return `host:${hostname}`;
  return `ip:${target}:${String(device?.ip ?? "unknown")}`;
}

export function displayNameForDevice(device, profile = null) {
  return profile?.customName || device?.custom_name || device?.hostname || device?.ip || "Unknown device";
}
