export const BUILT_IN_PROFILES = Object.freeze([
  Object.freeze({ name: "Quick", addressMode: "standard", portMode: "selected", ports: Object.freeze([22, 80, 443]), timeoutMs: 180 }),
  Object.freeze({ name: "Standard", addressMode: "standard", portMode: "selected", ports: Object.freeze([22, 53, 80, 443, 445, 631, 3389, 8080, 8443, 9100]), timeoutMs: 260 }),
  Object.freeze({ name: "Deep", addressMode: "extended", portMode: "selected", ports: Object.freeze([20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 515, 587, 631, 636, 993, 995, 1433, 1521, 1883, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 8883, 9000, 9100, 9200, 27017]), timeoutMs: 360 }),
  Object.freeze({ name: "All TCP ports", addressMode: "extended", portMode: "all", ports: Object.freeze([22, 53, 80, 443, 445, 631, 3389, 8080, 8443, 9100]), timeoutMs: 260 }),
]);

export function builtInProfilesForApi() {
  return BUILT_IN_PROFILES.map((profile, index) => ({
    id: index + 1,
    name: profile.name,
    built_in: true,
    address_mode: profile.addressMode,
    port_mode: profile.portMode,
    ports: [...profile.ports],
    timeout_ms: profile.timeoutMs,
  }));
}
