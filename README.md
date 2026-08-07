<p align="center">
  <img src="static/favicon.svg" width="92" height="92" alt="NetScope Lite logo">
</p>

<h1 align="center">NetScope Lite</h1>

<p align="center">
  A private, host-observed network mapper and monitor for attached local networks.
</p>

NetScope Lite discovers devices, maps logical network context, keeps scan history, tracks known equipment, and highlights meaningful changes from a responsive local dashboard. It is built with Node.js, plain JavaScript, HTML, CSS, SQLite, `better-sqlite3`, and Drizzle ORM.

The application is intentionally smaller than a SIEM. It does not ingest logs, connect to routers or infrastructure controllers, match vulnerabilities, or send network data to a cloud service.

## Highlights

- Combined ICMP, neighbor-table, reverse-DNS, and bounded TCP discovery.
- Logical topology grouped into infrastructure, servers, endpoints, peripherals/IoT, and unknown devices.
- Gateway, route, interface, resolver, subnet, host, and passive IPv6 context.
- Quick, Standard, Deep, All TCP Ports, and custom scan profiles.
- Single-network or multi-network scans across attached private and link-local interfaces.
- SQLite-backed snapshots, comparisons, device observations, alerts, schedules, exclusions, and settings.
- Persistent device names, notes, tags, trust states, ignored status, and Wake-on-LAN.
- Alerts for new devices, missing devices, service changes, sensitive ports, gateway changes, and DNS changes.
- Optional browser notifications with a persistent local notification-delivery history.
- JSON and spreadsheet-safe CSV export, JSON import, and printable reports.
- Purple, Midnight, Light, High Contrast, and Custom themes.
- Optional local password protection.
- Responsive desktop and mobile layouts with keyboard navigation.
- Docker image, Compose examples, automated checks, container smoke tests, and GHCR publishing workflows.

## Safety model

NetScope Lite only accepts private or IPv4 link-local networks that overlap an interface attached to the computer running it.

It rejects:

- Public or reserved Internet targets.
- Private targets that are not attached to the host.
- Standard scans larger than 256 addresses.
- Extended scans larger than 4,096 addresses.
- More than eight networks in one batch.

All-port mode discovers devices first and then checks TCP ports 1 through 65,535 only on devices with observed evidence. It does not blindly attempt every port against every silent address. Manual and scheduled all-port scans require explicit authorization.

Use this software only on networks you own or are authorized to administer.

## Requirements

### Native installation

- Node.js 20 or newer.
- Windows, Linux, or macOS.
- Permission to scan the selected attached network.
- Build tools only when a prebuilt `better-sqlite3` binary is unavailable for the operating system and Node.js release.

### Container installation

- Docker Engine or Docker Desktop with Compose support.
- Linux host networking for the most accurate containerized LAN view.

## Quick start

```bash
npm install
npm start
```

Open:

```text
http://127.0.0.1:8787
```

To start the server and ask the operating system to open the browser:

```bash
npm run launch
```

The native server binds to loopback by default and refuses non-loopback addresses.

## Docker

The image runs as the unprivileged `node` user, stores its database under `/data`, includes the Linux networking tools used by discovery, and exposes a `/healthz` health check. The image defaults to loopback binding; bridge-mode examples explicitly opt into the container-internal `0.0.0.0` bind and still publish only to the host loopback interface.

### Safe bridge mode

```bash
cp .env.example .env
docker compose up --build -d
```

Open `http://127.0.0.1:8787`.

Bridge mode publishes the dashboard only on the host loopback interface. It is suitable for validating the container and observing its Docker bridge network, but the container does not share the host's physical network interfaces.

### LAN or reverse-proxy access

Host-header validation accepts loopback hosts by default. To open the dashboard through a LAN IP, DNS name, or reverse-proxy hostname, add the exact browser-facing hostnames or IP addresses to `NETSCOPE_ALLOWED_HOSTS`. Values are comma-separated, case-insensitive, and must not include a URL scheme or port.

For example, if the Docker host is `192.168.1.50` and you browse to `http://192.168.1.50:8787`, set:

```dotenv
NETSCOPE_ALLOWED_HOSTS=192.168.1.50
```

The Compose files pass this value through from `.env`. Their default port publishing is still loopback-only. To intentionally expose bridge mode to the LAN, change the port mapping from `127.0.0.1:8787:8787` to `8787:8787` (or bind it to a specific host interface), and enable `NETSCOPE_PASSWORD`. Use a host firewall to limit which clients can reach the dashboard.

`NETSCOPE_ALLOWED_HOSTS` only controls incoming HTTP Host-header validation. It does not change the server bind address and does not replace `NETSCOPE_ALLOW_NON_LOOPBACK`. The built-in loopback hosts (`127.0.0.1`, `localhost`, and `::1`) remain allowed.

### Linux host-network mode

Use host networking when the container must inspect the Linux host's attached LAN interfaces:

```bash
cp .env.example .env
docker compose -f compose.host-network.yaml up --build -d
```

The service still binds to `127.0.0.1:8787` by default, so the dashboard remains local to the host. To intentionally expose host-network mode to your LAN, set `NETSCOPE_HOST=0.0.0.0`, `NETSCOPE_ALLOW_NON_LOOPBACK=1`, `NETSCOPE_ALLOWED_HOSTS` to the host IP/name clients will use, and enable `NETSCOPE_PASSWORD` in `.env`. The host-network Compose file reads these values without requiring edits.

Host-network mode can expose Docker, Podman, CNI, VPN, and other virtual interfaces alongside the real LAN. NetScope Lite hides recognized virtual interfaces from scan targets by default so **Scan all targets** does not spend its time enumerating container networks. Set `NETSCOPE_INCLUDE_VIRTUAL_TARGETS=1` only when you intentionally want those networks listed and scannable. Virtual interfaces remain visible in the host inventory.

Docker host networking is Linux-specific; behavior on Docker Desktop varies and may not expose the same interface and neighbor context as a native installation.

### Published image

The release workflow publishes multi-architecture images to GitHub Container Registry at:

```text
ghcr.io/<owner>/<repository>
```

Example bridge-mode run:

```bash
docker run --rm \
  --name netscope-lite \
  --publish 127.0.0.1:8787:8787 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --cap-add NET_RAW \
  --security-opt no-new-privileges:true \
  --env NETSCOPE_HOST=0.0.0.0 \
  --env NETSCOPE_ALLOW_NON_LOOPBACK=1 \
  --volume netscope-data:/data \
  ghcr.io/<owner>/<repository>:latest
```

Example Linux host-network run:

```bash
docker run --rm \
  --name netscope-lite \
  --network host \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --cap-add NET_RAW \
  --security-opt no-new-privileges:true \
  --env NETSCOPE_HOST=127.0.0.1 \
  --env NETSCOPE_ALLOW_NON_LOOPBACK=0 \
  --volume netscope-data:/data \
  ghcr.io/<owner>/<repository>:latest
```

## Data and database

The SQLite database is named `netscope.sqlite`.

| Platform | Default location |
| --- | --- |
| Windows | `%LOCALAPPDATA%\NetScopeLite\netscope.sqlite` |
| macOS | `~/Library/Application Support/NetScope Lite/netscope.sqlite` |
| Linux | `${XDG_STATE_HOME:-~/.local/state}/netscope-lite/netscope.sqlite` |
| Docker | `/data/netscope.sqlite` |

Override the native data directory:

```bash
NETSCOPE_DATA_DIR=/path/to/private/state npm start
```

SQLite uses write-ahead logging, foreign keys, a busy timeout, and normal synchronous mode. On POSIX systems, the data directory and database are created with restrictive permissions where supported.

Stop NetScope Lite before making a simple file-copy backup, or copy the database together with its `-wal` and `-shm` files.

A legacy `latest_scan.json` in the same data directory is imported into history on first launch when the database is empty.

Scan snapshots, observations, alerts, and notification history are retained until they are deleted from the dashboard. On long-running installations, periodically remove unneeded snapshots and notification events and monitor the size of the database and its `-wal` file.

## Scanning

### Profiles

- **Quick** checks a small service set on the local segment.
- **Standard** balances discovery coverage and scan duration.
- **Deep** covers the full attached subnet and a broader service set.
- **All TCP Ports** discovers devices and checks every TCP port on observed devices.
- **Custom** profiles control scope, selected or all-port mode, ports, and timeout.

### Exclusions

Settings includes a dedicated exclusion manager for:

- One private or link-local IPv4 address.
- A private or link-local IPv4 CIDR.
- A MAC address.

Exclusions can be labeled, paused, re-enabled, or deleted. Active address exclusions are applied before probing; MAC exclusions suppress matching devices when neighbor evidence is available.

### IPv6

IPv6 support is passive. NetScope Lite records IPv6 interface addresses and IPv6 neighbor entries already known to the host. It does not enumerate IPv6 address space or perform arbitrary IPv6 TCP probing.

## Alerts and notifications

### Network alerts

Alerts are generated from saved scan comparisons and stored locally in SQLite. The first scan for a target establishes a baseline and does not create change alerts.

The alert center supports:

- Unacknowledged and complete alert views.
- Individual acknowledgement and reopening.
- Acknowledge-all.
- Persistent history after acknowledgement.

Devices marked **Ignored** remain in inventory and history but do not produce device-specific change alerts.

### Browser notifications

Browser notifications are optional. They have the following behavior:

- The dashboard must be open for a notification to be requested.
- Permission is stored by the browser for the local site.
- NetScope Lite never sends notification data to an external service.
- The browser can accept a notification while the operating system still hides it because of Focus, Do Not Disturb, or system notification settings.
- Disabling notifications in NetScope Lite preserves browser permission but stops new notification requests.

### Notification history

The Alert Center includes a local notification history. It records:

- Permission granted, denied, or dismissed.
- Notifications handed to the browser.
- Unsupported-browser results.
- Delivery errors.
- Manual disabling.

A **Shown** record means the browser accepted the notification constructor. It is not proof that the operating system visibly displayed the banner. Notification history can be refreshed or cleared independently from network alerts.

## Scheduled scans

Schedules run inside the active Node.js process, so NetScope Lite must remain running.

A schedule stores:

- One to eight attached targets.
- A scan profile.
- An interval from 5 minutes to 7 days.
- Next-run, last-run, and last-status details.
- Separate authorization for recurring all-port scans.

Only one scan runs at a time. A due schedule waits for the active scan to finish.

## Password protection

Password protection is optional and protects the local API and dashboard data. It does not change the loopback-only exposure of a native installation.

Enable it in Settings or set an initial password before first launch:

```bash
NETSCOPE_PASSWORD='use-a-long-local-password' npm start
```

For Compose, add `NETSCOPE_PASSWORD` to a local `.env` file. Do not commit that file.

Passwords use scrypt-derived records. Password verification runs on the asynchronous crypto worker pool so a login attempt does not stall scanning or dashboard requests. Failed sign-ins are rate-limited, active sessions are bounded, and sessions expire after inactivity or when the server restarts or the password changes.

## Themes and keyboard controls

Themes:

- Purple
- Midnight
- Light
- High Contrast
- Custom palette
- Optional automatic day/night theme scheduling

Keyboard shortcuts:

| Key | Action |
| --- | --- |
| `S` | Start the configured scan |
| `/` | Focus device search |
| `H` | Open History |
| `A` | Open Alerts |
| `T` | Open Theme settings |
| `Esc` | Close the active dialog |

Shortcuts are disabled while typing in a form field or while any dialog is open.

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `NETSCOPE_DATA_DIR` | SQLite and local state directory | Platform-specific state directory |
| `NETSCOPE_HOST` | HTTP bind address | `127.0.0.1` |
| `NETSCOPE_PORT` | HTTP port | `8787` |
| `NETSCOPE_PASSWORD` | Optional first-run dashboard password | Disabled |
| `NETSCOPE_ALLOW_NON_LOOPBACK` | Explicitly allow a container to bind the dashboard to `0.0.0.0` | Disabled |
| `NETSCOPE_ALLOWED_HOSTS` | Comma-separated exact hostnames/IPs accepted by Host-header validation, in addition to loopback hosts | Empty |
| `NETSCOPE_INCLUDE_VIRTUAL_TARGETS` | Include recognized Docker/Podman/CNI/VPN virtual interfaces in scan targets | `0` |

`NETSCOPE_ALLOWED_HOSTS` is additive: `127.0.0.1`, `localhost`, and `::1` always remain allowed. Entries are normalized to lowercase and should contain only the hostname or IP address, without a scheme or port. For IPv6, use the bare address (for example `fd00::10`, not `[fd00::10]:8787`).

`NETSCOPE_ALLOW_NON_LOOPBACK=1` only permits the `0.0.0.0` bind used inside a container. It is independent from Host-header validation. The default Compose configuration still publishes the container port to `127.0.0.1`; exposing it on a LAN requires an explicit port-publishing change and should be paired with `NETSCOPE_PASSWORD` and appropriate firewall rules.

## Development

Run tests:

```bash
npm test
```

Run syntax checks and tests:

```bash
npm run check
```

When native dependencies are installed, the suite also exercises the production `better-sqlite3`/Drizzle store. Source-only audit environments skip only that adapter-specific test.

Build the local container:

```bash
npm run docker:build
```

Start bridge-mode Compose:

```bash
npm run docker:up
```

Start Linux host-network Compose:

```bash
npm run docker:up:host
```

## Continuous integration and delivery

The repository includes three GitHub Actions workflows:

- **Checks** installs dependencies and runs all syntax checks and tests on Linux, Windows, and macOS across supported Node.js releases.
- **Docker build** builds the image with Buildx, starts it, and smoke-tests `/healthz` for pull requests and changes on the main branch.
- **Publish container** builds Linux AMD64 and ARM64 images and pushes them to GitHub Container Registry when a GitHub Release is published. Published images include OCI metadata, provenance, and an SBOM.

Dependabot is configured for npm packages, GitHub Actions, and the Docker base image.

### Recommended branch protection

Require these checks before merging to the default branch:

- All **Checks** matrix jobs.
- **Docker build / build-and-smoke-test**.

### Release process

1. Merge a tested change to the default branch.
2. Create and publish a GitHub Release from the intended commit or tag.
3. The publish workflow logs in to GHCR with the repository `GITHUB_TOKEN`.
4. Multi-architecture images are published under the repository package name.
5. Verify the package visibility and release notes in GitHub.

The repository workflow needs `packages: write`; no personal registry token is required for GHCR publishing from the same repository.

## Project structure

```text
.
├── .github/workflows/       GitHub Actions checks and container publishing
├── src/db/                  Drizzle schema, migrations, and SQLite store
├── src/                     Scanner, safety, authentication, identity, schedules, Wake-on-LAN
├── static/                  Browser application, shared theme, and logo
├── test/                    Node.js test suite
├── Dockerfile               Production container image
├── compose.yaml             Loopback-published bridge-mode container
├── compose.host-network.yaml Linux host-network container
├── server.js                Local HTTP server and API
└── package.json             Runtime dependencies and scripts
```

## Troubleshooting

### `better-sqlite3` does not install

Use a supported Node.js release and ensure native build tools are installed if no prebuilt binary is available:

- Debian/Ubuntu: `python3 make g++`
- macOS: Xcode Command Line Tools
- Windows: Visual Studio Build Tools with the C++ workload

Then remove `node_modules` and run `npm install` again.

### Docker only sees a container subnet

That is expected in bridge mode. Use the Linux host-network Compose file or run NetScope Lite natively when accurate host interface, route, and neighbor context is required.

In Linux host-network mode, the host inventory will also contain Docker/Podman/CNI virtual interfaces. Those are intentionally excluded from scan targets by default. If the target selector still shows only a container subnet, verify the container is really using host networking with `docker inspect netscope-lite --format '{{.HostConfig.NetworkMode}}'` and confirm the container can see the host LAN interface with `docker exec netscope-lite ip -br -4 addr`.

### Ping results are unavailable

The scanner still uses neighbor and TCP evidence. On Linux containers, retain the `NET_RAW` capability used by the provided Compose files.

### Browser notifications do not appear

Check all three layers:

1. Notifications are enabled in NetScope Lite.
2. The browser grants notification permission for `http://127.0.0.1:8787`.
3. The operating system allows notifications from that browser and is not suppressing them.

The notification history in the Alert Center shows whether the dashboard requested and handed a notification to the browser.

## Privacy and security

- The native server binds to loopback.
- A `0.0.0.0` container bind requires the explicit non-loopback flag; the default bridge Compose file still publishes only to host loopback.
- Host-header validation allows loopback hosts plus exact names/IPs explicitly added with `NETSCOPE_ALLOWED_HOSTS`; LAN exposure should also use authentication and firewall restrictions.
- Restrictive security headers, request-size limits, and path-traversal protection are enabled.
- Network inventory, alerts, notification history, schedules, and settings stay in the local SQLite database.
- The application does not include telemetry or cloud synchronization.

Security reports should avoid posting sensitive network inventories, exported scans, or database files in public issues.

## License

AGPLv3. See [LICENSE](LICENSE).
