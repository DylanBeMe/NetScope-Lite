# NetScope Lite code, performance, security, and UX audit

## Scope

The current release archive was extracted and reviewed independently. The audit covered the Node.js server, local-network safety rules, scanner and cancellation paths, authentication, schedules, alerts, browser-notification history, Drizzle schema, production SQLite adapter, in-memory test store, Wake-on-LAN, browser application, responsive layouts, themes, Docker files, and GitHub Actions workflows.

The review focused on confirmed defects and regressions rather than adding SIEM-oriented integrations.

## Final status

- **75 automated tests executed:** 74 passed and one production-adapter test skipped locally because native npm dependencies could not be installed in this environment.
- **88.73% line, 73.30% branch, and 87.37% function coverage** across loaded files.
- A real bounded host-only scan completed, observed one device, saved a snapshot, and passed saved-result validation without warnings.
- All Compose, Dependabot, and GitHub Actions YAML files parsed successfully.
- Desktop and mobile browser audits completed without application exceptions, console warnings, page-level horizontal overflow, or dialog overflow.
- The exact final ZIP is extracted and retested before handoff.

## Confirmed issues corrected

### Production/test profile drift

The in-memory store and production SQLite store had separate built-in scan-profile definitions. The production **Deep** profile contained a broader port list than the profile exercised by most tests, allowing behavior to drift without a failing test.

Built-in profiles now come from one immutable `src/profiles.js` definition used by both stores. A regression test verifies profile parity, and the optional production SQLite test verifies it against the real adapter when native dependencies are available.

### Case-only duplicate profiles

The in-memory store rejected profile names case-insensitively, while SQLite's existing unique index could permit names such as `Office` and `office` as separate profiles.

The production store now performs an explicit case-insensitive duplicate check before inserts and updates and returns a coherent conflict response.

### Permissive exclusion updates

An empty or unknown exclusion PATCH could reach the persistence layer, and an incorrectly typed `enabled` value could be accepted ambiguously.

Exclusion patches now allow only `label` and `enabled`, require a boolean for `enabled`, reject empty updates, and reject unknown properties. HTTP regression tests cover valid and invalid patches.

### Authentication event-loop blocking

Password verification previously used synchronous scrypt during login and password changes. Repeated attempts could block scanner progress and dashboard responses on the main Node.js thread.

Interactive password hashing and verification now use Node's asynchronous crypto worker pool. Failed sign-ins are bounded within a rolling window, session count is capped, passwords have explicit size limits, and sessions continue to expire on inactivity. Initial environment-password hashing remains synchronous only during process startup.

### Unbounded authentication state

Failed-login timestamps and active sessions could grow without explicit caps in a long-running process.

Failed attempts now expire after one minute, successful authentication clears the failed-attempt window, and the oldest session is removed when the bounded session limit is reached.

### Hidden asynchronous UI failures

Several dynamically created action buttons and top-level async listeners could reject without showing a usable message, leaving an unhandled promise rejection or an apparently inert control.

Shared action controls now disable while pending, await their handlers, restore their state, and surface errors through the existing dashboard feedback system. A global rejection handler provides a final UI-safe fallback.

### Global shortcuts behind dialogs

Letter shortcuts could activate another workflow while a modal dialog was already open. For example, pressing `H` inside Settings could open History behind it.

Global shortcuts are now suspended while any dialog is open, as well as while the user is typing. The browser audit confirms that Settings remains the only active dialog when a shortcut key is pressed.

### Automatic-theme state mismatch

Turning automatic day/night themes off could leave the most recently selected automatic theme active instead of restoring the user's manually selected theme.

Disabling automatic themes now restores the persisted manual theme immediately.

### Misleading blocked-notification controls

When browser notification permission was permanently denied, the control label suggested that the app could resolve it and remained actionable.

The Alert Center now reports **Blocked in browser settings**, disables actions the app cannot perform, and rechecks permission when the browser window regains focus.

### Container security defaults

The image previously defaulted to a container-internal `0.0.0.0` bind. Although documented examples published to host loopback, a careless direct port publication could unnecessarily expose the listener.

The image now defaults to `127.0.0.1` with non-loopback binding disabled. Bridge-mode Compose, documented bridge commands, and the Docker smoke test opt into `0.0.0.0` explicitly while publishing only to host loopback. Container examples and CI also use a read-only root filesystem, a bounded `/tmp` tmpfs, dropped capabilities with only `NET_RAW` restored, and `no-new-privileges`.

## Performance review

### Scanner

- ICMP and TCP discovery queues remain bounded and start concurrently.
- Reverse DNS has a total time budget and cancellation support.
- Full-port progress updates are throttled rather than emitted for every connection.
- All-port mode scans ports 1–65,535 only on devices with prior discovery evidence; it does not blindly perform every port attempt against every silent address.
- Equivalent CIDR targets are canonicalized before batch execution.
- Only one scan runs at a time, and cancellation remains available throughout discovery and DNS stages.

### Persistence

- Device observations are written in batches.
- Lightweight monitor polling avoids repeatedly rebuilding full host and scan payloads.
- Corrupt saved-result validation uses a file-state-aware negative cache.
- SQLite is configured for WAL mode, foreign keys, a busy timeout, and restrictive data permissions where supported.

Snapshot, observation, alert, and notification-event retention remains manual. This is intentional for now because an automatic retention limit is a product policy that could delete evidence users expect to keep. Long-running deployments should monitor database and WAL growth and remove unneeded history from the dashboard.

### Browser

- Inventory rendering starts with 60 cards and expands progressively.
- Dense maps use a representative cap rather than creating an unbounded SVG/DOM tree.
- Search still covers the complete loaded inventory, not only initially rendered cards.
- Search and resize work are debounced.
- Pending action controls prevent duplicate requests.

A synthetic 181-device browser scenario rendered 60 initial inventory cards and 183 logical-map nodes without page overflow or application exceptions.

## UX, accessibility, and theme review

The actual HTML, CSS, and browser JavaScript were rendered in headless Chromium at 1,440-pixel desktop and 390-pixel mobile widths with mocked monitoring data.

### Theme consistency

Purple, Midnight, Light, High Contrast, and Custom themes were exercised. The overview, monitor strip, changes, topology, inventory, Settings, and Alert Center all resolve through the same surface, border, radius, text, focus, status, and control tokens. No panel introduces a separate visual system.

### Responsive behavior

- Desktop document width remained within the viewport.
- Settings and Alert Center cards measured 1,078 pixels of both client and scroll width: no internal overflow.
- Mobile document width remained exactly 390 pixels.
- Mobile Settings and Alert Center cards measured 350 pixels of both client and scroll width.
- Progressive inventory, dense topology, notification history, exclusions, profile controls, and scan controls remained contained.

### Interaction and accessibility

- Native buttons, form controls, and dialogs retain accessible names.
- Device cards and topology nodes expose selection state.
- Pending buttons communicate their disabled state and cannot submit duplicate requests.
- Global shortcuts do not activate behind dialogs.
- Browser-notification state distinguishes app preference, browser permission, browser acceptance, and possible operating-system suppression.
- Custom themes retain contrast feedback and adaptive button text.

## Production SQLite coverage

A new integration test imports the production `better-sqlite3` and Drizzle adapter, creates a temporary database, validates shared built-in profiles, and verifies case-insensitive duplicate rejection. It runs automatically whenever native dependencies are installed.

The audit environment could not resolve the configured npm registry and therefore could not install `better-sqlite3` or Drizzle. The integration test was skipped locally for that specific missing-module condition; any installed-but-broken native binding will fail rather than skip. Migration SQL was still executed independently using Node's built-in SQLite support and remains idempotent.

## CI, Docker, and release files

- Node syntax checks cover every server and browser JavaScript module.
- The test matrix runs on Linux, Windows, and macOS.
- Docker CI builds the image and smoke-tests `/healthz` using production-like security flags.
- Release automation publishes AMD64 and ARM64 images to GHCR with metadata, provenance, and an SBOM.
- Compose and CI configuration parse as valid YAML.

Docker itself is unavailable in this audit environment, so the image could not be built locally. The GitHub Actions Docker workflow remains the executable container build and smoke-test path.

## Remaining release considerations

### Dependency lockfile

The repository pins its two direct dependencies exactly, but it does not yet contain `package-lock.json`. A lockfile could not be generated honestly because the npm registry was unreachable in the audit environment. On a networked development machine, run `npm install`, review and commit the generated lockfile, then switch CI and Docker installation commands to `npm ci` for fully reproducible transitive dependency resolution.

### Retention policy

History cleanup remains user-driven. Before unattended long-term deployments, decide whether retention should be count-based, age-based, size-based, or explicitly disabled by default. Any future automatic cleanup should be configurable and transactionally tested.

## Deliberate product limits

- IPv6 discovery remains passive.
- Browser notifications require an open dashboard and can still be suppressed by operating-system Focus or Do Not Disturb settings.
- Schedules require the Node.js process to remain running.
- The topology represents host-observed logical evidence, not physical switch-port wiring.
- Infrastructure-controller integrations, centralized agents, log ingestion, threat intelligence, vulnerability matching, multi-user roles, and other SIEM-oriented features remain intentionally excluded.
