# Responsive web console

The console at `/console/` is the sole production browser UI. `/` and retired `/ui/` bookmarks redirect to it; known old pages map to the matching hash route without forwarding query strings. Old UI form submissions, asset URLs and live streams return 410 and cannot change settings. Shared security/certificate helpers and archived renderer fixtures remain internally; the legacy rendering module is compiled for tests only.

## Interface

The five main sections are Dashboard, Network, SMS, Tools and Settings. Phones use fixed bottom navigation and horizontally scrollable secondary tabs. Tablet and desktop use expandable sidebar groups. The same navigation element moves to a document-level dock on phones, outside the sticky header, scrolling panels and page animations. Visual-viewport changes keep the dock and dialogs in view when a keyboard reduces or pans the visible area. Short touch-screen landscape layouts retain the dock. Content reserves space for the dock and safe areas.

Light, Dark and System appearance apply across every screen. Page and dialog transitions use opacity and transforms; rapid navigation settles on the latest route. Reduced-motion preferences and hidden tabs skip or finish transitions. Live numbers retain their latest accessible value while changed digits animate. Addresses, identifiers and editable fields stay literal. Forms preserve drafts across routes and SSE updates.

## Authentication and transport

Static assets are under `/console/a/`. The shell contains no device readings. Its Host allowlist and strict CSP apply before serving it. Production startup requires a valid B31 factory admin verifier or a nonempty `ZTE_AGENT_PASSWORD`. If neither is available, the agent exits before serving the console and records the reason in its startup log. Device reads, writes and streaming use the existing authenticated JSON API and its Host/Origin checks, login rate limits and blocking-work lanes. The console does not replace the upstream random-token auth implementation, CLOCK_BOOTTIME expiry, LAN admission checks or TLS listener.

The API runs blocking work through two lanes. `ZTE_AGENT_THREADS` sets the
General lane size (default 4, clamped to 1–32) and the Slow lane has two slots.
Admission times out after 7 s with 503 `agent busy, retry`.

The bearer token is kept in this tab’s `sessionStorage`; the password is cleared after sign-in and is never persisted. Navigation and reloads retain the tab session. Explicit lock or expiry clears the token, readings and drafts. A late unauthorized response from an older login cannot lock a newer session. eSIM ICCIDs are masked in text and use opaque DOM keys; full identifiers needed for commands stay in authenticated in-memory state.

Bearer tokens are random 64-digit hex strings with a one-hour idle timeout and
24-hour maximum lifetime. The retired renderer fixtures use browser sessions
with 12-hour idle and seven-day maximum timeouts. Expiry uses `CLOCK_BOOTTIME`.
Login throttling returns 429 with `Retry-After`. Tailnet clients arrive as
loopback peers and share that limiter, with blocks capped at 10 s.

## Live data

`GET /api/dashboard/events` is an authenticated axum SSE response. It sends a snapshot followed by changed readings in `{readings: {name: {ok, data, error}}}` envelopes, plus comment heartbeats. Its async response does not hold an API lane or introduce another HTTP listener. Streams are capped at eight, end on expiry/revocation and reconnect after their maximum lifetime. Dropping the last subscription discards saved readings. Collectors sleep without polling or sampling when they have no viewers.

Base readings include device, WAN/WAN6, signal, modem/mobile state, charging, speed, battery, Wi-Fi/guest and remembered clients. `sms=1` opts into SMS data only on message pages. Optional `topics` are `clients`, `routing`, `esim`, `operators`, `forwarding`, `health`, `power`, `https`, `dns`, `ota`, `relay`, `mihomo`, `tailscale`, `radio`, `speedtest` and `terminal`. Subscribers receive only their selected optional data; the shared snapshot is discarded when its last subscriber leaves. Firmware notifications and successful API mutations accelerate sampling. The separate [`GET /api/events` protocol](events.md) remains available to API clients.

WAN IPv4 and IPv6 use the separate firmware interfaces and display all reported addresses; delegated prefixes are not mislabeled as interface addresses. Missing addresses are explicit. Device rates derive from verified Wi-Fi association byte counters using monotonic elapsed time. AP RX is device upload; AP TX is device download. Observed peaks cover continuously monitored associations and reset after counter resets, reassociation, interface changes or monitoring gaps. Link rates, observed rates and configured caps are separate. Firmware without per-device caps reports null/“Not reported”.

The eSIM topic reads saved agent state only; it never opens a card channel or sends receipts. Explicit profile reads and normal page loading use the existing eSIM API. Profile changes have fresh-state checks and readbacks; downloads require an operator preview before installation. Confirmation, cancellation and dismissal include job identity so stale previews cannot operate on another job. Uncertain actions are never automatically retried. A late command response cannot overwrite newer SSE progress.

| Dashboard topic | Reading and when it changes |
| --- | --- |
| `relay` | `relay_status` follows controller notifications, including during restore. The page also reads status on load, manual refresh and return to a visible, focused page. When a state-changing request receives no response, the page reports uncertainty and tries to read status up to eight times, waiting 6 s before the first attempt and after each failed attempt. |
| `mihomo` | `mihomo_status` follows controller and profile notifications. Relay and Mihomo share the event-driven `dashboard-state` collector with eSIM. |
| `tailscale` | `tailscale_status` uses its own five-second cadence while subscribed. |

## Battery & Power

Tools → Battery & Power subscribes to the optional `power` topic (five-second sampling while viewed). `battery_details` combines a read-only allowlist of Linux power-supply measurements with cached firmware battery/charger data and current charge policy. No charging controls are changed by viewing the page. Identifiers and writable sysfs fields are excluded.

Battery and USB power use measured voltage × current with µV/µA conversion, independently of unreliable driver `power_now`. Battery flow and USB input are separate. Kernel time estimates use seconds; the existing firmware estimates use minutes. Nonpositive/sentinel estimates are unavailable, and charging estimates are suppressed outside charging/full state. Raw source fields remain available in a collapsed details section. Missing data is not zero; interrupted streams retain values with a stale caption, and locking or leaving the page clears its optional data.

## Network extensions

Four pages under **Network** manage the optional agent extensions. The pages render router text with `textContent`. See [Network extensions](network-extensions.md) for operating details and the full API.

- **Wi-Fi Relay** (`#network/relay`): scan, pick an upstream, connect and disconnect, explicit clock check, strict zero-cellular toggle (`POST /api/wifi-relay/strict-zero-cellular`), saved networks (forget; the per-network bandwidth choice was retired in v6), what the router's parental control, URL filter and hardware forwarding cover while connected (D8), and the compatibility notes. Passwords go in the request body. The console preselects remembering a protected network after a successful connection. API callers must explicitly send `remember: true`.
- **Mihomo** (`#network/mihomo`): install the pinned core, start and stop, up to 16 configuration profiles (add by subscription URL, file or paste; edit, refresh, select, delete) and the global Merge and Script. The authenticated profile editor reads the complete subscription URL on demand. The global extensions editor reads the saved Merge and Script. Saved profile YAML is never returned to the browser.
- **Mihomo proxies** (`#network/proxies`): routing mode, node choice per selector group (rolled back on failure) and delay tests (three at a time, at most 30 nodes per group). The Mihomo controller secret never leaves the router; the agent performs these fixed operations itself.
- **Tailscale** (`#network/tailscale`) manages binary install and upgrade, interactive HTTPS login or an auth key, enable, disable, logout, hostname, Tailscale SSH and wakelock preferences. It clears the auth key after submit and on Lock. The version picker uses `GET /api/tailscale/versions` to read the version catalog, cached for ten minutes, and `POST /api/tailscale/versions/refresh` for a fresh lookup. Updates use `POST /api/tailscale/update`. When `sha256` is omitted, the agent fetches the official package's `.sha256` and verifies the download. Both `/ui/tailscale` and `/ui/router/tailscale` redirect to this page. See the [Tailscale route table](network-extensions.md#tailscale-routes).

The Tailscale page's **Subnet routes & Exit Node** panel (`#tailscale-routing`) shows the reported TUN mode and configuration sync state (`applied`, `pending_daemon`, `drift`, or `unknown`). Add IPv4 or IPv6 CIDRs manually or use the LAN quick-add buttons. Saved routes show their live approval state. Exit Node has overall, IPv4 and IPv6 approval indicators, a link to the Tailscale admin console, and a Mihomo routing preference. The Clean DNS indicator reads `routing.clean_dns` first (falling back to `routing.exit.clean_dns`) and can report `Active`, `Inactive`, or `Degraded` even when Exit Node approval status is `Unknown`. When saved routing changes elsewhere, the console applies outstanding local edits to the latest saved settings and lets you review the result before saving or discarding.

Below it, **Tailscale Services (`svc:*`)** (`#tailscale-services`) manages `svc:*` service endpoints directly against `tailscaled`'s `ServeConfig` (`/api/tailscale/services`, `PUT /api/tailscale/services/:name`, `POST /api/tailscale/services/:name/drain`, `POST /api/tailscale/services/:name/advertise`, and `DELETE /api/tailscale/services/:name`, all on the Slow lane). It merges locally configured services with `CapMap`-assigned unconfigured services, renders live `Active`, `Pending approval`, `Drained`, `Port mismatch` (calling out unallowed ports), and `Unconfigured` states, provides one-click address copy and Tailscale admin console links (linking undefined services to the `Define Service` list view and offering one-click `Re-advertise` once defined), and edits existing services in-place inside their card. Each service edits and saves independently with multi-rule HTTPS (optional URL path prefix; `http://`, `https://`, `https+insecure://`, `unix:`, `file://`) and raw TCP (`host:port`, `unix:`) targets, a masked-MAC device/DHCP-reservation picker, non-blocking hints when a private LAN IP lacks a static DHCP reservation or an approved Subnet Route, read-only protection for CLI-only handlers (`Text`, plaintext `HTTP`, `TerminateTLS`, `ProxyProtocol`, `AcceptAppCaps`, `--tun`), and confirmation dialogs for drain, advertise, and clear.

The Mihomo console uses `POST /api/mihomo/dashboard`, `GET /api/mihomo/extensions`, `GET /api/mihomo/profiles/{id}`, `GET /api/mihomo/proxies`, `POST /api/mihomo/proxies/select`, `POST /api/mihomo/proxies/delay` and `POST /api/mihomo/mode`. Profile and extension reads use the general lane and remain available while Mihomo is off. Proxy reads and controller changes use the slow lane and return 409 while Mihomo is off. Dashboard passes use a dedicated authenticated precheck and a general-lane running-state check; they also return 409 while Mihomo is off. Old `/ui/relay` and `/ui/router/mihomo` bookmarks redirect to these pages.

**Open Zashboard** (Mihomo and Mihomo proxies pages, shown only while Mihomo runs) opens the pinned dashboard in a new tab for connections, logs, traffic, rules and providers. The page opens the tab first, so the click still counts as a user gesture, then trades its bearer token for a short-lived `zte_ui_zashboard` cookie with `POST /api/mihomo/dashboard`. Over HTTP the cookie is scoped to `/ui/mihomo/`; HTTPS translates it to a Secure `__Host-` cookie with `Path=/`. Server-side checks restrict it to the dashboard and bridge, and the JSON API never accepts it. Lock console calls `POST /api/auth/logout` to revoke the session and its passes; if the router cannot confirm logout, the locked tab reports that existing dashboard access may remain. Open streams end when their pass expires, is replaced or evicted, or its session is revoked. If the browser blocks the tab, a link appears instead.

## Source and checks

- `zte-agent/ui/`: dependency-free HTML, CSS and browser modules.
- `src/console.rs`: static shell/assets and Host/CSP handling.
- `src/dashboard.rs`, `dashboard_extra.rs`, `client_details.rs`: demand-driven readings, bounded async SSE and client measurements.
- `ui/tests/`: pure Node validation checks and Playwright browser fixtures. They never contact a router or mutate real settings.

Run the [host and browser checks](README.md#tests-and-qa) from the repository root. The pure suite includes `data-usage-model`, `dns-model` and `wireguard-model`.

## Public screenshots

`ui/screenshots/` contains rendered captures of this console using fictional readings, names and profile identifiers. WAN addresses use RFC documentation ranges; device MACs use local demonstration values. No live probe captures, SMS bodies, credentials, activation codes, EIDs or personal device identifiers are included. The existing iOS screenshot gallery remains in `mobile/ios/screenshots/`.

## HTTPS and installed shortcuts

Settings → HTTPS & Install subscribes to `topics=https` for five-second status updates while viewed. The LAN HTTPS listener shares the HTTP routing, connection caps and upstream admission check. It defaults to `0.0.0.0:9443` and accepts `ZTE_AGENT_TLS_BIND` to override the bind address. The TLS service exposes confirmed bearer-authenticated `POST /api/https/on`, `/renew` and `/reset` commands through the slow work lane. Host/Origin admission and login limits remain unchanged. Certificate/profile downloads remain public while HTTPS is enabled; private keys are never served. The new screen includes expiry, router-clock trust, authority fingerprints and platform trust/install instructions.

TLS files live in `/data/zte-agent-tls/` (0700 directory, 0600 keys).
The agent publishes `u60.home.arpa` through `/tmp/hosts/zte-agent` and
reloads dnsmasq with SIGHUP. Certificate checks run at startup, on TLS
connections and after a LAN address change. Automatic renewal requires the
verified clock from a configured Live Activity provider. Without it, Settings
offers manual Renew. Reset closes open HTTPS connections. See the
[LAN HTTPS security policy](../../SECURITY.md#security-considerations).

Both `/console/manifest.webmanifest` and the old `/ui/manifest.webmanifest` keep the installed application id `/ui/`, start at `/console/` and cover the root scope. Public icon aliases serve only generated icons, never legacy scripts or styles. The production router no longer mounts the server-rendered interface. Its archived tests use an explicit test-only harness; production retirement and HTTPS API security are tested through `httpd::app`.
