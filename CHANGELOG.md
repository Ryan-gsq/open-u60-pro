# Changelog

Notable changes to OpenU60 (the `zte-agent` for the ZTE U60 Pro, and the iOS, Android and web apps). Each version has a [GitHub release](https://github.com/jesther-ai/open-u60-pro/releases) with the `zte-agent` binary for the router (aarch64, musl), `THIRD_PARTY_NOTICES.md` and the license texts. `./setup.sh` downloads the binary from the latest release.

## [2.2.0] - 2026-10-20

### Highlights

- **eSIM profiles, built in.** With an eSIM card in the SIM slot (tested with a 9eSIM B1), the agent lists, switches, downloads (from the operator's QR code), renames and deletes profiles, and sends the operator receipts. It is its own GSMA SGP.22 LPA: lpac's card library translated to Rust, talking to the card through the modem (QMI over QRTR). Nothing else needs installing, and the apps get new eSIM Profiles screens.
- **SIM identity events.** When the active SIM changes (an eSIM switch, a switch from the card's menu, or a physical swap), the agent publishes `zte_agent.sim_identity` (`leaving` → `changed` → `online`) inside the agent and over `ubus`. The apps, the Live Activity and SMS forwarding refresh themselves. Before a switch, the apps warn about a manual APN or Data Roaming being off.
- **iOS Live Activity.** The router's signal on the Lock Screen, pushed by the agent through Apple's push service. It is off until configured, and keeps working across network and SIM changes.
- **Tailscale remote management**, plus lower power use on the router.

### zte-agent

#### Added

- **eSIM profile management** (`/api/esim/*`, #28–#31):
  - list profiles and card info;
  - switch, verified card → modem identity → data, with a reason when data doesn't come up (for example Data Roaming off), and retries for up to 4 minutes while the card is busy;
  - download from an activation code with a preview, confirm and cancel;
  - delete disabled profiles and rename;
  - operator receipts, sent and retried.

  Operator servers must present TLS certificates from the GSMA eSIM root CI, which is embedded in the agent.
- **SIM identity event** `zte_agent.sim_identity` (#32):
  - phases `leaving`, `changed`, `online` and `stalled`;
  - published in-process and with `ubus send`; the payload carries only the PLMN, the operator name and the last 4 ICCID digits;
  - `sim_epoch`, `sim_phase` and `agent_instance` on `/api/network/signal`, `/api/sim/info` and `/api/esim/switch`.
- **Pre-switch warnings** on `GET /api/esim/profiles` (`manual_apn`, `roaming_off`; read-only), and `observed_seq` for ordering lists without the wall clock (#32).
- **Live Activity sender** (APNs, off unless configured), with recovery after network and time changes. It opens a fresh connection to Apple after every network change (#27, #32).
- **SIM Toolkit** over the RIL socket, default-bearer (QoS) info, and opt-in no-service and connectivity-watchdog policies, off by default (#27).
- **Tailscale remote management** (`/api/tailscale/*`): a supervised `tailscaled` in userspace-networking mode. Enabling it requires an agent password (#13).
- **`/api/device/auto-sleep`** (#25).
- **`zte-agent esim-native <command>`** runs one eSIM card command for diagnostics on the router (#31).

#### Changed

- **Power:** idle wakeups went from 13.2/s to 0.1/s, short-lived caching of `ubus` reads, and fewer processes per app request (#27).
- **SMS forwarding** (#32):
  - an IPv6-only WAN counts as connected;
  - forwards that hit a dead link are held and retried instead of being marked "permanent error";
  - held forwards survive "Clear log".
- **Tailscale:** the WAN-reconnect health check uses a monotonic clock, so the clock jump on attach no longer suppresses it (#32).

#### Removed

- **lpac.** The agent no longer runs lpac and needs no `/data/lpac` bundle; a bundle left by an earlier build can be deleted.
  - The `ZTE_AGENT_LPAC_*` settings are now `ZTE_AGENT_ESIM_QRTR_NODE`, `ZTE_AGENT_ESIM_UIM_SLOT` and `ZTE_AGENT_ESIM_LOCK` (lock file `/tmp/esim.lock`).
  - `GET /api/esim/chip` no longer reports an lpac build (#31).
- **Device identifiers** removed from published files (#27).

#### Licensing

- The binary links the `euicc` crate (LGPL-2.1-only, a Rust translation of lpac's libeuicc). Releases now include `THIRD_PARTY_NOTICES.md`, `LICENSE-LGPL-2.1.txt` and `LICENSE-MIT.txt` (#31).

### Mobile apps (iOS and Android)

- **eSIM:**
  - Router → eSIM Profiles: add (scan or paste a QR code), switch with live progress, rename, delete, receipts and card info. These replace the 9eSIM B1 Bluetooth screens (#28–#30).
  - Switch dialogs show the router's warnings (#32).
- **SIM changes:** dashboard, SIM and device screens refresh by themselves when the SIM changes (#32).
- **Live Activity (iOS):** the "Live signal" card on the dashboard (#27).
- **SMS forwarding:** held forwards show as "Held, will retry" (#32).
- **Dashboard:**
  - cellular traffic from the modem's own counters, which is accurate, and a fix for battery percentages above 100%;
  - 3G/WCDMA signal and auto-sleep controls;
  - hardened networking and session recovery (#25).
- **App icons, signal symbols and Chinese:** app icons, standard signal symbols, and Simplified Chinese translations (#3).
- **Fixes:**
  - turning on Data Roaming on iOS no longer leaves mobile data off;
  - Android's SIM screen used a route that doesn't exist (`/api/sim/lock`) and could crash during a switch;
  - Android keeps 19–20 digit ICCIDs and EIDs exact.

### Web dashboard

- Vercel Analytics (#11).

### Build

- The release workflow cross-compiles the TLS crypto library (`ring`) for the router and test-builds the agent on pull requests that touch it.

### Known issues

- The network sets the router's clock on every attach, often by +8 h, and that ends agent login sessions. The apps log in again by themselves.
- After an eSIM switch, the first operator receipt usually times out and goes out on the next try about 30 s later.

## [2.1.0] - 2026-05-04

- AT terminal, SMS forwarding improvements and UI refinements across all platforms.
- Fix: deleting SIM-stored SMS failed silently.

## [2.0.1] - 2026-04-11

- Fix: `./setup.sh` no longer exits silently when the router is unreachable (#2).

## [2.0.0] - 2026-03-12

- Agent: event bus, SMS forwarding, charge limit, scheduler, speed test, LAN test, process monitor, power-save and fast-boot controls.
- Android app (Jetpack Compose); the apps were renamed to OpenU60; Next.js web dashboard.
- Interactive `./setup.sh` with a pre-built binary download; GitHub Actions release builds.

## [1.0.0] - 2026-03-06

- On-device HTTP agent.

[2.2.0]: https://github.com/jesther-ai/open-u60-pro/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/jesther-ai/open-u60-pro/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/jesther-ai/open-u60-pro/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/jesther-ai/open-u60-pro/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/jesther-ai/open-u60-pro/releases/tag/v1.0.0
