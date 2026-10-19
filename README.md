<div align="center">

<p>
<img src="mobile/ios/screenshots/screenshot1.PNG" alt="Dashboard" width="250">&nbsp;&nbsp;<img src="mobile/ios/screenshots/screenshot3.png" alt="Signal Monitor" width="250">&nbsp;&nbsp;<img src="mobile/ios/screenshots/screenshot2.PNG" alt="Router Settings" width="250">
</p>

# ZTE U60 Pro Toolkit

**Unlock the full potential of your ZTE U60 Pro (MU5250) 5G mobile router.**

On-device REST agent + native mobile companion apps for signal monitoring, band locking,
config backup/decryption, network customization, and more.

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/device-ZTE%20U60%20Pro%20(MU5250)-orange.svg)]()
[![Qualcomm](https://img.shields.io/badge/chipset-Snapdragon%20X75-red.svg)]()
[![OS](https://img.shields.io/badge/firmware-ZWRT%20(OpenWrt%2023.05)-green.svg)]()
[![Website](https://img.shields.io/badge/website-open--u60--pro.vercel.app-blue.svg)](https://open-u60-pro.vercel.app)

</div>

---

## Device

| | |
|---|---|
| **Model** | ZTE U60 Pro (MU5250) |
| **Hardware** | `MU5250_HW1.0` |
| **Firmware** | `CN_ZTE_MU5250V1.0.0B27` (Oct 31, 2025) |
| **Chipset** | Qualcomm Snapdragon X75 (SDX75 / SDXPINN) |
| **CPU** | 4x Cortex-A55 (ARMv8.2-A) @ 2.2 GHz |
| **RAM** | 1.6 GB |
| **Storage** | 8 GB eMMC (Longsys JS08AC), 69 partitions, A/B slots |
| **Modem** | 5G-A Sub-6 + mmWave, Cat 22 LTE |
| **NR Bands** | n1/2/3/5/7/8/18/20/26/28/29/38/40/41/48/66/71/75/77/78/79 |
| **LTE Bands** | 1/2/3/4/5/7/8/18/19/20/26/28/29/32/34/38/39/40/41/42/43/48/66/71 |
| **WiFi** | WiFi 7 (802.11be), 2x2 MIMO, EHT160 |
| **WiFi Chipset** | Qualcomm WCN7851 (`qcacld32`) |
| **WiFi Radios** | 2.4 GHz (ch 1-13, EHT40, 19 dBm) · 5 GHz (ch 36-165, EHT160, 18 dBm) |
| **Battery** | 10,000 mAh Li-ion, 4.5V max, PM7550B fuel gauge |
| **Charging** | USB-PD, 15W (5V/3A), fast charge |
| **USB** | USB-C (PD sink, OTG/powerbank) |
| **Display** | 3.5" IPS LCD (Sitronix ST77926), 320x480, RGB565, DRM/KMS |
| **UI Toolkit** | LVGL with FreeType + LodePNG, assets at `/usr/ui/` |
| **Backlight** | AWINIC AW9523B (I2C `1-005b`), sysfs `/sys/class/leds/led:lcd/brightness` (0-255) |
| **Touch** | Sitronix (I2C `1-0055`) -> `/dev/input/event3` |
| **OS** | ZWRT (OpenWrt 23.05.4 r24012-d8dd03c46f) |
| **Kernel** | Linux 5.15.170-perf, SMP PREEMPT, aarch64 |
| **PMICs** | PMX75 + PM7550BA + PMG1110 |
| **SIM** | Single nano-SIM (no built-in eSIM; eSIM cards such as the 9eSIM B1 work in the slot) |
| **NFC** | Quick device pairing |
| **Bluetooth** | Qualcomm WCN7850 (BT 5.3+), UART transport — disabled (services stopped, module unloaded) |
| **Clients** | Up to 64 (32 per radio) |

## What's Included

### On-Device Agent (`zte-agent`)

A lightweight Rust HTTP server that runs directly on the router (port 9090, LAN-only). It proxies ubus calls, AT commands, and sysfs reads into a typed REST API that mobile apps consume over WiFi.

```bash
# Cross-compile for the device
cargo build --release --target aarch64-unknown-linux-musl -p zte-agent
```

**156 endpoints across 17 categories:**

| Category | # | Capabilities |
|---|---|---|
| Device | 14 | System info, battery, CPU, memory, thermal, charger, charge control, reboot, factory reset, power save |
| Network | 9 | Signal strength (RSRP/SINR/RSRQ), speed, traffic stats, WAN/LAN status, rmnet, connected clients |
| Modem | 12 | Airplane mode, mobile data toggle, network mode (2G-5G), operator scan, manual registration |
| SMS | 5 | List, send, delete, mark read, storage capacity |
| SIM | 7 | SIM info, IMEI, PIN management, PUK unlock |
| Cell/Band | 19 | NR/LTE band locking, cell locking, neighbor scan, STC, signal quality detection |
| Router | 29 | DNS, LAN/DHCP, firewall, NAT, DMZ, UPnP, port forwarding, QoS, domain filter, APN profiles, VPN/ALG |
| WiFi | 4 | Status, SSID/password/channel/TX power, guest WiFi |
| USB | 3 | USB mode switching, powerbank control |
| Telephony | 11 | Voice calls (dial/hangup/answer/DTMF/mute), USSD codes, SIM Toolkit menus |
| eSIM | 13 | eSIM profiles via lpac: list, switch (verified card → modem → data), rename, download from QR with preview/cancel, delete, operator receipts, card info |
| Speed Test | 4 | Server list, run test, progress tracking |
| DoH Proxy | 6 | DNS-over-HTTPS proxy, cache management |
| LAN Test | 3 | WiFi ping, download/upload throughput measurement |
| SMS Forwarding | 9 | Auto-forward rules, CRUD, test, log management |
| System | 2 | Process list, kill bloatware |
| Scheduler | 5 | Scheduled/recurring jobs for any API action |

### Mobile Companion Apps

Native apps that connect directly over WiFi -- no computer needed.

| | iOS | Android |
|---|---|---|
| **Framework** | SwiftUI | Jetpack Compose |
| **Min Version** | iOS 16.0 | Android 8.0 (API 26) |
| **Dependencies** | None (Apple frameworks only) | OkHttp, Hilt, Vico, kotlinx.serialization |
| **Features** | BandLock, Call, Clients, Config, Dashboard, DeviceInfo, Login, RouterSettings, Scheduler, Signal, SIM/STK/USSD, SMS, Tools, USBMode | BandLock, Clients, Config, Dashboard, DeviceInfo, Login, RouterSettings, Scheduler, Signal, SIM/STK, SMS, Tools, USBMode |
| **Tabs** | Dashboard, SMS, Tools, Router, Settings | Dashboard, SMS, Tools, Router, Settings |
| **Path** | `mobile/ios/OpenU60/` (109 Swift files) | `mobile/android/OpenU60/` (90 Kotlin files) |

## Why Use This Instead of the Official ZTE App?

The stock ZTE U60 Pro runs **44 proprietary daemons** consuming **225 MB of RAM** just for device management. Many of these are unnecessary (TR-069 remote management, MQTT telemetry, Samba, NFC, diagnostics) and phone home to ZTE servers.

`zte-agent` replaces the need for the official ZTE management app with a single ~2.3 MB binary:

| | zte-agent | ZTE Official Stack |
|---|---|---|
| **Processes** | 1 | 44 |
| **Memory (RSS)** | ~0.8 MB | 225 MB |
| **Binary size** | ~2.3 MB | ~50+ MB combined |
| **Threads** | ~10 | ~130+ |
| **Telemetry** | None | Phones home to `iot.zte.com.cn` etc. |
| **App** | Open-source native iOS/Android | Closed-source, Chinese-only |

The official ZTE stack's top memory consumers:

| Process | RAM | Purpose |
|---------|-----|---------|
| `zte_topsw_devui` | 22.8 MB | LCD UI daemon |
| `zte_topsw_get_brand` | 14.2 MB | Carrier branding |
| `zte_topsw_data` | 10.9 MB | Mobile data management |
| `zte_topsw_tr069` + subs | 23.2 MB | ISP remote management |
| `zte_topsw_diag` | 7.1 MB | Diagnostics/logging |

zte-agent provides equivalent API access to the same underlying ubus/AT services using **0.35% of the memory** -- freeing ~224 MB of RAM for actual routing and WiFi workloads.

## Device Impact

> **Warning** -- The agent exposes device control endpoints that modify firmware settings.
> Destructive actions (factory reset, reboot) require confirmation in the mobile app.

### Filesystem Layout

```
/data/                              (writable /data partition)
├── zte-agent                       <- on-device REST agent
└── local/tmp/
    ├── start_zte_agent.sh          <- agent boot script
    ├── dropbear                    <- SSH binary (if installed)
    └── start_dropbear.sh          <- SSH boot script (if installed)

/etc/                               (read-only rootfs)
├── rc.local                        <- boot hooks appended here
└── dropbear/
    ├── authorized_keys             <- SSH public key (if installed)
    └── dropbear_rsa_host_key       <- generated host key (if installed)
```

## Quick Start

### Prerequisites

```bash
# 1. Install Rust -- see https://rustup.rs
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Add musl cross-compilation target
rustup target add aarch64-unknown-linux-musl

# 3. Install musl cross-linker
# macOS:
brew install filosottile/musl-cross/musl-cross
# Ubuntu/Debian:
sudo apt install musl-tools gcc-aarch64-linux-gnu

# 4. Install ADB
# macOS:
brew install android-platform-tools
# Ubuntu/Debian:
sudo apt install android-tools-adb

# 5. Build the agent
cargo build --release --target aarch64-unknown-linux-musl -p zte-agent
```

### First-Time Setup

For a factory-fresh device that has never had zte-agent installed:

**Option A -- Browser (no tools needed)**

Visit [open-u60-pro.vercel.app](https://open-u60-pro.vercel.app), enter your router password and desired agent password, connect USB, and click Deploy. Requires Chrome or Edge.

**Option B -- Command line**

```bash
./setup.sh <router-password> <agent-password>
```

Enables ADB, builds and pushes the agent, creates boot scripts, and optionally sets up SSH for wireless deploys.

### Deploy Agent (subsequent updates)

```bash
./deploy.sh yourpassword
```

This builds, deploys the binary to the device via SSH (port 2222), updates the boot password, and restarts the agent.

### eSIM profiles (optional)

With an eSIM card in the SIM slot (tested with a [9eSIM B1](docs/9esim-b1.md)), the agent manages its operator profiles through [lpac](https://github.com/estkme-group/lpac), the open-source GSMA SGP.22 eSIM manager:

- **List** profiles and card details (EID, firmware, free space).
- **Switch** the active profile. The agent verifies each step (card → modem identity → mobile data) and reports why a switch didn't complete; it never switches back on its own. Internet returns in about 15–45 s; Wi‑Fi stays on.
- **Add** a profile from the operator's QR code or activation code, with a preview of the operator and profile name before anything is written, and cancel.
- **Rename** profiles (nicknames) and **delete** inactive ones.
- **Operator receipts:** the card's add, switch and remove notifications are sent to the operator's server one by one, right after the change once data is up, and retried while the router has mobile data.
- **Safety:**
  - one eSIM operation at a time;
  - checks that it's still the same card before any change;
  - no switching while you have airplane mode on;
  - downloads only with mobile data.
  - operator servers are reached over TLS checked against the GSMA eSIM root certificate that the card trusts.

lpac is built separately and copied to the router once:

```bash
cd lpac-qrtr-build
./make-bundle.sh          # needs python3, curl and the musl cross compiler from step 3
./install-to-router.sh    # SSH to root@192.168.0.1:2222, installs to /data/lpac
```

Switching, adding, renaming and deleting require an agent password. In the apps: Router → eSIM Profiles. To run lpac by hand on the router, use `flock -n /tmp/lpac.lock …` so it never overlaps the agent (full command in [`lpac-qrtr-build/README.md`](lpac-qrtr-build/README.md#running-lpac-by-hand)). If you installed lpac before 2026-10-19, rebuild and reinstall it: older bundles can't reach the operators' servers. API and behaviour: [`zte-agent/docs/esim.md`](zte-agent/docs/esim.md). The lpac patch is AGPL-3.0 (see [`lpac-qrtr-build/`](lpac-qrtr-build/)).

### Connect Mobile App

1. Connect your phone to the router's WiFi
2. Open OpenU60 app
3. Set agent URL: `http://192.168.0.1:9090`
4. Enter the agent password you set above

## Project Structure

```
u60-Pro-rs/
├── zte-agent/                 On-device REST API server
│   └── src/
│       ├── main.rs            Entry point (Axum HTTP server)
│       └── routes/            REST endpoint handlers
│
└── mobile/                    Native companion apps
    ├── README.md              Mobile apps documentation
    ├── ios/OpenU60/           SwiftUI app
    │   ├── Core/              Networking, crypto, models
    │   ├── Features/
    │   │   ├── BandLock/      Band locking
    │   │   ├── Call/          Voice calls
    │   │   ├── Clients/       Connected devices
    │   │   ├── Config/        Config backup/restore
    │   │   ├── Dashboard/     Signal cards, WiFi card, status
    │   │   ├── DeviceInfo/    Hardware + firmware info
    │   │   ├── Login/         Auth + keychain
    │   │   ├── RouterSettings/
    │   │   │   ├── APN/       APN profile management
    │   │   │   ├── CellLock/  Cell locking
    │   │   │   ├── Device/    Reboot, USB, battery, charge policy
    │   │   │   ├── DNS/       DNS settings
    │   │   │   ├── Firewall/  Firewall rules
    │   │   │   ├── LAN/       DHCP settings
    │   │   │   ├── MobileNetwork/  Network mode, SA/NSA
    │   │   │   ├── NetworkMode/    Network selection
    │   │   │   ├── QoS/       Traffic shaping
    │   │   │   ├── Schedule/  Scheduled reboot/wifi
    │   │   │   ├── SignalDetect/   Signal quality detection
    │   │   │   ├── SIM/       SIM card PIN/PUK management
    │   │   │   │   └── STK/   SIM Toolkit & USSD
    │   │   │   ├── STC/       Smart Tower Connect
    │   │   │   ├── Telemetry/ Telemetry blocking
    │   │   │   ├── VPN/       VPN settings
    │   │   │   └── WiFi/      WiFi configuration
    │   │   ├── Scheduler/     Scheduled/recurring jobs
    │   │   ├── Settings/      App settings
    │   │   ├── Signal/        Signal monitor
    │   │   ├── SMS/           SMS compose/read/conversations
    │   │   ├── Tools/         Band lock, clients, config, etc.
    │   │   └── USBMode/       USB mode detection/switching
    │   └── Navigation/        5-tab bar (Dashboard, SMS, Tools, Router, Settings)
    └── android/OpenU60/       Jetpack Compose app
        ├── core/              Network, crypto, models, DI
        ├── feature/           bandlock, clients, config, dashboard,
        │                      deviceinfo, login, router, scheduler,
        │                      settings, signal, sms, tools, usb
        └── navigation/        NavHost + bottom bar

├── web/                       Landing page & web dashboard (open-u60-pro.vercel.app)
│   ├── src/
│   │   ├── app/               Next.js app router (page, layout, globals)
│   │   ├── components/        Landing sections, UI primitives
│   │   └── data/              Feature data, API endpoints, device specs
│   └── public/                Static assets (images, icons)
```

## Signal Thresholds

| Metric | Excellent | Good | Fair | Poor |
|---|---|---|---|---|
| **RSRP** (dBm) | >= -80 | >= -100 | >= -110 | < -110 |
| **SINR** (dB) | >= 20 | >= 10 | >= 0 | < 0 |
| **RSRQ** (dB) | >= -10 | >= -15 | >= -20 | < -20 |

## iOS Live Activities

Show the modem's signal on your iPhone Lock Screen and Dynamic Island. The layout
adapts to LTE, LTE carrier aggregation (4G+), and 5G, with signal bars, RSRP,
SINR, and sample age. Readings describe the modem's cellular connection.

<p align="center">
  <img src="mobile/ios/screenshots/live-activity-lock-screen.png" alt="OpenU60 Lock Screen Live Activity showing 4G+ LTE carrier aggregation, -72 dBm RSRP, 9 dB SINR, and a 12-second sample age" width="430">
</p>

### Enable the feature

1. **Prepare Apple signing.** Use your own Apple Developer team, an explicit app
   bundle ID with Push Notifications enabled, a matching provisioning profile,
   and an APNs authentication key (`AuthKey_<KEY_ID>.p8`). Update the app and
   extension bundle IDs/signing in
   [project.yml](mobile/ios/OpenU60/project.yml). The ActivityKit manager,
   Live Activity extension, and Live Activities Info.plist flags are included.
   The current iOS project targets iOS 17 or later.
2. **Configure the modem.** Copy your `.p8` and an edited
   [example configuration](zte-agent/config/live-activity.example.json) to
   `/data/zte-agent-apns/`. Set `enabled` to `true`, fill in your Team ID, Key ID,
   containing-app bundle ID, and key path. Match `environment` to the installed
   build: `sandbox` for development, `production` for TestFlight/App Store.
   Keep the directory root-owned with mode `700` and both files mode `600`.
3. **Enable the agent sender.** Preserve the existing password and startup
   settings, add the following environment variable to the agent launch script,
   and restart only `zte-agent` to load the configuration:

   ```sh
   export ZTE_AGENT_LIVE_ACTIVITY_CONFIG=/data/zte-agent-apns/live-activity.private.json
   ```

4. **Start on the iPhone.** Install your signed app, connect to the modem, log in,
   and tap **Dashboard → Live signal → Start**. Allow Live Activities in iPhone
   Settings. Lock the phone to see the card, or expand the Dynamic Island on a
   supported iPhone. Tap **Stop** in the app to end the session.

The modem sends directly to Apple Push Notification service (APNs); no hosted
backend is required. Both the modem and iPhone need internet access for push
updates. Keep private keys out of Git and the app bundle; self-hosting developers
use their own credentials. See the [full setup and API guide](zte-agent/docs/live-activity.md)
for file provisioning, signing, and configuration details.

### Freshness and recovery

- The default send interval is **15 seconds**, with readings marked stale after
  **30 seconds**. Apple controls delivery, so this is not a guaranteed refresh
  rate. Sample age should reset when a newly sampled update reaches the phone.
- Sessions last **one hour**. Currently the agent holds **one registration**;
  starting an activity on another phone replaces it. Agent restarts clear that
  registration; reopen the app to register again, or use Stop/Start if needed.
- SIM removal/ready and WAN events trigger agent recovery. It verifies internet
  access and UTC before resuming delivery, retaining an unexpired registration.
- **Apple accepted an update** confirms submission, not phone delivery. During
  physical testing after a SIM swap, agent sends recovered but the iPhone stayed
  stale until Wi-Fi was toggled off/on. If this happens, reconnect the iPhone's
  Wi-Fi and check sample age. Fully automatic phone-side recovery is not yet
  verified; see the [SIM-swap test findings](zte-agent/docs/sim-swap-ubus-2026-09-15.md).

## License & Disclaimers

This project is licensed under the [MIT License](LICENSE).

**Disclaimer:** This software is provided "as is", without warranty of any kind. Use it at your own risk. The authors are not responsible for any damage to your device, voided warranties, or other consequences arising from the use of this software.

- **Not affiliated with ZTE Corporation.** This is an independent community project.
- Intended for use on devices you personally own.
- Reverse engineering was performed solely for interoperability and educational purposes.
- Encryption keys and protocol details are sourced from publicly available community research.
- No proprietary source code from ZTE is included in this repository.
