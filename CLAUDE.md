# CLAUDE.md — ZTE U60 Pro Project Guidelines

## Device Overview
- **Model**: ZTE U60 Pro 5G CPE router
- **OS**: OpenWrt 23.05.4 on Qualcomm SDX75 (aarch64, musl libc)
- **SSH**: Port 2222 at 192.168.0.1
- **Filesystem**: Read-only rootfs, writable overlay at `/zteoverlay/`, writable `/data`

## Architecture
- `zte-agent/` — Rust agent on the device, port 9090 (LAN, plus the tailnet when Tailscale is on): JSON API under `/api/` for the apps, browser UI under `/ui/` (`/` redirects there)
  - HTTP (`src/httpd/`): axum on hyper http1, one current-thread tokio runtime on the main thread. There is no tiny_http and there are no `http-N` worker threads. The accept loop itself refuses connections from the mobile-data side (`httpd::mobile`, owner decision 53): only loopback (Tailscale), the router's own addresses and peers whose most specific local subnet belongs to an interface other than `rmnet*` or the relay's `ath20` are served. The interface table is read on the blocking pool (awaited at most 0.5 s); a failed lookup keeps the last table 10 min, then serves everything; `ZTE_AGENT_ALLOW_MOBILE=1` turns it off.
  - LAN HTTPS (`src/tls/`, `httpd::tls`, owner decision 59): off until the owner turns it on in Settings; the router's own CA, name-constrained to the LAN address at Turn On (/32) and `u60.home.arpa` only (root key dropped after signing one issuing CA with the same constraints; files in `/data/zte-agent-tls/`, dir 0700, keys 0600, never logged/rendered/served), HTTPS on `0.0.0.0:9443` (`ZTE_AGENT_TLS_BIND`) with the same router, caps (shared) and mobile check as :9090, `__Host-` cookies over HTTPS, `u60.home.arpa` via `/tmp/hosts/zte-agent` + SIGHUP to dnsmasq and a Host only over HTTPS; Reset ends open HTTPS connections; no timers (issue again at start, on a TLS connection, after a LAN apply; renew automatically only on the verified clock, which needs a Live Activity provider; else Settings › Renew); no HSTS.
  - Never run blocking work (ubus, uci, AT, APDU, blocking HTTP) on the runtime thread. `/api` calls go `server::precheck` → `httpd::gate` (General lane = `ZTE_AGENT_THREADS`, default 4, clamped 1–32; Slow lane 2; 7 s wait → 503 `agent busy, retry`) → `server::route()` on the blocking pool. Debug builds panic on a device call from the runtime thread. Put new long-running routes in `server::lane()` as Slow.
  - Relay status/scans are snapshots with `phase`. Owner requests queue to `relay`, waiting at most 3 s for admission/start, then 409 with the phase. Abandoned requests never run. Connect validates the scan snapshot first. Disconnect cancels immediately during work; idle callers wait for the controller's teardown/CAC (`zte-agent/docs/relay-mihomo-architecture.md` §6.1).
  - Auth (`src/auth/`): random 64-hex bearer tokens (1 h idle / 24 h max) and browser sessions (12 h / 7 d), expiry on CLOCK_BOOTTIME, login rate limit (429 + Retry-After; loopback = all Tailscale clients, blocks capped at 10 s). Never log passwords, tokens or cookies. Automation over ADB uses the per-start local token in `/tmp/zte-agent-run/admin-token` (0600, loopback peers only, so through `adb forward`; no event streams; never print it), see Basic Debugging.
  - Live data (`src/events/`): event hub plus a demand-driven sampler (`hub-fast`, `hub-ubus`) feeding `GET /api/events` (`zte-agent/docs/events.md`) and the UI's live pages. Nothing may be sampled or polled while no stream is open.
  - Web UI (`src/web/`, `zte-agent/docs/web-ui.md`): maud pages that work without JavaScript; never use `PreEscaped` (a test checks). Datastar 1.0.4 is vendored and SHA-pinned in `build.rs` (keep `.gitattributes`); the only other script is `assets/theme.js` (System theme only, owner decision 60). `app.css` ≤ 48 KiB (a test checks). Never render IMEI, IMSI or a full ICCID (last 4 at most). The authenticated Wi-Fi connected-device page and its live fragment show full MACs and hostnames (owner choice); other device lists mask MACs to the last 2 octets and mask MAC-derived hostnames. Fixed client IP reservations show full MACs for binding verification. SMS numbers and text only on authenticated SMS pages, never in `<title>`, URLs, `next`, logs or fragment ids. Never render Wi-Fi, guest Wi-Fi or APN passwords, or forwarding secrets, except the Wi-Fi password on the no-store Share Wi-Fi page.
  - Measure the release binary for every change: `aarch64-linux-musl-size -A` Total and gzip size.
- `mobile/ios/` — SwiftUI companion app
- `mobile/android/` — Jetpack Compose companion app
- `web/` — Next.js landing page, docs and browser installer (open-u60-pro.vercel.app); not the on-router web UI

---

## Deployment

Run commands from the repository root (`open-u60-pro/`). Use `setup.sh` for
normal deployments; `deploy.sh` is the older SSH/password-based path.
Prerequisites: Rust, the `aarch64-unknown-linux-musl` target, `adb`, and
`aarch64-linux-musl-gcc` on `PATH`.

```sh
adb devices -l
export ANDROID_SERIAL="<serial from adb devices -l>"
./setup.sh --build --adb --serial "$ANDROID_SERIAL" --factory-password --no-ssh
```

This builds the current checkout as a release, installs it in the update supervisor's slot A (`/data/open-u60/update/slot-a/zte-agent`,
linked at `/data/zte-agent`), and starts it through `/data/local/tmp/start_zte_agent.sh`. Factory-password mode uses the official router
admin password and requires already-authorized ADB. The management page is `http://192.168.0.1:9090/ui/`. A build from before
2026-11-12 (station `u60sta0`) and this one do not undo each other's relay: disconnect the relay before changing between them, or reboot.

On this development Mac, an alternative musl toolchain uses existing Zig
wrappers. If using them, first confirm the files exist, then set these variables
before running the build or installer; `/tmp` paths are not permanent:

```sh
export PATH="/tmp/u60-cross-tools:$PATH"
export CC_aarch64_unknown_linux_musl=/tmp/u60-cross-tools/aarch64-linux-musl-gcc
export AR_aarch64_unknown_linux_musl=/tmp/u60-cross-tools/aarch64-linux-musl-ar
```

To compile without deploying:

```sh
cargo build --locked --release --target aarch64-unknown-linux-musl -p zte-agent
```

## Basic Debugging

Use the same `ANDROID_SERIAL` when inspecting the device. Read agent output,
identify the running executable, or read the kernel log (`logread` only
repeats "Failed to find log object" on this firmware):

```sh
adb shell 'tail -n 100 /tmp/zte-agent.log'
adb shell 'p=$(cat /tmp/zte-agent-run/pid); readlink "/proc/$p/exe"'
adb shell 'dmesg | tail -n 100'
```

Use `adb shell 'tail -f /tmp/zte-agent.log'` for live agent output; Ctrl-C ends
the log stream. To call the API without the admin password (the agent accepts
its local token only over loopback, which an ADB forward is):

```sh
adb forward tcp:18090 tcp:9090
TOKEN=$(adb shell cat /tmp/zte-agent-run/admin-token | tr -d '\r\n')
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18090/api/wifi-relay/status
```

Run unit tests on the development computer, not the router:

```sh
cargo test --locked -p zte-agent
cargo test --locked -p zte-agent wifi_relay:: -- --nocapture
```

Replace `wifi_relay::` with the module or test name being investigated. Run one
`cargo test` per machine at a time (worktrees included): the `httpd::tls` bridge
test's mock core binds the fixed `127.0.0.1:19090`.

## Test Scripts and Backups

Keep every ad-hoc file in one fixed folder per kind, so cleanup is deleting a folder:

| Kind | Router | Development Mac |
| --- | --- | --- |
| Test scripts, samplers, logs, captures | `/data/local/tmp/zte-agent-test/` | `/tmp/u60-test/` |
| Copies of router files before a manual change, and their restore scripts | `/data/zte-agent-backup/<topic>/` | `../backups/<topic>/` (next to the repository) |

- Delete both test folders when the test ends; repeatable checks belong in `scripts/` instead.
- Name a backup after the original plus `.orig`, keep it until the owner asks to remove it, and record it in the topic's doc. Kept now: none (the old IPACM install's copies on the router and in `../backups/ipacm/` were removed 2026-11-12 at the owner's request).
- The agent's own runtime state and backups stay in its directories (`/data/zte-agent-relay/`, `/data/zte-agent-mihomo/`); `setup.sh` keeps no installation backup.

---

## CRITICAL: ZTE Daemon Sync Barrier

`zte_topsw_daemon` is the master daemon. It reads `/etc/config/zte_topsw_daemon.conf` and **waits for ALL listed daemons to register** before releasing the boot sequence.

### If you disable a daemon listed in daemon.conf via init.d, the device will:
- **Display stuck on ZTE boot logo** (UI never renders)
- **WAN never connects** (mobile data call never initiated)
- **Touchscreen unresponsive** (mtdev2tuio bridge never starts)

All other daemons appear to run fine — making the root cause very hard to diagnose.

### Daemons in daemon.conf (NEVER disable via init.d):
```
zte_topsw_mc, zte_router, zte_topsw_data, zte_topsw_nwinfo,
zte_topsw_mdm, zte_topsw_sleep_faw, zte_topsw_apn, zte_topsw_wms,
zte_topsw_key, zte_topsw_led, zte_topsw_tr098db, zte_dm,
zte_topsw_fota_result, zte_topsw_devui, zte_topsw_wlan, zte_smart_manage
```

### Safe to disable via init.d (NOT in daemon.conf):
```
zte_topsw_diag, zte_topsw_samba, zte_topsw_nfc, zte_topsw_get_brand,
zte_topsw_jwxk_query, zte_topsw_tr069_sub, zte_mqtt_sdk_st,
zte_topsw_dua, zte-topsw-tunnel
```

### How to properly disable a daemon.conf daemon:
Comment it out in `/etc/config/zte_topsw_daemon.conf` (prefix with `#`). Do NOT use `/etc/init.d/<name> disable`.

### Overlay Whiteouts
`/etc/init.d/<name> disable` creates **whiteout character devices** in `/zteoverlay/etc-upper_a/rc.d/` that silently delete the ROM symlinks. These are invisible in normal `ls /etc/rc.d/` but persist across reboots.

- **Check**: `ls -la /zteoverlay/etc-upper_a/rc.d/ | grep '^c'`
- **Fix**: `rm /zteoverlay/etc-upper_a/rc.d/<whiteout_file>`

### Verify sync status after boot:
```sh
ubus call zwrt_topsw_daemon.sync get_sync_info '{}'
# Should return: "noSyncModuleName": "sync success"
```

---

## Recovery Commands

### Display stuck on logo
```sh
# Start touchscreen driver + bridge
sh /usr/bin/mtdev2tuio.sh
# Restart UI daemon
kill -9 $(pidof zte_topsw_devui); /usr/bin/zte_topsw_devui &
```

### WAN not connecting
```sh
# Enable IPv4 data call
ubus call zwrt_qcmap_cli set_qcliiface '{"source_module":"zte_topsw_data","type":1,"enable":1,"sub_id":1}'
# Enable IPv6
ubus call zwrt_qcmap_cli set_qcliiface '{"source_module":"zte_topsw_data","type":2,"enable":1,"sub_id":1}'
```

### Check data call status
```sh
ubus call zwrt_data get_wwaniface '{"source_module":"zte_topsw_data","cid":1}'
# Look for: "enable": 1, "connect_status": "connected"
```

---

## Other Device Notes

- **Airplane mode bug**: `nwinfo_set_mode ONLINE` does NOT recover modem from LPM. Only fix: reboot.
- **Charge policy bug**: Wall mode `enable` STOPS charging, `disable` STARTS charging (inverted).
- **procd respawn**: `kill -9` may trigger procd respawn. Use `/etc/init.d/<name> stop` instead.
- **Touchscreen**: Sitronix at I2C `1-0055`, kernel module `sitronix-ts.ko` loaded by `/usr/bin/mtdev2tuio.sh`.
- **eSIM**: No built-in eUICC. The user-tested 9eSIM B1 in the SIM slot is managed by the agent in-process (`euicc/` crate, a Rust translation of lpac's libeuicc, over QMI-over-QRTR, node 3, slot 1): list, switch, download, delete — see `zte-agent/docs/esim.md`. lpac itself is no longer used (removed 2026-10-19; the old `/data/lpac` bundle is archived on the router as `/data/lpac.removed`). The old phone-Bluetooth B1 code was removed. Do not reverse-engineer the qcril/RIL internals to forward SIM Toolkit screens.
- **IMEI**: Hardware-locked (QFPROM fused), not modifiable.
- **USB network and ADB share one gadget** (`/sys/kernel/config/usb_gadget/g1`): the agent maintains one `c.1` with `f1`→`gsi.rndis`, `f2`→`gsi.ecm`, `f3`→`ffs.adb` (owner decision 66, `usb_net.rs`, `zte-agent/docs/usb-network.md`). Windows uses RNDIS and macOS ECM; device class is `EF/02/01`, and the serial gets the stable `-u60net1` suffix to refresh Windows' driver binding. This three-function layout exposes network and ADB; the vendor's diagnostic/serial/storage functions await separate validation. The old agent-owned `c.2` is migrated away. ZTE's `usb_switch` clears `f*` and rebuilds the vendor layout; inotify repairs it after about 1 s. Edit only unbound with `adbd` stopped (`kill -STOP`), because it rebinds within about 20 ms. Failures restore the prior links/descriptors and rebind. First bound-device conversion waits 60 s after agent start so deployment can finish. `zwrt_bsp.usb` has `list` only, no `set`.
- **The development Mac's internet goes through the router**: macOS ranks the USB service "ZTE Mobile Broadband" above Wi-Fi, so a relay disconnect cuts the Mac's internet and an agent session running there (taking `ecm0` down does not make macOS fail over). Before testing relay disconnects, give the Mac an internet path that does not go through the router.
- **Power-off charging boot**: after a low-battery power-off (`reboot_module_name='lowbatt power off'`), restored power boots the vendor's power-off charging mode: Linux, `adbd` and the agent run, Wi-Fi never starts (`zwrt_zte_mc_tmp.mode.mode_main_state=mode_power_off_charger`, `iw dev` empty). `ubus call system reboot '{}'` brings it up normally. `wireless.zte_mbb.wifi_onoff` is 0 then while the owner's switch `wifi_onoff_by_user` stays 1; the relay keeps its restart choice because it reads the latter (`hotspot::off_by_owner`).
- **5 GHz DFS channel switch**: after each 160 MHz 5 GHz start on an auto channel, `/sbin/zte_wifi_dfs_hdlr.sh` runs `iwpriv wlan2 disableDfsCS 1` for 599 s. While this driver-wide flag is 1 every channel switch ends on the old channel, and a STA connect with the AP spanning DFS (any 160 MHz AP here) wedges the AP in `Channel switch in progress` until a hotspot restart. The relay keeps `wireless.zte_mbb.dfs_channel_switch_disable=1` (persistent; the script and the next driver load then leave the flag off) and still runs `disableDfsCS 0` before each join (owner decision 62, `wifi_relay/dfs_switch.rs`). No setting replaces the staging step: before every STA join the driver moves a hotspot spanning DFS, which fails with a DFS upstream, so the relay first puts it on a non-DFS 20 MHz channel. A hotspot that followed the station onto a DFS channel blocks a new association there (SCANNING), so a switch between 5 GHz upstreams keeps the station, the hotspot journal and the offline-portal suppression (`dns.json`) and only moves the hotspot back to staging first (`handover`; about 8-11 s instead of 75-85 s). Reconnecting to the same access point also keeps IPv6.
- **IPA hardware forwarding of the relay**: IPACM reads `/etc/data/ipa/IPACM_cfg.xml` once at boot; never restart `ipacm` at runtime (the new process misses the driver's earlier Wi-Fi events). It offloads relay NAT only for an interface that file lists, with a `main` default through it (policy tables are ignored). So the station is `ath20`, which B31's stock file lists (never a `wlan*` name: the vendor's Wi-Fi off waits for those to vanish); the agent only reads the file and adds the route. IPACM's mode is the vendor's (owner decision 2026-11-12, `wifi_relay/offload.rs`; `zte-agent/docs/relay-hw-offload.md`): working mode Balanced (`zwrt_smart_mng.smart_qos.mode=Nomal_mode`, 极速模式) turns acceleration on; the other five, the vendor speed limits and `ipa_disable` turn it off (`Ai_mode`, the factory default, and `Game_mode` flip it with traffic).
- **IPACM hands offloaded uplink to other upstream hosts**: in STA mode every IPv4 neighbour of `ath20` becomes a WAN client whose rule (`src` = relay address) goes ahead of the gateway's in `WANRTBLv4`, so offloaded connections stall about 30 KB in (their ACKs go to that host). IPACM drops a client's rule, without re-adding it, when its MAC shows up at another IPv4 address; `wifi_relay/offload/neighbours.rs` does that for every non-gateway MAC. (`zte-agent/docs/relay-hw-offload.md`, section 8).
- **IPACM loses a hotspot client's LAN route when it changes bands**: after a bridge FDB deletion IPACM re-registers the client with 0.0.0.0 and adds its `COMRTBLLANv4` route only on the next IPv4 neighbour event from `br-lan`, which a busy (REACHABLE) client never causes, so its traffic stays on the CPU. `wifi_relay/offload/clients.rs` sets that entry STALE (`ip -4 neigh change … nud stale`) 5 s after each `iw event` association and once for all clients at start; never deauthenticate, restart ipacm or delete the entry. IPACM's log is `/data/data_ipa/log_file.txt` (verbose: `kill -46`/`-47` the ipacm pid); IPA debugfs (`/sys/kernel/debug/ipa/hdr`, `ip4_rt`) prints to the kernel log, so mark `/dev/kmsg` first and never `dmesg -c` (`zte-agent/docs/relay-hw-offload.md`, section 9).
- **ZTE rewrites the agent's network changes**: fw3, firewall/speed-limit/QoS/guest-isolation scripts and WAN events rewrite legacy rules, sysctls and routes. Every fw3 reload runs `firewall_init.sh`, setting `bridge-nf-call-ip(6)tables=1` and flushing nat `redirect_chain`. The post-connect reload comes from IPv6's `ubus call network.interface.lan set_data` (`wifi_relay/ipv6/ra.rs`), netifd's `iface` hotplug (`ifupdate`), then `20-firewall` → `fw3 -q reload`. Put changes in the owner's `EffectSet`. `net_guard.rs` checks 2 s after inotify (`WATCHED`, fw3 plus five brnf/redirect writers) or ubus (`EVENTS`) settles, 5 s after repair, or every minute. `net_tools::Pass` shares one listing per tool/table and `ip` family/kind, invalidated after repair. Repair only confirmed absence/mismatch, replace owned chains whole, keep one hook copy. Only portal RETURN positions are enforced; later vendor rules ahead of other hooks stay (D8). B31 `-C`/`-D` exit 1 means missing with "Bad rule (does a matching rule exist in that chain?)" for ACCEPT/RETURN or "No chain/target/match by that name." for MASQUERADE/existing-chain jumps (`netfx::effect::legacy::no_rule`). `not checked` waits for the next check; repair logs name commands/resources, e.g. `iptables -t nat hook redirect_chain …`. For 3 s after each trigger, held `@u60-sysctl` values are sampled every 0.5 s. Keep repairs here except IPv6's addresses, routes and RA, checked by its session on settled triggers or every 15 s. Legacy ownership requires a `U60_*` chain/target or `zte-agent*` comment, never an interface name. Never leave two station MASQUERADE rules: B31 drops some new connections (Mihomo's included) with `nf_nat_setup_info` warnings. `Cmd::undo` skips unknown `@u60-*` steps (`[net] skipped an undo`).
- **Mihomo is TPROXY, rules in nftables**: tables `ip`/`ip6 u60_mihomo` (ZTE never touches nft; the relay's own are `ip`/`ip6 u60_relay`, built in `wifi_relay/uplink.rs`: its upstream guard, forwarding drops, IPv6 baseline rejects, NAT66 masquerade and DNS; both loaded whole by the owner's `EffectSet` through `NftTables` with a generation marker), port 17894 (17893 is the private download proxy). TPROXY needs `bridge-nf-call-ip(6)tables=0` while the core runs (with 1 the socket is lost on the bridge path). The kernel has no `NFT_FIB_INET` (`fib` only in `ip`/`ip6` tables) and no nft bridge family. An nft accept cannot override a legacy DROP, so exceptions stay in legacy as accept-only chains (IPv4 `U60_RELAY_IN`/`U60_RELAY_FWD`, IPv6 `U60_R6_IN`/`U60_R6_FWD`, the latter INPUT hooked directly), with the `redirect_chain` RETURN (kept ahead of every vendor rule there) and the IPv4 MASQUERADE; denials go in the nft tables. nft rejects the chain names `fwd`, `post` and `c`. DNS is always fake-ip (`198.18.0.1/16`, no IPv6 pool), and `198.18.0.0/16` always goes to the core. With the DIRECT bypass on (`cn-direct`), rule mode compiles the subscription's rules top-down into the IPv4 chain: address/port/network rules that reach DIRECT through `select` groups `return`, others `goto to_core`, domain rules are left to fake-ip, and a non-DIRECT rule the kernel cannot check ends the chain (`mihomo/routing.rs`, owner decision 64). The rule-mode `fake-ip-filter` depends only on the configuration and the bypass switch: only domain rules sent to `DIRECT` itself from a fixed list keep real addresses; anything behind a group or a refreshed rule set is fake (owner choices Q2/Q3, 2026-11-10). `http` rule sets lose their `interval`; the controller refreshes them. Never let the kernel bypass traffic the rules would not send DIRECT.
- **Mihomo controller** (`mihomo/controller.rs`, `zte-agent/docs/relay-mihomo-architecture.md` §5): one thread owns the core/effects, never the relay lock. Routing writes hold first, write, read back, reset only lost DIRECT (`routing::lost_from` over all possibly held tables), then load; domain rule-set refresh goes straight to the core. Selected-subscription refresh hot-reloads: identical source skips compile/validation; a changed source validates `candidate.yaml` once while the old core serves. Startup-only changes or rejected/unconfirmed reloads restart with that candidate, falling back to `Run.prepared`; profile selection/edits and extensions still use restart. Every `to_core` ends with TCP/UDP drop. Confirmed core exit goes D3 direct (fake-ip reset/reject; retries 5/15/30/60 s, then 5 min); failed withdrawal stays CleanupPending; boot restore/new IPv4 egress retries immediately. Controller panic aborts the agent; `zte-agent guard` restarts it and adopts this boot's tables and valid relay connection (`wifi_relay/adopt.rs`, supplicant/`odhcp6c` kept, new `udhcpc`). `touch /tmp/zte-agent-run/stopped` before deliberate stops. Egress moves restart once (`mihomo/egress.rs`); planned restart prepares before Hold. The last 4 validation fingerprints omit top-level `interface-name` and persist for this boot in `/data/zte-agent-mihomo/validated`; journals use undos the previous agent runs (`tests/mihomo-qa`). With no keep-alive setting, managed defaults are idle 120 s/interval 30 s; router probes fell from 88/min (87 core descriptors) to 6/min (99), measured over 60 s/120 s in `measurements/b4-final/{mihomo-refresh,keepalive-later}.txt` beside the handoff (full conditions: implementation batch 4).
- **`iwpriv ath20 chwidth` (manual tests only; the agent never runs it)**: a narrower width lapses silently after about 100-260 s (5 GHz downlink back to wide or collapsing, e.g. 80 MHz from about 310 to 45 Mbit/s; 2.4 GHz 20 MHz to about 3 Mbit/s) while `iw` still reads it; re-sending the same value does nothing (set another, then the target). It survives reconnects, interface re-creation and band changes, so set the width back after a test. After a change `iw` can read the new width while the gateway stops answering ping for about 60 s (`arping` still answers, so check with ICMP); the wider width for 1 s, then the target, recovers it (`zte-agent/docs/network-extensions.md`).
- **The STA width cannot be capped at association**: the vendor `wpa_supplicant` has no HT/VHT overrides; an upstream 2.11 build with them sent `disable_ht40=1` and qcacld still associated at 40 MHz, and it lacks the vendor `DRIVER` commands (`SETROAMMODE`) the relay uses, so keep the system supplicant. Debugfs `ll_stats` per-rate counters are TX-only, so the AP's downlink width cannot be read either (`zte-agent/docs/network-extensions.md`, driver limits).
