# ZTE U60 Pro project guidelines

The router is a Qualcomm SDX75 (aarch64, musl) running OpenWrt 23.05.4. SSH is at `192.168.0.1:2222`. The rootfs is read-only, with a writable overlay at `/zteoverlay/` and writable `/data`.

## Architecture

- `zte-agent/` serves the JSON API at `/api/` and the browser console at `/console/` on port 9090 for LAN and enabled tailnet clients. HTTP uses axum on hyper HTTP/1 and one current-thread Tokio runtime. Keep all blocking device and HTTP work on the blocking pool, and put new long-running routes in `server::lane()` as Slow. Preserve the `precheck` → lane admission → route boundary.
- The HTTP and HTTPS accept loops refuse upstream peers on `rmnet*` and `ath20`. Preserve these checks and the LAN HTTPS trust rules, including the LAN address and `u60.home.arpa` CA constraints and private key handling. See the [security policy](SECURITY.md#security-considerations) and [console transport](zte-agent/docs/responsive-console.md#authentication-and-transport).
- Relay status and scan results are snapshots. Owner requests have 3 s total for admission and controller start before returning 409 with the phase, and abandoned requests must never run. Validate Connect against the scan snapshot first. Disconnect during work cancels immediately. Idle callers wait for teardown and any CAC. See [architecture §6.1](zte-agent/docs/relay-mihomo-architecture.md#61-会话与取消).
- Sample or poll live readings only while subscribed. See [API events](zte-agent/docs/events.md) and [console live data](zte-agent/docs/responsive-console.md#live-data).
- Production UI lives in `zte-agent/ui/`. `/ui/` bookmarks redirect into the console. Keep `src/web/` as retired renderer fixtures, avoid `PreEscaped` in maud fixtures, and preserve the Datastar 1.0.4 SHA pin in `build.rs`, `.gitattributes`, the System-theme-only `assets/theme.js` and the 48 KiB `app.css` budget. See [Responsive console](zte-agent/docs/responsive-console.md).
- Never render IMEI or IMSI. Limit ICCID to its last four digits and mask device-list MACs to their last two octets. Render SMS numbers and text only on authenticated SMS pages, outside titles, URLs, `next`, logs and fragment IDs. Keep Wi-Fi, guest Wi-Fi, APN and forwarding secrets out of rendered pages, with the Wi-Fi password allowed on the no-store Share Wi-Fi page.
- Measure release binary size for every change using the `aarch64-linux-musl-size -A` Total and gzip byte count.
- Companion apps live in `mobile/ios/` (SwiftUI) and `mobile/android/` (Jetpack Compose). `web/` is the Next.js landing site, docs and browser installer.

## Deployment and debugging

Run from the repository root. For local release work, use Rust with the `aarch64-unknown-linux-musl` target and `aarch64-linux-musl-gcc` on `PATH`. Build with `cargo build --locked --release --target aarch64-unknown-linux-musl -p zte-agent`.

Use `setup.sh` for normal deployments. `deploy.sh` is the older SSH/password path. For an ADB-authorized B31, set `ANDROID_SERIAL` to the intended device and run `./setup.sh --build --adb --serial "$ANDROID_SERIAL" --factory-password --no-ssh`. This uses the router's official admin verifier, initializes both OTA slots with the same new build and starts slot A. See [first-time setup](README.md#first-time-setup).

Before switching between this relay and a test build from before 2026-11-12 (`u60sta0`), disconnect the relay or reboot. Before an intentional agent stop, run `touch /tmp/zte-agent-run/stopped` to suspend guard restarts.

Always select the intended `ANDROID_SERIAL` for ADB, including debugging. Never log passwords, tokens or cookies or print `/tmp/zte-agent-run/admin-token`. The mode-0600 per-start token works only over loopback via ADB forwarding and excludes event streams. See the [ADB debugging commands](zte-agent/docs/README.md#adb-debugging).

## Tests and backups

Run Rust tests on the development host with `cargo test --locked -p zte-agent --no-fail-fast` or select a module with `cargo test --locked -p zte-agent wifi_relay:: -- --nocapture`. Use `node scripts/test-agent.cjs pure`, `browser`, a suite name or `screenshots` for console checks. See [Tests and QA](zte-agent/docs/README.md#tests-and-qa) for CI coverage, browser setup, isolated harnesses and device-only probes.

| Kind | Router | Development Mac |
| --- | --- | --- |
| Ad-hoc scripts, samplers, logs and captures | `/data/local/tmp/zte-agent-test/` | `/tmp/u60-test/` |
| Copies before a manual device change and their restore scripts | `/data/zte-agent-backup/<topic>/` | `../backups/<topic>/` (next to the repository) |

- Clear the test folders when the test ends. Put repeatable checks in `scripts/`.
- Append `.orig` to backup names, record them in the topic doc and keep them until the owner asks to remove them.
- Keep the agent's runtime state and backup data in the relevant agent directories, such as `/data/zte-agent-relay/` and `/data/zte-agent-mihomo/`. `setup.sh` keeps no installation backup. See [OTA trial recovery](docs/ota-updates.md#failure-behavior) for signed updates.

## Critical ZTE daemon sync barrier

`zte_topsw_daemon` waits for every daemon listed in `/etc/config/zte_topsw_daemon.conf`. A missing registration stalls the boot logo, touchscreen and mobile data even when other daemons are running. Never use init.d `disable` on a listed daemon. To take it out of the boot barrier, comment it out in that config. Check membership on the target firmware before disabling an unlisted daemon through init.d.

`/etc/init.d/<name> disable` leaves a persistent overlay whiteout even when `ls /etc/rc.d/` shows nothing. Inspect `ls -la /zteoverlay/etc-upper_a/rc.d/ | grep '^c'` and remove the specific whiteout to restore the ROM link. Verify boot sync with `ubus call zwrt_topsw_daemon.sync get_sync_info '{}'` and check for `"noSyncModuleName": "sync success"`.

## Recovery commands

For a display stuck on the logo, start the Sitronix touchscreen driver and bridge, then restart the UI daemon.

```sh
sh /usr/bin/mtdev2tuio.sh
kill -9 $(pidof zte_topsw_devui); /usr/bin/zte_topsw_devui &
```

If WAN stays disconnected, start the IPv4 and IPv6 data calls, then check that `enable` is 1 and `connect_status` is `connected`.

```sh
ubus call zwrt_qcmap_cli set_qcliiface '{"source_module":"zte_topsw_data","type":1,"enable":1,"sub_id":1}'
ubus call zwrt_qcmap_cli set_qcliiface '{"source_module":"zte_topsw_data","type":2,"enable":1,"sub_id":1}'
ubus call zwrt_data get_wwaniface '{"source_module":"zte_topsw_data","cid":1}'
```

- Reboot if `nwinfo_set_mode ONLINE` leaves the modem in LPM. Wall charge mode's `enable` stops charging and `disable` starts it. Use `/etc/init.d/<name> stop` where available to avoid procd respawn.
- IMEI is fused in QFPROM. For eSIM, use the [QMI-over-QRTR profile implementation](zte-agent/docs/esim.md) with the card in the SIM slot. Do not reverse-engineer qcril/RIL to forward SIM Toolkit screens.

## USB, relay and network changes

- **USB gadget.** Keep RNDIS, ECM and ADB in one `c.1` and migrate the old `c.2`. Pause `adbd` before unbinding, edit only unbound, restore links and descriptors and rebind on failure, then resume `adbd`. Delay the first bound-device conversion by 60 s. See [USB behavior](zte-agent/docs/usb-network.md#zte-重建与-adbd) and [2026-11-13 validation limits](zte-agent/docs/usb-network.md#2026-11-13-的单配置).
- **Relay disconnect tests.** Verify an independent internet path on the Mac first. macOS may prefer its USB service through the router even when `ecm0` goes down. See [Mac network path](zte-agent/docs/usb-network.md#开发-mac-的联网路径).
- **Hotspot and DFS.** Preserve the relay's restart choice in power-off charging mode. Use `wifi_onoff_by_user` to detect an owner shutdown. Preserve `wireless.zte_mbb.dfs_channel_switch_disable=1`, clear `disableDfsCS` before each join, stage at non-DFS 20 MHz before 5 GHz joins, and retain the station, hotspot journal and portal suppression through 5 GHz handover. See [relay lifecycle](zte-agent/docs/relay-lifecycle.md#连接方案) and [charging boot](zte-agent/docs/network-extensions.md#power-off-charging-boot).
- **STA width.** Keep `iwpriv ath20 chwidth` out of the agent. For a manual width test, record and restore the original value and validate connectivity with ICMP. Keep the system `wpa_supplicant` and its `SETROAMMODE` support. See the [2026-10-29 width and driver record](zte-agent/docs/archive/2026-10-29-width-v2-acceptance.md).
- **IPA.** Use `ath20` with the `main` default route and firmware-selected IPA mode. Never use `wlan*` for the STA, edit IPACM configuration, restart IPACM, deauthenticate clients or delete their neighbour entries. Mark `/dev/kmsg` before reading IPA debugfs and never clear the kernel log with `dmesg -c`. See [relay hardware offload](zte-agent/docs/relay-hw-offload.md).
- **Network guard.** Keep changes in the owner's `EffectSet` with undo compatible with the previous slot. Require `U60_*` or `zte-agent*` for legacy ownership and keep at most one matching station MASQUERADE rule. Repair only confirmed absence or mismatch, replace whole owned chains and keep a single hook. D8 maintains only the portal RETURN position. IPv6 addresses, routes and RA stay with the session. See [firewall layout and guard](zte-agent/docs/network-extensions.md#firewall-layout).
- **Portal.** Use a browser User-Agent to reproduce ZTE's kernel HTTP redirect. Keep the portal RETURN ahead of the vendor redirect and preserve the session's kernel redirect setting. See [hotel authentication](zte-agent/docs/network-extensions.md#hotel-authentication).
- **Mihomo firewall.** TPROXY needs `bridge-nf-call-ip(6)tables=0`. B31 lacks `NFT_FIB_INET` and the nft bridge family and rejects chain names `fwd`, `post` and `c`. An nft accept cannot override a legacy DROP. Preserve dual-family batches and the legacy accept-only exceptions. Allow kernel bypass only for traffic the active rules would send DIRECT. See [firewall and rule changes](zte-agent/docs/relay-mihomo-architecture.md#53-拦截表).
- **Mihomo controller.** One thread owns the core and its effects. Routing writes tighten first, write and read back, then reset lost DIRECT software connections, with a LAN IPv4 fallback when the lost scope is unknown or too broad. Every `to_core` ends with a TCP/UDP drop. Enter D3 direct only after confirming core exit and withdrawing interception. See [Mihomo architecture](zte-agent/docs/relay-mihomo-architecture.md#5-mihomo) and [batch 4 keep-alive evidence](zte-agent/docs/archive/2026-11-12-relay-mihomo-implementation.md#batch-4).
