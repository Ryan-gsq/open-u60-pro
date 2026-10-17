# zte-agent power optimization plan (2026-10-17)

Goal: less battery use on the ZTE U60 Pro (MU5250, SDX75, 4x Cortex-A55, OpenWrt, battery powered). Scope: the Rust `zte-agent` daemon, the firmware behaviour it can correct, and what the mobile apps must change. Everything below was measured on the live router on 2026-10-17 (agent SHA `35d3cfda…`, firmware B27) or verified line by line in the working tree by a 79-agent audit (Part B).

Nothing in this document has been applied. Items that change the router are marked **needs approval**.

---

## Part A. Measurements and firmware findings

### A1. What the router is actually doing

| Measurement (live, 2026-10-17 18:50–19:30 PST) | Value |
|---|---|
| Agent CPU at idle, apps closed, 300 s | 240 ms = 0.08 % of one core |
| Agent child processes at idle (kernel fork trace) | 0 |
| Agent timer wakeups at idle | 13.2 /s (STK socket reader 10.0, SMS-forward connectivity monitor 2.0, speed sampler 1.0, Live Activity recovery 0.07, scheduler 0.03) |
| Agent CPU since restart (8.5 h) | self 51 s, children 24 s, HTTP workers 24 s of that |
| **System-wide forks at idle** | **265 /s** (79,256 in 300 s), 5,600 context switches/s, 34 % sys CPU |
| Threads parked on dead HTTP keep-alive connections | 12 (13 ESTABLISHED sockets from one phone, 192.168.0.240) |
| Share of wall time the SoC spends suspended | ~80 % (kernel monotonic 41,633 s vs `/proc/uptime` 203,076 s) |

The last row matters for priorities: the firmware's auto-sleep already turns the SoC off most of the day. What drains the battery is what runs **while it is awake** (Wi‑Fi clients connected, app open, modem searching). In that state the agent is a rounding error next to the firmware's own loops.

### A2. Per-request cost of the endpoints the apps poll

12 requests per endpoint from this Mac at 1/s, kernel fork trace on, 2026-10-17 19:05 PST. "Own" is agent CPU per request (includes ~1.7 ms of HTTP handling), "child" is CPU of the processes it spawned.

| Endpoint | Spawns / request | Own ms | Child ms | Note |
|---|---|---|---|---|
| `/api/wifi/status` | **27** (22 `uci`, 2 `iw`, 2 `sh`, 1 `ubus`) | 11.7 | 62.5 | worst endpoint; Android dashboard polls it every tick |
| `/api/data-usage` | **15** (`uci` ×15) | 7.5 | 28.3 | |
| `/api/network/clients` | 2 (`ubus` ×2) | 3.3 | 4.2 | Android calls it twice per tick |
| `/api/network/signal` | 1 `ubus` (+0.17 `uci` from the 10 s bearer cache) | 2.5 | 4.2 | |
| `/api/network/wan` | 1 `ubus` | 2.5 | 2.5 | |
| `/api/device/battery-info` | 1 `ubus` | 1.7 | 3.3 | |
| `/api/modem/status` | 1 `uci` | 1.7 | 1.7 | |
| `/api/system/top` | 0 | **33** | 0 | reads every `/proc/<pid>/stat` + `cmdline` |
| `/api/device/thermal` | 0 | 10.8 | 0 | re-enumerates ~40 thermal zones |
| `/api/network/traffic` | 0 | 3.3 | 0 | |
| `/api/device`, `/api/battery`, `/api/cpu`, `/api/memory`, `/api/network/speed`, `/api/tailscale/status`, `/api/live-activity` | 0 | 1.7–2.5 | 0 | already free |

Raw captures: `/tmp/u60-perf/{idle,ep-*}` on this Mac (not in the repo). Scripts to reproduce: `scripts/power/`.

### A3. Firmware finding 1: `zte_post_wifi.sh` spins forever when the 2.4 GHz radio is off (265 forks/s)

**What:** two copies of `/sbin/zte_post_wifi.sh` (PIDs 26342 and 5643 at the time of writing) are stuck in `check_and_start_hostapd_cli()` (script lines 171–249). The loop has no `sleep`; each iteration runs `cat`, `awk`, `ps`, `grep`, `uci show`, `uci get` ×3 per interface… That is the 265 forks/s and the 34 % system CPU seen in `top`, and it continues until the next reboot or Wi‑Fi reload. In the 5-minute idle capture the firmware executed `grep` 22,291 times, `uci` 21,239, `awk` 7,092, `ps` 6,222, `hostapd_cli` 4,108.

**Why:** before the loop the script counts enabled SSIDs: `hostapd_cnt=$(uci show wireless | grep -cE "main.*.disabled.*0|guest.*.disabled.*0")` → 2 on this router (`main_2g.disabled=0`, `main_5g.disabled=0`). Inside the loop it counts running `hostapd_cli … wps-hostapd` processes → 1 (only `wlan2`, 5 GHz). The 2.4 GHz SSID never starts because the *radio* is off (`wifi0.disabled=1`), so `2 == 1` never becomes true. The script is launched by `/lib/wifi/zteqcawifi.sh`, `/sbin/zte_wlan_func.sh` and `/usr/bin/zte_topsw_wlan` on every Wi‑Fi (re)configuration, so each change spawns one more stuck copy.

**Who creates the state:** our own app. `wifi.rs:180` maps the app's `radio2_disabled` to `wireless.wifi0.disabled` only and leaves `main_2g.disabled=0`. The stock UI keeps radio and SSID flags consistent; the agent does not.

**Full fix (three parts). Part 1 was tried live on 2026-10-17 and the SSID-flag variant does NOT work on this firmware, see below.**

1. **Router repair, one time (done 2026-10-17 ~20:00 PST).** Killing the two stuck copies and reloading Wi‑Fi cleared the spin (303 → 15 forks/s, system CPU 34 % → 4 %). The first reload failed inside the firmware (`QCMAP: zte EnableWLAN failed!`) and left Wi‑Fi off for about six minutes until `wireless.zte_mbb.wifi_onoff=1` plus another reload brought it back; the reload is flaky, expect one retry. **Do not set `main_2g.disabled=1` to make the counts match:** with the 2.4 GHz SSID disabled the driver creates only `wlan0`, the 5 GHz AP (configured on `wlan2`) never starts and the firmware gives up after 50 s. The firmware's own "Wi‑Fi on" path also re-enables every radio (`wifi0.disabled` went back to 0), so after the repair both radios were up. Turning 2.4 GHz off again (the app path, `wifi0.disabled=1` + reload) re-creates the stuck script, which the watchdog in part 3 kills about 150 s later.
2. **Agent change, `wifi.rs` (done in the working tree):** one `uci show wireless` per request instead of 22 `uci get`, `iw <iface> station dump` without the `sh|grep` pipeline, the master switch written to `wireless.zte_mbb.wifi_onoff` (the key this firmware uses; the old `zte_mbb.wifi.*` path silently did nothing), the reload spawned directly with a reaper thread instead of `sh -c '… &'`, and the watchdog armed after every reload. The radio/SSID-flag coupling originally planned here is dropped for the reason in part 1.
3. **Watchdog in the agent, `system.rs` (done in the working tree):** `kill_stuck_post_wifi(120)` scans `/proc` for exactly `sh /sbin/zte_post_wifi.sh` older than 120 s and sends SIGTERM; armed once 150 s after agent start and 150 s after every reload the agent triggers. No periodic timer. Killing is safe: the steps after the loop (`handle_macfilter_at_post`, `zte_post_txpower`, mesh) are re-run by the next reload and were being skipped anyway.

Expected saving: ~265 forks/s and roughly a third of one core, whenever Wi‑Fi has been reconfigured with 2.4 GHz off. This is the single largest battery item in this document.

### A4. Firmware finding 2: out-of-service "abnormal protection" restarts the modem every ~100 s

**What:** when the modem has no PS service, `zte_topsw_nwinfo` (feature `zte_wan_nw_abnormal_protection`, strings verified in the binary) cycles the modem to LPM and back online (`set_operate_mode=4`, then `=1` five seconds later), and escalates to full modem restarts. Each cycle re-initialises the modem: SIM not ready → SIM ready → `sim_changed` → fresh PLMN scan ("5g domain 0, rmcc 0, rmnc 0"). Captured this morning while the router sat in `Only_5G` with no 5G SA available: **16 restarts in 25 minutes, one every 100 s** (key.log 02:19–02:44, log clock), ending only when the mode was switched to `LTE_AND_5G`. On a two-hour flight with the device awake that is ~70 restarts, each a maximum-power scan.

**Tunables (UCI, `zte_nwinfo.sys_info`):** `ps_no_srv_check_timer_cfg='5'` (observed cycle 100 s, so the unit is probably 20 s ticks), `abs_lpm_online_max_times_cfg='3'`, `abs_restart_max_times_cfg='3'`, counters persisted in NV (`abs_protection_restart_count`, `set_online_times` = 306 so far). The max-times caps clearly do not stop the loop as observed (16 > 3), so the counter is being reset, probably by the SIM events each cycle produces.

**Plan:**

- **Experiment E1 — needs approval, ~15 min without service.** With data on, set `net_select=Only_5G` to force the no-service state (reproducible, as this morning), then set `ps_no_srv_check_timer_cfg=60`, `abs_lpm_online_max_times_cfg=0`, `abs_restart_max_times_cfg=0` and count `set_operate_mode` lines in `/logfs/key.log` over 10 min; then revert all four keys. If the count drops to 0–1 the knobs work and the agent can own them.
- **Agent feature "no-service power policy"** (new module `oos_policy.rs`, event driven, no timer while service is present): subscribe to `zwrt_servicestatus` (already consumed by `sms_forward`). On `NO_SERVICE`/`LIMITED_SERVICE` for longer than `oos_grace_min` (default 10): set the firmware knobs to the quiet values from E1, put the modem in LPM (`zte_nwinfo_api nwinfo_set_mode LPM`), and re-probe by going ONLINE (the existing `modem_online`, `AT+CFUN=1`) for `probe_window_min` (3) every `probe_every_min` (20, doubling to 60). On any service event, stay online and restore the knobs. `GET/PUT /api/modem/oos-policy` with `{enabled, grace_min, probe_every_min}`; persisted in `/data/local/tmp/oos_policy.json`; off by default until E1 confirms the knobs. Log every transition. The policy must never run while a voice call or USSD session is active (`telephony` state) and must leave LPM immediately on `PUT /api/modem/airplane ONLINE`.

### A5. Firmware finding 3: "connected but no internet" after a long no-service period

**What the owner saw** (about four months ago, outside the retained logs): after a 2+ hour flight the modem registered and got an IP but passed no traffic. A warm reboot with fast boot on did not help; turning fast boot off and rebooting (which resets the modem subsystem) fixed it. So the modem/data path was wedged below the PDN level, and only a modem reset cleared it.

**What the logs show for the same class of event today:** the firmware's own data-stall monitor fires (`ZTE_DATA_DST_DATASTALL_MONITOR_EVENT`, `[DATA] no ul pkts NOTIFY … ulpkts=0, dlpkts=0`) and reconnects the PDN (`ABNORMAL DISCONNECTED end_type=3` → `CONNECTED`), which is the only remedy it has. The agent's Live Activity recovery thread already detects the failure mode independently: WAN reports connected while its HTTPS probe to Apple fails.

**Agent feature "connectivity watchdog"** (new module `conn_watchdog.rs`, reuses the recovery probe from Part B Phase 1 #4 as the signal; no new timer):

| Rung | Trigger | Action | Cooldown |
|---|---|---|---|
| 1 | WAN `*_connected` and 3 consecutive probe failures (≥ 10 min) | PDN reconnect: `ubus call zwrt_data set_wwaniface {"cid":1,"enable":0}` then `enable:1` | 10 min |
| 2 | rung 1 did not restore the probe within 5 min | LPM → ONLINE (`nwinfo_set_mode LPM`, then `AT+CFUN=1` via `modem_online`) | 20 min |
| 3 | rung 2 failed | Modem reset `AT+CFUN=1,1` on `/dev/at_mdm0` (the AT path exists and the agent runs as root; validate once by hand) | 1 h, max 3/day |
| 4 (opt-in) | rung 3 failed | `quicken_power_on=0`, `system reboot`, restore `quicken_power_on=1` after boot (state file in `/data`) | 1/day |

Each step is logged and pushed to the Live Activity if one is registered. `GET/PUT /api/modem/conn-watchdog {enabled, allow_reboot}`; rungs 1–3 on by default once validated, rung 4 off. Never acts while a call/USSD is active, while a speed test runs, or within 2 min of a user-initiated modem change.

### A6. Smaller device-level items

- **Stale keep-alive threads:** tiny_http spawns one thread per client connection and never times it out; phones that leave without closing pin a thread and two fds forever (12 today). Fix is Part B hygiene `server.rs:25-31` (bind the listener yourself, set `SO_KEEPALIVE`, `TCP_KEEPIDLE=300`, `TCP_KEEPINTVL=60`, `TCP_KEEPCNT=3`; accepted sockets inherit it). Memory and fd hygiene, not battery.
- **Clock repairs:** 49 `corrected modem UTC` repairs in 8.7 h; the firmware steps the clock from the network, the agent steps it back. Cheap (a `clock_settime`, no process), but each step invalidates agent tokens and can shift scheduler minutes. Part B lists the `timerfd` design that removes the 15 s wake without changing repair latency. Also note for anyone reading `key.log`: different firmware daemons write it in UTC and in local time, so consecutive lines jump ±8 h; only the `4g/5g domain`, `set_operate_mode`, `[DATA]` and `[cutoff]` writers are UTC.
- **Diagnostics the agent could expose cheaply:** `stuck_scripts` (A3), system forks/s (`/proc/stat` `processes` delta, zero cost), modem restarts in the last hour (count of `set_operate_mode=4` in `key.log` tail). These make the two firmware loops visible in the app instead of silent.

### A7. Recommended order

1. **Now, 2 minutes:** A3 step 1 (router repair). Largest saving, no code.
2. **Deploy "power-1"** (agent, no behaviour change): Part B Phase 1 #1 (SMS monitor), #2 (speed sampler), #6 (`wifi/status` 27 → 7 processes), #11 (thread names), plus A3 steps 2–3 (band consistency + watchdog) and the TCP-keepalive hygiene row. Measure with `scripts/power` before and after.
3. **Deploy "power-2"**: Part B Phase 2 A (STK, −10 wakeups/s after the toolkit has been opened), B (charger cache), C (signal memo), D (slow-endpoint caches), G (scheduler), plus A4 (no-service policy, after E1) and A5 (connectivity watchdog rungs 1–3).
4. **Apps (hand to the UI implementer):** Part B Phase 3, above all the Android tiering and lifecycle gate (600–750 processes/min today while the dashboard is open, and it keeps polling in the background).
5. **Follow-on design items:** in-process ubus client, `timerfd` clock watcher, Live Activity probe cadence (#4).

### A8. Results of the first deployment ("power-1", 2026-10-17 ~20:50 PST)

Deployed binary SHA `95ff6fe3…` (4.2 MB), backup `/data/zte-agent.bak-power-1` (the pre-deploy `35d3cfda…`). Contents: Part B Phase 1 #1–#11, Phase 2 A–E and G, the hygiene rows for the event bus, TCP keepalive, the Cargo profile, plus A3 parts 2–3, A4 and A5 (both policies wired but disabled by default). Not included: Phase 2 F (dashboard endpoint), Phase 2 H (AT direct I/O), Phase 3 (apps).

| Measurement (3 min idle, apps closed) | Before | After |
|---|---|---|
| Agent timer wakeups | 13.2 /s | 0.07 /s |
| Agent CPU | 0.08 % of a core | ~0.02 % |
| Agent child processes | 0 | 0 |
| Threads parked on dead keep-alive sockets | 12 | 0 |
| `stk-ril` after opening SIM Toolkit | 10 wakeups/s forever | 0 (parked in `poll()`) |
| System-wide forks | 265 /s (stuck Wi‑Fi script) | 29 /s |

End-to-end check of A3: 2.4 GHz turned off through `PUT /api/wifi/settings {"radio2_disabled":"1"}`; the 5 GHz AP stayed up throughout; the firmware script got stuck as predicted and the watchdog killed it at 138 s (`[wifi] killed stuck zte_post_wifi.sh pid 5577`). All changed endpoints return their previous JSON shapes with a token. `ubus listen` now runs with an explicit 7-event filter and dies with the agent (two orphans from earlier restarts were cleaned up at deploy).

**"power-2" (2026-10-17 ~22:15 PST, SHA `6168708e…`, backup `/data/zte-agent.bak-power-2`):** after power-1 the router woke from sleep, the firmware restarted Wi‑Fi (`zte_wlan_deal_device_power_status_event: recv mode_power_on, start wifi`) and a new copy of `zte_post_wifi.sh` stuck (254 forks/s again). The one-shot watchdog only covered boot and the agent's own reloads, so power-2 adds (a) a periodic sweep every 5 min (`system::start_post_wifi_watchdog`, first pass at 150 s; one wakeup per 300 s) and (b) a subscription to the `zwrt_device_power_state_event` ubus event that arms the 150 s one-shot on every `mode_power_on`. Also included: `call_answer` now sets the call-active flag. Note: the previous instance's `ubus listen` child still had to be reaped by the deploy script despite `PR_SET_PDEATHSIG`; harmless (the script handles it) but worth a look if orphans reappear.

**"power-3" (2026-10-17 ~23:00 PST, SHA `8fe742d1…`, backup `/data/zte-agent.bak-power-3`):** the adversarial review of the merged diff (20 agents) found no blockers, 4 majors and 10 minors (3 claims refuted); all 14 were fixed in isolated copies, each patch re-reviewed, 180 unit tests now pass. Majors: the AT port had no cross-thread lock and the call guard treated an empty `AT+CLCC` reply as "no call" (fixed: process-wide AT lock, guard and `call_status` fail closed on anything but a terminal `OK`); the connectivity watchdog's rung 2 could leave the modem in LPM after one failed `AT+CFUN=1` (fixed: 3 attempts, mode verified via UCI, `nwinfo_set_mode ONLINE` fallback, logged); the no-service policy's restart recovery restored the UCI knobs but left a parked modem in LPM (fixed: brings it online). Minors: knob backup write failure no longer quiets the knobs; charger re-seed keeps the previous state on a ubus failure and backs off to 1 h on battery; cache invalidation no longer waits behind an in-flight fork (generation counter); thread-spawn failure on the Wi‑Fi path logs instead of panicking a worker; a failed `uci show wireless` now returns 503 instead of an empty config; `uci show` list values keep their raw form; the Live Activity recovery wait is capped at 15 s only while an activity is registered (300 s otherwise); the connectivity watchdog reports `probe_source` and warns when enabled without one; fast-boot restore after a rung-4 reboot is retried every 60 s until it succeeds.

**Live Activity on (2026-10-17 ~23:15 PST, power-3, app closed, 300 s):** agent 102 ms own + 82 ms reaped children = ~0.06 % of one core, 0.8 wakeups/s (`la-push` 0.33/s, reqwest runtime 0.25/s), exactly one `ubus` netinfo fork per 15 s push, and one APNs TLS connection reused for the whole session. The agent does not show up in `top`; the busiest processes are `zte_topsw_data` and `zte_topsw_devui` at ~2 % each. The router had not suspended since USB was plugged in 4.6 h earlier (ZTE's sleep policy holds `sysZteSleepLock` while clients/USB are attached), so the remaining cost of Live Activity is the cellular radio sending a packet every 15 s, not CPU. Measurement fix: the fork trace used `parent_comm == "zte-agent"`, which misses the threads named in power-1 (`la-push`, `http-N`); `router-measure.sh` now records TGIDs and `analyze.py` filters on the agent PID. The earlier idle captures are unaffected (0 ms reaped-children CPU).

Still open after this deploy: experiment E1 (needs the owner to run `/tmp/e1.sh` on the router; the policy in A4 stays disabled until then), the SIM Toolkit menu check with a SIM that actually serves a menu (the GOMO SIM answers "menu_unavailable", the same as before), and Phase 3.

---

## Part B. Agent code audit (79 agents: 6 finders, 71 of 72 findings confirmed by independent verifiers, 1 synthesizer; line numbers verified against the working tree on 2026-10-17)

> Note on Part B §1: the audit assumed SIM Toolkit had never been opened. On this router the STK session has been open since the morning test, which is why the live idle figure is 13.2 wakeups/s rather than 3.1; Phase 2 A removes the difference. Per-request process counts in Part B (e.g. 31 for `wifi/status`) include grandchildren of `sh` pipelines; Part A counts kernel forks (27). Both agree on the ranking.

### Audit summary

Scope: `zte-agent/src` (line numbers re-verified with `grep -n` on 2026-10-17 against the working tree, which is what the router runs). Target: ZTE U60 Pro, SDX75 aarch64 musl, 4x Cortex-A55 (`CPU part 0xd05`), agent pid runs 34-35 threads.

**Does the router need to be online for this?** Not for the code changes; every finding below was verified from source. Keep it reachable on the LAN (`ssh root@192.168.0.1 -p 2222`) for the before/after measurements and deploys in section 3, and run each before/after pair in the same WAN state (SIM in, data connected): WAN-down changes the Live Activity probe retry cadence (`live_activity_recovery.rs:175`) and the Tailscale supervisor path, which would skew the comparison.

### 1. Where the CPU goes

At idle with the deployed config (password set, Live Activity configured, DoH/Tailscale/charge-limit/SMS-forward off, SIM Toolkit never opened) the agent's measured CPU is negligible (52.7 s over 204,110 s uptime, 0.026 % of one core) but it fires about **3.1 timer wakeups/s**, which is what keeps the SoC out of deep idle: 2.0/s from `sms_forward.rs:655` (`connectivity_monitor` spinning `try_recv` + `sleep(500ms)` on two channels, unconditional from boot), 1.0/s from `system.rs:318` (SpeedTracker sampler reading 4 sysfs counters nobody consumes), 0.067/s from `live_activity_recovery.rs:133` (15 s wait cap), 0.033/s from `scheduler.rs:185` (30 s tick with zero jobs), ~0.022/s from two hyper-util pool reapers, 0.003/s each from `charge_policy.rs:143` and `sms_forward.rs:681`, plus ~0.05 data-driven `ubus listen` events/s (measured). The only idle WAN traffic is one cold DNS+TCP+TLS probe to www.apple.com every 300 s (`live_activity_recovery.rs:166`) trailed by kernel keepalives for up to 180 s, i.e. ~12 radio wakes/h. Opt-in features add: DoH +2/s (`doh/mod.rs:49,172`), Tailscale +1/s and two Go `tailscale status` forks/min (`tailscale/mod.rs:424,612`; +0.5/s forever after a runtime disable, `:230`), a single visit to SIM Toolkit +10/s for the rest of the process lifetime (`stk/mod.rs:139,428,455`), charge limit enabled on battery +1 ubus fork/min (`charge_policy.rs:103,199`). While a phone dashboard is open the cost moves to fork+exec: iOS ≈ 190 child processes/min (`/api/network/speeds` 60, `/api/network/signal` 30, charger 36, `/api/wifi/status` ~26, clients 12, battery-info 6, slow tier ~6), Android ≈ 41 agent forks + ~4 grandchildren per tick at 13-17 ticks/min ≈ **600-750 processes/min**, 26 of them from `/api/wifi/status` alone (`wifi.rs:80-149`), and Android keeps polling in the background because its ViewModel has no lifecycle gate. Measured per-fork CPU on this SoC is lower than the brief's 5-30 ms assumption for BusyBox applets (`uci get` ≈ 2.6 ms, `ubus call zwrt_bsp.charger list` ≈ 7.8 ms, whole `/api/wifi/status` ≈ 75 ms), so the dashboard load is roughly 2 % (iOS) to 5 % (Android) of one core; the Go CLI forks are unmeasured and likely 30-150 ms each. The two top idle fixes (Phase 1 #1 and #2) remove 97 % of idle wakeups; the per-request work is dominated by `ubus.rs:7` forking the `ubus` CLI on every call, which only caching and (eventually) an in-process ubus client can address.

### 2. Ranked changes

Value = battery value in the deployed configuration. "Saving" is steady-state. Every Phase 1/2 item keeps user-visible behaviour identical unless stated.

#### Phase 1 — free wins, no behaviour change

| # | File:line | Change | Saving | Risk / test |
|---|---|---|---|---|
| 1 | `sms_forward.rs:603-606, 614-658` | Delete `connectivity_monitor`; spawn two threads `service_monitor(rx)` / `wan_monitor(rx)` each doing `for event in rx.iter()` with the exact bodies of lines 620-626 / 638-644 (same `Ordering::Relaxed` swaps, same log lines). Keep `start()` signature, seed loop 566-601, and `main.rs:69` unchanged. Same pattern as `tailscale/mod.rs:174`, `live_activity_recovery.rs:92`. | **-2.0 wakeups/s, always.** The agent's dominant idle timer. | Nil: flags update sooner, not later. Test: `grep -c` the two `[sms_forward] ... state changed` lines in `/tmp/zte-agent.log` across a SIM pull/replug; per-thread wake rate for the two new threads must read 0 at idle (section 3). |
| 2 | `system.rs:296-346` | Demand-driven SpeedTracker: `SpeedInner { ring, latest, last_request: Mutex<Option<Instant>>, wake: Condvar }`, `const SPEED_LINGER = 20 s` (≥ `SPEED_RING_SIZE`). `sample()` sets `last_request`, and on idle→active does one synchronous `read_rmnet_bytes()`, clears/reseeds the ring, resets `latest` to zero speeds, `notify_one()`. Sampler loop: `wake.wait_while(lr, |t| t.map_or(true, |t| t.elapsed() > SPEED_LINGER))` then the existing 1 s body. Drop the seed read in `new()` (306-312). | **-1.0 wakeups/s, always.** | First `/api/network/speed` after >20 s idle returns speeds 0 for one tick (identical to the first second after boot today). Only iOS on its `.agentSpeed` fallback tier can see it; Android discards this endpoint. Test: curl the endpoint 1/s for 20 s and check `rx_speed` ramps as before; sampler thread wake rate 0 at idle, 1/s while polled. |
| 3 | `doh/mod.rs:16-24, 48-50, 60-66, 170-176` | Remove `set_read_timeout(500ms)`; store `socket.local_addr()` in a new `bound_addr: Mutex<Option<SocketAddr>>` after bind. In `stop()`: store `running=false`, take the handle, then loop ≤50x `{ if h.is_finished() break; send 1 byte from a throwaway `UdpSocket::bind("127.0.0.1:0")` to bound_addr (0.0.0.0/:: rewritten to loopback); sleep 20 ms }`, then `join`. The datagram fails `is_valid_query` (len<12) → `continue` → `running` check → break. Collapse the `WouldBlock` arm to `Err(_) => continue`. Use the bound address, not `config.listen_addr` (patchable at runtime). | -2 wakeups/s while DoH enabled. | `/api/doh/disable` returns faster; disable→enable re-bind still works because stop() still joins. Test: toggle DoH on/off 5x from iOS, `dig @127.0.0.1 -p 5353 example.com` works while on, no EADDRINUSE in the log. |
| 4 | `live_activity_recovery.rs:115-122, 166, 175` | (a) Idle-aware probe cadence: `PROBE_INTERVAL_ACTIVE = 300 s`, `PROBE_INTERVAL_IDLE = 3600 s`; keep `last_ok: Option<Instant>`; after the revision branch re-derive `next_probe = last_ok + (if registered {ACTIVE} else {IDLE})` where `registered` is the same expression as `status()` at `live_activity.rs:188`; set `last_ok=None` on revision change and on Err. Registration already `notify_all`s, so a new activity pulls the next probe in to ≤300 s. (b) Offline backoff at :175: `probe_retry_delay(failures) = (30 << failures.min(4)).min(300)`, reset `failures` on success and on revision change. Keep the 3 s event probe (:121) and the 15 s drift cap (:133) exactly as they are. Add `.pool_max_idle_per_host(0)` to the probe client builder (:105-111) so no socket lingers with 15 s keepalives and no 90 s reaper task is spawned. Optional: in `live_activity.rs` `register()` new-token path (after :232) bump `recovery.revision` only `if state.recovery.paused`. | Idle: 12 → 1 cold TLS + radio wake per hour; up to 11 keepalive packets per probe gone; -0.011 wakeups/s reaper. Offline: 120 → ~12 probe attempts/h. | With an activity registered behaviour is byte-identical. Idle-only: `last_time_sync_at` advances hourly; a silent WAN loss is noticed ≤1 h later instead of ≤5 min (nothing consumes that state until an activity exists). Test: `grep -c "network and UTC verified" /tmp/zte-agent.log` over 1 h idle must be ~1; start a Live Activity and confirm a probe within 3 s and pushes every 15 s as before. |
| 5 | `doh/upstream.rs:4-20`, `doh/mod.rs:16, 27-39, 87-95, 202-204` | One `ureq::Agent` per DohProxy (`agent: Mutex<(ureq::Agent, Instant)>` built by `build_agent(timeout_ms)`), cloned (Arc-backed) out of the lock before the call; rebuild on `timeout_ms` change in `update_config`. Because ureq 3.2.0 `Connection::age()` always returns 0 (pool.rs:153-155, verified in the vendored source) `max_idle_age` is dead, so also rebuild the Agent when the stored Instant is >15 s old to bound half-open NAT sockets. Keep `timeout_global` at agent level (request-level config defeats the rustls config cache). | Per DNS cache miss while DoH on: no rustls ClientConfig rebuild, no TLS handshake when the previous query was <15 s ago (-5..20 ms CPU and -2 cellular RTTs per uncached name). | Same per-query timeout semantics. Test: `time dig @127.0.0.1 -p 5353 a.example b.example c.example` back-to-back; second and third should be noticeably faster; SERVFAIL path unchanged by pointing upstream_url at a dead host. |
| 6 | `wifi.rs:12-18, 55-68, 80-149, 282-302` | Replace 22 `uci get` with two `ubus::uci_show("wireless")` / `uci_show("zte_mbb.wifi")` and a local `uci_show_option(show, "wireless.<sec>.<opt>")` (exact prefix + `=`, strip outer `'`, unescape `'\''` → `'`); `zte_mbb` does not exist on this firmware so its Err → "" still triggers the `zwrt_wlan report` fallback at :89. Rewrite `station_count` as `Command::new("iw").args([iface,"station","dump"])` counting lines containing `"Station"` (drops `sh` and `grep`). Optionally skip `iw_info`/`station_count` for a radio whose `disabled=="1"`. Apply the same helper to `guest_status` (8 → 1 fork). **No TTL cache** (see rejected list). | 31 → 7 processes per request (~75 → ~15 ms CPU). Android dashboard: -24 processes/tick ≈ -360/min; iOS -24/min. | Output identical incl. "" for missing keys. Test: diff `curl /api/wifi/status` before/after (expect byte-equal JSON apart from `clients_*` jitter); set an SSID containing `'` via the ZTE web UI and confirm it round-trips. |
| 7 | `tailscale/mod.rs:494-513` | Line 505: `connect_status` is compared to `"connected"` but the device reports `ipv4_ipv6_connected`, so the gate never passes and all 90 forks + 90 s run on every tailscaled spawn even with WAN up. Change to `.is_some_and(\|s\| s == "connected" \|\| s.ends_with("_connected"))` (or reuse `bearer.rs:35` CONNECTED). Then fork `ubus` only on `i < 3 \|\| i % 10 == 0` (11 forks max per 90 s while WAN is down). | Tailscale-enabled only: 90 → 1 fork per spawn with WAN up; tailscaled comes up ~89 s sooner. | Visible only as faster Tailscale availability after boot/enable. Test: `grep` the supervisor log timestamps between "supervise" entry and tailscaled spawn. |
| 8 | `network_ext.rs:27-39` (+ `handlers.rs:13,30` field) | Single-flight cache `clients_cache: Mutex<Option<(Instant, Value)>>` in `AppState`, `CLIENTS_CACHE_TTL = 5 s`, lock held across the two `ubus::call`s, store only when `hints != Null`. Replace `.cloned()` with `get_mut("dhcp_leases").map(Value::take)`. | Android 80 → ~20 forks/min (its duplicate `getJSONArray` call and consecutive ticks hit the cache); iOS unchanged (10 s cadence). | Android client list refreshes every ~6 s instead of ~3 s. No shape change. Test: two back-to-back curls return identical JSON; third after 6 s differs when a device joins. |
| 9 | `network_ext.rs:41-46` | Single-flight cache on `get_wwandst`, `SPEEDS_TTL = 800 ms` (must stay < the 1 s iOS traffic poll), never cache Err. | Only with ≥2 concurrent clients (iOS+Android, second phone): -1 fork/s per extra client. Single client: 0. | None for a 1 Hz client (always a miss). Test: iOS dashboard digit reels animate as before; two curls <800 ms apart return the same `real_rx_speed`. |
| 10 | `charge_policy.rs:103, 198-216` | Seed `charger_connected` from `ubus call zwrt_bsp.charger list` via the existing `charger_connect_value()` (fallback `true`), NOT from sysfs. In `enforce()` read sysfs status/capacity first and only call `is_charging_stopped()` when `(capacity >= limit && !discharging) \|\| capacity <= limit - hysteresis`; keep the decision table verbatim. Optional: `rx.recv_timeout(600 s)` in the disconnected branch with a re-seed on timeout. | Charge-limit-enabled only: on battery 1 fork + 1 wakeup/min → 0; on charger the in-band ticks no longer fork. | No stop/resume decision changes; one extra fork at thread start. Test: enable limit on battery, confirm the thread's wake rate is 0 and `[charge_policy]` log is silent; plug in, confirm stop at limit and resume at limit-hysteresis as today. |
| 11 | all `std::thread::spawn` sites | Name every thread (`std::thread::Builder::new().name("sms-wan")...`); today only `stk-ril` is named, so per-thread measurement shows 30 threads called `zte-agent`. | None; makes section 3 attributable. | Nil. |

#### Phase 2 — structural

| # | File:line | Change | Saving | Risk / test |
|---|---|---|---|---|
| A | `stk/mod.rs:50-77, 139, 381-419, 425-459, 462` | Event-driven STK worker (high value once SIM Toolkit has been opened): create a non-blocking `pipe2(O_CLOEXEC\|O_NONBLOCK)` self-pipe; `request()` writes 1 byte after `try_send`. Split `Session::read()` into `read_socket()` (382-406) and `check_deadlines()` (407-417); add `next_wake() = min(pending deadlines, waiting_since + 30 s)`. In `run()` with a session: drain pipe, drain `rx.try_recv()` loop, then `libc::poll([stream fd, pipe fd], timeout = next_wake or -1)`; on socket readable `read_socket()`, always `check_deadlines()`, `invalidate()` on Err. Keep the socket blocking and the 100 ms `SO_RCVTIMEO` (write_all relies on the 2 s write timeout). No idle teardown. Fallback if the refactor is deferred: invalidate the session after 120 s without any request ("SIM Toolkit session closed after inactivity"), keyed on `last_request`. | -10 wakeups/s for the rest of the process lifetime after the first `/api/stk/menu`. | Request latency drops by up to 100 ms, deadlines fire exactly. Test: open SIM Toolkit, navigate a submenu, leave the screen; `stk-ril` wake rate must be 0 after 30 s; reopen the screen and confirm the cached root menu is served. |
| B | new `charger_cache.rs`; `device_ext.rs:45,86,120`; `charge_policy.rs:44,58`; `usb.rs:29`; `main.rs` | One cached `zwrt_bsp.charger list` Value, single-flight, `TTL = 10 s`, errors never cached. HTTP readers (`device_charger`, `charge_control_get`) read the cache; the enforcer (`is_charging_stopped`) always forks fresh and refreshes the cache. `invalidate()` after every local `set` (device_ext.rs:120 before the trailing `charge_control_get`, charge_policy.rs:58, usb.rs:29) and from the existing `BSP_CHARGER_EVENT` receiver in `charge_policy::event_loop` (:109, :144) plus a new blocking `BSP_POWERBANK_EVENT` subscriber (`while rx.recv().is_ok() { invalidate() }`). | iOS dashboard 36 → ~6 forks/min; Android 40 → ~5/min; idle unchanged (0). | Fields that change with no event and no local set (e.g. `charge_status` → full) can lag ≤10 s; iOS renders them as "discharging" anyway. Hysteresis untouched. Test: plug/unplug while polling `/api/device/charger` at 1 Hz, transition visible on the next poll; `PUT /api/device/charge-control` response reflects the write. |
| C | new `nwinfo.rs`; `handlers.rs:110`; `live_activity.rs:353`; `sms_forward.rs:568` | `netinfo(max_age)` single-flight memo of `nwinfo_get_netinfo`, `NETINFO_TTL = 500 ms` (not 1 s: the iOS slider floor is 1.0 s). Handler uses the TTL; the Live Activity pusher calls `netinfo(Duration::ZERO)` (always fresh, keeps `sampledAt` honest, still populates the cache). Only `Ok` objects are cached. | Only overlapping callers: Android Dashboard+Signal (~-20/min), two phones (~-15/min), app+Live Activity (≤-4/min). Single poller: 0. | None observable. Test: two curls 200 ms apart return identical JSON; 1 s apart differ. |
| D | `device_ext.rs:51-56`; new `UbusCache` in `handlers.rs:13-27`; `network_ext.rs:6-18, 55-60`; `modem_ext.rs:6-48`; `sim.rs:6-11`; `handlers.rs:134-139, 176-183`; `main.rs` before `:63` | (1) `/api/device/system`: synthesize from `/proc` (uptime, loadavg×65536 as integers, meminfo in bytes incl. shared/buffered/cached, swap) in the exact OpenWrt `system info` shape → 0 forks. (2) Per-key single-flight `UbusCache { entries: Mutex<HashMap<&'static str, Arc<Mutex<Slot>>>> }` with `get_or_fetch(key, ttl, fetch)`, `invalidate(key)`, `invalidate_with_settle(key, 20 s)` (effective TTL 1 s inside the settle window), never caching Err. Apply: wan/wan6 30 s, invalidated by `router_event_wan_connect_status` and `network.interface` for `zte_wan`/`zte_wan6` (subscribe before `event_bus.start()`); battery-info 10 s, invalidated on a second `BSP_CHARGER_EVENT` subscription; modem/data 30 s + settle after `modem_data_set`, `modem_airplane`, `modem_network_mode_set`, `modem_online` and on the WAN events; sim/info 30 s, invalidated on `zwrt_card_state_event` + settle after PIN ops. (3) `/api/modem/status`: no cache; read `/etc/config/zte_nwinfo` section `sys_info` option `operate_mode` and apply `/tmp/.uci/zte_nwinfo` delta lines, falling back to `uci get` on any miss (the daemon writes this key asynchronously after toggles, so a TTL would pin stale state). (4) Leave `usb/status` uncached. | Android slow-changing endpoints ~120 → ~20 forks/min; iOS ~18 → ~17/min. | iOS none. Android: wan/wan6/battery-info/sim up to 30/10/30 s stale except within 20 s after a write or on an event; all post-write 2 s confirmation loops in both apps keep working. Test: toggle mobile data from Android and from the router touchscreen; the app reflects both within its normal 2-3 s; `curl /api/device/system` fields match `ubus call system info`. |
| E | `tailscale/mod.rs:39-62, 136-153, 225-236, 330-427, 612, 717, 748, 764, 790, 1231-1289` | (1) Add `wake_lock: Mutex<()>` + `wake_cv: Condvar`; `wake_supervisor()` takes the lock before `notify_all`. Idle park at :228-231 → `wait_timeout_while(60 s, \|_\| !running \|\| paused)` (keep `supervisor_idle=true` before the wait); notify after every `running.store(true)` (164, 717, 748) and every `paused.store(false)` (1231, 1259, 1267, 1282, 1289). (2) Monitor slice loop :415-426 → deadline loop with `wait_timeout(min(remaining, CHILD_POLL_SECS = 5))` checking `running`/`paused`/`child.try_wait()`; notify from `do_disable`, `quiesce_supervisor`, and `kill_child`; do NOT `continue` to the loop top on a wake (keeps the 30 s status cadence and `bad_cycles` ladder). (3) `localapi_status()` over `UnixStream::connect(SOCK)`: `GET /localapi/v0/status?peers=false HTTP/1.0\r\nHost: local-tailscaled.sock\r\n\r\n`, read to EOF, require `200`, `serde_json::from_slice` after the first blank line; same `ipnstate.Status` JSON the CLI prints, so `build_status` mapping is unchanged. Use it at :612 (and optionally for the 1 s readiness probes at :500/:721/:1270). Keep `cli()` for up/set/down/logout. Validate on-device first with `curl --unix-socket /tmp/tailscale/tailscaled.sock`. | Tailscale-enabled: 1 → 0.2 wakeups/s, 2 Go forks + 2 waiter threads/min → 0; after disable 0.5 → 0.017 wakeups/s. | External tailscaled death noticed ≤5 s instead of ≤1 s (masked by the 5 s respawn backoff). Note `hold_wakelock` defaults true (`config.rs:17-18`), so while Tailscale is on the agent holds a system wakelock by design; that policy, not these timers, is the real Tailscale battery cost. Test: `/api/tailscale/status` JSON identical before/after; `POST /disable` quiesces within 2 s; `kill -9 $(pidof tailscaled)` respawns within ~10 s. |
| F | new `GET /api/dashboard` in `server.rs` `route()` | One response assembling signal (C), battery (sysfs), charger (B), thermal, cpu, speed/speeds (9) from the caches. Additive, zero risk, zero gain until Phase 3 adopts it. | Android tick: 19 HTTP requests → 1 + a few slow-tier calls once adopted. | Test: schema equals the union of the individual endpoints. |
| G | `scheduler.rs:72-74, 176-189, 372, 409, 431, 457` | Add `changed: Condvar`; keep the initial 30 s sleep (boot grace for past-due Once jobs); loop: park with `changed.wait` while no job is enabled; otherwise sleep `(61 - now%60).clamp(1,61)` s (wake ~1 s after each minute boundary) then `tick()`. `notify_all` after `save()` in create/update/toggle/delete. Do NOT sleep until the next due HH:MM (clock steps would skip firings). | -0.033 wakeups/s with no jobs (the default); 0.017/s with jobs. | Jobs fire ~1 s after the minute instead of within 0-30 s. Test: create a job 2 minutes ahead, confirm it fires in that minute. |
| H | `at_cmd.rs:23-67`; `telephony.rs:242,302,337`; `at_terminal.rs:44` | Direct I/O on the AT node (it is a Qualcomm `glinkpkt` packet device, not a tty: no `cfmakeraw`/`tcsetattr`): `OpenOptions` read+write `O_NOCTTY`, drain pending packets, single `write("{cmd}\r\n")`, `libc::poll`+`read` until a complete final result line (`OK`, `ERROR`, `+CME/+CMS ERROR`, `NO CARRIER`, ...) or the existing timeout; add `Wait::Urc("+CUSD:")` for `ussd_send`/`ussd_respond` (they rely on a URC after OK), `Wait::FullWindow` for the AT terminal; one `static` mutex serialises the port; keep the shell script as fallback if open fails. | Only during voice calls/USSD/AT terminal: 55 spawns/min → 0 during a call, 2.3 s → ~0.1 s latency; low battery value, high UX value. | Call-status polls ~2x more often (afterCompletion schedule) but spawn nothing; USSD returns as soon as `+CUSD:` arrives. Test: dial, poll `/api/call/status`, send a USSD menu code, run `AT+CGMI` in the terminal. |

#### Phase 3 — needs the mobile apps to change (read-only here; hand to the app owners)

| # | App / file | Change | Saving |
|---|---|---|---|
| 1 | Android `feature/dashboard/DashboardViewModel.kt:85-128` | Tier `fetchAll()` like iOS (`DashboardViewModel.swift:70-71`): fast = signal + health; medium 10 s = clients, battery-info; slow 60 s = wan, wan6, wifi/status, device/system, sim/info, modem/status, modem/data. Gate polling on `repeatOnLifecycle(STARTED)` / ON_STOP so it stops in the background and on other tabs. | Android dashboard 41 → ~8 agent forks per 3 s tick; 0 when backgrounded (today it never stops until the OS kills the process). |
| 2 | Android `DashboardViewModel.kt:259-267`, `AgentClient.kt:61-72` | Drop the second `getJSONArray("/api/network/clients")` (always empty: payload is an object) and read `data["hosts"]`/`data["dhcp_leases"]` from the first response; same for `ClientsViewModel.kt:44` (`/api/network/dhcp-leases` is not a route). Fixes the currently non-functional Android client list. | -2 forks/tick. |
| 3 | Android `DashboardViewModel.kt:194-258` | Lead `fetchTraffic()` with `/api/network/speeds` (tiers 1-2 can never succeed: agent emits `rx_speed`, and `/api/network/traffic` is an array that `unwrapResponse` turns into an empty map). | -2 HTTP requests/tick, no spawn change. |
| 4 | Android `DeviceModels.kt:329-330`, `DNSSettingsViewModel.kt:116/135`, `LANSettingsViewModel.kt:41/63`, `GuestWiFiSettingsViewModel.kt:60-69` | Field/route mismatches found while auditing: `main2g_ssid` vs agent `ssid_2g`; `POST/DELETE /api/doh` vs `/api/doh/enable|disable`; `/api/network/lan` (no route); guest keys sent without the `guest_` prefix (only `guest_active_time` is applied). Not CPU, but each wasted request still forks. | Correctness. |
| 5 | Both apps | Adopt `GET /api/dashboard` (Phase 2 F) for the fast tier. | Android 19 → ~2 HTTP requests/tick; iOS health tier 4 → 1. |
| 6 | iOS `DashboardViewModel.swift:237-243` | Replace `/api/device/system` with `/api/device` + `/api/memory` (0 forks) if Phase 2 D(1) is not done. | -1 fork/min. |
| 7 | Config only (no app change): `live-activity` JSON | `interval_seconds: 30, stale_after_seconds: 60` halves pushes, ubus forks and timer wakeups during a Live Activity session; the opt-in `skip_unchanged` content compare saves less and needs stale ≥ 2x interval. | 4 → 2 forks/min + 2 fewer APNs POST/min while a session runs. |
| 8 | Poll intervals | Optional, visible: Android default `poll_interval` 3 → 5 s; iOS leaves its 2 s default (the 1 s `/api/network/speeds` poll is the single biggest iOS fork source and is intentional for the digit-reel animation). | Proportional. |

#### Low-value hygiene (safe; bundle when the file is touched, do not deploy on their own)

| File:line | Change | Why low |
|---|---|---|
| `event_bus.rs:111-118, 45-49` | `spawn_ubus_listen(&names)` passing the sorted/deduped subscriber names to `ubus listen` (verified on-device: exact match, multi-pattern OK; never pass ""); add `pre_exec(prctl(PR_SET_PDEATHSIG, SIGTERM))` so the child dies with the agent (an orphan from a previous `killall` is alive on the router now). | Idle ubus rate is 0.05 events/s; saves ~0.03 wakeups/s. The orphan fix is the real reason. |
| `live_activity.rs:267-271, 291-296` | `wait_timeout(30 s)` → `wait()` (utc-None branch) and `wait_timeout(until expiry)` (paused branch); both transitions already `notify_all`. | 2 wakeups/min only while waiting for time/network. |
| `live_activity.rs:323-330` | `.tcp_keepalive(None).tcp_keepalive_interval(None).tcp_keepalive_retries(None)` on the APNs client (all three; otherwise SO_KEEPALIVE stays on). Leave `pool_idle_timeout` default. | Only after a session ends. |
| `live_activity_recovery.rs:105-114, 181` | Replace the second `reqwest::blocking::Client` with a ureq Agent (`https_only`, `proxy(None)`, `max_redirects(0)`, `max_redirects_will_error(false)`, `http_status_as_error(false)`, 5 s/10 s timeouts, `max_idle_connections(0)`); `verified_server_time` reads the same `status`/`age`/`date`. Supersedes `pool_max_idle_per_host(0)` from Phase 1 #4 if done. | One fewer tokio runtime thread and 90 s reaper; a few KB RSS. |
| `sms_forward.rs:564-611` | Move the whole `start()` body (seed loop + monitor spawns + `event_loop`) into one spawned thread so `main()` reaches `server::start` 0-8 s sooner at boot; keep the seed before `event_loop`, keep it unconditional. Also `:681` fallback poll 300 → 900 s (`FALLBACK_POLL_SECS`), and 3600 s when forwarding is disabled, computed per iteration (never a bare `recv()`). | Boot latency; 1 wakeup/5 min. |
| `sms_forward.rs:336-341` | `http_agent()` returns a cached Agent rebuilt when last use >15 s ago (ureq `max_idle_age` is dead in 3.2.0). | Per SMS batch only. |
| `speedtest.rs:92,152,157`, `tailscale/mod.rs:1178` | Shared Agent with request-scoped `timeout_global` and the same 15 s rebuild rule. | User actions only. |
| `handlers.rs:142-171`, `router.rs:55-60`, `device_ext.rs:213-215`, `wifi.rs:285-292, 207-244, 343-360` | One `uci_show` per section with a shared `ubus::uci_show_option()` parser (unescape `'\''`); `wifi_set`/`guest_set` diff against `uci show` and write via one `uci batch` on stdin (fail if stderr is non-empty: `uci batch` exits 0 after a failed line); keep `uci commit` as a separate call so a failed set still returns 500 before commit; replace `sh -c "ubus call zwrt_wlan reload &"` with a direct `Command::new("ubus").spawn()` plus a reaper thread (else zombies). | Screen opens / saves only. |
| `system.rs:442-577` | `/api/system/top`: skip `cmdline` for `PF_KTHREAD` (stat flags & 0x00200000) and Z/X states; cache the resolved name per `(pid, starttime, comm)` in `prev`; single `split_whitespace` pass. | Only while the process sheet is open (3 s). |
| `device_ext.rs:8-40` | Enumerate thermal zones once into a `OnceLock` (never cache an empty list); read only `temp` per request. Keep `read_thermal_zones(base)` uncached for the test. | ~1-2 ms per health tick. |
| `server.rs:72` | `.find(\|h\| h.field.equiv("authorization"))` (the finder's `eq_ignore_ascii_case` form does not compile against `&AsciiStr`). | Microseconds. |
| `server.rs:25-31` | Bind a `TcpListener` yourself, set `SO_KEEPALIVE`/`TCP_KEEPIDLE=300`/`TCP_KEEPINTVL=60`/`TCP_KEEPCNT=3` via libc, then `Server::from_listener`; accepted sockets inherit it, so vanished phones stop leaking a tiny_http thread + 2 fds. | Memory/fd hygiene, not CPU. |
| `system.rs:125-153, 190` | `read_meminfo` without the HashMap; kernel version in a `OnceLock` (not hostname). | Unpolled endpoints. |
| `tailscale/mod.rs:459-489, 250-253, 985-988, 1269-1278, 286-293` | Orphan check via `/proc/*/comm` scan instead of 3x `pidof`; run `tailscaled --cleanup` once per agent process; login-url poll 500 ms → 1 s; update health wait as a wall-clock deadline loop gated on `Path::new(SOCK).exists()` with 2 s probes; crash backoff via the Phase 2 E condvar. | Rare user actions / crash paths. |
| `Cargo.toml:6`, `.cargo/config.toml` | `opt-level = "s"`, `rustflags = ["-C","target-cpu=cortex-a55"]` (verified `CPU part 0xd05`, all required features present; binary 3.61 → 4.00 MB). Makes release artifacts A55-specific. | Rust-side time is ≤0.5 ms/request vs 5-30 ms forks. |

#### Rejected / needs design

- **Raise the 15 s clock-drift cap** (`live_activity_recovery.rs:133`) to 60 s: rejected. The log shows 49 "corrected modem UTC" repairs in 8.7 h (firmware `time_daemon`/`zte_topsw_ntp` step the clock); a wider window affects `auth.rs:77-85` token expiry, `scheduler.rs` HH:MM matching and SMS timestamps. Needs design: a `timerfd(CLOCK_REALTIME, TFD_TIMER_ABSTIME|TFD_TIMER_CANCEL_ON_SET)` polled alongside the condvar fires only when the clock is stepped and would remove the 0.067/s wakeup with identical repair latency.
- **In-process ubus client** (`ubus.rs:7`): the only lever for the single-client fork load (~2.4/s iOS, ~4.7/s Android ubus forks) but it needs design, not a patch: the musl build is `+crt-static` so `dlopen(libubus)` is a stub; a native wire-protocol client (`/var/run/ubus.sock`, LOOKUP+INVOKE, exact libubox blobmsg↔JSON type mapping, 30 s timeout, never retry after a sent INVOKE, thread-local connections, CLI fallback, env gate `ZTE_AGENT_UBUS=cli|native`) must be A/B validated on-device with `serde_json::Value` equality across every GET route before flipping the default. Do Phase 1-2 first and measure; this is the follow-on.
- **STK fix as originally proposed** (`try_clone` reader with "no read timeout", no session serial): `SO_RCVTIMEO` is per socket object so the clone still spins, and without `shutdown()` + serial tagging a stale reader can inject bytes into a later session. Phase 2 A uses `poll()` instead.
- **30 s TTL on `/api/wifi/status`**: `wifi_onoff`/radio state changes out of band (ZTE web UI on :80, hardware button, sleep mode) with no event to invalidate on; Android displays exactly those fields. Phase 1 #6 gets 31 → 7 processes without it.
- **Uniform 10-60 s TTL on modem/data, modem/status, sim/info, usb/status, 1-2 s on speeds/signal**: both apps run 2 s post-write confirmation loops against asynchronous daemon transitions (`MobileNetworkViewModel.kt:69-85`, `SIMViewModel.kt:53-57`), iOS re-reads modem/status 2 s after airplane-off, the iOS traffic poll is a fixed 1 s and the signal slider floor is 1 s. Phase 2 D uses settle windows and 500/800 ms caps.
- **Seed `charger_connected` from `/sys/class/power_supply/battery/status`**: reads "Discharging" while plugged in with charging stopped by the limit, which would park the enforcer and never resume at the hysteresis floor. A cached `stopped` with TTL and blocking `recv()` while the limit is disabled are rejected for the same class of reason (`set_charging` discards errors; `set()` cannot wake the loop).
- **Gate the SMS seed loop / watermark init on `config.enabled`**: enabling forwarding at runtime would leave `has_service`/`wan_connected` false (every forward logged as permanent failure) and the first SMS event would forward up to ~100 historical messages. If the watermark gate is wanted, `config_set` must seed on the disabled→enabled edge.
- **Scheduler "sleep until next due HH:MM, capped 3600 s"**: exact-minute string matching plus the agent's own `clock_settime` can skip a day's firing; a next-due of 0 inside an already-fired minute busy-loops. Phase 2 G keeps a per-minute cadence.
- **Tailscale `wait_timeout(30 s)` alone / plain blocking park / 120 s healthy poll**: the 1 s slice is the only crash detector and the WAN-watch `kill_child` path depends on it; there are 8 scattered wake sites so an unbounded park risks a permanent hang; the design doc intended ≤60 s healthy and with LocalAPI each poll is ~1 ms, so there is no reason to stretch it.
- **Replace `luci-rpc getHostHints` with `/proc/net/arp` + lease file**: drops IPv6 neighbours, `/etc/hosts`, static leases; the apps show `ip6addrs`.
- **Serve `/api/network/speeds` from rmnet sysfs**: measured to capture ~5 % of modem bytes (IPA offload).
- **`operate_mode` from `nwinfo_get_netinfo`**: the payload has no such field (48 keys checked on-device).
- **Refresh the UTC anchor from APNs `Date`**: APNs answers `405` with only `apns-id`, no `date` header; also the first probe must succeed before any APNs connection exists.
- **`pool_idle_timeout(None)` / `tcp_keepalive(120 s)` on the APNs client**: pools the h2 socket forever after a session; first push of the next session can hit a dead NAT mapping → 10 s timeout → 30 s backoff.
- **Push-loop `skip_unchanged`**: only as an opt-in config key with `stale_after_seconds >= 2*interval_seconds` validation; the compare runs after the ubus read so it saves neither the fork nor the wakeup. Interval 30 / stale 60 in the private config saves more.
- **Process-wide `nice -n 5`** in `start_zte_agent.sh`: deprioritises tailscaled (userspace WireGuard), the DoH resolver serving all LAN DNS, `ubus listen`, the STK deadline thread and the APNs worker; `setup.sh:381` would not even rewrite the script on existing installs.
- **`at_cmd` with `cfmakeraw` + return-on-OK**: the AT nodes are not ttys (`tcsetattr` → ENOTTY) and USSD's `+CUSD:` arrives as a URC after `OK`. Phase 2 H handles both.
- **`/api/system/top` kthread test `ppid == 2` and name cache keyed on `(pid, starttime)`**: usermode helpers are children of kthreadd; exec keeps pid+starttime but rewrites `comm`. Use the `PF_KTHREAD` flag and key on comm.
- **`rx_bytes_per_sec` aliases in `SpeedSnapshot`**: tier 1 has no `return`, so Android would still fork `get_wwandst`, and it would silently switch the displayed rate to kernel counters that miss offloaded traffic.
- **`sync_channel` for the event bus**: a blocking send would stall all subscribers behind the slowest; `try_send` would drop charger/SMS/recovery events the consumers must never lose. Fix the misleading comment at `event_bus.rs:104` only.
- **Process-lifetime `OnceLock<ureq::Agent>`**: ureq 3.2.0 `max_idle_age` never expires connections (`age()` returns 0), so a shared Agent keeps WAN sockets open indefinitely; use the 15 s rebuild rule everywhere (Phase 1 #5, hygiene rows).

### 3. Measurement protocol (BusyBox ash, run over `ssh root@192.168.0.1 -p 2222`)

Scenarios, each 5 min, before and after each phase: **A** idle, no app connected; **B** iOS dashboard foreground; **C** Android dashboard foreground; **D** (optional) DoH on, SIM Toolkit opened once then closed, Tailscale on. Keep the WAN state identical across pairs. USER_HZ is 100 on Linux, so one `stat` tick = 10 ms.

```sh
PID=$(pidof zte-agent); echo "agent pid $PID, threads $(ls /proc/$PID/task | wc -l)"
```

Per-thread CPU and wakeups (utime+stime from `task/*/stat`, `nr_switches`/`nr_voluntary_switches` from `task/*/sched`; falls back to `voluntary_ctxt_switches` in `task/*/status` if `sched` is absent):

```sh
snap() {
  : > "$1"
  for t in /proc/$PID/task/*; do
    tid=${t##*/}
    set -- $(sed 's/.*) //' "$t/stat")
    cpu=$(( ${12} + ${13} ))
    if [ -r "$t/sched" ]; then
      sw=$(awk '/^nr_switches/{print $3}' "$t/sched"); vsw=$(awk '/^nr_voluntary_switches/{print $3}' "$t/sched")
    else
      sw=0; vsw=$(awk '/^voluntary_ctxt_switches/{print $2}' "$t/status")
    fi
    echo "$tid $cpu $sw $vsw $(cat "$t/wchan") $(cat "$t/comm")" >> "$1"
  done
}
snap /tmp/t1; sleep 300; snap /tmp/t2
awk 'NR==FNR{c[$1]=$2; s[$1]=$3; v[$1]=$4; next}
     {dc=$2-c[$1]; dv=$4-v[$1]; ds=$3-s[$1];
      if (dc>0 || dv>0) printf "%8.4f wake/s %7.2f ms/s  tid %-6s %-22s %s\n", dv/300, dc*10/300, $1, $5, $6}' /tmp/t1 /tmp/t2 | sort -rn
```

Expected idle (scenario A) before Phase 1: one thread at ~2.0 wake/s (sms connectivity_monitor, wchan `hrtimer_nanosleep`), one at ~1.0 (SpeedTracker), one at ~0.067 (recovery loop, `futex_wait`), one at ~0.033 (scheduler). After Phase 1 the sum of all `wake/s` lines should be ≤0.15; after Phase 2 G ≤0.1. With an STK session open before Phase 2 A, `stk-ril` shows 10 wake/s.

Process-level counters (sum of per-task voluntary switches, self CPU, CPU of reaped children, system fork rate):

```sh
pv() { awk '/^voluntary_ctxt_switches/{s+=$2} END{print s}' /proc/$PID/task/*/status; }
pc() { sed 's/.*) //' /proc/$PID/stat | awk '{print $12+$13, $14+$15}'; }
PM=$(cat /proc/sys/kernel/pid_max)
v1=$(pv); set -- $(pc); s1=$1; c1=$2; f1=$(awk '/^processes/{print $2}' /proc/stat); l1=$(awk '{print $5}' /proc/loadavg)
sleep 300
v2=$(pv); set -- $(pc); s2=$1; c2=$2; f2=$(awk '/^processes/{print $2}' /proc/stat); l2=$(awk '{print $5}' /proc/loadavg)
awk -v a=$v1 -v b=$v2 'BEGIN{printf "agent wakeups: %.3f/s\n",(b-a)/300}'
echo "agent self CPU: $(( (s2-s1)*10 )) ms; reaped-children CPU (ubus/uci/sh/iw): $(( (c2-c1)*10 )) ms over 300 s"
echo "system forks: /proc/stat processes +$((f2-f1)); loadavg last-pid delta $(( (l2-l1+PM) % PM )) over 300 s"
```

`cutime+cstime` (fields 16/17 of `/proc/$PID/stat`) accumulate only for children the agent has waited on, which is every `Command::output()` child and their grandchildren; the long-lived `ubus listen` child is excluded until it exits. This is the authoritative "child processes" figure: with the Android dashboard open expect several hundred ms per minute before Phase 1 #6 and a drop of roughly a third after it; the system-wide fork counters are dominated by firmware daemons (~250 forks/s measured) and are only useful as a sanity check that the agent is not the main forker.

Identify which binaries are spawned (60 s sample; undercounts children shorter than one `/proc` pass and costs CPU itself, so use it for attribution only):

```sh
seen=" "; end=$(( $(cut -d. -f1 /proc/uptime) + 60 ))
while [ "$(cut -d. -f1 /proc/uptime)" -lt "$end" ]; do
  for s in /proc/[0-9]*/stat; do
    p=${s#/proc/}; p=${p%/stat}
    set -- $(sed 's/.*) //' "$s" 2>/dev/null)
    [ "$2" = "$PID" ] || continue
    case "$seen" in *" $p "*) continue;; esac
    seen="$seen$p "; echo "$(cat /proc/$p/comm 2>/dev/null) $(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | cut -c1-70)"
  done
done | sort | uniq -c | sort -rn
```

Per-command cost, when a number is needed (CPU is `utime+stime` of the shell's reaped children):

```sh
b=$(sed 's/.*) //' /proc/$$/stat | awk '{print $14+$15}'); i=0
while [ $i -lt 50 ]; do ubus call zwrt_bsp.charger list >/dev/null; i=$((i+1)); done
a=$(sed 's/.*) //' /proc/$$/stat | awk '{print $14+$15}'); echo "$(( (a-b)*10/50 )) ms CPU per call"
```

Radio and clock side-effects (Phase 1 #4 must not change the second number):

```sh
grep -c "network and UTC verified" /tmp/zte-agent.log      # successful probes since agent start: ~12/h before, ~1/h after at idle
grep -c "corrected modem UTC" /tmp/zte-agent.log           # clock-step repairs: ~5-6/h today; must stay the same
cat /proc/net/tcp | awk 'NR>1 && $4=="01"' | wc -l         # ESTABLISHED sockets; should drop to 0 between probes after #4
```

Orphan check before every measurement (a stale `ubus listen` from a previous `killall` inflates nothing in the agent's counters but wakes on every event):

```sh
for p in $(pidof ubus); do echo "$p ppid $(awk '{print $4}' /proc/$p/stat) $(tr '\0' ' ' < /proc/$p/cmdline)"; done
```

### 4. Rollback

`deploy.sh` overwrites `/data/zte-agent` in place (step 3) with no backup. Before each phase's deploy:

```sh
ssh -p 2222 root@192.168.0.1 'cp /data/zte-agent /data/zte-agent.bak-pre-phase1 && ls -l /data/zte-agent.bak-*'
```

Tag convention: `/data/zte-agent.bak-<tag>` with `<tag>` = `pre-phase1`, `pre-phase2`, `pre-phase2-stk`, etc.; keep at most the last three (`/data` has ~1.7 GB free, the binary is 3.6-4 MB). Add that `cp` as step 2b of `deploy.sh` with a `--tag` argument so it cannot be forgotten.

Rollback:

```sh
ssh -p 2222 root@192.168.0.1 'killall zte-agent; sleep 1; for p in $(pidof ubus); do kill $p; done; cp /data/zte-agent.bak-<tag> /data/zte-agent && chmod +x /data/zte-agent && sh /data/local/tmp/start_zte_agent.sh'
```

Then rerun the scenario A snapshot to confirm the old wakeup profile is back. Build only from the working tree that produced the deployed binary (it contains uncommitted Live Activity/STK code; never build from `main`), and note that `deploy.sh` step 6 (`sleep 2` then login) can fail spuriously while the SMS seed loop still blocks `main()` at boot; the hygiene item for `sms_forward.rs:564-611` removes that.

---

## Part C. Appendix

### C1. Approvals needed from the owner

| Item | What it does to the router | Reversible |
|---|---|---|
| A3 step 1: 2.4 GHz repair | sets `main_2g.disabled=1`, `guest_2g.disabled=1`, kills two stuck scripts, one Wi‑Fi reload (phones drop for seconds) | yes, two UCI keys |
| A4 experiment E1 | ~15 min without mobile data (forced no-service), three UCI keys changed, all reverted after | yes |
| A5 rung 3/4 validation | one manual `AT+CFUN=1,1` (modem reset, ~20 s offline); rung 4 reboots | yes |
| Each agent deploy | restart of the agent; backup at `/data/zte-agent.bak-<tag>` first | yes |

### C2. Where things are

- Plan: this file. Audit raw findings (JSON) and the audit's own notes: `/tmp/u60-perf/audit-*.{json,md,txt}` on this Mac.
- Measurement scripts: `scripts/power/` (README inside). Raw captures from 2026-10-17: `/tmp/u60-perf/idle`, `/tmp/u60-perf/ep-*`.
- Firmware logs copied for the flight investigation: `/tmp/u60-logs/{key.log,syslog,zte-agent.log}`; `key.log` only reaches back to 2026-10-13, so the flight itself (about June 2026) is not recoverable.
- Router backup of the pre-bearer agent: `/data/zte-agent.bak-pre-bearer-20261017`.
