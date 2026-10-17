# Physical SIM swap ubus capture — September 15, 2026

Read-only `ubus listen` capture with host UTC receipt timestamps and two-second
modem epoch/uptime sampling. Times below are Asia/Manila (UTC+8), derived from
Mac receipt time because the modem clock was incorrect. Capture stopped after
the user reported completion. Raw data remains in `/tmp/u60-sim-events/` with
restricted permissions; it contains SIM identifiers and must not be committed.

| Time | Event | Relevant payload |
|---|---|---|
| 17:39:58.438 | `network.interface` | `action=ifdown`, `interface=zte_wan` |
| 17:39:58.672 | `zwrt_servicestatus` | `network_type=NO_SERVICE` |
| 17:39:58.800 | `zwrt_card_state_event` | `sim_hotswap=sim hot remove` |
| 17:40:00.229 | `zwrt_data_connect_status` | `cid=1`, `connect_status=disconnected` |
| 17:40:14.295 | `zwrt_card_state_event` | `sim_states=sim ready`, `sim_changed=1` |
| 17:40:14.364 | `zwrt_apn_list_changed` | APN profiles refreshed |
| 17:40:39.108 | `zwrt_servicestatus` | `network_type=ENDC` |
| 17:40:39.519 | `zwrt_data_connect_status` | `connect_status=connecting` |
| 17:40:39.734 | `zwrt_data_connect_status` | `connect_status=ipv4_connected` |
| 17:40:42.381 | `network.interface` | `action=ifup`, `interface=zte_wan` |
| 17:40:42.504 | `router_event_wan_connect_status` | `wan_status=ipv4_connected` |
| 17:40:52.209 | `zwrt_servicestatus` | `network_type=LTE` |

No explicit `sim hot insert` event was observed. The reliable observed insertion/
initialization signal was `sim_states=sim ready`; do not invent an insert event.
SIM-ready occurred about 15.5 seconds after removal; WAN router-ready followed
about 28.2 seconds later. WAN-up is a trigger to probe internet/DNS availability,
not proof that APNs or a time source is reachable.

## Clock evidence

130 complete epoch samples between 09:38:30 and 09:42:49 UTC showed the modem
about 28,790–28,795 seconds ahead of the Mac (approximately eight hours).
No successive offset change exceeded five seconds. The error was already
present before the swap, so this capture does not prove that SIM insertion
caused it. No time correction was performed during capture. Receipt timestamp
jitter and modem clock drift limit subsecond interpretation.

## Recovery implementation

- On SIM removal: treat WAN-dependent delivery as unavailable; avoid busy retries.
- On SIM ready: pause delivery and request fresh network/UTC verification; retain the monotonic UTC anchor for expiry calculations.
- On WAN connected/ifup: debounce the burst of events, verify internet and UTC,
  then resume APNs attempts if an unexpired phone registration exists.
- Also detect clock jumps independently of SIM events, because this capture
  began with a pre-existing offset and did not identify the time-setting process.
- Do not retain ICCID, IMSI, APN credentials, or unrelated event fields in logs.

Implemented in `src/live_activity_recovery.rs` and deployed September 15.
The worker preserves the active registration through SIM/WAN interruptions,
verifies UTC using an HTTPS response from Apple, and repairs modem wall-clock
jumps using a monotonic time anchor. Failed verification retries after 30 seconds;
healthy verification repeats every five minutes. The app retries missing
registration while open. Agent restart still requires phone registration.

## Post-deployment physical SIM-swap verification

After the user started Live signal on iPhone 17 Pro Max and swapped the SIM,
the running agent logged `wan_down`, `sim_removed`, `wan_down`, `sim_ready`,
`wan_up`, then a modem UTC correction and delivery resumption. Read-only SSH
checks found `registered=true`, `recovery_state=ready`, `clock_verified=true`,
no clock or APNs error, and modem epoch equal to the Mac to whole-second
precision. Apple accepted updates after reconnection. This verifies agent-side
recovery and Apple acceptance; it does not by itself prove iOS rendered every
accepted update. No manual clock adjustment or restart was performed during
this verification.

### Correction after phone verification

The user reported the phone still displayed the 17:55 sample despite successful
Apple acceptance. Live iPhone 17 logs initially showed no incoming activity
pushes. After the user toggled Wi-Fi off/on without restarting the activity,
the user confirmed sample age reset and liveactivitiesd logged pushes for the
same activity at 18:07:03, 18:07:18, 18:07:33, and 18:07:49 Manila. This supports
a stalled phone APNs connection after the WAN transition; the precise iOS
transport cause is not proven. Agent-side recovery does not guarantee phone
reconnection or rendering. Do not describe this test as fully automatic
end-to-end recovery.

### Local clock correction

UTC was correct but the timezone was UTC, so the physical screen's local time
remained incorrect. Set official zwrt_sntp timezone to `8` with DST disabled,
OpenWrt timezone to `HKT-8`/Asia/Manila, and installed standard Manila TZif data
in `/data/zoneinfo/Manila`. `/tmp/localtime` is restored from this file by the
existing agent startup script. Restarted only time and screen services to clear
cached timezone data; the official get_systime API then returned 18:07:50 while
UTC was 10:07:50. Master daemon reported sync/register success. No modem reboot.
Backup: `/data/local/tmp/timezone-backup-1789466704` (includes original time
settings, TZif, and startup script). Physical-screen rendering and persistence
through a later reboot/SIM swap still require verification.
