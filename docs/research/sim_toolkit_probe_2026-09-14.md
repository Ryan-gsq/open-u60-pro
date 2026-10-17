# U60 Pro SIM Toolkit: live probing and implementation

## Result

The U60 Pro exposes a working Qualcomm SIM Toolkit transport. Both a small C probe and the new Rust backend received a successful response to STK initialization through `/dev/socket/qcrild/rild0`. Neither received a proactive menu. An independent QMI CAT query for the cached SET UP MENU returned error 74, **InformationUnavailable**.

This establishes the transport and the current absence of a cached menu. It does **not** establish that the inserted SIM lacks toolkit applications, or that menu selection works end to end. The application now reports this distinction instead of assuming failed AT queries mean an unsupported SIM.

The code changes are local. The production agent and installed mobile apps were not replaced by this work. Temporary probe binaries were uploaded to `/tmp`, executed, and removed. The initial probe requested no carrier menu item, SMS, USSD, call, SIM reset, modem reset, reboot, PIN operation, or persistent device configuration change. The subsequent controlled-restart verification is recorded below. STK initialization does change the radio daemon's transient client-ready state.

## Live evidence

SSH: `root@192.168.0.1`, port `2222`. Kernel: `5.15.170-perf`, aarch64.

`qrtr-lookup` advertised:

```text
Service Version Instance Node Port
10      2       0        3    82    Card Application Toolkit service (v2)
```

Node/port are discovery results for this boot, not stable configuration. No STK method appeared in the live ubus method inventory. The running `qcrilNrd` process had `libqcrilNr.so`, `libqcrilNrSocketModule.so`, `libqcrilNrQmiModule.so`, `libqmiservices.so`, and `libqmi_cci.so` mapped. `/dev/socket/qcrild/rild0` was a listening Unix socket owned by `radio:radio` with mode `0660`.

The installed `libqcrilClient.so` exports `RilApiSession` methods for:

- `ReportStkServiceIsRunning`
- `StkSendEnvelopeCommand`
- `StkSendTerminalResponse`
- `registerStkUnsolProactiveCommand`
- `registerStkUnsolSessionEnd`
- `registerStkEventNotify`
- `StkHandleCallSetupRequestedFromSim`

The C initialization probe sent exactly:

```text
0000000C 67000000 0100000000000000
```

The response was:

```text
00000000 0000000000000001 00000000
type=0   token=1          RIL error=0 (success)
```

No proactive menu arrived during its eight-second receive window. The Rust probe subsequently reproduced initialization success and `menu_unavailable`. See final Rust probe and WAN check.

### Direct cached-menu query

The installed CAT IDL service object accepts version arguments `(2, 37, 6)`. Disassembly of `CatModemEndPointModule::handleQcrilGstkRequest` identified `GET_CACHED_PROACTIVE_CMD` as message `0x002f`, with a 12-byte C request structure: command enum, slot-valid byte with padding, and slot enum. The recovery table maps SET UP MENU (`0x25`) to cached-command enum `1`.

The installed `qmi_idl_message_encode` encoded command `1`, slot `1` into:

```text
QMI request:  0001002F000B000104000100000010010001
QMI response: 0201002F00070002040001004A00
```

The result TLV is `02 0400 0100 4A00`: failure, error `0x004a`. The mapping to InformationUnavailable is defined in [OpenWrt's QMI error enumeration](https://lxr.openwrt.org/source/uqmi/qmi-errors.h). This was a get-cache request, without event registration, terminal-profile replacement, or application selection.

Probe sources: RIL C probe, cached-menu C probe. The cache probe contains the boot-specific node/port above; rediscover these before reusing it on another boot. Firmware libraries were inspected locally under `/tmp/u60-stk-probe`; they are not added to this repository.

### Firmware library fingerprints

| Library | SHA-256 |
|---|---|
| libqcrilClient.so | `8c9a3c7c650263addaef98cfeb198f5656e08697dcb52df21c86f7995b5d82ad` |
| libqcrilNr.so | `848e8d9d35a850800c5beb62377a251eadb4b21d2a8c94982808570b89c30d51` |
| libqcrilNrQmiModule.so | `7bd4ed91bce67da5c2cb7b09ef2ac439a6d9b4fd567cb562e4974205e46b41e2` |
| libqmiservices.so | `352467e671869fd5ed4b6e6b25412c19b2a78d11ee6fba1f8c0ddf53db7c6615` |

## Implemented integration

```text
iOS / Android → authenticated zte-agent API → persistent RIL socket → QMI CAT → SIM
```

[Rust STK service](../../zte-agent/src/stk/mod.rs) owns one stream and serializes mutations. It correlates 64-bit response tokens, buffers fragmented records, bounds record sizes and request queues, checks timeouts, rejects stale `command_id` values, and discards cached state on socket failure or SIM refresh. Failed or ambiguous mutations are not replayed. Other radio indications are ignored without logging their contents.

Verified RIL framing:

- Requests: big-endian 32-bit record length, little-endian 32-bit request number, little-endian 64-bit token, then Marshal payload.
- Responses: big-endian type, token, and error. Unsolicited records contain type `1`, then indication number.
- Request `103` initializes STK, `69` sends an envelope, and `70` sends a terminal response.
- STK strings use a big-endian 32-bit byte length followed by ASCII hex.
- Indication `1013` carries a proactive command; `1012` ends a session; `1017` refreshes SIM state.

[CAT codec](../../zte-agent/src/stk/codec.rs) handles BER lengths, comprehension tags, GSM alpha identifiers, UCS-2 and compressed alpha forms. The implemented interaction subset is SET UP MENU, SELECT ITEM, DISPLAY TEXT, GET INKEY, and GET INPUT. Root selections use the corrected `D307820201819001<item>` envelope; submenu selections use a terminal response containing the original command details. See [ETSI CAT specification](https://www.etsi.org/deliver/etsi_ts/102200_102299/102223/10.01.00_60/ts_102223v100100p.pdf) for these distinct procedures.

Other structurally parsed proactive command types receive an unsupported-command response; malformed or unrecognized required TLVs invalidate the session. The implementation does not automatically approve calls or execute carrier-service commands. Icons and advanced toolkit presentation/event behavior are not fully implemented; this is not a complete CAT terminal conformance implementation.

### API contract

All routes use the existing agent authentication and `{ok,data}` / `{ok:false,error}` envelopes.

| Method | Path | Behavior/body |
|---|---|---|
| GET | `/api/stk/menu` | Initialize/recover the RIL session and return its current snapshot. **May send STK initialization; not a strictly read-only getter.** |
| GET | `/api/stk/session` | Read current state without reconnecting or initializing. |
| POST | `/api/stk/select` | `{ "item_id": 1, "command_id": "..." }` |
| POST | `/api/stk/respond` | `{ "text": "...", "command_id": "..." }`, or `yes: true/false`; DISPLAY TEXT needs only `command_id`. |
| POST | `/api/stk/back` | `{ "command_id": "..." }`; sends backward-move response for a pending command. |
| POST | `/api/stk/cancel` | `{ "command_id": "..." }`; ends a pending command. |

Snapshots include `status`, `type`, `reason`, `command_id`, `busy`, `root_menu`, `items`, and prompt metadata. `supported: null` means the SIM's application support is still unknown; `transport_available: true` means the socket connection exists. Empty items are not proof of an unsupported SIM.

Clients must poll `/session` for asynchronous results and supply the latest opaque string `command_id` on every mutation. A successful request acknowledgement may precede the SIM's next command. After an error, reload explicitly rather than repeating a selection. Older clients lacking `command_id` receive a stale/missing-command error instead of executing a potentially outdated selection.

Both mobile STK screens now poll while visible, render menu/display/input states, clear hidden input when commands change, and send protocol-backed Back/End Session actions. Android's incorrect `id` request field is corrected to `item_id`. A one-line existing Android build error in DeviceControlScreen was also corrected: its footer now uses `state.chargeLimit` instead of an out-of-scope `sliderValue`.

## Validation and remaining work

- Rust tests: 15 STK tests pass; the binary test target also passes its existing test (16 total), and the probe example repeats the same 15 STK tests.
- Dedicated STK example passes strict Clippy. Full-workspace strict Clippy remains blocked by 12 pre-existing findings in unrelated code.
- Release agent and standalone STK probe build for `aarch64-unknown-linux-musl`.
- iOS simulator build passes; Android `compileDebugKotlin` passes.
- The standalone Rust probe executes successfully on the real device without starting the agent's unrelated background services. The final WAN check reports `ipv4_ipv6_connected` and zero connection failures.
- Live root-menu retrieval, carrier item selection, nested prompts, and session completion remain **unverified** because the modem returned no cached menu. Tests for these paths use synthetic protocol fixtures, not captured carrier menus.

Next hardware investigation: determine why this SIM/boot did not produce SET UP MENU, including the terminal profile and the radio daemon's CAT registration state. Capturing SIM initialization during a separately planned reconnect/reboot, or comparing a SIM known to show a toolkit menu, can distinguish these possibilities. No reset or profile replacement was performed in this probe. The app cannot display carrier applications until the SIM/modem supplies a menu.


## Controlled-restart verification — 2026-09-14

**Transport verified again; end-to-end SIM application access remains unverified.** A controlled router restart did not make a SET UP MENU available during the captured period. No carrier selection or terminal response was sent, and the production agent and mobile apps were not replaced.

- Boot ID changed from `28f9ba74-76ce-41b3-abae-dbb5feb61df1` to `c3e803ff-5eeb-4154-bced-a7e7c58591f3`.
- SSH returned around 51 seconds after boot. The RIL observer ran from uptime 65.869 to 215.880 seconds. STK initialization request 103 succeeded at approximately 66, 86, and 106 seconds, with no proactive menu received during the 150-second observation.
- Cached SET UP MENU queries after restart and after observation both returned result 1 / error 74 (`InformationUnavailable`).
- Read-only CAT GET_CONFIGURATION (`0x2e`, empty request) succeeded: `0201002E000B000204000000000010010002`. Its configuration TLV (`0x10`) contains value `2`. Firmware disassembly treats configuration modes 2 and 5 as acceptable without reconfiguration; this does not prove the SIM emitted a menu. No SET_CONFIGURATION (`0x2d`) was sent.
- `qtigetprop persist.vendor.radio.qcril_gstk.disable` returned `0`.
- Radio daemon and agent were running, master daemon synchronization and registration succeeded, and final WAN status was `ipv4_ipv6_connected` with zero connection failures.
- All uploaded probe binaries and their archive metadata were removed from `/tmp/u60-stk-verify-20260914`.

Automatic approval review rejected installation of the proposed `/etc/rc.d/S18u60_stk_verify` startup hook because custom boot-time code could affect startup or connectivity. No hook or persistent probe directory was installed. The alternative post-SSH capture cannot establish what happened during the earliest SIM initialization. The local `reboot/boot.sh` is an unexecuted proposal, not part of the verification procedure used.

Evidence: RIL observation, initial cache and health, final configuration and cache, cleanup and final health. The first configuration-probe attempt failed locally in the IDL encoder with -41 before sending; the successful probe sends the firmware's empty GET request directly.

A comparison with a SIM known to display a toolkit menu, or confirmation that this same SIM shows one in a phone, is the next useful discriminating check. Until a real menu arrives, app menu rendering, safe submenu navigation, Back, and session completion cannot be verified on this device.
