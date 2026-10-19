# eSIM profiles (lpac)

The agent manages the profiles on an eSIM card in the router's SIM slot (for example a 9eSIM B1): list them, switch which one is enabled, download new ones from an activation code (the operator's QR code) and delete them. It does this with [lpac](https://github.com/estkme-group/lpac), the open-source GSMA SGP.22 LPA: card commands go over the modem's QMI UIM service (QMI over QRTR), downloads use HTTPS from the router's own connection. The SIM Toolkit menu is not used.

lpac is not built into the agent. Build the private bundle and install it on the router with the scripts in [`lpac-qrtr-build/`](../../lpac-qrtr-build/):

```sh
cd lpac-qrtr-build
./make-bundle.sh          # pinned, checksum-verified inputs → out/bundle
./install-to-router.sh    # → /data/lpac on root@192.168.0.1:2222 (previous copy kept as /data/lpac.old)
```

The agent refuses a bundle whose files are symlinks, owned by another user, or group/world-writable.

**TLS to the operators' servers.** SM-DP+ servers present TLS certificates issued by the GSMA eSIM root CI ("GSM Association - RSP2 Root CI1"), which no web CA list contains. The bundle ships that root as `gsma-ci.pem`, and the agent passes it to lpac as `LPAC_HTTP_CA_FILE`. lpac checks the certificate and host name against it and ignores the system CA directory. Upstream lpac doesn't check these certificates at all. A bundle built before this fix fails every download and receipt with "SSL peer certificate or SSH remote key was not OK"; rebuild and reinstall it.

| Variable | Default | Meaning |
|---|---|---|
| `ZTE_AGENT_LPAC_DIR` | `/data/lpac` | Bundle directory |
| `ZTE_AGENT_LPAC_QRTR_NODE` | `3` | QRTR node of the modem's UIM service (`qrtr-lookup`, service 11) |
| `ZTE_AGENT_LPAC_UIM_SLOT` | `1` | SIM slot |
| `ZTE_AGENT_LPAC_LOCK` | `/tmp/lpac.lock` | Lock file shared with manual lpac runs |

## API

All routes use the agent's bearer authentication and `{ok,data}` / `{ok:false,error}` envelopes. The agent runs one lpac command at a time (30 s limit for card commands, 300 s for a download); a request made while another is running gets 409. Enable, delete, download, rename and sending receipts require an agent password (403 otherwise). `GET /api/esim/profiles` also returns `pending_receipts`.

| Method | Path | Result |
|---|---|---|
| GET | `/api/esim/profiles` | `profiles`: `iccid`, `isdp_aid`, `state` (`enabled`/`disabled`), `nickname`, `provider`, `name`, `class`; plus `enabled_iccid`, `observed_at`, `generation`, `agent_instance`, `updating`, `stale`, `error` (see Reading during a switch) |
| GET | `/api/esim/chip` | `eid`, `firmware`, `sgp22_version`, `profile_version`, `free_nvm_bytes`, `free_ram_bytes`, `card_changed`, `lpac` (`build`: contents of the bundle's `BUILDINFO`; `lpac_sha256` from `SHA256SUMS`) |
| POST | `/api/esim/enable` | Body `{"iccid": "..."}`. Returns `enabled_iccid`, `previous_iccid`, `reconnecting: true`, `generation`. If lpac fails or times out the reply carries `outcome: "unknown"`: the switch may still have happened, see `/api/esim/switch`. If the card refuses because it is busy, the reply is 202 with `retrying: true` and the agent keeps trying (state `card_busy`) |
| GET | `/api/esim/switch` | Last switch: `state`, `target_iccid`, `previous_iccid`, `generation`, `started_at`, `card_confirmed_at`, `modem_confirmed_at`, `connected_at`, `finished_at`, `note`, `reason` (for `no_data`: `roaming_off` or `data_off`, else null) |
| POST | `/api/esim/delete` | Body `{"iccid": "..."}`. Disabled profiles only. Returns `deleted_iccid`, `operator_notified` |
| POST | `/api/esim/nickname` | Body `{"iccid": "...", "nickname": "..."}` (at most 64 bytes, no control characters; empty clears it). Returns `iccid`, `nickname`, `generation` |
| GET | `/api/esim/notifications` | Operator receipts waiting on the card: `count`, `pending` (`seq`, `operation`, `address`, `iccid`, `attempts`, `last_error`, `gave_up`), `listed_at`, `last_attempt_at`, `last_sent_at`, `retrying`, `stale` |
| POST | `/api/esim/notifications/process` | Sends the waiting receipts now in the background (202) and restarts the retry loop, including receipts that gave up |
| POST | `/api/esim/download` | Body `{"activation_code": "LPA:1$...", "confirmation_code": "...", "preview": true}`. Starts a background download; 202 with the status below |
| GET | `/api/esim/download` | Status: `state` (`idle`, `running`, `confirm`, `cancelling`, `done`, `failed`, `cancelled`), `step` (last lpac progress step), `provider`, `name`, `iccid`, `error`, `started_at`, `finished_at` |
| POST | `/api/esim/download/confirm` | Body `{"accept": true}` or `false`, while `state` is `confirm` |
| POST | `/api/esim/download/cancel` | Cancels a running download |
| DELETE | `/api/esim/download` | Dismisses a finished result (status back to `idle`); 409 while a download runs |

### Download

The activation code must have the SGP.22 form `LPA:1$<server>$<matching ID>[$<OID>[$1]]`; a final `1` means the operator also issued a confirmation code, which the request must then include. The agent runs `lpac profile download -p -a <code> [-c <code>]` in a background thread. With preview on (the default), lpac stops once the operator's server has sent the profile metadata: the status moves to `confirm` with `provider` and `name` filled in, and lpac waits for the answer from `/download/confirm`. An unanswered preview is declined after 2 minutes. Cancel sends lpac SIGINT, which cancels the session with the card and the server at the next step; a step blocked on the network is killed after 15 s. A downloaded profile is disabled until it is enabled. A finished result (`done`, `failed`, `cancelled`) is reported for 10 minutes, then the status reads `idle`; the result is also lost when the agent restarts.

After a successful download or delete the agent sends the operator receipts (see [Operator receipts](#operator-receipts)). Activation codes are never logged.

### Safety checks

- **Card identity.** Before enable, delete, download and rename the agent reads the card's EID. If it differs from the card the saved list belongs to (the card was swapped), the list is dropped, `generation` goes up and the request gets 409 "a different eSIM card is in the slot".
- **Radio.** `enable` is refused (409) while the modem is in airplane / low-power mode (`zte_nwinfo.sys_info.operate_mode` not `ONLINE`), unless the no-service policy parked it: switching to another network is then the way out, and the firmware's SIM reload brings the radio back.
- **Download.** Refused (409) when the router has no mobile data connection; the start reply includes `free_nvm_bytes`.
- **Shared lock.** Every agent lpac run holds the agent's own flag and a non-blocking `flock` on `/tmp/lpac.lock` (`ZTE_AGENT_LPAC_LOCK`). Run lpac by hand as `flock -n /tmp/lpac.lock <lpac command>` so the two never overlap; while a manual run holds it the agent answers "busy".

### Operator receipts

After installing, enabling, disabling or deleting a profile the card keeps an SGP.22 notification for the operator's server until it is delivered. lpac's `notification process -a` stops at the first failure, so the agent sends each receipt on its own (`notification process -r <seq>`, 45 s limit). The first successful profile read after the agent starts lists them. After a download or delete the agent sends them. After a switch it sends them 5 s after the data connection is confirmed and tries the failed ones once more 30 s later (right after the attach a request can stall); a switch that ended without data only lists them. A server that fails or hangs is skipped for the rest of that round, so one unreachable operator holds the card for at most 45 s per round. Unsent receipts are retried every 10 minutes while the router has mobile data (at most 24 rounds). A receipt that failed 10 times is reported with `gave_up: true` and left on the card; it is never deleted unsent. `POST /api/esim/notifications/process` resets the attempt counts and tries again.

### Reading during a switch

For several seconds after `enable` (3–8 s in most switches, about 25 s in one test) the modem is reloading the SIM and the eUICC's management application cannot be selected: lpac fails in `euicc_init` with QMI error 80 (`SimFileNotFound`). The app saw this as "Could not read eSIM profiles" in 3 of 14 switches. The agent therefore:

- keeps the last good profile list. While a switch reloads the SIM, `GET /api/esim/profiles` answers from it with `updating: true` and does not start lpac. It does the same while another eSIM operation holds the card (instead of 409). A failed read returns the last good list with `stale: true` and `error: {kind, message, at}`. `kind` is `sim_reloading` (within 5 minutes of a switch), `management_unavailable`, `read_failed` or `not_installed`. A successful read clears the error;
- re-reads the card itself after the switch: from 5 s, every 3 s once `get_sim_info` reports the SIM ready, for up to 60 s;
- refuses enable, delete and download while the SIM reloads (409);
- numbers each change of the card's contents or selection (`generation`) and each agent run (`agent_instance`, start time in ms), so clients can drop answers older than what they have shown.

`GET /api/esim/switch` reports the verified outcome. `state` starts at `card_busy` when the card refused the enable because it was busy (see below), then moves `reloading` → `card_confirmed` (fresh card read shows the target enabled) → `modem_confirmed` (`get_sim_info` `sim_iccid` equals the target) and ends as:

- `connected` (`get_wwaniface` `connect_status` connected);
- `no_data` (card and modem switched, no data within 150 s). `reason` says why when the firmware shows it: `roaming_off` when the SIM's country code differs from the network's (a travel eSIM) and data roaming is off, or `data_off` when mobile data is switched off;
- `modem_unconfirmed` (the modem kept the old identity);
- `card_unconfirmed` (the card stayed unreadable for 60 s);
- `not_applied` (the card still has another profile enabled; `reason: card_busy` when it kept refusing).

**Busy card.** The card can refuse an enable with SGP.22 `catBusy` (5: its SIM Toolkit is in a proactive session), `undefinedError` (127), or a code lpac doesn't name. The patched lpac reports these as `cat busy`, `undefined error` and `unknown result N`; older bundles say `unknown`. Nothing changes on the card. The agent answers 202, reports `card_busy` and retries every 10 s for up to 240 s, then verifies the switch as usual. A second switch request in that time gets 409.

Apart from that, the agent never retries a switch or switches back by itself. "Connected" comes from the firmware; traffic can need a few more seconds.

### Switching

`enable` only accepts a profile that exists, is disabled and has class `operational`. It runs `lpac profile enable <iccid> 1`: the refresh flag makes the card tell the modem to reload the SIM. The router's mobile data then drops while the modem attaches with the new profile (20–45 s in testing); Wi-Fi and the agent API stay up. The firmware picks the APN from its ICCID list. For five minutes after a switch the no-service policy and the connection watchdog treat the router as busy and do not act.

ICCIDs and the EID are digit strings longer than 64-bit integers can hold: clients must keep them as strings.

## Tested

Card details, setup and limits for the tested card: [docs/9esim-b1.md](../../docs/9esim-b1.md).

U60 Pro (B27), 9eSIM B1 (eUICC firmware 4.2.0, SGP.22 2.2.2), three operator profiles, 2026-10-18:

- `chip info` and `profile list` left the connection untouched (about 0.3 s and 30 ms of CPU each; lpac peaks at about 10 MB RAM and exits).
- Switching Smart → GOMO took 25 s to internet and GOMO → DITO 43 s, each with one firmware radio restart and no reboot.
- With the reload handling (2026-10-18 21:40): Smart → DITO, list read at 3.5 s answered from the saved list (`updating`), card and modem confirmed at 6.6 s, data at 31 s. DITO → Smart: the card stayed unreadable for about 25 s (three `euicc_init` failures in the background re-read), reads at 3.5 s and 12.7 s still got the saved list and no error, modem confirmed at 28 s, data at 43 s.
- Delete and download were exercised only on their refusal and failure paths: the active profile is refused, a download to an unresolvable server fails at `es9p_initiate_authentication`, and a download to an unresponsive address is cancelled within 16 s. (A real download followed on 2026-10-19; see below.)

Agent `esim-8`, 2026-10-19:

- **Operator receipts.** The switching tests had left 35 enable/disable receipts on the card for three servers (`glo.prod.ondemandconnectivity.com`, `sci.prod.ondemandconnectivity.com`, `rsp-0001.linksfield.net`). The first attempt failed on TLS (the bundle didn't yet trust the GSMA root). After the fix, `POST /api/esim/notifications/process` delivered all 35 in 76 s (about 2 s each); the count went to 0 and the retry loop stopped.
- **Rename.** Setting "Test" on DITO, reading it back and clearing it worked; `generation` went up each time; a 65-byte name was refused.
- **Shared lock.** While a manual `flock -n /tmp/lpac.lock` held the lock, `chip` answered busy and `profiles` served the saved list (`updating`, `stale`); after release, `chip` worked again.
- **Download pre-check.** The start reply carried `free_nvm_bytes` (971752); a download to an unresolvable server failed safely; `DELETE /api/esim/download` cleared the result.
- **Build info.** `chip` reported the bundle's BUILDINFO (lpac commit, patch, Alpine pins, CA file SHA-256, build time) and the lpac checksum.
- **Receipts after switching** (agent `esim-11`, switches made in the app). Smart → GOMO: modem confirmed at 6 s, data at 21 s. At 26 s the Smart disable receipt was sent and the GOMO enable receipt failed at once (`SSL connect error`); the second try at 60 s sent it. On the earlier DITO → Smart switch, the first request also failed: it hung until the 45 s limit. In both cases the request right after it went through, so the first request after the attach is unreliable and the second try is needed.
- **Download against a real SM-DP+** (agent `esim-11`). A deliberately unknown matching ID on Globe's server (`glo.prod.ondemandconnectivity.com`) ran `es9p_initiate_authentication` (verified TLS), `es10b_authenticate_server` (the card accepted the server's GSMA certificate chain and signed) and `es9p_authenticate_client`. The server answered "The matchingID is not found"; lpac cancelled the session, and the download ended `failed` 6 s after it started. Nothing was installed and no receipt was created. 
- **Real download** (agent `esim-12`, from the iOS app). The test used a Klook travel eSIM QR code. The preview showed provider "Travel - PHL" and name "Klook_app" 4 s after the start; the user confirmed 9 s later. `es10b_load_bound_profile_package` took 16 s, and the whole download took 31 s. The profile was installed disabled, using about 36 KB of card storage (free space 971752 → 934475 bytes). The install receipt reached the operator right after (`operator_notified: true`), and the other profiles and the active connection were untouched. Renaming from the app worked on all three existing profiles.
- **Travel eSIM** (Klook, a Singapore-issued profile, MCC 525, that roams on Globe and Smart). The switch reached `modem_confirmed` at 5 s and ended `no_data` at 150 s. The router had data roaming off, and while roaming is blocked the firmware also turns mobile data off (`enable: 0`). The iOS app's Data Roaming save then re-sent that off value, so data stayed off even with roaming on; fixed in the app, which now turns mobile data on together with roaming. With roaming and mobile data on, the profile connected within 3 s using the provider's APN (`e-ideas`, entered in the app), and the retry loop delivered both receipts. The agent now reports `reason: roaming_off` for this case.
- **Busy card** (2026-10-19, Klook travel profile enabled). Three switches to DITO within about two minutes ended `not_applied`: lpac reported `es10c_enable_profile: unknown`, so the card answered with a code other than 1–4. An enable about two minutes later was accepted (`BF31 03 80 01 00`, result 0). DITO's modem identity was confirmed at 12 s and data at 28 s. The refusal code wasn't captured. Confirmed on the next switch away from Klook (to GOMO, agent `esim-14`): the patched lpac reported `es10c_enable_profile: cat busy` (SGP.22 `catBusy`). The agent retried every 10 s, and attempt 13 was accepted 2 min 3 s after the first. GOMO's card and modem were confirmed 5 s later, and data followed. Both busy spells lasted about two minutes from the first attempt, so the retry window is 240 s.
- **Not exercised live:** the airplane-mode refusal (the modem stayed ONLINE) and the card-swap check (one card).
