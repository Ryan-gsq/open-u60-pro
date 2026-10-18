# eSIM profiles (lpac)

The agent manages the profiles on an eSIM card in the router's SIM slot (for example a 9eSIM B1): list them, switch which one is enabled, download new ones from an activation code (the operator's QR code) and delete them. It does this with [lpac](https://github.com/estkme-group/lpac), the open-source GSMA SGP.22 LPA: card commands go over the modem's QMI UIM service (QMI over QRTR), downloads use HTTPS from the router's own connection. The SIM Toolkit menu is not used.

lpac is not built into the agent. Build the private bundle and install it on the router with the scripts in [`lpac-qrtr-build/`](../../lpac-qrtr-build/):

```sh
cd lpac-qrtr-build
./make-bundle.sh          # pinned, checksum-verified inputs → out/bundle
./install-to-router.sh    # → /data/lpac on root@192.168.0.1:2222 (previous copy kept as /data/lpac.old)
```

The agent refuses a bundle whose files are symlinks, owned by another user, or group/world-writable.

| Variable | Default | Meaning |
|---|---|---|
| `ZTE_AGENT_LPAC_DIR` | `/data/lpac` | Bundle directory |
| `ZTE_AGENT_LPAC_QRTR_NODE` | `3` | QRTR node of the modem's UIM service (`qrtr-lookup`, service 11) |
| `ZTE_AGENT_LPAC_UIM_SLOT` | `1` | SIM slot |

## API

All routes use the agent's bearer authentication and `{ok,data}` / `{ok:false,error}` envelopes. The agent runs one lpac command at a time (30 s limit for card commands, 300 s for a download); a request made while another is running gets 409. Enable, delete and download require an agent password (403 otherwise).

| Method | Path | Result |
|---|---|---|
| GET | `/api/esim/profiles` | `profiles`: `iccid`, `isdp_aid`, `state` (`enabled`/`disabled`), `nickname`, `provider`, `name`, `class`; plus `enabled_iccid`, `observed_at`, `generation`, `agent_instance`, `updating`, `stale`, `error` (see Reading during a switch) |
| GET | `/api/esim/chip` | `eid`, `firmware`, `sgp22_version`, `profile_version`, `free_nvm_bytes`, `free_ram_bytes` |
| POST | `/api/esim/enable` | Body `{"iccid": "..."}`. Returns `enabled_iccid`, `previous_iccid`, `reconnecting: true`, `generation`. If lpac fails or times out the reply carries `outcome: "unknown"`: the switch may still have happened, see `/api/esim/switch` |
| GET | `/api/esim/switch` | Last switch: `state`, `target_iccid`, `previous_iccid`, `generation`, `started_at`, `card_confirmed_at`, `modem_confirmed_at`, `connected_at`, `finished_at`, `note` |
| POST | `/api/esim/delete` | Body `{"iccid": "..."}`. Disabled profiles only. Returns `deleted_iccid`, `operator_notified` |
| POST | `/api/esim/download` | Body `{"activation_code": "LPA:1$...", "confirmation_code": "...", "preview": true}`. Starts a background download; 202 with the status below |
| GET | `/api/esim/download` | Status: `state` (`idle`, `running`, `confirm`, `cancelling`, `done`, `failed`, `cancelled`), `step` (last lpac progress step), `provider`, `name`, `iccid`, `error`, `started_at`, `finished_at` |
| POST | `/api/esim/download/confirm` | Body `{"accept": true}` or `false`, while `state` is `confirm` |
| POST | `/api/esim/download/cancel` | Cancels a running download |
| DELETE | `/api/esim/download` | Dismisses a finished result (status back to `idle`); 409 while a download runs |

### Download

The activation code must have the SGP.22 form `LPA:1$<server>$<matching ID>[$<OID>[$1]]`; a final `1` means the operator also issued a confirmation code, which the request must then include. The agent runs `lpac profile download -p -a <code> [-c <code>]` in a background thread. With preview on (the default), lpac stops once the operator's server has sent the profile metadata: the status moves to `confirm` with `provider` and `name` filled in, and lpac waits for the answer from `/download/confirm`. An unanswered preview is declined after 2 minutes. Cancel sends lpac SIGINT, which cancels the session with the card and the server at the next step; a step blocked on the network is killed after 15 s. A downloaded profile is disabled until it is enabled. A finished result (`done`, `failed`, `cancelled`) is reported for 10 minutes, then the status reads `idle`; the result is also lost when the agent restarts.

After a successful download or delete the agent runs `lpac notification process -a -r` once, which sends the install/delete receipts to the operators' servers. Without internet they stay on the card for the next attempt. Activation codes are never logged.

### Reading during a switch

For several seconds after `enable` (3–8 s in most switches, about 25 s in one test) the modem is reloading the SIM and the eUICC's management application cannot be selected: lpac fails in `euicc_init` with QMI error 80 (`SimFileNotFound`). The app saw this as "Could not read eSIM profiles" in 3 of 14 switches. The agent therefore:

- keeps the last good profile list. While a switch reloads the SIM, `GET /api/esim/profiles` answers from it with `updating: true` and does not start lpac. It does the same while another eSIM operation holds the card (instead of 409). A failed read returns the last good list with `stale: true` and `error: {kind, message, at}`. `kind` is `sim_reloading` (within 5 minutes of a switch), `management_unavailable`, `read_failed` or `not_installed`. A successful read clears the error;
- re-reads the card itself after the switch: from 5 s, every 3 s once `get_sim_info` reports the SIM ready, for up to 60 s;
- refuses enable, delete and download while the SIM reloads (409);
- numbers each change of the card's contents or selection (`generation`) and each agent run (`agent_instance`, start time in ms), so clients can drop answers older than what they have shown.

`GET /api/esim/switch` reports the verified outcome. `state` moves `reloading` → `card_confirmed` (fresh card read shows the target enabled) → `modem_confirmed` (`get_sim_info` `sim_iccid` equals the target) and ends as:

- `connected` (`get_wwaniface` `connect_status` connected);
- `no_data` (card and modem switched, no data within 150 s);
- `modem_unconfirmed` (the modem kept the old identity);
- `card_unconfirmed` (the card stayed unreadable for 60 s);
- `not_applied` (the card still has another profile enabled).

The agent never retries a switch or switches back by itself. "Connected" comes from the firmware; traffic can need a few more seconds.

### Switching

`enable` only accepts a profile that exists, is disabled and has class `operational`. It runs `lpac profile enable <iccid> 1`: the refresh flag makes the card tell the modem to reload the SIM. The router's mobile data then drops while the modem attaches with the new profile (20–45 s in testing); Wi-Fi and the agent API stay up. The firmware picks the APN from its ICCID list. For five minutes after a switch the no-service policy and the connection watchdog treat the router as busy and do not act.

ICCIDs and the EID are digit strings longer than 64-bit integers can hold: clients must keep them as strings.

## Tested

Card details, setup and limits for the tested card: [docs/9esim-b1.md](../../docs/9esim-b1.md).

U60 Pro (B27), 9eSIM B1 (eUICC firmware 4.2.0, SGP.22 2.2.2), three operator profiles, 2026-10-18:

- `chip info` and `profile list` left the connection untouched (about 0.3 s and 30 ms of CPU each; lpac peaks at about 10 MB RAM and exits).
- Switching Smart → GOMO took 25 s to internet and GOMO → DITO 43 s, each with one firmware radio restart and no reboot.
- With the reload handling (2026-10-18 21:40): Smart → DITO, list read at 3.5 s answered from the saved list (`updating`), card and modem confirmed at 6.6 s, data at 31 s. DITO → Smart: the card stayed unreadable for about 25 s (three `euicc_init` failures in the background re-read), reads at 3.5 s and 12.7 s still got the saved list and no error, modem confirmed at 28 s, data at 43 s.
- Delete and download were exercised only on their refusal and failure paths: the active profile is refused, a download to an unresolvable server fails at `es9p_initiate_authentication`, and a download to an unresponsive address is cancelled within 16 s. No profile has been deleted or downloaded on the router yet.

Renaming (nicknames) is not exposed.
