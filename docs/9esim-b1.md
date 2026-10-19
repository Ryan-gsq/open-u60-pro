# 9eSIM B1 in the ZTE U60 Pro

The U60 Pro has no built-in eSIM, only a nano-SIM slot. A **9eSIM B1** is a removable eSIM card in normal SIM form: it holds several operator eSIM profiles, and the router uses whichever one is enabled. With the card in the slot, zte-agent can list the profiles, switch between them, download new ones from an operator's QR code and delete them, all from the OpenU60 app. This is the card the eSIM feature was built and tested with.

Product page: [9esim.com/en/shop/9esim-b1](https://www.9esim.com/en/shop/9esim-b1). The B1 also has Bluetooth, used by the vendor's 9eSIM phone app. OpenU60 does not use Bluetooth; the router manages the card directly through the modem.

## How it works

```
OpenU60 app ──Wi‑Fi──▶ zte-agent ──QMI over QRTR──▶ modem ──▶ 9eSIM B1 (eUICC)
                            └──HTTPS (router's own data)──▶ operator's SM-DP+ (downloads, receipts)
```

zte-agent is the GSMA SGP.22 LPA, the software phones use to manage eSIMs. Its card code is a Rust translation of the open-source [lpac](https://github.com/estkme-group/lpac)'s library. It talks to the card's management application (ISD-R) through the modem's SIM service; nothing else needs installing on the router. The card's SIM Toolkit menu ("LPAe Menu") is not used; see [Limits](#limits).

## Tested card and setup

| Item | Value |
|---|---|
| Card | 9eSIM B1 |
| eUICC firmware | 4.2.0 |
| SGP.22 (RSP) version | 2.2.2 |
| Profile package version | 2.3.1 (protection profile 1.0.0, GlobalPlatform 2.3.0, ETSI TS 102 241 9.2.0) |
| Free storage | about 950 KB with three profiles installed; a travel profile took about 36 KB |
| Capabilities | USIM, ISIM, CSIM; Milenage and TUAK; additional profiles and test profiles |
| Management application | Default ISD-R AID (`A0000005591010FFFFFFFF8900000100`), no override needed |
| Trusted root CI | One: GSMA RSP2 Root CI1 (key ID `81370f51…5bebfb`), for both verification and signing. Operators' servers use TLS certificates from this root, so the agent trusts it ([certificates](../zte-agent/certs/README.md)) |
| SIM Toolkit | Offers one menu item, "LPAe Menu" (the card's built-in profile switcher) |
| Router | ZTE U60 Pro (MU5250), firmware `CN_ZTE_MU5250V1.0.0B27` |
| Card access | QMI over QRTR, QRTR node 3, SIM slot 1 (tests up to 2026-10-19 used lpac commit `c7c8d4f`; the agent's own code gave the same results) |
| Profiles | Three Philippine operator profiles (Smart, Globe/GOMO, DITO) |

## Set it up

1. **Put at least one working profile on the card first**, for example with the 9eSIM phone app over Bluetooth. Downloading through the router needs the router's own mobile data, which needs a working profile.
2. **Switch the router off, insert the card into the SIM slot, switch it on.** The router uses the enabled profile like a normal SIM. The firmware picks the APN from its built-in list (Smart → `smartbro`, Globe/GOMO → `homebroadband.globe.com.ph`, DITO → `internet.dito.ph`).
3. **Install zte-agent with an agent password** (see the main [README](../README.md#quick-start)). Switching, downloading and deleting are refused without one.
4. **In the app:** Router → eSIM Profiles.

## What works

| Feature | Status |
|---|---|
| List profiles, card info | Works; about 0.3 s, no effect on the connection |
| Switch profile | Works; over 20 switches between the three profiles on 2026-10-18, no reboot needed |
| Switch verification | Works; the agent confirms card → modem identity → data connection (`GET /api/esim/switch`) |
| Download from QR (with preview and cancel) | Works; a Klook travel eSIM installed from the app on 2026-10-19 (preview, confirm, 31 s in total, about 36 KB of card storage, install receipt delivered) |
| Delete profile | Works; the Klook travel profile was deleted and re-added from its QR code on 2026-10-19 (delete receipt delivered 2 s after the delete). The active profile and unknown profiles are refused. Many operators' QR codes are single-use, so a deleted profile may not download again: Klook's did, though its FAQ says a used eSIM can't be restored |
| Rename (nickname) | Works; set, read back and cleared on the router on 2026-10-19 |
| Operator receipts | Works; 35 receipts left by the switching tests were delivered to three operator servers in 76 s on 2026-10-19 |

## What to expect when switching

The card switches immediately, then the modem reloads the SIM. Times measured on the tested setup:

| After the switch | What happens |
|---|---|
| 0 s | The card enables the new profile and tells the modem to reload the SIM |
| ~1–8 s | The modem reloads the SIM, the firmware restarts the radio once and selects the APN |
| 5–25 s | The card's management application can't be reached (`euicc_init`, QMI error 80 `SimFileNotFound`). The agent answers profile reads from its last good list during this time. |
| 6–28 s | The agent confirms the card and the modem's new identity |
| 15–45 s | Mobile data is connected on the new profile; Wi‑Fi and the app's connection to the router stay up throughout |

If the new profile has no data (no load, expired, no coverage), the switch still completes: the agent reports `no_data` and does not switch back by itself. Switch back from the app; that works without internet because it all happens on the router.

## Limits

- **SIM Toolkit menu.** The modem caches the card's "LPAe Menu" but doesn't forward SIM Toolkit screens to the agent, so the menu can't be used from the app. The agent does everything that menu does, and more, without it.
- **Bluetooth.** The vendor app can still manage the card over Bluetooth while it sits in the router. It is independent of OpenU60 and was not tested inside the router.
- **Power draw.** The card's supply voltage and current in the U60's slot were not measured. It worked throughout testing (more than 20 switches over about 8 hours); see the [inspection notes](research/U60_Pro_9eSIM_B1_SSH_Findings.md).
- **Travel eSIMs.** A travel profile is issued in another country, so in your country it always roams: turn on **Data Roaming** in Router → Mobile Network, and enter the provider's APN if the router doesn't pick it (a Klook profile tested on 2026-10-19 needed `e-ideas`, PAP). Switch back to a local profile from the app at any time; this works without internet. With the Klook profile enabled, the card refused switching away for about two minutes (SGP.22 `catBusy`: its SIM Toolkit was busy). The router keeps retrying for up to 4 minutes, and the app shows that it's retrying.
- **Other eSIM cards.** Any SGP.22 eUICC in the slot should work the same way, including models without a SIM Toolkit menu, since the agent doesn't use it. Only the 9eSIM B1 has been tested.

More detail: [zte-agent/docs/esim.md](../zte-agent/docs/esim.md) (API and agent behaviour), [docs/research/](research/) (investigation notes).
