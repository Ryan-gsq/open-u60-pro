# OpenU60 — eSIM Profiles: mobile UI brief (design + implementation)

## What it is
OpenU60 is the companion app (iOS SwiftUI + Android Jetpack Compose) for a ZTE U60 Pro 5G pocket router. The router can hold a multi-profile eSIM card in its SIM slot (e.g. a 9eSIM B1). The **eSIM Profiles** screen manages the operator profiles on that card:

1. **List** profiles and card info
2. **Switch** (select) the active profile
3. **Add** a profile — scan the operator's eSIM QR code (or paste the code), preview, confirm, download
4. **Remove** a profile

Everything runs on the router (its agent is the eSIM manager); the phone only talks to the router agent over the router's Wi-Fi. There is **no Bluetooth** flow (the old "9eSIM B1 Bluetooth" screen was removed — do not design one).

The router side is finished and live-tested. This brief covers the mobile UI.

## Where it lives / what exists
- Router Settings → section **Cellular** → row **eSIM Profiles** (below "SIM Card").
- iOS: `mobile/ios/OpenU60/Features/RouterSettings/SIM/ESim/` — `RouterESimView`, `RouterESimViewModel`, `RouterESimModels` (+ test `mobile/ios/Tests/RouterESimTests.swift`, run `sh scripts/test-router-esim.sh`).
- Android: `.../feature/router/esim/RouterESimScreen.kt`, `RouterESimViewModel.kt`; models `core/model/RouterESimModels.kt` (+ test `core/model/RouterESimParserTest.kt`).
- Existing screens implement **list + switch** as a functional placeholder (plain list, confirmation dialog). Redesign freely; add **add/QR** and **remove**.
- **Android pitfall:** `AgentClient.getJSON()` converts digit-only strings to numbers, corrupting 19–20 digit ICCIDs and the 32-digit EID. Decode eSIM responses with the typed `agentClient.get<T>()` + `@Serializable` classes (already done for list/chip). iOS `JSONSerialization` is fine.

## Router API (all need the agent bearer token; envelope `{ "ok": true, "data": … }` or `{ "ok": false, "error": "text" }`)

| Method | Path | Body → data |
|---|---|---|
| GET | `/api/esim/profiles` | → `{ enabled_iccid, profiles: [{ iccid, isdp_aid, state: "enabled"/"disabled", nickname, provider, name, class }] }` (~0.3–3 s) |
| POST | `/api/esim/nickname` | `{ iccid, nickname }` → `{ iccid, nickname, generation }`. Up to 64 bytes; empty clears it |
| GET | `/api/esim/notifications` | → `{ count, pending: [{ seq, operation, address, attempts, last_error, gave_up }], retrying, … }` — operator receipts waiting on the card |
| POST | `/api/esim/notifications/process` | → 202. Sends waiting receipts now; the router also retries every 10 min |
| GET | `/api/esim/switch` | → `{ state, target_iccid, previous_iccid, generation, started_at, card_confirmed_at, modem_confirmed_at, connected_at, finished_at, note }` — verified progress of the last switch |
| GET | `/api/esim/chip` | → `{ eid, firmware, sgp22_version, profile_version, free_nvm_bytes, free_ram_bytes }` |
| POST | `/api/esim/enable` | `{ iccid }` → `{ enabled_iccid, previous_iccid, reconnecting: true }` |
| POST | `/api/esim/delete` | `{ iccid }` → `{ deleted_iccid, operator_notified }` |
| POST | `/api/esim/download` | `{ activation_code, confirmation_code?, preview?: true }` → **202**, `DownloadStatus` (runs in background) |
| GET | `/api/esim/download` | → `DownloadStatus` |
| POST | `/api/esim/download/confirm` | `{ accept: true/false }` → `DownloadStatus` (only while `state == "confirm"`) |
| POST | `/api/esim/download/cancel` | → `DownloadStatus` (while `running`/`confirm`) |
| DELETE | `/api/esim/download` | → `DownloadStatus` (`idle`). Dismisses a finished result; call it when the user closes the result card |

`DownloadStatus` = `{ state, step, provider, name, iccid, error, started_at, finished_at }`
- `state`: `idle` · `running` · `confirm` (waiting for the user to approve the profile) · `cancelling` · `done` · `failed` · `cancelled`
- `provider` / `name`: operator and profile name, filled in once the operator's server has sent them (before `confirm`).
- `iccid`: the new profile, when `done`.
- A finished result (`done`/`failed`/`cancelled`) is reported for **10 minutes** after `finished_at`, then the status reads `idle`. Only show a result card for a download the user started (or one that finished within those 10 minutes), and dismiss it with `DELETE /api/esim/download` when closed.
- `error`: reason when `failed`/`cancelled` (e.g. "declined", "not confirmed within 2 minutes", "cancelled", or the operator/card error text).

HTTP errors to surface (show the `error` text): **400** invalid input (bad QR/code, missing confirmation code) · **403** "agent password required" (enable/delete/download need the router agent password set) · **404** profile not on the card · **409** busy ("eSIM manager busy; retry shortly" — one eSIM operation at a time; also wrong state) · **502** card/operator error · **503** eSIM manager not installed on the router.

Only one eSIM operation runs at a time. While a download runs, list/switch/delete return 409 — disable those actions in the UI and refresh when the download ends.

## Flows

### List
Load profiles, then chip info (sequentially). Active profile clearly marked. Show card info (EID masked by default with reveal/copy, firmware, free memory). Pull-to-refresh / refresh button.

### Reading the list during and after a switch (agent behaviour since esim-6)
- `GET /api/esim/profiles` also returns `observed_at`, `generation`, `agent_instance`, `updating`, `stale` and `error` (`{kind, message, at}`; kind `sim_reloading` / `management_unavailable` / `read_failed` / `busy` / `not_configured`).
- While a switch reloads the SIM (5–60 s) the agent answers from its last good list with `updating: true` and never touches the card, so the old "Could not read eSIM profiles: euicc_init … SimFileNotFound" error no longer appears for that window. Show such a list as "updating…", with the switch target as pending.
- A failed read still returns the last good list (`stale: true`) plus `error`: show the list as "last read <time>" with the error scoped to the list. **Clear the list error only when a newer response has `error: null`** — never because the network connected.
- Ignore any response whose (`agent_instance`, `generation`, `observed_at`) is older than what is on screen.
- Do not read the list on a fixed timer after a switch; follow `GET /api/esim/switch` (`reloading` → `card_confirmed` → `modem_confirmed` → `connected`, or `no_data` / `modem_unconfirmed` / `card_unconfirmed` / `not_applied`) and re-read the list when it reaches `card_confirmed` or later.
- Enable, delete and download return 409 "the SIM is still reloading…" during that window; disable them while `updating` is true.
- "Try again" re-reads the list only; it never repeats a switch.

### Switch (select)
Tap a non-active profile → confirm: "Switch to GOMO? The router disconnects from Smart and connects with GOMO. Internet is down for about a minute; Wi-Fi stays on." → `POST /enable` → new active profile shows immediately; internet returns in **25–45 s** (measured). The app stays connected to the router throughout, so show a "Reconnecting…" state (optionally watch the router's connection status elsewhere in the app).

### Add (QR scan / paste) — new
1. Entry: "Add eSIM" button (e.g. toolbar "+" or a row at the bottom of the list).
2. Add screen/sheet with: **Scan QR code** (camera, primary), **Choose QR from Photos/Gallery**, **Enter code manually** (text field, paste supported).
3. QR content is an SGP.22 activation code: `LPA:1$<server>$<matching ID>` — optionally `$<OID>$1`, where a final `1` means the operator also gave a **confirmation code** (ask for it; numeric/text, ≤ 64 chars). Trim whitespace; accept lowercase `lpa:`. Reject anything else with "This QR code isn't an eSIM activation code." (the router validates again).
4. `POST /api/esim/download` with `{ activation_code, confirmation_code? }` (preview defaults on) → poll `GET /api/esim/download` every ~1 s.
5. Progress (map `step` to friendly text):
   - `starting`, `es10a_get_euicc_configured_addresses`, `es10b_get_euicc_challenge_and_info` → "Preparing eSIM…"
   - `es9p_initiate_authentication`, `es10b_authenticate_server`, `es9p_authenticate_client` → "Connecting to the operator…"
   - `es8p_metadata_parse` → "Reading profile details…"
   - state `confirm` → **confirmation**: "Install {provider} — {name}?" with Install / Cancel → `POST /download/confirm`. Auto-declined after 2 minutes.
   - `es10b_prepare_download`, `es9p_get_bound_profile_package` → "Downloading profile…"
   - `es10b_load_bound_profile_package` → "Installing on the eSIM…" (do not offer cancel here; it can't stop mid-install)
   - state `cancelling` / steps `*_cancel_session` → "Cancelling…"
6. `done` → success: "GOMO added." The new profile is **disabled**; offer **"Switch to it now"** (→ switch flow) or "Later". Refresh the list.
7. `failed` → show `error`, offer Try again (keep the code in memory only for this screen). `cancelled` → back to the add screen.
8. Cancel button while `running`/`confirm` → `POST /download/cancel` (stops within ~15 s).
- Requirements: the **router** needs internet for the download (the phone's own data doesn't matter). Typical duration 10–60 s plus the user's confirmation.
- **Activation codes are secrets** (single-use; whoever uses it first gets the profile): never log, persist or send them anywhere but the router; clear them after the flow.

### Remove — new
Only for **non-active** profiles (the router refuses to delete the active one: "switch to another profile before deleting the active one"). Entry: swipe-to-delete / context menu / detail screen "Delete". Strong destructive confirmation: "Delete GOMO permanently? This can't be undone — you'd need a new QR code from GOMO to get this eSIM back." → `POST /delete`. If `operator_notified` is false, optionally note that the operator will be informed on the next eSIM change (the router retries).

## QR scanning — implementation notes
- **iOS:** VisionKit `DataScannerViewController` (iOS 16+, `.barcode(symbologies: [.qr])`) with an AVFoundation `AVCaptureMetadataOutput` fallback for unsupported devices; Photos import via `PhotosPicker` + Vision `VNDetectBarcodesRequest`. Add `NSCameraUsageDescription`: "OpenU60 uses the camera to scan eSIM QR codes." (no photo-library permission needed with PhotosPicker).
- **Android:** CameraX + ML Kit barcode scanning (`com.google.mlkit:barcode-scanning`, QR only) — or the Google code scanner (`play-services-code-scanner`, no camera permission needed); gallery import via Photo Picker + ML Kit `InputImage.fromFilePath`. If using CameraX, request `android.permission.CAMERA` at runtime with a rationale.
- Stop the camera as soon as a valid `LPA:` code is read; haptic on success; torch toggle; viewfinder framing.
- Unit-test the activation-code parsing (valid, lowercase prefix, confirmation flag, garbage, whitespace).

### Rename and receipts (implemented)
- Rename: long-press (iOS) / ⋮ menu (Android) on any profile, including the active one → text field prefilled with the nickname; empty restores the operator's name.
- When `pending_receipts` > 0 on the profile list: a card "N operator receipts waiting" with **Send now**. Receipts tell the operator a profile was added/removed; the router retries on its own.
- Refusals to show as-is: 409 "the modem is in airplane / low-power mode…" (switch), 409 "the router has no mobile data connection…" (download), 409 "a different eSIM card is in the slot…" (then reload).

## States to design
Loading · list (active highlighted) · empty ("No profiles yet — add one with a QR code") · switching/reconnecting · add: scanner, manual entry, confirmation-code prompt, progress, profile confirmation, success (+ switch now), failure, cancelling · delete confirmation · busy (409) · not available (503 / not installed) · password required (403) · offline/unauthorized.

## Content guidelines
- Plain words: "eSIM", "profile", "active", "add", "switch", "delete". Avoid "eUICC", "ISD-P", "SM-DP+", "lpac", "SGP.22" in the UI (the server address may be shown small as "from smdp.example.com").
- Always warn that switching interrupts internet ~1 minute; deleting is permanent.
- Carrier names come from the card/operator; no hard-coded logos (initials or a generic SIM glyph).
- Identifiers (ICCID, EID) are private: hide or mask by default (e.g. "…1234").

## Platform notes
- iOS: SwiftUI, NavigationStack push; existing patterns: `List` sections, `.refreshable`, `.confirmationDialog`, sheets, overlay `ProgressView`; iOS 17+, light/dark.
- Android: Material 3 Compose, Scaffold + TopAppBar, Hilt view models, `AlertDialog`/bottom sheets.
- Keep both platforms functionally identical.

## Measured on the real router (U60 Pro + 9eSIM B1, 3 profiles: Smart, GOMO, DITO)
List/chip ~0.3 s · switch: internet back in 25 s (GOMO) / 43 s (DITO) · download cancel stops within ~16 s · eSIM actions cost ~30 ms CPU on the router, nothing when idle.
