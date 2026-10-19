# OpenU60 eSIM Profiles — UI handoff: new features

For the designer. The data, view-model logic and tests are done on both platforms. The current screens are **functional placeholders**: redesign the visuals freely, but keep the view-model API listed for each feature. The general eSIM brief (list, switch, add by QR, delete) is in `mobile/docs/esim-profiles-design-brief.md`.

**Code:**

| Platform | Location | Files |
|---|---|---|
| iOS | `mobile/ios/OpenU60/Features/RouterSettings/SIM/ESim/` | `RouterESimView.swift`, `RouterESimViewModel.swift`, `RouterESimModels.swift` |
| Android | `mobile/android/OpenU60/app/src/main/java/com/openu60/feature/router/esim/` | `RouterESimScreen.kt`, `RouterESimViewModel.kt` (`RouterESimState`) |
| Android models | `core/model/RouterESimModels.kt` | |

Tests: `sh scripts/test-router-esim.sh` (iOS) and `gradle testDebugUnitTest` (Android).

---

## 1. Verified switch progress

After the user confirms a switch, the router reports each stage. The app shows these; it no longer guesses.

| Router state | Screen phase | Meaning |
|---|---|---|
| `reloading` | `.reloading` / `RELOADING` | Card switched; modem is reloading the SIM. The card can't be read during this (5–25 s) |
| `card_confirmed`, `modem_confirmed` | `.registering` | Card shows the new profile; modem has loaded it; registering on the network |
| `connected` | `.connected` | Mobile data is up on the new profile (traffic can need a few more seconds) |
| `no_data` | `.waiting` + note | Profile active, but no data within 150 s (no load, no coverage) |
| `modem_unconfirmed` | `.waiting` + note | Card switched but the modem kept the old SIM → advise "Restart the router" |
| `card_unconfirmed` | `.waiting` + note | Card unreadable for 60 s after switching |
| `not_applied` | `.unavailable` + note | Switch didn't happen; previous profile still active |

Typical timing: internet back in **15–45 s**.

**View-model fields:**
- `connectionPhase`;
- `connectionNote` (the outcome text above, or nil);
- `switchingTo` (target display name).

**Steps UI:** the existing 3-step list ("Switch profile" → "Reload SIM" → "Connect to network") maps onto the phases above.

**Rules:**
- **Never offer an automatic switch back.** On `no_data`, let the user choose; a manual switch back works offline.
- While a switch runs, disable switch, delete, rename and add (`blocksSwitching`).
- Final copy should say "connected", not "internet works".
- Use a live region (Android) / accessibility announcement (iOS) on phase changes.

**Older agents** without this endpoint fall back automatically to the app's own reconnect tracking; no UI difference.

## 2. List freshness ("updating", "last read", errors)

**Updating** (`inventory.updating`) means the router is reloading the SIM or busy with another eSIM task. It is serving the last good list.
- Show a quiet "Updating…" marker near the list.
- Keep the switch target shown as active; the view model already prevents the old list from flipping it back.

**Read failed:** `listError` holds the text (nil when the list is current).
- The list stays visible; show the error **scoped to the list**, e.g. "Couldn't refresh profiles. *reason*. Showing the list read at 11:42."
- Error kinds and their copy:
  - `sim_reloading`: "The eSIM is still settling after the switch."
  - `management_unavailable`: "The eSIM's management app isn't responding."
  - otherwise: the raw message.
- The error clears **only** when a newer clean read arrives, never because the network connected.
- **Try again** re-reads the list only. It never repeats a switch.

**Not for the UI:** `generation`, `agent_instance` and `observed_at` are used inside the view model to ignore out-of-order answers. Don't display them.

## 3. Rename (nickname)

**Entry:** on any profile, including the active one.
- iOS: long-press context menu → "Rename".
- Android: the ⋮ menu → "Rename".
- Consider a more discoverable entry, such as a profile detail sheet.

**Field rules:**
- Prefilled with the current nickname; placeholder is the operator's profile name.
- At most **64 bytes** (UTF-8), trimmed, no line breaks.
- **Empty = remove the nickname**, so the operator's name shows again.
- Disable Save when over the limit.

**After saving:** the list reloads, then a confirmation shows ("Renamed to Travel" / "Nickname cleared").

**Errors to show as-is:**
- 403 "agent password required"
- 409 "a different eSIM card is in the slot…"
- 409 busy
- 409 "the SIM is still reloading…"

**View-model API:**

| Platform | Calls |
|---|---|
| iOS | `requestRename(profile)`, `renameText` (binding), `confirmRename(profile, to:)` (pass the profile from the dialog), `pendingRename` |
| Android | `requestRename`, `dismissRename`, `confirmRename(name)`, `state.pendingRename` |

## 4. Operator receipts

**What they are:** when a profile is added, enabled, disabled or deleted, the eSIM keeps a receipt (an SGP.22 notification) for the operator's server until it is delivered. The router sends them and retries every 10 minutes while it has mobile data. Some operators use them to activate or release a profile.

**When to show:** `pendingReceipts > 0` (null = unknown/older agent → show nothing).

**Current placeholder:** a card reading "N operator receipts waiting", with an explanation and **Send now**.
- Sending state: `receiptsSending`.
- Result message: "Operator receipts sent" or "Some receipts couldn't be sent yet. The router keeps retrying."

**Optional detail view.** `GET /api/esim/notifications` returns, for each receipt:
- `operation` (install / enable / disable / delete);
- `address` (operator server, e.g. `smdp.example.com`);
- `iccid`, `attempts`, `last_error`;
- `gave_up` (after 10 failures; still on the card, never deleted unsent).

It also returns `retrying`, `last_sent_at` and `last_attempt_at`. The view model currently exposes only the count; add a detail fetch if the design wants a list.

**Tone:** informational, not alarming. This is housekeeping, not an error.

**View-model API:** `sendReceipts()`, `pendingReceipts`, `receiptsSending`.

## 5. New refusals to surface (show the router's text; design a consistent "can't do that now" pattern)

| When | Router message (409 unless noted) | Suggested treatment |
|---|---|---|
| Switch while airplane / low-power mode is on | "the modem is in airplane / low-power mode; turn it back on before switching profiles" | Inline on the switch dialog / result, with a link to Mobile Network |
| Add (download) with no mobile data | "the router has no mobile data connection; downloads use the router's own internet" | On the add screen before scanning, if possible |
| Any change after the card was swapped | "a different eSIM card is in the slot; reload the profile list" | Reload the list automatically after showing it |
| During a switch's SIM reload | "the SIM is still reloading after the last switch; try again in a moment" | Usually prevented by disabled controls |
| Another eSIM task running | "eSIM manager busy; retry shortly" | Brief, retry |
| No agent password set | 403 "agent password required" | Point to agent settings |

The download start reply also includes `free_nvm_bytes` (free eSIM storage). It's optional to show, for example "Free space on eSIM: 949 KB" on the add screen.

## 6. Optional: card details

`GET /api/esim/chip` returns the card's EID, firmware, SGP.22 version and free memory. This is for an "About / diagnostics" row at most; not needed on the main screen. (It no longer reports an lpac build: the agent manages the card itself since 2026-10-19.)

---

## States to design (new)
- Switch progress: reloading → registering → connected.
- Switch outcomes: no data, modem not reloaded ("restart the router"), card unreadable, not applied.
- List: "updating" marker, scoped list error with last-read time, cleared state.
- Rename: field, over-limit, saving, success, error.
- Receipts: waiting count, sending, sent, still waiting / gave up (if a detail view is designed).
- Refusals from section 5.

## Platform notes
- **iOS (SwiftUI, iOS 17+):** keep each `body` small. The current view already had to split its content and dialogs because the compiler timed out type-checking one large expression. Existing building blocks: `CardView`, `.confirmationDialog`, `.alert` with `TextField`, `.contextMenu`, accessibility actions.
- **Android (Material 3 Compose):** `AlertDialog` with `OutlinedTextField`, `DropdownMenu` on ⋮, Cards. Use `liveRegion` for progress text.
- Keep both platforms functionally identical.
- **Identifiers:** never show full ICCIDs or EIDs by default (mask as "…1234"; the EID is revealed only on tap).
- **Testing against a router:** the test router runs an agent with all of these endpoints (switch status, freshness, receipts, rename, refusals). Against an older agent, rename and receipts return 404 and the UI hides them or fails gracefully.
