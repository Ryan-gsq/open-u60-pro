# Direct Apple Live Activity pushes

The agent can send signal readings directly to APNs. No hosted relay, curl,
OpenSSL command, or modem firmware upgrade is required. Disabled by default.
The iOS app includes an ActivityKit registration manager and a WidgetKit Live
Activity extension. Start a session from Dashboard → Live signal after logging
into the modem. The activity shows LTE/NR bars, RSRP, SINR, sample age, and stale
state on the Lock Screen and Dynamic Island. Sessions register for one hour;
Stop ends the activity locally and removes the modem registration. Apple controls
actual delivery timing, so the configured 15-second send interval is not a
display-refresh guarantee.

## Files and Apple account information needed

1. **Apple APNs signing key (`AuthKey_<KEY_ID>.p8`)**: download from the Apple
   Developer account's Keys section, with APNs permission for this app/environment.
   This is an ES256/P-256 private key in PKCS#8 PEM format, not a firmware file or
   provisioning profile. Apple only offers the private-key download once.
2. **Key ID** and **Team ID**, both 10 characters, from that account.
3. **App bundle identifier**: the containing iOS app's identifier, not the widget
   extension identifier. It must belong to the team authorized by the key.
4. **Private JSON configuration**, based on `config/live-activity.example.json`.
5. **ActivityKit update push token**: generated at runtime by the iOS app for a
   particular Live Activity. Not the ordinary notification device token and not
   a push-to-start token. It is registered over the authenticated agent API and
   kept only in RAM, never placed in the config or repository.

An Apple Developer account with the required push capability/signing setup is
necessary. The app needs Push Notifications entitlement, Live Activities support,
matching ContentState (below), and `pushType: .token` when starting its activity.
A development build normally uses `sandbox`; TestFlight/App Store use `production`.
The configured environment must match the installed app's APNs entitlement.

Do not upload the .p8 key to Git or share a project-wide private key with users.
Each self-hosting developer provisions credentials authorized for their own app.
Root on the modem can read the key; root-owned 0600 permissions do not protect it
from another root user. Prefer an app-scoped Apple key where available.

## Device configuration (not installed automatically)

Use SSH/SCP to provision secrets on the trusted device, not the web API:

```sh
mkdir -p /data/zte-agent-apns
chmod 700 /data/zte-agent-apns
# Copy your key and edited JSON into this directory using SCP over SSH port 2222.
chmod 600 /data/zte-agent-apns/AuthKey.p8
chmod 600 /data/zte-agent-apns/live-activity.private.json
```

Set `enabled` to true only after editing the identifiers and key path. The agent
rejects symlink/non-regular files, files larger than 16 KiB, files owned by another
user, and group/world permissions. Keep the parent directory private too.

Add this environment variable to the existing agent launch script, preserving all
of its other settings:

```sh
export ZTE_AGENT_LIVE_ACTIVITY_CONFIG=/data/zte-agent-apns/live-activity.private.json
```

An agent restart loads config/key changes. A modem reboot is unnecessary. The
agent must have `ZTE_AGENT_PASSWORD` configured; push endpoints refuse access when
no password is set and the background worker will not start. Credentials cannot
be uploaded or read through this API. Neither this change nor the example enables
anything on an existing modem automatically.

## iOS API contract

All routes require the existing agent bearer authentication. The current agent
API is HTTP on local Wi-Fi: use a trusted LAN or an encrypted tunnel for tokens.
Do not expose port 9090 publicly.

- `GET /api/live-activity`: enabled/registered state, expiry, send interval,
  last APNs acceptance time, and a sanitized error. No token or private key returned.
- `PUT /api/live-activity`: register or replace the one active session:
  `{"push_token":"<hex ActivityKit update token>","expires_at":<Unix seconds>}`.
  Expiry must be in the future and within 8 hours; choose the remaining activity
  lifetime, not a fresh 8 hours each time the token rotates.
- `DELETE /api/live-activity`: stops future sends; it does not dismiss the iOS UI.
  The iOS app must also end the activity through ActivityKit. One already in-flight
  push can still arrive after cancellation.

Observe `pushTokenUpdates` and register replacements. Stop registration when the
activity ends. Agent restarts lose registration; re-register on reconnect. A second
phone replaces the first in this initial implementation. The agent sends updates
only; it does not remotely start or end activities.

The iOS ContentState must decode these exact fields:

```swift
struct ContentState: Codable, Hashable {
    var schemaVersion: Int
    var sampledAt: UInt64 // Unix seconds, conservative start of agent read
    var lteRsrp: Double?
    var nrRsrp: Double?
    var lteBars: Int?
    var nrBars: Int?
    var lteSinr: Double?
    var nrSinr: Double?
}
```

Null means unknown/unavailable, distinct from a valid 0-bar signal. Bars currently
match the app's RSRP helper: >= -80:4, >= -90:3, >= -100:2, >= -110:1, below:0.
These are app display thresholds, not proof of ZTE's official quality grade.
LTE and NR are kept separate. The values come from the existing read-only
`zte_nwinfo_api.nwinfo_get_netinfo` source, which may itself cache modem readings;
`sampledAt` is not a hardware measurement timestamp or proof of network attachment.
No SIM identifier, IP address, or entire raw netinfo response is sent to Apple.

## Refresh and failure behavior

The worker reads signal immediately before each scheduled push, rather than
polling each second and discarding the intermediate readings. Default interval is
15 seconds (configurable 15–3600), stale-date is 30 seconds. These are send targets,
not guarantees of iOS delivery or rendering. Show sample age and ActivityKit stale
state on iOS; an unchanged signal value can still be freshly read.

Uses persistent HTTP/2 with TLS certificate verification, embedded CA roots,
ES256 provider JWT reused for up to 50 minutes, configurable priority (5 by
default), and expiration bounded by sample freshness and session expiry. Only
the latest queued sample is retained. No redirects or environment proxy forwarding. Requests
have 5-second connect / 10-second total timeouts. Temporary transport, 429 and 5xx
failures back off exponentially to at most one hour; no historical reading queue.
A failed signal read never becomes a new successful sample. Token/config/payload
rejections stop that registration and expose a sanitized error; correct the issue
and register again. Accurate device UTC is needed for TLS, JWT and sample age.

`last_accepted_at` means Apple accepted a request, NOT that the iPhone displayed it.
Without credentials and a matching iOS Live Activity, only local tests/builds can
be verified. Actual Apple delivery, background timing and modem resource use need
an end-to-end device test. Both modem and iPhone need internet for this path.

## References

- https://developer.apple.com/documentation/activitykit/starting-and-updating-live-activities-with-activitykit-push-notifications
- https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns

## OpenU60 development signing identity

On September 15, 2026, `com.jesthersilvestre.openu60` was registered with Push
Notifications selected. The old `com.openu60.app` identifier was unavailable.
Use the containing-app identifier in the agent configuration. An APNs key was
created for Sandbox with Topic Specific access to this app; its private `.p8`
file is kept outside this repository. If you build your own copy, register your
own bundle ID and APNs key and put your team ID, key ID and bundle ID in
`live-activity.private.json` (see `config/live-activity.example.json`).
The on-device provider is enabled, and physical iPhone registration and delivery
have been tested. SIM-swap testing also exposed a phone-side connection stall
that required a Wi-Fi reconnect; Apple acceptance alone does not verify delivery.
See the [SIM-swap findings](sim-swap-ubus-2026-09-15.md).
The iOS project and install script now use the new bundle ID. This installs as a
separate app from the old bundle ID; existing app-container data does not migrate
automatically. The existing Keychain service label is intentionally unchanged.

On September 15, 2026, the signed iOS build and embedded extension passed Xcode
validation and were installed on the physical iPhone 15 Pro Max. The containing
app uses the push-enabled OpenU60 iPhone 15 Development profile; the extension
uses the existing team wildcard development profile. An end-to-end APNs test
requires starting Live signal on the phone and checking last_accepted_at.

Physical-device follow-up: the iPhone registered its ActivityKit token and the
modem reported a non-null last_accepted_at with no APNs error. This confirms
Apple accepted an update, not that every update rendered. The active configuration
is 15 seconds between completed sends, with a 30-second stale deadline. The
expanded island now uses a padded bottom-region layout and dims stale metrics.

### Delivery diagnostics and priority

`push_priority` accepts 5 (default, opportunistic) or 10 (immediate delivery
request, subject to Apple’s budget). The September 15 physical-device diagnostic
uses 10 at a 15-second interval; this does not guarantee sustained 15-second
background rendering. APNs expiration is bounded by the sample stale deadline
and session expiry, with a collapse ID so only the latest queued reading matters.
The dashboard observes ActivityKit content updates and shows Phone sample time
separately from APNs acceptance. The age timer is keyed to the sample timestamp.

Device logs with priority 10 confirmed three successive widget renders at
16:38:07, 16:38:22, and 16:38:38 (Asia/Manila), each carrying a newer modem
sample timestamp. With priority 5 earlier, a newly started activity received
its initial update but then stopped receiving pushes despite continued APNs
acceptance. This supports a delivery scheduling issue; long-duration budget
behavior remains unverified. Both priority and bounded expiration changed in
the diagnostic, so this is not a priority-only isolated comparison.

### Offline CPU safeguards (September 15, 2026)

The APNs worker uses a condition variable: it sleeps until the next attempt or
registration change, and waits indefinitely with no active session. It performs
no extra internet probes, modem reads, or JWT signatures during backoff. At the
15-second normal interval, failures wait 30, 60, 120, 240, 480, 960, 1920, then
3600 seconds. A successful send restores normal cadence; connectivity recovery
is detected on the next attempt, not instantly. Expired sessions stop retrying.
Repeated registration of the same token preserves the delay and error history;
new tokens wake the worker. Slow/expired signal reads also take the retry path.
Requests retain 5-second connection and 10-second total timeouts.

Validation: 28 host tests passed; all 13 Live Activity tests passed in an isolated
process on the U60 Pro, including a refused local connection and idle/wake tests.
The Linux thread CPU clock measured 60 microseconds during a two-second backoff
wait (0.003% of one core). This measures the waiting scheduler, not the whole
agent or the brief CPU cost of DNS/TLS/retry attempts. The modem's actual internet
connection was not interrupted. Strict Clippy still reports 12 existing issues
outside live_activity.rs. Deployed with rollback at
`/data/local/tmp/apns-offline-backup-1789462213`.

### Mode-aware iOS layout

Optional `networkType` and `lteCarrierCount` fields extend the existing payload
without changing the existing signal fields. Both initial iOS state and agent
pushes parse the reported LTE carrier list, reject malformed records, and count
unique PCI/band/channel tuples. This is reported aggregation, not proof of
simultaneous traffic on every carrier. SINR remains the modem's per-technology
reading, not a strongest-carrier calculation.

The expanded center shows mode and sample age. LTE/4G+ show only active LTE
measurements, NSA shows LTE plus NR, and SA shows only NR. The compact layout
keeps 4G on the left and 5G on the right with a dash for an inactive technology.
Explicit no-service and unrecognized modes suppress residual measurements;
missing mode from an older agent shows Mode unknown. The UI does not infer NSA
from cached NR RSRP while firmware explicitly reports LTE. The camera area in
the compact island cannot contain app content.

Validation: 29 Rust tests, 12 Swift mode classification cases plus visibility
checks, and the signed iOS build passed. Live device was reporting LTE-NSA with
two LTE carriers during inspection. SA/LTE transitions were tested with fixtures,
not by interrupting the modem's serving network.

Single-radio layout follow-up: in SA, the left slot shows NR SINR (5G quality)
and the right shows NR bars/RSRP; in LTE/4G+, the left shows LTE bars/RSRP and
the right shows LTE SINR (LTE quality). Compact slots follow the same rule.
NSA retains both radio panels including their respective SINR. Missing SINR is
explicitly unavailable rather than inferred, rated, or replaced with old data.
This is an iOS-only change using the existing payload.

The provider currently stores one activity token, not a broadcast channel or
multi-phone registry. Last registration wins, including foreground resumption
on another phone. DELETE is global to that single registration. Multi-phone
support requires separate per-activity registration and removal before multiple
phones can reliably receive simultaneous updates.
