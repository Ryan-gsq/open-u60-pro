# 9eSIM B1 Bluetooth connection

The baseline is the user's working B1 installed in the ZTE U60 Pro. OpenU60 connects from the phone directly to the card's BLE endpoint. The Rust `zte-agent` continues to handle router HTTP operations; it is not a proxy for phone Bluetooth.

Open **Router → 9eSIM B1 Bluetooth** in either native mobile app. On iOS, the login screen also has a **9eSIM B1 Bluetooth** link, so BLE access does not require router login. Grant Bluetooth permissions, make the card discoverable using its documented procedure, scan, and select the device. Scanning, connection and service discovery each have a 20-second deadline. Scanning can be stopped while retaining the discovered devices for selection. Disconnect/cancel retires the session; scan again to reconnect. Leaving the screen or entering the background closes the connection. There is no automatic reconnect or background Bluetooth mode.

Nearby devices include unnamed devices and have no guessed B1 name/service filter. Explicit selection expresses the user's choice; it does not authenticate the device. Scan results are deduplicated by platform identifier and capped at 100. A new scan clears old observations. iOS uses CoreBluetooth identifiers; Android uses BLE addresses. Neither identifier is an authenticated B1 identity.

## Implemented behavior

- iOS: CoreBluetooth central, explicit privacy status with Settings recovery, radio status observations, repeated advertisement/RSSI updates, peripheral selection, service and characteristic discovery and native maximum-write-length observations.
- Android: runtime permissions, BLE availability and legacy location-service checks, `connectGatt` with `autoConnect=false`, service discovery, adapter power monitoring and GATT cleanup.
- Both: explicit connection states, bounded waits, cancellation, duplicate-tap guards, session generation checks and rejection of inventories for another device.
- Export: user-initiated GATT report containing device observations, service/characteristic UUIDs and properties, timestamp and explicit unresolved B1 contract fields.

The production Bluetooth state is **Bluetooth connected · B1 session unverified**. Native characteristic reads/writes, subscriptions, authorization messages and APDUs remain gated by the missing wire contract. The application-level eSIM controller and UI described below are implemented against an injectable adapter interface; the production default is `B1UnverifiedESimAdapter`, which sends no card commands. GATT discovery does not establish the B1 wire contract. The retained GATT report is labeled with the device and capture timestamp; it is not live state or a protocol definition.

## eSIM actions implemented in application code

Both native apps now have `B1ESimController`, typed card/profile/result models, a `B1ESimAdapter` interface, pending-notification storage and eSIM management screens. A verified adapter must authenticate/initialize the session and read the actual card EID and capabilities before the controller can become ready.

| Action | Controller behavior |
|---|---|
| List/display profiles | Reads card identity and profiles; validates unique nonempty ICCIDs; displays nickname, provider and enabled/disabled/unknown state. |
| Switch/enable | Pre-reads the list, checks the target, returns unchanged when already enabled, enables directly and verifies read-back. Never pre-disables the old profile. |
| Disable | Checks card capability/profile policy and verifies the disabled state. |
| Rename | Validates the app's nickname input budget of 1–128 UTF-8 bytes, trims it, writes it and verifies read-back. This budget is not a claimed B1 wire limit. |
| Remove | Offers a removal confirmation, checks capability/policy and verifies the ICCID is absent. An already absent profile is an idempotent no-op. |
| Add/download | Accepts an LPA activation code and optional confirmation code in memory; delegates provisioning to the verified adapter and verifies the installed ICCID. Never automatically enables or re-downloads a profile. |
| Export metadata | Saves an allowlisted JSON snapshot with EID, observation time and profile details. It is explicitly labeled `portable: false` and excludes provisioning credentials and profile keys. |
| Export transfer package | Requires an explicit adapter capability and copies the adapter's opaque bytes to a user-selected file. No package format, portability mechanism or B1 support is assumed. |
| Complete download notifications | Replays pending notification IDs for the matching EID without re-downloading profiles. |

One lock covers the entire async operation, including pre-read, mutation, recovery and read-back. Concurrent refreshes and mutations are blocked. An ambiguous mutation invalidates the session, calls the adapter's reconnect/reopen recovery once, checks the same EID and reads back state. It never blindly resends the mutation. Unresolved outcomes block further mutations until a refresh reconciles the card. Disconnect/background invalidates the generation; late results cannot overwrite another card's session.

The adapter publishes an installation receipt before subsequent notification/network work can fail or be canceled. Pending work is journaled by EID and notification ID, using atomic JSON file writes on iOS and checked SharedPreferences commits on Android. Provisioning credentials are not journaled. Failed saves retain records in memory and block new downloads. Notification failure preserves pending work and does not trigger reinstall; late receipts cannot recreate notifications already completed within the controller's lifetime. The adapter must make notification completion idempotent by ID.

These are unit-tested application flows, not verified live B1 commands. Filling in `B1ESimAdapter` requires the actual B1 wire contract and an eSIM provisioning/LPA implementation. The fake adapters exist only in unit tests; production does not display fake profiles or offer a mock-success mode.

Android declares BLE as optional so ordinary router features remain available on devices without it. It deliberately omits `neverForLocation` while the advertising contract is unresolved and requests precise location together with Nearby devices on modern Android. Legacy Android additionally checks location services. No scan or background location mode is requested outside the foreground screen.

## iOS foreground BLE setup

The iOS 17+ app includes `NSBluetoothAlwaysUsageDescription` in its checked-in Info.plist and explicitly links `CoreBluetooth.framework` through XcodeGen. Reading `CBManager.authorization` shows the current privacy decision without allocating a central. A central is created only after the user taps Scan. Denied/restricted access is explained in the screen, and the Settings action opens OpenU60's system settings. Authorization is refreshed when returning to the foreground.

During the 20-second foreground scan, duplicate advertisements are enabled to refresh RSSI and last-detected timestamps. Updates are limited to twice a second per device and retain the existing 100-device cap. The observed radio status is separate from permission and connection state. Scanning stops at its deadline and the whole session closes on screen exit or backgrounding, as requested. `UIBackgroundModes` is left without Bluetooth entries. BLE remains an optional feature, so `UIRequiredDeviceCapabilities` does not require `bluetooth-le` for installing this router companion app.

After generating/building the iOS project, run `python3 scripts/verify-ios-bluetooth-setup.py /path/to/OpenU60.app` to verify the compiled app's privacy description, foreground configuration and CoreBluetooth linkage. The source configuration is also checked by `scripts/test-b1-bluetooth.sh`. Live BLE sensing needs a physical iPhone; simulator builds validate code and UI integration.

## Protocol work remaining

The [repository evidence template](b1-protocol-evidence.json) leaves all B1-specific fields `null`. Null means unknown. Values in a discovered GATT report must not be automatically copied into a verified adapter.

Obtain the B1-specific SDK/documentation or an authorized session capture to establish discovery, service and characteristic UUIDs, write mode, authorization, initialization order, framing, fragmentation/acknowledgments, response correlation and session behavior. The existing working router arrangement does not require another compatibility test.

The native `B1BluetoothTransport` interfaces and controller are the connection boundary. Implement the native B1 protocol/LPA adapter behind `B1ESimAdapter` when its contract is established. The injectable factory is selected for a discovered GATT snapshot; the native implementation must bind to that live device/session, not infer support from UUIDs or names. Extend the native boundary with characteristic subscriptions and single-frame writes according to that contract, using actual native write limits/negotiated MTU. Never add generic frame splitting. Management readiness requires verified authorization, initialization and a valid card identity read.

The adapter implementation must serialize its individual transport/card commands, own only its logical channels, avoid an unverified basic-channel fallback, and implement the actual eSIM encodings and provisioning exchanges. The controller already locks whole operations and reconciles ambiguous results. Card state and router connectivity remain separate; every management result reports router outcome as `notVerified`.

## Code and verification

| Layer | iOS | Android |
|---|---|---|
| Controller/models | `Core/Bluetooth/B1BluetoothController.swift`, `B1BluetoothModels.swift` | `core/bluetooth/B1BluetoothController.kt`, `B1BluetoothModels.kt` |
| Native transport | `Core/Bluetooth/B1CoreBluetoothTransport.swift` | `core/bluetooth/AndroidB1BluetoothTransport.kt` |
| Screen | `Features/RouterSettings/SIM/B1/B1BluetoothView.swift` | `feature/router/sim/b1/B1BluetoothScreen.kt` |

Run `sh scripts/test-b1-bluetooth.sh` and `sh scripts/test-b1-esim.sh` from the repository root. Android regression tests run with `gradle :app:testDebugUnitTest`. Unit tests cover all application actions, unchanged/rejected/unknown outcomes, whole-operation serialization, ambiguous timeouts without resends, different-card recovery, stale results, interrupted installation receipts, notification persistence and replay, metadata credential exclusion, capability-gated transfer exports and invalid profile data. No Simulator, emulator or hardware session is needed for these tests. They do not claim physical B1 communication.

Device validation still needs the phone/card: grant/deny/revoke permission, Bluetooth off/on, scan stop, manual selection, connection/discovery, cancellation during connection, remote disconnect, background/foreground and report export. This is validation of the newly implemented phone connection, not router compatibility. Service discovery alone cannot validate authorization or profile management.

API references: [Android Bluetooth permissions](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions), [Android GATT connections](https://developer.android.com/develop/connectivity/bluetooth/ble/connect-gatt-server), [CoreBluetooth central manager](https://developer.apple.com/documentation/corebluetooth/cbcentralmanager).
