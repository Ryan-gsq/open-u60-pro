# Agent OTA updates

The U60 Pro agent can update itself without a Mac companion after one successful
`setup.sh` or `deploy.sh` bootstrap. Those scripts install the A/B slot layout
and the small boot supervisor. OTA restarts the agent only; it does not reboot
the router or intentionally interrupt Wi-Fi or cellular data.

For the first Beta hardware test, bootstrap the signed prerelease artifact rather
than an unsigned local development build:

```sh
ZTE_AGENT_DOWNLOAD_URL=https://github.com/jesther-ai/open-u60-pro/releases/download/v2.4.0-beta.1/zte-agent ./setup.sh
```

## Safety model

- Release metadata is signed with an offline P-256 key embedded in release
  builds. A checksum alone is not accepted.
- The manifest may reference only immutable release assets in
  `jesther-ai/open-u60-pro`, and downloads have strict size limits.
- The binary is streamed to the inactive slot, checked for its exact size and
  SHA-256 digest, made executable, and probed before installation is offered.
  A read that makes no progress for 30 seconds is stopped, the complete
  transfer has a five-minute budget, and partial files are removed immediately
  and again at startup.
- Install repeats the signed size, digest and compatibility checks. Damage to a
  staged binary or its metadata therefore cannot create a pending boot trial.
- Installation is blocked during a speed test, recent eSIM switch, voice call,
  USSD session, critically low unplugged battery, or another update operation.
- The supervisor observes the candidate for 60 seconds. A crash, an unavailable
  local listener, or a power loss before commit returns to the previous slot.
- At boot the supervisor verifies the stored size, SHA-256 digest and executable
  probe for every managed slot. It skips quarantined releases and can start the
  separately retained last Stable binary when neither A/B choice is safe.
- A fresh SSH/USB bootstrap seeds both slots and records a digest for each copy,
  so accidental corruption is detected before the first native OTA update.
- A failed version is quarantined so automatic checks do not repeatedly stage
  it. The last successful Stable build is also retained separately.
- Every modifying endpoint requires the configured agent password. Automatic
  checking is enabled by default; automatic download is opt-in; automatic
  installation is deliberately unsupported for now.

The download endpoint runs in the slow-work lane. A slow carrier or release
server does not consume the permits used by update status, the WebUI and normal
read-only API calls.

## Failure behavior

| Scenario | Result |
| --- | --- |
| Missing, malformed or incorrectly signed channel data | No binary is downloaded; the running agent is unchanged. |
| Slow or stalled download | A 30-second idle or five-minute total limit aborts it; partial files are deleted. |
| Truncated, oversized or wrong-hash payload | The inactive-slot download is rejected before staging. |
| Staged binary or metadata changes after download | Install preflight fails before writing a pending marker or stopping the agent. |
| Update-helper cannot start or confirm its handoff | The helper is stopped, the pending marker is cleared and the current agent keeps running. |
| Candidate cannot start, listen, or remain healthy | Once same-boot network cleanup (Tailscale kernel-TUN journal, pending Clean DNS DNAT flush, live `tailscaled`, performance tuning journal) and any strict `cellular-pause` restoration succeed and verify, the candidate is quarantined and the verified previous slot is restarted. If cleanup fails or cannot be verified, the supervisor stops with exit code `8` and retains `pending` rather than handing off to an older slot over live state it cannot undo. |
| Reboot or power loss during the trial | The unproven candidate is excluded and the verified previous slot is selected (still enforcing any surviving cross-boot `cellular-pause` restoration first). |
| Active slot is damaged at a later boot | The supervisor selects the other verified, non-quarantined slot once same-boot network cleanup and any `cellular-pause` restoration verify; if cleanup fails or cannot be verified, it stops with exit code `8` and keeps the recorded `active` slot. |
| Neither A/B slot is safe | The separately retained, verified last Stable copy is started without marking a broken A/B slot active (subject to the same cleanup verification gate before switching slots). |

There are two deliberate recovery boundaries:

1. **Failed or incomplete pre-handoff cleanup (exit code `8`)**: if the
   supervisor or OTA helper cannot finish and verify `network-recover` (for
   example, a surviving same-boot Tailscale journal `/data/tailscale/network.json`,
   pending Clean DNS flush marker `/data/tailscale/clean-dns-dnat-flush-pending`,
   running `tailscaled`, `/tmp/zte-agent-perf/network.json`, strict-relay
   `/data/zte-agent-relay/cellular-pause`, or an interrupted
   `/data/open-u60/update/network-recover-pending`), it deliberately exits `8`
   and keeps `pending` / `active` intact instead of starting an older binary
   that does not understand those journals. Over SSH or USB ADB:
   - Before running recovery, if `/data/zte-agent-relay/cellular-pause` exists,
     read and note its recorded original modem `enable` value (`0` or `1`),
     since `network-recover` removes that file once restoration succeeds.
   - Identify the binary that owns cleanup by checking
     `/data/open-u60/update/network-recover-pending`, `/data/open-u60/update/pending`
     (line 1 = candidate slot, line 2 = previous slot), and
     `/data/open-u60/update/active`:
     - First check line 1 of `network-recover-pending` against
       `/proc/sys/kernel/random/boot_id`. Only treat line 2 (`candidate`,
       `previous`, `stable`, `a`, or `b`) as an active cleanup owner when line 1
       matches the current boot (if the file is malformed/unreadable, fail closed
       and verify every journal, process, and Tailscale policy rule before
       continuing). Ignore a well-formed marker whose line 1 names a previous
       boot.
     - When `network-recover-pending` is active for the current boot and line 2
       names `a` or `b`, verify and run `/data/open-u60/update/slot-<a|b>/zte-agent network-recover`
       (both during a pending rollback and when `pending` is absent).
     - When `network-recover-pending` is active for the current boot with line 2
       `stable`, or `active` is `rescue` with the previous slot disarmed or
       unavailable, verify `/data/open-u60/update/last-stable/zte-agent` against
       `/data/open-u60/update/last-stable/release.json` (confirming
       `"channel": "stable"`) and run
       `/data/open-u60/update/last-stable/zte-agent network-recover` — do **not**
       invoke the quarantined candidate binary.
     - When `network-recover-pending` is active with line 2 `previous` (or
       same-boot `rollback-blocked` exists alongside `pending`), verify the slot
       named on `pending` line 2 against its `release.json` or `bootstrap.sha256`
       and run `/data/open-u60/update/slot-<a|b>/zte-agent network-recover`.
     - When `network-recover-pending` is active with line 2 `candidate` (or is
       absent / stale / single-line legacy while an ordinary trial `pending`
       exists), verify the slot named on `pending` line 1 and run
       `/data/open-u60/update/slot-<a|b>/zte-agent network-recover`.
     - When `pending` is absent and no active `network-recover-pending` names a
       slot, verify and run the slot named by `active` (`slot-<a|b>` or
       `last-stable` for `rescue`).
     - Only if the responsible binary itself is damaged, unverified, or predates
       Tailscale policy-rule cleanup, run another verified binary that supports
       full `network-recover` (or clear same-boot state manually / reboot after
       restoring cellular state).
   - Confirm `/data/tailscale/network.json`,
     `/data/tailscale/clean-dns-dnat-flush-pending`,
     `/tmp/zte-agent-perf/network.json`, `/data/zte-agent-relay/cellular-pause`,
     any live `tailscaled` process, and any residual Tailscale policy rules
     (`5110`, `5130`, `5131`, `5210`, `5230`, `5250`, `5270` in `ip -4/-6 rule show`)
     are gone. If `cellular-pause` was present, verify
     `ubus call zwrt_data get_wwaniface '{"cid":1}'` reports the `enable` value
     you recorded before running recovery.
   - If `/data/open-u60/update/network-recover-pending` is well-formed
     (`<boot_id>\n<owner>` or legacy single-token `<boot_id>`), leave it in
     place so the supervisor verifies cleanup and removes it automatically. If
     `network-recover-pending` itself is empty, corrupted, or malformed (so the
     fail-closed check keeps exiting `8` with an unknown owner even after
     cleanup or reboot), only after independently confirming that every
     same-boot journal/marker, `tailscaled`, Tailscale policy rule, and
     `cellular-pause` state is clean (or after a clean reboot with cellular
     restored), remove the malformed `/data/open-u60/update/network-recover-pending`
     file before restarting.
   - Check whether `/data/open-u60/update/rollback-blocked` exists **without**
     `/data/open-u60/update/pending`:
     - If `rollback-blocked` contains a valid single-token boot ID matching
       `/proc/sys/kernel/random/boot_id`, the supervisor exits `8`
       unconditionally for the rest of the current boot (even after
       `network-recover` succeeds); once cellular restoration is verified,
       **reboot** the router so kernel-only same-boot state clears and the
       marker becomes stale on the next boot.
     - If `rollback-blocked` is empty, corrupted, or malformed (not a valid
       single printable-ASCII boot token), the fail-closed supervisor check
       keeps exiting `8` **even across reboots**; only after verifying that all
       same-boot journals/markers are gone (or after a clean reboot) and that
       cellular state matches the recorded original value, remove the malformed
       `/data/open-u60/update/rollback-blocked` file before restarting.
     - Otherwise, restart the service through `/data/local/tmp/start_zte_agent.sh`
       (which sets the configured password, bind address, OTA environment
       variables, and start lock), or reboot after ensuring `cellular-pause`
       has been restored.
2. **All three copies unavailable**: if both A/B binaries and the last Stable
   rescue copy are all missing or corrupted, no on-device updater can run.
   Recovery then requires SSH/USB and `setup.sh`. Validation must not
   deliberately destroy all three copies on a production router.

## Release lanes

- `main` is the production branch. A `vMAJOR.MINOR.PATCH` Stable tag is
  accepted only when it points at the exact current `main` head.
- `beta` is the permanent pre-release branch. Feature changes should reach it
  first, and a `vMAJOR.MINOR.PATCH-beta.N` tag is accepted only when it points
  at the exact current `beta` head. Beta releases never replace GitHub's latest
  Stable release.
- Promote a tested release through a `beta` → `main` pull request. After the
  promotion merge and Stable release, bring `main` back into `beta` before the
  next development cycle so both lanes share the production fixes.
- `v2.4.0-beta.1` is the minimum updater version so the first manually
  bootstrapped Beta build can receive later Beta and Stable releases.
- Beta devices consider both lanes and choose the newer version. Returning to
  Stable discards any Beta candidate and can return from a Beta build to the
  current Stable build.

The release workflow writes signed `stable.json` and `beta.json` pointers to the
`ota-channels` branch. Devices never use GitHub's mutable `latest` redirect for
OTA selection.

## Signing-key setup

Generate the key once on a trusted offline machine:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out ota-private.pem
```

Store the complete PEM as the repository Actions secret
`OTA_SIGNING_KEY_PEM`. Keep the private key out of Git, build artifacts and the
router. For a tagged release, CI derives and embeds only the public key, builds
the static ARM64 binary, signs the canonical manifest and updates the
appropriate lane. A release tag fails closed when the secret is absent, invalid
or not a P-256 key.

## Hardware validation before enabling broader rollout

On a physical U60 Pro, verify the first SSH bootstrap, boot persistence, A/B
symlink updates on `/data`, a healthy manual update, forced candidate failure,
power loss during the trial, rollback, low-battery deferral and continued WAN,
DNS and WebUI availability. Automatic installation should remain disabled until
this checklist passes on the target firmware.
