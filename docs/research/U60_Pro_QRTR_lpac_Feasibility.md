# U60 Pro — off-device QRTR/lpac feasibility assessment

Date: 18 September 2026. The original assessment used public source and existing workstation evidence only. **A subsequently authorized SSH follow-up confirmed UIM service advertisement; see the live results below.** No router installation or SIM/card operation occurred.

## Result

**QMI-over-QRTR is a plausible development route, not a demonstrated working profile manager on this MU5250.** Absence of `/dev/cdc-wdm*` does not exclude this transport. The recorded vendor `libqmi 1.32.4-1` does not satisfy the reviewed current lpac build requirement, `qmi-glib >= 1.36.0`.

A private, separately built dependency bundle could avoid replacing the vendor libraries. This is an architecture recommendation, not a completed cross-build or ABI compatibility test. UIM service visibility is now confirmed. Correct modem/slot selection for card operations, sustained safe coexistence, APDU access and profile operations remain unverified.

**B1 electrical compatibility remains unverified.** Nothing in this assessment changes the [SSH power findings](U60_Pro_9eSIM_B1_SSH_Findings.md), measures SIM VCC/current, or tests Bluetooth behavior.

## Sources and provenance

Public source files were downloaded to probe_evidence/u60-qrtr-offdevice-20260918. The manifest records retrieval time, exact source URLs and SHA-256 for each file. Source was read, not executed.

| Project | Pinned revision used for this assessment |
| --- | --- |
| lpac, resolved from `main` through GitHub API | `c7c8d4f817ddfeab21d104870b4647439f9cfab7` |
| linux-msm/qrtr, resolved from `master` | `29e36ae164389580a0f8ea7a7fdb728140ae978d` |

Web-indexed `main` pages and commit history showed older snapshots during research. The downloaded commit-pinned files take precedence. Initial web requests also encountered missing paths/cache misses; none was treated as evidence that a feature is absent.

Device facts come from the earlier SSH evidence: aarch64 Linux 5.15.170-perf; MU5250_HW1.0/B27; GLINK/IPCRTR device-tree configuration; QRTR processes; vendor RIL socket, `qmuxbridge`, `zte_topsw_mc` and `zte-agent`; installed `libqmi 1.32.4-1`, `libqrtr-glib 1.2.2-3`; `qrtr-lookup` available; lpac absent. Exact listener ownership and safe concurrent card access were not established.

## Backend and dependency findings

The pinned [driver build configuration](https://github.com/estkme-group/lpac/blob/c7c8d4f817ddfeab21d104870b4647439f9cfab7/driver/CMakeLists.txt) makes `LPAC_WITH_APDU_QMI_QRTR` optional and disabled by default. Both QMI variants require `qmi-glib>=1.36.0`. The QRTR driver uses libqrtr-glib as well as libqmi/GLib; a newer libqmi must itself be built with the necessary QRTR support. Package-name presence alone proves neither symbols nor build features. The reviewed OpenWrt [package recipe](https://raw.githubusercontent.com/openwrt/packages/master/utils/lpac/Makefile) explicitly disables the QRTR backend; its comment mentioning 1.35.4 does not override current upstream's 1.36.0 build check.

The pinned [QRTR backend](https://github.com/estkme-group/lpac/blob/c7c8d4f817ddfeab21d104870b4647439f9cfab7/driver/apdu/qmi_qrtr.c) creates a QRTR bus, selects the **first** node advertising UIM, creates/opens a QMI device and allocates a UIM client. It defaults to slot **1** unless configured otherwise. These are implementation defaults, not evidence identifying this router's modem or removable slot. The shared implementation provides logical-channel and APDU operations. A profile-list command must therefore not be substituted for service-only discovery.

An older build is not automatically a solution to the library mismatch. No older version was validated against the actual 1.32.4 library, and simply lowering the CMake version check would not prove API compatibility. The original [QRTR backend pull request](https://github.com/estkme-group/lpac/pull/70) records its dependency on changes in libqmi; a backport would require explicit API/symbol review.

## Isolation approach to assess before any deployment

**Preferred design:** a separate lpac process with a private dependency tree, cross-built on the workstation or an isolated Linux builder for the router's actual userspace ABI. Keep the existing vendor manager and system libraries intact.

The upstream [top-level CMake configuration](https://github.com/estkme-group/lpac/blob/c7c8d4f817ddfeab21d104870b4647439f9cfab7/CMakeLists.txt) offers `STANDALONE_MODE`, a relocatable layout and origin-relative library search paths. This is useful packaging support; it does **not** fetch, bundle or verify every external dependency. Driver libraries are shared objects, so a completely static lpac executable is not a drop-in assumption either.

Before a build could be considered deployable:

1. Target the observed AArch64 musl userspace: the live follow-up identified `/lib/ld-musl-aarch64.so.1` as the installed lookup tool's ELF interpreter. A bundle still needs compatible libc/dependency versions and symbol verification; architecture and interpreter alone are not a complete compatibility test.
2. Pin libqmi with QRTR support, libqrtr-glib, GLib/GIO/GObject and their required dependencies. Include lpac's own libraries/driver and cJSON. Profile downloads additionally need a reviewed HTTPS backend, TLS dependencies and trust-store handling.
3. Cross-build into a private staging prefix. Inspect each ELF's interpreter, dependencies, search paths and imported/exported symbols off-device. Account for transitive dependencies and runtime driver loading.
4. Keep library selection scoped to the lpac process. Do not replace `/usr/lib` files, change global loader configuration, or expose a private `LD_LIBRARY_PATH` to vendor services. Do not link this dependency set into the running agent as an initial experiment.
5. Verify the bundle's error paths before live execution, then separately assess vendor-manager coexistence. Dependency isolation prevents library replacement; it does not isolate shared modem or SIM state.

These are proposed implementation checks. No compilation, executable validation, emulator run or router deployment was performed in this assessment.

## Source concern before a live lpac trial

In the reviewed QRTR initialization, `qmi_data` is allocated with `malloc`, but its `lastChannelId` is not initialized. Driver finalization calls `qmi_cleanup`, which inspects that field and may attempt a channel close. See the pinned [QRTR initializer](https://github.com/estkme-group/lpac/blob/c7c8d4f817ddfeab21d104870b4647439f9cfab7/driver/apdu/qmi_qrtr.c) and [shared cleanup implementation](https://github.com/estkme-group/lpac/blob/c7c8d4f817ddfeab21d104870b4647439f9cfab7/driver/apdu/qmi_common.c).

This is a **static code-review concern**, not an observed modem failure: the effect depends on the loader/error path and whether a channel was successfully opened first. A proposed bundle should initialize all state deterministically and make cleanup conditional on a valid client and owned channel, with off-device failure-path tests. No upstream/local application patch was made here. Until reviewed, do not assume an initialization failure has a harmless cleanup path.

## Original minimal live-check proposal — subsequently completed

**Question:** Does the existing QRTR name service advertise UIM service 11 to an additional local discovery client while the vendor manager remains running?

The reviewed [qrtr lookup implementation](https://github.com/linux-msm/qrtr/blob/29e36ae164389580a0f8ea7a7fdb728140ae978d/src/lookup.c) accepts a service filter. For this source, the candidate invocation is:

```sh
qrtr-lookup 11
```

Here **11 is the UIM service identifier, not a SIM slot number**. The implementation opens a QRTR datagram socket, sends `QRTR_TYPE_NEW_LOOKUP` to the local control port, reads service metadata and closes the socket. It sets a one-second receive timeout; this is not a guaranteed one-second total runtime if messages continue arriving. This constitutes active discovery traffic and temporary client state, not a filesystem-only read. It does not issue a UIM card command in the reviewed implementation.

**Prerequisite:** verify the installed `qrtr-lookup` version/implementation before using that syntax. The archived B27 inventory records SHA-256 `7b8eaf821c47923247ac65ece3bc55ef53473321c359709b9bf408e6c9c79b2b` for its executable, but no comparison to the current executable or this upstream build was made. Do not equate the archived hash or matching program name with source equivalence. If the installed tool cannot be verified, prepare a small auditable discovery-only executable off-device and review its complete build before seeking upload/execution approval.

The proposed approved run would be **one bounded lookup**, with UTC start/end, exit status, stderr and service/version/instance/node/port results saved on the workstation. Compare passive modem state and user-observed connectivity before and after. No lpac, QMI card-status query, client/APDU test, slot selection, profile access, SIM reset or daemon restart is included.

**Risk and recovery:** expected connectivity risk is low for the reviewed discovery implementation, but vendor behavior remains untested. Stop on unexpected delay, loss of connectivity or a modem-state change. Terminate only the lookup process identified for that run; do not kill the QRTR name service or vendor manager. No persistent rollback should be required because no configuration change is proposed. If connectivity fails to recover, halt and agree on recovery separately; reboot/reset is not preauthorized. Arrange an independent connection for the controlling workstation if this router is its only internet path.

**What success would mean:** UIM advertisement is visible and the limited discovery coexisted without an observed immediate disruption. It would not prove UIM requests are permitted, identify the physical SIM slot, prove safe channel access, or establish sustained coexistence. A no-match result means no UIM service was visible through that lookup at that time, not that the hardware permanently lacks UIM/APDU capability.

This proposal required separate approval under the user's handoff. The user subsequently authorized SSH access in response to the proposed next step, and only the bounded service-discovery scope was performed. No broader card-access approval was inferred.

## Authorized live results — 18 September 2026

**UIM discovery succeeded** at 05:56:49–05:56:55 UTC / 13:56:49–13:56:55 Manila:

```text
  Service Version Instance Node  Port
       11       1        0    3    86 User Identity Module service
LOOKUP_EXIT_CODE=0
```

The installed executable's SHA-256 matched the archived B27 inventory. Static disassembly of the copied binary verified argument parsing, a QRTR control-port lookup, a one-second receive timeout, service-announcement handling and socket closure. It was not assumed equivalent to current upstream merely from its name. ELF metadata established AArch64 musl userspace. No modified executable was uploaded.

A five-second watchdog was used because neither standalone nor BusyBox `timeout` was available. The command exited normally and the watchdog did not fire. The modem remained `running`, uptime increased continuously, monitored vendor process PIDs were unchanged, and the available filtered kernel log showed no new reset/card-fault event. Cellular throughput was not tested.

This confirms that an additional local discovery client can see UIM advertisement on this boot. **Service 11 and instance 0 are not SIM slot numbers.** Node 3 / port 86 must be treated as discovered endpoints, not permanent settings. No UIM client/card request, logical channel, APDU or profile operation was tested. B1 electrical compatibility is unchanged and remains unverified.

Detailed verification and exact commands: live evidence and results. The next software step is off-device preparation and validation of an isolated backend/dependency bundle and its error paths. A subsequent UIM/card operation needs its own exact reviewed scope; this lookup supplies no basis for automatically running lpac or changing SIM state.

## Changes and remaining boundary

Workstation changes: this assessment, public source snapshots/manifest, live evidence including the copied discovery executable, and clarification/link updates to the SSH report. The live follow-up opened a transient discovery socket; no persistent router or SIM configuration changed. No vendor message sent.

The next purchase-relevant evidence remains B1 input-power specifications or exact-model manufacturer compatibility evidence. QRTR development is a distinct option for modem-based management and does not resolve Bluetooth power requirements.
