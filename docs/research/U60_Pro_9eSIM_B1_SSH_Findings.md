# U60 Pro × 9eSIM B1 — SSH findings

## Executive conclusion

**Outcome: Insufficient visibility to establish electrical compatibility. SSH is reachable and a read-only inspection was completed.**

Purchase classification: **B1 compatibility is unverified. This was not a failed B1 test and did not demonstrate insufficient power.** A subsequent off-device [QRTR/lpac feasibility assessment](U60_Pro_QRTR_lpac_Feasibility.md) identifies a separate software route; it supplies no new electrical evidence.

Subsequently authorized SSH follow-up at 05:56:49–05:56:55 UTC confirmed **UIM service 11, version 1, instance 0, QRTR node 3 / port 86** through one bounded discovery lookup. The modem remained running. This advances service visibility only; no SIM/card command was sent, and the electrical conclusion is unchanged. See live evidence.

The inspected router is a **ZTE U60 Pro / MU5250, hardware MU5250_HW1.0, firmware CN_ZTE_MU5250V1.0.0B27**. The user confirmed that an **ordinary physical SIM** is installed. No B1 test occurred.

The router exposes 46 Linux regulator entries, an existing regulator summary, and a readable device tree. Two unmapped PMX75 rails, `pmx75_l11` and `pmx75_l13`, report **1,800,000 µV (1.8 V)** with software constraints of **1,704,000–2,928,000 µV**. These values do **not** establish the voltage at the SIM contacts: neither rail could be linked to the removable slot. No SIM-associated voltage/current sensor, guaranteed slot current capability, or B1 peak-current specification was established.

Consequently, this inspection cannot certify that the SIM has “proper voltage,” or that the slot can power the B1 during Bluetooth communication and profile writes. It also found **no evidence demonstrating insufficient SIM power**. The available kernel log contains no matching UICC/reset/brownout/overcurrent event; system-log access failed, and the observed boot was short.

## Device and access summary

| Item | Observed evidence |
| --- | --- |
| Inspection | 18 September 2026, 05:24:56–05:33:42 UTC / 13:24:56–13:33:42 Asia/Manila |
| Access | Previously documented project SSH target, port 2222; authenticated successfully with strict host-key verification. No credentials copied into this report. |
| Model | `/etc/config/zwrt_common_info`: `model_name 'MU5250'`; captured DT `/zte-board/compatible`: `U60PRO` |
| Hardware revision | Same config: `hardware_version 'MU5250_HW1.0'` |
| Firmware | Same config: `integrate_version 'CN_ZTE_MU5250V1.0.0B27'`, `wa_inner_version 'BD_CNMU5250V1.0.0B27'`; `/etc/config/zwrt_product`: matching `modem_inner_version` |
| Kernel | `uname -srmo`: `Linux 5.15.170-perf aarch64 GNU/Linux` |
| Userspace | `/etc/os-release`: OpenWrt 23.05.4, build `r24012-d8dd03c46f`, target `sdx75/generic` |
| DT platform | `Qualcomm Technologies, Inc. SDXPINN IDP MBB`; compatibles `qcom,sdxpinn-idp`, `qcom,sdxpinn`, `qcom,idp` |
| Installed card | Ordinary physical SIM, confirmed by user during inspection; no subscriber-identity query performed |
| Initial/final uptime | 124.17 / 649.66 seconds; no router reboot during inspection |
| Final modem state | `/sys/class/remoteproc/remoteproc0/state`: `running` |
| Scope | Read-only SSH and workstation analysis; no live AT/QMI/APDU/STK operations |

Evidence is retained privately on the controlling workstation in probe_evidence/u60-b1-20260918T052436Z. Each numbered section includes its exact `.command.sh`, redacted `.stdout.txt`, preserved `.stderr.txt`, and timing/exit metadata. An SSH exit code of zero does not imply that every command inside the section succeeded; exceptions are recorded below.

## Evidence table

In this table, **E** means the evidence directory linked above. DT paths are relative to `/sys/firmware/devicetree/base`.

| Claim/question | Exact command, path, source, or test | Relevant output | Interpretation | Confidence/limitation |
| --- | --- | --- | --- | --- |
| SIM supply mapping | `E/03-regulators.command.sh`; `/sys/kernel/debug/regulator/regulator_summary`; decoded `/sys/firmware/fdt` in `E/04-fdt-relevant.txt` | L11 phandle `0x1ab`; L13 `0x1ad`. Their only `*-supply` references are `/soc/regulator-ocp-notifier/periph-1cb-supply` and `periph-1cd-supply`. | References connect an overcurrent-notification node to these rails, not a SIM consumer. No slot/mux/level-shifter mapping established. | High confidence in decoded references; slot association unknown. |
| Supply voltage | `cat /sys/class/regulator/regulator.22/microvolts` and `.24/microvolts` within section 03 | Both `1800000`; corresponding `min_microvolts=1704000`, `max_microvolts=2928000` | Linux voltage settings and constraints for **unmapped rails**. Neither is a contact-voltage measurement. | High for reported settings; unknown for SIM VCC. |
| Configured current limit | Sections 03 and 07; same regulator directories | `microamps`, `min_microamps`, `max_microamps` unavailable; captured tree has no `*microamp*` constraints | No usable configured slot-current limit exposed by these interfaces. | Missing interface does not imply zero capability. |
| Requested load | Section 03, `.22/requested_microamps`, `.24/requested_microamps` | Both `0`; both `num_users=0` | No load/enable references represented by these Linux entries. No current measurement. | Does not account for an unexposed modem consumer. |
| Mode threshold | DT `/soc/rsc@17a00000/drv@2/rpmh-regulator-ldob11` and `...ldob13` | `qcom,mode-threshold-currents = <0 10000>` | Mode-selection thresholds in the corresponding Qualcomm binding, **not a 10 mA maximum**. | Binding-derived; exact vendor driver revision unavailable. |
| Guaranteed hardware capacity | Supply topology and constraints above | No mapped slot rail or board rating found | Guaranteed continuous/peak current, protection threshold, and contact voltage remain unknown. | No electrical measurement performed. |
| B1 maximum/peak demand | Manufacturer product page, rechecked 18 September 2026 | Bluetooth management advertised; displayed specs contain no input-voltage range or total peak-current figures | Electrical requirements needed for a match remain missing. | Manufacturer feature description, not a power datasheet. |
| Power during idle | Section 07; regulator suspend attributes and modem runtime-PM attributes; section 08 selected sleep config | L11/L13 `suspend_mem_state=disabled`; modem `control=auto`, `runtime_status=unsupported`; sleep config `sleepSwitch='0'`, `sleepStatus='wakeup'` | Exposed software state only; no mapped SIM retention policy. | SSH activity may alter idle behavior; no natural-idle test. |
| SIM clock behavior | DT inspection and exposed metadata | No relevant clock/rail linkage or SIM clock-stop policy identified | Clock-stop behavior remains unknown and is separate from VCC removal. | No direct clock observation. |
| Bluetooth management in-slot | User-confirmed ordinary SIM | B1 absent | Discovery, connection, download, switching, and idle reconnect untested. | No B1 compatibility inference from ordinary SIM. |
| Existing problems | `E/06-logs.command.sh`; `E/08-vendor-context.command.sh` | USB VBUS lookup error at boot +1.382371 s; modem firmware boot at +12.237213 s; `logread` fails | USB message is not evidence of a SIM supply fault; one boot sequence observed. | Filtered current kernel buffer only; system log and older history unavailable. |
| Modem management route | Sections 02/05/08; process names, node metadata, `ubus list`; DT modem GLINK node | QMI/QRTR libraries; `qrtr-lookup`; `qmuxbridge`; QCRIL socket; vendor ubus services; AT nodes. `lpac`, `uqmi`, `qmicli`, `mbimcli` absent from PATH. | Integrated modem/vendor control paths exist; profile-management readiness unproven. | No modem/card command issued. |

The standard ABI defines `microvolts` as a setting, `microamps` as a current-limit setting, `requested_microamps` as consumer-requested load, and `num_users` as enable references. A disabled Linux control state does not exclude non-Linux control. These definitions support conservative interpretation; they do not provide physical measurements. See the [Linux 5.15 regulator ABI](https://raw.githubusercontent.com/torvalds/linux/v5.15/Documentation/ABI/testing/sysfs-class-regulator).

## Findings, unknowns, and next action

### Observed on this router

**The supply path remains unmapped.** The flattened tree was captured without a pseudo-terminal: 264,299 bytes, valid FDT v17 header, 1,957 decoded nodes and 812 phandles. Its SHA-256 is `7f0d5fff6cbd2aff01eaf5aa45ad20f29a3aaa6c36958f2bcdea4b27a10606d1`. The full capture is private; only relevant decoded nodes appear in the report/evidence excerpts. A local parser decoded integer cells as big-endian. Section 09 independently cross-checked L11/L13 values against live-tree bytes.

No SIM/UIM/UICC text match was found in the captured tree using the recorded search. All `*-supply` references were resolved. L11 and L13 are retained as **unmapped investigation leads based on their voltage ranges**, not identified SIM1/SIM2 rails. Their exact child paths are:

```text
/soc/rsc@17a00000/drv@2/rpmh-regulator-ldob11/regulator-pmx75-l11
/soc/rsc@17a00000/drv@2/rpmh-regulator-ldob13/regulator-pmx75-l13
```

Both have `qcom,init-voltage=1800000`, matching the runtime setting, and lack `regulator-always-on`, `regulator-boot-on`, and explicit `regulator-state-mem` children. This does not establish the slot's startup or sleep behavior. Other apparent candidates were traced to different functions: L5/L10 to the USB repeater, L6 to storage/display/WLAN-related consumers. The board sysfs node exposes no SIM-voltage attribute. Exposed IIO channel names cover reference/main-power voltages, charger currents and temperatures; none identified SIM-contact telemetry. No raw register access was attempted.

**Fault evidence is limited.** Section 06 retains at most 160 matches from each log source. Nine kernel lines matched, including unrelated wireless “regulatory” messages. No matching UICC reset, removal, SIM brownout, or modem restart was found in that available buffer. The USB error's surrounding lines identify `msm-dwc3 a600000.ssusb`, followed by successful probe. The modem boot entry is ordinary boot context, not demonstrated crash recovery. The initial uptime places boot at approximately 05:22:52 UTC. No older-boot history was established.

**The modem remains managed by vendor software.** `/sys/class/remoteproc/remoteproc0` maps to `/soc/remoteproc-mss@04080000`, with `qcom_q6v5_pas` driver, state `running`, and `recovery=disabled`. Its GLINK child advertises `IPCRTR`; `qrtr_ns`/`qrtr_rx` process names were observed. `/dev/cdc-wdm*` and `/dev/ttyUSB*` were absent. `/dev/socket/qcrild/rild0` exists with `radio:radio` ownership and a listener entry in `/proc/net/unix`. `qmuxbridge`, `zte_topsw_mc`, and `zte-agent` run; `qcril` resolves to an `ujail` supervisor. The targeted FD inspection did not establish the exact process owning the RIL listener. No exclusive or safe concurrent client access was demonstrated.

`/dev/at_mdm0`, `/dev/at_mdm1`, `/dev/at_usb0`, SMD nodes and MHI pipes exist; only metadata was read. Ubus lists `zwrt_mc.device.manager` and other vendor services. No service method was invoked. Installed metadata includes `libqmi 1.32.4-1`, `libqrtr-glib 1.2.2-3`, and `qcril-qmi-services 1.0-1`.

### Source-code/configuration-derived findings

The running agent executable `/data/zte-agent` hashes to `96e3dc50054a1a081cc78368d3ccbd594162f680ad7e0feef816001d86b68700`, exactly matching the existing local release binary. Local source is a modified worktree at HEAD `9a603e31d46020157acb0860ed0aa665022989fd`; inspected source hashes are in `E/source-hashes.json`. A binary match alone does not establish that every current source file was used in that build.

The local [STK implementation](../../zte-agent/src/stk/mod.rs) uses a persistent RIL socket, initializes STK and handles SIM refresh. The [AT implementation](../../zte-agent/src/at_cmd.rs) actively opens candidate ports and sends commands even during detection. Those paths were not invoked. A source search found no `lpac`, APDU/logical-channel, `CSIM` or `CGLA` implementation in `zte-agent/src`. The prior [September 14 STK report](sim_toolkit_probe_2026-09-14.md) is historical evidence, not a test repeated today.

The modem-based management gates remain separate:

| Gate | Status |
| --- | --- |
| Service/tool presence | Vendor RIL/ubus/QMI infrastructure present; lpac absent at both expected paths |
| Suitable profile-management transport/backend | Not established on this router. Upstream QMI-over-QRTR is a candidate that does not require a USB QMI control node; see the subsequent off-device assessment. |
| Safe access alongside vendor manager | Not established |
| APDU/logical-channel access to this slot | Not tested |
| Profile management | Not tested |

Qualcomm's [RPMh binding at commit 1c7b30fe](https://android.googlesource.com/kernel/msm/+/1c7b30fefbb5b998e1093335ad27668c5c2dc50c/Documentation/devicetree/bindings/regulator/rpmh-regulator.txt) matches the observed compatible/property vocabulary. It distinguishes initialization requests, mode-current thresholds and ARC operating levels. Therefore the `10000` threshold is not a rail capacity, and tiny `microvolts` values on `_level` resources must not be presented as physical voltages. This reference is not proof of the installed vendor driver's exact source revision.

The [Linux 5.15 regulator binding](https://raw.githubusercontent.com/torvalds/linux/v5.15/Documentation/devicetree/bindings/regulator/regulator.yaml) distinguishes current constraints from modeled load and boot-time enablement from permanent enablement. None supplies the missing board-to-slot wiring.

### Manufacturer-documented, inferred, and unknown

**Manufacturer-documented:** The [B1 product page](https://www.9esim.com/en/shop/9esim-b1) advertises Bluetooth management and phone-based profile download/switching without a reader. Its displayed specifications do not supply numerical SIM VCC limits or whole-card maximum/peak demand.

**Inference only:** The running integrated modem and lack of a Linux SIM consumer are consistent with supply control outside the exposed application-processor regulator view. This does not identify the actual controller, rail or wiring. The 1.8 V readings may reflect initialization/request state; they are not sufficient to determine the slot's negotiated voltage.

**Unknown:** Actual SIM VCC, guaranteed host current and transient response, slot protection limits, B1 voltage/current requirements, voltage droop during writes, SIM-clock/reset dependence, Bluetooth advertising lifetime, enclosure RF performance, and behavior after natural idle. No measured electrical incompatibility was found.

### Errors, unavailable interfaces, and capture limits

- The first SSH attempt was blocked by the workstation network sandbox (`Operation not permitted`, exit 255). The authorized network-capable retry succeeded with strict host-key checking; this was not router unreachability or a rejected approval.
- `logread` produced 11 `Failed to find log object: Not found` errors. Its empty matching output cannot be treated as a clean system log.
- Reading the modem's `device/power/autosuspend_delay_ms` returned `cat: read error: I/O error`; no delay value was obtained. Runtime status reports `unsupported`, so its zero time counters are not useful sleep telemetry.
- Router tools `uqmi`, `qmicli`, `mbimcli`, `lpac`, `dtc`, `fdtget`, and `timeout` were unavailable in PATH. `/usr/bin/lpac` and `/usr/lib/lpac` were absent. Local `dtc`/`fdtget` were also unavailable; decoding ran locally using the retained parser.
- L11/L13 current-limit, actual-status and fault attributes were absent. Suspend voltage/mode attributes were absent. No matching endpoint was invented as a fallback.
- The regulator output display was truncated at 24,000 characters by the capture helper; the complete 26,403-character output is retained locally. Log selections are intentionally filtered and bounded.
- Initial narrow identity-field selection omitted the build's `model_name` and `integrate_version` keys; these were subsequently discovered by name and read in section 09.

### Smallest next check that materially helps the purchase decision

Obtain **B1 electrical specifications and exact MU5250 compatibility confirmation from 9eSIM**, using the observed HW1.0/B27 identity. This is the smallest useful next step without purchasing hardware or touching the active SIM. A defensible electrical match additionally needs ZTE/board documentation mapping the removable SIM VCC path and its guaranteed output capability. More generic Linux voltage readings cannot fill those gaps.

Draft to vendor — **not sent**:

> I plan to use a 9eSIM B1 inside a ZTE U60 Pro/MU5250, hardware MU5250_HW1.0, firmware CN_ZTE_MU5250V1.0.0B27, managed by a separate phone while it stays installed. Please provide the supported SIM VCC range and total maximum/peak input current, including pulse duration, during startup, advertising, Bluetooth connection, profile download/write and switching, plus permitted voltage droop. Does Bluetooth work with the SIM clock stopped or reset asserted? How does advertising start and resume after timeout? Is in-slot router use supported, and has this exact model been tested?

If a B1 becomes available, the first separately approved test should follow its documented discovery instructions using a phone with independent internet, with the router enclosure closed and a recoverable fallback SIM available. Installing the adapter requires a planned connectivity interruption. A later profile-write/switch test needs a recoverable test profile and a documented recovery route; neither is authorized by this read-only inspection. Successful use would establish practical operation under recorded conditions, not quantify peak-current headroom. Quantitative validation requires an appropriately instrumented SIM-interface measurement by someone equipped to avoid shorts and back-powering.

## Change log

- **No router or SIM configuration changed.** No packages installed, services restarted, modem/SIM reset, profiles accessed, GPIO/regulator settings written, debugfs mounted, or Bluetooth enabled.
- No code or evidence files were uploaded to the router. Collection scripts were supplied to `sh -s` over SSH; retained output and analysis files are on the workstation. Ordinary SSH access may generate the router's own access logs.
- Workstation changes: this report and its private evidence directory only. Existing project changes were preserved. No commit, deployment, vendor message or purchase was performed.
- No Phase B action occurred. Final SSH succeeded, uptime continued, and modem state remained `running`; cellular data throughput and ordinary-SIM functionality were not independently tested.
- Subsequent review on 18 September clarified the unverified B1 classification and added a separate QRTR/lpac assessment with public-source snapshots. That follow-up made no SSH connection and ran no modem/card operation.
- A later, separately authorized SSH follow-up verified the installed discovery executable and ran one bounded `qrtr-lookup 11`. UIM advertisement was visible; no persistent configuration changed and no SIM/card operation occurred. Discovery traffic and its limited health checks are recorded in the linked live evidence.
