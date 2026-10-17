# Live device health and temperature dashboard — 2026-09-14

## Investigation

SSH available at 192.168.0.1:2222. Initial uptime about two minutes; final uptime twelve minutes. No modem reboot performed. Firmware daemon synchronization remained successful.

The old iOS dashboard fetched fast health values concurrently but did not publish any until every general dashboard endpoint completed. Failed health requests retained previous values indefinitely. The battery temperature came from a slower firmware tier. The top-level view stopped polling on disappearance, but only an observed poll-key change restarted it; reappearance with an unchanged key now explicitly resumes polling. These are confirmed code weaknesses; the user's exact pre-restart screen freeze was not independently reproduced.

The old thermal endpoint returned only the integer firmware `cpuss_temp`. Direct sysfs exposes 40 thermal zones. `zeroc` is excluded, leaving 39 named entries, some unavailable. Observed invalid values include -273000 and -40960 millidegrees. Sensor names do not establish exact board positions; no case/ambient labels are inferred.

## Changes

- Agent thermal endpoint reads thermal-zone files on each request, returns stable zone IDs, names and Celsius values or null. Legacy `cpuss_temp` remains and reports the maximum valid CPU-zone temperature.
- iOS health has a separate two-second loop; CPU, temperatures and battery publish independently of general dashboard requests. Failed readings become unavailable; canceled sessions cannot publish late responses.
- Battery capacity, temperature, voltage and current come directly from `/api/battery`. Battery temperature is tenths of a degree, thermal zones millidegrees. Firmware charger policy still supplies charge-stopped status; slower battery ETA metadata is retained.
- Missing temperatures are optional, not fake zeroes. Actual zero Celsius and zero CPU utilization remain valid.
- New Temperatures card distinguishes hottest CPU zone, battery, USB, power chip and numbered board sensors, with an expandable list of all firmware sensor names. Values use one decimal, plain text and a sample-age indicator. Summary readings older than ten seconds show unavailable.
- Existing battery and CPU cards use exact temperature text rather than digit-reel animation. Traffic retains its independent one-second cadence.

## Validation and installation

- `sh scripts/test-ios-traffic.sh`: passed. Tests include slow general requests, live health changes, failures, recovery, cancellation, CPU zero, temperature units, invalid sensors, hottest CPU selection and existing traffic/battery regressions.
- `cargo test -p zte-agent thermal_tests --locked`: passed. Fixture verifies fresh file reads, conversion and invalid sensor handling.
- Simulator build and signed physical-device build: passed.
- `git diff --check`: passed.
- Full strict Clippy remains blocked by 12 existing warnings in unrelated agent modules; no warnings remain in the modified thermal module.
- Agent deployed with matching local/remote SHA256: `9fed9ff6a6630deb19ca52f2d0f9b7109829dfb52633477f3caa88e07a9f62e0`.
- Previous agent backed up at `/data/zte-agent.before-temperature-fix-20260914`. Existing startup script and credential preserved. Only zte-agent restarted.
- App installed and launched on iPhone 17 Pro Max and iPhone 15 Pro Max; installation independently verified via devicectl.

Six authenticated live API samples, approximately two seconds apart: CPU temperature 37.6, 38.0, 43.2, 38.0, 37.6, 37.2°C; battery 29.0°C throughout; CPU utilization 11.2, 10.8, 23.5, 16.8, 12.3, 11.2%. Raw non-sensitive readings: `probe_evidence/2026-09-14/live-health.jsonl`.

Physical phone pixels and precise screen-to-device timing were not independently captured. Validation covers builds, view-model behavior, installation and live device responses; one decimal describes display resolution, not calibrated sensor accuracy.

## Follow-up: charging-label flicker and Celsius animation

The battery refresh published a kernel charging state and then a different firmware-policy state every tick. These responses are now fetched concurrently and published as one combined battery sample. Polling pauses preserve health readings and their original timestamps rather than clearing them on each tab switch. Actual failed requests still mark readings unavailable.

All temperature values on CPU/battery cards, temperature summaries, expanded sensors and detail sheets now share SwiftUI's numeric content transition (0.3 seconds, one decimal place, respecting Reduce Motion). Regression tests cover a delayed charger response with a contradictory kernel state and preserving values on tab pauses; all health, battery and traffic tests pass. Signed builds installed and launched on both phones. No additional agent changes or modem restart needed.

## Follow-up: live cellular TX/RX flicker

Traffic retained a pause-time unavailable reset after health readings were fixed. Pauses now preserve the last traffic sample and its receipt timestamp while resetting only the delta baseline. Failed requests retain the last values with an explicit last-sample/waiting caption; data at least five seconds old receives the same age label. Real zero traffic still displays zero. Each rate now uses a single stable Text with a numeric content transition, including its unit. The independent one-second acquisition cadence is unchanged. Regression checks for pause, failed reads, cancellation, recovery and zero traffic passed; physical-device builds passed.

## Follow-up: match the app's animated number style

Live TX/RX now uses the existing AnimatedNumber digit reels with a 0.3-second duration and the formatted unit as a suffix (zero duration for Reduce Motion). Only the value renderer changed. Last-sample retention, delayed-sample labeling, cancellation protection and the independent one-second clock remain intact. Existing regression tests and signed builds passed.

## Board sensor 5 investigation

Three consecutive direct reads of thermal_zone33 (`sys-therm-5`) returned -40960 millidegrees while adjacent sensors changed normally. Its mode is enabled. The underlying IIO input `in_temp_pmx75_qtm_therm_input` also returns -40960. Device-tree `soc/thermal-zones/sys-therm-5/thermal-sensors` contains phandle 0x6b and channel 0x148; these match the VADC controller phandle and `pmx75_qtm_therm/reg`, confirming the channel mapping. No valid alternate reading was found. Firmware fault, absent component and hardware fault cannot be distinguished with this evidence.

The iOS summary and expanded list now explicitly say Unavailable for a missing sensor value instead of a bare dash. No invalid value was converted to a plausible temperature and no thermal configuration changed. Signed iOS build passed. The physical sensor reading remains unresolved at the device level.
