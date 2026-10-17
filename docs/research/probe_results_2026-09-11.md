# U60 Pro iOS dashboard live traffic investigation — 2026-09-11

Scope: the front iOS dashboard's real-time cellular upload/download readings. The built-in Speed Test tool is not the reported problem and was not changed.

## Phone reference and simultaneous device capture

The user ran Speedtest on a phone connected to the modem and supplied this screenshot:

- Result timestamp: September 11, 2026, 3:18 PM.
- Download: **198 Mbps**, data used 230.7 MB.
- Upload: **33.7 Mbps**, data used 38.4 MB.
- Idle latency 23 ms, download latency 516 ms, upload latency 323 ms; packet loss 0.00%.

150 simultaneous samples were collected over SSH approximately once per second. Each sample records router uptime, modem byte totals and native rates, and the two kernel interface counters. Probe requests are sequential, so fields are not sampled atomically.

## Confirmed source

```sh
ssh -p 2222 root@192.168.0.1
ubus -S call zwrt_data get_wwandst '{"cid":1,"type":1}'
```

- `real_rx_bytes` / `real_tx_bytes`: modem cumulative download/upload bytes.
- `real_rx_speed` / `real_tx_speed`: native live download/upload rates in **bytes/second**.
- Existing authenticated agent endpoint: **GET /api/network/speeds** (plural).
- Convert to decimal Mbps using `bytes_per_second * 8 / 1_000_000`.
- Firmware `/usr/zte_web/web/js/service_rpc.js` maps these fields to `data_counter.downloadRate` / `uploadRate`; `js/auth/home.js` and `dash_board.js` display those fields. The native chart multiplies by 8 when converting bytes to bits.

## Comparison with the user's test

The following windows cover the visible transfer phases in the capture, selected from the rise and fall in traffic (not from Speedtest's internal measurement timestamps). Compute `Mbps = (end_bytes - start_bytes) * 8 / (end_uptime - start_uptime) / 1_000_000`.

| Measurement | Download Mbps | Upload Mbps |
| --- | ---: | ---: |
| Phone Speedtest result | 198 | 33.7 |
| Modem byte-counter delta | 198.06 | 32.88 |
| `rmnet_data0` delta | 8.76 | 0.22 |
| `rmnet_ipa0` delta | 1.13 | 0.23 |
| Sum used by legacy agent speed source, before smoothing | 9.89 | 0.45 |

Download uses samples **8–18** (10.31 seconds); upload uses **19–29** (10.31 seconds). The modem calculation differs from the phone result by about +0.03% and −2.44% for these selected windows. This is a comparison from one run, not an accuracy guarantee: router counters include all clients/background traffic, protocol accounting can differ, and measurement windows are not synchronized with Speedtest.

Native instantaneous rates averaged 204.20 Mbps down / 32.03 Mbps up over those sampled windows. A brief native download sample reached 418.59 Mbps; upload peaked at 39.17 Mbps. These are individual samples, not final test speeds. Native counter/rate publication can be bursty; use byte deltas over an explicit elapsed interval to compare whole transfers.

A preceding 30.82-second passive probe also found 10,220,596 downloaded modem bytes versus 2,572,997 bytes from the summed kernel counters. Both probes demonstrate that the kernel source does not represent complete cellular traffic on this device, consistent with hardware-offloaded traffic bypassing software interface accounting. Do not calibrate it with a multiplier: the mismatch differs by direction and workload.

## iOS correction

- Prefer modem `/api/network/speeds` over legacy `/api/network/speed` (singular). The latter samples summed `rmnet_data0` + `rmnet_ipa0` kernel counters and keeps 16 one-second samples, averaging roughly 15 seconds.
- Poll live traffic independently on a fixed one-second start-to-start cadence, with existing failure backoff and skipped ticks on overruns. Slow signal/SIM/Wi-Fi/system requests no longer delay publishing a completed speed response.
- Preserve valid zero native rates even when byte totals change; zero must not trigger a client-side delta calculation.
- Stop/cancel traffic polling with the dashboard; keep manual/global refresh separate from traffic, and reject late results after cancellation.
- Show unavailable readings as dashes; mark legacy fallback readings as estimated. Label traffic as covering all devices.
- Keep totals and speeds on the same selected source. Totals may change when switching from incomplete kernel counters to modem accounting.

No router settings, agent binaries, or modem parameters were changed. The updated iOS app was subsequently built, installed, and launched on the connected iPhone 15 Pro Max using `mobile/ios/scripts/build_and_run.sh --skip-generate --no-logs --device 4680F0ED-4DEB-5485-8F3E-E3192678F542`. Installation of `com.openu60.app` was independently verified with `devicectl`.

## Validation

- iOS Simulator Debug build with Xcode 26.6.
- `sh scripts/test-ios-traffic.sh`: native rates, decimal Mbps conversion, explicit idle zeros, missing fields, counter resets/source changes, independent updates during slow dashboard requests, and cancellation across stop/start.

## Post-install background traffic check

A further 31 samples over 30.67 seconds were captured while OpenU60 was running on the iPhone 15 Pro Max (process verified with `devicectl`).

| Measurement | Download Mbps | Upload Mbps |
| --- | ---: | ---: |
| Modem byte delta / router uptime interval | 0.5811 | 1.8878 |
| Time-weighted mean of native live rates | 0.5989 | 1.9354 |

The two modem measurements agree within approximately 3.1% download and 2.5% upload over this window. Individual samples vary with short background bursts (up to 4.75 Mbps down and 10.07 Mbps up). This supports using the native source for live traffic, without claiming sample-by-sample agreement with an independently timed test.

Direct inspection of the phone's HTTP responses was not performed: automatic approval review rejected full-payload packet capture because it could expose authentication headers and unrelated payloads. Verification instead used read-only modem counters, the installed code's data source, active router connections, and the running app process. On-screen numbers were not independently observed in this check.

## Native cadence and independent traffic refresh

A follow-up probe sampled native rates 41 times at approximately 250 ms intervals. It observed 10 distinct rate updates, spaced 1.03–1.07 seconds apart at that sampling resolution. This supports a nominal one-second publication rate. Display-binary strings identify `TUFormDataSpeed::refreshRealtimeSpeed`, but do not establish the touchscreen's exact timer or redraw phase.

The final iOS behavior uses a dedicated one-second start-to-start schedule for upload/download, independent of general refresh settings. Manual refresh does not fetch an extra traffic sample; changing the general interval does not restart the traffic clock. Traffic still stops when the dashboard is not active and backs off when the router is unreachable. Successful requests include their duration within the one-second interval; overruns skip ticks rather than building a backlog.

The speed labels display received values immediately; the previous 0.4-second rolling-digit and unit transition animations were removed from upload/download. No interpolation or extra smoothing is added. Native source timing and Wi-Fi latency still prevent a guarantee that iOS and the built-in screen show precisely the same sample at the same instant.

Focused tests passed for timing, cancellation, and independence from general/manual refresh.

The fixed-cadence revision was built, installed, and launched on the iPhone 15 Pro Max; the new running app process was verified. A subsequent 21-sample check over 20.31 seconds measured 4.9428 Mbps down / 1.0400 Mbps up from byte deltas, versus sampled native-rate averages of 5.2925 / 1.1028 Mbps (about 7.1% / 6.0% difference). The latest native sample was 6.1432 / 0.9349 Mbps. Download bursts exceeded 22 Mbps during the window. These unsynchronized sample averages are not an exact calibration test; the app displays the native instantaneous rates, not this whole-window delta. The phone's on-screen values were not independently read.

## Requested one-minute capture (approximately 15:50–15:52 local)

61 samples over 60.67 seconds recorded 18.442 MB downloaded and 1.618 MB uploaded. Byte-counter averages were 2.432 Mbps down / 0.213 Mbps up; sampled native-rate averages were 2.418 / 0.215 Mbps. Peak native samples were 15.704 / 2.489 Mbps. No sustained high-throughput download/upload test phases were identifiable in this window, unlike the earlier 198/33.7 Mbps run. Tool approval delayed capture startup, so the speed-test start may have preceded recording. A result and timing reference are needed before comparing this capture with the user's new speed test.

The user then supplied the new Speedtest result: **80.8 Mbps download / 8.16 Mbps upload**, iPhone 17 Pro Max. Screenshot clock: 3:52 PM. The updated OpenU60 app is installed on the iPhone 15 Pro Max; the modem source measures all clients, so using a different test phone does not itself invalidate the comparison if both use this U60 Pro. The captured window does not contain traffic consistent with a sustained 80.8/8.16 Mbps test. Exact test start/end times are not present in the screenshot. Do not use these non-aligned measurements to calibrate the app or claim an accuracy result.

## Redo with recording confirmed before test start

121 samples across 122.35 seconds were recorded, with capture file creation at **15:54:02.804 +08:00** on the Mac. Recording was explicitly confirmed to the user after eight complete modem samples, before the user was told to start. Both sustained download and upload phases were captured.

- Detected download phase: samples 55–67, 12.43 seconds, 259,292,762 additional modem RX bytes → **166.882 Mbps**.
- Detected upload phase: samples 67–83, 16.39 seconds, 36,446,491 additional modem TX bytes → **17.790 Mbps**.
- Native instantaneous peaks: 230.557 Mbps down / 29.015 Mbps up.

These preliminary phase windows were identified using sustained native rates above 20 Mbps download / 5 Mbps upload, with the counter baseline immediately before each run. They are not Speedtest's internal timing boundaries; the user's final result is still needed for comparison. All device traffic is included.

The CSV retains the router's reported epoch, which appears about eight hours ahead of Mac local time when converted to the Mac timezone. Use router uptime for interval calculations and the Mac capture timestamp for synchronization; do not interpret the router epoch as a trustworthy wall clock.

### Confirmed redo result

The user's result screenshot identifies the test at **3:54 PM**: **190 Mbps download / 17.0 Mbps upload**, 242.7 MB download data and 30.6 MB upload data. This corresponds to the confirmed-start recording. The screenshot itself was taken at 3:57 PM; the result timestamp, not the screenshot clock, identifies the run.

The previously reported detected-phase byte averages remain **166.882 / 17.790 Mbps**, differing by **−12.2% / +4.6%** from Speedtest's results. Do not relabel them as an exact match. The original download window includes a low sample of 83.2 Mbps and a final native rate of 32.8 Mbps; many other samples are near 190–207 Mbps, with a peak of 230.6 Mbps. This demonstrates temporal variation and differing measurement boundaries, but does not by itself establish the cause of the entire discrepancy. No post-hoc window selection or calibration factor was applied to force agreement.

The displayed app value is the modem's native instantaneous rate. The whole-phase byte average is an independent comparison and is not the number the app continuously displays. A same-instant observation of the iOS dashboard and router screen is still needed to prove on-screen agreement. Keep the user's requested independent one-second refresh and native rates unchanged based on this comparison.

## Battery display correction

The user's dashboard screenshot showed an invalid **199%** battery level and "Charge Stopped". Subsequent read-only device checks found **100%** in both `/sys/class/power_supply/battery/capacity` and `zwrt_bsp.battery list` (`battery_capacity`). The charger service reported `charger_connect: 1`, `charge_status: 4`, and `direct_power_supply_mode: "enable"`, which supports the "Charge Stopped" label. No charging setting was changed.

The discrepancy points to the independent digit-reel renderer rather than a current 199% sensor reading, although the exact transient rendering failure was not reproduced. The battery card now renders the percentage as a single direct text value. Both the card and detail sheet use a validated 0–100 percentage; invalid percentages are shown as "—" rather than clamped to 100%. Regression checks cover 99→100→99, zero, invalid 199/101/negative values, and the live charge-stopped fixture.
