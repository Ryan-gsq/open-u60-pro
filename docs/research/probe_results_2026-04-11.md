# ZTE U60 Pro SSH Probe Results — 2026-04-11

## Goal
Discover auto-sleep and other hidden device features from ZTE's web UI files to emulate in our mobile companion apps.

---

## 1. ZTE Web UI Location

Web UI files are at **`/usr/zte_web/web/`** on device:
- `index.html` — main entry
- `js/service_rpc.js` — **master RPC definitions** (all ubus/UCI calls)
- `js/config/config.js` — feature flags and constants
- `js/config/ufi/U60Pro/config.js` — U60Pro-specific overrides
- `js/auth/adm/*.js` — admin page controllers

## 2. Sleep System Architecture

### 2.1 UCI Config: `zwrt_sleep`
```
zwrt_sleep.ztmp_switch.sleepSwitch='0'        # Master sleep enable (0=off, 1=on)
zwrt_sleep.ztmp_switch.wakeupSwitch='0'        # Scheduled wakeup enable
zwrt_sleep.ztmp_switch.Day_of_Week_1..7='1'    # Days enabled (Mon-Sun)
zwrt_sleep.ztmp_time.SysIdTime='5'             # Idle timeout in minutes before sleep
zwrt_sleep.ztmp_interval.timerInterval='10'    # Timer check interval
zwrt_sleep.ztmp_status.sleepStatus='wakeup'    # Current status: 'wakeup' or 'sleep'
zwrt_sleep.ztmp_status.wifiStatus='0'          # WiFi status during sleep
zwrt_sleep.sleepControl.restartTime='0'        # Restart time tracking
zwrt_sleep.sleepControl.restartCount='0'       # Restart count tracking
zwrt_sleep.profile.type='CPE'
zwrt_sleep.profile.model='MC8330'
```

### 2.2 ubus: `zwrt_zte_sleep_faw.wakelock`
Methods:
- `enableAutoSleep` `{"switch": true/false}` — **master auto-sleep toggle**
- `set_ufi_sleep` `{"ufiSleepTime": "5"}` — set idle timeout (minutes, "-1"=never)
- `createWakelock` / `destroyWakelock` — prevent/allow sleep
- `WakeLock` / `WakeUnlock` — by file descriptor
- `zteSleepTest` — debug/test

### 2.3 ubus: `zwrt_zte_sleep_faw.power_status`
- No methods exposed (notification-only object)
- Broadcasts `zwrt_device_power_state_event`

### 2.4 Daemon: `zte_topsw_sleep_faw`
State machine: **idle → sleeping → sleeped → wakeup**
- Monitors: WiFi clients (`zte_topsw_wlan_access_num`), LCD status, charger events, power key, powerbank
- Controls: `echo mem > /sys/power/autosleep` (enable), `echo off > /sys/power/autosleep` (disable)
- Events subscribed: `BSP_CHARGER_EVENT`, `BSP_POWERBANK_EVENT`, `zwrt_deviceui_event.lcdstatus`, `zwrt_key.event`
- Sources: `sleep_ufi_main_thread.cpp`, `sleep_ufi_lcd_proc.cpp`, `sleep_ufi_key_proc.cpp`

### 2.5 Web UI: `service_rpc.js` Sleep Functions

**getSleepMode** (reads `zwrt_sleep.ztmp_time.SysIdTime`):
```js
// UCI read: zwrt_sleep → ztmp_time → SysIdTime
// Returns: { sleepMode: "5" }  // minutes, "-1" = always on
```

**setSleepMode** (calls `zwrt_zte_sleep_faw.wakelock.set_ufi_sleep`):
```js
// ubus call: zwrt_zte_sleep_faw.wakelock set_ufi_sleep {"ufiSleepTime": "5"}
// Input: { sleepMode: "5" }
```

**Sleep mode options** (from config.js):
```
-1 = Always on
 5 = 5 minutes
10 = 10 minutes  
20 = 20 minutes
30 = 30 minutes
60 = 1 hour
120 = 2 hours
```

### 2.6 Config Flags
```
WIFI_SLEEP_SUPPORT: true (main) → false (U60Pro override)
AUTO_POWER_SAVE_SUPPORT: false
```

Note: `WIFI_SLEEP_SUPPORT` is disabled in U60Pro config but the underlying APIs work.

---

## 3. Night Mode / Sleep Protection

### UCI Config: `zwrt_led.nightmode`
```
zwrt_led.nightmode.switch='0'           # Night mode enable
zwrt_led.nightmode.starttime='22:00'    # Start time
zwrt_led.nightmode.endtime='7:00'       # End time  
zwrt_led.nightmode.is_nightmode='0'     # Currently in night mode
```

### ubus: `zwrt_led`
Methods available: `led_mesh_proc`, `led_mesh_wifi_agent_jion`, `led_mesh_wifi_agent_leave`, `led_mesh_webui_change_agent_nightmode`, `get_led_mesh_settings`
- NOTE: `get_nightmode_state` / `set_nightmode_state` are NOT available via ubus on this device
- Must use UCI directly: `uci get/set zwrt_led.nightmode.*`

### Web UI RPC:
```js
// getsleepProtection → zwrt_led get_nightmode_state (fails on device!)
// saveSleepProtection → zwrt_led set_nightmode_state (fails on device!)
```

---

## 4. Power Management APIs

### 4.1 `zwrt_mc.device.manager` — Full Key Vocabulary
Calling `get_device_info {}` returns ALL keys:

**Battery/Power:**
- `bat_online`, `bat_health`, `bat_mode`, `bat_low_power`
- `bat_percent`, `bat_level`, `bat_temperature`, `bat_temperature_level`
- `bat_charger_connect`, `bat_charger_type`, `bat_charger_status`
- `bat_ui_charger_type`, `external_charging_flag`
- `bat_time_to_full`, `bat_time_to_empty`
- `power_adapter`, `power_saver_mode`

**System:**
- `device_uptime`, `mode_main_state` (e.g. "mode_power_on_charger")
- `hightemp_datalimit_status`
- `quicken_power_on` (fast boot)
- `WatchDog_Setting_Option`
- `device_abnormal_reboot_flag`
- `cpuinfo` (per-core usage), `meminfo`, `flashinfo`
- `modem_imei`, `wa_version`, `wa_inner_version`

**Scheduled Power On/Off:**
- `poweronoff_schedule_enable` = "0"
- `poweron_schedule_hour` = "7", `poweron_schedule_min` = "0"
- `poweroff_schedule_hour` = "23", `poweroff_schedule_min` = "30"

**Scheduled Reboot:**
- `reboot_schedule_enable`, `reboot_schedule_mode`
- `reboot_dow`, `reboot_dod`
- `reboot_hour1/2/3`, `reboot_min1/2/3`
- `reboot_timeframe_hours1/2`

### 4.2 Power Save (`power_saver_mode`)
- GET: `get_device_info {"deviceInfoList":["power_saver_mode"]}`
- SET: `set_device_info {"deviceInfoList":{"power_saver_mode":"1"}}`

### 4.3 Power Supply / Wall Mode  
- Web RPC: `getPowerSupplySetting` / `setPowerSupplySetting`
- Returns: `{ powerSupplyEnabled: "0"|"1" }`
- Set: `{ enable: "0"|"1" }`

### 4.4 Fast Boot
- GET: `get_device_info {"deviceInfoList":["quicken_power_on"]}`
- SET: `set_device_info {"deviceInfoList":{"quicken_power_on":"1"}}`

### 4.5 `zwrt_bsp.pm` (Power Manager)
- `list {}` → `{ power_on_reason: 1 }`
- `set_device {"label":"...", "action":"..."}` — device power actions

---

## 5. Scheduled Power On/Off (NEW — not in mobile app)
The device supports scheduled power on and power off:
```
poweronoff_schedule_enable = "0"
poweron_schedule_hour = "7"
poweron_schedule_min = "0"
poweroff_schedule_hour = "23"
poweroff_schedule_min = "30"
```
Set via: `zwrt_mc.device.manager set_device_info`

---

## 6. QoS Working Modes (NEW — not in mobile app)
Smart QoS modes from web UI:
- `Ai_mode` — Intelligent (default)
- `Chat_mode` — Social/Meeting
- `Game_mode` — Gaming
- `Video_mode` — Video streaming
- `Nomal_mode` — Balanced
- `Live_mode` — Livestreaming

API: `zwrt_smart_mng.api` → `zte_smart_mng_set_qos_mode`

---

## 7. Client Detection for Sleep
The sleep daemon checks WiFi clients via:
- `zwrt_wlan get_assoc_info {}` → `{ assoc_num: "0", assoc_list: [] }`
- Internal string: `zte_topsw_wlan_access_num`
- UCI: `zwrt_sleep.ztmp_status.wifiStatus`

When `assoc_num == "0"` and idle timeout expires → device enters sleep.

---

## 8. Features We Can Now Add to Mobile Apps

### Priority 1: Auto-Sleep When Idle (no clients)
- **Toggle**: `enableAutoSleep {"switch": true/false}`
- **Timeout**: `set_ufi_sleep {"ufiSleepTime": "5"}` (minutes, -1=never)
- **Status**: UCI `zwrt_sleep.ztmp_status.sleepStatus`
- **Options**: 5, 10, 20, 30, 60, 120 minutes, or "Always on" (-1)

### Priority 2: Night Mode (LED sleep protection)
- UCI read/write `zwrt_led.nightmode.{switch, starttime, endtime}`
- Schedule when LEDs turn off

### Priority 3: Scheduled Power On/Off
- `poweronoff_schedule_enable`, `poweron_schedule_hour/min`, `poweroff_schedule_hour/min`
- Via `zwrt_mc.device.manager set_device_info`

### Priority 4: Smart QoS Modes
- 6 modes: AI, Chat, Game, Video, Normal, Live
- Via `zwrt_smart_mng.api`
