use std::fs;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cache::{self, UbusCache};
use crate::ubus;

const STORAGE_PATH: &str = "/data/local/tmp/charge_limit.json";
const POLL_ACTIVE_SECS: u64 = 60;
const POLL_IDLE_SECS: u64 = 300;
/// While the charger is disconnected the thread parks on the event channel.
/// The periodic re-seed (one `zwrt_bsp.charger list` fork) exists only to
/// recover from a missed BSP_CHARGER_EVENT: it fires this long after a
/// disconnect, then doubles on every "still disconnected" answer up to
/// `DISCONNECTED_RESEED_MAX_SECS`, so the steady-state on-battery cost is one
/// fork per hour. Any charger event resets the delay to the base interval.
const DISCONNECTED_RESEED_SECS: u64 = 600;
const DISCONNECTED_RESEED_MAX_SECS: u64 = 3600;
const DEFAULT_HYSTERESIS: u8 = 5;

const SYSFS_CAPACITY: &str = "/sys/class/power_supply/battery/capacity";
const SYSFS_STATUS: &str = "/sys/class/power_supply/battery/status";

fn default_hysteresis() -> u8 {
    DEFAULT_HYSTERESIS
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    enabled: bool,
    limit: u8,
    #[serde(default = "default_hysteresis")]
    hysteresis: u8,
}

struct LimitState {
    enabled: bool,
    limit: u8,
    hysteresis: u8,
    manual_override: bool,
}

pub struct ChargeLimitEnforcer {
    inner: Mutex<LimitState>,
    /// Shared `zwrt_bsp.charger list` cache (set in `start()`); the enforcer
    /// always reads fresh but refreshes the entry the HTTP readers use.
    cache: OnceLock<Arc<UbusCache>>,
}

/// Outcome of one enforcement tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChargeAction {
    /// Stop charging (battery reached the limit).
    Stop,
    /// Resume charging (battery fell to the hysteresis floor).
    Resume,
    /// Leave the charger as it is.
    Keep,
}

impl ChargeLimitEnforcer {
    /// Check if charging is currently stopped via ubus (ground truth).
    /// `direct_power_supply_mode: "enable"` = charging STOPPED (inverted naming).
    fn is_charging_stopped(&self) -> bool {
        match self.cache.get() {
            Some(cache) => cache.charger_list(Duration::ZERO),
            None => ubus::call("zwrt_bsp.charger", "list", Some("{}")),
        }
        .ok()
        .and_then(|v| {
            v["direct_power_supply_mode"]
                .as_str()
                .map(|s| s == "enable")
        })
        .unwrap_or(false)
    }

    /// Set charging state via ubus (inverted: "enable" = stop, "disable" = start)
    fn set_charging(&self, allow: bool) {
        let mode = if allow { "disable" } else { "enable" };
        let params = format!(r#"{{"direct_power_supply_mode":"{mode}"}}"#);
        let _ = ubus::call("zwrt_bsp.charger", "set", Some(&params));
        if let Some(c) = self.cache.get() {
            c.invalidate(cache::CHARGER);
        }
    }
}

/// Extract `charger_connect` from a charger payload (BSP_CHARGER_EVENT or
/// `zwrt_bsp.charger list`, both carry it).
/// Returns `Some(true)` for connected, `Some(false)` for disconnected, `None` if not present.
fn charger_connect_value(event: &Value) -> Option<bool> {
    match &event["charger_connect"] {
        Value::Number(n) => Some(n.as_u64() != Some(0)),
        Value::String(s) => Some(s != "0"),
        _ => None,
    }
}

/// Read the current charger-connected state from ubus (one fork).
/// `None` when the call fails or the payload lacks `charger_connect`; the
/// caller chooses the fallback (see `event_loop`). Deliberately not read
/// from sysfs `status`: that says "Discharging" while plugged in with
/// charging stopped by the limit, which would park the enforcer for good.
fn read_charger_connected() -> Option<bool> {
    match ubus::call("zwrt_bsp.charger", "list", Some("{}")) {
        Ok(v) => {
            let connected = charger_connect_value(&v);
            if connected.is_none() {
                eprintln!(
                    "[charge_policy] zwrt_bsp.charger list: no charger_connect, state unknown"
                );
            }
            connected
        }
        Err(e) => {
            eprintln!("[charge_policy] zwrt_bsp.charger list failed: {e}");
            None
        }
    }
}

/// Next re-seed delay while the charger stays disconnected: double, capped
/// at `DISCONNECTED_RESEED_MAX_SECS`.
fn next_reseed_secs(current: u64) -> u64 {
    current.saturating_mul(2).min(DISCONNECTED_RESEED_MAX_SECS)
}

/// Apply a re-seed read taken while disconnected. A failed read (`None`)
/// keeps the previous state rather than assuming "connected", so a ubus
/// hiccup on battery cannot move the enforcer into the 60/300 s tick loop.
/// Returns the new connected state and the delay before the next re-seed:
/// back to the base interval once connected, backed off while still
/// disconnected (a failed read backs off too; a broken ubus is no reason to
/// fork more often).
fn after_reseed(previous: bool, read: Option<bool>, reseed_secs: u64) -> (bool, u64) {
    let connected = read.unwrap_or(previous);
    if connected {
        (true, DISCONNECTED_RESEED_SECS)
    } else {
        (false, next_reseed_secs(reseed_secs))
    }
}

/// Pure enforcement decision.
///
/// `stopped` (the ubus ground truth, one fork) is only queried when the
/// outcome can depend on it: at or above the limit while not discharging
/// (candidate to stop) or at or below the hysteresis floor (candidate to
/// resume). Between the two, or discharging above the limit, sysfs alone
/// decides and no ubus call is made. The decision table itself is the
/// original one, unchanged.
fn decide(
    capacity: u8,
    discharging: bool,
    limit: u8,
    hysteresis: u8,
    stopped: impl FnOnce() -> bool,
) -> ChargeAction {
    let floor = limit.saturating_sub(hysteresis);
    let may_stop = capacity >= limit && !discharging;
    let may_resume = capacity <= floor;
    if !may_stop && !may_resume {
        return ChargeAction::Keep;
    }

    let stopped = stopped();

    if discharging && !stopped {
        return ChargeAction::Keep;
    }

    if capacity >= limit && !stopped {
        ChargeAction::Stop
    } else if capacity <= floor && stopped {
        ChargeAction::Resume
    } else {
        ChargeAction::Keep
    }
}

impl ChargeLimitEnforcer {
    pub fn new() -> Self {
        let persisted = fs::read_to_string(STORAGE_PATH)
            .ok()
            .and_then(|s| serde_json::from_str::<Persisted>(&s).ok());

        let (enabled, limit, hysteresis) = match persisted {
            Some(p) => (p.enabled, p.limit.clamp(50, 100), p.hysteresis.clamp(1, 20)),
            None => (false, 100, DEFAULT_HYSTERESIS),
        };

        ChargeLimitEnforcer {
            inner: Mutex::new(LimitState {
                enabled,
                limit,
                hysteresis,
                manual_override: false,
            }),
            cache: OnceLock::new(),
        }
    }

    /// Start with event-driven charger events + fallback polling.
    pub fn start(self: &Arc<Self>, charger_events: mpsc::Receiver<Value>, cache: Arc<UbusCache>) {
        let _ = self.cache.set(cache);
        let enforcer = Arc::clone(self);
        crate::system::spawn_named("charge-limit", move || {
            enforcer.event_loop(charger_events);
        });
    }

    fn event_loop(&self, rx: mpsc::Receiver<Value>) {
        // Seed from the charger daemon (one fork) instead of assuming
        // connected: on battery the thread parks right away rather than
        // forking ubus every POLL_ACTIVE_SECS until the first event. If the
        // read fails, assume connected so enforcement runs on the next tick;
        // the next real BSP_CHARGER_EVENT corrects it.
        let mut charger_connected = read_charger_connected().unwrap_or(true);
        // Delay before the next re-seed while disconnected; adaptive, see
        // DISCONNECTED_RESEED_SECS.
        let mut reseed_secs = DISCONNECTED_RESEED_SECS;

        loop {
            // When charger is disconnected, block until the next event; wake
            // only every `reseed_secs` to re-check via ubus in case a connect
            // event was missed.
            if !charger_connected {
                match rx.recv_timeout(std::time::Duration::from_secs(reseed_secs)) {
                    Ok(event) => {
                        // Any charger event proves the daemon is delivering,
                        // so restart the re-seed backoff from the base.
                        reseed_secs = DISCONNECTED_RESEED_SECS;
                        if charger_connect_value(&event) == Some(true) {
                            charger_connected = true;
                            eprintln!("[charge_policy] charger connected — resuming enforcement");
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            self.enforce_if_active();
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // On a failed read keep the previous (disconnected)
                        // state; never assume connected here.
                        let (connected, next) =
                            after_reseed(charger_connected, read_charger_connected(), reseed_secs);
                        reseed_secs = next;
                        if connected {
                            charger_connected = true;
                            eprintln!("[charge_policy] charger connected (re-seed) — resuming enforcement");
                            self.enforce_if_active();
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        eprintln!(
                            "[charge_policy] event channel disconnected, falling back to polling"
                        );
                        self.poll_loop();
                        return;
                    }
                }
                continue;
            }

            // Charger connected — poll with timeout for periodic enforcement
            let (enabled, manual_override, limit, hysteresis) = {
                let state = self.inner.lock().unwrap();
                (
                    state.enabled,
                    state.manual_override,
                    state.limit,
                    state.hysteresis,
                )
            };

            let timeout = if enabled && !manual_override {
                POLL_ACTIVE_SECS
            } else {
                POLL_IDLE_SECS
            };

            match rx.recv_timeout(std::time::Duration::from_secs(timeout)) {
                Ok(event) => {
                    if charger_connect_value(&event) == Some(false) {
                        charger_connected = false;
                        // First re-seed after a disconnect is at the base interval.
                        reseed_secs = DISCONNECTED_RESEED_SECS;
                        eprintln!("[charge_policy] charger disconnected — suspending enforcement");
                        // Re-enable charging so next plug-in starts normally
                        if self.is_charging_stopped() {
                            self.set_charging(true);
                            eprintln!("[charge_policy] re-enabled charging (was stopped by limit)");
                        }
                        continue;
                    }
                    // Other charger event while connected — enforce immediately
                    let state = self.inner.lock().unwrap();
                    if state.enabled && !state.manual_override {
                        let (limit, hyst) = (state.limit, state.hysteresis);
                        drop(state);
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        self.enforce(limit, hyst);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if enabled && !manual_override {
                        self.enforce(limit, hysteresis);
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    eprintln!(
                        "[charge_policy] event channel disconnected, falling back to polling"
                    );
                    self.poll_loop();
                    return;
                }
            }
        }
    }

    /// Run one enforcement tick if the limit is enabled and not overridden.
    fn enforce_if_active(&self) {
        let state = self.inner.lock().unwrap();
        if state.enabled && !state.manual_override {
            let (limit, hyst) = (state.limit, state.hysteresis);
            drop(state);
            self.enforce(limit, hyst);
        }
    }

    /// Pure polling fallback if event bus dies.
    fn poll_loop(&self) {
        loop {
            let state = self.inner.lock().unwrap();
            let (enabled, manual_override, limit, hysteresis) = (
                state.enabled,
                state.manual_override,
                state.limit,
                state.hysteresis,
            );
            drop(state);

            let interval = if enabled && !manual_override {
                self.enforce(limit, hysteresis);
                POLL_ACTIVE_SECS
            } else {
                POLL_IDLE_SECS
            };
            std::thread::sleep(std::time::Duration::from_secs(interval));
        }
    }

    /// Core enforcement logic: read capacity and stop/resume charging as needed.
    /// sysfs is read first (no fork); ubus is only consulted when the decision
    /// can depend on it (see `decide`).
    fn enforce(&self, limit: u8, hysteresis: u8) {
        let status = fs::read_to_string(SYSFS_STATUS).unwrap_or_default();
        let discharging = status.trim() == "Discharging";

        let capacity: u8 = fs::read_to_string(SYSFS_CAPACITY)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        match decide(capacity, discharging, limit, hysteresis, || {
            self.is_charging_stopped()
        }) {
            ChargeAction::Stop => self.set_charging(false),
            ChargeAction::Resume => self.set_charging(true),
            ChargeAction::Keep => {}
        }
    }

    pub fn get(&self) -> (bool, u8, u8, bool) {
        let state = self.inner.lock().unwrap();
        (
            state.enabled,
            state.limit,
            state.hysteresis,
            state.manual_override,
        )
    }

    pub fn set(&self, enabled: bool, limit: u8, hysteresis: u8) -> Result<(), String> {
        if limit < 50 || limit > 100 {
            return Err("limit must be 50-100".into());
        }
        if hysteresis < 1 || hysteresis > 20 {
            return Err("hysteresis must be 1-20".into());
        }
        let mut state = self.inner.lock().unwrap();
        state.enabled = enabled;
        state.limit = limit;
        state.hysteresis = hysteresis;
        state.manual_override = false;
        self.save_locked(&state);
        drop(state);

        if enabled {
            self.enforce(limit, hysteresis);
        } else {
            self.set_charging(true);
        }

        Ok(())
    }

    pub fn set_manual_override(&self, override_on: bool) {
        let mut state = self.inner.lock().unwrap();
        state.manual_override = override_on;
    }

    fn save_locked(&self, state: &LimitState) {
        let p = Persisted {
            enabled: state.enabled,
            limit: state.limit,
            hysteresis: state.hysteresis,
        };
        if let Ok(json) = serde_json::to_string(&p) {
            let _ = fs::write(STORAGE_PATH, json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::Cell;

    /// The original `enforce()` decision table, verbatim, as the oracle:
    /// `stopped` was always read first, then the three checks below.
    fn reference(
        capacity: u8,
        discharging: bool,
        stopped: bool,
        limit: u8,
        hysteresis: u8,
    ) -> ChargeAction {
        if discharging && !stopped {
            return ChargeAction::Keep;
        }
        if capacity >= limit && !stopped {
            ChargeAction::Stop
        } else if capacity <= limit.saturating_sub(hysteresis) && stopped {
            ChargeAction::Resume
        } else {
            ChargeAction::Keep
        }
    }

    #[test]
    fn decide_matches_original_table_and_reads_stopped_only_when_it_matters() {
        // Full domain the enforcer can see: limit 50..=100, hysteresis 1..=20
        // (both clamped in `new()`/`set()`), capacity 0..=100 (0 = sysfs read
        // failure), both status readings, both ubus answers.
        for limit in 50..=100u8 {
            for hysteresis in 1..=20u8 {
                for capacity in 0..=100u8 {
                    for discharging in [false, true] {
                        let keep_either_way =
                            reference(capacity, discharging, false, limit, hysteresis)
                                == ChargeAction::Keep
                                && reference(capacity, discharging, true, limit, hysteresis)
                                    == ChargeAction::Keep;
                        for stopped in [false, true] {
                            let asked = Cell::new(false);
                            let got = decide(capacity, discharging, limit, hysteresis, || {
                                asked.set(true);
                                stopped
                            });
                            let want = reference(capacity, discharging, stopped, limit, hysteresis);
                            assert_eq!(
                                got, want,
                                "cap={capacity} discharging={discharging} stopped={stopped} limit={limit} hyst={hysteresis}"
                            );
                            // The ubus fork is skipped exactly when the answer
                            // cannot depend on it, never otherwise.
                            assert_eq!(
                                !asked.get(),
                                keep_either_way,
                                "cap={capacity} discharging={discharging} limit={limit} hyst={hysteresis}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn decide_spot_checks() {
        let never = || panic!("ubus must not be consulted here");

        // Charging at the limit, not yet stopped: stop.
        assert_eq!(decide(80, false, 80, 5, || false), ChargeAction::Stop);
        // Already stopped at the limit: nothing to do.
        assert_eq!(decide(80, false, 80, 5, || true), ChargeAction::Keep);
        // Above the limit but discharging (load exceeds charger): no fork, keep.
        assert_eq!(decide(85, true, 80, 5, never), ChargeAction::Keep);
        // Between the floor and the limit: no fork, keep.
        assert_eq!(decide(76, false, 80, 5, never), ChargeAction::Keep);
        assert_eq!(decide(79, true, 80, 5, never), ChargeAction::Keep);
        // At the hysteresis floor and stopped: resume (even while "Discharging",
        // which is what sysfs reports while the limit holds the charger off).
        assert_eq!(decide(75, true, 80, 5, || true), ChargeAction::Resume);
        assert_eq!(decide(75, false, 80, 5, || true), ChargeAction::Resume);
        // At the floor but charging normally: keep.
        assert_eq!(decide(75, false, 80, 5, || false), ChargeAction::Keep);
        // sysfs capacity unreadable (0) while stopped: resume, as before.
        assert_eq!(decide(0, true, 100, 5, || true), ChargeAction::Resume);
        // 100 % limit: stop at full, resume at 95.
        assert_eq!(decide(100, false, 100, 5, || false), ChargeAction::Stop);
        assert_eq!(decide(95, true, 100, 5, || true), ChargeAction::Resume);
    }

    #[test]
    fn charger_connect_value_accepts_event_and_list_payloads() {
        // BSP_CHARGER_EVENT and `zwrt_bsp.charger list` both carry
        // `charger_connect`, numeric on this firmware.
        assert_eq!(
            charger_connect_value(&json!({"charger_connect": 1})),
            Some(true)
        );
        assert_eq!(
            charger_connect_value(&json!({"charger_connect": 0})),
            Some(false)
        );
        assert_eq!(
            charger_connect_value(&json!({"charger_connect": "1"})),
            Some(true)
        );
        assert_eq!(
            charger_connect_value(&json!({"charger_connect": "0"})),
            Some(false)
        );
        assert_eq!(
            charger_connect_value(&json!({
                "charger_connect": 1,
                "charge_status": 4,
                "direct_power_supply_mode": "enable"
            })),
            Some(true)
        );
        assert_eq!(charger_connect_value(&json!({"charge_status": 4})), None);
        assert_eq!(charger_connect_value(&Value::Null), None);
    }

    #[test]
    fn reseed_read_failure_keeps_previous_state() {
        // A failed `zwrt_bsp.charger list` at the re-seed must not flip the
        // enforcer to "connected" on battery (that would start the 60/300 s
        // tick loop until the next real charger event).
        let (connected, _) = after_reseed(false, None, DISCONNECTED_RESEED_SECS);
        assert!(!connected);
        // A real answer is applied as-is.
        let (connected, _) = after_reseed(false, Some(false), DISCONNECTED_RESEED_SECS);
        assert!(!connected);
        let (connected, _) = after_reseed(false, Some(true), DISCONNECTED_RESEED_SECS);
        assert!(connected);
    }

    #[test]
    fn reseed_backoff_doubles_to_max_and_resets_on_connect() {
        assert_eq!(next_reseed_secs(600), 1200);
        assert_eq!(next_reseed_secs(1200), 2400);
        assert_eq!(next_reseed_secs(2400), 3600);
        assert_eq!(next_reseed_secs(3600), 3600);
        assert_eq!(next_reseed_secs(u64::MAX), DISCONNECTED_RESEED_MAX_SECS);

        // While the answer stays "disconnected" (or unknown) the delay
        // doubles from the base and caps at one hour.
        let mut secs = DISCONNECTED_RESEED_SECS;
        let mut seen = Vec::new();
        for read in [Some(false), None, Some(false), Some(false), None] {
            let (connected, next) = after_reseed(false, read, secs);
            assert!(!connected);
            seen.push(next);
            secs = next;
        }
        assert_eq!(seen, [1200, 2400, 3600, 3600, 3600]);

        // Once connected the delay goes back to the base interval so the
        // next disconnect starts its re-seed at 600 s again.
        assert_eq!(
            after_reseed(false, Some(true), DISCONNECTED_RESEED_MAX_SECS),
            (true, DISCONNECTED_RESEED_SECS)
        );
    }
}
