//! No-service power policy (plan A4).
//!
//! While the modem has no PS service the firmware's "abnormal protection"
//! (`zte_topsw_nwinfo`) cycles the modem to LPM and back every ~100 s and
//! escalates to full modem restarts, each one a maximum-power PLMN scan.
//! This policy waits a grace period, then quiets the firmware knobs, parks
//! the modem in LPM and re-probes for service by going ONLINE for a short
//! window at a doubling interval (20 → 40 → 60 min). Any service event
//! brings the modem back online and restores the knobs.
//!
//! Layout: [`Machine`] is a pure state machine (`step(event, now) ->
//! Vec<Action>`), [`OosPolicy`] is the runtime: one thread blocking on an
//! mpsc receiver (`recv_timeout` only while a deadline is pending, plain
//! `recv` otherwise, so there is no timer while service is present) that
//! executes actions through the [`Effects`] trait. [`DeviceEffects`] is the
//! on-device implementation; tests use a mock.
//!
//! The effects never go through the HTTP handlers: `GoOnline` sends
//! `AT+CFUN=1` itself, so a handler instrumented to report user activity
//! (`PUT /api/modem/airplane`) cannot feed the policy's own action back to
//! it as a user change. As a second line of defence the runtime ignores
//! [`OosPolicy::user_mode`] / [`OosPolicy::set_user_activity`] calls made
//! from the policy thread itself.
//!
//! Off by default until experiment E1 confirms the firmware knobs.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::handlers::AppState;
use crate::ubus;

pub const CONFIG_PATH: &str = "/data/local/tmp/oos_policy.json";
/// The firmware knob values saved before they were quieted, so an agent
/// restart while the policy is active can still restore them.
pub const KNOB_BACKUP_PATH: &str = "/data/local/tmp/oos_policy_knobs.json";

const DEFAULT_GRACE_MIN: u64 = 10;
const DEFAULT_PROBE_EVERY_MIN: u64 = 20;
const DEFAULT_PROBE_WINDOW_MIN: u64 = 3;
/// The probe interval doubles from `probe_every_min` up to this cap (or up
/// to `probe_every_min` itself when that is configured longer).
pub const PROBE_EVERY_MAX: Duration = Duration::from_secs(60 * 60);
/// No action within this long after a user-initiated modem change.
pub const USER_ACTIVITY_GUARD: Duration = Duration::from_secs(120);
/// Retry delay when a call, USSD session or speed test blocks an action.
pub const GUARD_RETRY: Duration = Duration::from_secs(60);
/// First retry after a failed knob restore; doubles up to [`RESTORE_RETRY_MAX`].
pub const RESTORE_RETRY: Duration = Duration::from_secs(60);
pub const RESTORE_RETRY_MAX: Duration = Duration::from_secs(60 * 60);

pub const KNOB_SECTION: &str = "zte_nwinfo";
/// `uci show` target holding the three knobs (one fork for all of them).
pub const KNOB_UCI_SECTION: &str = "zte_nwinfo.sys_info";
pub const KNOB_KEYS: [&str; 3] = [
    "zte_nwinfo.sys_info.ps_no_srv_check_timer_cfg",
    "zte_nwinfo.sys_info.abs_lpm_online_max_times_cfg",
    "zte_nwinfo.sys_info.abs_restart_max_times_cfg",
];

/// The three `zte_nwinfo.sys_info` knobs of the abnormal-protection loop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Knobs {
    pub ps_no_srv_check_timer_cfg: String,
    pub abs_lpm_online_max_times_cfg: String,
    pub abs_restart_max_times_cfg: String,
}

impl Knobs {
    /// Quiet values from experiment E1: a long no-service check timer and no
    /// LPM/online cycles or restarts.
    pub fn quiet() -> Self {
        Self {
            ps_no_srv_check_timer_cfg: "60".into(),
            abs_lpm_online_max_times_cfg: "0".into(),
            abs_restart_max_times_cfg: "0".into(),
        }
    }

    pub fn pairs(&self) -> [(&'static str, &str); 3] {
        [
            (KNOB_KEYS[0], &self.ps_no_srv_check_timer_cfg),
            (KNOB_KEYS[1], &self.abs_lpm_online_max_times_cfg),
            (KNOB_KEYS[2], &self.abs_restart_max_times_cfg),
        ]
    }

    /// Parse the three knobs out of `uci show zte_nwinfo.sys_info` output
    /// (`config.section.option='value'` lines).
    pub fn from_uci_show(show: &str) -> Result<Knobs, String> {
        let mut values: [Option<String>; 3] = [None, None, None];
        for line in show.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if let Some(i) = KNOB_KEYS.iter().position(|k| *k == key.trim()) {
                let value = value.trim();
                let value = value
                    .strip_prefix('\'')
                    .and_then(|v| v.strip_suffix('\''))
                    .unwrap_or(value);
                values[i] = Some(value.replace("'\\''", "'"));
            }
        }
        let [a, b, c] = values;
        match (a, b, c) {
            (Some(a), Some(b), Some(c)) => Ok(Knobs {
                ps_no_srv_check_timer_cfg: a,
                abs_lpm_online_max_times_cfg: b,
                abs_restart_max_times_cfg: c,
            }),
            _ => Err(format!("uci show {KNOB_UCI_SECTION}: knob(s) missing")),
        }
    }
}

// ── Config ──────────────────────────────────────────────────────────

fn default_grace_min() -> u64 {
    DEFAULT_GRACE_MIN
}
fn default_probe_every_min() -> u64 {
    DEFAULT_PROBE_EVERY_MIN
}
fn default_probe_window_min() -> u64 {
    DEFAULT_PROBE_WINDOW_MIN
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_grace_min")]
    pub grace_min: u64,
    #[serde(default = "default_probe_every_min")]
    pub probe_every_min: u64,
    #[serde(default = "default_probe_window_min")]
    pub probe_window_min: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            grace_min: DEFAULT_GRACE_MIN,
            probe_every_min: DEFAULT_PROBE_EVERY_MIN,
            probe_window_min: DEFAULT_PROBE_WINDOW_MIN,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=240).contains(&self.grace_min) {
            return Err("grace_min must be 1-240".into());
        }
        if !(1..=240).contains(&self.probe_every_min) {
            return Err("probe_every_min must be 1-240".into());
        }
        if !(1..=30).contains(&self.probe_window_min) {
            return Err("probe_window_min must be 1-30".into());
        }
        Ok(())
    }

    fn grace(&self) -> Duration {
        Duration::from_secs(self.grace_min * 60)
    }

    fn probe_window(&self) -> Duration {
        Duration::from_secs(self.probe_window_min * 60)
    }

    /// Wait before probe number `probes + 1`: `probe_every_min` doubling up to
    /// [`PROBE_EVERY_MAX`] (a longer configured interval is honoured as is,
    /// without doubling).
    fn probe_interval(&self, probes: u32) -> Duration {
        let base = Duration::from_secs(self.probe_every_min.saturating_mul(60));
        let cap = PROBE_EVERY_MAX.max(base);
        base.saturating_mul(1u32 << probes.min(16)).min(cap)
    }

    /// Apply a partial JSON update (`{enabled, grace_min, probe_every_min,
    /// probe_window_min}`); unknown fields are ignored.
    pub fn patched(&self, patch: &Value) -> Result<Config, String> {
        let mut next = self.clone();
        if let Some(v) = patch.get("enabled") {
            next.enabled = v.as_bool().ok_or("enabled must be a boolean")?;
        }
        if let Some(v) = patch.get("grace_min") {
            next.grace_min = v.as_u64().ok_or("grace_min must be an integer")?;
        }
        if let Some(v) = patch.get("probe_every_min") {
            next.probe_every_min = v.as_u64().ok_or("probe_every_min must be an integer")?;
        }
        if let Some(v) = patch.get("probe_window_min") {
            next.probe_window_min = v.as_u64().ok_or("probe_window_min must be an integer")?;
        }
        next.validate()?;
        Ok(next)
    }

    fn load(path: &Path) -> Config {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str::<Config>(&s).ok())
            .filter(|c| c.validate().is_ok())
            .unwrap_or_default()
    }

    fn save(&self, path: &Path) {
        if let Ok(json) = serde_json::to_string(self) {
            let _ = fs::write(path, json);
        }
    }
}

// ── Inputs ──────────────────────────────────────────────────────────

/// `true` when a `zwrt_servicestatus` payload (or `nwinfo_get_netinfo`
/// result) reports real service; `None` when it carries no `network_type`.
pub fn service_from_event(payload: &Value) -> Option<bool> {
    let network_type = payload["network_type"].as_str()?;
    if network_type.is_empty() {
        return None;
    }
    Some(network_type != "NO_SERVICE" && !network_type.starts_with("LIMITED_SERVICE"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Service state from `zwrt_servicestatus`: `true` = service present.
    Service(bool),
    /// The user asked for an operate mode through the agent
    /// (`PUT /api/modem/airplane`): `true` = ONLINE, `false` = LPM. The
    /// handler performs the mode change itself; the policy only follows.
    UserMode(bool),
    /// The modem was not ONLINE when the policy wanted to start its cycle
    /// (airplane mode set outside the agent); stand down until the next
    /// service event.
    Standby,
    /// The pending deadline was reached.
    Timer,
    /// Configuration changed.
    Config(Config),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Back up and quiet the three firmware knobs.
    SetQuietKnobs,
    /// Restore the knobs from the backup (no-op without one).
    RestoreKnobs,
    /// `nwinfo_set_mode {"operate_mode":"LPM"}`.
    SetLpm,
    /// `modem_online` (AT+CFUN=1; `nwinfo_set_mode ONLINE` does not leave LPM).
    GoOnline,
    Log(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Service present, policy disabled or suspended; no deadline.
    Idle,
    /// No service since `since`; the modem is left alone until the grace
    /// period ends.
    Grace { since: Instant },
    /// Knobs quiet, modem in LPM; `probes` probes done so far.
    Quiet { probes: u32 },
    /// Modem online for one probe window (`probes` includes this one).
    Probing { probes: u32 },
}

// ── State machine ───────────────────────────────────────────────────

pub struct Machine {
    config: Config,
    state: State,
    deadline: Option<Instant>,
    has_service: Option<bool>,
    no_service_since: Option<Instant>,
    knobs_quiet: bool,
    /// The user put the modem in LPM through the agent; stay out of the way
    /// until they go ONLINE again or service appears.
    suspended: bool,
    user_activity: Option<Instant>,
    /// Consulted only when an action is about to run (see [`BusyCheck`]).
    busy: BusyCheck,
}

impl Machine {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            state: State::Idle,
            deadline: None,
            has_service: None,
            no_service_since: None,
            knobs_quiet: false,
            suspended: false,
            user_activity: None,
            busy: Box::new(|| None),
        }
    }

    #[cfg(test)]
    pub fn state(&self) -> &State {
        &self.state
    }

    /// The instant the runtime must deliver [`Event::Timer`] at, if any.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }

    #[cfg(test)]
    pub fn knobs_quiet(&self) -> bool {
        self.knobs_quiet
    }

    /// Install the guard that reports an active call, USSD session or speed
    /// test. It is called only when an action is about to run (on a timer
    /// expiry), never on service events.
    pub fn set_busy_check(&mut self, busy: BusyCheck) {
        self.busy = busy;
    }

    /// Last user-initiated modem change; actions wait [`USER_ACTIVITY_GUARD`].
    pub fn set_user_activity(&mut self, at: Option<Instant>) {
        self.user_activity = at;
    }

    pub fn step(&mut self, event: Event, now: Instant) -> Vec<Action> {
        match event {
            Event::Service(has) => self.on_service(has, now),
            Event::UserMode(online) => self.on_user_mode(online, now),
            Event::Standby => self.on_standby(),
            Event::Timer => self.on_timer(now),
            Event::Config(config) => self.on_config(config, now),
        }
    }

    pub fn status(&self, now: Instant) -> Value {
        let (state, probes) = match self.state {
            State::Idle => ("idle", 0),
            State::Grace { .. } => ("grace", 0),
            State::Quiet { probes } => ("lpm", probes),
            State::Probing { probes } => ("probing", probes),
        };
        json!({
            "state": state,
            "suspended": self.suspended,
            "has_service": self.has_service,
            "probes": probes,
            "knobs_quiet": self.knobs_quiet,
            "no_service_secs": self.no_service_since.map(|t| now.saturating_duration_since(t).as_secs()),
            "next_deadline_secs": self.deadline.map(|d| d.saturating_duration_since(now).as_secs()),
        })
    }

    fn on_service(&mut self, has: bool, now: Instant) -> Vec<Action> {
        self.has_service = Some(has);
        if has {
            self.suspended = false;
            return self.recover("service restored", now);
        }
        if self.no_service_since.is_none() {
            self.no_service_since = Some(now);
        }
        if self.config.enabled && !self.suspended && self.state == State::Idle {
            return self.start_grace(now);
        }
        Vec::new()
    }

    fn on_user_mode(&mut self, online: bool, now: Instant) -> Vec<Action> {
        self.user_activity = Some(now);
        if !online {
            self.suspended = true;
            return self.stand_down("user requested LPM; policy suspended until ONLINE", false);
        }
        self.suspended = false;
        let mut actions = match self.state {
            // The airplane handler sends AT+CFUN=1 itself.
            State::Quiet { .. } | State::Probing { .. } => {
                self.stand_down("user requested ONLINE; leaving the LPM cycle", false)
            }
            _ => Vec::new(),
        };
        if self.config.enabled && self.has_service == Some(false) {
            self.no_service_since.get_or_insert(now);
            actions.extend(self.start_grace(now));
        }
        actions
    }

    fn on_standby(&mut self) -> Vec<Action> {
        self.stand_down(
            "modem is not ONLINE (airplane mode set outside the agent); standing by",
            false,
        )
    }

    fn on_timer(&mut self, now: Instant) -> Vec<Action> {
        match self.deadline {
            Some(d) if now >= d => {}
            _ => return Vec::new(), // early or spurious wakeup
        }
        if self.state == State::Idle {
            self.deadline = None;
            return Vec::new();
        }
        if let Some((until, reason)) = self.blocked_until(now) {
            self.deadline = Some(until);
            return vec![Action::Log(format!(
                "action deferred {} s: {reason}",
                until.saturating_duration_since(now).as_secs()
            ))];
        }
        match self.state {
            State::Idle => unreachable!(),
            State::Grace { since } => {
                self.state = State::Quiet { probes: 0 };
                self.knobs_quiet = true;
                let wait = self.config.probe_interval(0);
                self.deadline = Some(now + wait);
                vec![
                    Action::Log(format!(
                        "no service for {} min; quieting firmware knobs and entering LPM, first probe in {} min",
                        now.saturating_duration_since(since).as_secs() / 60,
                        wait.as_secs() / 60
                    )),
                    Action::SetQuietKnobs,
                    Action::SetLpm,
                ]
            }
            State::Quiet { probes } => {
                let probes = probes + 1;
                self.state = State::Probing { probes };
                self.deadline = Some(now + self.config.probe_window());
                vec![
                    Action::Log(format!(
                        "probe {probes}: going ONLINE for {} min",
                        self.config.probe_window_min
                    )),
                    Action::GoOnline,
                ]
            }
            State::Probing { probes } => {
                self.state = State::Quiet { probes };
                let wait = self.config.probe_interval(probes);
                self.deadline = Some(now + wait);
                vec![
                    Action::Log(format!(
                        "probe {probes} found no service; back to LPM, next probe in {} min",
                        wait.as_secs() / 60
                    )),
                    Action::SetLpm,
                ]
            }
        }
    }

    fn on_config(&mut self, config: Config, now: Instant) -> Vec<Action> {
        let was_enabled = self.config.enabled;
        self.config = config;
        if !self.config.enabled {
            let mut actions = self.stand_down("policy disabled", true);
            if was_enabled && actions.is_empty() {
                actions.push(Action::Log("policy disabled".into()));
            }
            return actions;
        }
        match self.state {
            State::Grace { since } => {
                self.deadline = Some((since + self.config.grace()).max(now));
                Vec::new()
            }
            State::Idle if !self.suspended && self.has_service == Some(false) => {
                self.no_service_since.get_or_insert(now);
                let mut actions = vec![Action::Log("policy enabled".into())];
                actions.extend(self.start_grace(now));
                actions
            }
            _ => {
                if !was_enabled {
                    vec![Action::Log("policy enabled".into())]
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn start_grace(&mut self, now: Instant) -> Vec<Action> {
        self.state = State::Grace { since: now };
        self.deadline = Some(now + self.config.grace());
        vec![Action::Log(format!(
            "no service; entering LPM in {} min unless service returns",
            self.config.grace_min
        ))]
    }

    /// Service is back: leave LPM if we put the modem there and restore the knobs.
    fn recover(&mut self, why: &str, now: Instant) -> Vec<Action> {
        let probes = match self.state {
            State::Quiet { probes } | State::Probing { probes } => Some(probes),
            _ => None,
        };
        let since = self.no_service_since.take();
        let mut actions = self.stand_down(why, true);
        if let (Some(probes), Some(since)) = (probes, since) {
            actions.push(Action::Log(format!(
                "{why} after {probes} probe(s), {} min without service",
                now.saturating_duration_since(since).as_secs() / 60
            )));
        }
        actions
    }

    /// Return to [`State::Idle`], undoing whatever the cycle has done.
    /// `go_online` is false when the modem must stay in LPM (the user asked
    /// for it) or the caller brings it online itself.
    fn stand_down(&mut self, why: &str, go_online: bool) -> Vec<Action> {
        let mut actions = Vec::new();
        match self.state {
            State::Idle => return actions,
            State::Grace { .. } => actions.push(Action::Log(format!("{why}; grace cancelled"))),
            State::Quiet { .. } if go_online => {
                actions.push(Action::Log(format!(
                    "{why}; leaving LPM and restoring knobs"
                )));
                actions.push(Action::RestoreKnobs);
                actions.push(Action::GoOnline);
            }
            State::Quiet { .. } => {
                actions.push(Action::Log(format!("{why}; restoring knobs")));
                actions.push(Action::RestoreKnobs);
            }
            State::Probing { .. } => {
                actions.push(Action::Log(format!(
                    "{why}; staying online and restoring knobs"
                )));
                actions.push(Action::RestoreKnobs);
            }
        }
        self.state = State::Idle;
        self.deadline = None;
        self.knobs_quiet = false;
        actions
    }

    fn blocked_until(&self, now: Instant) -> Option<(Instant, String)> {
        if let Some(reason) = (self.busy)() {
            return Some((now + GUARD_RETRY, format!("{reason} in progress")));
        }
        if let Some(at) = self.user_activity {
            let until = at + USER_ACTIVITY_GUARD;
            if now < until {
                return Some((until, "recent user modem change".into()));
            }
        }
        None
    }
}

// ── Side effects ────────────────────────────────────────────────────

pub trait Effects: Send {
    /// `ubus call zte_nwinfo_api nwinfo_set_mode {"operate_mode":"LPM"}`.
    fn set_lpm(&self) -> Result<(), String>;
    /// `AT+CFUN=1` sent directly through `crate::at_cmd::send` (the same
    /// command `handlers::modem_online` uses, but not through the handler:
    /// the wiring may count handler calls as user activity).
    fn go_online(&self) -> Result<(), String>;
    fn read_knobs(&self) -> Result<Knobs, String>;
    /// `uci set` the three knobs and `uci commit zte_nwinfo`.
    fn write_knobs(&self, knobs: &Knobs) -> Result<(), String>;
    /// `zte_nwinfo.sys_info.operate_mode` (`ONLINE`/`LPM`), checked before
    /// entering LPM so an airplane mode set outside the agent is respected.
    /// `None` skips the check.
    fn operate_mode(&self) -> Option<String> {
        None
    }
    /// Current service state, read once at thread start (the ubus event only
    /// fires on change). `None` waits for the first event.
    fn read_service(&self) -> Option<bool> {
        None
    }
}

/// Returns `Some(reason)` while a call, USSD session or speed test is active.
/// Called only when an action is about to run (a few times per outage), so
/// it may afford a quick `AT+CLCC` when a call flag is set; it is never
/// called on service events or while idle.
pub type BusyCheck = Box<dyn Fn() -> Option<&'static str> + Send>;

pub struct DeviceEffects {
    app: Arc<AppState>,
}

impl DeviceEffects {
    pub fn new(app: Arc<AppState>) -> Self {
        Self { app }
    }
}

impl Effects for DeviceEffects {
    fn set_lpm(&self) -> Result<(), String> {
        ubus::call(
            "zte_nwinfo_api",
            "nwinfo_set_mode",
            Some(r#"{"operate_mode":"LPM"}"#),
        )
        .map(|_| ())
    }

    fn go_online(&self) -> Result<(), String> {
        // Same command as handlers::modem_online, sent directly: going
        // through the handler would let an instrumented handler report the
        // policy's own action as a user mode change.
        let resp = crate::at_cmd::send(&self.app.at_port, "AT+CFUN=1", 8)?;
        if resp.contains("OK") {
            Ok(())
        } else {
            Err(format!("AT+CFUN=1 failed: {}", resp.trim()))
        }
    }

    fn read_knobs(&self) -> Result<Knobs, String> {
        Knobs::from_uci_show(&ubus::uci_show(KNOB_UCI_SECTION)?)
    }

    fn write_knobs(&self, knobs: &Knobs) -> Result<(), String> {
        for (key, value) in knobs.pairs() {
            ubus::uci_set_no_commit(key, value)?;
        }
        ubus::uci_commit(KNOB_SECTION)
    }

    fn operate_mode(&self) -> Option<String> {
        ubus::uci_get("zte_nwinfo.sys_info.operate_mode").ok()
    }

    fn read_service(&self) -> Option<bool> {
        ubus::call("zte_nwinfo_api", "nwinfo_get_netinfo", Some("{}"))
            .ok()
            .and_then(|v| service_from_event(&v))
    }
}

/// Executes actions and owns the knob backup (in memory and on disk).
struct Executor {
    effects: Box<dyn Effects>,
    backup_path: PathBuf,
    backup: Option<Knobs>,
    /// The knobs actually hold the quiet values (a backup exists and the
    /// last write was the quiet set).
    knobs_quiet: bool,
    /// A restore failed: retry at this instant (doubling delay).
    retry_at: Option<Instant>,
    retry_delay: Duration,
}

impl Executor {
    fn new(effects: Box<dyn Effects>, backup_path: PathBuf) -> Self {
        let backup = fs::read_to_string(&backup_path)
            .ok()
            .and_then(|s| serde_json::from_str::<Knobs>(&s).ok());
        Self {
            effects,
            backup_path,
            knobs_quiet: backup.is_some(),
            backup,
            retry_at: None,
            retry_delay: RESTORE_RETRY,
        }
    }

    /// A backup left behind by a previous run means the knobs are still
    /// quiet and that run may have parked the modem in LPM: restore the
    /// knobs and bring the modem back online.
    fn restore_leftover(&mut self, now: Instant) {
        if self.backup.is_none() {
            return;
        }
        eprintln!("[oos_policy] knob backup found from a previous run; restoring");
        self.perform(Action::RestoreKnobs, now);
        // Independent of the restore outcome (the retry path handles the
        // knobs). The machine starts Idle with no grace timer, so a modem
        // left in LPM would otherwise stay there until a service event,
        // which an LPM modem never produces. An unreadable mode is treated
        // as LPM: one AT+CFUN=1 on an online modem is harmless.
        if matches!(self.effects.operate_mode().as_deref(), Some("LPM") | None) {
            eprintln!("[oos_policy] leftover LPM from a previous run, bringing the modem online");
            self.perform(Action::GoOnline, now);
        }
    }

    /// Instant of the pending restore retry, if a restore failed.
    fn retry_deadline(&self) -> Option<Instant> {
        self.retry_at
    }

    /// Retry a failed restore once its deadline has passed.
    fn retry_restore(&mut self, now: Instant) {
        match self.retry_at {
            Some(at) if now >= at => {}
            _ => return,
        }
        if self.backup.is_none() {
            self.retry_at = None;
            return;
        }
        eprintln!("[oos_policy] retrying knob restore");
        self.perform(Action::RestoreKnobs, now);
    }

    /// Perform one action. `Some(event)` aborts the rest of the batch and
    /// feeds that event back to the machine.
    fn perform(&mut self, action: Action, now: Instant) -> Option<Event> {
        match action {
            Action::Log(message) => eprintln!("[oos_policy] {message}"),
            Action::SetQuietKnobs => {
                if let Some(mode) = self.effects.operate_mode() {
                    if mode != "ONLINE" {
                        eprintln!("[oos_policy] operate_mode is {mode}, not ONLINE; not starting the cycle");
                        return Some(Event::Standby);
                    }
                }
                // A new cycle supersedes any pending restore retry.
                self.retry_at = None;
                self.retry_delay = RESTORE_RETRY;
                match self.effects.read_knobs() {
                    Ok(current) => {
                        if self.backup.is_none() && current != Knobs::quiet() {
                            // The backup must be on disk before the knobs
                            // change: without it an agent restart has
                            // nothing to restore and the owner's values are
                            // lost.
                            let saved = serde_json::to_string(&current)
                                .map_err(|e| e.to_string())
                                .and_then(|json| {
                                    fs::write(&self.backup_path, json).map_err(|e| e.to_string())
                                });
                            if let Err(e) = saved {
                                eprintln!(
                                    "[oos_policy] cannot back up knobs: {e}; leaving them unchanged"
                                );
                                return None;
                            }
                            self.backup = Some(current);
                        }
                        match self.effects.write_knobs(&Knobs::quiet()) {
                            Ok(()) => {
                                self.knobs_quiet = true;
                                eprintln!("[oos_policy] firmware knobs set to quiet values")
                            }
                            Err(e) => eprintln!("[oos_policy] failed to quiet knobs: {e}"),
                        }
                    }
                    Err(e) => {
                        eprintln!("[oos_policy] cannot read knobs ({e}); leaving them as they are")
                    }
                }
            }
            Action::RestoreKnobs => match self.backup.take() {
                Some(saved) => match self.effects.write_knobs(&saved) {
                    Ok(()) => {
                        let _ = fs::remove_file(&self.backup_path);
                        self.knobs_quiet = false;
                        self.retry_at = None;
                        self.retry_delay = RESTORE_RETRY;
                        eprintln!("[oos_policy] firmware knobs restored");
                    }
                    Err(e) => {
                        self.backup = Some(saved);
                        self.retry_at = Some(now + self.retry_delay);
                        eprintln!(
                            "[oos_policy] failed to restore knobs: {e}; retry in {} s",
                            self.retry_delay.as_secs()
                        );
                        self.retry_delay = (self.retry_delay * 2).min(RESTORE_RETRY_MAX);
                    }
                },
                None => eprintln!("[oos_policy] no knob backup; nothing to restore"),
            },
            Action::SetLpm => match self.effects.set_lpm() {
                Ok(()) => eprintln!("[oos_policy] modem set to LPM"),
                Err(e) => eprintln!("[oos_policy] set LPM failed: {e}"),
            },
            Action::GoOnline => match self.effects.go_online() {
                Ok(()) => eprintln!("[oos_policy] modem set ONLINE"),
                Err(e) => eprintln!("[oos_policy] go online failed: {e}"),
            },
        }
        None
    }
}

// ── Runtime ─────────────────────────────────────────────────────────

pub struct OosPolicy {
    config: Mutex<Config>,
    tx: Mutex<Option<mpsc::Sender<Event>>>,
    user_activity: Mutex<Option<Instant>>,
    status: Mutex<Value>,
    /// The policy thread; user-activity reports from it are the policy's
    /// own effects echoed back through an instrumented handler.
    thread: Mutex<Option<ThreadId>>,
    config_path: PathBuf,
    knob_backup_path: PathBuf,
}

impl OosPolicy {
    pub fn new() -> Self {
        Self::with_paths(CONFIG_PATH.into(), KNOB_BACKUP_PATH.into())
    }

    pub fn with_paths(config_path: PathBuf, knob_backup_path: PathBuf) -> Self {
        let config = Config::load(&config_path);
        Self {
            config: Mutex::new(config),
            tx: Mutex::new(None),
            user_activity: Mutex::new(None),
            status: Mutex::new(json!({"state": "stopped"})),
            thread: Mutex::new(None),
            config_path,
            knob_backup_path,
        }
    }

    /// True on the policy thread itself, i.e. inside one of its own effects.
    fn is_own_thread(&self) -> bool {
        *self.thread.lock().unwrap() == Some(std::thread::current().id())
    }

    /// Spawn the policy thread and a forwarder for the `zwrt_servicestatus`
    /// subscription. Call once, after `EventBus::start()`.
    pub fn start(
        self: &Arc<Self>,
        effects: Box<dyn Effects>,
        busy: BusyCheck,
        service_rx: mpsc::Receiver<Value>,
    ) {
        let (tx, rx) = mpsc::channel();
        *self.tx.lock().unwrap() = Some(tx.clone());
        let _ = std::thread::Builder::new()
            .name("oos-service".into())
            .spawn(move || {
                for payload in service_rx {
                    if let Some(has) = service_from_event(&payload) {
                        if tx.send(Event::Service(has)).is_err() {
                            break;
                        }
                    }
                }
            });
        let policy = Arc::clone(self);
        let _ = std::thread::Builder::new()
            .name("oos-policy".into())
            .spawn(move || policy.run(rx, effects, busy));
    }

    fn run(&self, rx: mpsc::Receiver<Event>, effects: Box<dyn Effects>, busy: BusyCheck) {
        *self.thread.lock().unwrap() = Some(std::thread::current().id());
        let mut machine = Machine::new(self.config());
        machine.set_busy_check(busy);
        let mut executor = Executor::new(effects, self.knob_backup_path.clone());
        executor.restore_leftover(Instant::now());
        if let Some(has) = executor.effects.read_service() {
            eprintln!("[oos_policy] initial service state: has_service={has}");
            self.apply(
                &mut machine,
                &mut executor,
                Event::Service(has),
                Instant::now(),
            );
        }
        self.publish(&machine, &executor);
        loop {
            // Sleep until the machine's deadline or a pending restore retry,
            // whichever is first; block without a timeout when neither exists.
            let deadline = match (machine.next_deadline(), executor.retry_deadline()) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let event = match deadline {
                Some(deadline) => {
                    let wait = deadline.saturating_duration_since(Instant::now());
                    match rx.recv_timeout(wait) {
                        Ok(event) => Some(event),
                        Err(mpsc::RecvTimeoutError::Timeout) => None,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                None => match rx.recv() {
                    Ok(event) => Some(event),
                    Err(_) => break,
                },
            };
            let now = Instant::now();
            executor.retry_restore(now);
            // The machine ignores a Timer before its own deadline.
            let event = event.unwrap_or(Event::Timer);
            self.apply(&mut machine, &mut executor, event, now);
            self.publish(&machine, &executor);
        }
        eprintln!("[oos_policy] event channel closed; policy thread exiting");
    }

    fn apply(&self, machine: &mut Machine, executor: &mut Executor, event: Event, now: Instant) {
        let mut pending = Some(event);
        // A batch can abort with a follow-up event (e.g. Standby); bounded so
        // a misbehaving effect cannot loop.
        for _ in 0..4 {
            let Some(event) = pending.take() else { break };
            machine.set_user_activity(*self.user_activity.lock().unwrap());
            let actions = machine.step(event, now);
            for action in actions {
                if let Some(follow_up) = executor.perform(action, now) {
                    pending = Some(follow_up);
                    break;
                }
            }
        }
    }

    fn publish(&self, machine: &Machine, executor: &Executor) {
        let mut status = machine.status(Instant::now());
        // The machine reports intent; the executor knows what the uci writes did.
        status["knobs_quiet"] = json!(executor.knobs_quiet);
        status["knob_restore_pending"] = json!(executor.retry_at.is_some());
        *self.status.lock().unwrap() = status;
    }

    fn send(&self, event: Event) {
        if let Some(tx) = self.tx.lock().unwrap().as_ref() {
            let _ = tx.send(event);
        }
    }

    /// Feed a `zwrt_servicestatus` payload directly (alternative to the
    /// receiver passed to [`OosPolicy::start`]).
    #[allow(dead_code)]
    pub fn service_event(&self, payload: &Value) {
        if let Some(has) = service_from_event(payload) {
            self.send(Event::Service(has));
        }
    }

    /// The user changed the operate mode through `PUT /api/modem/airplane`:
    /// `online == true` for ONLINE (leave the LPM cycle immediately), `false`
    /// for LPM (suspend the policy). Also counts as user activity.
    ///
    /// Ignored when called from the policy thread: that is one of the
    /// policy's own effects echoed back through an instrumented handler,
    /// not a user change.
    pub fn user_mode(&self, online: bool) {
        if self.is_own_thread() {
            eprintln!(
                "[oos_policy] ignoring user_mode({online}) reported by the policy's own action"
            );
            return;
        }
        self.set_user_activity(Instant::now());
        self.send(Event::UserMode(online));
    }

    /// Record a user-initiated modem change (network mode, data toggle,
    /// airplane, cell lock...). No policy action within
    /// [`USER_ACTIVITY_GUARD`] of it. Ignored from the policy thread (see
    /// [`OosPolicy::user_mode`]).
    pub fn set_user_activity(&self, at: Instant) {
        if self.is_own_thread() {
            return;
        }
        *self.user_activity.lock().unwrap() = Some(at);
    }

    pub fn config(&self) -> Config {
        self.config.lock().unwrap().clone()
    }

    pub fn status(&self) -> Value {
        self.status.lock().unwrap().clone()
    }

    /// Validate, persist and apply a partial config update.
    pub fn update(&self, patch: &Value) -> Result<Config, String> {
        let mut config = self.config.lock().unwrap();
        let next = config.patched(patch)?;
        if next != *config {
            *config = next.clone();
            config.save(&self.config_path);
            self.send(Event::Config(next.clone()));
        }
        Ok(next)
    }
}

// ── HTTP handlers ───────────────────────────────────────────────────

fn config_json(config: &Config, status: Value) -> Value {
    json!({"ok": true, "data": {
        "enabled": config.enabled,
        "grace_min": config.grace_min,
        "probe_every_min": config.probe_every_min,
        "probe_window_min": config.probe_window_min,
        "status": status,
    }})
}

/// GET /api/modem/oos-policy
pub fn config_get(policy: &OosPolicy) -> (u16, Value) {
    (200, config_json(&policy.config(), policy.status()))
}

/// PUT /api/modem/oos-policy — body: any of `{enabled, grace_min,
/// probe_every_min, probe_window_min}`.
pub fn config_set(policy: &OosPolicy, body: &[u8]) -> (u16, Value) {
    let patch: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    match policy.update(&patch) {
        Ok(config) => (200, config_json(&config, policy.status())),
        Err(e) => (400, json!({"ok": false, "error": e})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const MIN: Duration = Duration::from_secs(60);

    fn config() -> Config {
        Config {
            enabled: true,
            ..Config::default()
        }
    }

    fn enabled_with_no_service(t0: Instant) -> Machine {
        let mut m = Machine::new(config());
        assert_eq!(
            m.step(Event::Service(false), t0),
            vec![Action::Log(
                "no service; entering LPM in 10 min unless service returns".into()
            )]
        );
        assert_eq!(m.state(), &State::Grace { since: t0 });
        assert_eq!(m.next_deadline(), Some(t0 + 10 * MIN));
        m
    }

    fn without_logs(actions: Vec<Action>) -> Vec<Action> {
        actions
            .into_iter()
            .filter(|a| !matches!(a, Action::Log(_)))
            .collect()
    }

    #[test]
    fn classifies_network_type() {
        assert_eq!(
            service_from_event(&json!({"network_type": "NO_SERVICE"})),
            Some(false)
        );
        assert_eq!(
            service_from_event(&json!({"network_type": "LIMITED_SERVICE_EMERGENCY"})),
            Some(false)
        );
        assert_eq!(
            service_from_event(&json!({"network_type": "LTE"})),
            Some(true)
        );
        assert_eq!(
            service_from_event(&json!({"network_type": "5G_NSA"})),
            Some(true)
        );
        assert_eq!(service_from_event(&json!({"network_type": ""})), None);
        assert_eq!(service_from_event(&json!({"other": 1})), None);
    }

    #[test]
    fn config_defaults_and_validation() {
        let c: Config = serde_json::from_str("{}").unwrap();
        assert_eq!(c, Config::default());
        assert!(!c.enabled);
        assert_eq!(
            (c.grace_min, c.probe_every_min, c.probe_window_min),
            (10, 20, 3)
        );
        let c = c
            .patched(&json!({"enabled": true, "grace_min": 5}))
            .unwrap();
        assert!(c.enabled);
        assert_eq!(c.grace_min, 5);
        assert!(c.patched(&json!({"grace_min": 0})).is_err());
        assert!(c.patched(&json!({"probe_every_min": 1000})).is_err());
        assert!(c.patched(&json!({"enabled": "yes"})).is_err());
        assert_eq!(c.probe_interval(0), 20 * MIN);
        assert_eq!(c.probe_interval(1), 40 * MIN);
        assert_eq!(c.probe_interval(2), 60 * MIN);
        assert_eq!(c.probe_interval(40), 60 * MIN);
        // A configured interval above the 60-min cap is honoured, not clamped.
        let long = c.patched(&json!({"probe_every_min": 120})).unwrap();
        assert_eq!(long.probe_interval(0), 120 * MIN);
        assert_eq!(long.probe_interval(1), 120 * MIN);
        assert_eq!(long.probe_interval(40), 120 * MIN);
    }

    #[test]
    fn parses_knobs_from_uci_show() {
        let show = "zte_nwinfo.sys_info=sys_info\n\
                    zte_nwinfo.sys_info.operate_mode='ONLINE'\n\
                    zte_nwinfo.sys_info.ps_no_srv_check_timer_cfg='5'\n\
                    zte_nwinfo.sys_info.abs_lpm_online_max_times_cfg='3'\n\
                    zte_nwinfo.sys_info.abs_restart_max_times_cfg='3'\n\
                    zte_nwinfo.sys_info.net_select='LTE_AND_5G'\n";
        assert_eq!(Knobs::from_uci_show(show).unwrap(), firmware_knobs());
        // A missing knob is an error, not a default.
        let partial = "zte_nwinfo.sys_info.ps_no_srv_check_timer_cfg='5'\n";
        assert!(Knobs::from_uci_show(partial).is_err());
        assert!(Knobs::from_uci_show("").is_err());
    }

    #[test]
    fn disabled_policy_ignores_no_service() {
        let t0 = Instant::now();
        let mut m = Machine::new(Config::default());
        assert!(m.step(Event::Service(false), t0).is_empty());
        assert_eq!(m.state(), &State::Idle);
        assert_eq!(m.next_deadline(), None);
        // Enabling later with no service starts the grace period.
        let actions = m.step(Event::Config(config()), t0 + MIN);
        assert!(without_logs(actions).is_empty());
        assert_eq!(m.state(), &State::Grace { since: t0 + MIN });
        assert_eq!(m.next_deadline(), Some(t0 + 11 * MIN));
    }

    #[test]
    fn service_during_grace_cancels_without_actions() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        let actions = m.step(Event::Service(true), t0 + 3 * MIN);
        assert!(without_logs(actions).is_empty());
        assert_eq!(m.state(), &State::Idle);
        assert_eq!(m.next_deadline(), None);
        // A new outage starts a fresh grace period.
        m.step(Event::Service(false), t0 + 4 * MIN);
        assert_eq!(m.next_deadline(), Some(t0 + 14 * MIN));
    }

    #[test]
    fn grace_expiry_quiets_knobs_and_enters_lpm() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        // Early wakeups do nothing.
        assert!(m.step(Event::Timer, t0 + 9 * MIN).is_empty());
        assert_eq!(m.state(), &State::Grace { since: t0 });
        let actions = m.step(Event::Timer, t0 + 10 * MIN);
        assert_eq!(
            without_logs(actions),
            vec![Action::SetQuietKnobs, Action::SetLpm]
        );
        assert_eq!(m.state(), &State::Quiet { probes: 0 });
        assert!(m.knobs_quiet());
        assert_eq!(m.next_deadline(), Some(t0 + 30 * MIN));
    }

    #[test]
    fn probe_cycle_doubles_up_to_one_hour() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        m.step(Event::Timer, t0 + 10 * MIN);
        let mut now = t0 + 30 * MIN;
        let expected_waits = [40, 60, 60, 60];
        for (i, wait) in expected_waits.iter().enumerate() {
            let probes = i as u32 + 1;
            assert_eq!(
                without_logs(m.step(Event::Timer, now)),
                vec![Action::GoOnline]
            );
            assert_eq!(m.state(), &State::Probing { probes });
            assert_eq!(m.next_deadline(), Some(now + 3 * MIN));
            // NO_SERVICE events while online are ignored.
            assert!(m.step(Event::Service(false), now + MIN).is_empty());
            now += 3 * MIN;
            assert_eq!(
                without_logs(m.step(Event::Timer, now)),
                vec![Action::SetLpm]
            );
            assert_eq!(m.state(), &State::Quiet { probes });
            assert_eq!(m.next_deadline(), Some(now + *wait * MIN));
            now += *wait * MIN;
        }
    }

    #[test]
    fn service_while_probing_restores_knobs_and_stays_online() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        m.step(Event::Timer, t0 + 10 * MIN);
        m.step(Event::Timer, t0 + 30 * MIN);
        let actions = m.step(Event::Service(true), t0 + 31 * MIN);
        assert_eq!(without_logs(actions.clone()), vec![Action::RestoreKnobs]);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::Log(s) if s.contains("after 1 probe(s), 31 min"))));
        assert_eq!(m.state(), &State::Idle);
        assert!(!m.knobs_quiet());
        assert_eq!(m.next_deadline(), None);
    }

    #[test]
    fn service_while_in_lpm_goes_online_and_restores_knobs() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        m.step(Event::Timer, t0 + 10 * MIN);
        let actions = m.step(Event::Service(true), t0 + 12 * MIN);
        assert_eq!(
            without_logs(actions),
            vec![Action::RestoreKnobs, Action::GoOnline]
        );
        assert_eq!(m.state(), &State::Idle);
        assert_eq!(m.next_deadline(), None);
    }

    #[test]
    fn user_online_leaves_cycle_and_restarts_grace_under_guard() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        m.step(Event::Timer, t0 + 10 * MIN);
        let actions = m.step(Event::UserMode(true), t0 + 15 * MIN);
        // The airplane handler sends AT+CFUN=1 itself: no GoOnline here.
        assert_eq!(without_logs(actions), vec![Action::RestoreKnobs]);
        assert_eq!(
            m.state(),
            &State::Grace {
                since: t0 + 15 * MIN
            }
        );
        assert_eq!(m.next_deadline(), Some(t0 + 25 * MIN));
        // The grace expiry is after the 2-min guard, so it acts normally.
        assert_eq!(
            without_logs(m.step(Event::Timer, t0 + 25 * MIN)),
            vec![Action::SetQuietKnobs, Action::SetLpm]
        );
    }

    #[test]
    fn user_lpm_suspends_policy_until_online_or_service() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        m.step(Event::Timer, t0 + 10 * MIN);
        let actions = m.step(Event::UserMode(false), t0 + 12 * MIN);
        assert_eq!(without_logs(actions), vec![Action::RestoreKnobs]);
        assert_eq!(m.state(), &State::Idle);
        assert_eq!(m.next_deadline(), None);
        // The modem's own NO_SERVICE on entering LPM must not restart the cycle.
        assert!(m
            .step(
                Event::Service(false),
                t0 + 12 * MIN + Duration::from_secs(2)
            )
            .is_empty());
        assert_eq!(m.state(), &State::Idle);
        // ONLINE again, still no service: grace restarts.
        let actions = m.step(Event::UserMode(true), t0 + 60 * MIN);
        assert!(without_logs(actions).is_empty());
        assert_eq!(
            m.state(),
            &State::Grace {
                since: t0 + 60 * MIN
            }
        );
    }

    #[test]
    fn standby_when_modem_is_not_online() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        m.step(Event::Timer, t0 + 10 * MIN);
        let actions = m.step(Event::Standby, t0 + 10 * MIN);
        // Restoring is a no-op without a backup; GoOnline must not be issued
        // because the modem is in LPM on purpose.
        assert_eq!(without_logs(actions), vec![Action::RestoreKnobs]);
        assert_eq!(m.state(), &State::Idle);
        assert_eq!(m.next_deadline(), None);
        // Unlike a user LPM, the next NO_SERVICE event restarts the grace.
        m.step(Event::Service(false), t0 + 12 * MIN);
        assert_eq!(
            m.state(),
            &State::Grace {
                since: t0 + 12 * MIN
            }
        );
    }

    #[test]
    fn busy_guard_defers_and_retries() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        let checks = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&checks);
        m.set_busy_check(Box::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
            Some("voice call")
        }));
        // Service events never consult the guard.
        m.step(Event::Service(false), t0 + MIN);
        assert_eq!(checks.load(Ordering::Relaxed), 0);
        let actions = m.step(Event::Timer, t0 + 10 * MIN);
        assert_eq!(
            actions,
            vec![Action::Log(
                "action deferred 60 s: voice call in progress".into()
            )]
        );
        assert_eq!(checks.load(Ordering::Relaxed), 1);
        assert_eq!(m.state(), &State::Grace { since: t0 });
        assert_eq!(m.next_deadline(), Some(t0 + 11 * MIN));
        m.set_busy_check(Box::new(|| None));
        assert_eq!(
            without_logs(m.step(Event::Timer, t0 + 11 * MIN)),
            vec![Action::SetQuietKnobs, Action::SetLpm]
        );
    }

    #[test]
    fn user_activity_guard_waits_two_minutes() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        m.set_user_activity(Some(t0 + 9 * MIN));
        let actions = m.step(Event::Timer, t0 + 10 * MIN);
        assert_eq!(
            actions,
            vec![Action::Log(
                "action deferred 60 s: recent user modem change".into()
            )]
        );
        assert_eq!(m.next_deadline(), Some(t0 + 11 * MIN));
        assert_eq!(
            without_logs(m.step(Event::Timer, t0 + 11 * MIN)),
            vec![Action::SetQuietKnobs, Action::SetLpm]
        );
    }

    #[test]
    fn disabling_while_in_lpm_goes_online_and_restores() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        m.step(Event::Timer, t0 + 10 * MIN);
        let actions = m.step(Event::Config(Config::default()), t0 + 20 * MIN);
        assert_eq!(
            without_logs(actions),
            vec![Action::RestoreKnobs, Action::GoOnline]
        );
        assert_eq!(m.state(), &State::Idle);
        assert_eq!(m.next_deadline(), None);
        assert!(m.step(Event::Service(false), t0 + 21 * MIN).is_empty());
    }

    #[test]
    fn config_change_during_grace_moves_deadline() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        let shorter = Config {
            grace_min: 2,
            ..config()
        };
        assert!(m.step(Event::Config(shorter), t0 + 5 * MIN).is_empty());
        // Already past the new grace: fire on the next wakeup.
        assert_eq!(m.next_deadline(), Some(t0 + 5 * MIN));
    }

    #[test]
    fn status_reports_state_and_deadline() {
        let t0 = Instant::now();
        let mut m = enabled_with_no_service(t0);
        let s = m.status(t0 + 2 * MIN);
        assert_eq!(s["state"], "grace");
        assert_eq!(s["has_service"], false);
        assert_eq!(s["no_service_secs"], 120);
        assert_eq!(s["next_deadline_secs"], 480);
        m.step(Event::Timer, t0 + 10 * MIN);
        assert_eq!(m.status(t0 + 10 * MIN)["state"], "lpm");
        assert_eq!(m.status(t0 + 10 * MIN)["knobs_quiet"], true);
    }

    // ── executor ────────────────────────────────────────────────────

    struct Mock {
        calls: Arc<Mutex<Vec<String>>>,
        knobs: Arc<Mutex<Knobs>>,
        mode: Option<String>,
        /// `write_knobs` fails while set (a uci failure).
        fail_write: Arc<AtomicBool>,
        /// Simulates a wired `handlers::modem_online` that reports the
        /// mode change to the policy as a user action.
        echo_to: Option<Arc<OosPolicy>>,
    }

    impl Mock {
        fn new(calls: Arc<Mutex<Vec<String>>>, knobs: Knobs, mode: Option<&str>) -> Self {
            Self {
                calls,
                knobs: Arc::new(Mutex::new(knobs)),
                mode: mode.map(str::to_string),
                fail_write: Arc::new(AtomicBool::new(false)),
                echo_to: None,
            }
        }
    }

    impl Effects for Mock {
        fn set_lpm(&self) -> Result<(), String> {
            self.calls.lock().unwrap().push("lpm".into());
            Ok(())
        }
        fn go_online(&self) -> Result<(), String> {
            self.calls.lock().unwrap().push("online".into());
            if let Some(policy) = &self.echo_to {
                policy.user_mode(true);
            }
            Ok(())
        }
        fn read_knobs(&self) -> Result<Knobs, String> {
            Ok(self.knobs.lock().unwrap().clone())
        }
        fn write_knobs(&self, knobs: &Knobs) -> Result<(), String> {
            if self.fail_write.load(Ordering::Relaxed) {
                return Err("uci commit zte_nwinfo: read-only".into());
            }
            self.calls
                .lock()
                .unwrap()
                .push(format!("knobs={}", knobs.ps_no_srv_check_timer_cfg));
            *self.knobs.lock().unwrap() = knobs.clone();
            Ok(())
        }
        fn operate_mode(&self) -> Option<String> {
            self.mode.clone()
        }
    }

    fn firmware_knobs() -> Knobs {
        Knobs {
            ps_no_srv_check_timer_cfg: "5".into(),
            abs_lpm_online_max_times_cfg: "3".into(),
            abs_restart_max_times_cfg: "3".into(),
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("oos-{name}-{}-{n}", std::process::id()))
    }

    #[test]
    fn executor_backs_up_quiets_and_restores_knobs() {
        let backup = temp_path("knobs");
        let now = Instant::now();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock::new(Arc::clone(&calls), firmware_knobs(), Some("ONLINE"));
        let knobs = Arc::clone(&mock.knobs);
        let mut ex = Executor::new(Box::new(mock), backup.clone());
        assert!(!ex.knobs_quiet);
        assert_eq!(ex.perform(Action::SetQuietKnobs, now), None);
        assert!(ex.knobs_quiet);
        assert_eq!(*knobs.lock().unwrap(), Knobs::quiet());
        let saved: Knobs = serde_json::from_str(&fs::read_to_string(&backup).unwrap()).unwrap();
        assert_eq!(saved, firmware_knobs());
        assert_eq!(ex.perform(Action::SetLpm, now), None);
        assert_eq!(ex.perform(Action::RestoreKnobs, now), None);
        assert!(!ex.knobs_quiet);
        assert_eq!(*knobs.lock().unwrap(), firmware_knobs());
        assert!(!backup.exists());
        assert_eq!(*calls.lock().unwrap(), vec!["knobs=60", "lpm", "knobs=5"]);
        // Nothing left to restore: no write.
        ex.perform(Action::RestoreKnobs, now);
        assert_eq!(calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn executor_restores_leftover_backup_from_previous_run() {
        let backup = temp_path("leftover");
        fs::write(&backup, serde_json::to_string(&firmware_knobs()).unwrap()).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock::new(Arc::clone(&calls), Knobs::quiet(), None);
        let knobs = Arc::clone(&mock.knobs);
        let mut ex = Executor::new(Box::new(mock), backup.clone());
        assert!(ex.knobs_quiet);
        ex.restore_leftover(Instant::now());
        assert!(!ex.knobs_quiet);
        assert_eq!(*knobs.lock().unwrap(), firmware_knobs());
        assert!(!backup.exists());
        // The mode could not be read: one AT+CFUN=1 is sent just in case.
        assert_eq!(*calls.lock().unwrap(), vec!["knobs=5", "online"]);
    }

    fn leftover_backup(name: &str) -> PathBuf {
        let backup = temp_path(name);
        fs::write(&backup, serde_json::to_string(&firmware_knobs()).unwrap()).unwrap();
        backup
    }

    /// Regression: after a restart with a leftover backup the knobs were
    /// restored but the modem stayed in the LPM the previous run had parked
    /// it in, and nothing ever brought it back online.
    #[test]
    fn executor_brings_leftover_lpm_modem_online() {
        // Parked in LPM by the previous run: knobs restored, then ONLINE.
        let backup = leftover_backup("leftover-lpm");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock::new(Arc::clone(&calls), Knobs::quiet(), Some("LPM"));
        let mut ex = Executor::new(Box::new(mock), backup.clone());
        ex.restore_leftover(Instant::now());
        assert_eq!(*calls.lock().unwrap(), vec!["knobs=5", "online"]);
        assert!(!backup.exists());

        // Already online: the knobs are restored and nothing else is sent.
        let backup = leftover_backup("leftover-online");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock::new(Arc::clone(&calls), Knobs::quiet(), Some("ONLINE"));
        let mut ex = Executor::new(Box::new(mock), backup.clone());
        ex.restore_leftover(Instant::now());
        assert_eq!(*calls.lock().unwrap(), vec!["knobs=5"]);
        assert!(!backup.exists());

        // The restore fails: the modem still goes online, the knobs are
        // left to the retry path.
        let backup = leftover_backup("leftover-retry");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock::new(Arc::clone(&calls), Knobs::quiet(), Some("LPM"));
        mock.fail_write.store(true, Ordering::Relaxed);
        let mut ex = Executor::new(Box::new(mock), backup.clone());
        ex.restore_leftover(Instant::now());
        assert_eq!(*calls.lock().unwrap(), vec!["online"]);
        assert!(ex.retry_deadline().is_some());
        assert!(backup.exists());
        let _ = fs::remove_file(&backup);

        // No backup: this policy did not park the modem; leave it alone.
        let backup = temp_path("leftover-none");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock::new(Arc::clone(&calls), firmware_knobs(), Some("LPM"));
        let mut ex = Executor::new(Box::new(mock), backup);
        ex.restore_leftover(Instant::now());
        assert!(calls.lock().unwrap().is_empty());
    }

    /// Regression: a failed backup write used to be ignored and the knobs
    /// quieted anyway, losing the owner's values across a restart.
    #[test]
    fn executor_leaves_knobs_alone_when_backup_cannot_be_written() {
        // A directory as the backup path makes the write fail, like a full
        // or read-only /data on the device.
        let backup = temp_path("unwritable");
        fs::create_dir_all(&backup).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock::new(Arc::clone(&calls), firmware_knobs(), Some("ONLINE"));
        let knobs = Arc::clone(&mock.knobs);
        let mut ex = Executor::new(Box::new(mock), backup.clone());
        assert_eq!(ex.perform(Action::SetQuietKnobs, Instant::now()), None);
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(*knobs.lock().unwrap(), firmware_knobs());
        assert!(!ex.knobs_quiet);
        assert_eq!(ex.backup, None);
        let _ = fs::remove_dir(&backup);
    }

    #[test]
    fn executor_stands_by_when_modem_is_not_online() {
        let backup = temp_path("standby");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock::new(Arc::clone(&calls), firmware_knobs(), Some("LPM"));
        let mut ex = Executor::new(Box::new(mock), backup.clone());
        assert_eq!(
            ex.perform(Action::SetQuietKnobs, Instant::now()),
            Some(Event::Standby)
        );
        assert!(calls.lock().unwrap().is_empty());
        assert!(!backup.exists());
    }

    #[test]
    fn executor_retries_a_failed_restore_with_backoff() {
        let backup = temp_path("retry");
        let t0 = Instant::now();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock::new(Arc::clone(&calls), firmware_knobs(), Some("ONLINE"));
        let knobs = Arc::clone(&mock.knobs);
        let fail_write = Arc::clone(&mock.fail_write);
        let mut ex = Executor::new(Box::new(mock), backup.clone());
        ex.perform(Action::SetQuietKnobs, t0);
        assert_eq!(ex.retry_deadline(), None);

        // uci breaks: the backup is kept and a retry is armed one minute out.
        fail_write.store(true, Ordering::Relaxed);
        ex.perform(Action::RestoreKnobs, t0 + 10 * MIN);
        assert_eq!(ex.backup, Some(firmware_knobs()));
        assert!(ex.knobs_quiet);
        assert!(backup.exists());
        assert_eq!(ex.retry_deadline(), Some(t0 + 11 * MIN));
        // Not due yet: nothing happens.
        ex.retry_restore(t0 + 10 * MIN + Duration::from_secs(30));
        assert_eq!(ex.retry_deadline(), Some(t0 + 11 * MIN));
        // Still failing: the delay doubles.
        ex.retry_restore(t0 + 11 * MIN);
        assert_eq!(ex.retry_deadline(), Some(t0 + 13 * MIN));
        ex.retry_restore(t0 + 13 * MIN);
        assert_eq!(ex.retry_deadline(), Some(t0 + 17 * MIN));

        // uci works again: restored, retry cleared, backup file gone.
        fail_write.store(false, Ordering::Relaxed);
        ex.retry_restore(t0 + 17 * MIN);
        assert_eq!(ex.retry_deadline(), None);
        assert_eq!(ex.backup, None);
        assert!(!ex.knobs_quiet);
        assert_eq!(*knobs.lock().unwrap(), firmware_knobs());
        assert!(!backup.exists());
        assert_eq!(*calls.lock().unwrap(), vec!["knobs=60", "knobs=5"]);

        // The delay is back to the base value for the next failure.
        ex.perform(Action::SetQuietKnobs, t0 + 20 * MIN);
        fail_write.store(true, Ordering::Relaxed);
        ex.perform(Action::RestoreKnobs, t0 + 30 * MIN);
        assert_eq!(ex.retry_deadline(), Some(t0 + 31 * MIN));
        // A new cycle supersedes the pending retry.
        fail_write.store(false, Ordering::Relaxed);
        ex.perform(Action::SetQuietKnobs, t0 + 40 * MIN);
        assert_eq!(ex.retry_deadline(), None);
        assert_eq!(ex.backup, Some(firmware_knobs()));
        let _ = fs::remove_file(&backup);
    }

    /// Regression: with `handlers::modem_online` instrumented to call
    /// `oos_policy.user_mode(true)`, the policy's own probe used to be seen
    /// as a user ONLINE request, which restored the knobs, re-ran the grace
    /// period and reset the probe count on every probe. The runtime must
    /// ignore reports that originate from its own thread.
    #[test]
    fn own_go_online_is_not_a_user_mode_change() {
        let policy = Arc::new(OosPolicy::with_paths(
            temp_path("echo-config"),
            temp_path("echo-knobs"),
        ));
        let (tx, rx) = mpsc::channel();
        *policy.tx.lock().unwrap() = Some(tx);
        // This test thread plays the policy thread.
        *policy.thread.lock().unwrap() = Some(std::thread::current().id());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut mock = Mock::new(Arc::clone(&calls), firmware_knobs(), Some("ONLINE"));
        mock.echo_to = Some(Arc::clone(&policy));
        let mut machine = Machine::new(config());
        let mut executor = Executor::new(Box::new(mock), policy.knob_backup_path.clone());

        let t0 = Instant::now();
        policy.apply(&mut machine, &mut executor, Event::Service(false), t0);
        policy.apply(&mut machine, &mut executor, Event::Timer, t0 + 10 * MIN);
        assert_eq!(machine.state(), &State::Quiet { probes: 0 });
        policy.apply(&mut machine, &mut executor, Event::Timer, t0 + 30 * MIN);
        assert_eq!(*calls.lock().unwrap(), vec!["knobs=60", "lpm", "online"]);
        // The echoed user_mode(true) was dropped: no event queued, no user
        // activity recorded, still probing with the 3-min window.
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert_eq!(*policy.user_activity.lock().unwrap(), None);
        assert_eq!(machine.state(), &State::Probing { probes: 1 });
        assert_eq!(machine.next_deadline(), Some(t0 + 33 * MIN));
        assert!(executor.knobs_quiet);
        // The window ends normally: back to LPM, interval doubled.
        policy.apply(&mut machine, &mut executor, Event::Timer, t0 + 33 * MIN);
        assert_eq!(machine.state(), &State::Quiet { probes: 1 });
        assert_eq!(machine.next_deadline(), Some(t0 + 73 * MIN));
        assert_eq!(calls.lock().unwrap().len(), 4);

        // A real user request from another thread is still delivered.
        let from_http = Arc::clone(&policy);
        std::thread::spawn(move || from_http.user_mode(true))
            .join()
            .unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)),
            Ok(Event::UserMode(true))
        );
        assert!(policy.user_activity.lock().unwrap().is_some());
        let _ = fs::remove_file(&policy.knob_backup_path);
    }

    #[test]
    fn handlers_roundtrip_config() {
        let policy = OosPolicy::with_paths(temp_path("config"), temp_path("knobs"));
        let (status, body) = config_get(&policy);
        assert_eq!(status, 200);
        assert_eq!(body["data"]["enabled"], false);
        assert_eq!(body["data"]["grace_min"], 10);
        let (status, body) = config_set(&policy, br#"{"enabled": true, "probe_every_min": 30}"#);
        assert_eq!(status, 200);
        assert_eq!(body["data"]["enabled"], true);
        assert_eq!(body["data"]["probe_every_min"], 30);
        let reloaded = Config::load(&policy.config_path);
        assert_eq!(reloaded, policy.config());
        let (status, _) = config_set(&policy, br#"{"grace_min": 0}"#);
        assert_eq!(status, 400);
        let (status, _) = config_set(&policy, b"nope");
        assert_eq!(status, 400);
        let _ = fs::remove_file(&policy.config_path);
    }

    #[test]
    fn runtime_applies_events_and_restores_on_disable() {
        let policy = Arc::new(OosPolicy::with_paths(
            temp_path("rt-config"),
            temp_path("rt-knobs"),
        ));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mock = Mock::new(Arc::clone(&calls), firmware_knobs(), Some("ONLINE"));
        let (service_tx, service_rx) = mpsc::channel();
        policy.start(Box::new(mock), Box::new(|| None), service_rx);
        policy
            .update(&json!({"enabled": true, "grace_min": 1}))
            .unwrap();
        service_tx
            .send(json!({"network_type": "NO_SERVICE"}))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while policy.status()["state"] != "grace" && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(policy.status()["state"], "grace");
        assert_eq!(policy.status()["has_service"], false);
        policy.update(&json!({"enabled": false})).unwrap();
        while policy.status()["state"] != "idle" && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(policy.status()["state"], "idle");
        assert!(calls.lock().unwrap().is_empty());
        let _ = fs::remove_file(&policy.config_path);
    }
}
