//! Standby Wi-Fi guard: turns Wi-Fi back off when the firmware switches it on
//! while the router is in fast-boot standby.
//!
//! Fast-boot "power off" is a standby (`mode_power_off_quicken`, or
//! `mode_power_off_charger_quicken` on a cable): Linux and the agent keep
//! running, Wi-Fi and the modem are off. Firmware bug (seen once, 2026-10-21,
//! charging from a computer): the sleep daemon broadcast `gotoWakeup` and
//! ZTE's Wi-Fi daemon started Wi-Fi without checking the power mode. It
//! stayed on, without internet (the modem stays off), until the cable was
//! unplugged.
//!
//! Signals, all event-driven:
//! - the [`POWER_EVENT`] ubus event: any `mode_power_off*` action means
//!   standby until `mode_startup`, `mode_initial` or `mode_power_on*` (a real
//!   power-on, which ZTE broadcasts before it starts Wi-Fi itself);
//! - `/tmp/zteqcawifi_test.txt`, to which the firmware appends `1 <uptime>
//!   power_on success` (or `power_off success`) when a Wi-Fi power change has
//!   finished; the `wifi-watchdog` thread already watches it with inotify and
//!   hands every new complete line to the guard, which also keeps the newest
//!   such report from before the agent started;
//! - the newest `setModeState from X to Y .` line of `/logfs/key.log`,
//!   re-read before acting (a file read, no fork). With no power event seen
//!   yet (the agent was restarted later than [`BOOT_SETTLE`] after boot) the
//!   guard goes by key.log, and acts only if the firmware's previous Wi-Fi
//!   report was `power_off success`; an agent started within [`BOOT_SETTLE`]
//!   of boot takes the router as on until a standby event.
//!
//! When Wi-Fi powers on in settled standby (not while the firmware is still
//! [`entering_standby`]) and key.log agrees, the guard turns it off the way
//! ZTE's own power-off does: `uci set wireless.zte_mbb.wifi_onoff=0`, `uci
//! commit wireless`, `ubus call zwrt_wlan reload` ([`Step`]), on a short-lived
//! thread that gives up before each step if a power-on event arrives
//! meanwhile (reverting a set it did not commit). It never touches
//! `wifi_onoff_by_user` (the user's switch); a real power-on sets
//! `wifi_onoff` back to 1 itself. If the firmware has not reported Wi-Fi off
//! within [`CONFIRM_WITHIN`], it tries once more. At most [`MAX_ACTIONS`]
//! turn-offs per standby period (tries included), then it only logs.
//!
//! After a power-on that ends a standby in which it acted, it expects the
//! firmware to report Wi-Fi on within [`RESTORE_AFTER`]; if the last report
//! is still `power_off success` (a turn-off of ours overlapped the power-on)
//! and the user's switch is on, it switches Wi-Fi on the same way, once.
//!
//! A timer runs only while one of those two reports is awaited; otherwise
//! there is no timer and no fork. Each decision is one log line stamped with
//! `CLOCK_BOOTTIME` seconds, the clock of `/proc/uptime` and of the test
//! log's lines.
//!
//! On by default; [`OPT_OUT_ENV`]`=0` in the agent's environment (its startup
//! script) turns it off.
//!
//! Layout: [`Guard`] is a pure state machine (`step(event, now) ->
//! Vec<Action>`), [`classify_mode`], [`key_log_mode`], [`parse_wifi_line`]
//! and [`user_wants_wifi`] decode the inputs, [`LineCursor`] follows the test
//! log, [`switch_wifi_with`] orders the firmware steps. The Linux runtime is
//! driven by the `wifi-watchdog` thread, which owns the `poll()` loop and the
//! one timerfd: ubus events reach it through an eventfd written by a
//! `wifi-guard-ev` thread that blocks in `recv()`.

// The runtime that drives the pure parts below is Linux-only; on the Mac
// only the tests use them.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fmt;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use serde_json::Value;

use crate::event_bus::EventBus;
use crate::key_log;
use crate::wifi_watchdog::config_option;

pub const POWER_EVENT: &str = "zwrt_device_power_state_event";
/// `ZTE_AGENT_STANDBY_WIFI_GUARD=0` (or `off`, `false`, `no`) turns the guard off.
pub const OPT_OUT_ENV: &str = "ZTE_AGENT_STANDBY_WIFI_GUARD";
/// The firmware's live Wi-Fi switch, the only setting the guard writes;
/// never `wifi_onoff_by_user`, the user's switch.
pub const WIFI_SWITCH: &str = "wireless.zte_mbb.wifi_onoff";
/// Turn-offs (second tries included) per standby period; after that the
/// guard only logs.
pub const MAX_ACTIONS: u8 = 3;
/// How long to wait for the firmware's `power_off success` line after acting.
pub const CONFIRM_WITHIN: Duration = Duration::from_secs(30);
/// After a power-on that ends a standby in which the guard acted, how long
/// the firmware has to report Wi-Fi on (its own Wi-Fi start gives up after
/// ~50 s) before the guard switches it on.
pub const RESTORE_AFTER: Duration = Duration::from_secs(90);
/// An agent started this soon after boot takes the router as on until a
/// standby event: it was started at boot, so any standby comes later, with
/// its event, and key.log, which survives reboots, may still end with the
/// previous session's power-off.
pub const BOOT_SETTLE: Duration = Duration::from_secs(600);
/// Stands for key.log's mode while a `setModeState` line is still being
/// written at its end: it has no power class, so the guard does not act on
/// the older line before it.
pub const MODE_BEING_WRITTEN: &str = "a setModeState line still being written";
/// Read window of the backward key.log scan.
const KEY_LOG_CHUNK: u64 = 64 * 1024;
/// At most this much of the test log is read at once (it grows by ~30 bytes
/// per Wi-Fi change); older unread lines are skipped.
const MAX_FOLLOW: u64 = 16 * 1024;

/// Whether the guard runs, given the value of [`OPT_OUT_ENV`].
pub fn enabled(value: Option<&str>) -> bool {
    let value = value.map(|v| v.trim().to_ascii_lowercase());
    !matches!(value.as_deref(), Some("0" | "off" | "false" | "no"))
}

/// Subscribes the guard to [`POWER_EVENT`] unless it is opted out. Must run
/// before `EventBus::start`, which fixes the `ubus listen` filter. The power
/// key's `zwrt_key.event` is not needed: a short press in standby only shows
/// the battery screen, and a power-on arrives as [`POWER_EVENT`] actions.
pub fn subscribe(bus: &EventBus) -> Option<Receiver<Value>> {
    if enabled(std::env::var(OPT_OUT_ENV).ok().as_deref()) {
        Some(bus.subscribe(POWER_EVENT))
    } else {
        eprintln!("[wifi] standby Wi-Fi guard off ({OPT_OUT_ENV})");
        None
    }
}

// ── Inputs ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Power {
    On,
    Standby,
}

/// The power class of a firmware mode name (an event action or a key.log
/// state). `None` for anything else, e.g. `zwrt_mode_lcd_shutdown`, which
/// alone is not standby.
pub fn classify_mode(mode: &str) -> Option<Power> {
    if mode.starts_with("mode_power_off") {
        Some(Power::Standby)
    } else if mode == "mode_startup" || mode == "mode_initial" || mode.starts_with("mode_power_on")
    {
        Some(Power::On)
    } else {
        None
    }
}

/// Whether the firmware is still entering standby in `mode` (a standby
/// mode): `mode_power_off`, then `…_quickening` (also briefly when a cable
/// is unplugged in standby). Its own power-off is about to turn Wi-Fi off,
/// and a reload of ours would race it.
pub fn entering_standby(mode: &str) -> bool {
    mode == "mode_power_off" || mode.ends_with("_quickening")
}

/// The new mode of a key.log line
/// `2026-10-19 02:45:11 : setModeState from mode_power_off to mode_power_off_quickening . `.
fn set_mode_target(line: &str) -> Option<&str> {
    const MARK: &str = "setModeState from ";
    let rest = &line[line.find(MARK)? + MARK.len()..];
    let mut words = rest.split_whitespace();
    let (_old, to, new) = (words.next()?, words.next()?, words.next()?);
    (to == "to" && new.starts_with("mode_")).then_some(new)
}

/// The new mode of the newest `setModeState` line in a block of key.log lines.
pub fn newest_set_mode(text: &str) -> Option<String> {
    text.lines()
        .rev()
        .find_map(set_mode_target)
        .map(str::to_string)
}

/// key.log's power mode: the new mode of its newest `setModeState` line
/// (from `rotated` when `log` has none), or [`MODE_BEING_WRITTEN`] while a
/// newer one is still being written.
pub fn key_log_mode(log: &Path, rotated: &Path, chunk: u64) -> Option<String> {
    let newest = key_log::newest(log, rotated, chunk, newest_set_mode);
    if newest.pending.contains("setModeState") {
        return Some(MODE_BEING_WRITTEN.to_string());
    }
    newest.found
}

/// One line of the firmware's Wi-Fi test log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiLine {
    /// `1 <uptime> power_on success`: Wi-Fi has come on.
    PowerOn,
    /// `1 <uptime> power_off success`: Wi-Fi has gone off.
    PowerOff,
    /// The `0 <uptime>` line at each reconf start, a failure, anything else.
    Other,
}

pub fn parse_wifi_line(line: &str) -> WifiLine {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        ["1", .., "power_on", "success"] => WifiLine::PowerOn,
        ["1", .., "power_off", "success"] => WifiLine::PowerOff,
        _ => WifiLine::Other,
    }
}

/// The firmware's newest Wi-Fi power report among `lines` (oldest first).
pub fn newest_power_line(lines: &[String]) -> Option<WifiLine> {
    lines
        .iter()
        .rev()
        .map(|line| parse_wifi_line(line))
        .find(|line| *line != WifiLine::Other)
}

/// The user's Wi-Fi switch in `/etc/config/wireless` (`wifi_onoff_by_user`
/// is `'1'`); `None` when it is not there.
pub fn user_wants_wifi(config: &str) -> Option<bool> {
    config_option(config, "zte_mbb", "wifi_onoff_by_user").map(|v| v == "1")
}

// ── State machine ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The `action` of a [`POWER_EVENT`].
    Power(String),
    /// A new complete line in the Wi-Fi test log.
    Wifi(WifiLine),
    /// Result of [`Action::ReadKeyLog`]: [`key_log_mode`].
    KeyLog(Option<String>),
    /// Result of [`Action::ReadUserSwitch`]: [`user_wants_wifi`], `None`
    /// also when the config cannot be read.
    UserSwitch(Option<bool>),
    /// The timer fired (possibly early or spuriously).
    Timer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Read key.log's power mode and feed it back as [`Event::KeyLog`].
    ReadKeyLog,
    /// Read the user's Wi-Fi switch and feed it back as [`Event::UserSwitch`].
    ReadUserSwitch,
    /// Turn Wi-Fi off through the firmware (on another thread).
    WifiOff,
    /// Switch Wi-Fi on through the firmware (on another thread).
    WifiOn,
    /// One log line.
    Log(Note),
}

/// What the guard decided, as one log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// The power class changed on an event. On a power-on: `dropped` when
    /// it ended a wait for Wi-Fi to go off, `check_back` when the guard
    /// acted in the standby it ended (see [`RESTORE_AFTER`]).
    Mode {
        power: Power,
        action: String,
        dropped: bool,
        check_back: bool,
    },
    /// The agent started within [`BOOT_SETTLE`] of boot: on.
    AssumedOn,
    /// An unknown state was settled by key.log: the router is on. `None`:
    /// key.log (and its rotated part) has no power mode at all, so there was
    /// no standby in its span; this also stops re-reading it on every start.
    LearnedOn { mode: Option<String> },
    /// The events said standby, key.log a newer power-on: its event was
    /// missed (e.g. while `ubus listen` restarted). Taken as on.
    MissedPowerOn { mode: String },
    /// Wi-Fi came on in standby: turning it off, the `n`th time this period
    /// (`again`: a second try after [`Note::Unconfirmed`]).
    Act {
        mode: String,
        n: u8,
        from_key_log: bool,
        again: bool,
    },
    /// Wi-Fi came on while the firmware is still [`entering_standby`].
    Entering { mode: String },
    /// Wi-Fi came on with the power state unknown and key.log saying
    /// standby, but the firmware's previous Wi-Fi report was not
    /// `power_off success`, as it is in a standby (key.log may be stale).
    NotOffBefore { mode: String },
    /// Wi-Fi came on, the events say standby or nothing, key.log disagrees.
    KeyLogDisagrees {
        mode: Option<String>,
        standby_event: bool,
    },
    /// Wi-Fi came on again while a turn-off of ours is still running.
    InFlight,
    /// Wi-Fi came on in standby again after [`MAX_ACTIONS`] turn-offs.
    Limit,
    /// The firmware reported Wi-Fi off `after` acting.
    Confirmed { after: Duration },
    /// No `power_off success` line within [`CONFIRM_WITHIN`]; `retrying`
    /// when a second try follows.
    Unconfirmed { retrying: bool },
    /// No `power_on success` line within [`RESTORE_AFTER`] of a power-on
    /// that ended a standby in which the guard acted; `user_on` is the
    /// user's switch (switched on only when `Some(true)`).
    NotBack { user_on: Option<bool> },
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Note::Mode {
                power: Power::Standby,
                action,
                ..
            } => write!(f, "standby ({action})"),
            Note::Mode {
                power: Power::On,
                action,
                dropped,
                check_back,
            } => {
                write!(f, "power on ({action})")?;
                if *dropped {
                    write!(f, "; no longer waiting for Wi-Fi off")?;
                }
                if *check_back {
                    write!(
                        f,
                        "; the firmware restores Wi-Fi, checking it reports it on within {} s",
                        RESTORE_AFTER.as_secs()
                    )?;
                }
                Ok(())
            }
            Note::AssumedOn => write!(
                f,
                "agent started within {} min of boot, no power event seen: taken as on until a standby event",
                BOOT_SETTLE.as_secs() / 60
            ),
            Note::LearnedOn { mode: Some(mode) } => write!(
                f,
                "Wi-Fi came on; power state was unknown, key.log says {mode}: taken as on, not acting"
            ),
            Note::LearnedOn { mode: None } => write!(
                f,
                "Wi-Fi came on; power state was unknown, key.log has no power mode: taken as on, not acting"
            ),
            Note::MissedPowerOn { mode } => write!(
                f,
                "Wi-Fi came on; the last power event was standby, but key.log says {mode}: a power-on event was missed, taken as on, not acting"
            ),
            Note::Act {
                mode,
                n,
                from_key_log,
                again,
            } => {
                if *again {
                    return write!(
                        f,
                        "Wi-Fi still not reported off (key.log says {mode}); turning it off again ({n} of {MAX_ACTIONS})"
                    );
                }
                let source = if *from_key_log {
                    "no power event seen yet, key.log says"
                } else {
                    "key.log agrees:"
                };
                write!(
                    f,
                    "Wi-Fi came on in standby ({source} {mode}); turning it off ({n} of {MAX_ACTIONS})"
                )
            }
            Note::Entering { mode } => write!(
                f,
                "Wi-Fi came on while the firmware is still entering standby (key.log says {mode}); its power-off turns Wi-Fi off, not acting"
            ),
            Note::NotOffBefore { mode } => write!(
                f,
                "Wi-Fi came on; power state unknown, key.log says {mode}, but the last Wi-Fi report before was not power_off success; not acting"
            ),
            Note::KeyLogDisagrees {
                mode,
                standby_event,
            } => {
                let events = if *standby_event {
                    "the last power event was standby"
                } else {
                    "the power state is unknown"
                };
                let mode = mode.as_deref().unwrap_or("no power mode");
                write!(f, "Wi-Fi came on, {events}, but key.log says {mode}; not acting")
            }
            Note::InFlight => write!(
                f,
                "Wi-Fi came on again while turning it off; waiting for that turn-off, not acting twice"
            ),
            Note::Limit => write!(
                f,
                "Wi-Fi came on in standby again; already turned it off {MAX_ACTIONS} times this standby, only logging"
            ),
            Note::Confirmed { after } => write!(
                f,
                "Wi-Fi is off again ({:.1} s after acting)",
                after.as_secs_f64()
            ),
            Note::Unconfirmed { retrying } => {
                write!(
                    f,
                    "no power_off success within {} s of turning Wi-Fi off",
                    CONFIRM_WITHIN.as_secs()
                )?;
                if *retrying {
                    write!(f, "; trying once more")?;
                }
                Ok(())
            }
            Note::NotBack { user_on } => {
                write!(
                    f,
                    "Wi-Fi not reported on {} s after the power-on (it was turned off this standby)",
                    RESTORE_AFTER.as_secs()
                )?;
                match user_on {
                    Some(true) => write!(f, "; switching it on"),
                    Some(false) => write!(f, "; the user's Wi-Fi switch is off, leaving it"),
                    None => write!(f, "; the user's Wi-Fi switch is unreadable, leaving it"),
                }
            }
        }
    }
}

/// An outstanding [`Action::ReadKeyLog`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Check {
    /// The second try after [`Note::Unconfirmed`].
    again: bool,
    /// The firmware's Wi-Fi report before this start was `power_off success`.
    was_off: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Waiting {
    since: Duration,
    until: Duration,
    /// Waiting after the second try.
    again: bool,
}

#[derive(Debug, Default)]
pub struct Guard {
    /// From the events, or settled by key.log; `None` until then.
    power: Option<Power>,
    /// Turn-offs since the last power-on (or agent start).
    acted: u8,
    /// A [`Action::ReadKeyLog`] is outstanding.
    checking: Option<Check>,
    /// Waiting for the `power_off success` line after acting.
    waiting: Option<Waiting>,
    /// The firmware's newest Wi-Fi power report (`PowerOn` or `PowerOff`).
    wifi: Option<WifiLine>,
    /// After a power-on that ended a standby in which the guard acted: when
    /// Wi-Fi should have been reported on.
    restore_at: Option<Duration>,
    /// A [`Action::ReadUserSwitch`] is outstanding.
    asking: bool,
}

impl Guard {
    /// The guard of an agent started at `now` (time since boot); `last` is
    /// the firmware's newest Wi-Fi power report from before then.
    pub fn start(now: Duration, last: Option<WifiLine>) -> (Self, Vec<Action>) {
        let mut guard = Guard {
            wifi: last.filter(|line| *line != WifiLine::Other),
            ..Guard::default()
        };
        if now < BOOT_SETTLE {
            guard.power = Some(Power::On);
            return (guard, vec![Action::Log(Note::AssumedOn)]);
        }
        (guard, Vec::new())
    }

    /// The boot-time instant the runtime must deliver [`Event::Timer`] at, if any.
    pub fn next_deadline(&self) -> Option<Duration> {
        match (self.waiting.map(|w| w.until), self.restore_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn step(&mut self, event: Event, now: Duration) -> Vec<Action> {
        match event {
            Event::Power(action) => self.on_power(action, now),
            Event::Wifi(line) => self.on_wifi(line, now),
            Event::KeyLog(mode) => self.on_key_log(mode, now),
            Event::UserSwitch(on) => self.on_user_switch(on),
            Event::Timer => self.on_timer(now),
        }
    }

    fn on_power(&mut self, action: String, now: Duration) -> Vec<Action> {
        let Some(power) = classify_mode(&action) else {
            return Vec::new();
        };
        if self.power == Some(power) {
            // e.g. mode_power_off -> _quickening -> _quicken: one standby period.
            return Vec::new();
        }
        self.power = Some(power);
        self.asking = false;
        let (mut dropped, mut check_back) = (false, false);
        match power {
            Power::On => {
                // A real power-on: ZTE turns Wi-Fi on itself, and the next
                // standby period gets a fresh budget. If a turn-off of ours
                // overlapped it (its reload still running), the firmware's
                // Wi-Fi start may have been refused: check it is reported.
                dropped = self.waiting.take().is_some();
                check_back = self.acted > 0;
                self.restore_at = check_back.then_some(now + RESTORE_AFTER);
                self.acted = 0;
                self.checking = None;
            }
            Power::Standby => self.restore_at = None,
        }
        vec![Action::Log(Note::Mode {
            power,
            action,
            dropped,
            check_back,
        })]
    }

    fn on_wifi(&mut self, line: WifiLine, now: Duration) -> Vec<Action> {
        match line {
            WifiLine::Other => Vec::new(),
            WifiLine::PowerOff => {
                self.wifi = Some(WifiLine::PowerOff);
                match self.waiting.take() {
                    Some(w) => vec![Action::Log(Note::Confirmed {
                        after: now.saturating_sub(w.since),
                    })],
                    None => Vec::new(),
                }
            }
            WifiLine::PowerOn => {
                let was_off = self.wifi == Some(WifiLine::PowerOff);
                self.wifi = Some(WifiLine::PowerOn);
                // Back after a power-on: nothing to restore.
                self.restore_at = None;
                self.on_wifi_on(was_off)
            }
        }
    }

    fn on_wifi_on(&mut self, was_off: bool) -> Vec<Action> {
        if self.power == Some(Power::On) {
            // The normal case: every Wi-Fi start while the router is on.
            return Vec::new();
        }
        if self.waiting.is_some() {
            // A turn-off of ours is still running; it ends with its
            // `power_off success` line or the timeout, and a second one
            // would race it.
            return vec![Action::Log(Note::InFlight)];
        }
        // Read even past the budget: key.log also shows a missed power-on.
        self.checking = Some(Check {
            again: false,
            was_off,
        });
        vec![Action::ReadKeyLog]
    }

    fn on_key_log(&mut self, mode: Option<String>, now: Duration) -> Vec<Action> {
        // Unasked, or a power-on arrived since the read was requested.
        let Some(check) = self.checking.take() else {
            return Vec::new();
        };
        if self.power == Some(Power::On) {
            return Vec::new();
        }
        let unknown = self.power.is_none();
        match (mode.as_deref().and_then(classify_mode), mode) {
            (Some(Power::Standby), Some(mode)) if entering_standby(&mode) => {
                vec![Action::Log(Note::Entering { mode })]
            }
            (Some(Power::Standby), Some(mode)) if unknown && !check.was_off => {
                vec![Action::Log(Note::NotOffBefore { mode })]
            }
            (Some(Power::Standby), Some(_)) if self.acted >= MAX_ACTIONS => {
                vec![Action::Log(Note::Limit)]
            }
            (Some(Power::Standby), Some(mode)) => {
                self.power = Some(Power::Standby);
                self.acted += 1;
                self.waiting = Some(Waiting {
                    since: now,
                    until: now + CONFIRM_WITHIN,
                    again: check.again,
                });
                vec![
                    Action::Log(Note::Act {
                        mode,
                        n: self.acted,
                        from_key_log: unknown,
                        again: check.again,
                    }),
                    Action::WifiOff,
                ]
            }
            // ZTE writes setModeState before it broadcasts the event, so an
            // "on" line newer than a standby event is a power-on we missed.
            (Some(Power::On), Some(mode)) if !unknown => {
                self.power = Some(Power::On);
                self.acted = 0;
                self.waiting = None;
                self.restore_at = None;
                vec![Action::Log(Note::MissedPowerOn { mode })]
            }
            (Some(Power::On), mode @ Some(_)) | (None, mode @ None) if unknown => {
                self.power = Some(Power::On);
                vec![Action::Log(Note::LearnedOn { mode })]
            }
            (_, mode) => vec![Action::Log(Note::KeyLogDisagrees {
                mode,
                standby_event: !unknown,
            })],
        }
    }

    fn on_user_switch(&mut self, on: Option<bool>) -> Vec<Action> {
        // Unasked, or a standby or a Wi-Fi start since the read was requested.
        if !std::mem::take(&mut self.asking)
            || self.power != Some(Power::On)
            || self.wifi != Some(WifiLine::PowerOff)
        {
            return Vec::new();
        }
        let mut actions = vec![Action::Log(Note::NotBack { user_on: on })];
        if on == Some(true) {
            actions.push(Action::WifiOn);
        }
        actions
    }

    fn on_timer(&mut self, now: Duration) -> Vec<Action> {
        // Early or spurious wakes do nothing: the timer is re-armed for the
        // same deadline.
        let mut actions = Vec::new();
        if let Some(w) = self.waiting.filter(|w| now >= w.until) {
            self.waiting = None;
            // The reload is flaky: one more try (counted), still in standby.
            let retrying =
                !w.again && self.power == Some(Power::Standby) && self.acted < MAX_ACTIONS;
            actions.push(Action::Log(Note::Unconfirmed { retrying }));
            if retrying {
                self.checking = Some(Check {
                    again: true,
                    was_off: true,
                });
                actions.push(Action::ReadKeyLog);
            }
        }
        if self.restore_at.is_some_and(|at| now >= at) {
            self.restore_at = None;
            // No `power_on success` since the power-on (it clears
            // `restore_at`), and the firmware's last report is Wi-Fi off.
            if self.power == Some(Power::On) && self.wifi == Some(WifiLine::PowerOff) {
                self.asking = true;
                actions.push(Action::ReadUserSwitch);
            }
        }
        actions
    }
}

// ── Test log follower ───────────────────────────────────────────────

/// Follows the complete lines appended to a small log file.
#[derive(Debug)]
pub struct LineCursor {
    ino: Option<u64>,
    offset: u64,
}

impl LineCursor {
    /// Starts at the file's current end: lines already there are history.
    /// A file that does not exist yet will be read from its start.
    pub fn at_end(path: &Path) -> Self {
        match std::fs::metadata(path) {
            Ok(m) => LineCursor {
                ino: Some(m.ino()),
                offset: m.len(),
            },
            Err(_) => LineCursor {
                ino: None,
                offset: 0,
            },
        }
    }

    /// The complete lines before the cursor (at most [`MAX_FOLLOW`] bytes of
    /// them): the history [`LineCursor::at_end`] skipped.
    pub fn history(&self, path: &Path) -> Vec<String> {
        let Ok(mut file) = File::open(path) else {
            return Vec::new();
        };
        if file.metadata().ok().map(|m| m.ino()) != self.ino {
            return Vec::new();
        }
        let from = self.offset.saturating_sub(MAX_FOLLOW);
        let Some(buf) = key_log::read_range(&mut file, from, self.offset) else {
            return Vec::new();
        };
        complete_lines(&buf, from > 0).0
    }

    /// The complete lines appended since the last call. A new file (another
    /// inode) or a truncated one is read from its start; a line still being
    /// written is left for the next call.
    pub fn read_new(&mut self, path: &Path) -> Vec<String> {
        let Ok(mut file) = File::open(path) else {
            return Vec::new();
        };
        let Ok(meta) = file.metadata() else {
            return Vec::new();
        };
        if self.ino != Some(meta.ino()) || meta.len() < self.offset {
            self.ino = Some(meta.ino());
            self.offset = 0;
        }
        let end = meta.len();
        let from = self.offset.max(end.saturating_sub(MAX_FOLLOW));
        let Some(buf) = key_log::read_range(&mut file, from, end) else {
            return Vec::new();
        };
        let (lines, consumed) = complete_lines(&buf, from > self.offset);
        self.offset = from + consumed;
        lines
    }
}

/// The complete lines of `buf` and the bytes they span (through the last
/// newline). With `cut`, `buf` starts inside a line, which is dropped.
fn complete_lines(buf: &[u8], cut: bool) -> (Vec<String>, u64) {
    let Some(last) = buf.iter().rposition(|&b| b == b'\n') else {
        return (Vec::new(), 0);
    };
    let start = if cut {
        buf.iter().position(|&b| b == b'\n').map_or(0, |i| i + 1)
    } else {
        0
    };
    let lines = String::from_utf8_lossy(&buf[start.min(last + 1)..=last])
        .lines()
        .map(str::to_string)
        .collect();
    (lines, last as u64 + 1)
}

// ── Switching Wi-Fi ─────────────────────────────────────────────────

/// The steps of ZTE's own Wi-Fi switch path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// `uci set wireless.zte_mbb.wifi_onoff=0` (`false`) or `=1`.
    Set(bool),
    /// `uci commit wireless`
    Commit,
    /// `uci revert wireless.zte_mbb.wifi_onoff`: drops a set of ours that
    /// was not committed, so no later commit (by anyone) writes it.
    Revert,
    /// `ubus call zwrt_wlan reload`
    Reload,
}

impl Step {
    /// The command line of the step.
    pub fn argv(self) -> &'static [&'static str] {
        match self {
            Step::Set(false) => &["uci", "set", "wireless.zte_mbb.wifi_onoff=0"],
            Step::Set(true) => &["uci", "set", "wireless.zte_mbb.wifi_onoff=1"],
            Step::Commit => &["uci", "commit", "wireless"],
            Step::Revert => &["uci", "revert", WIFI_SWITCH],
            Step::Reload => &["ubus", "call", "zwrt_wlan", "reload"],
        }
    }
}

/// Switches Wi-Fi off (`on == false`) or on through the firmware, giving up
/// before each step once `interrupted()`: a power change the decision did
/// not know about (a power-on for a turn-off: ZTE's handler then sets
/// `wifi_onoff=1` and starts Wi-Fi itself, and a reload of ours must not
/// race it; a standby for a turn-on). A set that ends up not committed,
/// after such a stop or a failed commit, is reverted.
pub fn switch_wifi_with(
    on: bool,
    interrupted: impl Fn() -> bool,
    mut run: impl FnMut(Step) -> Result<(), String>,
) -> Result<(), String> {
    if interrupted() {
        return Err("a power change came first; nothing changed".into());
    }
    run(Step::Set(on))?;
    let committed = if interrupted() {
        Err("a power change came before the commit".to_string())
    } else {
        run(Step::Commit)
    };
    if let Err(e) = committed {
        return Err(match run(Step::Revert) {
            Ok(()) => format!("{e}; reverted the uncommitted change"),
            Err(revert) => format!("{e}; {revert}"),
        });
    }
    if interrupted() {
        return Err("a power change came; left the reload to the firmware".into());
    }
    run(Step::Reload)
}

// ── Runtime ─────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub mod linux {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{self, Sender};
    use std::sync::Arc;

    use super::*;
    use crate::key_log::{KEY_LOG, KEY_LOG_ROTATED};
    use crate::system::try_spawn_named;
    use crate::wifi_watchdog::{boot_now, TEST_LOG, WIRELESS_CONFIG};

    /// Power actions `wifi-guard-ev` has received, by class. Bumped before
    /// the action is queued, so a switch thread sees one that the watchdog
    /// thread has not been fed yet.
    #[derive(Default)]
    struct Received {
        on: AtomicU64,
        standby: AtomicU64,
    }

    impl Received {
        fn of(&self, power: Power) -> &AtomicU64 {
            match power {
                Power::On => &self.on,
                Power::Standby => &self.standby,
            }
        }
    }

    /// The guard's side of the `wifi-watchdog` thread.
    pub struct Runtime {
        guard: Guard,
        /// Power actions forwarded by `wifi-guard-ev`, in order.
        events: Receiver<String>,
        /// Readable whenever `events` has news; polled by the watchdog loop.
        wake: Arc<OwnedFd>,
        cursor: LineCursor,
        received: Arc<Received>,
        /// Power actions of each class `guard` has been fed: a switch thread
        /// gives up as soon as `received` differs for the class that undoes
        /// its decision (one is queued or has arrived since).
        fed_on: u64,
        fed_standby: u64,
    }

    impl Runtime {
        /// Starts the `wifi-guard-ev` forwarder; `None` (logged) if the
        /// eventfd or the thread cannot be created.
        pub fn start(rx: Receiver<Value>) -> Option<Self> {
            // SAFETY: plain syscall; the result is checked before use.
            let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            if fd < 0 {
                let e = std::io::Error::last_os_error();
                eprintln!("[wifi] standby Wi-Fi guard off: eventfd: {e}");
                return None;
            }
            // SAFETY: the syscall succeeded, so `fd` is open and owned by nobody else.
            let wake = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });
            let (tx, events) = mpsc::channel();
            let received = Arc::new(Received::default());
            let (fwd_wake, fwd_received) = (Arc::clone(&wake), Arc::clone(&received));
            if let Err(e) = try_spawn_named("wifi-guard-ev", move || {
                forward(rx, tx, fwd_wake, fwd_received)
            }) {
                eprintln!("[wifi] standby Wi-Fi guard off: cannot spawn wifi-guard-ev: {e}");
                return None;
            }
            eprintln!(
                "[wifi] standby Wi-Fi guard on: Wi-Fi switched on during standby is turned off again (opt out: {OPT_OUT_ENV}=0)"
            );
            let path = Path::new(TEST_LOG);
            let cursor = LineCursor::at_end(path);
            let last = newest_power_line(&cursor.history(path));
            let now = boot_now();
            let (guard, actions) = Guard::start(now, last);
            let mut runtime = Runtime {
                guard,
                events,
                wake,
                cursor,
                received,
                fed_on: 0,
                fed_standby: 0,
            };
            runtime.run(actions, now);
            Some(runtime)
        }

        pub fn wake_fd(&self) -> RawFd {
            self.wake.as_raw_fd()
        }

        pub fn next_deadline(&self) -> Option<Duration> {
            self.guard.next_deadline()
        }

        /// The eventfd is readable: feed every forwarded power action.
        pub fn on_power_events(&mut self) {
            let mut count = [0u8; 8];
            // SAFETY: `count` is valid for writes of 8 bytes; EAGAIN (nothing
            // to read) is harmless, the channel below is the source of truth.
            unsafe {
                libc::read(
                    self.wake.as_raw_fd(),
                    count.as_mut_ptr().cast(),
                    count.len(),
                )
            };
            self.feed_power_events();
        }

        fn feed_power_events(&mut self) {
            while let Ok(action) = self.events.try_recv() {
                match classify_mode(&action) {
                    Some(Power::On) => self.fed_on += 1,
                    Some(Power::Standby) => self.fed_standby += 1,
                    None => {}
                }
                self.handle(Event::Power(action));
            }
        }

        /// The test log was written, or (re)appeared: feed its new lines.
        pub fn on_test_log(&mut self) {
            // A power event forwarded after this wake's poll() came first.
            self.feed_power_events();
            for line in self.cursor.read_new(Path::new(TEST_LOG)) {
                self.handle(Event::Wifi(parse_wifi_line(&line)));
            }
        }

        pub fn on_timer(&mut self) {
            self.handle(Event::Timer);
        }

        fn handle(&mut self, event: Event) {
            let now = boot_now();
            let actions = self.guard.step(event, now);
            self.run(actions, now);
        }

        fn run(&mut self, actions: Vec<Action>, now: Duration) {
            for action in actions {
                match action {
                    Action::ReadKeyLog => {
                        let mode = key_log_mode(
                            Path::new(KEY_LOG),
                            Path::new(KEY_LOG_ROTATED),
                            KEY_LOG_CHUNK,
                        );
                        self.handle(Event::KeyLog(mode));
                    }
                    Action::ReadUserSwitch => {
                        let on = std::fs::read_to_string(WIRELESS_CONFIG)
                            .ok()
                            .and_then(|text| user_wants_wifi(&text));
                        self.handle(Event::UserSwitch(on));
                    }
                    Action::WifiOff => {
                        switch_wifi(false, Arc::clone(&self.received), Power::On, self.fed_on)
                    }
                    Action::WifiOn => switch_wifi(
                        true,
                        Arc::clone(&self.received),
                        Power::Standby,
                        self.fed_standby,
                    ),
                    Action::Log(note) => log(now, &note),
                }
            }
        }
    }

    fn log(now: Duration, what: &dyn std::fmt::Display) {
        eprintln!(
            "[wifi] [boot {:.1}] standby guard: {what}",
            now.as_secs_f64()
        );
    }

    /// `wifi-guard-ev`: blocks in `recv()` (no timeout, no wakeups at idle)
    /// and hands each power action to the watchdog thread.
    fn forward(
        rx: Receiver<Value>,
        tx: Sender<String>,
        wake: Arc<OwnedFd>,
        received: Arc<Received>,
    ) {
        for payload in rx.iter() {
            let Some(action) = payload.get("action").and_then(Value::as_str) else {
                continue;
            };
            if let Some(power) = classify_mode(action) {
                received.of(power).fetch_add(1, Ordering::SeqCst);
            }
            if tx.send(action.to_string()).is_err() {
                return; // the watchdog thread gave up on events
            }
            let one = 1u64.to_ne_bytes();
            // SAFETY: `one` is valid for reads of 8 bytes. The only failure
            // (counter overflow) still leaves the eventfd readable.
            unsafe { libc::write(wake.as_raw_fd(), one.as_ptr().cast(), one.len()) };
        }
    }

    /// Runs ZTE's Wi-Fi switch path on a short-lived thread. It gives up
    /// once a power action of class `undo` arrives beyond the `seen` the
    /// decision was made with.
    fn switch_wifi(on: bool, received: Arc<Received>, undo: Power, seen: u64) {
        let (name, what) = if on {
            ("wifi-guard-on", "on")
        } else {
            ("wifi-guard-off", "off")
        };
        let spawned = try_spawn_named(name, move || {
            let interrupted = || received.of(undo).load(Ordering::SeqCst) != seen;
            if let Err(e) = switch_wifi_with(on, interrupted, run_step) {
                log(
                    boot_now(),
                    &format_args!(
                        "Wi-Fi {what} not completed: {}",
                        e.split_whitespace().collect::<Vec<_>>().join(" ")
                    ),
                );
            }
        });
        if let Err(e) = spawned {
            log(boot_now(), &format_args!("cannot spawn {name}: {e}"));
        }
    }

    fn run_step(step: Step) -> Result<(), String> {
        let argv = step.argv();
        let out = Command::new(argv[0])
            .args(&argv[1..])
            .output()
            .map_err(|e| format!("{}: {e}", argv.join(" ")))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{} failed: {}",
                argv.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);
    /// Long after boot: an agent started then does not assume "on".
    const LATE: Duration = Duration::from_secs(3600);

    fn power(action: &str) -> Event {
        Event::Power(action.to_string())
    }

    fn key_log(mode: &str) -> Event {
        Event::KeyLog(Some(mode.to_string()))
    }

    fn wifi(line: WifiLine) -> Event {
        Event::Wifi(line)
    }

    fn act(mode: &str, n: u8, from_key_log: bool) -> Vec<Action> {
        vec![
            Action::Log(Note::Act {
                mode: mode.to_string(),
                n,
                from_key_log,
                again: false,
            }),
            Action::WifiOff,
        ]
    }

    fn standby(action: &str) -> Vec<Action> {
        vec![Action::Log(Note::Mode {
            power: Power::Standby,
            action: action.to_string(),
            dropped: false,
            check_back: false,
        })]
    }

    fn power_on(action: &str, dropped: bool, check_back: bool) -> Vec<Action> {
        vec![Action::Log(Note::Mode {
            power: Power::On,
            action: action.to_string(),
            dropped,
            check_back,
        })]
    }

    fn note(note: Note) -> Vec<Action> {
        vec![Action::Log(note)]
    }

    /// An agent started at boot that has seen the router enter standby and
    /// the firmware turn Wi-Fi off.
    fn in_standby() -> Guard {
        let (mut g, _) = Guard::start(30 * S, Some(WifiLine::PowerOn));
        g.step(power("mode_power_off"), 2 * S);
        g.step(wifi(WifiLine::PowerOff), 3 * S);
        g
    }

    /// An agent restarted long after boot, with no power event seen yet.
    fn restarted(last: Option<WifiLine>) -> Guard {
        let (g, actions) = Guard::start(LATE, last);
        assert_eq!(actions, vec![]);
        g
    }

    // -- inputs --

    #[test]
    fn classifies_power_modes() {
        for off in [
            "mode_power_off",
            "mode_power_off_quickening",
            "mode_power_off_quicken",
            "mode_power_off_charger_quicken",
            "mode_power_off_charger",
            // Scheduled power-off, over-temperature (zte_topsw_mc).
            "mode_power_off_unreal",
        ] {
            assert_eq!(classify_mode(off), Some(Power::Standby), "{off}");
        }
        for on in [
            "mode_startup",
            "mode_initial",
            "mode_power_on",
            "mode_power_on_charger",
        ] {
            assert_eq!(classify_mode(on), Some(Power::On), "{on}");
        }
        for other in [
            "zwrt_mode_lcd_shutdown",
            "",
            "mode_reboot",
            "power_off",
            "mode_wispr_pwd",
            "mode_wispr_set",
            MODE_BEING_WRITTEN,
        ] {
            assert_eq!(classify_mode(other), None, "{other}");
        }
        // Still entering standby: the firmware's own stop is under way.
        for entering in ["mode_power_off", "mode_power_off_quickening"] {
            assert!(entering_standby(entering), "{entering}");
        }
        for settled in [
            "mode_power_off_quicken",
            "mode_power_off_charger_quicken",
            "mode_power_off_charger",
            "mode_power_off_unreal",
        ] {
            assert!(!entering_standby(settled), "{settled}");
        }
    }

    /// Lines verbatim from a U60 Pro key.log (2026-10-19), ending in a space.
    #[test]
    fn reads_the_newest_set_mode_line() {
        let log = "2026-10-19 02:45:01 : setModeState from mode_power_on_charger to mode_power_off . \n\
            2026-10-19 02:45:01 : [DATA] rev MC event:zwrt_device_power_state_event,action:mode_power_off,parameter:quicken  \n\
            2026-10-19 02:45:11 : setModeState from mode_power_off to mode_power_off_quickening . \n\
            2026-10-19 02:45:11 : setModeState from mode_power_off_quickening to mode_power_off_quicken . \n\
            2026-10-19 02:50:06 : bat:[1,100,33,4445,-57,0,1],chg:[0,0,0,2],ui_mode:[0],pon:[1]   \n\
            2026-10-19 02:45:40 : bat:[1,100,28,4446,-8,0,1],chg:[0,0,0,2],ui_mode:[0],pon:[1]   \n";
        // Order decides, not the (non-monotonic) timestamps.
        assert_eq!(
            newest_set_mode(log).as_deref(),
            Some("mode_power_off_quicken")
        );
        assert_eq!(newest_set_mode("2026-10-19 05:42:50 : setModeState from mode_initial to mode_power_on_charger . \n").as_deref(), Some("mode_power_on_charger"));
        assert_eq!(newest_set_mode("no mode lines\n"), None);
        assert_eq!(set_mode_target("x setModeState from mode_a to"), None);
        assert_eq!(
            set_mode_target("x setModeState from mode_a into mode_b ."),
            None
        );
        assert_eq!(
            set_mode_target("x setModeState from mode_a to garbage ."),
            None
        );
    }

    #[test]
    fn key_log_mode_survives_rotation_and_a_partial_line() {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let (log, rotated) = (
            dir.join(format!("zte-agent-guard-{pid}-key.log")),
            dir.join(format!("zte-agent-guard-{pid}-key.log.0")),
        );
        let filler: String = (0..200)
            .map(|i| {
                format!(
                    "2026-10-21 09:{:02}:00 : bat:[1,99,30,4400,-20,0,1] filler {i}\n",
                    i % 60
                )
            })
            .collect();
        let off = "2026-10-21 09:40:00 : setModeState from mode_power_off_quicken to mode_power_off_charger_quicken . \n";
        // Just rotated: the fresh log has no mode line, the rotated one does.
        std::fs::write(&rotated, format!("{filler}{off}{filler}")).unwrap();
        std::fs::write(&log, &filler).unwrap();
        let read = |chunk| key_log_mode(&log, &rotated, chunk);
        for chunk in [128, 1000, KEY_LOG_CHUNK] {
            assert_eq!(
                read(chunk).as_deref(),
                Some("mode_power_off_charger_quicken"),
                "chunk {chunk}"
            );
        }
        // A mode line still being written (here a power-on) is newer than
        // the standby line before it: no mode to act on yet.
        let on = "2026-10-21 09:52:55 : setModeState from mode_power_off_charger_quicken to mode_startup . \n";
        std::fs::write(&log, format!("{filler}{}", &on[..on.len() - 20])).unwrap();
        assert_eq!(read(1000).as_deref(), Some(MODE_BEING_WRITTEN));
        // Another daemon's line being written changes nothing.
        std::fs::write(&log, format!("{filler}{off}2026-10-21 09:52:56 : bat:[1,")).unwrap();
        assert_eq!(
            read(1000).as_deref(),
            Some("mode_power_off_charger_quicken")
        );
        std::fs::write(&log, format!("{filler}{on}")).unwrap();
        assert_eq!(read(1000).as_deref(), Some("mode_startup"));
        std::fs::remove_file(&log).unwrap();
        std::fs::remove_file(&rotated).unwrap();
        assert_eq!(read(1000), None);
    }

    #[test]
    fn parses_the_wifi_test_log() {
        assert_eq!(
            parse_wifi_line("1 3842.17 power_on success"),
            WifiLine::PowerOn
        );
        assert_eq!(
            parse_wifi_line("1 3901.55 power_off success"),
            WifiLine::PowerOff
        );
        // Both /proc/uptime fields, in case the firmware prints them.
        assert_eq!(
            parse_wifi_line("1 3842.17 7000.01 power_on success "),
            WifiLine::PowerOn
        );
        assert_eq!(parse_wifi_line("0 3840.02"), WifiLine::Other);
        assert_eq!(parse_wifi_line("1 3842.17 power_on fail"), WifiLine::Other);
        assert_eq!(
            parse_wifi_line("0 3842.17 power_on success"),
            WifiLine::Other
        );
        assert_eq!(parse_wifi_line(""), WifiLine::Other);

        let lines = |text: &str| text.lines().map(str::to_string).collect::<Vec<_>>();
        assert_eq!(
            newest_power_line(&lines(
                "0 10.00\n1 15.20 power_on success\n0 900.10\n1 905.33 power_off success\n0 906.00\n"
            )),
            Some(WifiLine::PowerOff)
        );
        assert_eq!(newest_power_line(&lines("0 10.00\n")), None);
        assert_eq!(newest_power_line(&[]), None);
    }

    #[test]
    fn reads_the_users_wifi_switch() {
        let config = |by_user: &str| {
            format!(
                "config wifi-device 'wifi1'\n\toption disabled '0'\n\nconfig zte_mbb 'zte_mbb'\n\toption wifi_onoff '0'\n{by_user}"
            )
        };
        assert_eq!(
            user_wants_wifi(&config("\toption wifi_onoff_by_user '1'\n")),
            Some(true)
        );
        assert_eq!(
            user_wants_wifi(&config("\toption wifi_onoff_by_user '0'\n")),
            Some(false)
        );
        assert_eq!(user_wants_wifi(&config("")), None);
        assert_eq!(user_wants_wifi(""), None);
    }

    #[test]
    fn opt_out_values() {
        assert!(enabled(None));
        assert!(enabled(Some("1")));
        assert!(enabled(Some("")));
        for off in ["0", "off", "OFF", "false", "no", " 0 "] {
            assert!(!enabled(Some(off)), "{off:?}");
        }
    }

    // -- state machine --

    #[test]
    fn the_reported_bug_is_undone_and_confirmed() {
        let (mut g, start) = Guard::start(40 * S, None);
        assert_eq!(start, note(Note::AssumedOn));
        // 2026-10-21: standby on a cable, then ZTE starts Wi-Fi on its own.
        let t = LATE;
        assert_eq!(
            g.step(power("zwrt_mode_lcd_shutdown"), t),
            vec![],
            "not standby alone"
        );
        assert_eq!(
            g.step(power("mode_power_off"), t + S),
            standby("mode_power_off")
        );
        assert_eq!(
            g.step(power("mode_power_off_quickening"), t + 2 * S),
            vec![]
        );
        assert_eq!(g.step(wifi(WifiLine::PowerOff), t + 8 * S), vec![]);
        assert_eq!(
            g.step(power("mode_power_off_charger_quicken"), t + 11 * S),
            vec![]
        );
        assert_eq!(g.step(wifi(WifiLine::Other), t + 100 * S), vec![]);
        assert_eq!(
            g.step(wifi(WifiLine::PowerOn), t + 101 * S),
            vec![Action::ReadKeyLog]
        );
        assert_eq!(g.next_deadline(), None);
        assert_eq!(
            g.step(key_log("mode_power_off_charger_quicken"), t + 101 * S),
            act("mode_power_off_charger_quicken", 1, false)
        );
        assert_eq!(g.next_deadline(), Some(t + 101 * S + CONFIRM_WITHIN));
        assert_eq!(
            g.step(wifi(WifiLine::PowerOff), t + 106 * S),
            note(Note::Confirmed { after: 5 * S })
        );
        assert_eq!(g.next_deadline(), None, "no timer once confirmed");
    }

    #[test]
    fn a_real_power_on_is_left_alone() {
        let mut g = in_standby();
        // ZTE broadcasts the mode change before its own Wi-Fi start finishes.
        assert_eq!(
            g.step(power("mode_startup"), 10 * S),
            power_on("mode_startup", false, false)
        );
        assert_eq!(g.step(power("mode_initial"), 10 * S), vec![]);
        assert_eq!(g.step(power("mode_power_on"), 10 * S), vec![]);
        assert_eq!(g.step(wifi(WifiLine::PowerOn), 12 * S), vec![]);
        assert_eq!(g.next_deadline(), None);
    }

    #[test]
    fn key_log_must_agree_before_acting() {
        let mut g = in_standby();
        for (answer, mode) in [
            (Event::KeyLog(None), None),
            (key_log("mode_reboot"), Some("mode_reboot")),
            (key_log(MODE_BEING_WRITTEN), Some(MODE_BEING_WRITTEN)),
        ] {
            assert_eq!(
                g.step(wifi(WifiLine::PowerOn), 10 * S),
                vec![Action::ReadKeyLog]
            );
            assert_eq!(
                g.step(answer, 10 * S),
                note(Note::KeyLogDisagrees {
                    mode: mode.map(str::to_string),
                    standby_event: true,
                })
            );
        }
        assert_eq!(g.next_deadline(), None);
    }

    #[test]
    fn a_missed_power_on_is_learned_from_key_log() {
        // The budget was used up, then the power-on event was lost (`ubus
        // listen` restarting); key.log already shows the power-on.
        let mut g = in_standby();
        for n in 1..=MAX_ACTIONS {
            let t = u32::from(n) * 100 * S;
            g.step(wifi(WifiLine::PowerOn), t);
            g.step(key_log("mode_power_off_quicken"), t);
            g.step(wifi(WifiLine::PowerOff), t + 5 * S);
        }
        assert_eq!(
            g.step(wifi(WifiLine::PowerOn), 600 * S),
            vec![Action::ReadKeyLog]
        );
        assert_eq!(
            g.step(key_log("mode_power_on_charger"), 600 * S),
            note(Note::MissedPowerOn {
                mode: "mode_power_on_charger".into()
            })
        );
        assert_eq!(g.next_deadline(), None);
        // On now: later starts cost nothing, and the next standby has its
        // full budget.
        assert_eq!(g.step(wifi(WifiLine::PowerOn), 700 * S), vec![]);
        g.step(power("mode_power_off"), 800 * S);
        g.step(wifi(WifiLine::PowerOff), 805 * S);
        assert_eq!(
            g.step(wifi(WifiLine::PowerOn), 900 * S),
            vec![Action::ReadKeyLog]
        );
        assert_eq!(
            g.step(key_log("mode_power_off_quicken"), 900 * S),
            act("mode_power_off_quicken", 1, false)
        );
    }

    #[test]
    fn not_while_the_firmware_is_still_entering_standby() {
        // A reconf started while on finishes after the user pressed power:
        // ZTE's own stop is queued behind it.
        for entering in ["mode_power_off", "mode_power_off_quickening"] {
            let (mut g, _) = Guard::start(30 * S, Some(WifiLine::PowerOn));
            g.step(power("mode_power_off"), 100 * S);
            assert_eq!(
                g.step(wifi(WifiLine::PowerOn), 103 * S),
                vec![Action::ReadKeyLog]
            );
            assert_eq!(
                g.step(key_log(entering), 103 * S),
                note(Note::Entering {
                    mode: entering.into()
                })
            );
            assert_eq!(g.next_deadline(), None);
            // Settled standby later: acting as usual, budget untouched.
            g.step(wifi(WifiLine::PowerOff), 110 * S);
            g.step(wifi(WifiLine::PowerOn), 500 * S);
            assert_eq!(
                g.step(key_log("mode_power_off_quicken"), 500 * S),
                act("mode_power_off_quicken", 1, false)
            );
        }
    }

    #[test]
    fn unknown_state_acts_only_when_key_log_says_standby() {
        // Agent restarted during standby: no power event yet.
        let t = LATE + 5 * S;
        let mut g = restarted(Some(WifiLine::PowerOff));
        assert_eq!(g.step(wifi(WifiLine::PowerOn), t), vec![Action::ReadKeyLog]);
        assert_eq!(
            g.step(key_log("mode_power_off_quicken"), t),
            act("mode_power_off_quicken", 1, true)
        );
        // A mode key.log has but that is neither: not acting, still unknown.
        let mut g = restarted(Some(WifiLine::PowerOff));
        g.step(wifi(WifiLine::PowerOn), t);
        assert_eq!(
            g.step(key_log("mode_reboot"), t),
            note(Note::KeyLogDisagrees {
                mode: Some("mode_reboot".into()),
                standby_event: false,
            })
        );
        g.step(wifi(WifiLine::PowerOff), t + S);
        assert_eq!(
            g.step(wifi(WifiLine::PowerOn), t + 2 * S),
            vec![Action::ReadKeyLog]
        );
        // No power mode in key.log at all: no standby in its span, so on.
        let mut g = restarted(Some(WifiLine::PowerOff));
        g.step(wifi(WifiLine::PowerOn), t);
        assert_eq!(
            g.step(Event::KeyLog(None), t),
            note(Note::LearnedOn { mode: None })
        );
        assert_eq!(g.step(wifi(WifiLine::PowerOn), t + S), vec![]);

        // Agent restarted while on: key.log settles it, later starts cost nothing.
        let mut g = restarted(Some(WifiLine::PowerOn));
        assert_eq!(g.step(wifi(WifiLine::PowerOn), t), vec![Action::ReadKeyLog]);
        assert_eq!(
            g.step(key_log("mode_power_on"), t),
            note(Note::LearnedOn {
                mode: Some("mode_power_on".into())
            })
        );
        assert_eq!(g.step(wifi(WifiLine::PowerOn), t + 60 * S), vec![]);
    }

    #[test]
    fn unknown_state_needs_wifi_reported_off_before() {
        // key.log may be stale (this boot's mode lines never written): it
        // alone does not turn Wi-Fi off. In a standby the firmware has
        // reported Wi-Fi off before it comes on again.
        let t = LATE + 5 * S;
        for last in [None, Some(WifiLine::PowerOn)] {
            let mut g = restarted(last);
            assert_eq!(
                g.step(wifi(WifiLine::PowerOn), t),
                vec![Action::ReadKeyLog],
                "{last:?}"
            );
            assert_eq!(
                g.step(key_log("mode_power_off_quicken"), t),
                note(Note::NotOffBefore {
                    mode: "mode_power_off_quicken".into()
                }),
                "{last:?}"
            );
            assert_eq!(g.next_deadline(), None);
            // Seen going off and coming on again: acting.
            g.step(wifi(WifiLine::PowerOff), t + 10 * S);
            g.step(wifi(WifiLine::PowerOn), t + 20 * S);
            assert_eq!(
                g.step(key_log("mode_power_off_quicken"), t + 20 * S),
                act("mode_power_off_quicken", 1, true)
            );
        }
    }

    #[test]
    fn an_agent_started_at_boot_takes_the_router_as_on() {
        // A cold boot: the agent starts before Wi-Fi, ZTE's boot-time power
        // events may predate `ubus listen`, and key.log may still end with
        // the last session's power-off. Not read, not trusted, however late
        // Wi-Fi first comes on (e.g. switched on by the user an hour later).
        let (mut g, start) = Guard::start(20 * S, Some(WifiLine::PowerOff));
        assert_eq!(start, note(Note::AssumedOn));
        assert_eq!(g.step(wifi(WifiLine::PowerOn), 45 * S), vec![]);
        assert_eq!(g.step(wifi(WifiLine::PowerOff), 3000 * S), vec![]);
        assert_eq!(g.step(wifi(WifiLine::PowerOn), LATE), vec![]);
        // Standby later is known from its events as usual.
        g.step(power("mode_power_off"), LATE + 100 * S);
        g.step(wifi(WifiLine::PowerOff), LATE + 105 * S);
        assert_eq!(
            g.step(wifi(WifiLine::PowerOn), LATE + 200 * S),
            vec![Action::ReadKeyLog]
        );

        // The boundary.
        let just_before = BOOT_SETTLE - Duration::from_millis(1);
        assert_eq!(Guard::start(just_before, None).1, note(Note::AssumedOn));
        let (mut g, start) = Guard::start(BOOT_SETTLE, Some(WifiLine::PowerOff));
        assert_eq!(start, vec![]);
        assert_eq!(
            g.step(wifi(WifiLine::PowerOn), BOOT_SETTLE),
            vec![Action::ReadKeyLog]
        );
    }

    #[test]
    fn at_most_three_turn_offs_per_standby() {
        let mut g = in_standby();
        for n in 1..=MAX_ACTIONS {
            let t = u32::from(n) * 100 * S;
            assert_eq!(g.step(wifi(WifiLine::PowerOn), t), vec![Action::ReadKeyLog]);
            assert_eq!(
                g.step(key_log("mode_power_off_quicken"), t),
                act("mode_power_off_quicken", n, false)
            );
            g.step(wifi(WifiLine::PowerOff), t + 5 * S);
        }
        assert_eq!(
            g.step(wifi(WifiLine::PowerOn), 500 * S),
            vec![Action::ReadKeyLog]
        );
        assert_eq!(
            g.step(key_log("mode_power_off_quicken"), 500 * S),
            note(Note::Limit)
        );
        // Staying in standby (cable attached, detached) does not reset the budget.
        g.step(power("mode_power_off_charger_quicken"), 600 * S);
        g.step(power("mode_power_off_quickening"), 601 * S);
        g.step(power("mode_power_off_quicken"), 602 * S);
        g.step(wifi(WifiLine::PowerOn), 700 * S);
        assert_eq!(
            g.step(key_log("mode_power_off_charger_quicken"), 700 * S),
            note(Note::Limit)
        );
        // A power-on does.
        g.step(power("mode_startup"), 800 * S);
        g.step(power("mode_power_off"), 900 * S);
        assert_eq!(
            g.step(wifi(WifiLine::PowerOn), 1000 * S),
            vec![Action::ReadKeyLog]
        );
        assert_eq!(
            g.step(key_log("mode_power_off_quicken"), 1000 * S),
            act("mode_power_off_quicken", 1, false)
        );
    }

    #[test]
    fn a_missing_confirmation_gets_one_more_try() {
        let mut g = in_standby();
        g.step(wifi(WifiLine::PowerOn), 10 * S);
        g.step(key_log("mode_power_off_quicken"), 10 * S);
        assert_eq!(g.step(Event::Timer, 39 * S), vec![], "early wake");
        assert_eq!(g.next_deadline(), Some(40 * S));
        assert_eq!(
            g.step(Event::Timer, 40 * S),
            vec![
                Action::Log(Note::Unconfirmed { retrying: true }),
                Action::ReadKeyLog
            ]
        );
        assert_eq!(
            g.step(key_log("mode_power_off_quicken"), 40 * S),
            vec![
                Action::Log(Note::Act {
                    mode: "mode_power_off_quicken".into(),
                    n: 2,
                    from_key_log: false,
                    again: true
                }),
                Action::WifiOff
            ]
        );
        assert_eq!(g.next_deadline(), Some(70 * S));
        // Only once per Wi-Fi start.
        assert_eq!(
            g.step(Event::Timer, 70 * S),
            note(Note::Unconfirmed { retrying: false })
        );
        assert_eq!(g.next_deadline(), None);
        assert_eq!(g.step(Event::Timer, 71 * S), vec![]);
        // A late power_off line is ZTE's business, not a confirmation.
        assert_eq!(g.step(wifi(WifiLine::PowerOff), 75 * S), vec![]);

        // Not past the budget.
        let mut g = in_standby();
        for n in 1..MAX_ACTIONS {
            let t = u32::from(n) * 100 * S;
            g.step(wifi(WifiLine::PowerOn), t);
            g.step(key_log("mode_power_off_quicken"), t);
            g.step(wifi(WifiLine::PowerOff), t + 5 * S);
        }
        g.step(wifi(WifiLine::PowerOn), 500 * S);
        assert_eq!(
            g.step(key_log("mode_power_off_quicken"), 500 * S),
            act("mode_power_off_quicken", MAX_ACTIONS, false)
        );
        assert_eq!(
            g.step(Event::Timer, 530 * S),
            note(Note::Unconfirmed { retrying: false })
        );

        // The second try finds the router on: no turn-off.
        let mut g = in_standby();
        g.step(wifi(WifiLine::PowerOn), 10 * S);
        g.step(key_log("mode_power_off_quicken"), 10 * S);
        g.step(Event::Timer, 40 * S);
        assert_eq!(
            g.step(key_log("mode_power_on"), 40 * S),
            note(Note::MissedPowerOn {
                mode: "mode_power_on".into()
            })
        );
    }

    #[test]
    fn a_second_wifi_start_while_turning_off_is_not_acted_on() {
        // Two power_on lines in one read (a backlog, an inotify overflow).
        let mut g = in_standby();
        g.step(wifi(WifiLine::PowerOn), 10 * S);
        assert_eq!(
            g.step(key_log("mode_power_off_quicken"), 10 * S),
            act("mode_power_off_quicken", 1, false)
        );
        assert_eq!(
            g.step(wifi(WifiLine::PowerOn), 10 * S),
            note(Note::InFlight)
        );
        assert_eq!(g.next_deadline(), Some(40 * S), "the wait goes on");
        assert_eq!(
            g.step(wifi(WifiLine::PowerOff), 15 * S),
            note(Note::Confirmed { after: 5 * S })
        );
        // Once that turn-off is over, a new start is handled again.
        assert_eq!(
            g.step(wifi(WifiLine::PowerOn), 100 * S),
            vec![Action::ReadKeyLog]
        );
        assert_eq!(
            g.step(key_log("mode_power_off_quicken"), 100 * S),
            act("mode_power_off_quicken", 2, false)
        );
    }

    #[test]
    fn a_power_on_ends_the_wait_and_any_pending_check() {
        let mut g = in_standby();
        g.step(wifi(WifiLine::PowerOn), 10 * S);
        g.step(key_log("mode_power_off_quicken"), 10 * S);
        assert_eq!(
            g.step(power("mode_startup"), 12 * S),
            power_on("mode_startup", true, true)
        );
        assert_eq!(g.next_deadline(), Some(12 * S + RESTORE_AFTER));

        // The power-on lands between the key.log request and its answer.
        let mut g = in_standby();
        assert_eq!(
            g.step(wifi(WifiLine::PowerOn), 10 * S),
            vec![Action::ReadKeyLog]
        );
        g.step(power("mode_startup"), 10 * S);
        assert_eq!(g.step(key_log("mode_power_off_quicken"), 10 * S), vec![]);
        // An unasked answer does nothing either.
        assert_eq!(g.step(key_log("mode_power_off_quicken"), 11 * S), vec![]);
        assert_eq!(g.next_deadline(), None);
    }

    #[test]
    fn wifi_is_checked_after_a_power_on_that_follows_a_turn_off() {
        // Acted, then a power-on while (or after) our reload ran.
        let acted_then_on = |confirmed: bool| {
            let mut g = in_standby();
            g.step(wifi(WifiLine::PowerOn), 10 * S);
            g.step(key_log("mode_power_off_charger_quicken"), 10 * S);
            if confirmed {
                g.step(wifi(WifiLine::PowerOff), 16 * S);
            }
            assert_eq!(
                g.step(power("mode_startup"), 20 * S),
                power_on("mode_startup", !confirmed, true)
            );
            g.step(power("mode_initial"), 20 * S);
            g.step(power("mode_power_on"), 21 * S);
            assert_eq!(g.next_deadline(), Some(20 * S + RESTORE_AFTER));
            g
        };
        // The firmware's own Wi-Fi start is reported: nothing to do.
        let mut g = acted_then_on(true);
        assert_eq!(g.step(wifi(WifiLine::PowerOn), 35 * S), vec![]);
        assert_eq!(g.next_deadline(), None);
        assert_eq!(g.step(Event::Timer, 110 * S), vec![]);

        // Not reported: with the user's switch on, Wi-Fi is switched on.
        for confirmed in [true, false] {
            let mut g = acted_then_on(confirmed);
            if !confirmed {
                // Our reload finished after the power-on; ZTE's start was refused.
                g.step(wifi(WifiLine::PowerOff), 25 * S);
            }
            assert_eq!(g.step(Event::Timer, 109 * S), vec![], "early wake");
            assert_eq!(g.step(Event::Timer, 110 * S), vec![Action::ReadUserSwitch]);
            assert_eq!(g.next_deadline(), None);
            assert_eq!(
                g.step(Event::UserSwitch(Some(true)), 110 * S),
                vec![
                    Action::Log(Note::NotBack {
                        user_on: Some(true)
                    }),
                    Action::WifiOn
                ]
            );
            assert_eq!(g.step(Event::UserSwitch(Some(true)), 111 * S), vec![]);
        }
        // The user's switch off or unreadable: left alone.
        for user_on in [Some(false), None] {
            let mut g = acted_then_on(true);
            g.step(Event::Timer, 110 * S);
            assert_eq!(
                g.step(Event::UserSwitch(user_on), 110 * S),
                note(Note::NotBack { user_on })
            );
        }
        // Standby again before the check: no check.
        let mut g = acted_then_on(true);
        g.step(power("mode_power_off"), 60 * S);
        assert_eq!(g.next_deadline(), None);
        assert_eq!(g.step(Event::Timer, 110 * S), vec![]);
        // The last report is Wi-Fi on (the turn-off never ran): nothing.
        let mut g = acted_then_on(false);
        assert_eq!(g.step(Event::Timer, 110 * S), vec![]);
        // A power-on without a turn-off this standby: no check at all.
        let mut g = in_standby();
        assert_eq!(
            g.step(power("mode_startup"), 20 * S),
            power_on("mode_startup", false, false)
        );
        assert_eq!(g.next_deadline(), None);
    }

    #[test]
    fn facts_file_sequences() {
        // Charger attached and detached while a turn-off is awaited: the
        // same standby, the wait and its deadline stay.
        let mut g = in_standby();
        g.step(wifi(WifiLine::PowerOn), 10 * S);
        g.step(key_log("mode_power_off_charger_quicken"), 10 * S);
        for (i, action) in [
            "mode_power_off_quickening",
            "mode_power_off_quicken",
            "mode_power_off_charger_quicken",
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(g.step(power(action), (12 + i as u32) * S), vec![]);
            assert_eq!(g.next_deadline(), Some(40 * S), "{action}");
        }
        assert_eq!(
            g.step(wifi(WifiLine::PowerOff), 20 * S),
            note(Note::Confirmed { after: 10 * S })
        );

        // A short press in standby (battery screen) is not a mode change:
        // still standby, budget kept.
        g.step(power("zwrt_mode_lcd_shutdown"), 30 * S);
        assert_eq!(
            g.step(wifi(WifiLine::PowerOn), 50 * S),
            vec![Action::ReadKeyLog]
        );
        assert_eq!(
            g.step(key_log("mode_power_off_charger_quicken"), 50 * S),
            act("mode_power_off_charger_quicken", 2, false)
        );

        // Unknown state, acted on key.log, then a real power-on: the budget
        // resets and Wi-Fi is checked.
        let mut g = restarted(Some(WifiLine::PowerOff));
        g.step(wifi(WifiLine::PowerOn), LATE);
        g.step(key_log("mode_power_off_quicken"), LATE);
        g.step(wifi(WifiLine::PowerOff), LATE + 5 * S);
        assert_eq!(
            g.step(power("mode_startup"), LATE + 60 * S),
            power_on("mode_startup", false, true)
        );
        g.step(power("mode_power_off"), LATE + 600 * S);
        g.step(wifi(WifiLine::PowerOff), LATE + 605 * S);
        g.step(wifi(WifiLine::PowerOn), LATE + 700 * S);
        assert_eq!(
            g.step(key_log("mode_power_off_quicken"), LATE + 700 * S),
            act("mode_power_off_quicken", 1, false)
        );
    }

    #[test]
    fn notes_carry_no_identifiers_and_read_well() {
        let notes = [
            Note::Mode {
                power: Power::Standby,
                action: "mode_power_off".into(),
                dropped: false,
                check_back: false,
            },
            Note::Mode {
                power: Power::On,
                action: "mode_startup".into(),
                dropped: true,
                check_back: true,
            },
            Note::AssumedOn,
            Note::LearnedOn {
                mode: Some("mode_power_on".into()),
            },
            Note::LearnedOn { mode: None },
            Note::MissedPowerOn {
                mode: "mode_power_on_charger".into(),
            },
            Note::Act {
                mode: "mode_power_off_quicken".into(),
                n: 2,
                from_key_log: false,
                again: false,
            },
            Note::Act {
                mode: "mode_power_off_quicken".into(),
                n: 2,
                from_key_log: false,
                again: true,
            },
            Note::Entering {
                mode: "mode_power_off_quickening".into(),
            },
            Note::NotOffBefore {
                mode: "mode_power_off_quicken".into(),
            },
            Note::KeyLogDisagrees {
                mode: Some("mode_reboot".into()),
                standby_event: false,
            },
            Note::KeyLogDisagrees {
                mode: None,
                standby_event: true,
            },
            Note::InFlight,
            Note::Limit,
            Note::Confirmed {
                after: Duration::from_millis(5300),
            },
            Note::Unconfirmed { retrying: true },
            Note::NotBack {
                user_on: Some(true),
            },
            Note::NotBack {
                user_on: Some(false),
            },
            Note::NotBack { user_on: None },
        ];
        let text: Vec<String> = notes.iter().map(ToString::to_string).collect();
        assert_eq!(text[1], "power on (mode_startup); no longer waiting for Wi-Fi off; the firmware restores Wi-Fi, checking it reports it on within 90 s");
        assert_eq!(text[6], "Wi-Fi came on in standby (key.log agrees: mode_power_off_quicken); turning it off (2 of 3)");
        assert_eq!(text[14], "Wi-Fi is off again (5.3 s after acting)");
        assert_eq!(
            text[15],
            "no power_off success within 30 s of turning Wi-Fi off; trying once more"
        );
        assert_eq!(text[16], "Wi-Fi not reported on 90 s after the power-on (it was turned off this standby); switching it on");
        for line in &text {
            assert!(!line.contains('\n') && !line.is_empty(), "{line:?}");
        }
    }

    // -- test log follower --

    #[test]
    fn follows_appended_lines_only() {
        let path =
            std::env::temp_dir().join(format!("zte-agent-guard-{}-test.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);
        // Absent at start: everything written later is news.
        let mut cursor = LineCursor::at_end(&path);
        assert!(cursor.history(&path).is_empty());
        assert!(cursor.read_new(&path).is_empty());
        std::fs::write(&path, "0 100.00\n").unwrap();
        assert_eq!(cursor.read_new(&path), ["0 100.00"]);

        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        // A line still being written is left for the next read.
        f.write_all(b"1 101.20 power_on succ").unwrap();
        assert!(cursor.read_new(&path).is_empty());
        f.write_all(b"ess\n0 200.00\n").unwrap();
        assert_eq!(
            cursor.read_new(&path),
            ["1 101.20 power_on success", "0 200.00"]
        );
        assert!(cursor.read_new(&path).is_empty());

        // Present at start: its history is not news, but is there to read.
        let mut late = LineCursor::at_end(&path);
        assert_eq!(
            late.history(&path),
            ["0 100.00", "1 101.20 power_on success", "0 200.00"]
        );
        assert!(late.read_new(&path).is_empty());

        // Truncated (or replaced by a shorter file): read from the start.
        std::fs::write(&path, "1 5.00 power_off success\n").unwrap();
        assert_eq!(cursor.read_new(&path), ["1 5.00 power_off success"]);
        std::fs::remove_file(&path).unwrap();
        assert!(cursor.read_new(&path).is_empty());
    }

    #[test]
    fn a_long_backlog_is_cut_at_a_line_start() {
        let all: String = (0..2000).map(|i| format!("0 {i}.00\n")).collect();
        let tail = &all.as_bytes()[all.len() - 100..];
        let (lines, consumed) = complete_lines(tail, true);
        assert_eq!(consumed, 100);
        assert_eq!(lines.last().map(String::as_str), Some("0 1999.00"));
        assert!(lines.iter().all(|l| l.starts_with("0 ")), "{lines:?}");
        assert_eq!(complete_lines(b"no newline", false), (vec![], 0));
        assert_eq!(complete_lines(b"cut\n", true), (vec![], 4));

        // A file with more news than one read: only the newest whole lines.
        let path = std::env::temp_dir().join(format!(
            "zte-agent-guard-{}-backlog.txt",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut cursor = LineCursor::at_end(&path);
        let backlog: String = (0..2000)
            .map(|i| format!("1 {i}.00 power_on success\n"))
            .collect();
        assert!(backlog.len() as u64 > MAX_FOLLOW);
        std::fs::write(&path, &backlog).unwrap();
        let lines = cursor.read_new(&path);
        assert!(!lines.is_empty() && lines.len() < 2000);
        assert_eq!(
            lines.last().map(String::as_str),
            Some("1 1999.00 power_on success")
        );
        assert!(
            lines
                .iter()
                .all(|l| parse_wifi_line(l) == WifiLine::PowerOn),
            "no line cut in half"
        );
        assert!(cursor.read_new(&path).is_empty());
        let history = LineCursor::at_end(&path).history(&path);
        assert_eq!(history, lines, "history is cut the same way");
        std::fs::remove_file(&path).unwrap();
    }

    // -- switching Wi-Fi --

    #[test]
    fn steps_write_only_the_live_switch() {
        assert_eq!(
            Step::Set(false).argv(),
            ["uci", "set", &format!("{WIFI_SWITCH}=0")]
        );
        assert_eq!(
            Step::Set(true).argv(),
            ["uci", "set", &format!("{WIFI_SWITCH}=1")]
        );
        assert_eq!(Step::Commit.argv(), ["uci", "commit", "wireless"]);
        assert_eq!(Step::Revert.argv(), ["uci", "revert", WIFI_SWITCH]);
        assert_eq!(Step::Reload.argv(), ["ubus", "call", "zwrt_wlan", "reload"]);
        for step in [
            Step::Set(false),
            Step::Set(true),
            Step::Commit,
            Step::Revert,
            Step::Reload,
        ] {
            for arg in step.argv() {
                assert!(
                    !arg.contains("by_user")
                        && !arg.contains("main_2g")
                        && !arg.contains("disabled"),
                    "{step:?}: {arg}"
                );
            }
        }
    }

    /// Runs `switch_wifi_with`, recording the steps; `fail` fails one step,
    /// `interrupt_after` makes a power change arrive once that step ran.
    fn switch(
        on: bool,
        fail: Option<Step>,
        interrupt_after: Option<Step>,
    ) -> (Result<(), String>, Vec<Step>) {
        use std::cell::{Cell, RefCell};
        let interrupted = Cell::new(false);
        let ran = RefCell::new(Vec::new());
        let result = switch_wifi_with(
            on,
            || interrupted.get(),
            |step| {
                ran.borrow_mut().push(step);
                if Some(step) == interrupt_after {
                    interrupted.set(true);
                }
                if Some(step) == fail {
                    Err(format!("{step:?} failed"))
                } else {
                    Ok(())
                }
            },
        );
        (result, ran.into_inner())
    }

    #[test]
    fn switching_runs_zte_steps_in_order() {
        for on in [false, true] {
            assert_eq!(
                switch(on, None, None),
                (Ok(()), vec![Step::Set(on), Step::Commit, Step::Reload])
            );
        }
    }

    #[test]
    fn switching_yields_to_a_power_change_and_leaves_nothing_pending() {
        // A power change before anything ran: nothing changes.
        use std::cell::RefCell;
        let ran = RefCell::new(Vec::new());
        assert!(switch_wifi_with(
            false,
            || true,
            |s| {
                ran.borrow_mut().push(s);
                Ok(())
            }
        )
        .is_err());
        assert!(ran.borrow().is_empty());

        // After the set: not committed, and reverted so no later commit
        // (the firmware's, the app's) writes it.
        let (result, ran) = switch(false, None, Some(Step::Set(false)));
        assert!(result.is_err());
        assert_eq!(ran, [Step::Set(false), Step::Revert]);

        // After the commit: no reload of ours races the firmware's.
        let (result, ran) = switch(false, None, Some(Step::Commit));
        assert!(result.is_err());
        assert_eq!(ran, [Step::Set(false), Step::Commit]);

        // A failed commit is reverted too, and a failed revert reported.
        let (result, ran) = switch(false, Some(Step::Commit), None);
        assert_eq!(
            result,
            Err("Commit failed; reverted the uncommitted change".to_string())
        );
        assert_eq!(ran, [Step::Set(false), Step::Commit, Step::Revert]);
        use std::cell::Cell;
        let ran = RefCell::new(Vec::new());
        let calls = Cell::new(0);
        let result = switch_wifi_with(
            false,
            || false,
            |s| {
                ran.borrow_mut().push(s);
                calls.set(calls.get() + 1);
                match s {
                    Step::Commit => Err("uci commit: busy".into()),
                    Step::Revert => Err("uci revert: busy".into()),
                    _ => Ok(()),
                }
            },
        );
        assert_eq!(
            result,
            Err("uci commit: busy; uci revert: busy".to_string())
        );
        assert_eq!(calls.get(), 3);

        // A failing set or reload stops there (nothing pending to revert).
        assert_eq!(
            switch(false, Some(Step::Set(false)), None),
            (Err("Set(false) failed".into()), vec![Step::Set(false)])
        );
        assert_eq!(
            switch(true, Some(Step::Reload), None),
            (
                Err("Reload failed".into()),
                vec![Step::Set(true), Step::Commit, Step::Reload]
            )
        );
    }
}
