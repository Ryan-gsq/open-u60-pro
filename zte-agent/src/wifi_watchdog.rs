//! Watchdog for the stuck firmware script `/sbin/zte_post_wifi.sh`.
//!
//! Firmware bug: `zte_post_wifi.sh` (run after every Wi-Fi start or
//! reconfiguration) loops without sleeping until it sees one `hostapd_cli`
//! per enabled SSID. With a radio disabled but its SSID still enabled that
//! never happens, and each stuck copy forks ~265 processes per second
//! forever. Healthy runs finish in ~5 s; a copy still running after
//! [`MAX_AGE`] is stuck and gets SIGTERM. Killing it is safe: the steps after
//! the loop (MAC filter, tx power) are unreachable while it spins and are
//! re-run by the next reload anyway.
//!
//! Why event-driven: the script is launched by several firmware paths
//! (daemon start, `zwrt_wlan` reloads, power-state events, the sleep
//! framework's wake-up, a mesh-only path), and no single ubus event covers
//! them all. Every launch, by any launcher, makes BusyBox ash open the
//! script file, so an inotify `IN_OPEN` watch on it sees all of them. As a
//! second signal, the launcher in `/lib/wifi/zteqcawifi.sh` appends to
//! `/tmp/zteqcawifi_test.txt` around each launch (watched for writes once it
//! exists). Each event triggers one `/proc` scan. A scan that finds a copy
//! arms a timer for the moment the oldest turns [`MAX_AGE`] (+ [`SLACK`]);
//! that re-check kills it or finds it gone (healthy runs end long before) and
//! re-arms for any younger copy (a scan that cannot read `/proc` retries
//! after [`SCAN_RETRY`]). Once a scan finds no copy it blocks in `poll()`
//! with no timeout - no timers, no forks.
//!
//! Fast path for a copy that can never finish: whenever a scan finds a copy,
//! `/etc/config/wireless` is read (a file read, no fork) and judged the way
//! the script's loop counts ([`Outlook`]). If, when the scan first sees the
//! copy, a radio is off while one of its SSIDs is on and the loop therefore
//! waits for more `hostapd_cli` monitors than it can ever start, the copy is
//! re-checked at [`STUCK_AGE`] (+ [`SLACK`]) instead of [`MAX_AGE`]. It is
//! stopped then if the config still says so (the script counts ~3 s after
//! launch, and the read at launch may have caught a change half-way) and the
//! loop has started every monitor it can (it starts them itself, so after
//! that it only spins; only monitors started since the copy count, and while
//! one is missing it is re-checked every [`MONITOR_RETRY`]); otherwise the
//! 120 s rule applies.
//!
//! The same thread drives the standby Wi-Fi guard ([`crate::standby_guard`]):
//! it hands it each new line of [`TEST_LOG`], power events through an
//! eventfd in the same `poll()`, and shares the one timerfd with it.
//!
//! Layout: [`Machine`] is a pure state machine (`step(event, now) ->
//! Vec<Action>`, time = [`Duration`] since boot on `CLOCK_BOOTTIME`, which
//! keeps counting while the SoC is suspended), [`parse_events`] and
//! [`classify`] decode inotify reads, [`top_level`] drops the ash subshells
//! that share the script's command line, [`Outlook::from_config`] parses the
//! UCI file. The Linux runtime (one `wifi-watchdog` thread: an inotify fd, a
//! `CLOCK_BOOTTIME` timerfd and the guard's eventfd in one `poll()`)
//! executes the actions; if inotify is unavailable it falls back to the old
//! sweep every [`FALLBACK_SWEEP`] and says so in the log.

// The runtime that drives the pure parts below is Linux-only; on the Mac
// only the tests use them.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::time::Duration;

pub const POST_WIFI_SCRIPT: &str = "/sbin/zte_post_wifi.sh";
/// Appended by `post_zteqcawifi()` at each reconf start and ~1 s after each
/// launch. Absent until the first Wi-Fi reconf after boot.
pub const TEST_LOG: &str = "/tmp/zteqcawifi_test.txt";
pub const WIRELESS_CONFIG: &str = "/etc/config/wireless";

/// A copy running this long is stuck (healthy runs take ~5 s).
pub const MAX_AGE: Duration = Duration::from_secs(120);
/// A copy that can never finish ([`Outlook::endless`]) is stopped once it
/// has run this long: its 3 s + 2 s of sleeps are over and its loop runs.
pub const STUCK_AGE: Duration = Duration::from_secs(5);
/// Re-check delay while such a copy's loop has not started every
/// `hostapd_cli` monitor it can yet.
pub const MONITOR_RETRY: Duration = Duration::from_secs(5);
/// Margin past [`MAX_AGE`] or [`STUCK_AGE`] for the re-check, so the copy is
/// surely old enough.
pub const SLACK: Duration = Duration::from_secs(1);
/// Re-check delay after `/proc` could not be read, so a pending check is not lost.
pub const SCAN_RETRY: Duration = Duration::from_secs(30);
/// Fallback without inotify: first sweep after start (covers the boot-time
/// launch), then one every [`FALLBACK_SWEEP`].
pub const FALLBACK_FIRST: Duration = Duration::from_secs(150);
pub const FALLBACK_SWEEP: Duration = Duration::from_secs(300);

// ── Process matching ────────────────────────────────────────────────

/// `sh /sbin/zte_post_wifi.sh` exactly, or the B31 form with one numeric
/// argument (`sh /sbin/zte_post_wifi.sh "$p1905_restart_flag"`): never a
/// shell that merely mentions the script.
fn is_post_wifi_cmdline(cmdline: &[u8]) -> bool {
    let args: Vec<&[u8]> = cmdline
        .split(|&b| b == 0)
        .filter(|a| !a.is_empty())
        .collect();
    let (shell, script) = match args.as_slice() {
        [shell, script] => (*shell, *script),
        [shell, script, flag] if flag.iter().all(u8::is_ascii_digit) => (*shell, *script),
        _ => return false,
    };
    matches!(shell, b"sh" | b"/bin/sh" | b"ash" | b"/bin/ash")
        && script == POST_WIFI_SCRIPT.as_bytes()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A `hostapd_cli … wps-hostapd…` process, as the script's loop counts them
/// (`ps | grep -v grep | grep -c "hostapd_cli.*wps-hostapd"`).
fn is_hostapd_monitor(cmdline: &[u8]) -> bool {
    find(cmdline, b"grep").is_none()
        && find(cmdline, b"hostapd_cli")
            .is_some_and(|at| find(&cmdline[at..], b"wps-hostapd").is_some())
}

/// One matching `hostapd_cli` process: its parent and start time.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Monitor {
    ppid: i32,
    start: Duration,
}

/// Start times of the monitors that are up. The loop launches `hostapd_cli
/// -B` itself, and one still a child of a copy (or of its subshells) has not
/// attached and daemonized yet; in the stuck state the loop retries the
/// hopeless radio's monitor many times a second, so a scan often catches
/// such an attempt.
fn monitors_up(monitors: Vec<Monitor>, copies: &[Found]) -> Vec<Duration> {
    let scripts: HashSet<i32> = copies.iter().map(|f| f.pid).collect();
    monitors
        .into_iter()
        .filter(|m| !scripts.contains(&m.ppid))
        .map(|m| m.start)
        .collect()
}

// ── Wi-Fi config ────────────────────────────────────────────────────

/// One `config` section of a UCI file; `list` values are not kept.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Section {
    kind: String,
    /// `None` for an anonymous section (`uci show` names it `@kind[i]`).
    name: Option<String>,
    options: Vec<(String, String)>,
}

impl Section {
    fn get(&self, key: &str) -> Option<&str> {
        // uci keeps the last of repeated options.
        self.options
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Splits one line of a UCI file into words: `'…'` (literal), `"…"` (with
/// backslash escapes) and bare words, which may be glued together; `#` at
/// the start of a word comments out the rest of the line.
fn uci_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for c in chars.by_ref() {
                    if c == '\'' {
                        break;
                    }
                    word.push(c);
                }
            }
            '"' => {
                in_word = true;
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => word.extend(chars.next()),
                        c => word.push(c),
                    }
                }
            }
            '\\' => {
                in_word = true;
                word.extend(chars.next());
            }
            '#' if !in_word => break,
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

/// The sections of a UCI file (`config <type> ['<name>']` followed by
/// `option <key> '<value>'` lines).
fn parse_uci(text: &str) -> Vec<Section> {
    let mut sections: Vec<Section> = Vec::new();
    for line in text.lines() {
        match uci_words(line).as_slice() {
            [cmd, kind, rest @ ..] if cmd == "config" => sections.push(Section {
                kind: kind.clone(),
                name: rest.first().cloned(),
                options: Vec::new(),
            }),
            [cmd, key, value, ..] if cmd == "option" => {
                if let Some(section) = sections.last_mut() {
                    section.options.push((key.clone(), value.clone()));
                }
            }
            _ => {}
        }
    }
    sections
}

/// The value of `option <key>` in the section named `section` of a UCI file.
pub fn config_option(text: &str, section: &str, key: &str) -> Option<String> {
    parse_uci(text)
        .iter()
        .find(|s| s.name.as_deref() == Some(section))
        .and_then(|s| s.get(key))
        .map(str::to_string)
}

/// Whether `grep -E "main.*.disabled.*0|guest.*.disabled.*0"` matches a line.
fn counted_by_script(line: &str) -> bool {
    ["main", "guest"].iter().any(|word| {
        let Some(at) = line.find(word) else {
            return false;
        };
        // `.*.`: at least one character between the word and "disabled".
        let rest = &line[at + word.len()..];
        let Some((skip, _)) = rest.char_indices().nth(1) else {
            return false;
        };
        rest[skip..]
            .find("disabled")
            .is_some_and(|d| rest[skip + d + "disabled".len()..].contains('0'))
    })
}

/// What the script's `check_and_start_hostapd_cli()` waits for, judged from
/// `/etc/config/wireless` the way the script reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outlook {
    /// SSIDs it waits for: `uci show wireless | grep -cE
    /// "main.*.disabled.*0|guest.*.disabled.*0"`.
    pub wanted: usize,
    /// `hostapd_cli` monitors its loop can ever start: one per enabled AP
    /// interface on an enabled radio (it skips `backhaul` ones).
    pub reachable: usize,
    /// An enabled SSID sits on a disabled radio (or Wi-Fi is switched off
    /// altogether, `zte_mbb.wifi_onoff=0`).
    pub ssid_on_radio_off: bool,
}

impl Outlook {
    /// The loop can never count `wanted` monitors, so the script never ends.
    pub fn endless(&self) -> bool {
        self.ssid_on_radio_off && self.wanted > self.reachable
    }

    pub fn from_config(text: &str) -> Self {
        let sections = parse_uci(text);
        // Section names as `uci show` prints them.
        let mut index: HashMap<&str, usize> = HashMap::new();
        let names: Vec<String> = sections
            .iter()
            .map(|s| {
                let i = index.entry(s.kind.as_str()).or_default();
                let name = s
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("@{}[{i}]", s.kind));
                *i += 1;
                name
            })
            .collect();
        let wanted = sections
            .iter()
            .zip(&names)
            .map(|(s, name)| {
                let header = usize::from(counted_by_script(&format!("wireless.{name}={}", s.kind)));
                let options = s.options.iter().filter(|(key, value)| {
                    let value = value.replace('\'', "'\\''");
                    counted_by_script(&format!("wireless.{name}.{key}='{value}'"))
                });
                header + options.count()
            })
            .sum();
        let wifi_on = sections
            .iter()
            .zip(&names)
            .find(|(_, name)| *name == "zte_mbb")
            .and_then(|(s, _)| s.get("wifi_onoff"))
            != Some("0");
        let radio_on = |device: &str| {
            wifi_on
                && sections.iter().zip(&names).any(|(s, name)| {
                    s.kind == "wifi-device" && name == device && s.get("disabled") != Some("1")
                })
        };
        let mut reachable = 0;
        let mut ssid_on_radio_off = false;
        for (s, name) in sections.iter().zip(&names) {
            if s.kind != "wifi-iface" || s.get("disabled") == Some("1") {
                continue;
            }
            let Some(device) = s.get("device") else {
                continue;
            };
            if !radio_on(device) {
                ssid_on_radio_off = true;
            } else if s.get("mode") == Some("ap")
                && !format!("wireless.{name}.device='{device}'").contains("backhaul")
            {
                reachable += 1;
            }
        }
        Outlook {
            wanted,
            reachable,
            ssid_on_radio_off,
        }
    }
}

/// `(ppid, starttime)` from a `/proc/<pid>/stat` line: fields 4 and 22, the
/// start time in clock ticks since boot. The comm (field 2) may contain
/// spaces and parentheses, so fields are counted after the last `)`.
fn parse_stat(stat: &str) -> Option<(i32, u64)> {
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] = state (field 3)
    let ppid = fields.get(1)?.parse().ok()?;
    let starttime = fields.get(19)?.parse().ok()?;
    Some((ppid, starttime))
}

/// Clock ticks since boot -> time since boot.
fn ticks_to_duration(ticks: u64, hz: u64) -> Duration {
    let hz = hz.max(1);
    Duration::from_secs(ticks / hz) + Duration::from_nanos((ticks % hz) * 1_000_000_000 / hz)
}

/// One running copy of the script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Copy {
    pub pid: i32,
    /// Process start, as time since boot.
    pub start: Duration,
}

/// A process whose command line matched, before subshell filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Found {
    pid: i32,
    ppid: i32,
    start: Duration,
}

/// The real runs only: a spinning copy constantly forks command-substitution
/// subshells with the same command line, so drop any match whose parent is
/// itself a match.
fn top_level(found: Vec<Found>) -> Vec<Copy> {
    let pids: HashSet<i32> = found.iter().map(|f| f.pid).collect();
    found
        .into_iter()
        .filter(|f| !pids.contains(&f.ppid))
        .map(|f| Copy {
            pid: f.pid,
            start: f.start,
        })
        .collect()
}

// ── State machine ───────────────────────────────────────────────────

/// Result of a [`Action::Scan`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scan {
    /// Every top-level copy running now.
    pub copies: Vec<Copy>,
    /// Start times of the `hostapd_cli` monitors up now ([`monitors_up`]).
    pub monitors: Vec<Duration>,
    /// The Wi-Fi config, read whenever the scan found a copy; `None` if not
    /// read or unreadable.
    pub outlook: Option<Outlook>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Something may have launched the script: an inotify event, agent
    /// start, an inotify queue overflow or a re-armed watch.
    Trigger,
    /// The timer fired (possibly early or spuriously).
    Timer,
    Scanned(Scan),
    /// A [`Action::Scan`] could not read `/proc` (e.g. out of file
    /// descriptors): nothing is known, so check again after [`SCAN_RETRY`].
    ScanFailed,
}

/// When a copy is stopped, chosen when a scan first sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Once it has run [`MAX_AGE`].
    Age,
    /// The config makes it endless ([`Outlook::endless`]): once it has run
    /// [`STUCK_AGE`], the config still makes it endless and `reachable`
    /// monitors (by the config then) started since it did are up (an older
    /// one may be from before the reconf, about to exit with its hostapd),
    /// or at [`MAX_AGE`]. Becomes [`Rule::Age`] if the config no longer
    /// makes it endless (or cannot be read) when it is due.
    Endless { reachable: usize },
}

impl Rule {
    fn for_outlook(outlook: Option<Outlook>) -> Self {
        match outlook {
            Some(o) if o.endless() => Rule::Endless {
                reachable: o.reachable,
            },
            _ => Rule::Age,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Scan `/proc` and feed the result back as [`Event::Scanned`].
    Scan,
    /// SIGTERM a copy that has run for `age`.
    Kill { pid: i32, age: Duration, rule: Rule },
    /// A copy seen for the first time (logged once); re-checked at `at`.
    Watch { pid: i32, at: Duration, rule: Rule },
    /// An endless copy is old enough, but its loop has started only
    /// `monitors` of the `reachable` monitors (logged once per copy).
    Wait {
        pid: i32,
        monitors: usize,
        reachable: usize,
    },
    /// A copy first judged endless is due, but the config no longer makes
    /// it endless (or cannot be read): back to the 120 s rule, re-checked at `at`.
    Relax { pid: i32, at: Duration },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tracked {
    start: Duration,
    rule: Rule,
    /// [`Action::Wait`] was emitted.
    waited: bool,
}

#[derive(Debug, Default)]
pub struct Machine {
    /// When the first tracked copy is due for a re-check.
    deadline: Option<Duration>,
    /// The copies of the last scan that were not stopped, by pid.
    tracked: HashMap<i32, Tracked>,
}

impl Machine {
    pub fn new() -> Self {
        Self::default()
    }

    /// The boot-time instant the runtime must deliver [`Event::Timer`] at, if any.
    pub fn next_deadline(&self) -> Option<Duration> {
        self.deadline
    }

    /// Whether `copy` was seen by an earlier scan (a reused pid is a new copy).
    #[cfg(test)]
    pub fn tracks(&self, copy: &Copy) -> bool {
        self.tracked
            .get(&copy.pid)
            .is_some_and(|t| t.start == copy.start)
    }

    pub fn step(&mut self, event: Event, now: Duration) -> Vec<Action> {
        match event {
            Event::Trigger => vec![Action::Scan],
            Event::Timer => match self.deadline {
                Some(at) if now >= at => {
                    self.deadline = None;
                    vec![Action::Scan]
                }
                // Early or spurious wake: the timer is re-armed for the same deadline.
                _ => Vec::new(),
            },
            Event::Scanned(scan) => self.on_scanned(scan, now),
            Event::ScanFailed => {
                let at = now + SCAN_RETRY;
                self.deadline = Some(self.deadline.map_or(at, |d| d.min(at)));
                Vec::new()
            }
        }
    }

    fn on_scanned(&mut self, scan: Scan, now: Duration) -> Vec<Action> {
        let mut actions = Vec::new();
        // The scan saw every copy, so it replaces any earlier deadline and
        // forgets copies that are gone.
        self.deadline = None;
        let mut before = std::mem::take(&mut self.tracked);
        for copy in scan.copies {
            let age = now.saturating_sub(copy.start);
            let (mut t, new) = match before.remove(&copy.pid) {
                Some(t) if t.start == copy.start => (t, false),
                _ => {
                    let rule = Rule::for_outlook(scan.outlook);
                    let t = Tracked {
                        start: copy.start,
                        rule,
                        waited: false,
                    };
                    (t, true)
                }
            };
            let last_chance = copy.start + MAX_AGE + SLACK;
            // Monitors this copy's loop (or the reconf that launched it) started.
            let fresh = scan.monitors.iter().filter(|&&m| m >= copy.start).count();
            let mut wait = None;
            let mut relaxed = false;
            // Each `Some(at)` is > now: age < MAX_AGE, and age < STUCK_AGE where used.
            let check_at = match t.rule {
                _ if age >= MAX_AGE => None,
                Rule::Age => Some(last_chance),
                Rule::Endless { .. } if age < STUCK_AGE => Some(copy.start + STUCK_AGE + SLACK),
                // Due: judged again by the config now, which the script's
                // count (~3 s after launch) is closer to.
                Rule::Endless { .. } => match scan.outlook.filter(Outlook::endless) {
                    Some(o) => {
                        t.rule = Rule::Endless {
                            reachable: o.reachable,
                        };
                        if fresh >= o.reachable {
                            None
                        } else {
                            if !t.waited {
                                t.waited = true;
                                wait = Some(o.reachable);
                            }
                            Some((now + MONITOR_RETRY).min(last_chance))
                        }
                    }
                    None => {
                        t.rule = Rule::Age;
                        relaxed = true;
                        Some(last_chance)
                    }
                },
            };
            let Some(at) = check_at else {
                actions.push(Action::Kill {
                    pid: copy.pid,
                    age,
                    rule: t.rule,
                });
                continue;
            };
            if new {
                actions.push(Action::Watch {
                    pid: copy.pid,
                    at,
                    rule: t.rule,
                });
            }
            if let Some(reachable) = wait {
                actions.push(Action::Wait {
                    pid: copy.pid,
                    monitors: fresh,
                    reachable,
                });
            }
            if relaxed {
                actions.push(Action::Relax { pid: copy.pid, at });
            }
            self.deadline = Some(self.deadline.map_or(at, |d| d.min(at)));
            self.tracked.insert(copy.pid, t);
        }
        actions
    }
}

// ── inotify records ─────────────────────────────────────────────────

// Linux uapi values, defined here so the parser builds and tests on the Mac.
const IN_CLOSE_WRITE: u32 = 0x0000_0008;
const IN_OPEN: u32 = 0x0000_0020;
const IN_DELETE_SELF: u32 = 0x0000_0400;
const IN_MOVE_SELF: u32 = 0x0000_0800;
const IN_Q_OVERFLOW: u32 = 0x0000_4000;
const IN_IGNORED: u32 = 0x0000_8000;
/// `struct inotify_event` without the name: wd, mask, cookie, len.
const EVENT_HEADER: usize = 16;

#[cfg(target_os = "linux")]
const _: () = assert!(
    IN_CLOSE_WRITE == libc::IN_CLOSE_WRITE
        && IN_OPEN == libc::IN_OPEN
        && IN_DELETE_SELF == libc::IN_DELETE_SELF
        && IN_MOVE_SELF == libc::IN_MOVE_SELF
        && IN_Q_OVERFLOW == libc::IN_Q_OVERFLOW
        && IN_IGNORED == libc::IN_IGNORED
        && EVENT_HEADER == std::mem::size_of::<libc::inotify_event>()
);

#[derive(Debug, Clone, PartialEq, Eq)]
struct InotifyEvent {
    wd: i32,
    mask: u32,
}

fn ne_bytes(buf: &[u8], at: usize) -> [u8; 4] {
    [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]
}

/// Decodes the `struct inotify_event` records of one `read()`: a 16-byte
/// header, then `len` name bytes (NUL-padded). Makes no alignment
/// assumption; a truncated tail is ignored.
fn parse_events(buf: &[u8]) -> Vec<InotifyEvent> {
    let mut events = Vec::new();
    let mut rest = buf;
    while rest.len() >= EVENT_HEADER {
        let wd = i32::from_ne_bytes(ne_bytes(rest, 0));
        let mask = u32::from_ne_bytes(ne_bytes(rest, 4));
        let len = u32::from_ne_bytes(ne_bytes(rest, 12)) as usize;
        let Some(next) = EVENT_HEADER
            .checked_add(len)
            .and_then(|end| rest.get(end..))
        else {
            break;
        };
        events.push(InotifyEvent { wd, mask });
        rest = next;
    }
    events
}

/// What one drained batch of inotify events means.
#[derive(Debug, Default, PartialEq, Eq)]
struct Batch {
    /// Scan once for the whole batch.
    trigger: bool,
    /// The script watch is gone (`IN_IGNORED`): re-add it.
    primary_lost: bool,
    /// The test-log watch is gone or the file moved: forget it, retry later.
    secondary_lost: bool,
    /// The test log may have new lines (for the standby guard).
    test_log_written: bool,
}

fn classify(events: &[InotifyEvent], primary: i32, secondary: Option<i32>) -> Batch {
    let mut batch = Batch::default();
    for ev in events {
        if ev.mask & IN_Q_OVERFLOW != 0 {
            // Events were dropped (wd -1): one may have been a launch or a
            // test-log line.
            batch.trigger = true;
            batch.test_log_written = true;
        } else if ev.wd == primary {
            batch.trigger |= ev.mask & IN_OPEN != 0;
            batch.primary_lost |= ev.mask & IN_IGNORED != 0;
        } else if Some(ev.wd) == secondary {
            let written = ev.mask & IN_CLOSE_WRITE != 0;
            batch.trigger |= written;
            batch.test_log_written |= written;
            batch.secondary_lost |= ev.mask & (IN_IGNORED | IN_DELETE_SELF | IN_MOVE_SELF) != 0;
        }
    }
    batch
}

// ── Runtime ─────────────────────────────────────────────────────────

/// Starts the `wifi-watchdog` thread. `standby_rx` carries the power events
/// for the standby Wi-Fi guard (`None` when it is opted out).
#[cfg(target_os = "linux")]
pub fn start(standby_rx: Option<std::sync::mpsc::Receiver<serde_json::Value>>) {
    let spawned = crate::system::try_spawn_named("wifi-watchdog", move || linux::run(standby_rx));
    if let Err(e) = spawned {
        eprintln!("[wifi] cannot spawn wifi-watchdog: {e}");
    }
}

#[cfg(not(target_os = "linux"))]
pub fn start(_standby_rx: Option<std::sync::mpsc::Receiver<serde_json::Value>>) {}

/// Time since boot on `CLOCK_BOOTTIME` (the clock of `/proc/uptime` and of
/// the process start times; it keeps counting during suspend).
#[cfg(target_os = "linux")]
pub(crate) fn boot_now() -> Duration {
    // SAFETY: an all-zero timespec is a valid value.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `ts` is a valid out-pointer for the duration of the call.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    Duration::new(
        ts.tv_sec.max(0) as u64,
        ts.tv_nsec.clamp(0, 999_999_999) as u32,
    )
}

/// The earlier of two optional deadlines.
fn earliest(a: Option<Duration>, b: Option<Duration>) -> Option<Duration> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::fs;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::mpsc::Receiver;
    use std::time::Duration;

    use serde_json::Value;

    use super::*;
    use crate::standby_guard;

    pub fn run(standby_rx: Option<Receiver<Value>>) {
        let hz = clock_ticks();
        let guarded = standby_rx.is_some();
        if let Err(e) = watch(hz, standby_rx) {
            eprintln!(
                "[wifi] cannot watch {POST_WIFI_SCRIPT}: {e}; sweeping for stuck copies every {} s instead",
                FALLBACK_SWEEP.as_secs()
            );
            if guarded {
                eprintln!("[wifi] standby Wi-Fi guard off: it needs the {TEST_LOG} watch");
            }
            sweep_forever(hz);
        }
    }

    /// The event loop. Returns only on an error that leaves the script
    /// unwatched; the caller then falls back to sweeping.
    fn watch(hz: u64, standby_rx: Option<Receiver<Value>>) -> io::Result<()> {
        // SAFETY: plain syscall; the result is checked before use.
        let ifd = owned(
            unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) },
            "inotify_init1",
        )?;
        // Watches go in before the first scan, so a launch between the scan
        // and the watch cannot be missed.
        let mut primary = add_watch(&ifd, POST_WIFI_SCRIPT, IN_OPEN)?;
        let mut secondary = add_secondary(&ifd);
        // SAFETY: plain syscall; the result is checked before use.
        let tfd = owned(
            unsafe {
                libc::timerfd_create(libc::CLOCK_BOOTTIME, libc::TFD_CLOEXEC | libc::TFD_NONBLOCK)
            },
            "timerfd_create",
        )?;
        let pending = if secondary.is_some() {
            ""
        } else {
            " (once it exists)"
        };
        eprintln!(
            "[wifi] watching for stuck zte_post_wifi.sh (event-driven): {POST_WIFI_SCRIPT} opens, {TEST_LOG} writes{pending}"
        );
        let mut guard = standby_rx.and_then(standby_guard::linux::Runtime::start);

        let mut rt = Runtime {
            machine: Machine::new(),
            hz,
            scan_failing: false,
        };
        rt.handle(Event::Trigger);
        arm(&tfd, rt.machine.next_deadline())?;
        loop {
            let pollfd = |fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // A negative fd is ignored by poll(): no guard, no eventfd.
            let mut fds = [
                pollfd(ifd.as_raw_fd()),
                pollfd(tfd.as_raw_fd()),
                pollfd(guard.as_ref().map_or(-1, |g| g.wake_fd())),
            ];
            // SAFETY: `fds` is a valid array of pollfd entries that outlives the call.
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if rc < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(context("poll", e));
            }

            // Power events first: a power-on that came with a Wi-Fi start
            // must be known before the test log is read.
            if fds[2].revents != 0 {
                if let Some(g) = guard.as_mut() {
                    g.on_power_events();
                }
            }
            let mut trigger = false;
            let mut test_log = false;
            if fds[0].revents != 0 {
                let batch = classify(&drain_events(&ifd)?, primary, secondary);
                if batch.secondary_lost {
                    if let Some(wd) = secondary.take() {
                        // Still watched after a move; already gone otherwise (EINVAL, ignored).
                        // SAFETY: plain syscall on our own inotify fd.
                        unsafe { libc::inotify_rm_watch(ifd.as_raw_fd(), wd) };
                    }
                }
                if batch.primary_lost {
                    primary = add_watch(&ifd, POST_WIFI_SCRIPT, IN_OPEN)?;
                    eprintln!(
                        "[wifi] watch on {POST_WIFI_SCRIPT} was dropped by the kernel; re-added"
                    );
                    trigger = true;
                }
                trigger |= batch.trigger;
                test_log |= batch.test_log_written;
            }
            // Absent until the first Wi-Fi reconf after boot, or removed since.
            if secondary.is_none() {
                secondary = add_secondary(&ifd);
                // Lines written before the watch was in place are news too.
                test_log |= secondary.is_some();
            }
            if test_log {
                if let Some(g) = guard.as_mut() {
                    g.on_test_log();
                }
            }
            if trigger {
                rt.handle(Event::Trigger);
            }
            if fds[1].revents != 0 && read_timer(&tfd)? {
                rt.handle(Event::Timer);
                if let Some(g) = guard.as_mut() {
                    g.on_timer();
                }
            }
            let guard_deadline = guard.as_ref().and_then(|g| g.next_deadline());
            arm(&tfd, earliest(rt.machine.next_deadline(), guard_deadline))?;
        }
    }

    /// Without inotify: the pre-event-driven behaviour, a sweep every
    /// [`FALLBACK_SWEEP`] after a first one at [`FALLBACK_FIRST`].
    fn sweep_forever(hz: u64) -> ! {
        std::thread::sleep(FALLBACK_FIRST);
        let mut machine = Machine::new();
        loop {
            let scan = scan(hz).unwrap_or_default();
            for action in machine.step(Event::Scanned(scan), boot_now()) {
                if let Action::Kill { pid, age, rule } = action {
                    kill(pid, age, rule);
                }
            }
            std::thread::sleep(FALLBACK_SWEEP);
        }
    }

    struct Runtime {
        machine: Machine,
        hz: u64,
        /// The last scan could not read `/proc` (logged once per streak).
        scan_failing: bool,
    }

    impl Runtime {
        fn handle(&mut self, event: Event) {
            let now = boot_now();
            for action in self.machine.step(event, now) {
                self.act(action, now);
            }
        }

        fn act(&mut self, action: Action, now: Duration) {
            match action {
                Action::Scan => self.scan(),
                Action::Kill { pid, age, rule } => kill(pid, age, rule),
                Action::Watch { pid, at, rule } => {
                    let secs = at.saturating_sub(now).as_secs_f64();
                    match rule {
                        Rule::Age => eprintln!(
                            "[wifi] zte_post_wifi.sh running (pid {pid}); checking again in ~{secs:.0} s"
                        ),
                        Rule::Endless { .. } => eprintln!(
                            "[wifi] zte_post_wifi.sh running (pid {pid}) with a radio off but its SSID on, so it cannot finish; stopping it in ~{secs:.0} s"
                        ),
                    }
                }
                Action::Wait {
                    pid,
                    monitors,
                    reachable,
                } => eprintln!(
                    "[wifi] zte_post_wifi.sh pid {pid} cannot finish, but its loop has started only {monitors} of {reachable} hostapd_cli monitors; waiting for them (at most until it has run {} s)",
                    MAX_AGE.as_secs()
                ),
                Action::Relax { pid, at } => {
                    let secs = at.saturating_sub(now).as_secs_f64();
                    eprintln!(
                        "[wifi] zte_post_wifi.sh pid {pid}: the Wi-Fi config changed (or is unreadable) and no longer says it cannot finish; checking again in ~{secs:.0} s"
                    )
                }
            }
        }

        fn scan(&mut self) {
            let scanned = scan(self.hz);
            let now = boot_now();
            let Some(mut scan) = scanned else {
                if !self.scan_failing {
                    eprintln!(
                        "[wifi] cannot read /proc to check for stuck zte_post_wifi.sh; retrying every {} s",
                        SCAN_RETRY.as_secs()
                    );
                }
                self.scan_failing = true;
                self.machine.step(Event::ScanFailed, now);
                return;
            };
            self.scan_failing = false;
            // Judge each copy by the config it runs with: a new one, and an
            // endless one again before it is stopped.
            if !scan.copies.is_empty() {
                scan.outlook = fs::read_to_string(WIRELESS_CONFIG)
                    .ok()
                    .map(|text| Outlook::from_config(&text));
            }
            for action in self.machine.step(Event::Scanned(scan), now) {
                self.act(action, now);
            }
        }
    }

    /// Every top-level copy of the script running now and the `hostapd_cli`
    /// monitors that are up; `None` when `/proc` cannot be read at all (a
    /// process that exits mid-scan is just skipped).
    fn scan(hz: u64) -> Option<Scan> {
        let entries = fs::read_dir("/proc").ok()?;
        let mut found = Vec::new();
        let mut monitors = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            let monitor = is_hostapd_monitor(&cmdline);
            if !monitor && !is_post_wifi_cmdline(&cmdline) {
                continue;
            }
            let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            let Some((ppid, ticks)) = parse_stat(&stat) else {
                continue;
            };
            let start = ticks_to_duration(ticks, hz);
            if monitor {
                monitors.push(Monitor { ppid, start });
            } else {
                found.push(Found { pid, ppid, start });
            }
        }
        Some(Scan {
            monitors: monitors_up(monitors, &found),
            copies: top_level(found),
            outlook: None,
        })
    }

    fn kill(pid: i32, age: Duration, rule: Rule) {
        // SAFETY: plain syscall; `pid` is a matching copy found by the scan.
        if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
            let age = age.as_secs_f64();
            let why = match rule {
                Rule::Age => "",
                Rule::Endless { .. } => "; a radio is off but its SSID is on",
            };
            eprintln!("[wifi] killed stuck zte_post_wifi.sh pid {pid} (running {age:.0} s{why})");
        }
    }

    fn clock_ticks() -> u64 {
        // SAFETY: plain libc call without pointers.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz > 0 {
            hz as u64
        } else {
            100
        }
    }

    fn context(what: &str, e: io::Error) -> io::Error {
        io::Error::new(e.kind(), format!("{what}: {e}"))
    }

    fn owned(fd: libc::c_int, what: &str) -> io::Result<OwnedFd> {
        if fd < 0 {
            return Err(context(what, io::Error::last_os_error()));
        }
        // SAFETY: the syscall succeeded, so `fd` is open and owned by nobody else.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn add_watch(ifd: &OwnedFd, path: &str, mask: u32) -> io::Result<i32> {
        let c_path =
            CString::new(path).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call.
        let wd = unsafe { libc::inotify_add_watch(ifd.as_raw_fd(), c_path.as_ptr(), mask) };
        if wd < 0 {
            return Err(context(
                &format!("inotify_add_watch {path}"),
                io::Error::last_os_error(),
            ));
        }
        Ok(wd)
    }

    /// Best effort: ENOENT until the first Wi-Fi reconf after boot creates
    /// the file. The `/tmp` directory itself is not watched (too noisy).
    fn add_secondary(ifd: &OwnedFd) -> Option<i32> {
        add_watch(
            ifd,
            TEST_LOG,
            IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF,
        )
        .ok()
    }

    #[repr(C, align(8))]
    struct EventBuf([u8; 4096]);

    /// Reads every queued inotify record until EAGAIN.
    fn drain_events(ifd: &OwnedFd) -> io::Result<Vec<InotifyEvent>> {
        let mut buf = EventBuf([0; 4096]);
        let mut events = Vec::new();
        loop {
            // SAFETY: `buf` is valid for writes of its full length during the call.
            let n = unsafe { libc::read(ifd.as_raw_fd(), buf.0.as_mut_ptr().cast(), buf.0.len()) };
            if n > 0 {
                events.extend(parse_events(&buf.0[..n as usize]));
                continue;
            }
            if n == 0 {
                return Ok(events);
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock => return Ok(events),
                io::ErrorKind::Interrupted => continue,
                _ => return Err(context("inotify read", e)),
            }
        }
    }

    /// Consumes the timerfd expiration count; `false` when nothing expired
    /// (spurious wake).
    fn read_timer(tfd: &OwnedFd) -> io::Result<bool> {
        let mut count = [0u8; 8];
        loop {
            // SAFETY: `count` is valid for writes of 8 bytes during the call.
            let n = unsafe { libc::read(tfd.as_raw_fd(), count.as_mut_ptr().cast(), count.len()) };
            if n >= 0 {
                return Ok(n == 8);
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock => return Ok(false),
                io::ErrorKind::Interrupted => continue,
                _ => return Err(context("timerfd read", e)),
            }
        }
    }

    /// Arms the timerfd for `deadline` (absolute, time since boot) or
    /// disarms it.
    fn arm(tfd: &OwnedFd, deadline: Option<Duration>) -> io::Result<()> {
        // SAFETY: an all-zero itimerspec is valid and means "disarmed".
        let mut spec: libc::itimerspec = unsafe { std::mem::zeroed() };
        let mut flags = 0;
        if let Some(at) = deadline {
            spec.it_value.tv_sec = at.as_secs() as _;
            spec.it_value.tv_nsec = at.subsec_nanos() as _;
            flags = libc::TFD_TIMER_ABSTIME;
        }
        // SAFETY: `spec` is valid for the call; the old value is not requested.
        let rc =
            unsafe { libc::timerfd_settime(tfd.as_raw_fd(), flags, &spec, std::ptr::null_mut()) };
        if rc < 0 {
            return Err(context("timerfd_settime", io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Duration = Duration::from_secs(1);

    fn copy(pid: i32, start_secs: u32) -> Copy {
        Copy {
            pid,
            start: start_secs * S,
        }
    }

    // -- matcher and /proc parsing --

    #[test]
    fn matches_only_the_firmware_script_invocation() {
        assert!(is_post_wifi_cmdline(b"sh\0/sbin/zte_post_wifi.sh\0"));
        assert!(is_post_wifi_cmdline(b"/bin/sh\0/sbin/zte_post_wifi.sh\0"));
        assert!(is_post_wifi_cmdline(b"ash\0/sbin/zte_post_wifi.sh\0"));
        // a shell that merely mentions the script (ssh session, grep) must not match
        assert!(!is_post_wifi_cmdline(
            b"ash\0-c\0ps | grep zte_post_wifi.sh\0"
        ));
        assert!(!is_post_wifi_cmdline(b"sh\0/sbin/zte_wlan_func.sh\0"));
        assert!(!is_post_wifi_cmdline(b"bash\0/sbin/zte_post_wifi.sh\0"));
        assert!(!is_post_wifi_cmdline(b""));
    }

    #[test]
    fn matches_the_b31_form_with_one_numeric_flag() {
        assert!(is_post_wifi_cmdline(b"sh\0/sbin/zte_post_wifi.sh\x001\0"));
        assert!(is_post_wifi_cmdline(b"sh\0/sbin/zte_post_wifi.sh\x000\0"));
        assert!(!is_post_wifi_cmdline(
            b"sh\0/sbin/zte_post_wifi.sh\0extra\0"
        ));
        assert!(!is_post_wifi_cmdline(b"sh\0/sbin/zte_post_wifi.sh\0-1\0"));
        assert!(!is_post_wifi_cmdline(
            b"sh\0/sbin/zte_post_wifi.sh\x001\x001\0"
        ));
    }

    #[test]
    fn stat_yields_ppid_and_field_22_after_the_comm() {
        // comm with spaces and parentheses, as /proc renders it
        let stat = "123 (sh (x) y) S 77 123 123 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 4500 1500000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0";
        assert_eq!(parse_stat(stat), Some((77, 4500)));
        assert_eq!(parse_stat("garbage"), None);
        assert_eq!(parse_stat("1 (sh)"), None);
        assert_eq!(ticks_to_duration(4500, 100), 45 * S);
        assert_eq!(ticks_to_duration(4550, 100), Duration::from_millis(45_500));
    }

    #[test]
    fn subshells_of_a_copy_are_not_counted() {
        let found = vec![
            Found {
                pid: 500,
                ppid: 1,
                start: 10 * S,
            },
            // command-substitution subshells (and a subshell's subshell)
            Found {
                pid: 900,
                ppid: 500,
                start: 200 * S,
            },
            Found {
                pid: 901,
                ppid: 900,
                start: 200 * S,
            },
            // an unrelated second run
            Found {
                pid: 600,
                ppid: 42,
                start: 50 * S,
            },
        ];
        assert_eq!(top_level(found), vec![copy(500, 10), copy(600, 50)]);
    }

    #[test]
    fn counts_hostapd_monitors_like_the_script() {
        let monitor = b"/usr/sbin/hostapd_cli\0-i\0wlan2\0-s\0/data/vendor/wifi\0-p\0/data/vendor/wifi/hostapd\0-B\0-a\0/lib/wifi/wps-hostapd-update-uci.sh\0";
        assert!(is_hostapd_monitor(monitor));
        assert!(!is_hostapd_monitor(
            b"/usr/sbin/hostapd_cli\0-i\0wlan0\0-s\0/data/vendor/wifi\0-p\0/data/vendor/wifi/hostapd\0list_sta\0"
        ));
        // The mesh backhaul monitor is not one the script waits for.
        assert!(!is_hostapd_monitor(
            b"/usr/sbin/hostapd_cli\0-i\0wlan3\0-B\0-a\0/lib/wifi/wifi_backhaul_hostapd_monitor.sh\0"
        ));
        // `grep -v grep`: the script's own count, or someone's ps | grep.
        assert!(!is_hostapd_monitor(b"grep\0-c\0hostapd_cli.*wps-hostapd\0"));
        assert!(!is_hostapd_monitor(b"wps-hostapd\0hostapd_cli\0"));
        assert!(!is_hostapd_monitor(b""));

        // Up: daemonized (re-parented). Not yet: still the child of a copy or
        // of one of its subshells (an attempt for the radio that is off).
        let copies = [
            Found {
                pid: 500,
                ppid: 1,
                start: 10 * S,
            },
            Found {
                pid: 900,
                ppid: 500,
                start: 20 * S,
            },
        ];
        let monitor = |ppid, secs| Monitor {
            ppid,
            start: secs * S,
        };
        assert_eq!(
            monitors_up(
                vec![
                    monitor(1, 3),
                    monitor(500, 25),
                    monitor(900, 26),
                    monitor(1234, 27)
                ],
                &copies
            ),
            [3 * S, 27 * S]
        );
        assert!(monitors_up(vec![], &copies).is_empty());
    }

    // -- Wi-Fi config --

    /// The owner's layout: 2.4 GHz radio off, both main SSIDs on, guests off.
    const WIRELESS: &str = "\
config wifi-device 'wifi0'
\toption type 'qcawificfg80211'
\toption channel 'auto'
\toption disabled '1'

config wifi-device 'wifi1'
\toption type 'qcawificfg80211'
\toption disabled '0'

config wifi-iface 'main_2g'
\toption device 'wifi0'
\toption ifname 'wlan0'
\toption mode 'ap'
\toption ssid 'Home'
\toption disabled '0'

config wifi-iface 'main_5g'
\toption device 'wifi1'
\toption ifname 'wlan2'
\toption mode 'ap'
\toption ssid 'Home 5G'
\toption disabled '0'

config wifi-iface 'guest_2g'
\toption device 'wifi0'
\toption mode 'ap'
\toption disabled '1'

config wifi-iface 'guest_5g'
\toption device 'wifi1'
\toption mode 'ap'
\toption disabled '1'

config wifi-iface 'backhaul_5g'
\toption device 'wifi1'
\toption mode 'ap'
\toption disabled '0'

config zte_mbb 'zte_mbb'
\toption wifi_onoff '1'
\toption wifi_onoff_by_user '1'
";

    #[test]
    fn radio_off_with_its_ssid_on_is_endless() {
        let o = Outlook::from_config(WIRELESS);
        assert_eq!(
            o,
            Outlook {
                wanted: 2,
                reachable: 1,
                ssid_on_radio_off: true
            }
        );
        assert!(o.endless());
    }

    #[test]
    fn consistent_configs_are_not_endless() {
        // Both radios on.
        let both = WIRELESS.replacen("option disabled '1'", "option disabled '0'", 1);
        let o = Outlook::from_config(&both);
        assert_eq!((o.wanted, o.reachable, o.ssid_on_radio_off), (2, 2, false));
        assert!(!o.endless());
        // 2.4 GHz SSID off as well (the script finishes; Wi-Fi is broken in
        // another way, see the power plan, but that is not this guard's call).
        let ssid_off = WIRELESS.replace(
            "'wlan0'\n\toption mode 'ap'\n\toption ssid 'Home'\n\toption disabled '0'",
            "'wlan0'\n\toption mode 'ap'\n\toption ssid 'Home'\n\toption disabled '1'",
        );
        let o = Outlook::from_config(&ssid_off);
        assert_eq!((o.wanted, o.reachable, o.ssid_on_radio_off), (1, 1, false));
        assert!(!o.endless());
        // An SSID on the off radio that the script does not wait for.
        let anonymous = "config wifi-device 'wifi0'\n\toption disabled '1'\nconfig wifi-iface\n\toption device 'wifi0'\n\toption mode 'ap'\n\toption disabled '0'\n";
        let o = Outlook::from_config(anonymous);
        assert_eq!((o.wanted, o.reachable, o.ssid_on_radio_off), (0, 0, true));
        assert!(!o.endless());
        assert!(!Outlook::from_config("").endless());
    }

    #[test]
    fn wifi_switched_off_makes_every_ssid_hopeless() {
        // Standby, or the guard's own turn-off: no hostapd at all.
        let off = WIRELESS.replace("option wifi_onoff '1'", "option wifi_onoff '0'");
        let o = Outlook::from_config(&off);
        assert_eq!((o.wanted, o.reachable, o.ssid_on_radio_off), (2, 0, true));
        assert!(o.endless());
    }

    #[test]
    fn parses_uci_quoting_comments_and_anonymous_sections() {
        let text = "# generated\n\
            package wireless\n\
            config wifi-iface\n\
            \toption ssid \"Bob's \\\"Net\\\"\"  # trailing comment\n\
            \toption key 'a b'\\''c'\n\
            \toption disabled 1\n\
            \tlist maclist '00:11:22:33:44:55'\n\
            \toption disabled 0\n\
            config wifi-iface \"named\"\n\
            \toption device wifi1\n";
        let sections = parse_uci(text);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].name, None);
        assert_eq!(sections[0].get("ssid"), Some("Bob's \"Net\""));
        assert_eq!(sections[0].get("key"), Some("a b'c"));
        assert_eq!(
            sections[0].get("disabled"),
            Some("0"),
            "the last repeat wins"
        );
        assert_eq!(sections[0].get("maclist"), None);
        assert_eq!(sections[1].name.as_deref(), Some("named"));
        assert_eq!(sections[1].get("device"), Some("wifi1"));
        assert_eq!(uci_words("  option x  'y' #c"), ["option", "x", "y"]);
        assert_eq!(uci_words("option x a#b"), ["option", "x", "a#b"]);
        assert!(uci_words("   ").is_empty());
    }

    #[test]
    fn mirrors_the_scripts_grep() {
        assert!(counted_by_script("wireless.main_2g.disabled='0'"));
        assert!(counted_by_script("wireless.guest_5g.disabled='0'"));
        assert!(!counted_by_script("wireless.guest_5g.disabled='1'"));
        assert!(!counted_by_script("wireless.wifi0.disabled='0'"));
        // `.*.` needs a character between the word and "disabled".
        assert!(!counted_by_script("maindisabled0"));
        assert!(counted_by_script("main.disabled0"));
        // The grep is that loose: an SSID text can count.
        assert!(counted_by_script("wireless.main_5g.ssid='not disabled 0'"));
        assert!(!counted_by_script("wireless.main_5g.ssid='Hé'"));
        // Anonymous sections are `@wifi-iface[i]` to uci show, never counted.
        assert!(!counted_by_script("wireless.@wifi-iface[0].disabled='0'"));
    }

    // -- state machine --

    /// A scan with `up` monitors started at 103 s, after the copies the
    /// tests start at 100 s (and before those started later).
    fn scan(copies: Vec<Copy>, up: usize, outlook: Option<Outlook>) -> Event {
        Event::Scanned(Scan {
            copies,
            monitors: vec![103 * S; up],
            outlook,
        })
    }

    fn scanned(copies: Vec<Copy>) -> Event {
        scan(copies, 0, None)
    }

    fn kill(pid: i32, age: Duration) -> Action {
        Action::Kill {
            pid,
            age,
            rule: Rule::Age,
        }
    }

    fn watch(pid: i32, at: Duration) -> Action {
        Action::Watch {
            pid,
            at,
            rule: Rule::Age,
        }
    }

    /// A config whose loop waits for one monitor more than it can start.
    fn endless(reachable: usize) -> Option<Outlook> {
        Some(Outlook {
            wanted: reachable + 1,
            reachable,
            ssid_on_radio_off: true,
        })
    }

    #[test]
    fn trigger_scans() {
        let mut m = Machine::new();
        assert_eq!(m.step(Event::Trigger, 60 * S), vec![Action::Scan]);
    }

    #[test]
    fn no_copies_leaves_no_deadline() {
        let mut m = Machine::new();
        assert!(m.step(scanned(vec![]), 60 * S).is_empty());
        assert_eq!(m.next_deadline(), None);
    }

    #[test]
    fn fresh_copy_schedules_a_check_when_it_turns_max_age() {
        let mut m = Machine::new();
        assert_eq!(
            m.step(scanned(vec![copy(500, 100)]), 101 * S),
            vec![watch(500, 221 * S)]
        );
        assert_eq!(m.next_deadline(), Some(221 * S));
    }

    #[test]
    fn two_copies_are_scheduled_from_the_older() {
        let mut m = Machine::new();
        assert_eq!(
            m.step(scanned(vec![copy(600, 150), copy(500, 100)]), 160 * S),
            vec![watch(600, 271 * S), watch(500, 221 * S)]
        );
        assert_eq!(m.next_deadline(), Some(221 * S));
    }

    #[test]
    fn copy_already_stuck_at_startup_is_killed_at_once() {
        // Agent restarted while a copy was spinning.
        let mut m = Machine::new();
        assert_eq!(m.step(Event::Trigger, 300 * S), vec![Action::Scan]);
        assert_eq!(
            m.step(scanned(vec![copy(500, 10)]), 300 * S),
            vec![kill(500, 290 * S)]
        );
        assert_eq!(m.next_deadline(), None);
    }

    #[test]
    fn exactly_max_age_is_killed() {
        let mut m = Machine::new();
        assert_eq!(
            m.step(scanned(vec![copy(500, 100)]), 220 * S),
            vec![kill(500, MAX_AGE)]
        );
    }

    #[test]
    fn failed_scan_retries_instead_of_forgetting_the_check() {
        let mut m = Machine::new();
        m.step(scanned(vec![copy(500, 100)]), 101 * S);
        // The re-check at 221 s cannot read /proc: retry, do not disarm.
        assert_eq!(m.step(Event::Timer, 221 * S), vec![Action::Scan]);
        assert!(m.step(Event::ScanFailed, 221 * S).is_empty());
        assert_eq!(m.next_deadline(), Some(221 * S + SCAN_RETRY));
        assert_eq!(
            m.step(Event::Timer, 221 * S + SCAN_RETRY),
            vec![Action::Scan]
        );
        // A failed scan after a launch event also schedules a retry...
        let mut m = Machine::new();
        assert!(m.step(Event::ScanFailed, 60 * S).is_empty());
        assert_eq!(m.next_deadline(), Some(60 * S + SCAN_RETRY));
        // ...but never postpones an earlier pending check.
        let mut m = Machine::new();
        m.step(scanned(vec![copy(500, 100)]), 210 * S);
        assert!(m.step(Event::ScanFailed, 215 * S).is_empty());
        assert_eq!(m.next_deadline(), Some(221 * S));
    }

    #[test]
    fn mixed_copies_kill_the_old_and_schedule_the_young() {
        let mut m = Machine::new();
        let actions = m.step(scanned(vec![copy(500, 10), copy(600, 250)]), 260 * S);
        assert_eq!(actions, vec![kill(500, 250 * S), watch(600, 371 * S)]);
        assert_eq!(m.next_deadline(), Some(371 * S));
    }

    #[test]
    fn timer_scans_only_once_the_deadline_is_reached() {
        let mut m = Machine::new();
        assert!(
            m.step(Event::Timer, 50 * S).is_empty(),
            "no deadline, no work"
        );
        m.step(scanned(vec![copy(500, 100)]), 101 * S);
        assert!(
            m.step(Event::Timer, 200 * S).is_empty(),
            "early wake does nothing"
        );
        assert_eq!(m.next_deadline(), Some(221 * S));
        assert_eq!(m.step(Event::Timer, 221 * S), vec![Action::Scan]);
        assert_eq!(m.next_deadline(), None);
        assert!(
            m.step(Event::Timer, 222 * S).is_empty(),
            "deadline consumed"
        );
    }

    #[test]
    fn a_scan_replaces_the_previous_deadline() {
        let mut m = Machine::new();
        m.step(scanned(vec![copy(500, 100)]), 101 * S);
        // The copy finished (healthy run): nothing left to check.
        m.step(scanned(vec![]), 106 * S);
        assert_eq!(m.next_deadline(), None);
        m.step(scanned(vec![copy(500, 100)]), 101 * S);
        m.step(scanned(vec![copy(700, 150)]), 151 * S);
        assert_eq!(m.next_deadline(), Some(271 * S));
    }

    #[test]
    fn deadline_is_always_in_the_future() {
        let outlooks = [None, endless(0), endless(1)];
        for start_ms in (0..300_000).step_by(997) {
            for now_ms in (0..400_000).step_by(1009) {
                for (first, later, monitors) in outlooks
                    .iter()
                    .flat_map(|f| outlooks.iter().map(move |l| (*f, *l)))
                    .flat_map(|(f, l)| [(f, l, 0), (f, l, 1)])
                {
                    let mut m = Machine::new();
                    let now = Duration::from_millis(now_ms);
                    let c = Copy {
                        pid: 1,
                        start: Duration::from_millis(start_ms),
                    };
                    // First sight, then a re-check of the tracked copy.
                    m.step(scan(vec![c.clone()], monitors, first), now);
                    m.step(scan(vec![c], monitors, later), now);
                    if let Some(at) = m.next_deadline() {
                        assert!(
                            at > now,
                            "start {start_ms} ms, now {now_ms} ms, {first:?} then {later:?}: deadline {at:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn each_copy_is_reported_once_and_forgotten_when_gone() {
        let mut m = Machine::new();
        assert_eq!(
            m.step(scanned(vec![copy(500, 100)]), 101 * S),
            vec![watch(500, 221 * S)]
        );
        assert!(m.step(scanned(vec![copy(500, 100)]), 110 * S).is_empty());
        assert_eq!(
            m.step(scanned(vec![copy(500, 100), copy(600, 120)]), 121 * S),
            vec![watch(600, 241 * S)]
        );
        // 500 finished; pid 600 was reused by a new copy.
        assert_eq!(
            m.step(scanned(vec![copy(600, 130)]), 131 * S),
            vec![watch(600, 251 * S)]
        );
        assert!(!m.tracks(&copy(500, 100)));
        assert!(!m.tracks(&copy(600, 120)));
        assert!(m.tracks(&copy(600, 130)));
        // A stuck copy is killed, not reported or tracked.
        assert_eq!(
            m.step(scanned(vec![copy(600, 130)]), 251 * S),
            vec![kill(600, 121 * S)]
        );
        assert!(!m.tracks(&copy(600, 130)));
    }

    #[test]
    fn hopeless_copy_is_stopped_after_six_seconds() {
        let mut m = Machine::new();
        let rule = Rule::Endless { reachable: 1 };
        // Seen at launch (the script's open): re-check at start + 6 s.
        assert_eq!(
            m.step(scan(vec![copy(500, 100)], 0, endless(1)), 100 * S),
            vec![Action::Watch {
                pid: 500,
                at: 106 * S,
                rule
            }]
        );
        // The launcher's log line ~1 s later rescans; the rule stays.
        assert!(m
            .step(scan(vec![copy(500, 100)], 0, None), 101 * S)
            .is_empty());
        assert_eq!(m.next_deadline(), Some(106 * S));
        assert_eq!(m.step(Event::Timer, 106 * S), vec![Action::Scan]);
        assert_eq!(
            m.step(scan(vec![copy(500, 100)], 1, endless(1)), 106 * S),
            vec![Action::Kill {
                pid: 500,
                age: 6 * S,
                rule
            }]
        );
        assert_eq!(m.next_deadline(), None);
    }

    #[test]
    fn hopeless_copy_first_lets_its_loop_start_the_monitors() {
        let mut m = Machine::new();
        let rule = Rule::Endless { reachable: 1 };
        m.step(scan(vec![copy(500, 100)], 0, endless(1)), 100 * S);
        // At 6 s the 5 GHz monitor is not up yet: wait, and say so once.
        assert_eq!(
            m.step(scan(vec![copy(500, 100)], 0, endless(1)), 106 * S),
            vec![Action::Wait {
                pid: 500,
                monitors: 0,
                reachable: 1
            }]
        );
        assert_eq!(m.next_deadline(), Some(111 * S));
        assert!(m
            .step(scan(vec![copy(500, 100)], 0, endless(1)), 111 * S)
            .is_empty());
        assert_eq!(m.next_deadline(), Some(116 * S));
        assert_eq!(
            m.step(scan(vec![copy(500, 100)], 1, endless(1)), 116 * S),
            vec![Action::Kill {
                pid: 500,
                age: 16 * S,
                rule
            }]
        );

        // The monitor never comes up: stopped at 120 s like any other copy.
        let mut m = Machine::new();
        m.step(scan(vec![copy(500, 100)], 0, endless(1)), 100 * S);
        let mut now = 106 * S;
        let mut checks = 0;
        loop {
            checks += 1;
            let actions = m.step(scan(vec![copy(500, 100)], 0, endless(1)), now);
            if let [Action::Kill { age, .. }] = actions.as_slice() {
                assert_eq!(*age, now - 100 * S);
                break;
            }
            now = m.next_deadline().unwrap();
        }
        assert_eq!(now, 221 * S);
        assert_eq!(
            checks, 24,
            "one scan per {MONITOR_RETRY:?} after the first 6 s"
        );
    }

    #[test]
    fn a_monitor_older_than_the_copy_does_not_count() {
        // A reload while on: the old hostapd_cli lives on until its PING to
        // the restarted hostapd fails, and the loop then starts a new one.
        let with = |monitors: Vec<Duration>, outlook| {
            Event::Scanned(Scan {
                copies: vec![copy(500, 100)],
                monitors,
                outlook,
            })
        };
        let mut m = Machine::new();
        m.step(with(vec![90 * S], endless(1)), 100 * S);
        assert_eq!(
            m.step(with(vec![90 * S], endless(1)), 106 * S),
            vec![Action::Wait {
                pid: 500,
                monitors: 0,
                reachable: 1
            }]
        );
        assert_eq!(
            m.step(with(vec![90 * S, 107 * S], endless(1)), 111 * S),
            vec![Action::Kill {
                pid: 500,
                age: 11 * S,
                rule: Rule::Endless { reachable: 1 }
            }]
        );
    }

    #[test]
    fn a_copy_keeps_the_rule_it_was_first_seen_with() {
        let healthy = Some(Outlook {
            wanted: 2,
            reachable: 2,
            ssid_on_radio_off: false,
        });
        let mut m = Machine::new();
        assert_eq!(
            m.step(scan(vec![copy(500, 100)], 0, healthy), 100 * S),
            vec![watch(500, 221 * S)]
        );
        // The config changing later does not shorten its check...
        assert!(m
            .step(scan(vec![copy(500, 100)], 5, endless(1)), 107 * S)
            .is_empty());
        assert_eq!(m.next_deadline(), Some(221 * S));
        // ...but a new copy is judged by the config it starts with.
        assert_eq!(
            m.step(
                scan(vec![copy(500, 100), copy(600, 107)], 0, endless(1)),
                107 * S
            ),
            vec![Action::Watch {
                pid: 600,
                at: 113 * S,
                rule: Rule::Endless { reachable: 1 }
            }]
        );
        assert_eq!(m.next_deadline(), Some(113 * S));
        // An unreadable config keeps the 120 s rule.
        let mut m = Machine::new();
        assert_eq!(
            m.step(scan(vec![copy(700, 100)], 0, None), 100 * S),
            vec![watch(700, 221 * S)]
        );
    }

    #[test]
    fn agent_start_during_a_hopeless_spin_kills_at_once() {
        let mut m = Machine::new();
        assert_eq!(
            m.step(scan(vec![copy(500, 100)], 1, endless(1)), 160 * S),
            vec![Action::Kill {
                pid: 500,
                age: 60 * S,
                rule: Rule::Endless { reachable: 1 }
            }]
        );
        // Wi-Fi switched off (standby): nothing to wait for.
        let mut m = Machine::new();
        m.step(scan(vec![copy(500, 100)], 0, endless(0)), 100 * S);
        assert_eq!(
            m.step(scan(vec![copy(500, 100)], 0, endless(0)), 106 * S),
            vec![Action::Kill {
                pid: 500,
                age: 6 * S,
                rule: Rule::Endless { reachable: 0 }
            }]
        );
    }

    #[test]
    fn the_config_is_judged_again_before_a_fast_kill() {
        // Seen at launch while a power-on had switched Wi-Fi on but not yet
        // its 5 GHz radio: nothing reachable then, one monitor by 6 s.
        let mut m = Machine::new();
        m.step(scan(vec![copy(500, 100)], 0, endless(0)), 100 * S);
        assert_eq!(m.next_deadline(), Some(106 * S));
        assert_eq!(
            m.step(scan(vec![copy(500, 100)], 0, endless(1)), 106 * S),
            vec![Action::Wait {
                pid: 500,
                monitors: 0,
                reachable: 1
            }],
            "waits for the monitor the config now allows"
        );
        assert_eq!(
            m.step(scan(vec![copy(500, 100)], 1, endless(1)), 111 * S),
            vec![Action::Kill {
                pid: 500,
                age: 11 * S,
                rule: Rule::Endless { reachable: 1 }
            }]
        );

        // The config no longer makes it endless (or cannot be read): the
        // 120 s rule, said once.
        let healthy = Some(Outlook {
            wanted: 1,
            reachable: 1,
            ssid_on_radio_off: false,
        });
        for later in [healthy, None] {
            let mut m = Machine::new();
            m.step(scan(vec![copy(500, 100)], 0, endless(1)), 100 * S);
            assert_eq!(
                m.step(scan(vec![copy(500, 100)], 1, later), 106 * S),
                vec![Action::Relax {
                    pid: 500,
                    at: 221 * S
                }],
                "{later:?}"
            );
            assert_eq!(m.next_deadline(), Some(221 * S));
            assert!(m
                .step(scan(vec![copy(500, 100)], 1, endless(1)), 150 * S)
                .is_empty());
            assert_eq!(
                m.step(scan(vec![copy(500, 100)], 1, later), 221 * S),
                vec![kill(500, 121 * S)]
            );
        }
    }

    #[test]
    fn reads_an_option_of_a_named_section() {
        assert_eq!(
            config_option(WIRELESS, "zte_mbb", "wifi_onoff_by_user").as_deref(),
            Some("1")
        );
        assert_eq!(
            config_option(WIRELESS, "wifi0", "disabled").as_deref(),
            Some("1")
        );
        assert_eq!(config_option(WIRELESS, "zte_mbb", "missing"), None);
        assert_eq!(config_option(WIRELESS, "nowhere", "disabled"), None);
        assert_eq!(config_option("", "zte_mbb", "wifi_onoff"), None);
    }

    #[test]
    fn earliest_of_two_deadlines() {
        assert_eq!(earliest(None, None), None);
        assert_eq!(earliest(Some(5 * S), None), Some(5 * S));
        assert_eq!(earliest(None, Some(7 * S)), Some(7 * S));
        assert_eq!(earliest(Some(9 * S), Some(7 * S)), Some(7 * S));
    }

    // -- inotify records --

    fn record(wd: i32, mask: u32, name: &[u8], len: u32) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&wd.to_ne_bytes());
        r.extend_from_slice(&mask.to_ne_bytes());
        r.extend_from_slice(&0u32.to_ne_bytes());
        r.extend_from_slice(&len.to_ne_bytes());
        let mut padded = name.to_vec();
        padded.resize(len as usize, 0);
        r.extend_from_slice(&padded);
        r
    }

    #[test]
    fn parses_a_single_event() {
        let buf = record(1, IN_OPEN, b"", 0);
        assert_eq!(
            parse_events(&buf),
            vec![InotifyEvent {
                wd: 1,
                mask: IN_OPEN
            }]
        );
    }

    #[test]
    fn parses_multiple_events_with_padded_names() {
        let mut buf = record(1, IN_OPEN, b"", 0);
        buf.extend(record(2, IN_CLOSE_WRITE, b"zteqcawifi_test.txt", 32));
        buf.extend(record(2, IN_IGNORED, b"x", 16));
        assert_eq!(
            parse_events(&buf),
            vec![
                InotifyEvent {
                    wd: 1,
                    mask: IN_OPEN
                },
                InotifyEvent {
                    wd: 2,
                    mask: IN_CLOSE_WRITE
                },
                InotifyEvent {
                    wd: 2,
                    mask: IN_IGNORED
                },
            ]
        );
        // Not 8-byte aligned in memory: the parser must not care.
        let mut shifted = vec![0u8];
        shifted.extend(&buf);
        assert_eq!(parse_events(&shifted[1..]).len(), 3);
    }

    #[test]
    fn ignores_a_truncated_tail() {
        let mut buf = record(1, IN_OPEN, b"", 0);
        let second = record(2, IN_CLOSE_WRITE, b"name", 16);
        buf.extend_from_slice(&second[..20]); // header plus part of the name
        assert_eq!(
            parse_events(&buf),
            vec![InotifyEvent {
                wd: 1,
                mask: IN_OPEN
            }]
        );
        assert_eq!(parse_events(&buf[..10]), vec![]);
        assert_eq!(parse_events(&[]), vec![]);
    }

    #[test]
    fn overflow_triggers_a_scan() {
        let events = parse_events(&record(-1, IN_Q_OVERFLOW, b"", 0));
        assert_eq!(
            classify(&events, 1, None),
            Batch {
                trigger: true,
                test_log_written: true,
                ..Batch::default()
            }
        );
    }

    #[test]
    fn classifies_watch_events() {
        let ev = |wd, mask| InotifyEvent { wd, mask };
        // A launch, then the launcher's log line: one trigger for the batch.
        assert_eq!(
            classify(&[ev(1, IN_OPEN), ev(2, IN_CLOSE_WRITE)], 1, Some(2)),
            Batch {
                trigger: true,
                test_log_written: true,
                ..Batch::default()
            }
        );
        // Only the launch: the test log has nothing new.
        assert_eq!(
            classify(&[ev(1, IN_OPEN)], 1, Some(2)),
            Batch {
                trigger: true,
                ..Batch::default()
            }
        );
        // The log file removed: forget its watch, nothing to scan.
        assert_eq!(
            classify(&[ev(2, IN_DELETE_SELF), ev(2, IN_IGNORED)], 1, Some(2)),
            Batch {
                secondary_lost: true,
                ..Batch::default()
            }
        );
        assert_eq!(
            classify(&[ev(2, IN_MOVE_SELF)], 1, Some(2)),
            Batch {
                secondary_lost: true,
                ..Batch::default()
            }
        );
        assert_eq!(
            classify(&[ev(1, IN_IGNORED)], 1, Some(2)),
            Batch {
                primary_lost: true,
                ..Batch::default()
            }
        );
        // Stale watch descriptors are ignored.
        assert_eq!(
            classify(&[ev(7, IN_OPEN), ev(2, IN_CLOSE_WRITE)], 1, None),
            Batch::default()
        );
    }
}
