//! The only writer of conntrack (`relay-mihomo-architecture.md` section
//! 4.5). Deleting an entry makes established and IPA-offloaded connections
//! take the current path: IPACM drops the hardware entry on the DESTROY event
//! and offloads a connection whose path did not change again about 0.1 s
//! later (plan, confirmation 4), so a download that keeps its path goes on.
//! Deleting an entry neither sends a TCP reset nor clears a client's DNS
//! cache.
//!
//! `conntrack -D` (conntrack-tools 1.4.8) exits 1 both when nothing matched
//! and when an operation failed; only its standard error tells them apart
//! (`print_stats` writes "N flow entries have been deleted." last, a failure
//! writes "Operation failed: …" and no count). A request is settled by a
//! deletion that started after its path changed, succeeded and covered it;
//! a failed one stays pending (`retry`).

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use ipnet::Ipv4Net;
use serde_json::{json, Value};

/// Which LAN connections lose their entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Every connection from the LAN subnets of these families.
    Lan { v4: bool, v6: bool },
    /// LAN IPv4 connections to these destinations.
    Destinations(Vec<Ipv4Net>),
}

impl Scope {
    fn covers(&self, other: &Scope) -> bool {
        match (self, other) {
            (Scope::Lan { v4, v6 }, Scope::Lan { v4: v4b, v6: v6b }) => (*v4 || !v4b) && (*v6 || !v6b),
            (Scope::Lan { v4, .. }, Scope::Destinations(_)) => *v4,
            (Scope::Destinations(have), Scope::Destinations(want)) => want.iter().all(|w| have.iter().any(|h| h.contains(w))),
            (Scope::Destinations(_), Scope::Lan { .. }) => false,
        }
    }

    /// More destination ranges than this reset the whole LAN instead (D10).
    pub const MAX_RANGES: usize = 64;

    fn bounded(self) -> Scope {
        match self {
            Scope::Destinations(ranges) if ranges.len() > Self::MAX_RANGES => Scope::Lan { v4: true, v6: false },
            other => other,
        }
    }

    fn empty(&self) -> bool {
        match self {
            Scope::Lan { v4, v6 } => !v4 && !v6,
            Scope::Destinations(ranges) => ranges.is_empty(),
        }
    }

    /// Both scopes in one (a pending request and a new one).
    fn union(&self, other: &Scope) -> Scope {
        match (self, other) {
            (Scope::Lan { v4, v6 }, Scope::Lan { v4: v4b, v6: v6b }) => Scope::Lan { v4: *v4 || *v4b, v6: *v6 || *v6b },
            (Scope::Destinations(a), Scope::Destinations(b)) => {
                let mut all = a.clone();
                all.extend(b.iter().filter(|r| !a.contains(r)));
                Scope::Destinations(all).bounded()
            }
            (Scope::Lan { v6, .. }, Scope::Destinations(_)) | (Scope::Destinations(_), Scope::Lan { v6, .. }) => Scope::Lan { v4: true, v6: *v6 },
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Scope::Lan { v4: true, v6: true } => "LAN IPv4 and IPv6".into(),
            Scope::Lan { v4: true, .. } => "LAN IPv4".into(),
            Scope::Lan { v6: true, .. } => "LAN IPv6".into(),
            Scope::Lan { .. } => "nothing".into(),
            Scope::Destinations(ranges) => format!("LAN IPv4 to {} range(s)", ranges.len()),
        }
    }
}

/// What one `conntrack -D` did.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Found {
    Deleted(u64),
    /// The tool's own count of zero: evidence that nothing matched.
    NoMatch,
    Failed(String),
}

/// Reads conntrack-tools 1.4.8's exit code and standard error.
fn classify(code: i32, report: &str) -> Found {
    let last = report.lines().map(str::trim).filter(|l| !l.is_empty()).last().unwrap_or("");
    let count = last
        .strip_suffix(" flow entries have been deleted.")
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|n| n.parse::<u64>().ok());
    let failed = report.lines().any(|l| l.contains("Operation failed") || l.contains("Can't open handler"));
    match (code, count) {
        _ if failed => Found::Failed(short(last)),
        (0, Some(n)) if n > 0 => Found::Deleted(n),
        (0 | 1, Some(0)) => Found::NoMatch,
        (code, _) => Found::Failed(if last.is_empty() { format!("conntrack exited {code} without a result") } else { short(last) }),
    }
}

/// One line of the tool's report, without its prefix or control characters, bounded.
fn short(line: &str) -> String {
    let line = line.split("(conntrack-tools): ").last().unwrap_or(line);
    line.chars().filter(|c| !c.is_control()).take(120).collect()
}

/// What a reset did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub scope: Scope,
    /// Settled by a deletion that started after this path changed and
    /// covered it; nothing ran for this request.
    pub merged: bool,
    /// Entries the tool reported deleted (0 with `merged` false: it found
    /// none, with evidence).
    pub deleted: u64,
}

impl Report {
    /// For the console: the outcome a page shows.
    pub fn json(&self) -> Value {
        let result = if self.merged {
            "merged"
        } else if self.deleted > 0 {
            "reset"
        } else {
            "none"
        };
        json!({"result": result, "deleted": self.deleted, "scope": self.scope.describe()})
    }
}

/// A failed reset for the console (`Report::json`'s counterpart).
pub fn failed_json(error: &str) -> Value {
    json!({"result": "failed", "error": error})
}

/// A deletion that succeeded for its whole scope, and when it started.
struct Done {
    started: Instant,
    scope: Scope,
}

struct Pending {
    reason: &'static str,
    scope: Scope,
    changed: Instant,
}

struct State {
    last: Option<Done>,
    /// A request whose deletion failed: tried again by `retry`.
    pending: Option<Pending>,
}

static STATE: Mutex<State> = Mutex::new(State { last: None, pending: None });
// Resets take STATE then RESULTS; readers take only RESULTS, never STATE.
static RESULTS: Mutex<VecDeque<Value>> = Mutex::new(VecDeque::new());
/// Results kept for the status pages.
const HISTORY: usize = 8;

/// Deletes the conntrack entries of `scope`, whose path changed at `changed`
/// (an earlier deletion that started at or after it settles the request;
/// `reason` goes to the log and the history).
pub fn reset_since(reason: &'static str, scope: Scope, changed: Instant) -> Result<Report, String> {
    reset_with(reason, scope, changed, &mut Device)
}

/// Tries a failed request again; `None` when nothing is pending.
pub fn retry() -> Option<Result<Report, String>> {
    retry_with(&mut Device)
}

/// The latest results, newest first (time since boot, reason, scope, outcome).
pub fn history() -> Value {
    Value::Array(RESULTS.lock().unwrap_or_else(PoisonError::into_inner).iter().rev().cloned().collect())
}

fn lock() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
pub(crate) fn while_reset_locked(check: impl FnOnce()) {
    let _serial = tests::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let _reset = lock();
    check();
}

trait Tables {
    fn lan_v4(&mut self) -> Result<Ipv4Net, String>;
    fn lan_v6(&mut self) -> Result<Vec<String>, String>;
    fn delete(&mut self, family: &str, filter: &[&str]) -> Found;
}

struct Device;

impl Tables for Device {
    fn lan_v4(&mut self) -> Result<Ipv4Net, String> {
        let ip: Ipv4Addr = crate::ubus::uci_get("network.lan.ipaddr")?.parse().map_err(|_| "Invalid LAN address")?;
        let mask: Ipv4Addr = crate::ubus::uci_get("network.lan.netmask")?.parse().map_err(|_| "Invalid LAN mask")?;
        Ipv4Net::with_netmask(ip, mask).map(|net| net.trunc()).map_err(|_| "Invalid LAN mask".into())
    }

    fn lan_v6(&mut self) -> Result<Vec<String>, String> {
        let mut command = Command::new("ip");
        command.args(["-j", "-6", "addr", "show", "dev", "br-lan"]);
        Ok(lan_prefixes(&super::exec::run(command, Duration::from_secs(8))?))
    }

    fn delete(&mut self, family: &str, filter: &[&str]) -> Found {
        let mut command = Command::new("conntrack");
        command.args(["-D", "-f", family]).args(filter);
        match super::exec::run_report(command, Duration::from_secs(8)) {
            Ok((code, report)) => classify(code, &report),
            Err(error) => Found::Failed(error),
        }
    }
}

/// The global and ULA prefixes on the LAN bridge (`ip -j -6 addr`).
fn lan_prefixes(text: &str) -> Vec<String> {
    let links: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
    let mut prefixes: Vec<String> = links
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|link| link["addr_info"].as_array().into_iter().flatten())
        .filter(|addr| addr["family"] == "inet6" && addr["scope"] == "global")
        .filter_map(|addr| {
            let net: ipnet::Ipv6Net = format!("{}/{}", addr["local"].as_str()?, addr["prefixlen"].as_u64()?).parse().ok()?;
            Some(net.trunc().to_string())
        })
        .collect();
    prefixes.sort();
    prefixes.dedup();
    prefixes
}

fn record(reason: &str, scope: &Scope, outcome: &str) {
    let mut history = RESULTS.lock().unwrap_or_else(PoisonError::into_inner);
    if history.len() == HISTORY {
        history.pop_front();
    }
    history.push_back(json!({"at": super::uptime(), "reason": reason, "scope": scope.describe(), "outcome": outcome}));
}

fn reset_with(reason: &'static str, scope: Scope, changed: Instant, tables: &mut impl Tables) -> Result<Report, String> {
    let scope = scope.bounded();
    if scope.empty() {
        return Ok(Report { scope, merged: false, deleted: 0 });
    }
    let mut state = lock();
    if state.last.as_ref().is_some_and(|done| done.started >= changed && done.scope.covers(&scope)) {
        crate::netlog!("[net] conntrack reset for {reason} settled by one that started after the change");
        record(reason, &scope, "merged");
        return Ok(Report { scope, merged: true, deleted: 0 });
    }
    // A pending failed request joins this one: one deletion settles both.
    let (scope, changed) = match state.pending.take() {
        Some(pending) => (pending.scope.union(&scope), pending.changed.min(changed)),
        None => (scope, changed),
    };
    run(&mut state, reason, scope, changed, tables)
}

fn retry_with(tables: &mut impl Tables) -> Option<Result<Report, String>> {
    let mut state = lock();
    let pending = state.pending.take()?;
    Some(run(&mut state, pending.reason, pending.scope, pending.changed, tables))
}

/// Runs the deletion for `scope`; the state lock orders resets.
fn run(state: &mut State, reason: &'static str, scope: Scope, changed: Instant, tables: &mut impl Tables) -> Result<Report, String> {
    let started = Instant::now();
    let mut deleted = 0;
    let mut failures = Vec::new();
    let mut commands: Vec<(&str, Vec<String>)> = Vec::new();
    let prepared: Result<(), String> = (|| {
        match &scope {
            Scope::Lan { v4, v6 } => {
                if *v4 {
                    commands.push(("ipv4", vec!["-s".into(), tables.lan_v4()?.to_string()]));
                }
                if *v6 {
                    for prefix in tables.lan_v6()? {
                        commands.push(("ipv6", vec!["-s".into(), prefix]));
                    }
                }
            }
            Scope::Destinations(ranges) => {
                let lan = tables.lan_v4()?.to_string();
                for range in ranges {
                    commands.push(("ipv4", vec!["-s".into(), lan.clone(), "-d".into(), range.to_string()]));
                }
            }
        }
        Ok(())
    })();
    if let Err(why) = prepared {
        failures.push(why);
    }
    for (family, filter) in &commands {
        let filter: Vec<&str> = filter.iter().map(String::as_str).collect();
        match tables.delete(family, &filter) {
            Found::Deleted(n) => deleted += n,
            Found::NoMatch => {}
            Found::Failed(why) => failures.push(why),
        }
    }
    if failures.is_empty() {
        crate::netlog!("[net] conntrack reset {} for {reason}: {deleted} deleted", scope.describe());
        record(reason, &scope, &format!("{deleted} deleted"));
        state.last = Some(Done { started, scope: scope.clone() });
        return Ok(Report { scope, merged: false, deleted });
    }
    let error = format!("{deleted} deleted, then failed: {}", failures.join("; "));
    crate::netlog!("[net] conntrack reset {} for {reason}: {error}; will retry", scope.describe());
    record(reason, &scope, &format!("failed ({error})"));
    state.pending = Some(Pending { reason, scope, changed });
    Err(format!("Existing connections were not all reset ({error}); retrying"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        deleted: Vec<String>,
        /// Answers in order; `Deleted(1)` after they run out.
        answers: VecDeque<Found>,
    }

    impl Tables for Fake {
        fn lan_v4(&mut self) -> Result<Ipv4Net, String> {
            Ok("192.168.0.0/24".parse().unwrap())
        }
        fn lan_v6(&mut self) -> Result<Vec<String>, String> {
            Ok(vec!["fd00:1::/64".into()])
        }
        fn delete(&mut self, family: &str, filter: &[&str]) -> Found {
            self.deleted.push(format!("{family} {}", filter.join(" ")));
            self.answers.pop_front().unwrap_or(Found::Deleted(1))
        }
    }

    /// The tests share `STATE`.
    pub(super) static SERIAL: Mutex<()> = Mutex::new(());

    fn fresh() -> std::sync::MutexGuard<'static, ()> {
        let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        *lock() = State { last: None, pending: None };
        RESULTS.lock().unwrap_or_else(PoisonError::into_inner).clear();
        serial
    }

    fn ranges(n: usize) -> Vec<Ipv4Net> {
        (0..n).map(|i| format!("10.{}.0.0/16", i % 256).parse().unwrap()).collect()
    }

    /// conntrack-tools 1.4.8, `conntrack -D -f ipv4 -s 192.168.0.0/24`.
    const DELETED: &str = "conntrack v1.4.8 (conntrack-tools): 37 flow entries have been deleted.";
    const NONE: &str = "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.";
    const FAILED: &str = "conntrack v1.4.8 (conntrack-tools): Operation failed: such conntrack doesn't exist";

    #[test]
    fn the_same_exit_code_is_a_zero_match_or_a_failure_by_the_tools_report() {
        assert_eq!(classify(0, DELETED), Found::Deleted(37));
        assert_eq!(classify(1, NONE), Found::NoMatch, "exit 1 with the tool's count of zero");
        assert_eq!(classify(1, FAILED), Found::Failed("Operation failed: such conntrack doesn't exist".into()), "exit 1 too, but no count");
        assert!(matches!(classify(1, ""), Found::Failed(_)), "no report is no evidence");
        assert!(matches!(classify(2, "conntrack v1.4.8 (conntrack-tools): Bad parameter `x'"), Found::Failed(_)));
        assert!(matches!(classify(1, "conntrack v1.4.8 (conntrack-tools): Can't open handler"), Found::Failed(_)));
        assert!(matches!(classify(0, &format!("{FAILED}\n{DELETED}")), Found::Failed(_)), "a failure anywhere is a failure");
        assert!(matches!(classify(1, "conntrack v1.4.8 (conntrack-tools): 5 flow entries have been deleted."), Found::Failed(_)), "a count with a failing exit is not a success");
    }

    #[test]
    fn destinations_reset_only_lan_connections_to_them_and_too_many_reset_the_lan() {
        let _serial = fresh();
        let mut fake = Fake::default();
        let done = reset_with("test", Scope::Destinations(ranges(2)), Instant::now(), &mut fake).unwrap();
        assert_eq!((done.merged, done.deleted), (false, 2));
        assert_eq!(fake.deleted, ["ipv4 -s 192.168.0.0/24 -d 10.0.0.0/16", "ipv4 -s 192.168.0.0/24 -d 10.1.0.0/16"]);
        let mut fake = Fake::default();
        let done = reset_with("test", Scope::Destinations(ranges(65)), Instant::now(), &mut fake).unwrap();
        assert_eq!(done.scope, Scope::Lan { v4: true, v6: false });
        assert_eq!(fake.deleted, ["ipv4 -s 192.168.0.0/24"]);
        let mut fake = Fake::default();
        let none = reset_with("test", Scope::Destinations(Vec::new()), Instant::now(), &mut fake).unwrap();
        assert!(!none.merged && none.deleted == 0 && fake.deleted.is_empty());
    }

    #[test]
    fn only_a_deletion_that_started_after_the_change_settles_a_request() {
        let _serial = fresh();
        let mut fake = Fake::default();
        let before = Instant::now();
        assert_eq!(reset_with("a", Scope::Lan { v4: true, v6: true }, Instant::now(), &mut fake).unwrap().deleted, 2);
        assert!(reset_with("b", Scope::Lan { v4: true, v6: false }, before, &mut fake).unwrap().merged, "changed before that deletion started");
        assert!(reset_with("c", Scope::Destinations(ranges(1)), before, &mut fake).unwrap().merged);
        assert_eq!(fake.deleted, ["ipv4 -s 192.168.0.0/24", "ipv6 -s fd00:1::/64"]);
        std::thread::sleep(Duration::from_millis(2));
        let later = Instant::now();
        assert!(!reset_with("d", Scope::Lan { v4: true, v6: false }, later, &mut fake).unwrap().merged, "changed after it started: flows may have taken the old path since");
        assert!(!Scope::Destinations(ranges(1)).covers(&Scope::Lan { v4: true, v6: false }));
        assert!(Scope::Destinations(vec!["10.0.0.0/8".parse().unwrap()]).covers(&Scope::Destinations(ranges(1))));
    }

    #[test]
    fn a_failure_is_not_reported_as_a_reset_and_stays_pending_until_retried() {
        let _serial = fresh();
        let mut fake = Fake { answers: [Found::Deleted(3), Found::Failed("Operation failed: x".into())].into(), ..Fake::default() };
        let changed = Instant::now();
        let error = reset_with("ipa", Scope::Lan { v4: true, v6: true }, changed, &mut fake).unwrap_err();
        assert!(error.contains("3 deleted") && error.contains("Operation failed"), "{error}");
        assert!(lock().pending.is_some() && lock().last.is_none(), "a partial deletion settles nothing");
        assert!(reset_with("later", Scope::Lan { v4: true, v6: false }, changed, &mut fake).is_ok(), "a later request carries the pending scope");
        assert_eq!(fake.deleted.last().unwrap(), "ipv6 -s fd00:1::/64", "the failed IPv6 part ran again");
        assert!(lock().pending.is_none());
        assert!(retry_with(&mut fake).is_none(), "nothing pending");
        let mut failing = Fake { answers: [Found::Failed("timed out".into())].into(), ..Fake::default() };
        assert!(reset_with("mihomo", Scope::Lan { v4: true, v6: false }, Instant::now(), &mut failing).is_err());
        let retried = retry_with(&mut failing).unwrap().unwrap();
        assert_eq!((retried.merged, retried.deleted), (false, 1));
        let outcomes: Vec<String> = history().as_array().unwrap().iter().map(|h| h["outcome"].as_str().unwrap().to_owned()).collect();
        assert!(outcomes[0] == "1 deleted" && outcomes[1].starts_with("failed"), "{outcomes:?}");
    }

    #[test]
    fn a_zero_match_is_evidence_and_reported_as_none() {
        let _serial = fresh();
        let mut fake = Fake { answers: [Found::NoMatch].into(), ..Fake::default() };
        let report = reset_with("t", Scope::Lan { v4: true, v6: false }, Instant::now(), &mut fake).unwrap();
        assert_eq!(report.json()["result"], "none");
        assert_eq!(Report { scope: Scope::Lan { v4: true, v6: false }, merged: false, deleted: 4 }.json()["result"], "reset");
        assert_eq!(failed_json("x")["result"], "failed");
    }

    #[test]
    fn only_global_lan_prefixes_are_reset() {
        let text = r#"[{"ifname":"br-lan","addr_info":[{"family":"inet6","local":"fd1b:f7f5:d006::1","prefixlen":64,"scope":"global"},{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"},{"family":"inet6","local":"2409:8a3c::5","prefixlen":64,"scope":"global"}]}]"#;
        assert_eq!(lan_prefixes(text), ["2409:8a3c::/64", "fd1b:f7f5:d006::/64"]);
        assert!(lan_prefixes("not json").is_empty());
    }

    #[test]
    fn history_and_relay_status_do_not_wait_for_a_reset_or_tick() {
        let relay = std::sync::Arc::new(crate::wifi_relay::WifiRelay::new(std::sync::Arc::new(Mutex::new(()))));
        let (send, receive) = std::sync::mpsc::channel();
        while_reset_locked(|| {
            let worker = std::thread::spawn(move || send.send((history(), relay.status())).unwrap());
            let result = receive.recv_timeout(Duration::from_millis(200));
            assert!(result.is_ok(), "a reset must not block either memory snapshot");
            worker.join().unwrap();
        });
    }
}
