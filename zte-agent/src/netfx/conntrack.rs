//! The only writer of conntrack (`relay-mihomo-architecture.md` section
//! 4.5). Deletion evicts software conntrack state. On B31 an active
//! IPA NAT entry stayed enabled for over 12 s (454 MB) after deletion.
//! A successful delete is not evidence of hardware eviction.
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
use std::sync::{Mutex, MutexGuard, PoisonError};
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
    /// Connections carrying a specific conntrack mark/mask (e.g. Tailscale origin).
    Mark { mark: u32, mask: u32, v4: bool, v6: bool },
}

impl Scope {
    fn covers(&self, other: &Scope) -> bool {
        match (self, other) {
            (Scope::Lan { v4, v6 }, Scope::Lan { v4: v4b, v6: v6b }) => (*v4 || !v4b) && (*v6 || !v6b),
            (Scope::Lan { v4, .. }, Scope::Destinations(_)) => *v4,
            (Scope::Destinations(have), Scope::Destinations(want)) => want.iter().all(|w| have.iter().any(|h| h.contains(w))),
            (Scope::Mark { mark, mask, v4, v6 }, Scope::Mark { mark: mb, mask: maskb, v4: v4b, v6: v6b }) => {
                *mark == *mb && *mask == *maskb && (*v4 || !v4b) && (*v6 || !v6b)
            }
            _ => false,
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
            Scope::Lan { v4, v6 } | Scope::Mark { v4, v6, .. } => !v4 && !v6,
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
            (Scope::Mark { mark, mask, v4, v6 }, Scope::Mark { mark: mb, mask: maskb, v4: v4b, v6: v6b }) if mark == mb && mask == maskb => {
                Scope::Mark { mark: *mark, mask: *mask, v4: *v4 || *v4b, v6: *v6 || *v6b }
            }
            _ => other.clone(),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Scope::Lan { v4: true, v6: true } => "LAN IPv4 and IPv6".into(),
            Scope::Lan { v4: true, .. } => "LAN IPv4".into(),
            Scope::Lan { v6: true, .. } => "LAN IPv6".into(),
            Scope::Lan { .. } | Scope::Mark { v4: false, v6: false, .. } => "nothing".into(),
            Scope::Destinations(ranges) => format!("LAN IPv4 to {} range(s)", ranges.len()),
            Scope::Mark { mark, mask, v4: true, v6: true } => format!("mark 0x{mark:x}/0x{mask:x} IPv4 and IPv6"),
            Scope::Mark { mark, mask, v4: true, .. } => format!("mark 0x{mark:x}/0x{mask:x} IPv4"),
            Scope::Mark { mark, mask, v6: true, .. } => format!("mark 0x{mark:x}/0x{mask:x} IPv6"),
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
        json!({"result": result, "deleted": self.deleted, "scope": self.scope.describe(), "hardware_eviction_confirmed": false})
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

struct PendingMark {
    reason: &'static str,
    mark: u32,
    mask: u32,
    v4: bool,
    v6: bool,
}

struct State {
    last: Option<Done>,
    /// A request whose deletion failed: tried again by `retry`.
    pending: Option<Pending>,
    /// A marked-conntrack reset whose deletion failed: retried independently
    /// of LAN coalescing batches until every failed family succeeds.
    pending_mark: Option<PendingMark>,
    /// Start instant of the latest completed IPv4 marked-conntrack deletion
    /// (`(mark, mask, started)`), recorded before `conntrack -D` runs so callers
    /// can order completions against table retirements even when another
    /// subsystem drives the retry.
    mark_v4_completed_at: Option<(u32, u32, Instant)>,
}

/// Results kept for the status pages.
const HISTORY: usize = 8;

struct Batch {
    scope: Scope,
    latest: Instant,
    replies: Vec<std::sync::mpsc::SyncSender<Result<Report, String>>>,
}

struct Tracker {
    collect: Mutex<Option<Batch>>,
    state: Mutex<State>,
    // Resets take state then results; readers take only results, never state.
    results: Mutex<VecDeque<Value>>,
}

static TRACKER: Tracker = Tracker::new();

/// Deletes the conntrack entries of `scope`, whose path changed at `changed`
/// (an earlier deletion that started at or after it settles the request;
/// `reason` goes to the log and the history).
pub fn reset_since(reason: &'static str, scope: Scope, changed: Instant) -> Result<Report, String> {
    TRACKER.coalesce(
        reason, scope, changed, &mut Device,
        || std::thread::sleep(Duration::from_millis(200)),
        #[cfg(test)]
        || {},
    )
}

/// Deletes conntrack entries carrying `mark/mask` directly under the tracker lock
/// without mixing them into LAN coalescing batches or overwriting LAN retry state.
pub fn reset_mark(reason: &'static str, mark: u32, mask: u32, v4: bool, v6: bool) -> Result<Report, String> {
    TRACKER.reset_mark_with(reason, mark, mask, v4, v6, &mut Device)
}

/// Reports which families (`(v4, v6)`) are still pending a retry for `mark/mask`.
pub fn pending_mark_families(mark: u32, mask: u32) -> (bool, bool) {
    TRACKER.pending_mark_families(mark, mask)
}

/// Start instant of the latest completed IPv4 marked-conntrack deletion for
/// `mark/mask`, so callers (e.g. Mihomo) can order completions performed by
/// other subsystems (e.g. Wi-Fi relay) against table changes.
pub fn mark_v4_completed_at(mark: u32, mask: u32) -> Option<Instant> {
    TRACKER.mark_v4_completed_at(mark, mask)
}

/// Flushes loopback IPv4 UDP/TCP conntrack entries targeting Clean DNS
/// (`127.0.0.54:53`) after withdrawing `chain dns_out`, so reused UDP tuples
/// cannot keep hitting the old fallback DNAT mapping.
pub fn flush_clean_dns_dnat() -> Result<(), String> {
    TRACKER.flush_clean_dns_dnat_with(&mut Device)
}

/// Tries a failed request again; `None` when nothing is pending.
pub fn retry() -> Option<Result<Report, String>> {
    TRACKER.retry_with(&mut Device)
}

/// The latest results, newest first (time since boot, reason, scope, outcome).
pub fn history() -> Value {
    TRACKER.history()
}

#[cfg(test)]
pub(crate) fn while_reset_locked(check: impl FnOnce()) {
    let _reset = TRACKER.lock();
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

impl Tracker {
    const fn new() -> Self {
        Self {
            collect: Mutex::new(None),
            state: Mutex::new(State { last: None, pending: None, pending_mark: None, mark_v4_completed_at: None }),
            results: Mutex::new(VecDeque::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn history(&self) -> Value {
        Value::Array(self.results.lock().unwrap_or_else(PoisonError::into_inner).iter().rev().cloned().collect())
    }

    fn coalesce(
        &self,
        reason: &'static str,
        scope: Scope,
        changed: Instant,
        tables: &mut impl Tables,
        window: impl FnOnce(),
        #[cfg(test)] registered: impl FnOnce(),
    ) -> Result<Report, String> {
        if scope.empty() { return Ok(Report { scope, merged: false, deleted: 0 }); }
        let mut open = self.collect.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(batch) = open.as_mut() {
            batch.scope = batch.scope.union(&scope);
            batch.latest = batch.latest.max(changed);
            let (reply, receive) = std::sync::mpsc::sync_channel(1);
            batch.replies.push(reply);
            drop(open);
            #[cfg(test)]
            registered();
            receive.recv().map_err(|_| "Conntrack batch interrupted")??;
            self.record(reason, &scope, "merged");
            return Ok(Report { scope, merged: true, deleted: 0 });
        }
        *open = Some(Batch { scope, latest: changed, replies: Vec::new() });
        drop(open);
        window();
        let batch = self.collect.lock().unwrap_or_else(PoisonError::into_inner).take().unwrap();
        let result = self.reset_with(reason, batch.scope, batch.latest, tables);
        for reply in batch.replies { let _ = reply.send(result.clone()); }
        result
    }

    fn record(&self, reason: &str, scope: &Scope, outcome: &str) {
        let mut history = self.results.lock().unwrap_or_else(PoisonError::into_inner);
        if history.len() == HISTORY {
            history.pop_front();
        }
        history.push_back(json!({"at": super::uptime(), "reason": reason, "scope": scope.describe(), "outcome": outcome}));
    }

    fn reset_with(&self, reason: &'static str, scope: Scope, changed: Instant, tables: &mut impl Tables) -> Result<Report, String> {
        let scope = scope.bounded();
        if scope.empty() {
            return Ok(Report { scope, merged: false, deleted: 0 });
        }
        let mut state = self.lock();
        if state.last.as_ref().is_some_and(|done| done.started >= changed && done.scope.covers(&scope)) {
            crate::netlog!("[net] conntrack reset for {reason} settled by one that started after the change");
            self.record(reason, &scope, "merged");
            return Ok(Report { scope, merged: true, deleted: 0 });
        }
        // A pending failed request joins this one: one deletion settles both.
        let (scope, changed) = match state.pending.take() {
            Some(pending) => (pending.scope.union(&scope), pending.changed.max(changed)),
            None => (scope, changed),
        };
        self.run(&mut state, reason, scope, changed, tables)
    }

    fn retry_with(&self, tables: &mut impl Tables) -> Option<Result<Report, String>> {
        let mut state = self.lock();
        let lan_result = state
            .pending
            .take()
            .map(|pending| self.run(&mut state, pending.reason, pending.scope, pending.changed, tables));
        let mark_result = state.pending_mark.take().map(|pm| {
            self.run_mark_locked(&mut state, pm.reason, pm.mark, pm.mask, pm.v4, pm.v6, tables)
        });
        match (lan_result, mark_result) {
            (Some(Err(e)), _) => Some(Err(e)),
            (_, Some(Err(e))) => Some(Err(e)),
            (Some(ok), _) => Some(ok),
            (None, Some(ok)) => Some(ok),
            (None, None) => None,
        }
    }

    fn pending_mark_families(&self, mark: u32, mask: u32) -> (bool, bool) {
        let state = self.lock();
        match state.pending_mark.as_ref() {
            Some(pm) if pm.mark == mark && pm.mask == mask => (pm.v4, pm.v6),
            _ => (false, false),
        }
    }

    fn mark_v4_completed_at(&self, mark: u32, mask: u32) -> Option<Instant> {
        self.lock()
            .mark_v4_completed_at
            .filter(|(m, k, _)| *m == mark && *k == mask)
            .map(|(_, _, started)| started)
    }

    fn flush_clean_dns_dnat_with(&self, tables: &mut impl Tables) -> Result<(), String> {
        let _state = self.lock();
        let port = super::ids::CLEAN_DNS_PORT.to_string();
        let mut failures = Vec::new();
        for proto in ["udp", "tcp"] {
            match tables.delete("ipv4", &["-d", super::ids::CLEAN_DNS_ADDR, "-p", proto, "--dport", &port]) {
                Found::Deleted(_) | Found::NoMatch => {}
                Found::Failed(why) => failures.push(format!("{proto}: {why}")),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    fn reset_mark_with(
        &self,
        reason: &'static str,
        mark: u32,
        mask: u32,
        v4: bool,
        v6: bool,
        tables: &mut impl Tables,
    ) -> Result<Report, String> {
        let mut state = self.lock();
        let (v4, v6) = match state.pending_mark.take() {
            Some(pm) if pm.mark == mark && pm.mask == mask => (v4 || pm.v4, v6 || pm.v6),
            Some(other) => {
                state.pending_mark = Some(other);
                (v4, v6)
            }
            None => (v4, v6),
        };
        self.run_mark_locked(&mut state, reason, mark, mask, v4, v6, tables)
    }

    fn run_mark_locked(
        &self,
        state: &mut State,
        reason: &'static str,
        mark: u32,
        mask: u32,
        v4: bool,
        v6: bool,
        tables: &mut impl Tables,
    ) -> Result<Report, String> {
        let scope = Scope::Mark { mark, mask, v4, v6 };
        if scope.empty() {
            return Ok(Report { scope, merged: false, deleted: 0 });
        }
        let started = Instant::now();
        let spec = format!("0x{mark:08x}/0x{mask:08x}");
        let mut deleted = 0;
        let mut failures = Vec::new();
        let mut failed_v4 = false;
        let mut failed_v6 = false;
        for (is_v4, enabled, family) in [(true, v4, "ipv4"), (false, v6, "ipv6")] {
            if !enabled {
                continue;
            }
            match tables.delete(family, &["-m", &spec]) {
                Found::Deleted(n) => deleted += n,
                Found::NoMatch => {}
                Found::Failed(why) => {
                    if is_v4 {
                        failed_v4 = true;
                    } else {
                        failed_v6 = true;
                    }
                    failures.push(why);
                }
            }
        }
        if v4 && !failed_v4 {
            state.mark_v4_completed_at = Some((mark, mask, started));
        }
        if failures.is_empty() {
            crate::netlog!("[net] conntrack reset {} for {reason}: {deleted} deleted", scope.describe());
            self.record(reason, &scope, &format!("{deleted} deleted"));
            return Ok(Report { scope, merged: false, deleted });
        }
        state.pending_mark = Some(match state.pending_mark.take() {
            Some(existing) if existing.mark == mark && existing.mask == mask => PendingMark {
                reason,
                mark,
                mask,
                v4: existing.v4 || failed_v4,
                v6: existing.v6 || failed_v6,
            },
            _ => PendingMark {
                reason,
                mark,
                mask,
                v4: failed_v4,
                v6: failed_v6,
            },
        });
        let error = format!("{deleted} deleted, then failed: {}", failures.join("; "));
        crate::netlog!("[net] conntrack reset {} for {reason}: {error}", scope.describe());
        self.record(reason, &scope, &format!("failed ({error})"));
        Err(format!("Existing connections were not all reset ({error})"))
    }

    /// Runs the deletion for `scope`; the state lock orders resets.
    fn run(&self, state: &mut State, reason: &'static str, scope: Scope, changed: Instant, tables: &mut impl Tables) -> Result<Report, String> {
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
                Scope::Mark { mark, mask, v4, v6 } => {
                    let spec = format!("0x{mark:08x}/0x{mask:08x}");
                    if *v4 {
                        commands.push(("ipv4", vec!["-m".into(), spec.clone()]));
                    }
                    if *v6 {
                        commands.push(("ipv6", vec!["-m".into(), spec]));
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
            self.record(reason, &scope, &format!("{deleted} deleted"));
            state.last = Some(Done { started, scope: scope.clone() });
            return Ok(Report { scope, merged: false, deleted });
        }
        let error = format!("{deleted} deleted, then failed: {}", failures.join("; "));
        crate::netlog!("[net] conntrack reset {} for {reason}: {error}; will retry", scope.describe());
        self.record(reason, &scope, &format!("failed ({error})"));
        state.pending = Some(Pending { reason, scope, changed });
        Err(format!("Existing connections were not all reset ({error}); retrying"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        deleted: Vec<String>,
        before_delete: Option<Box<dyn FnOnce() + Send>>,
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
            if let Some(before_delete) = self.before_delete.take() {
                before_delete();
            }
            self.deleted.push(format!("{family} {}", filter.join(" ")));
            self.answers.pop_front().unwrap_or(Found::Deleted(1))
        }
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
        let tracker = Tracker::new();
        let mut fake = Fake::default();
        let done = tracker.reset_with("test", Scope::Destinations(ranges(2)), Instant::now(), &mut fake).unwrap();
        assert_eq!((done.merged, done.deleted), (false, 2));
        assert_eq!(fake.deleted, ["ipv4 -s 192.168.0.0/24 -d 10.0.0.0/16", "ipv4 -s 192.168.0.0/24 -d 10.1.0.0/16"]);
        let mut fake = Fake::default();
        let done = tracker.reset_with("test", Scope::Destinations(ranges(65)), Instant::now(), &mut fake).unwrap();
        assert_eq!(done.scope, Scope::Lan { v4: true, v6: false });
        assert_eq!(fake.deleted, ["ipv4 -s 192.168.0.0/24"]);
        let mut fake = Fake::default();
        let none = tracker.reset_with("test", Scope::Destinations(Vec::new()), Instant::now(), &mut fake).unwrap();
        assert!(!none.merged && none.deleted == 0 && fake.deleted.is_empty());
    }

    #[test]
    fn requests_in_one_window_share_the_union_and_return_only_after_deletion() {
        use std::sync::mpsc::{channel, TryRecvError};

        const WAIT: Duration = Duration::from_secs(2);
        let tracker = &Tracker::new();
        std::thread::scope(|threads| {
            let (open, opened) = channel();
            let (close, closed) = channel();
            let (register, registered) = channel();
            let (delete, deleting) = channel();
            let (finish, finished) = channel();
            let (first_reply, first_result) = channel();
            let (second_reply, second_result) = channel();

            threads.spawn(move || {
                let mut tables = Fake {
                    before_delete: Some(Box::new(move || {
                        delete.send(()).unwrap();
                        finished.recv_timeout(WAIT).unwrap();
                    })),
                    ..Fake::default()
                };
                let report = tracker.coalesce(
                    "first", Scope::Lan { v4: true, v6: false }, Instant::now(), &mut tables,
                    || {
                        open.send(()).unwrap();
                        closed.recv_timeout(WAIT).unwrap();
                    },
                    || panic!("the first request must open the batch"),
                );
                first_reply.send((report, tables.deleted)).unwrap();
            });
            opened.recv_timeout(WAIT).unwrap();
            threads.spawn(move || {
                let mut tables = Fake::default();
                let report = tracker.coalesce(
                    "second", Scope::Lan { v4: false, v6: true }, Instant::now(), &mut tables,
                    || panic!("the second request must join the batch"),
                    || register.send(()).unwrap(),
                );
                second_reply.send((report, tables.deleted)).unwrap();
            });
            registered.recv_timeout(WAIT).unwrap();
            close.send(()).unwrap();
            deleting.recv_timeout(WAIT).unwrap();
            assert_eq!(first_result.try_recv(), Err(TryRecvError::Empty));
            assert_eq!(second_result.try_recv(), Err(TryRecvError::Empty));
            finish.send(()).unwrap();

            let (first, deleted) = first_result.recv_timeout(WAIT).unwrap();
            let (second, second_deleted) = second_result.recv_timeout(WAIT).unwrap();
            assert_eq!(first.unwrap(), Report { scope: Scope::Lan { v4: true, v6: true }, merged: false, deleted: 2 });
            assert_eq!(deleted, ["ipv4 -s 192.168.0.0/24", "ipv6 -s fd00:1::/64"]);
            assert_eq!(second.unwrap(), Report { scope: Scope::Lan { v4: false, v6: true }, merged: true, deleted: 0 });
            assert!(second_deleted.is_empty());
        });
    }

    #[test]
    fn only_a_deletion_that_started_after_the_change_settles_a_request() {
        let tracker = Tracker::new();
        let mut fake = Fake::default();
        let before = Instant::now();
        assert_eq!(tracker.reset_with("a", Scope::Lan { v4: true, v6: true }, Instant::now(), &mut fake).unwrap().deleted, 2);
        assert!(tracker.reset_with("b", Scope::Lan { v4: true, v6: false }, before, &mut fake).unwrap().merged, "changed before that deletion started");
        assert!(tracker.reset_with("c", Scope::Destinations(ranges(1)), before, &mut fake).unwrap().merged);
        assert_eq!(fake.deleted, ["ipv4 -s 192.168.0.0/24", "ipv6 -s fd00:1::/64"]);
        std::thread::sleep(Duration::from_millis(2));
        let later = Instant::now();
        assert!(!tracker.reset_with("d", Scope::Lan { v4: true, v6: false }, later, &mut fake).unwrap().merged, "changed after it started: flows may have taken the old path since");
        assert!(!Scope::Destinations(ranges(1)).covers(&Scope::Lan { v4: true, v6: false }));
        assert!(Scope::Destinations(vec!["10.0.0.0/8".parse().unwrap()]).covers(&Scope::Destinations(ranges(1))));
    }

    #[test]
    fn a_failure_is_not_reported_as_a_reset_and_stays_pending_until_retried() {
        let tracker = Tracker::new();
        let mut fake = Fake { answers: [Found::Deleted(3), Found::Failed("Operation failed: x".into())].into(), ..Fake::default() };
        let changed = Instant::now();
        let error = tracker.reset_with("ipa", Scope::Lan { v4: true, v6: true }, changed, &mut fake).unwrap_err();
        assert!(error.contains("3 deleted") && error.contains("Operation failed"), "{error}");
        assert!(tracker.lock().pending.is_some() && tracker.lock().last.is_none(), "a partial deletion settles nothing");
        assert!(tracker.reset_with("later", Scope::Lan { v4: true, v6: false }, changed, &mut fake).is_ok(), "a later request carries the pending scope");
        assert_eq!(fake.deleted.last().unwrap(), "ipv6 -s fd00:1::/64", "the failed IPv6 part ran again");
        assert!(tracker.lock().pending.is_none());
        assert!(tracker.retry_with(&mut fake).is_none(), "nothing pending");
        let mut failing = Fake { answers: [Found::Failed("timed out".into())].into(), ..Fake::default() };
        assert!(tracker.reset_with("mihomo", Scope::Lan { v4: true, v6: false }, Instant::now(), &mut failing).is_err());
        let retried = tracker.retry_with(&mut failing).unwrap().unwrap();
        assert_eq!((retried.merged, retried.deleted), (false, 1));
        let outcomes: Vec<String> = tracker.history().as_array().unwrap().iter().map(|h| h["outcome"].as_str().unwrap().to_owned()).collect();
        assert!(outcomes[0] == "1 deleted" && outcomes[1].starts_with("failed"), "{outcomes:?}");
    }

    #[test]
    fn a_zero_match_is_evidence_and_reported_as_none() {
        let tracker = Tracker::new();
        let mut fake = Fake { answers: [Found::NoMatch].into(), ..Fake::default() };
        let report = tracker.reset_with("t", Scope::Lan { v4: true, v6: false }, Instant::now(), &mut fake).unwrap();
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
        let relay = std::sync::Arc::new(crate::wifi_relay::WifiRelay::new(std::sync::Arc::new(crate::netfx::admission::Gate::new())));
        let (send, receive) = std::sync::mpsc::channel();
        while_reset_locked(|| {
            let worker = std::thread::spawn(move || send.send((history(), relay.status())).unwrap());
            let result = receive.recv_timeout(Duration::from_millis(200));
            assert!(result.is_ok(), "a reset must not block either memory snapshot");
            worker.join().unwrap();
        });
    }

    #[test]
    fn reset_mark_targets_only_matching_mark_without_touching_lan_pending() {
        let tracker = Tracker::new();
        let mut failing_lan = Fake { answers: [Found::Failed("busy".into())].into(), ..Fake::default() };
        assert!(tracker.reset_with("lan", Scope::Lan { v4: true, v6: false }, Instant::now(), &mut failing_lan).is_err());
        assert!(tracker.lock().pending.is_some());

        let mut fake = Fake { answers: [Found::Deleted(4), Found::NoMatch].into(), ..Fake::default() };
        let report = tracker
            .reset_mark_with("tailscale switch", 0x0200_0000, 0x0200_0000, true, true, &mut fake)
            .unwrap();
        assert_eq!(report.deleted, 4);
        assert_eq!(
            fake.deleted,
            [
                "ipv4 -m 0x02000000/0x02000000",
                "ipv6 -m 0x02000000/0x02000000",
            ]
        );
        assert!(tracker.lock().pending.is_some(), "LAN pending retry state stays intact");

        // A failed marked-conntrack family MUST remain pending and be retried
        // by `retry_with` until deletion succeeds.
        let mut partial_fail = Fake {
            answers: [Found::Deleted(2), Found::Failed("v6 busy".into())].into(),
            ..Fake::default()
        };
        assert!(tracker
            .reset_mark_with("tailscale retry test", 0x0200_0000, 0x0200_0000, true, true, &mut partial_fail)
            .is_err());
        {
            let state = tracker.lock();
            let pm = state.pending_mark.as_ref().expect("failed v6 family must remain pending");
            assert!(!pm.v4 && pm.v6, "only the failed family stays pending");
        }
        let mut recover = Fake {
            answers: [Found::NoMatch, Found::Deleted(3)].into(),
            ..Fake::default()
        };
        assert!(tracker.retry_with(&mut recover).unwrap().is_ok());
        assert!(tracker.lock().pending.is_none());
        assert!(tracker.lock().pending_mark.is_none());
        assert_eq!(tracker.pending_mark_families(0x0200_0000, 0x0200_0000), (false, false));
        let completed1 = tracker
            .mark_v4_completed_at(0x0200_0000, 0x0200_0000)
            .expect("completed IPv4 marked reset must record start instant");
        assert!(recover.deleted.iter().any(|cmd| cmd == "ipv6 -m 0x02000000/0x02000000"));
        assert!(
            !recover.deleted.iter().any(|cmd| cmd == "ipv4 -m 0x02000000/0x02000000"),
            "retry after v4-ok/v6-fail must NOT reset healthy IPv4 flows: {:?}",
            recover.deleted
        );

        // When IPv4 fails and another caller completes `retry_with`, the shared
        // `mark_v4_completed_at` advances to an instant >= the failure time.
        let mut fail_v4 = Fake { answers: [Found::Failed("v4 busy".into())].into(), ..Fake::default() };
        assert!(tracker
            .reset_mark_with("v4 fail", 0x0200_0000, 0x0200_0000, true, false, &mut fail_v4)
            .is_err());
        assert_eq!(tracker.mark_v4_completed_at(0x0200_0000, 0x0200_0000), Some(completed1));
        let retired_at = Instant::now();
        let mut other_caller_retry = Fake { answers: [Found::Deleted(1)].into(), ..Fake::default() };
        assert!(tracker.retry_with(&mut other_caller_retry).unwrap().is_ok());
        let completed2 = tracker
            .mark_v4_completed_at(0x0200_0000, 0x0200_0000)
            .unwrap();
        assert!(completed2 >= retired_at);

        // Flushing loopback Clean DNS NAT mappings deletes both UDP and TCP
        // entries targeting `127.0.0.54:53` and surfaces any deletion error.
        let mut flush_ok = Fake { answers: [Found::Deleted(1), Found::NoMatch].into(), ..Fake::default() };
        tracker.flush_clean_dns_dnat_with(&mut flush_ok).unwrap();
        assert_eq!(
            flush_ok.deleted,
            [
                "ipv4 -d 127.0.0.54 -p udp --dport 53",
                "ipv4 -d 127.0.0.54 -p tcp --dport 53",
            ]
        );
        let mut flush_err = Fake { answers: [Found::Failed("conntrack busy".into()), Found::NoMatch].into(), ..Fake::default() };
        assert!(tracker.flush_clean_dns_dnat_with(&mut flush_err).is_err());
    }
}
