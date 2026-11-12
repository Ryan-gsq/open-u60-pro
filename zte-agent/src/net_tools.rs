//! Private device effects shared by the optional network modules. No shell,
//! bounded commands, private atomic files and an on-disk rollback journal.

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub use crate::netfx::exec::{owned_child, owned_reader, run, run_input, stop_child};
pub use crate::netfx::files::{private_dir, write_private};

pub mod firewall;

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyRule {
    Missing,
    Owned,
    Foreign,
    /// Several rules use the priority; none can be attributed to us.
    Shared,
}

/// Errors are inspection failures only (the rule table could not be read).
pub fn plain_policy_rule(family: &str, priority: &str, table: &str) -> Result<PolicyRule, String> {
    let text = Cmd::new("ip", &["-j", family, "rule", "show"]).run()?;
    policy_rule_state(&text, priority, table)
}

fn policy_rule_state(text: &str, priority: &str, table: &str) -> Result<PolicyRule, String> {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(text).map_err(|_| "Cannot inspect policy rules")?;
    let priority: u64 = priority.parse().map_err(|_| "Invalid policy priority")?;
    let matches: Vec<_> = rows
        .iter()
        .filter(|r| r["priority"].as_u64() == Some(priority))
        .collect();
    if matches.is_empty() {
        return Ok(PolicyRule::Missing);
    }
    if matches.len() != 1 {
        return Ok(PolicyRule::Shared);
    }
    let rule = matches[0];
    let known = [
        "priority", "src", "dst", "from", "to", "table", "protocol", "flags", "action",
    ];
    let plain = rule
        .as_object()
        .is_some_and(|m| m.keys().all(|k| known.contains(&k.as_str())))
        && ["src", "dst", "from", "to"].iter().all(|k| {
            rule[*k].is_null() || matches!(rule[*k].as_str(), Some("all" | "0.0.0.0/0" | "::/0"))
        })
        && (rule["flags"].is_null() || rule["flags"].as_array().is_some_and(Vec::is_empty))
        && (rule["action"].is_null() || rule["action"] == "to_tbl")
        && (rule["table"] == table || rule["table"].as_u64() == table.parse().ok());
    Ok(if plain {
        PolicyRule::Owned
    } else {
        PolicyRule::Foreign
    })
}

/// Whether any `family` route uses `table`. An emptied table may not exist at
/// all: `ip route show table N` then fails (ENOENT) instead of listing nothing.
pub fn route_table_listed(family: &str, table: &str) -> Result<bool, String> {
    let all = Cmd::new("ip", &[family, "route", "show", "table", "all"]).run()?;
    Ok(lists_table(&all, table))
}

fn lists_table(routes: &str, table: &str) -> bool {
    routes.lines().any(|line| {
        line.split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|w| w == ["table", table])
    })
}

/// Route type and destination of an `ip <family> route <action> ...` command.
pub fn route_target(args: &[String]) -> (&str, &str) {
    let kind = args[3].as_str();
    if matches!(kind, "throw" | "local" | "unreachable") {
        (kind, args[4].as_str())
    } else {
        ("unicast", kind)
    }
}

pub type NetworkLock = Arc<Mutex<()>>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
}

impl Cmd {
    pub fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.into(),
            args: args.iter().map(|s| (*s).into()).collect(),
        }
    }

    pub fn command(&self) -> Command {
        let mut c = Command::new(&self.program);
        c.args(&self.args).stdin(Stdio::null());
        c
    }

    pub fn run(&self) -> Result<String, String> {
        if self.program == "@u60-relay-channel" {
            return crate::wifi_relay::hotspot::switch(&self.args).map(|_| String::new());
        }
        if self.program == "@u60-relay-ipv6-dad" {
            return crate::wifi_relay::ipv6::wait_addresses(&self.args).map(|_| String::new());
        }
        if self.program == "@u60-relay-ra" {
            return crate::wifi_relay::ipv6::ra_command(&self.args).map(|_| String::new());
        }
        if self.program == "@u60-relay-dns" {
            return crate::wifi_relay::dns::command(&self.args).map(|_| String::new());
        }
        if self.program == "@u60-relay-portal" {
            return crate::wifi_relay::portal::command(&self.args).map(|_| String::new());
        }
        if self.program == "@u60-relay-portal-return" {
            return crate::wifi_relay::portal::place_return(&self.args).map(|_| String::new());
        }
        if self.program == "@u60-sysctl" {
            return sysctl_command(&self.args).map(|_| String::new());
        }
        if self.program == "@u60-mihomo-nft" {
            return crate::mihomo::nft_command(&self.args).map(|_| String::new());
        }
        if self.program == "@u60-relay-steer" {
            return crate::wifi_relay::steering::command(&self.args).map(|_| String::new());
        }
        if self.program == "@u60-relay-power-save" {
            return crate::wifi_relay::power_save::command(&self.args).map(|_| String::new());
        }
        if self.program == "@u60-relay-nft" {
            return crate::wifi_relay::uplink::command(&self.args).map(|_| String::new());
        }
        if self.program == "@u60-relay-roam" {
            return match self.args.as_slice() {
                [mode] if matches!(mode.as_str(), "0" | "1") => {
                    crate::wifi_relay::restore_roam(mode).map(|_| String::new())
                }
                _ => Err("Invalid relay recovery mode".into()),
            };
        }
        if self.program == "@u60-relay-detach" {
            return if self.args.is_empty() {
                crate::wifi_relay::detach_station().map(|_| String::new())
            } else {
                Err("Invalid relay disconnect recovery".into())
            };
        }
        if self.program.starts_with('@') {
            return Err(format!("{UNKNOWN_STEP} {}", self.program));
        }
        let out = run(self.command(), Duration::from_secs(8))?;
        if self.program == "hostapd_cli"
            && self
                .args
                .iter()
                .any(|a| matches!(a.as_str(), "set" | "disable" | "enable"))
            && out.lines().last() != Some("OK")
        {
            return Err("Hostapd refused the runtime change".into());
        }
        if self.program == "wpa_cli"
            && self
                .args
                .iter()
                .any(|a| matches!(a.as_str(), "SETROAMMODE" | "reconfigure"))
            && out.lines().last() != Some("OK")
        {
            return Err("Wi-Fi control refused the runtime change".into());
        }
        Ok(out)
    }

    fn undo(&self) -> Result<(), String> {
        // Don't delete an externally replaced rule using a broad priority match.
        if self.program == "ip"
            && self.args.len() == 7
            && self.args[1..4] == ["rule", "del", "pref"]
            && self.args[5] == "lookup"
        {
            match plain_policy_rule(&self.args[0], &self.args[4], &self.args[6])? {
                PolicyRule::Owned => {}
                PolicyRule::Missing | PolicyRule::Foreign => return Ok(()),
                PolicyRule::Shared => {
                    return Err("Policy priority is shared; cleanup paused".into())
                }
            }
        }
        if crate::wifi_relay::hotspot::skip_undo(self) {
            return Ok(());
        }
        if crate::wifi_relay::power_save::is_restore(self) {
            if let Err(e) = self.run() {
                crate::netlog!("[relay] upstream Wi-Fi power save not restored: {e}");
            }
            return Ok(());
        }
        // Firewall steps: every copy of an owned rule, an owned chain emptied
        // first, and only a definite "not there" taken as already undone.
        if matches!(self.program.as_str(), "iptables" | "ip6tables") && self.args.iter().any(|a| a == "-D" || a == "-X") {
            return firewall::undo(self, &mut Device);
        }
        let error = match self.run() {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };
        // A journal from another agent version can hold an internal step this
        // build does not have. It cannot be undone here; stopping on it would
        // block every later cleanup (a removed step once kept the relay down).
        if error.starts_with(UNKNOWN_STEP) {
            crate::netlog!("[net] skipped an undo this agent version does not know: {} {}", self.program, self.args.join(" "));
            return Ok(());
        }
        // OFF during a channel switch/CAC makes that runtime snapshot obsolete.
        if crate::wifi_relay::hotspot::skip_undo(self) {
            return Ok(());
        }
        // A crash may have occurred after journaling but before applying a
        // step. Already-absent objects are successful, idempotent recovery.
        // The interface is the one the command names: an older agent's
        // journal names the station it used.
        if self.program == "iw" && matches!(self.args.as_slice(), [dev, name, ..] if dev == "dev" && !Path::new("/sys/class/net").join(name).exists()) {
            return Ok(());
        }
        if self.program == "ip" && self.args.get(2).map(String::as_str) == Some("del") {
            let family = self.args[0].as_str();
            let value = |name| {
                self.args
                    .windows(2)
                    .find(|a| a[0] == name)
                    .map(|a| a[1].as_str())
            };
            match self.args[1].as_str() {
                "rule" => {
                    let rules = Cmd::new("ip", &[family, "rule", "show"]).run()?;
                    if value("pref").is_some_and(|p| {
                        !rules
                            .lines()
                            .any(|l| l.trim_start().starts_with(&format!("{p}:")))
                    }) {
                        return Ok(());
                    }
                    if let (Some(oif), Some(table)) = (value("oif"), value("lookup")) {
                        if !has_oif_rule(&rules, oif, table) {
                            return Ok(());
                        }
                    }
                }
                "route" => {
                    if let Some(table) = value("table") {
                        let (kind, destination) = route_target(&self.args);
                        // The kernel removes a vanished interface's routes.
                        let device = value("dev");
                        if device.is_some_and(|d| !Path::new(&format!("/sys/class/net/{d}")).exists()) {
                            return Ok(());
                        }
                        let mut show = vec![family, "route", "show", "table", table, "type", kind, "exact", destination];
                        // A shared table (main) may hold another writer's route
                        // to the same destination through another interface.
                        if let Some(device) = device {
                            show.extend(["dev", device]);
                        }
                        if Cmd::new("ip", &show).run().is_ok_and(|s| s.is_empty()) {
                            return Ok(());
                        }
                        if !route_table_listed(family, table)? {
                            return Ok(());
                        }
                    }
                }
                "addr" => {
                    if let Some(iface) = value("dev") {
                        if !Path::new(&format!("/sys/class/net/{iface}")).exists() {
                            return Ok(());
                        }
                        let address = &self.args[3];
                        let all =
                            Cmd::new("ip", &["-o", family, "addr", "show", "dev", iface]).run()?;
                        if !all.split_whitespace().any(|s| s == address) {
                            return Ok(());
                        }
                    }
                }
                _ => {}
            }
        }
        Err(if self.program.starts_with("@u60-relay-") {
            error
        } else {
            "Cannot restore an owned network change".into()
        })
    }

    /// Whether this applied change can be re-checked and re-applied as is
    /// (`Transaction::reconcile`). Radio, daemon and journal-only steps cannot.
    pub(crate) fn checkable(&self) -> bool {
        match self.program.as_str() {
            "iptables" | "ip6tables" => self.args.iter().any(|a| matches!(a.as_str(), "-N" | "-I" | "-A")),
            "ip" => self.args.get(2).map(String::as_str) == Some("add"),
            "@u60-sysctl" | "@u60-mihomo-nft" | "@u60-relay-steer" | "@u60-relay-power-save" | "@u60-relay-portal-return" => true,
            _ => false,
        }
    }

    /// Whether the effect of this (applied) command is still in place, read
    /// on its own (`adopt`).
    fn present(&self) -> Result<bool, String> {
        self.present_in(&mut Listings::default(), &mut Device)
    }

    /// `present`, judged against the listings of the current check: one per
    /// tool and table, one per kind of `ip` object and family. An error is
    /// "could not check" (a listing or the tool failed), never "absent":
    /// re-adding a rule that is there adds a second copy.
    fn present_in(&self, listings: &mut Listings, probe: &mut impl Probe) -> Result<bool, String> {
        let value = |name: &str| self.args.windows(2).find(|w| w[0] == name).map(|w| w[1].as_str());
        match self.program.as_str() {
            "iptables" | "ip6tables" => {
                let Some(at) = self.args.iter().position(|a| matches!(a.as_str(), "-N" | "-I" | "-A")) else { return Ok(true) };
                let Some(chain) = self.args.get(at + 1) else { return Ok(true) };
                let Some(listing) = listing_for(self) else { return Ok(true) };
                let tables = listings.get(listing, probe)?;
                if self.args[at] == "-N" {
                    // Re-adding a chain that exists fails; it never doubles.
                    return Ok(firewall::has_chain(tables, chain));
                }
                if firewall::listed_rule(self).is_some_and(|line| tables.lines().any(|l| l == line)) {
                    return Ok(true);
                }
                if !firewall::has_chain(tables, chain) {
                    return Ok(false);
                }
                // Not listed as predicted: only the tool's own check is a
                // definite answer either way.
                let mut check = self.clone();
                if check.args[at] == "-I" && check.args.get(at + 2).is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit())) {
                    check.args.remove(at + 2);
                }
                check.args[at] = "-C".into();
                let status = probe.status(&check)?;
                if status.0 == 0 {
                    unpredicted(self);
                    Ok(true)
                } else if firewall::no_rule(&status) {
                    Ok(false)
                } else {
                    Err(format!("the check exited {}", status.0))
                }
            }
            "ip" => {
                let Some(listing) = listing_for(self) else { return Ok(true) };
                let text = listings.get(listing, probe)?;
                match self.args[1].as_str() {
                    "rule" => {
                        let Some(pref) = value("pref") else { return Ok(true) };
                        Ok(text.lines().any(|l| l.trim_start().starts_with(&format!("{pref}:"))))
                    }
                    "route" => Ok(route_listed(text, &self.args)),
                    "addr" => {
                        let Some(device) = value("dev") else { return Ok(true) };
                        Ok(addr_listed(text, device, &self.args[3]))
                    }
                    _ => Ok(true),
                }
            }
            "@u60-sysctl" => Ok(match self.args.as_slice() {
                [key, wanted] => sysctl_path(key).and_then(|p| fs::read_to_string(p).ok()).is_some_and(|v| v.trim() == wanted),
                _ => true,
            }),
            "@u60-mihomo-nft" => crate::mihomo::nft_present(&self.args),
            "@u60-relay-steer" => Ok(crate::wifi_relay::steering::present(&self.args)),
            "@u60-relay-power-save" => crate::wifi_relay::power_save::present(&self.args),
            "@u60-relay-portal-return" => {
                let listing = listing_for(self).ok_or("Invalid relay portal bypass")?;
                Ok(crate::wifi_relay::portal::return_first(listings.get(listing, probe)?))
            }
            _ => Ok(true),
        }
    }
}

const UNKNOWN_STEP: &str = "Unknown agent step";

/// Logs, once per rule, an owned rule `iptables -S` lists in a form
/// `firewall::listed_rule` does not predict: each check of it then costs a
/// `-C` of its own.
fn unpredicted(cmd: &Cmd) {
    static SEEN: std::sync::Mutex<Vec<Cmd>> = std::sync::Mutex::new(Vec::new());
    let mut seen = SEEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if !seen.contains(cmd) {
        seen.push(cmd.clone());
        crate::netlog!("[net] listed in a form not predicted, checked with -C: {} {}", cmd.program, cmd.args.join(" "));
    }
}

/// The listing a step is checked against: the whole table (`-S`) for a
/// firewall step, all routes (`table all`), rules or addresses of the
/// family for an `ip` one.
fn listing_for(cmd: &Cmd) -> Option<Cmd> {
    match cmd.program.as_str() {
        "iptables" | "ip6tables" => {
            let table = cmd.args.windows(2).find(|w| w[0] == "-t").map_or("filter", |w| w[1].as_str());
            Some(Cmd::new(&cmd.program, &["-w", "2", "-t", table, "-S"]))
        }
        "@u60-relay-portal-return" => match cmd.args.as_slice() {
            [tool] if matches!(tool.as_str(), "iptables" | "ip6tables") => Some(Cmd::new(tool, &["-w", "2", "-t", "nat", "-S"])),
            _ => None,
        },
        "ip" => {
            let family = cmd.args.first()?.as_str();
            Some(match cmd.args.get(1)?.as_str() {
                "rule" => Cmd::new("ip", &[family, "rule", "show"]),
                "route" => Cmd::new("ip", &[family, "route", "show", "table", "all"]),
                "addr" => Cmd::new("ip", &["-o", family, "addr", "show"]),
                _ => return None,
            })
        }
        _ => None,
    }
}

/// Route types `ip route` prints before the destination (unicast has none).
const ROUTE_TYPES: [&str; 9] = ["local", "broadcast", "throw", "unreachable", "prohibit", "blackhole", "nat", "anycast", "multicast"];

/// Whether `ip <family> route show table all` lists the route an
/// `ip route add` step adds: same type, destination and table, and the same
/// device if the step names one (as `ip route show table T type K exact D
/// dev X` judged it). Main-table routes are listed without `table`.
fn route_listed(listing: &str, args: &[String]) -> bool {
    let value = |words: &[&str], name: &str| words.windows(2).find(|w| w[0] == name).map(|w| w[1].to_owned());
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let (kind, destination) = route_target(args);
    let destination = route_destination(destination);
    let table = route_table(&value(&words, "table").unwrap_or_else(|| "main".into()));
    let device = value(&words, "dev");
    listing.lines().any(|line| {
        let words: Vec<&str> = line.split_whitespace().collect();
        let (listed, rest) = match words.as_slice() {
            [first, rest @ ..] if ROUTE_TYPES.contains(first) => (*first, rest),
            words => ("unicast", words),
        };
        let Some((to, rest)) = rest.split_first() else { return false };
        listed == kind
            && route_destination(to) == destination
            && route_table(&value(rest, "table").unwrap_or_else(|| "main".into())) == table
            && device.as_ref().is_none_or(|d| value(rest, "dev").as_ref() == Some(d))
    })
}

/// A destination as `ip` compares it: `default` is the zero-length prefix,
/// a bare address a host route.
fn route_destination(text: &str) -> String {
    let (ip, length) = text.split_once('/').map_or((text, None), |(ip, l)| (ip, l.parse::<u8>().ok()));
    match ip.parse::<std::net::IpAddr>() {
        Ok(_) if length == Some(0) => "default".into(),
        Ok(ip) => format!("{ip}/{}", length.unwrap_or(if ip.is_ipv4() { 32 } else { 128 })),
        Err(_) => text.into(),
    }
}

fn route_table(name: &str) -> String {
    match name {
        "main" => "254".into(),
        "local" => "255".into(),
        "default" => "253".into(),
        _ => name.into(),
    }
}

/// Whether `ip -o <family> addr show` lists `address` on `device`.
fn addr_listed(listing: &str, device: &str, address: &str) -> bool {
    listing.lines().any(|line| {
        let mut words = line.split_whitespace();
        words.nth(1) == Some(device) && words.any(|w| w == address)
    })
}

/// What a check reads and re-applies through: the device, or a test's model.
pub(crate) trait Probe {
    /// A listing's text (standard output).
    fn list(&mut self, cmd: &Cmd) -> Result<String, String>;
    /// A firewall command's exit code and standard error (`firewall::no_rule`).
    fn status(&mut self, cmd: &Cmd) -> Result<(i32, String), String>;
    fn apply(&mut self, cmd: &Cmd) -> Result<(), String>;
}

pub(crate) struct Device;

impl Probe for Device {
    fn list(&mut self, cmd: &Cmd) -> Result<String, String> {
        cmd.run()
    }

    fn status(&mut self, cmd: &Cmd) -> Result<(i32, String), String> {
        crate::netfx::exec::run_report(cmd.command(), Duration::from_secs(8))
    }

    fn apply(&mut self, cmd: &Cmd) -> Result<(), String> {
        cmd.run().map(|_| ())
    }
}

/// The listings one check took (`Cmd::present_in`), each read once. A
/// failed listing stays failed for the check: every step it would have
/// answered is "could not check" and is tried again by the next one.
#[derive(Default)]
pub struct Listings {
    read: Vec<(Cmd, Result<String, String>)>,
}

impl Listings {
    fn get(&mut self, listing: Cmd, probe: &mut impl Probe) -> Result<&str, String> {
        let at = match self.read.iter().position(|(c, _)| *c == listing) {
            Some(at) => at,
            None => {
                let text = probe.list(&listing).map_err(|e| format!("{} {}: {e}", listing.program, listing.args.join(" ")));
                self.read.push((listing, text));
                self.read.len() - 1
            }
        };
        self.read[at].1.as_deref().map_err(Clone::clone)
    }

    /// After a change to what `cmd` is listed in: the next step reads again.
    fn forget(&mut self, cmd: &Cmd) {
        if let Some(listing) = listing_for(cmd) {
            self.read.retain(|(c, _)| *c != listing);
        }
    }
}

thread_local! {
    /// The listings of the check open on this thread (`Pass`).
    static PASS: RefCell<Option<Listings>> = const { RefCell::new(None) };
}

/// One guard check: while it lives, every `Transaction::reconcile` on this
/// thread reads each listing once and shares it (the relay checks four
/// transactions in a row). Each `reconcile` opens one for itself; an owner
/// that reconciles several opens one around them. Drop it when the check
/// ends: a vendor reload flushes `redirect_chain` and rewrites
/// `bridge-nf-call-*` within about 3 s, and two reloads can come 3.2 s
/// apart, so a listing must never answer a later check. A write through any
/// `Transaction` on this thread drops the listings read so far.
#[must_use]
pub struct Pass {
    opened: bool,
}

impl Pass {
    pub fn open() -> Self {
        let opened = PASS.with(|pass| {
            let mut pass = pass.borrow_mut();
            if pass.is_some() {
                return false;
            }
            *pass = Some(Listings::default());
            true
        });
        Self { opened }
    }
}

impl Drop for Pass {
    fn drop(&mut self) {
        if self.opened {
            PASS.with(|pass| pass.borrow_mut().take());
        }
    }
}

/// A `Transaction` changed the device: an open check reads again.
fn changed() {
    PASS.with(|pass| {
        if let Some(listings) = pass.borrow_mut().as_mut() {
            *listings = Listings::default();
        }
    });
}

/// `Transaction::reconcile_only` over `desired`: re-applies, in order, only
/// what is definitely gone.
fn reconcile_steps(desired: &[(Cmd, Cmd)], keep: impl Fn(&Cmd) -> bool, listings: &mut Listings, probe: &mut impl Probe) -> Reconciled {
    let mut result = Reconciled::default();
    for (apply, _) in desired.iter().filter(|(apply, _)| keep(apply)) {
        let line = format!("{} {}", apply.program, apply.args.join(" "));
        match apply.present_in(listings, probe) {
            Ok(true) => {}
            Ok(false) => {
                let applied = probe.apply(apply);
                listings.forget(apply);
                match applied {
                    Ok(()) => result.restored.push(line),
                    Err(e) => result.failed.push(format!("{line}: {e}")),
                }
            }
            // Left alone; the next check tries again.
            Err(e) => result.failed.push(format!("{line}: not checked: {e}")),
        }
    }
    result
}

/// Rules per chain in nft text: a definition (`netfx::effect::table`, its
/// blocks) or an `nft -t list table` listing (hook lines are not rules).
pub fn nft_chain_rules(text: &str) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    let mut current: Option<(String, usize)> = None;
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("chain ").and_then(|l| l.strip_suffix(" {")) {
            current = Some((name.to_owned(), 0));
        } else if line == "}" {
            if let Some((name, n)) = current.take() {
                counts.insert(name, n);
            }
        } else if let Some((_, n)) = current.as_mut() {
            if !line.is_empty() && !line.starts_with("type ") {
                *n += 1;
            }
        }
    }
    counts
}

/// Kernel settings an owner may change for its lifetime (`@u60-sysctl`).
fn sysctl_path(key: &str) -> Option<&'static str> {
    Some(match key {
        "tcp_pacing_ss_ratio" => "/proc/sys/net/ipv4/tcp_pacing_ss_ratio",
        "tcp_pacing_ca_ratio" => "/proc/sys/net/ipv4/tcp_pacing_ca_ratio",
        "bridge-nf-call-iptables" => "/proc/sys/net/bridge/bridge-nf-call-iptables",
        "bridge-nf-call-ip6tables" => "/proc/sys/net/bridge/bridge-nf-call-ip6tables",
        _ => return None,
    })
}

pub fn sysctl_read(key: &str) -> Result<String, String> {
    let path = sysctl_path(key).ok_or("Unknown kernel setting")?;
    Ok(fs::read_to_string(path).map_err(|_| "Cannot read a kernel setting")?.trim().to_owned())
}

/// The step that sets `key` to `value` and restores `old`.
pub fn sysctl_step(key: &str, value: &str, old: &str) -> Result<Step, String> {
    sysctl_path(key).ok_or("Unknown kernel setting")?;
    Ok(Step::new(Cmd::new("@u60-sysctl", &[key, value]), Cmd::new("@u60-sysctl", &[key, old])))
}

fn sysctl_command(args: &[String]) -> Result<(), String> {
    match args {
        [key, value] => sysctl_write(key, value),
        _ => Err("Invalid kernel setting".into()),
    }
}

/// Writes one of the kernel settings an owner may hold.
pub fn sysctl_write(key: &str, value: &str) -> Result<(), String> {
    if !value.parse::<u32>().is_ok_and(|v| v <= 100_000) {
        return Err("Invalid kernel setting".into());
    }
    let path = sysctl_path(key).ok_or("Unknown kernel setting")?;
    fs::write(path, value).map_err(|_| "Cannot set a kernel setting".into())
}

fn has_oif_rule(rules: &str, oif: &str, table: &str) -> bool {
    rules.lines().any(|line| {
        let words = line.split_whitespace().collect::<Vec<_>>();
        words.windows(2).any(|w| w == ["oif", oif])
            && words.windows(2).any(|w| w == ["lookup", table])
    })
}

pub fn key<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix('='))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Step {
    pub apply: Cmd,
    pub undo: Cmd,
}

impl Step {
    pub fn new(apply: Cmd, undo: Cmd) -> Self {
        Self { apply, undo }
    }
}

/// What `Transaction::reconcile` re-applied and could not.
#[derive(Debug, Default)]
pub struct Reconciled {
    pub restored: Vec<String>,
    pub failed: Vec<String>,
}

impl Reconciled {
    pub fn extend(&mut self, other: Reconciled) {
        self.restored.extend(other.restored);
        self.failed.extend(other.failed);
    }
}

/// The caller first reserves empty chain names, route tables and rule priorities.
/// Save each undo BEFORE applying it, so interruption is recoverable at startup.
pub struct Transaction {
    path: PathBuf,
    undo: Vec<Cmd>,
    /// Applied, re-checkable changes with their undo, in apply order
    /// (`reconcile`). Memory only: the journal is for rollback.
    desired: Vec<(Cmd, Cmd)>,
}

#[derive(Serialize, Deserialize)]
struct Journal {
    boot: String,
    undo: Vec<Cmd>,
}

pub(crate) fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_default()
        .trim()
        .to_owned()
}

impl Transaction {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            undo: Vec::new(),
            desired: Vec::new(),
        }
    }

    pub fn recover(path: &Path) -> Result<(), String> {
        if !path.exists() {
            return Ok(());
        }
        let journal: Journal = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|_| "Network recovery journal is invalid")?;
        // All owned changes are runtime-only. Never replay an old boot's
        // hostapd snapshot over a newly configured/started vendor hotspot.
        if !journal.boot.is_empty() && journal.boot != boot_id() {
            return fs::remove_file(path).map_err(|e| e.to_string());
        }
        Self {
            path: path.into(),
            undo: journal.undo,
            desired: Vec::new(),
        }
        .rollback()
    }

    /// A journal a previous agent wrote in this boot, taken over as it is:
    /// its undo list stays, nothing runs (`adopt` re-takes each step).
    pub fn load(path: &Path) -> Result<Self, String> {
        let journal: Journal = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|_| "Network recovery journal is invalid")?;
        if journal.boot != boot_id() {
            return Err("The network journal is from another boot".into());
        }
        Ok(Self { path: path.into(), undo: journal.undo, desired: Vec::new() })
    }

    /// Whether `path` holds a journal of this boot.
    pub fn current(path: &Path) -> bool {
        fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Journal>(&bytes).ok())
            .is_some_and(|journal| journal.boot == boot_id())
    }

    /// The journaled undo whose program and first argument match `undo`
    /// (a kernel setting's original value, kept across agent restarts).
    pub fn journaled(&self, program: &str, first: &str) -> Option<&Cmd> {
        self.undo.iter().find(|u| u.program == program && u.args.first().map(String::as_str) == Some(first))
    }

    /// Re-takes a step of an adopted journal: journaled if it is not, applied
    /// only if its effect is gone (a previous agent may have died before or
    /// after applying it), then kept for `reconcile`.
    pub fn adopt(&mut self, step: Step) -> Result<(), String> {
        changed();
        if !self.undo.contains(&step.undo) {
            self.undo.push(step.undo.clone());
            self.save()?;
        }
        if !step.apply.present()? {
            step.apply.run()?;
        }
        self.remember(&step);
        Ok(())
    }

    fn remember(&mut self, step: &Step) {
        // A held kernel setting is also sampled right after ZTE's scripts
        // run (`net_guard::hold`), until its undo is about to run.
        if let ("@u60-sysctl", [key, value]) = (step.apply.program.as_str(), step.apply.args.as_slice()) {
            crate::net_guard::hold(&self.owner(), key, value);
        }
        if step.apply.checkable() && !self.desired.iter().any(|(_, undo)| *undo == step.undo) {
            self.desired.push((step.apply.clone(), step.undo.clone()));
        }
    }

    fn owner(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    /// Re-applies, in their original order, the changes another writer
    /// removed since (ZTE's firewall reloads, scripts, sysctls); `net_guard`
    /// decides when. Only a change that is definitely gone is re-applied; one
    /// that cannot be checked (a listing, the xtables lock or the tool
    /// failed) is left alone and reported as failed, and the next check
    /// tries again. Neither stops the rest. Checked against one listing per
    /// tool and table and per kind of `ip` object (`Pass`), not one command
    /// per change.
    pub fn reconcile(&mut self) -> Reconciled {
        self.reconcile_only(|_| true)
    }

    /// `reconcile` limited to the changes `keep` selects (an owner that
    /// repairs the rest itself, with stricter checks).
    pub fn reconcile_only(&mut self, keep: impl Fn(&Cmd) -> bool) -> Reconciled {
        self.reconcile_with(keep, &mut Device)
    }

    pub(crate) fn reconcile_with(&mut self, keep: impl Fn(&Cmd) -> bool, probe: &mut impl Probe) -> Reconciled {
        let pass = Pass::open();
        let mut listings = PASS.with(|p| p.borrow_mut().take()).unwrap_or_default();
        let result = reconcile_steps(&self.desired, keep, &mut listings, probe);
        PASS.with(|p| *p.borrow_mut() = Some(listings));
        drop(pass);
        result
    }

    /// Steps as if applied: kept for `reconcile`, nothing runs.
    #[cfg(test)]
    pub(crate) fn assume(&mut self, steps: Vec<Step>) {
        for step in steps {
            self.undo.push(step.undo.clone());
            if step.apply.checkable() && !self.desired.iter().any(|(_, undo)| *undo == step.undo) {
                self.desired.push((step.apply, step.undo));
            }
        }
    }

    fn save(&self) -> Result<(), String> {
        write_private(
            &self.path,
            &serde_json::to_vec(&Journal {
                boot: boot_id(),
                undo: self.undo.clone(),
            })
            .map_err(|e| e.to_string())?,
        )
    }

    pub fn apply(&mut self, step: Step) -> Result<(), String> {
        changed();
        self.undo.push(step.undo.clone());
        self.save()?;
        step.apply.run()?;
        self.remember(&step);
        Ok(())
    }

    /// A network plan with supported firewall runs batched into restore. Every
    /// undo is journaled with one durable write before the first effect (so
    /// before any table can COMMIT), and the applies then run in order. An
    /// interrupted plan therefore also rolls back steps that never ran: their
    /// undo must succeed for absent objects (see `Cmd::undo`) and must never
    /// match another writer's object, so a rule in a chain we do not own jumps
    /// to an owned `U60_*` chain or carries our comment (`foreign_identity`;
    /// the station's name is no identity). Never retry a failed restore as
    /// individual commands: it may be partly applied. Radio and daemon
    /// changes use `apply`.
    pub fn apply_network(&mut self, steps: Vec<Step>) -> Result<(), String> {
        if steps.is_empty() {
            return Ok(());
        }
        changed();
        self.undo.extend(steps.iter().map(|s| s.undo.clone()));
        self.save()?;
        let mut at = 0;
        while at < steps.len() {
            if let Some(batch) = firewall::Batch::collect(&steps[at..]) {
                let count = batch.count;
                batch.run()?;
                steps[at..at + count].iter().for_each(|s| self.remember(s));
                at += count;
            } else {
                steps[at].apply.run()?;
                self.remember(&steps[at]);
                at += 1;
            }
        }
        Ok(())
    }

    /// Reapply a missing independent effect without duplicating its undo.
    /// Save even on retries: a prior failed save may have changed only RAM.
    pub fn ensure(&mut self, step: Step) -> Result<(), String> {
        changed();
        if !self.undo.contains(&step.undo) {
            self.undo.push(step.undo.clone());
        }
        self.save()?;
        step.apply.run()?;
        self.remember(&step);
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<(), String> {
        changed();
        crate::net_guard::release(&self.owner(), None);
        while let Some(c) = self.undo.last() {
            if let Err(error) = c.undo() {
                let left = self.undo.clone();
                self.desired.retain(|(_, u)| left.contains(u));
                self.save()?;
                return Err(format!("Network cleanup paused: {error}. Retry cleanup in the panel; if it persists, use network-recover over USB ADB"));
            }
            self.undo.pop();
        }
        self.desired.clear();
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Undoes only the changes with these undo commands, newest first, and
    /// forgets them; the rest stays applied and journaled. For an optional
    /// part of a live plan the owner turns off (hardware forwarding).
    pub fn release(&mut self, undos: &[Cmd]) -> Result<(), String> {
        changed();
        for undo in undos.iter().rev() {
            let Some(at) = self.undo.iter().rposition(|u| u == undo) else { continue };
            if let ("@u60-sysctl", Some(key)) = (undo.program.as_str(), undo.args.first()) {
                crate::net_guard::release(&self.owner(), Some(key));
            }
            undo.undo()?;
            self.undo.remove(at);
            self.desired.retain(|(_, u)| u != undo);
            self.save()?;
        }
        Ok(())
    }
}

/// Steps of a prejournaled plan whose undo could delete an identical rule of
/// another writer: a rule in a chain we do not own that neither jumps to an
/// owned chain nor carries our comment (`firewall::owned_rule`).
#[cfg(test)]
pub fn foreign_identity(plan: &[Step]) -> Vec<&Step> {
    plan.iter()
        .filter(|step| {
            matches!(step.undo.program.as_str(), "iptables" | "ip6tables")
                && step.undo.args.iter().any(|a| a == "-D")
                && !firewall::owned_rule(&step.undo.args)
        })
        .collect()
}

pub fn chain(tool: &str, table: &str, name: &str) -> Vec<Step> {
    vec![Step::new(
        Cmd::new(tool, &["-w", "2", "-t", table, "-N", name]),
        Cmd::new(tool, &["-w", "2", "-t", table, "-X", name]),
    )]
}

pub fn rule(tool: &str, table: &str, name: &str, args: &[&str], first: bool) -> Step {
    let mut a = vec![
        "-w",
        "2",
        "-t",
        table,
        if first { "-I" } else { "-A" },
        name,
    ];
    if first {
        a.push("1");
    }
    a.extend_from_slice(args);
    let mut d = vec!["-w", "2", "-t", table, "-D", name];
    d.extend_from_slice(args);
    Step::new(Cmd::new(tool, &a), Cmd::new(tool, &d))
}

pub fn ip_step(family: &str, what: &str, args: &[&str]) -> Step {
    let mut a = vec![family, what, "add"];
    a.extend_from_slice(args);
    let mut d = vec![family, what, "del"];
    d.extend_from_slice(args);
    Step::new(Cmd::new("ip", &a), Cmd::new("ip", &d))
}

pub fn reserve(
    tool: &str,
    table: &str,
    names: &[&str],
    family: &str,
    route_table: &str,
    pref: &str,
) -> Result<(), String> {
    for name in names {
        if Cmd::new(tool, &["-w", "2", "-t", table, "-S", name])
            .run()
            .is_ok()
        {
            return Err(
                "A reserved network chain already exists; recover it before starting".into(),
            );
        }
    }
    // An empty table may return ENOENT. Verify against all tables rather
    // than treating every command failure as permission to take it over.
    let occupied = match Cmd::new("ip", &[family, "route", "show", "table", route_table]).run() {
        Ok(routes) => !routes.trim().is_empty(),
        Err(_) => route_table_listed(family, route_table)?,
    };
    if occupied {
        return Err("A reserved network route table is already in use".into());
    }
    let rules = Cmd::new("ip", &[family, "rule", "show"]).run()?;
    if rules
        .lines()
        .any(|l| l.trim_start().starts_with(&format!("{pref}:")))
    {
        return Err("A reserved network rule priority is already in use".into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod bench {
    //! A device for checks and undos: the router's own listings, scripted
    //! answers, and every command it was asked to run (on the router, one
    //! process each).
    use super::{Cmd, Probe, Step};

    /// `iptables -C`/`-D` of a rule that is not there.
    pub const NO_RULE: (i32, &str) = (1, "iptables: Bad rule (does a matching rule exist in that chain?).");
    /// The same for a rule that jumps to a user-defined chain that exists,
    /// as B31 words it.
    pub const NO_JUMP: (i32, &str) = (1, "iptables: No chain/target/match by that name.");
    /// `-w 2` without the xtables lock.
    pub const LOCKED: (i32, &str) = (4, "Another app is currently holding the xtables lock. Stopped waiting after 2s.");

    /// `iptables -S` of one table as B31 printed it with the relay connected
    /// on 5 GHz with IPv6 (2026-11-11, `testdata/`), the station renamed to
    /// `ath20` and the MASQUERADE given its comment as this build adds them.
    pub fn router(tool: &str, table: &str) -> String {
        let text = match tool {
            "iptables" => include_str!("net_tools/testdata/iptables-v4.txt"),
            _ => include_str!("net_tools/testdata/iptables-v6.txt"),
        };
        let header = format!("### {tool} -t {table}");
        let start = text.find(&header).expect("listed table") + header.len();
        let rest = &text[start..];
        rest[..rest.find("###").unwrap_or(rest.len())].trim().to_owned()
    }

    /// The same check's `ip -4` listings: routes and rules as printed; the
    /// addresses rebuilt in `ip -o` form from the address list.
    pub const ROUTES4: &str = "local default dev lo table 60625 scope host \ndefault via 192.168.2.1 dev ath20 table 60631 \nthrow 100.64.0.0/10 table 60631 \nthrow 169.254.0.0/16 table 60631 \nthrow 192.168.0.0/24 table 60631 \n192.168.2.0/24 dev ath20 table 60631 scope link src 192.168.2.124 \nthrow 224.0.0.0/4 table 60631 \ndefault via 192.168.2.1 dev ath20 metric 60631 \nunreachable 100.64.0.0/10 metric 60631 \nunreachable 169.254.0.0/16 metric 60631 \n169.254.20.0/24 dev rndis0 proto kernel scope link src 169.254.20.1 linkdown \n169.254.21.0/24 dev ecm0 proto kernel scope link src 169.254.21.1 \n169.254.30.0/24 dev wlan0 proto kernel scope link src 169.254.30.1 \n169.254.32.0/24 dev wlan2 proto kernel scope link src 169.254.32.1 \n192.168.0.0/24 dev br-lan proto static scope link metric 128 \n192.168.2.0/24 dev ath20 proto kernel scope link src 192.168.2.124 \nunreachable 224.0.0.0/4 metric 60631 ";
    pub const RULES4: &str = "0:\tfrom all lookup local\n18620:\tfrom all fwmark 0x700/0xff00 lookup 60625\n18640:\tfrom all lookup 60631\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default";
    pub const ADDRS4: &str = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n14: br-lan    inet 192.168.0.1/24 brd 192.168.0.255 scope global br-lan\\       valid_lft forever preferred_lft forever\n33: ath20    inet 192.168.2.124/24 brd 192.168.2.255 scope global ath20\\       valid_lft forever preferred_lft forever\n";

    /// The IPv6 legacy steps of the relay as `wifi_relay::ipv6` builds them
    /// (`setup_plan`, `network_plan` with the router's ULA source); the IPv4
    /// ones run through the relay's own plans in `wifi_relay::portal`.
    pub fn relay_ipv6_firewall() -> Vec<Step> {
        let accept = |args: &[&str]| super::rule("ip6tables", "filter", "U60_R6_IN", args, false);
        let mut plan = super::chain("ip6tables", "filter", "U60_R6_IN");
        plan.push(accept(&["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]));
        plan.push(accept(&["-p", "ipv6-icmp", "--icmpv6-type", "134", "-m", "hl", "--hl-eq", "255", "-s", "fe80::/10", "-j", "ACCEPT"]));
        for kind in ["135", "136"] {
            plan.push(accept(&["-p", "ipv6-icmp", "--icmpv6-type", kind, "-m", "hl", "--hl-eq", "255", "-j", "ACCEPT"]));
        }
        for kind in ["1", "2", "3", "4"] {
            plan.push(accept(&["-p", "ipv6-icmp", "--icmpv6-type", kind, "-j", "ACCEPT"]));
        }
        plan.push(accept(&["-p", "udp", "--sport", "547", "--dport", "546", "-j", "ACCEPT"]));
        plan.push(super::rule("ip6tables", "filter", "U60_RELAY_IN", &["-j", "U60_R6_IN"], true));
        plan.extend(super::chain("ip6tables", "filter", "U60_R6_FWD"));
        plan.push(super::rule("ip6tables", "filter", "U60_R6_FWD", &["-i", "br-lan", "-o", "ath20", "-s", "fd1b:f7f5:d006::/64", "-j", "ACCEPT"], false));
        plan.push(super::rule("ip6tables", "filter", "U60_R6_FWD", &["-i", "ath20", "-o", "br-lan", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], false));
        plan.push(super::rule("ip6tables", "filter", "FORWARD", &["-j", "U60_R6_FWD"], true));
        plan
    }

    #[derive(Default)]
    pub struct Bench {
        pub listings: Vec<(Cmd, Result<String, String>)>,
        /// Answers to `status` by command; a `-C` not named is `NO_RULE`.
        pub answers: Vec<(Cmd, (i32, String))>,
        pub applied: Vec<Cmd>,
        pub ran: Vec<Cmd>,
    }

    impl Bench {
        /// The router as listed: all four tables of both tools, `ip -4`.
        pub fn router() -> Self {
            let mut bench = Self::default();
            for tool in ["iptables", "ip6tables"] {
                for table in ["filter", "nat", "mangle", "raw"] {
                    bench.list(Cmd::new(tool, &["-w", "2", "-t", table, "-S"]), Ok(router(tool, table)));
                }
            }
            bench.list(Cmd::new("ip", &["-4", "route", "show", "table", "all"]), Ok(ROUTES4.into()));
            bench.list(Cmd::new("ip", &["-4", "rule", "show"]), Ok(RULES4.into()));
            bench.list(Cmd::new("ip", &["-o", "-4", "addr", "show"]), Ok(ADDRS4.into()));
            bench
        }

        /// Sets (or replaces) a listing.
        pub fn list(&mut self, cmd: Cmd, text: Result<String, String>) {
            self.listings.retain(|(c, _)| *c != cmd);
            self.listings.push((cmd, text));
        }

        pub fn answer(&mut self, cmd: Cmd, (code, error): (i32, &str)) {
            self.answers.retain(|(c, _)| *c != cmd);
            self.answers.push((cmd, (code, error.into())));
        }
    }

    impl Probe for Bench {
        fn list(&mut self, cmd: &Cmd) -> Result<String, String> {
            self.ran.push(cmd.clone());
            self.listings.iter().find(|(c, _)| c == cmd).map_or_else(|| Err(format!("not listed: {cmd:?}")), |(_, text)| text.clone())
        }

        fn status(&mut self, cmd: &Cmd) -> Result<(i32, String), String> {
            self.ran.push(cmd.clone());
            let jumps = cmd.args.windows(2).any(|w| w[0] == "-j" && w[1].starts_with("U60_"));
            let absent = if jumps { NO_JUMP } else { NO_RULE };
            Ok(self.answers.iter().find(|(c, _)| c == cmd).map_or_else(|| (absent.0, absent.1.into()), |(_, a)| a.clone()))
        }

        fn apply(&mut self, cmd: &Cmd) -> Result<(), String> {
            self.ran.push(cmd.clone());
            self.applied.push(cmd.clone());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bench::{relay_ipv6_firewall, Bench, LOCKED, NO_RULE};

    fn lines(text: &str) -> Vec<&str> {
        text.lines().collect()
    }

    #[test]
    fn the_relays_ipv6_rules_are_predicted_as_the_router_lists_them() {
        let listed = bench::router("ip6tables", "filter");
        for step in relay_ipv6_firewall() {
            let a = &step.apply.args;
            if a[4] == "-N" {
                assert!(firewall::has_chain(&listed, &a[5]), "{a:?}");
            } else {
                let line = firewall::listed_rule(&step.apply).unwrap_or_else(|| panic!("not predicted: {a:?}"));
                assert!(lines(&listed).contains(&line.as_str()), "{line}");
            }
        }
        let mut tx = Transaction::new(PathBuf::from("/nonexistent/ipv6.json"));
        tx.assume(relay_ipv6_firewall());
        let mut device = Bench::router();
        let result = tx.reconcile_with(|_| true, &mut device);
        assert!(result.restored.is_empty() && result.failed.is_empty(), "{result:?}");
        assert_eq!(device.ran, [Cmd::new("ip6tables", &["-w", "2", "-t", "filter", "-S"])], "15 steps, one listing, no -C");
    }

    #[test]
    fn listed_forms_follow_the_tools_normalisation_and_never_match_another_rule() {
        let filter = bench::router("iptables", "filter");
        let at = |chain: &str, args: &[&str]| firewall::listed_rule(&rule("iptables", "filter", chain, args, false).apply);
        // What iptables -S makes of arguments it was given.
        assert_eq!(at("X", &["-p", "tcp", "--dport", "53", "-j", "ACCEPT"]).unwrap(), "-A X -p tcp -m tcp --dport 53 -j ACCEPT");
        assert_eq!(at("X", &["-p", "udp", "--dport", "68", "--sport", "67", "-j", "ACCEPT"]).unwrap(), "-A X -p udp -m udp --sport 67 --dport 68 -j ACCEPT");
        assert_eq!(at("X", &["-d", "192.168.0.1", "-o", "ath20", "-s", "10.1.2.3/8", "-j", "DROP"]).unwrap(), "-A X -s 10.0.0.0/8 -d 192.168.0.1/32 -o ath20 -j DROP");
        assert_eq!(at("X", &["-m", "comment", "--comment", "a b\"c", "-j", "RETURN"]).unwrap(), "-A X -m comment --comment \"a b\\\"c\" -j RETURN");
        // The vendor's own quoted comment, as listed.
        let vendor = at("INPUT", &["-i", "lo", "-m", "comment", "--comment", "!fw3", "-j", "ACCEPT"]).unwrap();
        assert!(lines(&filter).contains(&vendor.as_str()));
        // musl's IPv6 text: the first longest zero run, a leading one a character shorter.
        let v6 = |source: &str| firewall::listed_rule(&rule("ip6tables", "filter", "X", &["-s", source, "-j", "ACCEPT"], false).apply).unwrap();
        assert_eq!(v6("FD1B:f7f5:d006:0::5/64"), "-A X -s fd1b:f7f5:d006::/64 -j ACCEPT");
        assert_eq!(v6("2001:db8::1"), "-A X -s 2001:db8::1/128 -j ACCEPT");
        assert_eq!(v6("0:0:1:0:0:2:3:4"), "-A X -s 0:0:1::2:3:4/128 -j ACCEPT");
        // Unknown to the prediction: the tool is asked instead.
        assert!(at("X", &["-j", "REJECT"]).is_none(), "REJECT lists its default --reject-with");
        assert!(at("X", &["!", "-d", "192.168.0.1/32", "-j", "ACCEPT"]).is_none());
        assert!(firewall::listed_rule(&Cmd::new("iptables", &["-w", "2", "-t", "nat", "-A", "redirect_chain", "!", "-d", "192.168.0.1/32", "-p", "tcp", "-m", "tcp", "--dport", "80", "-m", "limit", "--limit", "20/sec", "--limit-burst", "40", "-j", "DNAT", "--to-destination", "192.168.0.1"])).is_none());
        // Present with other arguments is not present.
        for other in [
            at("U60_RELAY_IN", &["-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"]),
            at("U60_RELAY_IN", &["-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT"]),
            at("U60_RELAY_IN", &["-p", "tcp", "--sport", "67", "--dport", "68", "-j", "ACCEPT"]),
            at("INPUT", &["-i", "br-lan", "-j", "U60_RELAY_IN"]),
            at("FORWARD", &["-i", "ath20", "-j", "U60_RELAY_FWD"]),
            at("U60_RELAY_FWD", &["-i", "br-lan", "-o", "ath20", "-p", "tcp", "-j", "ACCEPT"]),
            at("U60_RELAY_FWD", &["-i", "br-lan", "-o", "ath20", "-j", "DROP"]),
            // The right rule in another chain.
            at("U60_RELAY_FWD", &["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]),
        ] {
            let other = other.unwrap();
            assert!(!lines(&filter).contains(&other.as_str()), "{other}");
        }
        // The TCP-only return accept does not stand in for the general one.
        let general = at("U60_RELAY_FWD", &["-i", "ath20", "-o", "br-lan", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]).unwrap();
        let tcp = at("U60_RELAY_FWD", &["-i", "ath20", "-o", "br-lan", "-p", "tcp", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]).unwrap();
        let without: String = filter.lines().filter(|l| *l != general).map(|l| format!("{l}\n")).collect();
        assert!(lines(&without).contains(&tcp.as_str()) && !lines(&without).contains(&general.as_str()));
    }

    /// The defect: a lock timeout read as "absent" re-added the rule, and the
    /// single `-D` of the undo then left the copy behind.
    #[test]
    fn a_check_that_fails_for_another_reason_than_absence_re_adds_nothing() {
        let missing = rule("iptables", "filter", "U60_RELAY_FWD", &["-i", "br-lan", "-o", "ath20", "-j", "DROP"], false);
        let check = Cmd::new("iptables", &["-w", "2", "-t", "filter", "-C", "U60_RELAY_FWD", "-i", "br-lan", "-o", "ath20", "-j", "DROP"]);
        let hook = rule("iptables", "filter", "FORWARD", &["-j", "U60_RELAY_FWD"], true);
        let mut tx = Transaction::new(PathBuf::from("/nonexistent/network.json"));
        tx.assume(vec![missing.clone(), hook]);
        let mut device = Bench::router();
        device.answer(check.clone(), LOCKED);
        let result = tx.reconcile_with(|_| true, &mut device);
        assert!(device.applied.is_empty(), "nothing re-added: {:?}", device.applied);
        assert!(result.restored.is_empty() && result.failed.len() == 1 && result.failed[0].contains("not checked"), "{result:?}");
        // The tool exits 1 for errors other than absence: only its message counts.
        device.answer(check.clone(), (1, "iptables: Resource temporarily unavailable."));
        assert!(tx.reconcile_with(|_| true, &mut device).failed.len() == 1 && device.applied.is_empty());
        // The next check gets a definite answer: re-added once.
        device.answer(check, NO_RULE);
        let result = tx.reconcile_with(|_| true, &mut device);
        assert_eq!(device.applied, [missing.apply]);
        assert!(result.failed.is_empty() && result.restored.len() == 1, "{result:?}");
    }

    #[test]
    fn a_failed_listing_leaves_its_steps_alone_and_does_not_stop_the_others() {
        let mut tx = Transaction::new(PathBuf::from("/nonexistent/network.json"));
        let mut steps = relay_ipv6_firewall();
        let masquerade = rule("iptables", "nat", "POSTROUTING", &["-o", "ath20", "-m", "comment", "--comment", "zte-agent-wifi-relay", "-j", "MASQUERADE"], true);
        steps.push(masquerade.clone());
        steps.push(ip_step("-4", "route", &["throw", "203.0.113.0/24", "table", "60631"]));
        tx.assume(steps);
        let mut device = Bench::router();
        device.list(Cmd::new("ip6tables", &["-w", "2", "-t", "filter", "-S"]), Err("Device tool failed (exit status: 4)".into()));
        device.list(Cmd::new("iptables", &["-w", "2", "-t", "nat", "-S"]), Ok(bench::router("iptables", "nat").replace("-A POSTROUTING -o ath20 -m comment --comment zte-agent-wifi-relay -j MASQUERADE\n", "")));
        let result = tx.reconcile_with(|_| true, &mut device);
        assert_eq!(result.failed.len(), 15, "every IPv6 step: {result:?}");
        assert_eq!(device.applied, [masquerade.apply, Cmd::new("ip", &["-4", "route", "add", "throw", "203.0.113.0/24", "table", "60631"])]);
        assert_eq!(device.ran.iter().filter(|c| c.args.contains(&"-S".to_owned())).count(), 2, "a failed listing is read once per check");
    }

    #[test]
    fn a_rule_listed_in_an_unpredicted_form_is_asked_of_the_tool_and_kept() {
        // As if the rule had been listed in a form the prediction misses.
        let step = rule("iptables", "filter", "INPUT", &["-i", "ath20", "-j", "U60_RELAY_IN"], true);
        let mut device = Bench::router();
        let listed = bench::router("iptables", "filter").replace("-A INPUT -i ath20 -j U60_RELAY_IN", "-A INPUT -i ath20 -m whatever -j U60_RELAY_IN");
        device.list(Cmd::new("iptables", &["-w", "2", "-t", "filter", "-S"]), Ok(listed));
        let check = Cmd::new("iptables", &["-w", "2", "-t", "filter", "-C", "INPUT", "-i", "ath20", "-j", "U60_RELAY_IN"]);
        device.answer(check.clone(), (0, ""));
        let mut tx = Transaction::new(PathBuf::from("/nonexistent/wireless.json"));
        tx.assume(vec![step]);
        let result = tx.reconcile_with(|_| true, &mut device);
        assert!(result.restored.is_empty() && result.failed.is_empty() && device.applied.is_empty());
        assert_eq!(device.ran.last(), Some(&check), "the -C drops the position");
    }

    #[test]
    fn a_re_added_chain_is_listed_again_before_its_rules_are_checked() {
        let mut device = Bench::router();
        let gone = bench::router("iptables", "filter").lines().filter(|l| !l.contains("U60_RELAY_FWD")).collect::<Vec<_>>().join("\n");
        device.list(Cmd::new("iptables", &["-w", "2", "-t", "filter", "-S"]), Ok(gone));
        let mut tx = Transaction::new(PathBuf::from("/nonexistent/network.json"));
        let mut steps = chain("iptables", "filter", "U60_RELAY_FWD");
        steps.push(rule("iptables", "filter", "U60_RELAY_FWD", &["-i", "br-lan", "-o", "ath20", "-j", "ACCEPT"], false));
        steps.push(rule("iptables", "filter", "FORWARD", &["-j", "U60_RELAY_FWD"], true));
        tx.assume(steps);
        let result = tx.reconcile_with(|_| true, &mut device);
        assert_eq!(result.restored.len(), 3, "{result:?}");
        let listings = device.ran.iter().filter(|c| c.args.last().is_some_and(|a| a == "-S")).count();
        assert_eq!(listings, 3, "read again after each re-apply, never judged on a listing taken before it");
    }

    #[test]
    fn one_pass_shares_its_listings_and_none_outlives_it() {
        let mut first = Transaction::new(PathBuf::from("/nonexistent/a.json"));
        first.assume(vec![rule("iptables", "filter", "INPUT", &["-i", "ath20", "-j", "U60_RELAY_IN"], true)]);
        let mut second = Transaction::new(PathBuf::from("/nonexistent/b.json"));
        second.assume(vec![rule("iptables", "filter", "FORWARD", &["-j", "U60_RELAY_FWD"], true)]);
        let mut device = Bench::router();
        {
            let _pass = Pass::open();
            first.reconcile_with(|_| true, &mut device);
            second.reconcile_with(|_| true, &mut device);
        }
        assert_eq!(device.ran.len(), 1, "one listing for both");
        // A vendor reload between two checks: the next one reads again.
        let flushed = bench::router("iptables", "filter").replace("-A FORWARD -j U60_RELAY_FWD\n", "");
        device.list(Cmd::new("iptables", &["-w", "2", "-t", "filter", "-S"]), Ok(flushed));
        {
            let _pass = Pass::open();
            first.reconcile_with(|_| true, &mut device);
            assert_eq!(second.reconcile_with(|_| true, &mut device).restored.len(), 1);
        }
        assert_eq!(device.ran.len(), 4, "listing, listing, -C, re-add");
        // Without an open pass each reconcile reads for itself.
        first.reconcile_with(|_| true, &mut device);
        first.reconcile_with(|_| true, &mut device);
        assert_eq!(device.ran.len(), 6);
    }

    #[test]
    fn routes_rules_and_addresses_are_found_in_one_listing_of_each() {
        let routes = bench::ROUTES4;
        let present = |args: &[&str]| route_listed(routes, &ip_step("-4", "route", args).apply.args);
        assert!(present(&["192.168.2.0/24", "dev", "ath20", "scope", "link", "src", "192.168.2.124", "table", "60631"]));
        assert!(present(&["throw", "100.64.0.0/10", "table", "60631"]));
        assert!(present(&["default", "via", "192.168.2.1", "dev", "ath20", "table", "60631"]));
        assert!(present(&["unreachable", "100.64.0.0/10", "metric", "60631", "table", "main"]));
        assert!(present(&["default", "via", "192.168.2.1", "dev", "ath20", "metric", "60631", "table", "main"]));
        assert!(present(&["local", "default", "dev", "lo", "table", "60625"]));
        assert!(!present(&["throw", "100.64.0.0/10", "table", "main"]), "other table");
        assert!(!present(&["unreachable", "100.64.0.0/10", "table", "60631"]), "other type");
        assert!(!present(&["192.168.2.0/24", "dev", "br-lan", "table", "60631"]), "other device");
        assert!(!present(&["192.168.2.0/25", "dev", "ath20", "table", "60631"]), "other prefix");
        assert!(!present(&["throw", "198.18.0.0/16", "table", "60631"]));
        // Mihomo's IPv6 local route as `ip -6 route show table all` lists it.
        let v6 = "local default dev lo table 60625 metric 1024 pref medium\nthrow ff00::/8 dev lo table 60631 metric 1024 pref medium";
        assert!(route_listed(v6, &ip_step("-6", "route", &["local", "::/0", "dev", "lo", "table", "60625"]).apply.args));
        assert!(route_listed(v6, &ip_step("-6", "route", &["throw", "ff00::/8", "table", "60631"]).apply.args));
        assert!(!route_listed(v6, &ip_step("-6", "route", &["local", "::/0", "dev", "lo", "table", "60631"]).apply.args));
        assert!(addr_listed(bench::ADDRS4, "ath20", "192.168.2.124/24"));
        assert!(!addr_listed(bench::ADDRS4, "br-lan", "192.168.2.124/24"));
        assert!(!addr_listed(bench::ADDRS4, "ath20", "192.168.2.124/25"));
        // All of them, and the policy rule, from three reads.
        let mut tx = Transaction::new(PathBuf::from("/nonexistent/mihomo.json"));
        tx.assume(vec![
            ip_step("-4", "addr", &["192.168.2.124/24", "dev", "ath20"]),
            ip_step("-4", "route", &["throw", "224.0.0.0/4", "table", "60631"]),
            ip_step("-4", "route", &["local", "default", "dev", "lo", "table", "60625"]),
            ip_step("-4", "rule", &["pref", "18640", "lookup", "60631"]),
            ip_step("-4", "rule", &["pref", "18620", "fwmark", "0x700/0xff00", "lookup", "60625"]),
        ]);
        let mut device = Bench::router();
        let result = tx.reconcile_with(|_| true, &mut device);
        assert!(result.restored.is_empty() && result.failed.is_empty(), "{result:?}");
        assert_eq!(device.ran.len(), 3);
        // An unreadable listing is "could not check", not "absent".
        device.list(Cmd::new("ip", &["-4", "rule", "show"]), Err("Device tool timed out".into()));
        let result = tx.reconcile_with(|_| true, &mut device);
        assert!(device.applied.is_empty() && result.failed.len() == 2, "{result:?}");
    }

    #[test]
    fn nft_rule_counts_match_between_a_written_ruleset_and_its_listing() {
        let written = crate::netfx::effect::table(
            "ip",
            "u60_t",
            &[("s", "type ipv4_addr; flags interval;", &["1.0.0.0/8".to_owned()])],
            &[("pre", "type filter hook prerouting priority 0; policy accept;", vec!["ip daddr @s return".into(), "accept".into()]), ("sub", "", vec!["return".into()])],
        );
        let listing = "table ip u60_t {\n\tset s {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t}\n\n\tchain pre {\n\t\ttype filter hook prerouting priority filter; policy accept;\n\t\tip daddr @s return\n\t\taccept\n\t}\n\n\tchain sub {\n\t\treturn\n\t}\n}\n";
        let want = nft_chain_rules(&written);
        assert_eq!(want, nft_chain_rules(listing));
        assert_eq!(want.get("pre"), Some(&2));
        let flushed = listing.replace("\t\tip daddr @s return\n\t\taccept\n", "");
        assert_eq!(nft_chain_rules(&flushed).get("pre"), Some(&0), "a flushed chain is not present");
    }

    #[test]
    fn release_undoes_only_the_named_steps_in_reverse_and_keeps_the_rest_journaled() {
        let dir = std::env::temp_dir().join(format!("u60-release-{}", std::process::id()));
        let path = dir.join("journal.json");
        let mut tx = Transaction::new(path.clone());
        let step = |name: &str| Step::new(Cmd::new("true", &[name]), Cmd::new("true", &[&format!("undo-{name}")]));
        for name in ["a", "b", "c"] {
            tx.apply(step(name)).unwrap();
        }
        tx.release(&[step("b").undo, Cmd::new("true", &["never-applied"])]).unwrap();
        let journal: Journal = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(journal.undo, vec![step("a").undo, step("c").undo]);
        tx.rollback().unwrap();
        assert!(!path.exists());
        let _ = fs::remove_dir_all(dir);
    }

    /// v4 release blocker: a reconcile after a release (brnf given back)
    /// never writes the running value again.
    #[test]
    fn a_reconcile_after_a_release_never_reapplies_the_released_step() {
        let dir = std::env::temp_dir().join(format!("u60-late-reconcile-{}", std::process::id()));
        let mut tx = Transaction::new(dir.join("journal.json"));
        // The setting's own step, with an undo this host can run.
        let step = Step::new(sysctl_step("bridge-nf-call-iptables", "0", "1").unwrap().apply, Cmd::new("true", &["restore-brnf"]));
        // As if applied: journaled and kept for `reconcile`.
        tx.undo.push(step.undo.clone());
        tx.remember(&step);
        // Read before the reconcile, which (as root on Linux) writes the
        // real setting; put it back afterwards.
        let original = sysctl_read("bridge-nf-call-iptables").ok();
        let before = tx.reconcile();
        assert_eq!(before.restored.len() + before.failed.len(), 1 - usize::from(original.as_deref() == Some("0")), "a live step is checked: {before:?}");
        tx.release(&[step.undo.clone()]).unwrap();
        if let Some(original) = &original {
            let _ = sysctl_write("bridge-nf-call-iptables", original);
        }
        let after = tx.reconcile();
        assert!(after.restored.is_empty() && after.failed.is_empty(), "released: nothing is written back");
        assert_eq!(sysctl_read("bridge-nf-call-iptables").ok(), original, "the released value stays as it was put back");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn an_undo_from_another_agent_version_is_skipped_not_executed() {
        let removed = Cmd::new("@u60-removed-step", &["on"]);
        assert!(removed.run().unwrap_err().starts_with(UNKNOWN_STEP), "never executed as a program");
        assert!(removed.undo().is_ok(), "does not block the rest of the cleanup");
    }

    #[test]
    fn core_tun_recovery_matches_only_its_exact_rule_including_detached_interfaces() {
        let rules = "32765: from all oif u60mh0 [detached] lookup 60630\n32764: from all oif other lookup 60630\n";
        assert!(has_oif_rule(rules, "u60mh0", "60630"));
        assert!(!has_oif_rule(rules, "u60mh0", "6063"));
        assert!(!has_oif_rule(
            "32765: from all oif other lookup 60630",
            "u60mh0",
            "60630"
        ));
        assert!(!has_oif_rule(
            "32765: from all oif u60mh0 lookup 2022",
            "u60mh0",
            "60630"
        ));
    }

    #[test]
    fn generated_undo_matches_only_the_owned_rule() {
        let s = rule(
            "iptables",
            "mangle",
            "PREROUTING",
            &["-i", "br-lan", "-j", "U60_MH"],
            true,
        );
        assert_eq!(
            s.apply.args,
            [
                "-w",
                "2",
                "-t",
                "mangle",
                "-I",
                "PREROUTING",
                "1",
                "-i",
                "br-lan",
                "-j",
                "U60_MH"
            ]
        );
        assert_eq!(
            s.undo.args,
            [
                "-w",
                "2",
                "-t",
                "mangle",
                "-D",
                "PREROUTING",
                "-i",
                "br-lan",
                "-j",
                "U60_MH"
            ]
        );
    }

    #[test]
    fn failed_effect_is_journaled_and_recovers_after_restart() {
        let dir = std::env::temp_dir().join(format!("u60-failed-effect-{}", std::process::id()));
        private_dir(&dir).unwrap();
        let journal = dir.join("journal.json");
        let file = dir.join("effect");
        let name = file.to_str().unwrap();
        let mut tx = Transaction::new(journal.clone());
        tx.apply(Step::new(
            Cmd::new("touch", &[name]),
            Cmd::new("rm", &["-f", name]),
        ))
        .unwrap();
        assert!(tx
            .apply(Step::new(
                Cmd::new("false", &[]),
                Cmd::new("rm", &["-f", name])
            ))
            .is_err());
        assert_eq!(
            serde_json::from_slice::<Journal>(&fs::read(&journal).unwrap())
                .unwrap()
                .undo
                .len(),
            2
        );
        drop(tx);
        Transaction::recover(&journal).unwrap();
        Transaction::recover(&journal).unwrap();
        assert!(!file.exists() && !journal.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rollback_stops_on_failure_and_keeps_remaining_recovery() {
        let dir = std::env::temp_dir().join(format!("u60-blocked-undo-{}", std::process::id()));
        private_dir(&dir).unwrap();
        let journal = dir.join("journal.json");
        let file = dir.join("effect");
        let blocker = dir.join("blocker");
        let mut tx = Transaction::new(journal.clone());
        tx.apply(Step::new(
            Cmd::new("touch", &[file.to_str().unwrap()]),
            Cmd::new("rm", &["-f", file.to_str().unwrap()]),
        ))
        .unwrap();
        tx.apply(Step::new(
            Cmd::new("mkdir", &[blocker.to_str().unwrap()]),
            Cmd::new("rmdir", &[blocker.to_str().unwrap()]),
        ))
        .unwrap();
        fs::write(blocker.join("busy"), b"not empty").unwrap();
        assert!(tx.rollback().is_err());
        assert!(file.exists() && journal.exists());
        drop(tx);
        fs::remove_file(blocker.join("busy")).unwrap();
        Transaction::recover(&journal).unwrap();
        assert!(!file.exists() && !blocker.exists() && !journal.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn previous_boot_runtime_journal_does_not_replay() {
        let dir = std::env::temp_dir().join(format!("u60-old-boot-{}", std::process::id()));
        let journal = dir.join("journal.json");
        let j = Journal {
            boot: "previous-boot".into(),
            undo: vec![Cmd::new("false", &[])],
        };
        write_private(&journal, &serde_json::to_vec(&j).unwrap()).unwrap();
        Transaction::recover(&journal).unwrap();
        assert!(!journal.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    fn touch_step(path: &Path) -> Step {
        let name = path.to_str().unwrap();
        Step::new(Cmd::new("touch", &[name]), Cmd::new("rm", &["-f", name]))
    }

    #[test]
    fn batched_plan_is_fully_journaled_before_its_first_effect_and_recovers_after_failure() {
        let dir = std::env::temp_dir().join(format!("u60-batch-{}", std::process::id()));
        private_dir(&dir).unwrap();
        let journal = dir.join("journal.json");
        let files: Vec<_> = (1..=3).map(|n| dir.join(format!("effect-{n}"))).collect();
        let mut first = touch_step(&files[0]);
        // Runs as the first effect: the journal must already name the last undo.
        first.apply = Cmd::new(
            "sh",
            &[
                "-c",
                &format!(
                    "grep -q effect-3 '{}' && touch '{}'",
                    journal.display(),
                    files[0].display()
                ),
            ],
        );
        let broken = Step::new(
            Cmd::new("false", &[]),
            Cmd::new("rm", &["-f", files[1].to_str().unwrap()]),
        );
        let mut tx = Transaction::new(journal.clone());
        assert!(tx
            .apply_network(vec![first, broken, touch_step(&files[2])])
            .is_err());
        assert!(files[0].exists() && !files[1].exists() && !files[2].exists());
        assert_eq!(
            serde_json::from_slice::<Journal>(&fs::read(&journal).unwrap())
                .unwrap()
                .undo
                .len(),
            3,
            "never-run steps stay journaled; their undo is idempotent"
        );
        drop(tx);
        Transaction::recover(&journal).unwrap();
        assert!(!files[0].exists() && !journal.exists());
        let mut tx = Transaction::new(journal.clone());
        tx.apply_network(Vec::new()).unwrap();
        assert!(!journal.exists(), "an empty batch writes nothing");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_emptied_route_table_is_recognised_from_the_full_listing() {
        let all = "default via 10.0.0.1 dev ath20 table 60631\nlocal ::1 dev lo table local proto kernel metric 0";
        assert!(lists_table(all, "60631"));
        assert!(!lists_table(all, "6063"));
        assert!(!lists_table(
            "fe80::/64 dev br-lan proto kernel metric 256",
            "60631"
        ));
    }

    #[test]
    fn only_rules_reaching_into_shared_chains_without_our_identity_are_foreign() {
        let foreign = rule(
            "ip6tables",
            "filter",
            "OUTPUT",
            &["-o", "rmnet+", "-j", "REJECT"],
            true,
        );
        let owned = [
            rule("ip6tables", "filter", "OUTPUT", &["-j", "U60_X"], true),
            rule(
                "iptables",
                "nat",
                "POSTROUTING",
                &["-o", "u60sta0", "-j", "MASQUERADE"],
                true,
            ),
            rule(
                "iptables",
                "nat",
                "POSTROUTING",
                &["-o", "ath20", "-m", "comment", "--comment", "zte-agent-wifi-relay", "-j", "MASQUERADE"],
                true,
            ),
            rule(
                "iptables",
                "nat",
                "redirect_chain",
                &[
                    "-i",
                    "br-lan",
                    "-m",
                    "comment",
                    "--comment",
                    "zte-agent-wifi-relay",
                    "-j",
                    "RETURN",
                ],
                true,
            ),
            rule(
                "ip6tables",
                "filter",
                "U60_X",
                &["-o", "rmnet+", "-j", "REJECT"],
                false,
            ),
        ];
        let mut plan = owned.to_vec();
        plan.push(foreign.clone());
        // The station's name alone, as another writer could have it.
        let bare = rule("iptables", "nat", "POSTROUTING", &["-o", "ath20", "-j", "MASQUERADE"], true);
        plan.push(bare.clone());
        let found: Vec<&Cmd> = foreign_identity(&plan).iter().map(|s| &s.undo).collect();
        assert_eq!(found, [&foreign.undo, &bare.undo]);
    }

    #[test]
    fn policy_rule_checks_selectors_before_repair_or_undo() {
        assert_eq!(
            policy_rule_state("[]", "60631", "60631").unwrap(),
            PolicyRule::Missing
        );
        assert_eq!(
            policy_rule_state(
                r#"[{"priority":60631,"src":"all","table":60631}]"#,
                "60631",
                "60631"
            )
            .unwrap(),
            PolicyRule::Owned
        );
        for text in [
            r#"[{"priority":60631,"src":"2001:db8::/64","table":60631}]"#,
            r#"[{"priority":60631,"src":"all","fwmark":1,"table":60631}]"#,
            r#"[{"priority":60631,"src":"all","table":100}]"#,
        ] {
            assert_eq!(
                policy_rule_state(text, "60631", "60631").unwrap(),
                PolicyRule::Foreign
            );
        }
        assert_eq!(
            policy_rule_state(
                r#"[{"priority":60631},{"priority":60631}]"#,
                "60631",
                "60631"
            )
            .unwrap(),
            PolicyRule::Shared
        );
        assert!(
            policy_rule_state("not json", "60631", "60631").is_err(),
            "only an unreadable table is an error"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Mutates firewall; only run in an empty disposable network namespace"]
    fn isolated_restore_partial_failure_keeps_vendor_rules_and_rolls_back() {
        assert_eq!(
            std::env::var("U60_FIREWALL_ISOLATED_QA").as_deref(),
            Ok("1")
        );
        let links: serde_json::Value =
            serde_json::from_str(&Cmd::new("ip", &["-j", "link"]).run().unwrap()).unwrap();
        let private_ns =
            fs::read_link("/proc/self/ns/net").unwrap() != fs::read_link("/proc/1/ns/net").unwrap();
        assert!(
            Path::new("/.dockerenv").exists() || private_ns,
            "never mutate the host namespace"
        );
        // B31 creates dormant fallback tunnel devices in every fresh namespace.
        let fallback = [
            "tunl0", "gre0", "gretap0", "erspan0", "ip_vti0", "ip6_vti0", "sit0", "ip6tnl0",
            "ip6gre0",
        ];
        assert!(links.as_array().unwrap().iter().all(|l| l["ifname"] == "lo"
            || (private_ns
                && l["operstate"] == "DOWN"
                && l["ifname"].as_str().is_some_and(|n| fallback.contains(&n)))));
        let dir = std::env::temp_dir().join(format!("u60-restore-{}", std::process::id()));
        private_dir(&dir).unwrap();
        for tool in ["iptables", "ip6tables"] {
            Cmd::new(tool, &["-t", "filter", "-N", "VENDOR_QA"])
                .run()
                .unwrap();
            Cmd::new(tool, &["-t", "filter", "-A", "VENDOR_QA", "-j", "RETURN"])
                .run()
                .unwrap();
            let before = Cmd::new(tool, &["-t", "filter", "-S", "VENDOR_QA"])
                .run()
                .unwrap();
            // An identical vendor rule in a shared chain must survive the
            // prejournaled undo of an owned-chain step that never ran.
            let vendor = [
                "-t", "filter", "-A", "OUTPUT", "-o", "rmnet+", "-j", "REJECT",
            ];
            Cmd::new(tool, &vendor).run().unwrap();
            let mut tx = Transaction::new(dir.join("network.json"));
            let mut plan = chain(tool, "filter", "U60_BATCH_F");
            plan.push(rule(
                tool,
                "filter",
                "U60_BATCH_F",
                &["-j", "RETURN"],
                false,
            ));
            plan.extend(chain(tool, "nat", "U60_BATCH_N"));
            plan.push(rule(tool, "nat", "U60_MISSING", &["-j", "ACCEPT"], false));
            plan.extend(chain(tool, "filter", "U60_BATCH_O"));
            plan.push(rule(
                tool,
                "filter",
                "U60_BATCH_O",
                &["-o", "rmnet+", "-j", "REJECT"],
                false,
            ));
            plan.push(rule(tool, "filter", "OUTPUT", &["-j", "U60_BATCH_O"], true));
            assert!(foreign_identity(&plan).is_empty());
            assert!(tx.apply_network(plan).is_err());
            assert!(
                Cmd::new(tool, &["-t", "filter", "-S", "U60_BATCH_F"])
                    .run()
                    .is_ok(),
                "earlier table committed before the later error"
            );
            let saved: Journal =
                serde_json::from_slice(&fs::read(dir.join("network.json")).unwrap()).unwrap();
            assert_eq!(
                saved.undo.len(),
                7,
                "even unexecuted undos were durable before the first commit"
            );
            tx.rollback().unwrap();
            assert!(Cmd::new(tool, &["-t", "filter", "-S", "U60_BATCH_F"])
                .run()
                .is_err());
            assert!(Cmd::new(tool, &["-t", "nat", "-S", "U60_BATCH_N"])
                .run()
                .is_err());
            assert_eq!(
                Cmd::new(tool, &["-t", "filter", "-S", "VENDOR_QA"])
                    .run()
                    .unwrap(),
                before
            );
            let mut check = vendor;
            check[2] = "-C";
            assert!(
                Cmd::new(tool, &check).run().is_ok(),
                "the vendor's identical reject survived"
            );
            check[2] = "-D";
            Cmd::new(tool, &check).run().unwrap();
            Cmd::new(tool, &["-t", "filter", "-F", "VENDOR_QA"])
                .run()
                .unwrap();
            Cmd::new(tool, &["-t", "filter", "-X", "VENDOR_QA"])
                .run()
                .unwrap();
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn repair_retry_keeps_one_undo_and_requires_a_saved_journal() {
        let dir = std::env::temp_dir().join(format!("u60-ensure-{}", std::process::id()));
        private_dir(&dir).unwrap();
        let mut tx = Transaction::new(dir.join("journal.json"));
        let file = dir.join("effect");
        let mut step = touch_step(&file);
        step.apply = Cmd::new("false", &[]);
        assert!(tx.ensure(step.clone()).is_err());
        assert!(tx.ensure(step).is_err());
        assert_eq!(tx.undo.len(), 1);
        tx.ensure(touch_step(&file)).unwrap();
        assert_eq!(tx.undo.len(), 1);
        tx.rollback().unwrap();
        assert!(!file.exists());
        fs::remove_dir_all(dir).unwrap();
    }

}
