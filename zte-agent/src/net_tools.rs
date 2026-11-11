//! Private device effects shared by the optional network modules. No shell,
//! bounded commands, private atomic files and an on-disk rollback journal.

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
        if self.program == "@u60-relay-ipa" {
            return crate::wifi_relay::offload::command(&self.args).map(|_| String::new());
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
        if matches!(self.program.as_str(), "iptables" | "ip6tables") {
            let table = self
                .args
                .windows(2)
                .find(|a| a[0] == "-t")
                .map(|a| a[1].as_str())
                .unwrap_or("filter");
            // If the tool/table itself is unavailable, that is NOT evidence
            // that our rule is absent. Preserve the journal for recovery.
            Cmd::new(&self.program, &["-w", "2", "-t", table, "-S"]).run()?;
            if let Some(i) = self.args.iter().position(|a| a == "-D") {
                let mut check = self.clone();
                check.args[i] = "-C".into();
                if check.run().is_err() {
                    return Ok(());
                }
            }
            if let Some(i) = self.args.iter().position(|a| a == "-X") {
                let mut check = self.clone();
                check.args[i] = "-S".into();
                if check.run().is_err() {
                    return Ok(());
                }
            }
        }
        if self.program == "iw" && !Path::new("/sys/class/net/u60sta0").exists() {
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

    /// Whether the effect of this (applied) command is still in place.
    fn present(&self) -> Result<bool, String> {
        let value = |name: &str| self.args.windows(2).find(|w| w[0] == name).map(|w| w[1].as_str());
        match self.program.as_str() {
            "iptables" | "ip6tables" => {
                let Some(at) = self.args.iter().position(|a| matches!(a.as_str(), "-N" | "-I" | "-A")) else { return Ok(true) };
                let mut check = self.clone();
                if check.args[at] == "-N" {
                    check.args[at] = "-S".into();
                } else {
                    if check.args[at] == "-I" && check.args.get(at + 2).is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit())) {
                        check.args.remove(at + 2);
                    }
                    check.args[at] = "-C".into();
                }
                Ok(check.run().is_ok())
            }
            "ip" => {
                let family = self.args[0].as_str();
                match self.args[1].as_str() {
                    "rule" => {
                        let Some(pref) = value("pref") else { return Ok(true) };
                        let rules = Cmd::new("ip", &[family, "rule", "show"]).run()?;
                        Ok(rules.lines().any(|l| l.trim_start().starts_with(&format!("{pref}:"))))
                    }
                    "route" => {
                        let (kind, destination) = route_target(&self.args);
                        let table = value("table").unwrap_or("main");
                        let mut show = vec![family, "route", "show", "table", table, "type", kind, "exact", destination];
                        if let Some(device) = value("dev") {
                            show.extend(["dev", device]);
                        }
                        Ok(Cmd::new("ip", &show).run().is_ok_and(|s| !s.is_empty()))
                    }
                    "addr" => {
                        let Some(device) = value("dev") else { return Ok(true) };
                        let all = Cmd::new("ip", &["-o", family, "addr", "show", "dev", device]).run()?;
                        Ok(all.split_whitespace().any(|s| s == self.args[3]))
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
            "@u60-relay-portal-return" => crate::wifi_relay::portal::return_first(&self.args),
            _ => Ok(true),
        }
    }
}

const UNKNOWN_STEP: &str = "Unknown agent step";

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

    /// Whether `undo` is journaled (an adopted journal's record of a step).
    pub fn holds(&self, undo: &Cmd) -> bool {
        self.undo.contains(undo)
    }

    /// Re-takes a step of an adopted journal: journaled if it is not, applied
    /// only if its effect is gone (a previous agent may have died before or
    /// after applying it), then kept for `reconcile`.
    pub fn adopt(&mut self, step: Step) -> Result<(), String> {
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
    /// decides when. One change that cannot be checked or re-applied does
    /// not stop the rest.
    pub fn reconcile(&mut self) -> Reconciled {
        self.reconcile_only(|_| true)
    }

    /// `reconcile` limited to the changes `keep` selects (an owner that
    /// repairs the rest itself, with stricter checks).
    pub fn reconcile_only(&mut self, keep: impl Fn(&Cmd) -> bool) -> Reconciled {
        let mut result = Reconciled::default();
        for (apply, _) in self.desired.clone().into_iter().filter(|(apply, _)| keep(apply)) {
            let line = format!("{} {}", apply.program, apply.args.join(" "));
            match apply.present().and_then(|present| if present { Ok(false) } else { apply.run().map(|_| true) }) {
                Ok(true) => result.restored.push(line),
                Ok(false) => {}
                Err(e) => result.failed.push(format!("{line}: {e}")),
            }
        }
        result
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
    /// to an owned `U60_*` chain or matches only our interfaces or comment
    /// (`foreign_identity`). Never retry a failed restore as individual
    /// commands: it may be partly applied. Radio and daemon changes use `apply`.
    pub fn apply_network(&mut self, steps: Vec<Step>) -> Result<(), String> {
        if steps.is_empty() {
            return Ok(());
        }
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
        if !self.undo.contains(&step.undo) {
            self.undo.push(step.undo.clone());
        }
        self.save()?;
        step.apply.run()?;
        self.remember(&step);
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<(), String> {
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
/// owned chain nor matches one of our interfaces or our comment.
#[cfg(test)]
pub fn foreign_identity(plan: &[Step]) -> Vec<&Step> {
    plan.iter()
        .filter(|step| {
            let args = &step.undo.args;
            if !matches!(step.undo.program.as_str(), "iptables" | "ip6tables") {
                return false;
            }
            let Some(at) = args.iter().position(|a| a == "-D") else {
                return false;
            };
            if args
                .get(at + 1)
                .is_some_and(|chain| chain.starts_with("U60_"))
            {
                return false;
            }
            let values = |flag: &str| {
                args.windows(2)
                    .filter(|w| w[0] == flag)
                    .map(|w| w[1].clone())
                    .collect::<Vec<_>>()
            };
            let owned_target = values("-j").iter().any(|t| t.starts_with("U60_"));
            let owned_interface = values("-i")
                .iter()
                .chain(&values("-o"))
                .any(|name| name.starts_with("u60"));
            let owned_comment = values("--comment")
                .iter()
                .any(|c| c.starts_with("zte-agent"));
            !(owned_target || owned_interface || owned_comment)
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
mod tests {
    use super::*;

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
        let all = "default via 10.0.0.1 dev u60sta0 table 60631\nlocal ::1 dev lo table local proto kernel metric 0";
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
        assert_eq!(foreign_identity(&plan).len(), 1);
        assert_eq!(foreign_identity(&plan)[0].undo, foreign.undo);
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
