use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::netfx::effect::legacy;

pub use crate::netfx::exec::{owned_child, owned_reader, run, run_input, stop_child};
pub use crate::netfx::files::{private_dir, write_private};
pub use crate::netfx::effect::shared::{Listings, Pass, sysctl_read, sysctl_write};
pub(crate) use crate::netfx::effect::shared::{addr_listed, changed, sysctl_command, with_listings};

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyRule { Missing, Owned, Foreign, Shared }

pub fn plain_policy_rule(family: &str, priority: &str, table: &str) -> Result<PolicyRule, String> {
    policy_rule_state(&Cmd::new("ip", &["-j", family, "rule", "show"]).run()?, priority, table)
}

fn policy_rule_state(text: &str, priority: &str, table: &str) -> Result<PolicyRule, String> {
    let rows: Vec<serde_json::Value> = serde_json::from_str(text).map_err(|_| "Cannot inspect policy rules")?;
    let priority: u64 = priority.parse().map_err(|_| "Invalid policy priority")?;
    let matches: Vec<_> = rows.iter().filter(|row| row["priority"].as_u64() == Some(priority)).collect();
    if matches.is_empty() { return Ok(PolicyRule::Missing); }
    if matches.len() != 1 { return Ok(PolicyRule::Shared); }
    let rule = matches[0];
    let known = ["priority", "src", "dst", "from", "to", "table", "protocol", "flags", "action"];
    let plain = rule.as_object().is_some_and(|map| map.keys().all(|key| known.contains(&key.as_str())))
        && ["src", "dst", "from", "to"].iter().all(|key| rule[*key].is_null() || matches!(rule[*key].as_str(), Some("all" | "0.0.0.0/0" | "::/0")))
        && (rule["flags"].is_null() || rule["flags"].as_array().is_some_and(Vec::is_empty))
        && (rule["action"].is_null() || rule["action"] == "to_tbl")
        && (rule["table"] == table || rule["table"].as_u64() == table.parse().ok());
    Ok(if plain { PolicyRule::Owned } else { PolicyRule::Foreign })
}

pub fn route_table_listed(family: &str, table: &str) -> Result<bool, String> {
    let all = Cmd::new("ip", &[family, "route", "show", "table", "all"]).run()?;
    Ok(lists_table(&all, table))
}

fn lists_table(routes: &str, table: &str) -> bool {
    routes.lines().any(|line| line.split_whitespace().collect::<Vec<_>>().windows(2).any(|pair| pair == ["table", table]))
}

pub fn route_target(args: &[String]) -> (&str, &str) {
    let kind = args[3].as_str();
    if matches!(kind, "throw" | "local" | "unreachable") { (kind, args[4].as_str()) } else { ("unicast", kind) }
}

pub type NetworkLock = Arc<Mutex<()>>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cmd { pub program: String, pub args: Vec<String> }

impl Cmd {
    pub fn new(program: &str, args: &[&str]) -> Self {
        Self { program: program.into(), args: args.iter().map(|value| (*value).into()).collect() }
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args).stdin(Stdio::null());
        command
    }

    pub fn run(&self) -> Result<String, String> {
        if let Some(handler) = crate::netfx::effect::internal::handler(&self.program) {
            return (handler.apply)(&self.args).map(|_| String::new());
        }
        if self.program.starts_with('@') { return Err(format!("{UNKNOWN_STEP} {}", self.program)); }
        let out = run(self.command(), Duration::from_secs(8))?;
        if self.program == "hostapd_cli" && self.args.iter().any(|arg| matches!(arg.as_str(), "set" | "disable" | "enable")) && out.lines().last() != Some("OK") {
            return Err("Hostapd refused the runtime change".into());
        }
        if self.program == "wpa_cli" && self.args.iter().any(|arg| matches!(arg.as_str(), "SETROAMMODE" | "reconfigure")) && out.lines().last() != Some("OK") {
            return Err("Wi-Fi control refused the runtime change".into());
        }
        Ok(out)
    }

    pub(crate) fn undo(&self) -> Result<(), String> {
        if self.program == "ip" && self.args.len() == 7 && self.args[1..4] == ["rule", "del", "pref"] && self.args[5] == "lookup" {
            match plain_policy_rule(&self.args[0], &self.args[4], &self.args[6])? {
                PolicyRule::Owned => {}
                PolicyRule::Missing | PolicyRule::Foreign => return Ok(()),
                PolicyRule::Shared => return Err("Policy priority is shared; cleanup paused".into()),
            }
        }
        if crate::wifi_relay::hotspot::skip_undo(self) { return Ok(()); }
        if crate::wifi_relay::power_save::is_restore(self) {
            if let Err(error) = self.run() { crate::netlog!("[relay] upstream Wi-Fi power save not restored: {error}"); }
            return Ok(());
        }
        if matches!(self.program.as_str(), "iptables" | "ip6tables") && self.args.iter().any(|arg| arg == "-D" || arg == "-X") {
            return legacy::undo(self, &mut Device);
        }
        let error = match self.run() { Ok(_) => return Ok(()), Err(error) => error };
        if error.starts_with(UNKNOWN_STEP) {
            crate::netlog!("[net] skipped an undo this agent version does not know: {} {}", self.program, self.args.join(" "));
            return Ok(());
        }
        if crate::wifi_relay::hotspot::skip_undo(self) { return Ok(()); }
        if self.program == "iw" && matches!(self.args.as_slice(), [dev, name, ..] if dev == "dev" && !Path::new("/sys/class/net").join(name).exists()) { return Ok(()); }
        if self.program == "ip" && self.args.get(2).map(String::as_str) == Some("del") {
            let family = self.args[0].as_str();
            let value = |name| self.args.windows(2).find(|pair| pair[0] == name).map(|pair| pair[1].as_str());
            match self.args[1].as_str() {
                "rule" => {
                    let rules = Cmd::new("ip", &[family, "rule", "show"]).run()?;
                    if value("pref").is_some_and(|priority| !rules.lines().any(|line| line.trim_start().starts_with(&format!("{priority}:")))) { return Ok(()); }
                }
                "route" => {
                    if let Some(table) = value("table") {
                        let (kind, destination) = route_target(&self.args);
                        let device = value("dev");
                        if device.is_some_and(|device| !Path::new(&format!("/sys/class/net/{device}")).exists()) { return Ok(()); }
                        let mut show = vec![family, "route", "show", "table", table, "type", kind, "exact", destination];
                        if let Some(device) = device { show.extend(["dev", device]); }
                        if Cmd::new("ip", &show).run().is_ok_and(|text| text.is_empty()) { return Ok(()); }
                        if !route_table_listed(family, table)? { return Ok(()); }
                    }
                }
                "addr" => {
                    if let Some(iface) = value("dev") {
                        if !Path::new(&format!("/sys/class/net/{iface}")).exists() { return Ok(()); }
                        let all = Cmd::new("ip", &["-o", family, "addr", "show", "dev", iface]).run()?;
                        if !all.split_whitespace().any(|value| value == self.args[3]) { return Ok(()); }
                    }
                }
                _ => {}
            }
        }
        Err(if self.program.starts_with("@u60-relay-") { error } else { "Cannot restore an owned network change".into() })
    }
}

const UNKNOWN_STEP: &str = "Unknown agent step";

pub(crate) trait Probe {
    fn list(&mut self, cmd: &Cmd) -> Result<String, String>;
    fn status(&mut self, cmd: &Cmd) -> Result<(i32, String), String>;
    fn apply(&mut self, cmd: &Cmd) -> Result<(), String>;
    fn restore(&mut self, program: &str, input: String) -> Result<(), String> { legacy::restore(program, input) }
    fn undo(&mut self, cmd: &Cmd) -> Result<(), String> { cmd.undo() }
    fn sysctl(&mut self, key: &str) -> Result<String, String> { sysctl_read(key) }
    fn internal(&mut self, name: &str, args: &[String]) -> Result<bool, String> {
        match crate::netfx::effect::internal::handler(name).and_then(|handler| handler.check) { Some(check) => check(args), None => Ok(true) }
    }
}

pub(crate) struct Device;
impl Probe for Device {
    fn list(&mut self, cmd: &Cmd) -> Result<String, String> { cmd.run() }
    fn status(&mut self, cmd: &Cmd) -> Result<(i32, String), String> { crate::netfx::exec::run_report(cmd.command(), Duration::from_secs(8)) }
    fn apply(&mut self, cmd: &Cmd) -> Result<(), String> { cmd.run().map(|_| ()) }
}

pub fn nft_chain_rules(text: &str) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    let mut current: Option<(String, usize)> = None;
    for line in text.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("chain ").and_then(|line| line.strip_suffix(" {")) { current = Some((name.to_owned(), 0)); }
        else if line == "}" { if let Some((name, count)) = current.take() { counts.insert(name, count); } }
        else if let Some((_, count)) = current.as_mut() { if !line.is_empty() && !line.starts_with("type ") { *count += 1; } }
    }
    counts
}

pub fn key<'a>(text: &'a str, name: &str) -> Option<&'a str> { text.lines().find_map(|line| line.strip_prefix(name)?.strip_prefix('=')) }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Step { pub apply: Cmd, pub undo: Cmd }
impl Step { pub fn new(apply: Cmd, undo: Cmd) -> Self { Self { apply, undo } } }

#[derive(Debug, Default)]
pub struct Reconciled { pub restored: Vec<String>, pub failed: Vec<String> }
impl Reconciled {
    pub fn extend(&mut self, other: Reconciled) { self.restored.extend(other.restored); self.failed.extend(other.failed); }
}

pub(crate) fn boot_id() -> String { fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default().trim().to_owned() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_undo_from_another_agent_version_is_skipped_not_executed() {
        let removed = Cmd::new("@u60-removed-step", &["on"]);
        assert!(removed.run().unwrap_err().starts_with(UNKNOWN_STEP));
        assert!(removed.undo().is_ok());
    }

    #[test]
    fn an_emptied_route_table_is_recognised_from_the_full_listing() {
        assert!(lists_table("default via 10.0.0.1 dev ath20 table 60631", "60631"));
        assert!(!lists_table("default via 10.0.0.1 dev ath20 table 60631", "6063"));
    }

    #[test]
    fn policy_rule_checks_selectors_before_repair_or_undo() {
        assert_eq!(policy_rule_state("[]", "60631", "60631").unwrap(), PolicyRule::Missing);
        assert_eq!(policy_rule_state(r#"[{"priority":60631,"src":"all","table":60631}]"#, "60631", "60631").unwrap(), PolicyRule::Owned);
        for text in [r#"[{"priority":60631,"src":"2001:db8::/64","table":60631}]"#, r#"[{"priority":60631,"src":"all","fwmark":1,"table":60631}]"#, r#"[{"priority":60631,"src":"all","table":100}]"#] {
            assert_eq!(policy_rule_state(text, "60631", "60631").unwrap(), PolicyRule::Foreign);
        }
        assert_eq!(policy_rule_state(r#"[{"priority":60631},{"priority":60631}]"#, "60631", "60631").unwrap(), PolicyRule::Shared);
        assert!(policy_rule_state("not json", "60631", "60631").is_err());
    }

    #[test]
    fn nft_rule_counts_match_between_a_written_ruleset_and_its_listing() {
        let written = crate::netfx::effect::table("ip", "u60_t", &[], &[("pre", "type filter hook prerouting priority 0; policy accept;", vec!["accept".into(), "return".into()])]);
        let listed = "table ip u60_t {\n chain pre {\n type filter hook prerouting priority filter; policy accept;\n accept\n return\n }\n}\n";
        assert_eq!(nft_chain_rules(&written), nft_chain_rules(listed));
        assert_eq!(nft_chain_rules(&listed.replace(" accept\n", ""))["pre"], 1);
    }
}
