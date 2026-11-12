use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::*;
use crate::net_tools::{Listings, Probe, Reconciled, Step};
use super::legacy as firewall;

#[cfg(test)]
#[path = "tests.rs"]
pub(crate) mod tests;

pub struct EffectSet {
    owner: &'static str,
    path: PathBuf,
    undo: Vec<Cmd>,
    held: Vec<Held>,
    #[cfg(test)]
    journal_writes: std::cell::Cell<usize>,
}

struct Held {
    resource: Resource,
    undo: Cmd,
    tables: Option<NftTables>,
    withdrawing: bool,
    obsolete: Vec<Cmd>,
    observed: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
struct Journal {
    boot: String,
    undo: Vec<Cmd>,
}

impl EffectSet {
    #[cfg(test)]
    pub(crate) fn assume(&mut self, resources: Vec<Resource>) {
        for resource in resources {
            let undo = resource.undo(|_| Ok("1".into())).unwrap();
            self.undo.push(undo.clone());
            self.undo.extend(resource.extra_undos());
            self.held.push(Held { resource, undo, tables: None, withdrawing: false, obsolete: Vec::new(), observed: None });
        }
    }

    #[cfg(test)]
    pub(crate) fn journal(&self) -> serde_json::Value {
        serde_json::json!({"boot": "BOOT", "undo": self.undo})
    }
    pub fn new(owner: &'static str, path: PathBuf) -> Self {
        Self { owner, path, undo: Vec::new(), held: Vec::new(), #[cfg(test)] journal_writes: std::cell::Cell::new(0) }
    }

    pub fn current(path: &Path) -> bool {
        Self::read(path).is_ok_and(|journal| journal.boot == net::boot_id())
    }

    fn read(path: &Path) -> Result<Journal, String> {
        serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|_| "Network recovery journal is invalid".into())
    }

    pub fn load(owner: &'static str, path: &Path) -> Result<Self, String> {
        let journal = Self::read(path)?;
        if journal.boot != net::boot_id() {
            return Err("The network journal is from another boot".into());
        }
        Ok(Self { owner, path: path.into(), undo: journal.undo, held: Vec::new(), #[cfg(test)] journal_writes: std::cell::Cell::new(0) })
    }

    pub fn recover(path: &Path) -> Result<(), String> {
        Self::recover_with(path, &mut net::Device)
    }

    fn recover_with(path: &Path, probe: &mut impl Probe) -> Result<(), String> {
        if !path.exists() {
            return Ok(());
        }
        let journal = Self::read(path)?;
        if !journal.boot.is_empty() && journal.boot != net::boot_id() {
            return fs::remove_file(path).map_err(|error| error.to_string());
        }
        Self { owner: "recovery", path: path.into(), undo: journal.undo, held: Vec::new(), #[cfg(test)] journal_writes: std::cell::Cell::new(0) }.release_with(probe)
    }

    pub fn journaled(&self, program: &str, first: &str) -> Option<&Cmd> {
        self.undo.iter().find(|undo| undo.program == program && undo.args.first().map(String::as_str) == Some(first))
    }

    fn save(&self) -> Result<(), String> {
        #[cfg(test)]
        self.journal_writes.set(self.journal_writes.get() + 1);
        net::write_private(&self.path, &serde_json::to_vec(&Journal { boot: net::boot_id(), undo: self.undo.clone() }).map_err(|error| error.to_string())?)
    }

    pub fn declare(&mut self, resources: Vec<Resource>) -> Result<(), String> {
        self.declare_with(resources, false, &mut net::Device, &mut Device)
    }

    pub fn adopt(&mut self, resources: Vec<Resource>) -> Result<(), String> {
        self.declare_with(resources, true, &mut net::Device, &mut Device)
    }

    pub(crate) fn declare_with(&mut self, resources: Vec<Resource>, adopting: bool, probe: &mut impl Probe, nft: &mut (impl Nft + ?Sized)) -> Result<(), String> {
        if resources.is_empty() {
            return Ok(());
        }
        let mut listings = Listings::default();
        let mut prepared = Vec::new();
        for resource in resources {
            validate(&resource, self.owner)?;
            let key = resource.key();
            if prepared.iter().any(|(previous, _, _): &(Resource, Cmd, bool)| previous.key() == key) {
                return Err("A network batch declares the same resource twice".into());
            }
            let held = self.held.iter().find(|held| held.resource.key() == key);
            let undo = resource.undo(|key| {
                self.journaled("@u60-sysctl", key).and_then(|undo| undo.args.get(1)).cloned().map_or_else(|| probe.sysctl(key), Ok)
            })?;
            let owned = held.is_some() || (adopting && self.undo.contains(&undo));
            if !owned {
                let table_held = match &resource {
                    Resource::Route(route) => self.held.iter().any(|held| matches!(&held.resource, Resource::Route(previous) if previous.family == route.family && shared::route_table(&previous.table) == shared::route_table(&route.table))),
                    _ => false,
                };
                vacant(&resource, table_held, &mut listings, probe, nft)?;
            }
            if let Resource::LegacyHook(hook) = &resource {
                if let Some(target) = hook.target() {
                    let pending = prepared.iter().any(|(resource, _, _)| matches!(resource, Resource::LegacyChain(chain) if chain.tool == hook.tool && chain.table == hook.table && chain.name == target));
                    if !pending && !firewall::has_chain(listings.get(legacy_listing(hook.tool, &hook.table), probe)?, target) {
                        return Err("The legacy hook's target chain is missing".into());
                    }
                }
            }
            if held.is_some_and(|held| held.withdrawing) {
                return Err("Network cleanup is pending".into());
            }
            prepared.push((resource, undo, owned));
        }
        for (resource, undo, _) in &prepared {
            if !self.undo.contains(undo) {
                self.undo.push(undo.clone());
            }
            for extra in resource.extra_undos() {
                if !self.undo.contains(&extra) { self.undo.push(extra); }
            }
        }
        self.save()?;
        net::changed();
        let mut indices = Vec::new();
        for (resource, undo, owned) in prepared {
            let previous = self.held.iter().find(|held| held.resource.key() == resource.key())
                .filter(|held| held.undo != undo)
                .map(|held| held.undo.clone());
            let index = match self.held.iter().position(|held| held.resource.key() == resource.key()) {
                Some(index) => {
                    if self.held[index].resource != resource { self.held[index].observed = None; }
                    self.held[index].resource = resource;
                    self.held[index].undo = undo;
                    if let Some(previous) = previous {
                        if !self.held[index].obsolete.contains(&previous) {
                            self.held[index].obsolete.push(previous);
                        }
                    }
                    index
                }
                None => {
                    let tables = match &resource {
                        Resource::NftTable(table) => Some(NftTables::new(table.owner, table.name, table.file.clone())),
                        _ => None,
                    };
                    self.held.push(Held { resource, undo, tables, withdrawing: false, obsolete: Vec::new(), observed: None });
                    self.held.len() - 1
                }
            };
            indices.push((index, owned));
        }
        let mut pending = Restore::default();
        for (index, owned) in indices {
            if !self.held[index].obsolete.is_empty() {
                pending.run(probe)?;
                self.clear_obsolete(index, probe)?;
                listings = Listings::default();
            }
            if !matches!(self.held[index].resource, Resource::LegacyChain(_) | Resource::LegacyHook(_)) && pending.tool.is_some() {
                pending.run(probe)?;
                listings = Listings::default();
            }
            let held = &mut self.held[index];
            let imperative = matches!(&held.resource, Resource::Internal(internal) if super::internal::handler(internal.name).is_some_and(|handler| handler.check.is_none()));
            let pending_target = matches!(&held.resource, Resource::LegacyHook(hook) if hook.target().is_some_and(|target| pending.input.contains(&format!("-N {target}\n"))));
            let repair = if (adopting || owned) && !(imperative && !adopting) && !pending_target {
                repair(&held.resource, &mut listings, probe)?
            } else {
                initial(&held.resource)?
            };
            if let Repair::Legacy(tool, table, lines) = repair {
                if pending.tool.is_some_and(|current| current != tool) {
                    pending.run(probe)?;
                    listings = Listings::default();
                }
                pending.push(tool, &table, lines);
                continue;
            }
            pending.run(probe)?;
            listings = Listings::default();
            if let Resource::Sysctl(setting) = &held.resource {
                crate::net_guard::hold(&self.path.to_string_lossy(), &setting.key, &setting.value);
            }
            if let Resource::NftTable(table) = &held.resource {
                if let Some(families) = &table.families {
                    let tables = held.tables.as_mut().unwrap();
                    if owned && tables.target.is_none() {
                        tables.adopt(families.clone(), nft)?;
                    } else {
                        tables.declare(families.clone(), nft)?;
                    }
                }
            } else if let Repair::Command(command) = repair {
                net::changed();
                probe.apply(&command)?;
            }
        }
        pending.run(probe)
    }

    pub fn step(&mut self, step: Step) -> Result<(), String> {
        if !self.undo.contains(&step.undo) {
            self.undo.push(step.undo);
        }
        self.save()?;
        net::changed();
        step.apply.run().map(|_| ())
    }

    fn clear_obsolete(&mut self, index: usize, probe: &mut impl Probe) -> Result<(), String> {
        while let Some(previous) = self.held[index].obsolete.last().cloned() {
            net::changed();
            probe.undo(&previous)?;
            self.undo.retain(|undo| *undo != previous);
            self.save()?;
            self.held[index].obsolete.pop();
        }
        Ok(())
    }

    pub fn withdraw(&mut self, keys: &[Key]) -> Result<(), String> {
        self.withdraw_with(keys, &mut net::Device)
    }

    fn withdraw_with(&mut self, keys: &[Key], probe: &mut impl Probe) -> Result<(), String> {
        let mut selected = Vec::new();
        for held in &mut self.held {
            if keys.contains(&held.resource.key()) {
                held.withdrawing = true;
                selected.push(held.undo.clone());
                selected.extend(held.resource.extra_undos());
                selected.extend(held.obsolete.iter().cloned());
            }
        }
        self.remove(&selected, probe)
    }

    fn remove(&mut self, selected: &[Cmd], probe: &mut impl Probe) -> Result<(), String> {
        net::changed();
        for index in (0..self.undo.len()).rev() {
            let undo = &self.undo[index];
            if !selected.contains(undo) {
                continue;
            }
            if undo.program == "@u60-sysctl" {
                if let Some(key) = undo.args.first() {
                    crate::net_guard::release(&self.path.to_string_lossy(), Some(key));
                }
            }
            if let Err(error) = probe.undo(undo) {
                self.save()?;
                return Err(format!("Network cleanup paused: {error}. Retry cleanup in the panel; if it persists, use network-recover over USB ADB"));
            }
            self.held.retain(|held| held.undo != *undo);
            for held in &mut self.held {
                held.obsolete.retain(|obsolete| obsolete != undo);
            }
            self.undo.remove(index);
        }
        if self.undo.is_empty() {
            match fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        } else {
            self.save()?;
        }
        Ok(())
    }

    pub fn release(&mut self) -> Result<(), String> {
        self.release_with(&mut net::Device)
    }

    fn release_with(&mut self, probe: &mut impl Probe) -> Result<(), String> {
        self.held.iter_mut().for_each(|held| held.withdrawing = true);
        crate::net_guard::release(&self.path.to_string_lossy(), None);
        self.remove(&self.undo.clone(), probe)
    }

    pub fn reconcile(&mut self) -> Reconciled {
        self.reconcile_only(|_| true)
    }

    pub fn reconcile_only(&mut self, keep: impl Fn(&Resource) -> bool) -> Reconciled {
        self.reconcile_selected(keep, &mut net::Device, &mut Device)
    }

    #[cfg(test)]
    pub(crate) fn reconcile_with(&mut self, probe: &mut impl Probe, nft: &mut impl Nft) -> Reconciled {
        self.reconcile_selected(|_| true, probe, nft)
    }

    pub(crate) fn reconcile_selected(&mut self, keep: impl Fn(&Resource) -> bool, probe: &mut impl Probe, nft: &mut (impl Nft + ?Sized)) -> Reconciled {
        net::with_listings(|listings| {
            let mut result = Reconciled::default();
            for index in 0..self.held.len() {
                if self.held[index].withdrawing || !keep(&self.held[index].resource) {
                    continue;
                }
                if !self.held[index].obsolete.is_empty() {
                    let cleaned = self.clear_obsolete(index, probe);
                    *listings = Listings::default();
                    if let Err(error) = cleaned {
                        result.failed.push(format!("resource replacement: not checked: {error}"));
                        continue;
                    }
                }
                let held = &mut self.held[index];
                let label = held.resource.label();
                if let Some(tables) = held.tables.as_mut() {
                    match tables.reconcile(nft) {
                        Ok(true) => {
                            *listings = Listings::default();
                            result.restored.push(label.clone());
                        }
                        Ok(false) => {}
                        Err(error) => result.failed.push(format!("{label}: {error}")),
                    }
                    continue;
                }
                if let (Resource::LegacyChain(chain), Some(observed)) = (&held.resource, &held.observed) {
                    match listings.get(legacy_listing(chain.tool, &chain.table), probe) {
                        Ok(text) if firewall::has_chain(text, &chain.name) && chain_rules(text, &chain.name) == *observed => continue,
                        _ => {}
                    }
                }
                match repair(&held.resource, listings, probe) {
                    Ok(Repair::None) => {}
                    Ok(repair) => {
                        net::changed();
                        let applied = match repair {
                            Repair::Command(command) => probe.apply(&command),
                            Repair::Legacy(tool, table, lines) => {
                                let mut batch = Restore::default();
                                batch.push(tool, &table, lines);
                                batch.run(probe)
                            }
                            Repair::None => unreachable!(),
                        };
                        *listings = Listings::default();
                        match applied {
                            Ok(()) => {
                                if let Resource::LegacyChain(chain) = &held.resource {
                                    if let Ok(text) = listings.get(legacy_listing(chain.tool, &chain.table), probe) {
                                        let actual = chain_rules(text, &chain.name);
                                        if chain_lines(chain, true).is_ok_and(|lines| lines[1..] != actual) {
                                            unexpected(&label);
                                            held.observed = Some(actual);
                                        }
                                    }
                                }
                                result.restored.push(label);
                            }
                            Err(error) => result.failed.push(format!("{label}: {error}")),
                        }
                    }
                    Err(error) => result.failed.push(format!("{label}: not checked: {error}")),
                }
            }
            result
        })
    }

    pub fn tables_status(&self, name: &str) -> Value {
        self.held.iter().filter_map(|held| held.tables.as_ref()).find(|tables| tables.name == name).map_or(Value::Null, NftTables::status)
    }

    pub fn tables_confirmed(&self, name: &str) -> bool {
        self.held.iter().filter_map(|held| held.tables.as_ref()).find(|tables| tables.name == name).is_some_and(NftTables::confirmed)
    }
}

fn validate(resource: &Resource, owner: &str) -> Result<(), String> {
    match resource {
        Resource::NftTable(table) if table.owner != owner => return Err("The nftables table has another owner".into()),
        Resource::LegacyChain(chain) => {
            if !chain.name.starts_with("U60_") || !safe(&chain.name) || !safe(&chain.table) {
                return Err("Invalid owned legacy chain".into());
            }
            chain_lines(chain, false)?;
        }
        Resource::LegacyHook(hook) => {
            let owned = hook.rule.windows(2).any(|pair| (pair[0] == "-j" && pair[1].starts_with("U60_")) || (pair[0] == "--comment" && pair[1].starts_with("zte-agent")));
            if !owned || !safe(&hook.chain) || !safe(&hook.table) {
                return Err("A legacy hook needs an owned identity".into());
            }
            hook_line(hook)?;
        }
        Resource::Sysctl(setting) => {
            shared::sysctl_path(&setting.key).ok_or("Unknown kernel setting")?;
        }
        _ => {}
    }
    Ok(())
}

fn safe(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn legacy_listing(tool: LegacyTool, table: &str) -> Cmd {
    Cmd::new(tool.program(), &["-w", "2", "-t", table, "-S"])
}

fn vacant(resource: &Resource, table_held: bool, listings: &mut Listings, probe: &mut impl Probe, nft: &mut (impl Nft + ?Sized)) -> Result<(), String> {
    let occupied = match resource {
        Resource::NftTable(table) => {
            NftTables::new(table.owner, table.name, table.file.clone()).presence(nft)? != Presence::Absent
        }
        Resource::LegacyChain(chain) => firewall::has_chain(listings.get(legacy_listing(chain.tool, &chain.table), probe)?, &chain.name),
        Resource::LegacyHook(hook) => {
            let text = listings.get(legacy_listing(hook.tool, &hook.table), probe)?;
            text.lines().any(|line| Some(line) == hook_line(hook).ok().as_deref())
        }
        Resource::Route(route) => {
            let text = listings.get(Cmd::new("ip", &[route.family.flag(), "route", "show", "table", "all"]), probe)?;
            if table_held || matches!(route.table.as_str(), "main" | "254") { route_present(route, text) } else { table_used(text, &route.table) }
        }
        Resource::Rule(rule) => {
            let text = listings.get(Cmd::new("ip", &[rule.family.flag(), "rule", "show"]), probe)?;
            text.lines().any(|line| line.trim_start().starts_with(&format!("{}:", rule.priority)))
        }
        Resource::Addr(addr) => {
            let text = listings.get(Cmd::new("ip", &["-o", addr.family.flag(), "addr", "show"]), probe)?;
            net::addr_listed(text, &addr.device, &addr.address)
        }
        Resource::Sysctl(_) | Resource::Internal(_) => false,
    };
    if occupied {
        Err(match resource {
            Resource::Route(_) => "A reserved network route table is already in use",
            Resource::Rule(_) => "A reserved network rule priority is already in use",
            _ => "A reserved network resource is already in use",
        }.into())
    } else {
        Ok(())
    }
}

enum Repair {
    None,
    Command(Cmd),
    Legacy(LegacyTool, String, Vec<String>),
}

fn initial(resource: &Resource) -> Result<Repair, String> {
    Ok(match resource {
        Resource::LegacyChain(chain) => Repair::Legacy(chain.tool, chain.table.clone(), chain_lines(chain, false)?),
        Resource::LegacyHook(hook) => Repair::Legacy(hook.tool, hook.table.clone(), vec![hook_insert(hook)?]),
        _ => resource.command().map_or(Repair::None, Repair::Command),
    })
}

fn chain_lines(chain: &LegacyChain, replace: bool) -> Result<Vec<String>, String> {
    let mut lines = vec![if replace { format!(":{} - [0:0]", chain.name) } else { format!("-N {}", chain.name) }];
    for rule in &chain.rules {
        lines.push(firewall::listed(chain.tool == LegacyTool::V6, &chain.name, rule).ok_or("Unsupported legacy rule description")?);
    }
    Ok(lines)
}

fn hook_line(hook: &LegacyHook) -> Result<String, String> {
    firewall::listed(hook.tool == LegacyTool::V6, &hook.chain, &hook.rule).ok_or_else(|| "Unsupported legacy hook description".into())
}

fn hook_insert(hook: &LegacyHook) -> Result<String, String> {
    let line = hook_line(hook)?;
    Ok(line.replacen(&format!("-A {}", hook.chain), &format!("-I {} 1", hook.chain), 1))
}

fn chain_rules(text: &str, name: &str) -> Vec<String> {
    text.lines().filter(|line| line.starts_with(&format!("-A {name} "))).map(str::to_owned).collect()
}

fn unexpected(label: &str) {
    static SEEN: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let mut seen = SEEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if !seen.iter().any(|seen| seen == label) {
        seen.push(label.into());
        crate::netlog!("[net] listed in a form not predicted: {label}");
    }
}

fn repair(resource: &Resource, listings: &mut Listings, probe: &mut impl Probe) -> Result<Repair, String> {
    let present = match resource {
        Resource::NftTable(_) => return Ok(Repair::None),
        Resource::LegacyChain(chain) => {
            let text = listings.get(legacy_listing(chain.tool, &chain.table), probe)?;
            let exists = firewall::has_chain(text, &chain.name);
            let desired = chain_lines(chain, exists)?;
            let prefix = format!("-A {} ", chain.name);
            let actual: Vec<&str> = text.lines().filter(|line| line.starts_with(&prefix)).collect();
            return Ok(if exists && actual == desired[1..] { Repair::None } else { Repair::Legacy(chain.tool, chain.table.clone(), desired) });
        }
        Resource::LegacyHook(hook) => {
            let text = listings.get(legacy_listing(hook.tool, &hook.table), probe)?;
            let desired = hook_line(hook)?;
            let prefix = format!("-A {} ", hook.chain);
            let rules: Vec<&str> = text.lines().filter(|line| line.starts_with(&prefix)).collect();
            let copies: Vec<usize> = rules.iter().enumerate().filter_map(|(index, line)| (*line == desired).then_some(index)).collect();
            let missing_target = hook.rule.windows(2).any(|pair| pair[0] == "-j" && pair[1].starts_with("U60_") && !firewall::has_chain(text, &pair[1]));
            if missing_target { return Err("The legacy hook's target chain is missing".into()); }
            if copies.is_empty() && firewall::has_chain(text, &hook.chain) && !missing_target {
                let status = probe.status(&hook.command("-C", None))?;
                if status.0 == 0 {
                    unexpected(&format!("{} -t {} chain {}", hook.tool.program(), hook.table, hook.chain));
                    return Ok(Repair::None);
                }
                if !firewall::no_rule(&status) {
                    return Err(format!("cannot establish hook position (check exited {})", status.0));
                }
            }
            let in_place = copies.len() == 1 && match hook.position {
                Position::InsertFirst => true,
                Position::BeforeVendor => rules[..copies[0]].iter().all(|line| line.contains("-j U60_") || line.contains("--comment zte-agent")),
            };
            if in_place {
                return Ok(Repair::None);
            }
            let mut lines = vec![desired.replacen("-A ", "-D ", 1); copies.len()];
            lines.push(hook_insert(hook)?);
            return Ok(Repair::Legacy(hook.tool, hook.table.clone(), lines));
        }
        Resource::Route(route) => route_present(route, listings.get(Cmd::new("ip", &[route.family.flag(), "route", "show", "table", "all"]), probe)?),
        Resource::Rule(rule) => {
            let text = listings.get(Cmd::new("ip", &[rule.family.flag(), "rule", "show"]), probe)?;
            let prefix = format!("{}:", rule.priority);
            let rows: Vec<_> = text.lines().filter(|line| line.trim_start().starts_with(&prefix)).collect();
            if rows.is_empty() { false } else {
                let mut expected = vec![prefix, "from".into(), "all".into()];
                if let Some(mark) = &rule.mark { expected.extend(["fwmark".into(), mark.clone()]); }
                expected.extend(["lookup".into(), rule.table.clone()]);
                if rows.len() != 1 || rows[0].split_whitespace().collect::<Vec<_>>() != expected {
                    return Err("Policy priority is shared or belongs to another writer".into());
                }
                true
            }
        }
        Resource::Addr(addr) => net::addr_listed(listings.get(Cmd::new("ip", &["-o", addr.family.flag(), "addr", "show"]), probe)?, &addr.device, &addr.address),
        Resource::Sysctl(setting) => probe.sysctl(&setting.key)? == setting.value,
        Resource::Internal(internal) => probe.internal(internal.name, &internal.apply)?,
    };
    Ok(if present { Repair::None } else { resource.command().map_or(Repair::None, Repair::Command) })
}

fn table_used(text: &str, table: &str) -> bool {
    text.lines().any(|line| line.split_whitespace().collect::<Vec<_>>().windows(2).any(|pair| pair[0] == "table" && shared::route_table(pair[1]) == shared::route_table(table)))
}

fn route_present(route: &Route, text: &str) -> bool {
    shared::route_matches(text, route.kind.name(), &route.destination, &route.table, route.device.as_deref(), route.gateway.as_deref(), route.metric)
}

#[derive(Default)]
struct Restore {
    tool: Option<LegacyTool>,
    table: String,
    input: String,
}

impl Restore {
    fn push(&mut self, tool: LegacyTool, table: &str, lines: Vec<String>) {
        self.tool = Some(tool);
        firewall::append(&mut self.input, &self.table, table, &lines);
        self.table = table.into();
    }

    fn run(&mut self, probe: &mut impl Probe) -> Result<(), String> {
        let Some(tool) = self.tool.take() else { return Ok(()) };
        self.input.push_str("COMMIT\n");
        self.table.clear();
        net::changed();
        probe.restore(tool.restore(), std::mem::take(&mut self.input))
    }
}
