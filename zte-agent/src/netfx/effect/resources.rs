use std::path::PathBuf;

use crate::net_tools::Cmd;
#[cfg(test)]
use crate::net_tools::Step;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn flag(self) -> &'static str {
        match self {
            Self::V4 => "-4",
            Self::V6 => "-6",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyTool {
    V4,
    V6,
}

impl LegacyTool {
    pub fn program(self) -> &'static str {
        match self {
            Self::V4 => "iptables",
            Self::V6 => "ip6tables",
        }
    }

    pub(super) fn restore(self) -> &'static str {
        match self {
            Self::V4 => "iptables-restore",
            Self::V6 => "ip6tables-restore",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Position {
    InsertFirst,
    BeforeVendor,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftTable {
    pub owner: &'static str,
    pub name: &'static str,
    pub file: PathBuf,
    pub families: Option<[String; 2]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyChain {
    pub tool: LegacyTool,
    pub table: String,
    pub name: String,
    pub rules: Vec<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyHook {
    pub tool: LegacyTool,
    pub table: String,
    pub chain: String,
    pub rule: Vec<String>,
    pub position: Position,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteType {
    Unicast,
    Local,
    Throw,
    Unreachable,
}

impl RouteType {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Unicast => "unicast",
            Self::Local => "local",
            Self::Throw => "throw",
            Self::Unreachable => "unreachable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub family: Family,
    pub kind: RouteType,
    pub destination: String,
    pub table: String,
    pub device: Option<String>,
    pub gateway: Option<String>,
    pub metric: Option<u32>,
    pub scope: Option<String>,
    pub source: Option<String>,
    pub mtu: Option<u32>,
    pub expires: Option<u32>,
}

impl Route {
    pub fn new(family: Family, kind: RouteType, destination: &str, table: &str) -> Self {
        Self { family, kind, destination: destination.into(), table: table.into(), device: None, gateway: None, metric: None, scope: None, source: None, mtu: None, expires: None }
    }

    pub(super) fn command(&self, action: &str) -> Cmd {
        let mut args = vec![self.family.flag().into(), "route".into(), action.into()];
        if self.kind != RouteType::Unicast {
            args.push(self.kind.name().into());
        }
        args.push(self.destination.clone());
        pair(&mut args, "via", self.gateway.as_deref());
        pair(&mut args, "dev", self.device.as_deref());
        pair(&mut args, "scope", self.scope.as_deref());
        if action == "add" || self.expires.is_none() {
            pair(&mut args, "src", self.source.as_deref());
        }
        pair(&mut args, "metric", self.metric.map(|metric| metric.to_string()).as_deref());
        if action == "add" {
            pair(&mut args, "mtu", self.mtu.map(|mtu| mtu.to_string()).as_deref());
            pair(&mut args, "expires", self.expires.map(|expires| expires.to_string()).as_deref());
        }
        pair(&mut args, "table", Some(&self.table));
        Cmd { program: "ip".into(), args }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub family: Family,
    pub priority: u32,
    pub table: String,
    pub mark: Option<String>,
}

impl Rule {
    pub(super) fn command(&self, action: &str) -> Cmd {
        let mut args = vec![self.family.flag().into(), "rule".into(), action.into(), "pref".into(), self.priority.to_string()];
        pair(&mut args, "fwmark", self.mark.as_deref());
        pair(&mut args, "lookup", Some(&self.table));
        Cmd { program: "ip".into(), args }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Addr {
    pub family: Family,
    pub device: String,
    pub address: String,
    pub broadcast: Option<String>,
    pub valid_lft: Option<u32>,
    pub preferred_lft: Option<u32>,
    pub noprefixroute: bool,
}

impl Addr {
    pub(super) fn command(&self, action: &str) -> Cmd {
        let mut args = vec![self.family.flag().into(), "addr".into(), action.into(), self.address.clone()];
        if action == "add" {
            pair(&mut args, "broadcast", self.broadcast.as_deref());
        }
        pair(&mut args, "dev", Some(&self.device));
        if action == "add" {
            pair(&mut args, "valid_lft", self.valid_lft.map(|value| value.to_string()).as_deref());
            pair(&mut args, "preferred_lft", self.preferred_lft.map(|value| value.to_string()).as_deref());
            if self.noprefixroute {
                args.push("noprefixroute".into());
            }
        }
        Cmd { program: "ip".into(), args }
    }
}

fn pair(args: &mut Vec<String>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        args.extend([key.into(), value.into()]);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sysctl {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Internal {
    pub name: &'static str,
    pub apply: Vec<String>,
    pub undo: Cmd,
}

impl Internal {
    pub fn new(name: &'static str, apply: Vec<String>, undo: Vec<String>) -> Self {
        Self { name, apply, undo: Cmd { program: name.into(), args: undo } }
    }

    pub fn with_undo(mut self, undo: Cmd) -> Self {
        self.undo = undo;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    NftTable(NftTable),
    LegacyChain(LegacyChain),
    LegacyHook(LegacyHook),
    Route(Route),
    Rule(Rule),
    Addr(Addr),
    Sysctl(Sysctl),
    Internal(Internal),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    NftTable(&'static str),
    LegacyChain(LegacyTool, String, String),
    LegacyHook(LegacyTool, String, String, Vec<String>),
    Route(Family, RouteType, String, String, Option<String>, Option<u32>),
    Rule(Family, u32),
    Addr(Family, String, String),
    Sysctl(String),
    Internal(&'static str, Cmd),
}

impl Resource {
    pub(crate) fn extra_undos(&self) -> Vec<Cmd> {
        match self {
            Self::NftTable(table) if table.owner == "relay" => vec![Cmd::new("@u60-relay-nft", &["remove", "ip6"])],
            _ => Vec::new(),
        }
    }
    pub fn label(&self) -> String {
        match self {
            Self::LegacyChain(chain) => format!("{} -t {} chain {}", chain.tool.program(), chain.table, chain.name),
            Self::LegacyHook(hook) => format!("{} -t {} hook {} {}", hook.tool.program(), hook.table, hook.chain, hook.rule.join(" ")),
            Self::NftTable(table) => format!("nftables tables {}", table.name),
            _ => self.command().map(|command| format!("{} {}", command.program, command.args.join(" "))).unwrap(),
        }
    }

    pub fn key(&self) -> Key {
        match self {
            Self::NftTable(table) => Key::NftTable(table.name),
            Self::LegacyChain(chain) => Key::LegacyChain(chain.tool, chain.table.clone(), chain.name.clone()),
            Self::LegacyHook(hook) => Key::LegacyHook(hook.tool, hook.table.clone(), hook.chain.clone(), hook.rule.clone()),
            Self::Route(route) => Key::Route(route.family, route.kind, super::shared::route_destination(&route.destination), super::shared::route_table(&route.table), route.device.clone(), route.metric),
            Self::Rule(rule) => Key::Rule(rule.family, rule.priority),
            Self::Addr(addr) => Key::Addr(addr.family, addr.device.clone(), addr.address.clone()),
            Self::Sysctl(setting) => Key::Sysctl(setting.key.clone()),
            Self::Internal(internal) => Key::Internal(internal.name, internal.undo.clone()),
        }
    }

    pub(crate) fn command(&self) -> Option<Cmd> {
        Some(match self {
            Self::Route(route) => route.command("add"),
            Self::Rule(rule) => rule.command("add"),
            Self::Addr(addr) => addr.command("add"),
            Self::Sysctl(setting) => Cmd::new("@u60-sysctl", &[&setting.key, &setting.value]),
            Self::Internal(internal) => Cmd { program: internal.name.into(), args: internal.apply.clone() },
            _ => return None,
        })
    }

    pub(crate) fn undo(&self, original: impl FnOnce(&str) -> Result<String, String>) -> Result<Cmd, String> {
        Ok(match self {
            Self::NftTable(table) => match (table.owner, table.name) {
                ("mihomo", "u60_mihomo") => Cmd::new("@u60-mihomo-nft", &["remove"]),
                ("relay", "u60_relay") => Cmd::new("@u60-relay-nft", &["remove", "ip"]),
                _ => return Err("Unknown owned nftables table".into()),
            },
            Self::LegacyChain(chain) => Cmd::new(chain.tool.program(), &["-w", "2", "-t", &chain.table, "-X", &chain.name]),
            Self::LegacyHook(hook) => hook.command("-D", None),
            Self::Route(route) => route.command("del"),
            Self::Rule(rule) => rule.command("del"),
            Self::Addr(addr) => addr.command("del"),
            Self::Sysctl(setting) => Cmd::new("@u60-sysctl", &[&setting.key, &original(&setting.key)?]),
            Self::Internal(internal) => {
                super::internal::handler(internal.name).ok_or("Unknown agent step")?;
                internal.undo.clone()
            }
        })
    }

    #[cfg(test)]
    pub(crate) fn step_with(&self, original: impl FnOnce(&str) -> Result<String, String>) -> Result<Step, String> {
        let apply = self.command().unwrap_or_else(|| match self {
            Self::NftTable(_) => Cmd::new("@u60-mihomo-nft", &["tables"]),
            _ => panic!("not a command resource"),
        });
        Ok(Step::new(apply, self.undo(original)?))
    }
}

#[cfg(test)]
pub(crate) fn test_plan(resources: Vec<Resource>) -> Vec<Step> {
    let mut steps = Vec::new();
    for resource in resources {
        match &resource {
            Resource::LegacyChain(chain) => {
                steps.push(Step::new(Cmd::new(chain.tool.program(), &["-w", "2", "-t", &chain.table, "-N", &chain.name]), resource.undo(|_| Ok("1".into())).unwrap()));
                for rule in &chain.rules {
                    let mut args = vec!["-w".into(), "2".into(), "-t".into(), chain.table.clone(), "-A".into(), chain.name.clone()];
                    args.extend(rule.clone());
                    let apply = Cmd { program: chain.tool.program().into(), args };
                    let mut undo = apply.clone();
                    undo.args[4] = "-D".into();
                    steps.push(Step::new(apply, undo));
                }
            }
            Resource::LegacyHook(hook) => steps.push(Step::new(hook.command("-I", Some(1)), resource.undo(|_| Ok("1".into())).unwrap())),
            _ => steps.push(resource.step_with(|_| Ok("1".into())).unwrap()),
        }
    }
    steps
}

impl LegacyHook {
    pub(super) fn target(&self) -> Option<&str> {
        self.rule.windows(2).find(|pair| pair[0] == "-j" && pair[1].starts_with("U60_")).map(|pair| pair[1].as_str())
    }

    pub(super) fn command(&self, action: &str, position: Option<usize>) -> Cmd {
        let mut args = vec!["-w".into(), "2".into(), "-t".into(), self.table.clone(), action.into(), self.chain.clone()];
        if let Some(position) = position {
            args.push(position.to_string());
        }
        args.extend(self.rule.iter().cloned());
        Cmd { program: self.tool.program().into(), args }
    }
}
