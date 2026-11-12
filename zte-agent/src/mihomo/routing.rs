//! What skips the core in the kernel while Mihomo runs, so that LAN traffic
//! follows its mode and rules (owner decision 64,
//! `zte-agent/docs/relay-hw-offload.md` section 4,
//! `relay-mihomo-architecture.md` section 5.4).
//!
//! DNS is always fake-ip (`Routes::dns`). With the DIRECT bypass on, a domain
//! gets its real address only when a rule fixed in the configuration sends it
//! to DIRECT itself (not through a group the owner can switch, not through a
//! rule set the core may change), or when no rule before the last point that
//! may skip the core can name it; every other domain always gets a fake
//! address, which always reaches the core (owner choice Q3: a client that
//! cached a real address must not keep a domain on DIRECT after a switch).
//! With the bypass off every domain but local names and the subscription's
//! own list is fake. In rule mode the rules are compiled top-down into the
//! kernel chain, in the core's order (`Routes::compile`, `Compiled::render`):
//! what a rule matches by address, port or network returns (kernel NAT, IPA
//! on the relay) when its target is DIRECT and goes to the core otherwise;
//! domain and process rules are left to fake-ip; a DIRECT rule the kernel
//! cannot check is skipped, a non-DIRECT one ends the chain (the rest goes to
//! the core). A proxy group counts as DIRECT only while its `select` chain
//! ends at DIRECT. A rule set counts only while its content cannot change
//! behind the agent's back (owner choice Q2): inline sets, and `http` sets,
//! whose refreshes the controller performs itself (the managed configuration
//! drops their `interval`, `Routes::refresh`); a `file` set (the core reloads
//! it whenever the file changes) and a set being refreshed (`unsettled`) are
//! treated as unknown.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use serde_json::Value;
use serde_yaml_ng::Value as Yaml;


/// The pinned fake-ip pool. It is always sent to the core, in every mode.
pub(super) const FAKE_RANGE: &str = crate::netfx::ids::FAKE_IP_RANGE;
pub(super) const FAKE_NET: &str = crate::netfx::ids::FAKE_IP_NET;
/// Names that must resolve to their real address (local names and Windows'
/// connectivity check, which compares the address it gets).
const LOCAL: [&str; 6] = ["lan", "local", "localdomain", "home.arpa", "msftconnecttest.com", "msftncsi.com"];
const MAX_DEPTH: usize = 8;
/// IPv4 ranges the chain returns before the rules (LAN, link-local,
/// multicast...): rule ranges inside them never reach the rules.
pub(super) const PRIVATE_V4: [&str; 8] = crate::netfx::ids::PRIVATE_V4;
/// At most this many alternatives for one rule (an `AND` of `OR`s multiplies).
const MAX_ALTERNATIVES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    Rule,
    Global,
    Direct,
}

impl Mode {
    pub(super) fn parse(mode: &str) -> Self {
        match mode.to_ascii_lowercase().as_str() {
            "global" => Self::Global,
            "direct" => Self::Direct,
            _ => Self::Rule,
        }
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Global => "global",
            Self::Direct => "direct",
        }
    }
}

/// `now` of every `select` group.
pub(super) type Selected = BTreeMap<String, String>;

/// A name whose DNS answer must change between two `fake-ip-filter`s, to
/// prove a reload took the new one (section 5.5), and whether the new filter
/// fakes it: the never-resolving probe name when the default changed, else a
/// `DOMAIN`/`DOMAIN-SUFFIX` entry whose first match is plain in both filters.
pub(super) fn reload_probe(old: &[String], new: &[String]) -> Option<(String, bool)> {
    const PROBE: &str = "u60-reload-probe.invalid";
    let fake = |filter: &[String], name: &str| -> Option<bool> {
        for entry in filter {
            let (rule, action) = entry.rsplit_once(',')?;
            let (kind, payload) = rule.split_once(',').unwrap_or((rule, ""));
            let hit = match kind {
                "MATCH" => true,
                "DOMAIN" => name.eq_ignore_ascii_case(payload),
                "DOMAIN-SUFFIX" => name.eq_ignore_ascii_case(payload) || name.to_ascii_lowercase().ends_with(&format!(".{}", payload.to_ascii_lowercase())),
                "DOMAIN-KEYWORD" => name.to_ascii_lowercase().contains(&payload.to_ascii_lowercase()),
                // A keyword, a pattern or a set might match: no plain answer.
                _ => return None,
            };
            if hit {
                return Some(action == "fake-ip");
            }
        }
        None
    };
    let mut names = vec![PROBE.to_owned()];
    names.extend(new.iter().filter_map(|e| {
        let (rule, _) = e.rsplit_once(',')?;
        let (kind, payload) = rule.split_once(',')?;
        matches!(kind, "DOMAIN" | "DOMAIN-SUFFIX").then(|| payload.to_owned())
    }));
    names.into_iter().find_map(|name| match (fake(old, &name), fake(new, &name)) {
        (Some(before), Some(after)) if before != after => Some((name, after)),
        _ => None,
    })
}

/// The selector choices in a controller `GET /proxies` listing.
pub(super) fn selected_from(listing: &Value) -> Option<Selected> {
    let proxies = listing["proxies"].as_object()?;
    Some(
        proxies
            .iter()
            .filter(|(_, p)| p["type"].as_str() == Some("Selector"))
            .filter_map(|(name, p)| Some((name.clone(), p["now"].as_str()?.to_owned())))
            .collect(),
    )
}

#[derive(Clone, Debug, Default)]
struct Group {
    select: bool,
    /// The configured members (`proxies`), in order; the core's choice
    /// before any is stored is the first.
    members: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct Provider {
    behavior: String,
    format: String,
    path: Option<String>,
    inline: Option<Vec<String>>,
    /// `type` (lower case): `http`, `file` or `inline`.
    kind: String,
    /// The subscription's refresh interval in seconds (0: none).
    interval: u64,
}

impl Provider {
    /// Whether the core itself may change the content while it runs: a
    /// `file` set is reloaded whenever the file changes (`fswatch` in
    /// v1.19.33 `component/resource/fetcher.go`); an `http` set refreshes
    /// only with an `interval`, which the managed configuration removes.
    fn dynamic(&self) -> bool {
        !matches!(self.kind.as_str(), "http" | "inline")
    }
}

/// The parts of a configuration that decide routing.
#[derive(Clone, Debug, Default)]
pub(super) struct Routes {
    rules: Vec<String>,
    groups: HashMap<String, Group>,
    providers: HashMap<String, Provider>,
    /// The subscription's own fake-ip-filter blacklist, as real-ip rules.
    compat: Vec<String>,
    /// `GEOIP` uses GeoIP.dat (the only database the kernel can read).
    geodata: bool,
    /// Nodes whose server is an IPv6 address: unreachable without an IPv6 egress.
    v6_only: std::collections::BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// Skip the core: kernel NAT.
    Direct,
    Core,
}

impl Verdict {
    fn nft(self) -> String {
        match self {
            Self::Direct => "return".into(),
            Self::Core => format!("goto {}", super::intercept::CORE),
        }
    }
}

/// One condition the kernel can check.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Term {
    Dst(String),
    /// The destination is in a `GEOIP` code's ranges.
    Geo(String),
    Src(String),
    /// `dport` or `sport`, and an nft set of ports.
    Port(&'static str, String),
    Proto(&'static str),
}

/// One way a rule matches: every term holds.
type Alt = Vec<Term>;
/// Everything a rule matches among LAN IPv4, as the kernel sees it. Nothing
/// when it never matches there or matches by domain (fake-ip decides); `Err`
/// for a part the kernel cannot check.
type Effect = Vec<Result<Alt, String>>;

struct Step {
    verdict: Verdict,
    alts: Vec<Alt>,
    label: String,
}

/// The rule-mode chain before `GEOIP` ranges are known.
pub(super) struct Compiled {
    steps: Vec<Step>,
    /// What the rest gets: DIRECT after `MATCH,DIRECT` or after the last rule
    /// (the core's default), the core after any other `MATCH` or a cut.
    tail: Verdict,
    cut: Option<String>,
    /// `GEOIP` codes (upper case) whose ranges `render` needs.
    pub geoip: Vec<String>,
    /// Rule-set files read: compile again when one's content changes.
    pub sources: Vec<Source>,
}

/// A rule-set file the plan read. The core rewrites a file only when its
/// content changed, but touches its modification time at every scheduled
/// refresh (plan, confirmation 13): the time only says when to look.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Source {
    path: PathBuf,
    modified: Option<SystemTime>,
    digest: Option<[u8; 32]>,
}

impl Source {
    fn read(path: PathBuf, bytes: Option<&[u8]>) -> Self {
        let modified = fs::metadata(&path).and_then(|m| m.modified()).ok();
        Self { path, modified, digest: bytes.map(digest) }
    }

    /// Whether the content differs from what the plan read. A file only
    /// touched takes its new time, so the next check is a `stat` again.
    pub(super) fn changed(&mut self) -> bool {
        let modified = fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        if modified == self.modified {
            return false;
        }
        self.modified = modified;
        fs::read(&self.path).ok().as_deref().map(digest) != self.digest
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

/// The kernel's rule-mode chain: sets and nft rules placed after the private
/// ranges return, before the final `goto to_core`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Chain {
    pub sets: Vec<(String, Vec<String>)>,
    pub rules: Vec<String>,
    /// Rules (a DIRECT `MATCH` or end included) that let traffic skip the core.
    pub returns: usize,
    /// Why the chain ends before the rules do.
    pub cut: Option<String>,
    /// Each rule as (returns, destination ranges) when it matches by
    /// destination alone; `None` for a source, port or protocol condition.
    pub plain: Vec<Option<(bool, Vec<String>)>>,
}

impl Chain {
    /// Direct mode: all IPv4 skips the core.
    pub(super) fn all() -> Self {
        Self { rules: vec!["return".into()], returns: 1, plain: vec![Some((true, vec!["0.0.0.0/0".into()]))], ..Self::default() }
    }

    /// The IPv4 the chain lets skip the core, first match wins, as sorted
    /// disjoint ranges; `None` when a rule before its last return matches by
    /// more than the destination.
    fn bypass(&self) -> Option<Vec<(u32, u32)>> {
        let last = self.plain.iter().rposition(|p| !matches!(p, Some((false, _))))?;
        let (mut decided, mut bypass) = (Vec::new(), Vec::new());
        for rule in &self.plain[..=last] {
            let (returns, ranges) = rule.as_ref()?;
            let matched = ranges::from_cidrs(ranges);
            if *returns {
                bypass = ranges::union(&bypass, &ranges::subtract(&matched, &decided));
            }
            decided = ranges::union(&decided, &matched);
        }
        Some(bypass)
    }
}

/// `lost_from` one chain.
#[cfg(test)]
pub(super) fn lost(old: &Chain, new: &Chain) -> crate::netfx::conntrack::Scope {
    lost_from(std::slice::from_ref(old), new)
}

/// The LAN IPv4 connections a change from `olds` to `new` must reset (D10,
/// `relay-mihomo-architecture.md` section 4.5): what any of `olds` let skip
/// the core and `new` does not. `olds` are every table connections may have
/// skipped the core by since the last reset: one the kernel was confirmed to
/// hold, or one a failed load left as the target (a reconcile may have
/// loaded it since). A chain that is not plain destinations up to its last
/// return makes it every LAN IPv4 connection (`old`) or all of what `old`
/// let through (`new`); more than 64 ranges also reset the whole LAN.
/// Nothing when nothing lost the bypass: re-compiling the same table resets
/// nothing.
pub(super) fn lost_from(olds: &[Chain], new: &Chain) -> crate::netfx::conntrack::Scope {
    use crate::netfx::conntrack::Scope;
    let mut before = Vec::new();
    for old in olds.iter().filter(|old| old.returns > 0) {
        let Some(bypass) = old.bypass() else { return Scope::Lan { v4: true, v6: false } };
        before = ranges::union(&before, &bypass);
    }
    if before.is_empty() {
        return Scope::Destinations(Vec::new());
    }
    let after = new.bypass().unwrap_or_default();
    let lost = ranges::to_cidrs(&ranges::subtract(&before, &after));
    if lost.len() > Scope::MAX_RANGES {
        return Scope::Lan { v4: true, v6: false };
    }
    Scope::Destinations(lost)
}

/// IPv4 address ranges as sorted, disjoint, inclusive `u32` pairs.
mod ranges {
    use std::net::Ipv4Addr;

    use ipnet::Ipv4Net;

    pub(super) fn from_cidrs(cidrs: &[String]) -> Vec<(u32, u32)> {
        let mut out: Vec<(u32, u32)> = cidrs
            .iter()
            .filter_map(|c| c.parse::<Ipv4Net>().ok())
            .map(|net| (u32::from(net.network()), u32::from(net.broadcast())))
            .collect();
        out.sort_unstable();
        merge(out)
    }

    fn merge(sorted: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
        let mut out: Vec<(u32, u32)> = Vec::new();
        for (low, high) in sorted {
            match out.last_mut() {
                Some(last) if low <= last.1.saturating_add(1) => last.1 = last.1.max(high),
                _ => out.push((low, high)),
            }
        }
        out
    }

    pub(super) fn union(a: &[(u32, u32)], b: &[(u32, u32)]) -> Vec<(u32, u32)> {
        let mut all = [a, b].concat();
        all.sort_unstable();
        merge(all)
    }

    pub(super) fn subtract(a: &[(u32, u32)], b: &[(u32, u32)]) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        for &(start, high) in a {
            let mut low = Some(start);
            for &(cut_low, cut_high) in b {
                let Some(at) = low else { break };
                if cut_high < at || cut_low > high {
                    continue;
                }
                if cut_low > at {
                    out.push((at, cut_low - 1));
                }
                low = (cut_high < high).then(|| cut_high + 1);
            }
            if let Some(at) = low {
                out.push((at, high));
            }
        }
        out
    }

    /// The fewest CIDR blocks that cover exactly these ranges.
    pub(super) fn to_cidrs(ranges: &[(u32, u32)]) -> Vec<Ipv4Net> {
        let mut out = Vec::new();
        for &(low, high) in ranges {
            let mut at = u64::from(low);
            let end = u64::from(high);
            while at <= end {
                let mut size = if at == 0 { 32 } else { at.trailing_zeros().min(32) };
                while size > 0 && at + (1u64 << size) - 1 > end {
                    size -= 1;
                }
                out.push(Ipv4Net::new(Ipv4Addr::from(at as u32), (32 - size) as u8).expect("prefix length is at most 32"));
                at += 1u64 << size;
            }
        }
        out
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Rule {
    kind: String,
    payload: String,
    target: String,
    /// The `src` parameter: match the source address instead.
    src: bool,
}

/// A rule line as the core splits it (`rules/common/base.go`
/// `ParseRulePayload`): `TYPE,payload[,target][,params]`.
fn parse(line: &str, with_target: bool) -> Rule {
    let mut item: Vec<&str> = line.split(',').map(str::trim).collect();
    let kind = item[0].to_ascii_uppercase();
    let mut rule = Rule { kind, ..Rule::default() };
    if item.len() > 1 {
        match rule.kind.as_str() {
            "MATCH" => rule.target = item[1].to_owned(),
            "NOT" | "OR" | "AND" | "SUB-RULE" | "DOMAIN-REGEX" | "PROCESS-NAME-REGEX" | "PROCESS-PATH-REGEX" => {
                if with_target {
                    rule.target = item.pop().unwrap_or_default().to_owned();
                }
                rule.payload = item[1..].join(",");
            }
            _ => {
                rule.payload = item[1].to_owned();
                let params = if with_target {
                    rule.target = item.get(2).copied().unwrap_or_default().to_owned();
                    item.get(3..).unwrap_or_default()
                } else {
                    &item[2..]
                };
                rule.src = params.iter().any(|p| p.eq_ignore_ascii_case("src"));
            }
        }
    }
    rule
}

/// The sub-rules of an `AND`/`OR`/`NOT` payload `((A),(B))`, as the core
/// finds them (`rules/logic/logic.go`): the outermost groups inside.
fn sub_rules(payload: &str) -> Option<Vec<Rule>> {
    if !payload.starts_with('(') || !payload.ends_with(')') {
        return None;
    }
    let (mut stack, mut ranges) = (Vec::new(), Vec::new());
    for (at, c) in payload.char_indices() {
        if c == '(' {
            stack.push(at);
        } else if c == ')' {
            ranges.push((stack.pop()?, at));
        }
    }
    if !stack.is_empty() {
        return None;
    }
    ranges.sort_unstable();
    let mut top: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if (start == 0 && end == payload.len() - 1) || top.iter().any(|&(s, e)| s < start && e > end) {
            continue;
        }
        top.push((start, end));
    }
    Some(top.iter().map(|&(s, e)| parse(&payload[s + 1..e], false)).collect())
}

fn domain_kind(kind: &str) -> bool {
    matches!(kind, "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "DOMAIN-REGEX" | "DOMAIN-WILDCARD" | "GEOSITE")
}

/// Process lookup is off, and LAN connections have no local process.
fn process_kind(kind: &str) -> bool {
    kind.starts_with("PROCESS-") || kind == "UID"
}

/// `GEOIP` codes of the private ranges, which return before the rules.
fn private_code(code: &str) -> bool {
    matches!(code.to_ascii_uppercase().as_str(), "PRIVATE" | "LAN")
}

/// `Some(Ok)` for IPv4 (host bits cleared), `None` for IPv6.
fn v4_cidr(text: &str) -> Option<Result<String, ()>> {
    let (ip, prefix) = text.split_once('/').map_or((text, None), |(ip, p)| (ip, Some(p)));
    if let Ok(ip) = ip.parse::<Ipv4Addr>() {
        let prefix = match prefix.map(str::parse::<u8>) {
            None => 32,
            Some(Ok(p)) if p <= 32 => p,
            _ => return Some(Err(())),
        };
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        return Some(Ok(format!("{}/{prefix}", Ipv4Addr::from(u32::from(ip) & mask))));
    }
    if ip.parse::<Ipv6Addr>().is_ok() {
        return None;
    }
    Some(Err(()))
}

/// Whether a normalized IPv4 range lies inside the private ranges.
fn private_v4(range: &str) -> bool {
    let bits = |text: &str| -> Option<(u32, u32)> {
        let (ip, prefix) = text.split_once('/')?;
        let prefix: u32 = prefix.parse().ok()?;
        Some((u32::from(ip.parse::<Ipv4Addr>().ok()?), prefix))
    };
    let Some((ip, prefix)) = bits(range) else { return false };
    PRIVATE_V4.iter().filter_map(|p| bits(p)).any(|(net, len)| len <= prefix && (len == 0 || (ip ^ net) >> (32 - len) == 0))
}

/// `22/80-90` (the core's `/` list of ports and ranges) as an nft set.
fn ports(spec: &str) -> Option<String> {
    let mut items = Vec::new();
    for part in spec.split('/').map(str::trim) {
        let (low, high) = part.split_once('-').unwrap_or((part, part));
        let (low, high): (u16, u16) = (low.trim().parse().ok()?, high.trim().parse().ok()?);
        if low > high {
            return None;
        }
        items.push(if low == high { low.to_string() } else { format!("{low}-{high}") });
    }
    (!items.is_empty()).then(|| format!("{{ {} }}", items.join(", ")))
}

fn short(text: &str) -> String {
    let mut out: String = text.chars().take(48).collect();
    if out.len() < text.len() {
        out.push('…');
    }
    out
}

impl Routes {
    /// From the subscription configuration, before the agent rewrites its DNS.
    pub(super) fn from(config: &Yaml) -> Self {
        let strings = |v: &Yaml| v.as_sequence().map(|s| s.iter().filter_map(Yaml::as_str).map(str::to_owned).collect::<Vec<_>>());
        let rules = strings(&config["rules"]).unwrap_or_default();
        let groups = config["proxy-groups"]
            .as_sequence()
            .into_iter()
            .flatten()
            .filter_map(|g| {
                let members = strings(&g["proxies"]).unwrap_or_default();
                Some((g["name"].as_str()?.to_owned(), Group { select: g["type"].as_str().is_some_and(|t| t.eq_ignore_ascii_case("select")), members }))
            })
            .collect();
        let providers: HashMap<String, Provider> = config["rule-providers"]
            .as_mapping()
            .into_iter()
            .flatten()
            .filter_map(|(name, p)| {
                let lower = |key: &str, default: &str| p[key].as_str().unwrap_or(default).to_ascii_lowercase();
                let inline = (lower("type", "") == "inline").then(|| strings(&p["payload"]).unwrap_or_default());
                let interval = p["interval"].as_u64().or_else(|| p["interval"].as_str().and_then(|i| i.trim().parse().ok())).unwrap_or(0);
                Some((name.as_str()?.to_owned(), Provider { behavior: lower("behavior", ""), format: lower("format", "yaml"), path: p["path"].as_str().map(str::to_owned), inline, kind: lower("type", ""), interval }))
            })
            .collect();
        let dns = &config["dns"];
        let blacklist = dns["fake-ip-filter-mode"].as_str().is_none_or(|m| m.eq_ignore_ascii_case("blacklist"));
        let compat = if blacklist { strings(&dns["fake-ip-filter"]).unwrap_or_default() } else { Vec::new() };
        let compat = compat.iter().filter_map(|entry| compat_rule(entry, &providers)).collect();
        let v6_only = config["proxies"]
            .as_sequence()
            .into_iter()
            .flatten()
            .filter(|p| p["server"].as_str().is_some_and(|s| s.trim_start_matches('[').trim_end_matches(']').parse::<std::net::Ipv6Addr>().is_ok()))
            .filter_map(|p| p["name"].as_str().map(str::to_owned))
            .collect();
        Self { rules, groups, providers, compat, geodata: config["geodata-mode"].as_bool() == Some(true), v6_only }
    }

    /// The nodes with only an IPv6 server address that traffic can reach now:
    /// through the rules' targets (rule mode) or `GLOBAL`, a `select` group's
    /// current choice, and every member of an automatic group.
    pub(super) fn v6_only_in_use(&self, mode: Mode, selected: &Selected) -> Vec<String> {
        if self.v6_only.is_empty() {
            return Vec::new();
        }
        let mut todo: Vec<(String, usize)> = match mode {
            Mode::Direct => return Vec::new(),
            Mode::Global => vec![("GLOBAL".to_owned(), 0)],
            Mode::Rule => self.rules.iter().map(|line| (parse(line, true).target, 0)).collect(),
        };
        let (mut seen, mut found) = (std::collections::BTreeSet::new(), std::collections::BTreeSet::new());
        while let Some((name, depth)) = todo.pop() {
            if depth > MAX_DEPTH * 2 || !seen.insert(name.clone()) {
                continue;
            }
            if self.v6_only.contains(&name) {
                found.insert(name);
                continue;
            }
            match self.groups.get(&name) {
                Some(group) if group.select => todo.extend(selected.get(&name).or(group.members.first()).map(|now| (now.clone(), depth + 1))),
                Some(group) => todo.extend(group.members.iter().map(|m| (m.clone(), depth + 1))),
                // `GLOBAL` is the core's own group: its choice only.
                None => todo.extend(selected.get(&name).map(|now| (now.clone(), depth + 1))),
            }
        }
        found.into_iter().collect()
    }

    fn direct(&self, target: &str, selected: &Selected) -> bool {
        let mut name = target.to_owned();
        for _ in 0..16 {
            if name == "DIRECT" {
                return true;
            }
            let Some(group) = self.groups.get(&name).filter(|g| g.select) else { return false };
            let Some(now) = selected.get(&name).or(group.members.first()) else { return false };
            name = now.clone();
        }
        false
    }

    /// Whether the owner could make `target` DIRECT: DIRECT itself, or a
    /// `select` group with a configured member that could. Automatic groups
    /// (`url-test` and the like) never count.
    fn could_direct(&self, target: &str) -> bool {
        fn walk(routes: &Routes, name: &str, depth: usize) -> bool {
            name == "DIRECT"
                || (depth < MAX_DEPTH * 2
                    && routes.groups.get(name).filter(|g| g.select).is_some_and(|g| g.members.iter().any(|m| walk(routes, m, depth + 1))))
        }
        walk(self, target, 0)
    }

    /// The rule-mode `fake-ip-filter` (`dns.fake-ip-filter-mode: rule`,
    /// first match wins), a function of the configuration and the bypass
    /// setting only: group choices and the mode never change it.
    ///
    /// Local names always keep their real address. With the bypass off the
    /// subscription's own list keeps it too and every other name is fake.
    /// With it on, top-down up to the last rule that may let traffic skip the
    /// core (`last_return`): a domain rule whose target is DIRECT itself, from
    /// a fixed list, keeps real addresses; every other rule that names domains
    /// fakes them (a group can be switched away from DIRECT, a rule set can
    /// lose the name at a refresh); a rule set that can gain any name, or a
    /// rule this filter cannot express, fakes everything from there on. Then
    /// the subscription's own list and the rest keep their real address.
    pub(super) fn dns(&self, bypass: bool) -> Vec<String> {
        let mut out: Vec<String> = LOCAL.iter().map(|d| format!("DOMAIN-SUFFIX,{d},real-ip")).collect();
        if !bypass {
            out.extend(self.compat.iter().cloned());
            out.push("MATCH,fake-ip".into());
            return out;
        }
        let tail = self.real_until(&mut out);
        out.extend(self.compat.iter().cloned());
        out.push(format!("MATCH,{tail}"));
        out
    }

    /// The per-rule entries of `dns`; the action for the names left over.
    fn real_until(&self, out: &mut Vec<String>) -> &'static str {
        let end = self.last_return().map_or(0, |last| last + 1);
        for line in &self.rules[..end] {
            let rule = parse(line, true);
            let fixed = rule.target == "DIRECT";
            let action = if fixed { "real-ip" } else { "fake-ip" };
            match rule.kind.as_str() {
                kind if domain_kind(kind) => out.push(format!("{kind},{},{action}", rule.payload)),
                "RULE-SET" => match self.providers.get(&rule.payload) {
                    Some(p) if p.behavior == "ipcidr" => {}
                    Some(p) if p.inline.is_some() => out.push(format!("RULE-SET,{},{action}", rule.payload)),
                    // Refreshed sets lose and gain names: fake what they hold;
                    // one that may gain any name ends the real addresses.
                    Some(_) if fixed => out.push(format!("RULE-SET,{},fake-ip", rule.payload)),
                    Some(_) => {
                        // Its current names stay fake ahead of the subscription's list.
                        out.push(format!("RULE-SET,{},fake-ip", rule.payload));
                        return "fake-ip";
                    }
                    None => return "fake-ip",
                },
                // DIRECT only in part (a network or a port as well): the
                // rules after it decide the rest, as for any other name.
                "AND" | "OR" if fixed => {}
                "AND" | "OR" => {
                    if !self.domain_leaves(&rule.payload, 0, out) {
                        return "fake-ip";
                    }
                }
                "NOT" | "SUB-RULE" if !fixed => return "fake-ip",
                _ => {}
            }
        }
        "real-ip"
    }

    /// Index of the last rule that may ever let traffic skip the core in the
    /// kernel, whatever the owner chooses: a rule that can match by address
    /// with a target the owner could make DIRECT (`could_direct`), or a
    /// `MATCH` with one; `None` if no rule can. No `MATCH` is the core's
    /// default, DIRECT. Judged from the configuration alone (not the current
    /// choices, which would move it when a group is switched), so a missing
    /// rule-set file or GeoIP code does not change DNS.
    fn last_return(&self) -> Option<usize> {
        let mut last = None;
        for (index, line) in self.rules.iter().enumerate() {
            let rule = parse(line, true);
            let direct = self.could_direct(&rule.target);
            if rule.kind == "MATCH" {
                return if direct { Some(index) } else { last };
            }
            let address = match rule.kind.as_str() {
                kind if domain_kind(kind) || process_kind(kind) => false,
                "GEOIP" => !private_code(&rule.payload),
                "IP-CIDR" | "IP-CIDR6" if !rule.src => match v4_cidr(&rule.payload) {
                    Some(Ok(range)) => !private_v4(&range),
                    Some(Err(())) => true,
                    None => false,
                },
                "RULE-SET" => self.providers.get(&rule.payload).is_none_or(|p| p.behavior != "domain"),
                _ => true,
            };
            if direct && address {
                last = Some(index);
            }
        }
        Some(self.rules.len().saturating_sub(1)).filter(|_| !self.rules.is_empty())
    }

    /// A non-DIRECT logical rule's domain conditions, as fake-ip entries;
    /// false when one names domains this filter cannot list (a refreshed set,
    /// a `NOT`, too deep).
    fn domain_leaves(&self, payload: &str, depth: usize, out: &mut Vec<String>) -> bool {
        if depth > MAX_DEPTH {
            return false;
        }
        for sub in sub_rules(payload).unwrap_or_default() {
            match sub.kind.as_str() {
                kind if domain_kind(kind) => out.push(format!("{kind},{},fake-ip", sub.payload)),
                "RULE-SET" => match self.providers.get(&sub.payload) {
                    Some(p) if p.behavior == "ipcidr" => {}
                    Some(p) if p.inline.is_some() => out.push(format!("RULE-SET,{},fake-ip", sub.payload)),
                    _ => return false,
                },
                "AND" | "OR" => {
                    if !self.domain_leaves(&sub.payload, depth + 1, out) {
                        return false;
                    }
                }
                "NOT" | "SUB-RULE" => return false,
                _ => {}
            }
        }
        true
    }

    /// The `http` rule sets the controller refreshes, with the
    /// subscription's interval in seconds (the managed configuration drops
    /// it, so the core never refreshes one by itself).
    pub(super) fn refresh(&self) -> Vec<(String, u64)> {
        let mut sets: Vec<(String, u64)> = self.providers.iter().filter(|(_, p)| p.kind == "http" && p.interval > 0).map(|(name, p)| (name.clone(), p.interval)).collect();
        sets.sort();
        sets
    }

    /// Whether a refresh of rule set `name` can change the kernel plan: a
    /// `domain` set never enters it (fake-ip decides, and what a refreshed
    /// set holds is fake in the DNS filter whatever it is), so its refresh
    /// needs no tightening and no table. An unknown set may.
    pub(super) fn reaches_kernel(&self, name: &str) -> bool {
        self.providers.get(name).is_none_or(|p| p.behavior != "domain")
    }

    /// Rule mode: the rules in the core's order, as kernel conditions. A rule
    /// set in `unsettled` (being refreshed) counts as unknown: skipped where
    /// it sends DIRECT, the end of the chain otherwise.
    pub(super) fn compile(&self, selected: &Selected, root: &Path, unsettled: &[String]) -> Compiled {
        let mut out = Compiled { steps: Vec::new(), tail: Verdict::Direct, cut: None, geoip: Vec::new(), sources: Vec::new() };
        for (index, line) in self.rules.iter().enumerate() {
            let rule = parse(line, true);
            let verdict = if self.direct(&rule.target, selected) { Verdict::Direct } else { Verdict::Core };
            if rule.kind == "MATCH" {
                out.tail = verdict;
                break;
            }
            let label = format!("Rule {} ({})", index + 1, short(line));
            let mut alts = Vec::new();
            for alt in self.effect(&rule, root, 0, &mut out.sources, unsettled) {
                match alt {
                    Ok(alt) => alts.push(alt),
                    // Skipping a DIRECT condition only sends more to the core.
                    Err(_) if verdict == Verdict::Direct => {}
                    Err(why) => {
                        out.cut = Some(format!("{label}: {why}"));
                        out.tail = Verdict::Core;
                        return out.with_codes();
                    }
                }
            }
            if !alts.is_empty() {
                out.steps.push(Step { verdict, alts, label });
            }
        }
        out.with_codes()
    }

    fn effect(&self, rule: &Rule, root: &Path, depth: usize, sources: &mut Vec<Source>, unsettled: &[String]) -> Effect {
        let cannot = |why: String| vec![Err(why)];
        let one = |term: Term| vec![Ok(vec![term])];
        let payload = rule.payload.as_str();
        match rule.kind.as_str() {
            kind if domain_kind(kind) || process_kind(kind) => Vec::new(),
            "IP-CIDR" | "IP-CIDR6" | "SRC-IP-CIDR" => match v4_cidr(payload) {
                Some(Ok(range)) if rule.src || rule.kind == "SRC-IP-CIDR" => one(Term::Src(range)),
                Some(Ok(range)) if private_v4(&range) => Vec::new(),
                Some(Ok(range)) => one(Term::Dst(range)),
                Some(Err(())) => cannot("invalid address range".into()),
                None => Vec::new(),
            },
            "GEOIP" if rule.src => cannot("source GeoIP needs the core".into()),
            "GEOIP" if private_code(payload) => Vec::new(),
            "GEOIP" if !self.geodata => cannot("GEOIP needs geodata-mode (the kernel reads GeoIP.dat)".into()),
            "GEOIP" => one(Term::Geo(payload.to_ascii_uppercase())),
            "DST-PORT" | "SRC-PORT" => {
                let field = if rule.kind == "DST-PORT" { "dport" } else { "sport" };
                ports(payload).map_or_else(|| cannot("invalid ports".into()), |set| one(Term::Port(field, set)))
            }
            "NETWORK" => match payload.to_ascii_lowercase().as_str() {
                "tcp" => one(Term::Proto("tcp")),
                "udp" => one(Term::Proto("udp")),
                _ => cannot("unknown network".into()),
            },
            "AND" | "OR" if depth < MAX_DEPTH => {
                let Some(subs) = sub_rules(payload).filter(|s| !s.is_empty()) else { return cannot("malformed rule".into()) };
                let effects: Vec<Effect> = subs.iter().map(|sub| self.effect(sub, root, depth + 1, sources, unsettled)).collect();
                if rule.kind == "OR" {
                    return effects.into_iter().flatten().collect();
                }
                let mut all: Effect = vec![Ok(Vec::new())];
                for effect in effects {
                    let mut next = Vec::new();
                    for a in &all {
                        for b in &effect {
                            next.push(match (a, b) {
                                (Ok(a), Ok(b)) => Ok([a.as_slice(), b.as_slice()].concat()),
                                (Err(why), _) | (_, Err(why)) => Err(why.clone()),
                            });
                        }
                    }
                    if next.len() > MAX_ALTERNATIVES {
                        return cannot("too many combinations".into());
                    }
                    all = next;
                }
                all
            }
            "RULE-SET" => self.rule_set(payload, root, depth, sources, unsettled),
            kind => cannot(format!("{kind} rules need the core")),
        }
    }

    fn rule_set(&self, name: &str, root: &Path, depth: usize, sources: &mut Vec<Source>, unsettled: &[String]) -> Effect {
        let Some(provider) = self.providers.get(name) else { return vec![Err(format!("rule set {} is not defined", short(name)))] };
        match provider.behavior.as_str() {
            "domain" => Vec::new(),
            "ipcidr" | "classical" if provider.dynamic() => vec![Err(format!("rule set {} is reloaded by the core whenever it changes", short(name)))],
            "ipcidr" | "classical" if unsettled.iter().any(|u| u == name) => vec![Err(format!("rule set {} is being refreshed", short(name)))],
            behavior @ ("ipcidr" | "classical") if depth < MAX_DEPTH => {
                let lines = match entries(name, provider, root, sources) {
                    Ok(lines) => lines,
                    Err(why) => return vec![Err(why)],
                };
                let mut effect = Vec::new();
                for line in lines {
                    let rule = if behavior == "ipcidr" { Rule { kind: "IP-CIDR".into(), payload: line, ..Rule::default() } } else { parse(&line, false) };
                    effect.extend(self.effect(&rule, root, depth + 1, sources, unsettled).into_iter().map(|alt| alt.map_err(|why| format!("rule set {}: {why}", short(name)))));
                }
                effect
            }
            _ => vec![Err(format!("rule set {} has an unknown behavior", short(name)))],
        }
    }
}

enum Expr {
    /// A plain destination range: joins the run's shared set.
    Range(String),
    /// A match expression, with its destination ranges when that is all it
    /// checks (a `GEOIP` code alone).
    Match(String, Option<Vec<String>>),
}

impl Compiled {
    /// Drops the proxy rules before a tail that goes to the core anyway, then
    /// lists the `GEOIP` codes left.
    fn with_codes(mut self) -> Self {
        if self.tail == Verdict::Core {
            while self.steps.last().is_some_and(|s| s.verdict == Verdict::Core) {
                self.steps.pop();
            }
        }
        let mut codes: Vec<String> = self.steps.iter().flat_map(|s| s.alts.iter().flatten()).filter_map(|t| if let Term::Geo(code) = t { Some(code.clone()) } else { None }).collect();
        codes.sort();
        codes.dedup();
        self.geoip = codes;
        self
    }

    /// The chain, given each `GEOIP` code's ranges (`Err`: the code's
    /// conditions cannot be checked; an empty list never matches IPv4).
    pub(super) fn render<'g>(&self, geo: &dyn Fn(&str) -> Result<&'g [String], String>) -> Chain {
        let mut chain = Chain { cut: self.cut.clone(), ..Chain::default() };
        let mut names = BTreeMap::new();
        let mut ranges_sets = 0;
        let mut at = 0;
        while at < self.steps.len() {
            let verdict = self.steps[at].verdict;
            let end = at + self.steps[at..].iter().take_while(|s| s.verdict == verdict).count();
            // One verdict for the whole run: its order does not matter, so
            // its plain ranges share one set.
            let (mut ranges, mut lines, mut cut): (Vec<String>, Vec<(String, Option<Vec<String>>)>, _) = (Vec::new(), Vec::new(), None);
            'run: for step in &self.steps[at..end] {
                let mut used = false;
                for alt in &step.alts {
                    match expr(alt, geo, &mut names, &mut chain.sets) {
                        Ok(Some(Expr::Range(range))) => ranges.push(range),
                        Ok(Some(Expr::Match(m, _))) if lines.iter().any(|(l, _)| *l == m) => {}
                        Ok(Some(Expr::Match(m, plain))) => lines.push((m, plain)),
                        Ok(None) => continue,
                        Err(_) if verdict == Verdict::Direct => continue,
                        Err(why) => {
                            cut = Some(format!("{}: {why}", step.label));
                            break 'run;
                        }
                    }
                    used = true;
                }
                chain.returns += usize::from(used && verdict == Verdict::Direct);
            }
            let returns = verdict == Verdict::Direct;
            if !ranges.is_empty() {
                let name = format!("ip_{ranges_sets}");
                ranges_sets += 1;
                chain.rules.push(format!("ip daddr @{name} {}", verdict.nft()));
                chain.plain.push(Some((returns, ranges.clone())));
                chain.sets.push((name, ranges));
            }
            for (m, plain) in lines {
                chain.rules.push(format!("{m} {}", verdict.nft()));
                chain.plain.push(plain.map(|ranges| (returns, ranges)));
            }
            if cut.is_some() {
                chain.cut = cut;
                return chain;
            }
            at = end;
        }
        if self.tail == Verdict::Direct {
            chain.rules.push("return".into());
            chain.plain.push(Some((true, vec!["0.0.0.0/0".into()])));
            chain.returns += 1;
        }
        chain
    }
}

/// One alternative as nft: a plain range, a match expression, or `None`
/// when it never matches IPv4 (a code without IPv4 ranges).
fn expr<'g>(alt: &Alt, geo: &dyn Fn(&str) -> Result<&'g [String], String>, names: &mut BTreeMap<String, String>, sets: &mut Vec<(String, Vec<String>)>) -> Result<Option<Expr>, String> {
    if let [Term::Dst(range)] = alt.as_slice() {
        return Ok(Some(Expr::Range(range.clone())));
    }
    let mut parts = Vec::new();
    let mut plain = None;
    for term in alt {
        parts.push(match term {
            Term::Dst(range) => format!("ip daddr {range}"),
            Term::Src(range) => format!("ip saddr {range}"),
            Term::Port(field, set) => format!("th {field} {set}"),
            Term::Proto(proto) => format!("meta l4proto {proto}"),
            Term::Geo(code) => {
                if !names.contains_key(code) {
                    let ranges = geo(code).map_err(|why| format!("GEOIP,{code}: {why}"))?;
                    if ranges.is_empty() {
                        return Ok(None);
                    }
                    let base: String = code.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).collect();
                    let mut name = format!("geo_{base}");
                    if sets.iter().any(|(n, _)| *n == name) {
                        name = format!("{name}_{}", sets.len());
                    }
                    sets.push((name.clone(), ranges.to_vec()));
                    names.insert(code.clone(), name);
                }
                if alt.len() == 1 {
                    plain = sets.iter().find(|(n, _)| *n == names[code]).map(|(_, ranges)| ranges.clone());
                }
                format!("ip daddr @{}", names[code])
            }
        });
    }
    Ok(Some(Expr::Match(parts.join(" "), plain)))
}

/// A rule set's entries: inline, or its local file (text or YAML `payload`).
fn entries(name: &str, provider: &Provider, root: &Path, sources: &mut Vec<Source>) -> Result<Vec<String>, String> {
    if let Some(inline) = &provider.inline {
        return Ok(inline.clone());
    }
    if provider.format == "mrs" {
        return Err(format!("rule set {} is binary (mrs)", short(name)));
    }
    let path = provider.path.as_deref().and_then(|p| local_path(root, p)).ok_or_else(|| format!("rule set {} has no local file", short(name)))?;
    let bytes = fs::read(&path).ok();
    sources.push(Source::read(path, bytes.as_deref()));
    let text = bytes.and_then(|b| String::from_utf8(b).ok()).ok_or_else(|| format!("rule set {} is not downloaded yet", short(name)))?;
    if provider.format == "text" {
        return Ok(text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//")).map(str::to_owned).collect());
    }
    let yaml: Yaml = serde_yaml_ng::from_str(&text).map_err(|_| format!("rule set {} is not valid YAML", short(name)))?;
    Ok(yaml["payload"].as_sequence().into_iter().flatten().filter_map(Yaml::as_str).map(|s| s.trim().to_owned()).collect())
}

/// A provider path inside the core's home directory (the core refuses others).
fn local_path(root: &Path, path: &str) -> Option<PathBuf> {
    let path = Path::new(path);
    let full = if path.is_absolute() { path.to_path_buf() } else { root.join(path) };
    let clean: PathBuf = full.components().filter(|c| *c != Component::CurDir).collect();
    (!clean.components().any(|c| c == Component::ParentDir) && clean.starts_with(root)).then_some(clean)
}

/// A blacklist `fake-ip-filter` entry (the core's domain-trie syntax) as a
/// rule-mode entry that keeps its real address.
fn compat_rule(entry: &str, providers: &HashMap<String, Provider>) -> Option<String> {
    let entry = entry.trim();
    if entry.is_empty() || entry.contains(',') {
        return None;
    }
    let prefixed = |prefix: &str| entry.get(..prefix.len()).filter(|p| p.eq_ignore_ascii_case(prefix)).map(|_| &entry[prefix.len()..]);
    if let Some(name) = prefixed("geosite:") {
        return Some(format!("GEOSITE,{name},real-ip"));
    }
    if let Some(name) = prefixed("rule-set:") {
        let set = providers.get(name).is_some_and(|p| matches!(p.behavior.as_str(), "domain" | "classical"));
        return set.then(|| format!("RULE-SET,{name},real-ip"));
    }
    if let Some(domain) = entry.strip_prefix("+.").filter(|d| !d.contains('*')) {
        return Some(format!("DOMAIN-SUFFIX,{domain},real-ip"));
    }
    if let Some(domain) = entry.strip_prefix('.') {
        return Some(format!("DOMAIN-WILDCARD,*.{domain},real-ip"));
    }
    if entry.contains('*') || entry.contains('+') {
        return Some(format!("DOMAIN-WILDCARD,{},real-ip", entry.replace("+.", "*.")));
    }
    Some(format!("DOMAIN,{entry},real-ip"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of the owner's subscription (2026-11-09).
    const CONFIG: &str = r#"
geodata-mode: true
dns:
  fake-ip-filter: ['*.lan', '+.local.dev', 'time.*.com', 'localhost.ptlogin2.qq.com', 'geosite:private', 'rule-set:Ads', 'rule-set:Missing', '.corp']
proxy-groups:
  - {name: 选择代理, type: select, proxies: [自动选择, 日本节点, DIRECT]}
  - {name: 直连, type: select, proxies: [DIRECT, 选择代理]}
  - {name: 哔哩哔哩, type: select, proxies: [直连, 选择代理]}
  - {name: 广告拦截, type: select, proxies: [REJECT, 直连]}
  - {name: Netflix, type: select, proxies: [选择代理, 直连]}
  - {name: 自动选择, type: url-test, proxies: [日本节点, DIRECT]}
  - {name: 日本节点, type: url-test, proxies: [JP]}
rule-providers:
  Ads: {type: http, behavior: domain, format: mrs, path: ./ruleset/Ads.mrs}
  Hentai: {type: http, behavior: classical, format: text, path: ./ruleset/Hentai.list}
  Fcm: {type: http, behavior: classical, format: text, path: ./ruleset/Fcm.list}
  Cidr: {type: inline, behavior: ipcidr, payload: ['91.108.4.0/22', '2001:b28:f23d::/48']}
rules:
  - AND,((IP-CIDR6,2a0e::1/128,no-resolve),(NETWORK,UDP),(DST-PORT,443)),DIRECT
  - DOMAIN-SUFFIX,claude.ai,JP
  - DOMAIN-SUFFIX,lihan.me,DIRECT
  - IP-CIDR,192.168.0.44/32,DIRECT,no-resolve
  - RULE-SET,Ads,广告拦截
  - RULE-SET,Hentai,Netflix
  - RULE-SET,Fcm,直连
  - RULE-SET,Cidr,选择代理
  - AND,((DOMAIN-SUFFIX,quic.example),(NETWORK,UDP)),REJECT
  - GEOSITE,BILIBILI,哔哩哔哩
  - GEOSITE,GFW,选择代理
  - GEOSITE,CN,直连
  - GEOIP,NETFLIX,Netflix,no-resolve
  - GEOIP,CN,直连
  - GEOIP,PRIVATE,直连
  - DOMAIN-SUFFIX,after.example,选择代理
  - DST-PORT,22,选择代理
  - MATCH,选择代理
"#;

    fn routes() -> Routes {
        Routes::from(&serde_yaml_ng::from_str(CONFIG).unwrap())
    }

    /// B31's subscription in short: an IPv6-only hy2 node behind a manual
    /// choice and an automatic group, a VLESS node by name, and one rule
    /// naming the hy2 node itself.
    #[test]
    fn an_ipv6_only_node_counts_only_where_traffic_can_reach_it() {
        let config = |claude: &str| {
            Routes::from(&serde_yaml_ng::from_str(&format!("proxies:
  - {{name: VLESS, type: vless, server: v.example}}
  - {{name: JP6, type: hysteria2, server: '2a0e:97c0:3f4:1::daf'}}
  - {{name: Bracketed, type: ss, server: '[2001:db8::1]'}}
proxy-groups:
  - {{name: Proxy, type: select, proxies: [Manual, Auto, DIRECT]}}
  - {{name: Manual, type: select, proxies: [VLESS, JP6]}}
  - {{name: Auto, type: url-test, proxies: [JP6, Bracketed]}}
rules: [{claude}'GEOIP,CN,DIRECT', 'MATCH,Proxy']")).unwrap())
        };
        let selected = |pairs: &[(&str, &str)]| pairs.iter().map(|(g, n)| (g.to_string(), n.to_string())).collect::<Selected>();
        let routes = config("");
        assert!(routes.v6_only_in_use(Mode::Rule, &selected(&[("Proxy", "Manual"), ("Manual", "VLESS")])).is_empty());
        assert_eq!(routes.v6_only_in_use(Mode::Rule, &selected(&[("Proxy", "Manual"), ("Manual", "JP6")])), ["JP6"]);
        assert_eq!(
            routes.v6_only_in_use(Mode::Rule, &selected(&[("Proxy", "Auto")])),
            ["Bracketed", "JP6"],
            "an automatic group may pick any member"
        );
        assert!(routes.v6_only_in_use(Mode::Rule, &selected(&[("Proxy", "DIRECT")])).is_empty());
        assert!(routes.v6_only_in_use(Mode::Direct, &selected(&[("Proxy", "Auto")])).is_empty());
        assert_eq!(routes.v6_only_in_use(Mode::Global, &selected(&[("GLOBAL", "Manual"), ("Manual", "JP6")])), ["JP6"]);
        assert!(routes.v6_only_in_use(Mode::Global, &selected(&[("GLOBAL", "DIRECT"), ("Manual", "JP6")])).is_empty());
        let named = config("'DOMAIN-SUFFIX,claude.ai,JP6', ");
        assert_eq!(
            named.v6_only_in_use(Mode::Rule, &selected(&[("Proxy", "Manual"), ("Manual", "VLESS")])),
            ["JP6"],
            "a rule may name the node itself"
        );
    }

    /// Rules only, with one `select` group `直连` (DIRECT first) and a proxy `P`.
    fn with_rules(rules: &[&str]) -> Routes {
        let rules: Vec<String> = rules.iter().map(|r| format!("'{r}'")).collect();
        Routes::from(&serde_yaml_ng::from_str(&format!("geodata-mode: true\nproxy-groups: [{{name: 直连, type: select, proxies: [DIRECT, P]}}]\nrules: [{}]", rules.join(", "))).unwrap())
    }

    fn home(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("u60-routing-{test}-{}", std::process::id()));
        fs::create_dir_all(dir.join("ruleset")).unwrap();
        fs::write(dir.join("ruleset/Hentai.list"), "# comment\nDOMAIN-SUFFIX,e-hentai.org\nIP-CIDR,178.175.129.0/21,no-resolve\nPROCESS-NAME,ehviewer\n").unwrap();
        fs::write(dir.join("ruleset/Fcm.list"), "IP-CIDR,64.233.177.188/32,no-resolve\nDOMAIN,mtalk.google.com\nIP-ASN,15169\n").unwrap();
        dir
    }

    /// CN, NETFLIX and JP have ranges, EMPTY has none, anything else is missing.
    fn geo(code: &str) -> Result<&'static [String], String> {
        use std::sync::OnceLock;
        static LISTS: OnceLock<HashMap<&'static str, Vec<String>>> = OnceLock::new();
        let lists = LISTS.get_or_init(|| {
            HashMap::from([("CN", vec!["1.0.1.0/24".into()]), ("NETFLIX", vec!["23.246.0.0/18".into()]), ("JP", vec!["1.0.16.0/20".into()]), ("EMPTY", Vec::new())])
        });
        lists.get(code).map(Vec::as_slice).ok_or_else(|| "not in GeoIP.dat".into())
    }

    fn chain(routes: &Routes, selected: &Selected, root: &Path) -> Chain {
        routes.compile(selected, root, &[]).render(&geo)
    }

    #[test]
    fn rule_lines_split_like_the_core_including_commas_in_logical_payloads() {
        assert_eq!(parse("ip-cidr,1.2.3.0/24,Proxy,no-resolve", true), Rule { kind: "IP-CIDR".into(), payload: "1.2.3.0/24".into(), target: "Proxy".into(), src: false });
        assert!(parse("IP-CIDR,1.2.3.0/24,Proxy,no-resolve,src", true).src);
        assert!(parse("IP-CIDR,1.2.3.0/24,src", false).src, "rule-set entries have no target");
        assert_eq!(parse("MATCH,Final", true).target, "Final");
        let and = parse("AND,((DOMAIN,a.com),(NETWORK,TCP)),DIRECT", true);
        assert_eq!((and.payload.as_str(), and.target.as_str()), ("((DOMAIN,a.com),(NETWORK,TCP))", "DIRECT"));
        assert_eq!(parse("DOMAIN-REGEX,^a{1,3}$,Proxy", true).payload, "^a{1,3}$");
        let subs = sub_rules("((DOMAIN,a.com),(OR,((NETWORK,UDP),(DST-PORT,443))))").unwrap();
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[1].kind, "OR");
        assert_eq!(subs[1].payload, "((NETWORK,UDP),(DST-PORT,443))");
        assert!(sub_rules("((DOMAIN,a.com)").is_none());
    }

    #[test]
    fn groups_count_as_direct_only_through_a_select_chain_that_ends_at_direct() {
        let r = routes();
        let none = Selected::new();
        assert!(r.direct("DIRECT", &none));
        assert!(r.direct("直连", &none), "first member before any stored choice");
        assert!(r.direct("哔哩哔哩", &none), "through another select group");
        assert!(!r.direct("选择代理", &none), "url-test may pick DIRECT, but not for certain");
        assert!(!r.direct("REJECT", &none));
        let chosen: Selected = [("直连".to_owned(), "选择代理".to_owned())].into();
        assert!(!r.direct("直连", &chosen));
        assert!(!r.direct("哔哩哔哩", &chosen));
        let looped: Selected = [("直连".to_owned(), "哔哩哔哩".to_owned()), ("哔哩哔哩".to_owned(), "直连".to_owned())].into();
        assert!(!r.direct("直连", &looped), "a loop is not DIRECT");
    }

    /// The owner's subscription (2026-11-09): `claude.ai` is sent to a
    /// group, `lihan.me` to DIRECT itself; `Ads` is a refreshed set that may
    /// gain any name, so everything after it is fake (Q2).
    #[test]
    fn the_owners_dns_filter_keeps_real_addresses_only_where_no_switch_or_refresh_can_change_them() {
        let mut expected: Vec<String> = LOCAL.iter().map(|d| format!("DOMAIN-SUFFIX,{d},real-ip")).collect();
        expected.extend(
            [
                "DOMAIN-SUFFIX,claude.ai,fake-ip",
                "DOMAIN-SUFFIX,lihan.me,real-ip",
                "RULE-SET,Ads,fake-ip",
                "DOMAIN-WILDCARD,*.lan,real-ip",
                "DOMAIN-SUFFIX,local.dev,real-ip",
                "DOMAIN-WILDCARD,time.*.com,real-ip",
                "DOMAIN,localhost.ptlogin2.qq.com,real-ip",
                "GEOSITE,private,real-ip",
                "RULE-SET,Ads,real-ip",
                "DOMAIN-WILDCARD,*.corp,real-ip",
                "MATCH,fake-ip",
            ]
            .map(String::from),
        );
        assert_eq!(routes().dns(true), expected, "the subscription's own list comes after the rules: `rule-set:Ads` cannot make the blocked names real");
        let mut off: Vec<String> = LOCAL.iter().map(|d| format!("DOMAIN-SUFFIX,{d},real-ip")).collect();
        off.extend(routes().compat.iter().cloned());
        off.push("MATCH,fake-ip".into());
        assert_eq!(routes().dns(false), off, "with the bypass off only local names and the subscription's list are real");
    }

    /// Q3: a domain a group sends somewhere is fake whatever the group's
    /// choice, so a client using the router's DNS never holds its real
    /// address when the group is switched away from DIRECT.
    #[test]
    fn a_switchable_domain_is_always_fake_and_dns_never_follows_a_group_choice() {
        let r = with_rules(&["DOMAIN-SUFFIX,blog.example,直连", "DOMAIN-SUFFIX,fixed.example,DIRECT", "IP-CIDR,1.2.3.0/24,DIRECT", "MATCH,P"]);
        let dns = r.dns(true);
        assert!(dns.contains(&"DOMAIN-SUFFIX,blog.example,fake-ip".to_owned()), "even while 直连 is on DIRECT");
        assert!(dns.contains(&"DOMAIN-SUFFIX,fixed.example,real-ip".to_owned()), "DIRECT itself cannot be switched");
        let root = home("q3");
        let direct = chain(&r, &Selected::new(), &root);
        let away = chain(&r, &[("直连".to_owned(), "P".to_owned())].into(), &root);
        assert_eq!(direct, away, "the address rule is DIRECT itself: still returns after the switch, which is why the domain must be fake");
        assert!(away.rules.contains(&"ip daddr @ip_0 return".to_owned()));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn the_dns_scope_reaches_the_last_rule_that_could_ever_return() {
        let fakes = |r: &Routes| r.dns(true).into_iter().filter(|e| e.ends_with("fake-ip") && !e.starts_with("MATCH")).collect::<Vec<_>>();
        let r = with_rules(&["DOMAIN,a.com,P", "GEOIP,CN,DIRECT", "DOMAIN,b.com,P", "GEOIP,JP,直连", "DOMAIN,c.com,P", "MATCH,P"]);
        assert_eq!(fakes(&r), ["DOMAIN,a.com,fake-ip", "DOMAIN,b.com,fake-ip"], "b.com would otherwise return through GEOIP,JP once 直连 is on DIRECT");
        let chosen = with_rules(&["DOMAIN,a.com,P", "GEOIP,CN,DIRECT", "DOMAIN,b.com,P", "GEOIP,JP,直连", "DOMAIN,c.com,P", "MATCH,P"]);
        assert_eq!(r.dns(true), chosen.dns(true));
        let r = with_rules(&["DOMAIN,a.com,P", "GEOIP,CN,DIRECT", "DOMAIN,c.com,P", "MATCH,DIRECT"]);
        assert_eq!(fakes(&r), ["DOMAIN,a.com,fake-ip", "DOMAIN,c.com,fake-ip"]);
        let r = with_rules(&["DOMAIN,a.com,P", "DOMAIN,c.com,P"]);
        assert_eq!(fakes(&r).len(), 2, "no MATCH: the core's default is DIRECT");
        let r = with_rules(&["DOMAIN,a.com,P", "GEOSITE,CN,DIRECT", "IP-CIDR6,2001:db8::/32,DIRECT", "GEOIP,PRIVATE,DIRECT", "IP-CIDR,192.168.0.44/32,DIRECT", "MATCH,P"]);
        assert!(fakes(&r).is_empty(), "no DIRECT rule matches IPv4 the chain sees, so nothing can skip the core");
        // Never narrower than the chain: every compiled return is inside it, for any choice.
        let root = home("scope");
        for r in [routes(), with_rules(&["IP-ASN,1,DIRECT", "DOMAIN,a.com,P", "GEOIP,XX,直连", "MATCH,P"])] {
            let last = r.last_return().unwrap_or(0);
            for selected in [Selected::new(), [("直连".to_owned(), "P".to_owned())].into()] {
                let compiled = r.compile(&selected, &root, &[]);
                let returns = compiled.steps.iter().filter(|s| s.verdict == Verdict::Direct).map(|s| s.label.trim_start_matches("Rule ").split(' ').next().unwrap().parse::<usize>().unwrap() - 1);
                assert!(returns.max().is_none_or(|at| at <= last));
            }
        }
        let _ = fs::remove_dir_all(root);
    }

    /// Q2: what a refreshed or reloaded set holds can change behind DNS.
    #[test]
    fn rule_sets_that_can_change_never_give_real_addresses_to_names_they_may_take() {
        let config = |rules: &str| Routes::from(&serde_yaml_ng::from_str(&format!("proxy-groups: [{{name: G, type: select, proxies: [DIRECT, P]}}]\nrule-providers:\n  Inline: {{type: inline, behavior: domain, payload: [a.example]}}\n  Web: {{type: http, behavior: domain, url: 'https://x', path: ./w.yaml, interval: 86400}}\n  Local: {{type: file, behavior: classical, path: ./l.list}}\nrules: {rules}")).unwrap());
        let r = config("['RULE-SET,Inline,DIRECT', 'RULE-SET,Web,DIRECT', 'DOMAIN,b.example,DIRECT', 'GEOIP,CN,DIRECT', 'MATCH,P']");
        let dns = r.dns(true);
        assert!(dns.contains(&"RULE-SET,Inline,real-ip".to_owned()), "a fixed inline list");
        assert!(dns.contains(&"RULE-SET,Web,fake-ip".to_owned()), "a name may leave the set at its next refresh");
        assert!(dns.contains(&"DOMAIN,b.example,real-ip".to_owned()) && dns.last().unwrap() == "MATCH,real-ip");
        for close in ["RULE-SET,Web,G", "RULE-SET,Local,P", "RULE-SET,Missing,P", "NOT,((DOMAIN,x.example)),P", "AND,((RULE-SET,Web),(NETWORK,TCP)),P"] {
            let dns = config(&format!("['{close}', 'DOMAIN,b.example,DIRECT', 'GEOIP,CN,DIRECT', 'MATCH,P']")).dns(true);
            assert_eq!(dns.last().unwrap(), "MATCH,fake-ip", "{close}: any later name may be taken");
            assert!(!dns.contains(&"DOMAIN,b.example,real-ip".to_owned()), "{close}");
        }
        assert_eq!(r.refresh(), [("Web".to_owned(), 86400)], "the controller refreshes http sets, never a file set");
    }

    #[test]
    fn the_owners_rules_compile_in_order_with_fcm_now_returning() {
        let root = home("owner");
        let c = chain(&routes(), &Selected::new(), &root);
        // 192.168.0.44 returns with the private ranges before the chain, and
        // DST-PORT,22 goes to the core like everything after GEOIP,CN.
        assert_eq!(
            c.rules,
            ["ip daddr @ip_0 goto to_core", "ip daddr @ip_1 return", "ip daddr @ip_2 goto to_core", "ip daddr @geo_netflix goto to_core", "ip daddr @geo_cn return"]
        );
        let set = |name: &str| c.sets.iter().find(|(n, _)| n == name).map(|(_, e)| e.clone()).unwrap();
        assert_eq!(set("ip_0"), ["178.175.128.0/21"], "Hentai, host bits cleared");
        assert_eq!(set("ip_1"), ["64.233.177.188/32"], "Fcm is DIRECT; its IP-ASN entry is skipped");
        assert_eq!(set("ip_2"), ["91.108.4.0/22"], "the inline set's IPv4 joins the run with GEOIP,NETFLIX");
        assert_eq!(set("geo_cn"), ["1.0.1.0/24"]);
        assert_eq!((c.returns, c.cut), (2, None));
        let compiled = routes().compile(&Selected::new(), &root, &[]);
        assert_eq!(compiled.geoip, ["CN", "NETFLIX"]);
        assert_eq!(compiled.sources.len(), 2, "both text rule sets were read");
        let mut sources = compiled.sources;
        assert!(!sources.iter_mut().any(Source::changed), "nothing changed");
        let path = sources[0].path.clone();
        let content = fs::read(&path).unwrap();
        let touched = sources[0].modified.unwrap() + std::time::Duration::from_secs(60);
        fs::File::options().write(true).open(&path).unwrap().set_modified(touched).unwrap();
        assert!(!sources[0].changed(), "a refresh that only touched the file");
        assert_eq!(sources[0].modified, Some(touched));
        let mut edited = content.clone();
        edited.extend_from_slice(b"\n# changed\n");
        fs::write(&path, &edited).unwrap();
        fs::File::options().write(true).open(&path).unwrap().set_modified(touched + std::time::Duration::from_secs(60)).unwrap();
        assert!(sources[0].changed(), "new content");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn any_direct_address_rule_returns_and_a_select_group_follows_its_choice() {
        let root = home("direct");
        let r = with_rules(&["IP-CIDR,1.1.1.0/24,P", "IP-CIDR,1.0.0.0/8,DIRECT", "GEOIP,JP,直连", "IP-CIDR,2.2.2.0/24,P", "IP-CIDR,3.3.3.0/24,P", "IP-CIDR,4.4.4.0/24,DIRECT", "IP-CIDR,5.5.5.0/24,P", "IP-CIDR,10.1.0.0/16,DIRECT", "MATCH,P"]);
        let c = chain(&r, &Selected::new(), &root);
        assert_eq!(c.rules, ["ip daddr @ip_0 goto to_core", "ip daddr @ip_1 return", "ip daddr @geo_jp return", "ip daddr @ip_2 goto to_core", "ip daddr @ip_3 return"], "the private range and the proxy rule before MATCH add nothing");
        let set = |name: &str| c.sets.iter().find(|(n, _)| n == name).map(|(_, e)| e.clone()).unwrap();
        assert_eq!(set("ip_2"), ["2.2.2.0/24", "3.3.3.0/24"], "consecutive ranges with one verdict share a set");
        assert_eq!(c.returns, 3);
        let away: Selected = [("直连".to_owned(), "P".to_owned())].into();
        let c = chain(&r, &away, &root);
        assert!(c.rules.contains(&"ip daddr @geo_jp goto to_core".to_owned()));
        assert_eq!(c.returns, 2);
        assert!(private_v4("192.168.0.44/32") && private_v4("10.0.0.0/8") && !private_v4("10.0.0.0/7") && !private_v4("1.0.0.0/8"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_proxy_rule_the_kernel_cannot_check_cuts_the_chain_a_direct_one_is_skipped() {
        let root = home("cut");
        let r = with_rules(&["IP-ASN,1,DIRECT", "NOT,((DOMAIN,a.com)),DIRECT", "GEOIP,CN,DIRECT", "IP-ASN,13335,P", "IP-CIDR,8.8.8.0/24,DIRECT", "MATCH,DIRECT"]);
        let c = chain(&r, &Selected::new(), &root);
        assert_eq!(c.rules, ["ip daddr @geo_cn return"], "earlier returns stay, nothing after the cut");
        assert_eq!(c.cut.as_deref(), Some("Rule 4 (IP-ASN,13335,P): IP-ASN rules need the core"));
        assert_eq!(c.returns, 1);
        let reason = |rules: &[&str]| chain(&with_rules(rules), &Selected::new(), &root).cut.unwrap();
        assert!(reason(&["RULE-SET,Bin,P"]).contains("not defined"));
        assert!(reason(&["NOT,((DOMAIN,a.com)),P"]).contains("NOT rules need the core"));
        assert!(reason(&["GEOIP,CN,P,src"]).contains("source GeoIP"));
        assert!(reason(&["GEOIP,XX,P"]).contains("GEOIP,XX: not in GeoIP.dat"), "a missing code is found when rendering");
        let c = chain(&with_rules(&["GEOIP,XX,DIRECT", "GEOIP,EMPTY,P", "GEOIP,CN,DIRECT", "MATCH,P"]), &Selected::new(), &root);
        assert_eq!((c.rules.as_slice(), c.cut), (&["ip daddr @geo_cn return".to_owned()][..], None), "a missing DIRECT code is skipped, an empty one never matches");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rule_set_files_and_geodata_mode_decide_what_the_kernel_can_check() {
        let root = home("files");
        let config = |extra: &str, rules: &str| Routes::from(&serde_yaml_ng::from_str(&format!("{extra}rule-providers:\n  Bin: {{type: http, behavior: ipcidr, format: mrs, path: ./ruleset/x.mrs}}\n  Gone: {{type: http, behavior: classical, format: text, path: ./ruleset/gone.list}}\n  Out: {{type: http, behavior: classical, format: text, path: ../outside.list}}\nrules: {rules}")).unwrap());
        let cut = |rules: &str| chain(&config("geodata-mode: true\n", rules), &Selected::new(), &root).cut.unwrap_or_default();
        assert!(cut("['RULE-SET,Bin,P']").contains("binary (mrs)"));
        assert!(cut("['RULE-SET,Gone,P']").contains("not downloaded yet"));
        assert!(cut("['RULE-SET,Out,P']").contains("no local file"));
        assert!(cut("['RULE-SET,Gone,DIRECT', 'MATCH,P']").is_empty(), "a DIRECT set that cannot be read is skipped");
        let c = chain(&config("", "['GEOIP,CN,DIRECT', 'GEOIP,US,P']"), &Selected::new(), &root);
        assert_eq!(c.returns, 0);
        assert!(c.cut.unwrap().contains("geodata-mode"), "without it the core uses geoip.metadb");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ports_networks_sources_and_logical_rules_compile_to_nft_matches() {
        let root = home("logic");
        let r = with_rules(&[
            "DST-PORT,22/8000-9000,P",
            "NETWORK,UDP,P",
            "SRC-IP-CIDR,192.168.0.9/32,P",
            "IP-CIDR,2.2.2.0/24,P,src",
            "AND,((NETWORK,UDP),(DST-PORT,443)),P",
            "AND,((IP-CIDR6,::1/128),(IP-ASN,1)),P",
            "OR,((IP-CIDR,1.1.1.0/24),(DOMAIN,x.com)),P",
            "PROCESS-NAME,curl,P",
            "AND,((GEOIP,CN),(OR,((DST-PORT,80),(DST-PORT,443)))),DIRECT",
            "MATCH,P",
        ]);
        let c = chain(&r, &Selected::new(), &root);
        assert_eq!(
            c.rules,
            [
                "ip daddr @ip_0 goto to_core",
                "th dport { 22, 8000-9000 } goto to_core",
                "meta l4proto udp goto to_core",
                "ip saddr 192.168.0.9/32 goto to_core",
                "ip saddr 2.2.2.0/24 goto to_core",
                "meta l4proto udp th dport { 443 } goto to_core",
                "ip daddr @geo_cn th dport { 80 } return",
                "ip daddr @geo_cn th dport { 443 } return",
            ]
        );
        assert_eq!(c.sets[0].1, ["1.1.1.0/24"]);
        assert_eq!(c.cut, None, "an AND that never matches IPv4 is skipped even with IP-ASN");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn addresses_ports_and_provider_paths_are_validated() {
        assert_eq!(v4_cidr("10.1.2.3/8"), Some(Ok("10.0.0.0/8".into())));
        assert_eq!(v4_cidr("1.2.3.4"), Some(Ok("1.2.3.4/32".into())));
        assert_eq!(v4_cidr("2001:db8::/32"), None);
        assert_eq!(v4_cidr("1.2.3.4/33"), Some(Err(())));
        assert_eq!(v4_cidr("nonsense"), Some(Err(())));
        assert_eq!(ports("443"), Some("{ 443 }".into()));
        assert_eq!(ports("90-80"), None);
        assert_eq!(ports("http"), None);
        let root = Path::new("/data/zte-agent-mihomo");
        assert_eq!(local_path(root, "./ruleset/a.list"), Some(root.join("ruleset/a.list")));
        assert_eq!(local_path(root, "/data/zte-agent-mihomo/b.yaml"), Some(root.join("b.yaml")));
        assert_eq!(local_path(root, "../etc/passwd"), None);
        assert_eq!(local_path(root, "/etc/passwd"), None);
    }

    /// D10: only what lost the bypass is reset, by destination when both
    /// chains are plain destinations up to their last return.
    #[test]
    fn a_switch_resets_what_lost_the_bypass_by_first_match() {
        use crate::netfx::conntrack::Scope;
        let root = home("lost");
        let plan = |rules: &[&str]| chain(&with_rules(rules), &Selected::new(), &root);
        let dests = |scope: Scope| match scope {
            Scope::Destinations(d) => d.iter().map(ToString::to_string).collect::<Vec<_>>(),
            other => panic!("{other:?}"),
        };
        let old = plan(&["IP-CIDR,9.9.9.0/24,DIRECT", "GEOIP,CN,DIRECT", "MATCH,P"]);
        assert!(dests(lost(&old, &old)).is_empty(), "the same table resets nothing");
        let fewer = plan(&["GEOIP,CN,DIRECT", "MATCH,P"]);
        assert_eq!(dests(lost(&old, &fewer)), ["9.9.9.0/24"]);
        assert!(dests(lost(&fewer, &old)).is_empty(), "gaining DIRECT keeps connections in the core");
        let shadowed = plan(&["IP-CIDR,9.9.9.128/25,P", "IP-CIDR,9.9.9.0/24,DIRECT", "GEOIP,CN,DIRECT", "MATCH,P"]);
        assert_eq!(dests(lost(&old, &shadowed)), ["9.9.9.128/25"], "first match: the proxy rule takes half the range");
        // A port rule ahead of an unchanged DIRECT range: its 443 flows must
        // leave too, so everything the old chain let through is reset.
        let port = plan(&["DST-PORT,443,P", "IP-CIDR,9.9.9.0/24,DIRECT", "GEOIP,CN,DIRECT", "MATCH,P"]);
        assert_eq!(dests(lost(&old, &port)), ["1.0.1.0/24", "9.9.9.0/24"]);
        assert_eq!(lost(&port, &old), Scope::Lan { v4: true, v6: false }, "an old chain that is not plain destinations resets the LAN");
        assert!(dests(lost(&Chain::default(), &old)).is_empty(), "nothing skipped the core before");
        assert_eq!(dests(lost(&old, &Chain::default())), ["1.0.1.0/24", "9.9.9.0/24"], "rule to global");
        let all = lost(&Chain::all(), &old);
        assert!(matches!(&all, Scope::Destinations(d) if d.len() > 2 && d.len() <= Scope::MAX_RANGES), "direct to rule: all but the DIRECT ranges, {all:?}");
        let many: Vec<String> = (0..70).map(|i| format!("IP-CIDR,10{}.{i}.0.0/16,DIRECT", i % 2)).chain(["MATCH,P".to_owned()]).collect();
        let many = plan(&many.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(lost(&many, &Chain::default()), Scope::Lan { v4: true, v6: false }, "more than 64 ranges");
        assert_eq!(ranges::to_cidrs(&[(0, u32::MAX)]).iter().map(ToString::to_string).collect::<Vec<_>>(), ["0.0.0.0/0"]);
        assert_eq!(ranges::to_cidrs(&[(u32::from(Ipv4Addr::new(10, 0, 0, 1)), u32::from(Ipv4Addr::new(10, 0, 0, 6)))]).iter().map(ToString::to_string).collect::<Vec<_>>(), ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]);
        // Finding 1: a table that failed to load may still be loaded by a
        // reconcile, so what it lets through counts as well.
        let other = plan(&["IP-CIDR,8.8.8.0/24,DIRECT", "MATCH,P"]);
        assert_eq!(dests(lost_from(&[fewer.clone(), other.clone()], &fewer)), ["8.8.8.0/24"]);
        assert!(dests(lost_from(&[Chain::default(), other.clone()], &other)).is_empty());
        assert!(dests(lost_from(&[], &other)).is_empty());
        let _ = fs::remove_dir_all(root);
    }

    /// Finding 6: a `domain` set's refresh cannot change the kernel plan.
    #[test]
    fn only_sets_the_kernel_reads_need_a_table_when_refreshed() {
        let config: serde_yaml_ng::Value = serde_yaml_ng::from_str("rule-providers:\n  names: {type: http, behavior: domain, url: 'https://example.invalid/a', interval: 3600}\n  cidrs: {type: http, behavior: ipcidr, url: 'https://example.invalid/b', interval: 3600}\n  rules: {type: http, behavior: classical, url: 'https://example.invalid/c', interval: 3600}\nrules: ['RULE-SET,names,DIRECT', 'MATCH,DIRECT']").unwrap();
        let routes = Routes::from(&config);
        assert_eq!(routes.refresh().len(), 3);
        assert!(!routes.reaches_kernel("names"));
        assert!(routes.reaches_kernel("cidrs") && routes.reaches_kernel("rules") && routes.reaches_kernel("unknown"));
    }

    /// v3: a reload is proven by an answer that must differ.
    #[test]
    fn a_reload_probe_is_a_name_whose_answer_must_change() {
        let r = with_rules(&["DOMAIN-SUFFIX,fixed.example,DIRECT", "DOMAIN-KEYWORD,ads,P", "GEOIP,CN,DIRECT", "MATCH,P"]);
        let (on, off) = (r.dns(true), r.dns(false));
        assert_eq!(reload_probe(&off, &on), Some(("u60-reload-probe.invalid".to_owned(), false)), "the default turned real");
        assert_eq!(reload_probe(&on, &off), Some(("u60-reload-probe.invalid".to_owned(), true)));
        let closed = with_rules(&["DOMAIN-SUFFIX,fixed.example,DIRECT", "RULE-SET,Missing,P", "GEOIP,CN,DIRECT", "MATCH,P"]);
        assert_eq!(closed.dns(true).last().unwrap(), "MATCH,fake-ip");
        assert_eq!(reload_probe(&closed.dns(false), &closed.dns(true)), Some(("fixed.example".to_owned(), false)), "a fixed DIRECT name when the default stays fake");
        assert_eq!(reload_probe(&on, &on), None, "the same filter: nothing to prove");
        let keyword = with_rules(&["DOMAIN-KEYWORD,fixed,DIRECT", "RULE-SET,Missing,P", "GEOIP,CN,DIRECT", "MATCH,P"]);
        assert_eq!(reload_probe(&keyword.dns(false), &keyword.dns(true)), None, "no plain name to ask");
    }

    #[test]
    fn selections_are_read_from_the_controller_listing() {
        let listing = serde_json::json!({"proxies": {"直连": {"type": "Selector", "now": "DIRECT"}, "自动选择": {"type": "URLTest", "now": "DIRECT"}, "JP": {"type": "Hysteria2"}}});
        let selected = selected_from(&listing).unwrap();
        assert_eq!(selected, [("直连".to_owned(), "DIRECT".to_owned())].into());
        assert!(selected_from(&serde_json::json!({})).is_none());
        assert_eq!(Mode::parse("Global"), Mode::Global);
        assert_eq!(Mode::parse("anything"), Mode::Rule);
    }
}
