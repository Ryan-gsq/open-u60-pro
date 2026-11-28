use std::cell::RefCell;
use std::fs;

use crate::net_tools::{Cmd, Probe};

#[derive(Default)]
pub struct Listings {
    read: Vec<(Cmd, Result<String, String>)>,
}

impl Listings {
    pub(crate) fn get(&mut self, listing: Cmd, probe: &mut impl Probe) -> Result<&str, String> {
        let index = match self.read.iter().position(|(command, _)| *command == listing) {
            Some(index) => index,
            None => {
                let text = probe.list(&listing).map_err(|error| format!("{} {}: {error}", listing.program, listing.args.join(" ")));
                self.read.push((listing, text));
                self.read.len() - 1
            }
        };
        self.read[index].1.as_deref().map_err(Clone::clone)
    }
}

thread_local! {
    static PASS: RefCell<Option<Listings>> = const { RefCell::new(None) };
    static NFT_READ: RefCell<Option<Result<String, String>>> = const { RefCell::new(None) };
    static PASS_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[must_use]
pub struct Pass {
    opened: bool,
}

impl Pass {
    pub fn open() -> Self {
        let opened = PASS_DEPTH.with(|depth| {
            let opened = depth.get() == 0;
            depth.set(depth.get() + 1);
            opened
        });
        if opened {
            PASS.with(|pass| *pass.borrow_mut() = Some(Listings::default()));
            NFT_READ.with(|read| read.borrow_mut().take());
        }
        Self { opened }
    }
}

impl Drop for Pass {
    fn drop(&mut self) {
        PASS_DEPTH.with(|depth| depth.set(depth.get() - 1));
        if self.opened {
            PASS.with(|pass| pass.borrow_mut().take());
            NFT_READ.with(|read| read.borrow_mut().take());
        }
    }
}

pub(crate) fn changed() {
    NFT_READ.with(|read| read.borrow_mut().take());
    PASS.with(|pass| {
        if let Some(listings) = pass.borrow_mut().as_mut() {
            *listings = Listings::default();
        }
    });
}

pub(crate) fn nft_ruleset(read: impl FnOnce() -> Result<String, String>) -> Result<String, String> {
    if PASS_DEPTH.with(|depth| depth.get() == 0) {
        return read();
    }
    NFT_READ.with(|cached| cached.borrow_mut().get_or_insert_with(read).clone())
}

pub(crate) fn with_listings<Result>(check: impl FnOnce(&mut Listings) -> Result) -> Result {
    let pass = Pass::open();
    let mut listings = PASS.with(|pass| pass.borrow_mut().take()).unwrap_or_default();
    let result = check(&mut listings);
    PASS.with(|pass| *pass.borrow_mut() = Some(listings));
    drop(pass);
    result
}

const ROUTE_TYPES: [&str; 9] = ["local", "broadcast", "throw", "unreachable", "prohibit", "blackhole", "nat", "anycast", "multicast"];

pub(crate) fn route_matches(listing: &str, kind: &str, destination: &str, table: &str, device: Option<&str>, gateway: Option<&str>, metric: Option<u32>) -> bool {
    listing.lines().any(|line| {
        let words: Vec<_> = line.split_whitespace().collect();
        let (listed, rest) = match words.as_slice() {
            [first, rest @ ..] if ROUTE_TYPES.contains(first) => (*first, rest),
            words => ("unicast", words),
        };
        let Some((to, rest)) = rest.split_first() else { return false };
        let value = |name| rest.windows(2).find(|pair| pair[0] == name).map(|pair| pair[1]);
        listed == kind
            && route_destination(to) == route_destination(destination)
            && route_table(value("table").unwrap_or("main")) == route_table(table)
            && device.is_none_or(|device| value("dev") == Some(device))
            && gateway.is_none_or(|gateway| value("via") == Some(gateway))
            && metric.is_none_or(|metric| value("metric").and_then(|value| value.parse::<u32>().ok()) == Some(metric))
    })
}

pub(crate) fn route_destination(text: &str) -> String {
    let (ip, length) = text.split_once('/').map_or((text, None), |(ip, length)| (ip, length.parse::<u8>().ok()));
    match ip.parse::<std::net::IpAddr>() {
        Ok(_) if length == Some(0) => "default".into(),
        Ok(ip) => format!("{ip}/{}", length.unwrap_or(if ip.is_ipv4() { 32 } else { 128 })),
        Err(_) => text.into(),
    }
}

pub(crate) fn route_table(name: &str) -> &str {
    match name {
        "main" => "254",
        "local" => "255",
        "default" => "253",
        _ => name,
    }
}

pub(crate) fn addr_listed(listing: &str, device: &str, address: &str) -> bool {
    listing.lines().any(|line| {
        let mut words = line.split_whitespace();
        words.nth(1) == Some(device) && words.any(|word| word == address)
    })
}

pub(crate) fn sysctl_path(key: &str) -> Option<&'static str> {
    Some(match key {
        "tcp_pacing_ss_ratio" => "/proc/sys/net/ipv4/tcp_pacing_ss_ratio",
        "tcp_pacing_ca_ratio" => "/proc/sys/net/ipv4/tcp_pacing_ca_ratio",
        "bridge-nf-call-iptables" => "/proc/sys/net/bridge/bridge-nf-call-iptables",
        "bridge-nf-call-ip6tables" => "/proc/sys/net/bridge/bridge-nf-call-ip6tables",
        "httpredirect_cmd" => "/sys/zte_genl/httpredirect_cmd",
        "ip_forward" => "/proc/sys/net/ipv4/ip_forward",
        "ipv6_forwarding" => "/proc/sys/net/ipv6/conf/all/forwarding",
        "all_rp_filter" => "/proc/sys/net/ipv4/conf/all/rp_filter",
        "tailscale0_rp_filter" => "/proc/sys/net/ipv4/conf/tailscale0/rp_filter",
        _ => return None,
    })
}

pub(crate) fn sysctl_interface(key: &str) -> Option<&'static str> {
    match key {
        "tailscale0_rp_filter" => Some(crate::netfx::ids::TAILSCALE_IFACE),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ParsedRule {
    pub priority: u32,
    pub to: Option<String>,
    pub mark: Option<(u32, u32)>,
    pub lookup: Option<String>,
    pub unreachable: bool,
}

pub(crate) fn parse_fwmark(text: &str) -> Option<(u32, u32)> {
    let parse_num = |part: &str| {
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            u32::from_str_radix(hex, 16).ok()
        } else {
            part.parse::<u32>().ok()
        }
    };
    match text.split_once('/') {
        Some((mark, mask)) => Some((parse_num(mark)?, parse_num(mask)?)),
        None => Some((parse_num(text)?, u32::MAX)),
    }
}

/// Parse one line from `ip -4/-6 rule show` into our supported rule subset.
/// Returns `None` for any rule carrying selectors or actions outside our schema
/// (such as `not`, `iif`, `oif`, non-`all` source, etc.).
pub(crate) fn parse_rule_line(line: &str) -> Option<ParsedRule> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let priority: u32 = words.first()?.strip_suffix(':')?.parse().ok()?;
    if words.get(1) != Some(&"from") || words.get(2) != Some(&"all") {
        return None;
    }
    let mut index = 3;
    let mut to = None;
    let mut mark = None;
    let mut lookup = None;
    let mut unreachable = false;
    while index < words.len() {
        match words[index] {
            "to" if to.is_none() && index + 1 < words.len() => {
                to = Some(route_destination(words[index + 1]));
                index += 2;
            }
            "fwmark" if mark.is_none() && index + 1 < words.len() => {
                mark = Some(parse_fwmark(words[index + 1])?);
                index += 2;
            }
            "lookup" if lookup.is_none() && !unreachable && index + 2 == words.len() => {
                lookup = Some(route_table(words[index + 1]).to_owned());
                index += 2;
            }
            "unreachable" if lookup.is_none() && !unreachable && index + 1 == words.len() => {
                unreachable = true;
                index += 1;
            }
            _ => return None,
        }
    }
    if lookup.is_none() && !unreachable {
        return None;
    }
    Some(ParsedRule { priority, to, mark, lookup, unreachable })
}

/// Parse an `ip -4/-6 rule del ...` argument vector into our supported rule subset.
pub(crate) fn parse_rule_del_args(args: &[String]) -> Option<ParsedRule> {
    if args.get(1).map(String::as_str) != Some("rule")
        || args.get(2).map(String::as_str) != Some("del")
    {
        return None;
    }
    let mut index = 3;
    let mut priority = None;
    let mut to = None;
    let mut mark = None;
    let mut lookup = None;
    let mut unreachable = false;
    while index < args.len() {
        match args[index].as_str() {
            "pref" if priority.is_none() && index + 1 < args.len() => {
                priority = args[index + 1].parse::<u32>().ok();
                priority?;
                index += 2;
            }
            "to" if to.is_none() && index + 1 < args.len() => {
                to = Some(route_destination(&args[index + 1]));
                index += 2;
            }
            "fwmark" if mark.is_none() && index + 1 < args.len() => {
                mark = Some(parse_fwmark(&args[index + 1])?);
                index += 2;
            }
            "lookup" if lookup.is_none() && !unreachable && index + 1 < args.len() => {
                lookup = Some(route_table(&args[index + 1]).to_owned());
                index += 2;
            }
            "unreachable" if lookup.is_none() && !unreachable => {
                unreachable = true;
                index += 1;
            }
            _ => return None,
        }
    }
    let priority = priority?;
    if lookup.is_none() && !unreachable {
        return None;
    }
    Some(ParsedRule { priority, to, mark, lookup, unreachable })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuleDelCheck {
    Missing,
    SafeSingleMatch,
    Ambiguous,
}

/// Inspect `ip rule show` before running `ip rule del`. Linux 5.15 `fib_rules.c`
/// treats `mark == 0` (e.g. `fwmark 0x0/0x80000`) and omitted selectors as
/// wildcards when deleting, so refuse deletion if any row at `priority` is
/// unparseable, duplicated, or could be matched ambiguously by `del`.
pub(crate) fn rule_del_check(rules: &str, args: &[String]) -> RuleDelCheck {
    let Some(expected) = parse_rule_del_args(args) else {
        return RuleDelCheck::Ambiguous;
    };
    let prefix = format!("{}:", expected.priority);
    let mut exact = 0usize;
    let mut ambiguous = false;
    let mut seen = std::collections::HashSet::new();
    for line in rules.lines().filter(|line| line.trim_start().starts_with(&prefix)) {
        let Some(parsed) = parse_rule_line(line) else {
            return RuleDelCheck::Ambiguous;
        };
        if !seen.insert(parsed.clone()) {
            return RuleDelCheck::Ambiguous;
        }
        if parsed == expected {
            exact += 1;
            continue;
        }
        // Check Linux fib_rule_match_del semantics: same action/table/to and
        // wildcard-compatible mark could let `ip rule del` remove `parsed`.
        let same_action = parsed.unreachable == expected.unreachable && parsed.lookup == expected.lookup;
        let same_to = expected.to.is_none() || parsed.to == expected.to;
        let mark_compatible = match (expected.mark, parsed.mark) {
            (None, _) => true,
            (Some((0, mask)), Some((_, parsed_mask))) => mask == 0 || parsed_mask == mask,
            (Some((0, 0)), None) => true,
            (Some((val, mask)), Some((pval, pmask))) => val == pval && (mask == 0 || pmask == mask),
            _ => false,
        };
        if same_action && same_to && mark_compatible {
            ambiguous = true;
        }
    }
    if ambiguous || exact > 1 {
        RuleDelCheck::Ambiguous
    } else if exact == 0 {
        RuleDelCheck::Missing
    } else {
        RuleDelCheck::SafeSingleMatch
    }
}

/// Whether an `ip -4/-6 rule del ...` command matches any line in `ip rule show`.
pub(crate) fn rule_del_listed(rules: &str, args: &[String]) -> bool {
    let Some(expected) = parse_rule_del_args(args) else {
        return true;
    };
    rules.lines().any(|line| parse_rule_line(line).as_ref() == Some(&expected))
}

pub fn sysctl_read(key: &str) -> Result<String, String> {
    let path = sysctl_path(key).ok_or("Unknown kernel setting")?;
    Ok(fs::read_to_string(path).map_err(|_| "Cannot read a kernel setting")?.trim().to_owned())
}

pub(crate) fn sysctl_command(args: &[String]) -> Result<(), String> {
    match args {
        [key, value] => sysctl_write(key, value),
        _ => Err("Invalid kernel setting".into()),
    }
}

pub fn sysctl_write(key: &str, value: &str) -> Result<(), String> {
    if !value.parse::<u32>().is_ok_and(|value| value <= 100_000) {
        return Err("Invalid kernel setting".into());
    }
    let path = sysctl_path(key).ok_or("Unknown kernel setting")?;
    fs::write(path, value).map_err(|_| "Cannot set a kernel setting".into())
}
