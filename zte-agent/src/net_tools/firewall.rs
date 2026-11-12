//! Bounded restore batches for generated, agent-owned firewall plans.
//! Preserve command order (including table COMMIT boundaries); a failed batch
//! is partially applied and must be unwound by its caller's durable journal.
//! Also how a rule an `-A`/`-I` step adds is listed (`-S`), and the undo of
//! the steps that add chains and rules.
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::time::Duration;

use super::{Cmd, Probe, Step};

fn token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.:/,+=![]".contains(&b))
}

fn entry(cmd: &Cmd) -> Option<(&str, &str, String)> {
    let program = match cmd.program.as_str() {
        "iptables" => "iptables-restore",
        "ip6tables" => "ip6tables-restore",
        _ => return None,
    };
    let a = &cmd.args;
    if a.len() < 6 || a[..3] != ["-w", "2", "-t"] || !a.iter().all(|s| token(s)) {
        return None;
    }
    let table = a[3].as_str();
    if !["filter", "nat", "mangle"].contains(&table) {
        return None;
    }
    let owned = a[5].starts_with("U60_");
    match a[4].as_str() {
        "-N" if owned && a.len() == 6 => Some((program, table, format!("-N {}", a[5]))),
        "-A" | "-I"
            if owned
                || [
                    "INPUT",
                    "OUTPUT",
                    "FORWARD",
                    "PREROUTING",
                    "POSTROUTING",
                    "redirect_chain",
                ]
                .contains(&a[5].as_str()) =>
        {
            Some((program, table, a[4..].join(" ")))
        }
        _ => None,
    }
}

#[derive(Debug)]
pub(super) struct Batch {
    program: String,
    input: String,
    pub(super) count: usize,
}

impl Batch {
    pub(super) fn collect(steps: &[Step]) -> Option<Self> {
        let (program, _, _) = entry(&steps.first()?.apply)?;
        let mut input = String::new();
        let mut current = "";
        let mut count = 0;
        for step in steps {
            let Some((next, table, line)) = entry(&step.apply) else {
                break;
            };
            if next != program || input.len() + line.len() > 128 * 1024 {
                break;
            }
            if table != current {
                if !current.is_empty() {
                    input.push_str("COMMIT\n");
                }
                input.push('*');
                input.push_str(table);
                input.push('\n');
                current = table;
            }
            input.push_str(&line);
            input.push('\n');
            count += 1;
        }
        if count == 0 {
            return None;
        }
        input.push_str("COMMIT\n");
        Some(Self {
            program: program.into(),
            input,
            count,
        })
    }

    pub(super) fn run(self) -> Result<(), String> {
        restore(&self.program, self.input)
    }
}

/// One `iptables-restore`/`ip6tables-restore --noflush` transaction: each
/// table's lines commit together or not at all.
pub(crate) fn restore(program: &str, input: String) -> Result<(), String> {
    let mut command = Command::new(program);
    command.args(["--noflush", "--wait", "2"]);
    super::run_input(command, Duration::from_secs(8), input.into_bytes()).map(|_| ())
}

/// What legacy iptables writes to standard error, with exit code 1, when a
/// `-C`/`-D` finds no such rule: libiptc's ENOENT, worded by what the rule
/// jumps to. A built-in target (ACCEPT, RETURN), or a chain that does not
/// exist, gives the first; an extension target (MASQUERADE) or a jump to a
/// user-defined chain that exists (every hook into a `U60_*` chain) gives
/// the second (B31, iptables 1.8.8, both families, 2026-11-12). A rule that
/// is there gives neither. Every other failure (2 a bad argument or an
/// unknown target, 4 the xtables lock not had within `-w 2`, a timeout)
/// says nothing about the rule.
const NO_RULE: [&str; 2] = ["does a matching rule exist in that chain", "No chain/target/match by that name"];

/// Whether a check's or delete's exit says the rule is not there.
pub(super) fn no_rule((code, error): &(i32, String)) -> bool {
    *code == 1 && NO_RULE.iter().any(|text| error.contains(text))
}

/// Whether a `-S` listing of a table has `chain` (a built-in one is listed
/// with its policy, `-P`).
pub(super) fn has_chain(listing: &str, chain: &str) -> bool {
    listing.lines().any(|line| {
        line == format!("-N {chain}")
            || line.strip_prefix("-P ").and_then(|rest| rest.strip_prefix(chain)).is_some_and(|rest| rest.starts_with(' '))
    })
}

/// Whether a rule (`-D`/`-A` arguments) is the agent's by the identity
/// `Transaction::apply_network` relies on: it sits in an owned `U60_*`
/// chain, jumps to one, or carries our comment. The relay's station name
/// is no identity (the vendor's IPACM configuration lists it too); the
/// names only older agents created (`ids::OLD_IFACES`) still are, for the
/// rules their journals hold. Another writer's identical rule fails all four.
pub(super) fn owned_rule(args: &[String]) -> bool {
    let Some(at) = args.iter().position(|a| matches!(a.as_str(), "-D" | "-A" | "-I")) else {
        return false;
    };
    let values = |flag: &str| args.windows(2).filter(|w| w[0] == flag).map(|w| w[1].as_str()).collect::<Vec<_>>();
    args.get(at + 1).is_some_and(|chain| chain.starts_with("U60_"))
        || values("-j").iter().any(|t| t.starts_with("U60_"))
        || values("-i").iter().chain(&values("-o")).any(|name| crate::netfx::ids::OLD_IFACES.contains(name))
        || values("--comment").iter().any(|c| c.starts_with("zte-agent"))
}

/// Copies of one owned rule a single undo removes at most; more keep the
/// journal for the next cleanup.
const COPIES: usize = 32;

/// The undo of an `-N` (`-X`) or `-A`/`-I` (`-D`) step. A rule may be in
/// place more than once (a re-apply after a check that failed for another
/// reason, before that was told apart; or an older agent's): every copy of
/// an owned rule is deleted, and an owned chain that still holds rules is
/// emptied before it is deleted, or its `-X` would fail on every later
/// recovery. Another writer's rule keeps the single `-D` it always had, and
/// a chain that is not `U60_*` is never emptied. Only a definite answer
/// (`no_rule`, a listing without the chain) counts as already removed: a
/// crash may come between journaling and applying a step, but a tool or
/// lock failure is no evidence of absence, so the journal is kept.
pub(super) fn undo(cmd: &Cmd, probe: &mut impl Probe) -> Result<(), String> {
    let args = &cmd.args;
    let table = args.windows(2).find(|w| w[0] == "-t").map_or("filter", |w| w[1].as_str());
    let listing = Cmd::new(&cmd.program, &["-w", "2", "-t", table, "-S"]);
    let failed = || "Cannot restore an owned network change".to_owned();
    if let Some(at) = args.iter().position(|a| a == "-X") {
        let chain = args.get(at + 1).ok_or_else(failed)?;
        if probe.status(cmd).is_ok_and(|s| s.0 == 0) {
            return Ok(());
        }
        let tables = probe.list(&listing)?;
        if !has_chain(&tables, chain) {
            return Ok(());
        }
        // Emptied only when nothing jumps to it any more, so that its delete
        // can then succeed: a hook outside the journal keeps the chain whole.
        let jumped = tables.lines().any(|line| line.starts_with("-A ") && line.split(' ').collect::<Vec<_>>().windows(2).any(|w| matches!(w[0], "-j" | "-g") && w[1] == chain));
        if chain.starts_with("U60_") && !jumped {
            let mut flush = cmd.clone();
            flush.args[at] = "-F".into();
            if probe.status(&flush).is_ok_and(|s| s.0 == 0) && probe.status(cmd).is_ok_and(|s| s.0 == 0) {
                return Ok(());
            }
        }
        return Err(failed());
    }
    let at = args.iter().position(|a| a == "-D").ok_or_else(failed)?;
    let chain = args.get(at + 1).ok_or_else(failed)?;
    let every = owned_rule(args);
    for _ in 0..COPIES {
        match probe.status(cmd) {
            Ok((0, _)) if every => {}
            Ok((0, _)) => return Ok(()),
            Ok(status) if no_rule(&status) => return Ok(()),
            _ => break,
        }
    }
    // The delete failed for another reason, or copies remain.
    let tables = probe.list(&listing)?;
    let target = args.windows(2).find(|w| w[0] == "-j").map(|w| w[1].as_str());
    // Without its chain, or its owned target chain, the rule cannot exist
    // (and the tool refuses a check that names a missing target).
    if !has_chain(&tables, chain) || target.is_some_and(|t| t.starts_with("U60_") && !has_chain(&tables, t)) {
        return Ok(());
    }
    let mut check = cmd.clone();
    check.args[at] = "-C".into();
    match probe.status(&check) {
        Ok(status) if no_rule(&status) => Ok(()),
        _ => Err(failed()),
    }
}

/// The line `iptables -S` / `ip6tables -S` prints for the rule an `-A`/`-I`
/// step adds, or `None` for a rule whose listed form this does not know (the
/// caller then asks the tool, `-C`). The tool does not print the arguments
/// it was given: the address part comes first in a fixed order (`-s -d -i -o
/// -p`), addresses are masked and get their prefix length (`/32`), a port or
/// ICMPv6 option loads the protocol's own match where it first appears
/// (`-p tcp -m tcp --dport 53`), conntrack states and a match's options come
/// in the tool's order, and a comment with other than letters, digits, `-`
/// and `_` is quoted. Only what the agent's rules use is known; a different
/// rule never gets the same line, so a prediction that is wrong costs one
/// `-C`, never a wrong answer.
pub(super) fn listed_rule(cmd: &Cmd) -> Option<String> {
    let v6 = match cmd.program.as_str() {
        "iptables" => false,
        "ip6tables" => true,
        _ => return None,
    };
    let args = &cmd.args;
    let at = args.iter().position(|a| matches!(a.as_str(), "-A" | "-I"))?;
    let chain = args.get(at + 1)?;
    let mut rest = &args[at + 2..];
    if args[at] == "-I" && rest.first().is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit())) {
        rest = &rest[1..];
    }
    // -s -d -i -o -p, as the tool prints them.
    let mut head: [Option<String>; 5] = Default::default();
    let mut matches: Vec<(&'static str, Vec<(&str, String)>)> = Vec::new();
    let mut target = None;
    for pair in rest.chunks(2) {
        let [flag, value] = pair else { return None };
        if target.is_some() {
            return None;
        }
        let slot = match flag.as_str() {
            "-s" => Some((0, address(value, v6)?)),
            "-d" => Some((1, address(value, v6)?)),
            "-i" => Some((2, interface(value)?)),
            "-o" => Some((3, interface(value)?)),
            "-p" => Some((4, protocol(value, v6)?)),
            _ => None,
        };
        if let Some((i, text)) = slot {
            if head[i].replace(text).is_some() {
                return None;
            }
            continue;
        }
        let protocol = match head[4].as_deref() {
            Some("tcp") => Some("tcp"),
            Some("udp") => Some("udp"),
            Some("ipv6-icmp") => Some("ipv6-icmp"),
            _ => None,
        };
        match flag.as_str() {
            "-m" => {
                let name = match (value.as_str(), protocol) {
                    ("conntrack", _) => "conntrack",
                    ("comment", _) => "comment",
                    ("hl", _) if v6 => "hl",
                    ("tcp", Some("tcp")) => "tcp",
                    ("udp", Some("udp")) => "udp",
                    ("icmp6", Some("ipv6-icmp")) => "icmp6",
                    _ => return None,
                };
                if matches.iter().any(|(m, _)| *m == name) {
                    return None;
                }
                matches.push((name, Vec::new()));
            }
            "-j" => target = Some(jump(value)?),
            option => {
                let (owner, text) = match option {
                    "--ctstate" => ("conntrack", states(value)?),
                    "--comment" => ("comment", saved_string(value)?),
                    "--hl-eq" | "--hl-lt" | "--hl-gt" => ("hl", value.parse::<u8>().ok()?.to_string()),
                    "--sport" | "--dport" => (protocol.filter(|p| matches!(*p, "tcp" | "udp"))?, port(value)?),
                    "--icmpv6-type" => (protocol.filter(|p| *p == "ipv6-icmp").map(|_| "icmp6")?, value.parse::<u8>().ok()?.to_string()),
                    _ => return None,
                };
                // The protocol's match loads where its first option is.
                if !matches.iter().any(|(m, _)| *m == owner) {
                    if !matches!(owner, "tcp" | "udp" | "icmp6") {
                        return None;
                    }
                    matches.push((owner, Vec::new()));
                }
                let options = &mut matches.iter_mut().find(|(m, _)| *m == owner)?.1;
                if options.iter().any(|(o, _)| *o == option) || (owner == "hl" && !options.is_empty()) {
                    return None;
                }
                options.push((option, text));
            }
        }
    }
    let mut line = format!("-A {chain}");
    for (flag, value) in ["-s", "-d", "-i", "-o", "-p"].iter().zip(&head) {
        if let Some(value) = value {
            line.push_str(&format!(" {flag} {value}"));
        }
    }
    for (name, mut options) in matches {
        if options.is_empty() {
            return None;
        }
        // tcp/udp print the source port first.
        options.sort_by_key(|(o, _)| *o != "--sport");
        line.push_str(&format!(" -m {name}"));
        for (option, value) in options {
            line.push_str(&format!(" {option} {value}"));
        }
    }
    if let Some(target) = target {
        line.push_str(&format!(" -j {target}"));
    }
    Some(line)
}

/// An address as the tool lists it: masked, with its prefix length, IPv6 in
/// musl's `inet_ntop` form (the router's libc).
fn address(value: &str, v6: bool) -> Option<String> {
    let (ip, length) = match value.split_once('/') {
        Some((ip, length)) => (ip, Some(length.parse::<u32>().ok()?)),
        None => (value, None),
    };
    if v6 {
        let length = length.unwrap_or(128);
        if !(1..=128).contains(&length) {
            return None;
        }
        let bits = u128::from(ip.parse::<Ipv6Addr>().ok()?) & (u128::MAX << (128 - length));
        Some(format!("{}/{length}", ipv6_text(Ipv6Addr::from(bits))?))
    } else {
        let length = length.unwrap_or(32);
        if !(1..=32).contains(&length) {
            return None;
        }
        let bits = u32::from(ip.parse::<Ipv4Addr>().ok()?) & (u32::MAX << (32 - length));
        Some(format!("{}/{length}", Ipv4Addr::from(bits)))
    }
}

/// musl's `inet_ntop`: the longest run of zero groups (at least two; on a tie
/// the first, but a run at the start counts one character less) becomes
/// `::`. Mapped IPv4 is printed another way and is not predicted.
fn ipv6_text(ip: Ipv6Addr) -> Option<String> {
    let groups = ip.segments();
    if groups[..5] == [0; 5] && groups[5] == 0xffff {
        return None;
    }
    let text = groups.iter().map(|g| format!("{g:x}")).collect::<Vec<_>>().join(":");
    let bytes = text.as_bytes();
    let (mut best, mut longest) = (0, 2);
    for i in 0..bytes.len() {
        if i > 0 && bytes[i] != b':' {
            continue;
        }
        let run = bytes[i..].iter().take_while(|b| matches!(b, b':' | b'0')).count();
        if run > longest {
            (best, longest) = (i, run);
        }
    }
    Some(if longest > 3 { format!("{}::{}", &text[..best], &text[best + longest..]) } else { text })
}

fn interface(value: &str) -> Option<String> {
    (!value.is_empty() && value.len() < 16 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))).then(|| value.to_owned())
}

fn protocol(value: &str, v6: bool) -> Option<String> {
    Some(match value {
        "tcp" | "udp" => value.to_owned(),
        "ipv6-icmp" | "icmpv6" if v6 => "ipv6-icmp".to_owned(),
        _ => return None,
    })
}

/// A single port; ranges and service names are listed differently.
fn port(value: &str) -> Option<String> {
    value.parse::<u16>().ok().filter(|p| *p > 0).map(|p| p.to_string())
}

/// Targets listed without options, and the owned chains.
fn jump(value: &str) -> Option<String> {
    (matches!(value, "ACCEPT" | "DROP" | "RETURN" | "MASQUERADE") || (value.starts_with("U60_") && interface(value).is_some()))
        .then(|| value.to_owned())
}

/// conntrack states in the order the match prints them.
fn states(value: &str) -> Option<String> {
    const ORDER: [&str; 7] = ["INVALID", "NEW", "RELATED", "ESTABLISHED", "UNTRACKED", "SNAT", "DNAT"];
    let given: Vec<&str> = value.split(',').collect();
    if given.iter().any(|s| !ORDER.contains(s)) {
        return None;
    }
    Some(ORDER.iter().filter(|s| given.contains(s)).copied().collect::<Vec<_>>().join(","))
}

/// `xtables_save_string`: bare if only letters, digits, `_` and `-`, else
/// quoted with `"`, `\` and `'` escaped.
fn saved_string(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 255 || value.contains('\n') {
        return None;
    }
    if value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Some(value.to_owned());
    }
    let mut quoted = String::from("\"");
    for c in value.chars() {
        if matches!(c, '"' | '\\' | '\'') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    Some(quoted)
}

/// The restore transactions `Transaction::apply_network` runs for `steps`
/// (program, input), skipping the steps between them: isolated acceptance.
#[cfg(test)]
pub(crate) fn inputs(steps: &[Step]) -> Vec<(String, String)> {
    let (mut out, mut at) = (Vec::new(), 0);
    while at < steps.len() {
        match Batch::collect(&steps[at..]) {
            Some(batch) => {
                at += batch.count;
                out.push((batch.program, batch.input));
            }
            None => at += 1,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_tools::bench::{LOCKED, NO_RULE};
    use crate::net_tools::rule;

    /// iptables as far as an undo sees it: per table, chains holding their
    /// rules as argument text; scripted lock failures by call number.
    #[derive(Default)]
    struct Kernel {
        chains: Vec<(String, String, bool, Vec<String>)>,
        calls: usize,
        locked: Vec<usize>,
    }

    impl Kernel {
        fn chain(&mut self, table: &str, name: &str, rules: &[&str]) {
            let builtin = name.bytes().all(|b| b.is_ascii_uppercase());
            self.chains.push((table.into(), name.into(), builtin && !name.starts_with("U60_"), rules.iter().map(|r| (*r).to_owned()).collect()));
        }

        fn rules(&self, table: &str, name: &str) -> Option<Vec<&str>> {
            self.chains.iter().find(|c| c.0 == table && c.1 == name).map(|c| c.3.iter().map(String::as_str).collect())
        }

        fn at(&self, table: &str, name: &str) -> Option<usize> {
            self.chains.iter().position(|c| c.0 == table && c.1 == name)
        }
    }

    impl Probe for Kernel {
        fn list(&mut self, cmd: &Cmd) -> Result<String, String> {
            self.calls += 1;
            if self.locked.contains(&self.calls) {
                return Err("Device tool failed (exit status: 4)".into());
            }
            let table = &cmd.args[3];
            let mut text = String::new();
            for (t, name, builtin, rules) in &self.chains {
                if t == table {
                    text.push_str(&if *builtin { format!("-P {name} ACCEPT\n") } else { format!("-N {name}\n") });
                    rules.iter().for_each(|r| text.push_str(&format!("-A {name} {r}\n")));
                }
            }
            Ok(text)
        }

        fn status(&mut self, cmd: &Cmd) -> Result<(i32, String), String> {
            self.calls += 1;
            if self.locked.contains(&self.calls) {
                return Ok((LOCKED.0, LOCKED.1.into()));
            }
            let (table, op, name, spec) = (&cmd.args[3], cmd.args[4].as_str(), &cmd.args[5], cmd.args[6..].join(" "));
            let no_chain = Ok((1, "iptables: No chain/target/match by that name.".to_owned()));
            let no_rule = Ok((NO_RULE.0, NO_RULE.1.to_owned()));
            let target = cmd.args.windows(2).find(|w| w[0] == "-j").map(|w| w[1].clone());
            match op {
                "-C" | "-D" => {
                    if target.as_ref().is_some_and(|t| t.starts_with("U60_") && self.at(table, t).is_none()) {
                        return Ok((2, "iptables v1.8.8 (legacy): Couldn't load target `U60_'".into()));
                    }
                    let Some(at) = self.at(table, name) else { return no_rule };
                    // As B31 answers: a missing rule that jumps to a
                    // user-defined chain is worded like a missing chain.
                    let jumps = target.as_ref().is_some_and(|t| self.at(table, t).is_some());
                    let Some(rule) = self.chains[at].3.iter().position(|r| *r == spec) else { return if jumps { no_chain } else { no_rule } };
                    if op == "-D" {
                        self.chains[at].3.remove(rule);
                    }
                    Ok((0, String::new()))
                }
                "-F" => {
                    let Some(at) = self.at(table, name) else { return no_chain };
                    self.chains[at].3.clear();
                    Ok((0, String::new()))
                }
                "-X" => {
                    let Some(at) = self.at(table, name) else { return no_chain };
                    if !self.chains[at].3.is_empty() {
                        return Ok((1, "iptables: Directory not empty.".into()));
                    }
                    if self.chains.iter().any(|c| c.0 == *table && c.3.iter().any(|r| r.ends_with(&format!("-j {name}")))) {
                        return Ok((1, "iptables: Too many links.".into()));
                    }
                    self.chains.remove(at);
                    Ok((0, String::new()))
                }
                _ => panic!("unexpected {cmd:?}"),
            }
        }

        fn apply(&mut self, cmd: &Cmd) -> Result<(), String> {
            panic!("an undo applies nothing: {cmd:?}")
        }
    }

    const VENDOR_LO: &str = "-i lo -m comment --comment !fw3 -j ACCEPT";
    const VENDOR_REJECT: &str = "-m comment --comment !fw3 -j reject";
    /// What `firewall_redirect.sh` added while the switch was 1 (2026-11-12).
    const VENDOR_DNAT: &str = "! -d 192.168.0.1/32 -p tcp -m tcp --dport 80 -m limit --limit 20/sec --limit-burst 40 -j DNAT --to-destination 192.168.0.1";
    const HOOK: &str = "-i ath20 -j U60_RELAY_IN";
    const ESTABLISHED: &str = "-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT";
    const DHCP: &str = "-p udp --sport 67 --dport 68 -j ACCEPT";
    const RETURN: &str = "-i br-lan -m comment --comment zte-agent-wifi-relay -j RETURN";

    fn args(text: &str) -> Vec<&str> {
        text.split(' ').collect()
    }

    /// The undos of the relay's upstream INPUT accepts and portal RETURN as
    /// its plans journal them, plus a rule without our identity, newest first.
    fn journal() -> Vec<Cmd> {
        let mut plan = super::super::chain("iptables", "filter", "U60_RELAY_IN");
        plan.push(rule("iptables", "filter", "U60_RELAY_IN", &args(ESTABLISHED), false));
        plan.push(rule("iptables", "filter", "U60_RELAY_IN", &args(DHCP), false));
        plan.push(rule("iptables", "filter", "INPUT", &args(HOOK), true));
        plan.push(rule("iptables", "nat", "redirect_chain", &args(RETURN), true));
        plan.push(rule("iptables", "filter", "OUTPUT", &["-o", "rmnet+", "-j", "REJECT"], true));
        plan.into_iter().rev().map(|s| s.undo).collect()
    }

    #[test]
    fn an_older_builds_duplicates_are_removed_and_every_vendor_rule_is_kept() {
        let mut kernel = Kernel::default();
        // A check that failed on the lock re-added the hook, the RETURN and
        // an accept: a single -D per rule left a copy and -X then failed.
        kernel.chain("filter", "INPUT", &[HOOK, VENDOR_LO, HOOK, VENDOR_REJECT]);
        kernel.chain("filter", "U60_RELAY_IN", &[ESTABLISHED, DHCP, ESTABLISHED]);
        // The vendor's identical twin of a rule without our identity.
        kernel.chain("filter", "OUTPUT", &["-o rmnet+ -j REJECT", "-o rmnet+ -j REJECT"]);
        kernel.chain("nat", "redirect_chain", &[VENDOR_DNAT, RETURN, RETURN]);
        for undo in journal() {
            undo_with(&undo, &mut kernel).unwrap_or_else(|e| panic!("{undo:?}: {e}"));
        }
        assert_eq!(kernel.rules("filter", "INPUT").unwrap(), [VENDOR_LO, VENDOR_REJECT]);
        assert_eq!(kernel.rules("filter", "U60_RELAY_IN"), None, "emptied and deleted");
        assert_eq!(kernel.rules("filter", "OUTPUT").unwrap(), ["-o rmnet+ -j REJECT"], "only one copy of a rule we cannot tell apart");
        assert_eq!(kernel.rules("nat", "redirect_chain").unwrap(), [VENDOR_DNAT]);
        // A recovery interrupted after these finds the owned ones gone.
        for undo in journal().iter().filter(|u| owned_rule(&u.args) || u.args.contains(&"-X".to_owned())) {
            undo_with(undo, &mut kernel).unwrap();
        }
    }

    fn undo_with(cmd: &Cmd, kernel: &mut Kernel) -> Result<(), String> {
        undo(cmd, kernel)
    }

    /// The relay's MASQUERADE is keyed by its interface alone. Under the
    /// station's name, which the vendor's IPACM configuration also lists,
    /// its comment is the identity: every copy goes, a vendor twin without
    /// it is deleted once. A rule an older agent journaled under its own
    /// interface names is still its own.
    #[test]
    fn an_interface_is_an_identity_only_under_the_names_older_agents_used() {
        const OURS: &str = "-o ath20 -m comment --comment zte-agent-wifi-relay -j MASQUERADE";
        const BARE: &str = "-o ath20 -j MASQUERADE";
        const OLD: &str = "-o u60sta0 -j MASQUERADE";
        let masquerade = |spec: &str| rule("iptables", "nat", "POSTROUTING", &args(spec), true).undo;
        assert!(owned_rule(&masquerade(OURS).args) && owned_rule(&masquerade(OLD).args));
        assert!(owned_rule(&masquerade("-i u60mh0 -j ACCEPT").args), "the core's former TUN device");
        assert!(!owned_rule(&masquerade(BARE).args), "the station's name alone is not ours");
        assert!(!owned_rule(&masquerade("-o u60sta1 -j MASQUERADE").args), "only the names older agents created");
        let mut kernel = Kernel::default();
        kernel.chain("nat", "POSTROUTING", &[OURS, BARE, OURS, OLD, OLD, BARE]);
        for spec in [OURS, OLD, BARE] {
            undo_with(&masquerade(spec), &mut kernel).unwrap_or_else(|e| panic!("{spec}: {e}"));
        }
        assert_eq!(kernel.rules("nat", "POSTROUTING").unwrap(), [BARE], "one delete for a rule we cannot tell apart");
    }

    #[test]
    fn a_lock_during_cleanup_keeps_the_step_until_the_answer_is_definite() {
        let hook = rule("iptables", "filter", "INPUT", &args(HOOK), true).undo;
        let mut kernel = Kernel::default();
        kernel.chain("filter", "INPUT", &[HOOK, VENDOR_LO, HOOK]);
        kernel.chain("filter", "U60_RELAY_IN", &[]);
        // The second delete and the check that follows run into the lock.
        kernel.locked = vec![2, 4];
        assert!(undo(&hook, &mut kernel).is_err(), "kept: a copy may remain");
        assert_eq!(kernel.rules("filter", "INPUT").unwrap(), [VENDOR_LO, HOOK]);
        undo(&hook, &mut kernel).unwrap();
        assert_eq!(kernel.rules("filter", "INPUT").unwrap(), [VENDOR_LO]);
        // Gone already, but the lock answers: not taken as gone.
        kernel.calls = 0;
        kernel.locked = vec![1, 3];
        assert!(undo(&hook, &mut kernel).is_err());
        kernel.locked.clear();
        undo(&hook, &mut kernel).unwrap();
        // The listing itself fails: kept.
        kernel.calls = 0;
        kernel.locked = vec![1, 2];
        assert!(undo(&hook, &mut kernel).is_err());
    }

    #[test]
    fn steps_that_never_ran_are_undone_without_their_chains() {
        let mut kernel = Kernel::default();
        kernel.chain("filter", "INPUT", &[VENDOR_LO]);
        for undo in journal().into_iter().filter(|u| u.args[3] == "filter" && u.args[5] != "OUTPUT") {
            super::undo(&undo, &mut kernel).unwrap_or_else(|e| panic!("{undo:?}: {e}"));
        }
        assert_eq!(kernel.rules("filter", "INPUT").unwrap(), [VENDOR_LO]);
    }

    /// The answers B31 gave (iptables 1.8.8 legacy, both families,
    /// 2026-11-12).
    #[test]
    fn only_the_two_wordings_of_a_missing_rule_mean_it_is_not_there() {
        let says = |code: i32, text: &str| no_rule(&(code, text.to_owned()));
        assert!(says(1, "iptables: Bad rule (does a matching rule exist in that chain?)."), "a built-in target, or no such chain");
        assert!(says(1, "ip6tables: No chain/target/match by that name."), "a jump to a user-defined chain that exists");
        assert!(!says(2, "iptables v1.8.8 (legacy): Couldn't load target `U60_NO_SUCH':No such file or directory"));
        assert!(!says(LOCKED.0, LOCKED.1));
        assert!(!says(1, "iptables: Too many links."));
        assert!(!says(0, ""));
    }

    /// Seen on B31 (2026-11-12): the vendor's firewall start flushed INPUT
    /// after the hook went in and left the owned chain. The hook's undo then
    /// finds nothing to delete, worded as a jump to a chain that exists; read
    /// as "could not check", it paused every later cleanup.
    #[test]
    fn a_hook_the_vendor_flushed_is_undone_while_its_chain_stays() {
        let mut kernel = Kernel::default();
        kernel.chain("filter", "INPUT", &[VENDOR_LO]);
        kernel.chain("filter", "U60_RELAY_IN", &[]);
        let hook = Cmd::new("ip6tables", &["-w", "2", "-t", "filter", "-D", "INPUT", "-i", "ath20", "-j", "U60_RELAY_IN"]);
        assert_eq!(undo(&hook, &mut kernel), Ok(()));
        // And one that is there: every copy goes, then the same answer ends it.
        kernel.chains[0].3.extend([HOOK.to_owned(), HOOK.to_owned()]);
        assert_eq!(undo(&hook, &mut kernel), Ok(()));
        assert_eq!(kernel.rules("filter", "INPUT").unwrap(), [VENDOR_LO]);
        assert_eq!(undo(&Cmd::new("ip6tables", &["-w", "2", "-t", "filter", "-X", "U60_RELAY_IN"]), &mut kernel), Ok(()));
        assert!(kernel.rules("filter", "U60_RELAY_IN").is_none());
    }

    #[test]
    fn an_owned_chain_is_emptied_before_deletion_and_a_vendor_chain_never() {
        let mut kernel = Kernel::default();
        kernel.chain("filter", "U60_R6_IN", &["-p udp --sport 547 --dport 546 -j ACCEPT"]);
        kernel.chain("filter", "vendor_chain", &[VENDOR_LO]);
        undo(&Cmd::new("iptables", &["-w", "2", "-t", "filter", "-X", "U60_R6_IN"]), &mut kernel).unwrap();
        assert_eq!(kernel.rules("filter", "U60_R6_IN"), None);
        assert!(undo(&Cmd::new("iptables", &["-w", "2", "-t", "filter", "-X", "vendor_chain"]), &mut kernel).is_err());
        assert_eq!(kernel.rules("filter", "vendor_chain").unwrap(), [VENDOR_LO]);
        // Still referenced (a hook outside this journal): kept, not deleted.
        kernel.chain("filter", "U60_X", &["-j RETURN"]);
        kernel.chain("filter", "FORWARD", &["-j U60_X"]);
        assert!(undo(&Cmd::new("iptables", &["-w", "2", "-t", "filter", "-X", "U60_X"]), &mut kernel).is_err());
        assert_eq!(kernel.rules("filter", "FORWARD").unwrap(), ["-j U60_X"]);
        assert_eq!(kernel.rules("filter", "U60_X").unwrap(), ["-j RETURN"], "not emptied");
    }

    #[test]
    fn restore_preserves_tables_insert_positions_and_effect_barriers() {
        let mut plan = super::super::chain("iptables", "filter", "U60_TEST");
        plan.push(super::super::rule(
            "iptables",
            "filter",
            "INPUT",
            &["-j", "U60_TEST"],
            true,
        ));
        plan.extend(super::super::chain("iptables", "nat", "U60_DNS"));
        plan.push(Step::new(
            Cmd::new("ip", &["-4", "rule", "add"]),
            Cmd::new("true", &[]),
        ));
        plan.extend(super::super::chain("iptables", "mangle", "U60_LATER"));
        let batch = Batch::collect(&plan).unwrap();
        assert_eq!(batch.count, 3);
        assert_eq!(
            batch.input,
            "*filter\n-N U60_TEST\n-I INPUT 1 -j U60_TEST\nCOMMIT\n*nat\n-N U60_DNS\nCOMMIT\n"
        );
        for cmd in [
            Cmd::new("iptables", &["-F"]),
            Cmd::new("iptables", &["-w", "2", "-t", "filter", "-N", "vendor"]),
            Cmd::new(
                "iptables",
                &["-w", "2", "-t", "filter", "-A", "U60_TEST", "\nCOMMIT"],
            ),
        ] {
            assert!(entry(&cmd).is_none());
        }
    }
}
