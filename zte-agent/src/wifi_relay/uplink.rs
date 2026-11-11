//! The relay's own nftables tables, `ip`/`ip6 u60_relay`, built in one place
//! (`relay-mihomo-architecture.md` section 4.3). Denials live here; legacy
//! iptables keeps only the accepts that must pass the vendor's DROP/REJECT
//! (`U60_RELAY_IN`, `U60_RELAY_FWD`, `U60_R6_IN`, `U60_R6_FWD`), the portal
//! RETURN and the IPv4 MASQUERADE (D11 not proven). A return here leaves
//! only these chains: the vendor's rules still apply after them.
//!
//! What the tables hold follows the session (`Layout`):
//! - always, from before `u60sta0` is raised (a scan too) until the station
//!   is gone: the upstream INPUT guard and a drop of all forwarding through
//!   the upstream;
//! - `relay` (routes installed): the forwarding returns, the relay DNS, and
//!   the IPv6 baseline (cellular rejected first, LAN-local exceptions, the
//!   one OUTPUT reject to `rmnet*`). Routes are released after shrinking back;
//! - `discovery` (IPv6 requested and started): RA, NS/NA, ICMPv6 errors and
//!   DHCPv6 replies on the upstream; closed otherwise;
//! - `nat66` (a valid IPv6 lease, from `ipv6`): its forwarding returns, the
//!   masquerade and IPv6 DNS.
//!
//! Each change replaces both families in one batch (`NftTables`, marker
//! read back); ZTE never touches nftables. The journal entry is the wireless
//! plan's: `@u60-relay-nft remove ip|ip6`, which every agent since relay DNS
//! moved to nftables (the TPROXY release) runs.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{json, Value};

use crate::net_tools::{self as net, Cmd, Step};
use crate::netfx::effect::{self, Nft, NftTables, Presence};
use crate::netfx::ids;

pub(crate) const TABLE: &str = ids::RELAY_NFT;
const IFACE: &str = ids::RELAY_IFACE;
/// NAT priority of the relay's LAN DNS chain (Mihomo's redirect: `dstnat - 2`).
pub(crate) const DNS_PRIORITY: &str = "dstnat - 1";
/// The output hook takes no `dstnat` keyword: just ahead of legacy NAT (-100).
const DNS_OUTPUT_PRIORITY: &str = "-101";
/// Just ahead of the vendor's legacy filter (0): a drop here is final,
/// whatever ZTE inserts first in legacy.
const FILTER: &str = "filter - 1";
/// Ahead of legacy NAT (100): the first NAT chain that binds a connection wins.
const SRCNAT: &str = "srcnat - 1";

/// What the session holds; see the module comment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layout {
    pub relay: Option<Relay>,
    pub discovery: bool,
    pub nat66: Option<Nat66>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relay {
    /// The Wi-Fi resolver (the gateway without one).
    pub dns: Ipv4Addr,
    /// The LAN subnet, `a.b.c.d/n`.
    pub lan: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nat66 {
    /// LAN source prefixes allowed out (the relay ULA among them).
    pub sources: Vec<String>,
    /// The upstream resolver for the router's own DNS; without one it is
    /// rejected so IPv4 DNS is used.
    pub dns: Option<Ipv6Addr>,
}

fn hook(kind: &str, at: &str, priority: &str) -> String {
    format!("type {kind} hook {at} priority {priority}; policy accept;")
}

fn network(text: &str, v6: bool) -> Result<&str, String> {
    let (address, bits) = text.split_once('/').ok_or("Invalid relay network")?;
    let valid = if v6 { address.parse::<Ipv6Addr>().is_ok() } else { address.parse::<Ipv4Addr>().is_ok() };
    let max = if v6 { 128 } else { 32 };
    if valid && bits.parse::<u8>().is_ok_and(|b| b <= max) {
        Ok(text)
    } else {
        Err("Invalid relay network".into())
    }
}

/// DNS to port 53 into `chain`.
fn dns_jump(chain: &str) -> String {
    format!("meta l4proto {{ tcp, udp }} th dport 53 jump {chain}")
}

/// The router's own DNS chain: the core's sockets keep their destination
/// once its outbound mark is verified (M13, `ids::CORE_OUT_MARK`).
fn dns_output(mark: Option<u32>) -> Vec<String> {
    let mut rules: Vec<String> = mark.map(|m| format!("meta mark & 0x{m:08x} == 0x{m:08x} return")).into_iter().collect();
    rules.push(dns_jump("dns_router"));
    rules
}

const LOCAL: &str = "fib daddr type local return";

fn v4(layout: &Layout, mark: Option<u32>) -> Result<String, String> {
    let mine = format!("iifname \"{IFACE}\"");
    let input = vec![
        format!("{mine} ct state established,related return"),
        format!("{mine} udp sport 67 udp dport 68 return"),
        format!("{mine} drop"),
    ];
    let mut forward = Vec::new();
    if layout.relay.is_some() {
        forward.push(format!("iifname \"br-lan\" oifname \"{IFACE}\" return"));
        forward.push(format!("{mine} oifname \"br-lan\" ct state established,related return"));
    }
    forward.extend([format!("{mine} drop"), format!("oifname \"{IFACE}\" drop")]);
    let (filter_in, filter_fwd) = (hook("filter", "input", FILTER), hook("filter", "forward", FILTER));
    let mut chains = vec![("input", filter_in.as_str(), input), ("forward", filter_fwd.as_str(), forward)];
    let (pre, out) = (hook("nat", "prerouting", DNS_PRIORITY), hook("nat", "output", DNS_OUTPUT_PRIORITY));
    if let Some(relay) = &layout.relay {
        // LAN and router DNS to the Wi-Fi resolver, except local, LAN,
        // tailnet and link-local destinations.
        let exempt = format!("ip daddr {{ {}, {} }} return", ids::LOCAL_DNS_V4.join(", "), network(&relay.lan, false)?);
        let to = format!("meta l4proto {{ tcp, udp }} dnat to {}:53", relay.dns);
        chains.push(("dns_lan", "", vec![LOCAL.into(), exempt.clone(), to.clone()]));
        chains.push(("dns_router", "", vec![LOCAL.into(), exempt, to]));
        chains.push(("dns_pre", pre.as_str(), vec![format!("iifname \"br-lan\" {}", dns_jump("dns_lan"))]));
        chains.push(("dns_out", out.as_str(), dns_output(mark)));
    }
    Ok(effect::table("ip", TABLE, &[], &chains))
}

fn v6(layout: &Layout, mark: Option<u32>) -> Result<String, String> {
    let mine = format!("iifname \"{IFACE}\"");
    let mut input = Vec::new();
    if layout.discovery {
        input.extend([
            format!("{mine} ct state established,related return"),
            format!("{mine} icmpv6 type nd-router-advert ip6 saddr {} ip6 hoplimit 255 return", ids::LINK_LOCAL_V6),
            format!("{mine} icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} ip6 hoplimit 255 return"),
            format!("{mine} icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem }} return"),
            format!("{mine} udp sport 547 udp dport 546 return"),
        ]);
    }
    input.push(format!("{mine} drop"));
    let mut forward = Vec::new();
    if layout.relay.is_some() {
        // First: no local or multicast exception below may let LAN traffic
        // out through cellular.
        forward.push("iifname \"br-lan\" oifname \"rmnet*\" reject".to_owned());
    }
    if let Some(nat) = &layout.nat66 {
        let sources = nat.sources.iter().map(|s| network(s, true)).collect::<Result<Vec<_>, _>>()?;
        if !sources.is_empty() {
            forward.push(format!("iifname \"br-lan\" oifname \"{IFACE}\" ip6 saddr {{ {} }} return", sources.join(", ")));
        }
        forward.push(format!("{mine} oifname \"br-lan\" ct state established,related return"));
    }
    forward.extend([format!("{mine} drop"), format!("oifname \"{IFACE}\" drop")]);
    if layout.relay.is_some() {
        forward.push(format!("iifname \"br-lan\" ip6 daddr {{ fc00::/7, {}, {} }} return", ids::LINK_LOCAL_V6, ids::MULTICAST_V6));
        forward.push("iifname \"br-lan\" reject".to_owned());
    }
    let (filter_in, filter_fwd, filter_out) = (hook("filter", "input", FILTER), hook("filter", "forward", FILTER), hook("filter", "output", FILTER));
    let mut chains = vec![("input", filter_in.as_str(), input), ("forward", filter_fwd.as_str(), forward)];
    if layout.relay.is_some() {
        // The one cellular OUTPUT reject, owned by the relay baseline: it
        // covers IPv6 off, a lost lease and a withdrawn NAT66 alike.
        chains.push(("output", filter_out.as_str(), vec!["oifname \"rmnet*\" reject".to_owned()]));
    }
    let nat = hook("nat", "postrouting", SRCNAT);
    let pre = hook("nat", "prerouting", DNS_PRIORITY);
    let (out, last) = match layout.nat66.as_ref().and_then(|n| n.dns) {
        Some(dns) => (hook("nat", "output", DNS_OUTPUT_PRIORITY), format!("meta l4proto {{ tcp, udp }} dnat to [{dns}]:53")),
        None => (filter_out.clone(), "reject".to_owned()),
    };
    if let Some(nat66) = &layout.nat66 {
        // Only the relay's upstream: covers core/router sockets that kept an
        // old cellular source and cellular LAN addresses not yet deprecated.
        chains.push(("nat66", nat.as_str(), vec![format!("oifname \"{IFACE}\" masquerade")]));
        // LAN DNS to local dnsmasq (Mihomo's redirect still wins); router
        // DNS to the Wi-Fi resolver, or rejected without one.
        let mut nets = vec!["::1/128", ids::TAILNET_V6, ids::LINK_LOCAL_V6];
        for source in &nat66.sources {
            nets.push(network(source, true)?);
        }
        let exempt = format!("ip6 daddr {{ {} }} return", nets.join(", "));
        chains.push(("dns_lan", "", vec![LOCAL.into(), exempt.clone(), "meta l4proto { tcp, udp } redirect to :53".into()]));
        chains.push(("dns_router", "", vec![LOCAL.into(), exempt, last]));
        chains.push(("dns_pre", pre.as_str(), vec![format!("iifname \"br-lan\" {}", dns_jump("dns_lan"))]));
        chains.push(("dns_out", out.as_str(), dns_output(mark)));
    }
    Ok(effect::table("ip6", TABLE, &[], &chains))
}

/// Both families' definitions for `NftTables::declare`.
pub fn tables(layout: &Layout, mark: Option<u32>) -> Result<[String; 2], String> {
    Ok([v4(layout, mark)?, v6(layout, mark)?])
}

/// The journal entries of the tables (`Shared` loads them): their undo
/// deletes one family's table.
pub fn steps() -> Vec<Step> {
    effect::FAMILIES.iter().map(|family| Step::new(Cmd::new("@u60-relay-nft", &["tables", family]), Cmd::new("@u60-relay-nft", &["remove", family]))).collect()
}

/// `@u60-relay-nft tables <family>` marks the journal entry; `remove
/// <family>` deletes that family's table (the undo; also what the previous
/// agent journaled for its DNS-only tables).
pub(crate) fn command(args: &[String]) -> Result<(), String> {
    match args {
        [what, family] if matches!(family.as_str(), "ip" | "ip6") && what == "tables" => Ok(()),
        [what, family] if matches!(family.as_str(), "ip" | "ip6") && what == "remove" => {
            if effect::Device.list(family, TABLE)?.is_some() {
                effect::Device.delete(family, TABLE)?;
            }
            Ok(())
        }
        _ => Err("Invalid relay nftables command".into()),
    }
}

struct State {
    file: PathBuf,
    tables: NftTables,
    nft: Box<dyn Nft + Send>,
    /// `None` until the guard is declared and after `forget`.
    layout: Option<Layout>,
}

/// The session's tables, shared with `ipv6` (which adds its parts). Only
/// the relay's own threads use it, one session operation at a time.
#[derive(Clone)]
pub struct Shared(Arc<Mutex<State>>);

impl Shared {
    pub fn new(file: PathBuf) -> Self {
        Self::with(file, Box::new(effect::Device))
    }

    pub fn with(file: PathBuf, nft: Box<dyn Nft + Send>) -> Self {
        let tables = NftTables::new("relay", TABLE, file.clone());
        Self(Arc::new(Mutex::new(State { file, tables, nft, layout: None })))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Before the first table: a table of this name without our marker is
    /// another program's (or an unjournaled leftover) and is not taken over.
    pub fn claim(&self) -> Result<(), String> {
        let mut s = self.state();
        let State { tables, nft, .. } = &mut *s;
        match tables.presence(&mut **nft)? {
            Presence::Foreign => Err("The relay's nftables table names are in use by another program; nothing was changed".into()),
            Presence::Absent | Presence::Ours => Ok(()),
        }
    }

    /// The upstream guard alone: the first table of a session.
    pub fn guard(&self) -> Result<(), String> {
        let mut s = self.state();
        s.layout = Some(Layout::default());
        Self::declare(&mut s)
    }

    /// A previous agent's tables, taken over with installed routes: only
    /// ours (by marker) are, and the guard with `relay`'s part replaces them
    /// in one load, so forwarding and DNS never lapse. IPv6 adds its parts
    /// again when it starts.
    pub fn adopt(&self, relay: Relay) -> Result<(), String> {
        let mut s = self.state();
        let State { tables, nft, .. } = &mut *s;
        if tables.presence(&mut **nft)? != Presence::Ours {
            return Err("The relay's nftables tables are not the previous agent's".into());
        }
        s.layout = Some(Layout { relay: Some(relay), ..Layout::default() });
        Self::declare(&mut s)
    }

    /// Changes what the tables hold and loads them when that differs from
    /// what is confirmed. Nothing is declared before `guard` (a session
    /// that never raised the station shrinks nothing). `Err` keeps the new
    /// layout the target: `reconcile` tries it again.
    pub fn update(&self, change: impl FnOnce(&mut Layout)) -> Result<(), String> {
        let mut s = self.state();
        let Some(mut next) = s.layout.clone() else { return Ok(()) };
        change(&mut next);
        if s.layout.as_ref() == Some(&next) && s.tables.confirmed() {
            return Ok(());
        }
        s.layout = Some(next);
        Self::declare(&mut s)
    }

    fn declare(s: &mut State) -> Result<(), String> {
        let families = tables(s.layout.as_ref().unwrap(), ids::CORE_OUT_MARK)?;
        let State { tables, nft, .. } = s;
        tables.declare(families, &mut **nft).map(|_| ())
    }

    /// `net_guard`: loads the target again when it is not confirmed or the
    /// tables lost their marker or a rule.
    pub fn reconcile(&self) -> net::Reconciled {
        let mut result = net::Reconciled::default();
        let mut s = self.state();
        if s.layout.is_none() {
            return result;
        }
        let State { tables, nft, .. } = &mut *s;
        match tables.reconcile(&mut **nft) {
            Ok(true) => result.restored.push("relay nftables tables".into()),
            Ok(false) => {}
            Err(e) => result.failed.push(e),
        }
        result
    }

    /// After the journal removed the tables: nothing is held any more.
    pub fn forget(&self) {
        let mut s = self.state();
        s.layout = None;
        s.tables = NftTables::new("relay", TABLE, s.file.clone());
    }

    pub fn status(&self) -> Value {
        let s = self.state();
        let Some(layout) = &s.layout else { return Value::Null };
        let mut status = s.tables.status();
        status["parts"] = json!({"guard": true, "relay": layout.relay.is_some(), "ipv6_discovery": layout.discovery, "nat66": layout.nat66.is_some()});
        status
    }

    #[cfg(test)]
    pub fn layout(&self) -> Option<Layout> {
        self.state().layout.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::netfx::effect::fake::FakeNft;

    /// A `FakeNft` the test can still read once a `Shared` holds it.
    #[derive(Clone, Default)]
    pub struct Kernel(pub Arc<Mutex<FakeNft>>);

    impl Nft for Kernel {
        fn load(&mut self, file: &std::path::Path) -> Result<(), String> {
            self.0.lock().unwrap().load(file)
        }
        fn list(&mut self, family: &str, name: &str) -> Result<Option<String>, String> {
            self.0.lock().unwrap().list(family, name)
        }
        fn delete(&mut self, family: &str, name: &str) -> Result<(), String> {
            self.0.lock().unwrap().delete(family, name)
        }
    }

    impl Kernel {
        pub fn table(&self, family: &str) -> Option<String> {
            self.0.lock().unwrap().tables.get(&(family.to_owned(), TABLE.to_owned())).cloned()
        }
    }

    pub fn shared(test: &str) -> (Shared, Kernel) {
        let dir = std::env::temp_dir().join(format!("u60-uplink-{test}-{}", std::process::id()));
        let kernel = Kernel::default();
        (Shared::with(dir.join("uplink.nft"), Box::new(kernel.clone())), kernel)
    }

    fn relay() -> Relay {
        Relay { dns: "10.20.0.53".parse().unwrap(), lan: "192.168.0.0/24".into() }
    }

    fn nat66(dns: Option<&str>) -> Nat66 {
        Nat66 { sources: vec!["fd12:3456:789a::/64".into(), "2001:db8:5::/64".into()], dns: dns.map(|d| d.parse().unwrap()) }
    }

    /// The rules of `chain` in a definition, in order.
    pub fn chain(text: &str, chain: &str) -> Vec<String> {
        let start = text.find(&format!("\tchain {chain} {{\n")).unwrap_or_else(|| panic!("no chain {chain} in {text}"));
        let body = &text[start..];
        body.lines().skip(1).take_while(|l| l.trim() != "}").map(|l| l.trim().to_owned()).filter(|l| !l.starts_with("type ")).collect()
    }

    fn at(rules: &[String], needle: &str) -> usize {
        rules.iter().position(|r| r.contains(needle)).unwrap_or_else(|| panic!("{needle} not in {rules:?}"))
    }

    #[test]
    fn a_guard_alone_closes_the_upstream_in_both_families() {
        let [ip, ip6] = tables(&Layout::default(), None).unwrap();
        assert_eq!(chain(&ip, "input"), ["iifname \"u60sta0\" ct state established,related return", "iifname \"u60sta0\" udp sport 67 udp dport 68 return", "iifname \"u60sta0\" drop"]);
        assert_eq!(chain(&ip, "forward"), ["iifname \"u60sta0\" drop", "oifname \"u60sta0\" drop"], "nothing is forwarded through the upstream before routes");
        assert_eq!(chain(&ip6, "input"), ["iifname \"u60sta0\" drop"], "IPv6 stays closed until discovery starts");
        assert_eq!(chain(&ip6, "forward"), ["iifname \"u60sta0\" drop", "oifname \"u60sta0\" drop"]);
        for text in [&ip, &ip6] {
            assert!(text.contains("type filter hook input priority filter - 1; policy accept;"));
            assert!(!text.contains("dns_") && !text.contains("chain output") && !text.contains("masquerade"));
        }
        for reserved in ["fwd", "post", "c"] {
            assert!(!ip.contains(&format!("chain {reserved} ")) && !ip6.contains(&format!("chain {reserved} ")));
        }
    }

    #[test]
    fn ipv6_discovery_opens_only_what_neighbour_discovery_and_dhcpv6_need() {
        let [_, ip6] = tables(&Layout { discovery: true, ..Layout::default() }, None).unwrap();
        let input = chain(&ip6, "input");
        assert!(input[1].contains("nd-router-advert ip6 saddr fe80::/10 ip6 hoplimit 255 return"));
        assert!(input[2].contains("{ nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 return"));
        assert!(input[3].contains("destination-unreachable, packet-too-big, time-exceeded, parameter-problem"));
        assert!(input[4].ends_with("udp sport 547 udp dport 546 return"));
        assert_eq!(input.last().unwrap(), "iifname \"u60sta0\" drop");
    }

    #[test]
    fn forwarding_returns_come_before_the_relays_drops() {
        let [ip, _] = tables(&Layout { relay: Some(relay()), ..Layout::default() }, None).unwrap();
        let forward = chain(&ip, "forward");
        assert_eq!(forward[0], "iifname \"br-lan\" oifname \"u60sta0\" return");
        assert_eq!(forward[1], "iifname \"u60sta0\" oifname \"br-lan\" ct state established,related return");
        assert!(at(&forward, "iifname \"u60sta0\" drop") > 1 && at(&forward, "oifname \"u60sta0\" drop") > 1);
        assert_eq!(chain(&ip, "input").len(), 3, "routes add nothing to the upstream INPUT guard");
    }

    #[test]
    fn ipv6_rejects_cellular_before_any_exception_and_once_on_output() {
        let [_, ip6] = tables(&Layout { relay: Some(relay()), discovery: true, nat66: Some(nat66(None)) }, None).unwrap();
        let forward = chain(&ip6, "forward");
        assert_eq!(forward[0], "iifname \"br-lan\" oifname \"rmnet*\" reject", "before the NAT66 and the local exceptions");
        let out = at(&forward, "ip6 saddr { fd12:3456:789a::/64, 2001:db8:5::/64 } return");
        let back = at(&forward, "oifname \"br-lan\" ct state established,related return");
        let drop = at(&forward, "iifname \"u60sta0\" drop");
        let local = at(&forward, "ip6 daddr { fc00::/7, fe80::/10, ff00::/8 } return");
        assert!(0 < out && out < back && back < drop && drop < local && local < forward.len() - 1);
        assert_eq!(forward.last().unwrap(), "iifname \"br-lan\" reject");
        assert_eq!(ip6.matches("oifname \"rmnet*\" reject").count(), 2, "one forward, one output reject");
        assert_eq!(chain(&ip6, "output"), ["oifname \"rmnet*\" reject"]);
        assert_eq!(chain(&ip6, "nat66"), ["oifname \"u60sta0\" masquerade"]);
        assert!(ip6.contains("type nat hook postrouting priority srcnat - 1; policy accept;"));
        // Without NAT66 the baseline still rejects cellular and keeps the
        // upstream closed.
        let [_, baseline] = tables(&Layout { relay: Some(relay()), ..Layout::default() }, None).unwrap();
        assert!(!baseline.contains("masquerade") && !baseline.contains("ip6 saddr"));
        assert_eq!(chain(&baseline, "output"), ["oifname \"rmnet*\" reject"]);
    }

    #[test]
    fn ipv4_dns_keeps_local_lan_and_tailnet_and_sends_the_rest_upstream() {
        let [ip, _] = tables(&Layout { relay: Some(relay()), ..Layout::default() }, None).unwrap();
        for name in ["dns_lan", "dns_router"] {
            let rules = chain(&ip, name);
            assert_eq!(rules[0], LOCAL);
            assert_eq!(rules[1], "ip daddr { 127.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/24 } return");
            assert_eq!(rules[2], "meta l4proto { tcp, udp } dnat to 10.20.0.53:53");
        }
        assert_eq!(chain(&ip, "dns_pre"), ["iifname \"br-lan\" meta l4proto { tcp, udp } th dport 53 jump dns_lan"]);
        assert!(ip.contains(&format!("type nat hook prerouting priority {DNS_PRIORITY}; policy accept;")));
        assert!(ip.contains(&format!("type nat hook output priority {DNS_OUTPUT_PRIORITY}; policy accept;")), "no dstnat keyword on output");
        assert_eq!(chain(&ip, "dns_out"), ["meta l4proto { tcp, udp } th dport 53 jump dns_router"]);
    }

    #[test]
    fn ipv6_dns_redirects_lan_dns_locally_and_rejects_router_dns_without_a_resolver() {
        let layout = |dns| Layout { relay: Some(relay()), discovery: true, nat66: Some(nat66(dns)) };
        let [_, with] = tables(&layout(Some("2001:db8:1::53")), None).unwrap();
        assert!(with.contains("ip6 daddr { ::1/128, fd7a:115c:a1e0::/48, fe80::/10, fd12:3456:789a::/64, 2001:db8:5::/64 } return"));
        assert!(with.contains("redirect to :53") && with.contains("dnat to [2001:db8:1::53]:53"));
        let [_, without] = tables(&layout(None), None).unwrap();
        assert_eq!(chain(&without, "dns_router").last().unwrap(), "reject");
        assert!(!without.contains("dnat to"));
        assert!(without.contains("chain dns_out {\n\t\ttype filter hook output priority filter - 1; policy accept;"));
    }

    /// M13: only once a free mark is verified on the device; off until then.
    #[test]
    fn the_cores_marked_dns_keeps_its_destination_only_with_a_verified_mark() {
        assert_eq!(ids::CORE_OUT_MARK, None, "not deployed before the device check");
        let layout = Layout { relay: Some(relay()), discovery: true, nat66: Some(nat66(Some("2001:db8:1::53"))) };
        for text in tables(&layout, Some(0x0100_0000)).unwrap() {
            assert_eq!(chain(&text, "dns_out")[0], "meta mark & 0x01000000 == 0x01000000 return");
        }
        for text in tables(&layout, None).unwrap() {
            assert!(!text.contains("meta mark"));
        }
    }

    #[test]
    fn malformed_networks_never_reach_nft() {
        for lan in ["192.168.0.0/24; flush ruleset", "not/24", "10.0.0.0/33"] {
            assert!(tables(&Layout { relay: Some(Relay { lan: lan.into(), ..relay() }), ..Layout::default() }, None).is_err(), "{lan}");
        }
        let bad = Nat66 { sources: vec!["fd00::/64 } accept".into()], dns: None };
        assert!(tables(&Layout { nat66: Some(bad), ..Layout::default() }, None).is_err());
        for args in [vec!["remove", "inet"], vec!["v4", "10.0.0.1", "192.168.0.0/24"], vec!["tables", "bridge"]] {
            let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
            assert!(command(&args).is_err(), "{args:?}");
        }
        assert!(command(&["tables".to_owned(), "ip6".to_owned()]).is_ok(), "the journal entry itself does nothing");
    }

    #[test]
    fn the_journal_entries_undo_with_what_the_previous_agent_runs() {
        let undos: Vec<_> = steps().into_iter().map(|s| (s.undo.program, s.undo.args.join(" "))).collect();
        assert_eq!(undos, [("@u60-relay-nft".to_owned(), "remove ip".to_owned()), ("@u60-relay-nft".to_owned(), "remove ip6".to_owned())]);
        assert!(steps().iter().all(|s| !s.apply.checkable()), "Shared checks the tables, not the journal entry");
    }

    /// The session's parts grow and shrink one batch at a time; nothing is
    /// declared before the guard; a failed load stays the target.
    #[test]
    fn parts_come_and_go_in_one_batch_and_a_failed_one_is_retried() {
        let (uplink, kernel) = shared("parts");
        uplink.update(|l| l.relay = Some(relay())).unwrap();
        assert!(kernel.table("ip").is_none() && uplink.layout().is_none(), "nothing before the guard");
        uplink.claim().unwrap();
        uplink.guard().unwrap();
        assert!(kernel.table("ip").unwrap().contains("iifname \"u60sta0\" drop") && kernel.table("ip6").is_some());
        uplink.update(|l| l.relay = Some(relay())).unwrap();
        uplink.update(|l| l.discovery = true).unwrap();
        uplink.update(|l| l.nat66 = Some(nat66(None))).unwrap();
        let loads = kernel.0.lock().unwrap().loads;
        uplink.update(|l| l.nat66 = Some(nat66(None))).unwrap();
        assert_eq!(kernel.0.lock().unwrap().loads, loads, "an unchanged layout is not loaded again");
        assert!(kernel.table("ip6").unwrap().contains("masquerade"));
        kernel.0.lock().unwrap().fail.push(("Device tool timed out".into(), false));
        assert!(uplink.update(|l| l.nat66 = None).is_err());
        assert!(kernel.table("ip6").unwrap().contains("masquerade"), "the previous tables stay");
        assert_eq!(uplink.reconcile().restored, ["relay nftables tables"]);
        assert!(!kernel.table("ip6").unwrap().contains("masquerade"));
        assert!(uplink.reconcile().restored.is_empty());
        uplink.update(|l| { l.relay = None; l.discovery = false; }).unwrap();
        assert_eq!(uplink.layout(), Some(Layout::default()), "shrunk back to the guard");
        uplink.forget();
        assert!(uplink.reconcile().restored.is_empty() && uplink.status().is_null());
    }

    #[test]
    fn another_programs_table_is_never_taken_over() {
        let (uplink, kernel) = shared("foreign");
        kernel.0.lock().unwrap().tables.insert(("ip".into(), TABLE.into()), "table ip u60_relay {\n}\n".into());
        assert!(uplink.claim().is_err());
        assert!(kernel.table("ip").unwrap() == "table ip u60_relay {\n}\n");
    }
}
