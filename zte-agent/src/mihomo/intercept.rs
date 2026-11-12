//! The core's nftables tables (`ip`/`ip6 u60_mihomo`) for each controller
//! state (`relay-mihomo-architecture.md` sections 5.2 and 5.3), replaced
//! whole through the owner's EffectSet NftTable resource.
//!
//! LAN TCP/UDP goes to the core by TPROXY except DNS (redirected to its
//! listener), the router's own addresses and private ranges; fake-ip
//! addresses always reach the core; IPv6 always does. Connections the core
//! already holds keep reaching it before any DIRECT return (`socket
//! transparent 1 socket wildcard 0`: an established transparent socket, never
//! the wildcard listener a new SYN to a remote port 17894 would find), so a
//! switch to DIRECT does not cut them. `to_core` ends with a TCP/UDP drop:
//! TPROXY without a listening core gives `NFT_BREAK`, which only skips the
//! rest of its own rule, and the packet would otherwise be forwarded
//! directly. The drop is resident (owner choice Q1): while the agent itself
//! is down nothing goes direct; the agent's guard process restarts it.

use super::routing;
use crate::netfx::effect::{table, FAMILIES};
use crate::netfx::ids;

pub(super) const NAME: &str = ids::MIHOMO_NFT;
pub(super) const CORE: &str = "to_core";
const SET_SPEC: &str = "type ipv4_addr; flags interval; auto-merge;";
const MARK: &str = "meta mark set mark and 0xffff00ff or 0x700 accept";

/// What the tables do.
#[derive(Clone, Copy, Debug)]
pub(super) enum Shape<'a> {
    /// Starting, before the core listens: only the input guard (DNS and the
    /// proxy port from the LAN only).
    Guard,
    /// A planned switch, an adopted table after the agent restarted, a core
    /// not yet verified: everything the core would take goes to it, nothing
    /// skips it, nothing goes direct.
    Hold,
    /// Running: the plan's IPv4 chain (`routing::Chain`).
    Full(&'a routing::Chain),
    /// D3 after a confirmed core failure: interception is gone and LAN
    /// traffic goes direct, except fake-ip addresses, which fail fast
    /// (TCP reset, UDP port unreachable) instead of hanging.
    FakeReject,
}

/// Both families' definitions for the owner's NftTable resource.
pub(super) fn tables(shape: Shape) -> [String; 2] {
    FAMILIES.map(|family| family_table(family, shape))
}

fn guard() -> Vec<String> {
    vec![format!("iifname != {{ \"br-lan\", \"lo\" }} meta l4proto {{ tcp, udp }} th dport {{ {}, {} }} drop", ids::DNS_PORT, ids::TPROXY_PORT)]
}

fn family_table(family: &str, shape: Shape) -> String {
    let v4 = family == "ip";
    let input = ("input", "type filter hook input priority filter - 1; policy accept;", guard());
    let chain = match shape {
        Shape::Guard => return table(family, NAME, &[], &[input]),
        Shape::FakeReject => {
            let rules = if v4 {
                vec![
                    format!("iifname \"br-lan\" ip daddr {} meta l4proto tcp reject with tcp reset", routing::FAKE_NET),
                    format!("iifname \"br-lan\" ip daddr {} meta l4proto udp reject", routing::FAKE_NET),
                ]
            } else {
                Vec::new()
            };
            // The input guard stays: a start from here binds the core's
            // ports before its interception is loaded.
            return table(family, NAME, &[], &[input, ("forward", "type filter hook forward priority filter - 1; policy accept;", rules)]);
        }
        Shape::Hold => None,
        Shape::Full(chain) => Some(chain),
    };
    let (address, private) = if v4 { ("ip", ids::PRIVATE_V4.join(", ")) } else { ("ip6", ids::PRIVATE_V6.join(", ")) };
    let mut prerouting = vec![
        "iifname != \"br-lan\" return".to_owned(),
        format!("meta l4proto tcp socket transparent 1 socket wildcard 0 {MARK}"),
        "meta l4proto { tcp, udp } th dport 53 return".to_owned(),
        "fib daddr type local return".to_owned(),
    ];
    if v4 {
        prerouting.push(format!("ip daddr {} goto {CORE}", routing::FAKE_NET));
    }
    prerouting.push(format!("{address} daddr {{ {private} }} return"));
    let mut sets: Vec<(&str, &str, &[String])> = Vec::new();
    if let (true, Some(chain)) = (v4, chain) {
        prerouting.extend(chain.rules.iter().cloned());
        sets = chain.sets.iter().map(|(name, elements)| (name.as_str(), SET_SPEC, elements.as_slice())).collect();
    }
    prerouting.push(format!("goto {CORE}"));
    let core = vec![
        format!("meta l4proto tcp socket transparent 1 {MARK}"),
        format!("meta l4proto {{ tcp, udp }} tproxy to :{} {MARK}", ids::TPROXY_PORT),
        "meta l4proto { tcp, udp } drop".to_owned(),
    ];
    let dns = vec![format!("iifname \"br-lan\" meta l4proto {{ tcp, udp }} th dport 53 redirect to :{}", ids::DNS_PORT)];
    // Ahead of the relay's DNS chains (`uplink::DNS_PRIORITY`), so the core's
    // DNS wins while it runs.
    table(
        family,
        NAME,
        &sets,
        &[
            input,
            (CORE, "", core),
            ("prerouting", "type filter hook prerouting priority mangle - 1; policy accept;", prerouting),
            ("dns", "type nat hook prerouting priority dstnat - 2; policy accept;", dns),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_chain() -> routing::Chain {
        routing::Chain {
            sets: vec![("geo_cn".into(), vec!["1.0.1.0/24".into(), "1.0.2.0/23".into()]), ("ip_0".into(), vec!["91.108.4.0/22".into()])],
            rules: vec!["ip daddr @ip_0 goto to_core".into(), "ip daddr @geo_cn return".into(), "th dport { 22 } goto to_core".into()],
            returns: 1,
            ..routing::Chain::default()
        }
    }

    fn at(part: &str, needle: &str) -> usize {
        part.find(needle).unwrap_or_else(|| panic!("missing {needle} in\n{part}"))
    }

    #[test]
    fn the_rule_chain_follows_fake_ip_and_private_ranges_and_ipv6_always_reaches_the_core() {
        let [v4, v6] = tables(Shape::Full(&rules_chain()));
        assert!(v4.contains("set geo_cn { type ipv4_addr; flags interval; auto-merge; elements = { 1.0.1.0/24, 1.0.2.0/23 } }"));
        let fake = at(&v4, "ip daddr 198.18.0.0/16 goto to_core");
        assert!(at(&v4, "fib daddr type local return") < fake && fake < at(&v4, "224.0.0.0/3 } return"), "fake addresses go to the core before any return");
        let private = at(&v4, "224.0.0.0/3 } return");
        let (first, second, third) = (at(&v4, "ip daddr @ip_0 goto to_core"), at(&v4, "ip daddr @geo_cn return"), at(&v4, "th dport { 22 } goto to_core"));
        assert!(private < first && first < second && second < third && third < v4.rfind("goto to_core\n").unwrap(), "in the rules' order, then the core");
        assert!(!v6.contains('@') && !v6.contains("198.18"), "IPv6 always goes to the core");
        for part in [&v4, &v6] {
            assert!(at(part, "th dport 53 return") < at(part, "goto to_core"));
            assert!(part.contains(&format!("tproxy to :{}", ids::TPROXY_PORT)));
            assert!(part.contains("redirect to :1053"));
            assert!(part.contains("dport { 1053, 17894 } drop"), "the input guard stays");
        }
        let [direct, _] = tables(Shape::Full(&routing::Chain::all()));
        assert!(at(&direct, "goto to_core") < at(&direct, "\t\treturn\n"), "direct mode: fake-ip still reaches the core, then everything returns");
        assert!(!direct.contains("elements"));
    }

    /// The core's own connections keep reaching it before any DIRECT return;
    /// a wildcard listener is never taken for one.
    #[test]
    fn established_core_sessions_come_before_direct_returns() {
        let [v4, _] = tables(Shape::Full(&rules_chain()));
        let established = at(&v4, "socket transparent 1 socket wildcard 0");
        assert!(at(&v4, "iifname != \"br-lan\" return") < established && established < at(&v4, "ip daddr @geo_cn return"));
        assert!(established < at(&v4, "th dport 53 return"));
    }

    /// TPROXY without a listener skips only its own rule: every interception
    /// table ends `to_core` with a drop, and only D3 lets traffic go direct.
    #[test]
    fn nothing_reaches_the_core_chain_and_goes_direct() {
        for shape in [Shape::Hold, Shape::Full(&rules_chain()), Shape::Full(&routing::Chain::all())] {
            for family in tables(shape) {
                let core = &family[at(&family, "chain to_core {")..];
                let core = &core[..at(core, "\t}\n")];
                assert!(core.trim_end().ends_with("meta l4proto { tcp, udp } drop"), "{core}");
                assert!(at(core, "tproxy to") < at(core, "drop"));
            }
        }
        let [hold, _] = tables(Shape::Hold);
        assert!(hold.contains("224.0.0.0/3 } return\n\t\tgoto to_core\n") && !hold.contains('@'), "a hold skips nothing past the private ranges");
        let [guard, guard6] = tables(Shape::Guard);
        assert!(!guard.contains("prerouting") && !guard6.contains("tproxy") && guard.contains("hook input"));
        let [reject, reject6] = tables(Shape::FakeReject);
        assert!(reject.contains("ip daddr 198.18.0.0/16 meta l4proto tcp reject with tcp reset") && reject.contains("meta l4proto udp reject"));
        assert!(!reject.contains("tproxy") && !reject.contains("redirect") && !reject6.contains("reject"), "D3: no interception, no DNS redirect");
        assert!(reject.contains("dport { 1053, 17894 } drop") && reject6.contains("dport { 1053, 17894 } drop"), "a start from D3 binds behind the guard");
    }
}
