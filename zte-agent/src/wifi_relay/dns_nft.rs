//! Relay DNS in the agent's own nftables tables (`ip`/`ip6 u60_relay`).
//! LAN queries to outside resolvers (IPv4: the Wi-Fi resolver; IPv6: local
//! dnsmasq) and the router's own queries (the Wi-Fi resolver) follow the
//! upstream; queries to the router, the LAN and the tailnet stay put. `fib
//! daddr type local` matches the router's addresses live (legacy iptables
//! here has no `addrtype`), so address changes need nothing. Priority
//! `dstnat - 1`: before ZTE's legacy NAT, after Mihomo's redirect, which
//! wins while it runs. ZTE never rewrites nftables.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::time::Duration;

use crate::net_tools::{self as net, Cmd, Step};

pub(crate) const TABLE: &str = "u60_relay";
/// NAT priority of the relay's LAN DNS chain (Mihomo's redirect: `dstnat - 2`).
pub(crate) const PRIORITY: &str = "dstnat - 1";
/// The output hook takes no `dstnat` keyword: just ahead of legacy NAT (-100).
const OUTPUT_PRIORITY: &str = "-101";

/// IPv4: LAN and router DNS to `dns`, except local, LAN, tailnet and
/// link-local destinations.
pub(super) fn v4(dns: Ipv4Addr, lan: &str) -> Step {
    Step::new(Cmd::new("@u60-relay-nft", &["v4", &dns.to_string(), lan]), remove("ip"))
}

/// IPv6: LAN DNS to local dnsmasq; router DNS to `upstream`, or rejected
/// without one so IPv4 DNS is used.
pub(super) fn v6(upstream: Option<Ipv6Addr>, sources: &[String]) -> Step {
    let upstream = upstream.map_or_else(|| "none".to_owned(), |a| a.to_string());
    let mut args = vec!["v6", upstream.as_str()];
    args.extend(sources.iter().map(String::as_str));
    Step::new(Cmd::new("@u60-relay-nft", &args), remove("ip6"))
}

fn remove(family: &str) -> Cmd {
    Cmd::new("@u60-relay-nft", &["remove", family])
}

fn network(text: &str, v6: bool) -> Result<&str, String> {
    let (address, bits) = text.split_once('/').ok_or("Invalid relay DNS exemption")?;
    let valid = if v6 { address.parse::<Ipv6Addr>().is_ok() } else { address.parse::<Ipv4Addr>().is_ok() };
    let max = if v6 { 128 } else { 32 };
    if valid && bits.parse::<u8>().is_ok_and(|b| b <= max) {
        Ok(text)
    } else {
        Err("Invalid relay DNS exemption".into())
    }
}

/// The family and ruleset an apply step stands for.
fn ruleset(args: &[String]) -> Result<(&'static str, String), String> {
    let local = "fib daddr type local return".to_owned();
    let jump = |chain: &str| format!("meta l4proto {{ tcp, udp }} th dport 53 jump {chain}");
    match args {
        [kind, dns, lan] if kind == "v4" => {
            let dns: Ipv4Addr = dns.parse().map_err(|_| "Invalid relay DNS server")?;
            let exempt = format!("ip daddr {{ 127.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, {} }} return", network(lan, false)?);
            let to = format!("meta l4proto {{ tcp, udp }} dnat to {dns}:53");
            let prerouting = format!("type nat hook prerouting priority {PRIORITY}; policy accept;");
            let output = format!("type nat hook output priority {OUTPUT_PRIORITY}; policy accept;");
            let chains = [
                ("lan", "", vec![local.clone(), exempt.clone(), to.clone()]),
                ("router", "", vec![local, exempt, to]),
                ("prerouting", prerouting.as_str(), vec![format!("iifname \"br-lan\" {}", jump("lan"))]),
                ("output", output.as_str(), vec![jump("router")]),
            ];
            Ok(("ip", net::nft_fill("ip", TABLE, None, &chains)))
        }
        [kind, upstream, sources @ ..] if kind == "v6" => {
            let mut nets = vec!["::1/128", super::ipv6::TAILNET, "fe80::/10"];
            for source in sources {
                nets.push(network(source, true)?);
            }
            let exempt = format!("ip6 daddr {{ {} }} return", nets.join(", "));
            let lan = vec![local.clone(), exempt.clone(), "meta l4proto { tcp, udp } redirect to :53".to_owned()];
            let (output, last) = if upstream == "none" {
                ("type filter hook output priority filter - 1; policy accept;".to_owned(), "reject".to_owned())
            } else {
                let dns: Ipv6Addr = upstream.parse().map_err(|_| "Invalid relay DNS server")?;
                (format!("type nat hook output priority {OUTPUT_PRIORITY}; policy accept;"), format!("meta l4proto {{ tcp, udp }} dnat to [{dns}]:53"))
            };
            let prerouting = format!("type nat hook prerouting priority {PRIORITY}; policy accept;");
            let chains = [
                ("lan", "", lan),
                ("router", "", vec![local, exempt, last]),
                ("prerouting", prerouting.as_str(), vec![format!("iifname \"br-lan\" {}", jump("lan"))]),
                ("output", output.as_str(), vec![jump("router")]),
            ];
            Ok(("ip6", net::nft_fill("ip6", TABLE, None, &chains)))
        }
        _ => Err("Invalid relay DNS rules".into()),
    }
}

fn listing(family: &str) -> Option<String> {
    Cmd::new("nft", &["-t", "list", "table", family, TABLE]).run().ok()
}

/// Whether a relay DNS table already exists (another owner or a leftover).
pub(super) fn occupied(family: &str) -> bool {
    listing(family).is_some()
}

/// `@u60-relay-nft v4 <dns> <lan>` | `v6 <dns|none> <source>...` | `remove ip|ip6`.
pub(crate) fn command(args: &[String]) -> Result<(), String> {
    if let [what, family] = args {
        if what == "remove" {
            if !matches!(family.as_str(), "ip" | "ip6") {
                return Err("Invalid relay DNS rules".into());
            }
            if occupied(family) {
                Cmd::new("nft", &["delete", "table", family, TABLE]).run()?;
            }
            return Ok(());
        }
    }
    let (_, text) = ruleset(args)?;
    let mut nft = Command::new("nft");
    nft.args(["-f", "-"]);
    net::run_input(nft, Duration::from_secs(8), text.into_bytes()).map(|_| ())
}

/// Whether an applied `@u60-relay-nft` step still holds, rule for rule.
pub(crate) fn present(args: &[String]) -> bool {
    let Ok((family, text)) = ruleset(args) else { return true };
    net::nft_holds(family, TABLE, &text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(step: &Step) -> String {
        ruleset(&step.apply.args).unwrap().1
    }

    #[test]
    fn ipv4_keeps_local_lan_and_tailnet_dns_and_sends_the_rest_upstream() {
        let step = v4("10.20.0.53".parse().unwrap(), "192.168.0.0/24");
        assert_eq!(step.undo.args, ["remove", "ip"]);
        let rules = text(&step);
        for chain in ["lan", "router"] {
            let body = &rules[rules.rfind(&format!("chain {chain} {{\n")).unwrap()..];
            let local = body.find("fib daddr type local return").unwrap();
            let exempt = body.find("127.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/24 } return").unwrap();
            assert!(local < exempt && exempt < body.find("dnat to 10.20.0.53:53").unwrap());
        }
        assert!(rules.contains("iifname \"br-lan\" meta l4proto { tcp, udp } th dport 53 jump lan"));
        assert!(rules.contains(&format!("type nat hook prerouting priority {PRIORITY}")));
        assert!(rules.contains(&format!("type nat hook output priority {OUTPUT_PRIORITY}")), "no dstnat keyword on output");
        assert!(rules.contains("flush chain ip u60_relay prerouting"), "a re-apply does not duplicate");
    }

    #[test]
    fn ipv6_redirects_lan_dns_locally_and_rejects_router_dns_without_a_resolver() {
        let sources = ["fd12:3456:789a::/64".to_owned()];
        let with = text(&v6(Some("2001:db8:1::53".parse().unwrap()), &sources));
        assert!(with.contains("ip6 daddr { ::1/128, fd7a:115c:a1e0::/48, fe80::/10, fd12:3456:789a::/64 } return"));
        assert!(with.contains("redirect to :53"));
        assert!(with.contains("dnat to [2001:db8:1::53]:53"));
        let without = text(&v6(None, &sources));
        assert!(without.contains("type filter hook output priority filter - 1"));
        assert!(without.contains("\t\treject\n"));
        assert!(!without.contains("dnat to"));
    }

    #[test]
    fn malformed_arguments_never_reach_nft() {
        for args in [
            vec!["v4", "not-an-ip", "192.168.0.0/24"],
            vec!["v4", "10.0.0.1", "192.168.0.0/24; flush ruleset"],
            vec!["v6", "none", "fd00::/64 } accept"],
            vec!["remove", "inet"],
        ] {
            let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
            assert!(command(&args).is_err(), "{args:?}");
        }
    }
}
