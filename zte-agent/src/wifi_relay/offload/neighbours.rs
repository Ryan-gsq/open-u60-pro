//! Upstream hosts that IPACM puts ahead of the gateway
//! (`zte-agent/docs/relay-hw-offload.md`, section 8).
//!
//! In STA mode IPACM makes every IPv4 neighbour of `u60sta0` a WAN client and
//! gives it a rule in `WANRTBLv4` that matches the relay's own address as
//! source, in front of the gateway's. Offloaded uplink, NATed to that address,
//! then goes to that host's MAC: once IPA takes a connection over, its ACKs
//! never reach the server and the download stalls, about 30 KB into a page.
//! One ARP request from another upstream host is enough.
//!
//! IPACM deletes a client's rules, and does not add them again, when the
//! client's MAC shows up at another IPv4 address. So every other MAC is
//! announced once at `SPARE` and then put back at its own address, where IPACM
//! still knows it as an upstream host (connections to it stay on the CPU).
//! Neither step, later sightings nor a SW→HW switch bring the rule back (B31,
//! 2026-11-09). IPACM drops its clients when `u60sta0` goes away, so a MAC is
//! retired once per relay session.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use super::monitor::Monitor;
use super::{Cmd, IFACE};

/// RFC 5737 TEST-NET-1: never a host upstream, and off-link, so the kernel
/// never sends through the brief entry. Not link-local: IPACM ignores those.
const SPARE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Neighbour {
    ip: Ipv4Addr,
    mac: String,
}

/// A line of `ip -4 neigh show` or `ip -4 monitor neigh` for `IFACE`. Only
/// entries with a link-layer address: not deletions, failed or incomplete
/// resolutions.
fn parse(line: &str) -> Option<Neighbour> {
    let mut words = line.split_whitespace();
    let ip = words.next()?.parse().ok()?;
    let mut mac = None;
    while let Some(word) = words.next() {
        if word == "lladdr" {
            mac = words.next();
        } else if word == "dev" && words.next() != Some(IFACE) {
            return None;
        }
    }
    let mac = mac?.to_ascii_lowercase();
    let octets: Vec<&str> = mac.split(':').collect();
    let valid = octets.len() == 6 && octets.iter().all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit()));
    (valid && mac != "00:00:00:00:00:00").then_some(Neighbour { ip, mac })
}

/// Which neighbours to retire: never the gateway's MAC, not even at another
/// address, or IPACM would lose its gateway client.
struct Retirer {
    gateway: Ipv4Addr,
    gateway_mac: Option<String>,
    retired: HashSet<String>,
    /// Seen before the gateway's own entry, so possibly its MAC.
    pending: Vec<Neighbour>,
}

impl Retirer {
    fn new(gateway: Ipv4Addr) -> Self {
        Self { gateway, gateway_mac: None, retired: HashSet::new(), pending: Vec::new() }
    }

    /// The neighbours to retire now, in order.
    fn observe(&mut self, seen: Neighbour) -> Vec<Neighbour> {
        if seen.ip == SPARE {
            return Vec::new();
        }
        if seen.ip == self.gateway {
            self.gateway_mac = Some(seen.mac);
            return std::mem::take(&mut self.pending).into_iter().filter_map(|n| self.claim(n)).collect();
        }
        if self.gateway_mac.is_none() {
            self.pending.retain(|n| n.mac != seen.mac);
            self.pending.push(seen);
            return Vec::new();
        }
        self.claim(seen).into_iter().collect()
    }

    fn claim(&mut self, seen: Neighbour) -> Option<Neighbour> {
        let gateway = self.gateway_mac.as_deref() == Some(seen.mac.as_str());
        (!gateway && self.retired.insert(seen.mac.clone())).then_some(seen)
    }

    /// Not retired after all: try again when the MAC is seen next.
    fn failed(&mut self, mac: &str) {
        self.retired.remove(mac);
    }
}

/// IPACM sees the MAC move to `SPARE`, which drops its rules, then back to its
/// own address as a REACHABLE event. The kernel reports nothing for an entry
/// already in that state, hence `stale` first.
fn retire_steps(n: &Neighbour) -> [Cmd; 4] {
    let (spare, own) = (SPARE.to_string(), n.ip.to_string());
    let entry = |ip: &str, state: &str| {
        Cmd::new("ip", &["-4", "neigh", "replace", ip, "lladdr", &n.mac, "nud", state, "dev", IFACE])
    };
    [
        entry(&spare, "reachable"),
        Cmd::new("ip", &["-4", "neigh", "del", &spare, "dev", IFACE]),
        entry(&own, "stale"),
        entry(&own, "reachable"),
    ]
}

fn retire(n: &Neighbour) -> Result<(), String> {
    retire_steps(n).iter().try_for_each(|cmd| cmd.run().map(|_| ()))
}

fn handle(retirer: &mut Retirer, line: &str, mut retire: impl FnMut(&Neighbour) -> Result<(), String>) {
    let Some(seen) = parse(line) else { return };
    for n in retirer.observe(seen) {
        // The MAC's last 2 octets only, as device lists show them.
        let tail = &n.mac[12..];
        match retire(&n) {
            Ok(()) => crate::netlog!("[relay] upstream host {} (MAC ..:{tail}) retired from IPACM's uplink rules", n.ip),
            Err(e) => {
                retirer.failed(&n.mac);
                crate::netlog!("[relay] cannot retire upstream host {} (MAC ..:{tail}) from IPACM's uplink rules: {e}", n.ip);
            }
        }
    }
}

/// One relay session's `ip -4 monitor neigh` on `IFACE`.
pub(super) fn watch(gateway: Ipv4Addr) -> Monitor {
    let mut retirer = Retirer::new(gateway);
    Monitor::start("relay-neigh", "upstream neighbour monitor", "ip", &["-4", "monitor", "neigh", "dev", IFACE], Some(crate::wifi_relay::pid_file("relay-neigh")), move |line, _| match line {
        Some(line) => handle(&mut retirer, line, retire),
        None => match Cmd::new("ip", &["-4", "neigh", "show", "dev", IFACE]).run() {
            Ok(table) => table.lines().for_each(|line| handle(&mut retirer, line, retire)),
            Err(e) => crate::netlog!("[relay] cannot list upstream neighbours: {e}"),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GATEWAY: &str = "c0:a4:76:b1:f0:e3";
    const HOST: &str = "e6:3e:70:62:48:a4";

    fn seen(ip: &str, mac: &str) -> Neighbour {
        Neighbour { ip: ip.parse().unwrap(), mac: mac.into() }
    }

    fn retirer() -> Retirer {
        Retirer::new("192.168.2.1".parse().unwrap())
    }

    #[test]
    fn only_entries_with_a_link_layer_address_on_the_relay_count() {
        assert_eq!(parse("192.168.2.250 lladdr 02:00:5E:00:00:99 REACHABLE "), Some(seen("192.168.2.250", "02:00:5e:00:00:99")));
        assert_eq!(parse("192.168.2.9 dev u60sta0 lladdr e6:3e:70:62:48:a4 STALE"), Some(seen("192.168.2.9", HOST)));
        for line in [
            "Deleted 192.168.2.250 lladdr 02:00:5e:00:00:99 REACHABLE",
            "192.0.2.1 FAILED ",
            "Deleted 192.0.2.1 FAILED ",
            "192.168.2.9 INCOMPLETE",
            "192.168.2.9 dev wlan0 lladdr e6:3e:70:62:48:a4 STALE",
            "fe80::c2a4:76ff:feb1:f0e3 lladdr c0:a4:76:b1:f0:e3 router REACHABLE",
            "192.168.2.9 lladdr 00:00:00:00:00:00 NOARP",
            "192.168.2.9 lladdr c0:a4:76:b1:f0 STALE",
            "192.168.2.9 lladdr",
            "",
        ] {
            assert_eq!(parse(line), None, "{line:?}");
        }
    }

    #[test]
    fn every_other_mac_is_retired_once_and_the_gateways_never() {
        let mut r = retirer();
        assert!(r.observe(seen("192.168.2.1", GATEWAY)).is_empty());
        assert_eq!(r.observe(seen("192.168.2.77", HOST)), [seen("192.168.2.77", HOST)]);
        assert!(r.observe(seen("192.168.2.78", HOST)).is_empty(), "IPACM does not give a retired MAC its rule back");
        assert!(r.observe(seen("192.168.2.254", GATEWAY)).is_empty(), "the gateway at another address");
        assert!(r.observe(seen("192.0.2.1", "02:00:5e:00:00:99")).is_empty(), "the retirement's own entry");
    }

    #[test]
    fn hosts_seen_before_the_gateway_wait_for_its_mac() {
        let mut r = retirer();
        assert!(r.observe(seen("192.168.2.254", GATEWAY)).is_empty());
        assert!(r.observe(seen("192.168.2.77", HOST)).is_empty());
        assert!(r.observe(seen("192.168.2.79", HOST)).is_empty());
        assert_eq!(r.observe(seen("192.168.2.1", GATEWAY)), [seen("192.168.2.79", HOST)], "latest address; the gateway's alias is dropped");
        assert!(r.observe(seen("192.168.2.1", GATEWAY)).is_empty());
    }

    #[test]
    fn the_mac_moves_to_the_spare_address_and_back_as_a_reachable_event() {
        let steps: Vec<String> = retire_steps(&seen("192.168.2.77", HOST)).iter().map(|c| format!("{} {}", c.program, c.args.join(" "))).collect();
        assert_eq!(
            steps,
            [
                format!("ip -4 neigh replace 192.0.2.1 lladdr {HOST} nud reachable dev u60sta0"),
                "ip -4 neigh del 192.0.2.1 dev u60sta0".to_owned(),
                format!("ip -4 neigh replace 192.168.2.77 lladdr {HOST} nud stale dev u60sta0"),
                format!("ip -4 neigh replace 192.168.2.77 lladdr {HOST} nud reachable dev u60sta0"),
            ]
        );
        assert!(SPARE.is_documentation() && !SPARE.is_link_local());
    }

    #[test]
    fn a_b31_transcript_retires_the_stranger_once_and_retries_a_failure() {
        // `ip -4 neigh show`, then `ip -4 monitor neigh` with the events the
        // retirement itself causes (B31, 2026-11-09).
        let transcript = [
            "192.168.2.1 lladdr c0:a4:76:b1:f0:e3 REACHABLE",
            "192.168.2.250 lladdr 02:00:5e:00:00:99 REACHABLE ",
            "192.0.2.1 lladdr 02:00:5e:00:00:99 REACHABLE ",
            "192.0.2.1 FAILED ",
            "Deleted 192.0.2.1 FAILED ",
            "192.168.2.250 lladdr 02:00:5e:00:00:99 STALE ",
            "192.168.2.250 lladdr 02:00:5e:00:00:99 REACHABLE ",
            "192.168.2.1 lladdr c0:a4:76:b1:f0:e3 STALE ",
            "Deleted 192.168.2.250 FAILED ",
        ];
        let mut r = retirer();
        let mut calls = Vec::new();
        for line in transcript {
            handle(&mut r, line, |n: &Neighbour| {
                calls.push(n.clone());
                Ok(())
            });
        }
        assert_eq!(calls, [seen("192.168.2.250", "02:00:5e:00:00:99")]);

        handle(&mut r, "192.168.2.77 lladdr e6:3e:70:62:48:a4 STALE", |_: &Neighbour| Err("busy".into()));
        let mut retried = 0;
        handle(&mut r, "192.168.2.77 lladdr e6:3e:70:62:48:a4 REACHABLE", |_: &Neighbour| {
            retried += 1;
            Ok(())
        });
        assert_eq!(retried, 1);
    }
}
