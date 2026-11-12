//! Hotspot clients whose IPv4 route IPACM lost
//! (`zte-agent/docs/relay-hw-offload.md`, section 9).
//!
//! When a client leaves a hotspot interface the bridge deletes its FDB entry,
//! and IPACM drops everything it cached for the client, IPv4 address
//! included. On the next association it registers the client again with
//! IPv4 0.0.0.0 and adds its LAN route (`COMRTBLLANv4`) only on the next IPv4
//! neighbour event from `br-lan`. A client that keeps transferring keeps its
//! ARP entry REACHABLE, so no event comes and its traffic stays on the CPU.
//! Relay restores move clients between the bands (the 5 GHz hotspot passes
//! through a staging channel), so this happened after every agent update.
//!
//! A few seconds after each association, the client's REACHABLE `br-lan`
//! entry is set STALE: the kernel reports it, IPACM adds the route, and the
//! entry is confirmed again without interrupting the client (B31, 2026-11-09).
//! IPACM skips the event for a client it already knows at that address.

use std::net::Ipv4Addr;
use std::time::Duration;

use super::monitor::{Alive, Monitor};
use super::Cmd;

const LAN: &str = "br-lan";
/// After an association: IPACM registers the client from the driver's event,
/// and the client usually renews DHCP and ARP meanwhile.
const SETTLE: Duration = Duration::from_secs(5);

/// One relay session's hotspot station watch (`iw event`); at its start every
/// client is announced, since the relay's connection moved them between bands.
pub(super) fn watch() -> Monitor {
    Monitor::start("relay-lan", "hotspot station monitor", "iw", &["event", "-t"], Some(crate::wifi_relay::pid_file("relay-lan")), |line, alive| match line {
        None => announce(None),
        Some(line) => {
            if let Some(mac) = joined(line) {
                let alive: Alive = alive.clone();
                crate::system::spawn_named("relay-lan-arp", move || {
                    if alive.wait(SETTLE) {
                        announce(Some(&mac));
                    }
                });
            }
        }
    })
}

fn valid_mac(mac: &str) -> bool {
    let octets: Vec<&str> = mac.split(':').collect();
    octets.len() == 6 && octets.iter().all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit())) && mac != "00:00:00:00:00:00"
}

/// The MAC of a station that joined a hotspot interface, from an `iw event`
/// line (`[<time>: ]wlan2: new station <mac>`).
fn joined(line: &str) -> Option<String> {
    let (head, mac) = line.split_once(": new station ")?;
    let mac = mac.trim().to_ascii_lowercase();
    let iface = head.rsplit(' ').next()?;
    (iface.starts_with("wlan") && valid_mac(&mac)).then_some(mac)
}

/// A REACHABLE IPv4 entry of `ip -4 neigh show dev br-lan`. Other states
/// need nothing: the kernel reports the next change itself.
fn reachable(line: &str) -> Option<(Ipv4Addr, String)> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let ip = words.first()?.parse().ok()?;
    let mac = words.windows(2).find(|w| w[0] == "lladdr")?[1].to_ascii_lowercase();
    (words.last() == Some(&"REACHABLE") && valid_mac(&mac)).then_some((ip, mac))
}

/// `change` never creates an entry the kernel has not learnt.
fn stale(ip: Ipv4Addr, mac: &str) -> Cmd {
    Cmd::new("ip", &["-4", "neigh", "change", &ip.to_string(), "dev", LAN, "lladdr", mac, "nud", "stale"])
}

/// Sets the REACHABLE entries of `mac` (all clients when `None`) STALE.
fn announce(mac: Option<&str>) {
    let table = match Cmd::new("ip", &["-4", "neigh", "show", "dev", LAN]).run() {
        Ok(table) => table,
        Err(e) => return crate::netlog!("[relay] cannot list LAN neighbours: {e}"),
    };
    for (ip, client) in table.lines().filter_map(reachable).filter(|(_, m)| mac.is_none_or(|mac| m.as_str() == mac)) {
        // The MAC's last 2 octets only, as device lists show them.
        let tail = &client[12..];
        match stale(ip, &client).run() {
            Ok(_) => crate::netlog!("[relay] LAN client {ip} (MAC ..:{tail}) announced to IPACM again"),
            Err(e) => crate::netlog!("[relay] cannot announce LAN client {ip} (MAC ..:{tail}) to IPACM: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: &str = "3a:01:42:84:11:82";

    #[test]
    fn only_stations_joining_a_hotspot_interface_count() {
        assert_eq!(joined("1794236997.960314: wlan0: new station 3A:01:42:84:11:82").as_deref(), Some(MAC));
        assert_eq!(joined("wlan2: new station 3a:01:42:84:11:82").as_deref(), Some(MAC));
        for line in [
            "1794236994.101543: wlan2: del station 3a:01:42:84:11:82",
            "1794236990.409515: ath20: new station c0:a4:76:b1:f0:e3",
            "1794236994.356731: wlan0 (phy #0): vendor event 001374:101",
            "wlan2: new station 3a:01:42:84:11",
            "",
        ] {
            assert_eq!(joined(line), None, "{line:?}");
        }
    }

    #[test]
    fn only_reachable_ipv4_entries_are_set_stale_and_never_created() {
        assert_eq!(reachable("192.168.0.124 lladdr 3A:01:42:84:11:82 REACHABLE "), Some(("192.168.0.124".parse().unwrap(), MAC.to_owned())));
        for line in ["192.168.0.89 lladdr c2:fe:8d:00:00:01 STALE", "192.168.0.89 lladdr c2:fe:8d:00:00:01 DELAY", "192.168.0.60 FAILED", "192.168.0.7 lladdr 00:00:00:00:00:00 REACHABLE", ""] {
            assert_eq!(reachable(line), None, "{line:?}");
        }
        let cmd = stale("192.168.0.124".parse().unwrap(), MAC);
        assert_eq!(format!("{} {}", cmd.program, cmd.args.join(" ")), format!("ip -4 neigh change 192.168.0.124 dev br-lan lladdr {MAC} nud stale"));
    }
}
