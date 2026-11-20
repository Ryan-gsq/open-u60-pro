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

use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::monitor::{Alive, Monitor};
use crate::netfx::neighbours::Change;

const LAN: &str = "br-lan";
/// After an association: IPACM registers the client from the driver's event,
/// and the client usually renews DHCP and ARP meanwhile.
const SETTLE: Duration = Duration::from_secs(5);
const COOLDOWN: Duration = Duration::from_secs(12);

fn trailing_join(joined: Instant, started: Instant, earliest: Instant) -> Option<Instant> {
    (joined > started).then(|| earliest.max(joined + SETTLE))
}

/// One relay session's hotspot station watch (`iw event`); at its start every
/// client is announced, since the relay's connection moved them between bands.
pub(super) fn watch() -> Monitor {
    let pending = Arc::new(Mutex::new(HashMap::<String, Instant>::new()));
    Monitor::start("relay-lan", "hotspot station monitor", "iw", &["event", "-t"], Some(crate::wifi_relay::pid_file("relay-lan")), move |line, alive| match line {
        None => announce(None),
        Some(line) => {
            if let Some(mac) = joined(line) {
                let now = Instant::now();
                if pending.lock().unwrap().insert(mac.clone(), now).is_some() { return; }
                let pending = Arc::clone(&pending);
                let alive: Alive = alive.clone();
                crate::system::spawn_named("relay-lan-arp", move || {
                    let mut due = now + SETTLE;
                    while alive.wait(due.saturating_duration_since(Instant::now())) {
                        let started = Instant::now();
                        let settled = pending.lock().unwrap()[&mac] + SETTLE;
                        if started < settled { due = settled; continue; }
                        announce(Some(&mac));
                        let earliest = Instant::now() + COOLDOWN;
                        if !alive.wait(earliest.saturating_duration_since(Instant::now())) { break; }
                        let mut pending = pending.lock().unwrap();
                        let last = pending[&mac];
                        match trailing_join(last, started, earliest) {
                            Some(next) => due = next,
                            None => { pending.remove(&mac); break; }
                        }
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

/// Sets the REACHABLE entries of `mac` (all clients when `None`) STALE.
fn announce(mac: Option<&str>) {
    let table = match crate::netfx::neighbours::list(LAN) {
        Ok(table) => table,
        Err(e) => return crate::netlog!("[relay] cannot list LAN neighbours: {e}"),
    };
    for (ip, client) in table.into_iter().filter(|e| e.reachable && mac.is_none_or(|mac| mac == e.mac)).map(|e| (e.ip, e.mac)) {
        // The MAC's last 2 octets only, as device lists show them.
        let tail = &client[12..];
        match Change::ChangeStale.apply(LAN, ip, &client) {
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
    fn repeated_associations_have_one_trailing_announcement_after_cooldown() {
        let start = Instant::now();
        let earliest = start + COOLDOWN;
        assert_eq!(trailing_join(start, start, earliest), None);
        assert_eq!(trailing_join(start + Duration::from_secs(1), start, earliest), Some(earliest));
        assert_eq!(trailing_join(earliest, start, earliest), Some(earliest + SETTLE));
    }

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


}
