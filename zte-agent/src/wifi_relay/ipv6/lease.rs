use std::fs;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{cidr, prefix, usable, IFACE, ROOT};
use crate::boottime::{BootClock, Clock};
use crate::net_tools as net;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Address {
    pub(super) address: Ipv6Addr,
    pub(super) prefix: u8,
    pub(super) preferred: u32,
    pub(super) valid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Router {
    pub(super) address: Ipv6Addr,
    pub(super) valid: u32,
    pub(super) metric: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct OnLink {
    pub(super) address: Ipv6Addr,
    pub(super) prefix: u8,
    pub(super) valid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Lease {
    pub(super) received: u64,
    pub(super) addresses: Vec<Address>,
    pub(super) routers: Vec<Router>,
    pub(super) onlink: Vec<OnLink>,
    pub(super) dns: Vec<Ipv6Addr>,
    pub(super) mtu: u32,
}

pub(super) fn now() -> u64 {
    BootClock.now().as_secs()
}

pub(super) fn parse_lease(get: impl Fn(&str) -> String, received: u64) -> Lease {
    let mut addresses = Vec::new();
    for name in ["ADDRESSES", "RA_ADDRESSES"] {
        for entry in get(name).split_whitespace().take(16) {
            let f: Vec<_> = entry.split(',').collect();
            if f.len() != 3 {
                continue;
            }
            let (Some((address, prefix)), Ok(preferred), Ok(valid)) =
                (cidr(f[0]), f[1].parse::<u32>(), f[2].parse::<u32>())
            else {
                continue;
            };
            if usable(address)
                && prefix > 0
                && valid > 0
                && preferred <= valid
                && !addresses.iter().any(|a: &Address| a.address == address)
            {
                addresses.push(Address {
                    address,
                    prefix,
                    preferred,
                    valid,
                });
            }
        }
    }
    let mut routers = Vec::new();
    let mut onlink = Vec::new();
    for entry in get("RA_ROUTES").split_whitespace().take(32) {
        let f: Vec<_> = entry.split(',').collect();
        if f.len() != 4 {
            continue;
        }
        let (Some((network, bits)), Ok(valid), Ok(metric)) =
            (cidr(f[0]), f[2].parse::<u32>(), f[3].parse::<u32>())
        else {
            continue;
        };
        if valid == 0 {
            continue;
        }
        if network.is_unspecified() && bits == 0 {
            if let Ok(address) = f[1].parse::<Ipv6Addr>() {
                if address.is_unicast_link_local() {
                    routers.push(Router {
                        address,
                        valid,
                        metric,
                    });
                }
            }
        } else if f[1].is_empty() && usable(network) && bits > 0 {
            let address = cidr(&prefix(network, bits)).unwrap().0;
            if !onlink
                .iter()
                .any(|r: &OnLink| r.address == address && r.prefix == bits)
            {
                onlink.push(OnLink {
                    address,
                    prefix: bits,
                    valid,
                });
            }
        }
    }
    routers.sort_by_key(|r| r.metric);
    let mut dns = Vec::new();
    for name in ["RDNSS", "RA_DNS"] {
        for text in get(name).split_whitespace().take(8) {
            if let Ok(a) = text.parse::<Ipv6Addr>() {
                if (usable(a) || a.is_unicast_link_local()) && !dns.contains(&a) {
                    dns.push(a);
                }
            }
        }
    }
    let mtu = get("RA_MTU")
        .parse::<u32>()
        .ok()
        .filter(|m| (1280..=1500).contains(m))
        .unwrap_or(1280);
    Lease {
        received,
        addresses,
        routers,
        onlink,
        dns,
        mtu,
    }
}

impl Lease {
    /// Seconds until the first finite lifetime of this (already remaining) lease ends.
    pub(super) fn shortest_lifetime(&self) -> u32 {
        self.addresses
            .iter()
            .flat_map(|a| [a.valid, a.preferred])
            .chain(self.routers.iter().map(|r| r.valid))
            .chain(self.onlink.iter().map(|r| r.valid))
            .filter(|&n| n != u32::MAX)
            .min()
            .unwrap_or(u32::MAX)
    }

    pub(super) fn remaining(&self, current: u64) -> Self {
        let elapsed = current
            .saturating_sub(self.received)
            .min(u64::from(u32::MAX)) as u32;
        let left = |n: u32| {
            if n == u32::MAX {
                n
            } else {
                n.saturating_sub(elapsed)
            }
        };
        let mut l = self.clone();
        for a in &mut l.addresses {
            a.valid = left(a.valid);
            a.preferred = left(a.preferred);
        }
        l.addresses.retain(|a| a.valid > 0 && a.preferred > 0);
        for r in &mut l.routers {
            r.valid = left(r.valid);
        }
        l.routers.retain(|r| r.valid > 0);
        for r in &mut l.onlink {
            r.valid = left(r.valid);
        }
        l.onlink.retain(|r| r.valid > 0);
        l
    }

    pub(super) fn ready(&self) -> bool {
        !self.addresses.is_empty() && !self.routers.is_empty()
    }
}

/// No shell and no vendor netifd callback: untrusted RA/DHCP data is parsed
/// into bounded typed state. Only the parent watchdog may change networking.
pub fn callback(interface: &str, event: &str) -> i32 {
    callback_with(interface, event, Path::new(ROOT), |key| std::env::var(key).ok())
}

pub(super) fn callback_with(interface: &str, event: &str, root: &Path, env: impl Fn(&str) -> Option<String>) -> i32 {
    if interface != IFACE {
        return 1;
    }
    let Some(path) = env("U60_RELAY_DHCP6_SESSION").and_then(|s| lease_file_in(root, &s))
    else {
        return 1;
    };
    if matches!(event, "started" | "stopped") {
        let _ = fs::remove_file(path);
        return 0;
    }
    if !matches!(
        event,
        "bound" | "informed" | "updated" | "rebound" | "ra-updated" | "unbound"
    ) {
        return 0;
    }
    let lease = parse_lease(|k| env(k).unwrap_or_default(), now());
    if net::write_private(&path, &serde_json::to_vec(&lease).unwrap()).is_ok() {
        0
    } else {
        1
    }
}

pub(super) fn lease_file(session: &str) -> Option<PathBuf> {
    lease_file_in(Path::new(ROOT), session)
}

pub(super) fn lease_file_in(root: &Path, session: &str) -> Option<PathBuf> {
    (session.len() == 32 && session.bytes().all(|c| c.is_ascii_hexdigit()))
        .then(|| root.join(format!("ipv6-lease-{session}.json")))
}
