use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Child, Command};

use serde::{Deserialize, Serialize};

use super::{net, Cmd, IFACE, ROOT};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lease {
    pub(super) ip: Ipv4Addr,
    pub(super) subnet: Ipv4Addr,
    pub(super) gateway: Ipv4Addr,
    pub(super) dns: Vec<Ipv4Addr>,
}

fn prefix(mask: Ipv4Addr) -> Option<u32> {
    let m = u32::from(mask);
    (m.count_ones() == m.leading_ones() && (8..=30).contains(&m.count_ones())).then(|| m.count_ones())
}

pub(super) fn validate_lease(l: &Lease, lan: Ipv4Addr, mask: Ipv4Addr) -> Result<u32, String> {
    let p = prefix(l.subnet).ok_or("Invalid upstream subnet mask")?;
    prefix(mask).ok_or("Invalid LAN subnet mask")?;
    let ip = u32::from(l.ip);
    let gw = u32::from(l.gateway);
    let m = u32::from(l.subnet);
    let low = ip & m;
    let high = low | !m;
    if !(0x01000000..0xe0000000).contains(&ip) || l.ip.is_loopback() || ip <= low || ip >= high || gw <= low || gw >= high || ip == gw {
        return Err("Invalid upstream IPv4 lease or gateway".into());
    }
    let overlap = |a: u32, b: u32| low <= b && high >= a;
    let lan_low = u32::from(lan) & u32::from(mask);
    if overlap(lan_low, lan_low | !u32::from(mask)) || overlap(0x64400000, 0x647fffff) || overlap(0xa9fe0000, 0xa9feffff) {
        return Err("Upstream subnet conflicts with LAN, Tailnet or link-local addresses".into());
    }
    let lan_high = lan_low | !u32::from(mask);
    for dns in &l.dns {
        let address = u32::from(*dns);
        if !(0x01000000..0xe0000000).contains(&address)
            || dns.is_loopback()
            || (lan_low..=lan_high).contains(&address)
            || (0x64400000..=0x647fffff).contains(&address)
            || dns.is_link_local()
            || (low..=high).contains(&address) && (address == low || address == high || address == ip)
        {
            return Err("Upstream DHCP supplied an invalid or conflicting DNS resolver".into());
        }
    }
    Ok(p)
}

pub(super) fn lease_file(root: &Path, session: &str) -> Option<std::path::PathBuf> {
    (session.len() == 32 && session.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| root.join(format!("ipv4-lease-{session}.json")))
}

/// The envelope identifies the NAT implementation on adoption. A rollback
/// to an older agent rejects this lease before it installs legacy NAT and
/// runs its ordinary journal recovery (including removal of the nft table).
#[derive(Serialize, Deserialize)]
pub(super) struct NftLease { pub(super) nft_v4: Lease }

pub(super) fn read_lease(session: &str) -> Result<Lease, String> {
    let path = lease_file(Path::new(ROOT), session).ok_or("Invalid DHCP session")?;
    serde_json::from_slice::<NftLease>(&fs::read(path).map_err(|_| "No DHCP lease")?).map(|record| record.nft_v4).map_err(|_| "Invalid DHCP lease".into())
}

/// A DHCP client on a new session path (its lease file), asking for
/// `request` when given: the session id and the client.
pub(super) fn start_dhcp(request: Option<Ipv4Addr>) -> Result<(String, Child), String> {
    let callback = std::env::current_exe().map_err(|e| e.to_string())?;
    #[cfg(test)]
    let callback = std::env::var_os("U60_IPV6_QA_CALLBACK").map(std::path::PathBuf::from).unwrap_or(callback);
    let mut nonce = [0; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| "Cannot create DHCP session")?;
    let nonce = crate::common::hex_lower(&nonce);
    let mut cmd = Command::new("udhcpc");
    cmd.args(["-f", "-i", IFACE, "-s"])
        .arg(callback)
        .args(["-t", "5", "-T", "3", "-A", "10"]);
    if let Some(address) = request {
        cmd.args(["-r", &address.to_string()]);
    }
    cmd.env("U60_RELAY_DHCP", "1").env("U60_RELAY_DHCP_SESSION", &nonce);
    Ok((nonce, net::owned_child(cmd)?))
}

/// BusyBox udhcpc invokes the agent executable with bound/renew/deconfig.
/// A per-connection path prevents late callback children corrupting a reconnect.
pub fn dhcp_callback(event: &str) -> i32 {
    dhcp_callback_at(Path::new(ROOT), event, |key| std::env::var(key).ok())
}

pub(super) fn dhcp_callback_at(root: &Path, event: &str, env: impl Fn(&str) -> Option<String>) -> i32 {
    let Some(path) = env("U60_RELAY_DHCP_SESSION").and_then(|session| lease_file(root, &session)) else { return 1 };
    if env("interface").as_deref() != Some(IFACE) {
        return 1;
    }
    if event == "deconfig" {
        let _ = fs::remove_file(path);
        return 0;
    }
    if !["bound", "renew"].contains(&event) {
        return 0;
    }
    let read = |name| env(name)?.split_whitespace().next()?.parse::<Ipv4Addr>().ok();
    let (Some(ip), Some(subnet), Some(gateway)) = (read("ip"), read("subnet"), read("router")) else { return 1 };
    let dns = env("dns").unwrap_or_default().split_whitespace().filter_map(|s| s.parse().ok()).take(3).collect();
    let lease = Lease { ip, subnet, gateway, dns };
    if net::write_private(&path, &serde_json::to_vec(&NftLease { nft_v4: lease }).unwrap()).is_ok() {
        0
    } else {
        1
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum LeaseChange {
    Same,
    /// Only the resolver list beyond the one the DNS rules point at differs.
    Resolvers(Lease),
    Replaced,
}

/// The installed rules bake in the address, mask, gateway and the first
/// resolver. Anything else in a renewal (extra or reordered resolvers) can be
/// adopted in place; a missing lease or a different baked-in value cannot.
pub(super) fn lease_change(installed: &Lease, current: Option<&Lease>) -> LeaseChange {
    let Some(current) = current else {
        return LeaseChange::Replaced;
    };
    if current == installed {
        return LeaseChange::Same;
    }
    let resolver = |lease: &Lease| lease.dns.first().copied().unwrap_or(lease.gateway);
    if (current.ip, current.subnet, current.gateway)
        == (installed.ip, installed.subnet, installed.gateway)
        && resolver(current) == resolver(installed)
    {
        LeaseChange::Resolvers(current.clone())
    } else {
        LeaseChange::Replaced
    }
}

/// A renewed lease passes the same checks as a new one before it is adopted.
pub(super) fn resolvers_acceptable(lease: &Lease) -> bool {
    let address = |key: &str| {
        Cmd::new("uci", &["-q", "get", key])
            .run()
            .ok()?
            .parse::<Ipv4Addr>()
            .ok()
    };
    let (Some(lan), Some(mask)) = (
        address("network.lan.ipaddr"),
        address("network.lan.netmask"),
    ) else {
        return false;
    };
    validate_lease(lease, lan, mask).is_ok()
}
