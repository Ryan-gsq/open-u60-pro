//! odhcp6c only discovers upstream state. Rust owns its effects and NAT66;
//! the existing odhcpd remains the sole LAN router-advertisement service.

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{IFACE, JOURNAL, PREF, ROOT, TABLE};
use crate::boottime::{BootClock, Clock};
use crate::net_tools::{self as net, Cmd, Step, Transaction};

const RA_STATE: &str = "ra.json";
const TAILNET: &str = "fd7a:115c:a1e0::/48";
// A client may keep a previously advertised address after the vendor removes
// it from br-lan. Keep only a bounded, session-owned return route, not the old
// vendor address/configuration. Never carry this observation across reboot.
const LAN_GRACE: u64 = 7200;
mod ra;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Address {
    address: Ipv6Addr,
    prefix: u8,
    preferred: u32,
    valid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Router {
    address: Ipv6Addr,
    valid: u32,
    metric: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OnLink {
    address: Ipv6Addr,
    prefix: u8,
    valid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Lease {
    received: u64,
    addresses: Vec<Address>,
    routers: Vec<Router>,
    onlink: Vec<OnLink>,
    dns: Vec<Ipv6Addr>,
    mtu: u32,
}

fn now() -> u64 {
    BootClock.now().as_secs()
}

fn usable(address: Ipv6Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !address.is_unicast_link_local()
        && address.to_ipv4_mapped().is_none()
}

fn cidr(text: &str) -> Option<(Ipv6Addr, u8)> {
    let (a, p) = text.split_once('/')?;
    let a = a.parse().ok()?;
    let p = p.parse().ok()?;
    (p <= 128).then_some((a, p))
}

fn prefix(address: Ipv6Addr, bits: u8) -> String {
    let mask = u128::MAX.checked_shl(u32::from(128 - bits)).unwrap_or(0);
    format!("{}/{bits}", Ipv6Addr::from(u128::from(address) & mask))
}

fn parse_lease(get: impl Fn(&str) -> String, received: u64) -> Lease {
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
    fn remaining(&self, current: u64) -> Self {
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

    fn ready(&self) -> bool {
        !self.addresses.is_empty() && !self.routers.is_empty()
    }
}

/// No shell and no vendor netifd callback: untrusted RA/DHCP data is parsed
/// into bounded typed state. Only the parent watchdog may change networking.
pub fn callback(interface: &str, event: &str) -> i32 {
    if interface != IFACE {
        return 1;
    }
    let Some(path) = std::env::var("U60_RELAY_DHCP6_SESSION")
        .ok()
        .and_then(|s| lease_file(&s))
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
    let lease = parse_lease(|k| std::env::var(k).unwrap_or_default(), now());
    if net::write_private(&path, &serde_json::to_vec(&lease).unwrap()).is_ok() {
        0
    } else {
        1
    }
}

fn lease_file(session: &str) -> Option<PathBuf> {
    (session.len() == 32 && session.bytes().all(|c| c.is_ascii_hexdigit()))
        .then(|| Path::new(ROOT).join(format!("ipv6-lease-{session}.json")))
}

pub struct Upstream {
    client: Option<Child>,
    session: Option<String>,
    setup: Transaction,
    network: Transaction,
    installed: Option<Lease>,
    path: Option<Lease>,
    phase: &'static str,
    error: Option<String>,
    lan_prefix: Option<String>,
    ra_mtu: Option<u32>,
    requested: bool,
    revision: u64,
    lan_observed: BTreeMap<String, u64>,
    lan_sources: Vec<String>,
    local: Vec<IpAddr>,
}

pub fn off_status() -> Value {
    json!({"requested":false,"state":"off","upstream":false,"nat66":false,"internet":"not_verified"})
}

impl Upstream {
    pub fn new() -> Self {
        Self {
            client: None,
            session: None,
            setup: Transaction::new(Path::new(JOURNAL).join("ipv6-setup.json")),
            network: Transaction::new(Path::new(JOURNAL).join("ipv6-network.json")),
            installed: None,
            path: None,
            phase: "off",
            error: None,
            lan_prefix: None,
            ra_mtu: None,
            requested: false,
            revision: 0,
            lan_observed: BTreeMap::new(),
            lan_sources: Vec::new(),
            local: Vec::new(),
        }
    }

    pub fn status(&self) -> Value {
        let ready = self
            .installed
            .as_ref()
            .is_some_and(|l| l.remaining(now()).ready());
        json!({"requested": self.requested, "state": if self.installed.is_some() && !ready { "expired" } else { self.phase },
            "upstream":ready,"nat66":ready,"internet":"not_verified","error":self.error,
            "address": self.installed.as_ref().and_then(|l| l.addresses.first()).map(|a| a.address),
            "gateway":self.installed.as_ref().and_then(|l| l.routers.first()).map(|r| r.address),"lan_prefix":self.lan_prefix,
            "upstream_mtu":self.installed.as_ref().map(|l| l.mtu),"lan_mtu":self.ra_mtu})
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn start(&mut self, requested: bool) -> Result<(), String> {
        self.requested = requested;
        if !requested {
            return Ok(());
        }
        let attempt = (|| {
            capabilities()?;
            net::reserve("ip6tables", "filter", &["U60_R6_IN"], "-6", TABLE, PREF)?;
            for step in setup_plan() {
                self.setup.apply(step)?;
            }
            let mut nonce = [0u8; 16];
            getrandom::getrandom(&mut nonce).map_err(|_| "Cannot create IPv6 relay session")?;
            let session = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
            self.session = Some(session.clone());
            let callback = std::env::current_exe().map_err(|_| "Cannot locate relay callback")?;
            // libtest replaces main(), so isolated Linux QA uses the real
            // release executable for callbacks. This override is test-only.
            #[cfg(test)]
            let callback = std::env::var_os("U60_IPV6_QA_CALLBACK")
                .map(std::path::PathBuf::from)
                .unwrap_or(callback);
            let mut cmd = Command::new("odhcp6c");
            cmd.args(["-N", "try", "-R", "-r", "23", "-s"])
                .arg(callback)
                .args(["-p", &format!("{ROOT}/odhcp6c.pid"), IFACE])
                .env("U60_RELAY_DHCP6", "1")
                .env("U60_RELAY_DHCP6_SESSION", session);
            self.client = Some(net::owned_child(cmd)?);
            self.phase = "detecting";
            Ok(())
        })();
        if let Err(e) = attempt {
            net::stop_child(&mut self.client);
            self.setup.rollback()?;
            self.phase = "unsupported";
            self.error = Some(e);
        }
        Ok(())
    }

    pub fn tick(&mut self) -> Result<(), String> {
        if let Err(error) = self.tick_inner() {
            // Only an unsafe, failed undo may propagate to the relay owner.
            // Ordinary RA/lease errors withdraw IPv6, not working IPv4.
            self.network.rollback()?;
            if self.installed.take().is_some() {
                self.revision = self.revision.wrapping_add(1);
            }
            self.path = None;
            self.lan_prefix = None;
            self.ra_mtu = None;
            self.phase = "error";
            self.error = Some(format!("{error}; IPv4 relay remains active"));
        }
        Ok(())
    }

    fn tick_inner(&mut self) -> Result<(), String> {
        if self.client.is_none() {
            return Ok(());
        }
        if !matches!(self.client.as_mut().unwrap().try_wait(), Ok(None)) {
            self.stop()?;
            self.phase = "error";
            self.error = Some("IPv6 discovery stopped; IPv4 relay remains active".into());
            return Ok(());
        }
        let lease = fs::read(lease_file(self.session.as_ref().unwrap()).unwrap())
            .ok()
            .filter(|b| b.len() <= 16384)
            .and_then(|b| serde_json::from_slice::<Lease>(&b).ok());
        let live = lease
            .as_ref()
            .map(|l| l.remaining(now()))
            .filter(Lease::ready);
        if live.is_none() {
            if self.installed.is_some() {
                self.network.rollback()?;
                self.revision = self.revision.wrapping_add(1);
                self.installed = None;
                self.path = None;
                self.lan_prefix = None;
                self.ra_mtu = None;
            }
            self.phase = "no_upstream";
            return Ok(());
        }
        let live = live.unwrap();
        let ra_mtu = ra::advertised_mtu(live.mtu, ra::lan_mtu()?)?;
        let lan = Cmd::new("ip", &["-j", "-6", "addr", "show", "dev", "br-lan"]).run()?;
        observe_lan(
            &mut self.lan_observed,
            &lan,
            self.lan_prefix.as_deref(),
            now(),
        )?;
        let local = vendor_local_addresses(&live, self.lan_prefix.as_deref())?;
        let sources: Vec<_> = self.lan_observed.keys().cloned().collect();
        if self.path.as_ref().is_some_and(|p| same_path(p, &live))
            && sources == self.lan_sources
            && local == self.local
            && self.ra_mtu == Some(ra_mtu)
        {
            maintain_ra()?;
            let ula = self.lan_prefix.as_ref().unwrap();
            let address = Ipv6Addr::from(u128::from(cidr(ula).unwrap().0) + 1);
            let refreshed = refresh_path(&live).and_then(|_| {
                for source in sources.iter().chain(std::iter::once(ula)) {
                    lan_route(source, "change").run()?;
                }
                Cmd::new(
                    "ip",
                    &[
                        "-6",
                        "addr",
                        "change",
                        &format!("{address}/64"),
                        "dev",
                        "br-lan",
                        "valid_lft",
                        "180",
                        "preferred_lft",
                        "90",
                    ],
                )
                .run()
            });
            if refreshed.is_ok() {
                self.installed = lease;
                self.path = Some(live);
                return Ok(());
            }
            // A delayed watchdog may find the old finite address/route already
            // expired. Rebuild only IPv6; this is not an IPv4 relay failure.
        }
        self.network.rollback()?;
        self.revision = self.revision.wrapping_add(1);
        self.installed = None;
        self.path = None;
        self.lan_prefix = None;
        self.ra_mtu = None;
        match self.configure(&live, ra_mtu) {
            Ok(lan_prefix) => {
                self.revision = self.revision.wrapping_add(1);
                self.installed = lease;
                self.path = Some(live);
                self.lan_prefix = Some(lan_prefix);
                self.ra_mtu = Some(ra_mtu);
                self.phase = "configured";
                self.error = None;
            }
            Err(e) => {
                self.network.rollback()?;
                self.path = None;
                self.phase = "error";
                self.error = Some(e);
            }
        }
        Ok(())
    }

    fn configure(&mut self, lease: &Lease, mtu: u32) -> Result<String, String> {
        net::reserve("ip6tables", "filter", &["U60_R6_FWD"], "-6", TABLE, PREF)?;
        for chain in ["U60_R6_NAT", "U60_R6_DNS", "U60_R6_RDNS"] {
            if Cmd::new("ip6tables", &["-w", "2", "-t", "nat", "-S", chain])
                .run()
                .is_ok()
            {
                return Err("IPv6 relay chains are already in use".into());
            }
        }
        if Cmd::new(
            "ip6tables",
            &["-w", "2", "-t", "filter", "-S", "U60_R6_RDNS"],
        )
        .run()
        .is_ok()
        {
            return Err("IPv6 relay DNS guard is already in use".into());
        }
        let lan = Cmd::new("ip", &["-j", "-6", "addr", "show", "dev", "br-lan"]).run()?;
        let (lan_prefixes, linklocal) = lan_state(&lan)?;
        let ula = stable_ula()?;
        let ula_address = cidr(&ula).unwrap().0;
        if lan_prefixes
            .iter()
            .any(|p| cidr(p).is_some_and(|(a, b)| prefix(ula_address, b) == prefix(a, b)))
        {
            return Err("Relay ULA prefix is already in use on LAN".into());
        }
        if lease.addresses.iter().any(|a| {
            lan_prefixes
                .iter()
                .chain(std::iter::once(&ula))
                .any(|p| cidr(p).is_some_and(|(n, b)| prefix(a.address, b) == prefix(n, b)))
        }) {
            return Err("Upstream IPv6 prefix overlaps LAN".into());
        }
        if lease.onlink.iter().any(|r| {
            lan_prefixes
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(ula.as_str()))
                .chain(std::iter::once(TAILNET))
                .any(|p| {
                    cidr(p).is_some_and(|(a, bits)| {
                        prefix(a, bits.min(r.prefix)) == prefix(r.address, bits.min(r.prefix))
                    })
                })
        }) {
            return Err("Upstream IPv6 on-link prefix overlaps LAN or Tailnet".into());
        }
        observe_lan(&mut self.lan_observed, &lan, None, now())?;
        let mut sources: Vec<_> = self.lan_observed.keys().cloned().collect();
        if sources.iter().any(|p| {
            lease.onlink.iter().any(|r| {
                cidr(p).is_some_and(|(a, bits)| {
                    prefix(a, bits.min(r.prefix)) == prefix(r.address, bits.min(r.prefix))
                })
            })
        }) {
            return Err("Upstream IPv6 prefix overlaps a retained LAN prefix".into());
        }
        let local_snapshot = vendor_local_addresses(lease, Some(&ula))?;
        self.lan_sources = sources.clone();
        if !sources.contains(&ula) {
            sources.push(ula.clone());
        }
        let local = Cmd::new("ip", &["-j", "-6", "addr", "show"]).run()?;
        let dns_lease = safe_dns_lease(lease, &sources, &local)?;
        let mihomo_dns = Cmd::new(
            "ip6tables",
            &[
                "-w",
                "2",
                "-t",
                "nat",
                "-C",
                "PREROUTING",
                "-i",
                "br-lan",
                "-j",
                "U60_MH_DNS",
            ],
        )
        .run()
        .is_ok();
        for step in network_plan(
            &dns_lease,
            &ula,
            &sources,
            mihomo_dns,
            &net::local_addresses()?,
        ) {
            self.network.apply(step)?;
        }
        let route = Cmd::new("ip", &["-6", "route", "get", "2606:4700:4700::1111"]).run()?;
        if !route.contains(&format!("dev {IFACE}")) {
            return Err("IPv6 routing did not select Wi-Fi".into());
        }
        // Advertising is last. Undo withdraws RA before removing NAT/routes.
        self.network.apply(ra_step(&ula, linklocal, mtu))?;
        self.local = local_snapshot;
        Ok(ula)
    }

    pub fn stop(&mut self) -> Result<(), String> {
        net::stop_child(&mut self.client);
        self.network.rollback()?;
        self.setup.rollback()?;
        if self.installed.is_some() {
            self.revision = self.revision.wrapping_add(1);
        }
        self.installed = None;
        self.path = None;
        self.lan_prefix = None;
        self.ra_mtu = None;
        self.phase = "off";
        self.lan_observed.clear();
        self.lan_sources.clear();
        self.local.clear();
        if let Some(path) = self.session.take().and_then(|s| lease_file(&s)) {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_file(Path::new(ROOT).join("odhcp6c.pid"));
        Ok(())
    }
}

pub fn recover() -> Result<(), String> {
    Transaction::recover(&Path::new(JOURNAL).join("ipv6-network.json"))?;
    // The separate RA snapshot also covers a crash before applying its journal step.
    ra_restore()?;
    Transaction::recover(&Path::new(JOURNAL).join("ipv6-setup.json"))?;
    // Delayed odhcp6c script children may survive their client. Each writes
    // only its own nonce path, never the next session's state.
    if let Ok(entries) = fs::read_dir(ROOT) {
        for entry in entries.flatten() {
            if let Some(session) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.strip_prefix("ipv6-lease-"))
                .and_then(|s| s.strip_suffix(".json").or_else(|| s.strip_suffix(".new")))
            {
                if lease_file(session).is_some() {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
    Ok(())
}

fn capabilities() -> Result<(), String> {
    // odhcp6c's help exits 1 even on OpenWrt. Its owned spawn below is the
    // executable check, and any failure rolls back the journaled setup.
    Cmd::new("ip6tables", &["-w", "2", "-t", "nat", "-S"]).run()?;
    Cmd::new("ip6tables", &["-t", "nat", "-j", "MASQUERADE", "--help"]).run()?;
    if fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
        .unwrap_or_default()
        .trim()
        != "1"
    {
        return Err("IPv6 forwarding is disabled; IPv4 relay remains available".into());
    }
    if Cmd::new("uci", &["-q", "get", "dhcp.lan.ra"]).run()? != "server" {
        return Err("IPv6 relay requires the existing LAN odhcpd RA server".into());
    }
    if !Cmd::new("pidof", &["odhcpd"])
        .run()?
        .split_whitespace()
        .any(|s| s.parse::<u32>().is_ok())
    {
        return Err("Existing LAN odhcpd is not running".into());
    }
    Ok(())
}

fn setup_plan() -> Vec<Step> {
    let mut plan = Vec::new();
    for (key, value) in [
        ("accept_ra", "0"),
        ("autoconf", "0"),
        ("accept_ra_defrtr", "0"),
        ("accept_redirects", "0"),
        ("use_tempaddr", "0"),
        ("disable_ipv6", "0"),
    ] {
        // Only this owned interface is changed; deleting it is the undo.
        plan.push(Step::new(
            Cmd::new(
                "sysctl",
                &["-w", &format!("net.ipv6.conf.{IFACE}.{key}={value}")],
            ),
            Cmd::new("true", &[]),
        ));
    }
    // The existing scan INPUT guard stays closed except for this owned subchain.
    plan.extend(net::chain("ip6tables", "filter", "U60_R6_IN"));
    plan.push(net::rule(
        "ip6tables",
        "filter",
        "U60_R6_IN",
        &[
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
        false,
    ));
    for (kind, source) in [("134", Some("fe80::/10")), ("135", None), ("136", None)] {
        let mut args = vec![
            "-p",
            "ipv6-icmp",
            "--icmpv6-type",
            kind,
            "-m",
            "hl",
            "--hl-eq",
            "255",
        ];
        if let Some(source) = source {
            args.extend(["-s", source]);
        }
        args.extend(["-j", "ACCEPT"]);
        plan.push(net::rule("ip6tables", "filter", "U60_R6_IN", &args, false));
    }
    for kind in ["1", "2", "3", "4"] {
        plan.push(net::rule(
            "ip6tables",
            "filter",
            "U60_R6_IN",
            &["-p", "ipv6-icmp", "--icmpv6-type", kind, "-j", "ACCEPT"],
            false,
        ));
    }
    plan.push(net::rule(
        "ip6tables",
        "filter",
        "U60_R6_IN",
        &[
            "-p", "udp", "--sport", "547", "--dport", "546", "-j", "ACCEPT",
        ],
        false,
    ));
    plan.push(net::rule(
        "ip6tables",
        "filter",
        "U60_R6_IN",
        &["-j", "DROP"],
        false,
    ));
    plan.push(net::rule(
        "ip6tables",
        "filter",
        "U60_RELAY_IN",
        &["-j", "U60_R6_IN"],
        true,
    ));
    plan
}

fn stable_ula() -> Result<String, String> {
    let path = Path::new(JOURNAL).join("ula-prefix");
    if let Ok(text) = fs::read_to_string(&path) {
        let text = text.trim();
        if cidr(text).is_some_and(|(a, p)| p == 64 && a.octets()[0] == 0xfd && prefix(a, p) == text)
        {
            return Ok(text.into());
        }
        return Err("Saved relay ULA prefix is invalid".into());
    }
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes[1..6]).map_err(|_| "Cannot create relay ULA prefix")?;
    bytes[0] = 0xfd;
    let value = format!("{}/64", Ipv6Addr::from(bytes));
    net::write_private(&path, value.as_bytes())?;
    Ok(value)
}

fn lan_state(text: &str) -> Result<(Vec<String>, Ipv6Addr), String> {
    let value: Value = serde_json::from_str(text).map_err(|_| "Cannot read IPv6 LAN addresses")?;
    let addrs = value[0]["addr_info"]
        .as_array()
        .ok_or("No IPv6 LAN addresses")?;
    let mut prefixes = Vec::new();
    let mut linklocal = None;
    for entry in addrs.iter().take(32) {
        let Some(address) = entry["local"]
            .as_str()
            .and_then(|a| a.parse::<Ipv6Addr>().ok())
        else {
            continue;
        };
        if address.is_unicast_link_local() {
            linklocal = Some(address);
            continue;
        }
        if usable(address) {
            let bits = entry["prefixlen"]
                .as_u64()
                .filter(|p| (48..=128).contains(p))
                .ok_or("Unsupported LAN IPv6 prefix")? as u8;
            let network = prefix(address, bits);
            if !prefixes.contains(&network) {
                prefixes.push(network);
            }
        }
    }
    if prefixes.len() > 8 {
        return Err("Too many IPv6 LAN prefixes".into());
    }
    Ok((
        prefixes,
        linklocal.ok_or("LAN IPv6 link-local address is missing")?,
    ))
}

fn observe_lan(
    known: &mut BTreeMap<String, u64>,
    text: &str,
    owned: Option<&str>,
    now: u64,
) -> Result<(), String> {
    let (prefixes, _) = lan_state(text)?;
    let value: Value = serde_json::from_str(text).map_err(|_| "Cannot read LAN lifetimes")?;
    for p in prefixes {
        if Some(p.as_str()) == owned {
            continue;
        }
        let lifetime = value[0]["addr_info"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|a| {
                a["local"]
                    .as_str()
                    .and_then(|a| a.parse::<Ipv6Addr>().ok())
                    .zip(a["prefixlen"].as_u64())
                    .is_some_and(|(a, b)| prefix(a, b as u8) == p)
            })
            .map(|a| {
                a["valid_life_time"]
                    .as_u64()
                    .unwrap_or(LAN_GRACE)
                    .min(LAN_GRACE)
            })
            .max()
            .unwrap_or(0);
        if lifetime > 0 {
            known.insert(p, now.saturating_add(lifetime));
        }
    }
    known.retain(|p, deadline| Some(p.as_str()) != owned && *deadline > now);
    if known.len() > 16 {
        return Err("Too many retained LAN IPv6 prefixes".into());
    }
    Ok(())
}

fn vendor_local_addresses(lease: &Lease, ula: Option<&str>) -> Result<Vec<IpAddr>, String> {
    let own = ula
        .and_then(cidr)
        .map(|(a, _)| Ipv6Addr::from(u128::from(a) + 1));
    let mut local: Vec<_> = crate::httpd::mobile::interfaces()
        .map_err(|_| "Cannot observe current local addresses")?.into_iter()
        .filter(|i| i.name != IFACE && i.name != "u60mh0")
        .map(|i| i.addr).filter(|a| !matches!(a, IpAddr::V6(a) if Some(*a) == own || lease.addresses.iter().any(|s| s.address == *a)))
        .collect();
    local.sort_unstable();
    local.dedup();
    Ok(local)
}

fn lan_route(source: &str, action: &str) -> Cmd {
    Cmd::new(
        "ip",
        &[
            "-6",
            "route",
            action,
            source,
            "dev",
            "br-lan",
            "expires",
            &LAN_GRACE.to_string(),
            "table",
            TABLE,
        ],
    )
}

fn same_path(a: &Lease, b: &Lease) -> bool {
    a.addresses
        .iter()
        .map(|a| (a.address, a.prefix))
        .eq(b.addresses.iter().map(|a| (a.address, a.prefix)))
        && a.routers.first().map(|r| r.address) == b.routers.first().map(|r| r.address)
        && a.dns == b.dns
        && a.mtu == b.mtu
        && a.onlink
            .iter()
            .map(|r| (r.address, r.prefix))
            .eq(b.onlink.iter().map(|r| (r.address, r.prefix)))
}

fn safe_dns_lease(l: &Lease, lan: &[String], local: &str) -> Result<Lease, String> {
    let interfaces: Value =
        serde_json::from_str(local).map_err(|_| "Cannot check IPv6 DNS conflicts")?;
    let interfaces = interfaces
        .as_array()
        .ok_or("Cannot check IPv6 DNS conflicts")?;
    let local: Vec<Ipv6Addr> = interfaces
        .iter()
        .filter_map(|i| i["addr_info"].as_array())
        .flatten()
        .filter_map(|a| a["local"].as_str()?.parse().ok())
        .collect();
    let mut safe = l.clone();
    safe.dns.retain(|a| {
        !local.contains(a)
            && !l.addresses.iter().any(|source| source.address == *a)
            && !lan
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(TAILNET))
                .any(|p| cidr(p).is_some_and(|(n, b)| prefix(*a, b) == prefix(n, b)))
    });
    Ok(safe)
}

fn default_route(l: &Lease, action: &str) -> Cmd {
    let r = &l.routers[0];
    let a = &l.addresses[0];
    Cmd::new(
        "ip",
        &[
            "-6",
            "route",
            action,
            "default",
            "via",
            &r.address.to_string(),
            "dev",
            IFACE,
            "src",
            &a.address.to_string(),
            "metric",
            "1024",
            "mtu",
            &l.mtu.to_string(),
            "expires",
            &r.valid.min(a.valid).to_string(),
            "table",
            TABLE,
        ],
    )
}

fn onlink_route(r: &OnLink, action: &str, mtu: u32) -> Step {
    Step::new(
        Cmd::new(
            "ip",
            &[
                "-6",
                "route",
                action,
                &prefix(r.address, r.prefix),
                "dev",
                IFACE,
                "expires",
                &r.valid.to_string(),
                "mtu",
                &mtu.to_string(),
                "table",
                TABLE,
            ],
        ),
        Cmd::new(
            "ip",
            &[
                "-6",
                "route",
                "del",
                &prefix(r.address, r.prefix),
                "dev",
                IFACE,
                "table",
                TABLE,
            ],
        ),
    )
}

fn refresh_path(l: &Lease) -> Result<(), String> {
    for a in &l.addresses {
        Cmd::new(
            "ip",
            &[
                "-6",
                "addr",
                "change",
                &format!("{}/128", a.address),
                "dev",
                IFACE,
                "valid_lft",
                &a.valid.to_string(),
                "preferred_lft",
                &a.preferred.to_string(),
            ],
        )
        .run()?;
    }
    for r in &l.onlink {
        onlink_route(r, "change", l.mtu).apply.run()?;
    }
    // This changes only the already-owned route and retains its journaled undo;
    // lease renewals must not tear down NAT/conntrack or re-advertise cellular RA.
    default_route(l, "change").run().map(|_| ())
}

pub fn wait_addresses(args: &[String]) -> Result<(), String> {
    if args.is_empty()
        || args.len() > 32
        || args
            .iter()
            .any(|a| !a.parse::<Ipv6Addr>().is_ok_and(usable))
    {
        return Err("Invalid IPv6 DAD address list".into());
    }
    for _ in 0..30 {
        let text = Cmd::new("ip", &["-j", "-6", "addr", "show", "dev", IFACE]).run()?;
        if addresses_ready(&text, args)? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("Upstream IPv6 duplicate-address detection did not complete".into())
}

fn addresses_ready(text: &str, addresses: &[String]) -> Result<bool, String> {
    let value: Value = serde_json::from_str(text).map_err(|_| "Cannot check IPv6 DAD")?;
    let info = value[0]["addr_info"]
        .as_array()
        .ok_or("Cannot check IPv6 DAD")?;
    for address in addresses {
        let Some(a) = info.iter().find(|a| a["local"].as_str() == Some(address)) else {
            return Ok(false);
        };
        if a["dadfailed"].as_bool() == Some(true) {
            return Err("Duplicate upstream IPv6 address".into());
        }
        if a["tentative"].as_bool() == Some(true) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn network_plan(
    l: &Lease,
    ula: &str,
    sources: &[String],
    mihomo_dns: bool,
    local: &[std::net::IpAddr],
) -> Vec<Step> {
    let mut local = local.to_vec();
    local.extend(l.addresses.iter().map(|a| std::net::IpAddr::V6(a.address)));
    local.sort_unstable();
    local.dedup();
    let mut p = Vec::new();
    for a in &l.addresses {
        // /128 noprefixroute avoids any new kernel route in the main table.
        let mut step = net::ip_step(
            "-6",
            "addr",
            &[
                &format!("{}/128", a.address),
                "dev",
                IFACE,
                "noprefixroute",
                "valid_lft",
                &a.valid.to_string(),
                "preferred_lft",
                &a.preferred.to_string(),
            ],
        );
        step.undo = Cmd::new(
            "ip",
            &[
                "-6",
                "addr",
                "del",
                &format!("{}/128", a.address),
                "dev",
                IFACE,
            ],
        );
        p.push(step);
    }
    let mut dad = Cmd::new("@u60-relay-ipv6-dad", &[]);
    dad.args = l.addresses.iter().map(|a| a.address.to_string()).collect();
    p.push(Step::new(dad, Cmd::new("true", &[])));
    let lan_address = Ipv6Addr::from(u128::from(cidr(ula).unwrap().0) + 1);
    p.push(net::ip_step(
        "-6",
        "addr",
        &[
            &format!("{lan_address}/64"),
            "dev",
            "br-lan",
            "valid_lft",
            "180",
            "preferred_lft",
            "90",
        ],
    ));
    p.push(net::ip_step(
        "-6",
        "route",
        &["fe80::/64", "dev", IFACE, "table", TABLE],
    ));
    let destinations: Vec<&str> = vec![TAILNET, "fe80::/10", "ff00::/8"];
    for source in sources {
        p.push(Step::new(
            lan_route(source, "add"),
            Cmd::new(
                "ip",
                &[
                    "-6", "route", "del", source, "dev", "br-lan", "table", TABLE,
                ],
            ),
        ));
    }
    for dest in destinations {
        // Link-local gateways are resolved within this table; destinations
        // with an explicit scope/interface retain the kernel link route.
        if dest == "fe80::/10" {
            continue;
        }
        p.push(net::ip_step(
            "-6",
            "route",
            &["throw", dest, "table", TABLE],
        ));
    }
    // SLAAC's A flag does not imply on-link (L). Only explicit no-gateway
    // RA_ROUTES entries authorize neighbor discovery for a global prefix.
    for route in &l.onlink {
        p.push(onlink_route(route, "add", l.mtu));
    }
    p.push(Step::new(
        default_route(l, "add"),
        Cmd::new(
            "ip",
            &[
                "-6",
                "route",
                "del",
                "default",
                "via",
                &l.routers[0].address.to_string(),
                "dev",
                IFACE,
                "metric",
                "1024",
                "table",
                TABLE,
            ],
        ),
    ));
    p.extend(net::chain("ip6tables", "nat", "U60_R6_NAT"));
    // Cover core/router sockets retaining an old cellular source, as well as
    // existing cellular LAN addresses that clients have not deprecated yet.
    p.push(net::rule(
        "ip6tables",
        "nat",
        "U60_R6_NAT",
        &["-j", "MASQUERADE"],
        false,
    ));
    p.push(net::rule(
        "ip6tables",
        "nat",
        "POSTROUTING",
        &["-o", IFACE, "-j", "U60_R6_NAT"],
        true,
    ));
    p.push(net::rule(
        "ip6tables",
        "filter",
        "OUTPUT",
        &["-o", "rmnet+", "-j", "REJECT"],
        true,
    ));
    p.extend(net::chain("ip6tables", "filter", "U60_R6_FWD"));
    for source in sources {
        p.push(net::rule(
            "ip6tables",
            "filter",
            "U60_R6_FWD",
            &["-i", "br-lan", "-o", IFACE, "-s", source, "-j", "ACCEPT"],
            false,
        ));
    }
    p.push(net::rule(
        "ip6tables",
        "filter",
        "U60_R6_FWD",
        &[
            "-i",
            IFACE,
            "-o",
            "br-lan",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
        false,
    ));
    for flag in ["-i", "-o"] {
        p.push(net::rule(
            "ip6tables",
            "filter",
            "U60_R6_FWD",
            &[flag, IFACE, "-j", "DROP"],
            false,
        ));
    }
    p.push(net::rule(
        "ip6tables",
        "filter",
        "FORWARD",
        &["-j", "U60_R6_FWD"],
        true,
    ));
    p.extend(net::chain("ip6tables", "nat", "U60_R6_DNS"));
    for dest in ["::1/128", TAILNET, "fe80::/10"]
        .into_iter()
        .chain(sources.iter().map(String::as_str))
    {
        p.push(net::rule(
            "ip6tables",
            "nat",
            "U60_R6_DNS",
            &["-d", dest, "-j", "ACCEPT"],
            false,
        ));
    }
    p.extend(net::local_exclusions(
        "ip6tables",
        "nat",
        "U60_R6_DNS",
        "ACCEPT",
        &local,
    ));
    // External client DNS goes through local dnsmasq (Mihomo still wins).
    for proto in ["tcp", "udp"] {
        p.push(net::rule(
            "ip6tables",
            "nat",
            "U60_R6_DNS",
            &["-p", proto, "-j", "REDIRECT", "--to-ports", "53"],
            false,
        ));
    }
    // Local management DNS is not rewritten; other router DNS follows
    // the Wi-Fi RDNSS instead of the vendor's SIM-only resolver.
    let upstream_dns = l.dns.iter().find(|a| !a.is_unicast_link_local());
    let dns_table = if upstream_dns.is_some() {
        "nat"
    } else {
        "filter"
    };
    p.extend(net::chain("ip6tables", dns_table, "U60_R6_RDNS"));
    for dest in ["::1/128", TAILNET, "fe80::/10"]
        .into_iter()
        .chain(sources.iter().map(String::as_str))
    {
        p.push(net::rule(
            "ip6tables",
            dns_table,
            "U60_R6_RDNS",
            &["-d", dest, "-j", "ACCEPT"],
            false,
        ));
    }
    p.extend(net::local_exclusions(
        "ip6tables",
        dns_table,
        "U60_R6_RDNS",
        "ACCEPT",
        &local,
    ));
    if let Some(dns) = upstream_dns {
        for proto in ["tcp", "udp"] {
            p.push(net::rule(
                "ip6tables",
                "nat",
                "U60_R6_RDNS",
                &[
                    "-p",
                    proto,
                    "-j",
                    "DNAT",
                    "--to-destination",
                    &format!("[{dns}]:53"),
                ],
                false,
            ));
        }
    } else {
        p.push(net::rule(
            "ip6tables",
            dns_table,
            "U60_R6_RDNS",
            &["-j", "REJECT"],
            false,
        ));
    }
    for proto in ["tcp", "udp"] {
        let mut jump = net::rule(
            "ip6tables",
            "nat",
            "PREROUTING",
            &[
                "-i",
                "br-lan",
                "-p",
                proto,
                "--dport",
                "53",
                "-j",
                "U60_R6_DNS",
            ],
            true,
        );
        if mihomo_dns {
            jump.apply.args[6] = "2".into();
        }
        p.push(jump);
        // Ordinary router DNS using a nonlocal IPv6 resolver must not retain
        // its SIM resolver. Without RDNSS, fail fast so IPv4 DNS can be used.
        p.push(net::rule(
            "ip6tables",
            dns_table,
            "OUTPUT",
            &["-p", proto, "--dport", "53", "-j", "U60_R6_RDNS"],
            true,
        ));
    }
    p.push(net::ip_step("-6", "rule", &["pref", PREF, "lookup", TABLE]));
    p
}

#[derive(Clone, Serialize, Deserialize)]
struct OptionState {
    key: String,
    list: bool,
    original: Option<String>,
    applied: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct RaState {
    boot: String,
    options: Vec<OptionState>,
}

fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_default()
        .trim()
        .into()
}

#[cfg(test)]
fn ra_options(ula: &str, dns: Ipv6Addr) -> Vec<(&'static str, bool, Option<String>)> {
    vec![
        ("ra", false, Some("server".into())),
        ("dhcpv6", false, Some("disabled".into())),
        ("ndp", false, Some("disabled".into())),
        ("ra_slaac", false, Some("1".into())),
        ("ra_default", false, Some("2".into())),
        ("ra_lifetime", false, Some("90".into())),
        ("ra_mininterval", false, Some("10".into())),
        ("ra_maxinterval", false, Some("30".into())),
        ("ra_flags", true, Some("none".into())),
        ("ra_mtu", false, Some("1280".into())),
        ("ra_useleasetime", false, Some("0".into())),
        ("prefix_filter", false, Some(ula.into())),
        ("ra_dns", false, Some("1".into())),
        ("dns", true, Some(dns.to_string())),
    ]
}

fn read_option(key: &str) -> Result<Option<String>, String> {
    let all = Cmd::new("uci", &["-q", "show", "dhcp.lan"]).run()?;
    if !all
        .lines()
        .any(|l| l.starts_with(&format!("dhcp.lan.{key}=")))
    {
        return Ok(None);
    }
    Cmd::new("uci", &["-q", "get", &format!("dhcp.lan.{key}")])
        .run()
        .map(Some)
}

fn write_option(key: &str, list: bool, value: &Option<String>) -> Result<(), String> {
    let name = format!("dhcp.lan.{key}");
    if (list || value.is_none()) && read_option(key)?.is_some() {
        Cmd::new("uci", &["-q", "delete", &name]).run()?;
    }
    if let Some(value) = value {
        if list {
            for part in value.split_whitespace() {
                Cmd::new("uci", &["add_list", &format!("{name}={part}")]).run()?;
            }
        } else {
            Cmd::new("uci", &["set", &format!("{name}={value}")]).run()?;
        }
    }
    Ok(())
}

fn reload_ra() -> Result<(), String> {
    Cmd::new("/etc/init.d/odhcpd", &["reload"])
        .run()
        .map(|_| ())
}

fn ra_step(ula: &str, dns: Ipv6Addr, mtu: u32) -> Step {
    Step::new(
        Cmd::new("@u60-relay-ra", &["apply", ula, &dns.to_string(), &mtu.to_string()]),
        Cmd::new("@u60-relay-ra", &["restore"]),
    )
}

pub fn ra_command(args: &[String]) -> Result<(), String> {
    match args {
        [action] if action == "restore" => ra_restore(),
        [action, ula, dns, mtu]
            if action == "apply"
                && cidr(ula).is_some_and(|(a, p)| a.octets()[0] == 0xfd && p == 64)
                && dns
                    .parse::<Ipv6Addr>()
                    .is_ok_and(|a| a.is_unicast_link_local()) =>
        {
            let mtu = mtu.parse().map_err(|_| "Invalid IPv6 RA MTU")?;
            ra::apply(ula, mtu)
        }
        _ => Err("Invalid IPv6 RA recovery command".into()),
    }
}

fn ra_restore() -> Result<(), String> {
    // Compatibility only: remove previously committed relay values once.
    // New sessions never create this historical UCI snapshot.
    legacy_ra_restore()?;
    ra::release()
}

#[cfg(all(test, target_os = "linux"))]
fn legacy_ra_command(args: &[String]) -> Result<(), String> {
    match args {
        [action] if action == "restore" => ra_restore(),
        [action, ula, dns]
            if action == "apply"
                && cidr(ula).is_some_and(|(a, p)| a.octets()[0] == 0xfd && p == 64) =>
        {
            let dns: Ipv6Addr = dns.parse().map_err(|_| "Invalid LAN RA DNS")?;
            if !dns.is_unicast_link_local() {
                return Err("LAN RA DNS must be link-local".into());
            }
            let path = Path::new(JOURNAL).join(RA_STATE);
            if path.exists()
                || !Cmd::new("uci", &["-q", "changes", "dhcp"])
                    .run()?
                    .is_empty()
            {
                return Err("DHCP settings changed; IPv6 RA was not taken over".into());
            }
            let mut options = Vec::new();
            for (key, list, applied) in ra_options(ula, dns) {
                options.push(OptionState {
                    key: key.into(),
                    list,
                    original: read_option(key)?,
                    applied,
                });
            }
            let state = RaState {
                boot: boot_id(),
                options,
            };
            net::write_private(&path, &serde_json::to_vec(&state).unwrap())?;
            for o in &state.options {
                write_option(&o.key, o.list, &o.applied)?;
            }
            reload_ra()
        }
        _ => Err("Invalid IPv6 RA recovery command".into()),
    }
}

fn legacy_ra_restore() -> Result<(), String> {
    let path = Path::new(JOURNAL).join(RA_STATE);
    if !path.exists() {
        return Ok(());
    }
    let state: RaState =
        serde_json::from_slice(&fs::read(&path).map_err(|_| "Cannot read RA recovery")?)
            .map_err(|_| "Invalid RA recovery snapshot")?;
    if !state.boot.is_empty() && state.boot != boot_id() {
        // Runtime overlays vanished. Keep the vendor's new boot baseline,
        // repairing only exact persisted relay values, never missing lists.
        if restore_committed_ra(&state, true)? {
            reload_ra()?;
        }
        return fs::remove_file(path).map_err(|e| e.to_string());
    }
    // A cellular toggle may rewrite only some options and commit our other
    // deltas. Release changed options individually; never let one vendor/user
    // edit strand all owned NAT/routes or overwrite its new value.
    let mut external = Vec::new();
    for o in &state.options {
        if !option_owned(o, &read_option(&o.key)?) {
            external.push(o.key.as_str());
        }
    }
    restore_committed_ra(&state, false)?;
    if !external.contains(&"ra_lifetime") {
        write_option("ra_lifetime", false, &Some("0".into()))?;
        reload_ra()?;
        std::thread::sleep(Duration::from_millis(1200));
    }
    for o in state.options.iter().rev() {
        if external.contains(&o.key.as_str()) || !option_owned(o, &read_option(&o.key)?) {
            continue;
        }
        // No commit: per-option revert removes our /tmp/.uci delta without
        // discarding any other option's changes. A vendor commit must not
        // silently turn temporary relay settings into permanent configuration.
        let name = format!("dhcp.lan.{}", o.key);
        let _ = Cmd::new("uci", &["-q", "revert", &name]).run();
        let current = read_option(&o.key)?;
        if current != o.original && option_owned(o, &current) {
            return Err("DHCP configuration changed during relay cleanup; retry cleanup".into());
        }
    }
    reload_ra()?;
    fs::remove_file(path).map_err(|e| e.to_string())
}

// B31's cellular switch can commit the whole DHCP package, including our
// temporary options. Repair only owned persisted values, never commit pending
// global UCI deltas. A random package alias isolates libuci's default delta path.
fn restore_committed_ra(state: &RaState, after_reboot: bool) -> Result<bool, String> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    let path = Path::new("/etc/config/dhcp");
    let mut source = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "Cannot open persistent DHCP configuration")?;
    if unsafe { libc::flock(source.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("Persistent DHCP configuration is busy; retry recovery".into());
    }
    let metadata = source.metadata().map_err(|e| e.to_string())?;
    let mut before = Vec::new();
    Read::by_ref(&mut source)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut before)
        .map_err(|e| e.to_string())?;
    if before.len() > 1024 * 1024 {
        return Err("Persistent DHCP configuration is too large".into());
    }
    let mut random = [0; 8];
    getrandom::getrandom(&mut random).map_err(|_| "Cannot create private RA staging")?;
    let alias = format!(
        "u60_ra_{}",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let stage = Path::new(JOURNAL).join(&alias);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&stage)
        .map_err(|e| e.to_string())?;
    let temporary = Path::new("/etc/config").join(format!(".{alias}.new"));
    let result = (|| {
        net::write_private(&stage.join(&alias), &before)?;
        let deltas = stage.join("deltas");
        net::private_dir(&deltas)?;
        let deltas = deltas.to_str().ok_or("Invalid RA delta path")?;
        let base = stage.to_str().ok_or("Invalid RA staging path")?;
        let uci = |args: &[&str]| {
            let mut command = vec!["-c", base, "-t", deltas, "-q"];
            command.extend_from_slice(args);
            Cmd::new("uci", &command).run()
        };
        let original = uci(&["show", &alias])?;
        let mut changed = Vec::new();
        for o in &state.options {
            let name = format!("{alias}.lan.{}", o.key);
            let exists = original.lines().any(|l| l.starts_with(&format!("{name}=")));
            let current = if exists {
                Some(uci(&["get", &name])?)
            } else {
                None
            };
            let owned = if after_reboot {
                current.is_some() && current == o.applied
            } else {
                option_owned(o, &current)
            };
            if current != o.original && owned {
                changed.push(o);
            }
        }
        if changed.is_empty() {
            return Ok(false);
        }
        for o in &changed {
            let name = format!("{alias}.lan.{}", o.key);
            if original.lines().any(|l| l.starts_with(&format!("{name}="))) {
                uci(&["delete", &name])?;
            }
            if let Some(value) = &o.original {
                if o.list {
                    for item in value.split_whitespace() {
                        uci(&["add_list", &format!("{name}={item}")])?;
                    }
                } else {
                    uci(&["set", &format!("{name}={value}")])?;
                }
            }
        }
        uci(&["commit", &alias])?;
        let revised = uci(&["show", &alias])?;
        let unowned = |text: &str| {
            let mut map = crate::ubus::uci_show_map(text);
            for o in &changed {
                map.remove(&format!("{alias}.lan.{}", o.key));
            }
            map
        };
        if unowned(&original) != unowned(&revised) {
            return Err("Unrelated DHCP configuration changed in RA staging".into());
        }
        let after = fs::read(stage.join(&alias)).map_err(|e| e.to_string())?;
        let mut replacement = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        replacement.write_all(&after).map_err(|e| e.to_string())?;
        if unsafe { libc::fchown(replacement.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0 {
            return Err("Cannot preserve DHCP configuration ownership".into());
        }
        replacement
            .set_permissions(fs::Permissions::from_mode(metadata.mode()))
            .map_err(|e| e.to_string())?;
        replacement.sync_all().map_err(|e| e.to_string())?;
        let current = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if current.ino() != metadata.ino()
            || current.dev() != metadata.dev()
            || fs::read(path).map_err(|e| e.to_string())? != before
        {
            return Err("DHCP configuration changed during RA recovery; retry".into());
        }
        fs::rename(&temporary, path).map_err(|e| e.to_string())?;
        fs::File::open("/etc/config")
            .and_then(|dir| dir.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(true)
    })();
    let _ = fs::remove_file(temporary);
    let _ = fs::remove_dir_all(stage);
    result
}

fn maintain_ra() -> Result<(), String> {
    ra::maintain()
}

#[cfg(all(test, target_os = "linux"))]
fn legacy_maintain_ra() -> Result<(), String> {
    let mut state: RaState = serde_json::from_slice(
        &fs::read(Path::new(JOURNAL).join(RA_STATE))
            .map_err(|_| "LAN RA ownership snapshot is missing")?,
    )
    .map_err(|_| "Invalid LAN RA ownership snapshot")?;
    let config = crate::ubus::uci_show_map(&Cmd::new("uci", &["-q", "show", "dhcp.lan"]).run()?);
    let pending = Cmd::new("uci", &["-q", "changes", "dhcp"]).run()?;
    let mut changes = Vec::new();
    for (index, o) in state.options.iter_mut().enumerate() {
        // All applied lists contain exactly one item, so uci_show_map can
        // compare them without flattening any externally changed list.
        if config.get(&format!("dhcp.lan.{}", o.key)) != o.applied.as_ref() {
            let current = read_option(&o.key)?;
            if pending_option(&pending, &o.key) {
                return Err("Pending LAN RA edits detected; relay cleanup preserves them".into());
            }
            if !option_owned(o, &current) {
                o.original = current.clone();
            }
            changes.push((index, current));
        }
    }
    if !changes.is_empty() {
        // Preserve the vendor's new baseline before reasserting the temporary
        // relay overlay. A mobile-data toggle must not disconnect Wi-Fi.
        net::write_private(
            &Path::new(JOURNAL).join(RA_STATE),
            &serde_json::to_vec(&state).unwrap(),
        )?;
        for (index, current) in changes {
            let o = &state.options[index];
            if read_option(&o.key)? != current {
                return Err("LAN RA settings changed again during refresh; retry relay".into());
            }
            write_option(&o.key, o.list, &o.applied)?;
        }
        reload_ra()?;
    }
    Ok(())
}

#[cfg(test)]
fn pending_option(changes: &str, key: &str) -> bool {
    let option = format!("dhcp.lan.{key}");
    changes.lines().any(|line| {
        let name = line
            .split('=')
            .next()
            .unwrap_or("")
            .trim_start_matches(['+', '-']);
        name == option || name == "dhcp.lan" || name == "dhcp"
    })
}

fn option_owned(o: &OptionState, current: &Option<String>) -> bool {
    current == &o.original
        || current == &o.applied
        || (o.key == "ra_lifetime" && current.as_deref() == Some("0"))
        || (o.list
            && (current.is_none()
                || current.as_ref().is_some_and(|c| {
                    [&o.original, &o.applied].into_iter().flatten().any(|v| {
                        v.starts_with(c)
                            && (v.len() == c.len() || v.as_bytes().get(c.len()) == Some(&b' '))
                    })
                })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease() -> Lease {
        parse_lease(
            |k| {
                match k {
                    "RA_ADDRESSES" => "2001:db8:1::2/64,600,1200",
                    "RA_ROUTES" => "::/0,fe80::1,300,512 2001:db8:1::/64,,1200,256",
                    "RA_DNS" => "2001:db8:1::53",
                    "RA_MTU" => "1500",
                    _ => "",
                }
                .into()
            },
            100,
        )
    }

    #[test]
    fn callbacks_validate_addresses_routes_dns_and_lifetimes() {
        let l = lease();
        assert!(l.ready());
        assert_eq!(l.mtu, 1500);
        assert!(l.remaining(399).ready());
        assert!(!l.remaining(400).ready());
        let l = parse_lease(
            |k| {
                match k {
            "ADDRESSES" => "::/64,5,10 ::1/128,5,10 fe80::1/64,5,10 ::ffff:192.0.2.1/128,5,10 2001:db8::2/64,20,10",
            "RA_ROUTES" => "::/0,2001:db8::1,30,5 ::/0,fe80::1,0,5", _=>""
        }.into()
            },
            100,
        );
        assert!(!l.ready());
        assert!(l.addresses.is_empty());
        assert!(l.routers.is_empty());
    }

    #[test]
    fn retained_lan_prefixes_expire_without_restoring_vendor_addresses() {
        let text = |addrs: Value| json!([{"addr_info":addrs}]).to_string();
        let mut known = BTreeMap::new();
        observe_lan(
            &mut known,
            &text(json!([
                {"local":"fe80::1","prefixlen":64},
                {"local":"2001:db8:2::1","prefixlen":64,"valid_life_time":30},
                {"local":"fd12::1","prefixlen":64,"valid_life_time":180}
            ])),
            Some("fd12::/64"),
            100,
        )
        .unwrap();
        assert_eq!(known, BTreeMap::from([("2001:db8:2::/64".into(), 130)]));
        let current = text(json!([
            {"local":"fe80::1","prefixlen":64},
            {"local":"2001:db8:3::1","prefixlen":64,"valid_life_time":u32::MAX}
        ]));
        observe_lan(&mut known, &current, None, 110).unwrap();
        assert_eq!(known.len(), 2);
        assert_eq!(known["2001:db8:2::/64"], 130);
        assert_eq!(known["2001:db8:3::/64"], 110 + LAN_GRACE);
        observe_lan(&mut known, &current, None, 130).unwrap();
        assert!(!known.contains_key("2001:db8:2::/64"));
        let plan = network_plan(
            &lease(),
            "fd12::/64",
            &["2001:db8:3::/64".into()],
            false,
            &[],
        );
        assert!(plan
            .iter()
            .any(|s| s.apply == lan_route("2001:db8:3::/64", "add")));
        assert!(!plan.iter().any(|s| s
            .apply
            .args
            .windows(2)
            .any(|a| a == ["throw", "2001:db8:3::/64"])));
    }

    #[test]
    fn delayed_callbacks_cannot_write_or_remove_the_next_sessions_lease() {
        let old = "a".repeat(32);
        let new = "b".repeat(32);
        assert_ne!(lease_file(&old), lease_file(&new));
        assert!(lease_file("../ipv6-lease").is_none());
        assert!(lease_file(&"g".repeat(32)).is_none());
        assert!(lease_file(&"a".repeat(33)).is_none());
    }

    #[test]
    fn upstream_dns_cannot_loop_back_to_lan_tailnet_or_router_addresses() {
        let mut l = lease();
        l.dns = [
            "2001:db8:1::2",
            "2001:db8:2::53",
            "fd7a:115c:a1e0::53",
            "2001:db8:9::1",
            "fd12:3456:789a::53",
            "2001:db8:1::53",
            "fe80::1",
        ]
        .iter()
        .map(|a| a.parse().unwrap())
        .collect();
        let safe = safe_dns_lease(
            &l,
            &["2001:db8:2::/64".into(), "fd12:3456:789a::/64".into()],
            r#"[{"addr_info":[{"local":"2001:db8:9::1"}]}]"#,
        )
        .unwrap();
        assert_eq!(
            safe.dns,
            [
                "2001:db8:1::53".parse::<Ipv6Addr>().unwrap(),
                "fe80::1".parse().unwrap()
            ]
        );
        assert!(safe_dns_lease(&l, &[], "{}").is_err());
    }

    #[test]
    fn slaac_without_onlink_flag_never_invents_a_connected_route() {
        let mut l = lease();
        assert_eq!(l.onlink.len(), 1);
        assert!(l.remaining(1300).onlink.is_empty());
        l.onlink.clear();
        let plan = network_plan(
            &l,
            "fd12:3456:789a::/64",
            &["fd12:3456:789a::/64".into()],
            false,
            &[],
        );
        assert!(!plan.iter().any(|s| s
            .apply
            .args
            .windows(2)
            .any(|w| w == ["add", "2001:db8:1::/64"])));
    }

    #[test]
    fn ipv6_plans_never_replace_main_defaults_or_enable_kernel_ra() {
        let p = network_plan(
            &lease(),
            "fd12:3456:789a::/64",
            &["fd12:3456:789a::/64".into(), "2001:db8:2::/64".into()],
            false,
            &[],
        );
        for s in &p {
            assert!(!s.apply.args.iter().any(|a| a == "replace" || a == "flush"));
            if s.apply.program == "ip" && s.apply.args.windows(2).any(|w| w == ["route", "add"]) {
                assert!(s.apply.args.windows(2).any(|w| w == ["table", TABLE]));
            }
        }
        assert!(p
            .last()
            .unwrap()
            .apply
            .args
            .ends_with(&["lookup".into(), TABLE.into()]));
        assert!(p.iter().any(|s| s
            .apply
            .args
            .windows(2)
            .any(|w| w == ["src", "2001:db8:1::2"])));
        assert!(setup_plan().iter().any(|s| s
            .apply
            .args
            .iter()
            .any(|a| a.ends_with("accept_ra=0"))));
        assert!(setup_plan().iter().all(|s| !s
            .apply
            .args
            .iter()
            .any(|a| a.ends_with("accept_ra=2"))));
    }

    #[test]
    fn upstream_firewall_allows_scoped_ndp_and_errors_not_management() {
        let p = setup_plan();
        let ra = p
            .iter()
            .find(|s| {
                s.apply
                    .args
                    .windows(2)
                    .any(|w| w == ["--icmpv6-type", "134"])
            })
            .unwrap();
        assert!(ra.apply.args.windows(2).any(|w| w == ["-s", "fe80::/10"]));
        assert!(ra.apply.args.windows(2).any(|w| w == ["--hl-eq", "255"]));
        assert!(!p
            .iter()
            .any(|s| s.apply.args.windows(2).any(|w| w == ["--dport", "9090"])));
    }

    #[test]
    fn nat66_keeps_mihomo_first_and_guards_native_lan_forwarding() {
        for active in [false, true] {
            let p = network_plan(
                &lease(),
                "fd12:3456:789a::/64",
                &["fd12:3456:789a::/64".into()],
                active,
                &[],
            );
            let jumps: Vec<_> = p
                .iter()
                .filter(|s| s.apply.args.windows(2).any(|w| w == ["-I", "PREROUTING"]))
                .collect();
            assert_eq!(jumps.len(), 2);
            assert!(jumps
                .iter()
                .all(|s| s.apply.args[6] == if active { "2" } else { "1" }));
            let snat = p
                .iter()
                .find(|s| s.apply.args.windows(2).any(|w| w == ["-I", "POSTROUTING"]))
                .unwrap();
            assert!(snat.apply.args.windows(2).any(|w| w == ["-o", IFACE]));
            assert!(p.iter().any(|s| s
                .apply
                .args
                .windows(2)
                .any(|w| w == ["--ctstate", "ESTABLISHED,RELATED"])));
            assert!(!p
                .iter()
                .any(|s| s.apply.args.windows(2).any(|w| w == ["throw", "fc00::/7"])));
            assert!(p
                .iter()
                .any(|s| s.apply.args.windows(2).any(|w| w == ["throw", TAILNET])));
        }
    }

    #[test]
    fn upstream_private_dns_is_not_mistaken_for_local_management() {
        let p = network_plan(
            &lease(),
            "fd12:3456:789a::/64",
            &["fd12:3456:789a::/64".into()],
            false,
            &[],
        );
        for chain in ["U60_R6_DNS", "U60_R6_RDNS"] {
            let rules: Vec<_> = p
                .iter()
                .filter(|s| s.apply.args.windows(2).any(|w| w == ["-A", chain]))
                .collect();
            assert!(!rules.iter().any(|s| s
                .apply
                .args
                .windows(2)
                .any(|w| w == ["-d", "fc00::/7"])));
            for local in [TAILNET, "fd12:3456:789a::/64", "fe80::/10"] {
                assert!(rules
                    .iter()
                    .any(|s| s.apply.args.windows(2).any(|w| w == ["-d", local])));
            }
        }
        let mut no_dns = lease();
        no_dns.dns.clear();
        let p = network_plan(
            &no_dns,
            "fd12:3456:789a::/64",
            &["fd12:3456:789a::/64".into()],
            false,
            &[],
        );
        assert!(p
            .iter()
            .any(|s| s.apply.args.windows(2).any(|w| w == ["-t", "filter"])
                && s.apply.args.windows(2).any(|w| w == ["-A", "U60_R6_RDNS"])
                && s.apply.args.ends_with(&["-j".into(), "REJECT".into()])));
        assert!(!p
            .iter()
            .any(|s| s.apply.args.iter().any(|a| a == "fc00::/7")));
    }

    #[test]
    fn ra_uses_single_existing_service_and_restores_only_owned_options() {
        let options = ra_options("fd12:3456:789a::/64", "fe80::1".parse().unwrap());
        assert!(options
            .iter()
            .any(|(k, _, v)| *k == "prefix_filter" && v.as_deref() == Some("fd12:3456:789a::/64")));
        assert!(options
            .iter()
            .any(|(k, _, v)| *k == "dhcpv6" && v.as_deref() == Some("disabled")));
        let o = OptionState {
            key: "dns".into(),
            list: true,
            original: Some("fe80::1 2001:db8::53".into()),
            applied: Some("fe80::1".into()),
        };
        assert!(option_owned(&o, &None));
        assert!(option_owned(&o, &Some("fe80::1".into())));
        assert!(!option_owned(&o, &Some("2001:db8::99".into())));
        assert!(option_owned(&o, &o.original));
    }

    #[test]
    fn pending_ra_edits_are_not_adopted_as_a_committed_vendor_baseline() {
        for changes in [
            "dhcp.lan.ra_mtu='1400'",
            "-dhcp.lan.ra_mtu",
            "+dhcp.lan.dns='fe80::1'",
            "-dhcp.lan",
        ] {
            assert!(pending_option(
                changes,
                if changes.contains("dns") {
                    "dns"
                } else {
                    "ra_mtu"
                }
            ));
        }
        assert!(!pending_option(
            "dhcp.lan.ra_mtu='1400'\ndhcp.lan.label='keep'",
            "dns"
        ));
    }

    #[test]
    fn ipv6_lan_parsing_preserves_existing_prefix_and_requires_linklocal_dns() {
        let s = r#"[{"addr_info":[{"local":"2001:db8:2::1","prefixlen":64},{"local":"fe80::1","prefixlen":64}]}]"#;
        let (p, ll) = lan_state(s).unwrap();
        assert_eq!(p, ["2001:db8:2::/64"]);
        assert_eq!(ll, "fe80::1".parse::<Ipv6Addr>().unwrap());
        assert!(lan_state("[]").is_err());
    }

    #[test]
    fn renewal_only_refreshes_owned_lifetimes_without_restarting_nat_or_ra() {
        let a = lease();
        let mut b = a.clone();
        b.received += 50;
        b.addresses[0].valid += 100;
        b.routers[0].valid += 100;
        assert!(same_path(&a, &b));
        b.routers[0].address = "fe80::2".parse().unwrap();
        assert!(!same_path(&a, &b));
        let route = default_route(&a, "change");
        assert!(route.args.windows(2).any(|w| w == ["table", TABLE]));
        assert!(route.args.windows(2).any(|w| w == ["expires", "300"]));
    }

    #[test]
    fn relay_ra_step_carries_the_current_bounded_mtu() {
        let mut upstream = lease();
        upstream.mtu = 1480;
        let mtu = ra::advertised_mtu(upstream.mtu, 1500).unwrap();
        let step = ra_step("fd12::/64", "fe80::1".parse().unwrap(), mtu);
        assert_eq!(step.apply.args, ["apply", "fd12::/64", "fe80::1", "1480"]);
        assert_eq!(step.undo.args, ["restore"]);
        let mut renewed = upstream.clone();
        renewed.mtu = 1400;
        assert!(!same_path(&upstream, &renewed), "An upstream MTU change must rebuild the RA");
        for bad in ["1279", "1501", "invalid"] {
            assert!(ra_command(&["apply".into(), "fd12::/64".into(), "fe80::1".into(), bad.into()]).is_err());
        }
    }

    #[test]
    fn dad_must_finish_before_default_route_selects_the_source() {
        let address = vec!["2001:db8::2".into()];
        assert!(!addresses_ready(
            r#"[{"addr_info":[{"local":"2001:db8::2","tentative":true}]}]"#,
            &address
        )
        .unwrap());
        assert!(addresses_ready(
            r#"[{"addr_info":[{"local":"2001:db8::2","dadfailed":true}]}]"#,
            &address
        )
        .is_err());
        assert!(addresses_ready(r#"[{"addr_info":[{"local":"2001:db8::2"}]}]"#, &address).unwrap());
        let p = network_plan(
            &lease(),
            "fd12:3456:789a::/64",
            &["fd12:3456:789a::/64".into()],
            false,
            &[],
        );
        let dad = p
            .iter()
            .position(|s| s.apply.program == "@u60-relay-ipv6-dad")
            .unwrap();
        let default = p
            .iter()
            .position(|s| s.apply.args.iter().any(|s| s == "default"))
            .unwrap();
        assert!(dad < default);
    }

    #[test]
    fn lifetime_options_are_not_replayed_by_address_and_route_undo() {
        let p = network_plan(
            &lease(),
            "fd12:3456:789a::/64",
            &["fd12:3456:789a::/64".into()],
            false,
            &[],
        );
        let address = p
            .iter()
            .find(|s| {
                s.apply.program == "ip"
                    && s.apply.args.windows(2).any(|w| w == ["addr", "add"])
                    && s.apply.args.iter().any(|s| s == IFACE)
            })
            .unwrap();
        assert!(!address
            .undo
            .args
            .iter()
            .any(|s| s == "valid_lft" || s == "preferred_lft"));
        let default = p
            .iter()
            .find(|s| s.apply.program == "ip" && s.apply.args.iter().any(|s| s == "default"))
            .unwrap();
        assert!(!default
            .undo
            .args
            .iter()
            .any(|s| s == "expires" || s == "src"));
    }

    #[test]
    fn export_plans_for_isolated_linux_acceptance() {
        let Ok(path) = std::env::var("U60_IPV6_QA_PLAN") else {
            return;
        };
        let l = lease();
        let source = "fd12:3456:789a::/64";
        let network = network_plan(
            &l,
            source,
            &[source.into(), "2001:db8:2::/64".into()],
            false,
            &[],
        );
        let ipv4 = super::super::relay_plan(
            &super::super::Lease {
                ip: "10.0.0.2".parse().unwrap(),
                subnet: "255.255.255.0".parse().unwrap(),
                gateway: "10.0.0.1".parse().unwrap(),
                dns: vec!["10.0.0.53".parse().unwrap()],
            },
            24,
            "192.168.0.1".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
            false,
            &[],
        );
        let mut ula_dns = l.clone();
        ula_dns.dns = vec!["fd99::53".parse().unwrap()];
        let network_ula_dns = network_plan(
            &ula_dns,
            source,
            &[source.into(), "2001:db8:2::/64".into()],
            false,
            &[],
        );
        net::write_private(Path::new(&path),&serde_json::to_vec_pretty(&json!({"setup":setup_plan(),"network":network,"network_ula_dns":network_ula_dns,"ipv4":ipv4,"mihomo":crate::mihomo::proxy_plan(&["192.168.0.1".parse().unwrap(), "2001:db8:2::1".parse().unwrap()])})).unwrap()).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Packet driver; only run in the disposable OpenWrt QA chroot"]
    fn isolated_openwrt_ra_packet_driver() {
        assert_eq!(std::env::var("U60_IPV6_ISOLATED_QA").as_deref(), Ok("1"));
        assert!(Path::new("/u60-ipv6-qa-disposable").exists());
        match std::env::var("U60_IPV6_RA_QA_ACTION").unwrap().as_str() {
            "apply" => ra_command(&[
                "apply".into(),
                "fd12:3456:789a::/64".into(),
                "fe80::1".into(),
                std::env::var("U60_IPV6_RA_QA_MTU").unwrap_or_else(|_| "1480".into()),
            ])
            .unwrap(),
            "maintain" => maintain_ra().unwrap(),
            "release" => ra_restore().unwrap(),
            "previous-boot" => {
                let path = Path::new(JOURNAL).join("ra-runtime.json");
                let mut overlay: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                overlay["boot"] = json!("previous-boot");
                net::write_private(&path, &serde_json::to_vec(&overlay).unwrap()).unwrap();
            }
            _ => panic!("Unknown disposable RA test action"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Mutates UCI; only run in the disposable OpenWrt QA chroot"]
    fn isolated_openwrt_runtime_ra_does_not_restore_old_ipv6() {
        assert_eq!(std::env::var("U60_IPV6_ISOLATED_QA").as_deref(), Ok("1"));
        assert!(Path::new("/u60-ipv6-qa-disposable").exists());
        let baseline = fs::read("/etc/config/dhcp").unwrap();
        fs::write("/tmp/resolv.conf", "").unwrap();
        let dns_step = Step::new(
            Cmd::new("@u60-relay-dns", &["192.0.2.53"]),
            Cmd::new("@u60-relay-dns", &[]),
        );
        let mut dns = Transaction::new(Path::new(JOURNAL).join("dns-qa.json"));
        dns.apply(dns_step).unwrap();
        assert!(fs::read_to_string("/tmp/resolv.conf")
            .unwrap()
            .contains("nameserver 192.0.2.53"));
        fs::write(
            "/tmp/resolv.conf",
            "# new vendor DNS\nnameserver 2001:db8:9::54\n",
        )
        .unwrap();
        super::super::dns::reconcile(&["192.0.2.53".parse().unwrap()]).unwrap();
        Transaction::recover(&Path::new(JOURNAL).join("dns-qa.json")).unwrap();
        assert_eq!(
            fs::read_to_string("/tmp/resolv.conf").unwrap(),
            "# new vendor DNS\nnameserver 2001:db8:9::54\n"
        );
        ra_command(&[
            "apply".into(),
            "fd12:3456:789a::/64".into(),
            "fe80::1".into(),
            "1480".into(),
        ])
        .unwrap();
        assert_eq!(fs::read("/etc/config/dhcp").unwrap(), baseline);
        assert!(
            Cmd::new("uci", &["-q", "changes", "dhcp"])
                .run()
                .unwrap()
                .is_empty(),
            "Normal relay must not create UCI deltas that vendor commits can persist"
        );
        Cmd::new("uci", &["set", "dhcp.lan.ra_mtu=1450"])
            .run()
            .unwrap();
        let _ = Cmd::new("uci", &["delete", "dhcp.lan.dns"]).run();
        Cmd::new("uci", &["commit", "dhcp"]).run().unwrap();
        let current = fs::read("/etc/config/dhcp").unwrap();
        maintain_ra().unwrap();
        ra_command(&["restore".into()]).unwrap();
        assert_eq!(
            fs::read("/etc/config/dhcp").unwrap(),
            current,
            "Use current vendor IPv6 configuration, never restore an old baseline"
        );
        assert_eq!(read_option("ra_mtu").unwrap().as_deref(), Some("1450"));
        assert!(read_option("dns").unwrap().is_none());
        ra_command(&["restore".into()]).unwrap();

        let runtime = |value: Value| {
            Cmd::new(
                "ubus",
                &[
                    "call",
                    "network.interface.lan",
                    "set_data",
                    &value.to_string(),
                ],
            )
            .run()
            .unwrap();
        };
        runtime(json!({"qa_preserve": {"nested": "vendor"}}));
        ra_command(&[
            "apply".into(),
            "fd12:3456:789a::/64".into(),
            "fe80::1".into(),
            "1480".into(),
        ])
        .unwrap();
        // A same-boot process crash recovers from the journal, not in-memory state.
        ra_restore().unwrap();
        assert_eq!(
            ra::data().unwrap()["qa_preserve"],
            json!({"nested": "vendor"})
        );
        assert!(ra::data().unwrap()["prefix_filter"].is_null());

        runtime(json!({"ra_mtu": 1420}));
        assert!(
            ra_command(&[
                "apply".into(),
                "fd12:3456:789a::/64".into(),
                "fe80::1".into(),
                "1480".into(),
            ])
            .is_err(),
            "Do not take over another runtime writer"
        );
        runtime(json!({"ra_mtu": null}));
        ra_command(&[
            "apply".into(),
            "fd12:3456:789a::/64".into(),
            "fe80::1".into(),
            "1480".into(),
        ])
        .unwrap();
        runtime(json!({"ra_mtu": 1420}));
        assert!(maintain_ra().is_err());
        ra_restore().unwrap();
        assert_eq!(
            ra::data().unwrap()["ra_mtu"],
            1420,
            "Preserve a later external runtime edit"
        );
        runtime(json!({"ra_mtu": null}));

        ra_command(&[
            "apply".into(),
            "fd12:3456:789a::/64".into(),
            "fe80::1".into(),
            "1480".into(),
        ])
        .unwrap();
        runtime(json!({"ra_lifetime": 0}));
        assert!(maintain_ra().is_err());
        ra_restore().unwrap();
        assert_eq!(
            ra::data().unwrap()["ra_lifetime"],
            0,
            "Never release an external router withdrawal"
        );
        runtime(json!({"ra_lifetime": null}));

        ra_command(&[
            "apply".into(),
            "fd12:3456:789a::/64".into(),
            "fe80::1".into(),
            "1480".into(),
        ])
        .unwrap();
        let state_path = Path::new(JOURNAL).join("ra-runtime.json");
        let mut overlay: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        let clear: serde_json::Map<_, _> = overlay["values"]
            .as_object()
            .unwrap()
            .keys()
            .map(|key| (key.clone(), Value::Null))
            .collect();
        runtime(Value::Object(clear));
        overlay["boot"] = json!("previous-boot");
        net::write_private(&state_path, &serde_json::to_vec(&overlay).unwrap()).unwrap();
        runtime(json!({"ra_mtu": 1440}));
        ra_restore().unwrap();
        assert_eq!(
            ra::data().unwrap()["ra_mtu"],
            1440,
            "Postboot cleanup must not touch fresh runtime state"
        );
        runtime(json!({"ra_mtu": null, "qa_preserve": null}));
        fs::write("/etc/config/dhcp", baseline).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Mutates UCI; only run in the disposable OpenWrt QA chroot"]
    fn isolated_openwrt_previous_boot_ra_recovery() {
        assert_eq!(std::env::var("U60_IPV6_ISOLATED_QA").as_deref(), Ok("1"));
        assert!(Path::new("/u60-ipv6-qa-disposable").exists());
        assert!(!Path::new(JOURNAL).join(RA_STATE).exists());
        let baseline = fs::read("/etc/config/dhcp").unwrap();
        assert!(Cmd::new("uci", &["-q", "changes", "dhcp"])
            .run()
            .unwrap()
            .is_empty());
        let dns = Some("fe80::1 2001:db8::53 2001:db8::54".into());
        write_option("dns", true, &dns).unwrap();
        Cmd::new("uci", &["commit", "dhcp"]).run().unwrap();
        legacy_ra_command(&[
            "apply".into(),
            "fd12:3456:789a::/64".into(),
            "fe80::1".into(),
        ])
        .unwrap();
        let path = Path::new(JOURNAL).join(RA_STATE);
        let mut state: RaState = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        state.boot = "previous-boot".into();
        net::write_private(&path, &serde_json::to_vec(&state).unwrap()).unwrap();
        // Reboot drops temporary UCI edits; B31 also clears old cellular DNS.
        Cmd::new("uci", &["revert", "dhcp"]).run().unwrap();
        Cmd::new("uci", &["delete", "dhcp.lan.dns"]).run().unwrap();
        Cmd::new("uci", &["set", "dhcp.lan.ra_mtu=1450"])
            .run()
            .unwrap();
        Cmd::new("uci", &["commit", "dhcp"]).run().unwrap();
        Cmd::new("uci", &["set", "dhcp.lan.qa_pending=preserve"])
            .run()
            .unwrap();
        let committed = fs::read("/etc/config/dhcp").unwrap();
        let pending = Cmd::new("uci", &["-q", "changes", "dhcp"]).run().unwrap();
        legacy_ra_command(&["restore".into()])
            .expect("Postboot vendor DNS/MTU changes must not block relay cleanup");
        assert!(!path.exists());
        assert_eq!(fs::read("/etc/config/dhcp").unwrap(), committed);
        assert_eq!(
            Cmd::new("uci", &["-q", "changes", "dhcp"]).run().unwrap(),
            pending
        );
        assert!(
            read_option("dns").unwrap().is_none(),
            "Never revive stale cellular DNS after reboot"
        );
        assert_eq!(read_option("ra_mtu").unwrap().as_deref(), Some("1450"));
        legacy_ra_command(&["restore".into()]).unwrap();
        Cmd::new("uci", &["revert", "dhcp"]).run().unwrap();
        fs::write("/etc/config/dhcp", baseline).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Mutates network/UCI; only run in the disposable OpenWrt QA chroot"]
    fn isolated_openwrt_start_refresh_stop() {
        assert_eq!(std::env::var("U60_IPV6_ISOLATED_QA").as_deref(), Ok("1"));
        assert!(Path::new("/u60-ipv6-qa-disposable").exists());
        assert!(std::env::var_os("U60_IPV6_QA_CALLBACK").is_some());
        assert!(!Path::new(JOURNAL).join(RA_STATE).exists());
        let original = Cmd::new("uci", &["-q", "show", "dhcp.lan"]).run().unwrap();
        let committed = fs::read("/etc/config/dhcp").unwrap();
        let main = Cmd::new("ip", &["-6", "route", "show", "table", "main"])
            .run()
            .unwrap();

        let mut upstream = Upstream::new();
        upstream.start(false).unwrap();
        assert_eq!(upstream.status()["state"], "off");
        upstream.start(true).unwrap();
        assert_eq!(upstream.status()["state"], "detecting");
        assert!(upstream.client.is_some());
        upstream.tick().unwrap();
        assert_eq!(upstream.status()["state"], "no_upstream");
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(150));
            upstream.tick().unwrap();
            if upstream.status()["state"] == "configured" {
                break;
            }
        }
        assert_eq!(
            upstream.status()["state"],
            "configured",
            "{}",
            upstream.status()
        );
        assert_eq!(upstream.status()["nat66"], true);
        assert_eq!(upstream.status()["internet"], "not_verified");
        assert!(
            Cmd::new("ip", &["-6", "route", "get", "2606:4700:4700::1111"])
                .run()
                .unwrap()
                .contains("dev u60sta0")
        );
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(200));
            upstream.tick().unwrap();
            assert_eq!(upstream.status()["state"], "configured");
        }
        assert_eq!(upstream.status()["upstream_mtu"], 1500);
        assert_eq!(upstream.status()["lan_mtu"], 1500);
        assert_eq!(ra::data().unwrap()["ra_mtu"], 1500);
        Cmd::new("ip", &["link", "set", "br-lan", "mtu", "1400"])
            .run()
            .unwrap();
        upstream.tick().unwrap();
        assert_eq!(upstream.status()["state"], "configured");
        assert_eq!(upstream.status()["lan_mtu"], 1400);
        assert_eq!(ra::data().unwrap()["ra_mtu"], 1400);
        Cmd::new("ip", &["link", "set", "br-lan", "mtu", "1500"])
            .run()
            .unwrap();
        upstream.tick().unwrap();
        assert_eq!(upstream.status()["lan_mtu"], 1500);
        assert_eq!(ra::data().unwrap()["ra_mtu"], 1500);
        Cmd::new(
            "ip",
            &["-6", "addr", "add", "2001:db8:3::1/64", "dev", "br-lan"],
        )
        .run()
        .unwrap();
        upstream.tick().unwrap();
        assert_eq!(upstream.status()["state"], "configured");
        for destination in ["2001:db8:2::123", "2001:db8:3::123"] {
            assert!(Cmd::new("ip", &["-6", "route", "get", destination])
                .run()
                .unwrap()
                .contains("dev br-lan"));
        }
        assert!(Cmd::new(
            "ip6tables",
            &[
                "-C",
                "U60_R6_FWD",
                "-i",
                "br-lan",
                "-o",
                IFACE,
                "-s",
                "2001:db8:3::/64",
                "-j",
                "ACCEPT"
            ]
        )
        .run()
        .is_ok());
        Cmd::new(
            "ip",
            &["-6", "addr", "del", "2001:db8:2::1/64", "dev", "br-lan"],
        )
        .run()
        .unwrap();
        upstream.tick().unwrap();
        assert!(Cmd::new("ip", &["-6", "route", "get", "2001:db8:2::123"])
            .run()
            .unwrap()
            .contains("dev br-lan"));
        Cmd::new(
            "ip",
            &["-6", "addr", "add", "2001:db8:2::1/64", "dev", "br-lan"],
        )
        .run()
        .unwrap();
        Cmd::new(
            "ip",
            &["-6", "addr", "del", "2001:db8:3::1/64", "dev", "br-lan"],
        )
        .run()
        .unwrap();
        upstream.tick().unwrap();
        // Simulate expiry while the shared network lock delayed supervision,
        // followed by renewal of exactly the same address/router.
        default_route(upstream.path.as_ref().unwrap(), "del")
            .run()
            .unwrap();
        upstream.tick().unwrap();
        assert_eq!(upstream.status()["state"], "configured");
        assert!(
            Cmd::new("ip", &["-6", "route", "get", "2606:4700:4700::1111"])
                .run()
                .unwrap()
                .contains("dev u60sta0")
        );
        let ula = upstream.lan_prefix.as_ref().unwrap().clone();
        assert_eq!(ra::data().unwrap()["prefix_filter"], ula);
        // DNS cleanup also runs before startup recovery. It must not commit
        // the temporary RA delta to the persistent DHCP configuration.
        crate::server::dnsmasq_restore_defaults();
        assert_eq!(fs::read("/etc/config/dhcp").unwrap(), committed);
        let old_session = upstream.session.as_ref().unwrap().clone();
        upstream.stop().unwrap();
        assert_eq!(upstream.status()["state"], "off");
        assert_eq!(
            Cmd::new("uci", &["-q", "show", "dhcp.lan"]).run().unwrap(),
            original
        );
        assert!(Cmd::new("uci", &["-q", "changes", "dhcp"])
            .run()
            .unwrap()
            .is_empty());
        assert_eq!(
            Cmd::new("ip", &["-6", "route", "show", "table", "main"])
                .run()
                .unwrap(),
            main
        );
        assert!(!Cmd::new("ip6tables", &["-S"])
            .run()
            .unwrap()
            .contains("U60_R6"));
        assert!(!Cmd::new("ip6tables", &["-t", "nat", "-S"])
            .run()
            .unwrap()
            .contains("U60_R6"));
        assert!(!Cmd::new("ip", &["-6", "rule", "show"])
            .run()
            .unwrap()
            .contains(PREF));
        assert!(!Path::new(JOURNAL).join(RA_STATE).exists());
        upstream.stop().unwrap();

        upstream.start(true).unwrap();
        assert_ne!(upstream.session.as_ref().unwrap(), &old_session);
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(150));
            upstream.tick().unwrap();
            if upstream.status()["state"] == "configured" {
                break;
            }
        }
        assert_eq!(upstream.status()["state"], "configured");
        for event in ["ra-updated", "stopped", "started"] {
            let mut callback = Command::new(std::env::var_os("U60_IPV6_QA_CALLBACK").unwrap());
            callback
                .args([IFACE, event])
                .env("U60_RELAY_DHCP6", "1")
                .env("U60_RELAY_DHCP6_SESSION", &old_session)
                .env("RA_ADDRESSES", "2001:db8:dead::2/64,600,1200")
                .env("RA_ROUTES", "::/0,fe80::dead,600,512");
            net::run(callback, Duration::from_secs(5)).unwrap();
            upstream.tick().unwrap();
            assert_eq!(upstream.status()["state"], "configured");
            assert_ne!(upstream.status()["gateway"], "fe80::dead");
        }
        let mut expired = upstream.installed.as_ref().unwrap().clone();
        expired.routers.clear();
        net::write_private(
            &lease_file(upstream.session.as_ref().unwrap()).unwrap(),
            &serde_json::to_vec(&expired).unwrap(),
        )
        .unwrap();
        upstream.tick().unwrap();
        assert_eq!(upstream.status()["state"], "no_upstream");
        assert_eq!(upstream.status()["nat66"], false);
        assert!(upstream.client.is_some());
        assert_eq!(
            Cmd::new("ip", &["-6", "route", "show", "table", "main"])
                .run()
                .unwrap(),
            main
        );
        upstream.stop().unwrap();
        assert_eq!(fs::read("/etc/config/dhcp").unwrap(), committed);
        assert!(Cmd::new("uci", &["-q", "changes", "dhcp"])
            .run()
            .unwrap()
            .is_empty());

        upstream.start(true).unwrap();
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(150));
            upstream.tick().unwrap();
            if upstream.status()["state"] == "configured" {
                break;
            }
        }
        assert_eq!(upstream.status()["state"], "configured");
        let revision = upstream.revision();
        let child = upstream.client.as_mut().unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
        upstream.tick().unwrap();
        assert_eq!(upstream.status()["state"], "error");
        assert!(!upstream.status()["nat66"].as_bool().unwrap());
        assert_ne!(
            upstream.revision(),
            revision,
            "client death must redial persistent core transports"
        );
        upstream.stop().unwrap();
        assert_eq!(fs::read("/etc/config/dhcp").unwrap(), committed);

        // An ordinary runtime conflict withdraws only IPv6, not the IPv4
        // relay supervised by the caller. Retry from fresh observations.
        upstream.start(true).unwrap();
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(150));
            upstream.tick().unwrap();
            if upstream.status()["state"] == "configured" {
                break;
            }
        }
        assert_eq!(upstream.status()["state"], "configured");
        Cmd::new(
            "ubus",
            &[
                "call",
                "network.interface.lan",
                "set_data",
                r#"{"ra_mtu":1400}"#,
            ],
        )
        .run()
        .unwrap();
        upstream
            .tick()
            .expect("Safe IPv6 withdrawal must not tear down IPv4 relay");
        assert_eq!(upstream.status()["state"], "error");
        assert_eq!(upstream.status()["nat66"], false);
        assert!(upstream.client.is_some());
        Cmd::new(
            "ubus",
            &[
                "call",
                "network.interface.lan",
                "set_data",
                r#"{"ra_mtu":null}"#,
            ],
        )
        .run()
        .unwrap();
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(150));
            upstream.tick().unwrap();
            if upstream.status()["state"] == "configured" {
                break;
            }
        }
        assert_eq!(upstream.status()["state"], "configured");
        upstream.stop().unwrap();

        // B31's cellular switch commits the full DHCP package. Runtime RA
        // never enters that package, including unrelated pending edits.
        upstream.start(true).unwrap();
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(150));
            upstream.tick().unwrap();
            if upstream.status()["state"] == "configured" {
                break;
            }
        }
        assert_eq!(upstream.status()["state"], "configured");
        Cmd::new("uci", &["set", "dhcp.lan.qa_external=preserve"])
            .run()
            .unwrap();
        // B31's mobile-data off/on also rewrites individual RA options, not
        // merely commits our temporary values. Preserve its new baseline.
        Cmd::new("uci", &["set", "dhcp.lan.ra_useleasetime=1"])
            .run()
            .unwrap();
        Cmd::new("uci", &["commit", "dhcp"]).run().unwrap();
        Cmd::new("uci", &["set", "dhcp.lan.qa_pending=uncommitted"])
            .run()
            .unwrap();
        upstream.stop().unwrap();
        assert_eq!(
            Cmd::new("uci", &["get", "dhcp.lan.qa_external"])
                .run()
                .unwrap(),
            "preserve"
        );
        assert_eq!(
            Cmd::new("uci", &["get", "dhcp.lan.qa_pending"])
                .run()
                .unwrap(),
            "uncommitted"
        );
        let persistent = fs::read_to_string("/etc/config/dhcp").unwrap();
        assert!(persistent.contains("qa_external"));
        assert!(!persistent.contains("qa_pending"));
        assert!(!persistent.contains("prefix_filter"));
        assert_eq!(
            read_option("ra_useleasetime").unwrap().as_deref(),
            Some("1")
        );
        assert!(!Path::new(JOURNAL).join(RA_STATE).exists());
        let deltas = Cmd::new("uci", &["-q", "changes", "dhcp"]).run().unwrap();
        assert_eq!(deltas, "dhcp.lan.qa_pending='uncommitted'");
        Cmd::new("uci", &["revert", "dhcp.lan.qa_pending"])
            .run()
            .unwrap();
        Cmd::new("uci", &["delete", "dhcp.lan.qa_external"])
            .run()
            .unwrap();
        Cmd::new("uci", &["delete", "dhcp.lan.ra_useleasetime"])
            .run()
            .unwrap();
        Cmd::new("uci", &["commit", "dhcp"]).run().unwrap();
        assert_eq!(
            Cmd::new("uci", &["-q", "show", "dhcp.lan"]).run().unwrap(),
            original
        );

        // While still relaying, a vendor reload must refresh only the RA
        // overlay and retain its new baseline, not disconnect the station.
        legacy_ra_command(&[
            "apply".into(),
            "fd12:3456:789a::/64".into(),
            "fe80::1".into(),
        ])
        .unwrap();
        for (key, value) in [
            ("ra_useleasetime", "1"),
            ("dhcpv6", "server"),
            ("ra_flags", "other-config"),
        ] {
            Cmd::new("uci", &["set", &format!("dhcp.lan.{key}={value}")])
                .run()
                .unwrap();
        }
        Cmd::new("uci", &["commit", "dhcp"]).run().unwrap();
        legacy_maintain_ra().unwrap();
        assert_eq!(
            read_option("ra_useleasetime").unwrap().as_deref(),
            Some("0")
        );
        assert_eq!(read_option("dhcpv6").unwrap().as_deref(), Some("disabled"));
        ra_restore().unwrap();
        assert_eq!(
            read_option("ra_useleasetime").unwrap().as_deref(),
            Some("1")
        );
        assert_eq!(
            read_option("ra_flags").unwrap().as_deref(),
            Some("other-config")
        );
        assert!(read_option("prefix_filter").unwrap().is_none());
        assert!(Cmd::new("uci", &["-q", "changes", "dhcp"])
            .run()
            .unwrap()
            .is_empty());

        legacy_ra_command(&[
            "apply".into(),
            "fd12:3456:789a::/64".into(),
            "fe80::1".into(),
        ])
        .unwrap();
        Cmd::new("uci", &["set", "dhcp.lan.ra_mtu=1400"])
            .run()
            .unwrap();
        let committed = fs::read("/etc/config/dhcp").unwrap();
        let edited_delta = Cmd::new("uci", &["-q", "changes", "dhcp"])
            .run()
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("dhcp.lan.ra_mtu="))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            legacy_maintain_ra().is_err(),
            "An uncommitted edit must not become a persisted baseline"
        );
        ra_restore().unwrap();
        assert_eq!(read_option("ra_mtu").unwrap().as_deref(), Some("1400"));
        assert_eq!(fs::read("/etc/config/dhcp").unwrap(), committed);
        assert_eq!(
            Cmd::new("uci", &["-q", "changes", "dhcp"]).run().unwrap(),
            edited_delta,
            "Preserve the external edit's same-key delta history instead of normalizing it"
        );
    }
}
