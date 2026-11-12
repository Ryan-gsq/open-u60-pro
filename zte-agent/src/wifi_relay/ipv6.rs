//! odhcp6c only discovers upstream state. Rust owns its effects and NAT66;
//! the existing odhcpd remains the sole LAN router-advertisement service.

use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{offload, stop_helper, Helper, IFACE, JOURNAL, PREF, ROOT, TABLE};
use crate::boottime::{BootClock, Clock};
use crate::net_tools::{self as net, Cmd, Step};
use super::{EffectSet, Resource, Family, Route, RouteType, Rule, Addr, Internal, LegacyChain, LegacyHook, LegacyTool, Position, words};

pub(super) const TAILNET: &str = crate::netfx::ids::TAILNET_V6;
// A client may keep a previously advertised address after the vendor removes
// it from br-lan. Keep only a bounded, session-owned return route, not the old
// vendor address/configuration. Never carry this observation across reboot.
const LAN_GRACE: u64 = 7200;
/// Lifetimes count down in the kernel, so an unchanged lease only needs its
/// address/route lifetimes and the RA overlay re-asserted now and then. The
/// LAN ULA address (valid 180 s, preferred 90 s) and RA router lifetime
/// (90 s) bound the interval; a short upstream lifetime refreshes every tick.
const MAINTAIN_EVERY: Duration = Duration::from_secs(15);
/// Without a settled `net_guard` trigger, the owned addresses, routes, policy
/// rule and RA overlay of an unchanged path are checked this often: an object
/// removed by something that fires no vendor trigger is noticed within it.
/// Each check spawns four read-only tools (`ubus`, the address, route and
/// rule listings) under the session lock; the owner traded promptness for
/// fewer of them (2026-11-12).
const CHECK_EVERY: Duration = Duration::from_secs(15);
/// Consecutive ticks whose inspection reads fail before the path is withdrawn.
/// A failed check is retried on the next tick, not `CHECK_EVERY` later.
const UNREADABLE_TICKS: u8 = 3;
mod ra;

/// Why checking an unchanged path failed.
#[derive(Debug)]
enum Fault {
    /// A device read failed. Nothing shows that the owned path changed, so it
    /// is kept and the check retried (`UNREADABLE_TICKS`).
    Unreadable(String),
    /// An owned object conflicts with another writer or cannot be restored.
    Conflict(String),
}

impl Fault {
    fn message(self) -> String {
        match self {
            Self::Unreadable(e) | Self::Conflict(e) => e,
        }
    }
}

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

/// Whether an unchanged lease is due for its periodic lifetime/RA refresh.
/// `shortest` is the first finite upstream lifetime in seconds.
fn maintenance_due(last: Option<Instant>, now: Instant, shortest: u32) -> bool {
    last.is_none_or(|at| now.saturating_duration_since(at) >= MAINTAIN_EVERY)
        || u64::from(shortest) <= 3 * MAINTAIN_EVERY.as_secs()
}

// A renewal must reach the kernel even when its new lifetime is long: the
// previously installed short lifetime may expire before the next periodic tick.
fn lease_maintenance_due(
    last: Option<Instant>,
    now: Instant,
    installed: Option<&Lease>,
    received: Option<&Lease>,
    live: &Lease,
) -> bool {
    installed != received || maintenance_due(last, now, live.shortest_lifetime())
}

/// Whether this tick checks the owned objects of an unchanged path: after a
/// settled `net_guard` trigger (`guard`), while a failed read is retried,
/// before a lifetime refresh (its `change` commands need the objects
/// present), or `CHECK_EVERY` after the last check.
fn check_due(
    guard: bool,
    unreadable: u8,
    refresh: bool,
    last: Option<Instant>,
    now: Instant,
) -> bool {
    guard
        || unreadable > 0
        || refresh
        || last.is_none_or(|at| now.saturating_duration_since(at) >= CHECK_EVERY)
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
    /// Seconds until the first finite lifetime of this (already remaining) lease ends.
    fn shortest_lifetime(&self) -> u32 {
        self.addresses
            .iter()
            .flat_map(|a| [a.valid, a.preferred])
            .chain(self.routers.iter().map(|r| r.valid))
            .chain(self.onlink.iter().map(|r| r.valid))
            .filter(|&n| n != u32::MAX)
            .min()
            .unwrap_or(u32::MAX)
    }

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
    client: Option<Helper>,
    session: Option<String>,
    setup: EffectSet,
    network: EffectSet,
    /// The relay's tables: discovery opens the upstream, a lease adds NAT66.
    uplink: super::uplink::Shared,
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
    maintained: Option<Instant>,
    /// The last `check_owned` of the current path (`CHECK_EVERY`).
    checked: Option<Instant>,
    /// Consecutive ticks whose inspection reads failed (`Fault::Unreadable`).
    unreadable: u8,
}

pub fn off_status() -> Value {
    json!({"requested":false,"state":"off","upstream":false,"nat66":false,"internet":"not_verified"})
}

impl Upstream {
    pub fn new(uplink: super::uplink::Shared) -> Self {
        Self {
            client: None,
            session: None,
            setup: EffectSet::new("relay", Path::new(JOURNAL).join("ipv6-setup.json")),
            network: EffectSet::new("relay", Path::new(JOURNAL).join("ipv6-network.json")),
            uplink,
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
            maintained: None,
            checked: None,
            unreadable: 0,
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

    /// Configured on a usable lease with its client running: kept across a
    /// reassociation to the same access point (`super::handover`).
    pub fn configured(&mut self) -> bool {
        self.phase == "configured" && self.installed.is_some() && self.client.as_mut().is_some_and(Helper::alive)
    }

    pub fn start(&mut self, requested: bool) -> Result<(), String> {
        self.requested = requested;
        if !requested {
            return Ok(());
        }
        let attempt = (|| {
            capabilities()?;
            for step in setup_settings() { self.setup.step(step)?; }
            self.setup.declare(setup_plan())?;
            // Open the upstream for discovery before the client asks.
            self.uplink.update(|l| l.discovery = true)?;
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
            self.client = Some(Helper::Owned(net::owned_child(cmd)?));
            self.phase = "detecting";
            Ok(())
        })();
        if let Err(e) = attempt {
            stop_helper(&mut self.client);
            self.setup.release()?;
            self.close();
            self.phase = "unsupported";
            self.error = Some(e);
        }
        Ok(())
    }

    /// Takes NAT66 out of the relay's tables after its routes and RA went.
    /// A failed load stays the target (`net_guard` retries) and does not stop
    /// the withdrawal: without the routes nothing uses it.
    fn withdraw(&mut self) -> Result<(), String> {
        self.network.release()?;
        if let Err(e) = self.uplink.update(|l| l.nat66 = None) {
            crate::netlog!("[relay] IPv6 NAT not yet removed from the relay tables: {e}");
        }
        Ok(())
    }

    /// Closes the upstream to IPv6 again.
    fn close(&mut self) {
        if let Err(e) = self.uplink.update(|l| { l.nat66 = None; l.discovery = false; }) {
            crate::netlog!("[relay] upstream IPv6 not yet closed in the relay tables: {e}");
        }
    }

    /// `net_guard`: re-applies the firewall and nft rules another writer
    /// removed from both IPv6 plans (the legacy accepts; the relay checks
    /// its tables). Addresses, routes and the policy rule stay with
    /// `check_owned`, which also checks for conflicts, waits for DAD and uses
    /// the current lease lifetimes.
    pub fn reconcile(&mut self) -> net::Reconciled {
        let firewall = |resource: &Resource| !matches!(resource, Resource::Route(_) | Resource::Rule(_) | Resource::Addr(_));
        let mut result = self.setup.reconcile_only(firewall);
        result.extend(self.network.reconcile_only(firewall));
        result
    }

    /// `guard`: the relay's `net_guard` cursor was due on this tick.
    pub fn tick(&mut self, guard: bool) -> Result<(), String> {
        // Only effective upstream identity/availability belongs to the core.
        // Repairs and LAN exemptions must not redial all proxy transports.
        let before = self.path.as_ref().map(upstream_identity);
        let revision = self.revision;
        if let Err(error) = self.tick_inner(guard) {
            // Only an unsafe, failed undo may propagate to the relay owner.
            // Ordinary RA/lease errors withdraw IPv6, not working IPv4.
            self.withdraw()?;
            self.installed = None;
            self.path = None;
            self.lan_prefix = None;
            self.ra_mtu = None;
            self.phase = "error";
            self.unreadable = 0;
            self.error = Some(format!("{error}; IPv4 relay remains active"));
        }
        self.revision = revision.wrapping_add(u64::from(
            before != self.path.as_ref().map(upstream_identity),
        ));
        Ok(())
    }

    fn tick_inner(&mut self, guard: bool) -> Result<(), String> {
        if self.client.is_none() {
            return Ok(());
        }
        if !self.client.as_mut().unwrap().alive() {
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
                self.withdraw()?;
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
        let sources: Vec<_> = self.lan_observed.keys().cloned().collect();
        if self.path.as_ref().is_some_and(|p| same_path(p, &live))
            && sources == self.lan_sources
            && self.ra_mtu == Some(ra_mtu)
        {
            let refresh = lease_maintenance_due(
                self.maintained,
                Instant::now(),
                self.installed.as_ref(),
                lease.as_ref(),
                &live,
            );
            if check_due(guard, self.unreadable, refresh, self.checked, Instant::now()) {
                let checked = self.check_owned(&live, &sources);
                self.checked = Some(Instant::now());
                self.tolerate(checked)?;
            }
            if !refresh {
                self.installed = lease;
                self.path = Some(live);
                return Ok(());
            }
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
                self.maintained = Some(Instant::now());
                return Ok(());
            }
            // A delayed watchdog may find the old finite address/route already
            // expired. Rebuild only IPv6; this is not an IPv4 relay failure.
        }
        self.withdraw()?;
        self.installed = None;
        self.path = None;
        self.lan_prefix = None;
        self.ra_mtu = None;
        match self.configure(&live, ra_mtu) {
            Ok(lan_prefix) => {
                self.installed = lease;
                self.path = Some(live);
                self.lan_prefix = Some(lan_prefix);
                self.ra_mtu = Some(ra_mtu);
                self.phase = "configured";
                self.error = None;
                self.maintained = Some(Instant::now());
                self.checked = Some(Instant::now());
                self.unreadable = 0;
            }
            Err(e) => {
                self.withdraw()?;
                self.path = None;
                self.phase = "error";
                self.error = Some(e);
            }
        }
        Ok(())
    }

    /// An unchanged path when `check_due`: RA ownership, owned addresses,
    /// routes and policy rule, with conflict checks, DAD and current lease
    /// lifetimes (`net_guard` covers the firewall and nft rules). Missing
    /// objects are re-added with their existing undo records; none of this
    /// changes the upstream identity.
    fn check_owned(&mut self, live: &Lease, sources: &[String]) -> Result<(), Fault> {
        maintain_ra()?;
        self.repair_addresses(live)?;
        self.repair_routes(live, sources)
    }

    /// A failed read is not evidence that the owned path changed: keep it for
    /// a few ticks (lifetime maintenance continues) instead of withdrawing
    /// IPv6 and restarting the core twice. A conflict, or reads that keep
    /// failing, withdraw it.
    fn tolerate(&mut self, checked: Result<(), Fault>) -> Result<(), String> {
        match checked {
            Ok(()) => {
                if self.unreadable > 0 {
                    self.unreadable = 0;
                    self.error = None;
                }
                Ok(())
            }
            Err(Fault::Unreadable(e)) if self.unreadable + 1 < UNREADABLE_TICKS => {
                self.unreadable += 1;
                crate::netlog!(
                    "[relay-ipv6] owned path check unavailable ({}/{UNREADABLE_TICKS}); path kept",
                    self.unreadable
                );
                self.error = Some(format!("{e}; IPv6 relay path kept, retrying"));
                Ok(())
            }
            Err(fault) => Err(fault.message()),
        }
    }

    fn repair_addresses(&mut self, lease: &Lease) -> Result<(), Fault> {
        let text = Cmd::new("ip", &["-j", "-6", "addr", "show"])
            .run()
            .map_err(Fault::Unreadable)?;
        let interfaces: Vec<Value> = serde_json::from_str(&text)
            .map_err(|_| Fault::Unreadable("Cannot inspect owned IPv6 addresses".into()))?;
        let ula = self.lan_prefix.as_ref().unwrap();
        let lan = Ipv6Addr::from(u128::from(cidr(ula).unwrap().0) + 1);
        let expected = lease
            .addresses
            .iter()
            .map(|a| (a.address, 128, IFACE, a.valid, a.preferred))
            .chain(std::iter::once((lan, 64, "br-lan", 180, 90)));
        let mut dad = Vec::new();
        for (ip, prefix, iface, valid, preferred) in expected {
            let text = ip.to_string();
            let present = interfaces
                .iter()
                .filter(|i| i["ifname"] == iface)
                .filter_map(|i| i["addr_info"].as_array())
                .flatten()
                .find(|a| a["local"].as_str().and_then(|s| s.parse::<Ipv6Addr>().ok()) == Some(ip));
            if present.is_some_and(|a| {
                a["prefixlen"].as_u64() != Some(u64::from(prefix)) || a["dadfailed"] == true
            }) {
                return Err(Fault::Conflict(
                    "An owned IPv6 address changed externally".into(),
                ));
            }
            if present.is_none() {
                self.network
                    .declare(vec![address_step(ip, prefix, iface, valid, preferred)])
                    .map_err(Fault::Conflict)?;
                if iface == IFACE {
                    dad.push(text);
                }
            }
        }
        if !dad.is_empty() {
            wait_addresses(&dad).map_err(Fault::Conflict)?;
        }
        Ok(())
    }

    fn repair_routes(&mut self, lease: &Lease, sources: &[String]) -> Result<(), Fault> {
        let routes: Vec<Value> =
            match Cmd::new("ip", &["-j", "-6", "route", "show", "table", TABLE]).run() {
                Ok(text) => serde_json::from_str(&text)
                    .map_err(|_| Fault::Unreadable("Cannot inspect owned IPv6 routes".into()))?,
                // Deleting every route removes the table itself: all are missing.
                Err(e) => match net::route_table_listed("-6", TABLE) {
                    Ok(false) => Vec::new(),
                    Ok(true) | Err(_) => return Err(Fault::Unreadable(e)),
                },
            };
        let mut all_sources = sources.to_vec();
        if let Some(ula) = &self.lan_prefix {
            if !all_sources.contains(ula) {
                all_sources.push(ula.clone());
            }
        }
        let expected = network_plan(lease, self.lan_prefix.as_ref().unwrap(), &all_sources)
        .into_iter()
        .filter(|resource| matches!(resource, Resource::Route(_)));
        for step in expected {
            let command = step.command().unwrap();
            let (_, destination) = net::route_target(&command.args);
            let existing: Vec<_> = routes
                .iter()
                .filter(|r| r["dst"].as_str() == Some(destination))
                .collect();
            if existing.is_empty() {
                // `add`, not `replace`: never overwrite a route racing this read.
                self.network.declare(vec![step]).map_err(Fault::Conflict)?;
            } else if existing.iter().any(|r| !route_matches(r, &command)) {
                return Err(Fault::Conflict(
                    "An owned IPv6 route changed externally".into(),
                ));
            }
        }
        match net::plain_policy_rule("-6", PREF, TABLE).map_err(Fault::Unreadable)? {
            net::PolicyRule::Missing => self
                .network
                .declare(vec![policy_rule()])
                .map_err(Fault::Conflict)?,
            net::PolicyRule::Owned => {}
            net::PolicyRule::Foreign | net::PolicyRule::Shared => {
                return Err(Fault::Conflict(
                    "IPv6 policy priority belongs to another writer".into(),
                ))
            }
        }
        Ok(())
    }

    fn configure(&mut self, lease: &Lease, mtu: u32) -> Result<String, String> {
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
        self.lan_sources = sources.clone();
        if !sources.contains(&ula) {
            sources.push(ula.clone());
        }
        let local = Cmd::new("ip", &["-j", "-6", "addr", "show"]).run()?;
        let dns_lease = safe_dns_lease(lease, &sources, &local)?;
        // NAT66, its forwarding and DNS join the relay's tables before the
        // policy rule moves LAN traffic.
        let mut plan = network_plan(&dns_lease, &ula, &sources);
        let rule = plan.pop().expect("the policy rule is the plan's last step");
        self.network.declare(plan)?;
        self.uplink.update(|l| l.nat66 = Some(super::uplink::Nat66 { sources: sources.clone(), dns: upstream_dns(&dns_lease) }))?;
        self.network.declare(vec![rule])?;
        let route = Cmd::new("ip", &["-6", "route", "get", "2606:4700:4700::1111"]).run()?;
        if !route.contains(&format!("dev {IFACE}")) {
            return Err("IPv6 routing did not select Wi-Fi".into());
        }
        // Advertising is last. Undo withdraws RA before removing NAT/routes.
        self.network.declare(vec![ra_step(&ula, linklocal, mtu)])?;
        Ok(ula)
    }

    pub fn stop(&mut self) -> Result<(), String> {
        stop_helper(&mut self.client);
        self.network.release()?;
        self.setup.release()?;
        self.close();
        if self.installed.is_some() {
            self.revision = self.revision.wrapping_add(1);
        }
        self.installed = None;
        self.path = None;
        self.lan_prefix = None;
        self.ra_mtu = None;
        self.phase = "off";
        self.maintained = None;
        self.checked = None;
        self.unreadable = 0;
        self.lan_observed.clear();
        self.lan_sources.clear();
        if let Some(path) = self.session.take().and_then(|s| lease_file(&s)) {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_file(Path::new(ROOT).join("odhcp6c.pid"));
        Ok(())
    }
}

impl Upstream {
    /// The previous agent's IPv6, taken over with its relay session after an
    /// agent restart (`super::adopt`): its client keeps running and the
    /// addresses, routes, NAT66 and RA stay. The journals are taken over and
    /// the plans re-taken from the lease, the relay ULA and the LAN as they
    /// are now (`EffectSet::adopt`: nothing that holds runs again), so
    /// `reconcile` and the ticks keep them from here on. `Err` before the
    /// journals are loaded changes nothing; after, the caller stops the
    /// client and rolls IPv6 back from its journals (`recover`).
    pub fn adopt(&mut self, client: offload::Record, session: &str) -> Result<(), String> {
        let path = lease_file(session).ok_or("Invalid IPv6 session")?;
        let bytes = fs::read(path).map_err(|_| "No IPv6 lease")?;
        let lease: Lease = serde_json::from_slice(&bytes).map_err(|_| "Invalid IPv6 lease")?;
        let live = lease.remaining(now());
        if !live.ready() {
            return Err("the IPv6 lease is not usable".into());
        }
        let ula = stable_ula()?;
        let lan = Cmd::new("ip", &["-j", "-6", "addr", "show", "dev", "br-lan"]).run()?;
        let (_, linklocal) = lan_state(&lan)?;
        let mut observed = BTreeMap::new();
        observe_lan(&mut observed, &lan, Some(&ula), now())?;
        let lan_sources: Vec<String> = observed.keys().cloned().collect();
        let mut sources = lan_sources.clone();
        if !sources.contains(&ula) {
            sources.push(ula.clone());
        }
        let local = Cmd::new("ip", &["-j", "-6", "addr", "show"]).run()?;
        let dns_lease = safe_dns_lease(&live, &sources, &local)?;
        let mtu = ra::advertised_mtu(live.mtu, ra::lan_mtu()?)?;
        let setup = EffectSet::load("relay", &Path::new(JOURNAL).join("ipv6-setup.json"))?;
        let network = EffectSet::load("relay", &Path::new(JOURNAL).join("ipv6-network.json"))?;
        // The tables first: the relay's adoption declared them without NAT66.
        self.uplink.update(|l| {
            l.discovery = true;
            l.nat66 = Some(super::uplink::Nat66 { sources: sources.clone(), dns: upstream_dns(&dns_lease) });
        })?;
        (self.setup, self.network) = (setup, network);
        self.client = Some(Helper::Adopted(client));
        self.session = Some(session.to_owned());
        super::adopt::adopt_resources(&mut self.setup, setup_plan(), &mut net::Device, &mut crate::netfx::effect::Device)?;
        self.network.adopt(network_plan(&dns_lease, &ula, &sources))?;
        self.network.adopt(vec![ra_step(&ula, linklocal, mtu)])?;
        self.requested = true;
        self.installed = Some(lease);
        self.path = Some(live);
        self.lan_prefix = Some(ula);
        self.lan_observed = observed;
        self.lan_sources = lan_sources;
        self.ra_mtu = Some(mtu);
        self.phase = "configured";
        self.error = None;
        self.maintained = Some(Instant::now());
        // Nothing has checked the taken-over objects yet: the first tick does.
        self.checked = None;
        self.unreadable = 0;
        Ok(())
    }

    /// Only the client (an adoption that did not finish).
    pub fn stop_client(&mut self) {
        stop_helper(&mut self.client);
    }
}

/// The previous agent's IPv6 client, still running, and its session (the
/// lease file it writes): `None` unless exactly one is found.
pub fn running_client() -> Option<(offload::Record, String)> {
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else { continue };
        let args: Vec<String> = cmdline.split(|&b| b == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
        if !session_client(&args) {
            continue;
        }
        let environ = fs::read(entry.path().join("environ")).unwrap_or_default();
        let session = environ
            .split(|&b| b == 0)
            .find_map(|v| v.strip_prefix(b"U60_RELAY_DHCP6_SESSION="))
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .filter(|s| lease_file(s).is_some());
        if let (Some(start), Some(session)) = (crate::netfx::exec::process_start(pid), session) {
            found.push((offload::Record { pid, start }, session));
        }
    }
    (found.len() == 1).then(|| found.remove(0))
}

/// The relay's IPv6 client, as `start` runs it.
fn session_client(args: &[String]) -> bool {
    let after = |flag: &str| args.windows(2).find(|w| w[0] == flag).map(|w| w[1].as_str());
    args.first().and_then(|a| a.rsplit('/').next()) == Some("odhcp6c")
        && args.last().map(String::as_str) == Some(IFACE)
        && after("-p") == Some(&format!("{ROOT}/odhcp6c.pid"))
}

pub fn recover() -> Result<(), String> {
    EffectSet::recover(&Path::new(JOURNAL).join("ipv6-network.json"))?;
    // The separate RA snapshot also covers a crash before applying its journal step.
    ra_restore()?;
    EffectSet::recover(&Path::new(JOURNAL).join("ipv6-setup.json"))?;
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
    // executable check, and any failure rolls back the journaled setup. The
    // NAT66 masquerade is nftables (`uplink`): loading the tables checks it.
    Cmd::new("ip6tables", &["-w", "2", "-t", "nat", "-S"]).run()?;
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

fn setup_settings() -> Vec<Step> {
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
    plan
}

pub(crate) fn setup_plan() -> Vec<Resource> {
    let mut rules = Vec::new();
    // Through the vendor's INPUT reject; the relay's tables open the same
    // traffic (`uplink`, discovery) and drop the rest first.
    rules.push(words(&[
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ]));
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
        rules.push(words(&args));
    }
    for kind in ["1", "2", "3", "4"] {
        rules.push(words(&["-p", "ipv6-icmp", "--icmpv6-type", kind, "-j", "ACCEPT"]));
    }
    rules.push(words(&[
            "-p", "udp", "--sport", "547", "--dport", "546", "-j", "ACCEPT",
        ]));
    vec![Resource::LegacyChain(LegacyChain { tool: LegacyTool::V6, table: "filter".into(), name: "U60_R6_IN".into(), rules }),
        Resource::LegacyHook(LegacyHook { tool: LegacyTool::V6, table: "filter".into(), chain: "INPUT".into(), rule: words(&["-i", IFACE, "-j", "U60_R6_IN"]), position: Position::InsertFirst })]
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

fn upstream_identity(lease: &Lease) -> (Vec<(Ipv6Addr, u8)>, Option<Ipv6Addr>) {
    (
        lease
            .addresses
            .iter()
            .map(|a| (a.address, a.prefix))
            .collect(),
        lease.routers.first().map(|r| r.address),
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

fn route_matches(route: &Value, command: &Cmd) -> bool {
    let args = &command.args;
    let field = |name: &str| {
        args.windows(2)
            .find(|a| a[0] == name)
            .map(|a| a[1].as_str())
    };
    // The kernel reports an implicit dev=lo on throw routes; it was not an
    // interface selected by this plan and must not look like an external edit.
    field("dev").is_none_or(|dev| route["dev"].as_str() == Some(dev))
        && route["gateway"].as_str() == field("via")
        && route["type"].as_str().unwrap_or("unicast") == net::route_target(args).0
}

fn address_step(ip: Ipv6Addr, prefix: u8, iface: &str, valid: u32, preferred: u32) -> Resource {
    Resource::Addr(Addr { family: Family::V6, address: format!("{ip}/{prefix}"), device: iface.into(), broadcast: None, valid_lft: Some(valid), preferred_lft: Some(preferred), noprefixroute: iface == IFACE })
}

fn policy_rule() -> Resource {
    Resource::Rule(Rule { family: Family::V6, priority: PREF.parse().unwrap(), table: TABLE.into(), mark: None })
}

fn network_plan(l: &Lease, ula: &str, sources: &[String]) -> Vec<Resource> {
    let mut p = Vec::new();
    for a in &l.addresses {
        p.push(address_step(a.address, 128, IFACE, a.valid, a.preferred));
    }
    p.push(Resource::Internal(Internal::new("@u60-relay-ipv6-dad", l.addresses.iter().map(|address| address.address.to_string()).collect(), vec![]).with_undo(Cmd::new("true", &[]))));
    let lan_address = Ipv6Addr::from(u128::from(cidr(ula).unwrap().0) + 1);
    p.push(address_step(lan_address, 64, "br-lan", 180, 90));
    let mut linklocal = Route::new(Family::V6, RouteType::Unicast, "fe80::/64", TABLE);
    linklocal.device = Some(IFACE.into());
    p.push(Resource::Route(linklocal));
    let destinations: Vec<&str> = vec![TAILNET, crate::netfx::ids::LINK_LOCAL_V6, crate::netfx::ids::MULTICAST_V6];
    for source in sources {
        let mut route = Route::new(Family::V6, RouteType::Unicast, source, TABLE);
        route.device = Some("br-lan".into());
        route.expires = Some(LAN_GRACE as u32);
        p.push(Resource::Route(route));
    }
    for dest in destinations {
        // Link-local gateways are resolved within this table; destinations
        // with an explicit scope/interface retain the kernel link route.
        if dest == "fe80::/10" {
            continue;
        }
        p.push(Resource::Route(Route::new(Family::V6, RouteType::Throw, dest, TABLE)));
    }
    // SLAAC's A flag does not imply on-link (L). Only explicit no-gateway
    // RA_ROUTES entries authorize neighbor discovery for a global prefix.
    for route in &l.onlink {
        let mut resource = Route::new(Family::V6, RouteType::Unicast, &prefix(route.address, route.prefix), TABLE);
        resource.device = Some(IFACE.into());
        resource.expires = Some(route.valid);
        resource.mtu = Some(l.mtu);
        p.push(Resource::Route(resource));
    }
    let mut default = Route::new(Family::V6, RouteType::Unicast, "default", TABLE);
    default.gateway = Some(l.routers[0].address.to_string());
    default.device = Some(IFACE.into());
    default.source = Some(l.addresses[0].address.to_string());
    default.metric = Some(1024);
    default.mtu = Some(l.mtu);
    default.expires = Some(l.routers[0].valid.min(l.addresses[0].valid));
    p.push(Resource::Route(default));
    // The masquerade, the denials and DNS are in the relay's tables
    // (`uplink`, NAT66); legacy keeps what must pass the vendor's FORWARD
    // rejects.
    let mut rules = Vec::new();
    for source in sources {
        rules.push(words(&["-i", "br-lan", "-o", IFACE, "-s", source, "-j", "ACCEPT"]));
    }
    rules.push(words(&[
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
        ]));
    p.push(Resource::LegacyChain(LegacyChain { tool: LegacyTool::V6, table: "filter".into(), name: "U60_R6_FWD".into(), rules }));
    p.push(Resource::LegacyHook(LegacyHook { tool: LegacyTool::V6, table: "filter".into(), chain: "FORWARD".into(), rule: words(&["-j", "U60_R6_FWD"]), position: Position::InsertFirst }));
    p.push(policy_rule());
    p
}

#[cfg(all(test, target_os = "linux"))]
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

fn reload_ra() -> Result<(), String> {
    Cmd::new("/etc/init.d/odhcpd", &["reload"])
        .run()
        .map(|_| ())
}

fn ra_step(ula: &str, dns: Ipv6Addr, mtu: u32) -> Resource {
    Resource::Internal(Internal::new("@u60-relay-ra", words(&["apply", ula, &dns.to_string(), &mtu.to_string()]), vec!["restore".into()]))
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
    ra::release()
}

/// The first upstream resolver router DNS is redirected to (link-local RDNSS
/// cannot be a DNAT target from the router).
fn upstream_dns(l: &Lease) -> Option<Ipv6Addr> {
    l.dns.iter().copied().find(|a| !a.is_unicast_link_local())
}

fn maintain_ra() -> Result<(), Fault> {
    ra::maintain()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network_plan(lease: &Lease, ula: &str, sources: &[String]) -> Vec<Step> {
        crate::netfx::effect::test_plan(super::network_plan(lease, ula, sources))
    }

    fn setup_plan() -> Vec<Step> {
        let mut steps = setup_settings();
        steps.extend(crate::netfx::effect::test_plan(super::setup_plan()));
        steps
    }

    fn ra_step(ula: &str, dns: Ipv6Addr, mtu: u32) -> Step {
        super::ra_step(ula, dns, mtu).step_with(|_| Ok("1".into())).unwrap()
    }

    #[test]
    fn only_the_relays_own_ipv6_client_is_taken_over() {
        let args = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();
        let ours = format!("odhcp6c -N try -R -r 23 -s /data/zte-agent -p {ROOT}/odhcp6c.pid {IFACE}");
        assert!(session_client(&args(&ours)));
        assert!(session_client(&args(&ours.replacen("odhcp6c", "/usr/sbin/odhcp6c", 1))));
        assert!(!session_client(&args(&ours.replace(&format!(" {IFACE}"), " rmnet_data0"))));
        assert!(!session_client(&args("odhcp6c -s /lib/netifd/dhcpv6.script -p /var/run/odhcp6c.pid ath20")), "the firmware's own client");
    }

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
    fn kernel_implicit_throw_device_is_not_a_foreign_route() {
        let throw = Resource::Route(Route::new(Family::V6, RouteType::Throw, "ff00::/8", TABLE)).step_with(|_| Ok("1".into())).unwrap();
        assert!(route_matches(
            &json!({"type":"throw","dst":"ff00::/8","dev":"lo","metric":1024}),
            &throw.apply
        ));
        let route = default_route(&lease(), "add");
        assert!(route_matches(
            &json!({"dst":"default","dev":IFACE,"gateway":"fe80::1"}),
            &route
        ));
        assert!(!route_matches(
            &json!({"dst":"default","dev":"rmnet_data0","gateway":"fe80::1"}),
            &route
        ));
    }

    #[test]
    fn prejournaled_undos_cannot_match_a_vendor_cellular_reject() {
        let plan = network_plan(
            &lease(),
            "fd12:3456:789a::/64",
            &["fd12:3456:789a::/64".into()],
        );
        let vendor = Cmd::new("ip6tables", &["-w", "2", "-t", "filter", "-D", "OUTPUT", "-o", "rmnet+", "-j", "REJECT"]);
        assert!(!plan.iter().any(|step| step.undo == vendor));
        // The cellular OUTPUT reject is the relay baseline's one rule in its
        // tables, not a second legacy chain here.
        assert!(!plan.iter().any(|s| s.apply.args.iter().any(|a| a == "OUTPUT" || a == "REJECT" || a == "DROP" || a == "MASQUERADE")));
        assert_eq!(plan.last().unwrap().apply.args, ["-6", "rule", "add", "pref", PREF, "lookup", TABLE], "the policy rule is last");
        assert!(plan.iter().chain(&setup_plan()).filter(|step| step.undo.program == "ip6tables" && step.undo.args.contains(&"-D".into())).all(|step| crate::netfx::effect::legacy::owned_rule(&step.undo.args)));
        assert!(!setup_plan().iter().any(|s| s.apply.args.iter().any(|a| a == "DROP")), "the drop is in the tables");
    }

    #[test]
    fn router_dns_follows_the_upstream_resolver_or_is_rejected_without_one() {
        let mut linklocal = lease();
        linklocal.dns = vec!["fe80::53".parse().unwrap()];
        assert!(upstream_dns(&lease()).is_some());
        assert_eq!(upstream_dns(&linklocal), None, "a link-local resolver is not used: the tables reject router DNS instead");
        let plan = network_plan(&lease(), "fd12:3456:789a::/64", &["fd12:3456:789a::/64".into()]);
        assert!(!plan.iter().any(|s| s.apply.program == "@u60-relay-nft"), "DNS is in the relay's tables");
    }

    #[test]
    fn unreadable_checks_keep_the_path_for_a_few_ticks_but_conflicts_withdraw_it() {
        let mut upstream = Upstream::new(super::super::uplink::tests::shared("unreadable").0);
        for _ in 1..UNREADABLE_TICKS {
            assert!(upstream
                .tolerate(Err(Fault::Unreadable("busy".into())))
                .is_ok());
        }
        assert!(upstream
            .error
            .as_deref()
            .is_some_and(|e| e.contains("path kept")));
        assert_eq!(
            upstream
                .tolerate(Err(Fault::Unreadable("busy".into())))
                .unwrap_err(),
            "busy"
        );
        upstream.unreadable = 1;
        upstream.tolerate(Ok(())).unwrap();
        assert_eq!(
            (upstream.unreadable, upstream.error.as_deref()),
            (0, None),
            "a good read resets the count"
        );
        assert_eq!(
            upstream
                .tolerate(Err(Fault::Conflict("foreign".into())))
                .unwrap_err(),
            "foreign"
        );
    }

    #[test]
    fn core_identity_ignores_maintenance_but_tracks_sources_and_gateway() {
        let original = lease();
        let mut changed = original.clone();
        changed.received += 10;
        changed.mtu = 1400;
        changed.dns.clear();
        changed.addresses[0].valid += 10;
        assert_eq!(upstream_identity(&original), upstream_identity(&changed));
        changed.routers[0].address = "fe80::99".parse().unwrap();
        assert_ne!(upstream_identity(&original), upstream_identity(&changed));
    }

    #[test]
    fn renewal_extends_the_kernel_lifetime_before_periodic_maintenance() {
        let start = Instant::now();
        let mut old = lease();
        old.addresses[0].valid = 5;
        old.addresses[0].preferred = 5;
        let next = lease();
        let live = next.remaining(next.received);
        assert!(same_path(&old, &next));
        assert!(lease_maintenance_due(
            Some(start),
            start + Duration::from_secs(3),
            Some(&old),
            Some(&next),
            &live
        ));
        assert!(!lease_maintenance_due(
            Some(start),
            start + Duration::from_secs(3),
            Some(&next),
            Some(&next),
            &live
        ));
        let mut preferred = live;
        preferred.addresses[0].preferred = 2;
        assert_eq!(preferred.shortest_lifetime(), 2);
    }

    #[test]
    fn unchanged_leases_are_maintained_on_a_schedule_not_every_tick() {
        let l = lease();
        // valid lifetimes in `lease()`: address 1200 s, router 300 s, on-link 1200 s.
        assert_eq!(l.remaining(100).shortest_lifetime(), 300);
        assert_eq!(l.remaining(250).shortest_lifetime(), 150);
        let forever = Lease {
            addresses: vec![Address {
                valid: u32::MAX,
                preferred: u32::MAX,
                ..l.addresses[0].clone()
            }],
            routers: vec![],
            onlink: vec![],
            ..l.clone()
        };
        assert_eq!(
            forever.shortest_lifetime(),
            u32::MAX,
            "infinite lifetimes never force a refresh"
        );
        let start = Instant::now();
        let tick = Duration::from_secs(3);
        assert!(
            maintenance_due(None, start, 300),
            "first sight after a rebuild or start"
        );
        assert!(!maintenance_due(Some(start), start + tick, 300));
        assert!(!maintenance_due(
            Some(start),
            start + MAINTAIN_EVERY - Duration::from_millis(1),
            300
        ));
        assert!(maintenance_due(Some(start), start + MAINTAIN_EVERY, 300));
        assert!(
            maintenance_due(Some(start), start + tick, 45),
            "short upstream lifetimes refresh every tick"
        );
        assert!(!maintenance_due(Some(start), start + tick, 46));
        assert!(!maintenance_due(Some(start), start + tick, u32::MAX));
        assert!(
            !maintenance_due(Some(start + tick), start, 300),
            "a clock step back never forces it"
        );
    }

    #[test]
    fn owned_objects_are_checked_on_a_trigger_a_retry_a_refresh_or_every_15_s() {
        let start = Instant::now();
        let tick = Duration::from_secs(3);
        assert!(check_due(false, 0, false, None, start), "first tick of a path");
        assert!(!check_due(false, 0, false, Some(start), start + tick), "a quiet tick spawns nothing");
        assert!(!check_due(false, 0, false, Some(start), start + CHECK_EVERY - Duration::from_millis(1)));
        assert!(check_due(false, 0, false, Some(start), start + CHECK_EVERY));
        assert!(check_due(true, 0, false, Some(start), start + tick), "a settled vendor trigger");
        assert!(check_due(false, 0, true, Some(start), start + tick), "a lifetime refresh needs the objects present");
        // A failed read is retried on the next tick, so `UNREADABLE_TICKS`
        // still withdraws after about 6 s of failures, not 30 s.
        assert!(check_due(false, 1, false, Some(start), start + tick));
        assert!(!check_due(false, 0, false, Some(start + tick), start), "a clock step back never forces it");
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
    fn nat66_guards_native_lan_forwarding_and_leaves_dns_to_nft() {
        let p = network_plan(
            &lease(),
            "fd12:3456:789a::/64",
            &["fd12:3456:789a::/64".into()],
        );
        assert!(!p.iter().any(|s| s.apply.args.windows(2).any(|w| w == ["--dport", "53"])), "no legacy DNS rules");
        assert!(!p.iter().any(|s| s.apply.args.windows(2).any(|w| w == ["-I", "POSTROUTING"])), "NAT66 is in nftables");
        let layout = super::super::uplink::Layout { nat66: Some(super::super::uplink::Nat66 { sources: vec!["fd12:3456:789a::/64".into()], dns: upstream_dns(&lease()) }), ..Default::default() };
        let [_, ip6] = super::super::uplink::tables(&layout, None).unwrap();
        assert_eq!(super::super::uplink::tests::chain(&ip6, "nat66"), [format!("oifname \"{IFACE}\" masquerade")], "only the relay's upstream");
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

    #[test]
    fn upstream_private_dns_is_not_mistaken_for_local_management() {
        let tables = |l: &Lease| {
            let nat66 = super::super::uplink::Nat66 { sources: vec!["fd12:3456:789a::/64".into()], dns: upstream_dns(l) };
            let [_, ip6] = super::super::uplink::tables(&super::super::uplink::Layout { nat66: Some(nat66), ..Default::default() }, None).unwrap();
            super::super::uplink::tests::chain(&ip6, "dns_router")
        };
        // Only the LAN's own prefixes stay local, not all of fc00::/7 (the
        // ruleset adds ::1, the tailnet and link-local: `uplink`).
        let with = tables(&lease());
        assert_eq!(with[1], "ip6 daddr { ::1/128, fd7a:115c:a1e0::/48, fe80::/10, fd12:3456:789a::/64 } return");
        assert!(with[2].contains("dnat to"));
        let mut no_dns = lease();
        no_dns.dns.clear();
        assert_eq!(tables(&no_dns)[2], "reject", "router DNS is rejected so IPv4 DNS is used");
        let p = network_plan(&no_dns, "fd12:3456:789a::/64", &["fd12:3456:789a::/64".into()]);
        assert!(!p
            .iter()
            .any(|s| s.apply.args.iter().any(|a| a == "fc00::/7")));
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
        assert!(
            !same_path(&upstream, &renewed),
            "An upstream MTU change must rebuild the RA"
        );
        for bad in ["1279", "1501", "invalid"] {
            assert!(ra_command(&[
                "apply".into(),
                "fd12::/64".into(),
                "fe80::1".into(),
                bad.into()
            ])
            .is_err());
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
    fn relay_resource_plans_have_literal_restore_and_journal_contracts() {
        use crate::netfx::effect::{fake::FakeNft, testing::Kernel};
        let directory = std::env::temp_dir().join(format!("u60-resource-plans-{}", std::process::id()));
        let v4 = super::super::Lease { ip: "10.20.0.7".parse().unwrap(), subnet: "255.255.255.0".parse().unwrap(), gateway: "10.20.0.1".parse().unwrap(), dns: vec![] };
        let ula = "fd12:3456:789a::/64";
        let plans = [
            ("wireless", super::super::input_guards(), vec!["iptables -w 2 -t filter -X U60_RELAY_IN", "iptables -w 2 -t filter -D INPUT -i ath20 -j U60_RELAY_IN"]),
            ("network", super::super::relay_plan(&v4, 24, "192.168.0.1".parse().unwrap(), "255.255.255.0".parse().unwrap()), vec![
                "ip -4 addr del 10.20.0.7/24 dev ath20", "ip -4 route del 10.20.0.0/24 dev ath20 scope link src 10.20.0.7 table 60631",
                "ip -4 route del throw 100.64.0.0/10 table 60631", "ip -4 route del throw 169.254.0.0/16 table 60631", "ip -4 route del throw 224.0.0.0/4 table 60631", "ip -4 route del throw 192.168.0.0/24 table 60631",
                "ip -4 route del default via 10.20.0.1 dev ath20 table 60631", "iptables -w 2 -t filter -X U60_RELAY_FWD", "iptables -w 2 -t filter -D FORWARD -j U60_RELAY_FWD", "iptables -w 2 -t nat -D POSTROUTING -o ath20 -m comment --comment zte-agent-wifi-relay -j MASQUERADE", "ip -4 rule del pref 18640 lookup 60631"]),
            ("ipv6-setup", super::setup_plan(), vec!["ip6tables -w 2 -t filter -X U60_R6_IN", "ip6tables -w 2 -t filter -D INPUT -i ath20 -j U60_R6_IN"]),
            ("ipv6-network", super::network_plan(&lease(), ula, &[ula.into()]), vec![
                "ip -6 addr del 2001:db8:1::2/128 dev ath20", "true", "ip -6 addr del fd12:3456:789a::1/64 dev br-lan", "ip -6 route del fe80::/64 dev ath20 table 60631", "ip -6 route del fd12:3456:789a::/64 dev br-lan table 60631", "ip -6 route del throw fd7a:115c:a1e0::/48 table 60631", "ip -6 route del throw ff00::/8 table 60631", "ip -6 route del 2001:db8:1::/64 dev ath20 table 60631", "ip -6 route del default via fe80::1 dev ath20 metric 1024 table 60631", "ip6tables -w 2 -t filter -X U60_R6_FWD", "ip6tables -w 2 -t filter -D FORWARD -j U60_R6_FWD", "ip -6 rule del pref 18640 lookup 60631"]),
            ("portal", super::super::portal::web_bypasses(), vec!["iptables -w 2 -t nat -D redirect_chain -i br-lan -m comment --comment zte-agent-wifi-relay -j RETURN", "ip6tables -w 2 -t nat -D redirect_chain -i br-lan -m comment --comment zte-agent-wifi-relay -j RETURN"]),
            ("offload", super::super::offload::route_plan("10.20.0.1", "10.20.0.0/24"), vec!["ip -4 route del unreachable 100.64.0.0/10 metric 60631 table main", "ip -4 route del unreachable 169.254.0.0/16 metric 60631 table main", "ip -4 route del unreachable 224.0.0.0/4 metric 60631 table main", "ip -4 route del default via 10.20.0.1 dev ath20 metric 60631 table main"]),
        ];
        let expected_restores = [
            "*filter\n-N U60_RELAY_IN\n-A U60_RELAY_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A U60_RELAY_IN -p udp -m udp --sport 67 --dport 68 -j ACCEPT\n-I INPUT 1 -i ath20 -j U60_RELAY_IN\nCOMMIT\n",
            "*filter\n-N U60_RELAY_FWD\n-A U60_RELAY_FWD -i br-lan -o ath20 -j ACCEPT\n-A U60_RELAY_FWD -i ath20 -o br-lan -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-I FORWARD 1 -j U60_RELAY_FWD\nCOMMIT\n*nat\n-I POSTROUTING 1 -o ath20 -m comment --comment zte-agent-wifi-relay -j MASQUERADE\nCOMMIT\n",
            "*filter\n-N U60_R6_IN\n-A U60_R6_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A U60_R6_IN -s fe80::/10 -p ipv6-icmp -m icmp6 --icmpv6-type 134 -m hl --hl-eq 255 -j ACCEPT\n-A U60_R6_IN -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT\n-A U60_R6_IN -p ipv6-icmp -m icmp6 --icmpv6-type 136 -m hl --hl-eq 255 -j ACCEPT\n-A U60_R6_IN -p ipv6-icmp -m icmp6 --icmpv6-type 1 -j ACCEPT\n-A U60_R6_IN -p ipv6-icmp -m icmp6 --icmpv6-type 2 -j ACCEPT\n-A U60_R6_IN -p ipv6-icmp -m icmp6 --icmpv6-type 3 -j ACCEPT\n-A U60_R6_IN -p ipv6-icmp -m icmp6 --icmpv6-type 4 -j ACCEPT\n-A U60_R6_IN -p udp -m udp --sport 547 --dport 546 -j ACCEPT\n-I INPUT 1 -i ath20 -j U60_R6_IN\nCOMMIT\n",
            "*filter\n-N U60_R6_FWD\n-A U60_R6_FWD -s fd12:3456:789a::/64 -i br-lan -o ath20 -j ACCEPT\n-A U60_R6_FWD -i ath20 -o br-lan -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-I FORWARD 1 -j U60_R6_FWD\nCOMMIT\n",
            "*nat\n-I redirect_chain 1 -i br-lan -m comment --comment zte-agent-wifi-relay -j RETURN\nCOMMIT\n*nat\n-I redirect_chain 1 -i br-lan -m comment --comment zte-agent-wifi-relay -j RETURN\nCOMMIT\n",
            "",
        ];
        for ((name, resources, expected), restore) in plans.into_iter().zip(expected_restores) {
            let mut set = EffectSet::new("relay", directory.join(format!("{name}.json")));
            let mut kernel = Kernel::empty_router();
            set.declare_with(resources, false, &mut kernel, &mut FakeNft::default()).unwrap();
            let journal = set.journal();
            let undo: Vec<Cmd> = serde_json::from_value(journal["undo"].clone()).unwrap();
            let lines: Vec<String> = undo.iter().map(|command| format!("{} {}", command.program, command.args.join(" ")).trim().to_owned()).collect();
            assert_eq!(lines, expected, "{name}");
            assert_eq!(kernel.writes.iter().map(|(_, input)| input.as_str()).collect::<String>(), restore, "{name}");
        }
        fs::remove_dir_all(directory).unwrap();
    }

    /// v5 isolated acceptance (`zte-agent/tests/relay-firewall-qa`): the
    /// relay's table batches per layout as `Shared` loads them, the legacy
    /// restore transactions the sets run, the portal
    /// RETURN moves and this version's journals (boot `BOOT`).
    #[test]
    #[ignore = "writes files for the isolated relay firewall QA; set U60_RELAY_QA"]
    fn export_relay_firewall_for_isolated_linux_acceptance() {
        use super::super::uplink::{self, Layout, Nat66, Relay};
        let dir = PathBuf::from(std::env::var("U60_RELAY_QA").expect("U60_RELAY_QA"));
        fs::create_dir_all(&dir).unwrap();
        let relay = Relay { dns: "10.20.0.1".parse().unwrap(), lan: "192.168.0.0/24".into() };
        let nat66 = |dns: Option<&str>| Nat66 { sources: vec!["fd12:3456:789a::/64".into()], dns: dns.map(|d| d.parse().unwrap()) };
        let layouts = [
            ("guard", Layout::default()),
            ("discovery", Layout { discovery: true, ..Layout::default() }),
            ("relay", Layout { relay: Some(relay.clone()), ..Layout::default() }),
            ("full", Layout { relay: Some(relay.clone()), discovery: true, nat66: Some(nat66(Some("2001:db8:20::1"))) }),
            ("full-nodns", Layout { relay: Some(relay.clone()), discovery: true, nat66: Some(nat66(None)) }),
        ];
        for (generation, (name, layout)) in layouts.iter().enumerate() {
            let (marker, text) = crate::netfx::effect::batch("relay", uplink::TABLE, generation as u64 + 1, uplink::tables(layout, None).unwrap()).unwrap();
            fs::write(dir.join(format!("{name}.nft")), text).unwrap();
            fs::write(dir.join(format!("{name}.marker")), marker).unwrap();
        }
        let [ip, ip6] = uplink::tables(&layouts[3].1, None).unwrap();
        let (_, broken) = crate::netfx::effect::batch("relay", uplink::TABLE, 99, [ip, ip6.replace("masquerade", "masquerade to nowhere")]).unwrap();
        fs::write(dir.join("broken.nft"), broken).unwrap();
        let v4 = super::super::Lease { ip: "10.20.0.7".parse().unwrap(), subnet: "255.255.255.0".parse().unwrap(), gateway: "10.20.0.1".parse().unwrap(), dns: vec!["10.20.0.1".parse().unwrap()] };
        let lan: (std::net::Ipv4Addr, std::net::Ipv4Addr) = ("192.168.0.1".parse().unwrap(), "255.255.255.0".parse().unwrap());
        let mut wireless = super::super::input_guards();
        wireless.push(Resource::NftTable(crate::netfx::effect::NftTable { owner: "relay", name: uplink::TABLE, file: dir.join("uplink.nft"), families: None }));
        let network = super::super::relay_plan(&v4, 24, lan.0, lan.1);
        // The portal RETURN, journaled with the switch in `dns.json`; the
        // switch and resolver steps need UCI and the vendor's resolv.conf.
        let dns = super::super::portal::web_bypasses();
        let ula = "fd12:3456:789a::/64";
        let v6 = super::network_plan(&lease(), ula, &[ula.into()]);
        let mut restore = Vec::new();
        let mut kernel = crate::netfx::effect::testing::Kernel::empty_router();
        for (name, plan) in [("wireless", &wireless), ("network", &network), ("dns", &dns), ("ipv6-setup", &super::setup_plan()), ("ipv6-network", &v6)] {
            let mut set = EffectSet::new("relay", dir.join(format!("{name}.json")));
            kernel.writes.clear();
            set.declare_with(plan.clone(), false, &mut kernel, &mut crate::netfx::effect::fake::FakeNft::default()).unwrap();
            for (program, input) in &kernel.writes {
                restore.push(json!({"plan": name, "program": program, "input": input}));
            }
            fs::write(dir.join(format!("{name}.json")), serde_json::to_vec_pretty(&set.journal()).unwrap()).unwrap();
        }
        fs::write(dir.join("restore.json"), serde_json::to_vec_pretty(&restore).unwrap()).unwrap();
        let mut set = EffectSet::new("relay", dir.join("portal-moves.json"));
        set.assume(vec![super::super::portal::web_bypass(LegacyTool::V4)]);
        let mut kernel = crate::netfx::effect::testing::Kernel::portal_late();
        set.reconcile_with(&mut kernel, &mut crate::netfx::effect::fake::FakeNft::default());
        let late = kernel.writes.last().unwrap().1.clone();
        kernel.tables.get_mut(&("iptables".into(), "nat".into())).unwrap().retain(|line| !line.contains("zte-agent"));
        set.reconcile_with(&mut kernel, &mut crate::netfx::effect::fake::FakeNft::default());
        let moves = json!({"late": late, "absent": kernel.writes.last().unwrap().1});
        fs::write(dir.join("portal.json"), moves.to_string()).unwrap();
        let mut repairs = serde_json::Map::new();
        let mut kernel = crate::netfx::effect::testing::Kernel::empty_router();
        let resources: Vec<Resource> = network.iter().filter(|resource| matches!(resource, Resource::LegacyChain(_) | Resource::LegacyHook(_))).cloned().collect();
        let mut set = EffectSet::new("relay", dir.join("repair-qa.json"));
        set.declare_with(resources, false, &mut kernel, &mut crate::netfx::effect::fake::FakeNft::default()).unwrap();
        kernel.tables.get_mut(&("iptables".into(), "filter".into())).unwrap().push("-A U60_RELAY_FWD -j RETURN".into());
        kernel.writes.clear();
        set.reconcile_with(&mut kernel, &mut crate::netfx::effect::fake::FakeNft::default());
        repairs.insert("chain".into(), json!(kernel.writes[0].1));
        kernel.tables.get_mut(&("iptables".into(), "filter".into())).unwrap().push("-A FORWARD -j U60_RELAY_FWD".into());
        kernel.writes.clear();
        set.reconcile_with(&mut kernel, &mut crate::netfx::effect::fake::FakeNft::default());
        repairs.insert("hook".into(), json!(kernel.writes[0].1));
        fs::write(dir.join("repairs.json"), serde_json::to_vec_pretty(&repairs).unwrap()).unwrap();
        fs::remove_file(dir.join("repair-qa.json")).unwrap();
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
        let mut dns = EffectSet::new("relay", Path::new(JOURNAL).join("dns-qa.json"));
        dns.step(dns_step).unwrap();
        assert!(fs::read_to_string("/tmp/resolv.conf")
            .unwrap()
            .contains("nameserver 192.0.2.53"));
        fs::write(
            "/tmp/resolv.conf",
            "# new vendor DNS\nnameserver 2001:db8:9::54\n",
        )
        .unwrap();
        super::super::dns::reconcile(&["192.0.2.53".parse().unwrap()]).unwrap();
        EffectSet::recover(&Path::new(JOURNAL).join("dns-qa.json")).unwrap();
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
    #[ignore = "Mutates network/UCI; only run in the disposable OpenWrt QA chroot"]
    fn isolated_openwrt_start_refresh_stop() {
        assert_eq!(std::env::var("U60_IPV6_ISOLATED_QA").as_deref(), Ok("1"));
        assert!(Path::new("/u60-ipv6-qa-disposable").exists());
        assert!(std::env::var_os("U60_IPV6_QA_CALLBACK").is_some());
        let original = Cmd::new("uci", &["-q", "show", "dhcp.lan"]).run().unwrap();
        let committed = fs::read("/etc/config/dhcp").unwrap();
        let main = Cmd::new("ip", &["-6", "route", "show", "table", "main"])
            .run()
            .unwrap();

        let effects = std::sync::Arc::new(std::sync::Mutex::new(EffectSet::new("relay", PathBuf::from("/tmp/u60-ipv6-qa-wireless.json"))));
        let uplink = super::super::uplink::Shared::new(PathBuf::from("/tmp/u60-ipv6-qa-uplink.nft"), effects);
        uplink.guard().unwrap();
        let mut upstream = Upstream::new(uplink);
        upstream.start(false).unwrap();
        assert_eq!(upstream.status()["state"], "off");
        upstream.start(true).unwrap();
        assert_eq!(upstream.status()["state"], "detecting");
        assert!(upstream.client.is_some());
        upstream.tick(true).unwrap();
        assert_eq!(upstream.status()["state"], "no_upstream");
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(150));
            upstream.tick(true).unwrap();
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
                .contains("dev ath20")
        );
        for _ in 0..3 {
            std::thread::sleep(Duration::from_millis(200));
            upstream.tick(true).unwrap();
            assert_eq!(
                upstream.status()["state"],
                "configured",
                "{}",
                upstream.status()
            );
        }
        assert_eq!(upstream.status()["upstream_mtu"], 1500);
        assert_eq!(upstream.status()["lan_mtu"], 1500);
        assert_eq!(ra::data().unwrap()["ra_mtu"], 1500);
        Cmd::new("ip", &["link", "set", "br-lan", "mtu", "1400"])
            .run()
            .unwrap();
        upstream.tick(true).unwrap();
        assert_eq!(
            upstream.status()["state"],
            "configured",
            "{}",
            upstream.status()
        );
        assert_eq!(upstream.status()["lan_mtu"], 1400);
        assert_eq!(ra::data().unwrap()["ra_mtu"], 1400);
        Cmd::new("ip", &["link", "set", "br-lan", "mtu", "1500"])
            .run()
            .unwrap();
        upstream.tick(true).unwrap();
        assert_eq!(upstream.status()["lan_mtu"], 1500);
        assert_eq!(ra::data().unwrap()["ra_mtu"], 1500);
        Cmd::new(
            "ip",
            &["-6", "addr", "add", "2001:db8:3::1/64", "dev", "br-lan"],
        )
        .run()
        .unwrap();
        upstream.tick(true).unwrap();
        assert_eq!(
            upstream.status()["state"],
            "configured",
            "{}",
            upstream.status()
        );
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
        upstream.tick(true).unwrap();
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
        upstream.tick(true).unwrap();
        let revision = upstream.revision();
        Cmd::new(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "fd00:60:1107::1/128",
                "dev",
                "lo",
                "nodad",
            ],
        )
        .run()
        .unwrap();
        upstream.tick(true).unwrap();
        assert_eq!(
            upstream.revision(),
            revision,
            "local address additions must not redial core transports"
        );
        let rule = [
            "-w",
            "2",
            "-C",
            "U60_R6_FWD",
            "-i",
            "br-lan",
            "-o",
            IFACE,
            "-s",
            "2001:db8:2::/64",
            "-j",
            "ACCEPT",
        ];
        Cmd::new("ip6tables", &rule).run().unwrap();
        let journal = fs::read(Path::new(JOURNAL).join("ipv6-network.json")).unwrap();
        let mut remove = rule;
        remove[2] = "-D";
        Cmd::new("ip6tables", &remove).run().unwrap();
        // The repair now comes from the `net_guard` reconcile, not the tick.
        assert!(upstream.reconcile().failed.is_empty());
        Cmd::new("ip6tables", &rule).run().unwrap();
        assert_eq!(
            fs::read(Path::new(JOURNAL).join("ipv6-network.json")).unwrap(),
            journal,
            "repair reuses the existing undo"
        );
        Cmd::new(
            "ip",
            &["-6", "addr", "del", "fd00:60:1107::1/128", "dev", "lo"],
        )
        .run()
        .unwrap();
        upstream.tick(true).unwrap();
        assert_eq!(upstream.revision(), revision);
        Cmd::new("ip", &["-6", "rule", "del", "pref", PREF, "lookup", TABLE])
            .run()
            .unwrap();
        upstream.tick(true).unwrap();
        assert_eq!(
            net::plain_policy_rule("-6", PREF, TABLE).unwrap(),
            net::PolicyRule::Owned
        );
        assert_eq!(
            upstream.revision(),
            revision,
            "policy repair is not a new uplink"
        );
        // Simulate expiry while the shared network lock delayed supervision,
        // followed by renewal of exactly the same address/router.
        default_route(upstream.path.as_ref().unwrap(), "del")
            .run()
            .unwrap();
        upstream.tick(true).unwrap();
        assert_eq!(
            upstream.status()["state"],
            "configured",
            "{}",
            upstream.status()
        );
        assert_eq!(
            upstream.revision(),
            revision,
            "repairing the same route must not restart the core"
        );
        assert!(
            Cmd::new("ip", &["-6", "route", "get", "2606:4700:4700::1111"])
                .run()
                .unwrap()
                .contains("dev ath20")
        );
        // Owned addresses, and a route table another writer emptied (which
        // then no longer exists), are restored in place as well.
        let owned = upstream.path.as_ref().unwrap().addresses[0].address;
        let lan_address =
            Ipv6Addr::from(u128::from(cidr(upstream.lan_prefix.as_ref().unwrap()).unwrap().0) + 1);
        Cmd::new(
            "ip",
            &["-6", "addr", "del", &format!("{owned}/128"), "dev", IFACE],
        )
        .run()
        .unwrap();
        Cmd::new(
            "ip",
            &[
                "-6",
                "addr",
                "del",
                &format!("{lan_address}/64"),
                "dev",
                "br-lan",
            ],
        )
        .run()
        .unwrap();
        upstream.tick(true).unwrap();
        let addresses = Cmd::new("ip", &["-6", "addr", "show"]).run().unwrap();
        assert!(
            addresses.contains(&format!("{owned}/128"))
                && addresses.contains(&format!("{lan_address}/64")),
            "{addresses}"
        );
        Cmd::new("ip", &["-6", "route", "flush", "table", TABLE])
            .run()
            .unwrap();
        upstream.tick(true).unwrap();
        assert_eq!(
            upstream.status()["state"],
            "configured",
            "{}",
            upstream.status()
        );
        assert!(
            Cmd::new("ip", &["-6", "route", "get", "2606:4700:4700::1111"])
                .run()
                .unwrap()
                .contains("dev ath20")
        );
        assert_eq!(
            upstream.revision(),
            revision,
            "restoring owned addresses and an emptied table is not a new uplink"
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
        upstream.stop().unwrap();

        upstream.start(true).unwrap();
        assert_ne!(upstream.session.as_ref().unwrap(), &old_session);
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(150));
            upstream.tick(true).unwrap();
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
        for event in ["ra-updated", "stopped", "started"] {
            let mut callback = Command::new(std::env::var_os("U60_IPV6_QA_CALLBACK").unwrap());
            callback
                .args([IFACE, event])
                .env("U60_RELAY_DHCP6", "1")
                .env("U60_RELAY_DHCP6_SESSION", &old_session)
                .env("RA_ADDRESSES", "2001:db8:dead::2/64,600,1200")
                .env("RA_ROUTES", "::/0,fe80::dead,600,512");
            net::run(callback, Duration::from_secs(5)).unwrap();
            upstream.tick(true).unwrap();
            assert_eq!(
                upstream.status()["state"],
                "configured",
                "{}",
                upstream.status()
            );
            assert_ne!(upstream.status()["gateway"], "fe80::dead");
        }
        let mut expired = upstream.installed.as_ref().unwrap().clone();
        expired.routers.clear();
        net::write_private(
            &lease_file(upstream.session.as_ref().unwrap()).unwrap(),
            &serde_json::to_vec(&expired).unwrap(),
        )
        .unwrap();
        upstream.tick(true).unwrap();
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
            upstream.tick(true).unwrap();
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
        let revision = upstream.revision();
        let Some(Helper::Owned(child)) = upstream.client.as_mut() else { panic!("the client this test started") };
        child.kill().unwrap();
        child.wait().unwrap();
        upstream.tick(true).unwrap();
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
            upstream.tick(true).unwrap();
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
            .tick(true)
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
            upstream.tick(true).unwrap();
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
        upstream.stop().unwrap();

        // B31's cellular switch commits the full DHCP package. Runtime RA
        // never enters that package, including unrelated pending edits.
        upstream.start(true).unwrap();
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(150));
            upstream.tick(true).unwrap();
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
    }
}
