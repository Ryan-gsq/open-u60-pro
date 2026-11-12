//! The core's egress (`relay-mihomo-architecture.md` section 5.6): what
//! interface and addresses its connections leave by, and which changes
//! restart it. The relay announces changes of its own routes at once; outside
//! the relay (cellular) the controller audits the egress every 15 s and only
//! an egress that strands the core's connections restarts it. A relay
//! announcement restarts the core at once when IPv4 moved (another interface,
//! a recreated one, or a lost source address) or first became available; an
//! IPv6-only move must hold for 5 s, and such restarts are at least 60 s
//! apart. No egress at all restarts nothing (there is nothing to bind to): a
//! relay switch restarts the core once, when the new uplink is up, and an
//! IPv6 address added to the same interface later restarts nothing.
//!
//! An observation spawns nothing but, for a route through the relay that
//! the relay announced, one `iw` (which access point it is on): routes come
//! from the kernel's own lookup over rtnetlink (what `ip route get` asks)
//! and addresses from `getifaddrs`. The 15 s audit used to start four tools
//! each time, and skips `iw` (an audit ignores the relay's routes).

use std::time::{Duration, Instant};

use crate::net_tools::Cmd;
use crate::netfx::ids;

/// The relay's station interface (`wifi_relay::IFACE`).
const RELAY_IFACE: &str = ids::RELAY_IFACE;
/// The destinations whose route is the egress, per family.
const PROBES: [&str; 2] = ["1.1.1.1", "2606:4700:4700::1111"];
/// A stranding egress change must stay identical this long before the
/// watchdog restarts the core: a flapping uplink restarts nothing until it settles.
pub(super) const EGRESS_SETTLE: Duration = Duration::from_secs(5);
/// At most one watchdog egress restart per window. Relay notifications and
/// owner operations are not limited.
pub(super) const EGRESS_RESTART_GAP: Duration = Duration::from_secs(60);

/// Effective egress per family (IPv4, IPv6), excluding timers/cache counters
/// and unrelated local IPs. `None`: no readable route or source address set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Uplink {
    pub(super) paths: [Option<Egress>; 2],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Egress {
    route: RouteIdentity,
    source: SourceIdentity,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RouteIdentity {
    device: String,
    gateway: Option<String>,
    source: Option<String>,
    /// The access point the relay is associated with, for a route through
    /// it: another network can keep the interface and address (the relay
    /// hands its station over) and still strand every connection.
    upstream: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SourceIdentity {
    ifindex: u64,
    addresses: Vec<(std::net::IpAddr, u8)>,
}
impl Uplink {
    /// `ip -j route get` output (tests describe routes this way).
    #[cfg(test)]
    pub(super) fn route(text: &str) -> Option<RouteIdentity> {
        let routes: serde_json::Value = serde_json::from_str(text).ok()?;
        let route = routes.as_array()?.first()?;
        Some(RouteIdentity {
            device: route["dev"].as_str()?.into(),
            gateway: route["gateway"].as_str().map(str::to_owned),
            source: route["prefsrc"]
                .as_str()
                .or_else(|| route["src"].as_str())
                .map(str::to_owned),
            upstream: None,
        })
    }
    /// Routes with the `ip -j addr show` links (tests describe links this way).
    #[cfg(test)]
    pub(super) fn read(routes: [Option<RouteIdentity>; 2], text: &str) -> Self {
        let links: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
        let links = links.as_array().cloned().unwrap_or_default();
        let mut addresses = Vec::new();
        for link in &links {
            for addr in link["addr_info"].as_array().into_iter().flatten() {
                if let (Some(name), Some(ip), Some(prefix)) = (link["ifname"].as_str(), addr["local"].as_str().and_then(|a| a.parse().ok()), addr["prefixlen"].as_u64()) {
                    addresses.push(crate::httpd::mobile::IfAddr { name: name.into(), addr: ip, prefix: prefix as u8, scope: 0 });
                }
            }
        }
        let index = |route: Option<RouteIdentity>| {
            let route = route?;
            let link = links.iter().find(|l| l["ifname"].as_str() == Some(&route.device))?;
            Some((route, link["ifindex"].as_u64()?))
        };
        let [v4, v6] = routes;
        Self::from_parts([index(v4), index(v6)], &addresses)
    }

    /// Each family's route (with its output interface's index) and the
    /// addresses that interface holds. A family without a route or without
    /// an address of its own on that interface is no egress.
    fn from_parts(routes: [Option<(RouteIdentity, u64)>; 2], addresses: &[crate::httpd::mobile::IfAddr]) -> Self {
        let path = |route: Option<(RouteIdentity, u64)>, v4: bool| -> Option<Egress> {
            let (route, ifindex) = route?;
            // `getifaddrs` names an IPv4 address by its label (`dev:alias`).
            let on = |name: &str| name.strip_prefix(route.device.as_str()).is_some_and(|rest| rest.is_empty() || rest.starts_with(':'));
            let mut found: Vec<(std::net::IpAddr, u8)> = addresses.iter().filter(|a| a.addr.is_ipv4() == v4 && on(&a.name)).map(|a| (a.addr, a.prefix)).collect();
            if found.is_empty() {
                return None;
            }
            found.sort_unstable();
            found.dedup();
            Some(Egress { route, source: SourceIdentity { ifindex, addresses: found } })
        };
        let [v4, v6] = routes;
        Self { paths: [path(v4, true), path(v6, false)] }
    }

    /// What the core's connections leave by now. `upstream`: also which
    /// access point a route through the relay is on (one `iw`).
    pub(super) fn observe(upstream: bool) -> Self {
        let mut routes = PROBES.map(|to| netlink::route_get(to.parse().expect("a probe address")));
        if upstream && routes.iter().flatten().any(|(r, _)| r.device == RELAY_IFACE) {
            let upstream = Cmd::new("iw", &["dev", RELAY_IFACE, "link"]).run().ok().and_then(|link| associated_bss(&link));
            for (route, _) in routes.iter_mut().flatten().filter(|(r, _)| r.device == RELAY_IFACE) {
                route.upstream.clone_from(&upstream);
            }
        }
        let addresses = crate::httpd::mobile::interfaces().unwrap_or_default();
        Self::from_parts(routes, &addresses)
    }
    /// Connections opened on `earlier` cannot leave through this egress any
    /// more: a readable family moved to another interface (name or index) or
    /// lost a source address it had. Added addresses, gateway or preferred
    /// source changes and a newly available family keep them usable; an
    /// unreadable family is no evidence (a failed read, or a lost uplink).
    pub(super) fn strands(&self, earlier: &Self) -> bool {
        self.paths
            .iter()
            .zip(&earlier.paths)
            .any(|(now, then)| match (now, then) {
                (Some(now), Some(then)) => now.strands_from(then),
                _ => false,
            })
    }
    /// Takes readable families as the new reference. An unreadable family
    /// keeps the last one, so its return on another address still strands.
    pub(super) fn adopt(&mut self, observed: &Self) {
        for (kept, now) in self.paths.iter_mut().zip(&observed.paths) {
            if now.is_some() {
                kept.clone_from(now);
            }
        }
    }
    pub(super) fn relayed(&self) -> bool {
        self.paths
            .iter()
            .flatten()
            .any(|path| path.route.device == RELAY_IFACE)
    }

    /// An egress through `dev` (index `ifindex`) with an IPv4 and an optional
    /// IPv6 source address, for tests elsewhere in the module.
    #[cfg(test)]
    pub(super) fn sample(dev: &str, ifindex: u64, v4: &str, v6: Option<&str>) -> Self {
        let mut info = vec![serde_json::json!({"family": "inet", "local": v4, "prefixlen": 24})];
        if let Some(v6) = v6 {
            info.push(serde_json::json!({"family": "inet6", "local": v6, "prefixlen": 64}));
        }
        let links = serde_json::json!([{"ifindex": ifindex, "ifname": dev, "addr_info": info}]).to_string();
        let route = |src: Option<&str>| src.and_then(|src| Self::route(&format!(r#"[{{"dev":"{dev}","prefsrc":"{src}"}}]"#)));
        Self::read([route(Some(v4)), route(v6)], &links)
    }
}

/// One watchdog egress observation. `uplink` is the egress the running core's
/// connections use, `stranding` a stranding observation and when it was first
/// seen. True: restart the core now. A core still bound to the relay's
/// interface after the relay left is stranded as soon as another egress
/// (cellular) appears; while there is none it keeps its reference.
pub(super) fn settle_egress(
    uplink: &mut Uplink,
    stranding: &mut Option<(Uplink, Instant)>,
    observed: Uplink,
    last_restart: Option<Instant>,
    now: Instant,
) -> bool {
    if observed.relayed() {
        *stranding = None;
        return false;
    }
    if !observed.strands(uplink) {
        uplink.adopt(&observed);
        *stranding = None;
        return false;
    }
    match stranding {
        Some((seen, since)) if *seen == observed => restart_due(*since, last_restart) <= now,
        _ => {
            *stranding = Some((observed, now));
            false
        }
    }
}

pub(super) fn restart_due(since: Instant, last_restart: Option<Instant>) -> Instant {
    let settled = since + EGRESS_SETTLE;
    last_restart.map_or(settled, |at| settled.max(at + EGRESS_RESTART_GAP))
}


/// How the egress the relay announced differs from the core's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Change {
    /// The same egress: a duplicate notification.
    None,
    /// Nothing the core's connections use moved (an added address or
    /// family, another gateway, a withdrawn family): take it as the new
    /// reference without a restart.
    Adopt,
    /// No readable egress at all: nothing to restart onto. The core keeps
    /// its reference; the next egress is compared with it.
    Gone,
    /// Only IPv6 moved: wait for it to hold (`EGRESS_SETTLE`, at most one
    /// such restart per `EGRESS_RESTART_GAP`).
    V6,
    /// IPv4 moved or first became available: restart now.
    V4,
}

pub(super) fn change(core: &Uplink, observed: &Uplink) -> Change {
    if observed == core {
        return Change::None;
    }
    if observed.paths.iter().all(Option::is_none) {
        return Change::Gone;
    }
    let moved = |family: usize| match (&core.paths[family], &observed.paths[family]) {
        (Some(then), Some(now)) => now.strands_from(then),
        // A newly available family: a core started without it has no
        // interface to use for it.
        (None, Some(_)) => family == 0,
        (_, None) => false,
    };
    if moved(0) {
        Change::V4
    } else if moved(1) {
        Change::V6
    } else {
        Change::Adopt
    }
}

impl Egress {
    /// Connections opened on `then` cannot leave through this path: another
    /// interface (name or index), another access point behind the relay, or
    /// a source address `then` had is gone.
    fn strands_from(&self, then: &Self) -> bool {
        self.route.device != then.route.device
            || self.source.ifindex != then.source.ifindex
            || matches!((&self.route.upstream, &then.route.upstream), (Some(now), Some(before)) if now != before)
            || then.source.addresses.iter().any(|(ip, _)| !self.source.addresses.iter().any(|(kept, _)| kept == ip))
    }
}

/// The BSSID in `iw dev <iface> link` (`Connected to <bssid> (on …)`).
fn associated_bss(link: &str) -> Option<String> {
    let bssid = link.lines().next()?.strip_prefix("Connected to ")?.split_whitespace().next()?;
    (bssid.len() == 17).then(|| bssid.to_ascii_lowercase())
}

/// When an IPv6-only change seen at `since` may restart the core.
pub(super) fn v6_due(since: Instant, last: Option<Instant>) -> Instant {
    restart_due(since, last)
}

/// The kernel's route lookup for one destination over rtnetlink: the
/// `RTM_GETROUTE` request `ip route get <to>` sends (same policy rules, no
/// mark), and its answer's output interface, gateway and preferred source.
mod netlink {
    // Only Linux asks the kernel; elsewhere the parsing is for tests.
    #![cfg_attr(not(target_os = "linux"), allow(dead_code))]

    use std::net::IpAddr;

    use super::RouteIdentity;

    const NLMSG_ERROR: u16 = 2;
    const RTM_NEWROUTE: u16 = 24;
    const RTM_GETROUTE: u16 = 26;
    const NLM_F_REQUEST: u16 = 1;
    const RTA_DST: u16 = 1;
    const RTA_OIF: u16 = 4;
    const RTA_GATEWAY: u16 = 5;
    const RTA_PREFSRC: u16 = 7;
    /// `struct nlmsghdr` and `struct rtmsg`.
    const HEADER: usize = 16;
    const RTMSG: usize = 12;

    /// What the kernel answered: the output interface's index, the gateway
    /// and the source address it would use.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct Answer {
        pub oif: u32,
        pub gateway: Option<IpAddr>,
        pub source: Option<IpAddr>,
    }

    fn octets(ip: IpAddr) -> Vec<u8> {
        match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        }
    }

    /// The `RTM_GETROUTE` message for `to`, in host byte order.
    pub(super) fn request(to: IpAddr, seq: u32) -> Vec<u8> {
        let address = octets(to);
        let (family, bits) = if to.is_ipv4() { (2u8, 32u8) } else { (10u8, 128u8) };
        let length = HEADER + RTMSG + 4 + address.len();
        let mut message = Vec::with_capacity(length);
        message.extend_from_slice(&(length as u32).to_ne_bytes());
        message.extend_from_slice(&RTM_GETROUTE.to_ne_bytes());
        message.extend_from_slice(&NLM_F_REQUEST.to_ne_bytes());
        message.extend_from_slice(&seq.to_ne_bytes());
        message.extend_from_slice(&0u32.to_ne_bytes());
        // family, dst_len, src_len, tos, table, protocol, scope, type; flags.
        message.extend_from_slice(&[family, bits, 0, 0, 0, 0, 0, 0]);
        message.extend_from_slice(&0u32.to_ne_bytes());
        message.extend_from_slice(&((4 + address.len()) as u16).to_ne_bytes());
        message.extend_from_slice(&RTA_DST.to_ne_bytes());
        message.extend_from_slice(&address);
        message
    }

    fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_ne_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
    }

    fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
    }

    fn address(bytes: &[u8]) -> Option<IpAddr> {
        match bytes.len() {
            4 => Some(IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?)),
            16 => Some(IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?)),
            _ => None,
        }
    }

    /// The answer to request `seq` among the messages in `reply`; `None`
    /// for an error (no route) or a reply without an output interface.
    pub(super) fn parse(reply: &[u8], seq: u32) -> Option<Answer> {
        let mut at = 0;
        while at + HEADER <= reply.len() {
            let length = u32_at(reply, at)? as usize;
            let kind = u16_at(reply, at + 4)?;
            if length < HEADER || at + length > reply.len() {
                return None;
            }
            let message = &reply[at..at + length];
            if u32_at(message, 8)? == seq {
                match kind {
                    RTM_NEWROUTE => return attributes(message.get(HEADER + RTMSG..)?),
                    NLMSG_ERROR => return None,
                    _ => {}
                }
            }
            at += (length + 3) & !3;
        }
        None
    }

    fn attributes(mut rest: &[u8]) -> Option<Answer> {
        let (mut oif, mut gateway, mut source) = (None, None, None);
        while rest.len() >= 4 {
            let length = usize::from(u16_at(rest, 0)?);
            if length < 4 || length > rest.len() {
                break;
            }
            let value = &rest[4..length];
            match u16_at(rest, 2)? {
                RTA_OIF => oif = u32_at(value, 0),
                RTA_GATEWAY => gateway = address(value),
                RTA_PREFSRC => source = address(value),
                _ => {}
            }
            rest = rest.get((length + 3) & !3..).unwrap_or_default();
        }
        Some(Answer { oif: oif?, gateway, source })
    }

    /// The route the kernel picks for `to` and its output interface's index;
    /// `None` when there is none or the kernel cannot be asked (an
    /// unreadable family is no evidence, as before).
    pub(super) fn route_get(to: IpAddr) -> Option<(RouteIdentity, u64)> {
        let answer = ask(to)?;
        let device = name(answer.oif)?;
        Some((RouteIdentity { device, gateway: answer.gateway.map(|g| g.to_string()), source: answer.source.map(|s| s.to_string()), upstream: None }, u64::from(answer.oif)))
    }

    #[cfg(target_os = "linux")]
    fn ask(to: IpAddr) -> Option<Answer> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // SAFETY: plain socket(2); the descriptor is owned (closed) below.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
        if fd < 0 {
            return None;
        }
        // SAFETY: `fd` is a new descriptor nothing else owns.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let timeout = libc::timeval { tv_sec: 2, tv_usec: 0 };
        // SAFETY: a valid descriptor and a `timeval` of the size given.
        unsafe { libc::setsockopt(socket.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, std::ptr::from_ref(&timeout).cast(), std::mem::size_of::<libc::timeval>() as libc::socklen_t) };
        let message = request(to, seq);
        // SAFETY: an all-zero `sockaddr_nl` is the kernel's address once the family is set.
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: the buffer and the address are valid for the lengths given.
        let sent = unsafe { libc::sendto(socket.as_raw_fd(), message.as_ptr().cast(), message.len(), 0, std::ptr::from_ref(&kernel).cast(), std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t) };
        if sent != message.len() as isize {
            return None;
        }
        let mut reply = vec![0u8; 8192];
        // A reply to another request (none is sent on this socket) is skipped.
        for _ in 0..4 {
            // SAFETY: `reply` is writable for its length.
            let read = unsafe { libc::recv(socket.as_raw_fd(), reply.as_mut_ptr().cast(), reply.len(), 0) };
            if read <= 0 {
                return None;
            }
            let got = &reply[..read as usize];
            let ours = got.len() >= HEADER && u32_at(got, 8) == Some(seq);
            if ours {
                return parse(got, seq);
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    fn ask(_: IpAddr) -> Option<Answer> {
        None
    }

    /// The interface name of index `oif`.
    fn name(oif: u32) -> Option<String> {
        let mut buffer = [0 as libc::c_char; libc::IF_NAMESIZE];
        // SAFETY: `buffer` holds IF_NAMESIZE bytes, as `if_indextoname` needs.
        let named = unsafe { libc::if_indextoname(oif, buffer.as_mut_ptr()) };
        if named.is_null() {
            return None;
        }
        // SAFETY: on success the buffer holds a NUL-terminated name.
        Some(unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }.to_string_lossy().into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn uplink_identity_ignores_route_counters_but_tracks_egress() {
        let a = Uplink::route(
            r#"[{"dev":"ath20","gateway":"192.0.2.1","prefsrc":"192.0.2.2","expires":30}]"#,
        );
        let b = Uplink::route(
            r#"[{"dev":"ath20","gateway":"192.0.2.1","prefsrc":"192.0.2.2","expires":10,"cache":[]}]"#,
        );
        assert_eq!(a, b);
        assert_ne!(
            a,
            Uplink::route(r#"[{"dev":"rmnet_data0","gateway":"192.0.2.1","prefsrc":"192.0.2.2"}]"#)
        );
        assert!(Uplink::route("[]").is_none());
        let mut links = json!([{ "ifindex": 7, "ifname": "ath20", "addr_info": [
            {"family":"inet","local":"192.0.2.2","prefixlen":24},
            {"family":"inet6","local":"2001:db8::2","prefixlen":64,"valid_life_time":30},
            {"family":"inet6","local":"2001:db8::3","prefixlen":64}
        ] }, {"ifindex":1,"ifname":"lo","addr_info":[]}]);
        let observe = |links: &Value| Uplink::read([a.clone(), a.clone()], &links.to_string());
        let before = observe(&links);
        assert!(before.paths.iter().all(Option::is_some));
        links[0]["addr_info"][1]["valid_life_time"] = json!(10);
        links[0]["addr_info"].as_array_mut().unwrap().reverse();
        links[1]["addr_info"] = json!([{"family":"inet6","local":"fd00::1","prefixlen":128}]);
        assert_eq!(
            observe(&links),
            before,
            "lifetimes, ordering and non-egress addresses are maintenance only"
        );
        assert!(!observe(&links).strands(&before));
        links[0]["addr_info"].as_array_mut().unwrap().remove(0);
        assert_ne!(
            observe(&links),
            before,
            "withdrawn secondary sources must invalidate deduplication"
        );
        assert!(observe(&links).strands(&before));
        assert!(
            Uplink::read([a.clone(), a], "[]").paths.iter().all(Option::is_none),
            "a route without a readable source address is no egress"
        );
    }

    #[test]
    fn only_an_egress_that_strands_connections_outside_the_relay_counts() {
        let start = cellular("rmnet_data0", 3, "10.1.0.1", &["10.1.0.2", "2001:db8::2"]);
        assert!(!start.relayed() && !start.strands(&start));
        assert!(
            cellular("rmnet_data0", 3, "10.1.0.5", &["10.1.0.6", "2001:db8::2"]).strands(&start),
            "a re-dial that withdrew the old cellular address strands its connections"
        );
        assert!(
            cellular("rmnet_data0", 3, "10.1.0.1", &["10.1.0.2", "2001:db8:1::7"]).strands(&start),
            "IPv6 renumbering that removed the old source does too"
        );
        assert!(
            cellular("rmnet_data1", 4, "10.1.0.1", &["10.1.0.2", "2001:db8::2"]).strands(&start),
            "another interface strands even with the same addresses"
        );
        assert!(
            cellular("rmnet_data0", 9, "10.1.0.1", &["10.1.0.2", "2001:db8::2"]).strands(&start),
            "so does a recreated interface"
        );
        assert!(
            !cellular("rmnet_data0", 3, "10.1.0.9", &["10.1.0.2", "2001:db8::2"]).strands(&start),
            "a gateway change keeps connections usable"
        );
        let added = cellular(
            "rmnet_data0",
            3,
            "10.1.0.1",
            &["10.1.0.2", "2001:db8:1::7", "2001:db8::2"],
        );
        assert!(
            !added.strands(&start),
            "an added address that also became the preferred source keeps the old one usable"
        );
        let v4_only = cellular("rmnet_data0", 3, "10.1.0.1", &["10.1.0.2"]);
        assert!(
            !v4_only.strands(&start),
            "an unreadable or lost family is not a move"
        );
        assert!(
            !start.strands(&v4_only),
            "IPv6 becoming available is not either"
        );
        let mut reference = start.clone();
        reference.adopt(&v4_only);
        assert_eq!(reference, start, "a lost family keeps its last reference");
        assert!(
            cellular("rmnet_data0", 3, "10.1.0.1", &["10.1.0.2", "2001:db8:2::9"])
                .strands(&reference),
            "its return on another address strands"
        );
        reference.adopt(&added);
        assert_eq!(reference, added);
        assert!(
            start.strands(&reference),
            "an adopted address is protected like the original ones"
        );
        let route = |dev: &str, src: &str| {
            Uplink::route(&format!(r#"[{{"dev":"{dev}","prefsrc":"{src}"}}]"#))
        };
        let link = |index: u64, name: &str, v4: &str, v6: &str| {
            json!({"ifindex": index, "ifname": name, "addr_info": [
                {"family":"inet","local":v4,"prefixlen":30},
                {"family":"inet6","local":v6,"prefixlen":64}
            ]})
        };
        let links = json!([
            link(7, RELAY_IFACE, "192.0.2.2", "fe80::2"),
            link(3, "rmnet_data0", "10.1.0.2", "2001:db8::2")
        ])
        .to_string();
        let relayed = Uplink::read(
            [
                route(RELAY_IFACE, "192.0.2.2"),
                route("rmnet_data0", "2001:db8::2"),
            ],
            &links,
        );
        assert!(
            relayed.relayed(),
            "the relay announces its own path changes"
        );
    }

    /// One interface carrying `addrs`; each family routes through its first
    /// address, or is unreadable without one.
    fn cellular(dev: &str, index: u64, gateway: &str, addrs: &[&str]) -> Uplink {
        let info: Vec<Value> = addrs
            .iter()
            .map(|addr| {
                let v6 = addr.contains(':');
                json!({
                    "family": if v6 { "inet6" } else { "inet" },
                    "local": addr,
                    "prefixlen": if v6 { 64 } else { 30 },
                })
            })
            .collect();
        let links = json!([{"ifindex": index, "ifname": dev, "addr_info": info}]).to_string();
        let route = |v6: bool| {
            let src = addrs.iter().find(|addr| addr.contains(':') == v6)?;
            Uplink::route(&format!(
                r#"[{{"dev":"{dev}","gateway":"{gateway}","prefsrc":"{src}"}}]"#
            ))
        };
        Uplink::read([route(false), route(true)], &links)
    }

    #[test]
    fn a_stranding_egress_restarts_once_settled_and_at_most_once_per_gap() {
        let cell = |addr: &str| cellular("rmnet_data0", 3, "10.1.0.1", &[addr, "2001:db8::2"]);
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let mut uplink = cell("10.1.0.2");
        let mut stranding = None;
        assert!(!settle_egress(
            &mut uplink,
            &mut stranding,
            cell("10.1.0.6"),
            None,
            at(0)
        ));
        assert_eq!(
            stranding,
            Some((cell("10.1.0.6"), at(0))),
            "only starts settling"
        );
        assert!(!settle_egress(
            &mut uplink,
            &mut stranding,
            cell("10.1.0.6"),
            None,
            at(4)
        ));
        assert!(
            !settle_egress(&mut uplink, &mut stranding, cell("10.1.0.10"), None, at(4)),
            "a flapping uplink starts settling again"
        );
        assert!(!settle_egress(
            &mut uplink,
            &mut stranding,
            cell("10.1.0.10"),
            None,
            at(8)
        ));
        assert!(settle_egress(
            &mut uplink,
            &mut stranding,
            cell("10.1.0.10"),
            None,
            at(9)
        ));
        assert_eq!(
            uplink,
            cell("10.1.0.2"),
            "only the restarted core takes a new reference"
        );

        let mut stranding = Some((cell("10.1.0.6"), at(0)));
        assert!(
            !settle_egress(&mut uplink, &mut stranding, cell("10.1.0.2"), None, at(10)),
            "the old address came back before the change settled"
        );
        assert_eq!(stranding, None);

        let last = Some(at(0));
        assert_eq!(restart_due(at(10), last), at(60));
        assert_eq!(restart_due(at(70), last), at(75));
        let mut stranding = None;
        assert!(!settle_egress(
            &mut uplink,
            &mut stranding,
            cell("10.1.0.6"),
            last,
            at(10)
        ));
        assert!(
            !settle_egress(&mut uplink, &mut stranding, cell("10.1.0.6"), last, at(59)),
            "settled, but the last watchdog restart was under a minute ago"
        );
        assert!(settle_egress(
            &mut uplink,
            &mut stranding,
            cell("10.1.0.6"),
            last,
            at(60)
        ));

        let mut stranding = Some((cell("10.1.0.6"), at(0)));
        let dual = cellular(
            "rmnet_data0",
            3,
            "10.1.0.9",
            &["10.1.0.2", "10.1.0.3", "2001:db8::2"],
        );
        assert!(
            !settle_egress(&mut uplink, &mut stranding, dual.clone(), None, at(10)),
            "added addresses and a new gateway only update the reference"
        );
        assert_eq!((uplink.clone(), stranding), (dual, None));

        let relay = cellular(RELAY_IFACE, 7, "192.0.2.1", &["192.0.2.2", "2001:db8::2"]);
        let mut stranding = Some((cell("10.1.0.6"), at(0)));
        assert!(
            !settle_egress(&mut uplink, &mut stranding, relay, None, at(10)),
            "the relay announces its own path changes"
        );
        assert_eq!(stranding, None);
    }


    #[test]
    fn a_relay_switch_restarts_the_core_once_when_the_new_uplink_is_up() {
        let core = cellular("ath20", 9, "192.168.2.1", &["192.168.2.124", "2409:8a00::5"]);
        assert_eq!(change(&core, &core), Change::None, "a duplicate");
        // The old session's teardown: no egress is left to restart onto.
        assert_eq!(change(&core, &Uplink::default()), Change::Gone);
        // The new session recreated the interface: IPv4 moved, once.
        let rejoined = cellular("ath20", 10, "192.168.2.1", &["192.168.2.124"]);
        assert_eq!(change(&core, &rejoined), Change::V4);
        // IPv6 arrives on the same interface later: nothing moved.
        let dual = cellular("ath20", 10, "192.168.2.1", &["192.168.2.124", "2409:8a00::5"]);
        assert_eq!(change(&rejoined, &dual), Change::Adopt);
        // and leaving it again (IPv6 lease expired) moves nothing either.
        assert_eq!(change(&dual, &rejoined), Change::Adopt);
        let v4 = cellular("rmnet_data0", 4, "10.0.0.1", &["10.0.0.9", "2409:8a00::5"]);
        assert_eq!(change(&core, &v4), Change::V4, "the relay left for cellular");
        assert_eq!(change(&Uplink::default(), &rejoined), Change::V4, "a core started without an egress binds to the first one");
        assert_eq!(
            change(&Uplink::default(), &Uplink::sample("ath20", 3, "192.0.2.2", None)),
            Change::V4
        );
        let regateway = cellular("ath20", 9, "192.168.2.254", &["192.168.2.124", "2409:8a00::5"]);
        assert_eq!(change(&core, &regateway), Change::Adopt, "another gateway keeps connections usable");
        let mut v6 = core.clone();
        v6.paths[1] = cellular("ath20", 9, "192.168.2.1", &["192.168.2.124", "2409:8b00::7"]).paths[1].clone();
        assert_eq!(change(&core, &v6), Change::V6, "IPv6 renumbered: held, then one restart");
        let mut v4_lost = core.clone();
        v4_lost.paths[0] = None;
        assert_eq!(change(&core, &v4_lost), Change::Adopt, "a lost family has nothing to restart onto");
        let since = Instant::now();
        assert_eq!(v6_due(since, None), since + EGRESS_SETTLE);
        assert_eq!(v6_due(since, Some(since)), since + EGRESS_RESTART_GAP);
    }

    #[test]
    fn a_core_left_on_the_relays_interface_follows_cellular_once_it_appears() {
        let relay = cellular(RELAY_IFACE, 7, "192.0.2.1", &["192.0.2.2", "2001:db8::2"]);
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let mut uplink = relay.clone();
        let mut stranding = None;
        assert!(
            !settle_egress(&mut uplink, &mut stranding, Uplink::default(), None, at(0)),
            "no egress: nothing to follow"
        );
        assert_eq!((uplink.clone(), stranding.clone()), (relay.clone(), None));
        let cell = cellular("rmnet_data0", 3, "10.1.0.1", &["10.1.0.2"]);
        assert!(!settle_egress(&mut uplink, &mut stranding, cell.clone(), None, at(15)));
        assert!(settle_egress(&mut uplink, &mut stranding, cell, None, at(20)), "cellular held 5 s");
    }

    /// A relay switch hands the station over: the interface and possibly the
    /// address stay, the access point does not.
    #[test]
    fn another_access_point_behind_the_relay_moves_the_egress() {
        let behind = |bss: Option<&str>| {
            let mut uplink = cellular(RELAY_IFACE, 9, "192.168.2.1", &["192.168.2.124", "2409:8a00::5"]);
            for path in uplink.paths.iter_mut().flatten() {
                path.route.upstream = bss.map(str::to_owned);
            }
            uplink
        };
        let first = behind(Some("c0:a4:76:b1:f0:e4"));
        assert_eq!(change(&first, &behind(Some("c0:a4:76:b1:f0:e4"))), Change::None, "the same access point again");
        assert_eq!(change(&first, &behind(Some("c0:a4:76:b1:f0:e5"))), Change::V4, "another network, same address");
        assert_eq!(change(&first, &behind(None)), Change::Adopt, "an unreadable link is no evidence");
        assert_eq!(associated_bss("Connected to C0:A4:76:B1:F0:E4 (on ath20)\n\tSSID: W_Game\n").as_deref(), Some("c0:a4:76:b1:f0:e4"));
        assert_eq!(associated_bss("Not connected."), None);
    }

    /// An rtnetlink message: header, `rtmsg`, attributes (each padded to 4).
    fn message(kind: u16, seq: u32, body: &[u8], attributes: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut rest = body.to_vec();
        for (kind, value) in attributes {
            rest.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
            rest.extend_from_slice(&kind.to_ne_bytes());
            rest.extend_from_slice(value);
            rest.resize((rest.len() + 3) & !3, 0);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&((16 + rest.len()) as u32).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&0u16.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend(rest);
        out
    }

    #[test]
    fn a_route_lookup_is_asked_and_read_as_ip_route_get_does() {
        let asked = netlink::request("1.1.1.1".parse().unwrap(), 7);
        assert_eq!(asked.len(), 36);
        assert_eq!(u32::from_ne_bytes(asked[..4].try_into().unwrap()), 36);
        assert_eq!(&asked[16..18], &[2, 32], "AF_INET, a /32 destination");
        assert_eq!(&asked[32..], &[1, 1, 1, 1]);
        let v6 = netlink::request("2606:4700:4700::1111".parse().unwrap(), 8);
        assert_eq!((v6.len(), v6[16], v6[17]), (48, 10, 128));
        // As B31 answers for the relay: table, destination, interface,
        // preferred source, gateway, uid and cache info, any order.
        let rtmsg = [2, 32, 0, 0, 254, 0, 0, 1, 0, 2, 0, 0];
        let answer = message(24, 7, &rtmsg, &[(15, 254u32.to_ne_bytes().to_vec()), (1, vec![1, 1, 1, 1]), (4, 9u32.to_ne_bytes().to_vec()), (7, vec![192, 168, 2, 124]), (5, vec![192, 168, 2, 1]), (25, 0u32.to_ne_bytes().to_vec()), (12, vec![0; 18])]);
        let read = netlink::parse(&answer, 7).unwrap();
        assert_eq!((read.oif, read.gateway, read.source), (9, Some("192.168.2.1".parse().unwrap()), Some("192.168.2.124".parse().unwrap())));
        assert_eq!(netlink::parse(&answer, 6), None, "another request's answer");
        let on_link = message(24, 3, &[10, 128, 0, 0, 254, 0, 0, 1, 0, 0, 0, 0], &[(4, 12u32.to_ne_bytes().to_vec()), (7, "2409:8a00::5".parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec())]);
        assert_eq!(netlink::parse(&on_link, 3).unwrap().source, Some("2409:8a00::5".parse().unwrap()));
        let unreachable = message(2, 4, &(-101i32).to_ne_bytes(), &[]);
        assert_eq!(netlink::parse(&unreachable, 4), None, "no route: no egress");
        assert_eq!(netlink::parse(&answer[..20], 7), None, "a cut-off reply");
        assert_eq!(netlink::parse(&message(24, 5, &rtmsg, &[(7, vec![10, 0, 0, 1])]), 5), None, "no output interface");
    }

    #[test]
    fn an_egress_takes_the_addresses_of_its_interface_and_its_labels() {
        use crate::httpd::mobile::IfAddr;
        let route = RouteIdentity { device: "rmnet_data0".into(), gateway: None, source: None, upstream: None };
        let addr = |name: &str, ip: &str, prefix| IfAddr { name: name.into(), addr: ip.parse().unwrap(), prefix, scope: 0 };
        let table = [addr("rmnet_data0", "10.1.0.2", 30), addr("rmnet_data0:1", "10.1.0.9", 32), addr("rmnet_data01", "10.9.0.1", 24), addr("rmnet_data0", "2001:db8::2", 64)];
        let uplink = Uplink::from_parts([Some((route.clone(), 3)), Some((route, 3))], &table);
        let [v4, v6] = uplink.paths.map(|p| p.unwrap().source);
        assert_eq!(v4.addresses, [("10.1.0.2".parse().unwrap(), 30), ("10.1.0.9".parse().unwrap(), 32)], "not another interface's");
        assert_eq!((v6.ifindex, v6.addresses.len()), (3, 1));
    }

    /// Inside a Linux namespace (`tests/mihomo-qa`, or any disposable
    /// container with `iproute2`): the kernel's answer over rtnetlink is what
    /// `ip -j route get` and `ip -j addr show` say.
    #[test]
    #[ignore]
    fn isolated_netlink_observation_matches_ip() {
        let observed = Uplink::observe(false);
        let routes = [("-4", PROBES[0]), ("-6", PROBES[1])].map(|(family, to)| Cmd::new("ip", &["-j", family, "route", "get", to]).run().ok().and_then(|s| Uplink::route(&s)));
        let links = Cmd::new("ip", &["-j", "addr", "show", "up"]).run().unwrap();
        let expected = Uplink::read(routes, &links);
        eprintln!("observed {observed:?}");
        assert!(observed.paths[0].is_some(), "the namespace needs an IPv4 default route");
        assert_eq!(observed, expected);
    }
}
