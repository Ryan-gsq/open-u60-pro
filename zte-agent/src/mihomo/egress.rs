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

use std::time::{Duration, Instant};

use serde_json::Value;

use crate::net_tools::Cmd;
use crate::netfx::ids;

/// The relay's station interface (`wifi_relay::IFACE`).
const RELAY_IFACE: &str = ids::RELAY_IFACE;
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
    pub(super) fn route(text: &str) -> Option<RouteIdentity> {
        let routes: Value = serde_json::from_str(text).ok()?;
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
    pub(super) fn read(routes: [Option<RouteIdentity>; 2], text: &str) -> Self {
        let links: Option<Value> = serde_json::from_str(text).ok();
        let source = |route: &RouteIdentity, family: &str| -> Option<SourceIdentity> {
            let link = links
                .as_ref()?
                .as_array()?
                .iter()
                .find(|v| v["ifname"].as_str() == Some(&route.device))?;
            let mut addresses = Vec::new();
            for addr in link["addr_info"]
                .as_array()?
                .iter()
                .filter(|a| a["family"].as_str() == Some(family))
            {
                let ip: std::net::IpAddr = addr["local"].as_str()?.parse().ok()?;
                let prefix = addr["prefixlen"].as_u64()?;
                if ip.is_ipv4() != (family == "inet")
                    || prefix > if ip.is_ipv4() { 32 } else { 128 }
                {
                    return None;
                }
                addresses.push((ip, prefix as u8));
            }
            if addresses.is_empty() {
                return None;
            }
            addresses.sort_unstable();
            addresses.dedup();
            Some(SourceIdentity {
                ifindex: link["ifindex"].as_u64()?,
                addresses,
            })
        };
        let path = |route: Option<RouteIdentity>, family: &str| -> Option<Egress> {
            let route = route?;
            let source = source(&route, family)?;
            Some(Egress { route, source })
        };
        let [v4, v6] = routes;
        Self {
            paths: [path(v4, "inet"), path(v6, "inet6")],
        }
    }
    pub(super) fn observe() -> Self {
        let mut routes = [("-4", "1.1.1.1"), ("-6", "2606:4700:4700::1111")].map(|(family, to)| {
            Cmd::new("ip", &["-j", family, "route", "get", to])
                .run()
                .ok()
                .and_then(|s| Self::route(&s))
        });
        if routes.iter().flatten().any(|r| r.device == RELAY_IFACE) {
            let upstream = Cmd::new("iw", &["dev", RELAY_IFACE, "link"]).run().ok().and_then(|link| associated_bss(&link));
            for route in routes.iter_mut().flatten().filter(|r| r.device == RELAY_IFACE) {
                route.upstream.clone_from(&upstream);
            }
        }
        let addresses = Cmd::new("ip", &["-j", "addr", "show"])
            .run()
            .unwrap_or_default();
        Self::read(routes, &addresses)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn uplink_identity_ignores_route_counters_but_tracks_egress() {
        let a = Uplink::route(
            r#"[{"dev":"u60sta0","gateway":"192.0.2.1","prefsrc":"192.0.2.2","expires":30}]"#,
        );
        let b = Uplink::route(
            r#"[{"dev":"u60sta0","gateway":"192.0.2.1","prefsrc":"192.0.2.2","expires":10,"cache":[]}]"#,
        );
        assert_eq!(a, b);
        assert_ne!(
            a,
            Uplink::route(r#"[{"dev":"rmnet_data0","gateway":"192.0.2.1","prefsrc":"192.0.2.2"}]"#)
        );
        assert!(Uplink::route("[]").is_none());
        let mut links = json!([{ "ifindex": 7, "ifname": "u60sta0", "addr_info": [
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
        let core = cellular("u60sta0", 9, "192.168.2.1", &["192.168.2.124", "2409:8a00::5"]);
        assert_eq!(change(&core, &core), Change::None, "a duplicate");
        // The old session's teardown: no egress is left to restart onto.
        assert_eq!(change(&core, &Uplink::default()), Change::Gone);
        // The new session recreated the interface: IPv4 moved, once.
        let rejoined = cellular("u60sta0", 10, "192.168.2.1", &["192.168.2.124"]);
        assert_eq!(change(&core, &rejoined), Change::V4);
        // IPv6 arrives on the same interface later: nothing moved.
        let dual = cellular("u60sta0", 10, "192.168.2.1", &["192.168.2.124", "2409:8a00::5"]);
        assert_eq!(change(&rejoined, &dual), Change::Adopt);
        // and leaving it again (IPv6 lease expired) moves nothing either.
        assert_eq!(change(&dual, &rejoined), Change::Adopt);
        let v4 = cellular("rmnet_data0", 4, "10.0.0.1", &["10.0.0.9", "2409:8a00::5"]);
        assert_eq!(change(&core, &v4), Change::V4, "the relay left for cellular");
        assert_eq!(change(&Uplink::default(), &rejoined), Change::V4, "a core started without an egress binds to the first one");
        assert_eq!(
            change(&Uplink::default(), &Uplink::sample("u60sta0", 3, "192.0.2.2", None)),
            Change::V4
        );
        let regateway = cellular("u60sta0", 9, "192.168.2.254", &["192.168.2.124", "2409:8a00::5"]);
        assert_eq!(change(&core, &regateway), Change::Adopt, "another gateway keeps connections usable");
        let mut v6 = core.clone();
        v6.paths[1] = cellular("u60sta0", 9, "192.168.2.1", &["192.168.2.124", "2409:8b00::7"]).paths[1].clone();
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
        assert_eq!(associated_bss("Connected to C0:A4:76:B1:F0:E4 (on u60sta0)\n\tSSID: W_Game\n").as_deref(), Some("c0:a4:76:b1:f0:e4"));
        assert_eq!(associated_bss("Not connected."), None);
    }
}
