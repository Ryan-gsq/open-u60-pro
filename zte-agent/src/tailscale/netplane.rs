//! Kernel-TUN (`tailscale0`) network data plane owned by Tailscale's `EffectSet`.
//!
//! Manages:
//! - Dual-family nftables `ip`/`ip6 u60_tail`:
//!   - `input` (`filter - 1`): anti-spoof drop for Tailnet source IPs arriving on
//!     non-`tailscale0`/non-`lo` interfaces toward management ports (9090/9443).
//!   - `prerouting` (`mangle - 2`): `ct mark |= 0x02000000` on `iifname "tailscale0"`
//!     for targeted conntrack teardown on uplink switches.
//!   - `forward` (`filter - 1`): bidirectional `rt mtu` SYN MSS clamping and strict
//!     allowlist for control-plane-approved LAN subnet routes (`oifname "br-lan"`)
//!     and public Exit Node traffic bound to the selected physical uplink
//!     (`ath20` when Wi-Fi relay is active, `rmnet*` when cellular is active).
//!   - `postrouting` (`srcnat - 1`): conditional masquerade for cellular Exit Node
//!     (`oifname "rmnet*"` only when cellular is the active uplink) and approved LAN
//!     subnet destinations (`oifname "br-lan"`), explicitly skipping `ath20` so it
//!     never duplicates the Wi-Fi relay's own masquerade.
//! - Legacy iptables/ip6tables accepts (`U60_TS_IN`, `U60_TS_FWD`) so traffic allowed
//!   by `u60_tail` passes vendor `INPUT`/`FORWARD` default rejects.
//! - RPDB priorities `5110`, `5130`, `5131` cooperating with Mihomo (`5100`),
//!   Wi-Fi relay (`5120`), and `tailscaled` (`5210–5270`).
//! - Forwarding and `rp_filter=0` sysctls (with `tailscale0_rp_filter` attached
//!   once `tailscale0` exists after the closed guard is already in place).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use super::config::{self, TsConfig};
use super::localapi::{FullStatus, PeerStatus, Status};
use crate::net_tools::{self as net, Probe, Reconciled};
use crate::netfx::effect::{
    self, Device as NftDevice, EffectSet, Family, Key, LegacyChain, LegacyHook, LegacyTool, Nft,
    NftTable, NftTables, Position, Presence, Resource, Rule, RuleAction, Sysctl, FAMILIES,
};
use crate::netfx::ids;

pub(crate) const JOURNAL_PATH: &str = "/data/tailscale/network.json";
const NFT_FILE_PATH: &str = "/data/tailscale/u60_tail.nft";
const MAX_VERIFIED_V4: usize = 1024;

const FILTER: &str = "filter - 1";
const MANGLE_PRE: &str = "mangle - 2";
const SRCNAT: &str = "srcnat - 1";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ExitUplink {
    /// Wi-Fi relay is active (`ath20`).
    Relay,
    /// Cellular WAN (`rmnet*`).
    #[default]
    Cellular,
}

impl ExitUplink {
    fn oifname(self) -> &'static str {
        match self {
            Self::Relay => ids::RELAY_IFACE,
            Self::Cellular => "rmnet*",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ApprovedRoutes {
    pub subnets_v4: Vec<Ipv4Net>,
    pub subnets_v6: Vec<Ipv6Net>,
    pub exit_v4: bool,
    pub exit_v6: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Layout {
    pub approved_subnets_v4: Vec<Ipv4Net>,
    pub approved_subnets_v6: Vec<Ipv6Net>,
    pub exit_v4: bool,
    pub exit_v6: bool,
    pub exit_uplink: ExitUplink,
    pub verified_v4: Vec<Ipv4Net>,
    /// Optional local DNAT target port on `127.0.0.54` when primary `:53` was
    /// occupied and Clean DNS fell back to `CLEAN_DNS_FALLBACK_PORT`.
    pub clean_dns_dnat_port: Option<u16>,
}

impl Layout {
    /// Closed guard installed before `tailscaled --tun=tailscale0` spawns:
    /// blocks all forwarding, installs CGNAT `5130/5131` guards, and routes
    /// Quad100 + IPv6 Tailnet via `5110`.
    pub(super) fn closed_guard(exit_uplink: ExitUplink) -> Self {
        Self {
            approved_subnets_v4: Vec::new(),
            approved_subnets_v6: Vec::new(),
            exit_v4: false,
            exit_v6: false,
            exit_uplink,
            verified_v4: vec![ids::TAILSCALE_QUAD100.parse().unwrap()],
            clean_dns_dnat_port: None,
        }
    }

    pub(super) fn with_clean_dns_dnat(mut self, port: Option<u16>) -> Self {
        self.clean_dns_dnat_port = port;
        self
    }

    pub(super) fn from_status(
        cfg: &TsConfig,
        status: Option<&Status>,
        peers: &[PeerStatus],
        exit_uplink: ExitUplink,
    ) -> (Self, Option<String>) {
        let approved = approved_routes(cfg, status);
        let (verified_v4, warning) = verified_v4_targets(status, peers);
        (
            Self {
                approved_subnets_v4: approved.subnets_v4,
                approved_subnets_v6: approved.subnets_v6,
                exit_v4: approved.exit_v4,
                exit_v6: approved.exit_v6,
                exit_uplink,
                verified_v4,
                clean_dns_dnat_port: None,
            },
            warning,
        )
    }

    pub(super) fn from_full_status(
        cfg: &TsConfig,
        full: &FullStatus,
        exit_uplink: ExitUplink,
    ) -> (Self, Option<String>) {
        Self::from_status(cfg, Some(&full.status), &full.peers, exit_uplink)
    }

    fn firewall_changed(&self, other: &Self) -> bool {
        self.approved_subnets_v4 != other.approved_subnets_v4
            || self.approved_subnets_v6 != other.approved_subnets_v6
            || self.exit_v4 != other.exit_v4
            || self.exit_v6 != other.exit_v6
            || self.exit_uplink != other.exit_uplink
            || self.clean_dns_dnat_port != other.clean_dns_dnat_port
    }
}

/// Compute control-plane-approved subnet routes and Exit Node flags using the
/// exact same matching rules as the console status payload.
pub(super) fn approved_routes(cfg: &TsConfig, status: Option<&Status>) -> ApprovedRoutes {
    let Some(status) = status.filter(|s| s.backend_state == "Running") else {
        return ApprovedRoutes::default();
    };
    let parse_prefixes = |routes: &[String]| -> BTreeSet<IpNet> {
        routes
            .iter()
            .filter_map(|route| route.parse::<IpNet>().ok())
            .map(|net| net.trunc())
            .collect()
    };
    let self_status = status.self_status.as_ref();
    let allowed = self_status
        .map(|s| parse_prefixes(&s.allowed_ips))
        .unwrap_or_default();
    let primary = self_status
        .map(|s| parse_prefixes(&s.primary_routes))
        .unwrap_or_default();
    let node_ips: BTreeSet<IpNet> = self_status
        .into_iter()
        .flat_map(|s| &s.tailscale_ips)
        .chain(status.tailscale_ips.iter().flatten())
        .filter_map(|addr| addr.parse::<IpAddr>().ok())
        .map(IpNet::from)
        .collect();

    let mut subnets_v4 = BTreeSet::new();
    let mut subnets_v6 = BTreeSet::new();
    for route in &cfg.advertise_routes {
        if config::normalize_route(route).is_err() {
            continue;
        }
        let Ok(prefix) = route.parse::<IpNet>() else {
            continue;
        };
        let prefix = prefix.trunc();
        if node_ips.contains(&prefix) {
            continue;
        }
        if primary.contains(&prefix) || allowed.contains(&prefix) {
            match prefix {
                IpNet::V4(v4) => {
                    subnets_v4.insert(v4);
                }
                IpNet::V6(v6) => {
                    subnets_v6.insert(v6);
                }
            }
        }
    }

    let default_v4: IpNet = config::DEFAULT_V4.parse().unwrap();
    let default_v6: IpNet = config::DEFAULT_V6.parse().unwrap();
    let exit_option = self_status.is_some_and(|s| s.exit_node_option);
    let approved_v4 = allowed.contains(&default_v4);
    let approved_v6 = allowed.contains(&default_v6);
    let implicit_dual_stack = exit_option && !approved_v4 && !approved_v6;

    ApprovedRoutes {
        subnets_v4: subnets_v4.into_iter().collect(),
        subnets_v6: subnets_v6.into_iter().collect(),
        exit_v4: cfg.advertise_exit_node && (implicit_dual_stack || approved_v4),
        exit_v6: cfg.advertise_exit_node && (implicit_dual_stack || approved_v6),
    }
}

/// Parse an individual `/32` IPv4 host/service address inside `100.64.0.0/10`.
/// Rejects any subnet prefix (`< /32`) so advertised CGNAT subnets can never
/// slip into priority `5110` ahead of `5130/5131`.
fn verified_cgnat_host(raw: &str, cgnat: Ipv4Net) -> Option<Ipv4Net> {
    let trimmed = raw.trim();
    let net = if let Ok(addr) = trimmed.parse::<Ipv4Addr>() {
        Ipv4Net::from(addr)
    } else if let Ok(parsed) = trimmed.parse::<Ipv4Net>() {
        if parsed.prefix_len() != 32 {
            return None;
        }
        parsed.trunc()
    } else {
        return None;
    };
    (net.prefix_len() == 32 && cgnat.contains(&net)).then_some(net)
}

/// Verified IPv4 Tailnet `/32` host and service addresses inside `100.64.0.0/10`
/// eligible for priority `5110 -> lookup 52`. Advertised subnet prefixes are
/// never admitted here. Returns an explicit degraded warning if the tailnet
/// exceeds `MAX_VERIFIED_V4`.
pub(super) fn verified_v4_targets(
    status: Option<&Status>,
    peers: &[PeerStatus],
) -> (Vec<Ipv4Net>, Option<String>) {
    let cgnat: Ipv4Net = ids::TAILNET_V4.parse().unwrap();
    let quad100: Ipv4Net = ids::TAILSCALE_QUAD100.parse().unwrap();
    let mut ordered: Vec<Ipv4Net> = vec![quad100];
    let mut seen: BTreeSet<Ipv4Net> = BTreeSet::from([quad100]);
    let mut dropped = 0usize;

    let mut push = |raw: &str| {
        let Some(net) = verified_cgnat_host(raw, cgnat) else {
            return;
        };
        if !seen.insert(net) {
            return;
        }
        if ordered.len() < MAX_VERIFIED_V4 {
            ordered.push(net);
        } else {
            dropped += 1;
        }
    };

    if let Some(status) = status {
        for ip in status.tailscale_ips.iter().flatten() {
            push(ip);
        }
        if let Some(self_status) = &status.self_status {
            for ip in &self_status.tailscale_ips {
                push(ip);
            }
        }
    }

    // Prioritize online peers first so offline nodes are shed first if a very
    // large tailnet ever exceeds MAX_VERIFIED_V4.
    let mut sorted_peers: Vec<&PeerStatus> = peers.iter().collect();
    sorted_peers.sort_by(|a, b| {
        b.online
            .cmp(&a.online)
            .then_with(|| a.tailscale_ips.cmp(&b.tailscale_ips))
    });
    for peer in sorted_peers {
        for ip in &peer.tailscale_ips {
            push(ip);
        }
    }

    let warning = (dropped > 0).then(|| {
        format!(
            "tailnet has {} verified IPv4 hosts exceeding the {} rule limit; {} peer host(s) omitted from priority 5110",
            ordered.len() + dropped,
            MAX_VERIFIED_V4,
            dropped
        )
    });
    let unique: BTreeSet<Ipv4Net> = ordered.into_iter().collect();
    (unique.into_iter().collect(), warning)
}

fn hook(kind: &str, at: &str, priority: &str) -> String {
    format!("type {kind} hook {at} priority {priority}; policy accept;")
}

fn format_v4_set(nets: &[Ipv4Net]) -> String {
    nets.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_v6_set(nets: &[Ipv6Net]) -> String {
    nets.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Build the dual-family `ip`/`ip6 u60_tail` table definitions.
pub(crate) fn tables(layout: &Layout) -> [String; 2] {
    [v4_table(layout), v6_table(layout)]
}

fn v4_table(layout: &Layout) -> String {
    let ts = ids::TAILSCALE_IFACE;
    let ct_mark = format!("0x{:08x}", ids::TAILSCALE_CT_MARK);
    let input = vec![format!(
        "iifname != {{ \"{ts}\", \"lo\" }} ip saddr {} meta l4proto tcp th dport {{ {}, {} }} drop",
        ids::TAILNET_V4,
        ids::HTTP_PORT,
        ids::HTTPS_PORT
    )];
    let prerouting = vec![format!("iifname \"{ts}\" ct mark set ct mark or {ct_mark}")];
    let mut forward = vec![
        format!("iifname \"{ts}\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"),
        format!("oifname \"{ts}\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"),
        format!("iifname \"{ts}\" oifname \"{ts}\" drop"),
        format!("iifname \"{ts}\" ip daddr {} reject", ids::FAKE_IP_NET),
    ];
    if !layout.approved_subnets_v4.is_empty() {
        let approved = format_v4_set(&layout.approved_subnets_v4);
        forward.push(format!(
            "iifname \"{ts}\" oifname \"br-lan\" ip daddr {{ {approved} }} return"
        ));
        // Reject approved LAN destinations on any non-`br-lan` egress before
        // the general Exit Node allow rule so a globally routed LAN prefix can
        // never leak out the physical uplink if the `br-lan` route disappears.
        forward.push(format!(
            "iifname \"{ts}\" ip daddr {{ {approved} }} drop"
        ));
    }
    if layout.exit_v4 {
        forward.push(format!(
            "iifname \"{ts}\" ip daddr {{ {} }} drop",
            ids::PRIVATE_V4.join(", ")
        ));
        forward.push(format!(
            "iifname \"{ts}\" oifname \"{}\" return",
            layout.exit_uplink.oifname()
        ));
    }
    forward.push(format!("iifname \"{ts}\" drop"));
    forward.push(format!("oifname \"{ts}\" ct state established,related return"));
    if !layout.approved_subnets_v4.is_empty() {
        forward.push(format!(
            "iifname \"br-lan\" oifname \"{ts}\" ip saddr {{ {} }} return",
            format_v4_set(&layout.approved_subnets_v4)
        ));
    }
    forward.push(format!("oifname \"{ts}\" drop"));

    let input_hook = hook("filter", "input", FILTER);
    let pre_hook = hook("filter", "prerouting", MANGLE_PRE);
    let fwd_hook = hook("filter", "forward", FILTER);
    let nat_hook = hook("nat", "postrouting", SRCNAT);
    let dns_out_hook = hook("nat", "output", "dstnat");

    let mut chains: Vec<(&str, &str, Vec<String>)> = vec![
        ("input", input_hook.as_str(), input),
        ("prerouting", pre_hook.as_str(), prerouting),
        ("forward", fwd_hook.as_str(), forward),
    ];
    if let Some(port) = layout.clean_dns_dnat_port {
        chains.push((
            "dns_out",
            dns_out_hook.as_str(),
            vec![format!(
                "ip daddr {} meta l4proto {{ tcp, udp }} th dport {} dnat to {}:{port}",
                ids::CLEAN_DNS_ADDR,
                ids::CLEAN_DNS_PORT,
                ids::CLEAN_DNS_ADDR
            )],
        ));
    }
    let need_cellular_nat = layout.exit_v4 && layout.exit_uplink == ExitUplink::Cellular;
    let need_subnet_nat = !layout.approved_subnets_v4.is_empty();
    if need_cellular_nat || need_subnet_nat {
        let mut postrouting = vec![format!("oifname \"{}\" return", ids::RELAY_IFACE)];
        if need_cellular_nat {
            postrouting.push(format!("iifname \"{ts}\" oifname \"rmnet*\" masquerade"));
        }
        if need_subnet_nat {
            postrouting.push(format!(
                "iifname \"{ts}\" oifname \"br-lan\" ip daddr {{ {} }} masquerade",
                format_v4_set(&layout.approved_subnets_v4)
            ));
        }
        chains.push(("postrouting", nat_hook.as_str(), postrouting));
    }
    effect::table("ip", ids::TAILSCALE_NFT, &[], &chains)
}

fn v6_table(layout: &Layout) -> String {
    let ts = ids::TAILSCALE_IFACE;
    let ct_mark = format!("0x{:08x}", ids::TAILSCALE_CT_MARK);
    let input = vec![format!(
        "iifname != {{ \"{ts}\", \"lo\" }} ip6 saddr {} meta l4proto tcp th dport {{ {}, {} }} drop",
        ids::TAILNET_V6,
        ids::HTTP_PORT,
        ids::HTTPS_PORT
    )];
    let prerouting = vec![format!("iifname \"{ts}\" ct mark set ct mark or {ct_mark}")];
    let mut forward = vec![
        format!("iifname \"{ts}\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"),
        format!("oifname \"{ts}\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"),
        format!("iifname \"{ts}\" oifname \"{ts}\" drop"),
    ];
    if !layout.approved_subnets_v6.is_empty() {
        let approved = format_v6_set(&layout.approved_subnets_v6);
        forward.push(format!(
            "iifname \"{ts}\" oifname \"br-lan\" ip6 daddr {{ {approved} }} return"
        ));
        // Reject approved LAN destinations on any non-`br-lan` egress before
        // the general Exit Node allow rule so a globally routed IPv6 LAN prefix
        // can never leak out the physical uplink if the `br-lan` route disappears.
        forward.push(format!(
            "iifname \"{ts}\" ip6 daddr {{ {approved} }} drop"
        ));
    }
    if layout.exit_v6 {
        forward.push(format!(
            "iifname \"{ts}\" ip6 daddr {{ {} }} drop",
            ids::PRIVATE_V6.join(", ")
        ));
        forward.push(format!(
            "iifname \"{ts}\" oifname \"{}\" return",
            layout.exit_uplink.oifname()
        ));
    }
    forward.push(format!("iifname \"{ts}\" drop"));
    forward.push(format!("oifname \"{ts}\" ct state established,related return"));
    if !layout.approved_subnets_v6.is_empty() {
        forward.push(format!(
            "iifname \"br-lan\" oifname \"{ts}\" ip6 saddr {{ {} }} return",
            format_v6_set(&layout.approved_subnets_v6)
        ));
    }
    forward.push(format!("oifname \"{ts}\" drop"));

    let input_hook = hook("filter", "input", FILTER);
    let pre_hook = hook("filter", "prerouting", MANGLE_PRE);
    let fwd_hook = hook("filter", "forward", FILTER);
    let nat_hook = hook("nat", "postrouting", SRCNAT);

    let mut chains: Vec<(&str, &str, Vec<String>)> = vec![
        ("input", input_hook.as_str(), input),
        ("prerouting", pre_hook.as_str(), prerouting),
        ("forward", fwd_hook.as_str(), forward),
    ];
    let need_cellular_nat = layout.exit_v6 && layout.exit_uplink == ExitUplink::Cellular;
    let need_subnet_nat = !layout.approved_subnets_v6.is_empty();
    if need_cellular_nat || need_subnet_nat {
        let mut postrouting = vec![format!("oifname \"{}\" return", ids::RELAY_IFACE)];
        if need_cellular_nat {
            postrouting.push(format!("iifname \"{ts}\" oifname \"rmnet*\" masquerade"));
        }
        if need_subnet_nat {
            postrouting.push(format!(
                "iifname \"{ts}\" oifname \"br-lan\" ip6 daddr {{ {} }} masquerade",
                format_v6_set(&layout.approved_subnets_v6)
            ));
        }
        chains.push(("postrouting", nat_hook.as_str(), postrouting));
    }
    effect::table("ip6", ids::TAILSCALE_NFT, &[], &chains)
}

fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn legacy_forward_chain(tool: LegacyTool, has_subnets: bool) -> Resource {
    let ts = ids::TAILSCALE_IFACE;
    let mut rules = vec![
        words(&["-i", ts, "-j", "ACCEPT"]),
        words(&["-o", ts, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]),
    ];
    if has_subnets {
        rules.push(words(&["-i", "br-lan", "-o", ts, "-j", "ACCEPT"]));
    }
    Resource::LegacyChain(LegacyChain {
        tool,
        table: "filter".into(),
        name: ids::TAILSCALE_FWD_CHAIN.into(),
        rules,
    })
}

fn verified_v4_rule(net: Ipv4Net) -> Resource {
    Resource::Rule(Rule {
        family: Family::V4,
        priority: ids::TAILSCALE_DEST_PREF.parse().unwrap(),
        to: Some(net.to_string()),
        mark: Some(ids::TAILSCALE_NO_BYPASS_MARK.into()),
        action: RuleAction::Lookup(ids::TAILSCALE_TABLE.into()),
    })
}

fn verified_v6_rule() -> Resource {
    Resource::Rule(Rule {
        family: Family::V6,
        priority: ids::TAILSCALE_DEST_PREF.parse().unwrap(),
        to: Some(ids::TAILNET_V6.into()),
        mark: Some(ids::TAILSCALE_NO_BYPASS_MARK.into()),
        action: RuleAction::Lookup(ids::TAILSCALE_TABLE.into()),
    })
}

pub(super) fn cgnat_main_rule() -> Resource {
    Resource::Rule(Rule {
        family: Family::V4,
        priority: ids::TAILSCALE_CGNAT_MAIN_PREF.parse().unwrap(),
        to: Some(ids::TAILNET_V4.into()),
        mark: None,
        action: RuleAction::Lookup("main".into()),
    })
}

fn cgnat_guard_rule() -> Resource {
    Resource::Rule(Rule::unreachable(
        Family::V4,
        ids::TAILSCALE_CGNAT_GUARD_PREF.parse().unwrap(),
        ids::TAILNET_V4,
    ))
}

fn tun_rp_filter_sysctl() -> Resource {
    Resource::Sysctl(Sysctl {
        key: "tailscale0_rp_filter".into(),
        value: "0".into(),
    })
}

fn base_plan(nft_file: &Path, layout: &Layout, attach_tun: bool) -> Vec<Resource> {
    let ts = ids::TAILSCALE_IFACE;
    let mut resources = vec![
        Resource::Sysctl(Sysctl { key: "ip_forward".into(), value: "1".into() }),
        Resource::Sysctl(Sysctl { key: "ipv6_forwarding".into(), value: "1".into() }),
        Resource::Sysctl(Sysctl { key: "all_rp_filter".into(), value: "0".into() }),
    ];
    if attach_tun {
        resources.push(tun_rp_filter_sysctl());
    }
    resources.push(Resource::NftTable(NftTable {
        owner: "tailscale",
        name: ids::TAILSCALE_NFT,
        file: nft_file.to_path_buf(),
        families: Some(tables(layout)),
    }));
    for (tool, has_subnets) in [
        (LegacyTool::V4, !layout.approved_subnets_v4.is_empty()),
        (LegacyTool::V6, !layout.approved_subnets_v6.is_empty()),
    ] {
        resources.push(Resource::LegacyChain(LegacyChain {
            tool,
            table: "filter".into(),
            name: ids::TAILSCALE_IN_CHAIN.into(),
            rules: vec![words(&["-i", ts, "-j", "ACCEPT"])],
        }));
        resources.push(Resource::LegacyHook(LegacyHook {
            tool,
            table: "filter".into(),
            chain: "INPUT".into(),
            rule: words(&["-j", ids::TAILSCALE_IN_CHAIN]),
            position: Position::InsertFirst,
        }));
        resources.push(legacy_forward_chain(tool, has_subnets));
        resources.push(Resource::LegacyHook(LegacyHook {
            tool,
            table: "filter".into(),
            chain: "FORWARD".into(),
            rule: words(&["-j", ids::TAILSCALE_FWD_CHAIN]),
            position: Position::InsertFirst,
        }));
    }
    // Install 5131 (unreachable guard) and 5130 (CGNAT -> main) before 5110
    // so 5270 can never hijack unknown carrier CGNAT destinations.
    resources.push(cgnat_guard_rule());
    resources.push(cgnat_main_rule());
    resources.push(verified_v6_rule());
    for &net in &layout.verified_v4 {
        resources.push(verified_v4_rule(net));
    }
    resources
}

/// `@u60-tailscale-nft remove`: journal undo for `ip`/`ip6 u60_tail`.
pub(crate) fn nft_command(args: &[String]) -> Result<(), String> {
    match args {
        [action] if action == "remove" => {
            for family in FAMILIES {
                if NftDevice.list(family, ids::TAILSCALE_NFT)?.is_some() {
                    NftDevice.delete(family, ids::TAILSCALE_NFT)?;
                }
            }
            Ok(())
        }
        _ => Err("Invalid Tailscale nftables command".into()),
    }
}

/// Recover any leftover Tailscale kernel-TUN journal on startup, rollback, or
/// via `zte-agent network-recover`. Always stops any running/orphaned
/// `tailscaled` (userspace or kernel) and confirms process absence independently
/// of journal presence, and propagates cleanup and journal-inspection errors.
pub(crate) fn recover() -> Result<(), String> {
    let boot = net::boot_id();
    recover_with(
        Path::new(JOURNAL_PATH),
        &boot,
        super::supervisor::stop_all_tailscaled_and_confirm,
        super::supervisor::cleanup_and_verify_ts_policy_rules,
        super::supervisor::run_tailscaled_cleanup_checked,
        EffectSet::is_other_boot,
        EffectSet::recover,
        crate::netfx::conntrack::flush_clean_dns_dnat,
    )
}

pub(crate) fn dnat_flush_marker_path(journal_path: &Path) -> PathBuf {
    journal_path.with_file_name("clean-dns-dnat-flush-pending")
}

fn remove_dnat_flush_marker(marker: &Path) -> Result<(), String> {
    match std::fs::remove_file(marker) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {e}", marker.display())),
    }
}

fn complete_pending_dnat_flush(
    marker: &Path,
    current_boot: &str,
    flush_dnat: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let exists = marker
        .try_exists()
        .map_err(|e| format!("inspect {}: {e}", marker.display()))?;
    if !exists {
        return Ok(());
    }
    let raw = std::fs::read(marker)
        .map_err(|e| format!("read {}: {e}", marker.display()))?;
    // Discard as stale ONLY when both boot IDs are valid, NUL-free, single
    // printable-ASCII tokens and differ; any NUL byte, internal whitespace,
    // control char, non-UTF-8 byte, or empty/unreadable boot ID fails closed
    // and runs the conntrack flush before deleting the marker (matching
    // `tailscale_same_boot_flush_pending`).
    let stale_other_boot = matches!(
        (
            net::valid_boot_token(current_boot.as_bytes()),
            net::valid_boot_token(&raw),
        ),
        (Some(current), Some(recorded)) if recorded != current
    );
    if !stale_other_boot {
        flush_dnat()?;
    }
    remove_dnat_flush_marker(marker)
}

pub(super) fn recover_with(
    path: &Path,
    current_boot: &str,
    stop_daemons: impl FnOnce() -> Result<(), String>,
    cleanup_policy_rules: impl FnOnce() -> Result<(), String>,
    cleanup_tailscaled: impl FnOnce() -> Result<(), String>,
    is_other_boot: impl FnOnce(&Path) -> bool,
    recover_journal: impl FnOnce(&Path) -> Result<(), String>,
    flush_dnat: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let marker = dnat_flush_marker_path(path);
    stop_daemons()?;
    let exists = path
        .try_exists()
        .map_err(|e| format!("inspect {}: {e}", path.display()))?;
    if !exists {
        cleanup_policy_rules()?;
        // Complete any outstanding same-boot loopback Clean DNS NAT flush left
        // behind by an earlier `release()` or `recover()` that removed the
        // journal before the conntrack flush completed.
        return complete_pending_dnat_flush(&marker, current_boot, flush_dnat);
    }
    let same_boot = !is_other_boot(path);
    if same_boot {
        cleanup_tailscaled()?;
        // Persist a same-boot flush marker BEFORE `recover_journal` deletes
        // the journal so a retry after a failed conntrack flush still flushes.
        net::write_private(&marker, current_boot.as_bytes())?;
    }
    recover_journal(path)?;
    if path
        .try_exists()
        .map_err(|e| format!("re-check {}: {e}", path.display()))?
    {
        return Err(format!(
            "tailscale journal {} still exists after recovery",
            path.display()
        ));
    }
    complete_pending_dnat_flush(&marker, current_boot, flush_dnat)
}

fn rule_key_v4(net: Ipv4Net) -> Key {
    Key::Rule(
        Family::V4,
        ids::TAILSCALE_DEST_PREF.parse().unwrap(),
        Some(net.to_string()),
    )
}

/// Complete all stale (`tracked_v4 \ desired_v4`) AND previously-failed
/// (`pending_withdraw_v4` / `effects.withdrawing_keys()`) priority-5110
/// withdrawals BEFORE any subsequent declaration. Even if a peer reappears in
/// `desired_v4` while its prior withdrawal is still marked `withdrawing` in
/// `EffectSet`, finishing the withdrawal first avoids permanently poisoning
/// `EffectSet::declare_with` for both the returning peer and unrelated peers.
fn withdraw_pending_v4(
    effects: &mut EffectSet,
    tracked_v4: &mut BTreeSet<Ipv4Net>,
    pending_withdraw_v4: &mut BTreeSet<Ipv4Net>,
    desired_v4: &BTreeSet<Ipv4Net>,
    probe: &mut impl Probe,
) -> Result<bool, String> {
    let pref: u32 = ids::TAILSCALE_DEST_PREF.parse().unwrap();
    let mut to_withdraw: BTreeSet<Ipv4Net> = tracked_v4
        .iter()
        .copied()
        .filter(|net| !desired_v4.contains(net))
        .collect();
    to_withdraw.extend(pending_withdraw_v4.iter().copied());
    for key in effects.withdrawing_keys() {
        if let Key::Rule(Family::V4, p, Some(dst)) = key {
            if p == pref {
                if let Ok(net) = dst.parse::<Ipv4Net>() {
                    to_withdraw.insert(net);
                }
            }
        }
    }
    if to_withdraw.is_empty() {
        return Ok(false);
    }
    pending_withdraw_v4.extend(to_withdraw.iter().copied());
    let keys: Vec<Key> = to_withdraw.iter().copied().map(rule_key_v4).collect();
    let result = effects.withdraw_with(&keys, probe);
    for net in to_withdraw {
        if !effects.holds_key(&rule_key_v4(net)) {
            tracked_v4.remove(&net);
            pending_withdraw_v4.remove(&net);
        }
    }
    result.map(|()| true)
}

fn listing_has_chain(listing: &str, name: &str) -> bool {
    let prefix = format!("chain {name}");
    listing.lines().any(|raw| {
        let line = raw.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix(&prefix) else {
            return false;
        };
        rest.is_empty()
            || rest.starts_with(char::is_whitespace)
            || rest.starts_with('{')
    })
}

fn tokenize_nft_line(line: &str) -> Vec<&str> {
    let line = line.split('#').next().unwrap_or("").trim();
    let line = if let Some(pos) = line.find(" comment \"") {
        let tail = &line[pos + " comment \"".len()..];
        if tail.ends_with('"') && !tail[..tail.len() - 1].contains('"') {
            line[..pos].trim_end()
        } else {
            line
        }
    } else {
        line
    };
    let mut tokens = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
        } else if matches!(b, b'{' | b'}' | b',' | b';') {
            tokens.push(&line[i..i + 1]);
            i += 1;
        } else {
            let start = i;
            while i < bytes.len()
                && !bytes[i].is_ascii_whitespace()
                && !matches!(bytes[i], b'{' | b'}' | b',' | b';')
            {
                i += 1;
            }
            tokens.push(&line[start..i]);
        }
    }
    tokens
}

fn is_expected_dns_out_hook(tokens: &[&str]) -> bool {
    matches!(
        tokens,
        ["type", "nat", "hook", "output", "priority", "dstnat" | "-100", ";", "policy", "accept", ";"]
            | ["type", "nat", "hook", "output", "priority", "dstnat" | "-100", ";", "policy", "accept"]
    )
}

/// Strictly parses a complete `chain dns_out` rule line and returns the
/// protocols (`(tcp, udp)`) it redirects unconditionally from
/// `127.0.0.54:53` to `127.0.0.54:{port}`. Rejects ANY extra condition (such as
/// `oifname != "lo"`), wrong IP/port, or unrecognized token.
fn parse_exact_dns_out_rule(tokens: &[&str], port_str: &str, target: &str) -> Option<(bool, bool)> {
    let tokens = tokens.strip_suffix(&[";"]).unwrap_or(tokens);
    let rest = match tokens {
        ["ip", "daddr", addr, rest @ ..] if *addr == ids::CLEAN_DNS_ADDR => rest,
        _ => return None,
    };
    let (tcp, udp, rest) = match rest {
        ["meta", "l4proto", "{", a, ",", b, "}", "th", "dport", dp, rest @ ..]
            if *dp == port_str
                && ((*a == "tcp" && *b == "udp") || (*a == "udp" && *b == "tcp")) =>
        {
            (true, true, rest)
        }
        ["meta", "l4proto", proto @ ("tcp" | "udp"), "th", "dport", dp, rest @ ..]
            if *dp == port_str =>
        {
            (*proto == "tcp", *proto == "udp", rest)
        }
        [proto @ ("tcp" | "udp"), "dport", dp, rest @ ..] if *dp == port_str => {
            (*proto == "tcp", *proto == "udp", rest)
        }
        _ => return None,
    };
    let ok_action = match rest {
        ["dnat", "to", t] | ["dnat", "ip", "to", t] => *t == target,
        _ => false,
    };
    ok_action.then_some((tcp, udp))
}

/// Reads back `table ip u60_tail` and verifies the exact `chain dns_out` state:
/// - `Some(port)`: `chain dns_out` exists with an output NAT hook and contains
///   ONLY the exact unconditional TCP+UDP DNAT rule(s) redirecting
///   `127.0.0.54:53` to `127.0.0.54:{port}`.
/// - `None`: `table ip u60_tail` is readable and contains NO `chain dns_out`
///   fallback redirect (so direct port-53 bindings never lose queries to a stale
///   redirect).
fn verify_clean_dns_dnat_listing(
    nft: &mut (impl Nft + ?Sized),
    expected_port: Option<u16>,
) -> bool {
    let listing = match nft.list("ip", ids::TAILSCALE_NFT) {
        Ok(listing) => listing,
        Err(_) => return false,
    };
    let Some(port) = expected_port else {
        return listing.is_none_or(|text| !listing_has_chain(&text, "dns_out"));
    };
    let Some(listing) = listing else {
        return false;
    };
    if crate::netfx::effect::nft_table_is_dormant(&listing) {
        return false;
    }
    let port_str = ids::CLEAN_DNS_PORT.to_string();
    let target = format!("{}:{port}", ids::CLEAN_DNS_ADDR);
    let mut in_dns_out = false;
    let mut seen_dns_out = false;
    let mut depth: i32 = 0;
    let mut has_hook = false;
    let mut has_tcp = false;
    let mut has_udp = false;
    for raw in listing.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if !in_dns_out {
            if let Some(rest) = line.strip_prefix("chain dns_out") {
                if (rest.is_empty()
                    || rest.starts_with(char::is_whitespace)
                    || rest.starts_with('{'))
                    && line.contains('{')
                {
                    if seen_dns_out {
                        return false;
                    }
                    seen_dns_out = true;
                    in_dns_out = true;
                    depth = 1;
                }
            }
            continue;
        }
        let opens = line.chars().filter(|&c| c == '{').count() as i32;
        let closes = line.chars().filter(|&c| c == '}').count() as i32;
        if line == "}" {
            depth += opens - closes;
            if depth <= 0 {
                in_dns_out = false;
            }
            continue;
        }
        let tokens = tokenize_nft_line(line);
        if tokens.is_empty() {
            continue;
        }
        if !has_hook && is_expected_dns_out_hook(&tokens) {
            has_hook = true;
        } else if let Some((tcp, udp)) = parse_exact_dns_out_rule(&tokens, &port_str, &target) {
            has_tcp |= tcp;
            has_udp |= udp;
        } else {
            return false;
        }
        depth += opens - closes;
        if depth <= 0 {
            in_dns_out = false;
        }
    }
    seen_dns_out && !in_dns_out && has_hook && has_tcp && has_udp
}

enum PlaneState {
    Inactive,
    Active {
        effects: EffectSet,
        /// Last layout confirmed applied cleanly (all resources + nft readback).
        confirmed: Option<Layout>,
        /// Latest desired layout passed to `EffectSet`.
        desired: Layout,
        /// True whenever `desired` firewall rules have not yet been confirmed
        /// applied to `EffectSet` / `NftTables`; forces `reconcile` to declare
        /// `desired` first rather than replaying a stale open generation.
        firewall_dirty: bool,
        /// Last fallback DNAT port confirmed present on readback in `ip u60_tail`
        /// (`Some(None)` = no fallback DNAT needed; `Some(Some(p))` = verified `dns_out`
        /// targeting `127.0.0.54:p`; `None` = unconfirmed/lost). Tracked independently
        /// of `pending_add_v4` so peer-route addition failures never conflate with
        /// firewall DNAT readiness and vice versa.
        dnat_confirmed: Option<Option<u16>>,
        /// Every `5110` IPv4 destination rule tracked in `effects`, including
        /// entries from an earlier partially-failed update so they are withdrawn.
        tracked_v4: BTreeSet<Ipv4Net>,
        /// Any `5110` IPv4 rules whose withdrawal was attempted in `effects`
        /// and has not yet completed (tracked independently of `desired` so a
        /// returning peer finishes withdrawing before being re-declared).
        pending_withdraw_v4: BTreeSet<Ipv4Net>,
        /// Any `5110` IPv4 rules in `desired.verified_v4` whose declaration in
        /// `effects` failed and has not yet been confirmed installed.
        pending_add_v4: BTreeSet<Ipv4Net>,
        /// Whether `tailscale0_rp_filter=0` has been declared and confirmed.
        tun_attached: bool,
    },
    /// Previous teardown failed midway; remaining resources are marked
    /// `withdrawing` and must finish releasing before any new activation.
    CleanupPending {
        effects: EffectSet,
    },
}

pub(crate) struct NetPlane {
    journal_path: PathBuf,
    nft_file: PathBuf,
    state: PlaneState,
    /// True whenever a fallback `dns_out` NAT rule was previously active,
    /// changed, repaired, or torn down and loopback `127.0.0.54:53` conntrack
    /// entries have not yet been flushed afterward. Lives on `NetPlane` so it
    /// survives `release_with()`, `reconcile_with()`, and kernel/userspace
    /// mode switches.
    dnat_flush_needed: bool,
}

impl NetPlane {
    pub(crate) fn router() -> Self {
        // Start with `dnat_flush_needed = true` on a real router process so
        // same-boot agent restarts or out-of-process `network-recover` always
        // flush any surviving loopback `127.0.0.54:53` NAT conntrack mappings
        // before confirming the first Clean DNS binding.
        let mut plane = Self::at(PathBuf::from(JOURNAL_PATH), PathBuf::from(NFT_FILE_PATH));
        plane.dnat_flush_needed = true;
        plane
    }

    pub(crate) fn at(journal_path: PathBuf, nft_file: PathBuf) -> Self {
        Self {
            journal_path,
            nft_file,
            state: PlaneState::Inactive,
            dnat_flush_needed: false,
        }
    }

    pub(crate) fn is_confirmed(&self) -> bool {
        matches!(
            &self.state,
            PlaneState::Active {
                effects,
                confirmed: Some(_),
                firewall_dirty: false,
                pending_withdraw_v4,
                pending_add_v4,
                tun_attached: true,
                ..
            } if pending_withdraw_v4.is_empty()
                && pending_add_v4.is_empty()
                && effects.tables_confirmed(ids::TAILSCALE_NFT)
        )
    }

    pub(crate) fn confirmed_layout(&self) -> Option<&Layout> {
        match &self.state {
            PlaneState::Active {
                confirmed: Some(layout),
                tun_attached: true,
                ..
            } => Some(layout),
            _ => None,
        }
    }

    /// True when `ip u60_tail`'s `dns_out` state matches `expected_port`
    /// (`Some(port)` = exact fallback redirect confirmed; `None` = no owned
    /// fallback redirect active) AND no loopback NAT conntrack flush remains
    /// pending, tracked independently of `5110` peer rules.
    pub(crate) fn clean_dns_dnat_confirmed(&self, expected_port: Option<u16>) -> bool {
        if self.dnat_flush_needed {
            return false;
        }
        match (&self.state, expected_port) {
            (PlaneState::Inactive, None) => true,
            (
                PlaneState::Active {
                    effects,
                    firewall_dirty: false,
                    dnat_confirmed: Some(confirmed_port),
                    ..
                },
                expected,
            ) => *confirmed_port == expected && effects.tables_confirmed(ids::TAILSCALE_NFT),
            _ => false,
        }
    }

    /// Verifies and (if missing, tampered, dormant, stale, or port-changed)
    /// locally repairs the `chain dns_out` DNAT state in `ip u60_tail` without
    /// waiting on any LocalAPI or CLI call. Whenever a fallback DNAT rule was
    /// removed, changed, repaired, or torn down, flushes loopback
    /// `127.0.0.54:53` conntrack entries AFTER confirming the ruleset so reused
    /// UDP tuples cannot keep hitting a stale NAT destination.
    pub(crate) fn ensure_clean_dns_dnat(&mut self, expected_port: Option<u16>) -> Result<(), String> {
        self.ensure_clean_dns_dnat_with_flush(
            expected_port,
            &mut net::Device,
            &mut NftDevice,
            crate::netfx::conntrack::flush_clean_dns_dnat,
        )
    }

    #[cfg(test)]
    pub(crate) fn ensure_clean_dns_dnat_with(
        &mut self,
        expected_port: Option<u16>,
        probe: &mut impl Probe,
        nft: &mut (impl Nft + ?Sized),
    ) -> Result<(), String> {
        self.ensure_clean_dns_dnat_with_flush(expected_port, probe, nft, || Ok(()))
    }

    pub(crate) fn ensure_clean_dns_dnat_with_flush(
        &mut self,
        expected_port: Option<u16>,
        probe: &mut impl Probe,
        nft: &mut (impl Nft + ?Sized),
        mut flush_dnat_conntrack: impl FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let needs_repair = match &mut self.state {
            PlaneState::Active {
                effects,
                confirmed,
                desired,
                firewall_dirty,
                dnat_confirmed,
                ..
            } => {
                let listing_ok = verify_clean_dns_dnat_listing(nft, expected_port);
                if desired.clean_dns_dnat_port != expected_port
                    || *dnat_confirmed != Some(expected_port)
                    || !listing_ok
                {
                    // Any transition (Some -> None, None -> Some, Some(a) -> Some(b))
                    // or tampered/missing `dns_out` repair requires flushing
                    // loopback `127.0.0.54:53` conntrack after the ruleset is fixed.
                    self.dnat_flush_needed = true;
                }
                if desired.clean_dns_dnat_port != expected_port
                    || *firewall_dirty
                    || *dnat_confirmed != Some(expected_port)
                    || !effects.tables_confirmed(ids::TAILSCALE_NFT)
                    || !listing_ok
                {
                    desired.clean_dns_dnat_port = expected_port;
                    *firewall_dirty = true;
                    *dnat_confirmed = None;
                    *confirmed = None;
                    effects.invalidate_tables(ids::TAILSCALE_NFT);
                    true
                } else {
                    false
                }
            }
            PlaneState::Inactive | PlaneState::CleanupPending { .. } => {
                if expected_port.is_some() {
                    return Err("tailscale netplane is not active for fallback DNAT".into());
                }
                if !verify_clean_dns_dnat_listing(nft, None) {
                    self.dnat_flush_needed = true;
                    return Err("stale u60_tail dns_out fallback redirect is still active while Clean DNS uses port 53".into());
                }
                if self.dnat_flush_needed {
                    flush_dnat_conntrack().map_err(|err| {
                        format!("clean DNS fallback NAT conntrack flush failed: {err}")
                    })?;
                    remove_dnat_flush_marker(&dnat_flush_marker_path(&self.journal_path))?;
                    self.dnat_flush_needed = false;
                }
                return Ok(());
            }
        };
        if needs_repair {
            let _ = self.reconcile_with(probe, nft);
        }
        let table_ready = match &self.state {
            PlaneState::Active {
                effects,
                firewall_dirty: false,
                dnat_confirmed: Some(confirmed_port),
                ..
            } => {
                *confirmed_port == expected_port
                    && effects.tables_confirmed(ids::TAILSCALE_NFT)
                    && verify_clean_dns_dnat_listing(nft, expected_port)
            }
            _ => false,
        };
        if !table_ready {
            // Invalidate cached readiness and retain the conntrack-flush
            // obligation even when the first listing passed and the final
            // listing failed, so callers cannot keep reading delivery as ready
            // or skip the flush once listings recover.
            self.dnat_flush_needed = true;
            if let PlaneState::Active {
                effects,
                confirmed,
                firewall_dirty,
                dnat_confirmed,
                ..
            } = &mut self.state
            {
                *firewall_dirty = true;
                *dnat_confirmed = None;
                *confirmed = None;
                effects.invalidate_tables(ids::TAILSCALE_NFT);
            }
            return Err(match expected_port {
                Some(port) => format!("clean DNS fallback DNAT rule for port {port} is not confirmed"),
                None => "stale u60_tail dns_out fallback redirect could not be withdrawn".into(),
            });
        }
        if self.dnat_flush_needed {
            if let Err(err) = flush_dnat_conntrack() {
                if let PlaneState::Active {
                    dnat_confirmed,
                    confirmed,
                    ..
                } = &mut self.state
                {
                    *dnat_confirmed = None;
                    *confirmed = None;
                }
                return Err(format!("clean DNS fallback NAT conntrack flush failed: {err}"));
            }
            remove_dnat_flush_marker(&dnat_flush_marker_path(&self.journal_path))?;
            self.dnat_flush_needed = false;
        }
        if self.clean_dns_dnat_confirmed(expected_port) {
            Ok(())
        } else {
            Err("clean DNS DNAT delivery state is not confirmed".into())
        }
    }

    #[cfg(test)]
    pub(super) fn active(&self) -> bool {
        matches!(self.state, PlaneState::Active { .. })
    }

    /// Install the closed forwarding + CGNAT guard before spawning
    /// `tailscaled --tun=tailscale0` (without `tailscale0_rp_filter` yet).
    pub(crate) fn stage_closed_guard(
        &mut self,
        exit_uplink: ExitUplink,
        clean_dns_dnat_port: Option<u16>,
    ) -> Result<(), String> {
        self.sync_with(
            Layout::closed_guard(exit_uplink).with_clean_dns_dnat(clean_dns_dnat_port),
            false,
            &mut net::Device,
            &mut NftDevice,
        )
    }

    /// Apply locally known revocations (disabled Exit Node, removed advertised
    /// subnets, or uplink switch to Wi-Fi relay) even if LocalAPI full status
    /// is transiently unavailable.
    pub(crate) fn enforce_local_config(
        &mut self,
        cfg: &TsConfig,
        uplink: ExitUplink,
    ) -> Result<(), String> {
        self.enforce_local_config_with(cfg, uplink, &mut net::Device, &mut NftDevice)
    }

    pub(crate) fn enforce_local_config_with(
        &mut self,
        cfg: &TsConfig,
        uplink: ExitUplink,
        probe: &mut impl Probe,
        nft: &mut (impl Nft + ?Sized),
    ) -> Result<(), String> {
        let PlaneState::Active {
            desired,
            firewall_dirty,
            tracked_v4,
            pending_withdraw_v4,
            tun_attached,
            ..
        } = &self.state
        else {
            return Ok(());
        };
        let configured_v4: BTreeSet<Ipv4Net> = cfg
            .advertise_routes
            .iter()
            .filter(|r| config::normalize_route(r).is_ok())
            .filter_map(|r| r.parse::<IpNet>().ok())
            .filter_map(|n| match n.trunc() {
                IpNet::V4(v4) => Some(v4),
                IpNet::V6(_) => None,
            })
            .collect();
        let configured_v6: BTreeSet<Ipv6Net> = cfg
            .advertise_routes
            .iter()
            .filter(|r| config::normalize_route(r).is_ok())
            .filter_map(|r| r.parse::<IpNet>().ok())
            .filter_map(|n| match n.trunc() {
                IpNet::V6(v6) => Some(v6),
                IpNet::V4(_) => None,
            })
            .collect();
        let mut next = desired.clone();
        if !cfg.advertise_exit_node {
            next.exit_v4 = false;
            next.exit_v6 = false;
        }
        next.approved_subnets_v4.retain(|s| configured_v4.contains(s));
        next.approved_subnets_v6.retain(|s| configured_v6.contains(s));
        next.exit_uplink = uplink;
        let has_pending_withdraw = !pending_withdraw_v4.is_empty()
            || tracked_v4.iter().any(|net| !next.verified_v4.contains(net));
        if next == *desired && !*firewall_dirty && !has_pending_withdraw {
            return Ok(());
        }
        let attach = *tun_attached;
        self.sync_with(next, attach, probe, nft)
    }

    pub(crate) fn sync(&mut self, layout: Layout) -> Result<(), String> {
        self.sync_with(layout, true, &mut net::Device, &mut NftDevice)
    }

    pub(crate) fn sync_with(
        &mut self,
        layout: Layout,
        attach_tun: bool,
        probe: &mut impl Probe,
        nft: &mut (impl Nft + ?Sized),
    ) -> Result<(), String> {
        // Retry any pending teardown before claiming or activating again.
        if matches!(self.state, PlaneState::CleanupPending { .. }) {
            self.release_with(probe)?;
        }

        if matches!(self.state, PlaneState::Inactive) {
            if self.journal_path.exists() {
                let same_boot = !EffectSet::is_other_boot(&self.journal_path);
                if same_boot {
                    let marker = dnat_flush_marker_path(&self.journal_path);
                    let boot = net::boot_id();
                    net::write_private(&marker, boot.as_bytes())
                        .map_err(|e| format!("write clean DNS flush marker: {e}"))?;
                }
                EffectSet::recover(&self.journal_path)?;
                if same_boot {
                    self.dnat_flush_needed = true;
                }
            }
            let checker = NftTables::new("tailscale", ids::TAILSCALE_NFT, self.nft_file.clone());
            if checker.presence(nft)? == Presence::Foreign {
                return Err(
                    "Tailscale's nftables table name u60_tail is in use by another program; nothing was changed"
                        .into(),
                );
            }
            let mut effects = EffectSet::new("tailscale", self.journal_path.clone());
            let plan = base_plan(&self.nft_file, &layout, attach_tun);
            // Activating fallback DNAT from `Inactive` (e.g. after an earlier
            // direct port-53 binding cleared the initial flush flag) must flush
            // existing loopback `127.0.0.54:53` conntrack entries before
            // confirming delivery, and retain that obligation even if initial
            // activation fails partially.
            if layout.clean_dns_dnat_port.is_some()
                || !verify_clean_dns_dnat_listing(nft, layout.clean_dns_dnat_port)
            {
                self.dnat_flush_needed = true;
            }
            if let Err(error) = effects.declare_with(plan, probe, nft) {
                self.state = PlaneState::CleanupPending { effects };
                let _ = self.release_with(probe);
                return Err(error);
            }
            if !effects.tables_confirmed(ids::TAILSCALE_NFT)
                || !verify_clean_dns_dnat_listing(nft, layout.clean_dns_dnat_port)
            {
                self.dnat_flush_needed = true;
                self.state = PlaneState::CleanupPending { effects };
                let _ = self.release_with(probe);
                return Err("Tailscale nftables batch did not read back".into());
            }
            let tracked_v4: BTreeSet<Ipv4Net> = layout.verified_v4.iter().copied().collect();
            let dnat_port = layout.clean_dns_dnat_port;
            self.state = PlaneState::Active {
                effects,
                confirmed: Some(layout.clone()),
                desired: layout,
                firewall_dirty: false,
                dnat_confirmed: Some(dnat_port),
                tracked_v4,
                pending_withdraw_v4: BTreeSet::new(),
                pending_add_v4: BTreeSet::new(),
                tun_attached: attach_tun,
            };
            return Ok(());
        }

        let PlaneState::Active {
            effects,
            confirmed,
            desired,
            firewall_dirty,
            dnat_confirmed,
            tracked_v4,
            pending_withdraw_v4,
            pending_add_v4,
            tun_attached,
        } = &mut self.state
        else {
            unreachable!("CleanupPending and Inactive handled above");
        };

        if desired.clean_dns_dnat_port != layout.clean_dns_dnat_port
            || *dnat_confirmed != Some(layout.clean_dns_dnat_port)
        {
            self.dnat_flush_needed = true;
        }

        let tables_ok = effects.tables_confirmed(ids::TAILSCALE_NFT);
        if !*firewall_dirty
            && *dnat_confirmed == Some(layout.clean_dns_dnat_port)
            && !self.dnat_flush_needed
            && pending_withdraw_v4.is_empty()
            && pending_add_v4.is_empty()
            && confirmed.as_ref() == Some(&layout)
            && *desired == layout
            && (*tun_attached || !attach_tun)
            && tables_ok
        {
            return Ok(());
        }

        // Track the latest desired layout independently from what is confirmed
        // so a subsequent revocation after a partial failure never takes an
        // equality shortcut and always supersedes pending targets/rules.
        let prev_confirmed = confirmed.take();
        *desired = layout.clone();

        let need_fw = *firewall_dirty
            || !tables_ok
            || *dnat_confirmed != Some(layout.clean_dns_dnat_port)
            || prev_confirmed
                .as_ref()
                .is_none_or(|prev| prev.firewall_changed(&layout));
        let mut fw_error: Option<String> = None;
        if need_fw {
            // Check the live `dns_out` state BEFORE overwriting the table: an
            // unrelated firewall update (e.g. uplink or subnet change) can
            // silently repair a tampered/wrong-port fallback rule, which still
            // leaves stale NAT conntrack mappings unless we schedule a flush.
            if !verify_clean_dns_dnat_listing(nft, layout.clean_dns_dnat_port) {
                self.dnat_flush_needed = true;
                effects.invalidate_tables(ids::TAILSCALE_NFT);
            }
            // Apply firewall updates in their own isolated declaration BEFORE
            // touching 5110 rules or sysctls, and do NOT abort stale 5110
            // withdrawal if this fails so both restrictive changes execute.
            *firewall_dirty = true;
            *dnat_confirmed = None;
            let fw_updates = vec![
                Resource::NftTable(NftTable {
                    owner: "tailscale",
                    name: ids::TAILSCALE_NFT,
                    file: self.nft_file.clone(),
                    families: Some(tables(&layout)),
                }),
                legacy_forward_chain(LegacyTool::V4, !layout.approved_subnets_v4.is_empty()),
                legacy_forward_chain(LegacyTool::V6, !layout.approved_subnets_v6.is_empty()),
            ];
            match effects.declare_with(fw_updates, probe, nft) {
                Ok(())
                    if effects.tables_confirmed(ids::TAILSCALE_NFT)
                        && verify_clean_dns_dnat_listing(nft, layout.clean_dns_dnat_port) =>
                {
                    *firewall_dirty = false;
                    *dnat_confirmed = Some(layout.clean_dns_dnat_port);
                }
                Ok(()) => {
                    self.dnat_flush_needed = true;
                    effects.invalidate_tables(ids::TAILSCALE_NFT);
                    fw_error = Some("Tailscale nftables batch did not read back".into());
                }
                Err(error) => {
                    if !verify_clean_dns_dnat_listing(nft, layout.clean_dns_dnat_port) {
                        self.dnat_flush_needed = true;
                    }
                    fw_error = Some(error);
                }
            }
        }

        // Withdraw revoked/stale AND previously-unfinished 5110 destinations
        // independently of `fw_error` and BEFORE declaring any new host
        // additions or interface sysctls.
        let desired_v4: BTreeSet<Ipv4Net> = layout.verified_v4.iter().copied().collect();
        pending_add_v4.retain(|net| desired_v4.contains(net));
        let withdraw_error = withdraw_pending_v4(
            effects,
            tracked_v4,
            pending_withdraw_v4,
            &desired_v4,
            probe,
        )
        .err();

        match (fw_error, withdraw_error) {
            (Some(fw), Some(wd)) => return Err(format!("{fw}; {wd}")),
            (Some(fw), None) => return Err(fw),
            (None, Some(wd)) => return Err(wd),
            (None, None) => {}
        }

        let mut updates = Vec::new();
        if attach_tun && !*tun_attached {
            updates.push(tun_rp_filter_sysctl());
        }
        let mut added_v4 = Vec::new();
        for &net in &desired_v4 {
            let held_in_effects = effects.holds_key(&rule_key_v4(net));
            let confirmed_present = held_in_effects
                && prev_confirmed
                    .as_ref()
                    .is_some_and(|prev| prev.verified_v4.contains(&net));
            if !confirmed_present || !tracked_v4.contains(&net) || pending_add_v4.contains(&net) {
                pending_add_v4.insert(net);
                added_v4.push(net);
                updates.push(verified_v4_rule(net));
            }
        }
        if !updates.is_empty() {
            let res = effects.declare_with(updates, probe, nft);
            for net in added_v4 {
                if effects.holds_key(&rule_key_v4(net)) {
                    tracked_v4.insert(net);
                    pending_add_v4.remove(&net);
                }
            }
            res?;
        }
        if attach_tun {
            *tun_attached = true;
        }
        if !effects.tables_confirmed(ids::TAILSCALE_NFT)
            || !verify_clean_dns_dnat_listing(nft, layout.clean_dns_dnat_port)
        {
            *firewall_dirty = true;
            *dnat_confirmed = None;
            self.dnat_flush_needed = true;
            effects.invalidate_tables(ids::TAILSCALE_NFT);
            return Err("Tailscale nftables batch did not read back".into());
        }
        *dnat_confirmed = Some(layout.clean_dns_dnat_port);
        *confirmed = Some(layout);
        Ok(())
    }

    pub(crate) fn reconcile(&mut self) -> Reconciled {
        self.reconcile_with(&mut net::Device, &mut NftDevice)
    }

    pub(crate) fn reconcile_with(
        &mut self,
        probe: &mut impl Probe,
        nft: &mut (impl Nft + ?Sized),
    ) -> Reconciled {
        match &mut self.state {
            PlaneState::Inactive => Reconciled::default(),
            PlaneState::Active {
                effects,
                confirmed,
                desired,
                firewall_dirty,
                dnat_confirmed,
                tracked_v4,
                pending_withdraw_v4,
                pending_add_v4,
                ..
            } => {
                let mut result = Reconciled::default();
                let desired_v4: BTreeSet<Ipv4Net> = desired.verified_v4.iter().copied().collect();
                pending_add_v4.retain(|net| desired_v4.contains(net));
                // Catch exact `dns_out` tampering (e.g. destination port changed
                // or extra match condition inserted while preserving marker and
                // rule count) unconditionally — even when `firewall_dirty` is
                // already set — so dirty repair never drops the conntrack flush
                // obligation.
                if !verify_clean_dns_dnat_listing(nft, desired.clean_dns_dnat_port) {
                    *firewall_dirty = true;
                    *dnat_confirmed = None;
                    *confirmed = None;
                    self.dnat_flush_needed = true;
                    effects.invalidate_tables(ids::TAILSCALE_NFT);
                }
                // If the latest desired firewall (e.g. a revocation or tampered
                // `dns_out` rule) has not yet superseded EffectSet's target, make
                // it authoritative FIRST so reconcile_selected can never replay an
                // older open generation or skip a tampered table.
                let mut fw_blocked = false;
                if *firewall_dirty {
                    *dnat_confirmed = None;
                    effects.invalidate_tables(ids::TAILSCALE_NFT);
                    let fw_updates = vec![
                        Resource::NftTable(NftTable {
                            owner: "tailscale",
                            name: ids::TAILSCALE_NFT,
                            file: self.nft_file.clone(),
                            families: Some(tables(desired)),
                        }),
                        legacy_forward_chain(LegacyTool::V4, !desired.approved_subnets_v4.is_empty()),
                        legacy_forward_chain(LegacyTool::V6, !desired.approved_subnets_v6.is_empty()),
                    ];
                    match effects.declare_with(fw_updates, probe, nft) {
                        Ok(())
                            if effects.tables_confirmed(ids::TAILSCALE_NFT)
                                && verify_clean_dns_dnat_listing(nft, desired.clean_dns_dnat_port) =>
                        {
                            *firewall_dirty = false;
                            *dnat_confirmed = Some(desired.clean_dns_dnat_port);
                        }
                        Ok(()) => {
                            effects.invalidate_tables(ids::TAILSCALE_NFT);
                            result
                                .failed
                                .push("tailscale firewall target: nftables did not read back".into());
                            fw_blocked = true;
                        }
                        Err(error) => {
                            result.failed.push(format!("tailscale firewall target: {error}"));
                            fw_blocked = true;
                        }
                    }
                }
                // Retry any pending stale OR unfinished priority-5110 withdrawals
                // independently of LocalAPI availability or firewall status.
                match withdraw_pending_v4(
                    effects,
                    tracked_v4,
                    pending_withdraw_v4,
                    &desired_v4,
                    probe,
                ) {
                    Ok(true) => result.restored.push("tailscale 5110 revoked rules".into()),
                    Ok(false) => {}
                    Err(error) => {
                        result
                            .failed
                            .push(format!("tailscale 5110 withdrawal: {error}"));
                    }
                }
                // Compute missing priority-5110 peer additions AFTER withdrawals
                // finish so a returning peer whose earlier withdrawal just
                // completed in this pass is immediately re-added instead of
                // being certified missing.
                for &net in &desired_v4 {
                    if !effects.holds_key(&rule_key_v4(net)) {
                        pending_add_v4.insert(net);
                    }
                }
                // Retry any previously-failed or newly-missing priority-5110
                // peer additions so reconciliation never certifies a layout with
                // missing peer rules.
                if !pending_add_v4.is_empty() {
                    let to_add: Vec<Ipv4Net> = pending_add_v4.iter().copied().collect();
                    let add_updates: Vec<Resource> =
                        to_add.iter().copied().map(verified_v4_rule).collect();
                    match effects.declare_with(add_updates, probe, nft) {
                        Ok(()) => {
                            for net in to_add {
                                if effects.holds_key(&rule_key_v4(net)) {
                                    tracked_v4.insert(net);
                                    pending_add_v4.remove(&net);
                                }
                            }
                            if pending_add_v4.is_empty() {
                                result.restored.push("tailscale 5110 peer rules".into());
                            }
                        }
                        Err(error) => {
                            for net in to_add {
                                if effects.holds_key(&rule_key_v4(net)) {
                                    tracked_v4.insert(net);
                                    pending_add_v4.remove(&net);
                                }
                            }
                            result.failed.push(format!("tailscale 5110 addition: {error}"));
                        }
                    }
                }
                if !fw_blocked {
                    result.extend(effects.reconcile_selected(|_| true, probe, nft));
                }
                let dnat_ok = verify_clean_dns_dnat_listing(nft, desired.clean_dns_dnat_port);
                let fw_failed = fw_blocked
                    || !effects.tables_confirmed(ids::TAILSCALE_NFT)
                    || !dnat_ok
                    || result.failed.iter().any(|f| {
                        f.contains(ids::TAILSCALE_NFT)
                            || f.contains("firewall")
                            || f.contains("nftables")
                    });
                if fw_failed {
                    *firewall_dirty = true;
                    *dnat_confirmed = None;
                    *confirmed = None;
                    if !dnat_ok {
                        self.dnat_flush_needed = true;
                    }
                    effects.invalidate_tables(ids::TAILSCALE_NFT);
                    if !dnat_ok && result.failed.is_empty() {
                        result
                            .failed
                            .push("tailscale clean DNS DNAT rule did not read back".into());
                    }
                } else {
                    *dnat_confirmed = Some(desired.clean_dns_dnat_port);
                    let all_desired_held = desired_v4
                        .iter()
                        .all(|net| effects.holds_key(&rule_key_v4(*net)));
                    if result.failed.is_empty()
                        && !*firewall_dirty
                        && pending_withdraw_v4.is_empty()
                        && pending_add_v4.is_empty()
                        && all_desired_held
                    {
                        *confirmed = Some(desired.clone());
                    } else {
                        *confirmed = None;
                    }
                }
                result
            }
            PlaneState::CleanupPending { .. } => {
                let mut result = Reconciled::default();
                if let Err(error) = self.release_with(probe) {
                    result.failed.push(format!("tailscale cleanup pending: {error}"));
                } else {
                    result.restored.push("tailscale cleanup completed".into());
                }
                result
            }
        }
    }

    pub(crate) fn release(&mut self) -> Result<(), String> {
        self.release_with(&mut net::Device)
    }

    pub(crate) fn release_with(&mut self, probe: &mut impl Probe) -> Result<(), String> {
        let previous = std::mem::replace(&mut self.state, PlaneState::Inactive);
        let mut effects = match previous {
            PlaneState::Inactive => return Ok(()),
            PlaneState::Active {
                effects,
                desired,
                dnat_confirmed,
                ..
            } => {
                // If fallback DNAT was active before teardown, preserve the
                // conntrack-flush obligation across Inactive so the next start
                // (e.g. userspace on direct port 53) flushes stale NAT entries
                // before declaring Clean DNS delivery ready.
                if desired.clean_dns_dnat_port.is_some()
                    || matches!(dnat_confirmed, Some(Some(_)))
                {
                    self.dnat_flush_needed = true;
                }
                effects
            }
            PlaneState::CleanupPending { effects } => effects,
        };
        if self.dnat_flush_needed {
            // Persist the same-boot flush marker BEFORE `effects.release_with`
            // removes `self.journal_path`, so OTA slot changes and recovery
            // invocations after normal teardown still complete the flush.
            let marker = dnat_flush_marker_path(&self.journal_path);
            let boot = net::boot_id();
            if let Err(error) = net::write_private(&marker, boot.as_bytes()) {
                self.state = PlaneState::CleanupPending { effects };
                return Err(format!("write clean DNS flush marker: {error}"));
            }
        }
        match effects.release_with(probe) {
            Ok(()) => {
                self.state = PlaneState::Inactive;
                Ok(())
            }
            Err(error) => {
                self.state = PlaneState::CleanupPending { effects };
                Err(error)
            }
        }
    }
}

#[cfg(test)]
#[path = "../wifi_relay/test_dir.rs"]
mod test_dir;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netfx::effect::fake::FakeNft;
    use crate::netfx::effect::testing::Kernel;
    use crate::tailscale::localapi::SelfStatus;

    fn sample_status(allowed: &[&str], primary: &[&str], exit_option: bool) -> Status {
        Status {
            backend_state: "Running".into(),
            tun: Some(true),
            auth_url: None,
            tailscale_ips: Some(vec!["100.75.1.1".into(), "fd7a:115c:a1e0::1".into()]),
            self_status: Some(SelfStatus {
                online: true,
                tailscale_ips: vec!["100.75.1.1".into()],
                allowed_ips: allowed.iter().map(|s| (*s).into()).collect(),
                primary_routes: primary.iter().map(|s| (*s).into()).collect(),
                exit_node_option: exit_option,
                ..SelfStatus::default()
            }),
            health: vec![],
            version: Some("1.104.7".into()),
        }
    }

    #[test]
    fn approved_routes_requires_both_local_config_and_control_plane_approval() {
        let mut cfg = TsConfig::default();
        cfg.advertise_routes = vec!["192.168.0.0/24".into(), "10.20.0.0/24".into(), "fd01::/64".into()];
        cfg.advertise_exit_node = true;

        // Pending routes (not in AllowedIPs / PrimaryRoutes) stay closed.
        let pending = sample_status(&["100.75.1.1/32"], &[], false);
        let res = approved_routes(&cfg, Some(&pending));
        assert!(res.subnets_v4.is_empty());
        assert!(res.subnets_v6.is_empty());
        assert!(!res.exit_v4 && !res.exit_v6);

        // Approved subnet + v4-only exit node.
        let approved = sample_status(
            &["100.75.1.1/32", "192.168.0.0/24", "fd01::/64", "0.0.0.0/0"],
            &["192.168.0.0/24"],
            true,
        );
        let res = approved_routes(&cfg, Some(&approved));
        assert_eq!(res.subnets_v4, ["192.168.0.0/24".parse::<Ipv4Net>().unwrap()]);
        assert_eq!(res.subnets_v6, ["fd01::/64".parse::<Ipv6Net>().unwrap()]);
        assert!(res.exit_v4 && !res.exit_v6);
    }

    #[test]
    fn verified_v4_targets_admits_only_verified_slash32_hosts_and_warns_on_overflow() {
        let status = sample_status(
            &["100.75.1.1/32", "100.64.0.0/11", "100.64.0.0/10", "192.168.0.0/24"],
            &[],
            false,
        );
        let peers = vec![
            PeerStatus {
                online: true,
                tailscale_ips: vec![
                    "100.88.2.3".into(),
                    "100.64.0.0/11".into(),
                    "fd7a:115c:a1e0::2".into(),
                ],
            },
            PeerStatus {
                online: false,
                tailscale_ips: vec!["100.90.4.5".into()],
            },
        ];
        let (targets, warning) = verified_v4_targets(Some(&status), &peers);
        let text: Vec<String> = targets.iter().map(ToString::to_string).collect();
        assert_eq!(
            text,
            [
                "100.75.1.1/32",
                "100.88.2.3/32",
                "100.90.4.5/32",
                "100.100.100.100/32",
            ]
        );
        assert!(warning.is_none());

        // Exceeding MAX_VERIFIED_V4 emits an explicit warning and keeps Quad100 + online peers first.
        let mut many_peers = Vec::new();
        for i in 0..(MAX_VERIFIED_V4 + 5) {
            let third = (i / 250) as u8;
            let fourth = ((i % 250) + 1) as u8;
            many_peers.push(PeerStatus {
                online: i < 10,
                tailscale_ips: vec![format!("100.80.{third}.{fourth}")],
            });
        }
        let (capped, warning) = verified_v4_targets(Some(&status), &many_peers);
        assert_eq!(capped.len(), MAX_VERIFIED_V4);
        assert!(capped.contains(&"100.100.100.100/32".parse().unwrap()));
        assert!(capped.contains(&"100.80.0.1/32".parse().unwrap()));
        assert!(warning.as_deref().is_some_and(|w| w.contains("exceeding")));
    }

    #[test]
    fn u60_tail_binds_subnets_to_br_lan_and_exit_node_to_selected_physical_uplink() {
        let closed = Layout::closed_guard(ExitUplink::Cellular);
        let [v4, v6] = tables(&closed);
        for text in [&v4, &v6] {
            assert!(text.contains("iifname != { \"tailscale0\", \"lo\" }"));
            assert!(text.contains("th dport { 9090, 9443 } drop"));
            assert!(text.contains("iifname \"tailscale0\" ct mark set ct mark or 0x02000000"));
            assert!(text.contains("iifname \"tailscale0\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"));
            assert!(text.contains("oifname \"tailscale0\" tcp flags syn / syn,rst tcp option maxseg size set rt mtu"));
            assert!(text.contains("iifname \"tailscale0\" drop"));
            assert!(text.contains("oifname \"tailscale0\" drop"));
            assert!(!text.contains("chain postrouting"));
            for reserved in ["fwd", "post", "c"] {
                assert!(!text.contains(&format!("chain {reserved} ")));
            }
        }
        assert!(v4.contains("iifname \"tailscale0\" ip daddr 198.18.0.0/16 reject"));

        // Cellular uplink Exit Node + approved LAN subnet
        let cellular_open = Layout {
            approved_subnets_v4: vec!["192.168.0.0/24".parse().unwrap()],
            approved_subnets_v6: vec!["fd01::/64".parse().unwrap()],
            exit_v4: true,
            exit_v6: true,
            exit_uplink: ExitUplink::Cellular,
            verified_v4: vec!["100.100.100.100/32".parse().unwrap()],
            clean_dns_dnat_port: None,
        };
        let [v4, v6] = tables(&cellular_open);
        assert!(v4.contains("iifname \"tailscale0\" oifname \"br-lan\" ip daddr { 192.168.0.0/24 } return"));
        assert!(v4.contains("iifname \"tailscale0\" oifname \"rmnet*\" return"));
        assert!(!v4.contains("oifname != \"br-lan\""));
        let ath_ret = v4.find("oifname \"ath20\" return").unwrap();
        let rmnet_masq = v4.find("iifname \"tailscale0\" oifname \"rmnet*\" masquerade").unwrap();
        let subnet_masq = v4.find("iifname \"tailscale0\" oifname \"br-lan\" ip daddr { 192.168.0.0/24 } masquerade").unwrap();
        assert!(ath_ret < rmnet_masq && rmnet_masq < subnet_masq);

        assert!(v6.contains("iifname \"tailscale0\" oifname \"br-lan\" ip6 daddr { fd01::/64 } return"));
        assert!(v6.contains("iifname \"tailscale0\" oifname \"rmnet*\" return"));
        assert!(v6.contains("iifname \"tailscale0\" oifname \"rmnet*\" masquerade"));
        assert!(v6.contains("iifname \"tailscale0\" oifname \"br-lan\" ip6 daddr { fd01::/64 } masquerade"));

        // Wi-Fi relay uplink Exit Node: strictly binds to ath20, never rmnet*
        let relay_open = Layout {
            exit_uplink: ExitUplink::Relay,
            approved_subnets_v4: Vec::new(),
            approved_subnets_v6: Vec::new(),
            ..cellular_open
        };
        let [rv4, rv6] = tables(&relay_open);
        for text in [&rv4, &rv6] {
            assert!(text.contains("iifname \"tailscale0\" oifname \"ath20\" return"));
            assert!(!text.contains("rmnet*"));
            assert!(!text.contains("chain postrouting"), "relay owns ath20 masquerade");
        }

        // Globally routed approved LAN prefixes with Exit Node enabled:
        // `br-lan` return MUST precede the non-`br-lan` drop for the same
        // approved prefixes, which MUST precede the general Exit Node uplink
        // allow rule in both IPv4 and IPv6.
        let global_lan_open = Layout {
            approved_subnets_v4: vec!["198.51.100.0/24".parse().unwrap()],
            approved_subnets_v6: vec!["2001:db8:1::/64".parse().unwrap()],
            exit_v4: true,
            exit_v6: true,
            exit_uplink: ExitUplink::Cellular,
            verified_v4: vec!["100.100.100.100/32".parse().unwrap()],
            clean_dns_dnat_port: None,
        };
        let [gv4, gv6] = tables(&global_lan_open);
        let gv4_lan = gv4
            .find("iifname \"tailscale0\" oifname \"br-lan\" ip daddr { 198.51.100.0/24 } return")
            .unwrap();
        let gv4_drop = gv4
            .find("iifname \"tailscale0\" ip daddr { 198.51.100.0/24 } drop")
            .unwrap();
        let gv4_exit = gv4
            .find("iifname \"tailscale0\" oifname \"rmnet*\" return")
            .unwrap();
        assert!(gv4_lan < gv4_drop && gv4_drop < gv4_exit);

        let gv6_lan = gv6
            .find("iifname \"tailscale0\" oifname \"br-lan\" ip6 daddr { 2001:db8:1::/64 } return")
            .unwrap();
        let gv6_drop = gv6
            .find("iifname \"tailscale0\" ip6 daddr { 2001:db8:1::/64 } drop")
            .unwrap();
        let gv6_exit = gv6
            .find("iifname \"tailscale0\" oifname \"rmnet*\" return")
            .unwrap();
        assert!(gv6_lan < gv6_drop && gv6_drop < gv6_exit);
    }

    #[test]
    fn netplane_stages_closed_guard_attaches_tun_and_supersedes_failed_open_on_revocation() {
        let dir = test_dir::TestDir::new("u60-ts-netplane-fsm");
        let journal = dir.path().join("network.json");
        let nft_file = dir.path().join("u60_tail.nft");
        let mut plane = NetPlane::at(journal.clone(), nft_file.clone());
        let mut kernel = Kernel::seeded();
        let mut nft = FakeNft::default();

        // Stage closed guard before tailscaled spawns (no tailscale0_rp_filter yet).
        plane
            .sync_with(Layout::closed_guard(ExitUplink::Cellular), false, &mut kernel, &mut nft)
            .unwrap();
        assert!(plane.active());
        assert!(!plane.is_confirmed(), "not confirmed until tailscale0 is attached");
        assert!(!kernel.settings.contains_key("tailscale0_rp_filter"));

        // Attach tailscale0 with closed layout.
        let closed = Layout {
            verified_v4: vec![
                "100.75.1.1/32".parse().unwrap(),
                "100.100.100.100/32".parse().unwrap(),
            ],
            ..Layout::closed_guard(ExitUplink::Cellular)
        };
        plane.sync_with(closed.clone(), true, &mut kernel, &mut nft).unwrap();
        assert!(plane.is_confirmed());
        assert_eq!(kernel.settings.get("tailscale0_rp_filter").map(String::as_str), Some("0"));

        // Simulate a failed open update (nft load fails after NftTables recorded open target).
        let open = Layout {
            exit_v4: true,
            verified_v4: vec![
                "100.75.1.1/32".parse().unwrap(),
                "100.88.2.3/32".parse().unwrap(),
                "100.100.100.100/32".parse().unwrap(),
            ],
            ..closed.clone()
        };
        nft.fail.push(("simulated load failure".into(), false));
        assert!(plane.sync_with(open, true, &mut kernel, &mut nft).is_err());
        assert!(!plane.is_confirmed());

        // Now revoke back to closed: fail nft load during revocation, then verify
        // reconcile installs the restrictive closed target (NEVER replays open!).
        nft.fail.push(("revocation load failed once".into(), false));
        assert!(plane.sync_with(closed.clone(), true, &mut kernel, &mut nft).is_err());
        let reconciled = plane.reconcile_with(&mut kernel, &mut nft);
        assert!(reconciled.failed.is_empty(), "{reconciled:?}");
        let v4 = nft.tables.get(&("ip".into(), ids::TAILSCALE_NFT.into())).unwrap();
        assert!(!v4.contains("oifname \"rmnet*\" return"), "reconcile must install closed target, never replay open");

        plane.sync_with(closed.clone(), true, &mut kernel, &mut nft).unwrap();
        assert!(plane.is_confirmed());
        let PlaneState::Active { tracked_v4, .. } = &plane.state else {
            panic!("expected active plane");
        };
        assert!(!tracked_v4.contains(&"100.88.2.3/32".parse().unwrap()), "partially tracked 5110 rule must be withdrawn");

        // Local config tightening works immediately even without LocalAPI full status.
        let open_cell = Layout {
            approved_subnets_v4: vec!["192.168.0.0/24".parse().unwrap()],
            exit_v4: true,
            exit_uplink: ExitUplink::Cellular,
            ..closed.clone()
        };
        plane.sync_with(open_cell, true, &mut kernel, &mut nft).unwrap();
        let mut cfg = TsConfig::default();
        cfg.advertise_exit_node = false;
        cfg.advertise_routes.clear();
        plane.enforce_local_config_with(&cfg, ExitUplink::Relay, &mut kernel, &mut nft).unwrap();
        let v4 = nft.tables.get(&("ip".into(), ids::TAILSCALE_NFT.into())).unwrap();
        assert!(!v4.contains("192.168.0.0/24"));
        assert!(!v4.contains("rmnet*"));

        // Simultaneous firewall failure + peer removal MUST still withdraw the
        // revoked peer's priority-5110 rule independently and report the error.
        let with_peer = Layout {
            verified_v4: vec![
                "100.75.1.1/32".parse().unwrap(),
                "100.100.100.100/32".parse().unwrap(),
            ],
            exit_v4: true,
            exit_uplink: ExitUplink::Relay,
            ..closed.clone()
        };
        plane.sync_with(with_peer, true, &mut kernel, &mut nft).unwrap();
        nft.fail.push(("firewall update failed".into(), false));
        let revoke_both = Layout {
            verified_v4: vec!["100.100.100.100/32".parse().unwrap()],
            exit_v4: false,
            exit_uplink: ExitUplink::Relay,
            ..closed.clone()
        };
        assert!(plane.sync_with(revoke_both, true, &mut kernel, &mut nft).is_err());
        let PlaneState::Active { tracked_v4, .. } = &plane.state else {
            panic!("expected active plane");
        };
        assert!(
            !tracked_v4.contains(&"100.75.1.1/32".parse().unwrap()),
            "revoked peer 5110 rule must be withdrawn even when firewall update fails"
        );
        plane.reconcile_with(&mut kernel, &mut nft);
        let with_peer_again = Layout {
            verified_v4: vec![
                "100.75.1.1/32".parse().unwrap(),
                "100.100.100.100/32".parse().unwrap(),
            ],
            exit_uplink: ExitUplink::Relay,
            ..closed.clone()
        };
        plane.sync_with(with_peer_again, true, &mut kernel, &mut nft).unwrap();

        // Simultaneous peer removal + failing peer addition MUST still withdraw
        // the revoked peer's priority-5110 rule first.
        let fail_add = verified_v4_rule("100.99.9.9/32".parse().unwrap())
            .command()
            .unwrap();
        kernel.apply_error = Some(fail_add);
        let replace_peer = Layout {
            verified_v4: vec![
                "100.99.9.9/32".parse().unwrap(),
                "100.100.100.100/32".parse().unwrap(),
            ],
            exit_uplink: ExitUplink::Relay,
            ..closed.clone()
        };
        assert!(plane.sync_with(replace_peer, true, &mut kernel, &mut nft).is_err());
        let PlaneState::Active { tracked_v4, .. } = &plane.state else {
            panic!("expected active plane");
        };
        assert!(
            !tracked_v4.contains(&"100.75.1.1/32".parse().unwrap()),
            "removed peer 5110 rule must be withdrawn even when adding a new peer fails"
        );
        kernel.apply_error = None;

        // Failed 5110 withdrawal MUST be retried by reconcile_with AND
        // enforce_local_config_with even when desired has not changed and no
        // new LocalAPI status arrives.
        let with_peer2 = Layout {
            verified_v4: vec![
                "100.75.1.2/32".parse().unwrap(),
                "100.100.100.100/32".parse().unwrap(),
            ],
            exit_uplink: ExitUplink::Relay,
            ..closed.clone()
        };
        plane.sync_with(with_peer2, true, &mut kernel, &mut nft).unwrap();
        let revoke_peer2 = Layout {
            verified_v4: vec!["100.100.100.100/32".parse().unwrap()],
            exit_uplink: ExitUplink::Relay,
            ..closed.clone()
        };
        kernel.undo_error = true;
        assert!(plane.sync_with(revoke_peer2, true, &mut kernel, &mut nft).is_err());
        let PlaneState::Active { tracked_v4, .. } = &plane.state else {
            panic!("expected active plane");
        };
        assert!(tracked_v4.contains(&"100.75.1.2/32".parse().unwrap()));
        // Re-try via reconcile_with once undo succeeds (no new full status).
        kernel.undo_error = false;
        let rec = plane.reconcile_with(&mut kernel, &mut nft);
        assert!(rec.failed.is_empty(), "{rec:?}");
        let PlaneState::Active { tracked_v4, .. } = &plane.state else {
            panic!("expected active plane");
        };
        assert!(
            !tracked_v4.contains(&"100.75.1.2/32".parse().unwrap()),
            "reconcile must retry and complete pending 5110 withdrawal from desired state"
        );

        // Same check for enforce_local_config_with when LocalAPI is unavailable:
        let with_peer3 = Layout {
            verified_v4: vec![
                "100.75.1.3/32".parse().unwrap(),
                "100.100.100.100/32".parse().unwrap(),
            ],
            exit_uplink: ExitUplink::Relay,
            ..closed.clone()
        };
        plane.sync_with(with_peer3, true, &mut kernel, &mut nft).unwrap();
        let revoke_peer3 = Layout {
            verified_v4: vec!["100.100.100.100/32".parse().unwrap()],
            exit_uplink: ExitUplink::Relay,
            ..closed.clone()
        };
        kernel.undo_error = true;
        assert!(plane.sync_with(revoke_peer3, true, &mut kernel, &mut nft).is_err());
        kernel.undo_error = false;
        plane
            .enforce_local_config_with(&TsConfig::default(), ExitUplink::Relay, &mut kernel, &mut nft)
            .unwrap();
        let PlaneState::Active { tracked_v4, .. } = &plane.state else {
            panic!("expected active plane");
        };
        assert!(
            !tracked_v4.contains(&"100.75.1.3/32".parse().unwrap()),
            "enforce_local_config must retry pending 5110 withdrawal even when config flags are unchanged"
        );

        // Returning peer after a failed withdrawal MUST finish withdrawing first
        // and then cleanly re-declare alongside unrelated newly verified peers.
        let returning_a: Ipv4Net = "100.75.1.4/32".parse().unwrap();
        let new_peer_b: Ipv4Net = "100.75.1.9/32".parse().unwrap();
        let with_a = Layout {
            verified_v4: vec![returning_a, "100.100.100.100/32".parse().unwrap()],
            exit_uplink: ExitUplink::Relay,
            ..closed.clone()
        };
        plane.sync_with(with_a, true, &mut kernel, &mut nft).unwrap();
        let without_a = Layout {
            verified_v4: vec!["100.100.100.100/32".parse().unwrap()],
            exit_uplink: ExitUplink::Relay,
            ..closed.clone()
        };
        kernel.undo_error = true;
        assert!(plane.sync_with(without_a, true, &mut kernel, &mut nft).is_err());
        // Before undo recovers, peer A returns in desired alongside new peer B.
        let return_a_and_b = Layout {
            verified_v4: vec![returning_a, new_peer_b, "100.100.100.100/32".parse().unwrap()],
            exit_uplink: ExitUplink::Relay,
            ..closed
        };
        kernel.undo_error = false;
        plane
            .sync_with(return_a_and_b, true, &mut kernel, &mut nft)
            .expect("returning peer must complete unfinished withdrawal and allow both A and B");
        let PlaneState::Active {
            tracked_v4,
            pending_withdraw_v4,
            ..
        } = &plane.state
        else {
            panic!("expected active plane");
        };
        assert!(pending_withdraw_v4.is_empty());
        assert!(tracked_v4.contains(&returning_a));
        assert!(tracked_v4.contains(&new_peer_b));
    }

    #[test]
    fn netplane_failed_release_enters_cleanup_pending_and_never_reports_false_success() {
        let dir = test_dir::TestDir::new("u60-ts-cleanup-pending");
        let journal = dir.path().join("network.json");
        let nft_file = dir.path().join("u60_tail.nft");
        let mut plane = NetPlane::at(journal, nft_file);
        let mut kernel = Kernel::seeded();
        let mut nft = FakeNft::default();

        let layout = Layout::closed_guard(ExitUplink::Cellular);
        plane.sync_with(layout.clone(), true, &mut kernel, &mut nft).unwrap();
        assert!(plane.is_confirmed());

        // Fail undo during release -> CleanupPending.
        kernel.undo_error = true;
        assert!(plane.release_with(&mut kernel).is_err());
        assert!(!plane.is_confirmed());
        // Next sync MUST fail while cleanup cannot complete (never return Ok(())!).
        assert!(plane.sync_with(layout.clone(), true, &mut kernel, &mut nft).is_err());
        assert!(!plane.is_confirmed());
        let pending = plane.reconcile_with(&mut kernel, &mut nft);
        assert!(!pending.failed.is_empty());

        // Once undo succeeds, reconcile finishes pending cleanup cleanly,
        // and a fresh sync on the cleaned kernel re-activates and confirms.
        kernel.undo_error = false;
        let finished = plane.reconcile_with(&mut kernel, &mut nft);
        assert!(finished.failed.is_empty(), "{finished:?}");
        assert!(!plane.active());
        let mut clean_kernel = Kernel::seeded();
        let mut clean_nft = FakeNft::default();
        plane.sync_with(layout, true, &mut clean_kernel, &mut clean_nft).unwrap();
        assert!(plane.is_confirmed());
    }

    #[test]
    fn netplane_rejects_foreign_table_without_mutating_kernel() {
        let dir = test_dir::TestDir::new("u60-ts-foreign");
        let journal = dir.path().join("network.json");
        let nft_file = dir.path().join("u60_tail.nft");
        let mut foreign_nft = FakeNft::default();
        foreign_nft
            .tables
            .insert(("ip".into(), ids::TAILSCALE_NFT.into()), "table ip u60_tail {\n}\n".into());
        let mut plane = NetPlane::at(journal, nft_file);
        let mut kernel = Kernel::seeded();
        let err = plane
            .sync_with(Layout::closed_guard(ExitUplink::Cellular), false, &mut kernel, &mut foreign_nft)
            .unwrap_err();
        assert!(err.contains("in use by another program"));
        assert!(!plane.active());
        assert!(kernel.commands.is_empty());
    }

    #[test]
    fn clean_dns_fallback_dnat_rule_only_emitted_when_configured() {
        let normal = Layout::closed_guard(ExitUplink::Cellular);
        let [v4_normal, v6_normal] = tables(&normal);
        assert!(!v4_normal.contains("dns_out"));
        assert!(!v6_normal.contains("dns_out"));

        let fallback = normal.with_clean_dns_dnat(Some(ids::CLEAN_DNS_FALLBACK_PORT));
        let [v4_fb, v6_fb] = tables(&fallback);
        assert!(v4_fb.contains("chain dns_out"));
        assert!(v4_fb.contains("type nat hook output priority dstnat; policy accept;"));
        assert!(v4_fb.contains("ip daddr 127.0.0.54 meta l4proto { tcp, udp } th dport 53 dnat to 127.0.0.54:1054"));
        assert!(!v6_fb.contains("dns_out"));

        // Missing `dns_out` with failed repair MUST drop `clean_dns_dnat_confirmed`
        // to false, and restore it only once repair confirms the table again.
        let dir = test_dir::TestDir::new("u60-ts-dnat-gate");
        let mut plane = NetPlane::at(dir.path().join("network.json"), dir.path().join("u60_tail.nft"));
        let mut kernel = Kernel::seeded();
        let mut nft = FakeNft::default();
        plane.sync_with(fallback.clone(), true, &mut kernel, &mut nft).unwrap();
        // Activating fallback DNAT from `Inactive` MUST still require a
        // loopback NAT conntrack flush before certifying delivery.
        assert!(!plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));
        plane
            .ensure_clean_dns_dnat_with(Some(ids::CLEAN_DNS_FALLBACK_PORT), &mut kernel, &mut nft)
            .unwrap();
        assert!(plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));
        assert!(!plane.clean_dns_dnat_confirmed(Some(1055)));

        // 1. Delete ONLY the `dns_out` rule (preserving the generation marker!)
        //    and fail nft reload -> MUST NOT reconfirm fallback DNAT!
        let key = ("ip".into(), ids::TAILSCALE_NFT.into());
        let original = nft.tables[&key].clone();
        let missing_rule = original.replace(
            "ip daddr 127.0.0.54 meta l4proto { tcp, udp } th dport 53 dnat to 127.0.0.54:1054",
            "",
        );
        assert_ne!(missing_rule, original);
        nft.tables.insert(key.clone(), missing_rule);
        nft.fail.push(("nft reload failed".into(), false));
        let failed_missing = plane.reconcile_with(&mut kernel, &mut nft);
        assert!(!failed_missing.failed.is_empty());
        assert!(
            !plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)),
            "deleted dns_out rule with surviving marker and failed repair must unconfirm DNAT"
        );
        let recovered1 = plane.reconcile_with(&mut kernel, &mut nft);
        assert!(recovered1.failed.is_empty(), "{recovered1:?}");
        // Repairing a lost/tampered `dns_out` via `reconcile_with` MUST keep
        // `clean_dns_dnat_confirmed` false until loopback NAT conntrack is flushed!
        assert!(
            !plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)),
            "reconcile repairing dns_out must gate confirmation on NAT conntrack flush"
        );
        plane
            .ensure_clean_dns_dnat_with(Some(ids::CLEAN_DNS_FALLBACK_PORT), &mut kernel, &mut nft)
            .unwrap();
        assert!(plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));

        // 2. Mutate ONLY the destination port (`1054 -> 9999`, preserving marker
        //    AND chain rule count = 1!) and fail nft reload -> MUST detect wrong
        //    port, invalidate confirmation, and require NAT conntrack flush
        //    before certifying fallback port 1054 again!
        let wrong_port = nft.tables[&key].replace("127.0.0.54:1054", "127.0.0.54:9999");
        assert_ne!(wrong_port, nft.tables[&key]);
        nft.tables.insert(key.clone(), wrong_port);
        nft.fail.push(("nft reload failed".into(), false));
        let failed_port = plane.reconcile_with(&mut kernel, &mut nft);
        assert!(!failed_port.failed.is_empty());
        assert!(
            !plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)),
            "tampered dns_out port with surviving marker must unconfirm DNAT"
        );
        let recovered2 = plane.reconcile_with(&mut kernel, &mut nft);
        assert!(recovered2.failed.is_empty(), "{recovered2:?}");
        assert!(nft.tables[&key].contains("127.0.0.54:1054"));
        assert!(
            !plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)),
            "repaired wrong fallback port must stay unconfirmed until conntrack flush succeeds"
        );
        assert!(plane
            .ensure_clean_dns_dnat_with_flush(
                Some(ids::CLEAN_DNS_FALLBACK_PORT),
                &mut kernel,
                &mut nft,
                || Err("conntrack busy".into()),
            )
            .is_err());
        assert!(!plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));
        plane
            .ensure_clean_dns_dnat_with(Some(ids::CLEAN_DNS_FALLBACK_PORT), &mut kernel, &mut nft)
            .unwrap();
        assert!(plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));

        // 3. Failing a new priority-5110 peer addition MUST NOT let reconcile
        //    certify `is_confirmed()`, while keeping `clean_dns_dnat_confirmed`
        //    true because the firewall itself succeeded; a later sync or reconcile
        //    installs the missing peer rule.
        let new_peer: Ipv4Net = "100.64.9.9/32".parse().unwrap();
        let with_peer = Layout {
            verified_v4: vec![new_peer, "100.100.100.100/32".parse().unwrap()],
            ..fallback
        };
        kernel.apply_error = Some(verified_v4_rule(new_peer).command().unwrap());
        assert!(plane.sync_with(with_peer.clone(), true, &mut kernel, &mut nft).is_err());
        assert!(!plane.is_confirmed());
        assert!(
            plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)),
            "peer-route failure must stay independent of verified firewall DNAT"
        );
        // Reconcile while RTNETLINK still fails MUST NOT certify `confirmed = desired`.
        let rec_still_failing = plane.reconcile_with(&mut kernel, &mut nft);
        assert!(!rec_still_failing.failed.is_empty());
        assert!(!plane.is_confirmed());

        // Once RTNETLINK recovers, an identical sync installs the missing peer rule.
        kernel.apply_error = None;
        plane
            .sync_with(with_peer, true, &mut kernel, &mut nft)
            .expect("identical sync must retry missing 5110 peer addition");
        assert!(plane.is_confirmed());
        let PlaneState::Active {
            effects,
            pending_add_v4,
            ..
        } = &plane.state
        else {
            panic!("expected active plane");
        };
        assert!(pending_add_v4.is_empty());
        assert!(effects.holds_key(&rule_key_v4(new_peer)));

        // 4. Extra match condition (e.g. `oifname != "lo"`) inserted into
        //    `dns_out` keeps every individual token, marker, and rule count = 1,
        //    but MUST fail exact readback verification and trigger reload!
        let excluded_lo = nft.tables[&key].replace(
            "ip daddr 127.0.0.54",
            "oifname != \"lo\" ip daddr 127.0.0.54",
        );
        assert_ne!(excluded_lo, nft.tables[&key]);
        nft.tables.insert(key.clone(), excluded_lo);
        nft.fail.push(("nft reload failed".into(), false));
        assert!(plane.ensure_clean_dns_dnat_with(Some(ids::CLEAN_DNS_FALLBACK_PORT), &mut kernel, &mut nft).is_err());
        assert!(!plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));
        plane
            .ensure_clean_dns_dnat_with(Some(ids::CLEAN_DNS_FALLBACK_PORT), &mut kernel, &mut nft)
            .expect("repair must overwrite tampered oifname rule");
        assert!(!nft.tables[&key].contains("oifname != \"lo\""));

        // 4b. A dormant `table ip u60_tail` preserves marker, hook, rule, and
        //     counts while Netfilter unregisters its base chains -> MUST fail
        //     fallback verification and reload an active table!
        let dormant = nft.tables[&key].replacen("{\n", "{\n\tflags dormant\n", 1);
        nft.tables.insert(key.clone(), dormant);
        nft.fail.push(("nft reload failed".into(), false));
        assert!(plane.ensure_clean_dns_dnat_with(Some(ids::CLEAN_DNS_FALLBACK_PORT), &mut kernel, &mut nft).is_err());
        assert!(!plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));
        plane
            .ensure_clean_dns_dnat_with(Some(ids::CLEAN_DNS_FALLBACK_PORT), &mut kernel, &mut nft)
            .expect("repair must replace dormant table with an active table");
        assert!(!nft.tables[&key].contains("flags dormant"));

        // 5. Switching from fallback port 1054 back to direct port 53 (`None`)
        //    MUST withdraw `chain dns_out` from `ip u60_tail` AND flush
        //    loopback `127.0.0.54:53` NAT conntrack entries before declaring
        //    direct delivery restored.
        nft.fail.push(("nft reload failed".into(), false));
        assert!(
            plane.ensure_clean_dns_dnat_with(None, &mut kernel, &mut nft).is_err(),
            "direct port-53 bind must fail closed while old dns_out redirect stays active"
        );
        assert!(!plane.clean_dns_dnat_confirmed(None));
        // Even after `dns_out` disappears, a failed conntrack NAT flush MUST
        // keep direct port-53 delivery unconfirmed!
        let mut flush_calls = 0usize;
        assert!(
            plane
                .ensure_clean_dns_dnat_with_flush(None, &mut kernel, &mut nft, || {
                    flush_calls += 1;
                    Err("conntrack busy".into())
                })
                .is_err(),
            "failed NAT conntrack flush after removing dns_out must fail closed"
        );
        assert_eq!(flush_calls, 1);
        assert!(!nft.tables[&key].contains("chain dns_out"));
        assert!(!plane.clean_dns_dnat_confirmed(None));
        // Once conntrack flush succeeds, direct port-53 delivery is confirmed!
        plane
            .ensure_clean_dns_dnat_with_flush(None, &mut kernel, &mut nft, || {
                flush_calls += 1;
                Ok(())
            })
            .expect("direct port-53 switch succeeds once old dns_out and NAT conntrack are cleared");
        assert_eq!(flush_calls, 2);
        assert!(plane.clean_dns_dnat_confirmed(None));
        assert!(!nft.tables[&key].contains("chain dns_out"));

        // 6. Reconcile returning-peer ordering: peer withdrawal fails, peer
        //    returns in `desired` while withdrawal is still pending, then undo
        //    recovers and `reconcile_with` runs -> MUST complete withdrawal AND
        //    re-install the peer's 5110 rule before confirming!
        let returning: Ipv4Net = "100.64.55.5/32".parse().unwrap();
        let with_ret = Layout {
            verified_v4: vec![returning, "100.100.100.100/32".parse().unwrap()],
            clean_dns_dnat_port: None,
            ..Layout::closed_guard(ExitUplink::Cellular)
        };
        let without_ret = Layout {
            verified_v4: vec!["100.100.100.100/32".parse().unwrap()],
            ..with_ret.clone()
        };
        plane.sync_with(with_ret.clone(), true, &mut kernel, &mut nft).unwrap();
        kernel.undo_error = true;
        assert!(plane.sync_with(without_ret, true, &mut kernel, &mut nft).is_err());
        // Peer returns while prior withdrawal is still failing.
        assert!(plane.sync_with(with_ret, true, &mut kernel, &mut nft).is_err());
        // Undo recovers -> `reconcile_with` finishes withdrawal AND re-adds peer!
        kernel.undo_error = false;
        let rec_ret = plane.reconcile_with(&mut kernel, &mut nft);
        assert!(rec_ret.failed.is_empty(), "{rec_ret:?}");
        assert!(plane.is_confirmed());
        let PlaneState::Active { effects, .. } = &plane.state else {
            panic!("expected active plane");
        };
        assert!(
            effects.holds_key(&rule_key_v4(returning)),
            "reconcile must re-install returning peer after completing prior withdrawal"
        );

        // 7. Releasing a NetPlane that had fallback DNAT active MUST carry the
        //    flush obligation across `Inactive` so the next userspace startup
        //    on port 53 must flush stale NAT conntrack before reporting ready!
        let fb_before_release = Layout::closed_guard(ExitUplink::Cellular)
            .with_clean_dns_dnat(Some(ids::CLEAN_DNS_FALLBACK_PORT));
        plane
            .sync_with(fb_before_release, true, &mut kernel, &mut nft)
            .unwrap();
        plane
            .ensure_clean_dns_dnat_with(Some(ids::CLEAN_DNS_FALLBACK_PORT), &mut kernel, &mut nft)
            .unwrap();
        plane.release_with(&mut kernel).unwrap();
        nft.tables.remove(&key);
        assert!(
            !plane.clean_dns_dnat_confirmed(None),
            "release after fallback DNAT must retain flush obligation across Inactive"
        );
        let mut inactive_flushes = 0usize;
        assert!(plane
            .ensure_clean_dns_dnat_with_flush(None, &mut kernel, &mut nft, || {
                inactive_flushes += 1;
                Err("conntrack busy".into())
            })
            .is_err());
        assert_eq!(inactive_flushes, 1);
        assert!(!plane.clean_dns_dnat_confirmed(None));
        plane
            .ensure_clean_dns_dnat_with_flush(None, &mut kernel, &mut nft, || {
                inactive_flushes += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(inactive_flushes, 2);
        assert!(plane.clean_dns_dnat_confirmed(None));

        // 8. An unrelated firewall update (uplink Cellular -> Relay with active
        //    Exit Node) that silently overwrites a wrong fallback port
        //    (`9999 -> 1054`) MUST reload the table AND schedule a conntrack
        //    flush instead of leaving `clean_dns_dnat_confirmed` true!
        let mut kernel2 = Kernel::seeded();
        let mut nft2 = FakeNft::default();
        let mut cell_fb = Layout::closed_guard(ExitUplink::Cellular)
            .with_clean_dns_dnat(Some(ids::CLEAN_DNS_FALLBACK_PORT));
        cell_fb.exit_v4 = true;
        plane.sync_with(cell_fb, true, &mut kernel2, &mut nft2).unwrap();
        plane
            .ensure_clean_dns_dnat_with(Some(ids::CLEAN_DNS_FALLBACK_PORT), &mut kernel2, &mut nft2)
            .unwrap();
        assert!(plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));
        let tampered_port = nft2.tables[&key].replace("127.0.0.54:1054", "127.0.0.54:9999");
        nft2.tables.insert(key.clone(), tampered_port);
        let mut relay_fb = Layout::closed_guard(ExitUplink::Relay)
            .with_clean_dns_dnat(Some(ids::CLEAN_DNS_FALLBACK_PORT));
        relay_fb.exit_v4 = true;
        plane.sync_with(relay_fb, true, &mut kernel2, &mut nft2).unwrap();
        assert!(nft2.tables[&key].contains("127.0.0.54:1054"));
        assert!(
            !plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)),
            "unrelated firewall update repairing a wrong fallback port must still require conntrack flush"
        );
        plane
            .ensure_clean_dns_dnat_with(Some(ids::CLEAN_DNS_FALLBACK_PORT), &mut kernel2, &mut nft2)
            .unwrap();
        assert!(plane.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));

        // 9. Fresh router NetPlane starts with `dnat_flush_needed = true` so
        //    same-boot recovery flushes stale fallback mappings before
        //    confirming the first direct port-53 or fallback binding.
        let router_plane = NetPlane::router();
        assert!(
            !router_plane.clean_dns_dnat_confirmed(None),
            "fresh router NetPlane must require initial conntrack flush before confirming direct port-53"
        );

        // 10. Activating fallback DNS from `Inactive` AFTER direct port-53 was
        //     already confirmed (so the initial flush flag is clear) MUST still
        //     require a conntrack flush before confirming, AND retain that flush
        //     obligation across a partial activation failure.
        let dir10 = test_dir::TestDir::new("u60-ts-dnat-inactive-fb");
        let mut plane10 = NetPlane::at(
            dir10.path().join("network.json"),
            dir10.path().join("u60_tail.nft"),
        );
        plane10.dnat_flush_needed = true;
        let mut k10 = Kernel::seeded();
        let mut nft10 = FakeNft::default();
        plane10
            .ensure_clean_dns_dnat_with(None, &mut k10, &mut nft10)
            .unwrap();
        assert!(plane10.clean_dns_dnat_confirmed(None));
        let fb10 = Layout::closed_guard(ExitUplink::Cellular)
            .with_clean_dns_dnat(Some(ids::CLEAN_DNS_FALLBACK_PORT));
        // Partial activation failure (nft table installed `dns_out`, then a
        // later base_plan rule fails) MUST persist the flush marker BEFORE
        // deleting `network.json`, leave `dnat_flush_needed` set, and keep
        // recovery blocked until the loopback NAT conntrack flush succeeds!
        let marker10 = dnat_flush_marker_path(&plane10.journal_path);
        k10.apply_error = Some(cgnat_main_rule().command().unwrap());
        assert!(plane10
            .sync_with(fb10.clone(), false, &mut k10, &mut nft10)
            .is_err());
        k10.apply_error = None;
        assert!(
            !plane10.journal_path.exists(),
            "partial activation teardown removed network.json"
        );
        assert!(
            marker10.exists(),
            "partial activation failure must persist flush marker before deleting journal"
        );
        assert!(
            !plane10.clean_dns_dnat_confirmed(None),
            "partial fallback activation failure must preserve flush obligation"
        );
        // Simulate post-failure OTA handoff: `release_with` returns early while
        // `Inactive`, and `recover_with` still flushes via the persisted marker.
        plane10.release_with(&mut k10).unwrap();
        let boot10 = net::boot_id();
        let mut partial_flushes = 0usize;
        assert!(recover_with(
            &plane10.journal_path,
            &boot10,
            || Ok(()),
            || Ok(()),
            || Ok(()),
            |_| false,
            |_| unreachable!("journal already deleted by partial activation teardown"),
            || {
                partial_flushes += 1;
                Err("conntrack busy after partial activation".into())
            },
        )
        .is_err());
        assert_eq!(partial_flushes, 1);
        assert!(marker10.exists());
        assert!(recover_with(
            &plane10.journal_path,
            &boot10,
            || Ok(()),
            || Ok(()),
            || Ok(()),
            |_| false,
            |_| unreachable!(),
            || {
                partial_flushes += 1;
                Ok(())
            },
        )
        .is_ok());
        assert_eq!(partial_flushes, 2);
        assert!(!marker10.exists());

        // Second activation error branch (`declare_with` succeeds including
        // its two-family generation readback, then the exact `dns_out` listing
        // fails so `sync_with` hits the second error branch) MUST also persist
        // the flush marker before deleting `network.json`.
        struct FailThirdPostLoadListNft<'a> {
            inner: &'a mut FakeNft,
            loaded: bool,
            post_load_lists: usize,
        }
        impl Nft for FailThirdPostLoadListNft<'_> {
            fn load(&mut self, file: &Path) -> Result<(), String> {
                self.loaded = true;
                self.inner.load(file)
            }
            fn list(&mut self, family: &str, name: &str) -> Result<Option<String>, String> {
                if self.loaded {
                    self.post_load_lists += 1;
                    // Calls 1 & 2 are `NftTables::load`'s two-family generation
                    // readbacks inside `declare_with`; call 3 is `sync_with`'s
                    // post-declare `verify_clean_dns_dnat_listing`.
                    if self.post_load_lists == 3 {
                        return Err("simulated post-declare dns_out readback error".into());
                    }
                }
                self.inner.list(family, name)
            }
            fn delete(&mut self, family: &str, name: &str) -> Result<(), String> {
                self.inner.delete(family, name)
            }
        }
        let mut nft10_rb = FakeNft::default();
        let mut fail_rb = FailThirdPostLoadListNft {
            inner: &mut nft10_rb,
            loaded: false,
            post_load_lists: 0,
        };
        let rb_err = plane10
            .sync_with(fb10.clone(), false, &mut k10, &mut fail_rb)
            .unwrap_err();
        assert_eq!(
            rb_err, "Tailscale nftables batch did not read back",
            "test must hit sync_with's second (post-declare readback) error branch"
        );
        assert!(fail_rb.loaded);
        assert_eq!(fail_rb.post_load_lists, 3);
        assert!(!plane10.journal_path.exists());
        assert!(
            marker10.exists(),
            "readback failure during activation must persist flush marker before deleting journal"
        );
        assert!(recover_with(
            &plane10.journal_path,
            &boot10,
            || Ok(()),
            || Ok(()),
            || Ok(()),
            |_| false,
            |_| unreachable!(),
            || {
                partial_flushes += 1;
                Err("conntrack busy after readback failure".into())
            },
        )
        .is_err());
        assert_eq!(partial_flushes, 3);
        assert!(marker10.exists());
        assert!(recover_with(
            &plane10.journal_path,
            &boot10,
            || Ok(()),
            || Ok(()),
            || Ok(()),
            |_| false,
            |_| unreachable!(),
            || {
                partial_flushes += 1;
                Ok(())
            },
        )
        .is_ok());
        assert_eq!(partial_flushes, 4);
        assert!(!marker10.exists());

        // Successful fallback activation from `Inactive` still requires flush!
        let mut k10b = Kernel::seeded();
        let mut nft10b = FakeNft::default();
        plane10.release_with(&mut k10b).unwrap();
        plane10.dnat_flush_needed = false;
        plane10
            .sync_with(fb10, false, &mut k10b, &mut nft10b)
            .unwrap();
        assert!(
            !plane10.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)),
            "activating fallback DNS from Inactive must require conntrack flush before confirming"
        );
        let mut fb_flushes = 0usize;
        plane10
            .ensure_clean_dns_dnat_with_flush(
                Some(ids::CLEAN_DNS_FALLBACK_PORT),
                &mut k10b,
                &mut nft10b,
                || {
                    fb_flushes += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(fb_flushes, 1);
        assert!(plane10.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));

        // 11. Dirty reconciliation observing a tampered wrong fallback port
        //     (`firewall_dirty == true` already) MUST still record the flush
        //     obligation and refuse `clean_dns_dnat_confirmed` until flushed!
        if let PlaneState::Active { firewall_dirty, .. } = &mut plane10.state {
            *firewall_dirty = true;
        }
        let wrong_port10 = nft10b.tables[&key].replace("127.0.0.54:1054", "127.0.0.54:9999");
        nft10b.tables.insert(key.clone(), wrong_port10);
        let rec10 = plane10.reconcile_with(&mut k10b, &mut nft10b);
        assert!(rec10.failed.is_empty(), "{rec10:?}");
        assert!(nft10b.tables[&key].contains("127.0.0.54:1054"));
        assert!(
            !plane10.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)),
            "dirty reconcile repairing wrong fallback port must still require conntrack flush"
        );
        plane10
            .ensure_clean_dns_dnat_with_flush(
                Some(ids::CLEAN_DNS_FALLBACK_PORT),
                &mut k10b,
                &mut nft10b,
                || {
                    fb_flushes += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(fb_flushes, 2);
        assert!(plane10.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));

        // 12. Standalone `recover_with` retry after journal removal + failed
        //     DNS conntrack flush MUST still execute the flush on same-boot
        //     retry, skip flush once clean (no journal and no marker), and
        //     clear a stale marker from a prior boot without running conntrack!
        let rec_dir = test_dir::TestDir::new("u60-ts-recover-flush-retry");
        let rec_journal = rec_dir.path().join("network.json");
        let rec_marker = dnat_flush_marker_path(&rec_journal);
        std::fs::write(&rec_journal, "{}").unwrap();
        let mut recover_flushes = 0usize;
        let first = recover_with(
            &rec_journal,
            "boot-A",
            || Ok(()),
            || Ok(()),
            || Ok(()),
            |_| false,
            |p| std::fs::remove_file(p).map_err(|e| e.to_string()),
            || {
                recover_flushes += 1;
                Err("conntrack busy".into())
            },
        );
        assert!(first.is_err(), "first recover must fail when DNS flush fails");
        assert!(!rec_journal.exists(), "journal was already removed");
        assert!(rec_marker.exists(), "same-boot flush marker must persist across failed flush");
        assert_eq!(recover_flushes, 1);

        let second = recover_with(
            &rec_journal,
            "boot-A",
            || Ok(()),
            || Ok(()),
            || Ok(()),
            |_| false,
            |_| unreachable!("journal no longer exists"),
            || {
                recover_flushes += 1;
                Err("conntrack still busy".into())
            },
        );
        assert!(second.is_err(), "retry without journal must still fail if DNS flush fails");
        assert!(rec_marker.exists());
        assert_eq!(recover_flushes, 2);

        let third = recover_with(
            &rec_journal,
            "boot-A",
            || Ok(()),
            || Ok(()),
            || Ok(()),
            |_| false,
            |_| unreachable!("journal no longer exists"),
            || {
                recover_flushes += 1;
                Ok(())
            },
        );
        assert!(third.is_ok(), "retry succeeds once DNS flush succeeds");
        assert!(!rec_marker.exists(), "marker must be removed once flush succeeds");
        assert_eq!(recover_flushes, 3);

        // Clean recovery (no journal, no marker) does not invoke conntrack.
        let fourth = recover_with(
            &rec_journal,
            "boot-A",
            || Ok(()),
            || Ok(()),
            || Ok(()),
            |_| false,
            |_| unreachable!(),
            || {
                recover_flushes += 1;
                Err("should not run flush when clean".into())
            },
        );
        assert!(fourth.is_ok());
        assert_eq!(recover_flushes, 3);

        // A stale marker from a previous boot is discarded without invoking conntrack.
        net::write_private(&rec_marker, b"boot-OLD").unwrap();
        let fifth = recover_with(
            &rec_journal,
            "boot-NEW",
            || Ok(()),
            || Ok(()),
            || Ok(()),
            |_| false,
            |_| unreachable!(),
            || {
                recover_flushes += 1;
                Err("should not flush across reboot".into())
            },
        );
        assert!(fifth.is_ok());
        assert!(!rec_marker.exists());
        assert_eq!(recover_flushes, 3);

        // An unreadable/empty current boot ID MUST NOT discard a non-empty
        // pending flush marker without completing the flush!
        net::write_private(&rec_marker, b"boot-A").unwrap();
        let sixth = recover_with(
            &rec_journal,
            "",
            || Ok(()),
            || Ok(()),
            || Ok(()),
            |_| false,
            |_| unreachable!(),
            || {
                recover_flushes += 1;
                Err("conntrack busy on unknown boot".into())
            },
        );
        assert!(sixth.is_err(), "unknown current boot ID must fail closed and run flush");
        assert!(rec_marker.exists(), "marker must survive failed flush when boot ID is unreadable");
        assert_eq!(recover_flushes, 4);

        let seventh = recover_with(
            &rec_journal,
            "",
            || Ok(()),
            || Ok(()),
            || Ok(()),
            |_| false,
            |_| unreachable!(),
            || {
                recover_flushes += 1;
                Ok(())
            },
        );
        assert!(seventh.is_ok(), "unknown current boot ID succeeds once flush succeeds");
        assert!(!rec_marker.exists());
        assert_eq!(recover_flushes, 5);

        // Malformed markers (NUL byte, internal space, multi-line, control
        // character, non-UTF-8) MUST ALL fail closed in Rust just like the
        // shell guard: run the flush, preserve the marker if the flush fails,
        // and delete it only after the flush succeeds!
        for bad_marker in [
            b"boot-A\0".as_slice(),
            b"boot-OLD extra\n".as_slice(),
            b"boot-OLD\nboot-EXTRA\n".as_slice(),
            b"boot-OLD\x0c\n".as_slice(),
            b"boot-OLD\xff\n".as_slice(),
        ] {
            let before = recover_flushes;
            net::write_private(&rec_marker, bad_marker).unwrap();
            let fail_res = recover_with(
                &rec_journal,
                "boot-A",
                || Ok(()),
                || Ok(()),
                || Ok(()),
                |_| false,
                |_| unreachable!(),
                || {
                    recover_flushes += 1;
                    Err("conntrack busy on malformed marker".into())
                },
            );
            assert!(
                fail_res.is_err(),
                "malformed marker {:?} must fail closed and run flush",
                String::from_utf8_lossy(bad_marker)
            );
            assert!(
                rec_marker.exists(),
                "malformed marker {:?} must survive failed flush",
                String::from_utf8_lossy(bad_marker)
            );
            assert_eq!(recover_flushes, before + 1);

            let ok_res = recover_with(
                &rec_journal,
                "boot-A",
                || Ok(()),
                || Ok(()),
                || Ok(()),
                |_| false,
                |_| unreachable!(),
                || {
                    recover_flushes += 1;
                    Ok(())
                },
            );
            assert!(
                ok_res.is_ok(),
                "malformed marker {:?} succeeds once flush completes",
                String::from_utf8_lossy(bad_marker)
            );
            assert!(!rec_marker.exists());
            assert_eq!(recover_flushes, before + 2);
        }

        // 13. On an already-confirmed plane, if the first listing passes and
        //     the final listing fails inside `ensure_clean_dns_dnat_with_flush`,
        //     it MUST invalidate cached readiness AND retain `dnat_flush_needed`
        //     so a later successful listing still executes the conntrack flush!
        struct FailNthListNft<'a> {
            inner: &'a mut FakeNft,
            fail_on_call: usize,
            calls: usize,
        }
        impl Nft for FailNthListNft<'_> {
            fn load(&mut self, file: &Path) -> Result<(), String> {
                self.inner.load(file)
            }
            fn list(&mut self, family: &str, name: &str) -> Result<Option<String>, String> {
                self.calls += 1;
                if self.calls == self.fail_on_call {
                    return Err("simulated final listing failure".into());
                }
                self.inner.list(family, name)
            }
            fn delete(&mut self, family: &str, name: &str) -> Result<(), String> {
                self.inner.delete(family, name)
            }
        }
        assert!(plane10.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));
        {
            let mut flaky = FailNthListNft {
                inner: &mut nft10b,
                fail_on_call: 2,
                calls: 0,
            };
            assert!(
                plane10
                    .ensure_clean_dns_dnat_with_flush(
                        Some(ids::CLEAN_DNS_FALLBACK_PORT),
                        &mut k10b,
                        &mut flaky,
                        || Ok(()),
                    )
                    .is_err(),
                "final listing failure must fail closed"
            );
            assert_eq!(flaky.calls, 2);
        }
        assert!(
            !plane10.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)),
            "final listing failure must immediately invalidate cached readiness"
        );
        let mut recovery_flushes = 0usize;
        plane10
            .ensure_clean_dns_dnat_with_flush(
                Some(ids::CLEAN_DNS_FALLBACK_PORT),
                &mut k10b,
                &mut nft10b,
                || {
                    recovery_flushes += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            recovery_flushes, 1,
            "later successful listing after final-check failure must still run conntrack flush"
        );
        assert!(plane10.clean_dns_dnat_confirmed(Some(ids::CLEAN_DNS_FALLBACK_PORT)));
    }
}
