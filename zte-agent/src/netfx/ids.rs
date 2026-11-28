//! Every network name and number the agent's features use
//! (`relay-mihomo-architecture.md` section 4.7). A test checks that none is
//! used twice; take a new one here before using it anywhere. Some entries
//! are listed only to be checked (the code spells them out in rules).
#![allow(dead_code)]

/// The relay's station interface. IPACM forwards only interfaces its
/// configuration lists, read once at boot; B31's factory file lists `ath20`
/// as a Wi-Fi interface (Category UNKNOWN, WlanMode full), so the relay is
/// offloaded without changing that file (2026-11-12). No name with `wlan`:
/// the vendor's Wi-Fi off waits for every such interface to disappear.
pub const RELAY_IFACE: &str = "ath20";
/// The comment on the relay's legacy rules in chains it does not own and
/// without a jump to one (the portal RETURN and the old IPv4 MASQUERADE undo): their
/// identity, since the station's name is one the vendor's files also list.
pub const RELAY_COMMENT: &str = "zte-agent-wifi-relay";

/// Route tables: Mihomo's local delivery of marked packets, the relay (IPv4
/// and IPv6), and tailscaled's own kernel-TUN table.
pub const MIHOMO_TABLE: &str = "60625";
pub const RELAY_TABLE: &str = "60631";
pub const TAILSCALE_TABLE: &str = "52";
/// Policy rule priorities (5100–5131, ahead of tailscaled's 5210–5270):
/// - 5100: Mihomo TPROXY local delivery
/// - 5110: Verified Tailnet destinations (non-bypass) -> table 52
/// - 5120: Active Wi-Fi relay catch-all -> table 60631
/// - 5130/5131: IPv4 CGNAT -> main, then unreachable guard ahead of 5270
pub const MIHOMO_PREF: &str = "5100";
pub const TAILSCALE_DEST_PREF: &str = "5110";
pub const RELAY_PREF: &str = "5120";
pub const TAILSCALE_CGNAT_MAIN_PREF: &str = "5130";
pub const TAILSCALE_CGNAT_GUARD_PREF: &str = "5131";
/// Previous policy rule priorities retired during same-boot adoption.
pub const LEGACY_MIHOMO_PREF: &str = "18620";
pub const LEGACY_RELAY_PREF: &str = "18640";
/// Metric of the relay's `main` default and unreachable guards (IPACM's
/// WAN trigger). Not 0: netifd replaces the cellular default at metric 0.
pub const RELAY_METRIC: &str = "60631";
/// TPROXY mark and mask (`mark and 0xffff00ff or 0x700`).
pub const TPROXY_MARK: &str = "0x700/0xff00";
/// The core's outbound socket mark (M13): the relay's DNS output chain lets
/// the core's own plain DNS keep its destination. B31's portal PREROUTING
/// can overwrite a transit mark with decimal 8880. Only test locally
/// generated OUTPUT here, never trust a mark on a forwarded packet.
pub const CORE_OUT_MARK: Option<u32> = Some(0x0100_0000);
/// Tailscale kernel TUN interface, bypass mark (bit 19) and conntrack origin bit.
pub const TAILSCALE_IFACE: &str = "tailscale0";
pub const TAILSCALE_NO_BYPASS_MARK: &str = "0x0/0x80000";
pub const TAILSCALE_CT_MARK: u32 = 0x0200_0000;
/// Tailscale's Quad100 service address (MagicDNS / PeerAPI).
pub const TAILSCALE_QUAD100: &str = "100.100.100.100/32";

/// nftables tables (one `ip` and one `ip6` table each).
pub const MIHOMO_NFT: &str = "u60_mihomo";
pub const RELAY_NFT: &str = "u60_relay";
pub const TAILSCALE_NFT: &str = "u60_tail";

/// Legacy iptables chains of the relay: only accepts that must pass the
/// vendor's DROP/REJECT (its denials are in `u60_relay`).
pub const RELAY_CHAINS: [&str; 4] = ["U60_RELAY_IN", "U60_RELAY_FWD", "U60_R6_IN", "U60_R6_FWD"];
/// Legacy iptables chains of Tailscale kernel TUN: accepts that pass vendor
/// INPUT/FORWARD rejects while `u60_tail` owns denials, MSS clamping and NAT.
pub const TAILSCALE_IN_CHAIN: &str = "U60_TS_IN";
pub const TAILSCALE_FWD_CHAIN: &str = "U60_TS_FWD";
pub const TAILSCALE_CHAINS: [&str; 2] = [TAILSCALE_IN_CHAIN, TAILSCALE_FWD_CHAIN];
/// Legacy chains of features that still write iptables themselves.
pub const WG_FORWARD_CHAIN: &str = "OPENU60_WG_FORWARD";
pub const WG_NAT_CHAIN: &str = "OPENU60_WG_NAT";
pub const TTL_CHAIN: &str = "OPENU60_TTL";
pub const OTHER_CHAINS: [&str; 3] = [WG_FORWARD_CHAIN, WG_NAT_CHAIN, TTL_CHAIN];

/// Mihomo's DNS listener, private download proxy, transparent proxy and
/// controller; Tailscale Clean DNS listener; the agent's HTTP and HTTPS listeners.
pub const DNS_PORT: u16 = 1053;
pub const CLEAN_DNS_ADDR: &str = "127.0.0.54";
pub const CLEAN_DNS_PORT: u16 = 53;
pub const CLEAN_DNS_FALLBACK_PORT: u16 = 1054;
pub const DOWNLOAD_PORT: u16 = 17893;
pub const TPROXY_PORT: u16 = 17894;
pub const CONTROLLER_PORT: u16 = 19090;
pub const HTTP_PORT: u16 = 9090;
pub const HTTPS_PORT: u16 = 9443;

pub const LOOPBACK_V4: &str = "127.0.0.0/8";
pub const TAILNET_V4: &str = "100.64.0.0/10";
pub const LINK_LOCAL_V4: &str = "169.254.0.0/16";
pub const MULTICAST_V4: &str = "224.0.0.0/4";
/// IPv4 that keeps the router's own routes while the relay carries the
/// default (the relay table throws it; IPA's `main` default guards it).
pub const LOCAL_ROUTES_V4: [&str; 3] = [TAILNET_V4, LINK_LOCAL_V4, MULTICAST_V4];
/// IPv4 DNS that stays with its destination: loopback, tailnet, link-local.
pub const LOCAL_DNS_V4: [&str; 3] = [LOOPBACK_V4, TAILNET_V4, LINK_LOCAL_V4];
/// IPv4 the proxy never takes: unspecified, private, CGNAT/tailnet,
/// loopback, link-local, multicast and reserved.
pub const PRIVATE_V4: [&str; 8] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    TAILNET_V4,
    LOOPBACK_V4,
    LINK_LOCAL_V4,
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/3",
];
pub const TAILNET_V6: &str = "fd7a:115c:a1e0::/48";
pub const LINK_LOCAL_V6: &str = "fe80::/10";
pub const MULTICAST_V6: &str = "ff00::/8";
/// IPv6 the proxy never takes: unspecified, loopback, ULA, link-local, multicast.
pub const PRIVATE_V6: [&str; 5] = ["::/128", "::1/128", "fc00::/7", LINK_LOCAL_V6, MULTICAST_V6];
/// Mihomo's fake-ip pool (`dns.fake-ip-range`) and its network.
pub const FAKE_IP_RANGE: &str = "198.18.0.1/16";
pub const FAKE_IP_NET: &str = "198.18.0.0/16";

#[cfg(test)]
mod tests {
    use super::*;

    fn distinct<T: PartialEq + std::fmt::Debug>(what: &str, values: &[T]) {
        for (at, value) in values.iter().enumerate() {
            assert!(!values[..at].contains(value), "{what} {value:?} is used twice");
        }
    }

    #[test]
    fn no_name_or_number_is_used_twice() {
        distinct("route table", &[MIHOMO_TABLE, RELAY_TABLE, TAILSCALE_TABLE]);
        distinct("policy priority", &[
            MIHOMO_PREF,
            TAILSCALE_DEST_PREF,
            RELAY_PREF,
            TAILSCALE_CGNAT_MAIN_PREF,
            TAILSCALE_CGNAT_GUARD_PREF,
            LEGACY_MIHOMO_PREF,
            LEGACY_RELAY_PREF,
        ]);
        let prefs: Vec<u32> = [
            MIHOMO_PREF,
            TAILSCALE_DEST_PREF,
            RELAY_PREF,
            TAILSCALE_CGNAT_MAIN_PREF,
            TAILSCALE_CGNAT_GUARD_PREF,
        ]
        .iter()
        .map(|p| p.parse().unwrap())
        .collect();
        assert!(prefs.windows(2).all(|w| w[0] < w[1]) && *prefs.last().unwrap() < 5210);
        assert!(!RELAY_IFACE.contains("wlan"), "the vendor's Wi-Fi off waits for every wlan interface");
        assert!(RELAY_COMMENT.starts_with("zte-agent"), "the comment identity `owned_rule` reads");
        distinct("nft table", &[MIHOMO_NFT, RELAY_NFT, TAILSCALE_NFT]);
        let chains: Vec<&str> = RELAY_CHAINS
            .iter()
            .chain(&TAILSCALE_CHAINS)
            .chain(&OTHER_CHAINS)
            .copied()
            .collect();
        distinct("legacy chain", &chains);
        distinct("port", &[
            DNS_PORT,
            CLEAN_DNS_PORT,
            CLEAN_DNS_FALLBACK_PORT,
            DOWNLOAD_PORT,
            TPROXY_PORT,
            CONTROLLER_PORT,
            HTTP_PORT,
            HTTPS_PORT,
        ]);
        assert!(chains.iter().all(|c| c.starts_with("U60_") || c.starts_with("OPENU60_")), "owned chains carry our prefix");
        assert!(["fwd", "post", "c"].iter().all(|reserved| ![MIHOMO_NFT, RELAY_NFT, TAILSCALE_NFT].contains(reserved)));
        if let Some(mark) = CORE_OUT_MARK {
            assert_eq!(mark & 0x40ff_ff00, 0, "clear of ZTE's, TPROXY's and Tailscale's bits");
            assert_eq!(mark.count_ones(), 1);
            assert_eq!(mark & TAILSCALE_CT_MARK, 0, "clear of Tailscale ct mark bit");
        }
        assert_eq!(TAILSCALE_CT_MARK & 0x40ff_ff00, 0);
        assert_eq!(TAILSCALE_CT_MARK.count_ones(), 1);
    }

    #[test]
    fn every_range_is_a_valid_network() {
        for range in PRIVATE_V4.iter().chain(&LOCAL_ROUTES_V4).chain(&LOCAL_DNS_V4).chain(&[FAKE_IP_NET]) {
            let net: ipnet::Ipv4Net = range.parse().unwrap();
            assert_eq!(net.trunc(), net, "{range}");
        }
        for range in PRIVATE_V6.iter().chain(&[TAILNET_V6]) {
            let net: ipnet::Ipv6Net = range.parse().unwrap();
            assert_eq!(net.trunc(), net, "{range}");
        }
        let pool: ipnet::Ipv4Net = FAKE_IP_RANGE.parse().unwrap();
        assert_eq!(pool.trunc().to_string(), FAKE_IP_NET);
    }
}
