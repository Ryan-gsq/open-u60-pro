//! An agent restart (owner choice Q1, `relay-mihomo-architecture.md`
//! section 6.1) takes over the connection the previous agent left working in
//! this boot instead of tearing it down and joining again. On B31 a
//! teardown waits for the hotspot's channel availability check, so a crash
//! used to cost about 84 s of relay and three core restarts (2026-11-10).
//!
//! What outlives the agent: the routes, tables and journals, and the
//! supplicant (its own SELinux domain clears the parent-death signal), so
//! the association holds, and so does the IPv6 client (`odhcp6c`). The DHCP
//! client runs in the agent's domain and dies with it: a new one renews the
//! same address on a fresh session path before the session is published.
//! IPv6 is taken over the same way; if it does not match, IPv6 alone is
//! rolled back and started again. IPv4 never stops. Anything else that does
//! not match ends the attempt, and the caller rolls back and restores as
//! before.

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

use super::{
    decode_ssid, input_guards, lease_change, lease_file, net, network_id, offload, power_save, read_lease, relay_layout,
    relay_plan, resolvers_acceptable, resume, start_dhcp, steering, validate_lease, wpa, Cmd, Helper, Lease,
    LeaseChange, Network, Session, EffectSet, IFACE, JOURNAL, ROOT,
};

/// How long the new DHCP client may take to renew the address.
const RENEW_WAIT: Duration = Duration::from_secs(10);

/// The session the previous agent left, taken over as it is.
pub(super) fn adopt(target: &resume::Resume, lan_ip: Ipv4Addr, lan_mask: Ipv4Addr) -> Result<Session, String> {
    let root = Path::new(JOURNAL);
    for name in ["wireless.json", "network.json", "dns.json"] {
        if !EffectSet::current(&root.join(name)) {
            return Err(format!("no {name} of this boot"));
        }
    }
    if !Path::new(&format!("/sys/class/net/{IFACE}")).exists() {
        return Err("the relay interface is gone".into());
    }
    let mut selected = associated(&wpa("status", &[])?, target)?;
    selected.signal = wpa("signal_poll", &[]).ok().and_then(|s| net::key(&s, "RSSI").and_then(|v| v.parse().ok())).unwrap_or(0);
    let supplicant = supplicant()?;
    let client = if target.ipv6 { super::ipv6::running_client() } else { None };
    let (old, installed) = installed_lease(Path::new(ROOT))?;
    let prefix = validate_lease(&installed, lan_ip, lan_mask)?;
    let address = format!("{}/{prefix}", installed.ip);
    if !Cmd::new("ip", &["-o", "-4", "addr", "show", "dev", IFACE]).run()?.split_whitespace().any(|w| w == address) {
        return Err("the lease's address is not on the relay interface".into());
    }
    // From here on the previous agent's helpers change: its monitors go,
    // its supplicant and IPv6 client stay.
    let spare: Vec<offload::Record> = std::iter::once(supplicant).chain(client.as_ref().map(|(c, _)| *c)).collect();
    super::stop_strays(&spare)?;
    let mut session = Session::new(root);
    session.supplicant = Some(Helper::Adopted(supplicant));
    // IPv6 right after the tables: its NAT66 goes back into them at once.
    let taken = take_over(&mut session, &installed, prefix, lan_ip, lan_mask)
        .and_then(|()| take_over_ipv6(&mut session, client, target.ipv6))
        .and_then(|()| session.uplink.finish_adopt())
        .and_then(|()| renew(&mut session, &installed, prefix));
    match taken {
        Ok(()) => {
            session.selected = Some(selected);
            if let Some(path) = lease_file(Path::new(ROOT), &old) {
                let _ = fs::remove_file(path);
            }
            Ok(session)
        }
        Err(e) => {
            // What this attempt started goes; the rollback (`recover`)
            // stops the supplicant and undoes the journals (IPv6's too:
            // `Upstream::stop` here could drop a journal it never loaded).
            session.offload.stop();
            session.ipv6.stop_client();
            net::stop_child(&mut session.dhcp);
            if let Some(path) = session.dhcp_session.take().and_then(|s| lease_file(Path::new(ROOT), &s)) {
                let _ = fs::remove_file(path);
            }
            session.supplicant = None;
            Err(e)
        }
    }
}

/// Re-takes the journaled resources (`EffectSet::adopt`: nothing that still
/// holds runs again).
fn take_over(session: &mut Session, installed: &Lease, prefix: u32, lan_ip: Ipv4Addr, lan_mask: Ipv4Addr) -> Result<(), String> {
    let root = Path::new(JOURNAL);
    *session.wireless.lock().unwrap() = EffectSet::load("relay", &root.join("wireless.json"))?;
    let mut guards = input_guards();
    guards.push(session.uplink.resource(None));
    adopt_resources(&mut session.wireless.lock().unwrap(), guards, &mut net::Device, &mut crate::netfx::effect::Device)?;
    session.network = EffectSet::load("relay", &root.join("network.json"))?;
    session.network.adopt(relay_plan(installed, prefix, lan_ip, lan_mask))?;
    session.routed = true;
    for step in steering::plan() {
        if let Err(e) = session.network.adopt(vec![step]) {
            crate::netlog!("[relay] receive steering not applied: {e}");
        }
    }
    session.dns = EffectSet::load("relay", &root.join("dns.json"))?;
    session.dns.adopt(super::portal::web_bypasses())?;
    session.dns.adopt(vec![super::resolver(installed)])?;
    // The previous tables keep working until here; IPv6 adds its part next.
    session.uplink.adopt(relay_layout(installed, lan_ip, lan_mask))
}

pub(crate) fn adopt_resources(set: &mut EffectSet, resources: Vec<super::Resource>, probe: &mut impl net::Probe, nft: &mut impl crate::netfx::effect::Nft) -> Result<(), String> {
    set.declare_with(resources, true, probe, nft)
}

/// A new DHCP client renews the same address (the old one died with the
/// previous agent); then power save and the hardware path are taken over.
fn renew(session: &mut Session, installed: &Lease, prefix: u32) -> Result<(), String> {
    let root = Path::new(JOURNAL);
    let (nonce, dhcp) = start_dhcp(Some(installed.ip))?;
    session.dhcp_session = Some(nonce.clone());
    session.dhcp = Some(dhcp);
    let renewed = wait_lease(&nonce)?;
    session.lease = Some(match lease_change(installed, Some(&renewed)) {
        LeaseChange::Same => installed.clone(),
        LeaseChange::Resolvers(next) if resolvers_acceptable(&next) => next,
        _ => return Err("the DHCP server answered with another lease".into()),
    });
    if power_save::auto_off(root) {
        let _ = session.power_save.set(&mut session.network, true);
    }
    let subnet = format!("{}/{prefix}", Ipv4Addr::from(u32::from(installed.ip) & u32::from(installed.subnet)));
    session.offload = offload::Runtime::adopt(&mut session.network, installed.gateway, subnet);
    Ok(())
}

/// The previous IPv6, taken over when its client still runs; otherwise (or
/// when it does not match) rolled back and started again.
fn take_over_ipv6(session: &mut Session, client: Option<(offload::Record, String)>, requested: bool) -> Result<(), String> {
    if let Some((client, id)) = client {
        let current = ["ipv6-setup.json", "ipv6-network.json"].iter().all(|name| EffectSet::current(&Path::new(JOURNAL).join(name)));
        let adopted = if current { session.ipv6.adopt(client, &id) } else { Err("no IPv6 journals of this boot".into()) };
        match adopted {
            Ok(()) => return Ok(()),
            Err(e) => {
                crate::netlog!("[relay] previous IPv6 not taken over ({e}); starting it again");
                session.ipv6.stop_client();
                session.ipv6 = super::ipv6::Upstream::new(session.uplink.clone());
            }
        }
    }
    super::ipv6::recover()?;
    session.ipv6.start(requested)
}

fn wait_lease(session: &str) -> Result<Lease, String> {
    let deadline = Instant::now() + RENEW_WAIT;
    loop {
        if let Ok(lease) = read_lease(session) {
            return Ok(lease);
        }
        if Instant::now() >= deadline {
            return Err("the DHCP server did not renew the address".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The upstream the supplicant is associated with, when it is the one the
/// owner left connected (`resume`).
fn associated(status: &str, target: &resume::Resume) -> Result<Network, String> {
    if net::key(status, "wpa_state") != Some("COMPLETED") {
        return Err("the supplicant is not associated".into());
    }
    let ssid = decode_ssid(net::key(status, "ssid").unwrap_or_default());
    if ssid != target.ssid {
        return Err("the supplicant is associated with another network".into());
    }
    let (security, key_mgmt) = match target.security.as_str() {
        "wpa2" => ("wpa2", "WPA2-PSK"),
        "open" => ("open", "NONE"),
        _ => return Err("unsupported security".into()),
    };
    if net::key(status, "key_mgmt") != Some(key_mgmt) {
        return Err("the association's security differs".into());
    }
    let bssid = net::key(status, "bssid").filter(|b| b.len() == 17 && b.split(':').all(|p| p.len() == 2 && p.bytes().all(|c| c.is_ascii_hexdigit()))).ok_or("no BSSID")?;
    let frequency: u32 = net::key(status, "freq").and_then(|f| f.parse().ok()).ok_or("no frequency")?;
    Ok(Network { id: network_id(bssid, frequency, &ssid), ssid, frequency, signal: 0, security, supported: true, bssid: bssid.into() })
}

/// The session's supplicant (`prepare` starts it with `wpa.conf`).
fn supplicant() -> Result<offload::Record, String> {
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc").map_err(|_| "Cannot list processes")?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else { continue };
        let args: Vec<String> = cmdline.split(|&b| b == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
        if session_supplicant(&args) {
            if let Some(start) = crate::netfx::exec::process_start(pid) {
                found.push(offload::Record { pid, start });
            }
        }
    }
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err("the relay's supplicant is not running".into()),
        _ => Err("more than one relay supplicant is running".into()),
    }
}

fn session_supplicant(args: &[String]) -> bool {
    let after = |flag: &str| args.windows(2).find(|w| w[0] == flag).map(|w| w[1].as_str());
    args.first().and_then(|a| a.rsplit('/').next()) == Some("wpa_supplicant")
        && after("-i") == Some(IFACE)
        && after("-c") == Some(&format!("{ROOT}/wpa.conf"))
}

/// The one lease the previous session's DHCP client wrote: its session id
/// and the lease.
fn installed_lease(dir: &Path) -> Result<(String, Lease), String> {
    let sessions = lease_sessions(dir);
    match sessions.as_slice() {
        [one] => {
            let path = lease_file(dir, one).ok_or("Invalid DHCP session")?;
            let lease = serde_json::from_slice(&fs::read(path).map_err(|_| "No DHCP lease")?).map_err(|_| "Invalid DHCP lease")?;
            Ok((one.clone(), lease))
        }
        [] => Err("no DHCP lease of the previous session".into()),
        _ => Err("more than one DHCP lease".into()),
    }
}

fn lease_sessions(dir: &Path) -> Vec<String> {
    let mut sessions: Vec<String> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.strip_prefix("ipv4-lease-")?.strip_suffix(".json").map(str::to_owned))
        .filter(|s| lease_file(dir, s).is_some())
        .collect();
    sessions.sort();
    sessions
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(ssid: &str, security: &str) -> resume::Resume {
        resume::Resume { ssid: ssid.into(), security: security.into(), bssid: "c0:a4:76:b1:f0:e4".into(), ipv6: true }
    }

    const STATUS: &str = "bssid=c0:a4:76:b1:f0:e4\nfreq=5260\nssid=W_Game\nid=0\nmode=station\npairwise_cipher=CCMP\nkey_mgmt=WPA2-PSK\nwpa_state=COMPLETED\nip_address=192.168.2.124\n";

    #[test]
    fn only_the_owners_completed_association_is_taken_over() {
        let n = associated(STATUS, &target("W_Game", "wpa2")).unwrap();
        assert_eq!((n.ssid.as_str(), n.frequency, n.security, n.bssid.as_str()), ("W_Game", 5260, "wpa2", "c0:a4:76:b1:f0:e4"));
        assert_eq!(n.id, network_id("c0:a4:76:b1:f0:e4", 5260, "W_Game"), "the id a scan gives the same BSS");
        assert!(associated(&STATUS.replace("COMPLETED", "SCANNING"), &target("W_Game", "wpa2")).is_err());
        assert!(associated(STATUS, &target("W", "wpa2")).is_err(), "another network");
        assert!(associated(STATUS, &target("W_Game", "open")).is_err(), "another security");
        assert!(associated(&STATUS.replace("bssid=c0:a4:76:b1:f0:e4\n", ""), &target("W_Game", "wpa2")).is_err());
        let escaped = STATUS.replace("ssid=W_Game", "ssid=\\xe9\\x85\\x92\\xe5\\xba\\x97");
        assert_eq!(associated(&escaped, &target("酒店", "wpa2")).unwrap().ssid, "酒店");
    }

    #[test]
    fn the_session_supplicant_is_told_from_recovery_and_other_ones() {
        let args = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();
        assert!(session_supplicant(&args(&format!("wpa_supplicant -D nl80211 -i {IFACE} -c {ROOT}/wpa.conf -qq"))));
        assert!(session_supplicant(&args(&format!("/usr/sbin/wpa_supplicant -D nl80211 -i {IFACE} -c {ROOT}/wpa.conf -qq"))));
        assert!(!session_supplicant(&args(&format!("wpa_supplicant -D nl80211 -i {IFACE} -c {ROOT}/recover.conf -qq"))));
        assert!(!session_supplicant(&args(&format!("wpa_supplicant -D nl80211 -i wlan0 -c {ROOT}/wpa.conf"))));
        assert!(!session_supplicant(&args("hostapd -i ath20 -c /tmp/zte-agent-relay/wpa.conf")));
    }

    #[test]
    fn exactly_one_previous_lease_is_taken() {
        let dir = std::env::temp_dir().join(format!("u60-adopt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(installed_lease(&dir).is_err(), "none");
        let a = "67092e919edacc2b4443865a63d75b32";
        let lease = r#"{"ip":"192.168.2.124","subnet":"255.255.255.0","gateway":"192.168.2.1","dns":["192.168.2.1"]}"#;
        fs::write(dir.join(format!("ipv4-lease-{a}.json")), lease).unwrap();
        fs::write(dir.join("ipv4-lease-short.json"), lease).unwrap();
        fs::write(dir.join(format!("ipv6-lease-{a}.json")), "{}").unwrap();
        let (session, taken) = installed_lease(&dir).unwrap();
        assert_eq!(session, a);
        assert_eq!(taken.ip, Ipv4Addr::new(192, 168, 2, 124));
        fs::write(dir.join(format!("ipv4-lease-{}.json", "0".repeat(32))), lease).unwrap();
        assert!(installed_lease(&dir).is_err(), "two sessions are not one connection");
        fs::remove_dir_all(&dir).unwrap();
    }
}
