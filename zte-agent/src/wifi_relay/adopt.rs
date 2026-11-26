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
    relay_plan, resolvers_acceptable, resume, start_dhcp, steering, validate_lease, wpa, Helper, Lease,
    LeaseChange, Network, Session, EffectSet, IFACE, JOURNAL, ROOT,
};

/// How long the new DHCP client may take to renew the address.
const RENEW_WAIT: Duration = Duration::from_secs(10);

/// The session the previous agent left, taken over as it is.
pub(super) fn adopt(target: &resume::Resume, lan_ip: Ipv4Addr, lan_mask: Ipv4Addr) -> Result<Session, String> {
    let root = Path::new(JOURNAL);
    for name in [super::journals::WIRELESS, super::journals::NETWORK, super::journals::DNS] {
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
    let ipv6_process = client.as_ref().map(|(process, _)| *process);
    adopt_session_with(
        Path::new(ROOT), selected,
        |installed| {
            let prefix = validate_lease(installed, lan_ip, lan_mask)?;
            if !crate::httpd::mobile::interfaces().map_err(|e| e.to_string())?.iter().any(|address| address.name == IFACE && address.addr == std::net::IpAddr::V4(installed.ip) && u32::from(address.prefix) == prefix) {
                return Err("the lease's address is not on the relay interface".into());
            }
            // From here on the previous agent's helpers change: its monitors go,
            // its supplicant and IPv6 client stay.
            let spare: Vec<offload::Record> = std::iter::once(supplicant).chain(ipv6_process).collect();
            super::stop_strays(&spare)?;
            let mut session = Session::new(root);
            session.supplicant = Some(Helper::Adopted(supplicant));
            Ok((session, prefix))
        },
        |session, installed, prefix| take_over(session, installed, prefix, lan_ip, lan_mask),
        |session| take_over_ipv6(session, client, target.ipv6),
        renew,
    )
}

fn adopt_session_with(
    runtime: &Path, selected: Network,
    prepare: impl FnOnce(&Lease) -> Result<(Session, u32), String>,
    take_over: impl FnOnce(&mut Session, &Lease, u32) -> Result<(), String>,
    take_over_ipv6: impl FnOnce(&mut Session) -> Result<(), String>,
    renew: impl FnOnce(&mut Session, &Lease, u32) -> Result<(), String>,
) -> Result<Session, String> {
    let (old, installed) = installed_lease(runtime)?;
    let (mut session, prefix) = prepare(&installed)?;
    // Stage IPv4 first. IPv6 takeover may confirm the combined tables before
    // finish_adopt reuses them or loads the layout in one batch.
    let taken = take_over(&mut session, &installed, prefix)
        .and_then(|()| take_over_ipv6(&mut session))
        .and_then(|()| session.uplink.finish_adopt())
        .and_then(|()| renew(&mut session, &installed, prefix));
    match taken {
        Ok(()) => {
            session.selected = Some(selected);
            if let Some(path) = lease_file(runtime, &old) {
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
            if let Some(path) = session.dhcp_session.take().and_then(|s| lease_file(runtime, &s)) {
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
    take_over_with(
        session, Path::new(JOURNAL), installed, (prefix, lan_ip, lan_mask),
        EffectSet::declare, retire_legacy_hook,
    )
}

fn take_over_with(
    session: &mut Session, root: &Path, installed: &Lease, lan: (u32, Ipv4Addr, Ipv4Addr),
    mut declare: impl FnMut(&mut EffectSet, Vec<super::Resource>) -> Result<(), String>,
    retire_legacy_hook: impl FnOnce(&mut EffectSet) -> Result<(), String>,
) -> Result<(), String> {
    let (prefix, lan_ip, lan_mask) = lan;
    *session.wireless.lock().unwrap() = EffectSet::load("relay", &root.join(super::journals::WIRELESS))?;
    let mut guards = input_guards();
    guards.push(session.uplink.resource(None));
    declare(&mut session.wireless.lock().unwrap(), guards)?;
    session.network = EffectSet::load("relay", &root.join(super::journals::NETWORK))?;
    // Remove precisely the old tagged rule before any declaration of nat4.
    retire_legacy_hook(&mut session.network)?;
    declare(&mut session.network, relay_plan(installed, prefix, lan_ip, lan_mask))?;
    session.routed = true;
    for step in steering::plan() {
        if let Err(e) = declare(&mut session.network, vec![step]) {
            crate::netlog!("[relay] receive steering not applied: {e}");
        }
    }
    session.dns = EffectSet::load("relay", &root.join(super::journals::DNS))?;
    declare(&mut session.dns, super::portal::web_bypasses())?;
    let redirect = super::portal::web_redirect(&session.dns);
    declare(&mut session.dns, redirect)?;
    declare(&mut session.dns, vec![super::resolver(installed)])?;
    // Verify the previous tables and stage IPv4 before IPv6 takeover.
    session.uplink.adopt(relay_layout(installed, lan_ip, lan_mask))
}

fn retire_legacy_hook(network: &mut EffectSet) -> Result<(), String> {
    let hook = super::LegacyHook {
        tool: super::LegacyTool::V4, table: "nat".into(), chain: "POSTROUTING".into(), position: super::Position::InsertFirst,
        rule: super::words(&["-o", IFACE, "-m", "comment", "--comment", crate::netfx::ids::RELAY_COMMENT, "-j", "MASQUERADE"]),
    };
    network.retire_legacy_hook(hook)
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
    session.offload = offload::Runtime::start(&mut session.network, installed.gateway, subnet);
    Ok(())
}

/// The previous IPv6, taken over when its client still runs; otherwise (or
/// when it does not match) rolled back and started again.
fn take_over_ipv6(session: &mut Session, client: Option<(offload::Record, String)>, requested: bool) -> Result<(), String> {
    take_over_ipv6_with(session, client, requested, Path::new(JOURNAL), Ipv6Takeover {
        adopt: |session: &mut Session, record, nonce: &str| session.ipv6.adopt(record, nonce),
        stop: |session: &mut Session| session.ipv6.stop_client(),
        recover: super::ipv6::recover,
        start: |session: &mut Session, requested| session.ipv6.start(requested),
    })
}

struct Ipv6Takeover<A, S, R, N> {
    adopt: A,
    stop: S,
    recover: R,
    start: N,
}

fn take_over_ipv6_with(
    session: &mut Session, client: Option<(offload::Record, String)>, requested: bool, journal: &Path,
    steps: Ipv6Takeover<
        impl FnOnce(&mut Session, offload::Record, &str) -> Result<(), String>,
        impl FnOnce(&mut Session),
        impl FnOnce() -> Result<(), String>,
        impl FnOnce(&mut Session, bool) -> Result<(), String>,
    >,
) -> Result<(), String> {
    if let Some((client, id)) = client {
        let current = [super::journals::V6_SETUP, super::journals::V6_NETWORK].iter().all(|name| EffectSet::current(&journal.join(name)));
        let adopted = if current { (steps.adopt)(session, client, &id) } else { Err("no IPv6 journals of this boot".into()) };
        match adopted {
            Ok(()) => return Ok(()),
            Err(e) => {
                crate::netlog!("[relay] previous IPv6 not taken over ({e}); starting it again");
                (steps.stop)(session);
                session.ipv6 = super::ipv6::Upstream::new(session.uplink.clone());
            }
        }
    }
    (steps.recover)()?;
    (steps.start)(session, requested)
}

fn wait_lease(session: &str) -> Result<Lease, String> {
    wait_lease_with(|| read_lease(session), Instant::now, std::thread::sleep)
}

fn wait_lease_with(
    mut read: impl FnMut() -> Result<Lease, String>, mut now: impl FnMut() -> Instant,
    mut sleep: impl FnMut(Duration),
) -> Result<Lease, String> {
    let deadline = now() + RENEW_WAIT;
    loop {
        if let Ok(lease) = read() {
            return Ok(lease);
        }
        if now() >= deadline {
            return Err("the DHCP server did not renew the address".into());
        }
        sleep(Duration::from_millis(200));
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
            let bytes = fs::read(&path).map_err(|_| "No DHCP lease")?;
            let lease = match serde_json::from_slice::<super::NftLease>(&bytes) {
                Ok(record) => record.nft_v4,
                Err(_) => {
                    let lease: Lease = serde_json::from_slice(&bytes).map_err(|_| "Invalid DHCP lease")?;
                    let record = super::NftLease { nft_v4: lease };
                    net::write_private(&path, &serde_json::to_vec(&record).map_err(|e| e.to_string())?)?;
                    record.nft_v4
                }
            };
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

    #[test]
    fn takeover_migrates_the_lease_and_retires_legacy_nat_before_staging_and_finishing_tables() {
        use std::cell::RefCell;
        use std::sync::{Arc, Mutex};
        use super::super::uplink;

        let dir = super::super::test_dir::TestDir::new("adoption-order");
        let runtime = dir.path();
        let old_path = lease_file(runtime, &"a".repeat(32)).unwrap();
        let lease = Lease { ip: "10.0.0.2".parse().unwrap(), subnet: "255.255.255.0".parse().unwrap(), gateway: "10.0.0.1".parse().unwrap(), dns: vec![] };
        fs::write(&old_path, serde_json::to_vec(&lease).unwrap()).unwrap();
        let at = |name| runtime.join(name);
        let kernel = uplink::tests::Kernel::default();
        let wireless = Arc::new(Mutex::new(EffectSet::new("relay", at(super::super::journals::WIRELESS))));
        let previous = uplink::Shared::with(at("uplink.nft"), wireless, Box::new(kernel.clone()));
        previous.guard().unwrap();
        let before = kernel.0.lock().unwrap().loads;
        for name in [super::super::journals::NETWORK, super::super::journals::DNS] {
            fs::write(at(name), serde_json::to_vec(&serde_json::json!({"boot": net::boot_id(), "undo": []})).unwrap()).unwrap();
        }
        let calls = RefCell::new(Vec::new());
        let selected = associated("ssid=Test\nbssid=02:00:00:00:00:01\nfreq=5180\nwpa_state=COMPLETED\nkey_mgmt=NONE", &target("Test", "open")).unwrap();
        let session = adopt_session_with(runtime, selected, |installed| {
            assert_eq!(installed, &lease);
            let migrated: super::super::NftLease = serde_json::from_slice(&fs::read(&old_path).unwrap()).unwrap();
            assert_eq!(migrated.nft_v4, lease);
            calls.borrow_mut().push("installed_lease");
            let mut owner = Session::new(runtime);
            owner.uplink = uplink::Shared::with(at("uplink.nft"), owner.wireless.clone(), Box::new(kernel.clone()));
            Ok((owner, 24))
        }, |owner, installed, prefix| {
            let uplink = owner.uplink.clone();
            take_over_with(owner, runtime, installed, (prefix, "192.168.0.1".parse().unwrap(), "255.255.255.0".parse().unwrap()), |_, _| Ok(()), |network| {
                assert!(uplink.layout().is_none(), "retirement precedes staging either table");
                calls.borrow_mut().push("retire_legacy_hook");
                retire_legacy_hook(network)
            })?;
            assert!(owner.uplink.layout().unwrap().relay.is_some());
            assert_eq!(kernel.0.lock().unwrap().loads, before, "adopt stages the IPv4 layout");
            calls.borrow_mut().push("uplink.adopt");
            Ok(())
        }, |_| {
            calls.borrow_mut().push("take_over_ipv6");
            assert_eq!(kernel.0.lock().unwrap().loads, before);
            Ok(())
        }, |_, _, _| {
            assert_eq!(kernel.0.lock().unwrap().loads, before + 1, "finish_adopt loads the staged layout");
            calls.borrow_mut().push("finish_adopt");
            Ok(())
        }).ok().unwrap();
        assert!(session.routed);
        assert!(!old_path.exists());
        assert_eq!(calls.into_inner(), ["installed_lease", "retire_legacy_hook", "uplink.adopt", "take_over_ipv6", "finish_adopt"]);
    }

    #[test]
    fn retiring_legacy_nat_only_acts_on_the_exact_journaled_rule() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        const CHILD: &str = "U60_TEST_RETIRE_LEGACY_NAT";
        if let Ok(case) = std::env::var(CHILD) {
            let path = &std::env::current_dir().unwrap().join("network.json");
            let mut network = EffectSet::load("relay", path).unwrap();
            if case == "retry" {
                let before: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                assert!(retire_legacy_hook(&mut network).unwrap_err().starts_with("Network cleanup paused:"));
                assert_eq!(serde_json::from_slice::<serde_json::Value>(&fs::read(path).unwrap()).unwrap(), before);
                network = EffectSet::load("relay", path).unwrap();
            }
            retire_legacy_hook(&mut network).unwrap();
            return;
        }

        let exact = super::super::Cmd::new("iptables", &["-w", "2", "-t", "nat", "-D", "POSTROUTING", "-o", "ath20", "-m", "comment", "--comment", "zte-agent-wifi-relay", "-j", "MASQUERADE"]);
        let mut similar = exact.clone();
        similar.args[11] = "vendor-wifi-relay".into();
        for (case, journaled, copies, expected) in [
            ("not journaled", false, 2, &[][..]),
            ("exact", true, 1, &["-D", "-D"][..]),
            ("duplicates", true, 2, &["-D", "-D", "-D"][..]),
            ("missing", true, 0, &["-D"][..]),
            ("retry", true, 1, &["-D", "-S", "-C", "-D", "-D"][..]),
        ] {
            let dir = super::super::test_dir::TestDir::new("legacy-nat");
            let at = |name: &str| dir.path().join(name);
            let undo = if journaled { vec![&exact, &similar] } else { vec![&similar] };
            let journal = |undo: Vec<&super::super::Cmd>| serde_json::json!({"boot": net::boot_id(), "undo": undo});
            fs::write(at("network.json"), serde_json::to_vec(&journal(undo)).unwrap()).unwrap();
            fs::write(at("copies"), format!("{copies}\n")).unwrap();
            fs::write(at("calls"), b"").unwrap();
            if case == "retry" { fs::write(at("locked"), b"").unwrap(); }
            fs::write(at("iptables"), r#"#!/bin/sh
set -eu
[ "$1 $2 $3 $4" = '-w 2 -t nat' ] || exit 99
printf '%s\n' "$5" >> calls
if [ "$5" = '-S' ]; then
    printf '%s\n' '-P POSTROUTING ACCEPT' '-A POSTROUTING -o ath20 -m comment --comment vendor-wifi-relay -j MASQUERADE'
    exit 0
fi
shift 4
operation=$1
shift
[ "$*" = 'POSTROUTING -o ath20 -m comment --comment zte-agent-wifi-relay -j MASQUERADE' ] || exit 99
if [ "$operation" = '-D' ] && [ -f locked ]; then
    /bin/rm locked
    exit 4
fi
read -r copies < copies
if [ "$copies" = 0 ]; then
    printf '%s\n' 'No chain/target/match by that name.' >&2
    exit 1
fi
case "$operation" in
    -D) printf '%s\n' "$((copies - 1))" > copies ;;
    -C) exit 0 ;;
    *) exit 99 ;;
esac
"#).unwrap();
            fs::set_permissions(at("iptables"), fs::Permissions::from_mode(0o700)).unwrap();
            let result = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "wifi_relay::adopt::tests::retiring_legacy_nat_only_acts_on_the_exact_journaled_rule"])
                .env(CHILD, case).env("PATH", dir.path()).current_dir(dir.path()).output().unwrap();
            assert!(result.status.success(), "{case}: {} {}", String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
            assert_eq!(fs::read_to_string(at("calls")).unwrap().lines().collect::<Vec<_>>(), expected, "{case}");
            assert_eq!(fs::read_to_string(at("copies")).unwrap().trim().parse::<u32>().unwrap(), if journaled { 0 } else { copies }, "{case}");
            let remaining: serde_json::Value = serde_json::from_slice(&fs::read(at("network.json")).unwrap()).unwrap();
            assert_eq!(remaining, journal(vec![&similar]), "{case}");
        }
    }

    #[test]
    fn an_old_ipv6_journal_or_failed_adoption_stops_then_recovers_then_starts() {
        use std::cell::RefCell;
        for (current, recover_ok) in [(false, true), (true, true), (true, false)] {
            let dir = super::super::test_dir::TestDir::new("ipv6-fallback");
            let mut session = Session::new(dir.path());
            let boot = if current { net::boot_id() } else { "old boot".into() };
            for name in [super::super::journals::V6_SETUP, super::super::journals::V6_NETWORK] {
                fs::write(dir.path().join(name), serde_json::to_vec(&serde_json::json!({"boot": boot, "undo": []})).unwrap()).unwrap();
            }
            let calls = RefCell::new(Vec::new());
            let record = offload::Record { pid: 41, start: 42 };
            let nonce = "a".repeat(32);
            let result = take_over_ipv6_with(&mut session, Some((record, nonce.clone())), true, dir.path(), Ipv6Takeover {
                adopt: |_: &mut Session, found, id: &str| { assert_eq!(found, record); assert_eq!(id, nonce); calls.borrow_mut().push("adopt"); Err("adopt failed".into()) },
                stop: |_: &mut Session| calls.borrow_mut().push("stop_client"),
                recover: || { calls.borrow_mut().push("recover"); if recover_ok { Ok(()) } else { Err("recover failed".into()) } },
                start: |_: &mut Session, enabled: bool| { assert!(enabled); calls.borrow_mut().push("start"); Ok(()) },
            });
            let mut expected = if current { vec!["adopt"] } else { vec![] };
            expected.extend(["stop_client", "recover"]);
            if recover_ok { expected.push("start"); assert_eq!(result, Ok(())); }
            else { assert_eq!(result, Err("recover failed".into())); }
            assert_eq!(calls.into_inner(), expected);
        }
    }

    #[test]
    fn wait_lease_reads_before_checking_the_deadline_and_polls_every_200_ms() {
        use std::cell::{Cell, RefCell};
        for final_read_succeeds in [false, true] {
            let started = Instant::now();
            let elapsed = Cell::new(Duration::ZERO);
            let calls = RefCell::new(Vec::new());
            let lease = Lease { ip: "10.0.0.2".parse().unwrap(), subnet: "255.255.255.0".parse().unwrap(), gateway: "10.0.0.1".parse().unwrap(), dns: vec![] };
            let result = wait_lease_with(
                || { calls.borrow_mut().push("read"); if final_read_succeeds && elapsed.get() == Duration::from_secs(10) { Ok(lease.clone()) } else { Err("not ready".into()) } },
                || { calls.borrow_mut().push("check clock"); started + elapsed.get() },
                |delay| { assert_eq!(delay, Duration::from_millis(200)); calls.borrow_mut().push("sleep"); elapsed.set(elapsed.get() + delay); },
            );
            let mut expected = vec!["check clock"];
            for _ in 0..50 { expected.extend(["read", "check clock", "sleep"]); }
            expected.push("read");
            if final_read_succeeds { assert_eq!(result, Ok(lease)); }
            else { expected.push("check clock"); assert_eq!(result, Err("the DHCP server did not renew the address".into())); }
            assert_eq!(calls.into_inner(), expected);
        }
    }

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
        let temp = crate::wifi_relay::test_dir::TestDir::new("u60-adopt");
        let dir = temp.path();
        assert!(installed_lease(dir).is_err(), "none");
        let a = "67092e919edacc2b4443865a63d75b32";
        let lease = r#"{"ip":"192.168.2.124","subnet":"255.255.255.0","gateway":"192.168.2.1","dns":["192.168.2.1"]}"#;
        fs::write(dir.join(format!("ipv4-lease-{a}.json")), lease).unwrap();
        fs::write(dir.join("ipv4-lease-short.json"), lease).unwrap();
        fs::write(dir.join(format!("ipv6-lease-{a}.json")), "{}").unwrap();
        let (session, taken) = installed_lease(dir).unwrap();
        assert_eq!(session, a);
        let migrated = fs::read(dir.join(format!("ipv4-lease-{a}.json"))).unwrap();
        assert!(serde_json::from_slice::<Lease>(&migrated).is_err(), "the old slot must recover before adding legacy NAT");
        assert_eq!(installed_lease(dir).unwrap().1, taken);
        assert_eq!(taken.ip, Ipv4Addr::new(192, 168, 2, 124));
        fs::write(dir.join(format!("ipv4-lease-{}.json", "0".repeat(32))), lease).unwrap();
        assert!(installed_lease(dir).is_err(), "two sessions are not one connection");
    }
}
