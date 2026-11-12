//! Qualcomm IPA hardware forwarding of the relay's IPv4 NAT (owner decision
//! 63, `zte-agent/docs/relay-hw-offload.md`). IPACM can offload the relay
//! only when its configuration lists the station interface (it reads the
//! file once, at boot; restarting it at runtime loses the driver's earlier
//! Wi-Fi events) and the `main` table has a default route through the relay
//! (IPACM's WAN-up trigger, it ignores policy tables). B31's factory file
//! lists the name the relay takes (`ids::RELAY_IFACE`), so the agent only
//! reads that file, never writes it. Whether IPACM then offloads is up to
//! the router's own settings (owner choice, 2026-11-12): the Balanced
//! working mode (`Nomal_mode`, 极速模式) turns acceleration on; every other
//! working mode, a vendor speed limit, power saver mode and `ipa_disable`
//! turn it off. The agent never reads or changes any of them.
//! Connections that are offloaded skip iptables, tc and parental control.
//! IPACM also puts a rule for every other upstream host ahead of the
//! gateway's; `neighbours` removes them. It also loses hotspot clients' LAN
//! routes when they change bands; `clients` brings them back. The owner's
//! switch applies to a connected relay at once (owner decision 64): without
//! the `main` route IPACM has no relay WAN, so the relay forwards on the CPU.

mod clients;
mod monitor;
pub(crate) use monitor::Record;
mod neighbours;

use std::{fs, net::Ipv4Addr, path::Path};

use serde::Serialize;
use serde_json::{json, Value};

use super::{net, Cmd, Step, Transaction, IFACE};

/// IPACM's interface table, which IPACM read at boot and the agent reads
/// now. QCMAP rewrites it at runtime (B31's running file, read 2026-11-11,
/// still had every factory interface) and a factory reset copies
/// `factory_IPACM_cfg.xml` over it: neither drops the station's entry.
const CONFIG: &str = "/etc/data/ipa/IPACM_cfg.xml";
/// Present while the owner has hardware forwarding turned off (survives
/// reboots and updates).
const OFF: &str = "/data/zte-agent-relay/ipacm/off";
/// Metric of the relay's `main` default and its unreachable guards. Not 0:
/// netifd installs the cellular default with metric 0 and NLM_F_REPLACE, so
/// an equal metric would let either route replace the other.
pub(super) const METRIC: &str = crate::netfx::ids::RELAY_METRIC;
/// Ranges the relay table throws to `main` for their specific routes. With a
/// relay default in `main` they would otherwise leave through the hotel.
/// The LAN subnet always has its connected route there.
pub(super) const GUARDED: [&str; 3] = crate::netfx::ids::LOCAL_ROUTES_V4;

/// What IPACM's configuration says about the station interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Config {
    /// Listed as a Wi-Fi interface, as B31's factory file has it.
    Listed,
    /// No such entry (another firmware): IPACM ignores the relay.
    NotListed,
    /// The file cannot be read.
    Unavailable,
}

/// Reads the file; never writes it.
pub(crate) fn config() -> Config {
    match fs::read_to_string(CONFIG) {
        Ok(text) if listed(&text) => Config::Listed,
        Ok(_) => Config::NotListed,
        Err(_) => Config::Unavailable,
    }
}

/// Whether an `<Iface>` element names the station with the vendor's Wi-Fi
/// entry (Category UNKNOWN, WlanMode full), the one the offload was
/// measured with (2026-11-12).
fn listed(text: &str) -> bool {
    text.split("<Iface>").skip(1).filter_map(|rest| rest.split_once("</Iface>")).any(|(entry, _)| {
        let field = |tag: &str| {
            let (_, rest) = entry.split_once(&format!("<{tag}>"))?;
            rest.split_once(&format!("</{tag}>")).map(|(value, _)| value.trim())
        };
        field("Name") == Some(IFACE) && field("Category") == Some("UNKNOWN") && field("WlanMode") == Some("full")
    })
}

/// The owner's runtime switch (on unless turned off).
pub(crate) fn enabled() -> bool {
    !Path::new(OFF).exists()
}

pub(crate) fn set_enabled(on: bool) -> Result<(), String> {
    let path = Path::new(OFF);
    if !on {
        return net::write_private(path, b"1\n");
    }
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err("Cannot clear the hardware forwarding switch".into()),
        _ => Ok(()),
    }
}

/// Why a session has no `main` route.
fn idle_reason(config: Config) -> String {
    match config {
        Config::Listed => "Hardware forwarding is turned off".into(),
        Config::NotListed => format!("This firmware's IPA configuration does not list the relay interface ({IFACE})"),
        Config::Unavailable => "The IPA configuration is unavailable".into(),
    }
}

/// The firmware the B31-specific workarounds were verified on
/// (`relay-mihomo-architecture.md` section 7): the neighbour retirement and
/// the clients' STALE nudge. Elsewhere the relay adds no `main` route, so it
/// forwards on the CPU, and the reason shows.
const FIRMWARE: &str = "BD_CNMU5250V1.0.0B31";
const IPACM: &str = "/usr/bin/ipacm";
/// SHA-256 of B31's `/usr/bin/ipacm` (4,129,835 bytes, read 2026-11-10).
const IPACM_SHA256: &str = "95385816da7b2edb9a977cee328c091753463fcd4a70a67fa1676e8b335c11c0";

/// Whether the session's `main` route is in place (section 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    /// Not wanted, or not possible: no session, another firmware, a failure.
    Off,
    /// The `main` route and the monitors are in place.
    Routed,
    /// The route being taken back. A failed undo stays here, never `Off`.
    Releasing,
}

/// The device side of IPACM and the session's journal, so the state machine
/// runs against a fake in tests (I6).
trait IpacmPort {
    fn config(&mut self) -> Config;
    fn enabled(&mut self) -> bool;
    /// `Err(why)` unless this is the firmware the workarounds were verified on.
    fn fingerprint(&mut self) -> Result<(), String>;
    fn monitors(&mut self, gateway: Ipv4Addr) -> Vec<monitor::Monitor>;
    fn apply_network(&mut self, tx: &mut Transaction, plan: Vec<Step>) -> Result<(), String>;
    fn release(&mut self, tx: &mut Transaction, undos: &[Cmd]) -> Result<(), String>;
}

/// The router.
struct Device;

impl IpacmPort for Device {
    fn config(&mut self) -> Config {
        config()
    }
    fn enabled(&mut self) -> bool {
        enabled()
    }
    fn fingerprint(&mut self) -> Result<(), String> {
        let version = crate::ubus::uci_get("zwrt_common_info.common_config.wa_inner_version").unwrap_or_default();
        let binary = fs::read(IPACM).ok().map(|bytes| {
            use sha2::Digest;
            sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()
        });
        fingerprint(&version, binary.as_deref())
    }
    fn monitors(&mut self, gateway: Ipv4Addr) -> Vec<monitor::Monitor> {
        vec![neighbours::watch(gateway), clients::watch()]
    }
    fn apply_network(&mut self, tx: &mut Transaction, plan: Vec<Step>) -> Result<(), String> {
        tx.apply_network(plan)
    }
    fn release(&mut self, tx: &mut Transaction, undos: &[Cmd]) -> Result<(), String> {
        tx.release(undos)
    }
}

/// The router, for a `main` route the previous agent added in a session
/// this one adopts (`Runtime::adopt`): the journaled steps are re-taken.
struct Adopting;

impl IpacmPort for Adopting {
    fn config(&mut self) -> Config {
        Device.config()
    }
    fn enabled(&mut self) -> bool {
        Device.enabled()
    }
    fn fingerprint(&mut self) -> Result<(), String> {
        Device.fingerprint()
    }
    fn monitors(&mut self, gateway: Ipv4Addr) -> Vec<monitor::Monitor> {
        Device.monitors(gateway)
    }
    fn apply_network(&mut self, tx: &mut Transaction, plan: Vec<Step>) -> Result<(), String> {
        plan.into_iter().try_for_each(|step| tx.adopt(step))
    }
    fn release(&mut self, tx: &mut Transaction, undos: &[Cmd]) -> Result<(), String> {
        Device.release(tx, undos)
    }
}

/// `Err(why)` unless the firmware and IPACM are the ones verified (B31).
fn fingerprint(version: &str, ipacm_sha256: Option<&str>) -> Result<(), String> {
    if version != FIRMWARE {
        return Err(format!("Hardware forwarding was verified on firmware {FIRMWARE} only (this router runs {})", if version.is_empty() { "an unknown version" } else { version }));
    }
    if ipacm_sha256 != Some(IPACM_SHA256) {
        return Err("Hardware forwarding was verified with another IPACM build".into());
    }
    Ok(())
}

/// One relay session's hardware forwarding path (section 7).
pub(super) struct Runtime {
    state: State,
    reason: Option<String>,
    /// `neighbours` and `clients`, while the route is in place.
    monitors: Vec<monitor::Monitor>,
    /// Undo commands of the `main` route steps added to the session's plan,
    /// for `release`.
    applied: Vec<Cmd>,
    /// The session's gateway and subnet, to add the route again later.
    uplink: Option<(Ipv4Addr, String)>,
}

impl Runtime {
    pub(super) fn off() -> Self {
        Self { state: State::Off, reason: None, monitors: Vec::new(), applied: Vec::new(), uplink: None }
    }

    /// Called with the session's network plan applied.
    pub(super) fn start(tx: &mut Transaction, gateway: Ipv4Addr, subnet: String) -> Self {
        Self::start_with(&mut Device, tx, gateway, subnet)
    }

    /// The previous agent's `main` route, taken over with its session
    /// (`wifi_relay::adopt`): its journaled steps are re-taken, not run
    /// again, and new monitors replace the stopped ones. A journal of a
    /// build that still switched IPACM's mode keeps that step's undo until
    /// the session ends; `Cmd::undo` then skips it as unknown, so IPACM
    /// stays in whatever mode it is in.
    pub(super) fn adopt(tx: &mut Transaction, gateway: Ipv4Addr, subnet: String) -> Self {
        Self::start_with(&mut Adopting, tx, gateway, subnet)
    }

    fn start_with(port: &mut impl IpacmPort, tx: &mut Transaction, gateway: Ipv4Addr, subnet: String) -> Self {
        let mut runtime = Self::off();
        runtime.uplink = Some((gateway, subnet));
        if let Err(e) = runtime.sync_with(port, tx) {
            runtime.reason = Some(e);
        }
        runtime
    }

    /// Follows the owner's switch on a live session. `Ok(true)` when the
    /// path changed (the caller resets LAN IPv4 connections onto it).
    pub(super) fn sync(&mut self, tx: &mut Transaction) -> Result<bool, String> {
        self.sync_with(&mut Device, tx)
    }

    fn sync_with(&mut self, port: &mut impl IpacmPort, tx: &mut Transaction) -> Result<bool, String> {
        let config = port.config();
        let wanted = config == Config::Listed && port.enabled() && self.uplink.is_some();
        match (wanted, self.state) {
            (true, State::Routed) => Ok(false),
            (true, State::Off) => self.add(port, tx),
            (false, State::Off) => {
                self.reason = Some(idle_reason(config));
                Ok(false)
            }
            (_, State::Routed | State::Releasing) => {
                // A failed release stays Releasing (never Off while the route
                // may hold); a route wanted again comes back once it is gone.
                self.release(port, tx)?;
                self.state = State::Off;
                self.reason = Some(idle_reason(config));
                if wanted {
                    self.add(port, tx)?;
                }
                Ok(true)
            }
        }
    }

    /// Off → Routed, or Off with the reason. A route that fails is taken
    /// back first: the snapshot never says Off while the route may hold.
    fn add(&mut self, port: &mut impl IpacmPort, tx: &mut Transaction) -> Result<bool, String> {
        if let Err(why) = port.fingerprint() {
            self.reason = Some(why);
            return Ok(false);
        }
        let Some((gateway, subnet)) = self.uplink.clone() else { return Ok(false) };
        let plan = route_plan(&gateway.to_string(), &subnet);
        self.applied.extend(plan.iter().map(|s| s.undo.clone()));
        if let Err(e) = port.apply_network(tx, plan) {
            self.release(port, tx)?;
            self.state = State::Off;
            self.reason = Some(format!("Hardware forwarding route was not added: {e}"));
            return Ok(false);
        }
        self.state = State::Routed;
        self.reason = None;
        self.monitors = port.monitors(gateway);
        Ok(true)
    }

    /// Routed → Releasing → (the caller's next state): the monitors stop and
    /// the `main` route goes (IPACM's relay WAN is down). The session goes on.
    fn release(&mut self, port: &mut impl IpacmPort, tx: &mut Transaction) -> Result<(), String> {
        self.state = State::Releasing;
        self.monitors.clear();
        let applied = std::mem::take(&mut self.applied);
        let result = port.release(tx, &applied);
        if let Err(e) = &result {
            // Keep what was not undone: recovery still knows it from the journal.
            self.applied = applied;
            self.reason = Some(format!("Hardware forwarding was not fully released: {e}"));
        }
        result
    }

    /// Relay teardown, before the interface goes away.
    pub(super) fn stop(&mut self) {
        self.monitors.clear();
    }

    pub(super) fn status(&self) -> Value {
        json!({"state": self.state, "route": self.state == State::Routed, "reason": self.reason})
    }
}

/// `main` default through the relay plus its unreachable guards, for a plan
/// that already has the relay table. Only with the station listed.
pub(super) fn route_plan(gateway: &str, subnet: &str) -> Vec<Step> {
    let mut plan: Vec<Step> = GUARDED
        .iter()
        .filter(|dest| **dest != subnet)
        .map(|dest| net::ip_step("-4", "route", &["unreachable", dest, "metric", METRIC, "table", "main"]))
        .collect();
    plan.push(net::ip_step("-4", "route", &["default", "via", gateway, "dev", IFACE, "metric", METRIC, "table", "main"]));
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B31's factory configuration around the station's entry, as it is
    /// indented there (`factory_IPACM_cfg.xml`, read 2026-11-12).
    const FACTORY: &str = "\t\t<IPACMIface>\n\t\t\t<Iface>\n\t\t\t   <Name>rmnet_data0</Name>\n\t\t\t   <Category>WAN</Category>\n\t\t\t   <Mode>ROUTER</Mode>\n\t\t\t</Iface>\n\t\t\t<Iface>\n\t\t\t   <Name>ath10</Name>\n\t\t\t   <Category>UNKNOWN</Category>\n\t\t\t   <WlanMode>full</WlanMode>\n\t\t\t</Iface>\n\t\t\t<Iface>\n\t\t\t   <Name>ath20</Name>\n\t\t\t   <Category>UNKNOWN</Category>\n\t\t\t   <WlanMode>full</WlanMode>\n\t\t\t</Iface>\n\t\t</IPACMIface>\n";

    #[test]
    fn only_a_wifi_entry_naming_the_station_lists_it() {
        assert_eq!(IFACE, "ath20", "the name B31's factory file lists");
        assert!(listed(FACTORY));
        let without = FACTORY.replace("<Name>ath20</Name>", "<Name>ath21</Name>");
        assert!(!listed(&without), "another firmware's file");
        assert!(!listed(&FACTORY.replace("<Name>ath20</Name>", "<Name>ath200</Name>")));
        let wan = FACTORY.replacen("<Category>UNKNOWN</Category>\n\t\t\t   <WlanMode>full</WlanMode>\n\t\t\t</Iface>\n\t\t</IPACMIface>", "<Category>WAN</Category>\n\t\t\t</Iface>\n\t\t</IPACMIface>", 1);
        assert!(!listed(&wan), "not as a Wi-Fi interface");
        // A field of the next entry does not count for one that lacks it.
        assert!(!listed("<Iface><Name>ath20</Name></Iface><Iface><Name>ath10</Name><Category>UNKNOWN</Category><WlanMode>full</WlanMode></Iface>"));
        assert!(!listed(""));
    }

    #[test]
    fn the_main_route_never_shares_the_cellular_metric_and_guards_thrown_ranges() {
        let plan = route_plan("192.168.2.1", "192.168.2.0/24");
        let last = plan.last().unwrap();
        assert_eq!(last.apply.args.join(" "), format!("-4 route add default via 192.168.2.1 dev {IFACE} metric {METRIC} table main"));
        assert_ne!(METRIC, "0");
        for dest in GUARDED {
            assert!(plan.iter().any(|s| s.apply.args.windows(2).any(|w| w == ["unreachable", dest])));
        }
        assert!(plan.iter().all(|s| s.undo.args.windows(2).any(|w| w == ["table", "main"])));
        // An upstream inside a guarded range keeps its own connected route.
        assert_eq!(route_plan("100.64.0.1", "100.64.0.0/10").len(), GUARDED.len());
    }

    /// A fake IPACM and journal: what was added, released and started.
    struct Fake {
        config: Config,
        enabled: bool,
        fingerprint: Result<(), String>,
        route_fails: bool,
        release_fails: bool,
        log: Vec<String>,
    }

    impl Default for Fake {
        fn default() -> Self {
            Self { config: Config::Listed, enabled: true, fingerprint: Ok(()), route_fails: false, release_fails: false, log: Vec::new() }
        }
    }

    impl IpacmPort for Fake {
        fn config(&mut self) -> Config {
            self.config
        }
        fn enabled(&mut self) -> bool {
            self.enabled
        }
        fn fingerprint(&mut self) -> Result<(), String> {
            self.fingerprint.clone()
        }
        fn monitors(&mut self, _: Ipv4Addr) -> Vec<monitor::Monitor> {
            self.log.push("monitors".into());
            Vec::new()
        }
        fn apply_network(&mut self, _: &mut Transaction, plan: Vec<Step>) -> Result<(), String> {
            self.log.push(format!("routes {}", plan.len()));
            if self.route_fails { Err("RTNETLINK answers: Network is unreachable".into()) } else { Ok(()) }
        }
        fn release(&mut self, _: &mut Transaction, undos: &[Cmd]) -> Result<(), String> {
            if self.release_fails {
                return Err("Network cleanup paused".into());
            }
            // Newest first, as `Transaction::release` runs them.
            for undo in undos.iter().rev() {
                self.log.push(format!("undo {} {}", undo.program, undo.args.first().map(String::as_str).unwrap_or("")));
            }
            Ok(())
        }
    }

    const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 2, 1);

    fn session(fake: &mut Fake) -> (Runtime, Transaction) {
        let mut tx = Transaction::new(std::env::temp_dir().join("u60-ipa-fake-never-written.json"));
        let runtime = Runtime::start_with(fake, &mut tx, GATEWAY, "192.168.2.0/24".into());
        (runtime, tx)
    }

    #[test]
    fn the_owners_switch_adds_and_removes_only_the_main_route_and_the_monitors() {
        let mut fake = Fake::default();
        let (mut runtime, mut tx) = session(&mut fake);
        assert_eq!(runtime.state, State::Routed);
        assert_eq!(fake.log, ["routes 4", "monitors"]);
        assert_eq!(runtime.status(), json!({"state": "routed", "route": true, "reason": null}));
        fake.log.clear();
        assert!(!runtime.sync_with(&mut fake, &mut tx).unwrap(), "nothing changed");
        assert!(fake.log.is_empty());
        fake.enabled = false;
        assert!(runtime.sync_with(&mut fake, &mut tx).unwrap(), "the path changed");
        assert_eq!(runtime.state, State::Off);
        assert_eq!(fake.log.len(), 4);
        assert!(fake.log.iter().all(|l| l.starts_with("undo ip -4")), "the route and its guards, nothing else: {:?}", fake.log);
        assert_eq!(runtime.status(), json!({"state": "off", "route": false, "reason": "Hardware forwarding is turned off"}));
        fake.enabled = true;
        fake.log.clear();
        assert!(runtime.sync_with(&mut fake, &mut tx).unwrap());
        assert_eq!((runtime.state, fake.log.as_slice()), (State::Routed, &["routes 4".to_owned(), "monitors".to_owned()][..]));
    }

    /// Another firmware's IPACM configuration without the station: the file
    /// is only read, no route is added, and the reason says why.
    #[test]
    fn a_configuration_without_the_station_gets_no_route_and_says_why() {
        for (config, why) in [
            (Config::NotListed, "This firmware's IPA configuration does not list the relay interface (ath20)"),
            (Config::Unavailable, "The IPA configuration is unavailable"),
        ] {
            let mut fake = Fake { config, ..Fake::default() };
            let (mut runtime, mut tx) = session(&mut fake);
            assert_eq!((runtime.state, runtime.reason.as_deref()), (State::Off, Some(why)));
            assert!(fake.log.is_empty(), "nothing added");
            fake.enabled = false;
            assert!(!runtime.sync_with(&mut fake, &mut tx).unwrap());
            assert_eq!(runtime.reason.as_deref(), Some(why), "the listing explains it before the switch does");
        }
    }

    #[test]
    fn another_firmware_gets_no_route_and_says_why() {
        let mut fake = Fake { fingerprint: Err("verified on B31 only".into()), ..Fake::default() };
        let (runtime, _) = session(&mut fake);
        assert_eq!((runtime.state, runtime.reason.as_deref()), (State::Off, Some("verified on B31 only")));
        assert!(fake.log.is_empty(), "nothing added");
    }

    #[test]
    fn a_route_that_fails_is_taken_back_and_a_failed_release_never_reads_off() {
        let mut fake = Fake { route_fails: true, ..Fake::default() };
        let (runtime, _) = session(&mut fake);
        assert_eq!(runtime.state, State::Off);
        assert!(runtime.reason.as_deref().unwrap().contains("route was not added"));
        assert_eq!(fake.log.iter().filter(|l| l.starts_with("undo ip -4")).count(), 4, "what this attempt journaled is undone: {:?}", fake.log);
        assert!(!fake.log.contains(&"monitors".to_owned()));
        let mut fake = Fake::default();
        let (mut runtime, mut tx) = session(&mut fake);
        fake.release_fails = true;
        fake.enabled = false;
        assert!(runtime.sync_with(&mut fake, &mut tx).is_err());
        assert_eq!(runtime.state, State::Releasing, "not Off while the route may hold");
        assert_eq!(runtime.status()["route"], false);
        assert!(!runtime.applied.is_empty(), "what is left stays known");
        // Wanted again before the release went through: it finishes first.
        fake.release_fails = false;
        fake.enabled = true;
        fake.log.clear();
        assert!(runtime.sync_with(&mut fake, &mut tx).unwrap());
        assert_eq!(runtime.state, State::Routed);
        assert_eq!(fake.log[..4].iter().filter(|l| l.starts_with("undo ip -4")).count(), 4, "{:?}", fake.log);
        assert_eq!(fake.log[4..], ["routes 4", "monitors"]);
        assert_eq!(runtime.applied.len(), 4, "only the new route's undos");
    }

    #[test]
    fn the_firmware_fingerprint_is_b31_and_its_ipacm() {
        assert!(fingerprint(FIRMWARE, Some(IPACM_SHA256)).is_ok());
        assert!(fingerprint("BD_CNMU5250V1.0.0B32", Some(IPACM_SHA256)).unwrap_err().contains("B32"));
        assert!(fingerprint(FIRMWARE, Some("00")).is_err());
        assert!(fingerprint(FIRMWARE, None).is_err());
        assert!(fingerprint("", None).unwrap_err().contains("unknown"));
    }
}
