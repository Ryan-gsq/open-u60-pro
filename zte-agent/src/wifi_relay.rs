//! B31 AP+STA relay, implemented with the firmware's public nl80211 and
//! hostapd/wpa control tools. No vendor daemon or persistent Wi-Fi UCI is
//! replaced. Optional upstream IPv6 and downstream NAT66 use owned runtime state.

pub(crate) mod ipv6;
pub(crate) mod adopt;
mod controller;
pub(crate) mod dns;
pub(crate) mod portal;
mod dfs_switch;
pub(crate) mod hotspot;
pub(crate) mod offload;
pub(crate) mod power_save;
mod resume;
mod scan;
pub(crate) mod steering;
pub(crate) mod uplink;

use std::fs;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use controller::{Command as RelayCommand, Message, Observation, Selection, State};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::boottime::{BootClock, BootInstant, Clock};
use crate::net_tools::{self as net, Cmd, NetworkLock, Step};
use crate::netfx::effect::{EffectSet, Resource, Addr, Family, Internal, Key, LegacyChain, LegacyHook, LegacyTool, Position, Route, RouteType, Rule};

const IFACE: &str = crate::netfx::ids::RELAY_IFACE;
mod saved;
const ROOT: &str = "/tmp/zte-agent-relay";
const JOURNAL: &str = "/data/zte-agent-relay";
const HOSTAPD: &str = "/data/vendor/wifi/hostapd";
const TABLE: &str = crate::netfx::ids::RELAY_TABLE;
const PREF: &str = crate::netfx::ids::RELAY_PREF;

#[derive(Clone, Serialize)]
pub struct Network {
    pub id: String,
    pub ssid: String,
    pub frequency: u32,
    pub signal: i32,
    pub security: &'static str,
    pub supported: bool,
    #[serde(skip)]
    bssid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lease {
    ip: Ipv4Addr,
    subnet: Ipv4Addr,
    gateway: Ipv4Addr,
    dns: Vec<Ipv4Addr>,
}

struct Session {
    wireless: Arc<Mutex<EffectSet>>,
    network: EffectSet,
    /// The resolver line (`dns`) and the suppression of the vendor's offline
    /// redirect (`portal`: the switch delta and the RETURN). A handover
    /// releases only the resolver and moves the rest to the next session.
    dns: EffectSet,
    /// The relay's nftables tables (`uplink`), shared with `ipv6`.
    uplink: uplink::Shared,
    dns_error: Option<String>,
    supplicant: Option<Helper>,
    dhcp: Option<Child>,
    dhcp_session: Option<String>,
    lease: Option<Lease>,
    selected: Option<Network>,
    ipv6: ipv6::Upstream,
    association: Association,
    offload: offload::Runtime,
    power_save: power_save::State,
    /// When to re-check `network` against ZTE's rewrites (`net_guard`).
    guard: crate::net_guard::Cursor,
    /// Last DHCP renew requested after a recovered association.
    renewed: Option<Instant>,
    /// The relay's routes were installed (its policy rule is the plan's last
    /// step): only then does a teardown change the uplink Mihomo uses.
    routed: bool,
}

/// BusyBox udhcpc deconfigures when a second renew signal arrives while the
/// first is still pending, so recovered associations renew at most this often.
const RENEW_SPACING: Duration = Duration::from_secs(30);

/// A helper process of the session: one this agent started, or one the
/// previous agent left running and this one took over with the session
/// (`adopt`), named by its process id and start time so a reused id is never
/// taken for it.
enum Helper {
    Owned(Child),
    Adopted(offload::Record),
}

impl Helper {
    fn alive(&mut self) -> bool {
        match self {
            Helper::Owned(child) => matches!(child.try_wait(), Ok(None)),
            Helper::Adopted(process) => same_process(*process),
        }
    }
}

/// Whether `process` still runs (a zombie has an empty command line; its
/// parent, init for an adopted helper, reaps it).
fn same_process(process: offload::Record) -> bool {
    fs::read(format!("/proc/{}/cmdline", process.pid)).is_ok_and(|c| !c.is_empty())
        && crate::netfx::exec::process_start(process.pid) == Some(process.start)
}

fn stop_helper(helper: &mut Option<Helper>) {
    match helper.take() {
        Some(Helper::Owned(child)) => net::stop_child(&mut Some(child)),
        Some(Helper::Adopted(process)) => {
            for signal in [libc::SIGTERM, libc::SIGKILL] {
                if !same_process(process) {
                    return;
                }
                // SAFETY: kill(2) on the process just re-identified by id and start time.
                unsafe { libc::kill(process.pid as libc::pid_t, signal) };
                for _ in 0..10 {
                    if !same_process(process) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        None => {}
    }
}

impl Session {
    /// A session journaled under `journal`, before anything is applied.
    fn new(journal: &Path) -> Self {
        let wireless = Arc::new(Mutex::new(EffectSet::new("relay", journal.join("wireless.json"))));
        let uplink = uplink::Shared::new(journal.join("uplink.nft"), Arc::clone(&wireless));
        Session {
            wireless,
            network: EffectSet::new("relay", journal.join("network.json")),
            dns: EffectSet::new("relay", journal.join("dns.json")),
            ipv6: ipv6::Upstream::new(uplink.clone()),
            uplink,
            dns_error: None,
            supplicant: None,
            dhcp: None,
            dhcp_session: None,
            lease: None,
            selected: None,
            association: Association::default(),
            offload: offload::Runtime::off(),
            power_save: power_save::State::default(),
            guard: crate::net_guard::Cursor::default(),
            renewed: None,
            routed: false,
        }
    }

    /// The lease file proves only that udhcpc has not given the lease up. A
    /// recovered association may be a roam onto another network with the same
    /// SSID: a renew there is NAKed, the deconfig removes the lease and the
    /// next tick tears the relay down instead of keeping a stale address.
    fn renew_lease(&mut self) {
        if self.renewed.is_some_and(|at| at.elapsed() < RENEW_SPACING) {
            return;
        }
        let Some(dhcp) = self.dhcp.as_mut() else {
            return;
        };
        if !matches!(dhcp.try_wait(), Ok(None)) {
            return;
        }
        // SAFETY: kill(2) on our own child, which is alive and not yet reaped.
        unsafe {
            libc::kill(dhcp.id() as i32, libc::SIGUSR1);
        }
        self.renewed = Some(Instant::now());
        crate::netlog!("[relay] association recovered; DHCP renew requested");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase { Idle, Scanning, Connecting, Active, Recovering, Disconnecting, RecoveryPending }

#[derive(Default)]
struct Cancel {
    restoring: Option<String>,
    restore_generation: u64,
    disconnect: bool,
    working: bool,
    tearing_down: bool,
    reply: Option<controller::Reply>,
}

struct Snapshot {
    value: Value,
    scans: Vec<Network>,
}

struct Shared {
    cancel: Mutex<Cancel>,
    snapshot: Mutex<Snapshot>,
    active: AtomicBool,
    owned: AtomicBool,
    tick_pending: AtomicBool,
}

impl Shared {
    fn new() -> Self {
        Self {
            cancel: Mutex::new(Cancel::default()),
            snapshot: Mutex::new(Snapshot { value: snapshot(&State::default(), BootClock.now()), scans: Vec::new() }),
            active: AtomicBool::new(false),
            owned: AtomicBool::new(false),
            tick_pending: AtomicBool::new(false),
        }
    }

    fn generation_matches(&self, generation: u64) -> bool {
        let cancel = self.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        cancel.restore_generation == generation && !cancel.disconnect
    }

    fn queue_tick(&self, sender: &std::sync::mpsc::Sender<Message>) -> Result<(), String> {
        if self.tick_pending.swap(true, Ordering::AcqRel) { return Ok(()); }
        if sender.send(Message::Tick).is_err() {
            self.tick_pending.store(false, Ordering::Release);
            return Err("The relay controller stopped".into());
        }
        Ok(())
    }

    fn cancel_restore(&self) -> u64 {
        let mut cancel = self.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        cancel.restore_generation = cancel.restore_generation.wrapping_add(1);
        cancel.restoring = None;
        self.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner).value["restoring"] = Value::Null;
        cancel.restore_generation
    }

    fn phase(&self, phase: Phase) {
        let cancel = self.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut snapshot = self.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        snapshot.value["phase"] = json!(if cancel.disconnect { Phase::Disconnecting } else { phase });
        snapshot.value["recovery_required"] = json!(false);
    }

    fn in_progress(&self) -> String {
        let snapshot = self.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        format!("A network operation is in progress ({}); retry after it finishes", snapshot.value["phase"].as_str().unwrap_or("idle"))
    }

    fn publish(&self, state: &State, mut value: Value, pending: bool, cancel: &Cancel) {
        value["restoring"] = json!(cancel.restoring);
        if cancel.disconnect { value["phase"] = json!(Phase::Disconnecting); }
        value["recovery_required"] = json!(pending && matches!(state.phase, Phase::Idle | Phase::RecoveryPending) && !cancel.disconnect);
        self.active.store(state.session.as_ref().is_some_and(|session| session.selected.is_some()), Ordering::Release);
        self.owned.store(state.session.is_some() || pending || cancel.disconnect, Ordering::Release);
        *self.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Snapshot { value, scans: state.scans.clone() };
    }
}

struct Cancellation {
    shared: Arc<Shared>,
    generation: u64,
    target: Option<resume::Resume>,
}

impl Cancellation {
    fn check(&self) -> Result<(), String> {
        if self.shared.generation_matches(self.generation) { Ok(()) } else { Err(RESTORE_CANCELLED.into()) }
    }
}

pub struct WifiRelay {
    lock: NetworkLock,
    shared: Arc<Shared>,
    commands: OnceLock<std::sync::mpsc::Sender<Message>>,
    mihomo: Option<Arc<crate::mihomo::Mihomo>>,
}

impl WifiRelay {
    pub fn new(lock: NetworkLock) -> Self {
        let relay = Self { lock, shared: Arc::new(Shared::new()), commands: OnceLock::new(), mihomo: None };
        let mut port = DevicePort { shared: Arc::clone(&relay.shared), mihomo: None };
        let mut state = State::default();
        if recovery_pending(Path::new(JOURNAL)) { state.phase = Phase::RecoveryPending; }
        port.publish(&state);
        relay
    }

    pub fn with_core(lock: NetworkLock, core: Arc<crate::mihomo::Mihomo>) -> Self {
        Self { mihomo: Some(core), ..Self::new(lock) }
    }

    pub fn start(self: &Arc<Self>) {
        let (sender, receiver) = std::sync::mpsc::channel();
        let (reply, _) = std::sync::mpsc::sync_channel(1);
        controller::boot(&sender, reply);
        if self.commands.set(sender.clone()).is_err() { return; }
        let port = DevicePort { shared: Arc::clone(&self.shared), mihomo: self.mihomo.clone() };
        let controller = controller::Controller::new(port, receiver, sender.clone(), Arc::clone(&self.shared), Arc::clone(&self.lock), controller::Timings::default());
        crate::system::spawn_named("relay", move || controller.supervised(|_| {
            crate::netlog!("[relay] the controller thread panicked; ending the agent so that its guard starts it again and it adopts the connection");
            std::process::abort();
        }));
        let shared = Arc::clone(&self.shared);
        crate::net_guard::on_settled(move || { let _ = shared.queue_tick(&sender); });
    }

    fn send(&self, message: Message) -> Result<(), String> {
        let sender = self.commands.get().ok_or("The relay controller is not running")?;
        if matches!(message, Message::Tick) { return self.shared.queue_tick(sender); }
        sender.send(message).map_err(|_| "The relay controller stopped".into())
    }

    fn call(&self, command: RelayCommand) -> Result<Option<Value>, String> {
        controller::request(self, command, Some(Instant::now() + crate::netfx::admission::WAIT))
    }

    fn in_progress(&self) -> String { self.shared.in_progress() }
    pub fn active(&self) -> bool { self.shared.active.load(Ordering::Acquire) }
    pub fn owns_network(&self) -> bool {
        self.shared.owned.load(Ordering::Acquire) || crate::netfx::admission::held(crate::netfx::admission::RELAY_OPERATION)
    }

    pub fn status(&self) -> Value { self.status_with_clock(&crate::network_clock::WIFI) }
    fn status_with_clock(&self, clock: &crate::network_clock::WifiClock) -> Value {
        let mut value = self.shared.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner).value.clone();
        value["clock_error"] = if value["connected"] == true { json!(clock.error()) } else { Value::Null };
        value["offload"]["ipv4_through_mihomo"] = json!(self.mihomo.as_ref().map_or("none", |core| core.ipv4_share()));
        value["connection_resets"] = crate::netfx::conntrack::history();
        value
    }

    pub fn recover(&self) -> Result<(), String> {
        DevicePort { shared: Arc::clone(&self.shared), mihomo: self.mihomo.clone() }.recover()
    }

    pub fn recover_idle(&self) { let _ = controller::request(self, RelayCommand::Boot, None); }
    pub fn wants_restore(&self) -> bool { resume::load(Path::new(JOURNAL)).is_some() }
    pub fn restore(&self) { let _ = controller::request(self, RelayCommand::Restore, None); }
    pub fn scan(&self) -> Result<(), String> { self.call(RelayCommand::Scan).map(|_| ()) }

    fn connect_remembered(&self, id: &str, password: &str, confirmed: bool, ipv6: bool, remember: bool) -> Result<(), String> {
        if !confirmed { return Err("Confirm hotspot interruption and possible cellular charges first".into()); }
        let deadline = Instant::now() + crate::netfx::admission::WAIT;
        let scans = self.shared.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner).scans.clone();
        let selection = Selection::from(&scans, id, password)?;
        let generation = self.shared.cancel_restore();
        let _ = self.send(Message::Wake);
        controller::request(self, RelayCommand::Connect { selection, ipv6, remember, generation }, Some(deadline)).map(|_| ())
    }

    pub fn disconnect(&self) -> Result<(), String> {
        let receiver = {
            let mut cancel = self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            cancel.restore_generation = cancel.restore_generation.wrapping_add(1);
            cancel.restoring = None;
            cancel.disconnect = !cancel.tearing_down;
            let mut snapshot = self.shared.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            snapshot.value["restoring"] = Value::Null;
            snapshot.value["phase"] = json!(Phase::Disconnecting);
            snapshot.value["recovery_required"] = json!(false);
            self.shared.owned.store(true, Ordering::Release);
            if cancel.working { None } else {
                cancel.working = true;
                let (reply, receiver) = std::sync::mpsc::sync_channel(1);
                cancel.reply = Some(reply);
                Some(receiver)
            }
        };
        self.send(Message::Disconnect)?;
        receiver.map_or(Ok(()), |receiver| receiver.recv().map_err(|_| "The relay controller stopped".to_owned())?.map(|_| ()))
    }

    fn set_power_save(&self, enabled: bool) -> Result<(), String> { self.call(RelayCommand::PowerSave(enabled)).map(|_| ()) }
    fn set_offload_enabled(&self, enabled: bool) -> Result<Option<Value>, String> { self.call(RelayCommand::Offload(enabled)) }
    fn forget(&self, id: &str) -> Result<(), String> { self.call(RelayCommand::Forget(id.into())).map(|_| ()) }
    fn recheck_clock(&self) -> Result<(), String> {
        if self.commands.get().is_none() && !self.active() {
            return Err("Connect Wi-Fi relay before checking time".into());
        }
        self.call(RelayCommand::Clock).map(|_| ())
    }
}

fn snapshot(i: &State, now: BootInstant) -> Value {
        let s = i.session.as_ref();
        let lease = s.and_then(|s| s.lease.as_ref());
        let ipv6 = s.map(|s| s.ipv6.status()).unwrap_or_else(ipv6::off_status);
        json!({"connected": s.is_some_and(|s| s.selected.is_some() && s.lease.is_some()),
            "network_id": s.and_then(|s| s.selected.as_ref()).map(|n| &n.id),
            "saved_network_id": s.and_then(|s| s.selected.as_ref()).map(|n| saved::key(&n.ssid, n.security)),
            "ssid": s.and_then(|s| s.selected.as_ref()).map(|n| &n.ssid),
            "frequency": s.and_then(|s| s.selected.as_ref()).map(|n| n.frequency),
            "address": lease.map(|l| l.ip), "gateway": lease.map(|l| l.gateway), "networks": i.scans,
            "phase": i.phase, "ipv6_relay": ipv6["nat66"], "ipv6": ipv6,
            "association_state": s.map(|s| s.association.state),
            "association_recovering": s.is_some_and(|s| s.association.since.is_some()),
            "association_recovery_ms": s.map(|s| s.association.elapsed(now).as_millis() as u64),
            "offload": s.map(|s| s.offload.status()),
            "power_save": s.map(|s| s.power_save.status()),
            "tables": s.map(|s| s.uplink.status()),
            "error": i.error.as_ref().or_else(|| s.and_then(|s| s.dns_error.as_ref()))})
    }

struct DevicePort {
    shared: Arc<Shared>,
    mihomo: Option<Arc<crate::mihomo::Mihomo>>,
}

impl DevicePort {
    pub fn recover(&self) -> Result<(), String> {
        stop_strays(&[])?;
        let ipv6 = ipv6::recover();
        let ipv4 = EffectSet::recover(&Path::new(JOURNAL).join("network.json"));
        let dns = EffectSet::recover(&Path::new(JOURNAL).join("dns.json"));
        // Preserve the interface while failed IPv6 recovery still owns it,
        // but never strand IPv4 on an already disconnected STA.
        ipv6.and(ipv4)?;
        let wireless = EffectSet::recover(&Path::new(JOURNAL).join("wireless.json"));
        if let Ok(entries) = fs::read_dir(ROOT) {
            for entry in entries.flatten() {
                if entry.file_name().to_str().is_some_and(|name| name.strip_prefix("ipv4-lease-")
                    .and_then(|s| s.strip_suffix(".json").or_else(|| s.strip_suffix(".new")))
                    .is_some_and(|session| lease_file(Path::new(ROOT), session).is_some())) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        wireless.and(dns)
    }

    fn adopt_previous(&self) -> Option<Session> {
        let target = resume::load(Path::new(JOURNAL))?;
        if !routes_journaled(Path::new(JOURNAL)) || hotspot::owner_off("wlan2") {
            return None;
        }
        let lan = |key: &str| Cmd::new("uci", &["-q", "get", key]).run().ok()?.parse::<Ipv4Addr>().ok();
        let (lan_ip, lan_mask) = (lan("network.lan.ipaddr")?, lan("network.lan.netmask")?);
        let started = Instant::now();
        match adopt::adopt(&target, lan_ip, lan_mask) {
            Ok(session) => {
                crate::netlog!("[relay] took over the previous agent's connection in {} ms", started.elapsed().as_millis());
                Some(session)
            }
            Err(e) => {
                crate::netlog!("[relay] previous connection not taken over ({e}); rolling back and reconnecting");
                None
            }
        }
    }

    fn prepare(&self, cancel: &Cancellation) -> Result<Session, String> {
        // A Wi-Fi reload the agent started is still reconfiguring the radio.
        if crate::netfx::admission::held(crate::netfx::admission::VENDOR_WIFI_RELOAD) {
            return Err("Wi-Fi is still applying its new settings; retry in a moment".into());
        }
        self.recover()?;
        if Path::new(&format!("/sys/class/net/{IFACE}")).exists() {
            return Err("Relay interface already exists; do not take over another process's interface".into());
        }
        let wireless = Cmd::new("uci", &["-q", "show", "wireless"]).run()?;
        let config = crate::ubus::uci_show_map(&wireless);
        for guest in ["wireless.guest_2g.disabled", "wireless.guest_5g.disabled"] {
            if config.get(guest).map(String::as_str) != Some("1") {
                return Err("Turn off Guest WiFi before using relay".into());
            }
        }
        let phy = radio_phy()?;
        let phy = phy.as_str();
        let _ = ap("wlan2", "status", &[]).and_then(|s| {
            if net::key(&s, "state") == Some("ENABLED") {
                Ok(s)
            } else {
                Err("Enable 5 GHz main hotspot first".into())
            }
        })?;
        net::private_dir(Path::new(ROOT))?;
        let mut session = Session::new(Path::new(JOURNAL));
        let result = (|| {
            // Protect INPUT and forwarding before the interface exists,
            // including scan-only sessions (`uplink`). The journal undoes in
            // reverse, so the interface is deleted before its guard goes.
            session.uplink.claim()?;
            let mut guards = input_guards();
            guards.push(session.uplink.resource(None));
            session.wireless.lock().unwrap().declare(guards)?;
            session.uplink.guard()?;
            session
                .wireless
                .lock().unwrap().step(Step::new(Cmd::new("iw", &["phy", phy, "interface", "add", IFACE, "type", "managed"]), Cmd::new("iw", &["dev", IFACE, "del"])))?;
            let base = fs::read_to_string("/sys/class/net/wlan2/address").map_err(|_| "Cannot read radio MAC")?;
            let mut bytes: Vec<u8> = base.trim().split(':').map(|b| u8::from_str_radix(b, 16)).collect::<Result<_, _>>().map_err(|_| "Invalid radio MAC")?;
            if bytes.len() != 6 {
                return Err("Invalid radio MAC".into());
            }
            bytes[0] = (bytes[0] | 2) & !1;
            bytes[5] ^= 0x60;
            let mac = bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
            Cmd::new("ip", &["link", "set", "dev", IFACE, "address", &mac]).run()?;
            // Deleting the interface is the undo.
            session.wireless.lock().unwrap().step(Step::new(Cmd::new("sysctl", &["-w", &format!("net.ipv6.conf.{IFACE}.disable_ipv6=1")]), Cmd::new("true", &[])))?;
            Cmd::new("ip", &["link", "set", "dev", IFACE, "up"]).run()?;
            net::write_private(&Path::new(ROOT).join("wpa.conf"), format!("ctrl_interface={ROOT}/ctrl\nupdate_config=0\n").as_bytes())?;
            let mut cmd = Command::new("wpa_supplicant");
            cmd.args(["-D", "nl80211", "-i", IFACE, "-c", &format!("{ROOT}/wpa.conf"), "-qq"]);
            session.supplicant = Some(Helper::Owned(net::owned_child(cmd)?));
            let mut ready = false;
            for _ in 0..30 {
                self.check(cancel)?;
                if wpa("ping", &[]).is_ok_and(|s| s.ends_with("PONG")) {
                    ready = true;
                    break;
                } else {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            if !ready {
                return Err("wpa_supplicant did not become ready".into());
            }
            // A PONG from another supplicant must not pass for ours.
            if !session.supplicant.as_mut().is_some_and(Helper::alive) {
                return Err("wpa_supplicant exited; another process may own the relay interface".into());
            }
            let old = wpa("driver", &["GETROAMMODE"])?;
            let mode = old.split_whitespace().last().filter(|s| matches!(*s, "0" | "1")).ok_or("Cannot determine original roam mode")?;
            session.wireless.lock().unwrap().step(roam_step(mode))?;
            Ok(())
        })();
        if let Err(e) = result {
            return Err(cleanup(&mut session, || self.uplink_changed()).err().unwrap_or(e));
        }
        Ok(session)
    }

}

impl DevicePort {
    fn uplink_changed(&self) {
        if let Some(core) = &self.mihomo { core.uplink_changed(); }
    }

    fn check(&self, cancel: &Cancellation) -> Result<(), String> {
        cancel.check()?;
        if cancel.target.as_ref().is_some_and(|target| self.shared.active.load(Ordering::Acquire) || resume::load(Path::new(JOURNAL)).as_ref() != Some(target)) {
            return Err(RESTORE_CANCELLED.into());
        }
        Ok(())
    }

    fn set_phase(&self, phase: Phase) { self.shared.phase(phase); }

    fn publish(&mut self, state: &State) {
        let value = <Self as controller::Port>::snapshot(self, state);
        let pending = recovery_pending(Path::new(JOURNAL));
        let cancel = self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.shared.publish(state, value, pending, &cancel);
    }
}

impl controller::Port for DevicePort {
    fn now(&self) -> Instant { Instant::now() }
    fn boot_now(&self) -> BootInstant { BootClock.now() }
    fn snapshot(&mut self, state: &State) -> Value {
        if let Some(core) = &self.mihomo {
            core.set_subscription_dns(state.session.as_ref().and_then(|session| session.lease.as_ref()).map(|lease| if lease.dns.is_empty() { vec![lease.gateway] } else { lease.dns.clone() }).unwrap_or_default());
        }
        let mut value = snapshot(state, BootClock.now());
        value["autostart"] = json!(resume::load(Path::new(JOURNAL)).is_some());
        if !value["offload"].is_object() { value["offload"] = json!({}); }
        value["offload"]["config"] = json!(offload::config());
        value["offload"]["enabled"] = json!(offload::enabled());
        if !value["power_save"].is_object() { value["power_save"] = json!({}); }
        value["power_save"]["auto_off"] = json!(power_save::auto_off(Path::new(JOURNAL)));
        saved::annotate(&mut value);
        value
    }

    fn pending(&self) -> bool { recovery_pending(Path::new(JOURNAL)) }
    fn target(&mut self) -> Option<resume::Resume> { resume::load(Path::new(JOURNAL)) }
    fn clear(&mut self) -> Result<(), String> { resume::clear(Path::new(JOURNAL)) }
    fn hotspot(&mut self) -> (bool, bool) { (hotspot::owner_off("wlan2"), hotspot::off_by_owner("wlan2")) }
    fn recover(&mut self) -> Result<(), String> {
        let routed = routes_journaled(Path::new(JOURNAL));
        let recovered = DevicePort::recover(self);
        if routed && !routes_journaled(Path::new(JOURNAL)) { self.uplink_changed(); }
        recovered
    }
    fn adopt(&mut self) -> Option<Session> { self.adopt_previous() }

    fn scan(&mut self, state: &mut State, cancel: &Cancellation) -> Result<Vec<Network>, String> {
        self.check(cancel)?;
        let mut temporary = if state.session.is_none() { Some(self.prepare(cancel)?) } else { None };
        let result = (|| {
            self.check(cancel)?;
            let channels = scan::Channels::parse(&Cmd::new("iw", &["phy", &radio_phy()?, "channels"]).run()?);
            let plan = channels.plan();
            let mut ctrl = scan::Ctrl::attach(&Path::new(ROOT).join("ctrl").join(IFACE), Path::new(ROOT))?;
            let (table, took) = scan::run(&mut ctrl, &plan, || self.check(cancel))?;
            Ok(parse_bss_on_channels(&table, took.as_secs() + 1, &channels))
        })();
        if let Some(session) = &mut temporary {
            self.set_phase(Phase::Disconnecting);
            cleanup(session, || ())?;
        }
        self.check(cancel)?;
        result
    }

    fn join(&mut self, state: &mut State, selection: Selection, ipv6: bool, cancel: &Cancellation) -> Result<Session, String> {
        self.check(cancel)?;
        let root = Path::new(JOURNAL);
        let selected = selection.network;
        let network_config = selection.config;
        // Country/driver restrictions may have changed since the last scan.
        let channels = scan::Channels::parse(&Cmd::new("iw", &["phy", &radio_phy()?, "channels"]).run()?);
        if !channels.contains(selected.frequency) {
            return Err("The upstream channel is disabled by the radio; scan again".into());
        }
        // A validated replacement owns the next restart choice only once it
        // succeeds. Until then, do not silently restart the previous network.
        if cancel.target.is_none() { resume::clear(root)?; }
        let old = state.session.take();
        self.publish(state);
        // Between 5 GHz upstreams the station and hotspot are handed over
        // (`handover`); otherwise the old session is torn down first.
        let mut handed = None;
        if let Some(mut old) = old {
            let five = |n: Option<&Network>| n.is_some_and(|n| n.frequency > 5000);
            if five(old.selected.as_ref()) && five(Some(&selected)) {
                // The same access point again: IPv6 (its client, addresses,
                // routes, NAT66 and the LAN's RA) goes over as it is.
                let same_bss = old.selected.as_ref().is_some_and(|n| n.bssid == selected.bssid);
                let keep_ipv6 = ipv6 && same_bss && old.ipv6.configured();
                match handover(&mut old, &channels, keep_ipv6, || self.uplink_changed()) {
                    Ok(next) => handed = Some((next, keep_ipv6)),
                    Err(e) => crate::netlog!("[relay] station not handed over ({e}); tearing the old connection down"),
                }
            }
            if handed.is_none() {
                if let Err(e) = cleanup(&mut old, || self.uplink_changed()) {
                    return Err(e);
                }
            }
        }
        let kept = handed.is_some();
        let ipv6_kept = handed.as_ref().is_some_and(|(_, ipv6)| *ipv6);
        let mut session = match handed.map_or_else(|| self.prepare(cancel), |(next, _)| Ok(next)) {
            Ok(session) => session,
            Err(e) => return Err(e),
        };
        let check = || self.check(cancel);
        let result = (|| {
            check()?;
            if !kept {
                hotspot::prepare(&mut session.wireless, selected.frequency, &channels)?;
            }
            check()?;
            net::write_private(&Path::new(ROOT).join("wpa.conf"), format!("ctrl_interface={ROOT}/ctrl\nupdate_config=0\n{network_config}").as_bytes())?;
            // Undo must detach STA before restoring the same-radio AP channel,
            // including a crash between reconfigure and association completion
            // (a handed-over station has that undo already).
            session.wireless.lock().unwrap().step(association_step())?;
            if kept {
                // `handover` disconnected it; a reconfigure alone keeps it so.
                wpa("reconnect", &[]).and_then(expect_ok)?;
            }
            let mut linked = false;
            for _ in 0..30 {
                check()?;
                if wpa("status", &[]).is_ok_and(|s| net::key(&s, "wpa_state") == Some("COMPLETED") && net::key(&s, "bssid") == Some(&selected.bssid)) {
                    linked = true;
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            if !linked {
                return Err("Wi-Fi association failed; check password and signal".into());
            }
            let (nonce, dhcp) = start_dhcp(None)?;
            session.dhcp_session = Some(nonce.clone());
            session.dhcp = Some(dhcp);
            let mut lease = None;
            for _ in 0..25 {
                check()?;
                if let Ok(current) = read_lease(&nonce) {
                    lease = Some(current);
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            let lease = lease.ok_or("No usable DHCP lease received")?;
            let lan_ip: Ipv4Addr = Cmd::new("uci", &["-q", "get", "network.lan.ipaddr"]).run()?.parse().map_err(|_| "Invalid LAN address")?;
            let lan_mask: Ipv4Addr = Cmd::new("uci", &["-q", "get", "network.lan.netmask"]).run()?.parse().map_err(|_| "Invalid LAN mask")?;
            let prefix = validate_lease(&lease, lan_ip, lan_mask)?;
            if fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default().trim() != "1" {
                return Err("Router IPv4 forwarding is disabled".into());
            }
            // The tables grow (forwarding, DNS, the IPv6 baseline) after the
            // legacy accepts and routes, before the policy rule moves traffic.
            let mut plan = relay_plan(&lease, prefix, lan_ip, lan_mask);
            let rule = plan.pop().expect("the policy rule is the plan's last step");
            session.network.declare(plan)?;
            // LAN web traffic skips the vendor's offline redirect before the
            // policy rule moves it; a handed-over session holds the RETURN.
            for step in portal::web_bypasses() {
                session.dns.declare(vec![step])?;
            }
            session.uplink.update(|l| l.relay = Some(relay_layout(&lease, lan_ip, lan_mask)))?;
            session.network.declare(vec![rule])?;
            session.routed = true;
            let route = Cmd::new("ip", &["-4", "route", "get", "1.1.1.1"]).run()?;
            if !route.contains(&format!("dev {IFACE}")) {
                return Err("Firmware policy routing did not select the Wi-Fi upstream".into());
            }
            // CPU-path help and hardware forwarding are optional: the relay
            // works without them.
            if let Err(e) = session.network.declare(steering::plan()) {
                crate::netlog!("[relay] receive steering not applied: {e}");
            }
            if power_save::auto_off(Path::new(JOURNAL)) {
                let _ = session.power_save.set(&mut session.network, true);
            }
            let subnet = format!("{}/{prefix}", Ipv4Addr::from(u32::from(lease.ip) & u32::from(lease.subnet)));
            session.offload = offload::Runtime::start(&mut session.network, lease.gateway, subnet);
            session.dns.declare(vec![resolver(&lease)])?;
            // After a handover the switch already reads 0 (held): no step,
            // no dnsmasq restart.
            if let Some(step) = portal::plan()? {
                session.dns.declare(vec![step])?;
            }
            // A new uplink must not reuse the previous network's clock check.
            let _ = crate::network_clock::recheck_wifi();
            if !ipv6_kept {
                session.ipv6.start(ipv6)?;
            }
            check()?;
            if hotspot::owner_off("wlan2") || (selected.frequency < 3000 && hotspot::owner_off("wlan0")) {
                return Err("Hotspot was turned off while connecting relay".into());
            }
            session.lease = Some(lease);
            session.selected = Some(selected.clone());
            Ok(())
        })();
        if let Err(e) = result {
            let off = hotspot::owner_off("wlan2") || (selected.frequency < 3000 && hotspot::owner_off("wlan0"));
            let by_owner = off && (hotspot::off_by_owner("wlan2") || (selected.frequency < 3000 && hotspot::off_by_owner("wlan0")));
            let clear_error = if by_owner { resume::clear(root).err() } else { None };
            if off { self.shared.cancel_restore(); }
            self.set_phase(Phase::Disconnecting);
            let e = cleanup(&mut session, || self.uplink_changed()).err().unwrap_or(e);
            state.error = clear_error.or_else(|| (e != RESTORE_CANCELLED).then(|| e.clone()));
            return Err(e);
        }
        if !cancel.shared.generation_matches(cancel.generation) {
            self.set_phase(Phase::Disconnecting);
            let cleaned = cleanup(&mut session, || self.uplink_changed());
            return cleaned.and(Err(RESTORE_CANCELLED.into()));
        }
        Ok(session)
    }

    fn persist(&mut self, selection: &Selection, ipv6: bool, remember: bool) -> Option<String> {
        let mut error = None;
        if let Err(problem) = saved::remember(&selection.network, remember.then_some(selection.password.as_str())) { error = Some(format!("Relay connected, but {problem}")); }
        let kept = selection.network.security == "open" || saved::password(&selection.network).ok().flatten().is_some_and(|password| password == selection.password);
        if kept {
            if let Err(problem) = resume::save(Path::new(JOURNAL), &selection.network, ipv6) { error = Some(format!("Relay connected, but {problem}")); }
        }
        error
    }

    fn cleanup(&mut self, session: &mut Session) -> Result<(), String> { cleanup(session, || self.uplink_changed()) }
    fn observe_link(&mut self) -> (Option<String>, u128) {
        let started = Instant::now();
        let status = scan::status(&Path::new(ROOT).join("ctrl").join(IFACE), Path::new(ROOT)).ok();
        (status.as_deref().and_then(|text| net::key(text, "wpa_state")).map(str::to_owned), started.elapsed().as_millis())
    }
    fn observe(&mut self, session: &mut Session) -> Observation {
        let lease = session.dhcp_session.as_deref().and_then(|session| read_lease(session).ok());
        let helpers = session.supplicant.as_mut().is_some_and(Helper::alive) && session.dhcp.as_mut().is_some_and(|child| matches!(child.try_wait(), Ok(None)));
        let change = session.lease.as_ref().map_or(LeaseChange::Replaced, |installed| lease_change(installed, lease.as_ref()));
        let resolvers_valid = match change { LeaseChange::Resolvers(ref next) => resolvers_acceptable(next), _ => true };
        let two = session.selected.as_ref().is_some_and(|network| network.frequency < 3000);
        let hotspot_off = hotspot::owner_off("wlan2") || (two && hotspot::owner_off("wlan0"));
        let by_owner = hotspot_off && (hotspot::off_by_owner("wlan2") || (two && hotspot::off_by_owner("wlan0")));
        Observation { #[cfg(test)] link: None, lease, helpers, resolvers_valid, hotspot_off, by_owner }
    }
    fn renew(&mut self, session: &mut Session) { session.renew_lease(); }
    fn maintain(&mut self, session: &mut Session) -> Result<bool, String> {
        let lease = session.lease.as_ref().unwrap();
        let resolvers = if lease.dns.is_empty() { vec![lease.gateway] } else { lease.dns.clone() };
        let dns = dns::reconcile(&resolvers);
        if let Some(Err(error)) = crate::netfx::conntrack::retry() { crate::netlog!("[relay] connection reset retry failed: {error}"); }
        let guard_due = session.guard.due();
        let guarded = if guard_due {
            let _pass = net::Pass::open();
            let mut result = session.uplink.reconcile();
            result.extend(session.wireless.lock().unwrap().reconcile_only(firewall_resource));
            result.extend(session.network.reconcile());
            result.extend(session.dns.reconcile());
            result.extend(session.ipv6.reconcile());
            session.guard.after(&result);
            crate::net_guard::report("relay", result)
        } else { Ok(()) };
        session.dns_error = dns.and(guarded).err();
        let before = session.ipv6.revision();
        session.ipv6.tick(guard_due)?;
        Ok(before != session.ipv6.revision())
    }
    fn uplink_changed(&self) { DevicePort::uplink_changed(self); }
    fn power_save(&mut self, state: &mut State, auto_off: bool) -> Result<(), String> {
        power_save::save(Path::new(JOURNAL), auto_off)?;
        let result = state.session.as_mut().map_or(Ok(()), |session| session.power_save.set(&mut session.network, auto_off));
        result.map_err(|error| format!("Setting saved. {error}"))
    }
    fn offload(&mut self, state: &mut State, enabled: bool) -> Result<Option<Value>, String> {
        offload::set_enabled(enabled)?;
        crate::netlog!("[relay] hardware forwarding switched {}", if enabled { "on" } else { "off" });
        let Some(session) = state.session.as_mut() else { return Ok(None) };
        let changed_at = Instant::now();
        let changed = session.offload.sync(&mut session.network);
        self.publish(state);
        match changed {
            Ok(true) => Ok(Some(match crate::netfx::conntrack::reset_since("relay forwarding path changed", crate::netfx::conntrack::Scope::Lan { v4: true, v6: false }, changed_at) {
                Ok(report) => report.json(), Err(error) => crate::netfx::conntrack::failed_json(&error),
            })),
            Ok(false) => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn forget(&mut self, id: &str) -> Result<(), String> { saved::forget(id) }
    fn clock(&mut self) -> Result<(), String> { crate::network_clock::recheck_wifi() }
}

/// Seconds before each restore attempt: about 17 minutes in all, for a boot
/// (hotspot and DFS checks first) or an upstream that is itself restarting.
const RESTORE_WAITS: [u64; 10] = [0, 10, 20, 30, 60, 60, 120, 120, 300, 300];
const RESTORE_CANCELLED: &str = "Restore cancelled by the owner";
const RESTORE_NO_PASSWORD: &str = "The network's password is no longer remembered";

/// Time since the first failed observation, independent of sampling cadence.
/// Lease loss, helper death and explicit owner shutdown bypass this grace.
const ASSOCIATION_GRACE: Duration = Duration::from_secs(12);

#[derive(Debug, PartialEq, Eq)]
enum AssociationResult {
    Ready,
    Recovering,
    Expired,
}

struct Association {
    since: Option<BootInstant>,
    state: &'static str,
}
impl Default for Association {
    fn default() -> Self {
        Self {
            since: None,
            state: "COMPLETED",
        }
    }
}
impl Association {
    fn elapsed(&self, now: BootInstant) -> Duration {
        self.since
            .map_or(Duration::ZERO, |at| now.saturating_duration_since(at))
    }
    fn observe(&mut self, state: Option<&str>, now: BootInstant) -> AssociationResult {
        // Whitelisted diagnostics only, never raw tool output or credentials.
        self.state = match state {
            Some("COMPLETED") => "COMPLETED",
            Some("SCANNING") => "SCANNING",
            Some("ASSOCIATING") => "ASSOCIATING",
            Some("ASSOCIATED") => "ASSOCIATED",
            Some("4WAY_HANDSHAKE") => "4WAY_HANDSHAKE",
            Some("GROUP_HANDSHAKE") => "GROUP_HANDSHAKE",
            Some("DISCONNECTED") => "DISCONNECTED",
            Some(_) => "OTHER",
            None => "QUERY_UNAVAILABLE",
        };
        if self.state == "COMPLETED" {
            self.since = None;
            return AssociationResult::Ready;
        }
        self.since.get_or_insert(now);
        if self.elapsed(now) >= ASSOCIATION_GRACE {
            AssociationResult::Expired
        } else {
            AssociationResult::Recovering
        }
    }
}

/// What one 3 s observation of an active session decides (section 6.2):
/// observing is the tick's, deciding is this, acting is the tick's again.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// Tear the session down, for this reason (in this order of precedence).
    Teardown(&'static str),
    /// Association lost within the grace: keep the path, extend nothing.
    Hold,
    /// Keep it, with the renewed resolvers to adopt, if any.
    Keep(Option<Lease>),
}

fn decide(link: AssociationResult, helpers_alive: bool, change: LeaseChange, hotspot_off: bool) -> Decision {
    if hotspot_off {
        Decision::Teardown("hotspot_off")
    } else if !helpers_alive {
        Decision::Teardown("helper_exited")
    } else if change == LeaseChange::Replaced {
        Decision::Teardown("lease_changed")
    } else if link == AssociationResult::Expired {
        Decision::Teardown("association_timeout")
    } else if link == AssociationResult::Recovering {
        Decision::Hold
    } else {
        Decision::Keep(match change {
            LeaseChange::Resolvers(next) => Some(next),
            _ => None,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LeaseChange {
    Same,
    /// Only the resolver list beyond the one the DNS rules point at differs.
    Resolvers(Lease),
    Replaced,
}

/// The installed rules bake in the address, mask, gateway and the first
/// resolver. Anything else in a renewal (extra or reordered resolvers) can be
/// adopted in place; a missing lease or a different baked-in value cannot.
fn lease_change(installed: &Lease, current: Option<&Lease>) -> LeaseChange {
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
fn resolvers_acceptable(lease: &Lease) -> bool {
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

#[derive(Clone, Copy)]
enum Origin<'a> {
    /// A connect request; `remember` saves its password.
    Owner { remember: bool, generation: u64 },
    /// `restore`: only while this is still the network to restore.
    Restore(&'a resume::Resume, u64),
}

impl Origin<'_> {
    fn generation(self) -> u64 {
        match self { Self::Owner { generation, .. } | Self::Restore(_, generation) => generation }
    }
}

fn selected_config(scans: &[Network], id: &str, password: &str) -> Result<(Network, String, String), String> {
    let selected = scans.iter().find(|n| n.id == id && n.supported).cloned().ok_or("Scan and select a supported network first")?;
    let password = if password.is_empty() && selected.security == "wpa2" { saved::password(&selected)?.unwrap_or_default() } else { password.to_owned() };
    if selected.security != "open" && password.is_empty() { return Err(RESTORE_NO_PASSWORD.into()); }
    let config = wpa_network(&selected, &password)?;
    Ok((selected, password, config))
}

/// The radio behind the 5 GHz main hotspot, which also carries the STA.
fn radio_phy() -> Result<String, String> {
    let phy = fs::canonicalize("/sys/class/net/wlan2/phy80211").map_err(|_| "Enable the 5 GHz main hotspot first")?;
    phy.file_name()
        .and_then(|p| p.to_str())
        .filter(|p| p.starts_with("phy") && p[3..].bytes().all(|b| b.is_ascii_digit()))
        .map(str::to_owned)
        .ok_or_else(|| "Cannot identify the active Wi-Fi PHY".into())
}

/// Whether a journal holds relay routes (IPv4 or IPv6) still to undo.
fn routes_journaled(root: &Path) -> bool {
    ["network.json", "ipv6-network.json"].iter().any(|name| root.join(name).exists())
}

fn recovery_pending(root: &Path) -> bool {
    [
        "network.json",
        "wireless.json",
        "dns.json",
        "ipv6-setup.json",
        "ipv6-network.json",
        "ra-runtime.json",
    ]
    .iter()
    .any(|name| root.join(name).exists())
}

/// Where a monitor of `offload` records its process id (`stop_strays`).
pub(crate) fn pid_file(name: &str) -> std::path::PathBuf {
    Path::new(ROOT).join(format!("{name}.pid"))
}

/// The monitors whose processes an agent recorded.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const MONITORS: [&str; 2] = ["relay-neigh", "relay-lan"];

/// A relay helper on the station interface with our private paths
/// (`stop_strays`).
/// The monitors' command lines are common, so only the recorded process (id
/// and start time, this boot) is one: not an `iw event` run by hand, not a
/// process that reused the id.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn stray(args: &[String], process: offload::Record, recorded: &[offload::Record]) -> bool {
    let Some(program) = args.first().and_then(|a| a.rsplit('/').next()) else { return false };
    let after = |flag: &str| args.windows(2).find(|w| w[0] == flag).map(|w| w[1].as_str());
    let station = |name: Option<&str>| name == Some(IFACE);
    match program {
        "wpa_supplicant" => station(after("-i")) && after("-c").is_some_and(|c| [format!("{ROOT}/wpa.conf"), format!("{ROOT}/recover.conf")].iter().any(|p| p == c)),
        "odhcp6c" => station(args.last().map(String::as_str)) && after("-p") == Some(&format!("{ROOT}/odhcp6c.pid")),
        "udhcpc" => station(after("-i")),
        // `offload`'s monitors: an orphan only exits at its next write.
        "ip" => args.len() == 6 && args[1..5] == ["-4", "monitor", "neigh", "dev"] && station(Some(args[5].as_str())) && recorded.contains(&process),
        "iw" => args[1..] == ["event", "-t"] && recorded.contains(&process),
        _ => false,
    }
}

/// Relay helpers a previous agent left running. B31 runs wpa_supplicant in
/// SELinux domain `wpad.subj`, odhcp6c in `odhcp6c.subj`, ip in `ip.subj` and iw in `iw.subj`,
/// and the kernel clears the parent-death signal on any exec that changes
/// domain (even in permissive mode), so they outlive the agent. The old
/// supplicant keeps the control socket: a new one exits at once and every
/// command reaches the old one; the old odhcp6c keeps calling the new binary.
/// Only callers without a live session reach here, and our own children are
/// never matched. `spare`: the helpers an adopting agent keeps (`adopt`).
#[cfg(target_os = "linux")]
fn stop_strays(spare: &[offload::Record]) -> Result<(), String> {
    let me = std::process::id().to_string();
    let boot = net::boot_id();
    let recorded: Vec<offload::Record> = MONITORS.iter().filter_map(|name| offload::Record::parse(&fs::read_to_string(pid_file(name)).ok()?, &boot)).collect();
    let strays: Vec<(libc::pid_t, u64)> = fs::read_dir("/proc")
        .map_err(|_| "Cannot list processes")?
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_str()?.parse::<libc::pid_t>().ok()?;
            let cmdline = fs::read(entry.path().join("cmdline")).ok()?;
            let args: Vec<String> = cmdline.split(|&b| b == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
            let status = fs::read_to_string(entry.path().join("status")).ok()?;
            let parent = status.lines().find_map(|l| l.strip_prefix("PPid:")).map(str::trim);
            let process = offload::Record { pid: pid as u32, start: crate::netfx::exec::process_start(pid as u32)? };
            (stray(&args, process, &recorded) && parent != Some(me.as_str()) && !spare.contains(&process)).then_some((pid, process.start))
        })
        .collect();
    // Only a previous agent's records are left here: a live session has none.
    for name in MONITORS {
        let _ = fs::remove_file(pid_file(name));
    }
    if strays.is_empty() {
        return Ok(());
    }
    crate::netlog!("[relay] stopping {} helper(s) left by a previous agent", strays.len());
    // A zombie has an empty command line; its parent (init) reaps it.
    // Also the same process: a reused id is never signalled.
    let alive = |(pid, start): &(libc::pid_t, u64)| fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| !c.is_empty()) && crate::netfx::exec::process_start(*pid as u32) == Some(*start);
    for (signal, wait) in [(libc::SIGTERM, 10), (libc::SIGKILL, 10)] {
        for (pid, _) in strays.iter().filter(|p| alive(p)) {
            // SAFETY: plain kill(2) on a process matched and re-identified just above.
            unsafe { libc::kill(*pid, signal) };
        }
        for _ in 0..wait {
            if !strays.iter().any(alive) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Err("A previous relay helper is still running; retry".into())
}

#[cfg(not(target_os = "linux"))]
fn stop_strays(_spare: &[offload::Record]) -> Result<(), String> {
    Ok(())
}

fn wpa_command(action: &str, args: &[&str]) -> Cmd {
    let mut all = vec!["-p", "/tmp/zte-agent-relay/ctrl", "-i", IFACE, action];
    all.extend_from_slice(args);
    Cmd::new("wpa_cli", &all)
}

fn wpa(action: &str, args: &[&str]) -> Result<String, String> {
    wpa_command(action, args).run()
}

/// Whether hostapd runs `iface` (`ENABLED`).
pub(crate) fn hotspot_enabled(iface: &str) -> bool {
    ap(iface, "status", &[]).is_ok_and(|s| net::key(&s, "state") == Some("ENABLED"))
}

fn ap(iface: &str, action: &str, args: &[&str]) -> Result<String, String> {
    let mut all = vec!["-p", HOSTAPD, "-i", iface, action];
    all.extend_from_slice(args);
    Cmd::new("hostapd_cli", &all).run()
}

fn expect_ok(text: String) -> Result<(), String> {
    if text.lines().last() == Some("OK") {
        Ok(())
    } else {
        Err("Wi-Fi control command was refused".into())
    }
}

fn roam_step(mode: &str) -> Step {
    Step::new(
        Cmd::new("wpa_cli", &["-p", "/tmp/zte-agent-relay/ctrl", "-i", IFACE, "driver", "SETROAMMODE", "1"]),
        Cmd::new("@u60-relay-roam", &[mode]),
    )
}

fn association_step() -> Step {
    Step::new(wpa_command("reconfigure", &[]), Cmd::new("@u60-relay-detach", &[]))
}

/// Only an owned association journal invokes this. Normal cleanup stops an
/// unresponsive supplicant first; after a crash `stop_strays` did so.
pub(crate) fn detach_station() -> Result<(), String> {
    if !Path::new(&format!("/sys/class/net/{IFACE}")).exists() {
        return Ok(());
    }
    detach_with(|command| command.run(), || std::thread::sleep(Duration::from_millis(100)))
}

fn detach_with(mut run: impl FnMut(&Cmd) -> Result<String, String>, mut wait: impl FnMut()) -> Result<(), String> {
    // DISCONNECT prevents a live supplicant from immediately reassociating.
    // Driver state, not this acknowledgement, gates AP restoration.
    let _ = run(&wpa_command("disconnect", &[]));
    let link = Cmd::new("iw", &["dev", IFACE, "link"]);
    if run(&link)?.trim() == "Not connected." {
        return Ok(());
    }
    let _ = run(&Cmd::new("iw", &["dev", IFACE, "disconnect"]));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    for _ in 0..20 {
        if run(&link)?.trim() == "Not connected." {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        wait();
    }
    Err("Cannot confirm upstream Wi-Fi disconnected; hotspot recovery was retained".into())
}

/// On a same-boot restart the owned supplicant has died, but its interface
/// still exists. Recreate only its control socket to restore the driver mode
/// before the journal deletes that interface. No association is configured.
pub(crate) fn restore_roam(mode: &str) -> Result<(), String> {
    if !Path::new(&format!("/sys/class/net/{IFACE}")).exists() {
        return Ok(());
    }
    let mut recovery = None;
    if !wpa("ping", &[]).is_ok_and(|s| s.ends_with("PONG")) {
        let config = Path::new(ROOT).join("recover.conf");
        net::write_private(&config, format!("ctrl_interface={ROOT}/ctrl\nupdate_config=0\n").as_bytes())?;
        let mut cmd = Command::new("wpa_supplicant");
        cmd.args(["-D", "nl80211", "-i", IFACE, "-c"]).arg(&config).arg("-qq");
        recovery = Some(net::owned_child(cmd)?);
        let _ready = (0..30).any(|_| {
            if wpa("ping", &[]).is_ok_and(|s| s.ends_with("PONG")) {
                true
            } else {
                std::thread::sleep(Duration::from_millis(100));
                false
            }
        });
    }
    let restored = wpa("driver", &["SETROAMMODE", mode]).and_then(expect_ok);
    net::stop_child(&mut recovery);
    let _ = fs::remove_file(Path::new(ROOT).join("recover.conf"));
    restored
}

/// A switch between 5 GHz upstreams: the old session's hardware path, IPv6,
/// routes, resolver, lease and association go, as in `cleanup`; its station,
/// supplicant, guard, hotspot journal and the offline-redirect suppression
/// (`portal`) stay for the next session (`successor`), and the hotspot only
/// goes back to the non-DFS staging channel (`hotspot::restage`)
/// instead of first returning to the owner's 160 MHz channel and its radar
/// check (about 65 s on B31). `keep_ipv6` (the same access point again):
/// IPv6 stays as it is and goes to the next session too; the station keeps
/// its addresses and routes across the reassociation. `Err` leaves `old`
/// for `cleanup` to finish.
fn handover(old: &mut Session, channels: &scan::Channels, keep_ipv6: bool, uplink_changed: impl FnOnce()) -> Result<Session, String> {
    if crate::netfx::admission::held(crate::netfx::admission::VENDOR_WIFI_RELOAD) {
        return Err("Wi-Fi is still applying its new settings".into());
    }
    if !old.supplicant.as_mut().is_some_and(Helper::alive) {
        return Err("the supplicant exited".into());
    }
    old.offload.stop();
    if !keep_ipv6 {
        old.ipv6.stop()?;
    }
    if let Err(e) = old.uplink.update(|l| l.relay = None) {
        crate::netlog!("[relay] relay tables not narrowed before releasing routes (the journal removes them): {e}");
    }
    let routes = old.network.release();
    // Only the resolver follows the lease. Released here, the switch read 1
    // until the next lease and a fw3 reload in that gap let the vendor's
    // DNAT in for good (`portal`); the next session holds both as they are.
    let dns = old.dns.withdraw(&[resolver_key()]);
    if std::mem::take(&mut old.routed) {
        uplink_changed();
    }
    routes.and(dns)?;
    net::stop_child(&mut old.dhcp);
    if let Some(path) = old.dhcp_session.take().and_then(|session| lease_file(Path::new(ROOT), &session)) {
        let _ = fs::remove_file(path);
    }
    wpa("disconnect", &[]).and_then(expect_ok)?;
    hotspot::restage(channels)?;
    let next = successor(old, keep_ipv6, Path::new(JOURNAL));
    crate::netlog!("[relay] station handed over to the next upstream{}; the hotspot waits on its staging channel", if keep_ipv6 { " with its IPv6" } else { "" });
    Ok(next)
}

/// The next session of a handover. From here the station and the hotspot
/// journal (`wireless`), the tables, the supplicant, IPv6 when kept and
/// what the handover left of `dns` (the offline-redirect suppression) are
/// its own; `old` is dropped, never cleaned up, and its empty replacements
/// never roll back (and so remove) the journals that moved.
fn successor(old: &mut Session, keep_ipv6: bool, journal: &Path) -> Session {
    let mut next = Session::new(journal);
    next.wireless = Arc::clone(&old.wireless);
    next.dns = std::mem::replace(&mut old.dns, EffectSet::new("relay", journal.join("dns.json")));
    next.uplink = old.uplink.clone();
    next.ipv6 = if keep_ipv6 {
        std::mem::replace(&mut old.ipv6, ipv6::Upstream::new(next.uplink.clone()))
    } else {
        ipv6::Upstream::new(next.uplink.clone())
    };
    next.supplicant = old.supplicant.take();
    next
}

/// Tears the session down. `uplink_changed` runs only when the session had
/// installed its routes: a failed connection or a scan changes no uplink.
fn cleanup(s: &mut Session, uplink_changed: impl FnOnce()) -> Result<(), String> {
    s.offload.stop();
    let ipv6 = s.ipv6.stop();
    // Back to the guard before the routes go; the station is still up.
    if let Err(e) = s.uplink.update(|l| l.relay = None) {
        crate::netlog!("[relay] relay tables not narrowed before releasing routes (the journal removes them): {e}");
    }
    let routes = s.network.release();
    let dns = s.dns.release();
    // Rebind the proxy as soon as routes/DNS are released, before hotspot CAC.
    if std::mem::take(&mut s.routed) {
        uplink_changed();
    }
    if let Err(e) = ipv6 {
        net::stop_child(&mut s.dhcp);
        stop_helper(&mut s.supplicant);
        return routes.and(dns).and(Err(e));
    }
    net::stop_child(&mut s.dhcp);
    if s.supplicant.is_some() && wpa("disconnect", &[]).and_then(expect_ok).is_err() {
        // Without an acknowledged DISCONNECT it could reassociate between
        // the journal's link check and restoring the AP channel.
        stop_helper(&mut s.supplicant);
    }
    let wireless = s.wireless.lock().unwrap().release();
    if wireless.is_ok() {
        s.uplink.forget();
    }
    stop_helper(&mut s.supplicant);
    if let Some(path) = s.dhcp_session.take().and_then(|session| lease_file(Path::new(ROOT), &session)) {
        let _ = fs::remove_file(path);
    }
    let _ = fs::remove_file(Path::new(ROOT).join("wpa.conf"));
    routes.and(wireless).and(dns)
}

/// The `wireless` plan's firewall steps (the upstream INPUT accepts), which
/// `net_guard` re-checks; its radio steps cannot be re-applied.
fn firewall_resource(resource: &Resource) -> bool {
    matches!(resource, Resource::LegacyChain(_) | Resource::LegacyHook(_))
}

/// What must pass the vendor's INPUT rejects from the upstream: established
/// replies and DHCP offers (IPv6 hooks its own `U60_R6_IN` in here). The
/// guard's drop is in `uplink`; these chains hold accepts only, so a rule
/// re-added out of order can neither open nor close anything else.
pub(crate) fn input_guards() -> Vec<Resource> {
    vec![Resource::LegacyChain(LegacyChain { tool: LegacyTool::V4, table: "filter".into(), name: "U60_RELAY_IN".into(), rules: vec![
        words(&["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]),
        words(&["-p", "udp", "--sport", "67", "--dport", "68", "-j", "ACCEPT"]),
    ] }), Resource::LegacyHook(LegacyHook { tool: LegacyTool::V4, table: "filter".into(), chain: "INPUT".into(), rule: words(&["-i", IFACE, "-j", "U60_RELAY_IN"]), position: Position::InsertFirst })]
}

fn words(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

/// The tables' part for installed routes: the resolver DNS goes to and the
/// LAN it keeps.
fn relay_layout(l: &Lease, lan: Ipv4Addr, mask: Ipv4Addr) -> uplink::Relay {
    let lan = format!("{}/{}", Ipv4Addr::from(u32::from(lan) & u32::from(mask)), u32::from(mask).count_ones());
    uplink::Relay { dns: l.dns.first().copied().unwrap_or(l.gateway), lan }
}

/// The `dns` transaction's resolver line (`dns`), which follows the lease.
fn resolver(l: &Lease) -> Resource {
    let dns = l.dns.first().copied().unwrap_or(l.gateway).to_string();
    Resource::Internal(Internal::new("@u60-relay-dns", vec![dns], vec![]))
}

fn resolver_key() -> Key {
    Key::Internal("@u60-relay-dns", Cmd::new("@u60-relay-dns", &[]))
}

/// Addresses, routes, the legacy accepts and MASQUERADE; the policy rule is
/// last (the caller loads the tables before it). The portal RETURN is not
/// here: `handover` rolls this plan back, and the RETURN stays with the
/// switch in `dns` (`portal::web_bypasses`).
pub(crate) fn relay_plan(l: &Lease, prefix: u32, lan: Ipv4Addr, mask: Ipv4Addr) -> Vec<Resource> {
    let address = format!("{}/{prefix}", l.ip);
    let subnet = format!("{}/{prefix}", Ipv4Addr::from(u32::from(l.ip) & u32::from(l.subnet)));
    let lan_net = format!("{}/{}", Ipv4Addr::from(u32::from(lan) & u32::from(mask)), u32::from(mask).count_ones());
    let mut p = vec![Resource::Addr(Addr { family: Family::V4, device: IFACE.into(), address, broadcast: None, valid_lft: None, preferred_lft: None, noprefixroute: false })];
    let mut connected = Route::new(Family::V4, RouteType::Unicast, &subnet, TABLE);
    connected.device = Some(IFACE.into());
    connected.scope = Some("link".into());
    connected.source = Some(l.ip.to_string());
    p.push(Resource::Route(connected));
    // Other RFC1918 subnets can host the hotel's portal/DNS. Only our own
    // management/tailnet/link-local routes fall through to the main tables.
    for dest in crate::netfx::ids::LOCAL_ROUTES_V4.iter().copied().chain([lan_net.as_str()]) {
        if dest != subnet {
            p.push(Resource::Route(Route::new(Family::V4, RouteType::Throw, dest, TABLE)));
        }
    }
    let mut default = Route::new(Family::V4, RouteType::Unicast, "default", TABLE);
    default.gateway = Some(l.gateway.to_string());
    default.device = Some(IFACE.into());
    p.push(Resource::Route(default));
    // Through the vendor's FORWARD rejects; `uplink` drops the rest first.
    p.push(Resource::LegacyChain(LegacyChain { tool: LegacyTool::V4, table: "filter".into(), name: "U60_RELAY_FWD".into(), rules: vec![
        words(&["-i", "br-lan", "-o", IFACE, "-j", "ACCEPT"]),
        words(&["-i", IFACE, "-o", "br-lan", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]),
    ] }));
    p.push(Resource::LegacyHook(LegacyHook { tool: LegacyTool::V4, table: "filter".into(), chain: "FORWARD".into(), rule: words(&["-j", "U60_RELAY_FWD"]), position: Position::InsertFirst }));
    // Core/router UDP sockets may retain a previously selected SIM source.
    // Translate only our owned Wi-Fi egress, not cellular or local traffic
    // (it stays in legacy until an nft MASQUERADE is shown to keep hardware
    // forwarding, D11). It also covers router DNS that `uplink` redirects
    // from a socket bound to a SIM source. Its comment is its identity
    // (`owned_rule`): the station's name is one the vendor's files list.
    p.push(Resource::LegacyHook(LegacyHook { tool: LegacyTool::V4, table: "nat".into(), chain: "POSTROUTING".into(), rule: words(&["-o", IFACE, "-m", "comment", "--comment", crate::netfx::ids::RELAY_COMMENT, "-j", "MASQUERADE"]), position: Position::InsertFirst }));
    // Installed last: no downstream traffic switches until NAT/guards exist.
    p.push(Resource::Rule(Rule { family: Family::V4, priority: PREF.parse().unwrap(), table: TABLE.into(), mark: None }));
    p
}

fn channel(f: u32) -> Option<u32> {
    if (2412..=2472).contains(&f) && (f - 2407).is_multiple_of(5) {
        return Some((f - 2407) / 5);
    }
    if f == 2484 {
        return Some(14);
    }
    let ch = f.checked_sub(5000)? / 5;
    ((5005..=5895).contains(&f) && (f - 5000).is_multiple_of(5)).then_some(ch)
}

fn decode_ssid(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |byte: u8| (byte as char).to_digit(16).map(|n| n as u8);
    let mut bytes = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if i + 3 < b.len() && &b[i..i + 2] == b"\\x" {
            // Scan output is untrusted UTF-8: byte offsets need not be
            // character boundaries when a malformed escape follows \\x.
            if let (Some(hi), Some(lo)) = (hex(b[i + 2]), hex(b[i + 3])) {
                bytes.push(hi * 16 + lo);
                i += 4;
                continue;
            }
        }
        if b[i] == b'\\' && matches!(b.get(i + 1), Some(b'\\' | b'"')) {
            i += 1;
        }
        bytes.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Fresh entries of the supplicant's `BSS` pages (`====`/`####` after each
/// entry) as (bssid, MHz, dBm, flags, ssid). Entries older than `max_age`
/// seconds came from the kernel's cache, not this scan, and are left out.
fn fresh_bss(text: &str, max_age: u64, mut each: impl FnMut(&str, u32, i32, &str, &str)) {
    let mut fields = std::collections::HashMap::new();
    for line in text.lines().chain(["===="]) {
        if line != "====" && line != "####" {
            if let Some((key, value)) = line.split_once('=') {
                fields.insert(key, value);
            }
            continue;
        }
        let field = |key| fields.get(key).copied().unwrap_or("");
        let fresh = field("age").parse::<u64>().is_ok_and(|age| age <= max_age);
        if let (true, Ok(frequency), Ok(signal)) = (fresh, field("freq").parse(), field("level").parse()) {
            each(field("bssid"), frequency, signal, field("flags"), field("ssid"));
        }
        fields.clear();
    }
}

/// Networks offered for relay, strongest first.
pub fn parse_bss(text: &str, max_age: u64) -> Vec<Network> {
    let mut out: Vec<Network> = Vec::new();
    fresh_bss(text, max_age, |bssid, frequency, signal, flags, ssid| out.extend(network(bssid, frequency, signal, flags, ssid)));
    out.sort_by_key(|n| std::cmp::Reverse(n.signal));
    out.truncate(80);
    out
}

/// A cached BSS can be returned even when its channel was not scanned.
/// Only the PHY's currently enabled channels may be offered for connection.
fn parse_bss_on_channels(text: &str, max_age: u64, channels: &scan::Channels) -> Vec<Network> {
    let mut networks = parse_bss(text, max_age);
    for network in &mut networks {
        network.supported &= channels.contains(network.frequency);
    }
    networks
}

fn network(bssid: &str, frequency: u32, signal: i32, flags: &str, ssid: &str) -> Option<Network> {
    if bssid.len() != 17 || !bssid.split(':').all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }
    let ssid = decode_ssid(ssid);
    if ssid.is_empty() || ssid.len() > 32 || ssid.chars().any(char::is_control) {
        return None;
    }
    let security = if flags.contains("WPA2-PSK") {
        "wpa2"
    } else if flags == "[ESS]" || flags == "[WPS][ESS]" {
        "open"
    } else {
        "unsupported"
    };
    let id = network_id(bssid, frequency, &ssid);
    Some(Network { id, ssid, frequency, signal, security, supported: security != "unsupported" && channel(frequency).is_some(), bssid: bssid.into() })
}

/// A scanned network's id: stable for one BSS, channel and name.
fn network_id(bssid: &str, frequency: u32, ssid: &str) -> String {
    format!("{:x}", Sha256::digest(format!("{bssid}:{frequency}:{ssid}").as_bytes()))[..16].to_owned()
}

fn wpa_network(n: &Network, password: &str) -> Result<String, String> {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    // scan_freq keeps the supplicant's own scans to one channel: the driver
    // drops 5 GHz from multi-channel scans while the hotspot runs 160 MHz.
    let mut config = format!("network={{\nssid={}\nbssid={}\nfreq_list={f}\nscan_freq={f}\n", hex(n.ssid.as_bytes()), n.bssid, f = n.frequency);
    match n.security {
        "open" if password.is_empty() => config.push_str("key_mgmt=NONE\n"),
        "wpa2" => {
            let psk = if password.len() == 64 && password.bytes().all(|b| b.is_ascii_hexdigit()) {
                password.to_ascii_lowercase()
            } else {
                if !(8..=63).contains(&password.len()) || !password.bytes().all(|b| (32..=126).contains(&b)) {
                    return Err("WPA2 password must be 8-63 printable ASCII characters or a 64-digit hex PSK".into());
                }
                let mut key = [0u8; 32];
                ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA1, NonZeroU32::new(4096).unwrap(), n.ssid.as_bytes(), password.as_bytes(), &mut key);
                hex(&key)
            };
            config.push_str(&format!("key_mgmt=WPA-PSK\nproto=RSN\npsk={psk}\n"));
        }
        _ => return Err("Unsupported Wi-Fi security or password supplied for an open network".into()),
    }
    config.push_str("}\n");
    Ok(config)
}

fn prefix(mask: Ipv4Addr) -> Option<u32> {
    let m = u32::from(mask);
    (m.count_ones() == m.leading_ones() && (8..=30).contains(&m.count_ones())).then(|| m.count_ones())
}

fn validate_lease(l: &Lease, lan: Ipv4Addr, mask: Ipv4Addr) -> Result<u32, String> {
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

fn lease_file(root: &Path, session: &str) -> Option<std::path::PathBuf> {
    (session.len() == 32 && session.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| root.join(format!("ipv4-lease-{session}.json")))
}

fn read_lease(session: &str) -> Result<Lease, String> {
    let path = lease_file(Path::new(ROOT), session).ok_or("Invalid DHCP session")?;
    serde_json::from_slice(&fs::read(path).map_err(|_| "No DHCP lease")?).map_err(|_| "Invalid DHCP lease".into())
}

/// A DHCP client on a new session path (its lease file), asking for
/// `request` when given: the session id and the client.
fn start_dhcp(request: Option<Ipv4Addr>) -> Result<(String, Child), String> {
    let callback = std::env::current_exe().map_err(|e| e.to_string())?;
    #[cfg(test)]
    let callback = std::env::var_os("U60_IPV6_QA_CALLBACK").map(std::path::PathBuf::from).unwrap_or(callback);
    let mut nonce = [0; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| "Cannot create DHCP session")?;
    let nonce = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
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

fn dhcp_callback_at(root: &Path, event: &str, env: impl Fn(&str) -> Option<String>) -> i32 {
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
    if net::write_private(&path, &serde_json::to_vec(&lease).unwrap()).is_ok() {
        0
    } else {
        1
    }
}

pub fn status(state: &crate::handlers::AppState) -> (u16, Value) {
    (200, json!({"ok":true,"data":state.wifi_relay.status()}))
}

pub fn change(state: &crate::handlers::AppState, action: &str, body: &[u8]) -> (u16, Value) {
    if action == "offload" {
        // `reset`: what resetting existing LAN IPv4 connections onto the new
        // path did (`conntrack::Report::json`), or null when it did not change.
        let result = match serde_json::from_slice::<Value>(body).ok() {
            Some(v) if v["enabled"].is_boolean() => state.wifi_relay.set_offload_enabled(v["enabled"] == true),
            _ => Err("Send enabled as a boolean".into()),
        };
        return match result {
            Ok(reset) => {
                let (code, mut reply) = status(state);
                reply["data"]["reset"] = reset.unwrap_or(Value::Null);
                (code, reply)
            }
            Err(e) => change_error(&state.wifi_relay, e),
        };
    }
    let result = match action {
        "scan" => state.wifi_relay.scan(),
        "disconnect" => state.wifi_relay.disconnect(),
        "clock" => state.wifi_relay.recheck_clock(),
        "power-save" => serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v["auto_off"].as_bool())
            .ok_or_else(|| "auto_off must be a boolean".to_owned())
            .and_then(|auto_off| state.wifi_relay.set_power_save(auto_off)),
        "forget" => serde_json::from_slice::<Value>(body).map_err(|_| "Invalid request".to_owned())
            .and_then(|v| state.wifi_relay.forget(v["id"].as_str().unwrap_or(""))),
        "connect" => match serde_json::from_slice::<Value>(body) {
            Ok(v) => state.wifi_relay.connect_remembered(v["network"].as_str().unwrap_or(""), v["password"].as_str().unwrap_or(""), v["confirmed"].as_bool() == Some(true), v["ipv6"].as_bool().unwrap_or(true), v["remember"].as_bool() == Some(true)),
            Err(_) => Err("Invalid relay request".into()),
        },
        _ => Err("Unknown relay action".into()),
    };
    match result {
        Ok(()) => status(state),
        Err(e) => change_error(&state.wifi_relay, e),
    }
}

fn change_error(relay: &WifiRelay, error: String) -> (u16, Value) {
    let busy = error.contains("in progress") || error.contains("still applying");
    let phase = relay.status()["phase"].clone();
    (if busy { 409 } else { 503 }, json!({"ok":false,"error":error,"phase":phase}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay_plan(lease: &Lease, prefix: u32, lan: Ipv4Addr, mask: Ipv4Addr) -> Vec<Step> {
        crate::netfx::effect::test_plan(super::relay_plan(lease, prefix, lan, mask))
    }

    fn input_guards() -> Vec<Step> {
        crate::netfx::effect::test_plan(super::input_guards())
    }

    #[test]
    fn association_grace_uses_elapsed_time_and_resets_only_on_success() {
        let at = |s| BootInstant::from_duration(Duration::from_secs(s));
        let mut a = Association::default();
        assert_eq!(
            a.observe(Some("SCANNING"), at(1)),
            AssociationResult::Recovering
        );
        assert_eq!(
            a.observe(Some("4WAY_HANDSHAKE"), at(10)),
            AssociationResult::Recovering
        );
        assert_eq!(a.observe(None, at(13)), AssociationResult::Expired);
        assert_eq!(a.state, "QUERY_UNAVAILABLE");
        assert_eq!(
            a.observe(Some("COMPLETED"), at(14)),
            AssociationResult::Ready
        );
        assert_eq!(
            a.observe(Some("SCANNING"), at(50)),
            AssociationResult::Recovering
        );
        assert_eq!(a.elapsed(at(50)), Duration::ZERO);
    }

    #[test]
    fn restore_intent_io_failures_are_explicit_and_do_not_masquerade_as_cancellation() {
        let root = std::env::temp_dir().join(format!("u60-restore-io-{}", std::process::id()));
        fs::create_dir_all(root.join("resume.json")).unwrap();
        assert_eq!(resume::clear(&root).unwrap_err(), "Cannot clear the relay to restore");
        let network = Network { id: "write-fails".into(), ssid: "Restore test".into(), frequency: 2412, signal: -40, security: "open", supported: true, bssid: "02:00:00:00:00:01".into() };
        assert_eq!(resume::save(&root, &network, true).unwrap_err(), "Cannot save the relay to restore after a restart");
        let relay = WifiRelay::new(Arc::new(Mutex::new(())));
        let generation = relay.shared.cancel_restore();
        assert!(!relay.shared.generation_matches(generation - 1));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_upstream_input_guard_is_rechecked_but_radio_steps_are_not() {
        let guard = super::input_guards();
        assert!(guard.iter().all(firewall_resource));
        assert!(matches!(&guard[0], Resource::LegacyChain(chain) if chain.name == "U60_RELAY_IN" && chain.tool == LegacyTool::V4));
        assert_eq!(guard.len(), 2);
    }

    #[test]
    fn strays_are_only_relay_helpers_on_our_interface_and_paths() {
        let args = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();
        let mine = offload::Record { pid: 42, start: 500 };
        for helper in [
            "wpa_supplicant -D nl80211 -i ath20 -c /tmp/zte-agent-relay/wpa.conf -qq",
            "/usr/sbin/wpa_supplicant -D nl80211 -i ath20 -c /tmp/zte-agent-relay/recover.conf -qq",
            "odhcp6c -N try -R -r 23 -s /data/zte-agent -p /tmp/zte-agent-relay/odhcp6c.pid ath20",
            "udhcpc -f -i ath20 -s /data/zte-agent -t 5 -T 3 -A 10",
            "ip -4 monitor neigh dev ath20",
            "iw event -t",
        ] {
            assert!(stray(&args(helper), mine, &[mine]), "{helper}");
        }
        // A monitor this agent did not record is someone else's, and so is a
        // process that reused a recorded id (R2).
        let reused = offload::Record { pid: 42, start: 777 };
        for manual in ["ip -4 monitor neigh dev ath20", "iw event -t"] {
            assert!(!stray(&args(manual), offload::Record { pid: 43, start: 500 }, &[mine]), "{manual}");
            assert!(!stray(&args(manual), reused, &[mine]), "{manual} with a reused id");
        }
        for other in [
            // The firmware's own supplicants and clients, and look-alikes.
            "wpa_supplicant -D nl80211 -i wlan1 -c /var/run/wpa_supplicant-wlan1.conf",
            "wpa_supplicant -D nl80211 -i ath20 -c /etc/wpa.conf",
            "wpa_supplicant -D nl80211 -i ath21 -c /tmp/zte-agent-relay/wpa.conf",
            "odhcp6c -s /lib/netifd/dhcpv6.script -p /var/run/odhcp6c.pid rmnet_data0",
            "odhcp6c -p /tmp/zte-agent-relay/odhcp6c.pid wlan0",
            "udhcpc -f -i br-lan -s /usr/share/udhcpc/default.script",
            "sh -c udhcpc -i ath20",
            "ip -4 monitor neigh dev wlan0",
            "ip monitor neigh dev ath20",
            "ip -4 monitor neigh dev ath20 extra",
            "ip -4 monitor neigh",
            "ip",
            "iw event",
            "iw dev wlan2 station dump",
            "/data/zte-agent",
            "",
        ] {
            assert!(!stray(&args(other), mine, &[mine]), "{other}");
        }
    }

    #[test]
    fn later_successful_clock_check_clears_relay_warning_without_reconnecting() {
        let clock = crate::network_clock::WifiClock::new();
        let relay = WifiRelay::new(Arc::new(Mutex::new(())));
        let error = "Cannot verify UTC over Wi-Fi HTTPS; check upstream/portal access";
        assert!(clock.sync_with(false, |_| Err(error.into())).is_err());
        relay.shared.snapshot.lock().unwrap().value = json!({
            "connected":true,"ssid":"W","address":"192.168.2.124",
            "clock_error":clock.error(),"error":"Unrelated DNS warning"
        });
        assert_eq!(relay.status_with_clock(&clock)["clock_error"], error);

        clock.sync_with(false, |_| Ok(())).unwrap();
        let status = relay.status_with_clock(&clock);
        assert!(status["clock_error"].is_null(), "A later verified check must replace the connect-time warning");
        assert_eq!(status["connected"], true);
        assert_eq!(status["ssid"], "W");
        assert_eq!(status["error"], "Unrelated DNS warning");

        assert!(clock.sync_with(false, |_| Err("Clock sources disagree".into())).is_err());
        assert_eq!(relay.status_with_clock(&clock)["clock_error"], "Clock sources disagree");
        relay.shared.snapshot.lock().unwrap().value["connected"] = json!(false);
        assert!(relay.status_with_clock(&clock)["clock_error"].is_null(), "No stale warning while relay is off");
    }

    #[test]
    fn late_ipv4_callbacks_cannot_overwrite_or_delete_a_new_sessions_lease() {
        let root = std::env::temp_dir().join(format!("u60-dhcp4-session-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let old = "a".repeat(32);
        let new = "b".repeat(32);
        let call = |event: &str, session: &str, ip: &str| dhcp_callback_at(&root, event, |key| Some(match key {
            "interface" => IFACE, "U60_RELAY_DHCP_SESSION" => session,
            "ip" => ip, "subnet" => "255.255.255.0", "router" | "dns" => "10.0.0.1", _ => return None,
        }.into()));
        assert_eq!(call("bound", &new, "10.0.0.3"), 0);
        let active = root.join(format!("ipv4-lease-{new}.json"));
        let original = fs::read(&active).expect("current lease must use its session path");
        assert_eq!(call("bound", &old, "10.0.0.2"), 0);
        assert_eq!(fs::read(&active).unwrap(), original);
        assert_eq!(call("deconfig", &old, "10.0.0.2"), 0);
        assert_eq!(fs::read(&active).unwrap(), original);
        assert_eq!(call("renew", "../escape", "10.0.0.2"), 1);
        assert_eq!(call("deconfig", &new, "10.0.0.3"), 0);
        assert!(!active.exists());
        fs::remove_dir_all(root).unwrap();
    }

    fn bss(entries: &[(&str, u32, i32, u64, &str, &str)]) -> String {
        entries
            .iter()
            .enumerate()
            .map(|(id, (bssid, freq, level, age, flags, ssid))| format!("id={id}\nbssid={bssid}\nfreq={freq}\nlevel={level}\nage={age}\nflags={flags}\nssid={ssid}\n====\n"))
            .collect()
    }

    #[test]
    fn dfs_upstream_is_selectable_and_keeps_its_association_frequency() {
        for frequency in [5260, 5280, 5300, 5320, 5500, 5700] {
            let table = bss(&[("02:11:22:33:44:55", frequency, -49, 0, "[WPA2-PSK-CCMP][ESS]", "W_Game")]);
            let channels = scan::Channels::parse(&format!("* {frequency} MHz [52]\n Radar detection\n"));
            let n = parse_bss_on_channels(&table, 0, &channels).remove(0);
            assert!(n.supported, "DFS upstream at {frequency} MHz must be selectable");
            assert!(!parse_bss_on_channels(&table, 0, &scan::Channels::parse("* 2412 MHz [1]\n")).remove(0).supported,
                "cached BSS on a disabled channel must remain unavailable");
            let config = wpa_network(&n, "test-password").unwrap();
            assert!(config.contains(&format!("freq_list={frequency}\nscan_freq={frequency}\n")));
        }
    }

    #[test]
    fn scan_filters_and_keeps_selection_opaque() {
        let n = parse_bss(&bss(&[
            ("02:11:22:33:44:55", 2427, -43, 0, "[ESS]", "JinJiangRewards"),
            ("02:11:22:33:44:66", 5500, -30, 1, "[WPA2-PSK-CCMP][ESS]", "DFS"),
            ("02:11:22:33:44:77", 5180, -60, 2, "[SAE][ESS]", "WPA3"),
            ("02:11:22:33:44:88", 5220, -40, 9, "[WPA2-PSK-CCMP][ESS]", "Cached"),
            ("02:11:22:33:44:99", 5240, -41, 0, "[WPA2-PSK-CCMP][ESS]", "Say \\\"hi\\\" \\\\o/"),
        ]), 2);
        assert_eq!(n.len(), 4, "the entry older than this scan is left out");
        assert!(n.iter().find(|n| n.ssid == "DFS").unwrap().supported);
        assert!(!n.iter().find(|n| n.ssid == "WPA3").unwrap().supported);
        let hotel = n.iter().find(|n| n.ssid == "JinJiangRewards").unwrap();
        assert!(hotel.supported);
        assert!(!serde_json::to_string(hotel).unwrap().contains("02:11:22:33:44:55"));
        assert_eq!(hotel.id.len(), 16);
        assert!(n.iter().any(|n| n.ssid == r#"Say "hi" \o/"# && n.supported));
    }

    #[test]
    fn association_scans_only_the_upstream_channel() {
        // freq_list only limits selection; without scan_freq the supplicant's
        // own scans are full scans, which lose 5 GHz while the hotspot runs
        // 160 MHz, so the upstream was never found.
        for (freq, flags) in [(5220, "[WPA2-PSK-CCMP][ESS]"), (2412, "[ESS]")] {
            let n = parse_bss(&bss(&[("02:11:22:33:44:55", freq, -40, 0, flags, "Hotel")]), 0).remove(0);
            let config = wpa_network(&n, if n.security == "wpa2" { "password" } else { "" }).unwrap();
            assert!(config.lines().any(|l| l == format!("scan_freq={freq}")), "{config}");
            assert!(config.lines().any(|l| l == format!("freq_list={freq}")));
        }
    }

    #[test]
    fn passwords_never_become_supplicant_directives() {
        let mut n = parse_bss(&bss(&[("02:11:22:33:44:55", 2427, -40, 0, "[ESS]", "Hotel")]), 0).remove(0);
        assert!(wpa_network(&n, "").unwrap().contains("key_mgmt=NONE"));
        n.security = "wpa2";
        let c = wpa_network(&n, "hello;\"$password").unwrap();
        assert!(!c.contains("hello"));
        assert!(c.contains("psk="));
        assert!(wpa_network(&n, "bad\nnew=directive").is_err());
    }

    #[test]
    fn malformed_ssid_escapes_cannot_panic_at_utf8_boundaries() {
        assert_eq!(decode_ssid(r"Hotel\x20WiFi"), "Hotel WiFi");
        assert_eq!(decode_ssid("\\x\u{4e2d}"), "\\x\u{4e2d}");
        assert_eq!(decode_ssid("\\xF\u{4e2d}"), "\\xF\u{4e2d}");
        assert_eq!(decode_ssid(r"Hotel\xGG"), r"Hotel\xGG");
    }

    #[test]
    fn subnet_conflicts_and_bogus_gateways_are_rejected() {
        let mut l = Lease { ip: "10.20.1.2".parse().unwrap(), subnet: "255.255.240.0".parse().unwrap(), gateway: "10.20.0.1".parse().unwrap(), dns: vec![] };
        let lan = "192.168.0.1".parse().unwrap();
        let mask = "255.255.255.0".parse().unwrap();
        assert_eq!(validate_lease(&l, lan, mask), Ok(20));
        l.gateway = "10.30.0.1".parse().unwrap();
        assert!(validate_lease(&l, lan, mask).is_err());
        l.ip = "192.168.0.20".parse().unwrap();
        l.gateway = lan;
        l.subnet = mask;
        assert!(validate_lease(&l, lan, mask).is_err());
    }

    #[test]
    fn dhcp_cannot_redirect_dns_into_management_or_non_unicast_addresses() {
        let mut l = Lease { ip: "10.20.1.2".parse().unwrap(), subnet: "255.255.240.0".parse().unwrap(), gateway: "10.20.0.1".parse().unwrap(), dns: vec![] };
        let lan = "192.168.0.1".parse().unwrap();
        let mask = "255.255.255.0".parse().unwrap();
        for dns in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "192.168.0.1", "192.168.0.2", "100.100.100.100", "169.254.1.1", "10.20.0.0", "10.20.15.255", "10.20.1.2"] {
            l.dns = vec![dns.parse().unwrap()];
            assert!(validate_lease(&l, lan, mask).is_err(), "{dns}");
        }
        for dns in ["10.20.0.1", "10.20.0.53", "1.1.1.1"] {
            l.dns = vec![dns.parse().unwrap()];
            assert_eq!(validate_lease(&l, lan, mask), Ok(20), "{dns}");
        }
    }

    #[test]
    fn roam_mode_undo_is_serialized_for_recovery_without_a_live_supplicant() {
        for mode in ["0", "1"] {
            let step = roam_step(mode);
            let saved = serde_json::to_vec(&step).unwrap();
            let restored: Step = serde_json::from_slice(&saved).unwrap();
            assert_eq!(restored.undo, Cmd::new("@u60-relay-roam", &[mode]));
            assert!(restored.apply.args.ends_with(&["SETROAMMODE".into(), "1".into()]));
        }
    }

    #[test]
    fn association_journals_driver_detachment_before_any_ap_channel_restore() {
        let step = association_step();
        let restored: Step = serde_json::from_slice(&serde_json::to_vec(&step).unwrap()).unwrap();
        assert_eq!(restored.apply, wpa_command("reconfigure", &[]));
        assert_eq!(restored.undo, Cmd::new("@u60-relay-detach", &[]));

        let mut calls = Vec::new();
        let mut links = ["Connected to upstream", "Connected to upstream", "Not connected."].into_iter();
        detach_with(
            |command| {
                calls.push(command.clone());
                Ok(if command.args.last().is_some_and(|s| s == "link") { links.next().unwrap().into() } else { "OK".into() })
            },
            || {},
        )
        .unwrap();
        assert_eq!(calls[0], wpa_command("disconnect", &[]));
        assert_eq!(calls[2], Cmd::new("iw", &["dev", IFACE, "disconnect"]));
        assert_eq!(calls.last().unwrap(), &Cmd::new("iw", &["dev", IFACE, "link"]));
    }

    #[test]
    fn uncertain_driver_detachment_refuses_ap_recovery() {
        for status in [Ok("Connected to upstream".to_owned()), Ok("unknown".to_owned()), Err("iw unavailable".to_owned())] {
            assert!(detach_with(|_| status.clone(), || {}).is_err());
        }
        // The crash-recovery path has no live supplicant; positive driver
        // evidence is still sufficient, even when iw disconnect races it.
        detach_with(
            |command| {
                if command.args.last().is_some_and(|s| s == "link") { Ok("Not connected.\n".into()) } else { Err("No supplicant".into()) }
            },
            || {},
        )
        .unwrap();
    }

    #[test]
    fn no_default_main_route_or_persistent_wifi_is_overwritten() {
        let l = Lease { ip: "10.0.0.2".parse().unwrap(), subnet: "255.255.255.0".parse().unwrap(), gateway: "10.0.0.1".parse().unwrap(), dns: vec![] };
        let p = relay_plan(&l, 24, "192.168.0.1".parse().unwrap(), "255.255.255.0".parse().unwrap());
        assert!(p.iter().any(|s| s.apply.program == "iptables" && s.apply.args.ends_with(&["-o", IFACE, "-m", "comment", "--comment", crate::netfx::ids::RELAY_COMMENT, "-j", "MASQUERADE"].map(String::from))));
        assert!(p.iter().filter(|s| s.apply.args.iter().any(|a| a == "default")).all(|s| s.apply.args.iter().any(|a| a == TABLE)));
        assert!(p.iter().all(|s| s.apply.program != "uci"));
        assert!(p.last().unwrap().apply.args.iter().any(|a| a == PREF));
        assert!(p.iter().all(|s| !s.apply.args.windows(2).any(|w| w == ["throw", "10.0.0.0/8"])));
        assert!(p.iter().any(|s| s.apply.args.windows(2).any(|w| w == ["throw", "192.168.0.0/24"])));
        assert!(p
            .iter()
            .filter(|s| s.apply.args.windows(2).any(|w| w == ["-I", "PREROUTING"]))
            .all(|s| s.apply.args[6] == "1"));
    }

    #[test]
    fn relay_web_traffic_bypasses_vendor_offline_redirect_without_bypassing_filtering() {
        let p = crate::netfx::effect::test_plan(portal::web_bypasses());
        for tool in ["iptables", "ip6tables"] {
            let rule = p.iter().find(|step| step.apply.program == tool).expect("missing vendor offline-portal bypass");
            assert_eq!(rule.undo.program, tool);
            assert_eq!(&rule.undo.args[..6], &["-w", "2", "-t", "nat", "-D", "redirect_chain"]);
            assert_eq!(&rule.undo.args[6..], &["-i", "br-lan", "-m", "comment", "--comment", "zte-agent-wifi-relay", "-j", "RETURN"]);
        }
    }

    /// B31, 2026-11-12: released at a reconnect and applied again with the
    /// next lease, the switch read 1 for seconds and the RETURN was gone; a
    /// fw3 reload in that gap left the vendor's port-80 DNAT in
    /// `redirect_chain` for minutes. A handover now rolls back nothing of the
    /// suppression: `network`, which it rolls back whole, holds none of it,
    /// it releases only the resolver of `dns`, and the next session takes
    /// the rest, which its guard keeps checking and its teardown (a failed
    /// join's too) or the next start's recovery rolls back.
    #[test]
    fn a_handover_hands_the_offline_redirect_suppression_to_the_next_session() {
        let l = Lease { ip: "10.0.0.2".parse().unwrap(), subnet: "255.255.255.0".parse().unwrap(), gateway: "10.0.0.1".parse().unwrap(), dns: vec!["10.0.0.53".parse().unwrap()] };
        let plan = relay_plan(&l, 24, "192.168.0.1".parse().unwrap(), "255.255.255.0".parse().unwrap());
        assert!(!plan.iter().any(|s| s.apply.program.starts_with("@u60-relay-portal") || s.undo.args.iter().any(|a| a == "redirect_chain")));
        let switch = Resource::Internal(Internal::new("@u60-relay-portal", vec!["disable".into()], vec!["release".into()]));
        let mut held = portal::web_bypasses();
        held.push(switch);
        assert_eq!(resolver(&l).command().unwrap(), Cmd::new("@u60-relay-dns", &["10.0.0.53"]));
        assert!(!held.iter().any(|resource| resource.key() == resolver_key()), "the handover's release takes none of it");
        // The old session as `handover` leaves it before `successor`.
        let dir = std::env::temp_dir().join(format!("u60-relay-successor-{}", std::process::id()));
        let mut old = Session::new(&dir);
        old.dns.assume(held);
        let mut next = successor(&mut old, false, &dir);
        for (program, first) in [("iptables", "-w"), ("ip6tables", "-w"), ("@u60-relay-portal", "release")] {
            assert!(next.dns.journaled(program, first).is_some(), "{program}: the next session's to undo");
            assert!(old.dns.journaled(program, first).is_none(), "{program}: nothing left to release with the old session");
        }
        // The next session's guard puts the RETURN back ahead of a DNAT a
        // reload left (a reload while the switch reads 0 adds none).
        let mut device = crate::netfx::effect::testing::Kernel::portal_late();
        let result = next.dns.reconcile_with(&mut device, &mut crate::netfx::effect::fake::FakeNft::default());
        assert_eq!(device.writes.len(), 1);
        assert!(result.restored.len() == 1 && result.failed.is_empty(), "{result:?}");
        let _ = fs::remove_dir_all(dir);
    }

    /// v5: the denials are in the relay's tables; legacy holds accepts only
    /// (the vendor's DROP/REJECT is what they pass), MASQUERADE (D11) and
    /// the portal RETURN.
    #[test]
    fn legacy_rules_only_accept_what_must_pass_the_vendors_rejects() {
        let l = Lease { ip: "10.0.0.2".parse().unwrap(), subnet: "255.255.255.0".parse().unwrap(), gateway: "10.0.0.1".parse().unwrap(), dns: vec![] };
        let plan = relay_plan(&l, 24, "192.168.0.1".parse().unwrap(), "255.255.255.0".parse().unwrap());
        let guards = input_guards();
        let owned = |s: &&Step| matches!(s.apply.program.as_str(), "iptables" | "ip6tables") && s.apply.args.get(5).is_some_and(|c| c.starts_with("U60_"));
        for step in plan.iter().chain(&guards).filter(owned) {
            let target = step.apply.args.windows(2).find(|w| w[0] == "-j").map(|w| w[1].as_str());
            assert!(matches!(target, None | Some("ACCEPT" | "U60_R6_IN")), "{:?}", step.apply);
        }
        assert!(!plan.iter().any(|s| s.apply.program == "ip6tables" && s.apply.args.iter().any(|a| a == "REJECT" || a == "OUTPUT")));
        // LAN to upstream, and its replies back.
        let forward: Vec<_> = plan.iter().filter(|s| s.apply.args.windows(2).any(|w| w == ["-A", "U60_RELAY_FWD"])).collect();
        assert_eq!(forward.len(), 2);
        assert!(forward.iter().all(|s| !s.apply.args.iter().any(|a| a == "-p")));
        // Absent upstream IPv6 never uses cellular: the baseline's rejects.
        let [_, ip6] = uplink::tables(&uplink::Layout { relay: Some(relay_layout(&l, "192.168.0.1".parse().unwrap(), "255.255.255.0".parse().unwrap())), ..Default::default() }, None).unwrap();
        assert_eq!(uplink::tests::chain(&ip6, "output"), ["oifname \"rmnet*\" reject"]);
        assert_eq!(uplink::tests::chain(&ip6, "forward")[0], "iifname \"br-lan\" oifname \"rmnet*\" reject");
    }

    #[test]
    fn prejournaled_relay_rules_never_match_another_writers_rule() {
        let l = Lease {
            ip: "10.0.0.2".parse().unwrap(),
            subnet: "255.255.255.0".parse().unwrap(),
            gateway: "10.0.0.1".parse().unwrap(),
            dns: vec!["10.0.0.53".parse().unwrap()],
        };
        let plan = relay_plan(
            &l,
            24,
            "192.168.0.1".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        );
        assert!(plan.iter().chain(&input_guards()).filter(|step| step.undo.program.ends_with("tables") && step.undo.args.contains(&"-D".into())).all(|step| crate::netfx::effect::legacy::owned_rule(&step.undo.args)));
    }

    #[test]
    fn an_observation_decides_teardown_hold_or_keep_in_order() {
        use AssociationResult::*;
        let lease = Lease { ip: "10.0.0.2".parse().unwrap(), subnet: "255.255.255.0".parse().unwrap(), gateway: "10.0.0.1".parse().unwrap(), dns: vec!["10.0.0.53".parse().unwrap()] };
        assert_eq!(decide(Expired, false, LeaseChange::Replaced, true), Decision::Teardown("hotspot_off"), "the owner turning the hotspot off wins");
        assert_eq!(decide(Expired, false, LeaseChange::Replaced, false), Decision::Teardown("helper_exited"));
        assert_eq!(decide(Expired, true, LeaseChange::Replaced, false), Decision::Teardown("lease_changed"));
        assert_eq!(decide(Expired, true, LeaseChange::Same, false), Decision::Teardown("association_timeout"));
        assert_eq!(decide(Recovering, true, LeaseChange::Resolvers(lease.clone()), false), Decision::Hold, "nothing is adopted while the link is lost");
        assert_eq!(decide(Ready, true, LeaseChange::Resolvers(lease.clone()), false), Decision::Keep(Some(lease)), "only the DNS changed: adopted in place");
        assert_eq!(decide(Ready, true, LeaseChange::Same, false), Decision::Keep(None));
    }

    /// R4, M2: a scan, a join that failed before its routes and a second
    /// disconnect leave Mihomo's uplink alone; a session that routed tells it once.
    #[test]
    fn only_a_session_that_installed_routes_tells_mihomo_its_uplink_changed() {
        let dir = std::env::temp_dir().join(format!("u60-relay-routed-{}", std::process::id()));
        let mut told = 0;
        let mut scan = Session::new(&dir);
        cleanup(&mut scan, || told += 1).unwrap();
        assert_eq!(told, 0, "a scan or a join that failed before routing");
        let mut routed = Session::new(&dir);
        routed.routed = true;
        cleanup(&mut routed, || told += 1).unwrap();
        cleanup(&mut routed, || told += 1).unwrap();
        assert_eq!(told, 1, "once, not again for a repeated teardown");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_recovery_journals_keep_network_ownership() {
        let dir = std::env::temp_dir().join(format!("u60-relay-ownership-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert!(!recovery_pending(&dir));
        for name in [
            "network.json",
            "wireless.json",
            "dns.json",
            "ipv6-network.json",
            "ipv6-setup.json",
            "ra-runtime.json",
        ] {
            fs::write(dir.join(name), b"retained recovery evidence").unwrap();
            assert!(recovery_pending(&dir), "{name}");
            fs::remove_file(dir.join(name)).unwrap();
        }
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn relay_dns_follows_the_wifi_resolver_and_keeps_the_lan_subnet() {
        let l = Lease {
            ip: "10.20.1.2".parse().unwrap(),
            subnet: "255.255.240.0".parse().unwrap(),
            gateway: "10.20.0.1".parse().unwrap(),
            dns: vec!["10.20.0.53".parse().unwrap()],
        };
        let p = relay_plan(&l, 20, "192.168.8.1".parse().unwrap(), "255.255.255.0".parse().unwrap());
        let lan = ("192.168.8.1".parse().unwrap(), "255.255.255.0".parse().unwrap());
        assert_eq!(relay_layout(&l, lan.0, lan.1), uplink::Relay { dns: "10.20.0.53".parse().unwrap(), lan: "192.168.8.0/24".into() });
        assert!(!p.iter().any(|s| s.apply.program == "@u60-relay-nft"), "DNS is in the relay's tables");
        assert!(!p.iter().any(|s| s.apply.args.windows(2).any(|w| w == ["--dport", "53"])), "no legacy DNS rules");
        // Router DNS redirected from a socket bound to a SIM source still
        // leaves with the relay's address.
        assert!(p.iter().any(|s| s.apply.args.windows(2).any(|w| w == ["-I", "POSTROUTING"])
            && s.apply.args.ends_with(&["-o", IFACE, "-m", "comment", "--comment", crate::netfx::ids::RELAY_COMMENT, "-j", "MASQUERADE"].map(String::from))));
        assert_eq!(relay_layout(&Lease { dns: vec![], ..l }, lan.0, lan.1).dns, "10.20.0.1".parse::<Ipv4Addr>().unwrap());
    }

    fn lease_with(dns: &[&str]) -> Lease {
        Lease {
            ip: "10.20.0.7".parse().unwrap(),
            subnet: "255.255.255.0".parse().unwrap(),
            gateway: "10.20.0.1".parse().unwrap(),
            dns: dns.iter().map(|d| d.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn a_renewal_is_adopted_in_place_unless_it_changes_what_the_rules_bake_in() {
        let installed = lease_with(&["10.20.0.53", "10.20.0.54"]);
        assert_eq!(
            lease_change(&installed, Some(&installed.clone())),
            LeaseChange::Same
        );
        let extra = lease_with(&["10.20.0.53", "10.20.0.54", "10.20.0.55"]);
        assert_eq!(
            lease_change(&installed, Some(&extra)),
            LeaseChange::Resolvers(extra.clone())
        );
        let reordered_tail = lease_with(&["10.20.0.53"]);
        assert_eq!(
            lease_change(&installed, Some(&reordered_tail)),
            LeaseChange::Resolvers(reordered_tail.clone())
        );
        // The DNAT and masquerade rules point at the first resolver.
        for next in [
            lease_with(&["10.20.0.54", "10.20.0.53"]),
            lease_with(&[]),
            lease_with(&["8.8.8.8"]),
        ] {
            assert_eq!(
                lease_change(&installed, Some(&next)),
                LeaseChange::Replaced,
                "{next:?}"
            );
        }
        let moved = Lease {
            ip: "10.20.0.8".parse().unwrap(),
            ..installed.clone()
        };
        let regateway = Lease {
            gateway: "10.20.0.2".parse().unwrap(),
            ..installed.clone()
        };
        let remask = Lease {
            subnet: "255.255.0.0".parse().unwrap(),
            ..installed.clone()
        };
        for next in [moved, regateway, remask] {
            assert_eq!(
                lease_change(&installed, Some(&next)),
                LeaseChange::Replaced,
                "{next:?}"
            );
        }
        assert_eq!(
            lease_change(&installed, None),
            LeaseChange::Replaced,
            "a deconfig removed the lease file"
        );
    }

    #[test]
    fn without_dns_the_gateway_is_the_resolver_the_rules_use() {
        let installed = lease_with(&[]);
        assert_eq!(
            lease_change(&installed, Some(&lease_with(&["10.20.0.1"]))),
            LeaseChange::Resolvers(lease_with(&["10.20.0.1"]))
        );
        assert_eq!(
            lease_change(&installed, Some(&lease_with(&["10.20.0.9"]))),
            LeaseChange::Replaced
        );
    }

}
