//! B31 AP+STA relay, implemented with the firmware's public nl80211 and
//! hostapd/wpa control tools. No vendor daemon or persistent Wi-Fi UCI is
//! replaced. Optional upstream IPv6 and downstream NAT66 use owned runtime state.

pub(crate) mod ipv6;
mod adopt;
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
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::boottime::{BootClock, BootInstant, Clock};
use crate::net_tools::{self as net, Cmd, NetworkLock, Step, Transaction};

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
    wireless: Transaction,
    network: Transaction,
    /// The resolver line (`dns`) and the suppression of the vendor's offline
    /// redirect (`portal`: the switch delta and the RETURN). A handover
    /// releases only the resolver and moves the rest to the next session.
    dns: Transaction,
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
        let uplink = uplink::Shared::new(journal.join("uplink.nft"));
        Session {
            wireless: Transaction::new(journal.join("wireless.json")),
            network: Transaction::new(journal.join("network.json")),
            dns: Transaction::new(journal.join("dns.json")),
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

struct Inner {
    session: Option<Session>,
    scans: Vec<Network>,
    error: Option<String>,
    phase: Phase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Idle,
    Scanning,
    Connecting,
    Active,
    Recovering,
    Disconnecting,
    RecoveryPending,
}

#[derive(Default)]
struct Restore {
    /// SSID being reconnected after the agent started (`restore`).
    restoring: Option<String>,
    /// Owner operations invalidate every pending restore, even for the same BSS.
    restore_generation: u64,
    disconnect: bool,
}

pub struct WifiRelay {
    /// The shared admission lock: held only to check and register an
    /// operation (`netfx::admission`), never across device work.
    lock: NetworkLock,
    /// Serializes the relay's own operations and its 3 s watch.
    op: Mutex<()>,
    // The network admission lock never nests with op/inner/restore: op -> inner
    // -> restore -> snapshot; cancellation uses only restore -> snapshot.
    // Status takes only short memory locks, never op or inner.
    inner: Mutex<Inner>,
    restore: Mutex<Restore>,
    restore_wake: Condvar,
    wake: Condvar,
    snapshot: Mutex<Value>,
    active: AtomicBool,
    owned: AtomicBool,
    mihomo: Option<Arc<crate::mihomo::Mihomo>>,
}

struct Operation<'a> {
    relay: &'a WifiRelay,
    lock: Option<std::sync::MutexGuard<'a, ()>>,
    _claim: crate::netfx::admission::Claim,
}

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        loop {
            let disconnect = self.relay.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner).disconnect;
            if disconnect { let _ = self.relay.teardown(); }
            self.relay.settle();
            let restore = self.relay.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if !restore.disconnect {
                self.lock.take();
                return;
            }
        }
    }
}

impl WifiRelay {
    pub fn new(lock: NetworkLock) -> Self {
        let relay = Self {
            lock,
            op: Mutex::new(()),
            inner: Mutex::new(Inner { session: None, scans: Vec::new(), error: None, phase: Phase::Idle }),
            restore: Mutex::new(Restore::default()),
            restore_wake: Condvar::new(),
            wake: Condvar::new(),
            snapshot: Mutex::new(Value::Null),
            active: AtomicBool::new(false),
            owned: AtomicBool::new(false),
            mihomo: None,
        };
        relay.settle();
        relay
    }

    pub fn with_core(lock: NetworkLock, core: Arc<crate::mihomo::Mihomo>) -> Self {
        Self { mihomo: Some(core), ..Self::new(lock) }
    }

    /// Mihomo follows a change of the routes this relay installed.
    fn uplink_changed(&self) {
        if let Some(core) = &self.mihomo {
            core.uplink_changed();
        }
    }

    pub fn active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// A session, an operation in progress or effects left to recover.
    pub fn owns_network(&self) -> bool {
        self.owned.load(Ordering::Acquire) || crate::netfx::admission::held(crate::netfx::admission::RELAY_OPERATION)
    }

    /// Teardown cannot be refused or wait behind another admission check.
    fn begin_teardown(&self) -> crate::netfx::admission::Claim {
        use crate::netfx::admission::{claim, RELAY_OPERATION};
        claim(RELAY_OPERATION, Duration::from_secs(3600))
    }

    fn operation(&self, phase: Option<Phase>) -> Result<Operation<'_>, String> {
        self.operation_by(phase, Instant::now() + crate::netfx::admission::WAIT)
    }

    /// The same, for a request that already spent part of its wait.
    fn operation_by(&self, phase: Option<Phase>, deadline: Instant) -> Result<Operation<'_>, String> {
        use crate::netfx::admission::{begin, enter, RELAY_OPERATION, VENDOR_WIFI_RELOAD, VENDOR_WRITE};
        let left = || deadline.saturating_duration_since(Instant::now());
        let claim = begin(&self.lock, RELAY_OPERATION, &[VENDOR_WRITE, VENDOR_WIFI_RELOAD], left())?;
        let lock = enter(&self.op, left()).ok_or_else(|| self.in_progress())?;
        Ok(self.hold_operation(lock, claim, phase))
    }

    fn hold_operation<'a>(&'a self, lock: std::sync::MutexGuard<'a, ()>, claim: crate::netfx::admission::Claim, phase: Option<Phase>) -> Operation<'a> {
        let operation = Operation { relay: self, lock: Some(lock), _claim: claim };
        if let Some(phase) = phase { self.set_phase(phase); }
        operation
    }

    fn in_progress(&self) -> String {
        let snapshot = self.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        format!("A network operation is in progress ({}); retry after it finishes", snapshot["phase"].as_str().unwrap_or("idle"))
    }

    fn set_phase(&self, phase: Phase) {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.phase = phase;
        self.publish(&inner);
    }

    fn settle(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.phase = if let Some(session) = &inner.session {
            if session.association.since.is_some() { Phase::Recovering } else { Phase::Active }
        } else if self.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner).restoring.is_some() {
            Phase::Recovering
        } else if recovery_pending(Path::new(JOURNAL)) {
            Phase::RecoveryPending
        } else {
            Phase::Idle
        };
        self.publish(&inner);
    }

    pub fn status(&self) -> Value {
        self.status_with_clock(&crate::network_clock::WIFI)
    }

    fn status_with_clock(&self, clock: &crate::network_clock::WifiClock) -> Value {
        let mut value = self.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        value["clock_error"] = if value["connected"] == true { json!(clock.error()) } else { Value::Null };
        // Public IPv4 Mihomo intercepts stays on the CPU whatever IPA does.
        value["offload"]["ipv4_through_mihomo"] = json!(self.mihomo.as_ref().map_or("none", |core| core.ipv4_share()));
        value["connection_resets"] = crate::netfx::conntrack::history();
        value
    }

    fn recheck_clock_with(&self, check: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
        let _operation = self.operation(None)?;
        // op keeps the uplink stable; no status lock is held over HTTPS.
        if self.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner)["connected"] != true {
            return Err("Connect Wi-Fi relay before checking time".into());
        }
        check()
    }

    fn publish(&self, inner: &Inner) {
        self.publish_at(inner, Path::new(JOURNAL));
    }

    fn publish_at(&self, inner: &Inner, root: &Path) {
        if let Some(core) = &self.mihomo {
            core.set_subscription_dns(inner.session.as_ref().and_then(|s| s.lease.as_ref()).map(|lease| if lease.dns.is_empty() { vec![lease.gateway] } else { lease.dns.clone() }).unwrap_or_default());
        }
        let mut value = Self::snapshot(inner);
        let pending = recovery_pending(root);
        value["autostart"] = json!(resume::load(root).is_some());
        if !value["offload"].is_object() { value["offload"] = json!({}); }
        value["offload"]["config"] = json!(offload::config());
        value["offload"]["enabled"] = json!(offload::enabled());
        if !value["power_save"].is_object() { value["power_save"] = json!({}); }
        value["power_save"]["auto_off"] = json!(power_save::auto_off(root));
        saved::annotate(&mut value);
        let restore = self.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        value["restoring"] = json!(restore.restoring);
        if restore.disconnect { value["phase"] = json!(Phase::Disconnecting); }
        value["recovery_required"] = json!(pending && matches!(inner.phase, Phase::Idle | Phase::RecoveryPending) && !restore.disconnect);
        self.active.store(inner.session.as_ref().is_some_and(|s| s.selected.is_some()), Ordering::Release);
        self.owned.store(inner.session.is_some() || pending || restore.disconnect, Ordering::Release);
        *self.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = value;
    }

    fn snapshot(i: &Inner) -> Value {
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
            "association_recovery_ms": s.map(|s| s.association.elapsed(BootClock.now()).as_millis() as u64),
            "offload": s.map(|s| s.offload.status()),
            "power_save": s.map(|s| s.power_save.status()),
            "tables": s.map(|s| s.uplink.status()),
            "error": i.error.as_ref().or_else(|| s.and_then(|s| s.dns_error.as_ref()))})
    }

    pub fn recover(&self) -> Result<(), String> {
        stop_strays(&[])?;
        let ipv6 = ipv6::recover();
        let ipv4 = Transaction::recover(&Path::new(JOURNAL).join("network.json"));
        let dns = Transaction::recover(&Path::new(JOURNAL).join("dns.json"));
        // Preserve the interface while failed IPv6 recovery still owns it,
        // but never strand IPv4 on an already disconnected STA.
        ipv6.and(ipv4)?;
        let wireless = Transaction::recover(&Path::new(JOURNAL).join("wireless.json"));
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

    pub fn start(self: &Arc<Self>) {
        let this = Arc::clone(self);
        // A settled ZTE trigger: the next tick checks at once (`net_guard`).
        let waker = Arc::clone(self);
        crate::net_guard::on_settled(move || waker.wake.notify_all());
        crate::system::spawn_named("relay-watch", move || {
            this.recover_idle();
            loop {
                let mut i = this.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                while !i.session.as_ref().is_some_and(|s| s.selected.is_some()) {
                    i = this.wake.wait(i).unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                let (next, _) = this.wake.wait_timeout(i, Duration::from_secs(3)).unwrap_or_else(std::sync::PoisonError::into_inner);
                drop(next);
                let wait_started = Instant::now();
                let lock = this.op.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let _operation = this.hold_operation(lock, this.begin_teardown(), None);
                let lock_ms = wait_started.elapsed().as_millis();
                if !this.active() {
                    continue;
                }
                let query_started = Instant::now();
                let status = scan::status(&Path::new(ROOT).join("ctrl").join(IFACE), Path::new(ROOT)).ok();
                let link = status.as_deref().and_then(|t| net::key(t, "wpa_state"));
                let query_ms = query_started.elapsed().as_millis();
                let mut i = this.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some(s) = i.session.as_mut().filter(|s| s.selected.is_some()) else { continue };
                let previous = s.association.state;
                let recovering = s.association.since.is_some();
                let link = s.association.observe(link, BootClock.now());
                if previous != s.association.state {
                    crate::netlog!("[relay] association state={} recovery_ms={} query_ms={query_ms} lock_ms={lock_ms}", s.association.state, s.association.elapsed(BootClock.now()).as_millis());
                }
                if recovering && link == AssociationResult::Ready {
                    s.renew_lease();
                }
                let current = s
                    .dhcp_session
                    .as_deref()
                    .and_then(|session| read_lease(session).ok());
                let child_ok = s.supplicant.as_mut().is_some_and(Helper::alive)
                    && s.dhcp.as_mut().is_some_and(|c| matches!(c.try_wait(), Ok(None)));
                let change = match s.lease.as_ref().map_or(LeaseChange::Replaced, |installed| {
                    lease_change(installed, current.as_ref())
                }) {
                    LeaseChange::Resolvers(next) if !resolvers_acceptable(&next) => {
                        LeaseChange::Replaced
                    }
                    other => other,
                };
                let hotspot_off = hotspot::owner_off("wlan2")
                    || s.selected
                        .as_ref()
                        .is_some_and(|n| n.frequency < 3000 && hotspot::owner_off("wlan0"));
                // Off by the owner's switch cancels the restart choice; Wi-Fi
                // the firmware keeps off for now (power-off charging) does not.
                let by_owner = hotspot_off
                    && (hotspot::off_by_owner("wlan2")
                        || s.selected
                            .as_ref()
                            .is_some_and(|n| n.frequency < 3000 && hotspot::off_by_owner("wlan0")));
                let decision = decide(link, child_ok, change, hotspot_off);
                if let Decision::Teardown(reason) = decision {
                    crate::netlog!("[relay] teardown reason={reason} recovery_ms={} query_ms={query_ms} lock_ms={lock_ms}", s.association.elapsed(BootClock.now()).as_millis());
                    let mut session = i.session.take().unwrap();
                    if hotspot_off {
                        this.cancel_restore();
                    }
                    i.phase = Phase::Disconnecting;
                    this.publish(&i);
                    drop(i);
                    let intent = if by_owner { resume::clear(Path::new(JOURNAL)) } else { Ok(()) };
                    let restored = cleanup(&mut session, || this.uplink_changed());
                    let mut i = this.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    i.error = Some(
                        restored.err().or_else(|| intent.err()).unwrap_or_else(||
                            if by_owner { "Hotspot was turned off; relay stopped and restart recovery cancelled".into() }
                            else if hotspot_off { "Wi-Fi is off; relay stopped. It reconnects when the router next starts with Wi-Fi on.".into() }
                            else { "Wi-Fi relay disconnected or lease changed; previous routing restored. Cellular data is used only if already enabled. Scan and reconnect.".into() }),
                    );
                    this.publish(&i);
                } else if decision == Decision::Hold {
                    // Only retain the configured path while its original lease
                    // and both helpers remain valid. No lease is extended here.
                    i.phase = Phase::Recovering;
                    this.publish(&i);
                    continue;
                } else {
                    if let Decision::Keep(Some(next)) = decision {
                        s.lease = Some(next);
                    }
                    let lease = s.lease.as_ref().unwrap();
                    let resolvers = if lease.dns.is_empty() { vec![lease.gateway] } else { lease.dns.clone() };
                    let dns = dns::reconcile(&resolvers);
                    if let Some(Err(e)) = crate::netfx::conntrack::retry() {
                        crate::netlog!("[relay] connection reset retry failed: {e}");
                    }
                    // `due` answers once per trigger: IPv6 reuses this answer.
                    let guard_due = s.guard.due();
                    let guarded = if guard_due {
                        // One set of listings for the five transactions below.
                        let _pass = net::Pass::open();
                        // The tables and the upstream INPUT accepts first:
                        // IPv6's own chain hooks into them.
                        let mut result = s.uplink.reconcile();
                        result.extend(s.wireless.reconcile_only(firewall_step));
                        result.extend(s.network.reconcile());
                        // The portal RETURN, held with the switch.
                        result.extend(s.dns.reconcile());
                        result.extend(s.ipv6.reconcile());
                        s.guard.after(&result);
                        crate::net_guard::report("relay", result)
                    } else {
                        Ok(())
                    };
                    s.dns_error = dns.and(guarded).err();
                    let before = s.ipv6.revision();
                    let tick = s.ipv6.tick(guard_due);
                    let changed = before != s.ipv6.revision();
                    if let Err(e) = tick {
                        // A failed IPv6 undo must not leave an unsupervised path.
                        let mut session = i.session.take().unwrap();
                        i.phase = Phase::Disconnecting;
                        this.publish(&i);
                        drop(i);
                        let restored = cleanup(&mut session, || this.uplink_changed());
                        let mut i = this.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        i.error = Some(restored.err().unwrap_or(e));
                        this.publish(&i);
                    } else if changed {
                        i.phase = Phase::Active;
                        this.publish(&i);
                        // The core restart takes seconds; do not hold the
                        // session lock for it (op still orders it).
                        drop(i);
                        this.uplink_changed();
                    } else {
                        i.phase = Phase::Active;
                        this.publish(&i);
                    }
                }
            }
        });
    }

    /// Roll back what a previous process left (crash, update, reboot).
    /// A connection the previous agent left working in this boot is taken
    /// over instead (`adopt`, owner choice Q1).
    pub fn recover_idle(&self) {
        let claim = self.begin_teardown();
        let lock = self.op.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _operation = self.hold_operation(lock, claim, Some(Phase::Recovering));
        // A request may have started the relay before this ran.
        let idle = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).session.is_none();
        if idle {
            if let Some(session) = self.adopt_previous() {
                let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                i.session = Some(session);
                i.error = None;
                self.publish(&i);
                self.wake.notify_all();
                return;
            }
            // Routes a previous agent left may be what Mihomo (adopted after
            // an agent restart) runs on: tell it once they are gone.
            let routed = routes_journaled(Path::new(JOURNAL));
            let recovered = self.recover();
            if routed && !routes_journaled(Path::new(JOURNAL)) {
                self.uplink_changed();
            }
            if let Err(e) = recovered {
                let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                i.error = Some(e);
                self.publish(&i);
            }
        }
    }

    /// The previous agent's working connection, when the owner left it on
    /// and it still matches; `None` rolls back and restores as before.
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

    pub fn wants_restore(&self) -> bool {
        resume::load(Path::new(JOURNAL)).is_some()
    }

    /// After the agent starts: rejoin the network the owner left connected
    /// (`resume`), retrying while the hotspot, radio or upstream comes up.
    /// Stops once the owner connects, disconnects or picks another network.
    pub fn restore(&self) {
        let root = Path::new(JOURNAL);
        let Some((target, generation)) = self.begin_restore(root) else { return };
        let mut last = String::new();
        for (attempt, wait) in RESTORE_WAITS.into_iter().enumerate() {
            if !self.wait_restore(generation, Duration::from_secs(wait)) {
                return;
            }
            if hotspot::owner_off("wlan2") {
                if !hotspot::off_by_owner("wlan2") {
                    // The firmware keeps Wi-Fi off for now: the restart
                    // choice stays for the next start.
                    crate::netlog!("[relay] restore attempt {} skipped: Wi-Fi is off, but not by the owner's switch", attempt + 1);
                    last = "Wi-Fi is off".into();
                    continue;
                }
                let lock = self.op.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let _operation = self.hold_operation(lock, self.begin_teardown(), None);
                let current = self.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner).restore_generation == generation;
                if current {
                    let error = resume::clear(root).err();
                    self.cancel_restore();
                    if let Some(error) = error {
                        let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        i.error = Some(error);
                        self.publish(&i);
                    }
                }
                return;
            }
            let found = self.scan_for_restore(Some((&target, generation))).and_then(|()| {
                let i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                resume::pick(&target, &i.scans).map(|n| n.id.clone()).ok_or_else(|| "The network was not found in the scan".to_owned())
            });
            match found.and_then(|id| self.join(&id, "", target.ipv6, Origin::Restore(&target, generation))) {
                Ok(()) => {
                    crate::netlog!("[relay] restored after {} attempt(s)", attempt + 1);
                    return self.finish_restore(generation, None);
                }
                Err(e) if e == RESTORE_CANCELLED => return self.finish_restore(generation, None),
                Err(e) if e == RESTORE_NO_PASSWORD => {
                    last = e;
                    break;
                }
                Err(e) => {
                    crate::netlog!("[relay] restore attempt {} failed: {e}", attempt + 1);
                    last = e;
                }
            }
        }
        self.finish_restore(generation, Some(format!("Could not reconnect after the agent restarted: {last}. Scan and reconnect.")));
    }

    fn begin_restore(&self, root: &Path) -> Option<(resume::Resume, u64)> {
        let lock = self.op.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _operation = self.hold_operation(lock, self.begin_teardown(), None);
        let target = resume::load(root)?;
        let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut restore = self.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if i.session.is_some() || restore.restore_generation != 0 { return None; }
        restore.restoring = Some(target.ssid.clone());
        let generation = restore.restore_generation;
        drop(restore);
        i.phase = Phase::Recovering;
        self.publish(&i);
        Some((target, generation))
    }

    fn cancel_restore(&self) -> u64 {
        let mut restore = self.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        restore.restore_generation = restore.restore_generation.wrapping_add(1);
        restore.restoring = None;
        self.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner)["restoring"] = Value::Null;
        self.restore_wake.notify_all();
        restore.restore_generation
    }

    fn wait_restore(&self, generation: u64, wait: Duration) -> bool {
        let restore = self.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (restore, _) = self.restore_wake.wait_timeout_while(restore, wait, |restore| {
            restore.restore_generation == generation && restore.restoring.is_some() && !self.active()
        }).unwrap_or_else(std::sync::PoisonError::into_inner);
        restore.restore_generation == generation && restore.restoring.is_some() && !self.active()
    }

    fn finish_restore(&self, generation: u64, error: Option<String>) {
        let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut restore = self.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if restore.restore_generation != generation { return; }
        restore.restoring = None;
        drop(restore);
        if error.is_some() { i.error = error; }
        drop(i);
        self.settle();
    }

    /// Caller holds op; reject stale work before any device call.
    fn check_restore(&self, root: &Path, target: &resume::Resume, generation: u64) -> Result<(), String> {
        let generation_matches = self.generation_matches(generation);
        if !generation_matches || self.active() || resume::load(root).as_ref() != Some(target) {
            return Err(RESTORE_CANCELLED.into());
        }
        Ok(())
    }

    fn generation_matches(&self, generation: u64) -> bool {
        let restore = self.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        restore.restore_generation == generation && !restore.disconnect
    }

    pub fn scan(&self) -> Result<(), String> {
        self.scan_for_restore(None)
    }

    fn scan_for_restore(&self, restore: Option<(&resume::Resume, u64)>) -> Result<(), String> {
        let _operation = self.operation(Some(Phase::Scanning))?;
        if let Some((target, generation)) = restore {
            self.check_restore(Path::new(JOURNAL), target, generation)?;
        }
        let idle = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).session.is_none();
        let mut temporary = if idle { Some(self.prepare()?) } else { None };
        let result: Result<_, String> = (|| {
            let channels = scan::Channels::parse(&Cmd::new("iw", &["phy", &radio_phy()?, "channels"]).run()?);
            let plan = channels.plan();
            let mut ctrl = scan::Ctrl::attach(&Path::new(ROOT).join("ctrl").join(IFACE), Path::new(ROOT))?;
            let (table, took) = scan::run(&mut ctrl, &plan)?;
            Ok(parse_bss_on_channels(&table, took.as_secs() + 1, &channels))
        })();
        if let Some(s) = &mut temporary {
            self.set_phase(Phase::Disconnecting);
            cleanup(s, || ())?;
        }
        let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        i.scans = result?;
        i.error = None;
        self.publish(&i);
        Ok(())
    }

    fn prepare(&self) -> Result<Session, String> {
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
            for tool in ["iptables", "ip6tables"] {
                if Cmd::new(tool, &["-w", "2", "-t", "filter", "-S", "U60_RELAY_IN"]).run().is_ok() {
                    return Err("Relay firewall chains are already in use".into());
                }
            }
            session.uplink.claim()?;
            let mut guards = input_guards();
            guards.extend(uplink::steps());
            session.wireless.apply_network(guards)?;
            session.uplink.guard()?;
            session
                .wireless
                .apply(Step::new(Cmd::new("iw", &["phy", phy, "interface", "add", IFACE, "type", "managed"]), Cmd::new("iw", &["dev", IFACE, "del"])))?;
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
            session.wireless.apply(Step::new(Cmd::new("sysctl", &["-w", &format!("net.ipv6.conf.{IFACE}.disable_ipv6=1")]), Cmd::new("true", &[])))?;
            Cmd::new("ip", &["link", "set", "dev", IFACE, "up"]).run()?;
            net::write_private(&Path::new(ROOT).join("wpa.conf"), format!("ctrl_interface={ROOT}/ctrl\nupdate_config=0\n").as_bytes())?;
            let mut cmd = Command::new("wpa_supplicant");
            cmd.args(["-D", "nl80211", "-i", IFACE, "-c", &format!("{ROOT}/wpa.conf"), "-qq"]);
            session.supplicant = Some(Helper::Owned(net::owned_child(cmd)?));
            let ready = (0..30).any(|_| {
                if wpa("ping", &[]).is_ok_and(|s| s.ends_with("PONG")) {
                    true
                } else {
                    std::thread::sleep(Duration::from_millis(100));
                    false
                }
            });
            if !ready {
                return Err("wpa_supplicant did not become ready".into());
            }
            // A PONG from another supplicant must not pass for ours.
            if !session.supplicant.as_mut().is_some_and(Helper::alive) {
                return Err("wpa_supplicant exited; another process may own the relay interface".into());
            }
            let old = wpa("driver", &["GETROAMMODE"])?;
            let mode = old.split_whitespace().last().filter(|s| matches!(*s, "0" | "1")).ok_or("Cannot determine original roam mode")?;
            session.wireless.apply(roam_step(mode))?;
            Ok(())
        })();
        if let Err(e) = result {
            return Err(cleanup(&mut session, || self.uplink_changed()).err().unwrap_or(e));
        }
        Ok(session)
    }

    fn connect_remembered(&self, id: &str, password: &str, confirmed: bool, ipv6: bool, remember: bool) -> Result<(), String> {
        if !confirmed {
            return Err("Confirm hotspot interruption and possible cellular charges first".into());
        }
        // Invalid selection/password must not cancel a working connection's
        // restart intent. No device calls or state changes until validation.
        // The tick holds `inner` over its device calls: that wait counts too.
        let deadline = Instant::now() + crate::netfx::admission::WAIT;
        {
            let i = crate::netfx::admission::enter(&self.inner, crate::netfx::admission::WAIT).ok_or_else(|| self.in_progress())?;
            selected_config(&i.scans, id, password)?;
        }
        // The owner's choice ends a restore first, so one that is joining
        // gives the operation up instead of refusing this request each time.
        let generation = self.cancel_restore();
        let _operation = self.operation_by(Some(Phase::Connecting), deadline)?;
        self.join_locked(id, password, ipv6, Origin::Owner { remember, generation })
    }

    fn join(&self, id: &str, password: &str, ipv6: bool, origin: Origin) -> Result<(), String> {
        let _operation = self.operation(Some(Phase::Connecting))?;
        self.join_locked(id, password, ipv6, origin)
    }

    fn join_locked(&self, id: &str, password: &str, ipv6: bool, origin: Origin) -> Result<(), String> {
        let root = Path::new(JOURNAL);
        match origin {
            Origin::Owner { .. } => {},
            Origin::Restore(target, generation) => self.check_restore(root, target, generation)?,
        }
        let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.generation_matches(origin.generation()) { return Err(RESTORE_CANCELLED.into()); }
        let (selected, password, network_config) = selected_config(&i.scans, id, password)?;
        // Country/driver restrictions may have changed since the last scan.
        let channels = scan::Channels::parse(&Cmd::new("iw", &["phy", &radio_phy()?, "channels"]).run()?);
        if !channels.contains(selected.frequency) {
            return Err("The upstream channel is disabled by the radio; scan again".into());
        }
        // A validated replacement owns the next restart choice only once it
        // succeeds. Until then, do not silently restart the previous network.
        if matches!(origin, Origin::Owner { .. }) { resume::clear(root)?; }
        let old = i.session.take();
        self.publish(&i);
        drop(i);
        // Publish early failures too, or the page keeps an older attempt's error.
        let failed = |e: String| {
            let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            i.error = Some(e.clone());
            self.publish(&i);
            Err(e)
        };
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
                    return failed(e);
                }
            }
        }
        let kept = handed.is_some();
        let ipv6_kept = handed.as_ref().is_some_and(|(_, ipv6)| *ipv6);
        let mut session = match handed.map_or_else(|| self.prepare(), |(next, _)| Ok(next)) {
            Ok(session) => session,
            Err(e) => return failed(e),
        };
        let check = || match origin {
            Origin::Restore(target, generation) => self.check_restore(root, target, generation),
            Origin::Owner { generation, .. } => {
                if self.generation_matches(generation) { Ok(()) } else { Err(RESTORE_CANCELLED.into()) }
            },
        };
        let result = (|| {
            check()?;
            if !kept {
                hotspot::prepare(&mut session.wireless, selected.frequency, &channels)?;
            }
            net::write_private(&Path::new(ROOT).join("wpa.conf"), format!("ctrl_interface={ROOT}/ctrl\nupdate_config=0\n{network_config}").as_bytes())?;
            // Undo must detach STA before restoring the same-radio AP channel,
            // including a crash between reconfigure and association completion
            // (a handed-over station has that undo already).
            session.wireless.ensure(association_step())?;
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
            net::reserve("iptables", "filter", &["U60_RELAY_FWD"], "-4", TABLE, PREF)?;
            if fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default().trim() != "1" {
                return Err("Router IPv4 forwarding is disabled".into());
            }
            // The tables grow (forwarding, DNS, the IPv6 baseline) after the
            // legacy accepts and routes, before the policy rule moves traffic.
            let mut plan = relay_plan(&lease, prefix, lan_ip, lan_mask);
            let rule = plan.pop().expect("the policy rule is the plan's last step");
            session.network.apply_network(plan)?;
            // LAN web traffic skips the vendor's offline redirect before the
            // policy rule moves it; a handed-over session holds the RETURN.
            for step in portal::web_bypasses() {
                session.dns.ensure(step)?;
            }
            session.uplink.update(|l| l.relay = Some(relay_layout(&lease, lan_ip, lan_mask)))?;
            session.network.apply_network(vec![rule])?;
            session.routed = true;
            let route = Cmd::new("ip", &["-4", "route", "get", "1.1.1.1"]).run()?;
            if !route.contains(&format!("dev {IFACE}")) {
                return Err("Firmware policy routing did not select the Wi-Fi upstream".into());
            }
            // CPU-path help and hardware forwarding are optional: the relay
            // works without them.
            if let Err(e) = session.network.apply_network(steering::plan()) {
                crate::netlog!("[relay] receive steering not applied: {e}");
            }
            if power_save::auto_off(Path::new(JOURNAL)) {
                let _ = session.power_save.set(&mut session.network, true);
            }
            let subnet = format!("{}/{prefix}", Ipv4Addr::from(u32::from(lease.ip) & u32::from(lease.subnet)));
            session.offload = offload::Runtime::start(&mut session.network, lease.gateway, subnet);
            session.dns.apply(resolver(&lease))?;
            // After a handover the switch already reads 0 (held): no step,
            // no dnsmasq restart.
            if let Some(step) = portal::plan()? {
                session.dns.ensure(step)?;
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
            if off { self.cancel_restore(); }
            self.set_phase(Phase::Disconnecting);
            let e = cleanup(&mut session, || self.uplink_changed()).err().unwrap_or(e);
            let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            i.error = clear_error.or_else(|| (e != RESTORE_CANCELLED).then(|| e.clone()));
            self.publish(&i);
            return Err(e);
        }
        if !self.generation_matches(origin.generation()) {
            self.set_phase(Phase::Disconnecting);
            let cleaned = cleanup(&mut session, || self.uplink_changed());
            return cleaned.and(Err(RESTORE_CANCELLED.into()));
        }
        let mut error = None;
        if let Origin::Owner { remember, .. } = origin {
            if let Err(e) = saved::remember(&selected, remember.then_some(password.as_str())) { error = Some(format!("Relay connected, but {e}")); }
            // Only a credential the router keeps can be rejoined after a restart.
            let kept = selected.security == "open" || saved::password(&selected).ok().flatten().is_some_and(|p| p == password);
            if kept {
                if let Err(e) = resume::save(root, &selected, ipv6) { error = Some(format!("Relay connected, but {e}")); }
            }
        }
        let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // No I/O under the cancellation lock. A pending disconnect clears
        // any intent saved above before this operation releases op.
        let restore = self.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if restore.restore_generation != origin.generation() || restore.disconnect {
            drop(restore);
            drop(i);
            self.set_phase(Phase::Disconnecting);
            let cleaned = cleanup(&mut session, || self.uplink_changed());
            return cleaned.and(Err(RESTORE_CANCELLED.into()));
        }
        i.session = Some(session);
        i.error = error;
        drop(restore);
        i.phase = Phase::Active;
        self.publish(&i);
        self.wake.notify_all();
        // Restarting the core takes seconds: do it without the session lock.
        drop(i);
        self.uplink_changed();
        Ok(())
    }

    pub fn disconnect(&self) -> Result<(), String> {
        {
            let mut restore = self.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            restore.restore_generation = restore.restore_generation.wrapping_add(1);
            restore.restoring = None;
            restore.disconnect = true;
            let mut snapshot = self.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            snapshot["restoring"] = Value::Null;
            snapshot["phase"] = json!(Phase::Disconnecting);
            snapshot["recovery_required"] = json!(false);
            self.owned.store(true, Ordering::Release);
            self.restore_wake.notify_all();
        }
        let Some(lock) = crate::netfx::admission::enter(&self.op, Duration::ZERO) else { return Ok(()) };
        let _operation = self.hold_operation(lock, self.begin_teardown(), None);
        self.teardown()
    }

    fn teardown(&self) -> Result<(), String> {
        self.restore.lock().unwrap_or_else(std::sync::PoisonError::into_inner).disconnect = false;
        self.set_phase(Phase::Disconnecting);
        // Off until the owner connects again, restarts included.
        let cleared = resume::clear(Path::new(JOURNAL));
        let session = {
            let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let session = i.session.take();
            self.publish(&i);
            session
        };
        let result = if let Some(mut s) = session {
            cleanup(&mut s, || self.uplink_changed())
        } else {
            // Mihomo follows only routes a previous agent left and this removed.
            let routed = routes_journaled(Path::new(JOURNAL));
            let recovered = self.recover();
            if routed && !routes_journaled(Path::new(JOURNAL)) {
                self.uplink_changed();
            }
            recovered
        };
        let result = result.and(cleared);
        let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        i.error = result.as_ref().err().cloned();
        self.publish(&i);
        result
    }

    /// Owner action (`power_save`): saved for later connections and applied
    /// to the current one at once.
    fn set_power_save(&self, auto_off: bool) -> Result<(), String> {
        let _operation = self.operation(None)?;
        power_save::save(Path::new(JOURNAL), auto_off)?;
        let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = i.session.as_mut().map_or(Ok(()), |s| s.power_save.set(&mut s.network, auto_off));
        self.publish(&i);
        result.map_err(|e| format!("Setting saved. {e}"))
    }

    /// Owner action: hardware forwarding on or off without a restart. Saved
    /// for later connections; a connected relay follows at once. A changed
    /// path resets LAN IPv4 connections, so established and offloaded flows
    /// move onto it: the reset's actual outcome (`conntrack::Report::json`,
    /// or a failure that stays pending for the watchdog's retry) when the
    /// path changed; the console says only what happened.
    fn set_offload_enabled(&self, on: bool) -> Result<Option<Value>, String> {
        let _operation = self.operation(None)?;
        offload::set_enabled(on)?;
        crate::netlog!("[relay] hardware forwarding switched {}", if on { "on" } else { "off" });
        let mut i = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(s) = i.session.as_mut() else { return Ok(None) };
        let changed_at = Instant::now();
        let changed = s.offload.sync(&mut s.network);
        self.publish(&i);
        drop(i);
        match changed {
            Ok(true) => Ok(Some(
                match crate::netfx::conntrack::reset_since("relay forwarding path changed", crate::netfx::conntrack::Scope::Lan { v4: true, v6: false }, changed_at) {
                    Ok(report) => report.json(),
                    Err(e) => crate::netfx::conntrack::failed_json(&e),
                },
            )),
            Ok(false) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn forget(&self, id: &str) -> Result<(), String> {
        let _operation = self.operation(None)?;
        saved::forget(id)
    }
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
    let routes = old.network.rollback();
    // Only the resolver follows the lease. Released here, the switch read 1
    // until the next lease and a fw3 reload in that gap let the vendor's
    // DNAT in for good (`portal`); the next session holds both as they are.
    let dns = old.dns.release(&[resolver_undo()]);
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
    next.wireless = std::mem::replace(&mut old.wireless, Transaction::new(journal.join("wireless.json")));
    next.dns = std::mem::replace(&mut old.dns, Transaction::new(journal.join("dns.json")));
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
    let routes = s.network.rollback();
    let dns = s.dns.rollback();
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
    let wireless = s.wireless.rollback();
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
fn firewall_step(cmd: &Cmd) -> bool {
    matches!(cmd.program.as_str(), "iptables" | "ip6tables")
}

/// What must pass the vendor's INPUT rejects from the upstream: established
/// replies and DHCP offers (IPv6 hooks its own `U60_R6_IN` in here). The
/// guard's drop is in `uplink`; these chains hold accepts only, so a rule
/// re-added out of order can neither open nor close anything else.
fn input_guards() -> Vec<Step> {
    let mut p = Vec::new();
    for tool in ["iptables", "ip6tables"] {
        p.extend(net::chain(tool, "filter", "U60_RELAY_IN"));
        if tool == "iptables" {
            p.push(net::rule(tool, "filter", "U60_RELAY_IN", &["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], false));
            p.push(net::rule(tool, "filter", "U60_RELAY_IN", &["-p", "udp", "--sport", "67", "--dport", "68", "-j", "ACCEPT"], false));
        }
        p.push(net::rule(tool, "filter", "INPUT", &["-i", IFACE, "-j", "U60_RELAY_IN"], true));
    }
    p
}

/// The tables' part for installed routes: the resolver DNS goes to and the
/// LAN it keeps.
fn relay_layout(l: &Lease, lan: Ipv4Addr, mask: Ipv4Addr) -> uplink::Relay {
    let lan = format!("{}/{}", Ipv4Addr::from(u32::from(lan) & u32::from(mask)), u32::from(mask).count_ones());
    uplink::Relay { dns: l.dns.first().copied().unwrap_or(l.gateway), lan }
}

/// The `dns` transaction's resolver line (`dns`), which follows the lease.
fn resolver(l: &Lease) -> Step {
    let dns = l.dns.first().copied().unwrap_or(l.gateway).to_string();
    Step::new(Cmd::new("@u60-relay-dns", &[&dns]), resolver_undo())
}

fn resolver_undo() -> Cmd {
    Cmd::new("@u60-relay-dns", &[])
}

/// Addresses, routes, the legacy accepts and MASQUERADE; the policy rule is
/// last (the caller loads the tables before it). The portal RETURN is not
/// here: `handover` rolls this plan back, and the RETURN stays with the
/// switch in `dns` (`portal::web_bypasses`).
fn relay_plan(l: &Lease, prefix: u32, lan: Ipv4Addr, mask: Ipv4Addr) -> Vec<Step> {
    let address = format!("{}/{prefix}", l.ip);
    let subnet = format!("{}/{prefix}", Ipv4Addr::from(u32::from(l.ip) & u32::from(l.subnet)));
    let lan_net = format!("{}/{}", Ipv4Addr::from(u32::from(lan) & u32::from(mask)), u32::from(mask).count_ones());
    let gw = l.gateway.to_string();
    let mut p = vec![net::ip_step("-4", "addr", &[&address, "dev", IFACE])];
    p.push(net::ip_step("-4", "route", &[&subnet, "dev", IFACE, "scope", "link", "src", &l.ip.to_string(), "table", TABLE]));
    // Other RFC1918 subnets can host the hotel's portal/DNS. Only our own
    // management/tailnet/link-local routes fall through to the main tables.
    for dest in crate::netfx::ids::LOCAL_ROUTES_V4.iter().copied().chain([lan_net.as_str()]) {
        if dest != subnet {
            p.push(net::ip_step("-4", "route", &["throw", dest, "table", TABLE]));
        }
    }
    p.push(net::ip_step("-4", "route", &["default", "via", &gw, "dev", IFACE, "table", TABLE]));
    // Through the vendor's FORWARD rejects; `uplink` drops the rest first.
    p.extend(net::chain("iptables", "filter", "U60_RELAY_FWD"));
    p.push(net::rule("iptables", "filter", "U60_RELAY_FWD", &["-i", "br-lan", "-o", IFACE, "-j", "ACCEPT"], false));
    p.push(net::rule("iptables", "filter", "U60_RELAY_FWD", &["-i", IFACE, "-o", "br-lan", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], false));
    p.push(net::rule("iptables", "filter", "FORWARD", &["-j", "U60_RELAY_FWD"], true));
    // Core/router UDP sockets may retain a previously selected SIM source.
    // Translate only our owned Wi-Fi egress, not cellular or local traffic
    // (it stays in legacy until an nft MASQUERADE is shown to keep hardware
    // forwarding, D11). It also covers router DNS that `uplink` redirects
    // from a socket bound to a SIM source. Its comment is its identity
    // (`owned_rule`): the station's name is one the vendor's files list.
    p.push(net::rule("iptables", "nat", "POSTROUTING", &["-o", IFACE, "-m", "comment", "--comment", crate::netfx::ids::RELAY_COMMENT, "-j", "MASQUERADE"], true));
    // Installed last: no downstream traffic switches until NAT/guards exist.
    p.push(net::ip_step("-4", "rule", &["pref", PREF, "lookup", TABLE]));
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
        "clock" => state.wifi_relay.recheck_clock_with(crate::network_clock::recheck_wifi),
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

    fn restore_fixture(name: &str) -> (WifiRelay, std::path::PathBuf, Network) {
        let root = std::env::temp_dir().join(format!("u60-restore-{name}-{}", std::process::id()));
        let network = Network { id: "restore-test".into(), ssid: "Restore test".into(), frequency: 2412, signal: -40, security: "open", supported: true, bssid: "02:00:00:00:00:01".into() };
        resume::save(&root, &network, true).unwrap();
        (WifiRelay::new(Arc::new(Mutex::new(()))), root, network)
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
    fn restore_cancel_is_immediate_and_stale_results_cannot_overwrite_owner_state() {
        let (relay, root, network) = restore_fixture("cancel");
        let (target, generation) = relay.begin_restore(&root).unwrap();
        assert_eq!(relay.snapshot.lock().unwrap()["restoring"], network.ssid);
        relay.cancel_restore();
        assert!(relay.snapshot.lock().unwrap()["restoring"].is_null());
        assert!(!relay.wait_restore(generation, Duration::from_secs(300)));
        // Even if clearing persistent intent fails, this process must stop.
        assert!(resume::load(&root).is_some());
        assert_eq!(relay.check_restore(&root, &target, generation).unwrap_err(), RESTORE_CANCELLED);
        assert!(relay.begin_restore(&root).is_none());
        // Both production entry points reject old work before touching tools.
        assert_eq!(relay.scan_for_restore(Some((&target, generation))).unwrap_err(), RESTORE_CANCELLED);
        assert_eq!(relay.join(&network.id, "", true, Origin::Restore(&target, generation)).unwrap_err(), RESTORE_CANCELLED);
        relay.inner.lock().unwrap().error = Some("New owner operation".into());
        relay.finish_restore(generation, Some("Stale restore failure".into()));
        assert_eq!(relay.inner.lock().unwrap().error.as_deref(), Some("New owner operation"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_wait_is_woken_by_cancel_instead_of_waiting_five_minutes() {
        let (relay, root, _) = restore_fixture("wake");
        let (_, generation) = relay.begin_restore(&root).unwrap();
        let relay = Arc::new(relay);
        let (send, receive) = std::sync::mpsc::channel();
        let waiting = Arc::clone(&relay);
        let thread = std::thread::spawn(move || {
            send.send(waiting.wait_restore(generation, Duration::from_secs(300))).unwrap();
        });
        relay.cancel_restore();
        assert!(!receive.recv_timeout(Duration::from_secs(2)).unwrap());
        thread.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_rechecks_changed_target_and_same_target_owner_replacement() {
        let (relay, root, mut network) = restore_fixture("target");
        let (target, generation) = relay.begin_restore(&root).unwrap();
        assert!(relay.check_restore(&root, &target, generation).is_ok());
        network.ssid = "Another choice".into();
        resume::save(&root, &network, true).unwrap();
        assert_eq!(relay.check_restore(&root, &target, generation).unwrap_err(), RESTORE_CANCELLED);
        network.ssid = target.ssid.clone();
        relay.cancel_restore();
        resume::save(&root, &network, true).unwrap();
        assert_eq!(resume::load(&root), Some(target.clone()));
        assert_eq!(relay.check_restore(&root, &target, generation).unwrap_err(), RESTORE_CANCELLED);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_intent_io_failures_are_explicit_and_do_not_masquerade_as_cancellation() {
        let root = std::env::temp_dir().join(format!("u60-restore-io-{}", std::process::id()));
        fs::create_dir_all(root.join("resume.json")).unwrap();
        assert_eq!(resume::clear(&root).unwrap_err(), "Cannot clear the relay to restore");
        let network = Network { id: "write-fails".into(), ssid: "Restore test".into(), frequency: 2412, signal: -40, security: "open", supported: true, bssid: "02:00:00:00:00:01".into() };
        assert_eq!(resume::save(&root, &network, true).unwrap_err(), "Cannot save the relay to restore after a restart");
        let relay = WifiRelay::new(Arc::new(Mutex::new(())));
        relay.cancel_restore();
        assert!(relay.begin_restore(&root).is_none());
        fs::remove_dir_all(root).unwrap();
    }


    #[test]
    fn the_upstream_input_guard_is_rechecked_but_radio_steps_are_not() {
        let guard = input_guards();
        assert!(guard.iter().all(|s| firewall_step(&s.apply) && s.apply.checkable()), "every guard step can be re-applied");
        assert!(guard.iter().any(|s| s.apply.args.windows(2).any(|w| w == ["-N", "U60_RELAY_IN"])));
        for radio in [roam_step("0"), association_step()] {
            assert!(!firewall_step(&radio.apply));
        }
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
        *relay.snapshot.lock().unwrap() = json!({
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
        relay.snapshot.lock().unwrap()["connected"] = json!(false);
        assert!(relay.status_with_clock(&clock)["clock_error"].is_null(), "No stale warning while relay is off");
    }

    #[test]
    fn clock_recheck_requires_a_stable_connected_relay_without_restarting_it() {
        let clock = crate::network_clock::WifiClock::new();
        let relay = WifiRelay::new(Arc::new(Mutex::new(())));
        assert_eq!(relay.recheck_clock_with(|| panic!("Must not probe while disconnected")).unwrap_err(), "Connect Wi-Fi relay before checking time");
        {
            let mut inner = relay.inner.lock().unwrap();
            let mut session = Session::new(Path::new(JOURNAL));
            session.selected = Some(Network { id: "clock-test".into(), ssid: "W".into(), frequency: 2412, signal: -40, security: "open", supported: true, bssid: "02:00:00:00:00:01".into() });
            session.lease = Some(lease_with(&[]));
            inner.session = Some(session);
        }
        relay.settle();
        let before = relay.snapshot.lock().unwrap().clone();
        let network = relay.op.lock().unwrap();
        assert!(relay.recheck_clock_with(|| panic!("Must not race a network operation")).unwrap_err().contains("network operation"));
        drop(network);
        for result in [Err("Upstream unavailable".to_owned()), Ok(())] {
            assert_eq!(relay.recheck_clock_with(|| {
                assert!(relay.op.try_lock().is_err(), "Keep the current uplink stable");
                assert!(relay.inner.try_lock().is_ok(), "Do not hold relay state during HTTPS");
                clock.sync_with(true, |_| {
                    assert_eq!(relay.status_with_clock(&clock)["ssid"], "W", "Status reads stay responsive");
                    result.clone()
                })
            }), result);
            assert_eq!(*relay.snapshot.lock().unwrap(), before, "No reconnect, cleanup or route changes");
            assert_eq!(relay.status_with_clock(&clock)["clock_error"], json!(result.err()));
        }
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
    fn invalid_owner_connect_preserves_the_current_recovery_generation() {
        let relay = WifiRelay::new(Arc::new(Mutex::new(())));
        {
            let mut i = relay.inner.lock().unwrap();
            relay.restore.lock().unwrap().restoring = Some("Working network".into());
            i.scans = parse_bss(&bss(&[("02:11:22:33:44:55", 5260, -49, 0, "[WPA2-PSK-CCMP][ESS]", "W_Game")]), 0);
        }
        assert!(relay.connect_remembered("unknown", "", true, true, false).is_err());
        let id = relay.inner.lock().unwrap().scans[0].id.clone();
        assert!(relay.connect_remembered(&id, "short", true, true, false).is_err());
        let restore = relay.restore.lock().unwrap();
        assert_eq!(restore.restore_generation, 0);
        assert_eq!(restore.restoring.as_deref(), Some("Working network"));
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
        let p = portal::web_bypasses();
        for tool in ["iptables", "ip6tables"] {
            let rule = p.iter().find(|s| s.apply.program == "@u60-relay-portal-return" && s.apply.args == [tool]).expect("missing vendor offline-portal bypass");
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
        let switch = Step::new(Cmd::new("@u60-relay-portal", &["disable"]), Cmd::new("@u60-relay-portal", &["release"]));
        let mut held = portal::web_bypasses();
        held.push(switch);
        assert_eq!((resolver(&l).apply, resolver(&l).undo), (Cmd::new("@u60-relay-dns", &["10.0.0.53"]), resolver_undo()));
        assert!(!held.iter().any(|s| s.undo == resolver_undo()), "the handover's release takes none of it");
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
        let dnat = "-A redirect_chain ! -d 192.168.0.1/32 -p tcp -m tcp --dport 80 -m limit --limit 20/sec --limit-burst 40 -j DNAT --to-destination 192.168.0.1";
        let ours = "-A redirect_chain -i br-lan -m comment --comment zte-agent-wifi-relay -j RETURN";
        let mut device = net::bench::Bench::router();
        device.list(Cmd::new("iptables", &["-w", "2", "-t", "nat", "-S"]), Ok(net::bench::router("iptables", "nat").replace(ours, &format!("{dnat}\n{ours}"))));
        let result = next.dns.reconcile_with(|_| true, &mut device);
        assert_eq!(device.applied, [portal::web_bypass("iptables").apply]);
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
        assert!(
            net::foreign_identity(&plan).is_empty(),
            "{:?}",
            net::foreign_identity(&plan)
        );
        assert!(net::foreign_identity(&input_guards()).is_empty());
    }

    #[test]
    fn status_reads_do_not_wait_for_ipv6_network_effects() {
        let relay = WifiRelay::new(Arc::new(Mutex::new(())));
        let _network_work = relay.inner.lock().unwrap();
        assert_eq!(relay.status()["connected"], false);
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

    #[test]
    fn admission_and_cancellation_do_not_wait_for_the_tick_state_lock() {
        let relay = Arc::new(WifiRelay::new(Arc::new(Mutex::new(()))));
        let tick = relay.inner.lock().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let waiting = Arc::clone(&relay);
        let worker = std::thread::spawn(move || {
            let active = waiting.active();
            let owns = waiting.owns_network();
            waiting.cancel_restore();
            send.send((active, owns)).unwrap();
        });
        let result = receive.recv_timeout(Duration::from_millis(200));
        drop(tick);
        worker.join().unwrap();
        assert!(!result.unwrap().0);
    }

    #[test]
    fn published_phases_do_not_report_journals_as_failed_recovery_during_work() {
        let relay = WifiRelay::new(Arc::new(Mutex::new(())));
        let root = std::env::temp_dir().join(format!("u60-relay-phases-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("wireless.json"), b"retained journal").unwrap();
        let mut inner = relay.inner.lock().unwrap();
        for phase in [Phase::Scanning, Phase::Connecting, Phase::Active, Phase::Recovering, Phase::Disconnecting] {
            inner.phase = phase;
            relay.publish_at(&inner, &root);
            let status = relay.status();
            assert_eq!(status["phase"], json!(phase));
            assert_eq!(status["recovery_required"], false, "{phase:?}");
        }
        for phase in [Phase::Idle, Phase::RecoveryPending] {
            inner.phase = phase;
            relay.publish_at(&inner, &root);
            assert_eq!(relay.status()["recovery_required"], true);
        }
        fs::remove_file(root.join("wireless.json")).unwrap();
        power_save::save(&root, false).unwrap();
        assert_eq!(relay.status()["recovery_required"], true, "GET does not re-read journals");
        assert_eq!(relay.status()["power_save"]["auto_off"], true, "GET does not re-read settings");
        relay.publish_at(&inner, &root);
        assert_eq!(relay.status()["recovery_required"], false);
        assert_eq!(relay.status()["power_save"]["auto_off"], false);
        let status = relay.status();
        for removed in ["experimental", "cellular_fallback", "internet"] {
            assert!(status.get(removed).is_none(), "unused field {removed}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn every_owner_request_stops_waiting_for_an_operation_and_reports_its_phase() {
        let state = crate::handlers::AppState::new();
        state.wifi_relay.set_phase(Phase::Disconnecting);
        state.wifi_relay.inner.lock().unwrap().scans.push(Network { id: "open".into(), ssid: "Open".into(), security: "open", bssid: "02:00:00:00:00:01".into(), frequency: 5180, supported: true, signal: -40 });
        let operation = state.wifi_relay.op.lock().unwrap();
        for (action, body) in [
            ("scan", json!({})),
            ("connect", json!({"network":"open","confirmed":true})),
            ("power-save", json!({"auto_off":true})),
            ("offload", json!({"enabled":true})),
            ("forget", json!({"id":"unavailable"})),
            ("clock", json!({})),
        ] {
            let started = Instant::now();
            let (code, reply) = change(&state, action, &serde_json::to_vec(&body).unwrap());
            assert_eq!(code, 409, "{action}: {reply}");
            assert_eq!(reply["phase"], "disconnecting", "{action}");
            assert!(reply["error"].as_str().unwrap().contains("in progress"), "{action}");
            assert!(started.elapsed() >= crate::netfx::admission::WAIT, "{action}: waited for short work");
            assert!(started.elapsed() < Duration::from_secs(1), "{action}: bounded wait");
        }
        drop(operation);
    }

    /// The tick holds `inner` over its device calls. A connect checks its
    /// selection there before anything else: that wait is bounded too, and
    /// a request that gave up there has cancelled nothing.
    #[test]
    fn a_connect_gives_up_on_the_tick_within_the_same_wait_and_cancels_nothing() {
        let state = crate::handlers::AppState::new();
        state.wifi_relay.inner.lock().unwrap().scans.push(Network { id: "open".into(), ssid: "Open".into(), security: "open", bssid: "02:00:00:00:00:01".into(), frequency: 5180, supported: true, signal: -40 });
        let generation = state.wifi_relay.restore.lock().unwrap().restore_generation;
        let tick = state.wifi_relay.inner.lock().unwrap();
        let started = Instant::now();
        let (code, reply) = change(&state, "connect", &serde_json::to_vec(&json!({"network":"open","confirmed":true})).unwrap());
        assert_eq!(code, 409, "{reply}");
        assert!(reply["error"].as_str().unwrap().contains("in progress"), "{reply}");
        assert!(started.elapsed() >= crate::netfx::admission::WAIT && started.elapsed() < Duration::from_secs(1));
        assert_eq!(state.wifi_relay.restore.lock().unwrap().restore_generation, generation, "no restore was cancelled");
        drop(tick);
    }

    #[test]
    fn disconnect_returns_immediately_during_teardown_and_invalidates_late_success() {
        let relay = Arc::new(WifiRelay::new(Arc::new(Mutex::new(()))));
        relay.set_phase(Phase::Disconnecting);
        let generation = relay.cancel_restore();
        let operation = relay.op.lock().unwrap();
        let tick = relay.inner.lock().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let stopping = Arc::clone(&relay);
        let worker = std::thread::spawn(move || send.send(stopping.disconnect()).unwrap());
        let result = receive.recv_timeout(Duration::from_millis(200));
        drop(tick);
        drop(operation);
        worker.join().unwrap();
        assert!(result.unwrap().is_ok());
        assert!(!relay.generation_matches(generation), "late successes cannot commit");
        assert!(relay.restore.lock().unwrap().disconnect, "the current holder finishes teardown");
        assert_eq!(relay.status()["phase"], "disconnecting");
        assert_eq!(relay.status()["recovery_required"], false);
    }

    #[tokio::test]
    async fn four_disconnects_cannot_fill_the_general_lane_behind_teardown() {
        use crate::httpd::gate::{Gate, Lane};
        use crate::server::{lane, route, Method};
        let state = Arc::new(crate::handlers::AppState::new());
        state.wifi_relay.set_phase(Phase::Disconnecting);
        let gate = Arc::new(Gate::new(4, 2, Duration::from_millis(200)));
        let operation = state.wifi_relay.op.lock().unwrap();
        let mut requests = Vec::new();
        for _ in 0..4 {
            let gate = Arc::clone(&gate);
            let state = Arc::clone(&state);
            requests.push(tokio::spawn(async move {
                gate.run(lane(Method::Post, "/api/wifi-relay/disconnect"), move || route(&Method::Post, "/api/wifi-relay/disconnect", &state, b"{}")).await
            }));
        }
        let finished = tokio::time::timeout(Duration::from_secs(1), async {
            for request in requests { assert_eq!(request.await.unwrap().unwrap().0, 200); }
            let state = Arc::clone(&state);
            assert_eq!(gate.run(Lane::General, move || route(&Method::Get, "/api/wifi-relay/status", &state, b"")).await.unwrap().0, 200);
        }).await;
        drop(operation);
        assert!(finished.is_ok(), "General requests complete while teardown still owns op");
        assert_eq!(gate.available(Lane::General), 4);
    }

    #[test]
    fn status_reads_only_memory_while_tick_and_conntrack_reset_are_locked() {
        let relay = Arc::new(WifiRelay::new(Arc::new(Mutex::new(()))));
        let tick = relay.inner.lock().unwrap();
        let operation = relay.op.lock().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let reading = Arc::clone(&relay);
        let mut result = None;
        let mut worker = None;
        crate::netfx::conntrack::while_reset_locked(|| {
            worker = Some(std::thread::spawn(move || send.send(reading.status()).unwrap()));
            result = Some(receive.recv_timeout(Duration::from_millis(200)));
        });
        drop(tick);
        drop(operation);
        worker.unwrap().join().unwrap();
        assert_eq!(result.unwrap().unwrap()["connected"], false);
    }

    #[test]
    fn an_operation_publishes_its_phase_until_the_holder_finishes() {
        let relay = WifiRelay::new(Arc::new(Mutex::new(())));
        for phase in [Phase::Scanning, Phase::Connecting, Phase::Recovering, Phase::Disconnecting] {
            let operation = relay.operation(Some(phase)).unwrap();
            assert_eq!(relay.status()["phase"], json!(phase));
            assert_eq!(relay.status()["recovery_required"], false);
            assert!(relay.op.try_lock().is_err());
            drop(operation);
            assert!(matches!(relay.status()["phase"].as_str(), Some("idle" | "recovery_pending")));
        }
    }

    #[test]
    fn the_holder_completes_a_busy_disconnect_before_releasing_the_operation() {
        let relay = WifiRelay::new(Arc::new(Mutex::new(())));
        let root = std::env::temp_dir().join(format!("u60-relay-deferred-stop-{}", std::process::id()));
        relay.inner.lock().unwrap().session = Some(Session::new(&root));
        let operation = relay.operation(Some(Phase::Scanning)).unwrap();
        relay.disconnect().unwrap();
        assert!(relay.restore.lock().unwrap().disconnect);
        assert!(relay.inner.lock().unwrap().session.is_some());
        drop(operation);
        assert!(!relay.restore.lock().unwrap().disconnect);
        assert!(relay.inner.lock().unwrap().session.is_none());
        assert!(relay.op.try_lock().is_ok());
        assert!(!relay.active());
    }
}
