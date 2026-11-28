//! Optional Mihomo process and LAN-only, dual-stack TCP/UDP TPROXY
//! interception in the agent's own nftables tables (owner decision 63). DNS
//! is fake-ip; what skips the core follows its mode and rules (`routing`,
//! owner decision 64). One controller thread owns the core and its network
//! effects (`controller`, `relay-mihomo-architecture.md` section 5); this
//! module is its device side (`DevicePort`) and the owner-facing API.
//! The agent owns lifecycle/routing; the separately distributed core owns
//! proxy protocols. No enhanced/GPL implementation is incorporated here.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use serde_yaml_ng::{Mapping, Value as Yaml};
use sha2::{Digest, Sha256};

use crate::net_tools::{self as net, Cmd};
use crate::netfx::effect::{self, EffectSet, Family, NftTable, NftTables, Presence, Resource, Route, RouteType, Rule, Sysctl};
use crate::netfx::ids;
use crate::netfx::perf::{Perf, PerfFeature};

pub mod control;
mod controller;
mod core;
pub mod dashboard;
mod dns;
mod download;
pub(crate) mod egress;
mod geodata;
mod follow;
mod geoip;
mod intercept;
pub mod profiles;
mod reload;
mod routing;
pub mod transform;
#[cfg(test)]
mod test_dir;

use controller::{Answered, Engage, Message, Phase, Prepared, Snapshot, Source};

pub const VERSION: &str = "1.19.33";
pub const DASHBOARD_VERSION: &str = "3.29.1";
pub const CONTROLLER: &str = "127.0.0.1:19090";
pub const ROOT: &str = "/data/zte-agent-mihomo";
/// Present while the owner wants Mihomo on (`restore`).
const WANTED: &str = "enabled";
pub const DASHBOARD: &str = "/ui/mihomo/dashboard/";
pub const API: &str = "/ui/mihomo/api";
const CORE_URL: &str =
    "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/mihomo-linux-arm64-v1.19.33.gz";
const CORE_SHA: &str = "ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187";
const UI_URL: &str =
    "https://github.com/Zephyruso/zashboard/releases/download/v3.29.1/dist-no-fonts.zip";
const UI_SHA: &str = "21371cd111b6b3d87774f3ea3ddeacdcb0f6aff8690a16d652daa3ea6e3b0145";
/// TPROXY mark (`mark and 0xffff00ff or 0x700`) and its local-delivery
/// table, ahead of Relay's catch-all table (18640).
const MARK: &str = ids::TPROXY_MARK;
const TABLE: &str = ids::MIHOMO_TABLE;
const PREF: &str = ids::MIHOMO_PREF;
/// Not 17893: the private download proxy listens there.
const TPROXY_PORT: u16 = ids::TPROXY_PORT;
/// `ip` and `ip6` tables of this name (B31 lacks inet `fib`). ZTE rewrites
/// only legacy iptables, never nftables.
const NFT_TABLE: &str = ids::MIHOMO_NFT;
/// Present while the owner lets IPv4 traffic matched as DIRECT skip the core
/// in the kernel (`routing`).
const BYPASS: &str = "direct-bypass";
const LEGACY_BYPASS: &str = "cn-direct";
/// The tables' batch file (`netfx::effect::NftTables`).
const NFT_FILE: &str = "nft-tables.nft";
pub const MAX_CONFIG: usize = 512 * 1024;
/// How long an owner command waits for the controller.
const COMMAND_WAIT: Duration = Duration::from_secs(150);
const QOS_MODE_TTL: Duration = Duration::from_secs(5);

/// Tailscale Strategy B Exit Node coordination state supplied by `TailscaleManager`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TailscaleExitConfig {
    /// Auto-enable Mihomo's `sniffer` (TLS/HTTP/QUIC + `parse-pure-ip`) for real-IP Exit traffic.
    pub sniffer: bool,
    /// Intercept IPv4 `tailscale0` Exit Node traffic (only when Exit Node IPv4 is approved).
    pub tproxy_v4: bool,
    /// Intercept IPv6 `tailscale0` Exit Node traffic (only when Exit Node IPv6 is approved).
    pub tproxy_v6: bool,
    /// Approved LAN IPv4 subnets on `tailscale0` that stay direct (never TPROXY'd).
    pub skip_v4: Vec<String>,
    /// Approved LAN IPv6 subnets on `tailscale0` that stay direct (never TPROXY'd).
    pub skip_v6: Vec<String>,
}

pub struct Mihomo {
    root: PathBuf,
    perf: Arc<Perf>,
    /// Excludes installation, configuration and owner starts.
    operation: Mutex<()>,
    profile_operation: Mutex<()>,
    profile_storage: Mutex<()>,
    profile_wake: Condvar,
    profile_revision: Mutex<u64>,
    library_revision: AtomicU64,
    status_cache: Mutex<Option<(profiles::LibraryStamp, Value)>>,
    qos_mode_cache: Mutex<Option<(Instant, Option<String>)>>,
    /// Fingerprints (secret and egress interface masked) of the last
    /// configurations that passed `mihomo -t`, newest first; a start with
    /// one of them skips the check (a relay/cellular switch, a fallback to
    /// the previous profile). Kept in `VALIDATED` for this boot, so a
    /// restarted agent reuses them.
    validated_config: Mutex<Vec<String>>,
    digests: geodata::Digests,
    subscription_dns: Mutex<Vec<std::net::Ipv4Addr>>,
    passes: dashboard::Passes,
    geoip: geoip::Cache,
    /// What the controller last published (pages never wait for it).
    shared: Arc<Mutex<Snapshot>>,
    commands: Mutex<Option<Sender<Message>>>,
    egress_generation: AtomicU64,
    tailscale_exit: Mutex<TailscaleExitConfig>,
    tailscale: OnceLock<Weak<crate::tailscale::TailscaleManager>>,
    #[cfg(test)]
    bridge_addr: Option<String>,
}

impl Mihomo {
    pub fn new() -> Self {
        Self::with_perf(PathBuf::from(ROOT), Perf::router())
    }

    fn with_perf(root: PathBuf, perf: Arc<Perf>) -> Self {
        let validated = remembered_validation(&root);
        Self {
            root,
            perf,
            operation: Mutex::new(()),
            profile_operation: Mutex::new(()),
            profile_storage: Mutex::new(()),
            profile_wake: Condvar::new(),
            profile_revision: Mutex::new(0),
            library_revision: AtomicU64::new(0),
            status_cache: Mutex::new(None),
            qos_mode_cache: Mutex::new(None),
            validated_config: Mutex::new(validated),
            digests: geodata::Digests::default(),
            subscription_dns: Mutex::new(Vec::new()),
            passes: dashboard::Passes::default(),
            geoip: geoip::Cache::default(),
            shared: Arc::new(Mutex::new(Snapshot::default())),
            commands: Mutex::new(None),
            egress_generation: AtomicU64::new(0),
            tailscale_exit: Mutex::new(TailscaleExitConfig::default()),
            tailscale: OnceLock::new(),
            #[cfg(test)]
            bridge_addr: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(root: PathBuf) -> Self {
        Self::at(root)
    }

    #[cfg(test)]
    fn at(root: PathBuf) -> Self {
        let perf = Arc::new(Perf::for_test(&root.join("perf")));
        Self::with_perf(root, perf)
    }

    pub(crate) fn perf(&self) -> &Arc<Perf> {
        &self.perf
    }

    fn set_perf_active(&self, active: bool) {
        self.perf.report(self.perf.set_active(PerfFeature::Mihomo, active));
    }

    /// A running core with this secret, for the bridge's tests.
    #[cfg(test)]
    pub(crate) fn for_bridge(root: PathBuf, secret: String) -> Self {
        Self::for_bridge_at(root, secret, CONTROLLER.parse().unwrap())
    }

    #[cfg(test)]
    pub(crate) fn for_bridge_at(root: PathBuf, secret: String, addr: std::net::SocketAddr) -> Self {
        let mut this = Self::for_test(root);
        this.bridge_addr = Some(addr.to_string());
        let mut snapshot = this.snapshot();
        snapshot.phase = Phase::Running;
        snapshot.secret = Some(secret);
        *this.shared.lock().unwrap() = snapshot;
        this
    }

    fn bridge_addr(&self) -> &str {
        #[cfg(test)]
        if let Some(addr) = &self.bridge_addr {
            return addr;
        }
        CONTROLLER
    }

    fn journal(&self) -> PathBuf {
        self.root.join("network.json")
    }

    fn direct_bypass_enabled(&self) -> bool {
        self.root.join(BYPASS).is_file() || self.root.join(LEGACY_BYPASS).is_file()
    }

    fn snapshot(&self) -> Snapshot {
        self.shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }

    pub fn status(&self) -> Value {
        self.status_with(|| self.profile_status(), || self.cached_qos_mode(crate::router::read_smart_qos_mode))
    }

    fn cached_qos_mode(&self, read: impl FnOnce() -> Option<String>) -> Option<String> {
        let mut cache = self.qos_mode_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((_, mode)) = cache.as_ref().filter(|(at, _)| at.elapsed() < QOS_MODE_TTL) {
            return mode.clone();
        }
        let mode = read();
        *cache = Some((Instant::now(), mode.clone()));
        mode
    }

    fn status_with(&self, profiles: impl FnOnce() -> Result<Value, String>, qos_mode: impl FnOnce() -> Option<String>) -> Value {
        let installed = self.root.join("mihomo").is_file();
        let configured = profiles().ok().is_some_and(|p| p["selected"].is_string());
        let journal = self.journal().exists();
        let s = self.snapshot();
        let running = s.running();
        let kernel = s.bypass.as_ref().filter(|_| running).map(|bypass| {
            json!({"mode": s.mode.map(routing::Mode::name), "bypass": bypass.label(),
                "returns": match bypass { controller::Bypass::Rules { returns, .. } => Some(*returns), _ => None },
                "reason": match bypass { controller::Bypass::None(reason) | controller::Bypass::Rules { cut: Some(reason), .. } => Some(reason), _ => None },
                "compilation": s.compilation})
        });
        json!({"installed": installed, "configured": configured,
            "running": running, "state": s.phase.name(), "version": VERSION, "dashboard_version": DASHBOARD_VERSION,
            "dashboard": if running { Some(DASHBOARD) } else { None },
            "scope": "lan_tcp_udp_dual_stack_tproxy", "experimental": true, "error": s.error,
            "notice": s.notice.filter(|_| running),
            "reason": s.reason,
            // D3: the core is down and LAN traffic goes direct until a retry works.
            "direct_fallback": s.phase == Phase::Backoff,
            "failures": s.failures,
            "retry_in_s": s.retry_at.map(|at| at.saturating_duration_since(Instant::now()).as_secs()),
            "direct_bypass": self.direct_bypass_enabled(),
            "direct_bypass_active": running && s.bypass.as_ref().is_some_and(|b| !matches!(b, controller::Bypass::None(_))),
            "kernel": kernel, "tables": s.tables, "generation": s.generation,
            "vendor_qos_mode": qos_mode(), "fake_ip_filter": s.dns_filter,
            "autostart": self.wants_restore(), "recovery_required": s.phase == Phase::CleanupPending || (s.phase == Phase::Off && journal),
            "connections_reset": s.last_reset, "connection_resets": crate::netfx::conntrack::history()})
    }

    pub fn running(&self) -> bool {
        self.shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner).running()
    }

    /// How much public LAN IPv4 the core intercepts: `all`, `rules` (what
    /// its DIRECT rules let skip it does not) or `none`.
    pub fn ipv4_share(&self) -> &'static str {
        let s = self.shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !s.running() {
            return "none";
        }
        match s.bypass {
            Some(controller::Bypass::All) => "none",
            Some(controller::Bypass::Rules { .. }) => "rules",
            _ => "all",
        }
    }

    pub fn owns_network(&self) -> bool {
        self.snapshot().phase != Phase::Off || self.journal().exists()
    }

    pub fn secret(&self) -> Option<String> {
        let s = self.shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if s.running() { s.secret.clone() } else { None }
    }

    pub(crate) fn set_tailscale(&self, ts: &Arc<crate::tailscale::TailscaleManager>) {
        let _ = self.tailscale.set(Arc::downgrade(ts));
    }

    pub(crate) fn tailscale_exit(&self) -> TailscaleExitConfig {
        self.tailscale_exit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn set_tailscale_exit(&self, next: TailscaleExitConfig) {
        let changed = {
            let mut guard = self
                .tailscale_exit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *guard == next {
                false
            } else {
                *guard = next;
                true
            }
        };
        if changed {
            if let Some(tx) = self
                .commands
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
            {
                let _ = tx.send(Message::TailscaleExit);
            }
        }
    }

    /// Loopback authenticated HTTP proxy credentials for Tailscale Clean DNS.
    /// Returns `None` whenever Mihomo is off, in D3 backoff, restarting, or in
    /// `Direct` mode so Clean DNS falls back immediately to direct IP-literal DoH.
    pub(crate) fn clean_dns_proxy(&self) -> Option<(String, String, String)> {
        let s = self.shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(s.phase, Phase::Running | Phase::Reloading) {
            return None;
        }
        if s.mode == Some(routing::Mode::Direct) {
            return None;
        }
        let secret = s.secret.clone()?;
        Some((download::PROXY.to_string(), download::USER.to_string(), secret))
    }

    fn notify_tailscale(&self) {
        if let Some(ts) = self.tailscale.get().and_then(Weak::upgrade) {
            ts.mihomo_state_changed();
        }
    }

    pub fn dashboard_root(&self) -> PathBuf {
        self.root.join("ui")
    }

    /// `network-recover`: rolls back what a previous process left.
    pub fn recover(&self) -> Result<(), String> {
        let result = EffectSet::recover(&self.journal());
        self.set_perf_active(false);
        result
    }

    /// Starts the controller and tells it the agent started (it adopts this
    /// boot's interception when the owner wants Mihomo on, else rolls back
    /// what a previous process left). `local` is the management name. A
    /// fresh start waits for `restore`, which `main` calls once the vendor
    /// boot sync released and the relay's journals were rolled back
    /// (section 5.2): started earlier, it ran without an uplink and
    /// restarted when the relay came up, or used up its first retries. A
    /// panic on the controller's thread ends the agent (`supervised`).
    pub fn start(self: &Arc<Self>, local: String) {
        let (tx, rx) = mpsc::channel();
        let port = DevicePort::new(Arc::clone(self), local);
        let controller = controller::Controller::new(port, rx, tx.clone(), Arc::clone(&self.shared), controller::Timings::default());
        crate::system::spawn_named("mihomo", move || {
            controller.supervised(|why| {
                crate::netlog!("[mihomo] the controller thread panicked ({why}); ending the agent so that its guard starts it again and it adopts the interception");
                std::process::abort();
            });
        });
        let _ = tx.send(Message::Boot);
        watch_guard(tx.clone());
        *self.commands.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(tx);
    }

    fn send(&self, message: Message) -> Result<(), String> {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .ok_or("Mihomo's controller is not running")?
            .send(message)
            .map_err(|_| "Mihomo's controller stopped".into())
    }

    /// Sends a command and waits for its result (blocking pool only).
    fn command(&self, make: impl FnOnce(controller::Reply) -> Message) -> Result<(), String> {
        let (reply, answer) = mpsc::sync_channel(1);
        self.send(make(reply))?;
        answer.recv_timeout(COMMAND_WAIT).map_err(|_| "Mihomo is still busy; check its status".to_owned())?
    }

    pub fn install(&self) -> Result<(), String> {
        self.install_from(|url, sha, max| self.download(url, sha, max))
    }

    fn install_from(&self, mut download: impl FnMut(&str, &str, u64) -> Result<Vec<u8>, String>) -> Result<(), String> {
        let _profiles = self
            .profile_operation
            .try_lock()
            .map_err(|_| "A profile operation is in progress")?;
        // Downloads must not park the relay watchdog behind the network lock.
        let _operation = self
            .operation
            .try_lock()
            .map_err(|_| "A Mihomo operation is in progress")?;
        if self.snapshot().phase != Phase::Off {
            return Err("Turn off Mihomo before installing".into());
        }
        *self
            .validated_config
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Vec::new();
        remember_validation(&self.root, &[]);
        net::private_dir(&self.root)?;
        let core = download(CORE_URL, CORE_SHA, 32 * 1024 * 1024)?;
        let mut binary = Vec::new();
        flate2::read::GzDecoder::new(core.as_slice())
            .take(100 * 1024 * 1024 + 1)
            .read_to_end(&mut binary)
            .map_err(|_| "Cannot decompress Mihomo")?;
        if binary.len() > 100 * 1024 * 1024 || !binary.starts_with(b"\x7fELF") {
            return Err("Invalid Mihomo binary".into());
        }
        let ui = download(UI_URL, UI_SHA, 8 * 1024 * 1024)?;
        let core_license = download(
            "https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.33/LICENSE",
            "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
            64 * 1024,
        )?;
        let ui_license = download(
            "https://raw.githubusercontent.com/Zephyruso/zashboard/v3.29.1/LICENSE",
            "ffc390eec51f16b58506b1a42c99fe0cd9ffea1e3081aab443100fd8c20182d9",
            8 * 1024,
        )?;
        net::write_private(&self.root.join("LICENSE-Mihomo-GPL-3.0.txt"), &core_license)?;
        net::write_private(&self.root.join("LICENSE-Zashboard-MIT.txt"), &ui_license)?;
        net::write_private(&self.root.join("SOURCES.txt"), b"Mihomo v1.19.33 (GPL-3.0): https://github.com/MetaCubeX/mihomo/tree/v1.19.33\nZashboard v3.29.1 (MIT): https://github.com/Zephyruso/zashboard/tree/v3.29.1\n")?;
        let stage = self.root.join("ui.new");
        if stage.exists() {
            fs::remove_dir_all(&stage).map_err(|e| e.to_string())?;
        }
        extract_ui(&ui, &stage)?;
        let ui_path = self.root.join("ui");
        let old = self.root.join("ui.previous");
        if old.exists() {
            fs::remove_dir_all(&old).map_err(|e| e.to_string())?;
        }
        if ui_path.exists() {
            fs::rename(&ui_path, &old).map_err(|e| e.to_string())?;
        }
        if let Err(e) = fs::rename(&stage, &ui_path) {
            let _ = fs::rename(&old, &ui_path);
            return Err(e.to_string());
        }
        net::write_private(&self.root.join("mihomo"), &binary)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(self.root.join("mihomo"), fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn configure(&self, source: &str) -> Result<(), String> {
        if self.running() {
            return Err("Turn off Mihomo before replacing its configuration".into());
        }
        self.profiles_change(profiles::Request {
            action: "replace-current".into(),
            id: String::new(),
            name: "Pasted configuration".into(),
            url: String::new(),
            yaml: source.into(),
            interval_hours: 0,
            extensions: transform::Extensions::default(),
            source_type: String::new(),
        })
    }

    fn validate_candidate(&self, file: &str, config: &str, secret: &str, assets: &[geodata::Asset], serving: bool) -> Result<(), String> {
        geodata::prepare_assets(&self.root, assets, &self.downloader())?;
        let fingerprint = self.validation_fingerprint(config, secret, assets);
        let reused = fingerprint.as_ref().is_some_and(|key| self.validated_config.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains(key));
        if reused {
            crate::netlog!("[mihomo] validation reused");
        } else {
            net::write_private(&self.root.join(file), config.as_bytes())?;
            let checked = self.check_with(file, serving);
            let _ = fs::remove_file(self.root.join(file));
            checked?;
            // Only dependencies that stayed the same across the check passed it.
            let after = self.validation_fingerprint(config, secret, assets);
            if let Some(key) = fingerprint.filter(|key| after.as_ref() == Some(key)) {
                let mut validated = self.validated_config.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                validated.retain(|k| *k != key);
                validated.insert(0, key);
                validated.truncate(VALIDATIONS_KEPT);
                remember_validation(&self.root, &validated);
            }
        }
        Ok(())
    }

    fn validation_fingerprint(&self, config: &str, secret: &str, assets: &[geodata::Asset]) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        let core = fs::metadata(self.root.join("mihomo")).ok()?;
        let dependencies = geodata::inputs(&self.root, assets, &self.digests)?;
        Some(format!(
            "{}:{dependencies}:{}:{}:{}:{}:{}",
            config_fingerprint(config, secret),
            core.dev(),
            core.ino(),
            core.len(),
            core.mtime(),
            core.mtime_nsec()
        ))
    }

    /// `background` keeps a validation that runs beside a live core (profile
    /// refresh, a profile change before the restart) from competing with
    /// forwarding: one Go execution slot, a soft memory limit for the Go
    /// runtime, and a lower scheduling priority.
    fn check_with(&self, name: &str, background: bool) -> Result<(), String> {
        let started = Instant::now();
        let result = net::run(self.validation_command(name, background), Duration::from_secs(30));
        let outcome = match &result {
            Ok(_) => "ok",
            Err(error) if error == "Device tool timed out" => "timeout",
            Err(_) => "rejected",
        };
        crate::netlog!(
            "[mihomo] validation background={background} elapsed_ms={} outcome={outcome}",
            started.elapsed().as_millis()
        );
        result.map(|_| ())
            .map_err(|error| {
                if error == "Device tool timed out" {
                    "Mihomo validation timed out; a provider or rule database may be unavailable. Check Internet access and retry; the saved configuration is unchanged".into()
                } else {
                    "Mihomo could not validate the configuration; check YAML, nodes, providers and rule databases".into()
                }
            })
    }

    fn validation_command(&self, name: &str, background: bool) -> Command {
        let mut c = Command::new(self.root.join("mihomo"));
        c.env("SKIP_SYSTEM_IPV6_CHECK", "true");
        if background {
            use std::os::unix::process::CommandExt;
            c.env("GOMAXPROCS", "1").env("GOMEMLIMIT", "128MiB");
            // SAFETY: only the async-signal-safe setpriority(2) runs before exec.
            unsafe {
                c.pre_exec(|| {
                    libc::setpriority(libc::PRIO_PROCESS as _, 0, 10);
                    Ok(())
                });
            }
        }
        c.args(["-t", "-d"])
            .arg(&self.root)
            .arg("-f")
            .arg(self.root.join(name));
        c
    }

    fn core_command(&self) -> Command {
        let mut command = Command::new(self.root.join("mihomo"));
        // The core listens on IPv6 even if only link-local addresses exist.
        command.env("SKIP_SYSTEM_IPV6_CHECK", "true").env("GOMEMLIMIT", "256MiB");
        command.arg("-d").arg(&self.root).arg("-f").arg(self.root.join("config.yaml"));
        command
    }

    /// The owner turns Mihomo on.
    pub fn enable(&self, local_name: &str) -> Result<(), String> {
        self.command(|reply| Message::Enable { local: local_name.into(), owner: true, reply: Some(reply) })
    }

    pub fn wants_restore(&self) -> bool {
        self.root.join(WANTED).is_file()
    }

    fn set_wanted(&self, on: bool) -> Result<(), String> {
        if on {
            return net::write_private(&self.root.join(WANTED), b"1");
        }
        match std::fs::remove_file(self.root.join(WANTED)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err("Cannot clear Mihomo's restart setting".into()),
            _ => Ok(()),
        }
    }

    /// After the agent starts: turn Mihomo on again if the owner left it on
    /// (an update, a crash or a reboot), retrying (D2) while that holds.
    /// Call after the relay's recovery, or the core would bind to a stale
    /// relay route. In D3 it retries at once rather than at the next step.
    pub fn restore(&self, local_name: &str) {
        if !self.wants_restore() {
            return;
        }
        let result = self.command(|reply| Message::Enable { local: local_name.into(), owner: false, reply: Some(reply) });
        let s = self.snapshot();
        let retry = s.retry_at.map_or_else(|| "no retry is scheduled".to_owned(), |at| format!("next retry in {} s", at.saturating_duration_since(Instant::now()).as_secs()));
        match (result, s.phase) {
            (Ok(()), Phase::Running) => crate::netlog!("[mihomo] restore: running generation={}", s.generation),
            (Ok(()), phase) => crate::netlog!("[mihomo] restore: {} ({retry})", phase.name()),
            (Err(e), phase) => crate::netlog!("[mihomo] restore did not start the core: {e}; state={} ({retry})", phase.name()),
        }
    }

    pub fn disable(&self) -> Result<(), String> {
        self.command(|reply| Message::Disable { reply: Some(reply) })
    }

    /// Owner choice: what the rules send DIRECT by address may bypass the
    /// core in the kernel (`routing`). DNS changes with it (`Routes::dns`).
    pub fn set_direct_bypass(&self, enabled: bool) -> Result<(), String> {
        let flag = self.root.join(BYPASS);
        let legacy = self.root.join(LEGACY_BYPASS);
        if enabled {
            net::write_private(&flag, b"1")?;
            let _ = fs::remove_file(&legacy);
        } else {
            for path in [&flag, &legacy] {
                match fs::remove_file(path) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        return Err("Cannot clear the DIRECT bypass setting".into())
                    }
                    _ => {}
                }
            }
        }
        crate::events::touch(crate::events::Topic::Mihomo);
        if self.snapshot().phase == Phase::Off {
            return Ok(());
        }
        self.command(|reply| Message::Bypass { reply })
    }

    /// The selected profile changed; refreshes reload a healthy core.
    fn config_changed(&self, refresh: bool, compiled: &str) -> Result<(), String> {
        if matches!(self.snapshot().phase, Phase::Off | Phase::CleanupPending) {
            return self.validate_profile(compiled);
        }
        self.command(|reply| Message::Config { refresh, reply })
    }

    /// A routing write from the console, ordered with every switch.
    fn routing_write(&self, write: controller::Write) -> Answered {
        let (tx, rx) = mpsc::sync_channel(1);
        self.send(Message::Write { write, answer: controller::Answer::Sync(tx) })?;
        rx.recv_timeout(COMMAND_WAIT).map_err(|_| "Mihomo is still busy; retry".to_owned())?
    }

    /// The same from the dashboard bridge, on the runtime thread: awaited.
    async fn routing_write_async(&self, write: controller::Write) -> Answered {
        #[cfg(test)]
        if self.commands.lock().unwrap().is_none() {
            // `for_bridge_at`: no controller; the write reaches the core as is.
            let secret = self.secret().ok_or("Mihomo is off")?;
            let addr = self.bridge_addr().to_owned();
            return tokio::task::spawn_blocking(move || control::raw_call(&addr, &secret, write.method, &write.segments, &write.body, Duration::from_secs(5)))
                .await
                .map_err(|_| "The bridge test write failed".to_owned())?;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.send(Message::Write { write, answer: controller::Answer::Async(tx) })?;
        rx.await.map_err(|_| "Mihomo's controller stopped".to_owned())?
    }

    /// Whether a routing write would be taken now (Running): the bridge
    /// answers 503 during a restart instead of queueing behind it.
    fn accepts_writes(&self) -> bool {
        self.shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner).phase == Phase::Running
    }

    /// The relay changed its routes. Never blocks the relay (I2).
    pub(crate) fn uplink_changed(&self) {
        self.egress_generation.fetch_add(1, Ordering::Release);
        let _ = self.send(Message::Egress);
    }
}

fn watch_guard(sender: Sender<Message>) {
    let guard = Mutex::new(sender);
    crate::net_guard::on_settled(move || {
        let _ = guard.lock().unwrap_or_else(std::sync::PoisonError::into_inner).send(Message::Guard);
    });
}

/// The controller's device side: the core's files and process, the network
/// effects, the controller API, conntrack and the egress.
struct DevicePort {
    m: Arc<Mihomo>,
    local: String,
    lan: Option<std::net::Ipv4Addr>,
    effects: Option<EffectSet>,
    guard: crate::net_guard::Cursor,
    /// Rule-set files the current LAN and Tailscale plans read.
    lan_sources: Vec<routing::Source>,
    ts_sources: Vec<routing::Source>,
    sources: Vec<routing::Source>,
    /// True when LAN and Tailscale compiled from different content digests for
    /// the same provider path within one planning pass (forcing a consistent
    /// recompile of both chains on the next check).
    sources_diverged: bool,
}

impl DevicePort {
    fn new(m: Arc<Mihomo>, local: String) -> Self {
        Self {
            m,
            local,
            lan: None,
            effects: None,
            guard: crate::net_guard::Cursor::default(),
            lan_sources: Vec::new(),
            ts_sources: Vec::new(),
            sources: Vec::new(),
            sources_diverged: false,
        }
    }

    fn rebuild_sources(&mut self) {
        let (merged, diverged) = merge_sources(&self.lan_sources, &self.ts_sources);
        self.sources = merged;
        self.sources_diverged = diverged;
    }

    fn owned_tables(&self) -> NftTables {
        NftTables::new("mihomo", NFT_TABLE, self.m.root.join(NFT_FILE))
    }

    fn table(&self, families: Option<[String; 2]>) -> Resource {
        Resource::NftTable(NftTable { owner: "mihomo", name: NFT_TABLE, file: self.m.root.join(NFT_FILE), families })
    }

    fn reconcile_effects(&mut self, reconcile: impl FnOnce(&mut EffectSet) -> net::Reconciled) -> controller::Guarded {
        let Some(effects) = self.effects.as_mut() else {
            return controller::Guarded { result: Ok(()), confirmed: false, confirmed_generation: None };
        };
        let result = reconcile(effects);
        let confirmed = effects.tables_confirmed(NFT_TABLE);
        let confirmed_generation = effects.tables_confirmed_generation(NFT_TABLE);
        self.guard.after(&result);
        controller::Guarded { result: crate::net_guard::report("mihomo", result), confirmed, confirmed_generation }
    }
}

impl controller::Port for DevicePort {
    fn adoptable(&mut self) -> bool {
        EffectSet::current(&self.m.journal()) && self.owned_tables().presence(&mut effect::Device).is_ok_and(|p| p == Presence::Ours)
    }

    fn recover(&mut self) -> Result<(), String> {
        self.effects = None;
        self.m.recover()
    }

    fn busy(&mut self) -> Option<String> {
        self.m.operation.try_lock().is_err().then(|| "A Mihomo operation is in progress".into())
    }

    fn prepare(&mut self, source: &Source, _serving: bool, egress: egress::Binding) -> Result<Prepared, String> {
        let m = &self.m;
        let prepared = match source {
            Source::Previous(previous) => {
                let mut prepared = (**previous).clone();
                if prepared.egress.interface() != egress.interface() {
                    let mut config: Yaml = serde_yaml_ng::from_str(&prepared.config).map_err(|_| "Invalid managed configuration")?;
                    bind_egress(&mut config, &egress);
                    prepared.facts = reload::Facts::from(&config);
                    prepared.config = serde_yaml_ng::to_string(&config).map_err(|_| "Cannot encode managed configuration")?;
                }
                prepared.egress = egress;
                prepared
            }
            Source::Reload(previous) | Source::Refresh(previous) => {
                let lan = lan_address()?;
                self.lan = Some(lan);
                let refresh = matches!(source, Source::Refresh(_));
                let bypass = if refresh { previous.bypass } else { m.direct_bypass_enabled() };
                let tailscale_sniffer = m.tailscale_exit().sniffer;
                let source = if refresh { m.selected_source()? } else { previous.source.clone() };
                let (mut config, (routes, dns)) = managed_mapping(&source, &previous.secret, Some((&previous.local, lan)), bypass, tailscale_sniffer)?;
                let running = &previous.facts.runtime;
                let map = config.as_mapping_mut().ok_or("Mihomo YAML must be a mapping")?;
                for key in ["interface-name", "mode", "log-level"] {
                    match running.get(key) {
                        Some(value) => drop(map.insert(Yaml::from(key), value.clone())),
                        None => drop(map.remove(Yaml::from(key))),
                    }
                }
                for key in ["mode", "log-level"] {
                    if let Some(value) = previous.runtime[key].as_str() {
                        map.insert(Yaml::from(key), Yaml::from(value));
                    }
                }
                let facts = reload::Facts::from(&config);
                let config = serde_yaml_ng::to_string(&config).map_err(|_| "Cannot encode managed configuration")?;
                let notice = geodata::notice(&facts.assets, bypass);
                Prepared { secret: previous.secret.clone(), local: previous.local.clone(), runtime: previous.runtime.clone(), routes, dns, bypass, tailscale_sniffer, notice, source, config, facts, egress }
            }
            Source::Selected { local, runtime } => {
                let local = if local.is_empty() { self.local.clone() } else { local.clone() };
                let source = m.selected_source()?;
                let mut random = [0u8; 32];
                getrandom::getrandom(&mut random).map_err(|_| "Random secret unavailable")?;
                let secret = crate::common::hex_lower(&random);
                let lan = lan_address()?;
                self.lan = Some(lan);
                let bypass = m.direct_bypass_enabled();
                let tailscale_sniffer = m.tailscale_exit().sniffer;
                let (mut config, (routes, dns)) = managed_mapping(&source, &secret, Some((&local, lan)), bypass, tailscale_sniffer)?;
                bind_egress(&mut config, &egress);
                // Always written, so a first start and a restart with the same
                // settings give the same text (the validation is reused).
                for (key, default) in [("mode", "rule"), ("log-level", "info")] {
                    let value = runtime.as_ref().and_then(|r| r[key].as_str()).or_else(|| config[key].as_str()).unwrap_or(default).to_owned();
                    config.as_mapping_mut().unwrap().insert(Yaml::from(key), Yaml::from(value));
                }
                let runtime = json!({"mode": config["mode"].as_str().unwrap_or("rule"), "log-level": config["log-level"].as_str().unwrap_or("info")});
                let facts = reload::Facts::from(&config);
                let config = serde_yaml_ng::to_string(&config).map_err(|_| "Cannot encode managed configuration")?;
                let notice = geodata::notice(&facts.assets, bypass);
                Prepared { secret, local, runtime, routes, dns, bypass, tailscale_sniffer, notice, source, config, facts, egress }
            }
        };
        if self.lan.is_none() {
            self.lan = Some(lan_address()?);
        }
        Ok(prepared)
    }

    fn validator(&self, prepared: &Prepared, serving: bool) -> Option<controller::Validation> {
        let m = Arc::clone(&self.m);
        let config = prepared.config.clone();
        let secret = prepared.secret.clone();
        let assets = prepared.facts.assets.clone();
        Some(Box::new(move || m.validate_candidate("candidate.yaml", &config, &secret, &assets, serving)))
    }

    fn ports_free(&mut self) -> Result<(), String> {
        dns::available(ids::DNS_PORT)?;
        drop(std::net::TcpListener::bind(download::PROXY).map_err(|_| "Mihomo's private download proxy port is occupied")?);
        // A taken port would fail silently in the core: check it here.
        let wildcard = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, TPROXY_PORT));
        if std::net::TcpListener::bind(wildcard).is_err() || std::net::UdpSocket::bind(wildcard).is_err() {
            return Err("Mihomo's transparent proxy port is occupied".into());
        }
        Ok(())
    }

    fn owns(&mut self) -> bool {
        self.effects.is_some()
    }

    fn engage(&mut self, how: Engage) -> Result<(), String> {
        match how {
            Engage::Fresh => {
                let tables = self.owned_tables();
                match tables.presence(&mut effect::Device)? {
                    Presence::Absent => {}
                    Presence::Ours => return Err("Mihomo's nftables tables are left from before; turn Mihomo off to clean them up".into()),
                    Presence::Foreign => return Err("Another program uses Mihomo's nftables table names; nothing was changed".into()),
                }
                if fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default().trim() != "1" {
                    return Err("IPv4 forwarding must already be enabled by the router".into());
                }
                // The tables' undo goes last in the journal, so it runs
                // first: interception stops before routes and settings go.
                let mut resources = proxy_resources();
                resources.push(self.table(None));
                let mut effects = EffectSet::new("mihomo", self.m.journal());
                if let Err(error) = effects.declare(resources) {
                    if let Err(cleanup) = effects.release() {
                        self.effects = Some(effects);
                        return Err(cleanup);
                    }
                    return Err(error);
                }
                self.effects = Some(effects);
                self.m.set_perf_active(true);
                Ok(())
            }
            Engage::FromBackoff => {
                let effects = self.effects.as_mut().ok_or("Mihomo owns nothing to start from")?;
                effects.declare(proxy_resources())?;
                self.m.set_perf_active(true);
                Ok(())
            }
            Engage::Adopt => {
                let mut resources = proxy_resources();
                resources.push(self.table(None));
                let mut effects = EffectSet::load("mihomo", &self.m.journal())?;
                effects.retire_legacy_commands(|undo| {
                    undo.program == "@u60-sysctl"
                        && undo.args.first().is_some_and(|key| {
                            matches!(key.as_str(), "tcp_pacing_ss_ratio" | "tcp_pacing_ca_ratio")
                        })
                })?;
                effects.declare(resources)?;
                effects.retire_legacy_commands(|undo| {
                    undo.program == "ip"
                        && undo.args.windows(2).any(|w| w == ["pref", ids::LEGACY_MIHOMO_PREF])
                })?;
                self.effects = Some(effects);
                self.m.set_perf_active(true);
                Ok(())
            }
        }
    }

    fn tables(&mut self, shape: intercept::Shape) -> Result<(), String> {
        self.tables_with_tailscale(shape, intercept::TailscaleExit::default())
    }

    fn tables_with_tailscale(&mut self, shape: intercept::Shape, ts: intercept::TailscaleExit) -> Result<(), String> {
        let table = self.table(Some(intercept::tables_with_tailscale(shape, ts)));
        let effects = self.effects.as_mut().ok_or("Mihomo owns no tables")?;
        effects.declare(vec![table])
    }

    fn tables_status(&mut self) -> Value {
        self.effects.as_ref().map_or(Value::Null, |effects| effects.tables_status(NFT_TABLE))
    }

    fn tables_target_generation(&mut self) -> Option<u64> {
        self.effects.as_ref().and_then(|effects| effects.tables_target_generation(NFT_TABLE))
    }

    fn direct(&mut self) -> Result<(), String> {
        let table = self.table(Some(intercept::tables(intercept::Shape::FakeReject)));
        let result = self.effects.as_mut().map_or(Ok(()), |effects| {
            effects.declare(vec![table])?;
            effects.withdraw(&proxy_resources().iter().map(Resource::key).collect::<Vec<_>>())
        });
        self.m.set_perf_active(false);
        result
    }

    fn release_all(&mut self) -> Result<(), String> {
        match self.effects.as_mut() {
            Some(effects) => {
                let result = effects.release();
                if result.is_ok() {
                    self.effects = None;
                }
                self.m.set_perf_active(false);
                result
            }
            None => self.m.recover(),
        }
    }

    fn spawn(&mut self, generation: u64, prepared: &Prepared, exits: Sender<Message>) -> Result<Box<dyn controller::CoreHandle>, String> {
        net::write_private(&self.m.root.join("config.yaml"), prepared.config.as_bytes())?;
        let core = core::Core::spawn(self.m.core_command(), generation, move |generation, how| {
            let _ = exits.send(Message::Exited { generation, how });
        })?;
        Ok(Box::new(core))
    }

    fn ready(&mut self, prepared: &Prepared) -> bool {
        let Some(lan) = self.lan else { return false };
        core_ready(&prepared.secret) && download::ready() && listening(TPROXY_PORT) && dns::ready(&prepared.local, lan, ids::DNS_PORT)
    }

    fn verify_routing(&mut self) -> Result<(), String> {
        for (family, destination) in [("-4", "1.1.1.1"), ("-6", "2606:4700:4700::1111")] {
            let route = Cmd::new("ip", &[family, "route", "get", destination, "mark", "0x700"]).run()?;
            if !route.trim_start().starts_with("local") {
                return Err("Firmware policy routing did not deliver proxied traffic locally".into());
            }
        }
        Ok(())
    }

    fn read_back(&mut self, secret: &str) -> Option<(routing::Mode, routing::Selected, Value)> {
        let configs = controller_get(secret, "/configs").filter(valid_runtime)?;
        let selected = controller_get(secret, "/proxies").and_then(|l| routing::selected_from(&l))?;
        let mode = routing::Mode::parse(configs["mode"].as_str().unwrap_or("rule"));
        Some((mode, selected, json!({"mode": configs["mode"], "log-level": configs["log-level"]})))
    }

    fn plan(&mut self, routes: &routing::Routes, bypass: bool, mode: routing::Mode, selected: &routing::Selected, unsettled: &[String]) -> (controller::Bypass, routing::Chain) {
        use controller::Bypass;
        // Every caller invokes `plan()` before an optional `plan_tailscale()`.
        // Reset Tailscale sources here so disabling Tailscale or switching modes
        // drops stale provider observations cleanly.
        self.ts_sources.clear();
        let none = |why: String| (Bypass::None(why), routing::Chain::default());
        if !bypass {
            self.lan_sources.clear();
            self.rebuild_sources();
            return none("Bypass for DIRECT rules is off".into());
        }
        match mode {
            routing::Mode::Global => {
                self.lan_sources.clear();
                self.rebuild_sources();
                none("Global mode sends everything through the proxy".into())
            }
            routing::Mode::Direct => {
                self.lan_sources.clear();
                self.rebuild_sources();
                (Bypass::All, routing::Chain::all())
            }
            routing::Mode::Rule => {
                let compiled = routes.compile(selected, &self.m.root, unsettled);
                let lists = self.m.geoip.get(&self.m.root, &compiled.geoip);
                let chain = compiled.render(&|code| match &lists {
                    Ok(lists) => lists.get(code).map(Vec::as_slice).ok_or_else(|| "not in GeoIP.dat".to_owned()),
                    Err(e) => Err(e.clone()),
                });
                self.lan_sources = compiled.sources;
                self.rebuild_sources();
                if chain.returns == 0 {
                    let reason = chain.cut.clone().unwrap_or_else(|| "No rule sends IPv4 DIRECT by address".into());
                    return (Bypass::None(reason), routing::Chain {
                        cut: chain.cut,
                        skipped_direct_alternatives: chain.skipped_direct_alternatives,
                        ..routing::Chain::default()
                    });
                }
                (Bypass::Rules { returns: chain.returns, cut: chain.cut.clone() }, chain)
            }
        }
    }

    fn plan_tailscale(&mut self, routes: &routing::Routes, mode: routing::Mode, selected: &routing::Selected, unsettled: &[String]) -> routing::Chain {
        match mode {
            routing::Mode::Global => {
                self.ts_sources.clear();
                self.rebuild_sources();
                routing::Chain::default()
            }
            routing::Mode::Direct => {
                self.ts_sources.clear();
                self.rebuild_sources();
                routing::Chain::all()
            }
            routing::Mode::Rule => {
                let compiled = routes.compile_tailscale(selected, &self.m.root, unsettled);
                let lists = self.m.geoip.get(&self.m.root, &compiled.geoip);
                let chain = compiled.render_with_prefix(&|code| match &lists {
                    Ok(lists) => lists.get(code).map(Vec::as_slice).ok_or_else(|| "not in GeoIP.dat".to_owned()),
                    Err(e) => Err(e.clone()),
                }, "ts_ip_");
                self.ts_sources = compiled.sources;
                self.rebuild_sources();
                if chain.returns == 0 {
                    return routing::Chain {
                        cut: chain.cut,
                        skipped_direct_alternatives: chain.skipped_direct_alternatives,
                        ..routing::Chain::default()
                    };
                }
                chain
            }
        }
    }

    fn tailscale_exit(&mut self) -> TailscaleExitConfig {
        self.m.tailscale_exit()
    }

    fn reset(&mut self, reason: &'static str, scope: crate::netfx::conntrack::Scope, changed: Instant) -> Result<crate::netfx::conntrack::Report, String> {
        crate::netfx::conntrack::reset_since(reason, scope, changed)
    }

    fn reset_tailscale(&mut self, reason: &'static str, v4: bool, v6: bool) -> Result<(), String> {
        crate::netfx::conntrack::reset_mark(reason, ids::TAILSCALE_CT_MARK, ids::TAILSCALE_CT_MARK, v4, v6).map(|_| ())
    }

    fn tailscale_reset_pending(&mut self) -> (bool, bool) {
        crate::netfx::conntrack::pending_mark_families(ids::TAILSCALE_CT_MARK, ids::TAILSCALE_CT_MARK)
    }

    fn tailscale_v4_reset_started(&mut self) -> Option<Instant> {
        crate::netfx::conntrack::mark_v4_completed_at(ids::TAILSCALE_CT_MARK, ids::TAILSCALE_CT_MARK)
    }

    fn on_state_change(&mut self) {
        self.m.notify_tailscale();
    }

    fn write(&mut self, secret: &str, write: &controller::Write) -> Answered {
        control::raw_call(CONTROLLER, secret, write.method, &write.segments, &write.body, Duration::from_secs(30))
    }

    fn reload(&mut self, secret: &str, config: &str) -> Result<u16, String> {
        net::write_private(&self.m.root.join("config.yaml"), config.as_bytes())?;
        let agent = control::new_agent(Some(Duration::from_secs(15)), false);
        let addr = self.m.bridge_addr();
        agent
            .put(&format!("http://{addr}/configs?force=false"))
            .header("Authorization", &format!("Bearer {secret}"))
            .send_json(json!({"payload": config}))
            .map(|r| r.status().as_u16())
            .map_err(|_| "Mihomo did not answer the reload".to_owned())
    }

    fn verify_reload(&mut self, prepared: &Prepared, probe: Option<&(String, bool)>, before: &routing::Selected) -> Result<(), String> {
        let secret = &prepared.secret;
        let (configs, proxies, providers) = (controller_get(secret, "/configs"), controller_get(secret, "/proxies"), controller_get(secret, "/providers/rules"));
        reload_findings(prepared, configs.as_ref(), proxies.as_ref(), providers.as_ref(), before)?;
        if !download::ready() || !listening(TPROXY_PORT) {
            return Err("a listener is down".into());
        }
        if let Some((name, fake)) = probe {
            let answer = dns::first_address(name, ids::DNS_PORT)?;
            let is_fake = answer.is_some_and(|ip| routing::FAKE_NET.parse::<ipnet::Ipv4Net>().is_ok_and(|net| net.contains(&ip)));
            if is_fake != *fake {
                return Err("the DNS probe still answers as before the reload".into());
            }
        }
        Ok(())
    }

    fn uplink(&mut self, upstream: bool) -> egress::Uplink {
        egress::Uplink::observe(upstream)
    }

    fn egress_generation(&self) -> u64 {
        self.m.egress_generation.load(Ordering::Acquire)
    }

    fn reconcile(&mut self) -> controller::Guarded {
        self.reconcile_effects(EffectSet::reconcile)
    }

    fn wanted(&mut self) -> bool {
        self.m.wants_restore()
    }

    fn set_wanted(&mut self, on: bool) -> Result<(), String> {
        self.m.set_wanted(on)
    }

    fn sources_changed(&mut self) -> bool {
        let disk_changed = self.sources.iter_mut().any(routing::Source::changed);
        self.sources_diverged || disk_changed
    }

    fn guard_due(&mut self) -> bool {
        self.guard.due()
    }

    fn retry_reset(&mut self) {
        if let Some(Err(e)) = crate::netfx::conntrack::retry() {
            crate::netlog!("[mihomo] connection reset retry failed: {e}");
        }
    }
}

fn merge_sources(lan: &[routing::Source], ts: &[routing::Source]) -> (Vec<routing::Source>, bool) {
    let mut merged: Vec<routing::Source> = Vec::with_capacity(lan.len() + ts.len());
    let mut diverged = false;
    for src in lan.iter().chain(ts.iter()) {
        if let Some(existing) = merged.iter_mut().find(|item| item.path() == src.path()) {
            if !existing.same_content(src) {
                diverged = true;
            }
            *existing = src.clone();
        } else {
            merged.push(src.clone());
        }
    }
    (merged, diverged)
}

impl controller::CoreHandle for core::Core {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn stop(&self) -> bool {
        core::Core::stop(self, Duration::from_secs(3))
    }
}

/// What the core reports after a reload against what it should run
/// (section 5.5): mode and egress interface as configured, every group's
/// choice as before (none fell back to `COMPATIBLE`, which acts as direct),
/// every configured rule set present.
fn reload_findings(prepared: &Prepared, configs: Option<&Value>, proxies: Option<&Value>, providers: Option<&Value>, before: &routing::Selected) -> Result<(), String> {
    let configs = configs.ok_or("Mihomo did not report its settings")?;
    let facts = &prepared.facts;
    if configs["mode"].as_str() != prepared.runtime["mode"].as_str() {
        return Err(format!("the mode is {}", configs["mode"]));
    }
    if configs["interface-name"].as_str().unwrap_or("") != facts.runtime["interface-name"].as_str().unwrap_or("") {
        return Err("the egress interface changed".into());
    }
    if prepared.tailscale_sniffer {
        if configs["sniffing"].as_bool() != Some(true) {
            return Err("Mihomo did not enable sniffer".into());
        }
    } else if let Some(sniffing) = configs.get("sniffing").and_then(Value::as_bool) {
        if sniffing != facts.sniffing {
            return Err("Mihomo sniffer state did not match configuration".into());
        }
    }
    let selected = proxies.and_then(routing::selected_from).ok_or("Mihomo did not report its groups")?;
    if selected.iter().any(|(group, now)| now == "COMPATIBLE" && before.get(group).is_none_or(|old| old != "COMPATIBLE")) {
        return Err("a group fell back to COMPATIBLE".into());
    }
    let listing = proxies.ok_or("Mihomo did not report its groups")?;
    for (group, old) in before {
        let Some(current) = selected.get(group) else {
            if facts.groups.iter().any(|(name, _)| name == group) {
                return Err("a configured group is missing".into());
            }
            continue;
        };
        if current != old && listing["proxies"][group]["all"].as_array().is_none_or(|members| members.iter().any(|member| member.as_str() == Some(old))) {
            return Err("a group's choice changed while its previous member still exists".into());
        }
    }
    for (name, selector) in &facts.groups {
        if *selector && !selected.contains_key(name) {
            return Err("a configured selector is missing".into());
        }
    }
    let providers = providers.ok_or("Mihomo did not report its rule sets")?;
    if facts.providers.iter().any(|name| providers["providers"][name]["ruleCount"].as_u64().is_none_or(|count| count == 0)) {
        return Err("a configured rule set is missing or empty".into());
    }
    Ok(())
}

fn lan_address() -> Result<std::net::Ipv4Addr, String> {
    crate::httpd::mobile::interfaces()
        .ok()
        .and_then(|v| {
            v.into_iter().find_map(|i| match i.addr {
                std::net::IpAddr::V4(ip) if i.name == "br-lan" => Some(ip),
                _ => None,
            })
        })
        .ok_or_else(|| "Cannot read the LAN address for the dashboard management name".into())
}

/// Checks UTC over the relay (`network_clock::sync_wifi`: TLS nodes need a
/// trusted clock with cellular off) on a thread of its own, one at a time.
/// A start never waits for it: a failing check took 4–16 s, inside a planned
/// restart's or an adoption's blackout. The agent restored its lower bound
/// at start; a check that passed is reused for 300 s.
fn check_clock() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static CHECKING: AtomicBool = AtomicBool::new(false);
    if CHECKING.swap(true, Ordering::SeqCst) {
        return;
    }
    let spawned = crate::system::try_spawn_named("mihomo-clock", || {
        if let Err(error) = crate::network_clock::sync_wifi() {
            // A captive portal must not tear down working IPv4 relay.
            crate::netlog!("[clock] {error}");
        }
        CHECKING.store(false, Ordering::SeqCst);
    });
    if spawned.is_err() {
        CHECKING.store(false, Ordering::SeqCst);
    }
}

/// The validations' fingerprints (hashes and file identities, nothing
/// secret), newest first, for this boot only.
const VALIDATED: &str = "validated";
/// The relay's and cellular's configurations, and a previous profile.
const VALIDATIONS_KEPT: usize = 4;

fn remember_validation(root: &Path, fingerprints: &[String]) {
    let path = root.join(VALIDATED);
    let _ = if fingerprints.is_empty() {
        fs::remove_file(path).map_err(|e| e.to_string())
    } else {
        net::write_private(&path, format!("{} {}", net::boot_id(), fingerprints.join(" ")).as_bytes())
    };
}

fn remembered_validation(root: &Path) -> Vec<String> {
    let text = fs::read_to_string(root.join(VALIDATED)).unwrap_or_default();
    let mut words = text.split_whitespace();
    match words.next() {
        Some(boot) if boot == net::boot_id() => words.map(str::to_owned).take(VALIDATIONS_KEPT).collect(),
        _ => Vec::new(),
    }
}

/// Identifies a configuration by content with the per-start secret masked
/// and the egress interface (`interface-name`, top level) left out: `mihomo
/// -t` does not bind it, so a relay/cellular switch alone reuses a passed
/// validation (section 5.6).
fn config_fingerprint(config: &str, secret: &str) -> String {
    let mut digest = Sha256::new();
    for line in config.replace(secret, "<secret>").lines().filter(|line| !line.starts_with("interface-name:")) {
        digest.update(line.as_bytes());
        digest.update(b"\n");
    }
    format!("{:x}", digest.finalize())
}

fn valid_runtime(runtime: &Value) -> bool {
    matches!(runtime["mode"].as_str(), Some("rule" | "global" | "direct"))
        && matches!(
            runtime["log-level"].as_str(),
            Some("silent" | "error" | "warning" | "info" | "debug")
        )
}

fn core_ready(secret: &str) -> bool {
    core_ready_at(CONTROLLER, secret)
}

fn core_ready_at(addr: &str, secret: &str) -> bool {
    control::new_agent(Some(Duration::from_millis(300)), true)
        .get(&format!("http://{addr}/version"))
        .header("Authorization", &format!("Bearer {secret}"))
        .call()
        .is_ok()
}

impl Mihomo {
    fn download(&self, url: &str, sha: &str, max: u64) -> Result<Vec<u8>, String> {
        let bytes = self
            .downloader()
            .bytes(url, max, Duration::from_secs(180))?;
        if format!("{:x}", Sha256::digest(&bytes)) != sha {
            return Err("Download SHA256 verification failed".into());
        }
        Ok(bytes)
    }
}

fn extract_ui(data: &[u8], destination: &Path) -> Result<(), String> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(data)).map_err(|_| "Invalid dashboard ZIP")?;
    net::private_dir(destination)?;
    let mut total = 0u64;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|_| "Invalid dashboard ZIP entry")?;
        let path = entry
            .enclosed_name()
            .ok_or("Unsafe dashboard archive path")?;
        let path = path.strip_prefix("dist").unwrap_or(&path);
        if path.as_os_str().is_empty() {
            continue;
        }
        if entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
            return Err("Dashboard symlinks are not allowed".into());
        }
        total += entry.size();
        if total > 32 * 1024 * 1024 {
            return Err("Dashboard archive too large".into());
        }
        let out = destination.join(path);
        if entry.is_dir() {
            fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            continue;
        }
        fs::create_dir_all(out.parent().unwrap()).map_err(|e| e.to_string())?;
        let mut file = File::create(out).map_err(|e| e.to_string())?;
        std::io::copy(&mut entry, &mut file).map_err(|e| e.to_string())?;
    }
    if !destination.join("index.html").is_file() {
        return Err("Dashboard index.html missing".into());
    }
    Ok(())
}

/// Parse rather than concatenate YAML: subscriptions cannot override the
/// controller, run scripts, open extra listeners or install their own routes.
#[cfg(test)]
pub fn managed_config(source: &str, secret: &str) -> Result<String, String> {
    config_with_lan_host(source, secret, None, true).map(|(config, _)| config)
}

#[cfg(test)]
pub fn managed_config_with_tailscale(source: &str, secret: &str, tailscale_sniffer: bool) -> Result<String, String> {
    let (mapping, _) = managed_mapping(source, secret, None, true, tailscale_sniffer)?;
    serde_yaml_ng::to_string(&mapping).map_err(|_| "Cannot encode Mihomo configuration".into())
}

/// The managed configuration and its routing (`routing::Routes`, read
/// before DNS is rewritten), with the DNS filter for the DIRECT bypass
/// setting (`routing::Routes::dns_filter`).
#[cfg(test)]
fn config_with_lan_host(
    source: &str,
    secret: &str,
    local: Option<(&str, std::net::Ipv4Addr)>,
    bypass: bool,
) -> Result<(String, routing::Routes), String> {
    let (mapping, (routes, _)) = managed_mapping(source, secret, local, bypass, false)?;
    let text = serde_yaml_ng::to_string(&mapping).map_err(|_| "Cannot encode Mihomo configuration")?;
    Ok((text, routes))
}

fn managed_mapping(source: &str, secret: &str, local: Option<(&str, std::net::Ipv4Addr)>, bypass: bool, tailscale_sniffer: bool) -> Result<(Yaml, (routing::Routes, routing::DnsFilter)), String> {
    if source.len() > MAX_CONFIG {
        return Err("Configuration exceeds 512 KiB".into());
    }
    let mut root: Yaml = serde_yaml_ng::from_str(source).map_err(|_| "Invalid Mihomo YAML")?;
    let routes = routing::Routes::from(&root);
    let filter = routes.dns_filter(bypass);
    let m = root
        .as_mapping_mut()
        .ok_or("Mihomo YAML must be a mapping")?;
    for section in ["proxies", "proxy-groups"] {
        if let Some(value) = m.get_mut(Yaml::from(section)) {
            clear_egress_overrides(value);
        }
    }
    for k in [
        "listeners",
        "tunnels",
        "external-controller-tls",
        "external-controller-unix",
        "external-controller-pipe",
        "external-ui",
        "external-ui-url",
        "external-ui-name",
        "external-doh-server",
        "interface-name",
        "routing-mark",
        "authentication",
        "script",
        "tun",
        "geox-url",
        "ss-config",
        "vmess-config",
        "tuic-server",
        "external-controller-cors",
    ] {
        m.remove(Yaml::from(k));
    }
    let set = |m: &mut Mapping, k: &str, v: Yaml| {
        m.insert(Yaml::from(k), v);
    };
    for k in ["port", "socks-port", "mixed-port", "redir-port"] {
        set(m, k, Yaml::from(0));
    }
    // M13: the core's sockets carry the verified outbound mark, so the
    // relay's DNS output chain lets its own DNS keep its destination.
    if let Some(mark) = ids::CORE_OUT_MARK {
        set(m, "routing-mark", Yaml::from(mark));
    }
    // The controller refreshes `http` rule sets itself, narrowing what skips
    // the core first (owner choice Q2, `routing::Routes::refresh`): the core
    // never refreshes one behind its back.
    if let Some(providers) = m.get_mut(Yaml::from("rule-providers")).and_then(Yaml::as_mapping_mut) {
        for provider in providers.values_mut().filter_map(Yaml::as_mapping_mut) {
            if provider.get(Yaml::from("type")).and_then(Yaml::as_str).is_some_and(|t| t.eq_ignore_ascii_case("http")) {
                provider.remove(Yaml::from("interval"));
            }
        }
    }
    if let Some(providers) = m.get_mut(Yaml::from("proxy-providers")) {
        let providers = providers
            .as_mapping_mut()
            .ok_or("proxy-providers must be a mapping")?;
        for provider in providers.values_mut() {
            let provider = provider
                .as_mapping_mut()
                .ok_or("Each proxy provider must be a mapping")?;
            if let Some(payload) = provider.get_mut(Yaml::from("payload")) {
                clear_egress_overrides(payload);
            }
            let overrides = provider
                .entry(Yaml::from("override"))
                .or_insert_with(|| Yaml::Mapping(Mapping::new()));
            let overrides = overrides
                .as_mapping_mut()
                .ok_or("Provider override must be a mapping")?;
            // Apply after remote/file node data, so it cannot bind a SIM
            // interface or inject an independent policy mark on later refresh.
            set(overrides, "interface-name", Yaml::from(""));
            set(overrides, "routing-mark", Yaml::from(ids::CORE_OUT_MARK.unwrap_or(0)));
            overrides.remove(Yaml::from("override-expr"));
        }
    }
    set(
        m,
        "listeners",
        serde_yaml_ng::to_value(json!([{
            "name":"u60-download", "type":"http", "listen":"127.0.0.1", "port":17893,
            "users":[{"username":download::USER,"password":secret}]
        }]))
        .unwrap(),
    );
    set(
        m,
        "skip-auth-prefixes",
        serde_yaml_ng::to_value(Vec::<String>::new()).unwrap(),
    );
    set(m, "tproxy-port", Yaml::from(TPROXY_PORT));
    set(m, "allow-lan", Yaml::from(true));
    set(m, "bind-address", Yaml::from("*"));
    set(m, "ipv6", Yaml::from(true));
    set(m, "external-controller", Yaml::from(CONTROLLER));
    set(m, "secret", Yaml::from(secret));
    // TPROXY (the agent's nft tables) instead of a TUN: the core terminates
    // LAN TCP/UDP with kernel sockets at about a third of the TUN's CPU.
    set(
        m,
        "tun",
        serde_yaml_ng::to_value(json!({"enable":false})).unwrap(),
    );
    set(
        m,
        "iptables",
        serde_yaml_ng::to_value(json!({"enable":false})).unwrap(),
    );
    set(
        m,
        "ntp",
        serde_yaml_ng::to_value(json!({"enable":false})).unwrap(),
    );
    set(m, "geo-auto-update", Yaml::from(false));
    set(m, "find-process-mode", Yaml::from("off"));
    if !["keep-alive-idle", "keep-alive-interval", "disable-keep-alive"].iter().any(|key| m.contains_key(Yaml::from(*key))) {
        set(m, "keep-alive-idle", Yaml::from(120));
        set(m, "keep-alive-interval", Yaml::from(30));
    }
    let profile = m
        .entry(Yaml::from("profile"))
        .or_insert_with(|| Yaml::Mapping(Mapping::new()));
    let profile = profile
        .as_mapping_mut()
        .ok_or("profile must be a mapping")?;
    // Group choices survive a restart (the DNS filter follows them), and so
    // do fake addresses, which clients may still hold across one.
    set(profile, "store-selected", Yaml::from(true));
    set(profile, "store-fake-ip", Yaml::from(true));
    if let Some((name, address)) = local {
        let hosts = m
            .entry(Yaml::from("hosts"))
            .or_insert_with(|| Yaml::Mapping(Mapping::new()));
        let hosts = hosts.as_mapping_mut().ok_or("hosts must be a mapping")?;
        set(hosts, name, Yaml::from(address.to_string()));
    }
    let dns = m
        .entry(Yaml::from("dns"))
        .or_insert_with(|| Yaml::Mapping(Mapping::new()));
    let dns = dns.as_mapping_mut().ok_or("dns must be a mapping")?;
    set(dns, "enable", Yaml::from(true));
    set(dns, "listen", Yaml::from("[::]:1053"));
    set(dns, "ipv6", Yaml::from(true));
    set(dns, "use-hosts", Yaml::from(true));
    // Always fake-ip (owner decision 64): a domain a rule sends through a
    // proxy before the last DIRECT address rule gets a fake address, which always reaches the
    // core; the rest keep their real one (`routing`). IPv4 pool only: an
    // IPv6 pool would sit in the ULA range the kernel returns early, and
    // without one such domains answer AAAA empty. A 1 s TTL lets clients
    // recover soon after the core stops.
    set(dns, "enhanced-mode", Yaml::from("fake-ip"));
    set(dns, "fake-ip-range", Yaml::from(routing::FAKE_RANGE));
    dns.remove(Yaml::from("fake-ip-range6"));
    set(dns, "fake-ip-ttl", Yaml::from(1));
    set(dns, "fake-ip-filter-mode", Yaml::from("rule"));
    set(dns, "fake-ip-filter", serde_yaml_ng::to_value(&filter.rules).map_err(|_| "Cannot encode the DNS filter")?);
    if !dns.contains_key(Yaml::from("nameserver")) {
        set(
            dns,
            "nameserver",
            serde_yaml_ng::to_value(["1.1.1.1", "8.8.8.8"]).unwrap(),
        );
    }
    if tailscale_sniffer {
        enable_tailscale_sniffer(m)?;
    }
    validate_dns_routes(&root)?;
    Ok((root, (routes, filter)))
}

/// Auto-enable TLS/HTTP/QUIC pure-IP domain sniffing for Tailscale Strategy B
/// Exit Node traffic while preserving any user-defined sniffer skip lists or
/// protocol port overrides. Crucially forces `override-destination: false` both
/// globally and per-protocol so Mihomo populates `SniffHost` for rule matching
/// WITHOUT clearing `DstIP` (preventing plaintext DNS re-resolution on DIRECT
/// connections after Clean DNS has already resolved the real destination IP).
fn enable_tailscale_sniffer(m: &mut Mapping) -> Result<(), String> {
    let sniffer = m
        .entry(Yaml::from("sniffer"))
        .or_insert_with(|| Yaml::Mapping(Mapping::new()));
    if sniffer.is_null() {
        *sniffer = Yaml::Mapping(Mapping::new());
    }
    let sniffer = sniffer
        .as_mapping_mut()
        .ok_or("sniffer must be a mapping")?;
    sniffer.insert(Yaml::from("enable"), Yaml::from(true));
    sniffer.insert(Yaml::from("force-dns-mapping"), Yaml::from(true));
    sniffer.insert(Yaml::from("parse-pure-ip"), Yaml::from(true));
    sniffer.insert(Yaml::from("override-destination"), Yaml::from(false));
    let sniff = sniffer
        .entry(Yaml::from("sniff"))
        .or_insert_with(|| Yaml::Mapping(Mapping::new()));
    if sniff.is_null() {
        *sniff = Yaml::Mapping(Mapping::new());
    }
    let sniff = sniff
        .as_mapping_mut()
        .ok_or("sniffer.sniff must be a mapping")?;
    for (proto, default_ports) in [
        ("HTTP", json!([80, "8080-8880"])),
        ("TLS", json!([443, 8443])),
        ("QUIC", json!([443, 8443])),
    ] {
        // Mihomo folds `sniffer.sniff` keys case-insensitively into the same
        // protocol slot when iterating a Go map; reuse any existing mixed-case
        // key instead of inserting a colliding uppercase sibling.
        let key = sniff
            .keys()
            .find(|k| k.as_str().is_some_and(|s| s.eq_ignore_ascii_case(proto)))
            .cloned()
            .unwrap_or_else(|| Yaml::from(proto));
        let entry = sniff
            .entry(key)
            .or_insert_with(|| serde_yaml_ng::to_value(json!({"ports": default_ports})).unwrap());
        if entry.is_null() {
            *entry = serde_yaml_ng::to_value(json!({"ports": default_ports})).unwrap();
        }
        let proto_map = entry
            .as_mapping_mut()
            .ok_or_else(|| format!("sniffer.sniff.{proto} must be a mapping"))?;
        if proto_map
            .get(&Yaml::from("ports"))
            .is_none_or(Yaml::is_null)
        {
            proto_map.insert(
                Yaml::from("ports"),
                serde_yaml_ng::to_value(default_ports).unwrap(),
            );
        }
        proto_map.insert(Yaml::from("override-destination"), Yaml::from(false));
    }
    for (_, value) in sniff.iter_mut() {
        if let Some(proto_map) = value.as_mapping_mut() {
            proto_map.insert(Yaml::from("override-destination"), Yaml::from(false));
        }
    }
    Ok(())
}

// Mihomo interprets an unknown bare DNS URL fragment as SO_BINDTODEVICE,
// overriding the selected uplink even when global interface-name is managed.
fn validate_dns_routes(root: &Yaml) -> Result<(), String> {
    let mut names: Vec<&str> = vec![
        "",
        "DIRECT",
        "REJECT",
        "REJECT-DROP",
        "COMPATIBLE",
        "PASS",
        "PASS-RULE",
        "GLOBAL",
        "RULES",
    ];
    for section in ["proxies", "proxy-groups"] {
        if let Some(items) = root[section].as_sequence() {
            names.extend(items.iter().filter_map(|item| item["name"].as_str()));
        }
    }
    fn check(value: &Yaml, names: &[&str]) -> Result<(), String> {
        match value {
            Yaml::String(server) => {
                if let Some((_, fragment)) = server.split_once('#') {
                    let mut bytes = Vec::new();
                    let mut source = fragment.bytes();
                    while let Some(byte) = source.next() {
                        bytes.push(if byte == b'%' {
                            let hex = |b: Option<u8>| b.and_then(|b| (b as char).to_digit(16));
                            match (hex(source.next()), hex(source.next())) {
                                (Some(h), Some(l)) => (h * 16 + l) as u8,
                                _ => return Err("Invalid escape in a DNS resolver fragment".into()),
                            }
                        } else {
                            byte
                        });
                    }
                    let fragment =
                        std::str::from_utf8(&bytes).map_err(|_| "Invalid DNS resolver fragment")?;
                    let proxy = fragment
                        .split('&')
                        .rfind(|s| !s.contains('='))
                        .unwrap_or("");
                    if !names.contains(&proxy) {
                        return Err("DNS resolvers cannot bind a network interface. Use a declared proxy/group name, DIRECT or RULES after #, or remove that suffix".into());
                    }
                }
            }
            Yaml::Sequence(items) => {
                for item in items {
                    check(item, names)?;
                }
            }
            Yaml::Mapping(items) => {
                for item in items.values() {
                    check(item, names)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    for key in [
        "nameserver",
        "fallback",
        "default-nameserver",
        "proxy-server-nameserver",
        "direct-nameserver",
        "nameserver-policy",
        "proxy-server-nameserver-policy",
    ] {
        check(&root["dns"][key], &names)?;
    }
    Ok(())
}

fn bind_egress(config: &mut Yaml, egress: &egress::Binding) {
    let mapping = config.as_mapping_mut().unwrap();
    let key = Yaml::from("interface-name");
    if let Some(interface) = egress.interface() {
        check_clock();
        mapping.insert(key, Yaml::from(interface));
    } else {
        mapping.remove(key);
    }
}

fn clear_egress_overrides(value: &mut Yaml) {
    match value {
        Yaml::Mapping(map) => {
            map.remove(Yaml::from("interface-name"));
            map.remove(Yaml::from("routing-mark"));
            for child in map.values_mut() {
                clear_egress_overrides(child);
            }
        }
        Yaml::Sequence(values) => {
            for child in values {
                clear_egress_overrides(child);
            }
        }
        _ => {}
    }
}

/// The kernel settings and policy routes a running core needs, in apply
/// order. EffectSet captures each setting's original value on first hold.
fn proxy_resources() -> Vec<Resource> {
    let mut resources = Vec::new();
    // TPROXY loses its socket on the bridge-netfilter path (iptables and nft
    // alike); LAN-to-LAN filtering such as guest isolation pauses meanwhile.
    for key in ["bridge-nf-call-iptables", "bridge-nf-call-ip6tables"] {
        resources.push(Resource::Sysctl(Sysctl { key: key.into(), value: "0".into() }));
    }
    for (family, all) in [(Family::V4, "default"), (Family::V6, "::/0")] {
        let mut route = Route::new(family, RouteType::Local, all, TABLE);
        route.device = Some("lo".into());
        resources.push(Resource::Route(route));
        let mut rule = Rule::lookup(family, PREF.parse().unwrap(), TABLE);
        rule.mark = Some(MARK.into());
        resources.push(Resource::Rule(rule));
    }
    resources
}

/// One controller read (the core's secret never leaves the router).
fn controller_get(secret: &str, path: &str) -> Option<Value> {
    controller_get_at(CONTROLLER, secret, path)
}

fn controller_get_at(addr: &str, secret: &str, path: &str) -> Option<Value> {
    control::new_agent(Some(Duration::from_secs(2)), true)
        .get(&format!("http://{addr}{path}"))
        .header("Authorization", &format!("Bearer {secret}"))
        .call()
        .ok()?
        .body_mut()
        .with_config()
        .limit(4 * 1024 * 1024)
        .read_json::<Value>()
        .ok()
}

/// `@u60-mihomo-nft`: `tables` marks the journal entry of the tables
/// (`NftTables` loads them); `remove` deletes both families' tables.
pub(crate) fn nft_command(args: &[String]) -> Result<(), String> {
    match args {
        [a] if a == "tables" => Ok(()),
        [a] if a == "remove" => {
            // An unreadable kernel is no evidence the tables are gone: the
            // undo then fails and the journal stays.
            use effect::Nft;
            for family in effect::FAMILIES {
                if effect::Device.list(family, NFT_TABLE)?.is_some() {
                    effect::Device.delete(family, NFT_TABLE)?;
                }
            }
            Ok(())
        }
        _ => Err("Invalid Mihomo nftables command".into()),
    }
}

/// A successful loopback TCP handshake confirms a listener without dumping all sockets.
fn listening(port: u16) -> bool {
    [std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)].into_iter()
        .any(|ip| std::net::TcpStream::connect_timeout(&(ip, port).into(), Duration::from_millis(75)).is_ok())
}

pub fn status(state: &crate::handlers::AppState) -> (u16, Value) {
    (200, json!({"ok":true,"data":state.mihomo.status()}))
}

pub fn change(state: &crate::handlers::AppState, action: &str, body: &[u8]) -> (u16, Value) {
    let result = match action {
        "install" => state.mihomo.install(),
        "config" => serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v["yaml"].as_str().map(str::to_owned))
            .ok_or_else(|| "Missing yaml field".to_owned())
            .and_then(|yaml| state.mihomo.configure(&yaml)),
        "switch" => match serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v["enabled"].as_bool())
        {
            Some(true) => state.mihomo.enable(state.tls.name()),
            Some(false) => state.mihomo.disable(),
            _ => Err("enabled must be a boolean".into()),
        },
        "direct-bypass" => match serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v["enabled"].as_bool())
        {
            Some(enabled) => state.mihomo.set_direct_bypass(enabled),
            None => Err("enabled must be a boolean".into()),
        },
        _ => Err("Unknown Mihomo action".into()),
    };
    match result {
        Ok(()) => status(state),
        Err(e) => (503, json!({"ok":false,"error":e})),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn assert_ra_firewall_guard(set_data: impl FnOnce()) {
        use controller::Port;
        use std::collections::BTreeMap;

        struct Bridge(BTreeMap<String, String>);
        impl net::Probe for Bridge {
            fn list(&mut self, _: &Cmd) -> Result<String, String> {
                unreachable!()
            }

            fn status(&mut self, _: &Cmd) -> Result<(i32, String), String> {
                unreachable!()
            }

            fn apply(&mut self, command: &Cmd) -> Result<(), String> {
                assert_eq!(command.program, "@u60-sysctl");
                self.0.insert(command.args[0].clone(), command.args[1].clone());
                Ok(())
            }

            fn sysctl(&mut self, key: &str) -> Result<String, String> {
                Ok(self.0[key].clone())
            }
        }

        let temp = test_dir::TestDir::new("mihomo-ra-guard");
        let mihomo = Arc::new(Mihomo::for_test(temp.path().to_owned()));
        let mut port = DevicePort::new(mihomo, "u60.home.arpa".into());
        let mut effects = EffectSet::new("mihomo", port.m.journal());
        let settings: Vec<_> = proxy_resources()
            .into_iter()
            .filter(|resource| matches!(resource, Resource::Sysctl(_)))
            .collect();
        let keys = ["bridge-nf-call-iptables", "bridge-nf-call-ip6tables"];
        let mut bridge = Bridge(keys.into_iter().map(|key| (key.into(), "1".into())).collect());
        effects.assume(settings);
        port.effects = Some(effects);
        assert!(port.guard_due(), "the initial guard check is already accounted for");

        let (sender, messages) = mpsc::channel();
        watch_guard(sender);
        crate::net_guard::start(&crate::event_bus::EventBus::new());
        set_data();
        assert!(matches!(
            messages.recv_timeout(Duration::from_secs(10)),
            Ok(Message::Guard)
        ));
        let check = |port: &mut DevicePort, bridge: &mut Bridge| {
            port.reconcile_effects(|effects| {
                effects.reconcile_selected(|_| true, bridge, &mut effect::Device)
            }).result.unwrap();
            for key in keys {
                assert_eq!(bridge.0[key], "0");
            }
        };
        assert!(port.guard_due(), "Mihomo checks at the guard's wakeup");
        check(&mut port, &mut bridge);

        bridge.0.values_mut().for_each(|value| *value = "1".into());
        let deadline = Instant::now() + Duration::from_secs(10);
        while !port.guard_due() {
            assert!(Instant::now() < deadline, "the bridge guard did not recheck");
            std::thread::sleep(Duration::from_millis(20));
        }
        check(&mut port, &mut bridge);
    }

    fn resource_steps(original: impl Fn(&str) -> Result<String, String>) -> Result<Vec<net::Step>, String> {
        let mut resources = proxy_resources();
        resources.push(Resource::NftTable(NftTable { owner: "mihomo", name: NFT_TABLE, file: PathBuf::from(NFT_FILE), families: None }));
        resources.iter().map(|resource| resource.step_with(&original)).collect()
    }

    fn write_start_journal(path: &Path, original: impl Fn(&str) -> Result<String, String>) {
        struct StartupProbe<Read>(Read);
        impl<Read: Fn(&str) -> Result<String, String>> net::Probe for StartupProbe<Read> {
            fn list(&mut self, _: &Cmd) -> Result<String, String> { Ok(String::new()) }
            fn status(&mut self, _: &Cmd) -> Result<(i32, String), String> { unreachable!() }
            fn apply(&mut self, _: &Cmd) -> Result<(), String> { Ok(()) }
            fn sysctl(&mut self, key: &str) -> Result<String, String> { (self.0)(key) }
        }
        let mut resources = proxy_resources();
        resources.push(Resource::NftTable(NftTable { owner: "mihomo", name: NFT_TABLE, file: path.with_extension("nft"), families: None }));
        EffectSet::new("mihomo", path.into()).declare_with(resources, &mut StartupProbe(original), &mut effect::fake::FakeNft::default()).unwrap();
        crate::net_guard::release(&path.to_string_lossy(), None);
    }

    #[test]
    fn the_typed_start_journal_keeps_only_the_proxy_resources() {
        let expected = vec![
            Cmd::new("@u60-sysctl", &["bridge-nf-call-iptables", "1"]),
            Cmd::new("@u60-sysctl", &["bridge-nf-call-ip6tables", "1"]),
            Cmd::new("ip", &["-4", "route", "del", "local", "default", "dev", "lo", "table", "60625"]),
            Cmd::new("ip", &["-4", "rule", "del", "pref", PREF, "fwmark", "0x700/0xff00", "lookup", "60625"]),
            Cmd::new("ip", &["-6", "route", "del", "local", "::/0", "dev", "lo", "table", "60625"]),
            Cmd::new("ip", &["-6", "rule", "del", "pref", PREF, "fwmark", "0x700/0xff00", "lookup", "60625"]),
            Cmd::new("@u60-mihomo-nft", &["remove"]),
        ];
        let temp = test_dir::TestDir::new("start-journal");
        let directory = temp.path().to_path_buf();
        let path = directory.join("network.json");
        write_start_journal(&path, |_| Ok("1".into()));
        let written: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(written["undo"], serde_json::to_value(expected).unwrap());
    }

    #[test]
    fn a_validation_is_remembered_for_this_boot_only() {
        let temp = test_dir::TestDir::new("validated");
        let dir = temp.path().to_path_buf();
        fs::create_dir_all(&dir).unwrap();
        remember_validation(&dir, &["abc:1:2".to_owned(), "def:3:4".to_owned()]);
        let boot = net::boot_id();
        let expected: Vec<String> = if boot.is_empty() { Vec::new() } else { vec!["abc:1:2".into(), "def:3:4".into()] };
        assert_eq!(remembered_validation(&dir), expected, "no boot id (not Linux): never reused");
        fs::write(dir.join(VALIDATED), "another-boot abc:1:2").unwrap();
        assert!(remembered_validation(&dir).is_empty(), "another boot's validation is not reused");
        remember_validation(&dir, &[]);
        assert!(!dir.join(VALIDATED).exists());
        assert!(Mihomo::for_test(dir.clone()).validated_config.lock().unwrap().is_empty());
    }

    #[test]
    fn slow_profile_status_does_not_hold_dashboard_runtime_mutex() {
        let temp = test_dir::TestDir::new("slow-profile-status");
        let m = Arc::new(Mihomo::for_bridge(temp.path().to_path_buf(), "fixture".into()));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = {
            let m = Arc::clone(&m);
            std::thread::spawn(move || {
                m.status_with(|| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                    Ok(json!({"selected":"fixture"}))
                }, || None)
            })
        };
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let available = m.shared.try_lock().is_ok();
        release_tx.send(()).unwrap();
        assert!(worker.join().unwrap()["running"].as_bool().unwrap());
        assert!(
            available,
            "async dashboard readers must not wait for profile I/O"
        );
    }

    #[test]
    fn the_production_core_and_validators_use_separate_go_limits() {
        fn env(command: &Command, key: &str) -> Option<String> {
            command.get_envs().find(|(name, _)| *name == key)
                .and_then(|(_, value)| value)
                .map(|value| value.to_string_lossy().into_owned())
        }

        let temp = test_dir::TestDir::new("mihomo-core-command");
        let mihomo = Mihomo::for_test(temp.path().to_owned());
        let core = mihomo.core_command();
        assert_eq!(env(&core, "GOMEMLIMIT").as_deref(), Some("256MiB"));
        assert_eq!(env(&core, "GOMAXPROCS"), None);
        assert!(!core.get_args().any(|arg| arg == "-t"));

        let background = mihomo.validation_command("candidate.yaml", true);
        assert_eq!(env(&background, "GOMEMLIMIT").as_deref(), Some("128MiB"));
        assert_eq!(env(&background, "GOMAXPROCS").as_deref(), Some("1"));
        assert_eq!(background.get_args().next().unwrap(), "-t");

        let foreground = mihomo.validation_command("candidate.yaml", false);
        assert_eq!(env(&foreground, "GOMEMLIMIT"), None);
        assert_eq!(env(&foreground, "GOMAXPROCS"), None);
        assert_eq!(foreground.get_args().next().unwrap(), "-t");
    }

    #[test]
    fn status_reports_read_only_qos_and_bypass_compilation_details() {
        use controller::Port;

        let temp = test_dir::TestDir::new("mihomo-diagnostics");
        let mihomo = Arc::new(Mihomo::for_test(temp.path().to_owned()));
        let off = mihomo.status_with(|| Ok(json!({})), || None);
        assert!(off["kernel"].is_null() && off["fake_ip_filter"].is_null());
        assert!(off["vendor_qos_mode"].is_null());
        let mut port = DevicePort::new(Arc::clone(&mihomo), "u60.home.arpa".into());
        let source = "
dns:
  fake-ip-filter: ['+.example.test']
rule-providers:
  Dynamic: {type: http, behavior: domain, path: ./dynamic.yaml}
rules:
  - IP-CIDR,1.2.3.0/24,DIRECT
  - IP-ASN,13334,DIRECT
  - IP-ASN,13335,REJECT
  - RULE-SET,Dynamic,REJECT
  - MATCH,DIRECT
";
        let (_, (routes, dns)) = managed_mapping(source, "fixture", None, true, false).unwrap();
        let mode = routing::Mode::Rule;
        let selected = routing::Selected::new();
        let (bypass, chain) = port.plan(&routes, true, mode, &selected, &[]);

        {
            let mut snapshot = mihomo.shared.lock().unwrap();
            snapshot.phase = Phase::Running;
            snapshot.mode = Some(mode);
            snapshot.bypass = Some(bypass);
            snapshot.compilation = Some(chain.compilation());
            snapshot.dns_filter = Some(dns.diagnostics);
        }
        let status = mihomo.status_with(|| Ok(json!({"selected": "fixture"})), || Some("Game_mode".into()));
        assert_eq!(status["vendor_qos_mode"], "Game_mode");
        assert_eq!(status["configured"], true);
        assert_eq!(status["running"], true);
        assert_eq!(status["direct_bypass_active"], true);
        assert_eq!(status["kernel"]["mode"], "rule");
        assert_eq!(status["kernel"]["bypass"], "rules");
        assert_eq!(status["kernel"]["returns"], 1);
        assert_eq!(status["kernel"]["reason"], "Rule 3 (IP-ASN,13335,REJECT): IP-ASN rules need the core");
        assert_eq!(status["kernel"]["compilation"], json!({
            "truncation_reason": status["kernel"]["reason"],
            "nft_rules": 1,
            "direct_returns": 1,
            "cidr_sets": 1,
            "cidr_set_entries": 1,
            "skipped_direct_alternatives": 1
        }));
        assert_eq!(status["fake_ip_filter"], json!({
            "truncation_reason": "Rule 4: a rule set can gain new domain names",
            "rules": dns.rules.len(),
            "fake_ip_rules": 2,
            "compatibility_rules_skipped": 1,
            "default_action": "fake-ip"
        }));
    }

    #[test]
    fn qos_mode_lookup_caches_absence_and_refreshes_after_the_ttl() {
        let temp = test_dir::TestDir::new("mihomo-qos-cache");
        let mihomo = Mihomo::for_test(temp.path().to_owned());

        assert_eq!(mihomo.cached_qos_mode(|| None), None);
        assert_eq!(mihomo.cached_qos_mode(|| panic!("the missing mode is cached")), None);

        mihomo.qos_mode_cache.lock().unwrap().as_mut().unwrap().0 -= QOS_MODE_TTL;
        assert_eq!(mihomo.cached_qos_mode(|| Some("Game_mode".into())).as_deref(), Some("Game_mode"));
        assert_eq!(mihomo.cached_qos_mode(|| panic!("the mode is cached")).as_deref(), Some("Game_mode"));
    }

    #[test]
    fn dns_cannot_override_wifi_with_literal_or_escaped_interface_fragments() {
        for key in [
            "nameserver",
            "fallback",
            "default-nameserver",
            "proxy-server-nameserver",
            "direct-nameserver",
        ] {
            for suffix in [
                "rmnet_data0",
                "rmnet%5Fdata0",
                "h3=true&rmnet_data0",
                "DIRECT&rmnet_data0",
                "%GG",
            ] {
                assert!(
                    managed_config(
                        &format!("dns: {{{key}: ['https://dns.example/dns-query#{suffix}']}}"),
                        "private"
                    )
                    .is_err(),
                    "{key} {suffix}"
                );
            }
        }
        assert!(managed_config(
            "dns: {nameserver-policy: {'geosite:cn': ['tls://dns.example#rmnet_data0']}}",
            "private"
        )
        .is_err());
        for suffix in [
            "DIRECT",
            "RULES",
            "GLOBAL",
            "Choice",
            "A+B",
            "A%2BB",
            "h3=true&skip-cert-verify=true",
            "rmnet_data0&DIRECT",
        ] {
            let source = format!("proxy-groups: [{{name: Choice, type: select, proxies: [DIRECT]}}, {{name: A+B, type: select, proxies: [DIRECT]}}]\ndns: {{nameserver: ['https://dns.example/dns-query#{suffix}']}}");
            assert!(managed_config(&source, "private").is_ok(), "{suffix}");
        }
    }

    #[test]
    fn keepalive_defaults_apply_only_when_all_three_settings_are_absent() {
        let config: Yaml = serde_yaml_ng::from_str(&managed_config("rules: ['MATCH,DIRECT']", "s").unwrap()).unwrap();
        assert_eq!(config["keep-alive-idle"].as_u64(), Some(120));
        assert_eq!(config["keep-alive-interval"].as_u64(), Some(30));
        for setting in ["keep-alive-idle: 0", "keep-alive-interval: 5", "disable-keep-alive: false", "disable-keep-alive: true"] {
            let source: Yaml = serde_yaml_ng::from_str(setting).unwrap();
            let config: Yaml = serde_yaml_ng::from_str(&managed_config(setting, "s").unwrap()).unwrap();
            for key in ["keep-alive-idle", "keep-alive-interval", "disable-keep-alive"] {
                assert_eq!(config.get(key), source.get(key));
            }
        }
    }

    #[test]
    fn configuration_cannot_open_an_upstream_controller_or_override_routes() {
        let s = managed_config(
            "external-controller: 0.0.0.0:9090\nsecret: stolen\ntun: {enable: true}\nlisteners: [{port: 9999}]\nproxies: []\nrules: [MATCH,DIRECT]\n",
            "private",
        )
        .unwrap();
        let v: Yaml = serde_yaml_ng::from_str(&s).unwrap();
        assert_eq!(v["external-controller"].as_str(), Some(CONTROLLER));
        assert_eq!(v["secret"].as_str(), Some("private"));
        assert_eq!(v["listeners"][0]["listen"], "127.0.0.1");
        assert_eq!(v["listeners"].as_sequence().unwrap().len(), 1);
        assert_eq!(v["listeners"][0]["users"][0]["password"], "private");
        assert_eq!(v["tun"]["enable"].as_bool(), Some(false));
        assert_eq!(v["tproxy-port"].as_u64(), Some(u64::from(TPROXY_PORT)));
        assert_eq!(v["dns"]["ipv6"].as_bool(), Some(true));
        assert!(managed_config("- not-a-mapping", "x").is_err());
        assert!(managed_config("dns: []", "x").is_err());
    }

    #[test]
    fn the_subscriptions_sniffer_is_kept_but_cannot_bind_an_interface() {
        let s = managed_config(
            "sniffer: {enable: true, force-dns-mapping: true, parse-pure-ip: true, sniff: {TLS: {ports: [443]}}}\nrules: [MATCH,DIRECT]\n",
            "private",
        )
        .unwrap();
        let v: Yaml = serde_yaml_ng::from_str(&s).unwrap();
        assert_eq!(v["sniffer"]["enable"].as_bool(), Some(true));
        assert_eq!(v["sniffer"]["force-dns-mapping"].as_bool(), Some(true));
        assert_eq!(v["sniffer"]["sniff"]["TLS"]["ports"][0].as_u64(), Some(443));
        let none = managed_config("rules: [MATCH,DIRECT]\n", "private").unwrap();
        assert!(serde_yaml_ng::from_str::<Yaml>(&none).unwrap()["sniffer"].is_null());
    }

    #[test]
    fn tailscale_exit_auto_enables_sniffer_preserving_dst_ip_and_custom_skip_lists() {
        // Subscription with no sniffer block gets TLS/HTTP/QUIC + parse-pure-ip enabled,
        // with override-destination forced false globally and per-protocol so Mihomo
        // uses SniffHost for rule matching without re-resolving via plaintext DNS.
        let auto = managed_config_with_tailscale("rules: [MATCH,DIRECT]\n", "private", true).unwrap();
        let v: Yaml = serde_yaml_ng::from_str(&auto).unwrap();
        assert_eq!(v["sniffer"]["enable"].as_bool(), Some(true));
        assert_eq!(v["sniffer"]["parse-pure-ip"].as_bool(), Some(true));
        assert_eq!(v["sniffer"]["override-destination"].as_bool(), Some(false));
        assert_eq!(v["sniffer"]["force-dns-mapping"].as_bool(), Some(true));
        for proto in ["HTTP", "TLS", "QUIC"] {
            assert!(v["sniffer"]["sniff"][proto].is_mapping(), "{proto}");
            assert_eq!(
                v["sniffer"]["sniff"][proto]["override-destination"].as_bool(),
                Some(false),
                "{proto} must preserve Clean DNS DstIP"
            );
        }

        // User-supplied skip-domain and custom TLS ports are preserved while any
        // user-supplied `override-destination: true` is overridden to false.
        let custom = managed_config_with_tailscale(
            "sniffer:\n  enable: false\n  override-destination: true\n  skip-domain: ['Mijia Cloud']\n  sniff:\n    HTTP: {ports: [80], override-destination: true}\n    TLS: {ports: [443]}\nrules: [MATCH,DIRECT]\n",
            "private",
            true,
        )
        .unwrap();
        let c: Yaml = serde_yaml_ng::from_str(&custom).unwrap();
        assert_eq!(c["sniffer"]["enable"].as_bool(), Some(true));
        assert_eq!(c["sniffer"]["parse-pure-ip"].as_bool(), Some(true));
        assert_eq!(c["sniffer"]["override-destination"].as_bool(), Some(false));
        assert_eq!(c["sniffer"]["skip-domain"][0].as_str(), Some("Mijia Cloud"));
        assert_eq!(c["sniffer"]["sniff"]["HTTP"]["override-destination"].as_bool(), Some(false));
        assert_eq!(c["sniffer"]["sniff"]["TLS"]["ports"].as_sequence().unwrap().len(), 1);
        assert_eq!(c["sniffer"]["sniff"]["TLS"]["override-destination"].as_bool(), Some(false));
        assert_eq!(c["sniffer"]["sniff"]["QUIC"]["override-destination"].as_bool(), Some(false));

        // Mixed-case user protocol keys (`tls`, `http`) MUST be matched
        // case-insensitively without inserting colliding `TLS`/`HTTP` siblings.
        let mixed = managed_config_with_tailscale(
            "sniffer:\n  enable: true\n  sniff:\n    tls: {ports: [443, 2053], override-destination: true}\n    Http: {override-destination: true}\nrules: [MATCH,DIRECT]\n",
            "private",
            true,
        )
        .unwrap();
        let m: Yaml = serde_yaml_ng::from_str(&mixed).unwrap();
        let sniff_map = m["sniffer"]["sniff"].as_mapping().unwrap();
        assert_eq!(sniff_map.len(), 3, "no colliding uppercase duplicates: {sniff_map:?}");
        assert!(sniff_map.get(&Yaml::from("TLS")).is_none());
        assert!(sniff_map.get(&Yaml::from("HTTP")).is_none());
        assert_eq!(m["sniffer"]["sniff"]["tls"]["ports"].as_sequence().unwrap().len(), 2);
        assert_eq!(m["sniffer"]["sniff"]["tls"]["override-destination"].as_bool(), Some(false));
        assert!(m["sniffer"]["sniff"]["Http"]["ports"].is_sequence());
        assert_eq!(m["sniffer"]["sniff"]["Http"]["override-destination"].as_bool(), Some(false));
        assert_eq!(m["sniffer"]["sniff"]["QUIC"]["override-destination"].as_bool(), Some(false));
    }

    #[test]
    fn clean_dns_proxy_gates_on_running_and_non_direct_mode() {
        let dir = test_dir::TestDir::new("clean-dns-proxy-gate");
        let m = Mihomo::for_test(dir.path().to_path_buf());
        assert!(m.clean_dns_proxy().is_none());

        {
            let mut s = m.shared.lock().unwrap();
            s.phase = Phase::Running;
            s.mode = Some(routing::Mode::Rule);
            s.secret = Some("s3cr3t".into());
        }
        assert_eq!(
            m.clean_dns_proxy(),
            Some((download::PROXY.to_string(), download::USER.to_string(), "s3cr3t".to_string()))
        );

        // Direct mode -> direct IP-literal DoH (no proxy hop)
        m.shared.lock().unwrap().mode = Some(routing::Mode::Direct);
        assert!(m.clean_dns_proxy().is_none());

        // D3 Backoff -> direct IP-literal DoH
        {
            let mut s = m.shared.lock().unwrap();
            s.mode = Some(routing::Mode::Rule);
            s.phase = Phase::Backoff;
        }
        assert!(m.clean_dns_proxy().is_none());

        // Recovery back to Running -> proxy mode re-engaged
        m.shared.lock().unwrap().phase = Phase::Running;
        assert!(m.clean_dns_proxy().is_some());
    }

    /// v4 release blocker: while the relay holds the network lock (an
    /// association or a CAC of up to 80 s), Mihomo's owner commands, egress
    /// news and failure handling still run: the controller never takes it.
    #[test]
    fn mihomo_never_waits_for_the_relays_network_lock() {
        let temp = test_dir::TestDir::new("core-cac");
        let dir = temp.path().to_path_buf();
        let lock = Arc::new(crate::netfx::admission::Gate::new());
        let m = Arc::new(Mihomo::for_test(dir.clone()));
        let controller = controller::tests::Harness::for_mihomo(&m);
        let held = crate::netfx::admission::enter(&lock, Duration::ZERO).unwrap();
        let started = Instant::now();
        assert_eq!(m.enable("u60.home.arpa").unwrap_err(), "fixture rejected the start");
        m.uplink_changed();
        m.set_direct_bypass(true).unwrap();
        m.disable().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5), "{:?} with the relay's lock held", started.elapsed());
        drop(held);
        drop(controller);
    }

    #[test]
    fn direct_bypass_flag_status_and_legacy_fallback() {
        let temp = test_dir::TestDir::new("direct-bypass");
        let dir = temp.path().to_path_buf();
        let m = Mihomo::for_test(dir.clone());
        assert_eq!(m.status()["direct_bypass"], Value::Bool(false));
        assert_eq!(m.status()["direct_bypass_active"], Value::Bool(false));
        net::write_private(&dir.join(LEGACY_BYPASS), b"1").unwrap();
        assert_eq!(m.status()["direct_bypass"], Value::Bool(true));
        m.set_direct_bypass(true).unwrap();
        assert!(dir.join(BYPASS).is_file());
        assert!(!dir.join(LEGACY_BYPASS).exists());
        assert_eq!(m.status()["direct_bypass"], Value::Bool(true));
        m.set_direct_bypass(false).unwrap();
        assert!(!dir.join(BYPASS).exists());
        assert!(!dir.join(LEGACY_BYPASS).exists());
        assert_eq!(m.status()["direct_bypass"], Value::Bool(false));
    }

    #[test]
    fn every_journaled_undo_is_one_the_previous_agent_runs() {
        const HEAD_SYSCTL: [&str; 4] = ["tcp_pacing_ss_ratio", "tcp_pacing_ca_ratio", "bridge-nf-call-iptables", "bridge-nf-call-ip6tables"];
        let undos: Vec<Cmd> = resource_steps(|_| Ok("1".into())).unwrap().into_iter().map(|step| step.undo).collect();
        for undo in &undos {
            let args: Vec<&str> = undo.args.iter().map(String::as_str).collect();
            let known = match (undo.program.as_str(), args.as_slice()) {
                ("@u60-sysctl", [key, value]) => HEAD_SYSCTL.contains(key) && value.parse::<u32>().is_ok(),
                ("@u60-mihomo-nft", ["remove"]) => true,
                ("ip", [family, "route" | "rule", "del", ..]) => matches!(*family, "-4" | "-6"),
                _ => false,
            };
            assert!(known, "{undo:?} is not in the previous agent's vocabulary");
        }
        // The undo list runs newest first: the tables go before routes and settings.
        assert_eq!(undos.last().unwrap().args, ["remove"]);
        let routes: Vec<String> = undos.iter().filter(|u| u.program == "ip").map(|u| u.args.join(" ")).collect();
        assert_eq!(routes, [
            "-4 route del local default dev lo table 60625",
            &format!("-4 rule del pref {PREF} fwmark 0x700/0xff00 lookup 60625"),
            "-6 route del local ::/0 dev lo table 60625",
            &format!("-6 rule del pref {PREF} fwmark 0x700/0xff00 lookup 60625"),
        ]);
    }

    fn port_with_performance_claim(root: &Path) -> (DevicePort, PathBuf) {
        let mihomo = Arc::new(Mihomo::for_test(root.to_owned()));
        let backlog = root.join("perf/proc/sys/net/core/netdev_max_backlog");
        fs::create_dir_all(backlog.parent().unwrap()).unwrap();
        fs::write(&backlog, "1000").unwrap();
        mihomo.perf.set_active(PerfFeature::Mihomo, true).unwrap();
        assert_eq!(fs::read_to_string(&backlog).unwrap(), "5000");
        (DevicePort::new(mihomo, "u60.home.arpa".into()), backlog)
    }

    #[test]
    fn direct_releases_performance_when_the_firewall_refuses_the_direct_table() {
        use controller::Port;
        let temp = test_dir::TestDir::new("mihomo-direct-perf");
        let (mut port, backlog) = port_with_performance_claim(temp.path());
        port.effects = Some(EffectSet::new("foreign", port.m.journal()));

        assert_eq!(port.direct().unwrap_err(), "The nftables table has another owner");
        assert_eq!(fs::read_to_string(backlog).unwrap(), "1000");
    }

    #[test]
    fn release_all_releases_performance_when_firewall_cleanup_pauses() {
        use controller::Port;
        let temp = test_dir::TestDir::new("mihomo-release-perf");
        let (mut port, backlog) = port_with_performance_claim(temp.path());
        let mut effects = EffectSet::new("mihomo", port.m.journal());
        effects.assume(vec![Resource::Sysctl(Sysctl { key: "unavailable-test-setting".into(), value: "0".into() })]);
        port.effects = Some(effects);

        let error = port.release_all().unwrap_err();
        assert!(error.starts_with("Network cleanup paused:"), "{error}");
        assert!(port.effects.is_some());
        assert_eq!(fs::read_to_string(backlog).unwrap(), "1000");
    }

    /// Writes the production table batches and the journal this version
    /// keeps, for the isolated Linux acceptance (`tests/mihomo-qa`). Run with
    /// `U60_MIHOMO_QA=<dir> cargo test -p zte-agent export_for_isolated_linux_acceptance -- --ignored`.
    #[test]
    #[ignore = "fixture exporter requires U60_MIHOMO_QA to name its output directory"]
    fn export_for_isolated_linux_acceptance() {
        let dir = PathBuf::from(std::env::var_os("U60_MIHOMO_QA").expect("U60_MIHOMO_QA"));
        fs::create_dir_all(&dir).unwrap();
        let temp = test_dir::TestDir::new("mihomo-qa");
        let root = temp.path().join("mihomo");
        let plan = |rules: &str| {
            let routes = routing::Routes::from(&serde_yaml_ng::from_str(&format!("proxy-groups: [{{name: P, type: select, proxies: [JP]}}]\nrules: {rules}")).unwrap());
            routes.compile(&routing::Selected::new(), &root, &[]).render(&|_| Err("no GeoIP here".to_owned()))
        };
        let one = plan("['IP-CIDR,203.0.113.0/24,DIRECT', 'MATCH,P']");
        let both = plan("['IP-CIDR,203.0.113.0/24,DIRECT', 'IP-CIDR,198.51.100.0/24,DIRECT', 'MATCH,P']");
        assert_eq!(one.returns, 1);
        let shapes = [
            ("guard", intercept::Shape::Guard),
            ("hold", intercept::Shape::Hold),
            ("full", intercept::Shape::Full(&one)),
            ("full-both", intercept::Shape::Full(&both)),
            ("reject", intercept::Shape::FakeReject),
        ];
        for (generation, (name, shape)) in shapes.into_iter().enumerate() {
            let (marker, text) = effect::batch("mihomo", NFT_TABLE, generation as u64 + 1, intercept::tables(shape)).unwrap();
            fs::write(dir.join(format!("{name}.nft")), text).unwrap();
            fs::write(dir.join(format!("{name}.marker")), marker).unwrap();
        }
        // A batch whose IPv6 half is invalid: nothing of it may load.
        let [v4, _] = intercept::tables(intercept::Shape::Hold);
        let (_, broken) = effect::batch("mihomo", NFT_TABLE, 99, [v4, "table ip6 u60_mihomo {\n\tchain x {\n\t\tnot a rule\n\t}\n}\n".into()]).unwrap();
        fs::write(dir.join("broken.nft"), broken).unwrap();
        // The journal as EffectSet writes it (the container fills in its
        // boot id and the original kernel values); bridge-netfilter keys are
        // left out where the container has no bridge sysctls.
        let path = dir.join("journal.json");
        write_start_journal(&path, |key| Ok(format!("{{{key}}}")));
        let mut journal: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        journal["boot"] = json!("{boot}");
        fs::write(path, serde_json::to_vec_pretty(&journal).unwrap()).unwrap();
    }

    /// Release blocker 2 with the real tools (`tests/mihomo-qa`, run inside
    /// the disposable container's router namespace): a name another writer
    /// holds is never taken over, and a journal cut short at any point (undo
    /// written but nothing applied, after each step, half rolled back) is
    /// recovered completely and only for our own objects.
    #[test]
    #[ignore = "requires the disposable Mihomo QA container and its router namespace"]
    fn isolated_ownership_and_interrupted_journals() {
        assert_eq!(std::env::var("U60_MIHOMO_QA_ISOLATED").as_deref(), Ok("1"));
        assert!(Path::new("/u60-qa-disposable").exists());
        use controller::Port;
        let run = |args: &[&str]| Cmd::new(args[0], &args[1..]).run();
        let root = PathBuf::from("/tmp/u60-mihomo-qa-root");
        fs::create_dir_all(&root).unwrap();
        let m = Arc::new(Mihomo::for_test(root.clone()));
        let mut port = DevicePort::new(Arc::clone(&m), "qa.home.arpa".into());
        // Foreign names: a table without our marker, a route in our table,
        // a rule at our priority. Each is refused and left as it was.
        for (take, give, expect) in [
            (vec!["nft", "add", "table", "ip6", NFT_TABLE], vec!["nft", "delete", "table", "ip6", NFT_TABLE], "Another program"),
            (vec!["ip", "-4", "route", "add", "192.0.2.0/24", "dev", "lo", "table", TABLE], vec!["ip", "-4", "route", "del", "192.0.2.0/24", "dev", "lo", "table", TABLE], "route table is already in use"),
            (vec!["ip", "-6", "rule", "add", "pref", PREF, "lookup", "main"], vec!["ip", "-6", "rule", "del", "pref", PREF, "lookup", "main"], "rule priority is already in use"),
        ] {
            run(&take).unwrap();
            let error = port.engage(Engage::Fresh).unwrap_err();
            assert!(error.contains(expect), "{error}");
            assert!(!m.journal().exists(), "nothing journaled for a refused claim");
            run(&give).expect("the foreign object is still there to remove");
        }
        let settings = || ["tcp_pacing_ss_ratio", "bridge-nf-call-iptables"].map(|key| net::sysctl_read(key).unwrap());
        let before = settings();
        let clean = || {
            let rules = run(&["ip", "-4", "rule", "show"]).unwrap() + &run(&["ip", "-6", "rule", "show"]).unwrap();
            let tables = run(&["nft", "list", "tables"]).unwrap();
            !rules.contains(&format!("{PREF}:")) && !tables.contains(NFT_TABLE) && settings() == before && !m.journal().exists()
        };
        // A real claim, the guard loaded, then the process "dies".
        port.engage(Engage::Fresh).unwrap();
        controller::Port::tables(&mut port, intercept::Shape::Guard).unwrap();
        assert!(!clean());
        drop(port);
        m.recover().unwrap();
        assert!(clean(), "recovered after a crash while running");
        // Cut short after each step: the journal holds every undo first.
        let steps = resource_steps(net::sysctl_read).unwrap();
        for applied in 0..=steps.len() {
            let journal = json!({"boot": net::boot_id(), "undo": steps.iter().map(|s| &s.undo).collect::<Vec<_>>()});
            net::write_private(&m.journal(), &serde_json::to_vec(&journal).unwrap()).unwrap();
            for step in &steps[..applied] {
                step.apply.run().unwrap();
            }
            m.recover().unwrap();
            assert!(clean(), "after {applied} applied step(s)");
        }
        // A rollback interrupted halfway is finished by the next one.
        for step in &steps {
            step.apply.run().unwrap();
        }
        let half: Vec<&Cmd> = steps[..steps.len() / 2].iter().map(|s| &s.undo).collect();
        for step in steps[steps.len() / 2..].iter().rev() {
            step.undo.run().unwrap();
        }
        net::write_private(&m.journal(), &serde_json::to_vec(&json!({"boot": net::boot_id(), "undo": half})).unwrap()).unwrap();
        m.recover().unwrap();
        assert!(clean(), "a half-finished rollback converges");
        let _ = fs::remove_dir_all(root);
    }

    /// v3: a 204 is not a reload; what the core reports must match.
    #[test]
    fn a_reload_is_confirmed_only_by_what_the_core_reports() {
        let config = "interface-name: ath20\nrule-providers:\n  Web: {type: http, behavior: ipcidr, url: 'https://x', path: ./w.yaml}\n";
        let prepared = Prepared {
            secret: "s".into(),
            local: "u60.home.arpa".into(),
            runtime: json!({"mode": "rule", "log-level": "info"}),
            routes: routing::Routes::default(),
            dns: Default::default(),
            bypass: true,
            tailscale_sniffer: false,
            notice: None,
            source: String::new(),
            config: config.into(), facts: reload::Facts::from(&serde_yaml_ng::from_str(config).unwrap()),
            egress: Default::default(),
        };
        let before: routing::Selected = [("G".to_owned(), "DIRECT".to_owned())].into();
        let configs = json!({"mode": "rule", "interface-name": "ath20"});
        let proxies = |now: &str| json!({"proxies": {"G": {"type": "Selector", "now": now}}});
        let providers = json!({"providers": {"Web": {"ruleCount": 3}}});
        assert!(reload_findings(&prepared, Some(&configs), Some(&proxies("DIRECT")), Some(&providers), &before).is_ok());
        let fell = reload_findings(&prepared, Some(&configs), Some(&proxies("COMPATIBLE")), Some(&providers), &before).unwrap_err();
        assert!(fell.contains("COMPATIBLE"), "{fell}");
        assert!(reload_findings(&prepared, Some(&configs), Some(&proxies("P")), Some(&providers), &before).is_err(), "a choice not restored");
        assert!(reload_findings(&prepared, Some(&configs), Some(&proxies("DIRECT")), Some(&json!({"providers": {}})), &before).unwrap_err().contains("rule set"));
        assert!(reload_findings(&prepared, Some(&configs), Some(&proxies("DIRECT")), Some(&json!({"providers": {"Web": {"ruleCount": 0}}})), &before).is_err());
        assert!(reload_findings(&prepared, Some(&json!({"mode": "global", "interface-name": "ath20"})), Some(&proxies("DIRECT")), Some(&providers), &before).is_err());
        assert!(reload_findings(&prepared, Some(&json!({"mode": "rule"})), Some(&proxies("DIRECT")), Some(&providers), &before).unwrap_err().contains("interface"));
        assert!(reload_findings(&prepared, None, Some(&proxies("DIRECT")), Some(&providers), &before).is_err(), "no answer is no proof");
        let renamed = json!({"proxies": {"G": {"type": "Selector", "now": "New", "all": ["New"]}, "Added": {"type": "Selector", "now": "New", "all": ["New"]}}});
        assert!(reload_findings(&prepared, Some(&configs), Some(&renamed), Some(&providers), &before).is_ok());
        let unchanged = json!({"proxies": {"G": {"type": "Selector", "now": "New", "all": ["New", "DIRECT"]}}});
        assert!(reload_findings(&prepared, Some(&configs), Some(&unchanged), Some(&providers), &before).is_err());

        // When tailscale_sniffer is required, reload_findings MUST require `configs["sniffing"] == true`.
        let mut sniff_prepared = prepared.clone();
        sniff_prepared.tailscale_sniffer = true;
        assert!(reload_findings(&sniff_prepared, Some(&configs), Some(&proxies("DIRECT")), Some(&providers), &before).is_err());
        assert!(reload_findings(&sniff_prepared, Some(&json!({"mode": "rule", "interface-name": "ath20", "sniffing": false})), Some(&proxies("DIRECT")), Some(&providers), &before).is_err());
        assert!(reload_findings(&sniff_prepared, Some(&json!({"mode": "rule", "interface-name": "ath20", "sniffing": true})), Some(&proxies("DIRECT")), Some(&providers), &before).is_ok());
    }

    /// Q2: the core never refreshes a rule set by itself; the controller
    /// does, at the subscription's interval.
    #[test]
    fn http_rule_sets_lose_their_interval_and_the_controller_keeps_it() {
        let source = "rule-providers:\n  Web: {type: http, behavior: ipcidr, url: 'https://x', path: ./w.yaml, interval: 86400}\n  Local: {type: file, behavior: classical, path: ./l.list, interval: 60}\n  Inline: {type: inline, behavior: domain, payload: [a.example]}\nrules: ['RULE-SET,Web,DIRECT', 'MATCH,DIRECT']\n";
        let (config, routes) = config_with_lan_host(source, "private", None, true).unwrap();
        let v: Yaml = serde_yaml_ng::from_str(&config).unwrap();
        assert!(v["rule-providers"]["Web"]["interval"].is_null());
        assert_eq!(v["rule-providers"]["Web"]["url"].as_str(), Some("https://x"));
        assert_eq!(v["rule-providers"]["Local"]["interval"].as_u64(), Some(60), "a file set is reloaded on change anyway; the plan treats it as unknown");
        assert_eq!(routes.refresh(), [("Web".to_owned(), 86400)]);
    }

    #[test]
    fn a_validated_reload_candidate_is_reused_without_overwriting_the_serving_config() {
        use controller::Port;
        use std::os::unix::fs::PermissionsExt;
        let temp = test_dir::TestDir::new("reload-validation");
        let dir = temp.path().to_path_buf();
        let mihomo = Arc::new(Mihomo::for_test(dir.clone()));
        net::write_private(&dir.join("mihomo"), b"#!/bin/sh\nprintf x >> \"$3/check-count\"\n").unwrap();
        fs::set_permissions(dir.join("mihomo"), fs::Permissions::from_mode(0o700)).unwrap();
        net::write_private(&dir.join("config.yaml"), b"serving config").unwrap();
        let mapping: Yaml = serde_yaml_ng::from_str("interface-name: ath20\nrules: ['MATCH,DIRECT']\n").unwrap();
        let config = serde_yaml_ng::to_string(&mapping).unwrap();
        let prepared = Prepared {
            secret: "s".into(), local: "u60.home.arpa".into(), runtime: json!({"mode":"rule"}),
            routes: routing::Routes::default(), dns: Default::default(), bypass: false, tailscale_sniffer: false, notice: None,
            facts: reload::Facts::from(&mapping),
            source: "rules: ['MATCH,DIRECT']".into(), config,
            egress: egress::Binding { uplink: egress::Uplink::sample("ath20", 9, "192.0.2.2", None), generation: 1 },
        };
        let mut port = DevicePort::new(Arc::clone(&mihomo), "u60.home.arpa".into());
        port.lan = Some(std::net::Ipv4Addr::LOCALHOST);
        port.validator(&prepared, true).unwrap()().unwrap();
        let first = port.prepare(&Source::Previous(Box::new(prepared)), true, Default::default()).unwrap();
        assert!(first.facts.runtime.get("interface-name").is_none());
        assert!(serde_yaml_ng::from_str::<Yaml>(&first.config).unwrap().get("interface-name").is_none());
        port.validator(&first, false).unwrap()().unwrap();
        assert_eq!(fs::read(dir.join("check-count")).unwrap(), b"x");
        assert_eq!(fs::read(dir.join("config.yaml")).unwrap(), b"serving config");
        assert!(!dir.join("candidate.yaml").exists());
        let remembered = remembered_validation(&dir);
        if net::boot_id().is_empty() {
            assert!(remembered.is_empty());
        } else {
            assert_eq!(remembered, *mihomo.validated_config.lock().unwrap());
        }
    }

    #[test]
    fn validation_does_not_cache_a_replaced_core_or_a_failed_candidate() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir::TestDir::new("validation-dependencies");
        let root = dir.path();
        let m = Mihomo::for_test(root.to_owned());
        let fake = br#"#!/bin/sh
printf x >> "$3/check-count"
if [ -f "$3/mihomo.next" ]; then mv "$3/mihomo.next" "$3/mihomo" || exit; fi
[ ! -e "$3/fail" ]
"#;
        for name in ["mihomo", "mihomo.next"] {
            let path = root.join(name);
            fs::write(&path, fake).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(root.join("config.yaml"), "serving bytes").unwrap();
        let check = |file, config| m.validate_candidate(file, config, "test-secret", &[], file == "candidate.yaml");
        let candidate = "rules: ['MATCH,DIRECT']";
        check("candidate.yaml", candidate).unwrap();
        assert!(m.validated_config.lock().unwrap().is_empty());
        assert!(!root.join("candidate.yaml").exists());
        check("candidate.yaml", candidate).unwrap();
        check("candidate.yaml", candidate).unwrap();
        assert_eq!(fs::read(root.join("check-count")).unwrap(), b"xx");
        let different = "rules: ['MATCH,REJECT']";
        fs::write(root.join("fail"), "").unwrap();
        for file in ["candidate.yaml", "check.yaml"] {
            assert_eq!(check(file, different).unwrap_err(), "Mihomo could not validate the configuration; check YAML, nodes, providers and rule databases");
            assert!(!root.join(file).exists());
            assert_eq!(fs::read(root.join("config.yaml")).unwrap(), b"serving bytes");
            assert_eq!(m.validated_config.lock().unwrap().len(), 1);
        }
        fs::remove_file(root.join("fail")).unwrap();
        check("check.yaml", different).unwrap();
        assert_eq!(fs::read(root.join("check-count")).unwrap(), b"xxxxx");
    }

    fn dashboard_zip(path: &str, method: zip::CompressionMethod, write: impl FnOnce(&mut zip::ZipWriter<std::io::Cursor<Vec<u8>>>)) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zip.start_file(path, zip::write::SimpleFileOptions::default().compression_method(method)).unwrap();
        write(&mut zip);
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn extract_ui_rejects_invalid_paths_symlinks_and_oversized_archives() {
        use std::io::Write;
        use zip::{write::SimpleFileOptions, CompressionMethod::Stored};
        let dir = test_dir::TestDir::new("extract-boundaries");
        let stage = dir.path().join("stage");
        assert_eq!(extract_ui(b"not a ZIP", &stage).unwrap_err(), "Invalid dashboard ZIP");
        let traversal = dashboard_zip("dist/../../escaped", Stored, |zip| zip.write_all(b"escape").unwrap());
        assert_eq!(extract_ui(&traversal, &stage).unwrap_err(), "Unsafe dashboard archive path");
        assert!(!dir.path().join("escaped").exists());
        let missing = dashboard_zip("dist/main.js", Stored, |zip| zip.write_all(b"missing index").unwrap());
        assert_eq!(extract_ui(&missing, &stage).unwrap_err(), "Dashboard index.html missing");
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zip.add_symlink("dist/index.html", "../escaped", SimpleFileOptions::default()).unwrap();
        assert_eq!(extract_ui(&zip.finish().unwrap().into_inner(), &stage).unwrap_err(), "Dashboard symlinks are not allowed");
        const LIMIT: u64 = 32 * 1024 * 1024;
        let large = |size| dashboard_zip("dist/index.html", zip::CompressionMethod::Deflated, |zip| {
            std::io::copy(&mut std::io::repeat(0).take(size), zip).unwrap();
        });
        extract_ui(&large(LIMIT), &stage).unwrap();
        assert_eq!(fs::metadata(stage.join("index.html")).unwrap().len(), LIMIT);
        assert_eq!(extract_ui(&large(LIMIT + 1), &stage).unwrap_err(), "Dashboard archive too large");
    }

    #[test]
    fn extract_ui_reads_stored_and_deflated_bytes_and_rejects_a_bad_crc() {
        use std::io::Write;
        use zip::CompressionMethod::{Deflated, Stored};
        let dir = test_dir::TestDir::new("extract-crc");
        let stage = dir.path().join("stage");
        let contents = b"dashboard contents for checksum test";
        for method in [Stored, Deflated] {
            let archive = dashboard_zip("dist/index.html", method, |zip| zip.write_all(contents).unwrap());
            extract_ui(&archive, &stage).unwrap();
            assert_eq!(fs::read(stage.join("index.html")).unwrap(), contents);
        }
        let mut archive = dashboard_zip("dist/index.html", Stored, |zip| zip.write_all(contents).unwrap());
        let at = archive.windows(contents.len()).position(|window| window == contents).unwrap();
        archive[at] ^= 1;
        assert_eq!(extract_ui(&archive, &stage).unwrap_err(), "Invalid checksum");
    }

    #[test]
    fn install_checks_gzip_elf_and_size_before_replacing_installed_files() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        const LIMIT: u64 = 100 * 1024 * 1024;
        let dir = test_dir::TestDir::new("install-boundaries");
        let root = dir.path();
        let m = Mihomo::for_test(root.to_owned());
        fs::create_dir(root.join("ui")).unwrap();
        fs::write(root.join("ui/index.html"), b"old ui").unwrap();
        fs::write(root.join("mihomo"), b"old core").unwrap();
        let gzip = |prefix: &[u8], size| {
            let mut out = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            out.write_all(prefix).unwrap();
            std::io::copy(&mut std::io::repeat(0).take(size - prefix.len() as u64), &mut out).unwrap();
            out.finish().unwrap()
        };
        for (body, error) in [
            (Err("Download SHA256 verification failed".into()), "Download SHA256 verification failed"),
            (Ok(b"not gzip".to_vec()), "Cannot decompress Mihomo"),
            (Ok(gzip(b"not ELF", 7)), "Invalid Mihomo binary"),
            (Ok(gzip(b"\x7fELF", LIMIT + 1)), "Invalid Mihomo binary"),
        ] {
            assert_eq!(m.install_from(|url, sha, max| {
                assert_eq!((url, sha, max), (CORE_URL, CORE_SHA, 32 * 1024 * 1024));
                body.clone()
            }).unwrap_err(), error);
            assert_eq!(fs::read(root.join("mihomo")).unwrap(), b"old core");
            assert_eq!(fs::read(root.join("ui/index.html")).unwrap(), b"old ui");
        }
        let mut requested = Vec::new();
        m.install_from(|url, _, max| {
            requested.push(max);
            if url == CORE_URL { return Ok(gzip(b"\x7fELF", LIMIT)); }
            if url == UI_URL {
                return Ok(dashboard_zip("dist/index.html", zip::CompressionMethod::Stored, |zip| zip.write_all(b"new ui").unwrap()));
            }
            Ok(b"license".to_vec())
        }).unwrap();
        assert_eq!(requested, [32 * 1024 * 1024, 8 * 1024 * 1024, 64 * 1024, 8 * 1024]);
        let binary = fs::metadata(root.join("mihomo")).unwrap();
        assert_eq!((binary.len(), binary.permissions().mode() & 0o777), (LIMIT, 0o700));
        assert_eq!(fs::read(root.join("ui/index.html")).unwrap(), b"new ui");
        assert_eq!(fs::read(root.join("ui.previous/index.html")).unwrap(), b"old ui");
        for file in ["LICENSE-Mihomo-GPL-3.0.txt", "LICENSE-Zashboard-MIT.txt"] {
            assert_eq!(fs::read(root.join(file)).unwrap(), b"license");
        }
    }

    #[test]
    fn a_config_fingerprint_ignores_only_the_per_start_secret_and_the_egress_interface() {
        let config = |secret: &str, interface: &str| {
            format!("secret: {secret}\nlisteners: [{{password: {secret}}}]\ninterface-name: {interface}\nproxies:\n- name: a\n  interface-name: {interface}\n")
        };
        let a = config_fingerprint(&config("aaaa", "ath20"), "aaaa");
        assert_eq!(a, config_fingerprint(&config("bbbb", "ath20"), "bbbb"));
        let top = |interface: &str| format!("secret: s\n{interface}mode: rule\n");
        assert_eq!(config_fingerprint(&top(""), "s"), config_fingerprint(&top("interface-name: ath20\n"), "s"), "relay or cellular: the same validation");
        assert_ne!(a, config_fingerprint(&config("aaaa", "rmnet0"), "aaaa"), "anything nested still counts");
        assert_ne!(config_fingerprint(&top(""), "s"), config_fingerprint("secret: s\nmode: global\n", "s"));
    }

    #[test]
    fn transparent_plan_tunes_the_kernel_and_restores_the_values_it_found() {
        let steps = resource_steps(|key| Ok(format!("old-{key}"))).unwrap();
        for (key, value) in [
            ("bridge-nf-call-iptables", "0"),
            ("bridge-nf-call-ip6tables", "0"),
        ] {
            let step = steps
                .iter()
                .find(|s| s.apply.program == "@u60-sysctl" && s.apply.args[0] == key)
                .expect("kernel setting");
            assert_eq!(step.apply.args, [key, value]);
            assert_eq!(step.undo.args, [key.to_owned(), format!("old-{key}")]);
        }
        for family in ["-4", "-6"] {
            assert!(steps.iter().any(|s| s.apply.args[0] == family
                && s.apply.args[1] == "route"
                && s.apply.args.iter().any(|a| a == "local")
                && s.apply.args.windows(2).any(|w| w == ["table", TABLE])));
            assert!(steps.iter().any(|s| s.apply.args[0] == family
                && s.apply.args.windows(2).any(|w| w == ["pref", PREF])
                && s.apply.args.windows(2).any(|w| w == ["fwmark", MARK])));
        }
        assert!(steps.iter().all(|s| !s.apply.args.iter().any(|a| a == "-F" || a == "flush")));
        assert!(resource_steps(|_| Err("unreadable".into())).is_err());
        // The tables' undo is what every agent since the TPROXY release runs.
        let undo = &steps.last().unwrap().undo;
        assert_eq!((undo.program.as_str(), undo.args.as_slice()), ("@u60-mihomo-nft", &["remove".to_owned()][..]));
        assert!(nft_command(&["tables".into()]).is_ok() && nft_command(&["bogus".into()]).is_err());
    }

    #[test]
    fn off_status_has_no_dashboard_and_creates_nothing() {
        let temp = test_dir::TestDir::new("mihomo-no-side-effects");
        let dir = temp.path().join("mihomo");
        let m = Mihomo::for_test(dir.clone());
        assert_eq!(m.status()["running"], false);
        assert!(m.status()["dashboard"].is_null());
        assert!(!dir.exists());
    }

    #[test]
    fn dns_is_always_fake_ip_with_a_rule_filter_from_the_routing_rules() {
        let source = "dns: {enhanced-mode: redir-host, fake-ip-range: 10.0.0.1/8, fake-ip-range6: 'fdfe:dcba:9876::1/64', fake-ip-filter: ['+.corp.example']}\nproxy-groups: [{name: P, type: select, proxies: [JP]}]\nrules: ['DOMAIN-SUFFIX,x.com,P', 'GEOSITE,CN,DIRECT', 'GEOIP,CN,DIRECT', 'MATCH,P']\n";
        let v: Yaml = serde_yaml_ng::from_str(&managed_config(source, "private").unwrap()).unwrap();
        let dns = &v["dns"];
        assert_eq!(dns["enhanced-mode"].as_str(), Some("fake-ip"));
        assert_eq!(dns["fake-ip-range"].as_str(), Some(routing::FAKE_RANGE));
        assert!(dns["fake-ip-range6"].is_null(), "an IPv6 pool would fall in the ULA range the kernel returns early");
        assert_eq!(dns["fake-ip-ttl"].as_u64(), Some(1));
        assert_eq!(dns["fake-ip-filter-mode"].as_str(), Some("rule"));
        let filter: Vec<&str> = dns["fake-ip-filter"].as_sequence().unwrap().iter().filter_map(Yaml::as_str).collect();
        let at = |e: &str| filter.iter().position(|f| *f == e).unwrap_or_else(|| panic!("missing {e}"));
        // The rules first: a name a rule sends to a group stays fake even if
        // the subscription's own list names it (Q3); then that list.
        assert!(at("DOMAIN-SUFFIX,x.com,fake-ip") < at("GEOSITE,CN,real-ip"));
        assert!(at("GEOSITE,CN,real-ip") < at("DOMAIN-SUFFIX,corp.example,real-ip"));
        assert_eq!(filter.last(), Some(&"MATCH,real-ip"));
        assert_eq!(v["profile"]["store-selected"].as_bool(), Some(true));
        assert_eq!(v["profile"]["store-fake-ip"].as_bool(), Some(true));
    }

    #[test]
    fn managed_dns_preserves_the_current_custom_https_management_name() {
        let source = "hosts: {router.home.arpa: 8.8.8.8, example.test: 1.1.1.1}\ndns: {use-hosts: false, nameserver: [9.9.9.9]}\n";
        let (config, _) = config_with_lan_host(
            source,
            "private",
            Some(("router.home.arpa", "192.168.8.1".parse().unwrap())),
            true,
        )
        .unwrap();
        let v: Yaml = serde_yaml_ng::from_str(&config).unwrap();
        assert_eq!(v["hosts"]["router.home.arpa"].as_str(), Some("192.168.8.1"));
        assert_eq!(v["hosts"]["example.test"].as_str(), Some("1.1.1.1"));
        assert_eq!(v["dns"]["use-hosts"].as_bool(), Some(true));
        assert_eq!(v["dns"]["nameserver"][0].as_str(), Some("9.9.9.9"));
        assert!(config_with_lan_host(
            "hosts: []",
            "private",
            Some(("u60.home.arpa", "192.168.0.1".parse().unwrap())),
            true,
        )
        .is_err());
    }

    #[test]
    fn core_operations_refuse_while_installing_without_occupying_the_network_lock() {
        let temp = test_dir::TestDir::new("core-busy");
        let dir = temp.path().join("mihomo");
        let lock = Arc::new(crate::netfx::admission::Gate::new());
        let m = Mihomo::for_test(dir.clone());
        let _operation = m.operation.lock().unwrap();
        assert!(
            crate::netfx::admission::enter(&lock, Duration::ZERO).is_some(),
            "install serialization must not stall the relay watchdog"
        );
        assert_eq!(m.install().unwrap_err(), "A Mihomo operation is in progress");
        // M10: the relay's egress news while the core is off or being
        // installed is no error and starts nothing.
        m.uplink_changed();
        assert!(m.snapshot().error.is_none() && !m.running());
        assert!(!dir.exists());
    }

    /// The owner's choice outlives restarts until it is turned off or a
    /// start the owner asked for fails. The port fixture fails preparation
    /// and delegates restart marker operations to Mihomo.
    #[test]
    fn owner_choice_outlives_restarts_until_turned_off_or_failing() {
        let temp = test_dir::TestDir::new("core-wanted");
        let dir = temp.path().to_path_buf();
        let m = Arc::new(Mihomo::for_test(dir.clone()));
        net::write_private(&dir.join(WANTED), b"1").unwrap();
        assert!(m.wants_restore());
        assert_eq!(m.status_with(|| Err("none".into()), || None)["autostart"], true);
        let controller = controller::tests::Harness::for_mihomo(&m);
        // The owner saw it fail: a restart must not retry it.
        assert_eq!(m.enable("u60.home.arpa").unwrap_err(), "fixture rejected the start");
        assert!(!m.wants_restore());
        assert_eq!(m.snapshot().phase, Phase::Off);
        net::write_private(&dir.join(WANTED), b"1").unwrap();
        m.disable().unwrap();
        assert!(!m.wants_restore());
        // Nothing wanted: returns at once and changes nothing.
        m.restore("u60.home.arpa");
        assert!(!m.running() && m.snapshot().phase == Phase::Off);
        drop(controller);
    }

    #[test]
    fn restore_marker_write_and_delete_failures_are_reported() {
        let temp = test_dir::TestDir::new("core-marker");
        let dir = temp.path().to_path_buf();
        let m = Arc::new(Mihomo::for_test(dir.clone()));
        std::fs::create_dir_all(dir.join(WANTED)).unwrap();
        assert!(net::write_private(&dir.join(WANTED), b"1").is_err());
        assert_eq!(m.set_wanted(false).unwrap_err(), "Cannot clear Mihomo's restart setting");
        let controller = controller::tests::Harness::for_mihomo(&m);
        let error = m.enable("u60.home.arpa").unwrap_err();
        assert!(error.contains("Cannot clear Mihomo's restart setting"), "{error}");
        drop(controller);
    }

    #[test]
    fn managed_nodes_and_provider_refresh_cannot_override_selected_uplink() {
        let config = managed_config(
            r#"
proxies:
  - {name: DirectTest, type: direct, interface-name: rmnet_data0, routing-mark: 1234}
proxy-groups:
  - {name: Select, type: select, proxies: [DirectTest], interface-name: rmnet_data0}
proxy-providers:
  Hotel:
    type: inline
    payload: [{name: Supplied, type: direct, interface-name: rmnet_data0}]
    override:
      interface-name: rmnet_data0
      routing-mark: 1234
      override-expr: ['true']
hosts: {interface-name: 192.0.2.1}
"#,
            "private",
        )
        .unwrap();
        let v: Yaml = serde_yaml_ng::from_str(&config).unwrap();
        assert!(v["proxies"][0]["interface-name"].is_null());
        assert!(v["proxies"][0]["routing-mark"].is_null());
        assert!(v["proxy-groups"][0]["interface-name"].is_null());
        assert!(v["proxy-providers"]["Hotel"]["payload"][0]["interface-name"].is_null());
        assert_eq!(
            v["proxy-providers"]["Hotel"]["override"]["interface-name"].as_str(),
            Some("")
        );
        assert_eq!(
            v["proxy-providers"]["Hotel"]["override"]["routing-mark"].as_i64(),
            Some(0x0100_0000)
        );
        assert!(v["proxy-providers"]["Hotel"]["override"]["override-expr"].is_null());
        assert_eq!(v["hosts"]["interface-name"].as_str(), Some("192.0.2.1"));
        assert_eq!(v["profile"]["store-selected"].as_bool(), Some(true));
    }

    #[test]
    fn tailscale_only_rule_provider_revisions_do_not_accumulate() {
        use controller::Port;
        let temp = test_dir::TestDir::new("core-ts-sources");
        let dir = temp.path().to_path_buf();
        let provider_path = dir.join("ruleset/direct.yaml");
        std::fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        std::fs::write(&provider_path, "payload:\n  - '1.2.3.0/24'\n").unwrap();

        let m = Arc::new(Mihomo::for_test(dir.clone()));
        let mut port = DevicePort::new(m, "u60.home.arpa".into());
        let doc: Yaml = serde_yaml_ng::from_str(
            "rule-providers:\n  direct_ip:\n    type: http\n    behavior: ipcidr\n    path: ./ruleset/direct.yaml\nrules:\n  - RULE-SET,direct_ip,DIRECT\n  - MATCH,P\n",
        )
        .unwrap();
        let routes = routing::Routes::from(&doc);
        let selected = routing::Selected::new();

        // Revision 1 with LAN bypass OFF and Tailscale Strategy B active.
        port.plan(&routes, false, routing::Mode::Rule, &selected, &[]);
        let chain1 = port.plan_tailscale(&routes, routing::Mode::Rule, &selected, &[]);
        assert_eq!(chain1.returns, 1);
        assert_eq!(port.sources.len(), 1);
        assert!(!port.sources_changed());

        // Rewrite provider content across multiple revisions: `sources` must
        // keep exactly one current entry per path (never retaining obsolete digests).
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&provider_path, "payload:\n  - '4.5.6.0/24'\n").unwrap();
        assert!(port.sources_changed());
        port.plan(&routes, false, routing::Mode::Rule, &selected, &[]);
        let chain2 = port.plan_tailscale(&routes, routing::Mode::Rule, &selected, &[]);
        assert_eq!(chain2.returns, 1);
        assert_eq!(port.sources.len(), 1, "revisions for the same provider path must replace, not accumulate");
        assert!(!port.sources_changed(), "no obsolete source revision may trigger perpetual changes");

        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&provider_path, "payload:\n  - '7.8.9.0/24'\n").unwrap();
        port.plan(&routes, false, routing::Mode::Rule, &selected, &[]);
        let _ = port.plan_tailscale(&routes, routing::Mode::Rule, &selected, &[]);
        assert_eq!(port.sources.len(), 1);
        assert!(!port.sources_changed());

        // When LAN bypass is ALSO on and reads the same file, deduplicate by path.
        port.plan(&routes, true, routing::Mode::Rule, &selected, &[]);
        let _ = port.plan_tailscale(&routes, routing::Mode::Rule, &selected, &[]);
        assert_eq!(port.sources.len(), 1);
        assert!(!port.sources_changed());

        // Mid-pass provider mutation between LAN `plan()` (rev A) and Tailscale
        // `plan_tailscale()` (rev B) MUST mark sources diverged so the next
        // `sources_changed()` forces recompiling both chains consistently even
        // though disk already matches rev B!
        port.plan(&routes, true, routing::Mode::Rule, &selected, &[]);
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&provider_path, "payload:\n  - '9.9.9.0/24'\n").unwrap();
        let _ = port.plan_tailscale(&routes, routing::Mode::Rule, &selected, &[]);
        assert_eq!(port.sources.len(), 1, "merged sources still keep one entry per path");
        assert!(
            port.sources_changed(),
            "differing LAN/Tailscale observations for the same path must force a recompile"
        );
        // Once both chains recompile from the same rev B, divergence clears.
        port.plan(&routes, true, routing::Mode::Rule, &selected, &[]);
        let _ = port.plan_tailscale(&routes, routing::Mode::Rule, &selected, &[]);
        assert_eq!(port.sources.len(), 1);
        assert!(!port.sources_changed());

        // When Tailscale planning stops and LAN bypass is off, stale sources clear.
        port.plan(&routes, false, routing::Mode::Rule, &selected, &[]);
        assert!(port.sources.is_empty());
        assert!(!port.sources_changed());
    }
}
