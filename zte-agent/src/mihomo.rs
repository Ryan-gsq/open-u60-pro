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
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use serde_yaml_ng::{Mapping, Value as Yaml};
use sha2::{Digest, Sha256};

use crate::net_tools::{self as net, Cmd, NetworkLock, Step, Transaction};
use crate::netfx::effect::{self, NftTables, Presence};
use crate::netfx::ids;

pub mod control;
mod controller;
mod core;
pub mod dashboard;
mod dns;
mod download;
mod egress;
mod geodata;
mod geoip;
mod intercept;
pub mod profiles;
mod reload;
mod routing;
pub mod transform;

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
/// Present while the owner lets IPv4 the rules send DIRECT skip the core
/// (`routing`); the name is from when this was China IP direct.
const BYPASS: &str = "cn-direct";
/// The tables' batch file (`netfx::effect::NftTables`).
const NFT_FILE: &str = "nft-tables.nft";
pub const MAX_CONFIG: usize = 512 * 1024;
/// How long an owner command waits for the controller.
const COMMAND_WAIT: Duration = Duration::from_secs(150);

pub struct Mihomo {
    root: PathBuf,
    /// Excludes installation, configuration and owner starts.
    operation: Mutex<()>,
    profile_operation: Mutex<()>,
    profile_wake: Condvar,
    profile_revision: Mutex<u64>,
    library_revision: AtomicU64,
    status_cache: Mutex<Option<(profiles::LibraryStamp, Value)>>,
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
}

impl Mihomo {
    pub fn new(lock: NetworkLock) -> Self {
        Self::at(PathBuf::from(ROOT), lock)
    }

    fn at(root: PathBuf, _lock: NetworkLock) -> Self {
        let validated = remembered_validation(&root);
        Self {
            root,
            operation: Mutex::new(()),
            profile_operation: Mutex::new(()),
            profile_wake: Condvar::new(),
            profile_revision: Mutex::new(0),
            library_revision: AtomicU64::new(0),
            status_cache: Mutex::new(None),
            validated_config: Mutex::new(validated),
            digests: geodata::Digests::default(),
            subscription_dns: Mutex::new(Vec::new()),
            passes: dashboard::Passes::default(),
            geoip: geoip::Cache::default(),
            shared: Arc::new(Mutex::new(Snapshot::default())),
            commands: Mutex::new(None),
        }
    }

    /// A running core with this secret, for the bridge's tests.
    #[cfg(test)]
    pub(crate) fn for_bridge(root: PathBuf, lock: NetworkLock, secret: String) -> Self {
        let this = Self::at(root, lock);
        let mut snapshot = this.snapshot();
        snapshot.phase = Phase::Running;
        snapshot.secret = Some(secret);
        *this.shared.lock().unwrap() = snapshot;
        this
    }

    fn journal(&self) -> PathBuf {
        self.root.join("network.json")
    }

    fn snapshot(&self) -> Snapshot {
        self.shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }

    pub fn status(&self) -> Value {
        self.status_with(|| self.profile_status())
    }

    fn status_with(&self, profiles: impl FnOnce() -> Result<Value, String>) -> Value {
        let installed = self.root.join("mihomo").is_file();
        let configured = profiles().ok().is_some_and(|p| p["selected"].is_string());
        let journal = self.journal().exists();
        let s = self.snapshot();
        let running = s.running();
        let kernel = s.bypass.as_ref().filter(|_| running).map(|bypass| {
            json!({"mode": s.mode.map(routing::Mode::name), "bypass": bypass.label(),
                "returns": match bypass { controller::Bypass::Rules { returns, .. } => Some(*returns), _ => None },
                "reason": match bypass { controller::Bypass::None(reason) | controller::Bypass::Rules { cut: Some(reason), .. } => Some(reason), _ => None }})
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
            "cn_direct": self.root.join(BYPASS).is_file(),
            "cn_direct_active": running && s.bypass.as_ref().is_some_and(|b| !matches!(b, controller::Bypass::None(_))),
            "kernel": kernel, "tables": s.tables, "generation": s.generation,
            "autostart": self.wants_restore(), "recovery_required": s.phase == Phase::CleanupPending || (s.phase == Phase::Off && journal),
            "connections_reset": s.last_reset, "connection_resets": crate::netfx::conntrack::history()})
    }

    pub fn running(&self) -> bool {
        self.snapshot().running()
    }

    /// How much public LAN IPv4 the core intercepts: `all`, `rules` (what
    /// its DIRECT rules let skip it does not) or `none`.
    pub fn ipv4_share(&self) -> &'static str {
        let s = self.snapshot();
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
        let s = self.snapshot();
        s.running().then_some(s.secret).flatten()
    }

    pub fn dashboard_root(&self) -> PathBuf {
        self.root.join("ui")
    }

    /// `network-recover`: rolls back what a previous process left.
    pub fn recover(&self) -> Result<(), String> {
        Transaction::recover(&self.journal())
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
        let guard = std::sync::Mutex::new(tx.clone());
        crate::net_guard::on_settled(move || {
            let _ = guard.lock().unwrap_or_else(std::sync::PoisonError::into_inner).send(Message::Guard);
        });
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
        let core = self.download(CORE_URL, CORE_SHA, 32 * 1024 * 1024)?;
        let mut binary = Vec::new();
        flate2::read::GzDecoder::new(core.as_slice())
            .take(100 * 1024 * 1024 + 1)
            .read_to_end(&mut binary)
            .map_err(|_| "Cannot decompress Mihomo")?;
        if binary.len() > 100 * 1024 * 1024 || !binary.starts_with(b"\x7fELF") {
            return Err("Invalid Mihomo binary".into());
        }
        let ui = self.download(UI_URL, UI_SHA, 8 * 1024 * 1024)?;
        let core_license = self.download(
            "https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.33/LICENSE",
            "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
            64 * 1024,
        )?;
        let ui_license = self.download(
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

    fn validation_fingerprint(&self, config: &str, secret: &str) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        let core = fs::metadata(self.root.join("mihomo")).ok()?;
        let dependencies = geodata::validation_inputs(&self.root, config, &self.digests)?;
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
        let started = Instant::now();
        let result = net::run(c, Duration::from_secs(30));
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
        if enabled {
            net::write_private(&flag, b"1")?;
        } else {
            match fs::remove_file(&flag) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err("Cannot clear the DIRECT bypass setting".into())
                }
                _ => {}
            }
        }
        if self.snapshot().phase == Phase::Off {
            return Ok(());
        }
        self.command(|reply| Message::Bypass { reply })
    }

    /// The selected profile changed; refreshes reload a healthy core.
    fn config_changed(&self, refresh: bool) -> Result<(), String> {
        if !refresh && matches!(self.snapshot().phase, Phase::Off | Phase::CleanupPending) {
            return Ok(());
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
            // `for_bridge`: no controller; the write reaches the core as is.
            let secret = self.secret().ok_or("Mihomo is off")?;
            return tokio::task::spawn_blocking(move || control::raw_call(CONTROLLER, &secret, write.method, &write.segments, &write.body, Duration::from_secs(5)))
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
        self.snapshot().phase == Phase::Running
    }

    /// The relay changed its routes. Never blocks the relay (I2).
    pub(crate) fn uplink_changed(&self) {
        let _ = self.send(Message::Egress);
    }
}

/// The controller's device side: the core's files and process, the network
/// effects (`Transaction` for kernel settings and policy routes, `NftTables`
/// for the tables), the controller API, conntrack and the egress.
struct DevicePort {
    m: Arc<Mihomo>,
    local: String,
    lan: Option<std::net::Ipv4Addr>,
    effects: Option<Effects>,
    guard: crate::net_guard::Cursor,
    /// Rule-set files the last plan read.
    sources: Vec<routing::Source>,
}

struct Effects {
    tx: Transaction,
    tables: NftTables,
}

impl DevicePort {
    fn new(m: Arc<Mihomo>, local: String) -> Self {
        Self { m, local, lan: None, effects: None, guard: crate::net_guard::Cursor::default(), sources: Vec::new() }
    }

    fn owned_tables(&self) -> NftTables {
        NftTables::new("mihomo", NFT_TABLE, self.m.root.join(NFT_FILE))
    }

    /// Kernel settings and policy routes, with the original values `old` gives.
    fn steps(old: impl Fn(&str) -> Result<String, String>) -> Result<Vec<Step>, String> {
        proxy_plan_with(old)
    }
}

impl controller::Port for DevicePort {
    fn adoptable(&mut self) -> bool {
        Transaction::current(&self.m.journal()) && self.owned_tables().presence(&mut effect::Device).is_ok_and(|p| p == Presence::Ours)
    }

    fn recover(&mut self) -> Result<(), String> {
        self.effects = None;
        self.m.recover()
    }

    fn busy(&mut self) -> Option<String> {
        self.m.operation.try_lock().is_err().then(|| "A Mihomo operation is in progress".into())
    }

    fn prepare(&mut self, source: &Source, serving: bool) -> Result<Prepared, String> {
        let m = &self.m;
        let prepared = match source {
            Source::Previous(previous) => (**previous).clone(),
            Source::Reload(previous) | Source::Refresh(previous) => {
                let lan = lan_address()?;
                self.lan = Some(lan);
                let refresh = matches!(source, Source::Refresh(_));
                let bypass = if refresh { previous.bypass } else { m.root.join(BYPASS).is_file() };
                let source = if refresh { m.selected_source()? } else { previous.source.clone() };
                let (managed, routes) = config_with_lan_host(&source, &previous.secret, Some((&previous.local, lan)), bypass)?;
                let running: Yaml = serde_yaml_ng::from_str(&previous.config).map_err(|_| "Cannot parse the running configuration")?;
                let mut config: Yaml = serde_yaml_ng::from_str(&managed).map_err(|_| "Cannot parse managed configuration")?;
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
                let dns = routes.dns(bypass);
                let config = serde_yaml_ng::to_string(&config).map_err(|_| "Cannot encode managed configuration")?;
                let notice = geodata::bypass_notice(&config, bypass);
                Prepared { secret: previous.secret.clone(), local: previous.local.clone(), runtime: previous.runtime.clone(), routes, dns, bypass, notice, source, config }
            }
            Source::Selected { local, runtime } => {
                let local = if local.is_empty() { self.local.clone() } else { local.clone() };
                let source = m.selected_source()?;
                let mut random = [0u8; 32];
                getrandom::getrandom(&mut random).map_err(|_| "Random secret unavailable")?;
                let secret: String = random.iter().map(|b| format!("{b:02x}")).collect();
                let lan = lan_address()?;
                self.lan = Some(lan);
                let bypass = m.root.join(BYPASS).is_file();
                let (managed, routes) = config_with_lan_host(&source, &secret, Some((&local, lan)), bypass)?;
                let dns = routes.dns(bypass);
                let mut config: Yaml = serde_yaml_ng::from_str(&managed).map_err(|_| "Cannot parse managed configuration")?;
                // A user may have disabled cellular data while Wi-Fi is offline. Keep
                // the core available without creating a route or enabling the modem.
                if Cmd::new("ip", &["-4", "route", "get", "1.1.1.1"]).run().is_ok_and(|route| route.contains(&format!("dev {}", ids::RELAY_IFACE))) {
                    check_clock();
                    config.as_mapping_mut().unwrap().insert(Yaml::from("interface-name"), Yaml::from(ids::RELAY_IFACE));
                }
                // Always written, so a first start and a restart with the same
                // settings give the same text (the validation is reused).
                for (key, default) in [("mode", "rule"), ("log-level", "info")] {
                    let value = runtime.as_ref().and_then(|r| r[key].as_str()).or_else(|| config[key].as_str()).unwrap_or(default).to_owned();
                    config.as_mapping_mut().unwrap().insert(Yaml::from(key), Yaml::from(value));
                }
                let runtime = json!({"mode": config["mode"].as_str().unwrap_or("rule"), "log-level": config["log-level"].as_str().unwrap_or("info")});
                let config = serde_yaml_ng::to_string(&config).map_err(|_| "Cannot encode managed configuration")?;
                let notice = geodata::bypass_notice(&config, bypass);
                Prepared { secret, local, runtime, routes, dns, bypass, notice, source, config }
            }
        };
        geodata::prepare(&m.root, &prepared.config, &m.downloader())?;
        let fingerprint = m.validation_fingerprint(&prepared.config, &prepared.secret);
        let reused = fingerprint.as_ref().is_some_and(|key| m.validated_config.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains(key));
        if reused {
            crate::netlog!("[mihomo] validation reused");
        } else {
            net::write_private(&m.root.join("candidate.yaml"), prepared.config.as_bytes())?;
            let checked = m.check_with("candidate.yaml", serving);
            let _ = fs::remove_file(m.root.join("candidate.yaml"));
            checked?;
            // Only dependencies that stayed the same across the check passed it.
            let after = m.validation_fingerprint(&prepared.config, &prepared.secret);
            if let Some(key) = fingerprint.filter(|key| after.as_ref() == Some(key)) {
                let mut validated = m.validated_config.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                validated.retain(|k| *k != key);
                validated.insert(0, key);
                validated.truncate(VALIDATIONS_KEPT);
                remember_validation(&m.root, &validated);
            }
        }
        if self.lan.is_none() {
            self.lan = Some(lan_address()?);
        }
        Ok(prepared)
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
                for family in ["-4", "-6"] {
                    net::reserve("iptables", "mangle", &[], family, TABLE, PREF)?;
                }
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
                let mut steps = DevicePort::steps(net::sysctl_read)?;
                steps.push(tables_step());
                let mut tx = Transaction::new(self.m.journal());
                if let Err(e) = tx.apply_network(steps) {
                    return Err(tx.rollback().err().unwrap_or(e));
                }
                self.effects = Some(Effects { tx, tables });
                Ok(())
            }
            Engage::FromBackoff => {
                let effects = self.effects.as_mut().ok_or("Mihomo owns nothing to start from")?;
                effects.tx.apply_network(DevicePort::steps(net::sysctl_read)?)
            }
            Engage::Adopt => {
                let mut tx = Transaction::load(&self.m.journal())?;
                // The original values a previous agent journaled, never ours.
                let original = |key: &str| tx.journaled("@u60-sysctl", key).and_then(|u| u.args.get(1).cloned()).map_or_else(|| net::sysctl_read(key), Ok);
                let mut steps = DevicePort::steps(original)?;
                steps.push(tables_step());
                for step in steps {
                    tx.adopt(step)?;
                }
                self.effects = Some(Effects { tx, tables: self.owned_tables() });
                Ok(())
            }
        }
    }

    fn tables(&mut self, shape: intercept::Shape) -> Result<(), String> {
        let effects = self.effects.as_mut().ok_or("Mihomo owns no tables")?;
        effects.tables.declare(intercept::tables(shape), &mut effect::Device).map(|_| ())
    }

    fn tables_status(&mut self) -> Value {
        self.effects.as_ref().map_or(Value::Null, |e| e.tables.status())
    }

    fn direct(&mut self) -> Result<(), String> {
        let Some(effects) = self.effects.as_mut() else { return Ok(()) };
        effects.tables.declare(intercept::tables(intercept::Shape::FakeReject), &mut effect::Device)?;
        let undos: Vec<Cmd> = DevicePort::steps(|_| Ok(String::new()))?
            .into_iter()
            .filter(|s| s.undo.program != "@u60-sysctl")
            .map(|s| s.undo)
            .collect();
        // Kernel settings are released by key: their undo holds the original value.
        let settings: Vec<Cmd> = ["tcp_pacing_ss_ratio", "tcp_pacing_ca_ratio", "bridge-nf-call-iptables", "bridge-nf-call-ip6tables"]
            .iter()
            .filter_map(|key| effects.tx.journaled("@u60-sysctl", key).cloned())
            .collect();
        effects.tx.release(&[settings, undos].concat())
    }

    fn release_all(&mut self) -> Result<(), String> {
        match self.effects.as_mut() {
            Some(effects) => {
                effects.tx.rollback()?;
                self.effects = None;
                Ok(())
            }
            None => self.m.recover(),
        }
    }

    fn spawn(&mut self, generation: u64, prepared: &Prepared, exits: Sender<Message>) -> Result<Box<dyn controller::CoreHandle>, String> {
        net::write_private(&self.m.root.join("config.yaml"), prepared.config.as_bytes())?;
        let mut cmd = Command::new(self.m.root.join("mihomo"));
        // With cellular off and Relay disconnected B31 has only link-local
        // IPv6; the core must still listen on IPv6 to use the next uplink.
        cmd.env("SKIP_SYSTEM_IPV6_CHECK", "true");
        cmd.arg("-d").arg(&self.m.root).arg("-f").arg(self.m.root.join("config.yaml"));
        let core = core::Core::spawn(cmd, generation, move |generation, how| {
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
        let none = |why: String| (Bypass::None(why), routing::Chain::default());
        if !bypass {
            return none("Bypass for DIRECT rules is off".into());
        }
        match mode {
            routing::Mode::Global => none("Global mode sends everything through the proxy".into()),
            routing::Mode::Direct => (Bypass::All, routing::Chain::all()),
            routing::Mode::Rule => {
                let compiled = routes.compile(selected, &self.m.root, unsettled);
                let lists = self.m.geoip.get(&self.m.root, &compiled.geoip);
                let chain = compiled.render(&|code| match &lists {
                    Ok(lists) => lists.get(code).map(Vec::as_slice).ok_or_else(|| "not in GeoIP.dat".to_owned()),
                    Err(e) => Err(e.clone()),
                });
                self.sources = compiled.sources;
                if chain.returns == 0 {
                    return none(chain.cut.unwrap_or_else(|| "No rule sends IPv4 DIRECT by address".into()));
                }
                (Bypass::Rules { returns: chain.returns, cut: chain.cut.clone() }, chain)
            }
        }
    }

    fn reset(&mut self, reason: &'static str, scope: crate::netfx::conntrack::Scope, changed: Instant) -> Result<crate::netfx::conntrack::Report, String> {
        crate::netfx::conntrack::reset_since(reason, scope, changed)
    }

    fn write(&mut self, secret: &str, write: &controller::Write) -> Answered {
        control::raw_call(CONTROLLER, secret, write.method, &write.segments, &write.body, Duration::from_secs(30))
    }

    fn reload(&mut self, secret: &str, config: &str) -> Result<u16, String> {
        net::write_private(&self.m.root.join("config.yaml"), config.as_bytes())?;
        let agent = ureq::Agent::config_builder().proxy(None).http_status_as_error(false).timeout_global(Some(Duration::from_secs(15))).build().new_agent();
        agent
            .put(&format!("http://{CONTROLLER}/configs?force=false"))
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

    fn reconcile(&mut self) -> controller::Guarded {
        let Some(effects) = self.effects.as_mut() else { return controller::Guarded { result: Ok(()), confirmed: false } };
        let mut result = effects.tx.reconcile();
        match effects.tables.reconcile(&mut effect::Device) {
            Ok(true) => result.restored.push("nftables tables".into()),
            Ok(false) => {}
            Err(e) => result.failed.push(e),
        }
        let confirmed = effects.tables.confirmed();
        self.guard.after(&result);
        controller::Guarded { result: crate::net_guard::report("mihomo", result), confirmed }
    }

    fn wanted(&mut self) -> bool {
        self.m.wants_restore()
    }

    fn set_wanted(&mut self, on: bool) -> Result<(), String> {
        self.m.set_wanted(on)
    }

    fn sources_changed(&mut self) -> bool {
        self.sources.iter_mut().any(routing::Source::changed)
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

impl controller::CoreHandle for core::Core {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn pid(&self) -> u32 {
        core::Core::pid(self)
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
    let config: Yaml = serde_yaml_ng::from_str(&prepared.config).map_err(|_| "Invalid configuration")?;
    if configs["mode"].as_str() != prepared.runtime["mode"].as_str() {
        return Err(format!("the mode is {}", configs["mode"]));
    }
    if configs["interface-name"].as_str().unwrap_or("") != config["interface-name"].as_str().unwrap_or("") {
        return Err("the egress interface changed".into());
    }
    let selected = proxies.and_then(routing::selected_from).ok_or("Mihomo did not report its groups")?;
    if selected.iter().any(|(group, now)| now == "COMPATIBLE" && before.get(group).is_none_or(|old| old != "COMPATIBLE")) {
        return Err("a group fell back to COMPATIBLE".into());
    }
    let listing = proxies.ok_or("Mihomo did not report its groups")?;
    for (group, old) in before {
        let Some(current) = selected.get(group) else {
            if config["proxy-groups"].as_sequence().is_some_and(|groups| groups.iter().any(|entry| entry["name"].as_str() == Some(group))) {
                return Err("a configured group is missing".into());
            }
            continue;
        };
        if current != old && listing["proxies"][group]["all"].as_array().is_none_or(|members| members.iter().any(|member| member.as_str() == Some(old))) {
            return Err("a group's choice changed while its previous member still exists".into());
        }
    }
    for group in config["proxy-groups"].as_sequence().into_iter().flatten().filter(|group| group["type"].as_str() == Some("select")) {
        if group["name"].as_str().is_none_or(|name| !selected.contains_key(name)) {
            return Err("a configured selector is missing".into());
        }
    }
    let providers = providers.ok_or("Mihomo did not report its rule sets")?;
    if config["rule-providers"].as_mapping().into_iter().flatten().filter_map(|(name, _)| name.as_str()).any(|name| providers["providers"][name]["ruleCount"].as_u64().is_none_or(|count| count == 0)) {
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

/// The journal step for the tables (`NftTables` loads them): its undo is the
/// one every agent version since the TPROXY release runs.
fn tables_step() -> Step {
    Step::new(Cmd::new("@u60-mihomo-nft", &["tables"]), Cmd::new("@u60-mihomo-nft", &["remove"]))
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
    ureq::Agent::config_builder()
        .proxy(None)
        .timeout_global(Some(Duration::from_millis(300)))
        .build()
        .new_agent()
        .get(&format!("http://{CONTROLLER}/version"))
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
pub fn managed_config(source: &str, secret: &str) -> Result<String, String> {
    config_with_lan_host(source, secret, None, true).map(|(config, _)| config)
}

/// The managed configuration and its routing (`routing::Routes`, read
/// before DNS is rewritten), with the DNS filter for the DIRECT bypass
/// setting (`routing::Routes::dns`).
fn config_with_lan_host(
    source: &str,
    secret: &str,
    local: Option<(&str, std::net::Ipv4Addr)>,
    bypass: bool,
) -> Result<(String, routing::Routes), String> {
    if source.len() > MAX_CONFIG {
        return Err("Configuration exceeds 512 KiB".into());
    }
    let mut root: Yaml = serde_yaml_ng::from_str(source).map_err(|_| "Invalid Mihomo YAML")?;
    let routes = routing::Routes::from(&root);
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
    // relay's DNS output chain lets its own DNS keep its destination. Off
    // (no mark) until a bit is verified free on the device.
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
            set(overrides, "routing-mark", Yaml::from(0));
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
    set(dns, "fake-ip-filter", serde_yaml_ng::to_value(routes.dns(bypass)).map_err(|_| "Cannot encode the DNS filter")?);
    if !dns.contains_key(Yaml::from("nameserver")) {
        set(
            dns,
            "nameserver",
            serde_yaml_ng::to_value(["1.1.1.1", "8.8.8.8"]).unwrap(),
        );
    }
    validate_dns_routes(&root)?;
    let text = serde_yaml_ng::to_string(&root).map_err(|_| "Cannot encode Mihomo configuration")?;
    Ok((text, routes))
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
/// order; `old` reads a setting's original value (restored on release).
pub fn proxy_plan_with(old: impl Fn(&str) -> Result<String, String>) -> Result<Vec<Step>, String> {
    let mut steps = Vec::new();
    // The core's TCP towards the LAN leaves through qcacld, which leaves TSQ
    // at ~1 ms of data: one connection ran at ~60 instead of ~230 Mbit/s.
    for key in ["tcp_pacing_ss_ratio", "tcp_pacing_ca_ratio"] {
        steps.push(net::sysctl_step(key, "1000", &old(key)?)?);
    }
    // TPROXY loses its socket on the bridge-netfilter path (iptables and nft
    // alike); LAN-to-LAN filtering such as guest isolation pauses meanwhile.
    for key in ["bridge-nf-call-iptables", "bridge-nf-call-ip6tables"] {
        steps.push(net::sysctl_step(key, "0", &old(key)?)?);
    }
    for (family, all) in [("-4", "default"), ("-6", "::/0")] {
        steps.push(net::ip_step(family, "route", &["local", all, "dev", "lo", "table", TABLE]));
        steps.push(net::ip_step(family, "rule", &["pref", PREF, "fwmark", MARK, "lookup", TABLE]));
    }
    Ok(steps)
}

/// One controller read (the core's secret never leaves the router).
fn controller_get(secret: &str, path: &str) -> Option<Value> {
    ureq::Agent::config_builder()
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(2)))
        .build()
        .new_agent()
        .get(&format!("http://{CONTROLLER}{path}"))
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

/// Whether some socket listens on `port` (`/proc/net/tcp*`, hex port, state 0A).
fn listening(port: u16) -> bool {
    let needle = format!(":{port:04X} ");
    ["/proc/net/tcp6", "/proc/net/tcp"].iter().any(|path| {
        fs::read_to_string(path).is_ok_and(|text| {
            text.lines().skip(1).any(|line| {
                let f: Vec<&str> = line.split_whitespace().collect();
                f.len() > 3 && format!("{} ", f[1]).ends_with(&needle) && f[3] == "0A"
            })
        })
    })
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
        "cn-direct" => match serde_json::from_slice::<Value>(body)
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
mod tests {
    use super::*;

    #[test]
    fn a_validation_is_remembered_for_this_boot_only() {
        let dir = std::env::temp_dir().join(format!("u60-validated-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        remember_validation(&dir, &["abc:1:2".to_owned(), "def:3:4".to_owned()]);
        let boot = net::boot_id();
        let expected: Vec<String> = if boot.is_empty() { Vec::new() } else { vec!["abc:1:2".into(), "def:3:4".into()] };
        assert_eq!(remembered_validation(&dir), expected, "no boot id (not Linux): never reused");
        fs::write(dir.join(VALIDATED), "another-boot abc:1:2").unwrap();
        assert!(remembered_validation(&dir).is_empty(), "another boot's validation is not reused");
        remember_validation(&dir, &[]);
        assert!(!dir.join(VALIDATED).exists());
        assert!(Mihomo::at(dir.clone(), Arc::new(Mutex::new(()))).validated_config.lock().unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn slow_profile_status_does_not_hold_dashboard_runtime_mutex() {
        let m = Arc::new(Mihomo::for_bridge(
            std::env::temp_dir(),
            Arc::new(Mutex::new(())),
            "fixture".into(),
        ));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = {
            let m = Arc::clone(&m);
            std::thread::spawn(move || {
                m.status_with(|| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                    Ok(json!({"selected":"fixture"}))
                })
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

    /// v4 release blocker: while the relay holds the network lock (an
    /// association or a CAC of up to 80 s), Mihomo's owner commands, egress
    /// news and failure handling still run: the controller never takes it.
    #[test]
    fn mihomo_never_waits_for_the_relays_network_lock() {
        let dir = std::env::temp_dir().join(format!("u60-core-cac-{}", std::process::id()));
        let lock = Arc::new(Mutex::new(()));
        let m = Arc::new(Mihomo::at(dir.clone(), Arc::clone(&lock)));
        m.start("u60.home.arpa".into());
        let held = lock.lock().unwrap();
        let started = Instant::now();
        assert!(m.enable("u60.home.arpa").is_err(), "fails fast here (no ip/nft), but answers");
        m.uplink_changed();
        m.set_direct_bypass(true).unwrap();
        m.disable().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5), "{:?} with the relay's lock held", started.elapsed());
        drop(held);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn every_journaled_undo_is_one_the_previous_agent_runs() {
        const HEAD_SYSCTL: [&str; 4] = ["tcp_pacing_ss_ratio", "tcp_pacing_ca_ratio", "bridge-nf-call-iptables", "bridge-nf-call-ip6tables"];
        let mut undos: Vec<Cmd> = proxy_plan_with(|_| Ok("1".into())).unwrap().into_iter().map(|s| s.undo).collect();
        undos.push(tables_step().undo);
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
            "-4 rule del pref 18620 fwmark 0x700/0xff00 lookup 60625",
            "-6 route del local ::/0 dev lo table 60625",
            "-6 rule del pref 18620 fwmark 0x700/0xff00 lookup 60625",
        ]);
    }

    /// Writes the production table batches and the journal this version
    /// keeps, for the isolated Linux acceptance (`tests/mihomo-qa`). Run with
    /// `U60_MIHOMO_QA=<dir> cargo test -p zte-agent export_for_isolated_linux_acceptance -- --ignored`.
    #[test]
    #[ignore]
    fn export_for_isolated_linux_acceptance() {
        let dir = PathBuf::from(std::env::var_os("U60_MIHOMO_QA").expect("U60_MIHOMO_QA"));
        fs::create_dir_all(&dir).unwrap();
        let root = std::env::temp_dir().join(format!("u60-mihomo-qa-{}", std::process::id()));
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
        // The journal as `Transaction` writes it (the container fills in its
        // boot id and the original kernel values); bridge-netfilter keys are
        // left out where the container has no bridge sysctls.
        let mut steps = proxy_plan_with(|key| Ok(format!("{{{key}}}"))).unwrap();
        steps.push(tables_step());
        let undo: Vec<&Cmd> = steps.iter().map(|s| &s.undo).collect();
        fs::write(dir.join("journal.json"), serde_json::to_vec_pretty(&json!({"boot": "{boot}", "undo": undo})).unwrap()).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    /// Release blocker 2 with the real tools (`tests/mihomo-qa`, run inside
    /// the disposable container's router namespace): a name another writer
    /// holds is never taken over, and a journal cut short at any point (undo
    /// written but nothing applied, after each step, half rolled back) is
    /// recovered completely and only for our own objects.
    #[test]
    #[ignore]
    fn isolated_ownership_and_interrupted_journals() {
        assert_eq!(std::env::var("U60_MIHOMO_QA_ISOLATED").as_deref(), Ok("1"));
        assert!(Path::new("/u60-qa-disposable").exists());
        use controller::Port;
        let run = |args: &[&str]| Cmd::new(args[0], &args[1..]).run();
        let root = PathBuf::from("/tmp/u60-mihomo-qa-root");
        fs::create_dir_all(&root).unwrap();
        let m = Arc::new(Mihomo::at(root.clone(), Arc::new(Mutex::new(()))));
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
        let mut steps = proxy_plan_with(net::sysctl_read).unwrap();
        steps.push(tables_step());
        for applied in 0..=steps.len() {
            let mut tx = Transaction::new(m.journal());
            tx.apply_network(Vec::new()).unwrap();
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
        let prepared = Prepared {
            secret: "s".into(),
            local: "u60.home.arpa".into(),
            runtime: json!({"mode": "rule", "log-level": "info"}),
            routes: routing::Routes::default(),
            dns: Vec::new(),
            bypass: true,
            notice: None,
            source: String::new(),
            config: "interface-name: ath20\nrule-providers:\n  Web: {type: http, behavior: ipcidr, url: 'https://x', path: ./w.yaml}\n".into(),
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
        let dir = std::env::temp_dir().join(format!("u60-reload-validation-{}", std::process::id()));
        let mihomo = Arc::new(Mihomo::at(dir.clone(), Arc::new(Mutex::new(()))));
        net::write_private(&dir.join("mihomo"), b"#!/bin/sh\nprintf x >> \"$3/check-count\"\n").unwrap();
        fs::set_permissions(dir.join("mihomo"), fs::Permissions::from_mode(0o700)).unwrap();
        net::write_private(&dir.join("config.yaml"), b"serving config").unwrap();
        let prepared = Prepared {
            secret: "s".into(), local: "u60.home.arpa".into(), runtime: json!({"mode":"rule"}),
            routes: routing::Routes::default(), dns: Vec::new(), bypass: false, notice: None,
            source: "rules: ['MATCH,DIRECT']".into(), config: "rules: ['MATCH,DIRECT']".into(),
        };
        let mut port = DevicePort::new(Arc::clone(&mihomo), "u60.home.arpa".into());
        port.lan = Some(std::net::Ipv4Addr::LOCALHOST);
        let first = port.prepare(&Source::Previous(Box::new(prepared)), true).unwrap();
        port.prepare(&Source::Previous(Box::new(first)), false).unwrap();
        assert_eq!(fs::read(dir.join("check-count")).unwrap(), b"x");
        assert_eq!(fs::read(dir.join("config.yaml")).unwrap(), b"serving config");
        assert!(!dir.join("candidate.yaml").exists());
        let remembered = remembered_validation(&dir);
        if net::boot_id().is_empty() {
            assert!(remembered.is_empty());
        } else {
            assert_eq!(remembered, *mihomo.validated_config.lock().unwrap());
        }
        fs::remove_dir_all(dir).unwrap();
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
        let steps = proxy_plan_with(|key| Ok(format!("old-{key}"))).unwrap();
        for (key, value) in [
            ("tcp_pacing_ss_ratio", "1000"),
            ("tcp_pacing_ca_ratio", "1000"),
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
        assert!(proxy_plan_with(|_| Err("unreadable".into())).is_err());
        // The tables' undo is what every agent since the TPROXY release runs.
        assert_eq!((tables_step().undo.program.as_str(), tables_step().undo.args.as_slice()), ("@u60-mihomo-nft", &["remove".to_owned()][..]));
        assert!(nft_command(&["tables".into()]).is_ok() && nft_command(&["bogus".into()]).is_err());
    }

    #[test]
    fn off_status_has_no_dashboard_and_creates_nothing() {
        let dir = std::env::temp_dir().join("u60-mihomo-no-side-effects");
        let m = Mihomo::at(dir.clone(), Arc::new(Mutex::new(())));
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
        let dir = std::env::temp_dir().join(format!("u60-core-busy-{}", std::process::id()));
        let lock = Arc::new(Mutex::new(()));
        let m = Mihomo::at(dir.clone(), Arc::clone(&lock));
        let _operation = m.operation.lock().unwrap();
        assert!(
            lock.try_lock().is_ok(),
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
    /// start the owner asked for fails (the controller, real device side;
    /// without `ip` and `nft` here, a start fails before taking anything).
    #[test]
    fn owner_choice_outlives_restarts_until_turned_off_or_failing() {
        let dir = std::env::temp_dir().join(format!("u60-core-wanted-{}", std::process::id()));
        let m = Arc::new(Mihomo::at(dir.clone(), Arc::new(Mutex::new(()))));
        net::write_private(&dir.join(WANTED), b"1").unwrap();
        assert!(m.wants_restore());
        assert_eq!(m.status_with(|| Err("none".into()))["autostart"], true);
        m.start("u60.home.arpa".into());
        // The owner saw it fail: a restart must not retry it.
        assert!(m.enable("u60.home.arpa").is_err());
        assert!(!m.wants_restore());
        assert_eq!(m.snapshot().phase, Phase::Off);
        net::write_private(&dir.join(WANTED), b"1").unwrap();
        m.disable().unwrap();
        assert!(!m.wants_restore());
        // Nothing wanted: returns at once and changes nothing.
        m.restore("u60.home.arpa");
        assert!(!m.running() && m.snapshot().phase == Phase::Off);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn restore_marker_write_and_delete_failures_are_reported() {
        let dir = std::env::temp_dir().join(format!("u60-core-marker-{}", std::process::id()));
        let m = Arc::new(Mihomo::at(dir.clone(), Arc::new(Mutex::new(()))));
        std::fs::create_dir_all(dir.join(WANTED)).unwrap();
        assert!(net::write_private(&dir.join(WANTED), b"1").is_err());
        assert_eq!(m.set_wanted(false).unwrap_err(), "Cannot clear Mihomo's restart setting");
        m.start("u60.home.arpa".into());
        let error = m.enable("u60.home.arpa").unwrap_err();
        assert!(error.contains("Cannot clear Mihomo's restart setting"), "{error}");
        std::fs::remove_dir_all(dir).unwrap();
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
            Some(0)
        );
        assert!(v["proxy-providers"]["Hotel"]["override"]["override-expr"].is_null());
        assert_eq!(v["hosts"]["interface-name"].as_str(), Some("192.0.2.1"));
        assert_eq!(v["profile"]["store-selected"].as_bool(), Some(true));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Uses real netfilter/core; only the disposable Linux QA runner"]
    fn isolated_real_core_uplink_transitions() {
        assert_eq!(std::env::var("U60_CORE_ISOLATED_QA").as_deref(), Ok("1"));
        assert!(Path::new("/u60-ipv6-qa-disposable").exists());
        let root = PathBuf::from(std::env::var_os("U60_CORE_QA_ROOT").unwrap());
        let m = Arc::new(Mihomo::at(root, Arc::new(Mutex::new(()))));
        m.start("test.home.arpa".into());
        let source = "proxies: [{name: TestDirect, type: direct, udp: true, interface-name: rmnet_data0}]\nproxy-groups: [{name: SelectTest, type: select, proxies: [DIRECT, TestDirect]}]\nrules: ['MATCH,SelectTest']\ndns: {nameserver: [1.1.1.1]}\n";
        m.configure(source).unwrap();
        for tcp in [true, false] {
            let listener = tcp.then(|| std::net::TcpListener::bind("0.0.0.0:1053").unwrap());
            let datagram = (!tcp).then(|| std::net::UdpSocket::bind("0.0.0.0:1053").unwrap());
            assert!(m.enable("test.home.arpa").is_err());
            assert!(
                !m.owns_network(),
                "occupied DNS must never leave interception"
            );
            drop((listener, datagram));
        }
        m.enable("test.home.arpa").unwrap();
        assert!(
            download::ready(),
            "Unauthenticated proxy requests must be rejected"
        );
        {
            use base64::Engine;
            use std::io::{Read, Write};
            let mut stream = std::net::TcpStream::connect(download::PROXY).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let auth = base64::engine::general_purpose::STANDARD.encode(format!(
                "{}:{}",
                download::USER,
                m.secret().unwrap()
            ));
            stream.write_all(format!("CONNECT 203.0.113.1:45679 HTTP/1.1\r\nHost: 203.0.113.1:45679\r\nProxy-Authorization: Basic {auth}\r\n\r\n").as_bytes()).unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut b = [0u8];
                stream.read_exact(&mut b).unwrap();
                headers.push(b[0]);
                assert!(headers.len() < 4096);
            }
            assert!(headers.starts_with(b"HTTP/1.1 200"));
            stream.write_all(b"test").unwrap();
            let mut echoed = [0u8; 8];
            stream.read_exact(&mut echoed).unwrap();
            assert_eq!(&echoed, b"10.9.0.2");
        }
        let profiles = m.profile_status().unwrap();
        let original = profiles["selected"].as_str().unwrap().to_owned();
        let request = |v| serde_json::from_value::<profiles::Request>(v).unwrap();
        assert!(m
            .profiles_change(request(json!({"action":"delete","id":original})))
            .is_err());
        assert!(m.running());
        m.profiles_change(request(
            json!({"action":"add","name":"Switch QA","yaml":source}),
        ))
        .unwrap();
        let alternate = m.profile_status().unwrap()["profiles"][1]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        m.profiles_change(request(json!({"action":"select","id":alternate})))
            .unwrap();
        assert!(m.running());
        m.profiles_change(request(json!({"action":"extensions","extensions":{
            "merge_enabled":true,"merge":"prepend-rules: ['DOMAIN,merge.test,DIRECT']",
            "script_enabled":true,"script":"function main(c,n){c.rules.unshift('DOMAIN,script.test,DIRECT');return c;}"
        }}))).unwrap();
        assert!(m.running());
        let compiled: Yaml =
            serde_yaml_ng::from_str(&fs::read_to_string(m.root.join("config.yaml")).unwrap())
                .unwrap();
        assert_eq!(compiled["rules"][0], "DOMAIN,script.test,DIRECT");
        assert_eq!(compiled["rules"][1], "DOMAIN,merge.test,DIRECT");
        m.profiles_change(request(json!({"action":"select","id":original})))
            .unwrap();
        let agent = ureq::Agent::config_builder()
            .proxy(None)
            .timeout_global(Some(Duration::from_secs(2)))
            .build()
            .new_agent();
        for (group, selection) in [("SelectTest", "TestDirect"), ("GLOBAL", "SelectTest")] {
            agent
                .put(&format!("http://{CONTROLLER}/proxies/{group}"))
                .header("Authorization", &format!("Bearer {}", m.secret().unwrap()))
                .send_json(json!({"name":selection}))
                .unwrap();
        }
        agent
            .patch(&format!("http://{CONTROLLER}/configs"))
            .header("Authorization", &format!("Bearer {}", m.secret().unwrap()))
            .send_json(json!({"mode":"global","log-level":"debug"}))
            .unwrap();
        // The same restart is used by manual/scheduled profile refresh and
        // global extension edits. Neither may reset the dashboard's mode.
        m.profiles_change(request(json!({"action":"extensions","extensions":{
            "merge_enabled":true,"merge":"prepend-rules: ['DOMAIN,refresh.test,DIRECT']",
            "script_enabled":false
        }})))
        .unwrap();
        let refreshed: Yaml =
            serde_yaml_ng::from_str(&fs::read_to_string(m.root.join("config.yaml")).unwrap())
                .unwrap();
        assert_eq!(refreshed["mode"].as_str(), Some("global"));
        assert_eq!(refreshed["log-level"].as_str(), Some("debug"));
        std::thread::sleep(Duration::from_secs(1));
        let generation = m.snapshot().generation;
        // Duplicate notifications keep the core (the controller compares the egress).
        m.uplink_changed();
        m.uplink_changed();
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(m.snapshot().generation, generation);
        net::write_private(Path::new("/qa-state/cell-ready"), b"1").unwrap();
        for (request, done) in [
            ("wifi", "wifi-ready"),
            ("v6", "v6-ready"),
            ("cell", "cell-again"),
            ("wifi2", "wifi2-ready"),
            ("offline", "offline-ready"),
            ("wifi3", "wifi3-ready"),
            ("stalled", "stalled-ready"),
        ] {
            for _ in 0..600 {
                if Path::new(&format!("/qa-state/{request}")).exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            assert!(
                Path::new(&format!("/qa-state/{request}")).exists(),
                "timed out at {request}"
            );
            if request == "stalled" {
                let pid = m.snapshot().core_pid.unwrap();
                assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGSTOP) }, 0);
            }
            let generation = m.snapshot().generation;
            m.uplink_changed();
            // The controller restarts the core for the new egress.
            for _ in 0..300 {
                let s = m.snapshot();
                if s.generation > generation && s.phase == Phase::Running {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            assert!(m.snapshot().generation > generation, "restarted at {request}");
            let config: Yaml =
                serde_yaml_ng::from_str(&fs::read_to_string(m.root.join("config.yaml")).unwrap())
                    .unwrap();
            assert_eq!(
                config["interface-name"].as_str(),
                if matches!(request, "cell" | "offline" | "stalled") {
                    None
                } else {
                    Some("ath20")
                }
            );
            assert_eq!(
                config["hosts"]["test.home.arpa"].as_str(),
                Some("192.168.0.1")
            );
            assert_eq!(config["mode"].as_str(), Some("global"));
            assert_eq!(config["log-level"].as_str(), Some("debug"));
            // The core exposes its controller/listeners before updateProfile
            // restores selectors. Observe bounded convergence, without writing
            // a selection again (which would conceal lost persisted state).
            let observed = Instant::now();
            let mut first = None;
            let proxies: Value = loop {
                let proxies: Value = agent
                    .get(&format!("http://{CONTROLLER}/proxies"))
                    .header("Authorization", &format!("Bearer {}", m.secret().unwrap()))
                    .call()
                    .unwrap()
                    .body_mut()
                    .read_json()
                    .unwrap();
                first.get_or_insert_with(|| {
                    (
                        proxies["proxies"]["SelectTest"]["now"].clone(),
                        proxies["proxies"]["GLOBAL"]["now"].clone(),
                    )
                });
                if (proxies["proxies"]["SelectTest"]["now"] == "TestDirect"
                    && proxies["proxies"]["GLOBAL"]["now"] == "SelectTest")
                    || observed.elapsed() >= Duration::from_secs(3)
                {
                    break proxies;
                }
                std::thread::sleep(Duration::from_millis(20));
            };
            crate::netlog!(
                "[qa] selectors stage={request} first={first:?} settled_ms={}",
                observed.elapsed().as_millis()
            );
            assert_eq!(proxies["proxies"]["SelectTest"]["now"], "TestDirect");
            assert_eq!(proxies["proxies"]["GLOBAL"]["now"], "SelectTest");
            net::write_private(Path::new(&format!("/qa-state/{done}")), b"1").unwrap();
        }
        for _ in 0..600 {
            if Path::new("/qa-state/finish").exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(Path::new("/qa-state/finish").exists());
        m.disable().unwrap();
        assert!(!m.owns_network());
    }
}
