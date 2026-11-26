//! Tailscale management for the router agent.
//!
//! The HTTP handlers manage enrollment, preferences, and binary updates. The supervisor
//! manages tailscaled and reacts to WAN and Wi-Fi relay changes. HTTP and dashboard
//! status share a cache backed by the daemon's LocalAPI with a CLI fallback.

pub mod config;
mod localapi;
mod supervisor;
mod update;

pub use config::TsConfig;
pub use update::{update, versions, versions_refresh};

use localapi::daemon_status;
use supervisor::{ChildIdentity, RelayWatchState};
use update::VersionCatalog;
#[cfg(not(test))]
use update::recover_binaries_in;

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::handlers::AppState;
use crate::ubus;
use crate::wifi_relay::WifiRelay;

const BIN_DIR: &str = "/data/tailscale/bin";
const TAILSCALED_BIN: &str = "/data/tailscale/bin/tailscaled";
const TAILSCALE_BIN: &str = "/data/tailscale/bin/tailscale";
const STATE_FILE: &str = "/data/tailscale/tailscaled.state";
const STATE_BAK: &str = "/data/tailscale/tailscaled.state.bak";
const RUN_DIR: &str = "/tmp/tailscale";
const SOCK: &str = "/tmp/tailscale/tailscaled.sock";

const CLI_TIMEOUT_SECS: u64 = 20;
/// Shorter than CLI_TIMEOUT_SECS so GET /status can't stall mobile clients
/// for long when the daemon is wedged.
const STATUS_CLI_TIMEOUT_SECS: u64 = 8;
const STATUS_CACHE_TTL_SECS: i64 = 10;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EnrollmentOp {
    Idle,
    AuthKey,
    InteractiveLogin,
}

struct AuthKeyEnrollmentGuard<'a> {
    mgr: &'a TailscaleManager,
}

impl Drop for AuthKeyEnrollmentGuard<'_> {
    fn drop(&mut self) {
        let mut op = self
            .mgr
            .enrollment
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if *op == EnrollmentOp::AuthKey {
            *op = EnrollmentOp::Idle;
        }
    }
}

struct InteractiveLoginGuard {
    mgr: Arc<TailscaleManager>,
}

impl Drop for InteractiveLoginGuard {
    fn drop(&mut self) {
        let mut op = self
            .mgr
            .enrollment
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if *op == EnrollmentOp::InteractiveLogin {
            *op = EnrollmentOp::Idle;
        }
    }
}

enum InteractiveLoginSlot {
    Started(InteractiveLoginGuard),
    AlreadyRunning,
}

struct StatusRefreshGuard {
    mgr: Arc<TailscaleManager>,
}

impl Drop for StatusRefreshGuard {
    fn drop(&mut self) {
        self.mgr.finish_status_refresh();
    }
}

struct StatusRefreshRefGuard<'a> {
    mgr: &'a TailscaleManager,
}

impl Drop for StatusRefreshRefGuard<'_> {
    fn drop(&mut self) {
        self.mgr.finish_status_refresh();
    }
}

static NEXT_AUTHKEY_ID: AtomicU64 = AtomicU64::new(0);

struct TempAuthKeyFile {
    path: PathBuf,
}

impl TempAuthKeyFile {
    fn write(dir: &Path, key: &str) -> Result<Self, String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        std::fs::create_dir_all(dir)
            .map_err(|err| format!("create auth key dir: {err}"))?;
        let pid = std::process::id();
        for _ in 0..16 {
            let seq = NEXT_AUTHKEY_ID.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("authkey-{pid}-{seq}"));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(mut file) => {
                    let guard = Self { path };
                    file.write_all(key.as_bytes())
                        .map_err(|_| "failed to write auth key".to_string())?;
                    return Ok(guard);
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(format!("write auth key: {err}")),
            }
        }
        Err("write auth key: could not allocate unique key file".to_string())
    }

    fn path_str(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for TempAuthKeyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub struct TailscaleManager {
    config: Mutex<TsConfig>,
    /// Desired state: should tailscaled be running?
    running: AtomicBool,
    /// Update in progress — supervisor must quiesce so binaries can be swapped.
    paused: AtomicBool,
    /// The single supervisor thread has been spawned.
    supervisor_started: AtomicBool,
    /// True only while the supervisor is parked with no child — the only
    /// window where swapping binaries is safe.
    supervisor_idle: AtomicBool,
    updating: AtomicBool,
    enrollment: Mutex<EnrollmentOp>,
    /// One state-file restore attempt per enrollment (reset on setup/logout).
    state_restore_attempted: AtomicBool,
    active_child: Mutex<Option<ChildIdentity>>,
    next_child_instance: AtomicU64,
    /// Last computed status payload + unix timestamp + monotonic refresh sequence.
    last_status: Mutex<(Value, i64, u64)>,
    status_seq: AtomicU64,
    status_refresh_lock: Mutex<bool>,
    status_refresh_cv: Condvar,
    /// Outcome of the most recent update attempt (surfaced in /status).
    last_update: Mutex<Option<Value>>,
    login_url: Mutex<Option<String>>,
    versions_cache: Mutex<Option<(VersionCatalog, Instant)>>,
    wakelock_held: AtomicBool,
    /// Supervisor wake-up: writers of `running` / `paused` notify so the
    /// thread parks instead of polling. The mutex guards no data; holding
    /// it while notifying orders the flag store before a parked thread's
    /// predicate re-check so a wake cannot be lost.
    wake_lock: Mutex<()>,
    wake_cv: Condvar,
    relay: OnceLock<Weak<WifiRelay>>,
    relay_watch_lock: Mutex<RelayWatchState>,
    relay_watch_cv: Condvar,
}

fn unix_now() -> i64 {
    unsafe { libc::time(std::ptr::null_mut()) as i64 }
}

/// Run a command with a hard timeout. On timeout the process is SIGKILLed
/// and reaped by the waiter thread.
fn run_with_timeout(mut cmd: Command, timeout_secs: u64) -> Result<std::process::Output, String> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(Duration::from_secs(timeout_secs)) {
        Ok(result) => result.map_err(|e| format!("wait: {e}")),
        Err(_) => {
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            Err(format!("timed out after {timeout_secs}s"))
        }
    }
}

/// `tailscale --socket=... <args>` -> stdout. Mirrors ubus::call.
fn cli(args: &[&str], timeout_secs: u64) -> Result<String, String> {
    let mut cmd = Command::new(TAILSCALE_BIN);
    cmd.arg(format!("--socket={SOCK}"));
    cmd.args(args);
    let out = run_with_timeout(cmd, timeout_secs)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let msg = if stderr.trim().is_empty() { stdout } else { stderr };
        return Err(msg.trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn installed() -> bool {
    Path::new(TAILSCALED_BIN).exists() && Path::new(TAILSCALE_BIN).exists()
}

fn state_file_exists() -> bool {
    Path::new(STATE_FILE).exists()
}

impl TailscaleManager {
    pub fn new() -> Self {
        #[cfg(not(test))]
        let cfg = {
            recover_binaries_in(Path::new(BIN_DIR));
            config::load()
        };
        #[cfg(test)]
        let cfg = TsConfig::default();
        Self::with_config(cfg)
    }

    fn with_config(cfg: TsConfig) -> Self {
        Self {
            config: Mutex::new(cfg),
            running: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            supervisor_started: AtomicBool::new(false),
            supervisor_idle: AtomicBool::new(true),
            updating: AtomicBool::new(false),
            enrollment: Mutex::new(EnrollmentOp::Idle),
            state_restore_attempted: AtomicBool::new(false),
            active_child: Mutex::new(None),
            next_child_instance: AtomicU64::new(0),
            last_status: Mutex::new((Value::Null, 0, 0)),
            status_seq: AtomicU64::new(0),
            status_refresh_lock: Mutex::new(false),
            status_refresh_cv: Condvar::new(),
            last_update: Mutex::new(None),
            login_url: Mutex::new(None),
            versions_cache: Mutex::new(None),
            wakelock_held: AtomicBool::new(false),
            wake_lock: Mutex::new(()),
            wake_cv: Condvar::new(),
            relay: OnceLock::new(),
            relay_watch_lock: Mutex::new(RelayWatchState::default()),
            relay_watch_cv: Condvar::new(),
        }
    }

    fn enrollment_active(&self) -> bool {
        *self
            .enrollment
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            != EnrollmentOp::Idle
    }

    fn enrollment_is_auth_key(&self) -> bool {
        *self
            .enrollment
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            == EnrollmentOp::AuthKey
    }

    fn try_begin_auth_key_enrollment(&self) -> Result<AuthKeyEnrollmentGuard<'_>, &'static str> {
        let mut op = self
            .enrollment
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        match *op {
            EnrollmentOp::Idle => {
                *op = EnrollmentOp::AuthKey;
                Ok(AuthKeyEnrollmentGuard { mgr: self })
            }
            EnrollmentOp::AuthKey => Err("enrollment already in progress"),
            EnrollmentOp::InteractiveLogin => Err("interactive login in progress"),
        }
    }

    fn try_begin_interactive_login(
        self: &Arc<Self>,
    ) -> Result<InteractiveLoginSlot, &'static str> {
        let mut op = self
            .enrollment
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        match *op {
            EnrollmentOp::Idle => {
                *op = EnrollmentOp::InteractiveLogin;
                Ok(InteractiveLoginSlot::Started(InteractiveLoginGuard {
                    mgr: Arc::clone(self),
                }))
            }
            EnrollmentOp::InteractiveLogin => Ok(InteractiveLoginSlot::AlreadyRunning),
            EnrollmentOp::AuthKey => Err("enrollment already in progress"),
        }
    }

    /// Shared pref flags for `set` (steady state) and `up` (enrollment /
    /// re-activation). Never includes --auth-key (tailscale#16987).
    fn pref_args(&self, verb: &str) -> Vec<String> {
        let cfg = self.config.lock().unwrap().clone();
        pref_args_for(&cfg, verb)
    }

    // --- Status ---

    fn finish_status_refresh(&self) {
        let mut in_flight = self
            .status_refresh_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        *in_flight = false;
        self.status_refresh_cv.notify_all();
    }

    fn store_status(&self, seq: u64, payload: &Value, now: i64) {
        let mut last = self
            .last_status
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if seq >= last.2 {
            *last = (payload.clone(), now, seq);
        }
    }

    /// Fetch `tailscale status --json` and cache the derived payload.
    fn refresh_status(&self) -> Value {
        let seq = self.status_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let payload = self.build_status();
        self.store_status(seq, &payload, unix_now());
        payload
    }

    fn status_nonblocking(self: &Arc<Self>) -> Value {
        self.status_nonblocking_with(
            unix_now,
            || self.build_base_status(),
            |mgr| {
                mgr.refresh_status();
            },
        )
    }

    fn status_nonblocking_with(
        self: &Arc<Self>,
        now_fn: impl Fn() -> i64,
        base_fn: impl FnOnce() -> (Value, bool),
        refresh_fn: impl FnOnce(Arc<Self>) + Send + 'static,
    ) -> Value {
        let now = now_fn();
        let (cached, at, _) = self
            .last_status
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        if !cached.is_null() && now.saturating_sub(at) < STATUS_CACHE_TTL_SECS {
            return cached;
        }
        let (base, needs_probe) = base_fn();
        if !needs_probe {
            let seq = self.status_seq.fetch_add(1, Ordering::SeqCst) + 1;
            self.store_status(seq, &base, now);
            return base;
        }
        let start = {
            let mut in_flight = self
                .status_refresh_lock
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            if *in_flight {
                false
            } else {
                *in_flight = true;
                true
            }
        };
        if start {
            let mgr = Arc::clone(self);
            let spawned = thread::Builder::new()
                .name("ts-status".into())
                .spawn(move || {
                    let _done = StatusRefreshGuard {
                        mgr: Arc::clone(&mgr),
                    };
                    refresh_fn(mgr);
                });
            if spawned.is_err() {
                self.finish_status_refresh();
            }
        }
        if !cached.is_null() && cached["daemon_running"].as_bool() == Some(true) {
            cached
        } else {
            base
        }
    }

    fn status_coalesced(&self) -> Value {
        self.status_coalesced_with(
            unix_now,
            || self.build_base_status(),
            || self.refresh_status(),
        )
    }

    fn status_coalesced_with(
        &self,
        now_fn: impl Fn() -> i64,
        base_fn: impl FnOnce() -> (Value, bool),
        refresh_fn: impl FnOnce() -> Value,
    ) -> Value {
        let now = now_fn();
        let (cached, at, _) = self
            .last_status
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        if !cached.is_null() && now.saturating_sub(at) < STATUS_CACHE_TTL_SECS {
            return cached;
        }
        let (base, needs_probe) = base_fn();
        if !needs_probe {
            let seq = self.status_seq.fetch_add(1, Ordering::SeqCst) + 1;
            self.store_status(seq, &base, now);
            return base;
        }
        let mut in_flight = self
            .status_refresh_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if *in_flight {
            while *in_flight {
                in_flight = self
                    .status_refresh_cv
                    .wait(in_flight)
                    .unwrap_or_else(|err| err.into_inner());
            }
            drop(in_flight);
            let (updated, _, _) = self
                .last_status
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .clone();
            return if !updated.is_null() { updated } else { base };
        }
        *in_flight = true;
        drop(in_flight);
        let _done = StatusRefreshRefGuard { mgr: self };
        refresh_fn()
    }

    fn build_base_status(&self) -> (Value, bool) {
        let cfg = self.config.lock().unwrap().clone();
        let daemon_up = self.active_child.lock().unwrap().is_some();

        let mut payload = json!({
            "installed": installed(),
            "enabled": cfg.enabled,
            "enrolled": cfg.enrolled,
            "daemon_running": daemon_up,
            "state": "unknown",
            "backend_state": Value::Null,
            "healthy": false,
            "health": [],
            "tailscale_ips": [],
            "dns_name": Value::Null,
            "relay": Value::Null,
            "direct": false,
            "key_expiry": Value::Null,
            "expired": false,
            "client_version": Value::Null,
            "login_url": *self.login_url.lock().unwrap(),
            "wakelock_held": self.wakelock_held.load(Ordering::SeqCst),
            "updating": self.updating.load(Ordering::SeqCst),
            "last_update": *self.last_update.lock().unwrap(),
            "hostname": cfg.hostname,
            "advertise_routes": cfg.advertise_routes,
            "tailscale_ssh": cfg.tailscale_ssh,
            "hold_wakelock": cfg.hold_wakelock,
            "pinned_version": cfg.pinned_version,
        });

        if !installed() {
            payload["state"] = json!("not_installed");
            return (payload, false);
        }
        if self.updating.load(Ordering::SeqCst) {
            payload["state"] = json!("updating");
            return (payload, false);
        }
        if !cfg.enabled && !daemon_up {
            payload["state"] = json!("disabled");
            return (payload, false);
        }
        if !daemon_up {
            payload["state"] = json!("respawning");
            return (payload, false);
        }
        payload["state"] = json!("starting");
        (payload, true)
    }

    fn build_status(&self) -> Value {
        let (mut payload, needs_probe) = self.build_base_status();
        if !needs_probe {
            return payload;
        }
        let cfg = self.config.lock().unwrap().clone();

        let status = match daemon_status(STATUS_CLI_TIMEOUT_SECS) {
            Ok(v) => v,
            Err(e) => {
                payload["state"] = json!("starting");
                payload["error"] = json!(e);
                return payload;
            }
        };

        let backend = status["BackendState"].as_str().unwrap_or("");
        let health: Vec<String> = status["Health"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let self_obj = &status["Self"];
        let online = self_obj["Online"].as_bool().unwrap_or(false);

        payload["backend_state"] = json!(backend);
        payload["health"] = json!(health);
        payload["tailscale_ips"] = status["TailscaleIPs"].clone();
        payload["dns_name"] = self_obj["DNSName"].clone();
        payload["relay"] = self_obj["Relay"].clone();
        payload["direct"] = json!(self_obj["CurAddr"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
        payload["key_expiry"] = self_obj["KeyExpiry"].clone();
        payload["expired"] = json!(self_obj["Expired"].as_bool().unwrap_or(false));
        payload["client_version"] = status["Version"].clone();

        if backend == "Running" {
            // Enrollment done — any cached interactive-login URL is stale
            *self.login_url.lock().unwrap() = None;
            payload["login_url"] = Value::Null;
        } else if let Some(url) = status["AuthURL"].as_str() {
            if !url.is_empty() {
                payload["login_url"] = json!(url);
                *self.login_url.lock().unwrap() = Some(url.to_string());
            }
        }

        // Health warnings are informational (can be benign and permanent);
        // "degraded" is reserved for Running-but-offline, which is actionable.
        let state = match backend {
            "NeedsLogin" => {
                if cfg.enrolled {
                    "needs_login"
                } else {
                    "awaiting_setup"
                }
            }
            "NeedsMachineAuth" => "pending_approval",
            "Stopped" => "paused",
            "Starting" | "NoState" => "connecting",
            "Running" => {
                if online {
                    "healthy"
                } else {
                    "degraded"
                }
            }
            _ => "unknown",
        };
        payload["state"] = json!(state);
        payload["healthy"] = json!(state == "healthy");
        payload
    }

    fn is_unhealthy(&self) -> bool {
        let status = self.last_status.lock().unwrap();
        matches!(
            status.0["state"].as_str().unwrap_or(""),
            "degraded" | "connecting" | "starting" | "unknown" | "respawning"
        )
    }

    /// Host names the HTTP Host allowlist accepts for the tailnet: the
    /// configured hostname, the MagicDNS name and its first label (which
    /// differs from the hostname after a collision or an admin rename),
    /// lowercased and de-duplicated; empty while Tailscale is disabled.
    /// Never blocks: `None` if `config` (held across flash writes) or
    /// `last_status` is locked or poisoned; the caller keeps its last answer.
    pub fn ui_host_names(&self) -> Option<Vec<String>> {
        let hostname = {
            let cfg = self.config.try_lock().ok()?;
            if !cfg.enabled {
                return Some(Vec::new());
            }
            cfg.hostname.to_ascii_lowercase()
        };
        let dns_name = {
            let status = self.last_status.try_lock().ok()?;
            status.0["dns_name"].as_str().map(str::to_ascii_lowercase)
        };
        let mut names = vec![hostname];
        if let Some(dns) = dns_name {
            let dns = dns.strip_suffix('.').unwrap_or(&dns);
            names.push(dns.to_owned());
            names.push(dns.split('.').next().unwrap_or_default().to_owned());
        }
        let mut unique: Vec<String> = Vec::with_capacity(names.len());
        for n in names {
            if !n.is_empty() && !unique.contains(&n) {
                unique.push(n);
            }
        }
        Some(unique)
    }

    /// A manager with the given config and cached status, for tests of
    /// callers (no file is read, nothing is started).
    #[cfg(test)]
    pub(crate) fn for_test(cfg: TsConfig, status: Value) -> Self {
        let mgr = Self::with_config(cfg);
        *mgr.last_status.lock().unwrap() = (status, 0, 0);
        mgr
    }

    /// Holds `config` as a flash write would, for contention tests.
    #[cfg(test)]
    pub(crate) fn lock_config_for_test(&self) -> std::sync::MutexGuard<'_, TsConfig> {
        self.config.lock().unwrap()
    }

    // --- Wakelock ---

    fn acquire_wakelock(&self) {
        match ubus::call("zwrt_zte_sleep_faw.wakelock", "createWakelock", Some("{}")) {
            Ok(_) => self.wakelock_held.store(true, Ordering::SeqCst),
            Err(e) => eprintln!("[tailscale] createWakelock: {e}"),
        }
    }

    fn release_wakelock(&self) {
        if !self.wakelock_held.load(Ordering::SeqCst) {
            return;
        }
        match ubus::call("zwrt_zte_sleep_faw.wakelock", "destroyWakelock", Some("{}")) {
            Ok(_) => self.wakelock_held.store(false, Ordering::SeqCst),
            Err(e) => eprintln!("[tailscale] destroyWakelock: {e}"),
        }
    }

    /// Mark enrollment success: persist flags, back up identity, wakelock.
    fn after_enrollment_success(&self) {
        let _ = std::fs::copy(STATE_FILE, STATE_BAK);
        self.state_restore_attempted.store(false, Ordering::SeqCst);
        let hold = {
            let mut cfg = self.config.lock().unwrap();
            cfg.enabled = true;
            cfg.enrolled = true;
            let _ = config::save(&cfg);
            cfg.hold_wakelock
        };
        if hold {
            self.acquire_wakelock();
        }
    }
}

fn pref_args_for(cfg: &TsConfig, verb: &str) -> Vec<String> {
    let mut args = vec![
        verb.to_string(),
        "--accept-dns=false".to_string(),
        "--accept-routes=false".to_string(),
        format!("--hostname={}", cfg.hostname),
        format!("--advertise-routes={}", cfg.advertise_routes.join(",")),
        format!("--ssh={}", cfg.tailscale_ssh),
    ];
    if verb == "up" {
        args.push("--reset".to_string());
    }
    args
}

/// Remote access without an agent password would expose an unauthenticated
/// management API to every tailnet device.
fn require_password(state: &AppState) -> Option<(u16, Value)> {
    if state.auth.has_password() {
        None
    } else {
        Some((
            403,
            json!({"ok": false, "error": "set an agent password (ZTE_AGENT_PASSWORD) before enabling remote access"}),
        ))
    }
}

// --- HTTP handlers (wired in server.rs) ---

/// GET /api/tailscale/status
pub fn status(state: &AppState) -> (u16, Value) {
    let payload = state.tailscale.status_nonblocking();
    (200, json!({"ok": true, "data": payload}))
}

/// Dedicated dashboard-tailscale topic reader (runs off the General lane).
pub fn dashboard_status(state: &AppState) -> Value {
    json!({"ok": true, "data": state.tailscale.status_coalesced()})
}

/// POST /api/tailscale/setup — body: {"auth_key": "tskey-auth-..."}
/// The only code path that ever passes an auth key (see tailscale#16987).
pub fn setup(state: &AppState, body: &[u8]) -> (u16, Value) {
    let mgr = &state.tailscale;
    if let Some(resp) = require_password(state) {
        return resp;
    }
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let key = match parsed["auth_key"].as_str() {
        Some(k) if !k.trim().is_empty() => k.trim().to_string(),
        _ => return (400, json!({"ok": false, "error": "missing 'auth_key' field"})),
    };
    if mgr.updating.load(Ordering::SeqCst) {
        return (409, json!({"ok": false, "error": "update in progress"}));
    }
    let _enroll_guard = match mgr.try_begin_auth_key_enrollment() {
        Ok(guard) => guard,
        Err(error) => return (409, json!({"ok": false, "error": error})),
    };

    if state_file_exists() {
        let current = mgr.refresh_status();
        if current["backend_state"].as_str() == Some("Running") {
            return (409, json!({"ok": false, "error": "already enrolled — logout first to re-enroll"}));
        }
    }

    if let Err(e) = mgr.ensure_daemon_ready(30) {
        return (503, json!({"ok": false, "error": e}));
    }

    let keyfile = match TempAuthKeyFile::write(Path::new(RUN_DIR), &key) {
        Ok(file) => file,
        Err(error) => return (500, json!({"ok": false, "error": error})),
    };

    let mut args = mgr.pref_args("up");
    args.push("--timeout=60s".to_string());
    args.push(format!("--auth-key=file:{}", keyfile.path_str()));
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = cli(&arg_refs, 90);
    drop(keyfile);

    match result {
        Ok(_) => {
            mgr.after_enrollment_success();
            let payload = mgr.refresh_status();
            (200, json!({"ok": true, "data": payload}))
        }
        Err(e) => (502, json!({"ok": false, "error": format!("tailscale up: {e}")})),
    }
}

/// POST /api/tailscale/login-url — interactive enrollment alternative.
/// Kicks off `tailscale up --json` in the background and returns the AuthURL.
pub fn login_url(state: &AppState) -> (u16, Value) {
    let mgr = &state.tailscale;
    if let Some(resp) = require_password(state) {
        return resp;
    }
    if mgr.updating.load(Ordering::SeqCst) {
        return (409, json!({"ok": false, "error": "update in progress"}));
    }
    if mgr.enrollment_is_auth_key() {
        return (409, json!({"ok": false, "error": "enrollment already in progress"}));
    }
    {
        let cfg = mgr.config.lock().unwrap().clone();
        if cfg.enrolled && !cfg.enabled {
            return (409, json!({"ok": false, "error": "tailscale is disabled — POST /api/tailscale/enable first"}));
        }
    }
    if let Err(e) = mgr.ensure_daemon_ready(30) {
        return (503, json!({"ok": false, "error": e}));
    }

    let current = mgr.refresh_status();
    if current["backend_state"].as_str() == Some("Running") {
        return (409, json!({"ok": false, "error": "already enrolled"}));
    }
    let slot = match mgr.try_begin_interactive_login() {
        Ok(slot) => slot,
        Err(error) => return (409, json!({"ok": false, "error": error})),
    };
    if let Some(url) = current["login_url"].as_str() {
        if !url.is_empty() {
            return (200, json!({"ok": true, "data": {"login_url": url, "pending": false}}));
        }
    }

    if let InteractiveLoginSlot::Started(login_guard) = slot {
        let mgr2 = Arc::clone(&state.tailscale);
        thread::spawn(move || {
            let _guard = login_guard;
            let mut args = mgr2.pref_args("up");
            args.push("--json".to_string());
            args.push("--timeout=300s".to_string());
            let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            // Blocks until the user completes login (or timeout); the AuthURL
            // surfaces via `tailscale status` which the monitor loop and the
            // poll below both read.
            let _ = cli(&arg_refs, 310);
            let status = mgr2.refresh_status();
            if status["backend_state"].as_str() == Some("Running") {
                mgr2.after_enrollment_success();
                mgr2.refresh_status();
            }
        });
    }

    // Poll briefly for the AuthURL to appear — wall-clock bounded so a
    // wedged daemon (8s CLI timeout per probe) can't pin this worker thread
    let deadline = unix_now() + 6;
    while unix_now() < deadline {
        thread::sleep(Duration::from_millis(500));
        let status = mgr.refresh_status();
        if let Some(url) = status["login_url"].as_str() {
            if !url.is_empty() {
                return (200, json!({"ok": true, "data": {"login_url": url, "pending": false}}));
            }
        }
    }
    (202, json!({"ok": true, "data": {"login_url": Value::Null, "pending": true}}))
}

/// POST /api/tailscale/enable — returns immediately; the supervisor brings
/// the daemon up in the background. Poll /status for progress.
pub fn enable(state: &AppState) -> (u16, Value) {
    if let Some(resp) = require_password(state) {
        return resp;
    }
    match state.tailscale.do_enable() {
        Ok(()) => (200, json!({"ok": true, "data": {"status": "enabling"}})),
        Err(e) => (500, json!({"ok": false, "error": e})),
    }
}

/// POST /api/tailscale/disable
pub fn disable(state: &AppState) -> (u16, Value) {
    match state.tailscale.do_disable() {
        Ok(()) => (200, json!({"ok": true, "data": {"status": "disabled"}})),
        Err(e) => (500, json!({"ok": false, "error": e})),
    }
}

/// PUT /api/tailscale/config — body: any of
/// {"hostname", "advertise_routes", "hold_wakelock", "tailscale_ssh"}
pub fn config_set(state: &AppState, body: &[u8]) -> (u16, Value) {
    let mgr = &state.tailscale;
    let patch: config::TsConfigPatch = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return (400, json!({"ok": false, "error": format!("invalid config JSON: {e}")})),
    };

    // Apply to a candidate first; persist only after the daemon accepted it
    // (otherwise saved config silently diverges from live prefs).
    let mut candidate = mgr.config.lock().unwrap().clone();
    if let Err(e) = candidate.apply_patch(patch) {
        return (400, json!({"ok": false, "error": e}));
    }

    let daemon_up = mgr.active_child.lock().unwrap().is_some();
    if candidate.enabled && daemon_up && state_file_exists() {
        let args = pref_args_for(&candidate, "set");
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        if let Err(e) = cli(&arg_refs, CLI_TIMEOUT_SECS) {
            return (502, json!({"ok": false, "error": format!("tailscale set: {e}")}));
        }
    }

    let (enabled, hold) = {
        let mut cfg = mgr.config.lock().unwrap();
        *cfg = candidate;
        if let Err(e) = config::save(&cfg) {
            return (500, json!({"ok": false, "error": e}));
        }
        (cfg.enabled, cfg.hold_wakelock)
    };

    if enabled {
        if hold {
            mgr.acquire_wakelock();
        } else {
            mgr.release_wakelock();
        }
    }
    let payload = mgr.refresh_status();
    (200, json!({"ok": true, "data": payload}))
}

/// POST /api/tailscale/logout — invalidates the node key and disables.
pub fn logout(state: &AppState) -> (u16, Value) {
    let mgr = &state.tailscale;
    if mgr.updating.load(Ordering::SeqCst) {
        return (409, json!({"ok": false, "error": "update in progress"}));
    }

    // The node key lives server-side too — start the daemon if needed so
    // `tailscale logout` can actually invalidate it.
    let mut warning: Option<String> = None;
    if installed() && state_file_exists() {
        if mgr.active_child.lock().unwrap().is_none() {
            let _ = mgr.ensure_daemon_ready(20);
        }
        if mgr.active_child.lock().unwrap().is_some() {
            if let Err(e) = cli(&["logout"], 30) {
                warning = Some(format!(
                    "tailscale logout failed ({e}) — remove this machine in the admin console"
                ));
            }
        } else {
            warning = Some(
                "daemon unavailable — node key not invalidated; remove this machine in the admin console"
                    .to_string(),
            );
        }
    }

    let _ = mgr.do_disable();
    let _ = std::fs::remove_file(STATE_FILE);
    let _ = std::fs::remove_file(STATE_BAK);
    *mgr.login_url.lock().unwrap() = None;
    mgr.state_restore_attempted.store(false, Ordering::SeqCst);
    {
        let mut cfg = mgr.config.lock().unwrap();
        cfg.enrolled = false;
        let _ = config::save(&cfg);
    }
    mgr.refresh_status();
    (200, json!({"ok": true, "data": {"status": "logged_out", "warning": warning}}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::supervisor::test_manager;

    #[test]
    fn pref_args_apply_the_same_preferences_and_reset_only_for_up() {
        let config = TsConfig {
            hostname: "test-router".into(),
            advertise_routes: vec!["192.0.2.0/24".into(), "198.51.100.0/24".into()],
            tailscale_ssh: true,
            ..TsConfig::default()
        };
        let shared = [
            "--accept-dns=false",
            "--accept-routes=false",
            "--hostname=test-router",
            "--advertise-routes=192.0.2.0/24,198.51.100.0/24",
            "--ssh=true",
        ];
        let mut set = vec!["set"];
        set.extend(shared);
        assert_eq!(pref_args_for(&config, "set"), set);
        let mut up = vec!["up"];
        up.extend(shared);
        up.push("--reset");
        assert_eq!(pref_args_for(&config, "up"), up);
        let cleared = pref_args_for(&TsConfig::default(), "set");
        assert!(cleared.iter().any(|arg| arg == "--advertise-routes="));
        assert!(cleared.iter().any(|arg| arg == "--ssh=false"));
    }

    #[test]
    fn enrollment_requires_a_password_and_config_rejects_bad_input_before_saving() {
        let state = AppState::new();
        let denied = (403, json!({
            "ok": false,
            "error": "set an agent password (ZTE_AGENT_PASSWORD) before enabling remote access",
        }));
        assert_eq!(setup(&state, b"{"), denied);
        assert_eq!(login_url(&state), denied);
        assert_eq!(
            config_set(&state, b"{"),
            (400, json!({"ok": false, "error": "invalid config JSON: EOF while parsing an object at line 1 column 1"})),
        );
        assert_eq!(
            config_set(&state, br#"{"hostname":"bad_name"}"#),
            (400, json!({"ok": false, "error": "hostname must be 1-63 chars, alphanumeric or '-'"})),
        );
        assert_eq!(
            config_set(&state, br#"{"hostname":"valid-name","advertise_routes":["192.0.2.0/33"]}"#),
            (400, json!({"ok": false, "error": "invalid CIDR route: 192.0.2.0/33"})),
        );
        assert_eq!(state.tailscale.config.lock().unwrap().hostname, "u60-pro");
    }

    #[test]
    fn enrollment_mutex_serializes_auth_key_and_interactive_login() {
        let manager = test_manager(true, Some(500));
        assert!(!manager.enrollment_active());

        let auth_guard = manager.try_begin_auth_key_enrollment().unwrap();
        assert!(manager.enrollment_active());
        assert!(manager.enrollment_is_auth_key());
        assert!(manager.try_begin_auth_key_enrollment().is_err());
        assert!(manager.try_begin_interactive_login().is_err());
        drop(auth_guard);
        assert!(!manager.enrollment_active());

        let login_guard = match manager.try_begin_interactive_login().unwrap() {
            InteractiveLoginSlot::Started(guard) => guard,
            InteractiveLoginSlot::AlreadyRunning => panic!("expected fresh interactive login"),
        };
        assert!(manager.enrollment_active());
        assert!(!manager.enrollment_is_auth_key());
        assert!(matches!(
            manager.try_begin_interactive_login().unwrap(),
            InteractiveLoginSlot::AlreadyRunning
        ));
        assert!(manager.try_begin_auth_key_enrollment().is_err());
        drop(login_guard);

        assert!(!manager.enrollment_active());
        assert!(manager.try_begin_auth_key_enrollment().is_ok());
    }

    #[test]
    fn temp_auth_key_file_is_unique_private_and_removed_on_drop() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("u60-ts-authkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = TempAuthKeyFile::write(&dir, "tskey-auth-first").unwrap();
        let second = TempAuthKeyFile::write(&dir, "tskey-auth-second").unwrap();
        let first_path = first.path.clone();
        let second_path = second.path.clone();

        assert_ne!(first_path, second_path);
        assert_eq!(std::fs::read_to_string(&first_path).unwrap(), "tskey-auth-first");
        assert_eq!(std::fs::read_to_string(&second_path).unwrap(), "tskey-auth-second");
        assert_eq!(
            std::fs::metadata(&first_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&second_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        drop(first);
        assert!(!first_path.exists());
        assert_eq!(std::fs::read_to_string(&second_path).unwrap(), "tskey-auth-second");

        drop(second);
        assert!(!second_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_nonblocking_returns_immediately_and_coalesces_background_refresh() {
        use std::sync::atomic::AtomicUsize;

        let manager = test_manager(true, Some(600));
        *manager.last_status.lock().unwrap() = (
            json!({"daemon_running": true, "state": "healthy", "relay": "hkg"}),
            100,
            1,
        );
        manager.status_seq.store(1, Ordering::SeqCst);

        let probes = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let shared_release = Arc::new(Mutex::new(Some(release_rx)));
        let (done_tx, done_rx) = mpsc::channel();

        let started_at = Instant::now();
        let mut callers = Vec::new();
        for _ in 0..4 {
            let call_mgr = Arc::clone(&manager);
            let call_probes = Arc::clone(&probes);
            let call_started = started_tx.clone();
            let call_release = Arc::clone(&shared_release);
            let call_done = done_tx.clone();
            callers.push(thread::spawn(move || {
                call_mgr.status_nonblocking_with(
                    || 200,
                    || (json!({"daemon_running": true, "state": "starting"}), true),
                    move |bg_mgr| {
                        call_probes.fetch_add(1, Ordering::SeqCst);
                        let _ = call_started.send(());
                        let rx = call_release.lock().unwrap().take();
                        if let Some(rx) = rx {
                            let _ = rx.recv_timeout(Duration::from_secs(2));
                        }
                        let seq = bg_mgr.status_seq.fetch_add(1, Ordering::SeqCst) + 1;
                        bg_mgr.store_status(
                            seq,
                            &json!({"daemon_running": true, "state": "healthy", "relay": "sin"}),
                            200,
                        );
                        let _ = call_done.send(());
                    },
                )
            }));
        }
        for caller in callers {
            let snapshot = caller.join().unwrap();
            assert_eq!(snapshot["relay"], "hkg");
        }
        assert!(started_at.elapsed() < Duration::from_millis(250));
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(probes.load(Ordering::SeqCst), 1);

        release_tx.send(()).unwrap();
        done_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let fresh = manager.status_nonblocking_with(
            || 205,
            || (json!({"daemon_running": true, "state": "starting"}), true),
            |_| panic!("fresh cache must not spawn background refresh"),
        );
        assert_eq!(fresh["relay"], "sin");
        assert_eq!(probes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn status_coalesced_joins_in_flight_refresh_and_rejects_stale_overwrite() {
        use std::sync::atomic::AtomicUsize;

        let manager = test_manager(true, Some(610));
        *manager.last_status.lock().unwrap() = (
            json!({"daemon_running": true, "state": "healthy", "relay": "hkg"}),
            100,
            1,
        );
        manager.status_seq.store(1, Ordering::SeqCst);

        let probes = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let probe_count = Arc::clone(&probes);
        let initial = manager.status_nonblocking_with(
            || 200,
            || (json!({"daemon_running": true, "state": "starting"}), true),
            move |bg_mgr| {
                probe_count.fetch_add(1, Ordering::SeqCst);
                let _ = started_tx.send(());
                let _ = release_rx.recv_timeout(Duration::from_secs(2));
                let seq = bg_mgr.status_seq.fetch_add(1, Ordering::SeqCst) + 1;
                bg_mgr.store_status(
                    seq,
                    &json!({"daemon_running": true, "state": "healthy", "relay": "nrt"}),
                    200,
                );
            },
        );
        assert_eq!(initial["relay"], "hkg");
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let waiter_mgr = Arc::clone(&manager);
        let waiter = thread::spawn(move || {
            waiter_mgr.status_coalesced_with(
                || 200,
                || (json!({"daemon_running": true, "state": "starting"}), true),
                || panic!("coalesced caller must join existing in-flight refresh"),
            )
        });
        thread::sleep(Duration::from_millis(20));
        release_tx.send(()).unwrap();
        let joined = waiter.join().unwrap();
        assert_eq!(joined["relay"], "nrt");
        assert_eq!(probes.load(Ordering::SeqCst), 1);

        manager.store_status(5, &json!({"state": "disabled"}), 210);
        manager.store_status(4, &json!({"state": "healthy"}), 211);
        let (latest, _, seq) = manager.last_status.lock().unwrap().clone();
        assert_eq!(seq, 5);
        assert_eq!(latest["state"], "disabled");
    }
}
