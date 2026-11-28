//! Tailscale management for the router agent.
//!
//! The HTTP handlers manage enrollment, preferences, and binary updates. The supervisor
//! manages tailscaled and reacts to WAN and Wi-Fi relay changes. HTTP and dashboard
//! status share a cache backed by the daemon's LocalAPI with a CLI fallback.

pub(crate) mod clean_dns;
pub mod config;
mod localapi;
pub(crate) mod netplane;
mod supervisor;
mod update;

pub use config::TsConfig;
pub(crate) use netplane::{nft_command, recover as recover_network};
pub use update::{update, versions, versions_refresh};

use localapi::{
    daemon_full_status_until, daemon_prefs_at_until, daemon_prefs_until, daemon_status,
    daemon_status_at_until, daemon_status_until, Prefs, Status,
};
use supervisor::{ChildIdentity, RelayWatchState, NETFILTER_OFF_MARKER};
#[cfg(not(test))]
use update::recover_binaries_in;
use update::VersionCatalog;

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use serde_json::{json, Value};

use crate::handlers::AppState;
use crate::httpd::mobile::{interfaces, IfAddr};
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
const ENROLLMENT_STOPPED: (u16, &str) = (409, "tailscale stopped during enrollment");

type HandlerError = (u16, String);

fn enrollment_stopped() -> HandlerError {
    (ENROLLMENT_STOPPED.0, ENROLLMENT_STOPPED.1.into())
}

fn handler_error((code, error): HandlerError) -> (u16, Value) {
    (code, json!({"ok": false, "error": error}))
}

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

        std::fs::create_dir_all(dir).map_err(|err| format!("create auth key dir: {err}"))?;
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
    prefs_lock: Mutex<()>,
    prefs_gen: AtomicU64,
    stopped_gen: AtomicU64,
    prefs_pending: AtomicBool,
    /// Desired state: should tailscaled be running?
    running: AtomicBool,
    /// True only when a kernel-TUN (`tailscale0`) daemon is confirmed active
    /// and no legacy userspace loopback forwarder is running.
    kernel_tun_active: AtomicBool,
    /// True while any userspace-networking or preflight `tailscaled` process
    /// is alive (including during stopping until `wait()` confirms exit).
    userspace_daemon_live: AtomicBool,
    /// Set only after startup confirms no orphaned `tailscaled` process from a
    /// previous agent remains alive (fail closed for loopback classification
    /// until verified).
    startup_orphan_cleared: AtomicBool,
    /// Set once startup network restore/adoption (Mihomo 5100, relay 5120) has
    /// completed so kernel TUN never races ahead of legacy 18620/18640 rules.
    network_restore_ready: AtomicBool,
    /// Set while a kernel-TUN promotion is staged/activating (between the final
    /// preflight check and publishing `active_child`) so enrollment cannot race in.
    kernel_promotion_pending: AtomicBool,
    /// Diagnostic reason when kernel TUN is unavailable or degraded to userspace.
    tun_degraded_reason: Mutex<Option<String>>,
    /// Owned kernel-TUN data plane (`u60_tail`, `U60_TS_IN`/`U60_TS_FWD`, 5110/5130/5131, sysctls).
    netplane: Mutex<netplane::NetPlane>,
    /// Dual-protocol (`127.0.0.54:53` UDP + TCP) Clean DNS resolver for kernel-TUN `tailscaled`.
    clean_dns: Arc<clean_dns::CleanDns>,
    /// Latest mount-namespace isolation verification result for the active kernel-TUN child.
    clean_dns_mount_state: Mutex<Result<bool, String>>,
    /// Fingerprint of `STATE_FILE` last confirmed free of persisted exit-node
    /// routes (`0.0.0.0/0`, `::/0`) before spawning a network-facing userspace daemon.
    exit_cleared_fingerprint: Mutex<Option<String>>,
    /// Signals the supervisor monitor loop to reconcile/update `netplane` immediately.
    netplane_dirty: AtomicBool,
    /// One-time `net_guard::on_settled` registration guard.
    net_guard_registered: AtomicBool,
    /// Shared kernel receive-steering and TCP performance owner.
    perf: Arc<crate::netfx::perf::Perf>,
    /// Update in progress — supervisor must quiesce so binaries can be swapped.
    paused: AtomicBool,
    /// OTA slot change / rollback in progress — mutually exclusive with `updating`
    /// and never cleared by `resume_supervisor()`.
    slot_change_paused: AtomicBool,
    #[cfg(test)]
    test_ota_trial_pending: AtomicBool,
    /// The single supervisor thread has been spawned.
    supervisor_started: AtomicBool,
    /// True only while the supervisor is parked with no child — the only
    /// window where swapping binaries is safe.
    supervisor_idle: AtomicBool,
    updating: AtomicBool,
    enrollment: Mutex<EnrollmentOp>,
    active_up_process: Mutex<Option<TrackedUpProcess>>,
    next_up_id: AtomicU64,
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
    mihomo: OnceLock<Weak<crate::mihomo::Mihomo>>,
    relay_watch_lock: Mutex<RelayWatchState>,
    relay_watch_cv: Condvar,
    #[cfg(test)]
    test_io: Option<TestIo>,
    #[cfg(test)]
    test_clean_dns_isolated: Option<bool>,
}

#[cfg(test)]
type TestUpCommand = dyn Fn(&[&str]) -> Command + Send + Sync;

#[cfg(test)]
type TestCli = dyn Fn(&[&str]) -> Result<String, String> + Send + Sync;

#[cfg(test)]
struct TestIo {
    root: PathBuf,
    cli: Box<TestCli>,
    status: Box<dyn Fn() -> Result<Value, String> + Send + Sync>,
    up_command: Option<Box<TestUpCommand>>,
}

struct TrackedUpProcess {
    id: u64,
    child: Child,
}

fn unix_now() -> i64 {
    unsafe { libc::time(std::ptr::null_mut()) as i64 }
}

/// Run a command with a hard timeout. On timeout the process is SIGKILLed
/// and reaped by the waiter thread.
fn run_with_timeout(cmd: Command, timeout_secs: u64) -> Result<std::process::Output, String> {
    command_output(cmd, Duration::from_secs(timeout_secs))
}

fn command_output(mut cmd: Command, timeout: Duration) -> Result<std::process::Output, String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(timeout) {
        Ok(result) => result.map_err(|e| format!("wait: {e}")),
        Err(_) => {
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            Err(format!("timed out after {}s", timeout.as_secs_f64()))
        }
    }
}

/// `tailscale --socket=... <args>` -> stdout. Mirrors ubus::call.
fn cli(args: &[&str], timeout_secs: u64) -> Result<String, String> {
    cli_with_timeout(args, Duration::from_secs(timeout_secs))
}

fn cli_with_timeout(args: &[&str], timeout: Duration) -> Result<String, String> {
    cli_output(command_output(cli_command(args), timeout)?)
}

fn cli_command(args: &[&str]) -> Command {
    let mut cmd = Command::new(TAILSCALE_BIN);
    cmd.arg(format!("--socket={SOCK}"));
    cmd.args(args);
    cmd
}

fn cli_output(out: std::process::Output) -> Result<String, String> {
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let msg = if stderr.trim().is_empty() {
            stdout
        } else {
            stderr
        };
        return Err(msg.trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn read_cli_pipe(mut pipe: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        bytes
    })
}

fn installed() -> bool {
    Path::new(TAILSCALED_BIN).exists() && Path::new(TAILSCALE_BIN).exists()
}

fn state_file_exists() -> bool {
    Path::new(STATE_FILE).exists()
}

impl TailscaleManager {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_perf(crate::netfx::perf::Perf::router())
    }

    pub(crate) fn with_perf(perf: Arc<crate::netfx::perf::Perf>) -> Self {
        #[cfg(not(test))]
        {
            recover_binaries_in(Path::new(BIN_DIR));
            let manager = Self::with_config_and_perf(config::load(), perf);
            manager
                .prefs_pending
                .store(config::exists(), Ordering::Relaxed);
            manager
        }
        #[cfg(test)]
        Self::with_config_and_perf(TsConfig::default(), perf)
    }

    #[cfg(test)]
    fn with_config(cfg: TsConfig) -> Self {
        Self::with_config_and_perf(cfg, crate::netfx::perf::Perf::router())
    }

    fn with_config_and_perf(cfg: TsConfig, perf: Arc<crate::netfx::perf::Perf>) -> Self {
        Self {
            config: Mutex::new(cfg),
            prefs_lock: Mutex::new(()),
            prefs_gen: AtomicU64::new(0),
            stopped_gen: AtomicU64::new(0),
            prefs_pending: AtomicBool::new(false),
            running: AtomicBool::new(false),
            kernel_tun_active: AtomicBool::new(false),
            userspace_daemon_live: AtomicBool::new(false),
            startup_orphan_cleared: AtomicBool::new(cfg!(test)),
            network_restore_ready: AtomicBool::new(cfg!(test)),
            kernel_promotion_pending: AtomicBool::new(false),
            tun_degraded_reason: Mutex::new(None),
            netplane: Mutex::new(netplane::NetPlane::router()),
            clean_dns: Arc::new(clean_dns::CleanDns::new()),
            clean_dns_mount_state: Mutex::new(Ok(false)),
            exit_cleared_fingerprint: Mutex::new(None),
            netplane_dirty: AtomicBool::new(false),
            net_guard_registered: AtomicBool::new(false),
            perf,
            paused: AtomicBool::new(false),
            slot_change_paused: AtomicBool::new(false),
            #[cfg(test)]
            test_ota_trial_pending: AtomicBool::new(false),
            supervisor_started: AtomicBool::new(false),
            supervisor_idle: AtomicBool::new(true),
            updating: AtomicBool::new(false),
            enrollment: Mutex::new(EnrollmentOp::Idle),
            active_up_process: Mutex::new(None),
            next_up_id: AtomicU64::new(0),
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
            mihomo: OnceLock::new(),
            relay_watch_lock: Mutex::new(RelayWatchState::default()),
            relay_watch_cv: Condvar::new(),
            #[cfg(test)]
            test_io: None,
            #[cfg(test)]
            test_clean_dns_isolated: None,
        }
    }

    fn is_installed(&self) -> bool {
        #[cfg(test)]
        if self.test_io.is_some() {
            return true;
        }
        installed()
    }

    fn device_path(&self, path: &str) -> PathBuf {
        #[cfg(test)]
        if let Some(io) = &self.test_io {
            return io.root.join(Path::new(path).file_name().unwrap());
        }
        PathBuf::from(path)
    }

    fn run_cli(&self, args: &[&str], timeout_secs: u64) -> Result<String, String> {
        #[cfg(test)]
        if let Some(io) = &self.test_io {
            return (io.cli)(args);
        }
        cli(args, timeout_secs)
    }

    fn probe_status<T: serde::de::DeserializeOwned>(&self, deadline: Instant) -> Result<T, String> {
        #[cfg(test)]
        if let Some(io) = &self.test_io {
            return serde_json::from_value((io.status)()?).map_err(|error| error.to_string());
        }
        daemon_status_until(deadline)
    }

    fn stopped_generation(&self) -> u64 {
        self.stopped_gen.load(Ordering::Acquire)
    }

    fn check_enrollment_generation(&self, stopped: u64) -> Result<(), HandlerError> {
        if stopped == self.stopped_generation() {
            Ok(())
        } else {
            Err(enrollment_stopped())
        }
    }

    fn check_enrollment_admission(&self, stopped: u64) -> Result<(), HandlerError> {
        self.check_enrollment_generation(stopped)?;
        if self.updating.load(Ordering::Acquire) {
            return Err((409, "update in progress".into()));
        }
        if self.slot_change_blocked() {
            return Err((409, "OTA slot change or health trial in progress".into()));
        }
        if self.kernel_promotion_pending.load(Ordering::Acquire) {
            return Err((409, "tailscale kernel TUN activation in progress; retry shortly".into()));
        }
        Ok(())
    }

    fn enrollment_active(&self) -> bool {
        *self
            .enrollment
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            != EnrollmentOp::Idle
    }

    #[cfg(test)]
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

    fn try_begin_interactive_login(self: &Arc<Self>) -> Result<InteractiveLoginSlot, &'static str> {
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

    fn apply_current_prefs(&self) -> Result<(), String> {
        let _prefs = self.prefs_lock.lock().unwrap();
        if !self.running.load(Ordering::SeqCst) || self.is_paused() {
            return Ok(());
        }
        let cfg = self.config.lock().unwrap().clone();
        self.apply_prefs_locked(&cfg)
    }

    fn apply_prefs_locked(&self, cfg: &TsConfig) -> Result<(), String> {
        let result = self.set_daemon_prefs(cfg);
        self.prefs_pending.store(result.is_err(), Ordering::Relaxed);
        result
    }

    fn set_daemon_prefs(&self, cfg: &TsConfig) -> Result<(), String> {
        let effective = self.effective_daemon_config(cfg);
        let args = pref_args_for(&effective, "set");
        let refs: Vec<_> = args.iter().map(String::as_str).collect();
        self.run_cli(&refs, CLI_TIMEOUT_SECS).map(|_| ())
    }

    fn run_enrollment_up(
        &self,
        stopped: u64,
        extra_args: &[&str],
        timeout: Duration,
    ) -> Result<(u64, Result<String, String>), HandlerError> {
        let prefs = self.prefs_lock.lock().unwrap();
        self.check_enrollment_admission(stopped)?;
        if !self.running.load(Ordering::SeqCst) || self.is_paused() {
            return Err(enrollment_stopped());
        }
        self.cancel_active_up_locked();
        let generation = self.prefs_gen.load(Ordering::Relaxed);
        let effective = self.effective_daemon_config(&self.config.lock().unwrap());
        let args = pref_args_for(&effective, "up");
        let result = self
            .run_tracked_up_locked(prefs, stopped, &args, extra_args, timeout)
            .ok_or_else(enrollment_stopped)?;
        self.check_enrollment_generation(stopped)?;
        Ok((generation, result))
    }

    pub(super) fn run_self_heal_up(
        &self,
        stopped: u64,
        extra_args: &[&str],
        timeout: Duration,
    ) -> Option<(u64, Result<String, String>)> {
        let prefs = self.prefs_lock.lock().unwrap();
        if stopped != self.stopped_generation()
            || !self.running.load(Ordering::SeqCst)
            || self.is_paused()
            || self.updating.load(Ordering::SeqCst)
            || self.enrollment_active()
            || self.active_up_process.lock().unwrap().is_some()
        {
            return None;
        }
        let cfg = self.config.lock().unwrap().clone();
        if !cfg.enabled {
            return None;
        }
        let generation = self.prefs_gen.load(Ordering::Relaxed);
        let effective = self.effective_daemon_config(&cfg);
        let args = pref_args_for(&effective, "up");
        let result = self.run_tracked_up_locked(prefs, stopped, &args, extra_args, timeout)?;
        if stopped != self.stopped_generation() {
            return None;
        }
        Some((generation, result))
    }

    fn run_tracked_up_locked(
        &self,
        prefs: std::sync::MutexGuard<'_, ()>,
        stopped: u64,
        args: &[String],
        extra_args: &[&str],
        timeout: Duration,
    ) -> Option<Result<String, String>> {
        let refs: Vec<_> = args
            .iter()
            .map(String::as_str)
            .chain(extra_args.iter().copied())
            .collect();
        let mut cmd = {
            #[cfg(test)]
            if let Some(io) = &self.test_io {
                if let Some(build) = &io.up_command {
                    build(&refs)
                } else {
                    drop(prefs);
                    let result = self.run_cli(&refs, timeout.as_secs().max(1));
                    if stopped != self.stopped_generation() {
                        return None;
                    }
                    return Some(result);
                }
            } else {
                cli_command(&refs)
            }
            #[cfg(not(test))]
            {
                cli_command(&refs)
            }
        };
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(error) => return Some(Err(format!("spawn: {error}"))),
        };
        let stdout = read_cli_pipe(child.stdout.take().unwrap());
        let stderr = read_cli_pipe(child.stderr.take().unwrap());
        let up_id = self.next_up_id.fetch_add(1, Ordering::Relaxed) + 1;
        *self.active_up_process.lock().unwrap() = Some(TrackedUpProcess { id: up_id, child });
        drop(prefs);

        let deadline = Instant::now() + timeout;
        let result = loop {
            let mut active = self.active_up_process.lock().unwrap();
            let Some(tracked) = active.as_mut().filter(|tracked| tracked.id == up_id) else {
                return None;
            };
            match tracked.child.try_wait() {
                Ok(Some(status)) => {
                    *active = None;
                    break Ok(status);
                }
                Ok(None) if Instant::now() < deadline => {}
                outcome => {
                    let _ = tracked.child.kill();
                    let _ = tracked.child.wait();
                    *active = None;
                    break Err(match outcome {
                        Err(error) => format!("wait: {error}"),
                        _ => format!("timed out after {}s", timeout.as_secs_f64()),
                    });
                }
            }
            drop(active);
            thread::sleep(Duration::from_millis(20));
        };
        let result = result.and_then(|status| {
            cli_output(std::process::Output {
                status,
                stdout: stdout.join().unwrap_or_default(),
                stderr: stderr.join().unwrap_or_default(),
            })
        });
        if stopped != self.stopped_generation() {
            return None;
        }
        Some(result)
    }

    pub(super) fn cancel_active_up_locked(&self) {
        if let Some(mut tracked) = self.active_up_process.lock().unwrap().take() {
            let _ = tracked.child.kill();
            let _ = tracked.child.wait();
        }
    }

    fn finish_up(&self, generation: u64) -> Result<(), String> {
        let _prefs = self.prefs_lock.lock().unwrap();
        self.reconcile_up_locked(generation)
    }

    fn reconcile_up_locked(&self, generation: u64) -> Result<(), String> {
        if self.up_is_current(generation)
            && (generation != self.prefs_gen.load(Ordering::Relaxed)
                || self.prefs_pending.load(Ordering::Relaxed))
        {
            let cfg = self.config.lock().unwrap().clone();
            self.apply_prefs_locked(&cfg)?;
        }
        Ok(())
    }

    fn up_is_current(&self, generation: u64) -> bool {
        self.running.load(Ordering::SeqCst)
            && !self.is_paused()
            && generation >= self.stopped_gen.load(Ordering::Relaxed)
    }

    fn commit_config_locked(&self, mut candidate: TsConfig) -> Result<u64, String> {
        let mut current = self.config.lock().unwrap();
        candidate.pinned_version.clone_from(&current.pinned_version);
        self.save_config(&candidate)?;
        *current = candidate;
        drop(current);
        let gen = self.prefs_gen.fetch_add(1, Ordering::Relaxed) + 1;
        self.sync_mihomo_exit_state();
        Ok(gen)
    }

    fn save_config(&self, cfg: &TsConfig) -> Result<(), String> {
        #[cfg(test)]
        if let Some(io) = &self.test_io {
            return config::save_at(&io.root.join("config.json"), cfg);
        }
        config::save(cfg)
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
        base_fn: impl FnOnce() -> Value,
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
        let base = base_fn();
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
        if cached["daemon_running"].as_bool() == Some(true)
            && base["daemon_running"].as_bool() == Some(true)
        {
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
        base_fn: impl FnOnce() -> Value,
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
        let base = base_fn();
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

    fn build_base_status(&self) -> Value {
        let cfg = self.config.lock().unwrap().clone();
        self.base_status_for(&cfg).0
    }

    fn base_status_for(&self, cfg: &TsConfig) -> (Value, bool) {
        let daemon_up = self.active_child.lock().unwrap().is_some();
        let installed = self.is_installed();

        let mut payload = json!({
            "installed": installed,
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
            "advertise_exit_node": cfg.advertise_exit_node,
            "exit_via_mihomo": cfg.exit_via_mihomo,
            "tailscale_ssh": cfg.tailscale_ssh,
            "hold_wakelock": cfg.hold_wakelock,
            "pinned_version": cfg.pinned_version,
        });
        payload["routing"] = routing_status(
            cfg,
            None,
            None,
            &[],
            self.has_prefs_intent(cfg),
        );
        self.attach_tun_diagnostics(&mut payload["routing"], cfg);

        if !installed {
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
        let stopped = self.stopped_generation();
        let child = *self.active_child.lock().unwrap();
        let cfg = self.config.lock().unwrap().clone();
        let (mut payload, needs_probe) = self.base_status_for(&cfg);
        let subnets = lan_subnets(&interfaces().unwrap_or_default());
        payload["routing"]["lan_subnets"] = json!(subnets);
        if !needs_probe {
            return payload;
        }

        let deadline = Instant::now() + Duration::from_secs(STATUS_CLI_TIMEOUT_SECS);
        let status: Status = match self.probe_status(deadline) {
            Ok(v) => v,
            Err(e) => {
                payload["state"] = json!("starting");
                payload["error"] = json!(e);
                return payload;
            }
        };

        let prefs = daemon_prefs_until(deadline);
        payload["routing"] = routing_status(
            &cfg,
            Some(&status),
            prefs.as_ref(),
            &subnets,
            self.has_prefs_intent(&cfg),
        );
        self.attach_tun_diagnostics(&mut payload["routing"], &cfg);
        let backend = status.backend_state.as_str();
        let self_obj = status.self_status.unwrap_or_default();
        let online = self_obj.online;

        payload["backend_state"] = json!(backend);
        payload["health"] = json!(status.health);
        payload["tailscale_ips"] = json!(status.tailscale_ips);
        payload["dns_name"] = json!(self_obj.dns_name);
        payload["relay"] = json!(self_obj.relay);
        payload["direct"] = json!(self_obj.cur_addr.is_some_and(|addr| !addr.is_empty()));
        payload["key_expiry"] = json!(self_obj.key_expiry);
        payload["expired"] = json!(self_obj.expired);
        payload["client_version"] = json!(status.version);

        {
            let mut login_url = self.login_url.lock().unwrap();
            let active_child = *self.active_child.lock().unwrap();
            if stopped == self.stopped_generation()
                && self.running.load(Ordering::Acquire)
                && child == active_child
            {
                if backend == "Running" {
                    *login_url = None;
                    payload["login_url"] = Value::Null;
                } else if let Some(url) = status.auth_url.as_deref().filter(|url| !url.is_empty()) {
                    payload["login_url"] = json!(url);
                    *login_url = Some(url.to_string());
                }
            } else {
                payload["login_url"] = Value::Null;
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

    fn has_prefs_intent(&self, cfg: &TsConfig) -> bool {
        cfg.enabled || cfg.enrolled || self.prefs_pending.load(Ordering::Relaxed)
    }

    fn attach_tun_diagnostics(&self, routing: &mut Value, cfg: &TsConfig) {
        let reason = self
            .tun_degraded_reason
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        if let Some(reason) = reason {
            if let Some(tun) = routing["tun"].as_object_mut() {
                tun.insert("degraded".into(), json!(true));
                tun.insert("reason".into(), json!(reason));
            }
        }
        let mount_state = self
            .clean_dns_mount_state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        let dnat_ready = self.clean_dns_dnat_ready();
        let mount_ref = match &mount_state {
            Ok(true) if !dnat_ready => Err("clean DNS fallback DNAT rule is not confirmed"),
            Ok(v) => Ok(*v),
            Err(err) => Err(err.as_str()),
        };
        let clean_dns_snap = self.clean_dns.snapshot();
        routing["clean_dns"] = clean_dns_snap.to_status_json(
            cfg.enabled,
            self.kernel_tun_active.load(Ordering::Acquire),
            mount_ref,
        );
        if cfg.advertise_exit_node && !self.clean_dns_isolated() {
            if let Some(exit) = routing["exit"].as_object_mut() {
                exit.insert("clean_dns_gated".into(), json!(true));
            }
        }
    }

    /// True when `ip u60_tail`'s `dns_out` state matches Clean DNS's current
    /// binding (`Some(port)` = exact fallback redirect confirmed; `None` = no
    /// owned fallback redirect active).
    pub(super) fn clean_dns_dnat_ready(&self) -> bool {
        let expected_port = self.clean_dns.dnat_port();
        self.netplane
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clean_dns_dnat_confirmed(expected_port)
    }

    /// True when the Clean DNS resolver is running, its child mount namespace
    /// isolation check succeeded, AND any fallback DNAT rule is confirmed.
    pub(super) fn clean_dns_verified(&self) -> bool {
        #[cfg(test)]
        if let Some(val) = self.test_clean_dns_isolated {
            return val;
        }
        self.clean_dns.is_running()
            && self.clean_dns_dnat_ready()
            && matches!(
                *self
                    .clean_dns_mount_state
                    .lock()
                    .unwrap_or_else(|err| err.into_inner()),
                Ok(true)
            )
    }

    /// True only when kernel-TUN mode is active AND Clean DNS isolation is
    /// verified. Exit Node advertisement is gated on this invariant so an
    /// approved userspace or unisolated daemon can never serve Exit traffic
    /// through the host resolver.
    pub(super) fn clean_dns_isolated(&self) -> bool {
        #[cfg(test)]
        if let Some(val) = self.test_clean_dns_isolated {
            return val;
        }
        self.kernel_tun_active.load(Ordering::Acquire) && self.clean_dns_verified()
    }

    pub(super) fn effective_daemon_config(&self, cfg: &TsConfig) -> TsConfig {
        let mut effective = cfg.clone();
        if effective.advertise_exit_node && !self.clean_dns_isolated() {
            effective.advertise_exit_node = false;
        }
        effective
    }

    pub(super) fn set_tun_degraded(&self, reason: Option<String>) {
        *self
            .tun_degraded_reason
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = reason;
    }

    pub(crate) fn set_mihomo(&self, mihomo: &Arc<crate::mihomo::Mihomo>) {
        let _ = self.mihomo.set(Arc::downgrade(mihomo));
    }

    pub(crate) fn sync_clean_dns_mode(&self) {
        let exit_via_mihomo = self.config.lock().unwrap().exit_via_mihomo;
        let mode = if exit_via_mihomo {
            if let Some((addr, username, secret)) = self
                .mihomo
                .get()
                .and_then(Weak::upgrade)
                .and_then(|m| m.clean_dns_proxy())
            {
                clean_dns::UpstreamMode::Proxy {
                    addr,
                    username,
                    secret,
                }
            } else {
                clean_dns::UpstreamMode::Direct
            }
        } else {
            clean_dns::UpstreamMode::Direct
        };
        let _ = self.clean_dns.set_mode(mode);
    }

    pub(crate) fn mihomo_state_changed(&self) {
        self.sync_clean_dns_mode();
    }

    pub(crate) fn sync_mihomo_exit_state(&self) {
        self.sync_clean_dns_mode();
        let cfg = self.config.lock().unwrap().clone();
        let isolated = self.clean_dns_isolated();
        let (exit_v4, exit_v6, skip_v4, skip_v6) = {
            let plane = self
                .netplane
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            match plane.confirmed_layout() {
                Some(layout) => (
                    layout.exit_v4,
                    layout.exit_v6,
                    layout
                        .approved_subnets_v4
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                    layout
                        .approved_subnets_v6
                        .iter()
                        .map(ToString::to_string)
                        .collect(),
                ),
                None => (false, false, Vec::new(), Vec::new()),
            }
        };
        let enabled = cfg.enabled && cfg.exit_via_mihomo;
        let desired = crate::mihomo::TailscaleExitConfig {
            sniffer: enabled,
            tproxy_v4: enabled && isolated && exit_v4,
            tproxy_v6: enabled && isolated && exit_v6,
            skip_v4,
            skip_v6,
        };
        if let Some(mihomo) = self.mihomo.get().and_then(Weak::upgrade) {
            mihomo.set_tailscale_exit(desired);
        }
    }

    pub(super) fn mark_netplane_dirty(&self) {
        self.netplane_dirty.store(true, Ordering::Release);
        self.wake_supervisor();
    }

    pub(super) fn clear_netfilter_off_marker(&self) {
        let _ = std::fs::remove_file(self.device_path(NETFILTER_OFF_MARKER));
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
    /// Returns `None` if `config` or `last_status` is locked or poisoned.
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

    /// Whether a legacy Tailscale userspace forwarder may be re-dialing remote
    /// Tailnet clients onto `127.0.0.1` / `::1` over `lo`. Fails closed (`true`)
    /// until startup confirms no orphan `tailscaled` survived, when config or
    /// child state is contended, while any userspace/preflight daemon has not
    /// confirmed exit, or while Tailscale is enabled or running without
    /// confirmed kernel TUN ownership.
    pub fn userspace_loopback_active(&self) -> bool {
        if !self.startup_orphan_cleared.load(Ordering::Acquire) {
            return true;
        }
        if self.userspace_daemon_live.load(Ordering::Acquire) {
            return true;
        }
        let enabled = match self.config.try_lock() {
            Ok(cfg) => cfg.enabled,
            Err(_) => return true,
        };
        let has_live_child = match self.active_child.try_lock() {
            Ok(child) => child.is_some(),
            Err(_) => return true,
        };
        if !enabled && !self.running.load(Ordering::Acquire) && !has_live_child {
            return false;
        }
        !self.kernel_tun_active.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn set_kernel_tun_for_test(&self, active: bool) {
        self.kernel_tun_active.store(active, Ordering::Release);
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
    fn after_enrollment_success(&self, stopped: u64, generation: u64) -> Result<(), HandlerError> {
        let _prefs = self.prefs_lock.lock().unwrap();
        self.check_enrollment_admission(stopped)?;
        if !self.up_is_current(generation) {
            return Err(enrollment_stopped());
        }
        let mut cfg = self.config.lock().unwrap().clone();
        cfg.enabled = true;
        cfg.enrolled = true;
        let hold = cfg.hold_wakelock;
        let reconciled = self.reconcile_up_locked(generation);
        self.commit_config_locked(cfg)
            .map_err(|error| (500, error))?;
        if let Err(error) =
            copy_state_atomically(&self.device_path(STATE_FILE), &self.device_path(STATE_BAK))
        {
            eprintln!("[tailscale] back up enrolled state: {error}");
        }
        self.state_restore_attempted.store(false, Ordering::SeqCst);
        if hold {
            self.acquire_wakelock();
        }
        if let Err(error) = reconciled {
            eprintln!("[tailscale] reapply preferences after enrollment: {error}");
        }
        Ok(())
    }
}

fn pref_args_for(cfg: &TsConfig, verb: &str) -> Vec<String> {
    let mut args = vec![
        verb.to_string(),
        "--accept-dns=false".to_string(),
        "--accept-routes=false".to_string(),
        "--netfilter-mode=off".to_string(),
        format!("--advertise-exit-node={}", cfg.advertise_exit_node),
        format!("--hostname={}", cfg.hostname),
        format!("--advertise-routes={}", cfg.advertise_routes.join(",")),
        format!("--ssh={}", cfg.tailscale_ssh),
    ];
    if verb == "up" {
        args.push("--reset".to_string());
    }
    args
}

fn copy_state_atomically(src: &Path, dest: &Path) -> std::io::Result<()> {
    let state = std::fs::read(src)?;
    crate::ota::storage::atomic_write_preserving_parent(dest, &state, 0o600)
}

fn lan_subnets(addresses: &[IfAddr]) -> Vec<IpNet> {
    addresses
        .iter()
        .filter(|entry| {
            entry.name == "br-lan"
                && !matches!(entry.addr, std::net::IpAddr::V6(addr) if addr.is_unicast_link_local())
        })
        .filter_map(|entry| {
            if entry.prefix == 0 {
                Some(IpNet::from(entry.addr))
            } else {
                IpNet::new(entry.addr, entry.prefix)
                    .ok()
                    .map(|net| net.trunc())
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn routing_status(
    cfg: &TsConfig,
    status: Option<&Status>,
    prefs: Option<&Prefs>,
    subnets: &[IpNet],
    pending_daemon: bool,
) -> Value {
    let parse_prefixes = |routes: &[String]| -> BTreeSet<IpNet> {
        routes
            .iter()
            .filter_map(|route| route.parse::<IpNet>().ok())
            .map(|net| net.trunc())
            .collect()
    };
    let configured = parse_prefixes(&cfg.advertise_routes);
    let defaults =
        [config::DEFAULT_V4, config::DEFAULT_V6].map(|route| route.parse::<IpNet>().unwrap());
    let running = status.is_some_and(|status| status.backend_state == "Running");
    let sync = if !running {
        if pending_daemon {
            "pending_daemon"
        } else {
            "unknown"
        }
    } else if let Some(prefs) = prefs {
        let mut desired = configured.clone();
        if cfg.advertise_exit_node {
            desired.extend(defaults);
        }
        let actual = parse_prefixes(&prefs.advertise_routes);
        if desired == actual
            && prefs.netfilter_mode == Some(0)
            && prefs.corp_dns == Some(false)
            && prefs.route_all == Some(false)
            && prefs.run_ssh == Some(cfg.tailscale_ssh)
            && prefs.hostname.as_deref() == Some(cfg.hostname.as_str())
            && prefs
                .advertise_routes
                .iter()
                .all(|route| route.parse::<IpNet>().is_ok())
        {
            "applied"
        } else {
            "drift"
        }
    } else {
        "unknown"
    };
    let netfilter_mode = match prefs.and_then(|prefs| prefs.netfilter_mode) {
        Some(0) => "off",
        Some(1) => "nodivert",
        Some(2) => "on",
        _ => "unknown",
    };
    let (mode, active) = match status.and_then(|status| status.tun) {
        Some(true) => ("kernel", true),
        Some(false) => ("userspace", false),
        None => ("unknown", false),
    };
    let self_status = status.and_then(|status| status.self_status.as_ref());
    let allowed = self_status
        .map(|status| parse_prefixes(&status.allowed_ips))
        .unwrap_or_default();
    let primary = self_status
        .map(|status| parse_prefixes(&status.primary_routes))
        .unwrap_or_default();
    let node_ips = self_status
        .into_iter()
        .flat_map(|status| &status.tailscale_ips)
        .chain(
            status
                .and_then(|status| status.tailscale_ips.as_ref())
                .into_iter()
                .flatten(),
        )
        .filter_map(|address| address.parse::<std::net::IpAddr>().ok())
        .map(IpNet::from)
        .collect::<BTreeSet<_>>();
    let routes: Vec<_> = cfg
        .advertise_routes
        .iter()
        .filter_map(|route| {
            let prefix = route.parse::<IpNet>().ok()?;
            if config::normalize_route(route).is_err() || node_ips.contains(&prefix) {
                return None;
            }
            let state = if !running {
                "unknown"
            } else if primary.contains(&prefix) {
                "approved"
            } else if allowed.contains(&prefix) {
                "standby"
            } else {
                "pending"
            };
            Some(json!({"prefix": prefix, "state": state}))
        })
        .collect();
    let exit_option = self_status.is_some_and(|status| status.exit_node_option);
    let exit_state = |approved| {
        if !cfg.advertise_exit_node {
            "off"
        } else if !running {
            "unknown"
        } else if approved {
            "approved"
        } else {
            "pending"
        }
    };
    let approved_v4 = allowed.contains(&defaults[0]);
    let approved_v6 = allowed.contains(&defaults[1]);
    let implicit_dual_stack = exit_option && !approved_v4 && !approved_v6;
    let approved_v4 = implicit_dual_stack || approved_v4;
    let approved_v6 = implicit_dual_stack || approved_v6;
    json!({
        "sync": sync,
        "tun": {"mode": mode, "active": active, "netfilter_mode": netfilter_mode},
        "lan_subnets": subnets,
        "routes": routes,
        "exit": {
            "advertised": cfg.advertise_exit_node,
            "state": exit_state(approved_v4 || approved_v6),
            "state_v4": exit_state(approved_v4),
            "state_v6": exit_state(approved_v6),
            "via_mihomo": cfg.exit_via_mihomo,
        }
    })
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
    let stopped = mgr.stopped_generation();
    if let Some(resp) = require_password(state) {
        return resp;
    }
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let key = match parsed["auth_key"].as_str() {
        Some(k) if !k.trim().is_empty() => k.trim().to_string(),
        _ => {
            return (
                400,
                json!({"ok": false, "error": "missing 'auth_key' field"}),
            )
        }
    };
    let _enroll_guard = {
        let Ok(_prefs) = mgr.prefs_lock.try_lock() else {
            return handler_error((409, "tailscale preferences are being changed".into()));
        };
        if let Err(error) = mgr.check_enrollment_admission(stopped) {
            return handler_error(error);
        }
        match mgr.try_begin_auth_key_enrollment() {
            Ok(guard) => guard,
            Err(error) => return handler_error((409, error.into())),
        }
    };

    if mgr.device_path(STATE_FILE).exists() {
        let current = mgr.refresh_status();
        if let Err(error) = mgr.check_enrollment_generation(stopped) {
            return handler_error(error);
        }
        if current["backend_state"].as_str() == Some("Running") {
            return (
                409,
                json!({"ok": false, "error": "already enrolled — logout first to re-enroll"}),
            );
        }
    }

    if let Err(error) = mgr.ensure_daemon_ready(stopped, 30) {
        return handler_error(error);
    }

    // Revalidate against the now-published child: when STATE_FILE exists, admit
    // `up --auth-key` ONLY when the daemon positively confirms `NeedsLogin`.
    // `Running` / `Starting` / `Stopped` indicate an existing profile; `NoState`
    // or a failed read means enrollment state is still unknown (503 retryable).
    if mgr.device_path(STATE_FILE).exists() {
        let current = mgr.refresh_status();
        if let Err(error) = mgr.check_enrollment_generation(stopped) {
            return handler_error(error);
        }
        match current["backend_state"].as_str() {
            Some("NeedsLogin") => {}
            Some("Running" | "Starting" | "Stopped") => {
                return (
                    409,
                    json!({"ok": false, "error": "already enrolled — logout first to re-enroll"}),
                );
            }
            _ => {
                return (
                    503,
                    json!({"ok": false, "error": "cannot verify tailscale enrollment state — retry shortly"}),
                );
            }
        }
    }

    let keyfile = match TempAuthKeyFile::write(&mgr.device_path(RUN_DIR), &key) {
        Ok(file) => file,
        Err(error) => return (500, json!({"ok": false, "error": error})),
    };

    let auth_key = format!("--auth-key=file:{}", keyfile.path_str());
    let outcome = mgr.run_enrollment_up(stopped, &["--timeout=60s", &auth_key], Duration::from_secs(90));
    drop(keyfile);
    let (generation, result) = match outcome {
        Ok(result) => result,
        Err(error) => return handler_error(error),
    };

    match result {
        Ok(_) => {
            if let Err(error) = mgr.after_enrollment_success(stopped, generation) {
                return handler_error(error);
            }
            let payload = mgr.refresh_status();
            (200, json!({"ok": true, "data": payload}))
        }
        Err(e) => {
            if let Err(error) = mgr.finish_up(generation) {
                eprintln!("[tailscale] reapply preferences after up: {error}");
            }
            if let Err(error) = mgr.check_enrollment_generation(stopped) {
                return handler_error(error);
            }
            (
                502,
                json!({"ok": false, "error": format!("tailscale up: {e}")}),
            )
        }
    }
}

/// POST /api/tailscale/login-url — interactive enrollment alternative.
/// Kicks off `tailscale up --json` in the background and returns the AuthURL.
pub fn login_url(state: &AppState) -> (u16, Value) {
    let mgr = &state.tailscale;
    let stopped = mgr.stopped_generation();
    if let Some(resp) = require_password(state) {
        return resp;
    }
    let slot = {
        let Ok(_prefs) = mgr.prefs_lock.try_lock() else {
            return handler_error((409, "tailscale preferences are being changed".into()));
        };
        if let Err(error) = mgr.check_enrollment_admission(stopped) {
            return handler_error(error);
        }
        let cfg = mgr.config.lock().unwrap().clone();
        if cfg.enrolled && !cfg.enabled {
            return (
                409,
                json!({"ok": false, "error": "tailscale is disabled — POST /api/tailscale/enable first"}),
            );
        }
        match mgr.try_begin_interactive_login() {
            Ok(slot) => slot,
            Err(error) => return handler_error((409, error.into())),
        }
    };
    if let Err(error) = mgr.ensure_daemon_ready(stopped, 30) {
        return handler_error(error);
    }

    let current = mgr.refresh_status();
    if let Err(error) = mgr.check_enrollment_generation(stopped) {
        return handler_error(error);
    }
    if current["backend_state"].as_str() == Some("Running") {
        return (409, json!({"ok": false, "error": "already enrolled"}));
    }
    if let Some(url) = current["login_url"].as_str() {
        if !url.is_empty() {
            return (
                200,
                json!({"ok": true, "data": {"login_url": url, "pending": false}}),
            );
        }
    }

    if let InteractiveLoginSlot::Started(login_guard) = slot {
        let mgr2 = Arc::clone(&state.tailscale);
        thread::spawn(move || {
            let _guard = login_guard;
            let Ok((generation, _)) =
                mgr2.run_enrollment_up(stopped, &["--json", "--timeout=300s"], Duration::from_secs(310))
            else {
                return;
            };
            let status = mgr2.refresh_status();
            if status["backend_state"].as_str() == Some("Running") {
                if let Err((_, error)) = mgr2.after_enrollment_success(stopped, generation) {
                    eprintln!("[tailscale] finish interactive enrollment: {error}");
                }
                mgr2.refresh_status();
            } else if let Err(error) = mgr2.finish_up(generation) {
                eprintln!("[tailscale] reapply preferences after up: {error}");
            }
        });
    }

    // Poll briefly for the AuthURL to appear — wall-clock bounded so a
    // wedged daemon (8s CLI timeout per probe) can't pin this worker thread
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(500));
        if let Err(error) = mgr.check_enrollment_generation(stopped) {
            return handler_error(error);
        }
        let status = mgr.refresh_status();
        if let Err(error) = mgr.check_enrollment_generation(stopped) {
            return handler_error(error);
        }
        if let Some(url) = status["login_url"].as_str() {
            if !url.is_empty() {
                return (
                    200,
                    json!({"ok": true, "data": {"login_url": url, "pending": false}}),
                );
            }
        }
    }
    if let Err(error) = mgr.check_enrollment_generation(stopped) {
        return handler_error(error);
    }
    (
        202,
        json!({"ok": true, "data": {"login_url": Value::Null, "pending": true}}),
    )
}

/// POST /api/tailscale/enable — returns immediately; the supervisor brings
/// the daemon up in the background. Poll /status for progress.
pub fn enable(state: &AppState) -> (u16, Value) {
    if let Some(resp) = require_password(state) {
        return resp;
    }
    let mgr = &state.tailscale;
    let Ok(_prefs) = mgr.prefs_lock.try_lock() else {
        return (
            409,
            json!({"ok": false, "error": "tailscale preferences are being changed"}),
        );
    };
    if mgr.updating.load(Ordering::Acquire) {
        return handler_error((409, "update in progress".into()));
    }
    if mgr.slot_change_blocked() {
        return handler_error((409, "OTA slot change or health trial in progress".into()));
    }
    match mgr.do_enable() {
        Ok(()) => (200, json!({"ok": true, "data": {"status": "enabling"}})),
        Err(e) => (500, json!({"ok": false, "error": e})),
    }
}

/// POST /api/tailscale/disable
pub fn disable(state: &AppState) -> (u16, Value) {
    let mgr = &state.tailscale;
    let Ok(prefs) = mgr.prefs_lock.try_lock() else {
        return (
            409,
            json!({"ok": false, "error": "tailscale preferences are being changed"}),
        );
    };
    if mgr.updating.load(Ordering::Acquire) {
        return handler_error((409, "update in progress".into()));
    }
    if mgr.slot_change_blocked() {
        return handler_error((409, "OTA slot change or health trial in progress".into()));
    }
    if let Err(error) = mgr.commit_disable_locked(false) {
        return handler_error((500, error));
    }
    mgr.stop_daemon_locked();
    drop(prefs);
    mgr.refresh_status();
    (200, json!({"ok": true, "data": {"status": "disabled"}}))
}

/// PUT /api/tailscale/config
pub fn config_set(state: &AppState, body: &[u8]) -> (u16, Value) {
    let mgr = &state.tailscale;
    let Ok(prefs) = mgr.prefs_lock.try_lock() else {
        return (
            409,
            json!({"ok": false, "error": "tailscale preferences are being changed"}),
        );
    };
    if mgr.updating.load(Ordering::Acquire) {
        return handler_error((409, "update in progress".into()));
    }
    if mgr.slot_change_blocked() {
        return handler_error((409, "OTA slot change or health trial in progress".into()));
    }
    let patch: config::TsConfigPatch = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return (
                400,
                json!({"ok": false, "error": format!("invalid config JSON: {e}")}),
            )
        }
    };

    let current = mgr.config.lock().unwrap().clone();
    let mut candidate = current.clone();
    if let Err(e) = candidate.apply_patch(patch) {
        return (400, json!({"ok": false, "error": e}));
    }

    let daemon_up = mgr.active_child.lock().unwrap().is_some();
    let running = daemon_up
        && mgr
            .probe_status::<Status>(Instant::now() + Duration::from_secs(STATUS_CLI_TIMEOUT_SECS))
            .is_ok_and(|status| status.backend_state == "Running");
    if running {
        if let Err(e) = mgr.set_daemon_prefs(&candidate) {
            mgr.prefs_pending.store(true, Ordering::Relaxed);
            return (
                502,
                json!({"ok": false, "error": format!("tailscale set: {e}")}),
            );
        }
    }

    let hold = candidate.enabled && candidate.hold_wakelock;
    if let Err(e) = mgr.commit_config_locked(candidate) {
        if running {
            if let Err(rollback_err) = mgr.apply_prefs_locked(&current) {
                eprintln!(
                    "[tailscale] restore preferences after config save error: {rollback_err}"
                );
            }
        }
        return (500, json!({"ok": false, "error": e}));
    }
    mgr.prefs_pending.store(!running, Ordering::Relaxed);

    if hold {
        if !mgr.wakelock_held.load(Ordering::SeqCst) {
            mgr.acquire_wakelock();
        }
    } else {
        mgr.release_wakelock();
    }
    drop(prefs);
    mgr.mark_netplane_dirty();
    let payload = mgr.refresh_status();
    (200, json!({"ok": true, "data": payload}))
}

/// POST /api/tailscale/logout — invalidates the node key and disables.
pub fn logout(state: &AppState) -> (u16, Value) {
    let mgr = &state.tailscale;
    let Ok(prefs) = mgr.prefs_lock.try_lock() else {
        return (
            409,
            json!({"ok": false, "error": "tailscale preferences are being changed"}),
        );
    };
    if mgr.updating.load(Ordering::SeqCst) {
        return (409, json!({"ok": false, "error": "update in progress"}));
    }
    if mgr.slot_change_blocked() {
        return (409, json!({"ok": false, "error": "OTA slot change or health trial in progress"}));
    }
    if let Err(error) = mgr.commit_disable_locked(true) {
        return handler_error((500, error));
    }

    // The node key lives server-side too — start the daemon if needed so
    // `tailscale logout` can actually invalidate it.
    let mut warning: Option<String> = None;
    if mgr.is_installed() && mgr.device_path(STATE_FILE).exists() {
        if mgr.active_child.lock().unwrap().is_none() {
            mgr.start_daemon_locked();
            let _ = mgr.wait_for_daemon(20, None);
        }
        if mgr.active_child.lock().unwrap().is_some() {
            if let Err(e) = mgr.run_cli(&["logout"], 30) {
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

    mgr.stop_daemon_locked();
    let _ = std::fs::remove_file(mgr.device_path(STATE_FILE));
    let _ = std::fs::remove_file(mgr.device_path(STATE_BAK));
    mgr.clear_netfilter_off_marker();
    *mgr.login_url.lock().unwrap() = None;
    mgr.state_restore_attempted.store(false, Ordering::SeqCst);
    drop(prefs);
    mgr.refresh_status();
    (
        200,
        json!({"ok": true, "data": {"status": "logged_out", "warning": warning}}),
    )
}

#[cfg(test)]
mod tests {
    use super::supervisor::test_manager;
    use super::*;
    use std::fs;

    struct ConfigStore(PathBuf);

    impl ConfigStore {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "zte-tailscale-handler-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn config_path(&self) -> PathBuf {
            self.0.join("config.json")
        }

        fn disk_config(&self) -> Value {
            serde_json::from_slice(&fs::read(self.config_path()).unwrap()).unwrap()
        }

        fn app(
            &self,
            online: bool,
            cli: impl Fn(&[&str]) -> Result<String, String> + Send + Sync + 'static,
            status: impl Fn() -> Result<Value, String> + Send + Sync + 'static,
        ) -> AppState {
            let cfg = TsConfig {
                enabled: online,
                enrolled: online,
                hold_wakelock: false,
                ..TsConfig::default()
            };
            config::save_at(&self.config_path(), &cfg).unwrap();
            let mut state = AppState::new();
            let mut manager = test_manager(online, online.then_some(500));
            let mgr = Arc::get_mut(&mut manager).unwrap();
            *mgr.config.lock().unwrap() = cfg;
            mgr.test_io = Some(TestIo {
                root: self.0.clone(),
                cli: Box::new(cli),
                status: Box::new(status),
                up_command: None,
            });
            state.tailscale = manager;
            state.auth.set_password("handler-test-password");
            state
        }
    }

    impl Drop for ConfigStore {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn saved_in_memory(state: &AppState) -> Value {
        serde_json::to_value(&*state.tailscale.config.lock().unwrap()).unwrap()
    }

    fn assert_logged_out(state: &AppState, store: &ConfigStore) {
        assert!(!state.tailscale.running.load(Ordering::Acquire));
        let disk = store.disk_config();
        assert_eq!(disk, saved_in_memory(state));
        assert_eq!(disk["enabled"], false);
        assert_eq!(disk["enrolled"], false);
    }

    #[test]
    fn setup_admitted_before_logout_cannot_start_the_daemon_after_preflight() {
        let store = ConfigStore::new();
        let (probing, entered) = mpsc::sync_channel(0);
        let (resume, wait) = mpsc::sync_channel(0);
        let wait = Mutex::new(wait);
        let state = store.app(
            true,
            |args| {
                assert!(matches!(args, ["logout"] | ["down"]), "{args:?}");
                Ok(String::new())
            },
            move || {
                probing.send(()).unwrap();
                wait.lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(3))
                    .unwrap();
                Ok(json!({"BackendState": "NeedsLogin"}))
            },
        );
        fs::write(state.tailscale.device_path(STATE_FILE), "fixture-state").unwrap();
        thread::scope(|scope| {
            let request = scope.spawn(|| setup(&state, br#"{"auth_key":"fixture"}"#));
            entered.recv_timeout(Duration::from_secs(3)).unwrap();
            assert_eq!(logout(&state).0, 200);
            resume.send(()).unwrap();
            let (code, reply) = request.join().unwrap();
            assert_eq!(code, 409);
            assert_eq!(reply["error"], ENROLLMENT_STOPPED.1);
        });
        assert_logged_out(&state, &store);
        assert!(!state.tailscale.device_path(STATE_FILE).exists());
    }

    #[test]
    fn setup_refuses_to_run_up_when_post_ready_status_is_unknown() {
        use std::sync::atomic::AtomicUsize;

        for (post_reply, expected_code) in [
            (Err("socket busy".to_string()), 503),
            (Ok(json!({"BackendState": "NoState"})), 503),
            (Ok(json!({"BackendState": "Stopped"})), 409),
        ] {
            let store = ConfigStore::new();
            let calls = AtomicUsize::new(0);
            let state = store.app(
                true,
                |args| panic!("setup must not invoke tailscale CLI: {args:?}"),
                move || {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    if n < 2 {
                        Ok(json!({"BackendState": "NeedsLogin"}))
                    } else {
                        post_reply.clone()
                    }
                },
            );
            fs::write(state.tailscale.device_path(STATE_FILE), "fixture-state").unwrap();
            let (code, _) = setup(&state, br#"{"auth_key":"fixture"}"#);
            assert_eq!(code, expected_code);
        }
    }

    #[test]
    fn login_url_admitted_before_logout_cannot_start_up_after_readiness_probe() {
        let store = ConfigStore::new();
        let (probing, entered) = mpsc::sync_channel(0);
        let (resume, wait) = mpsc::sync_channel(0);
        let wait = Mutex::new(wait);
        let state = store.app(
            false,
            |args| panic!("unexpected CLI: {args:?}"),
            move || {
                probing.send(()).unwrap();
                wait.lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(3))
                    .unwrap();
                Ok(json!({"BackendState": "NeedsLogin"}))
            },
        );
        thread::scope(|scope| {
            let request = scope.spawn(|| login_url(&state));
            entered.recv_timeout(Duration::from_secs(3)).unwrap();
            assert!(state.tailscale.running.load(Ordering::Acquire));
            assert_eq!(logout(&state).0, 200);
            resume.send(()).unwrap();
            let (code, reply) = request.join().unwrap();
            assert_eq!(code, 409);
            assert_eq!(reply["error"], ENROLLMENT_STOPPED.1);
        });
        assert_logged_out(&state, &store);
    }

    #[test]
    fn setup_cannot_save_enrollment_when_up_finishes_after_logout() {
        let store = ConfigStore::new();
        let (started, entered) = mpsc::sync_channel(0);
        let (resume, wait) = mpsc::sync_channel(0);
        let wait = Mutex::new(wait);
        let state = store.app(
            false,
            move |args| {
                assert_eq!(args[0], "up");
                started.send(()).unwrap();
                wait.lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(3))
                    .unwrap();
                Ok(String::new())
            },
            || Ok(json!({"BackendState": "NeedsLogin"})),
        );
        thread::scope(|scope| {
            let request = scope.spawn(|| setup(&state, br#"{"auth_key":"fixture"}"#));
            entered.recv_timeout(Duration::from_secs(3)).unwrap();
            assert_eq!(logout(&state).0, 200);
            resume.send(()).unwrap();
            let (code, reply) = request.join().unwrap();
            assert_eq!(code, 409);
            assert_eq!(reply["error"], ENROLLMENT_STOPPED.1);
        });
        assert_logged_out(&state, &store);
    }

    #[test]
    fn disabled_config_write_reports_pending_daemon_in_reply_and_status() {
        let store = ConfigStore::new();
        let state = store.app(
            false,
            |args| panic!("unexpected CLI: {args:?}"),
            || panic!("unexpected daemon probe"),
        );
        let (code, reply) = config_set(&state, br#"{"hostname":"next"}"#);
        assert_eq!(code, 200);
        assert_eq!(reply["data"]["routing"]["sync"], "pending_daemon");
        let (code, reply) = status(&state);
        assert_eq!(code, 200);
        assert_eq!(reply["data"]["routing"]["sync"], "pending_daemon");
        assert_eq!(store.disk_config()["hostname"], "next");
        assert_eq!(saved_in_memory(&state)["hostname"], "next");
    }

    #[test]
    fn online_config_set_cli_failure_preserves_disk_and_memory() {
        let store = ConfigStore::new();
        let state = store.app(
            true,
            |args| {
                assert_eq!(args[0], "set");
                assert!(args.contains(&"--hostname=next"));
                Err("set failed".into())
            },
            || Ok(json!({"BackendState": "Running"})),
        );
        let before = store.disk_config();
        let (code, reply) = config_set(&state, br#"{"hostname":"next"}"#);
        assert_eq!(code, 502);
        assert_eq!(reply["error"], "tailscale set: set failed");
        assert_eq!(before, store.disk_config());
        assert_eq!(before, saved_in_memory(&state));
    }

    #[test]
    fn online_config_set_save_failure_restores_daemon_prefs_and_preserves_memory() {
        let store = ConfigStore::new();
        let (cli, commands) = mpsc::channel();
        let state = store.app(
            true,
            move |args| {
                assert_eq!(args[0], "set");
                cli.send(
                    args.iter()
                        .find(|arg| arg.starts_with("--hostname="))
                        .unwrap()
                        .to_string(),
                )
                .unwrap();
                Ok(String::new())
            },
            || Ok(json!({"BackendState": "Running"})),
        );
        let before = store.disk_config();
        let previous_path = store.0.join("previous.json");
        fs::rename(store.config_path(), &previous_path).unwrap();
        fs::create_dir(store.config_path()).unwrap();
        let (code, reply) = config_set(&state, br#"{"hostname":"next"}"#);
        assert_eq!(code, 500);
        assert!(reply["error"].as_str().unwrap().starts_with("write "));
        assert_eq!(before, saved_in_memory(&state));
        assert_eq!(
            fs::read(previous_path).unwrap(),
            serde_json::to_vec_pretty(&*state.tailscale.config.lock().unwrap()).unwrap()
        );
        assert!(store.config_path().is_dir());
        assert_eq!(
            commands.try_iter().collect::<Vec<_>>(),
            ["--hostname=next", "--hostname=u60-pro"]
        );
    }

    #[test]
    fn active_update_handler_blocks_config_set_without_holding_prefs_lock() {
        let store = ConfigStore::new();
        let state = store.app(
            false,
            |args| panic!("unexpected CLI: {args:?}"),
            || panic!("unexpected daemon probe"),
        );
        let before = store.disk_config();
        let (started, entered) = mpsc::sync_channel(0);
        let (resume, wait) = mpsc::sync_channel(0);
        let (code, _) =
            update::update_with_runner(&state, br#"{"version":"1.104.7"}"#, move |mgr, _, _| {
                assert!(mgr.prefs_lock.try_lock().is_ok());
                started.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(3)).unwrap();
                Ok(())
            });
        assert_eq!(code, 202);
        entered.recv_timeout(Duration::from_secs(3)).unwrap();
        let (code, reply) = config_set(&state, br#"{"hostname":"next"}"#);
        resume.send(()).unwrap();
        assert_eq!(code, 409);
        assert_eq!(reply["error"], "update in progress");
        assert_eq!(before, store.disk_config());
        assert_eq!(before, saved_in_memory(&state));
    }

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
            "--netfilter-mode=off",
            "--advertise-exit-node=false",
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
        let exit = TsConfig {
            advertise_exit_node: true,
            ..config
        };
        for verb in ["up", "set"] {
            let args = pref_args_for(&exit, verb);
            assert!(args.iter().any(|arg| arg == "--netfilter-mode=off"));
            assert!(args.iter().any(|arg| arg == "--advertise-exit-node=true"));
        }
    }

    #[test]
    fn config_write_contention_is_conflict_and_does_not_lock_status() {
        let state = AppState::new();
        let _writer = state.tailscale.prefs_lock.lock().unwrap();
        thread::scope(|scope| {
            let (code, reply) = scope
                .spawn(|| config_set(&state, br#"{"hostname":"next"}"#))
                .join()
                .unwrap();
            assert_eq!(code, 409);
            assert_eq!(reply["error"], "tailscale preferences are being changed");
            assert_eq!(state.tailscale.build_base_status()["hostname"], "u60-pro");
        });
    }

    #[test]
    fn unreachable_registered_child_reports_pending_daemon_after_config_save() {
        for enabled in [true, false] {
            let store = ConfigStore::new();
            let state = store.app(
                true,
                |args| panic!("unexpected CLI: {args:?}"),
                || Err("socket unreachable".into()),
            );
            if !enabled {
                let mut cfg = state.tailscale.config.lock().unwrap();
                cfg.enabled = false;
                config::save_at(&store.config_path(), &cfg).unwrap();
            }
            let (code, reply) = config_set(&state, br#"{"hostname":"shutting-down"}"#);
            assert_eq!(code, 200);
            assert_eq!(reply["data"]["routing"]["sync"], "pending_daemon");
            let (code, cached) = status(&state);
            assert_eq!(code, 200);
            assert_eq!(cached["data"]["routing"]["sync"], "pending_daemon");
        }
    }

    #[test]
    fn self_heal_up_respects_generation_enrollment_and_logout_cancellation() {
        let store = ConfigStore::new();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let resume_rx = Mutex::new(resume_rx);
        let seen = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
        let seen_cli = Arc::clone(&seen);
        let state = store.app(
            true,
            move |args| {
                seen_cli
                    .lock()
                    .unwrap()
                    .push(args.iter().map(|s| (*s).to_string()).collect());
                if args.first().copied() == Some("up") {
                    let _ = entered_tx.send(());
                    let _ = resume_rx.lock().unwrap().recv_timeout(Duration::from_secs(3));
                }
                Ok(String::new())
            },
            || Ok(json!({"BackendState": "Stopped"})),
        );
        let stopped = state.tailscale.stopped_generation();
        state.tailscale.running.store(true, Ordering::SeqCst);

        // Active enrollment blocks supervisor self-heal before spawning `up`.
        *state.tailscale.enrollment.lock().unwrap() = EnrollmentOp::AuthKey;
        assert!(state
            .tailscale
            .run_self_heal_up(stopped, &["--timeout=30s"], Duration::from_secs(40))
            .is_none());
        assert!(seen.lock().unwrap().is_empty());
        *state.tailscale.enrollment.lock().unwrap() = EnrollmentOp::Idle;

        // Stale generation blocks supervisor self-heal before spawning `up`.
        assert!(state
            .tailscale
            .run_self_heal_up(stopped.saturating_add(1), &["--timeout=30s"], Duration::from_secs(40))
            .is_none());
        assert!(seen.lock().unwrap().is_empty());

        // Concurrent logout while self-heal `up` is running invalidates its result.
        thread::scope(|scope| {
            let heal = scope.spawn(|| {
                state
                    .tailscale
                    .run_self_heal_up(stopped, &["--timeout=30s"], Duration::from_secs(40))
            });
            entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            assert_eq!(logout(&state).0, 200);
            resume_tx.send(()).unwrap();
            assert!(heal.join().unwrap().is_none());
        });
        assert_logged_out(&state, &store);
        assert!(!state.tailscale.up_is_current(stopped));
    }

    #[test]
    fn canceled_self_heal_waiter_does_not_reap_or_kill_replacement_enrollment_child() {
        let store = ConfigStore::new();
        let mut state = store.app(
            true,
            |args| panic!("unexpected fallback CLI: {args:?}"),
            || Ok(json!({"BackendState": "Stopped"})),
        );
        {
            let mgr = Arc::get_mut(&mut state.tailscale).unwrap();
            mgr.test_io.as_mut().unwrap().up_command = Some(Box::new(|args| {
                let mut cmd = Command::new("/bin/sh");
                if args.contains(&"--enrollment-child") {
                    cmd.args(["-c", "sleep 0.35; printf enrolled-ok"]);
                } else {
                    cmd.args(["-c", "sleep 30"]);
                }
                cmd
            }));
        }
        let stopped = state.tailscale.stopped_generation();
        state.tailscale.running.store(true, Ordering::SeqCst);

        thread::scope(|scope| {
            let heal = scope.spawn(|| {
                state.tailscale.run_self_heal_up(
                    stopped,
                    &["--timeout=30s"],
                    Duration::from_millis(120),
                )
            });

            let wait_start = Instant::now();
            let heal_up_id = loop {
                if let Some(tracked) = state.tailscale.active_up_process.lock().unwrap().as_ref() {
                    break tracked.id;
                }
                assert!(
                    wait_start.elapsed() < Duration::from_secs(3),
                    "self-heal child never registered"
                );
                thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(heal_up_id, 1);

            let enrolled = state
                .tailscale
                .run_enrollment_up(stopped, &["--enrollment-child"], Duration::from_secs(5))
                .expect("enrollment should survive canceled self-heal timeout");
            assert_eq!(enrolled.1.as_deref(), Ok("enrolled-ok"));
            assert!(heal.join().unwrap().is_none());
        });
        assert!(state.tailscale.active_up_process.lock().unwrap().is_none());
    }

    #[test]
    fn routing_status_only_reports_configured_subnets_and_reconciles_prefs() {
        let cfg = TsConfig {
            enabled: true,
            advertise_routes: [
                "192.168.0.0/24",
                "192.168.2.0/24",
                "192.168.3.0/24",
                "100.75.1.2/32",
                "fd7a:115c:a1e0::1234/128",
                "192.0.2.1/32",
            ]
            .map(String::from)
            .to_vec(),
            advertise_exit_node: true,
            exit_via_mihomo: true,
            ..TsConfig::default()
        };
        let status: Status = serde_json::from_value(json!({
            "BackendState": "Running",
            "TUN": false,
            "Self": {
                "AllowedIPs": ["100.75.1.2/32", "192.168.0.0/24", "192.168.2.0/24", "0.0.0.0/0"],
                "PrimaryRoutes": ["192.168.0.0/24", "fd7a:115c:a1e0::1234/128", "192.0.2.1/32"],
                "TailscaleIPs": ["100.78.2.1", "192.0.2.1"],
            },
        }))
        .unwrap();
        let mut prefs_json = json!({
            "NetfilterMode": 2,
            "CorpDNS": false,
            "RouteAll": false,
            "RunSSH": false,
            "Hostname": "u60-pro",
            "AdvertiseRoutes": ["::/0", "192.168.2.0/24", "0.0.0.0/0", "192.168.0.0/24", "192.168.3.0/24"],
        });
        let prefs: Prefs = serde_json::from_value(prefs_json.clone()).unwrap();
        let approved = json!([
            {"prefix":"192.168.0.0/24", "state":"approved"},
            {"prefix":"192.168.2.0/24", "state":"standby"},
            {"prefix":"192.168.3.0/24", "state":"pending"},
        ]);
        let subnets = ["192.168.0.0/24".parse().unwrap()];
        let filtered = routing_status(&cfg, Some(&status), Some(&prefs), &subnets, true);
        assert_eq!(filtered["routes"], approved);
        let cfg = TsConfig {
            advertise_routes: cfg.advertise_routes[..3].to_vec(),
            ..cfg
        };
        assert_eq!(
            routing_status(&cfg, Some(&status), Some(&prefs), &subnets, true),
            json!({
                "sync": "drift",
                "tun": {"mode":"userspace", "active":false, "netfilter_mode":"on"},
                "lan_subnets": ["192.168.0.0/24"],
                "routes": approved,
                "exit": {
                    "advertised": true,
                    "state":"approved", "state_v4":"approved", "state_v6":"pending",
                    "via_mihomo": true,
                }
            }),
        );
        prefs_json["NetfilterMode"] = json!(0);
        let matched = serde_json::from_value(prefs_json.clone()).unwrap();
        assert_eq!(
            routing_status(&cfg, Some(&status), Some(&matched), &subnets, true)["sync"],
            "applied"
        );
        for (field, wrong) in [
            ("CorpDNS", json!(true)),
            ("RouteAll", json!(true)),
            ("RunSSH", json!(true)),
            ("Hostname", json!("wrong-host")),
        ] {
            let mut mismatched = prefs_json.clone();
            mismatched[field] = wrong;
            let mismatched = serde_json::from_value(mismatched).unwrap();
            assert_eq!(
                routing_status(&cfg, Some(&status), Some(&mismatched), &subnets, false)["sync"],
                "drift",
                "{field}"
            );
        }
        assert_eq!(
            routing_status(&cfg, Some(&status), None, &[], true)["sync"],
            "unknown"
        );
        let offline = routing_status(&cfg, None, None, &[], true);
        assert_eq!(offline["sync"], "pending_daemon");
        assert_eq!(offline["exit"]["state"], "unknown");
        assert_eq!(
            offline["tun"],
            json!({"mode":"unknown","active":false,"netfilter_mode":"unknown"})
        );
        assert!(offline["routes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|route| route["state"] == "unknown"));

        let cfg = TsConfig {
            enabled: false,
            advertise_exit_node: false,
            ..cfg
        };
        assert_eq!(
            routing_status(&cfg, None, None, &[], false)["sync"],
            "unknown"
        );
        let drift = routing_status(&cfg, Some(&status), Some(&prefs), &[], false);
        assert_eq!(drift["sync"], "drift");
        assert_eq!(
            drift["exit"],
            json!({
                "advertised":false, "state":"off", "state_v4":"off", "state_v6":"off", "via_mihomo":true,
            })
        );
    }

    #[test]
    fn exit_node_defaults_read_back_dual_stack_and_single_stack_approval() {
        let cfg = TsConfig {
            advertise_exit_node: true,
            ..TsConfig::default()
        };
        for (self_status, expected) in [
            (
                json!({"ExitNodeOption":true,"AllowedIPs":["100.75.1.1/32","0.0.0.0/0","::/0"]}),
                ["approved", "approved", "approved"],
            ),
            (
                json!({"ExitNodeOption":true,"AllowedIPs":["100.75.1.1/32"]}),
                ["approved", "approved", "approved"],
            ),
            (
                json!({"ExitNodeOption":true,"AllowedIPs":["100.75.1.1/32","0.0.0.0/0"]}),
                ["approved", "approved", "pending"],
            ),
            (
                json!({"ExitNodeOption":false,"AllowedIPs":["0.0.0.0/0"]}),
                ["approved", "approved", "pending"],
            ),
            (
                json!({"ExitNodeOption":false,"AllowedIPs":["::/0"]}),
                ["approved", "pending", "approved"],
            ),
            (
                json!({"ExitNodeOption":false,"AllowedIPs":["100.75.1.1/32"]}),
                ["pending", "pending", "pending"],
            ),
        ] {
            let status = serde_json::from_value(json!({
                "BackendState":"Running", "TUN":true, "Self": self_status,
            }))
            .unwrap();
            let prefs = serde_json::from_value(json!({"NetfilterMode":0})).unwrap();
            let routing = routing_status(&cfg, Some(&status), Some(&prefs), &[], false);
            for (field, state) in ["state", "state_v4", "state_v6"].into_iter().zip(expected) {
                assert_eq!(routing["exit"][field], state);
            }
            assert_eq!(
                routing["tun"],
                json!({"mode":"kernel","active":true,"netfilter_mode":"off"})
            );
        }
    }

    #[test]
    fn lan_subnets_are_canonical_sorted_and_exclude_other_interfaces_and_ipv6_link_local() {
        let addresses = [
            ("br-lan", "fd01::12", 64),
            ("br-lan", "192.168.3.1", 24),
            ("br-lan", "192.168.0.1", 24),
            ("br-lan", "192.168.0.2", 24),
            ("br-lan", "fe80::1", 64),
            ("br-lan", "febf:aa::3", 64),
            ("br-guest", "192.168.2.1", 24),
            ("rmnet0", "2001:db8::2", 64),
        ]
        .map(|(name, address, prefix)| IfAddr {
            name: name.into(),
            addr: address.parse().unwrap(),
            prefix,
            scope: 0,
        });
        assert_eq!(
            serde_json::to_value(lan_subnets(&addresses)).unwrap(),
            json!(["192.168.0.0/24", "192.168.3.0/24", "fd01::/64"]),
        );
    }

    #[test]
    fn enrollment_requires_a_password_and_config_rejects_bad_input_before_saving() {
        let state = AppState::new();
        let denied = (
            403,
            json!({
                "ok": false,
                "error": "set an agent password (ZTE_AGENT_PASSWORD) before enabling remote access",
            }),
        );
        assert_eq!(setup(&state, b"{"), denied);
        assert_eq!(login_url(&state), denied);
        assert_eq!(
            config_set(&state, b"{"),
            (
                400,
                json!({"ok": false, "error": "invalid config JSON: EOF while parsing an object at line 1 column 1"})
            ),
        );
        assert_eq!(
            config_set(&state, br#"{"hostname":"bad_name"}"#),
            (
                400,
                json!({"ok": false, "error": "hostname must be 1-63 chars, alphanumeric or '-'"})
            ),
        );
        assert_eq!(
            config_set(
                &state,
                br#"{"hostname":"valid-name","advertise_routes":["192.0.2.0/33"]}"#
            ),
            (
                400,
                json!({"ok": false, "error": "invalid CIDR route: 192.0.2.0/33"})
            ),
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
        assert_eq!(
            std::fs::read_to_string(&first_path).unwrap(),
            "tskey-auth-first"
        );
        assert_eq!(
            std::fs::read_to_string(&second_path).unwrap(),
            "tskey-auth-second"
        );
        assert_eq!(
            std::fs::metadata(&first_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&second_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        drop(first);
        assert!(!first_path.exists());
        assert_eq!(
            std::fs::read_to_string(&second_path).unwrap(),
            "tskey-auth-second"
        );

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
                    || json!({"daemon_running": true, "state": "starting"}),
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
            || json!({"daemon_running": true, "state": "starting"}),
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
            || json!({"daemon_running": true, "state": "starting"}),
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
                || json!({"daemon_running": true, "state": "starting"}),
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

    #[test]
    fn exit_node_advertisement_is_gated_on_verified_clean_dns_isolation() {
        let recorded = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
        let recorded_cli = Arc::clone(&recorded);
        let mut mgr = TailscaleManager::with_config(TsConfig {
            enabled: true,
            enrolled: true,
            advertise_exit_node: true,
            ..TsConfig::default()
        });
        mgr.running.store(true, Ordering::SeqCst);
        mgr.test_io = Some(TestIo {
            root: std::env::temp_dir(),
            cli: Box::new(move |args| {
                recorded_cli
                    .lock()
                    .unwrap()
                    .push(args.iter().map(|s| (*s).to_string()).collect());
                Ok(String::new())
            }),
            status: Box::new(|| Ok(json!({"BackendState": "Running"}))),
            up_command: None,
        });

        // 1. In userspace / unisolated state, applying prefs MUST suppress
        //    `--advertise-exit-node=true` so an approved node never serves Exit
        //    traffic through the host resolver.
        mgr.apply_current_prefs().unwrap();
        {
            let calls = recorded.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert!(
                calls[0].iter().any(|a| a == "--advertise-exit-node=false"),
                "unisolated daemon must force --advertise-exit-node=false: {:?}",
                calls[0]
            );
        }

        // 2. Kernel TUN active without verified mount isolation STILL suppresses exit node.
        mgr.kernel_tun_active.store(true, Ordering::Release);
        *mgr.clean_dns_mount_state.lock().unwrap() = Err("detached mount".into());
        mgr.apply_current_prefs().unwrap();
        {
            let calls = recorded.lock().unwrap();
            assert!(
                calls[1].iter().any(|a| a == "--advertise-exit-node=false"),
                "failed mount verification must withdraw exit node: {:?}",
                calls[1]
            );
        }

        // 3. Only once verified isolation succeeds does exit node advertisement restore.
        mgr.test_clean_dns_isolated = Some(true);
        mgr.apply_current_prefs().unwrap();
        {
            let calls = recorded.lock().unwrap();
            assert!(
                calls[2].iter().any(|a| a == "--advertise-exit-node=true"),
                "verified isolation must restore --advertise-exit-node=true: {:?}",
                calls[2]
            );
        }
    }
}
