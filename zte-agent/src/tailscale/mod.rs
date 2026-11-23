pub mod config;

pub use config::TsConfig;

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::net::UnixStream;
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
const LOG_FILE: &str = "/tmp/tailscaled.log";

const POLL_SECS: u64 = 30;
/// WAN-reconnect events closer together than this get one health check.
const WAN_DEBOUNCE: Duration = Duration::from_secs(30);
/// Brief settle window to coalesce rapid Wi-Fi relay route/IPv6 transitions.
const RELAY_SETTLE: Duration = Duration::from_secs(2);
/// Wait after a relay-triggered rebind/restun before escalating to a restart.
const RELAY_VERIFY_WAIT: Duration = Duration::from_secs(25);
const CLI_TIMEOUT_SECS: u64 = 20;
/// Shorter than CLI_TIMEOUT_SECS so GET /status can't stall mobile clients
/// for long when the daemon is wedged.
const STATUS_CLI_TIMEOUT_SECS: u64 = 8;
const BACKOFF_MIN_SECS: u64 = 5;
const BACKOFF_MAX_SECS: u64 = 60;
const QUIESCE_TIMEOUT_SECS: u64 = 60;
/// Supervisor park while disabled or paused. Every writer of `running` /
/// `paused` notifies `wake_cv`, so this bound is only a safety net.
const IDLE_PARK_SECS: u64 = 60;
/// How often the monitor checks for an externally killed tailscaled between
/// status polls (the respawn backoff is 5 s, so nothing finer is visible).
const CHILD_POLL_SECS: u64 = 5;
/// LocalAPI over the daemon socket: the same `ipnstate.Status` the CLI
/// prints, without forking the Go binary. HTTP/1.0 so the body ends at EOF
/// (Go never chunks a 1.0 response); the Host is the only one tailscaled
/// accepts over the socket.
const LOCALAPI_STATUS_REQUEST: &str =
    "GET /localapi/v0/status?peers=false HTTP/1.0\r\nHost: local-tailscaled.sock\r\n\r\n";
/// A peerless status is a few KB; anything larger is not tailscaled.
const LOCALAPI_MAX_BYTES: usize = 1024 * 1024;
const LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;
/// 2025-01-01 UTC — clock earlier than this means NTP hasn't synced yet.
const SANE_CLOCK_EPOCH: i64 = 1_735_689_600;
const VERSIONS_CACHE_TTL: Duration = Duration::from_secs(600);
const VERSIONS_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const VERSIONS_FETCH_TIMEOUT: Duration = Duration::from_secs(12);
const SHA256_FETCH_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_LISTED_VERSIONS: usize = 15;
const PKGS_INDEX_MAX_BYTES: usize = 64 * 1024;
const GITHUB_RELEASES_MAX_BYTES: usize = 512 * 1024;
const SHA256_FILE_MAX_BYTES: usize = 1024;
const TAILSCALE_PKGS_INDEX_URL: &str = "https://pkgs.tailscale.com/stable/?mode=json";
const TAILSCALE_GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/tailscale/tailscale/releases?per_page=30";
const TAILSCALE_USER_AGENT: &str = concat!("open-u60-tailscale/", env!("CARGO_PKG_VERSION"));

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReleaseEntry {
    version: String,
    published_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VersionCatalog {
    latest: String,
    versions: Vec<ReleaseEntry>,
    source: String,
    warning: Option<String>,
    fetched_at: i64,
}

impl VersionCatalog {
    fn to_json(&self) -> Value {
        let versions: Vec<Value> = self
            .versions
            .iter()
            .map(|entry| {
                json!({
                    "version": entry.version,
                    "published_at": entry.published_at,
                })
            })
            .collect();
        json!({
            "latest": self.latest,
            "versions": versions,
            "source": self.source,
            "warning": self.warning,
            "fetched_at": self.fetched_at,
        })
    }
}

#[derive(Default)]
struct RelayWatchState {
    generation: u64,
    child: Option<ChildIdentity>,
    saw_disconnect: bool,
    restart_request: Option<(u64, ChildIdentity)>,
    #[cfg(test)]
    stopped: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ChildIdentity {
    pid: u32,
    instance: u64,
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
        let mut in_flight = self
            .mgr
            .status_refresh_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        *in_flight = false;
        self.mgr.status_refresh_cv.notify_all();
    }
}

struct StatusRefreshRefGuard<'a> {
    mgr: &'a TailscaleManager,
}

impl Drop for StatusRefreshRefGuard<'_> {
    fn drop(&mut self) {
        let mut in_flight = self
            .mgr
            .status_refresh_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        *in_flight = false;
        self.mgr.status_refresh_cv.notify_all();
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

/// Logged once per process: LocalAPI failing while the CLI works means the
/// fork-free path is broken, which would otherwise be invisible.
static LOCALAPI_FALLBACK_LOGGED: AtomicBool = AtomicBool::new(false);

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

fn cli_json(args: &[&str], timeout_secs: u64) -> Result<Value, String> {
    let stdout = cli(args, timeout_secs)?;
    serde_json::from_str(stdout.trim()).map_err(|e| format!("parse tailscale JSON: {e}"))
}

#[derive(Debug)]
enum LocalApiError {
    /// tailscaled accepted the connection but did not answer in time. The
    /// CLI talks to the same socket and would stall the same way.
    Timeout,
    Other(String),
}

/// `ipnstate.Status` (peers omitted) from tailscaled's LocalAPI socket.
fn localapi_status(timeout_secs: u64) -> Result<Value, LocalApiError> {
    localapi_status_at(Path::new(SOCK), timeout_secs)
}

fn localapi_status_at(sock: &Path, timeout_secs: u64) -> Result<Value, LocalApiError> {
    use std::io::Write;
    let io_err = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => LocalApiError::Timeout,
        _ => LocalApiError::Other(e.to_string()),
    };
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let deadline = Instant::now() + timeout;
    let mut stream = UnixStream::connect(sock)
        .map_err(|e| LocalApiError::Other(format!("connect {}: {e}", sock.display())))?;
    stream.set_write_timeout(Some(timeout)).map_err(io_err)?;
    // Armed once, up front: tailscaled answers and closes in one go, and
    // setsockopt on a socket whose peer has already closed fails (EINVAL on
    // macOS). The socket timeout bounds each read; the deadline bounds the
    // total should the daemon trickle.
    stream.set_read_timeout(Some(timeout)).map_err(io_err)?;
    stream
        .write_all(LOCALAPI_STATUS_REQUEST.as_bytes())
        .map_err(io_err)?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > LOCALAPI_MAX_BYTES {
                    return Err(LocalApiError::Other(format!(
                        "response over {LOCALAPI_MAX_BYTES} bytes"
                    )));
                }
                if Instant::now() >= deadline {
                    return Err(LocalApiError::Timeout);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_err(e)),
        }
    }
    parse_localapi_response(&raw).map_err(LocalApiError::Other)
}

/// Body of a `200` HTTP/1.x response as JSON. Headers end at the first blank
/// line (CRLF or bare LF); a chunked body is refused rather than decoded
/// because tailscaled never sends one to an HTTP/1.0 request.
fn parse_localapi_response(raw: &[u8]) -> Result<Value, String> {
    let (head_len, sep_len) = (0..raw.len())
        .find_map(|i| {
            if raw[i..].starts_with(b"\r\n\r\n") {
                Some((i, 4))
            } else if raw[i..].starts_with(b"\n\n") {
                Some((i, 2))
            } else {
                None
            }
        })
        .ok_or_else(|| "incomplete HTTP response (no end of headers)".to_string())?;
    let head = String::from_utf8_lossy(&raw[..head_len]);
    let body = &raw[head_len + sep_len..];
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(format!("not an HTTP response: {status_line:?}"));
    }
    if code != "200" {
        let text = String::from_utf8_lossy(body);
        return Err(format!("{status_line}: {}", text.trim()));
    }
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
            {
                return Err("chunked localapi response".into());
            }
        }
    }
    serde_json::from_slice(body).map_err(|e| format!("parse localapi JSON: {e}"))
}

/// `tailscale status --json --peers=false` without the fork: LocalAPI first,
/// the Go CLI on any failure except a timeout, so a LocalAPI problem costs a
/// fork, never a feature, and a wedged daemon still stalls GET /status for
/// at most `timeout_secs` (the CLI would only hit the same wall).
fn daemon_status(timeout_secs: u64) -> Result<Value, String> {
    let reason = match localapi_status(timeout_secs) {
        Ok(v) => return Ok(v),
        Err(LocalApiError::Timeout) => return Err(format!("timed out after {timeout_secs}s")),
        Err(LocalApiError::Other(e)) => e,
    };
    let result = cli_json(&["status", "--json", "--peers=false"], timeout_secs);
    if result.is_ok() && !LOCALAPI_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
        eprintln!("[tailscale] localapi status failed ({reason}) — using the CLI");
    }
    result
}

fn installed() -> bool {
    Path::new(TAILSCALED_BIN).exists() && Path::new(TAILSCALE_BIN).exists()
}

fn state_file_exists() -> bool {
    Path::new(STATE_FILE).exists()
}

/// A reboot mid-swap can leave `tailscaled` missing with `.prev`/`.new`
/// siblings present. Promote the known-good `.prev` first, else `.new`.
fn recover_binaries() {
    for name in ["tailscaled", "tailscale"] {
        let current = format!("{BIN_DIR}/{name}");
        if Path::new(&current).exists() {
            continue;
        }
        for suffix in [".prev", ".new"] {
            let candidate = format!("{current}{suffix}");
            if Path::new(&candidate).exists() {
                eprintln!("[tailscale] recovering {name} from {suffix} after interrupted update");
                if std::fs::rename(&candidate, &current).is_ok() {
                    break;
                }
            }
        }
    }
}

impl TailscaleManager {
    pub fn new() -> Self {
        recover_binaries();
        Self {
            config: Mutex::new(config::load()),
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

    pub(crate) fn set_relay(&self, relay: &Arc<WifiRelay>) {
        let _ = self.relay.set(Arc::downgrade(relay));
    }

    fn relay_active(&self) -> bool {
        self.relay
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|relay| relay.active())
    }

    /// Non-blocking hook called by `WifiRelay` when its routes are installed,
    /// updated, or torn down. Wakes the startup gate immediately and schedules
    /// a fast rebind/restun when `tailscaled` is already running.
    pub(crate) fn relay_uplink_changed(&self) {
        self.wake_supervisor();
        if !self.running.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst) {
            return;
        }
        let Some(child) = *self.active_child.lock().unwrap_or_else(|err| err.into_inner()) else {
            return;
        };
        let relay_up = self.relay_active();
        let mut state = self
            .relay_watch_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        state.generation = state.generation.wrapping_add(1);
        state.child = Some(child);
        state.restart_request = None;
        if !relay_up {
            state.saw_disconnect = true;
        }
        self.relay_watch_cv.notify_all();
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

    /// Called once from main() — starts the daemon if previously enabled.
    pub fn auto_start(self: &Arc<Self>) {
        let cfg = self.config.lock().unwrap().clone();
        if !cfg.enabled || !installed() {
            return;
        }
        if cfg.hold_wakelock {
            self.acquire_wakelock();
        }
        self.running.store(true, Ordering::SeqCst);
        self.ensure_supervisor();
        self.wake_supervisor();
    }

    /// WAN-flap hook: on reconnect events, nudge tailscaled (rebind + restun)
    /// and escalate to a daemon restart if it stays unhealthy.
    pub fn start_wan_watch(self: &Arc<Self>, rx: mpsc::Receiver<Value>) {
        let relay_mgr = Arc::clone(self);
        thread::spawn(move || {
            relay_mgr.watch_relay_uplink(
                RELAY_SETTLE,
                RELAY_VERIFY_WAIT,
                Instant::now,
                || relay_mgr.relay_active(),
                probe_cellular_wan,
                || {
                    relay_mgr.refresh_status();
                },
                || relay_mgr.is_unhealthy(),
                || relay_mgr.nudge(),
                |generation, child| {
                    relay_mgr.request_relay_restart(generation, child);
                },
            );
        });

        let mgr = Arc::clone(self);
        thread::spawn(move || {
            let mut last_handled: Option<Instant> = None;
            for payload in rx.iter() {
                // Only react to reconnects (any `*_connected`, IPv6-only
                // included), not disconnects.
                let wan_status = payload["wan_status"].as_str().unwrap_or("");
                if !wan_connected(wan_status) {
                    continue;
                }
                if !mgr.running.load(Ordering::SeqCst) || mgr.paused.load(Ordering::SeqCst) {
                    continue;
                }
                // Debounce bursts of WAN events
                if debounced(last_handled, Instant::now()) {
                    continue;
                }
                last_handled = Some(Instant::now());
                eprintln!("[tailscale] WAN reconnect ({wan_status}): checking health in 20 s");
                // Give the data path time to settle, then check health (fresh
                // status — the cache may predate the flap)
                thread::sleep(Duration::from_secs(20));
                if !mgr.running.load(Ordering::SeqCst) {
                    continue;
                }
                mgr.refresh_status();
                if mgr.is_unhealthy() {
                    eprintln!("[tailscale] unhealthy after WAN reconnect — rebind/restun");
                    mgr.nudge();
                    thread::sleep(Duration::from_secs(30));
                    mgr.refresh_status();
                    if mgr.running.load(Ordering::SeqCst) && mgr.is_unhealthy() {
                        eprintln!("[tailscale] still unhealthy — restarting tailscaled");
                        mgr.kill_child(libc::SIGTERM);
                    }
                }
            }
        });
    }

    // --- Supervisor ---

    /// Spawn the single long-lived supervisor thread (idles while disabled).
    fn ensure_supervisor(self: &Arc<Self>) {
        if self
            .supervisor_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        let mgr = Arc::clone(self);
        thread::spawn(move || mgr.supervise());
    }

    /// Wake the supervisor from any park. Callers store their flag first;
    /// taking the lock orders that store before the waiter's predicate
    /// re-check (see `wake_lock`).
    fn wake_supervisor(&self) {
        {
            let _guard = self.wake_lock.lock().unwrap_or_else(|err| err.into_inner());
            self.wake_cv.notify_all();
        }
        {
            let _guard = self
                .relay_watch_lock
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            self.relay_watch_cv.notify_all();
        }
    }

    fn is_relay_check_current(
        &self,
        expected_generation: u64,
        expected_child: ChildIdentity,
    ) -> bool {
        let active = self
            .active_child
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let state = self
            .relay_watch_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        self.running.load(Ordering::SeqCst)
            && !self.paused.load(Ordering::SeqCst)
            && *active == Some(expected_child)
            && state.generation == expected_generation
    }

    fn request_relay_restart(
        &self,
        expected_generation: u64,
        expected_child: ChildIdentity,
    ) -> bool {
        let accepted = {
            let active = self
                .active_child
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            let mut state = self
                .relay_watch_lock
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            if self.running.load(Ordering::SeqCst)
                && !self.paused.load(Ordering::SeqCst)
                && *active == Some(expected_child)
                && state.generation == expected_generation
            {
                state.restart_request = Some((expected_generation, expected_child));
                true
            } else {
                false
            }
        };
        if accepted {
            self.wake_supervisor();
        }
        accepted
    }

    fn has_relay_restart(&self, identity: ChildIdentity) -> bool {
        let active = self
            .active_child
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let state = self
            .relay_watch_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        state.restart_request.is_some_and(|(req_gen, req_child)| {
            self.running.load(Ordering::SeqCst)
                && !self.paused.load(Ordering::SeqCst)
                && *active == Some(identity)
                && req_child == identity
                && req_gen == state.generation
        })
    }

    fn take_relay_restart(&self, identity: ChildIdentity) -> bool {
        let active = self
            .active_child
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let mut state = self
            .relay_watch_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let matches = state.restart_request.is_some_and(|(req_gen, req_child)| {
            self.running.load(Ordering::SeqCst)
                && !self.paused.load(Ordering::SeqCst)
                && *active == Some(identity)
                && req_child == identity
                && req_gen == state.generation
        });
        if matches {
            state.restart_request = None;
        }
        matches
    }

    fn wait_relay_quiet(&self, expected_generation: u64, duration: Duration) -> bool {
        let deadline = Instant::now() + duration;
        let mut guard = self
            .relay_watch_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        loop {
            if guard.generation != expected_generation
                || !self.running.load(Ordering::SeqCst)
                || self.paused.load(Ordering::SeqCst)
            {
                return false;
            }
            #[cfg(test)]
            if guard.stopped {
                return false;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return true;
            }
            let (next, _) = self
                .relay_watch_cv
                .wait_timeout(guard, remaining)
                .unwrap_or_else(|err| err.into_inner());
            guard = next;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn watch_relay_uplink(
        &self,
        settle: Duration,
        verify_wait: Duration,
        now_fn: impl Fn() -> Instant,
        relay_active: impl Fn() -> bool,
        mut probe_cellular: impl FnMut(bool) -> bool,
        mut refresh_status: impl FnMut(),
        is_unhealthy: impl Fn() -> bool,
        mut nudge: impl FnMut(),
        mut restart_child: impl FnMut(u64, ChildIdentity),
    ) {
        let mut seen = 0u64;
        let mut last_nudge: Option<(Instant, bool)> = None;
        let mut pending_disconnect = false;
        loop {
            let (generation, child, saw_disconnect) = {
                let mut guard = self
                    .relay_watch_lock
                    .lock()
                    .unwrap_or_else(|err| err.into_inner());
                loop {
                    #[cfg(test)]
                    if guard.stopped {
                        return;
                    }
                    if guard.generation != seen {
                        break;
                    }
                    guard = self
                        .relay_watch_cv
                        .wait(guard)
                        .unwrap_or_else(|err| err.into_inner());
                }
                let disconnected = std::mem::take(&mut guard.saw_disconnect);
                (guard.generation, guard.child, disconnected)
            };
            seen = generation;
            pending_disconnect |= saw_disconnect;
            let Some(child) = child else {
                pending_disconnect = false;
                continue;
            };

            if !self.wait_relay_quiet(generation, settle) {
                if !self.running.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst) {
                    pending_disconnect = false;
                    last_nudge = None;
                }
                continue;
            }
            if !self.is_relay_check_current(generation, child) {
                pending_disconnect = false;
                continue;
            }

            let relay_up = relay_active();
            let has_uplink = relay_up || probe_cellular(true);
            if !has_uplink {
                pending_disconnect = false;
                last_nudge = None;
                continue;
            }

            let saw_down = std::mem::take(&mut pending_disconnect);
            let now = now_fn();
            let same_direction = !saw_down
                && last_nudge.is_some_and(|(at, prev_relay)| {
                    prev_relay == relay_up && debounced(Some(at), now)
                });
            if same_direction {
                refresh_status();
                if !is_unhealthy() {
                    continue;
                }
            }
            if !self.is_relay_check_current(generation, child) {
                if !self.running.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst) {
                    pending_disconnect = false;
                    last_nudge = None;
                }
                continue;
            }

            eprintln!(
                "[tailscale] Wi-Fi relay {} — rebind/restun",
                if relay_up {
                    "connected/updated"
                } else {
                    "disconnected (cellular fallback)"
                }
            );
            nudge();
            last_nudge = Some((now_fn(), relay_up));

            if !self.wait_relay_quiet(generation, verify_wait) {
                if !self.running.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst) {
                    pending_disconnect = false;
                    last_nudge = None;
                }
                continue;
            }
            if !self.is_relay_check_current(generation, child) {
                continue;
            }

            refresh_status();
            if is_unhealthy() && (relay_active() || probe_cellular(false)) {
                if !self.is_relay_check_current(generation, child) {
                    if !self.running.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst) {
                        pending_disconnect = false;
                        last_nudge = None;
                    }
                    continue;
                }
                eprintln!(
                    "[tailscale] still unhealthy after Wi-Fi relay switch — requesting tailscaled restart"
                );
                restart_child(generation, child);
            }
        }
    }

    /// Park for `dur`, returning early once a disable or an update pause
    /// means the supervisor should stop what it is doing.
    fn park_while_active(&self, dur: Duration) {
        let guard = self.wake_lock.lock().unwrap_or_else(|e| e.into_inner());
        drop(
            self.wake_cv
                .wait_timeout_while(guard, dur, |_| {
                    self.running.load(Ordering::SeqCst) && !self.paused.load(Ordering::SeqCst)
                })
                .unwrap_or_else(|e| e.into_inner()),
        );
    }

    /// Undo `quiesce_supervisor`: the supervisor respawns at once instead
    /// of on its next idle tick.
    fn resume_supervisor(&self) {
        self.paused.store(false, Ordering::SeqCst);
        self.wake_supervisor();
    }

    fn supervise(&self) {
        let mut backoff = BACKOFF_MIN_SECS;
        loop {
            if !self.running.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst) {
                // Park until enable/resume notifies (bounded as a safety net)
                self.supervisor_idle.store(true, Ordering::SeqCst);
                let guard = self.wake_lock.lock().unwrap_or_else(|e| e.into_inner());
                drop(
                    self.wake_cv
                        .wait_timeout_while(guard, Duration::from_secs(IDLE_PARK_SECS), |_| {
                            !self.running.load(Ordering::SeqCst)
                                || self.paused.load(Ordering::SeqCst)
                        })
                        .unwrap_or_else(|e| e.into_inner()),
                );
                continue;
            }
            if !installed() {
                self.supervisor_idle.store(true, Ordering::SeqCst);
                thread::sleep(Duration::from_secs(10));
                continue;
            }
            self.supervisor_idle.store(false, Ordering::SeqCst);

            self.wait_for_clock_and_wan();
            if !self.running.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst) {
                continue;
            }

            // Adopt-by-replace: a previous agent instance (e.g. redeploy via
            // killall zte-agent) leaves its tailscaled orphaned; a second
            // instance would fight over the socket and state file.
            self.kill_orphan_tailscaled();

            // Clean up leftovers from a previous crash (no-op in userspace mode)
            let mut cleanup = Command::new(TAILSCALED_BIN);
            cleanup.arg("--cleanup");
            let _ = run_with_timeout(cleanup, 10);

            // Last gate before spawn — an update may have paused us meanwhile
            if !self.running.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst) {
                continue;
            }

            rotate_log_if_big();
            let _ = std::fs::create_dir_all(RUN_DIR);
            match self.spawn_tailscaled() {
                Ok(mut child) => {
                    eprintln!("[tailscale] tailscaled started (pid {})", child.id());
                    let instance = self.next_child_instance.fetch_add(1, Ordering::SeqCst) + 1;
                    let identity = ChildIdentity {
                        pid: child.id(),
                        instance,
                    };
                    *self.active_child.lock().unwrap() = Some(identity);
                    self.apply_prefs_when_ready();
                    let clean_exit = self.monitor_until_exit(&mut child, identity);
                    *self.active_child.lock().unwrap() = None;
                    self.relay_watch_lock
                        .lock()
                        .unwrap_or_else(|err| err.into_inner())
                        .restart_request = None;
                    // AuthURL was in-memory in the dead daemon — a cached copy
                    // would be served as live and block re-enrollment
                    *self.login_url.lock().unwrap() = None;
                    self.refresh_status();
                    if clean_exit {
                        backoff = BACKOFF_MIN_SECS;
                    }
                    eprintln!("[tailscale] tailscaled exited");
                }
                Err(e) => {
                    eprintln!("[tailscale] spawn failed: {e}");
                }
            }

            if !self.running.load(Ordering::SeqCst) {
                continue;
            }
            // Crash or spawn failure — back off before respawn
            self.park_while_active(Duration::from_secs(backoff));
            backoff = (backoff * 2).min(BACKOFF_MAX_SECS);
        }
    }

    fn spawn_tailscaled(&self) -> std::io::Result<std::process::Child> {
        let log_out = OpenOptions::new().create(true).append(true).open(LOG_FILE);
        let (stdout, stderr) = match log_out {
            Ok(f) => {
                let f2 = f.try_clone();
                (
                    Stdio::from(f),
                    f2.map(Stdio::from).unwrap_or_else(|_| Stdio::null()),
                )
            }
            Err(_) => (Stdio::null(), Stdio::null()),
        };
        Command::new(TAILSCALED_BIN)
            .args([
                "--tun=userspace-networking",
                &format!("--state={STATE_FILE}"),
                &format!("--statedir={RUN_DIR}"),
                &format!("--socket={SOCK}"),
                "--port=41641",
                "--no-logs-no-support",
            ])
            .env("GOGC", "25")
            .env("GOMEMLIMIT", "192MiB")
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
    }

    /// Poll status while the child is alive. Detects suspend/resume via
    /// wall-clock jumps and nudges the daemon. Returns true if the exit was
    /// requested (disable/update), false on crash/forced restart.
    fn monitor_until_exit(
        &self,
        child: &mut std::process::Child,
        identity: ChildIdentity,
    ) -> bool {
        let mut last_tick = unix_now();
        let mut bad_cycles = 0u32;
        let mut needs_login_cycles = 0u32;
        loop {
            // Requested stop?
            if !self.running.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst) {
                self.graceful_stop(child);
                return true;
            }
            if self.take_relay_restart(identity) {
                eprintln!("[tailscale] restarting tailscaled on verified relay health check");
                self.graceful_stop(child);
                return false;
            }
            match child.try_wait() {
                Ok(Some(_)) => return false, // crashed / externally killed
                Ok(None) => {}
                Err(_) => return false,
            }

            // Suspend/resume detection: wall clock jumped past our sleep
            let now = unix_now();
            if now - last_tick > (POLL_SECS as i64) * 2 + 30 {
                eprintln!("[tailscale] wall-clock jump detected (suspend?) — rebind/restun");
                self.nudge();
            }
            last_tick = now;

            let payload = self.refresh_status();
            let cfg = self.config.lock().unwrap().clone();

            // Wakelock is load-bearing for reachability — keep retrying if the
            // ubus call failed earlier (silent sleep = dead tunnel).
            if cfg.enabled && cfg.hold_wakelock && !self.wakelock_held.load(Ordering::SeqCst) {
                self.acquire_wakelock();
            }

            match payload["state"].as_str().unwrap_or("") {
                "healthy" => {
                    bad_cycles = 0;
                    needs_login_cycles = 0;
                }
                // Real connectivity problems only — Health warnings alone do
                // NOT restart the daemon (they can be benign and permanent).
                "degraded" | "connecting" | "starting" | "unknown" => {
                    bad_cycles += 1;
                    if bad_cycles == 2 {
                        eprintln!("[tailscale] unhealthy for 2 cycles — rebind/restun");
                        self.nudge();
                    } else if bad_cycles >= 4 {
                        eprintln!("[tailscale] unhealthy for {bad_cycles} cycles — restarting");
                        self.graceful_stop(child);
                        return false; // backoff respawn
                    }
                }
                // Backend Stopped (WantRunning=false, e.g. after `down`) while
                // the user wants it enabled — self-heal with a full-pref `up`.
                // Makes POST /enable eventually consistent regardless of the
                // daemon-startup races. Never runs during interactive login.
                "paused" if cfg.enabled && !self.enrollment_active() => {
                    eprintln!("[tailscale] backend Stopped while enabled — bringing it up");
                    let mut args = self.pref_args("up");
                    args.push("--timeout=30s".to_string());
                    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                    if let Err(e) = cli(&arg_refs, 40) {
                        eprintln!("[tailscale] up after Stopped: {e}");
                    }
                    self.refresh_status();
                }
                // Spurious logout with an enrolled node: one restore attempt
                // from the post-enrollment state backup (report §4.6 ladder).
                "needs_login" if cfg.enrolled => {
                    needs_login_cycles += 1;
                    if needs_login_cycles >= 3
                        && Path::new(STATE_BAK).exists()
                        && !self.enrollment_active()
                        && !self.state_restore_attempted.swap(true, Ordering::SeqCst)
                    {
                        eprintln!("[tailscale] enrolled node stuck in NeedsLogin — restoring state backup");
                        self.graceful_stop(child);
                        let _ = std::fs::copy(STATE_BAK, STATE_FILE);
                        return false; // respawn with restored state
                    }
                }
                _ => {
                    bad_cycles = 0;
                }
            }

            // Park until the next status poll. Disable/update/kill_child
            // notify the condvar; the child is re-checked every
            // CHILD_POLL_SECS. A wake never resets the deadline, so the
            // 30 s status cadence and the bad_cycles ladder are unchanged.
            let deadline = Instant::now() + Duration::from_secs(POLL_SECS);
            loop {
                if !self.running.load(Ordering::SeqCst)
                    || self.paused.load(Ordering::SeqCst)
                    || self.has_relay_restart(identity)
                    || matches!(child.try_wait(), Ok(Some(_)) | Err(_))
                {
                    break;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let guard = self.wake_lock.lock().unwrap_or_else(|e| e.into_inner());
                if !self.running.load(Ordering::SeqCst)
                    || self.paused.load(Ordering::SeqCst)
                    || self.has_relay_restart(identity)
                {
                    break;
                }
                drop(
                    self.wake_cv
                        .wait_timeout(guard, remaining.min(Duration::from_secs(CHILD_POLL_SECS)))
                        .unwrap_or_else(|e| e.into_inner()),
                );
            }
        }
    }

    fn graceful_stop(&self, child: &mut std::process::Child) {
        let pid = child.id();
        unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        for _ in 0..15 {
            if matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.wait();
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Signal the supervised child by pid, verifying via /proc that the pid
    /// still belongs to tailscaled (guards against pid recycling).
    fn kill_child(&self, sig: i32) {
        if let Some(child) = *self.active_child.lock().unwrap() {
            let pid = child.pid;
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            let comm = comm.trim();
            if comm.is_empty() || comm == "tailscaled" {
                unsafe { libc::kill(pid as i32, sig) };
            }
        }
        // The monitor would notice the exit within CHILD_POLL_SECS; wake it now
        self.wake_supervisor();
    }

    /// SIGTERM (then SIGKILL) any tailscaled we don't own. On this device any
    /// tailscaled instance is ours — typically an orphan from a previous
    /// zte-agent process.
    fn kill_orphan_tailscaled(&self) {
        let pids = |out: &std::process::Output| -> Vec<i32> {
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect()
        };
        let found = match Command::new("pidof").arg("tailscaled").output() {
            Ok(o) if o.status.success() => pids(&o),
            _ => return,
        };
        if found.is_empty() {
            return;
        }
        eprintln!("[tailscale] terminating orphaned tailscaled instance(s): {found:?}");
        for pid in &found {
            unsafe { libc::kill(*pid, libc::SIGTERM) };
        }
        for _ in 0..10 {
            thread::sleep(Duration::from_secs(1));
            match Command::new("pidof").arg("tailscaled").output() {
                Ok(o) if o.status.success() && !pids(&o).is_empty() => continue,
                _ => return,
            }
        }
        if let Ok(o) = Command::new("pidof").arg("tailscaled").output() {
            for pid in pids(&o) {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }

    /// Gate startup on a sane clock (control-plane TLS fails with a 1970
    /// clock) and a connected uplink (Wi-Fi relay or cellular WAN). Best-effort:
    /// proceeds after ~90s anyway — tailscaled retries on its own.
    fn wait_for_clock_and_wan(&self) {
        self.wait_for_clock_and_wan_with(
            unix_now,
            || probe_cellular_wan(true),
            || self.relay_active(),
            Duration::from_secs(1),
        );
    }

    fn wait_for_clock_and_wan_with(
        &self,
        now_fn: impl Fn() -> i64,
        mut probe_wan: impl FnMut() -> bool,
        relay_up: impl Fn() -> bool,
        tick_dur: Duration,
    ) {
        let mut cellular_ok = false;
        for tick in 0..90 {
            if !self.running.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst) {
                return;
            }
            let clock_ok = now_fn() >= SANE_CLOCK_EPOCH;
            let relay_ok = relay_up();
            if !relay_ok && should_probe_wan(tick) {
                cellular_ok = probe_wan();
            }
            if clock_ok && (relay_ok || cellular_ok) {
                return;
            }
            let guard = self.wake_lock.lock().unwrap_or_else(|err| err.into_inner());
            drop(
                self.wake_cv
                    .wait_timeout_while(guard, tick_dur, |_| {
                        self.running.load(Ordering::SeqCst)
                            && !self.paused.load(Ordering::SeqCst)
                            && (relay_ok || !relay_up())
                    })
                    .unwrap_or_else(|err| err.into_inner()),
            );
        }
    }

    /// Idempotent prefs, applied after every daemon start. Retries while the
    /// socket comes up. Failure is non-fatal (e.g. no profile before first
    /// enrollment).
    fn apply_prefs_when_ready(&self) {
        for _ in 0..15 {
            if !self.running.load(Ordering::SeqCst) || self.paused.load(Ordering::SeqCst) {
                return;
            }
            if daemon_status(5).is_ok() {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        if self.paused.load(Ordering::SeqCst) {
            return;
        }
        if state_file_exists() {
            let args = self.pref_args("set");
            let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            if let Err(e) = cli(&arg_refs, CLI_TIMEOUT_SECS) {
                eprintln!("[tailscale] apply prefs: {e}");
            }
        }
        self.refresh_status();
    }

    /// Shared pref flags for `set` (steady state) and `up` (enrollment /
    /// re-activation). Never includes --auth-key (tailscale#16987).
    fn pref_args(&self, verb: &str) -> Vec<String> {
        let cfg = self.config.lock().unwrap().clone();
        pref_args_for(&cfg, verb)
    }

    /// `tailscale debug rebind` + `restun`: cheap recovery for stale NAT
    /// mappings after suspend or WAN flap, without a daemon restart.
    fn nudge(&self) {
        let _ = cli(&["debug", "rebind"], 10);
        let _ = cli(&["debug", "restun"], 10);
    }

    // --- Status ---

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
        if !cached.is_null() && now.saturating_sub(at) < 10 {
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
                let mut in_flight = self
                    .status_refresh_lock
                    .lock()
                    .unwrap_or_else(|err| err.into_inner());
                *in_flight = false;
                self.status_refresh_cv.notify_all();
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
        if !cached.is_null() && now.saturating_sub(at) < 10 {
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
        let (status, _, _) = self.last_status.lock().unwrap().clone();
        matches!(
            status["state"].as_str().unwrap_or(""),
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
        let mgr = Self::new();
        *mgr.config.lock().unwrap() = cfg;
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

    // --- Lifecycle operations (called from handlers) ---

    fn ensure_daemon_ready(self: &Arc<Self>, wait_secs: u64) -> Result<(), String> {
        if !installed() {
            return Err("tailscale is not installed — POST /api/tailscale/update first".into());
        }
        if self.updating.load(Ordering::SeqCst) {
            return Err("update in progress".into());
        }
        self.running.store(true, Ordering::SeqCst);
        self.ensure_supervisor();
        self.wake_supervisor();
        for _ in 0..wait_secs {
            if daemon_status(5).is_ok() {
                return Ok(());
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err("tailscaled did not become ready in time — check /api/tailscale/status".into())
    }

    /// Non-blocking: flags the desired state and returns. The supervisor
    /// spawns the daemon and the monitor loop self-heals a Stopped backend
    /// (`up` with full pref flags — a previous `tailscale down` persists
    /// WantRunning=false). Track progress via GET /api/tailscale/status.
    pub fn do_enable(self: &Arc<Self>) -> Result<(), String> {
        if !installed() {
            return Err("tailscale is not installed — POST /api/tailscale/update first".into());
        }
        if self.updating.load(Ordering::SeqCst) {
            return Err("update in progress".into());
        }
        let hold = {
            let mut cfg = self.config.lock().unwrap();
            cfg.enabled = true;
            config::save(&cfg)?;
            cfg.hold_wakelock
        };
        if hold {
            self.acquire_wakelock();
        }
        self.running.store(true, Ordering::SeqCst);
        self.ensure_supervisor();
        self.wake_supervisor();
        self.refresh_status();
        Ok(())
    }

    pub fn do_disable(&self) -> Result<(), String> {
        {
            let mut cfg = self.config.lock().unwrap();
            cfg.enabled = false;
            config::save(&cfg)?;
        }
        // Politely stop the backend so the node shows offline, then stop the daemon
        if self.active_child.lock().unwrap().is_some() {
            let _ = cli(&["down"], 15);
        }
        self.running.store(false, Ordering::SeqCst);
        self.wake_supervisor();
        self.kill_child(libc::SIGTERM);
        self.release_wakelock();
        self.refresh_status();
        Ok(())
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

    /// Pause the supervisor and wait until it is parked with no child.
    /// Returns false if it fails to quiesce within the budget.
    fn quiesce_supervisor(&self) -> bool {
        self.paused.store(true, Ordering::SeqCst);
        self.wake_supervisor();
        for i in 0..QUIESCE_TIMEOUT_SECS {
            if i % 5 == 0 {
                self.kill_child(libc::SIGTERM);
            }
            if self.supervisor_idle.load(Ordering::SeqCst)
                && self.active_child.lock().unwrap().is_none()
            {
                return true;
            }
            thread::sleep(Duration::from_secs(1));
        }
        false
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

/// `connect_status` of `zwrt_data get_wwaniface` (or `wan_status` of
/// `router_event_wan_connect_status`) with a data session up. The firmware
/// reports `ipv4_connected` / `ipv6_connected` / `ipv4_ipv6_connected` (and
/// `disconnected` / `ipv4_disconnected` / `connecting`, which must not match);
/// older notes show a bare `connected`.
fn wan_connected(status: &str) -> bool {
    status == "connected" || status.ends_with("_connected")
}

/// WAN reconnects within [`WAN_DEBOUNCE`] of the last handled one share its
/// health check. Monotonic: the carrier's NITZ wall-clock jump (+8 h, landing
/// right at reconnect) must not suppress the checks that follow.
fn debounced(last: Option<Instant>, now: Instant) -> bool {
    last.is_some_and(|t| now.saturating_duration_since(t) < WAN_DEBOUNCE)
}

/// WAN probe schedule for the 90-tick startup gate: three quick probes, then
/// one every 10 s (11 forks per gate instead of 90 while WAN is down).
fn should_probe_wan(tick: u32) -> bool {
    tick < 3 || tick % 10 == 0
}

fn probe_cellular_wan(default_on_err: bool) -> bool {
    match ubus::call(
        "zwrt_data",
        "get_wwaniface",
        Some(r#"{"source_module":"zte_topsw_data","cid":1}"#),
    ) {
        Ok(value) => value["connect_status"]
            .as_str()
            .is_some_and(wan_connected),
        Err(_) => default_on_err,
    }
}

fn rotate_log_if_big() {
    if let Ok(meta) = std::fs::metadata(LOG_FILE) {
        if meta.len() > LOG_MAX_BYTES {
            let _ = std::fs::rename(LOG_FILE, format!("{LOG_FILE}.old"));
        }
    }
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

fn is_valid_version(version: &str) -> bool {
    !version.is_empty()
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

fn parse_stable_semver(raw: &str) -> Option<(String, semver::Version)> {
    let trimmed = raw.trim();
    let clean = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    if !is_valid_version(clean) {
        return None;
    }
    let parsed = semver::Version::parse(clean).ok()?;
    if !parsed.pre.is_empty() || !parsed.build.is_empty() {
        return None;
    }
    Some((clean.to_string(), parsed))
}

fn parse_pkgs_latest(body: &Value) -> Result<String, String> {
    if let Some(tarballs) = body.get("Tarballs").and_then(Value::as_object) {
        let arm64 = tarballs
            .get("arm64")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if arm64.is_empty() {
            return Err("pkgs.tailscale.com index is missing an arm64 tarball".into());
        }
    }
    let candidate = body["TarballsVersion"]
        .as_str()
        .or_else(|| body["Version"].as_str())
        .map(str::trim)
        .unwrap_or("");
    if is_valid_version(candidate) {
        Ok(candidate.to_string())
    } else {
        Err("pkgs.tailscale.com returned an invalid latest version".into())
    }
}

fn parse_github_releases(body: &Value) -> Result<Vec<ReleaseEntry>, String> {
    let list = body
        .as_array()
        .ok_or_else(|| "GitHub releases payload is not an array".to_string())?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for item in list {
        if item["draft"].as_bool().unwrap_or(false) || item["prerelease"].as_bool().unwrap_or(false)
        {
            continue;
        }
        let Some(tag) = item["tag_name"].as_str() else {
            continue;
        };
        let Some((version, _)) = parse_stable_semver(tag) else {
            continue;
        };
        if !seen.insert(version.clone()) {
            continue;
        }
        let published_at = item["published_at"]
            .as_str()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string);
        out.push(ReleaseEntry {
            version,
            published_at,
        });
    }
    Ok(out)
}

fn compare_release_desc(left: &ReleaseEntry, right: &ReleaseEntry) -> std::cmp::Ordering {
    match (
        semver::Version::parse(&left.version),
        semver::Version::parse(&right.version),
    ) {
        (Ok(left_sv), Ok(right_sv)) => right_sv
            .cmp(&left_sv)
            .then_with(|| right.version.cmp(&left.version)),
        _ => right.version.cmp(&left.version),
    }
}

fn merge_version_catalog(
    pkgs: Result<String, String>,
    github: Result<Vec<ReleaseEntry>, String>,
    fetched_at: i64,
) -> Result<VersionCatalog, String> {
    match (pkgs, github) {
        (Ok(latest), Ok(gh_entries)) => {
            let latest_sv = semver::Version::parse(&latest).ok();
            let mut versions: Vec<ReleaseEntry> = gh_entries
                .into_iter()
                .filter(|entry| match (&latest_sv, semver::Version::parse(&entry.version).ok()) {
                    (Some(max_sv), Some(entry_sv)) => entry_sv <= *max_sv,
                    _ => true,
                })
                .collect();
            let warning = if versions.is_empty() {
                Some(
                    "GitHub returned no matching stable releases; showing latest stable from pkgs.tailscale.com."
                        .to_string(),
                )
            } else {
                None
            };
            if !versions.iter().any(|entry| entry.version == latest) {
                versions.push(ReleaseEntry {
                    version: latest.clone(),
                    published_at: None,
                });
            }
            versions.sort_by(compare_release_desc);
            versions.dedup_by(|left, right| left.version == right.version);
            versions.truncate(MAX_LISTED_VERSIONS);
            Ok(VersionCatalog {
                latest,
                versions,
                source: "github+pkgs".to_string(),
                warning,
                fetched_at,
            })
        }
        (Ok(latest), Err(gh_err)) => Ok(VersionCatalog {
            versions: vec![ReleaseEntry {
                version: latest.clone(),
                published_at: None,
            }],
            latest,
            source: "pkgs".to_string(),
            warning: Some(format!(
                "Could not load release history from GitHub ({gh_err}); showing latest stable from pkgs.tailscale.com."
            )),
            fetched_at,
        }),
        (Err(pkgs_err), Ok(mut gh_entries)) if !gh_entries.is_empty() => {
            gh_entries.sort_by(compare_release_desc);
            gh_entries.dedup_by(|left, right| left.version == right.version);
            gh_entries.truncate(MAX_LISTED_VERSIONS);
            let latest = gh_entries[0].version.clone();
            Ok(VersionCatalog {
                latest,
                versions: gh_entries,
                source: "github".to_string(),
                warning: Some(format!(
                    "Could not verify latest package index at pkgs.tailscale.com ({pkgs_err}); showing GitHub releases."
                )),
                fetched_at,
            })
        }
        (Err(pkgs_err), Err(gh_err)) => Err(format!(
            "failed to load Tailscale releases: pkgs.tailscale.com ({pkgs_err}); GitHub ({gh_err})"
        )),
        (Err(pkgs_err), Ok(_)) => Err(format!(
            "failed to load Tailscale releases: pkgs.tailscale.com ({pkgs_err}); GitHub returned no stable releases"
        )),
    }
}

fn parse_sha256_text(text: &str) -> Result<String, String> {
    let token = text.split_whitespace().next().unwrap_or("");
    if token.len() == 64 && token.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Ok(token.to_ascii_lowercase())
    } else {
        Err("official checksum response is not a valid 64-character SHA-256 digest".into())
    }
}

fn read_bounded_string(
    resp: ureq::http::Response<ureq::Body>,
    max_bytes: usize,
) -> Result<String, String> {
    let mut raw = Vec::new();
    resp.into_body()
        .into_reader()
        .take((max_bytes as u64) + 1)
        .read_to_end(&mut raw)
        .map_err(|err| format!("read response: {err}"))?;
    if raw.len() > max_bytes {
        return Err(format!("response exceeded {max_bytes}-byte limit"));
    }
    String::from_utf8(raw).map_err(|err| format!("invalid UTF-8 response: {err}"))
}

fn fetch_json_url(
    agent: &ureq::Agent,
    url: &str,
    accept: Option<&str>,
    max_bytes: usize,
) -> Result<Value, String> {
    let mut req = agent.get(url).header("User-Agent", TAILSCALE_USER_AGENT);
    if let Some(header_val) = accept {
        req = req.header("Accept", header_val);
    }
    let resp = req.call().map_err(|err| err.to_string())?;
    let text = read_bounded_string(resp, max_bytes)?;
    serde_json::from_str(&text).map_err(|err| format!("parse JSON: {err}"))
}

fn fetch_versions_from_urls(pkgs_url: &str, github_url: &str) -> Result<VersionCatalog, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(VERSIONS_CONNECT_TIMEOUT))
        .timeout_global(Some(VERSIONS_FETCH_TIMEOUT))
        .build()
        .into();
    let (pkgs_res, gh_res) = thread::scope(|scope| {
        let pkgs_handle = scope.spawn(|| {
            let body = fetch_json_url(&agent, pkgs_url, None, PKGS_INDEX_MAX_BYTES)?;
            parse_pkgs_latest(&body)
        });
        let gh_handle = scope.spawn(|| {
            let body = fetch_json_url(
                &agent,
                github_url,
                Some("application/vnd.github+json"),
                GITHUB_RELEASES_MAX_BYTES,
            )?;
            parse_github_releases(&body)
        });
        let pkgs_out = pkgs_handle
            .join()
            .unwrap_or_else(|_| Err("pkgs.tailscale.com lookup panicked".into()));
        let gh_out = gh_handle
            .join()
            .unwrap_or_else(|_| Err("GitHub releases lookup panicked".into()));
        (pkgs_out, gh_out)
    });
    merge_version_catalog(pkgs_res, gh_res, unix_now())
}

fn fetch_versions_live() -> Result<VersionCatalog, String> {
    if cfg!(test) {
        return Err("version lookup disabled in tests".into());
    }
    fetch_versions_from_urls(TAILSCALE_PKGS_INDEX_URL, TAILSCALE_GITHUB_RELEASES_URL)
}

impl TailscaleManager {
    fn versions_catalog_with<F>(&self, force_refresh: bool, fetch: F) -> Result<VersionCatalog, String>
    where
        F: FnOnce() -> Result<VersionCatalog, String>,
    {
        if !force_refresh {
            let guard = self
                .versions_cache
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            if let Some((catalog, fetched_instant)) = guard.as_ref() {
                if fetched_instant.elapsed() < VERSIONS_CACHE_TTL {
                    return Ok(catalog.clone());
                }
            }
        }
        let fresh = fetch()?;
        let mut guard = self
            .versions_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        *guard = Some((fresh.clone(), Instant::now()));
        Ok(fresh)
    }
}

/// GET /api/tailscale/versions — recent official stable ARM64 versions
/// (cached in memory for 10 minutes).
pub fn versions(state: &AppState) -> (u16, Value) {
    match state
        .tailscale
        .versions_catalog_with(false, fetch_versions_live)
    {
        Ok(catalog) => (200, json!({"ok": true, "data": catalog.to_json()})),
        Err(err) => (502, json!({"ok": false, "error": err})),
    }
}

/// POST /api/tailscale/versions/refresh — bypass cache and fetch recent
/// official stable ARM64 versions immediately.
pub fn versions_refresh(state: &AppState) -> (u16, Value) {
    match state
        .tailscale
        .versions_catalog_with(true, fetch_versions_live)
    {
        Ok(catalog) => (200, json!({"ok": true, "data": catalog.to_json()})),
        Err(err) => (502, json!({"ok": false, "error": err})),
    }
}

fn parse_update_request(body: &[u8]) -> Result<(String, Option<String>), String> {
    let parsed: Value = serde_json::from_slice(body).map_err(|_| "invalid JSON".to_string())?;
    let version = match parsed["version"].as_str().map(str::trim) {
        Some(ver) if is_valid_version(ver) => ver.to_string(),
        _ => return Err("missing or invalid 'version'".into()),
    };
    let sha256 = match parsed.get("sha256") {
        None | Some(Value::Null) => None,
        Some(Value::String(raw)) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.len() == 64 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
                Some(trimmed.to_ascii_lowercase())
            } else {
                return Err("missing or invalid 'sha256' (64 hex chars)".into());
            }
        }
        _ => return Err("missing or invalid 'sha256' (64 hex chars)".into()),
    };
    Ok((version, sha256))
}

fn fetch_official_sha256_at(url: &str) -> Result<String, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(VERSIONS_CONNECT_TIMEOUT))
        .timeout_global(Some(SHA256_FETCH_TIMEOUT))
        .build()
        .into();
    let resp = agent
        .get(url)
        .header("User-Agent", TAILSCALE_USER_AGENT)
        .call()
        .map_err(|err| format!("fetch official sha256 {url}: {err}"))?;
    let body = read_bounded_string(resp, SHA256_FILE_MAX_BYTES)?;
    parse_sha256_text(&body)
}

/// POST /api/tailscale/update — body: {"version": "1.104.7", "sha256": "<optional hex>"}
/// Installs when absent; upgrades with rollback when present. Runs in the
/// background (multi-minute download on cellular) — poll /status for
/// "updating" and "last_update".
pub fn update(state: &AppState, body: &[u8]) -> (u16, Value) {
    let mgr = &state.tailscale;
    let (version, sha256) = match parse_update_request(body) {
        Ok(req) => req,
        Err(err) => return (400, json!({"ok": false, "error": err})),
    };

    if mgr
        .updating
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return (409, json!({"ok": false, "error": "update already in progress"}));
    }
    // Refresh so clients polling /status see "updating" immediately (the
    // cache is otherwise served for up to 10s)
    mgr.refresh_status();

    let mgr2 = Arc::clone(&state.tailscale);
    thread::spawn(move || {
        let result = run_update(&mgr2, &version, sha256.as_deref());
        if let Err(ref e) = result {
            eprintln!("[tailscale] update to {version} failed: {e}");
        }
        *mgr2.last_update.lock().unwrap() = Some(json!({
            "version": version,
            "ok": result.is_ok(),
            "error": result.err(),
            "finished_at": unix_now(),
        }));
        mgr2.updating.store(false, Ordering::SeqCst);
        mgr2.refresh_status();
    });
    (202, json!({"ok": true, "data": {"status": "updating"}}))
}

fn run_update(
    mgr: &Arc<TailscaleManager>,
    version: &str,
    expected_sha256: Option<&str>,
) -> Result<(), String> {
    let tgz_path = "/tmp/tailscale-update.tgz";
    let extract_dir = "/tmp/tailscale-update";
    let result = run_update_inner(mgr, version, expected_sha256, tgz_path, extract_dir);
    // Never leak tmpfs space, whatever the exit path
    let _ = std::fs::remove_file(tgz_path);
    let _ = std::fs::remove_dir_all(extract_dir);
    for name in ["tailscaled", "tailscale"] {
        let _ = std::fs::remove_file(format!("{BIN_DIR}/{name}.new"));
    }
    result
}

fn run_update_inner(
    mgr: &Arc<TailscaleManager>,
    version: &str,
    expected_sha256: Option<&str>,
    tgz_path: &str,
    extract_dir: &str,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let url = format!("https://pkgs.tailscale.com/stable/tailscale_{version}_arm64.tgz");
    let sha256 = match expected_sha256 {
        Some(digest) => digest.to_string(),
        None => {
            let sha_url = format!("{url}.sha256");
            fetch_official_sha256_at(&sha_url)?
        }
    };

    // 1. Download (streamed to tmpfs, 120 MB cap)
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_global(Some(Duration::from_secs(600)))
        .build()
        .into();
    let resp = agent
        .get(&url)
        .header("User-Agent", TAILSCALE_USER_AGENT)
        .call()
        .map_err(|err| format!("download {url}: {err}"))?;
    let mut reader = resp.into_body().into_reader().take(120 * 1024 * 1024);
    let mut out = std::fs::File::create(tgz_path).map_err(|e| format!("create {tgz_path}: {e}"))?;
    std::io::copy(&mut reader, &mut out).map_err(|e| format!("download stream: {e}"))?;
    drop(out);

    // 2. Verify sha256
    let actual = sha256_file(tgz_path)?;
    if actual != sha256 {
        return Err(format!("sha256 mismatch: expected {sha256}, got {actual}"));
    }

    // 3. Extract via busybox tar
    let _ = std::fs::remove_dir_all(extract_dir);
    std::fs::create_dir_all(extract_dir).map_err(|e| format!("mkdir {extract_dir}: {e}"))?;
    let mut tar = Command::new("tar");
    tar.args(["-xzf", tgz_path, "-C", extract_dir]);
    let out = run_with_timeout(tar, 120)?;
    if !out.status.success() {
        return Err(format!("tar extract failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let src_dir = format!("{extract_dir}/tailscale_{version}_arm64");

    // 4. Stage new binaries next to the current ones (same filesystem for
    //    atomic rename) and smoke-test before touching the live install.
    std::fs::create_dir_all(BIN_DIR).map_err(|e| format!("mkdir {BIN_DIR}: {e}"))?;
    for name in ["tailscaled", "tailscale"] {
        let src = format!("{src_dir}/{name}");
        let staged = format!("{BIN_DIR}/{name}.new");
        std::fs::copy(&src, &staged).map_err(|e| format!("stage {name}: {e}"))?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {name}: {e}"))?;
    }
    let _ = std::fs::remove_file(tgz_path);
    let _ = std::fs::remove_dir_all(extract_dir);

    let mut smoke = Command::new(format!("{BIN_DIR}/tailscaled.new"));
    smoke.arg("--version");
    let smoke_out = run_with_timeout(smoke, 15)?;
    if !smoke_out.status.success() {
        return Err("staged tailscaled failed --version smoke test".into());
    }

    // 5. Quiesce the supervisor — a real handshake, not a best-effort wait:
    //    swapping binaries under a live or mid-spawn supervisor can leave the
    //    OLD daemon running while we validate and pin the new version.
    let was_running = mgr.running.load(Ordering::SeqCst);
    let enrolled = mgr.config.lock().unwrap().enrolled;
    if !mgr.quiesce_supervisor() {
        mgr.resume_supervisor();
        return Err("supervisor did not quiesce — update aborted".into());
    }

    let swap = || -> Result<(), String> {
        for name in ["tailscaled", "tailscale"] {
            let current = format!("{BIN_DIR}/{name}");
            let prev = format!("{current}.prev");
            let staged = format!("{current}.new");
            if Path::new(&current).exists() {
                std::fs::rename(&current, &prev).map_err(|e| format!("backup {name}: {e}"))?;
            }
            std::fs::rename(&staged, &current).map_err(|e| format!("install {name}: {e}"))?;
        }
        Ok(())
    };
    let rollback = || {
        for name in ["tailscaled", "tailscale"] {
            let current = format!("{BIN_DIR}/{name}");
            let prev = format!("{current}.prev");
            if Path::new(&prev).exists() {
                let _ = std::fs::rename(&prev, &current);
            }
        }
    };

    if let Err(e) = swap() {
        rollback();
        mgr.resume_supervisor();
        return Err(e);
    }

    // 6. Resume; if it was enrolled+enabled, require Running within 120s or
    //    roll back. Gate on `enrolled`, not the state file — tailscaled
    //    creates a state file before first login, and an unenrolled node
    //    sits in NeedsLogin forever (which is not a failed update).
    mgr.resume_supervisor();
    if was_running && enrolled {
        let mut healthy = false;
        for _ in 0..120 {
            thread::sleep(Duration::from_secs(1));
            if let Ok(v) = daemon_status(10) {
                if v["BackendState"].as_str() == Some("Running") {
                    healthy = true;
                    break;
                }
            }
        }
        if !healthy {
            eprintln!("[tailscale] update: not Running within 120s — rolling back");
            if !mgr.quiesce_supervisor() {
                mgr.resume_supervisor();
                return Err(
                    "updated tailscaled unhealthy and supervisor did not quiesce for rollback — manual intervention needed"
                        .into(),
                );
            }
            rollback();
            mgr.resume_supervisor();
            return Err("updated tailscaled did not reach Running in 120s — rolled back".into());
        }
    }

    let mut cfg = mgr.config.lock().unwrap();
    cfg.pinned_version = version.to_string();
    let _ = config::save(&cfg);
    Ok(())
}

fn sha256_file(path: &str) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("read {path}: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    /// Tab-indented like tailscaled's encoder (`SetIndent("", "\t")`).
    const STATUS_BODY: &str = "{\n\t\"Version\": \"1.86.2\",\n\t\"BackendState\": \"Running\",\n\t\"Self\": {\n\t\t\"Online\": true,\n\t\t\"DNSName\": \"u60-pro.tail.ts.net.\"\n\t},\n\t\"Health\": []\n}\n";

    #[test]
    fn wan_gate_accepts_every_connected_variant() {
        for s in [
            "connected",
            "ipv4_connected",
            "ipv6_connected",
            "ipv4_ipv6_connected",
        ] {
            assert!(wan_connected(s), "{s}");
        }
        for s in [
            "",
            "disconnected",
            "connecting",
            "init",
            "ipv4_disconnected",
        ] {
            assert!(!wan_connected(s), "{s}");
        }
    }

    #[test]
    fn wan_watch_debounce_is_monotonic() {
        let start = Instant::now();
        assert!(!debounced(None, start));
        assert!(debounced(Some(start), start + Duration::from_secs(10)));
        assert!(!debounced(Some(start), start + Duration::from_secs(31)));
        // A `now` that reads earlier than the stamp still debounces, never panics.
        assert!(debounced(Some(start + Duration::from_secs(1)), start));
    }

    #[test]
    fn wan_gate_probes_eleven_times_per_ninety_ticks() {
        let probes: Vec<u32> = (0..90).filter(|&t| should_probe_wan(t)).collect();
        assert_eq!(probes, [0, 1, 2, 10, 20, 30, 40, 50, 60, 70, 80]);
    }

    #[test]
    fn parses_a_200_with_crlf_headers() {
        let raw = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{STATUS_BODY}"
        );
        let v = parse_localapi_response(raw.as_bytes()).unwrap();
        assert_eq!(v["BackendState"], "Running");
        assert_eq!(v["Self"]["Online"], true);
        assert_eq!(v["Self"]["DNSName"], "u60-pro.tail.ts.net.");
        assert_eq!(v["Version"], "1.86.2");
    }

    #[test]
    fn parses_bare_lf_headers_and_an_http11_status_line() {
        let raw = format!("HTTP/1.1 200 OK\nContent-Type: application/json\n\n{STATUS_BODY}");
        let v = parse_localapi_response(raw.as_bytes()).unwrap();
        assert_eq!(v["BackendState"], "Running");
    }

    #[test]
    fn body_is_everything_after_the_first_blank_line() {
        let body = "{\n\t\"BackendState\": \"NeedsLogin\",\n\n\t\"AuthURL\": \"https://login.tailscale.com/a/abc\"\n}";
        let raw = format!("HTTP/1.0 200 OK\r\n\r\n{body}");
        let v = parse_localapi_response(raw.as_bytes()).unwrap();
        assert_eq!(v["AuthURL"], "https://login.tailscale.com/a/abc");
    }

    #[test]
    fn rejects_non_200_incomplete_chunked_and_non_http() {
        let forbidden =
            b"HTTP/1.0 403 Forbidden\r\nContent-Type: text/plain\r\n\r\ninvalid localapi request\n";
        let err = parse_localapi_response(forbidden).unwrap_err();
        assert!(
            err.contains("403") && err.contains("invalid localapi request"),
            "{err}"
        );
        assert!(
            parse_localapi_response(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n")
                .unwrap_err()
                .contains("incomplete")
        );
        assert!(
            parse_localapi_response(b"HTTP/1.0 200 OK\r\n\r\n{\"Backend")
                .unwrap_err()
                .contains("parse localapi JSON")
        );
        let chunked = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{STATUS_BODY}");
        assert!(parse_localapi_response(chunked.as_bytes())
            .unwrap_err()
            .contains("chunked"));
        assert!(parse_localapi_response(b"").is_err());
        assert!(parse_localapi_response(b"garbage\r\n\r\n{}")
            .unwrap_err()
            .contains("not an HTTP response"));
    }

    fn sock_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("zte-ts-{}-{name}.sock", std::process::id()))
    }

    /// One-shot fake tailscaled: records the request head, then answers
    /// `response` and closes (HTTP/1.0 semantics) or, given an empty
    /// response, stays silent past the client's deadline.
    fn serve_once(path: &Path, response: &'static str) -> thread::JoinHandle<Vec<String>> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut head = Vec::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                head.push(line.trim_end().to_string());
            }
            if response.is_empty() {
                thread::sleep(Duration::from_secs(3));
            } else {
                let stream = reader.get_mut();
                stream.write_all(response.as_bytes()).unwrap();
                stream.shutdown(std::net::Shutdown::Both).unwrap();
            }
            head
        })
    }

    #[test]
    fn localapi_round_trip_over_a_unix_socket() {
        let path = sock_path("ok");
        let server = serve_once(
            &path,
            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"BackendState\": \"Running\", \"Self\": {\"Online\": true}}\n",
        );
        let v = localapi_status_at(&path, 5).unwrap();
        assert_eq!(v["BackendState"], "Running");
        let head = server.join().unwrap();
        assert_eq!(head[0], "GET /localapi/v0/status?peers=false HTTP/1.0");
        assert!(
            head.contains(&"Host: local-tailscaled.sock".to_string()),
            "{head:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_silent_daemon_is_a_timeout_not_a_cli_fallback() {
        let path = sock_path("silent");
        let _server = serve_once(&path, "");
        let started = Instant::now();
        assert!(matches!(
            localapi_status_at(&path, 1),
            Err(LocalApiError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(3));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_socket_is_an_ordinary_error() {
        let path = sock_path("missing");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(
            localapi_status_at(&path, 1),
            Err(LocalApiError::Other(_))
        ));
    }

    fn test_manager(running: bool, pid: Option<u32>) -> Arc<TailscaleManager> {
        let manager = Arc::new(TailscaleManager {
            config: Mutex::new(TsConfig::default()),
            running: AtomicBool::new(running),
            paused: AtomicBool::new(false),
            supervisor_started: AtomicBool::new(false),
            supervisor_idle: AtomicBool::new(true),
            updating: AtomicBool::new(false),
            enrollment: Mutex::new(EnrollmentOp::Idle),
            state_restore_attempted: AtomicBool::new(false),
            active_child: Mutex::new(pid.map(|pid| ChildIdentity { pid, instance: 1 })),
            next_child_instance: AtomicU64::new(u64::from(pid.is_some())),
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
        });
        manager
    }

    fn stop_relay_watch(manager: &TailscaleManager) {
        let mut state = manager
            .relay_watch_lock
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        state.stopped = true;
        manager.relay_watch_cv.notify_all();
    }

    #[test]
    fn startup_gate_returns_immediately_when_wifi_relay_is_active_without_probing_cellular() {
        use std::sync::atomic::AtomicUsize;

        let manager = test_manager(true, None);
        let probes = AtomicUsize::new(0);
        let started = Instant::now();
        manager.wait_for_clock_and_wan_with(
            || SANE_CLOCK_EPOCH + 100,
            || {
                probes.fetch_add(1, Ordering::SeqCst);
                false
            },
            || true,
            Duration::from_secs(2),
        );
        assert_eq!(probes.load(Ordering::SeqCst), 0);
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn startup_gate_wakes_immediately_when_wifi_relay_connects() {
        let manager = test_manager(true, None);
        let relay_up = Arc::new(AtomicBool::new(false));
        let wake_manager = Arc::clone(&manager);
        let wake_relay = Arc::clone(&relay_up);
        let waker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            wake_relay.store(true, Ordering::SeqCst);
            wake_manager.relay_uplink_changed();
        });

        let started = Instant::now();
        manager.wait_for_clock_and_wan_with(
            || SANE_CLOCK_EPOCH + 100,
            || false,
            || relay_up.load(Ordering::SeqCst),
            Duration::from_secs(5),
        );
        waker.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(manager.relay_watch_lock.lock().unwrap().generation, 0);
    }

    #[test]
    fn startup_gate_waits_for_clock_without_spinning_when_relay_is_already_up() {
        use std::sync::atomic::AtomicUsize;

        let manager = test_manager(true, None);
        let checks = AtomicUsize::new(0);
        let started = Instant::now();
        manager.wait_for_clock_and_wan_with(
            || {
                if checks.fetch_add(1, Ordering::SeqCst) >= 2 {
                    SANE_CLOCK_EPOCH + 100
                } else {
                    0
                }
            },
            || false,
            || true,
            Duration::from_millis(15),
        );
        assert_eq!(checks.load(Ordering::SeqCst), 3);
        assert!(started.elapsed() >= Duration::from_millis(20));
    }

    #[test]
    fn relay_watch_coalesces_bursts_and_escalates_when_unhealthy() {
        let manager = test_manager(true, Some(100));
        let (event_tx, event_rx) = mpsc::channel();
        let worker_mgr = Arc::clone(&manager);
        let worker_tx = event_tx.clone();
        let handle = thread::spawn(move || {
            worker_mgr.watch_relay_uplink(
                Duration::from_millis(35),
                Duration::from_millis(60),
                Instant::now,
                || true,
                |_| false,
                || {
                    let _ = worker_tx.send("refresh");
                },
                || true,
                || {
                    let _ = worker_tx.send("nudge");
                },
                |_generation, child| {
                    let _ = worker_tx.send(if child.pid == 100 { "restart-100" } else { "restart-other" });
                },
            );
        });

        {
            let mut state = manager.relay_watch_lock.lock().unwrap();
            state.generation = 1;
            state.child = Some(ChildIdentity { pid: 100, instance: 1 });
            manager.relay_watch_cv.notify_all();
        }
        thread::sleep(Duration::from_millis(10));
        {
            let mut state = manager.relay_watch_lock.lock().unwrap();
            state.generation = 2;
            state.child = Some(ChildIdentity { pid: 100, instance: 1 });
            manager.relay_watch_cv.notify_all();
        }

        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "nudge");
        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "refresh");
        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "restart-100");
        assert!(event_rx.recv_timeout(Duration::from_millis(50)).is_err());

        stop_relay_watch(&manager);
        handle.join().unwrap();
    }

    #[test]
    fn relay_watch_handles_cellular_fallback_offline_and_fast_handover() {
        let manager = test_manager(true, Some(200));
        let relay_up = Arc::new(AtomicBool::new(true));
        let cellular_up = Arc::new(AtomicBool::new(false));
        let (event_tx, event_rx) = mpsc::channel();

        let worker_mgr = Arc::clone(&manager);
        let worker_relay = Arc::clone(&relay_up);
        let worker_cell = Arc::clone(&cellular_up);
        let worker_tx = event_tx.clone();
        let handle = thread::spawn(move || {
            worker_mgr.watch_relay_uplink(
                Duration::from_millis(30),
                Duration::from_millis(50),
                Instant::now,
                || worker_relay.load(Ordering::SeqCst),
                |_| worker_cell.load(Ordering::SeqCst),
                || {
                    let _ = worker_tx.send("refresh");
                },
                || false,
                || {
                    let label = if worker_relay.load(Ordering::SeqCst) {
                        "nudge-relay"
                    } else {
                        "nudge-cell"
                    };
                    let _ = worker_tx.send(label);
                },
                |_, _| {
                    let _ = worker_tx.send("restart");
                },
            );
        });

        let fire = |gen_val: u64, disconnected: bool| {
            let mut state = manager.relay_watch_lock.lock().unwrap();
            state.generation = gen_val;
            state.child = Some(ChildIdentity { pid: 200, instance: 1 });
            if disconnected {
                state.saw_disconnect = true;
            }
            manager.relay_watch_cv.notify_all();
        };

        // 1. Initial relay connect nudges once.
        fire(1, false);
        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "nudge-relay");
        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "refresh");

        // 2. Same-direction IPv6 update within debounce skips redundant nudge while healthy.
        fire(2, false);
        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "refresh");
        assert!(event_rx.recv_timeout(Duration::from_millis(80)).is_err());

        // 3. Fast AP-A -> AP-B handover (< settle) preserves saw_disconnect and still nudges.
        relay_up.store(false, Ordering::SeqCst);
        fire(3, true);
        thread::sleep(Duration::from_millis(8));
        relay_up.store(true, Ordering::SeqCst);
        fire(4, false);
        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "nudge-relay");
        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "refresh");

        // 4. Disconnect with cellular off skips nudge cleanly.
        relay_up.store(false, Ordering::SeqCst);
        cellular_up.store(false, Ordering::SeqCst);
        fire(5, true);
        assert!(event_rx.recv_timeout(Duration::from_millis(120)).is_err());

        // 5. Disconnect with cellular on nudges immediately onto cellular.
        cellular_up.store(true, Ordering::SeqCst);
        fire(6, true);
        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "nudge-cell");
        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "refresh");

        stop_relay_watch(&manager);
        handle.join().unwrap();
    }

    #[test]
    fn relay_watch_ignores_stale_pid_after_daemon_restart() {
        let manager = test_manager(true, Some(300));
        let (event_tx, event_rx) = mpsc::channel();
        let worker_mgr = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            worker_mgr.watch_relay_uplink(
                Duration::from_millis(40),
                Duration::from_millis(40),
                Instant::now,
                || true,
                |_| false,
                || {},
                || true,
                || {
                    let _ = event_tx.send("nudge");
                },
                |_, _| {
                    let _ = event_tx.send("restart");
                },
            );
        });

        {
            let mut state = manager.relay_watch_lock.lock().unwrap();
            state.generation = 1;
            state.child = Some(ChildIdentity { pid: 300, instance: 1 });
            manager.relay_watch_cv.notify_all();
        }
        thread::sleep(Duration::from_millis(10));
        *manager.active_child.lock().unwrap() = Some(ChildIdentity { pid: 301, instance: 2 });
        assert!(event_rx.recv_timeout(Duration::from_millis(120)).is_err());

        stop_relay_watch(&manager);
        handle.join().unwrap();
    }

    #[test]
    fn relay_watch_skips_restart_when_new_event_arrives_during_status_refresh() {
        use std::sync::atomic::AtomicUsize;

        let manager = test_manager(true, Some(400));
        let refresh_count = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();

        let worker_mgr = Arc::clone(&manager);
        let worker_refreshes = Arc::clone(&refresh_count);
        let health_refreshes = Arc::clone(&refresh_count);
        let refresh_tx = event_tx.clone();
        let restart_tx = event_tx.clone();
        let handle = thread::spawn(move || {
            worker_mgr.watch_relay_uplink(
                Duration::from_millis(20),
                Duration::from_millis(20),
                Instant::now,
                || true,
                |_| false,
                move || {
                    let step = worker_refreshes.fetch_add(1, Ordering::SeqCst);
                    let _ = refresh_tx.send(if step == 0 { "refresh-1" } else { "refresh-2" });
                    if step == 0 {
                        let _ = entered_tx.send(());
                        let _ = release_rx.recv_timeout(Duration::from_secs(2));
                    }
                },
                move || health_refreshes.load(Ordering::SeqCst) < 2,
                move || {
                    let _ = event_tx.send("nudge");
                },
                move |_, _| {
                    let _ = restart_tx.send("restart");
                },
            );
        });

        let identity = ChildIdentity { pid: 400, instance: 1 };
        {
            let mut state = manager.relay_watch_lock.lock().unwrap();
            state.generation = 1;
            state.child = Some(identity);
            manager.relay_watch_cv.notify_all();
        }
        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "nudge");
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "refresh-1");

        {
            let mut state = manager.relay_watch_lock.lock().unwrap();
            state.generation = 2;
            state.child = Some(identity);
            state.saw_disconnect = true;
            manager.relay_watch_cv.notify_all();
        }
        release_tx.send(()).unwrap();

        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "nudge");
        assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "refresh-2");
        assert!(event_rx.recv_timeout(Duration::from_millis(120)).is_err());

        stop_relay_watch(&manager);
        handle.join().unwrap();
    }

    #[test]
    fn relay_watch_skips_restart_when_paused_or_disabled_during_status_refresh() {
        for pause_instead_of_stop in [true, false] {
            let manager = test_manager(true, Some(410));
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let (event_tx, event_rx) = mpsc::channel();

            let worker_mgr = Arc::clone(&manager);
            let worker_tx = event_tx.clone();
            let handle = thread::spawn(move || {
                worker_mgr.watch_relay_uplink(
                    Duration::from_millis(20),
                    Duration::from_millis(20),
                    Instant::now,
                    || true,
                    |_| false,
                    move || {
                        let _ = entered_tx.send(());
                        let _ = release_rx.recv_timeout(Duration::from_secs(2));
                    },
                    || true,
                    move || {
                        let _ = event_tx.send("nudge");
                    },
                    move |_, _| {
                        let _ = worker_tx.send("restart");
                    },
                );
            });

            {
                let mut state = manager.relay_watch_lock.lock().unwrap();
                state.generation = 1;
                state.child = Some(ChildIdentity { pid: 410, instance: 1 });
                manager.relay_watch_cv.notify_all();
            }
            assert_eq!(event_rx.recv_timeout(Duration::from_secs(2)).unwrap(), "nudge");
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

            if pause_instead_of_stop {
                manager.paused.store(true, Ordering::SeqCst);
            } else {
                manager.running.store(false, Ordering::SeqCst);
            }
            manager.wake_supervisor();
            release_tx.send(()).unwrap();

            assert!(event_rx.recv_timeout(Duration::from_millis(120)).is_err());

            stop_relay_watch(&manager);
            handle.join().unwrap();
        }
    }

    #[test]
    fn supervisor_relay_restart_verifies_generation_intent_and_instance() {
        let manager = test_manager(true, Some(420));
        let first = ChildIdentity { pid: 420, instance: 1 };
        let recycled = ChildIdentity { pid: 420, instance: 2 };
        {
            let mut state = manager.relay_watch_lock.lock().unwrap();
            state.generation = 3;
            state.child = Some(first);
        }

        assert!(!manager.request_relay_restart(2, first));
        assert!(!manager.request_relay_restart(3, recycled));
        assert!(manager.request_relay_restart(3, first));
        assert!(manager.has_relay_restart(first));
        assert!(!manager.take_relay_restart(recycled));
        assert!(manager.take_relay_restart(first));
        assert!(!manager.take_relay_restart(first));

        assert!(manager.request_relay_restart(3, first));
        manager.relay_watch_lock.lock().unwrap().generation = 4;
        assert!(!manager.take_relay_restart(first));

        assert!(manager.request_relay_restart(4, first));
        manager.paused.store(true, Ordering::SeqCst);
        assert!(!manager.take_relay_restart(first));
        manager.paused.store(false, Ordering::SeqCst);
        manager.running.store(false, Ordering::SeqCst);
        assert!(!manager.request_relay_restart(4, first));
        assert!(!manager.take_relay_restart(first));
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

    fn serve_http_once(response: &'static str) -> (String, thread::JoinHandle<String>) {
        use std::io::Write;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 4096];
            let read = stream.read(&mut buf).unwrap_or(0);
            let _ = stream.write_all(response.as_bytes());
            String::from_utf8_lossy(&buf[..read]).into_owned()
        });
        (format!("http://{addr}"), handle)
    }

    #[test]
    fn parse_update_request_accepts_optional_sha256_and_rejects_malformed_inputs() {
        let digest = "A1b2c3d4".repeat(8);
        assert_eq!(
            parse_update_request(br#"{"version":"1.104.7"}"#).unwrap(),
            ("1.104.7".to_string(), None)
        );
        assert_eq!(
            parse_update_request(br#"{"version":" 1.104.7 ","sha256":null}"#).unwrap(),
            ("1.104.7".to_string(), None)
        );
        assert_eq!(
            parse_update_request(br#"{"version":"1.104.7","sha256":"   "}"#).unwrap(),
            ("1.104.7".to_string(), None)
        );
        let body = format!(r#"{{"version":"1.104.7","sha256":" {digest} "}}"#);
        assert_eq!(
            parse_update_request(body.as_bytes()).unwrap(),
            ("1.104.7".to_string(), Some(digest.to_ascii_lowercase()))
        );
        for bad in [
            r#"{"version":"v1.104.7"}"#,
            r#"{"version":"1..2"}"#,
            r#"{"version":""}"#,
            r#"{"version":"1.104.7","sha256":"short"}"#,
            r#"{"version":"1.104.7","sha256":123}"#,
            "not-json",
        ] {
            assert!(parse_update_request(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn parse_sha256_text_accepts_bare_and_sha256sum_formats() {
        let digest = "D6BED2720310B328B861F943D7B4016C5358A9BAD60575EB51E8143B79068484";
        assert_eq!(
            parse_sha256_text(&format!("{digest}\n")).unwrap(),
            digest.to_ascii_lowercase()
        );
        assert_eq!(
            parse_sha256_text(&format!("  {digest}  tailscale_1.104.7_arm64.tgz\n")).unwrap(),
            digest.to_ascii_lowercase()
        );
        assert!(parse_sha256_text("not-a-hash").is_err());
        assert!(parse_sha256_text("").is_err());
    }

    #[test]
    fn parse_github_releases_filters_prereleases_drafts_and_non_semver_tags() {
        let payload = json!([
            {"tag_name": "v1.104.7", "draft": false, "prerelease": false, "published_at": "2026-11-12T22:56:51Z"},
            {"tag_name": "v1.105.0-pre", "draft": false, "prerelease": false, "published_at": "2026-11-13T00:00:00Z"},
            {"tag_name": "v1.104.8", "draft": true, "prerelease": false, "published_at": "2026-11-13T00:00:00Z"},
            {"tag_name": "v1.104.6", "draft": false, "prerelease": true, "published_at": "2026-11-11T00:00:00Z"},
            {"tag_name": "cmd/cigocacher/deadbeef", "draft": false, "prerelease": false},
            {"tag_name": "v1.104.5", "draft": false, "prerelease": false, "published_at": "2026-11-03T00:29:40Z"},
            {"tag_name": "v1.104.5", "draft": false, "prerelease": false, "published_at": "2026-11-03T00:29:40Z"}
        ]);
        let releases = parse_github_releases(&payload).unwrap();
        assert_eq!(
            releases,
            vec![
                ReleaseEntry {
                    version: "1.104.7".to_string(),
                    published_at: Some("2026-11-12T22:56:51Z".to_string()),
                },
                ReleaseEntry {
                    version: "1.104.5".to_string(),
                    published_at: Some("2026-11-03T00:29:40Z".to_string()),
                },
            ]
        );
    }

    #[test]
    fn merge_version_catalog_caps_to_pkgs_latest_and_handles_partial_fallbacks() {
        let combined = merge_version_catalog(
            Ok("1.104.7".to_string()),
            Ok(vec![
                ReleaseEntry {
                    version: "1.104.8".to_string(),
                    published_at: Some("2026-11-20T00:00:00Z".to_string()),
                },
                ReleaseEntry {
                    version: "1.98.10".to_string(),
                    published_at: Some("2026-07-28T23:02:06Z".to_string()),
                },
                ReleaseEntry {
                    version: "1.104.7".to_string(),
                    published_at: Some("2026-11-12T22:56:51Z".to_string()),
                },
                ReleaseEntry {
                    version: "1.104.6".to_string(),
                    published_at: Some("2026-11-11T00:29:49Z".to_string()),
                },
            ]),
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(combined.latest, "1.104.7");
        assert_eq!(combined.source, "github+pkgs");
        assert_eq!(combined.warning, None);
        let ordered: Vec<&str> = combined
            .versions
            .iter()
            .map(|entry| entry.version.as_str())
            .collect();
        assert_eq!(ordered, vec!["1.104.7", "1.104.6", "1.98.10"]);

        let pkgs_only = merge_version_catalog(
            Ok("1.104.7".to_string()),
            Err("rate limited".to_string()),
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(pkgs_only.latest, "1.104.7");
        assert_eq!(pkgs_only.source, "pkgs");
        assert_eq!(pkgs_only.versions.len(), 1);
        assert!(pkgs_only.warning.as_deref().unwrap().contains("rate limited"));

        let github_only = merge_version_catalog(
            Err("timeout".to_string()),
            Ok(vec![ReleaseEntry {
                version: "1.104.6".to_string(),
                published_at: Some("2026-11-11T00:29:49Z".to_string()),
            }]),
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(github_only.latest, "1.104.6");
        assert_eq!(github_only.source, "github");
        assert!(github_only.warning.as_deref().unwrap().contains("timeout"));

        assert!(merge_version_catalog(
            Err("pkgs down".to_string()),
            Err("gh down".to_string()),
            1_800_000_000,
        )
        .is_err());
    }

    #[test]
    fn versions_catalog_caches_until_forced_refresh() {
        use std::sync::atomic::AtomicUsize;

        let manager = test_manager(false, None);
        let calls = AtomicUsize::new(0);
        let make = |version: &str| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(VersionCatalog {
                latest: version.to_string(),
                versions: vec![ReleaseEntry {
                    version: version.to_string(),
                    published_at: None,
                }],
                source: "pkgs".to_string(),
                warning: None,
                fetched_at: 100,
            })
        };
        let first = manager.versions_catalog_with(false, || make("1.104.6")).unwrap();
        let second = manager.versions_catalog_with(false, || make("1.104.7")).unwrap();
        assert_eq!(first.latest, "1.104.6");
        assert_eq!(second.latest, "1.104.6");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let refreshed = manager.versions_catalog_with(true, || make("1.104.7")).unwrap();
        assert_eq!(refreshed.latest, "1.104.7");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn fetch_versions_and_official_sha256_work_over_local_http() {
        let (pkgs_url, pkgs_srv) = serve_http_once(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"TarballsVersion\":\"1.104.7\",\"Tarballs\":{\"arm64\":\"tailscale_1.104.7_arm64.tgz\"}}",
        );
        let (gh_url, gh_srv) = serve_http_once(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n[{\"tag_name\":\"v1.104.7\",\"draft\":false,\"prerelease\":false,\"published_at\":\"2026-11-12T22:56:51Z\"},{\"tag_name\":\"v1.104.6\",\"draft\":false,\"prerelease\":false,\"published_at\":\"2026-11-11T00:29:49Z\"}]",
        );
        let catalog = fetch_versions_from_urls(&pkgs_url, &gh_url).unwrap();
        let pkgs_req = pkgs_srv.join().unwrap();
        let gh_req = gh_srv.join().unwrap();
        assert!(pkgs_req.contains("open-u60-tailscale/"), "{pkgs_req}");
        assert!(gh_req.contains("open-u60-tailscale/"), "{gh_req}");
        assert_eq!(catalog.latest, "1.104.7");
        assert_eq!(catalog.versions.len(), 2);
        assert_eq!(catalog.versions[1].version, "1.104.6");

        let digest = "d6bed2720310b328b861f943d7b4016c5358a9bad60575eb51e8143b79068484";
        let (sha_url, sha_srv) = serve_http_once(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nd6bed2720310b328b861f943d7b4016c5358a9bad60575eb51e8143b79068484\n",
        );
        assert_eq!(fetch_official_sha256_at(&sha_url).unwrap(), digest);
        assert!(sha_srv.join().unwrap().contains("open-u60-tailscale/"));
    }
}
