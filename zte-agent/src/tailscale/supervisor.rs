use std::fs::OpenOptions;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::{
    cli, config, daemon_status, installed, run_with_timeout, state_file_exists, unix_now,
    TailscaleManager, WifiRelay, CLI_TIMEOUT_SECS, RUN_DIR, SOCK, STATE_BAK, STATE_FILE,
    TAILSCALED_BIN,
};
use crate::ubus;

const LOG_FILE: &str = "/tmp/tailscaled.log";

const POLL_SECS: u64 = 30;
/// WAN-reconnect events closer together than this get one health check.
const WAN_DEBOUNCE: Duration = Duration::from_secs(30);
/// Brief settle window to coalesce rapid Wi-Fi relay route/IPv6 transitions.
const RELAY_SETTLE: Duration = Duration::from_secs(2);
/// Wait after a relay-triggered rebind/restun before escalating to a restart.
const RELAY_VERIFY_WAIT: Duration = Duration::from_secs(25);
const BACKOFF_MIN_SECS: u64 = 5;
const BACKOFF_MAX_SECS: u64 = 60;
const QUIESCE_TIMEOUT_SECS: u64 = 60;
/// Supervisor park while disabled or paused. Every writer of `running` /
/// `paused` notifies `wake_cv`, so this bound is only a safety net.
const IDLE_PARK_SECS: u64 = 60;
/// How often the monitor checks for an externally killed tailscaled between
/// status polls (the respawn backoff is 5 s, so nothing finer is visible).
const CHILD_POLL_SECS: u64 = 5;
const LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;
/// 2025-01-01 UTC — clock earlier than this means NTP hasn't synced yet.
const SANE_CLOCK_EPOCH: i64 = 1_735_689_600;

#[derive(Default)]
pub(super) struct RelayWatchState {
    generation: u64,
    child: Option<ChildIdentity>,
    saw_disconnect: bool,
    restart_request: Option<(u64, ChildIdentity)>,
    #[cfg(test)]
    stopped: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct ChildIdentity {
    pid: u32,
    instance: u64,
}

impl TailscaleManager {
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
        let Some(child) = *self
            .active_child
            .lock()
            .unwrap_or_else(|err| err.into_inner())
        else {
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
    pub(super) fn resume_supervisor(&self) {
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
    fn monitor_until_exit(&self, child: &mut std::process::Child, identity: ChildIdentity) -> bool {
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

    /// `tailscale debug rebind` + `restun`: cheap recovery for stale NAT
    /// mappings after suspend or WAN flap, without a daemon restart.
    fn nudge(&self) {
        let _ = cli(&["debug", "rebind"], 10);
        let _ = cli(&["debug", "restun"], 10);
    }

    // --- Lifecycle operations (called from handlers) ---

    pub(super) fn ensure_daemon_ready(self: &Arc<Self>, wait_secs: u64) -> Result<(), String> {
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

    /// Pause the supervisor and wait until it is parked with no child.
    /// Returns false if it fails to quiesce within the budget.
    pub(super) fn quiesce_supervisor(&self) -> bool {
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
        Ok(value) => value["connect_status"].as_str().is_some_and(wan_connected),
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

#[cfg(test)]
pub(super) fn test_manager(running: bool, pid: Option<u32>) -> Arc<TailscaleManager> {
    let manager = Arc::new(TailscaleManager::new());
    manager.running.store(running, Ordering::SeqCst);
    if let Some(pid) = pid {
        *manager.active_child.lock().unwrap() = Some(ChildIdentity { pid, instance: 1 });
        manager.next_child_instance.store(1, Ordering::SeqCst);
    }
    manager
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

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
                    let _ = worker_tx.send(if child.pid == 100 {
                        "restart-100"
                    } else {
                        "restart-other"
                    });
                },
            );
        });

        {
            let mut state = manager.relay_watch_lock.lock().unwrap();
            state.generation = 1;
            state.child = Some(ChildIdentity {
                pid: 100,
                instance: 1,
            });
            manager.relay_watch_cv.notify_all();
        }
        thread::sleep(Duration::from_millis(10));
        {
            let mut state = manager.relay_watch_lock.lock().unwrap();
            state.generation = 2;
            state.child = Some(ChildIdentity {
                pid: 100,
                instance: 1,
            });
            manager.relay_watch_cv.notify_all();
        }

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "nudge"
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "refresh"
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "restart-100"
        );
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
            state.child = Some(ChildIdentity {
                pid: 200,
                instance: 1,
            });
            if disconnected {
                state.saw_disconnect = true;
            }
            manager.relay_watch_cv.notify_all();
        };

        // 1. Initial relay connect nudges once.
        fire(1, false);
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "nudge-relay"
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "refresh"
        );

        // 2. Same-direction IPv6 update within debounce skips redundant nudge while healthy.
        fire(2, false);
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "refresh"
        );
        assert!(event_rx.recv_timeout(Duration::from_millis(80)).is_err());

        // 3. Fast AP-A -> AP-B handover (< settle) preserves saw_disconnect and still nudges.
        relay_up.store(false, Ordering::SeqCst);
        fire(3, true);
        thread::sleep(Duration::from_millis(8));
        relay_up.store(true, Ordering::SeqCst);
        fire(4, false);
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "nudge-relay"
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "refresh"
        );

        // 4. Disconnect with cellular off skips nudge cleanly.
        relay_up.store(false, Ordering::SeqCst);
        cellular_up.store(false, Ordering::SeqCst);
        fire(5, true);
        assert!(event_rx.recv_timeout(Duration::from_millis(120)).is_err());

        // 5. Disconnect with cellular on nudges immediately onto cellular.
        cellular_up.store(true, Ordering::SeqCst);
        fire(6, true);
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "nudge-cell"
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "refresh"
        );

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
            state.child = Some(ChildIdentity {
                pid: 300,
                instance: 1,
            });
            manager.relay_watch_cv.notify_all();
        }
        thread::sleep(Duration::from_millis(10));
        *manager.active_child.lock().unwrap() = Some(ChildIdentity {
            pid: 301,
            instance: 2,
        });
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

        let identity = ChildIdentity {
            pid: 400,
            instance: 1,
        };
        {
            let mut state = manager.relay_watch_lock.lock().unwrap();
            state.generation = 1;
            state.child = Some(identity);
            manager.relay_watch_cv.notify_all();
        }
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "nudge"
        );
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "refresh-1"
        );

        {
            let mut state = manager.relay_watch_lock.lock().unwrap();
            state.generation = 2;
            state.child = Some(identity);
            state.saw_disconnect = true;
            manager.relay_watch_cv.notify_all();
        }
        release_tx.send(()).unwrap();

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "nudge"
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            "refresh-2"
        );
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
                state.child = Some(ChildIdentity {
                    pid: 410,
                    instance: 1,
                });
                manager.relay_watch_cv.notify_all();
            }
            assert_eq!(
                event_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                "nudge"
            );
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
        let first = ChildIdentity {
            pid: 420,
            instance: 1,
        };
        let recycled = ChildIdentity {
            pid: 420,
            instance: 2,
        };
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
}
