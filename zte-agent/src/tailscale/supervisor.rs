use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Weak};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::netplane::{ExitUplink, Layout};
use super::{
    cli, command_output, copy_state_atomically, daemon_full_status_until, daemon_prefs_at_until,
    daemon_prefs_until, daemon_status, daemon_status_at_until, installed, run_with_timeout,
    state_file_exists, unix_now, HandlerError, Status, TailscaleManager, WifiRelay,
    CLI_TIMEOUT_SECS, RUN_DIR, SOCK, STATE_BAK, STATE_FILE, TAILSCALED_BIN, TAILSCALE_BIN,
};
use crate::netfx::ids;
use crate::netfx::perf::PerfFeature;
use crate::ubus;

const LOG_FILE: &str = "/tmp/tailscaled.log";
pub(super) const NETFILTER_OFF_MARKER: &str = "/data/tailscale/netfilter-off.verified";
const PREFLIGHT_SOCK: &str = "/tmp/tailscale/tailscaled-preflight.sock";
const TUN_DEVICE: &str = "/dev/net/tun";
const TUN_WAIT_SECS: u64 = 15;
const PREFLIGHT_WAIT_SECS: u64 = 15;
const PREFLIGHT_POLL_MS: u64 = 200;
const RESTORE_BARRIER_WAIT_SECS: u64 = 240;

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TunMode {
    Kernel,
    Userspace,
    /// Network-isolated userspace preflight/scrub (`CLONE_NEWNET` with loopback
    /// only): talks solely over the LocalAPI Unix socket and cannot reach DERP,
    /// peers, or host DNS while inspecting/updating persisted `STATE_FILE`.
    PreflightIsolated,
}

#[derive(Debug, PartialEq, Eq)]
enum UserspaceScrubOutcome {
    Clear,
    Failed(String),
    ChildUnconfirmed(String),
    Aborted,
}

#[derive(Debug, PartialEq, Eq)]
enum PreflightOutcome {
    Kernel,
    Userspace { reason: String, sticky: bool },
    /// A preflight child did not confirm exit; must NOT spawn a replacement
    /// production daemon or clear `userspace_daemon_live`.
    ChildUnconfirmed { reason: String },
    Aborted,
}

struct PromotionGuard<'a>(&'a TailscaleManager);
impl Drop for PromotionGuard<'_> {
    fn drop(&mut self) {
        self.0.kernel_promotion_pending.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MonitorExit {
    clean: bool,
    exited: bool,
}

impl TailscaleManager {
    pub(crate) fn set_relay(&self, relay: &Arc<WifiRelay>) {
        let _ = self.relay.set(Arc::downgrade(relay));
    }

    pub(crate) fn mark_network_restore_ready(&self) {
        self.network_restore_ready.store(true, Ordering::Release);
        self.wake_supervisor();
    }

    /// Startup recovery run before the HTTP listener starts: recovers any
    /// leftover kernel-TUN journal AND confirms zero orphaned `tailscaled`
    /// processes (including userspace forwarders when `enabled == false`)
    /// remain alive before permitting local loopback classification.
    pub(crate) fn recover_startup(&self) -> Result<(), String> {
        let journal = super::netplane::recover();
        let orphan = stop_all_tailscaled_and_confirm();
        journal?;
        orphan?;
        self.startup_orphan_cleared.store(true, Ordering::Release);
        Ok(())
    }

    fn relay_active(&self) -> bool {
        self.relay
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|relay| relay.active())
    }

    fn current_exit_uplink(&self) -> ExitUplink {
        if self.relay_active() {
            ExitUplink::Relay
        } else {
            ExitUplink::Cellular
        }
    }

    pub(super) fn ota_trial_pending(&self) -> bool {
        #[cfg(test)]
        if self.test_io.is_some() || self.test_ota_trial_pending.load(Ordering::Acquire) {
            return self.test_ota_trial_pending.load(Ordering::Acquire);
        }
        crate::ota::slot_change_pending()
    }

    pub(super) fn slot_change_blocked(&self) -> bool {
        self.slot_change_paused.load(Ordering::SeqCst) || self.ota_trial_pending()
    }

    pub(super) fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst) || self.slot_change_blocked()
    }

    pub(crate) fn is_updating(&self) -> bool {
        self.updating.load(Ordering::Acquire)
    }

    /// Quiesce Tailscale and verify the kernel-TUN data plane and journal are
    /// completely removed before switching to another OTA slot (including
    /// rollback or switching from Beta to an older Stable build). Mutually
    /// exclusive with Tailscale binary updates and enrollment via `prefs_lock` +
    /// `slot_change_paused` (never cleared by `resume_supervisor()`).
    pub(crate) fn before_slot_change<T>(
        &self,
        action: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        self.before_slot_change_with(
            Path::new(super::netplane::JOURNAL_PATH),
            || stop_all_tailscaled_and_confirm().and_then(|()| run_tailscaled_cleanup_checked()),
            |plane| plane.release(),
            super::netplane::recover,
            action,
        )
    }

    fn before_slot_change_with<T>(
        &self,
        journal_path: &Path,
        stop_and_cleanup: impl FnOnce() -> Result<(), String>,
        release_plane: impl FnOnce(&mut super::netplane::NetPlane) -> Result<(), String>,
        recover_tailscale: impl FnOnce() -> Result<(), String>,
        action: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        {
            let _prefs = self.prefs_lock.lock().unwrap();
            if self.updating.load(Ordering::Acquire) {
                return Err("tailscale binary update in progress".into());
            }
            if self.enrollment_active() {
                return Err("tailscale enrollment in progress".into());
            }
            if self.slot_change_blocked() {
                return Err("OTA slot change or health trial already in progress".into());
            }
            self.slot_change_paused.store(true, Ordering::SeqCst);
            self.wake_supervisor();
        }
        if !self.wait_quiesced() {
            self.slot_change_paused.store(false, Ordering::SeqCst);
            self.wake_supervisor();
            return Err("tailscale supervisor did not quiesce before slot change".into());
        }
        // Clean and verify daemon firewall + IPv4/IPv6 policy rules BEFORE
        // releasing the agent journal so a failed cleanup retains the same-boot
        // journal as a rollback block; `release()` persists the Clean DNS flush
        // marker before removing the journal so `recover()` flushes conntrack
        // before slot handoff.
        let flush_marker = super::netplane::dnat_flush_marker_path(journal_path);
        let cleanup = stop_and_cleanup()
            .and_then(|()| {
                let mut plane = self
                    .netplane
                    .lock()
                    .unwrap_or_else(|err| err.into_inner());
                release_plane(&mut plane)
            })
            .and_then(|()| recover_tailscale())
            .and_then(|()| {
                if journal_path
                    .try_exists()
                    .map_err(|e| format!("inspect tailscale journal: {e}"))?
                {
                    Err("tailscale network journal still present after cleanup".into())
                } else if flush_marker
                    .try_exists()
                    .map_err(|e| format!("inspect tailscale clean DNS flush marker: {e}"))?
                {
                    Err("tailscale clean DNS flush marker still present after cleanup".into())
                } else {
                    Ok(())
                }
            });
        if let Err(error) = cleanup {
            self.slot_change_paused.store(false, Ordering::SeqCst);
            self.wake_supervisor();
            return Err(format!("tailscale slot-change cleanup failed: {error}"));
        }
        match action() {
            Ok(value) => Ok(value),
            Err(error) => {
                self.slot_change_paused.store(false, Ordering::SeqCst);
                self.wake_supervisor();
                Err(error)
            }
        }
    }

    /// Non-blocking hook called by `WifiRelay` when its routes are installed,
    /// updated, or torn down. Wakes the startup gate immediately and schedules
    /// a fast rebind/restun when `tailscaled` is already running.
    pub(crate) fn relay_uplink_changed(&self) {
        self.clean_dns.uplink_changed();
        if self.kernel_tun_active.load(Ordering::Acquire) {
            self.mark_netplane_dirty();
        }
        self.wake_supervisor();
        if !self.running.load(Ordering::SeqCst) || self.is_paused() {
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
                || relay_mgr.nudge_and_reset_flows("tailscale relay switch"),
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
                if !mgr.running.load(Ordering::SeqCst) || mgr.is_paused() {
                    continue;
                }
                // Debounce bursts of WAN events
                if debounced(last_handled, Instant::now()) {
                    continue;
                }
                last_handled = Some(Instant::now());
                mgr.clean_dns.uplink_changed();
                if !mgr.relay_active() && mgr.kernel_tun_active.load(Ordering::Acquire) {
                    eprintln!(
                        "[tailscale] cellular WAN reconnect ({wan_status}) — rebind/restun and flush tailscale flows"
                    );
                    mgr.nudge_and_reset_flows("tailscale cellular reconnect");
                }
                eprintln!("[tailscale] WAN reconnect ({wan_status}): checking health in 20 s");
                // Give the data path time to settle, then check health (fresh
                // status — the cache may predate the flap)
                thread::sleep(Duration::from_secs(20));
                if !mgr.running.load(Ordering::SeqCst) || mgr.is_paused() {
                    continue;
                }
                mgr.refresh_status();
                if mgr.is_unhealthy() {
                    eprintln!("[tailscale] unhealthy after WAN reconnect — rebind/restun");
                    mgr.nudge();
                    thread::sleep(Duration::from_secs(30));
                    mgr.refresh_status();
                    if mgr.running.load(Ordering::SeqCst)
                        && !mgr.is_paused()
                        && mgr.is_unhealthy()
                    {
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
        #[cfg(test)]
        if self.test_io.is_some() {
            return;
        }
        if self
            .supervisor_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        if self
            .net_guard_registered
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let weak = Arc::downgrade(self);
            crate::net_guard::on_settled(move || {
                if let Some(mgr) = weak.upgrade() {
                    if mgr.kernel_tun_active.load(Ordering::Acquire)
                        || mgr.userspace_daemon_live.load(Ordering::Acquire)
                    {
                        mgr.mark_netplane_dirty();
                    }
                }
            });
        }
        let mgr = Arc::clone(self);
        thread::spawn(move || mgr.supervise());
    }

    /// Wake the supervisor from any park. Callers store their flag first;
    /// taking the lock orders that store before the waiter's predicate
    /// re-check (see `wake_lock`).
    pub(super) fn wake_supervisor(&self) {
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
            && !self.is_paused()
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
                && !self.is_paused()
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
                && !self.is_paused()
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
                && !self.is_paused()
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
                || self.is_paused()
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
                if !self.running.load(Ordering::SeqCst) || self.is_paused() {
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
                if !self.running.load(Ordering::SeqCst) || self.is_paused() {
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
                if !self.running.load(Ordering::SeqCst) || self.is_paused() {
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
                    if !self.running.load(Ordering::SeqCst) || self.is_paused() {
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
                    self.running.load(Ordering::SeqCst) && !self.is_paused()
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
        let mut force_userspace_reason: Option<String> = None;
        loop {
            if !self.running.load(Ordering::SeqCst) || self.is_paused() {
                force_userspace_reason = None;
                let trial_pending = self.ota_trial_pending();
                if trial_pending {
                    self.set_tun_degraded(Some(
                        "OTA health trial pending; deferring tailscaled until slot commit".into(),
                    ));
                } else {
                    self.set_tun_degraded(None);
                }
                // Park until enable/resume notifies (shorter poll while waiting
                // for an OTA health trial to commit and remove `pending`).
                self.supervisor_idle.store(true, Ordering::SeqCst);
                let park = if trial_pending {
                    Duration::from_secs(5)
                } else {
                    Duration::from_secs(IDLE_PARK_SECS)
                };
                let guard = self.wake_lock.lock().unwrap_or_else(|e| e.into_inner());
                drop(
                    self.wake_cv
                        .wait_timeout_while(guard, park, |_| {
                            !self.running.load(Ordering::SeqCst) || self.is_paused()
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
            if !self.running.load(Ordering::SeqCst) || self.is_paused() {
                continue;
            }

            // Adopt-by-replace: a previous agent instance (e.g. redeploy via
            // killall zte-agent) leaves its tailscaled orphaned; a second
            // instance would fight over the socket and state file.
            if let Err(error) = stop_all_tailscaled_and_confirm() {
                eprintln!("[tailscale] {error}");
                self.park_while_active(Duration::from_secs(backoff));
                backoff = (backoff * 2).min(BACKOFF_MAX_SECS);
                continue;
            }
            self.startup_orphan_cleared.store(true, Ordering::Release);

            // Last gate before spawn — an update may have paused us meanwhile
            if !self.running.load(Ordering::SeqCst) || self.is_paused() {
                continue;
            }

            rotate_log_if_big();
            let _ = std::fs::create_dir_all(RUN_DIR);
            let stopped = self.stopped_generation();

            let mut promotion_guard: Option<PromotionGuard<'_>> = None;
            let mode = if let Some(reason) = force_userspace_reason.clone() {
                self.set_tun_degraded(Some(reason));
                TunMode::Userspace
            } else {
                match self.prepare_tun_mode() {
                    PreflightOutcome::Kernel => {
                        // Serialize the final promotion decision with enrollment
                        // admission and preference writers, and keep promotion
                        // reserved via `kernel_promotion_pending` until `active_child`
                        // is published (or activation fails).
                        let _prefs = self.prefs_lock.lock().unwrap();
                        let enrolled = self.config.lock().unwrap().enrolled;
                        if !self.running.load(Ordering::SeqCst) || self.is_paused()
                        {
                            continue;
                        }
                        if !enrolled || self.enrollment_active() {
                            self.set_tun_degraded(Some(
                                "enrollment became active during preflight; staying in userspace mode"
                                    .into(),
                            ));
                            TunMode::Userspace
                        } else if crate::ota::slot_change_pending() {
                            self.set_tun_degraded(Some(
                                "OTA trial pending; deferring kernel TUN until slot commit".into(),
                            ));
                            TunMode::Userspace
                        } else if let Err(reason) = verify_no_legacy_policy_rules() {
                            self.set_tun_degraded(Some(reason));
                            TunMode::Userspace
                        } else {
                            // Start the dual-protocol Clean DNS resolver (`127.0.0.54:53`)
                            // and install the closed u60_tail + 5130/5131 guard BEFORE
                            // spawning `tailscaled --tun=tailscale0` so tailscale0 can
                            // never exist without forwarding, CGNAT, or DNS isolation.
                            self.sync_clean_dns_mode();
                            let clean_dns_binding = self.clean_dns.ensure_running();
                            match clean_dns_binding {
                                Ok(binding) => match self.stage_closed_netplane_guard(binding.dnat_port) {
                                    Ok(()) => {
                                        self.kernel_promotion_pending.store(true, Ordering::Release);
                                        promotion_guard = Some(PromotionGuard(self));
                                        self.set_tun_degraded(None);
                                        TunMode::Kernel
                                    }
                                    Err(error) => {
                                        self.clean_dns.stop();
                                        let reason = format!("kernel TUN guard setup failed: {error}");
                                        eprintln!(
                                            "[tailscale] {reason}; falling back to userspace"
                                        );
                                        force_userspace_reason = Some(reason.clone());
                                        self.set_tun_degraded(Some(reason));
                                        TunMode::Userspace
                                    }
                                },
                                Err(error) => {
                                    drop(_prefs);
                                    let reason = format!("clean DNS startup failed: {error}");
                                    eprintln!(
                                        "[tailscale] {reason}; refusing to start unisolated tailscaled"
                                    );
                                    self.set_tun_degraded(Some(reason));
                                    self.park_while_active(Duration::from_secs(backoff));
                                    backoff = (backoff * 2).min(BACKOFF_MAX_SECS);
                                    continue;
                                }
                            }
                        }
                    }
                    PreflightOutcome::Userspace { reason, sticky } => {
                        eprintln!("[tailscale] staying in userspace mode: {reason}");
                        if sticky {
                            force_userspace_reason = Some(reason.clone());
                        }
                        self.set_tun_degraded(Some(reason));
                        TunMode::Userspace
                    }
                    PreflightOutcome::ChildUnconfirmed { reason } => {
                        eprintln!("[tailscale] {reason}; refusing to spawn replacement daemon");
                        self.set_tun_degraded(Some(reason));
                        self.park_while_active(Duration::from_secs(backoff));
                        backoff = (backoff * 2).min(BACKOFF_MAX_SECS);
                        continue;
                    }
                    PreflightOutcome::Aborted => continue,
                }
            };

            if mode == TunMode::Userspace {
                // Cold-start gate: before spawning a network-facing userspace
                // daemon with a persisted `STATE_FILE`, ensure any saved exit
                // node routes (`0.0.0.0/0`, `::/0`) are cleared and confirmed
                // via a second isolated cold-load readback from disk.
                match self.ensure_userspace_exit_node_cleared() {
                    UserspaceScrubOutcome::Clear => {}
                    UserspaceScrubOutcome::Aborted => continue,
                    UserspaceScrubOutcome::Failed(reason)
                    | UserspaceScrubOutcome::ChildUnconfirmed(reason) => {
                        eprintln!("[tailscale] {reason}; refusing to start unisolated userspace daemon");
                        self.set_tun_degraded(Some(reason));
                        self.park_while_active(Duration::from_secs(backoff));
                        backoff = (backoff * 2).min(BACKOFF_MAX_SECS);
                        continue;
                    }
                }
                // Protect PeerAPI `/dns-query` for EVERY reachable child,
                // including userspace mode: bind Clean DNS directly on
                // `127.0.0.54:53` (no `u60_tail` DNAT table exists in userspace)
                // and mount-isolate the child before spawning.
                self.sync_clean_dns_mode();
                match self.clean_dns.ensure_running() {
                    Ok(binding) if binding.dnat_port.is_none() => {
                        // Also confirm no stale `u60_tail` `dns_out` fallback
                        // redirect remains active (e.g. after a kernel teardown
                        // whose policy-rule cleanup failed and retained the table).
                        // Bind the result BEFORE `if let` so the `netplane`
                        // MutexGuard is dropped before `park_while_active()`.
                        let dnat_check = self
                            .netplane
                            .lock()
                            .unwrap_or_else(|err| err.into_inner())
                            .ensure_clean_dns_dnat(None);
                        if let Err(error) = dnat_check {
                            self.clean_dns.stop();
                            let reason = format!(
                                "cannot start userspace clean DNS on port 53 while fallback DNAT remains active: {error}"
                            );
                            eprintln!("[tailscale] {reason}; refusing to start unprotected userspace daemon");
                            self.set_tun_degraded(Some(reason));
                            self.park_while_active(Duration::from_secs(backoff));
                            backoff = (backoff * 2).min(BACKOFF_MAX_SECS);
                            continue;
                        }
                    }
                    Ok(binding) => {
                        self.clean_dns.stop();
                        let reason = format!(
                            "clean DNS requires fallback DNAT port {:?} unavailable in userspace mode",
                            binding.dnat_port
                        );
                        eprintln!("[tailscale] {reason}; refusing to start unprotected userspace daemon");
                        self.set_tun_degraded(Some(reason));
                        self.park_while_active(Duration::from_secs(backoff));
                        backoff = (backoff * 2).min(BACKOFF_MAX_SECS);
                        continue;
                    }
                    Err(error) => {
                        let reason = format!("clean DNS startup failed for userspace mode: {error}");
                        eprintln!("[tailscale] {reason}; refusing to start unprotected userspace daemon");
                        self.set_tun_degraded(Some(reason));
                        self.park_while_active(Duration::from_secs(backoff));
                        backoff = (backoff * 2).min(BACKOFF_MAX_SECS);
                        continue;
                    }
                }
                // Mark userspace forwarder live BEFORE spawn; cleared only
                // after confirmed child exit via `wait()`.
                self.userspace_daemon_live.store(true, Ordering::Release);
            }
            let spawned = self.spawn_tailscaled_on(mode, SOCK).map_err(|e| e.to_string());

            match spawned {
                Ok(mut child) => {
                    eprintln!(
                        "[tailscale] tailscaled started (pid {}, mode {:?})",
                        child.id(),
                        mode
                    );
                    let instance = self.next_child_instance.fetch_add(1, Ordering::SeqCst) + 1;
                    let identity = ChildIdentity {
                        pid: child.id(),
                        instance,
                    };

                    let mut immediate_respawn = false;
                    let mut monitor = true;
                    let mut exited = false;
                    if mode == TunMode::Kernel {
                        // Keep `active_child` unpublished and `kernel_promotion_pending`
                        // set until initial `NetfilterMode == Some(0)` readback and
                        // `NetPlane` confirmation succeed.
                        let activated = self.activate_kernel_tun(&mut child);
                        match activated {
                            Ok(()) => {
                                *self.active_child.lock().unwrap() = Some(identity);
                                drop(promotion_guard.take());
                                self.apply_prefs_when_ready();
                            }
                            Err(KernelActivationError::Aborted) => {
                                exited = self.graceful_stop(&mut child);
                                drop(promotion_guard.take());
                                monitor = false;
                                immediate_respawn = true;
                            }
                            Err(KernelActivationError::NeedsNetfilterPreflight(reason)) => {
                                eprintln!("[tailscale] {reason}; re-verifying netfilter-mode=off in userspace");
                                self.clear_netfilter_off_marker();
                                exited = self.graceful_stop(&mut child);
                                drop(promotion_guard.take());
                                if exited {
                                    let _ = run_tailscaled_cleanup_checked();
                                }
                                monitor = false;
                                immediate_respawn = true;
                            }
                            Err(KernelActivationError::DegradeToUserspace(reason)) => {
                                eprintln!("[tailscale] kernel TUN activation failed ({reason}); falling back to userspace");
                                exited = self.graceful_stop(&mut child);
                                drop(promotion_guard.take());
                                force_userspace_reason = Some(reason.clone());
                                self.set_tun_degraded(Some(reason));
                                monitor = false;
                                immediate_respawn = true;
                            }
                        }
                    } else {
                        drop(promotion_guard.take());
                        if let Err(error) = self.verify_clean_dns_isolation(child.id()) {
                            eprintln!(
                                "[tailscale] userspace clean DNS mount verification failed: {error}"
                            );
                            exited = self.graceful_stop(&mut child);
                            self.set_tun_degraded(Some(format!(
                                "clean DNS mount namespace verification failed: {error}"
                            )));
                            monitor = false;
                        } else {
                            *self.active_child.lock().unwrap() = Some(identity);
                            self.apply_prefs_when_ready();
                        }
                    }

                    let clean_exit = if monitor {
                        let outcome = self.monitor_until_exit(
                            &mut child,
                            identity,
                            stopped,
                            mode,
                            force_userspace_reason.is_none(),
                        );
                        exited = outcome.exited;
                        outcome.clean
                    } else {
                        immediate_respawn && exited
                    };

                    if !exited {
                        exited = self.graceful_stop(&mut child);
                    }
                    // Tear down kernel-TUN data plane ONLY after tailscaled exit
                    // is confirmed so tailscale0 is never exposed unguarded.
                    if mode == TunMode::Kernel {
                        if exited {
                            self.deactivate_kernel_tun();
                            *self.active_child.lock().unwrap() = None;
                        } else {
                            self.kernel_tun_active.store(false, Ordering::Release);
                            eprintln!("[tailscale] tailscaled exit unconfirmed; keeping u60_tail guards in place");
                        }
                    } else if exited {
                        *self
                            .clean_dns_mount_state
                            .lock()
                            .unwrap_or_else(|err| err.into_inner()) = Ok(false);
                        self.clean_dns.stop();
                        self.userspace_daemon_live.store(false, Ordering::Release);
                        *self.active_child.lock().unwrap() = None;
                    } else {
                        eprintln!("[tailscale] userspace tailscaled exit unconfirmed; keeping loopback classification fail-closed");
                    }
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
                    eprintln!("[tailscale] tailscaled exited (confirmed={exited})");
                    if immediate_respawn && exited {
                        continue;
                    }
                }
                Err(e) => {
                    if mode == TunMode::Kernel {
                        self.deactivate_kernel_tun();
                    } else {
                        *self
                            .clean_dns_mount_state
                            .lock()
                            .unwrap_or_else(|err| err.into_inner()) = Ok(false);
                        self.clean_dns.stop();
                        self.userspace_daemon_live.store(false, Ordering::Release);
                    }
                    eprintln!("[tailscale] spawn failed: {e}");
                }
            }

            if !self.running.load(Ordering::SeqCst) || self.is_paused() {
                continue;
            }
            // Crash or spawn failure — back off before respawn
            self.park_while_active(Duration::from_secs(backoff));
            backoff = (backoff * 2).min(BACKOFF_MAX_SECS);
        }
    }

    fn wait_for_network_restore_ready(&self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(RESTORE_BARRIER_WAIT_SECS);
        while !self.network_restore_ready.load(Ordering::Acquire) {
            if !self.running.load(Ordering::SeqCst) || self.is_paused() {
                return false;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let guard = self.wake_lock.lock().unwrap_or_else(|e| e.into_inner());
            if self.network_restore_ready.load(Ordering::Acquire)
                || !self.running.load(Ordering::SeqCst)
                || self.is_paused()
            {
                break;
            }
            drop(
                self.wake_cv
                    .wait_timeout(guard, remaining.min(Duration::from_secs(1)))
                    .unwrap_or_else(|e| e.into_inner()),
            );
        }
        self.network_restore_ready.load(Ordering::Acquire)
    }

    fn prepare_tun_mode(&self) -> PreflightOutcome {
        let cfg = self.config.lock().unwrap().clone();
        if !cfg.enrolled || self.enrollment_active() {
            return PreflightOutcome::Userspace {
                reason: "keeping unenrolled/enrolling node in userspace mode".into(),
                sticky: false,
            };
        }
        if crate::ota::slot_change_pending() {
            return PreflightOutcome::Userspace {
                reason: "OTA trial pending; deferring kernel TUN until slot commit".into(),
                sticky: false,
            };
        }
        if !self.wait_for_network_restore_ready() {
            if !self.running.load(Ordering::SeqCst) || self.is_paused() {
                return PreflightOutcome::Aborted;
            }
            return PreflightOutcome::Userspace {
                reason: "waiting for startup network policy restore before enabling kernel TUN"
                    .into(),
                sticky: false,
            };
        }
        if let Err(reason) = verify_no_legacy_policy_rules() {
            return PreflightOutcome::Userspace {
                reason,
                sticky: false,
            };
        }

        let marker = self.device_path(NETFILTER_OFF_MARKER);
        let state = self.device_path(STATE_FILE);
        let preflight_sock = Path::new(PREFLIGHT_SOCK);
        let _ = std::fs::remove_file(preflight_sock);

        let outcome = prepare_tun_mode_with(
            || probe_tun_device(Path::new(TUN_DEVICE)),
            || state.exists(),
            || marker_matches_state(&marker, &state),
            || write_bound_netfilter_off_marker(&marker, &state),
            || {
                self.userspace_daemon_live.store(true, Ordering::Release);
                match self.spawn_tailscaled_on(TunMode::PreflightIsolated, PREFLIGHT_SOCK) {
                    Ok(child) => Ok(child),
                    Err(e) => {
                        self.userspace_daemon_live.store(false, Ordering::Release);
                        Err(e.to_string())
                    }
                }
            },
            |child| self.wait_preflight_ready(child, preflight_sock),
            || {
                daemon_status_at_until::<Status>(
                    preflight_sock,
                    Instant::now() + Duration::from_secs(5),
                )
                .ok()
                .map(|s| s.backend_state)
            },
            || {
                daemon_prefs_at_until(preflight_sock, Instant::now() + Duration::from_secs(5))
                    .and_then(|p| p.netfilter_mode)
            },
            || {
                cli_on(
                    PREFLIGHT_SOCK,
                    &["set", "--netfilter-mode=off", "--advertise-exit-node=false"],
                    CLI_TIMEOUT_SECS,
                )
                .map(|_| ())
            },
            |mut child| {
                let exited = self.graceful_stop(&mut child);
                if exited {
                    self.userspace_daemon_live.store(false, Ordering::Release);
                }
                let _ = std::fs::remove_file(preflight_sock);
                exited
            },
            run_tailscaled_cleanup_checked,
        );
        let _ = std::fs::remove_file(preflight_sock);
        outcome
    }

    fn ensure_userspace_exit_node_cleared(&self) -> UserspaceScrubOutcome {
        let state = self.device_path(STATE_FILE);
        if !state.exists() {
            return UserspaceScrubOutcome::Clear;
        }
        if let Some(fp) = state_profile_fingerprint(&state) {
            if self
                .exit_cleared_fingerprint
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_deref()
                == Some(fp.as_str())
            {
                return UserspaceScrubOutcome::Clear;
            }
        }
        let preflight_sock = Path::new(PREFLIGHT_SOCK);
        let _ = std::fs::remove_file(preflight_sock);
        let outcome = ensure_userspace_exit_node_cleared_with(
            || {
                self.userspace_daemon_live.store(true, Ordering::Release);
                match self.spawn_tailscaled_on(TunMode::PreflightIsolated, PREFLIGHT_SOCK) {
                    Ok(child) => Ok(child),
                    Err(e) => {
                        self.userspace_daemon_live.store(false, Ordering::Release);
                        Err(e.to_string())
                    }
                }
            },
            |child| self.wait_preflight_ready(child, preflight_sock),
            || {
                daemon_prefs_at_until(preflight_sock, Instant::now() + Duration::from_secs(5))
                    .map(|p| p.advertise_routes)
            },
            || {
                cli_on(
                    PREFLIGHT_SOCK,
                    &["set", "--advertise-exit-node=false"],
                    CLI_TIMEOUT_SECS,
                )
                .map(|_| ())
            },
            |mut child| {
                let exited = self.graceful_stop(&mut child);
                if exited {
                    self.userspace_daemon_live.store(false, Ordering::Release);
                }
                let _ = std::fs::remove_file(preflight_sock);
                exited
            },
        );
        let _ = std::fs::remove_file(preflight_sock);
        if outcome == UserspaceScrubOutcome::Clear {
            if let Some(fp) = state_profile_fingerprint(&state) {
                *self
                    .exit_cleared_fingerprint
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(fp);
            }
        }
        outcome
    }

    fn wait_preflight_ready(&self, child: &mut Child, sock: &Path) -> PreflightWait {
        let deadline = Instant::now() + Duration::from_secs(PREFLIGHT_WAIT_SECS);
        let max_polls = ((PREFLIGHT_WAIT_SECS * 1000) / PREFLIGHT_POLL_MS).max(1) as usize;
        wait_preflight_ready_with(
            max_polls,
            || !self.running.load(Ordering::SeqCst) || self.is_paused(),
            || matches!(child.try_wait(), Ok(Some(_)) | Err(_)),
            || {
                let step_deadline = (Instant::now() + Duration::from_secs(2)).min(deadline);
                daemon_status_at_until::<Status>(sock, step_deadline)
                    .ok()
                    .map(|s| s.backend_state)
            },
            || {
                if Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(PREFLIGHT_POLL_MS));
                }
            },
            || Instant::now() >= deadline,
        )
    }

    fn stage_closed_netplane_guard(&self, clean_dns_dnat_port: Option<u16>) -> Result<(), String> {
        let uplink = self.current_exit_uplink();
        let mut plane = self
            .netplane
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        plane.stage_closed_guard(uplink, clean_dns_dnat_port)?;
        plane.ensure_clean_dns_dnat(clean_dns_dnat_port)
    }

    fn verify_clean_dns_isolation(&self, pid: u32) -> Result<(), String> {
        let res = super::clean_dns::verify_pid_mount_isolation(
            pid,
            Path::new(super::clean_dns::RESOLV_DIR),
        );
        let mut guard = self
            .clean_dns_mount_state
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        match &res {
            Ok(()) => *guard = Ok(true),
            Err(err) => *guard = Err(err.clone()),
        }
        res
    }

    fn activate_kernel_tun(&self, child: &mut Child) -> Result<(), KernelActivationError> {
        let tun_sysfs = format!("/sys/class/net/{}", ids::TAILSCALE_IFACE);
        for _ in 0..TUN_WAIT_SECS {
            if !self.running.load(Ordering::SeqCst) || self.is_paused() {
                return Err(KernelActivationError::Aborted);
            }
            if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
                return Err(KernelActivationError::DegradeToUserspace(
                    "tailscaled exited before tailscale0 became ready".into(),
                ));
            }
            if Path::new(&tun_sysfs).exists() {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        if !Path::new(&tun_sysfs).exists() {
            return Err(KernelActivationError::DegradeToUserspace(
                "tailscale0 interface did not appear".into(),
            ));
        }
        // Require a successful LocalAPI readback proving NetfilterMode == 0
        // BEFORE apply_prefs_when_ready() runs.
        let mut observed_mode = None;
        for _ in 0..PREFLIGHT_WAIT_SECS {
            if !self.running.load(Ordering::SeqCst) || self.is_paused() {
                return Err(KernelActivationError::Aborted);
            }
            if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
                return Err(KernelActivationError::DegradeToUserspace(
                    "tailscaled exited before LocalAPI readback".into(),
                ));
            }
            if let Some(prefs) = daemon_prefs_until(Instant::now() + Duration::from_secs(2)) {
                observed_mode = Some(prefs.netfilter_mode);
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        match observed_mode {
            Some(Some(0)) => {}
            Some(other) => {
                return Err(KernelActivationError::NeedsNetfilterPreflight(format!(
                    "expected netfilter-mode=off (0), observed {other:?}"
                )));
            }
            None => {
                return Err(KernelActivationError::DegradeToUserspace(
                    "could not read back netfilter-mode from kernel tailscaled".into(),
                ));
            }
        }
        if !self.clean_dns.is_running() {
            return Err(KernelActivationError::DegradeToUserspace(
                "clean DNS resolver is not running".into(),
            ));
        }
        if let Err(error) = self.verify_clean_dns_isolation(child.id()) {
            return Err(KernelActivationError::DegradeToUserspace(format!(
                "clean DNS mount namespace verification failed: {error}"
            )));
        }
        let capacity_warning = match self.sync_netplane_from_daemon(true) {
            Ok(warning) => warning,
            Err(error) => {
                return Err(KernelActivationError::DegradeToUserspace(format!(
                    "kernel TUN data plane setup failed: {error}"
                )));
            }
        };
        let confirmed = self
            .netplane
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .is_confirmed();
        if !confirmed {
            return Err(KernelActivationError::DegradeToUserspace(
                "kernel TUN data plane was not confirmed after setup".into(),
            ));
        }
        *self
            .exit_cleared_fingerprint
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = None;
        self.set_tun_degraded(capacity_warning);
        self.perf
            .report(self.perf.set_active(PerfFeature::Tailscale, true));
        self.kernel_tun_active.store(true, Ordering::Release);
        self.sync_mihomo_exit_state();
        Ok(())
    }

    fn deactivate_kernel_tun(&self) {
        self.deactivate_kernel_tun_with(cleanup_and_verify_ts_policy_rules);
    }

    fn deactivate_kernel_tun_with(&self, clean_policy_rules: impl FnOnce() -> Result<(), String>) {
        self.kernel_tun_active.store(false, Ordering::Release);
        *self
            .exit_cleared_fingerprint
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = None;
        *self
            .clean_dns_mount_state
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = Ok(false);
        self.clean_dns.stop();
        self.sync_mihomo_exit_state();
        self.perf
            .report(self.perf.set_active(PerfFeature::Tailscale, false));
        // Forced SIGKILL exit skips tailscaled's Close() and can leave daemon
        // IPv4/IPv6 policy rules (5210/5230/5250/5270) installed. Verify and
        // clean exact owned remnants BEFORE retiring the same-boot journal; if
        // cleanup fails, retain the journal so same-boot rollback stays blocked.
        if let Err(error) = clean_policy_rules() {
            eprintln!(
                "[tailscale] residual policy-rule cleanup failed ({error}); retaining netplane journal"
            );
            return;
        }
        self.release_netplane();
    }

    /// Synchronize `NetPlane` from `/localapi/v0/status`.
    /// - When `require_full_status` is true (initial kernel activation), any
    ///   LocalAPI failure fails activation rather than falling back to a
    ///   Quad100-only layout.
    /// - During steady-state reconciliation, a transient LocalAPI failure keeps
    ///   the previously confirmed layout intact and returns `Err` so callers
    ///   surface diagnostics without withdrawing approved routes.
    fn sync_netplane_from_daemon(&self, require_full_status: bool) -> Result<Option<String>, String> {
        let mut cfg = self.config.lock().unwrap().clone();
        if !self.clean_dns_verified() {
            cfg.advertise_exit_node = false;
        }
        let uplink = self.current_exit_uplink();
        let deadline = Instant::now() + Duration::from_secs(5);
        let full = match daemon_full_status_until(deadline) {
            Ok(full) => full,
            Err(error) => {
                return Err(if require_full_status {
                    format!("full LocalAPI status unavailable during activation: {error}")
                } else {
                    format!("full LocalAPI status unavailable: {error}")
                });
            }
        };
        let (layout, warning) = Layout::from_full_status(&cfg, &full, uplink);
        let layout = layout.with_clean_dns_dnat(self.clean_dns.dnat_port());
        let mut plane = self
            .netplane
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        plane.sync(layout)?;
        Ok(warning)
    }

    fn reconcile_netplane(&self, cursor: &mut crate::net_guard::Cursor) {
        match self.sync_netplane_from_daemon(false) {
            Ok(warning) => self.set_tun_degraded(warning),
            Err(error) => {
                // Even if LocalAPI is transiently unavailable, immediately apply
                // locally known revocations (disabled exit node, removed subnets)
                // and uplink switches before running reconciliation.
                let mut cfg = self.config.lock().unwrap().clone();
                if !self.clean_dns_verified() {
                    cfg.advertise_exit_node = false;
                }
                let uplink = self.current_exit_uplink();
                if let Err(local_err) = self
                    .netplane
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .enforce_local_config(&cfg, uplink)
                {
                    eprintln!("[tailscale] local netplane tightening failed: {local_err}");
                }
                eprintln!("[tailscale] netplane sync failed: {error}");
                self.set_tun_degraded(Some(error));
            }
        }
        if cursor.due() {
            let result = self
                .netplane
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .reconcile();
            cursor.after(&result);
            let _ = crate::net_guard::report("tailscale", result);
        }
        self.sync_mihomo_exit_state();
    }

    /// Immediately withdraw Exit Node forwarding and Mihomo `tailscale0` TPROXY
    /// locally without waiting on any LocalAPI or CLI control calls.
    fn withdraw_exit_locally(&self) {
        let mut cfg = self.config.lock().unwrap().clone();
        cfg.advertise_exit_node = false;
        let uplink = self.current_exit_uplink();
        if let Err(local_err) = self
            .netplane
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .enforce_local_config(&cfg, uplink)
        {
            eprintln!("[tailscale] local netplane exit withdrawal failed: {local_err}");
        }
        self.sync_mihomo_exit_state();
    }

    fn release_netplane(&self) {
        let mut plane = self
            .netplane
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Err(error) = plane.release() {
            eprintln!("[tailscale] netplane release failed: {error}");
        }
    }

    fn spawn_tailscaled_on(&self, mode: TunMode, sock: &str) -> std::io::Result<std::process::Child> {
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
        let tun_arg = match mode {
            TunMode::Kernel => format!("--tun={}", ids::TAILSCALE_IFACE),
            TunMode::Userspace | TunMode::PreflightIsolated => {
                "--tun=userspace-networking".to_string()
            }
        };
        let mut cmd = Command::new(TAILSCALED_BIN);
        cmd.args([
            &tun_arg,
            &format!("--state={STATE_FILE}"),
            &format!("--statedir={RUN_DIR}"),
            &format!("--socket={sock}"),
            "--port=41641",
            "--no-logs-no-support",
        ])
        .env("GOMEMLIMIT", "192MiB")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
        match mode {
            TunMode::Kernel | TunMode::Userspace => {
                super::clean_dns::apply_mount_namespace(
                    &mut cmd,
                    Path::new(super::clean_dns::RESOLV_DIR),
                )
                .map_err(std::io::Error::other)?;
            }
            TunMode::PreflightIsolated => {
                apply_isolated_net_namespace(&mut cmd)?;
            }
        }
        cmd.spawn()
    }

    /// Locally checks mount namespace isolation, Clean DNS liveness, and (for
    /// kernel mode) fallback DNAT delivery with ZERO LocalAPI or CLI calls.
    /// If Clean DNS delivery cannot be guaranteed for this reachable child,
    /// withdraws local Exit forwarding (kernel mode) and stops the child
    /// immediately so its PeerAPI `/dns-query` closes right away.
    fn enforce_child_dns_isolation(
        &self,
        child: &mut std::process::Child,
        mode: TunMode,
    ) -> Option<MonitorExit> {
        let pid = child.id();
        match check_child_dns_isolation_with(
            mode,
            || self.verify_clean_dns_isolation(pid),
            || self.clean_dns.is_running(),
            || self.clean_dns.ensure_running().map(|b| b.dnat_port),
            || self.clean_dns.dnat_port(),
            |expected_port| {
                self.netplane
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .ensure_clean_dns_dnat(expected_port)
            },
        ) {
            ChildIsolationAction::Healthy => None,
            ChildIsolationAction::StopChild { clean, reason } => {
                eprintln!("[tailscale] {reason}; stopping {mode:?} tailscaled immediately");
                if mode == TunMode::Kernel {
                    self.withdraw_exit_locally();
                }
                let exited = self.graceful_stop(child);
                Some(MonitorExit {
                    clean: clean && exited,
                    exited,
                })
            }
        }
    }

    /// Poll status while the child is alive. Detects suspend/resume via
    /// wall-clock jumps and nudges the daemon. Reports both whether the exit
    /// was requested and whether process reaping was actually confirmed.
    fn monitor_until_exit(
        &self,
        child: &mut std::process::Child,
        identity: ChildIdentity,
        stopped: u64,
        mode: TunMode,
        can_promote_to_kernel: bool,
    ) -> MonitorExit {
        let mut last_tick = unix_now();
        let mut bad_cycles = 0u32;
        let mut needs_login_cycles = 0u32;
        let mut guard_cursor = crate::net_guard::Cursor::default();
        loop {
            // Requested stop?
            if !self.running.load(Ordering::SeqCst) || self.is_paused() {
                let exited = self.graceful_stop(child);
                return MonitorExit { clean: exited, exited };
            }
            if self.take_relay_restart(identity) {
                eprintln!("[tailscale] restarting tailscaled on verified relay health check");
                let exited = self.graceful_stop(child);
                return MonitorExit { clean: false, exited };
            }
            match child.try_wait() {
                Ok(Some(_)) => return MonitorExit { clean: false, exited: true },
                Ok(None) => {}
                Err(_) => {
                    let exited = self.graceful_stop(child);
                    return MonitorExit { clean: false, exited };
                }
            }

            // Enforce local Clean DNS mount, resolver, and fallback DNAT
            // delivery BEFORE any blocking control work (`nudge`, 8s LocalAPI
            // `refresh_status`, or 20s CLI `apply_current_prefs`) so a
            // compromised child is withdrawn and stopped immediately and stale
            // mount state can never reassert exit advertisement.
            if let Some(exit) = self.enforce_child_dns_isolation(child, mode) {
                return exit;
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
            if self.prefs_pending.load(Ordering::Relaxed)
                && payload["backend_state"].as_str() == Some("Running")
            {
                if let Err(error) = self.apply_current_prefs() {
                    eprintln!("[tailscale] apply pending preferences: {error}");
                } else {
                    self.refresh_status();
                }
            }

            if mode == TunMode::Kernel {
                self.netplane_dirty.store(false, Ordering::Release);
                self.reconcile_netplane(&mut guard_cursor);
                if let Some(exit) = self.enforce_child_dns_isolation(child, mode) {
                    return exit;
                }
            } else if can_promote_to_kernel
                && cfg.enrolled
                && !self.enrollment_active()
                && !crate::ota::slot_change_pending()
                && self.network_restore_ready.load(Ordering::Acquire)
                && state_file_exists()
                && payload["backend_state"].as_str() == Some("Running")
                && probe_tun_device(Path::new(TUN_DEVICE)).is_ok()
                && verify_no_legacy_policy_rules().is_ok()
                && daemon_prefs_until(Instant::now() + Duration::from_secs(5))
                    .and_then(|prefs| prefs.netfilter_mode)
                    == Some(0)
            {
                // Do not certify an in-memory pref directly: stop userspace and
                // let the next supervisor cycle run cold-load preflight verification.
                eprintln!("[tailscale] enrolled node ready — verifying durable netfilter-mode=off before promoting to kernel TUN");
                let exited = self.graceful_stop(child);
                return MonitorExit { clean: exited, exited };
            }

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
                        let exited = self.graceful_stop(child);
                        return MonitorExit { clean: false, exited };
                    }
                }
                // Backend Stopped (WantRunning=false, e.g. after `down`) while
                // the user wants it enabled — self-heal with a full-pref `up`.
                // Makes POST /enable eventually consistent regardless of the
                // daemon-startup races. Never runs during interactive login.
                "paused" if cfg.enabled && !self.enrollment_active() => {
                    eprintln!("[tailscale] backend Stopped while enabled — bringing it up");
                    let Some((generation, result)) =
                        self.run_self_heal_up(stopped, &["--timeout=30s"], Duration::from_secs(40))
                    else {
                        continue;
                    };
                    if let Err(e) = result {
                        eprintln!("[tailscale] up after Stopped: {e}");
                    }
                    if let Err(e) = self.finish_up(generation) {
                        eprintln!("[tailscale] reapply preferences after up: {e}");
                    }
                    self.refresh_status();
                }
                // Spurious logout with an enrolled node: one restore attempt
                // from the post-enrollment state backup (report §4.6 ladder).
                "needs_login" if cfg.enrolled => {
                    needs_login_cycles += 1;
                    if needs_login_cycles >= 3 {
                        let mut stop_exited = false;
                        if self.restore_identity_if_current(identity, stopped, || {
                            stop_exited = self.graceful_stop(child);
                            stop_exited
                        }) {
                            return MonitorExit {
                                clean: false,
                                exited: stop_exited,
                            };
                        }
                    }
                }
                _ => {
                    bad_cycles = 0;
                }
            }

            // Park until the next status poll. Disable/update/kill_child/net_guard
            // notify the condvar; the child is re-checked every CHILD_POLL_SECS.
            // A netplane_dirty wake reconciles immediately without resetting the
            // 30 s status cadence or bad_cycles ladder.
            let deadline = Instant::now() + Duration::from_secs(POLL_SECS);
            loop {
                if !self.running.load(Ordering::SeqCst)
                    || self.is_paused()
                    || self.has_relay_restart(identity)
                    || matches!(child.try_wait(), Ok(Some(_)) | Err(_))
                {
                    break;
                }
                if self.netplane_dirty.swap(false, Ordering::AcqRel) {
                    if let Some(exit) = self.enforce_child_dns_isolation(child, mode) {
                        return exit;
                    }
                    if mode == TunMode::Kernel {
                        self.reconcile_netplane(&mut guard_cursor);
                        if let Some(exit) = self.enforce_child_dns_isolation(child, mode) {
                            return exit;
                        }
                    }
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let guard = self.wake_lock.lock().unwrap_or_else(|e| e.into_inner());
                if !self.running.load(Ordering::SeqCst)
                    || self.is_paused()
                    || self.has_relay_restart(identity)
                    || self.netplane_dirty.load(Ordering::Acquire)
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

    fn restore_identity_if_current(
        &self,
        identity: ChildIdentity,
        stopped: u64,
        stop_child: impl FnOnce() -> bool,
    ) -> bool {
        let Ok(_prefs) = self.prefs_lock.try_lock() else {
            return false;
        };
        if stopped != self.stopped_generation()
            || !self.running.load(Ordering::Acquire)
            || self.is_paused()
            || *self.active_child.lock().unwrap() != Some(identity)
            || !self.config.lock().unwrap().enrolled
            || self.enrollment_active()
            || self.state_restore_attempted.load(Ordering::Acquire)
        {
            return false;
        }
        let backup = self.device_path(STATE_BAK);
        if !backup.exists() {
            return false;
        }
        eprintln!("[tailscale] enrolled node stuck in NeedsLogin — restoring state backup");
        if !stop_child() {
            eprintln!("[tailscale] child exit unconfirmed; refusing to replace persisted state");
            return true;
        }
        // Restored backup may predate netfilter-mode=off; force userspace preflight.
        self.clear_netfilter_off_marker();
        match copy_state_atomically(&backup, &self.device_path(STATE_FILE)) {
            Ok(()) => self.state_restore_attempted.store(true, Ordering::Release),
            Err(error) => eprintln!("[tailscale] restore enrolled state: {error}"),
        }
        true
    }

    fn graceful_stop(&self, child: &mut std::process::Child) -> bool {
        let pid = child.id();
        unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        for _ in 0..15 {
            if matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.wait();
                return true;
            }
            thread::sleep(Duration::from_secs(1));
        }
        let _ = child.kill();
        child.wait().is_ok()
    }

    /// Signal the supervised child by pid, verifying via /proc that the pid
    /// still belongs to tailscaled (guards against pid recycling).
    fn kill_child(&self, sig: i32) {
        #[cfg(test)]
        if self.test_io.is_some() {
            *self.active_child.lock().unwrap() = None;
            return;
        }
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
            if !self.running.load(Ordering::SeqCst) || self.is_paused() {
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
                            && !self.is_paused()
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
            if !self.running.load(Ordering::SeqCst) || self.is_paused() {
                return;
            }
            if daemon_status(5).is_ok() {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        if self.is_paused() {
            return;
        }
        if state_file_exists() {
            if let Err(e) = self.apply_current_prefs() {
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

    /// Rebind/restun `tailscaled` and, when kernel TUN is active, evict only
    /// `tailscale0`-originated conntrack entries (`ct mark 0x02000000`) so
    /// Exit Node flows immediately switch to the new uplink without touching
    /// unrelated cellular connections.
    fn nudge_and_reset_flows(&self, reason: &'static str) {
        self.nudge();
        if self.kernel_tun_active.load(Ordering::Acquire) {
            if let Err(error) = crate::netfx::conntrack::reset_mark(
                reason,
                ids::TAILSCALE_CT_MARK,
                ids::TAILSCALE_CT_MARK,
                true,
                true,
            ) {
                eprintln!("[tailscale] conntrack reset ({reason}): {error}");
            }
            self.mark_netplane_dirty();
        }
    }

    // --- Lifecycle operations (called from handlers) ---

    pub(super) fn ensure_daemon_ready(
        self: &Arc<Self>,
        stopped: u64,
        wait_secs: u64,
    ) -> Result<(), HandlerError> {
        {
            let _prefs = self.prefs_lock.lock().unwrap();
            self.check_enrollment_admission(stopped)?;
            if !self.is_installed() {
                return Err((
                    503,
                    "tailscale is not installed — POST /api/tailscale/update first".into(),
                ));
            }
            self.start_daemon_locked();
        }
        self.wait_for_daemon(wait_secs, Some(stopped))
    }

    pub(super) fn start_daemon_locked(self: &Arc<Self>) {
        self.running.store(true, Ordering::SeqCst);
        self.ensure_supervisor();
        self.wake_supervisor();
    }

    pub(super) fn wait_for_daemon(
        &self,
        wait_secs: u64,
        stopped: Option<u64>,
    ) -> Result<(), HandlerError> {
        let check = || {
            stopped.map_or(Ok(()), |generation| {
                self.check_enrollment_generation(generation)
            })
        };
        let deadline = Instant::now() + Duration::from_secs(wait_secs);
        while Instant::now() < deadline {
            check()?;
            let published = self.active_child.lock().unwrap().is_some()
                || {
                    #[cfg(test)]
                    {
                        self.test_io.is_some()
                    }
                    #[cfg(not(test))]
                    {
                        false
                    }
                };
            let probe_deadline = deadline.min(Instant::now() + Duration::from_secs(5));
            let ready = published && self.probe_status::<Value>(probe_deadline).is_ok();
            check()?;
            if ready {
                return Ok(());
            }
            thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(1)),
            );
        }
        check()?;
        Err((
            503,
            "tailscaled did not become ready in time — check /api/tailscale/status".into(),
        ))
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
        if self.slot_change_blocked() {
            return Err("OTA slot change or health trial in progress".into());
        }
        let mut cfg = self.config.lock().unwrap().clone();
        cfg.enabled = true;
        let hold = cfg.hold_wakelock;
        self.commit_config_locked(cfg)?;
        if hold {
            self.acquire_wakelock();
        }
        self.running.store(true, Ordering::SeqCst);
        self.ensure_supervisor();
        self.wake_supervisor();
        self.refresh_status();
        Ok(())
    }

    pub(super) fn commit_disable_locked(&self, logout: bool) -> Result<(), String> {
        let mut cfg = self.config.lock().unwrap().clone();
        cfg.enabled = false;
        if logout {
            cfg.enrolled = false;
        }
        let generation = self.commit_config_locked(cfg)?;
        self.stopped_gen.store(generation, Ordering::Release);
        self.prefs_pending.store(true, Ordering::Relaxed);
        self.cancel_active_up_locked();
        Ok(())
    }

    pub(super) fn stop_daemon_locked(&self) {
        // Politely stop the backend so the node shows offline, then stop the daemon
        if self.active_child.lock().unwrap().is_some() {
            let _ = self.run_cli(&["down"], 15);
        }
        self.running.store(false, Ordering::SeqCst);
        self.wake_supervisor();
        self.kill_child(libc::SIGTERM);
        self.release_wakelock();
    }

    /// Pause the supervisor for a Tailscale binary update and wait until it is
    /// parked with confirmed process absence.
    pub(super) fn quiesce_supervisor(&self) -> bool {
        {
            let _prefs = self.prefs_lock.lock().unwrap();
            self.paused.store(true, Ordering::SeqCst);
            self.wake_supervisor();
        }
        self.wait_quiesced()
    }

    fn wait_quiesced(&self) -> bool {
        for i in 0..QUIESCE_TIMEOUT_SECS {
            if i % 5 == 0 {
                self.kill_child(libc::SIGTERM);
            }
            if self.supervisor_idle.load(Ordering::SeqCst)
                && self.active_child.lock().unwrap().is_none()
            {
                let live_userspace = self.userspace_daemon_live.load(Ordering::Acquire);
                #[cfg(test)]
                if self.test_io.is_some() {
                    if !live_userspace {
                        return true;
                    }
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
                if !live_userspace {
                    if list_running_tailscaled_pids().is_ok_and(|pids| pids.is_empty()) {
                        return true;
                    }
                }
                // Try terminating any unconfirmed/preflight tailscaled child before retrying.
                if stop_all_tailscaled_and_confirm().is_ok() {
                    self.userspace_daemon_live.store(false, Ordering::Release);
                    return true;
                }
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

#[derive(Debug, PartialEq, Eq)]
enum PreflightWait {
    Ready,
    Aborted,
    Failed(String),
}

enum KernelActivationError {
    Aborted,
    NeedsNetfilterPreflight(String),
    DegradeToUserspace(String),
}

fn cli_on(sock: &str, args: &[&str], timeout_secs: u64) -> Result<String, String> {
    let mut cmd = Command::new(TAILSCALE_BIN);
    cmd.arg(format!("--socket={sock}"));
    cmd.args(args);
    let out = command_output(cmd, Duration::from_secs(timeout_secs))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let msg = if stderr.trim().is_empty() { stdout } else { stderr };
        return Err(msg.trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn has_residual_ts_legacy_chains(listing: &str) -> bool {
    listing.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("-N ts-")
            || trimmed.starts_with(":ts-")
            || trimmed.starts_with("-A ts-")
            || trimmed.contains(" -j ts-")
    })
}

fn has_residual_ts_nft_ruleset(ruleset: &str) -> bool {
    ruleset.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("chain ts-")
            || trimmed.starts_with("table ip tailscale")
            || trimmed.starts_with("table ip6 tailscale")
            || trimmed.starts_with("table inet tailscale")
            || trimmed.contains("jump ts-")
            || trimmed.contains("goto ts-")
    })
}

fn verify_no_residual_ts_firewall_with(
    mut run_cmd: impl FnMut(&str, &[&str]) -> Result<String, String>,
) -> Result<(), String> {
    for (tool, table) in [
        ("iptables", "filter"),
        ("iptables", "nat"),
        ("ip6tables", "filter"),
        ("ip6tables", "nat"),
    ] {
        let out = run_cmd(tool, &["-w", "2", "-t", table, "-S"])
            .map_err(|e| format!("verify {tool} -t {table} cleanup readback: {e}"))?;
        if has_residual_ts_legacy_chains(&out) {
            return Err(format!(
                "residual tailscaled ts-* chains remain in {tool} -t {table}"
            ));
        }
    }
    let ruleset = run_cmd("nft", &["-t", "list", "ruleset"])
        .map_err(|e| format!("verify nft ruleset cleanup readback: {e}"))?;
    if has_residual_ts_nft_ruleset(&ruleset) {
        return Err("residual tailscaled nftables chains/tables remain".into());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn is_ts_fwmark(mark: Option<(u32, u32)>) -> bool {
    // Tailscale 1.104.7 router_linux.go emits fwmark 0x80000/0xff0000, with an
    // unmasked 0x80000 fallback for legacy iproute2. Never match foreign masks
    // such as 0x80000/0x80000.
    matches!(
        mark,
        Some((0x80000, mask)) if mask == 0xff0000 || mask == u32::MAX
    )
}

#[cfg(any(target_os = "linux", test))]
fn is_ts_daemon_rule(rule: &crate::netfx::effect::shared::ParsedRule) -> bool {
    if rule.to.is_some() {
        return false;
    }
    match rule.priority {
        5210 => rule.lookup.as_deref() == Some("254") && !rule.unreachable && is_ts_fwmark(rule.mark),
        5230 => rule.lookup.as_deref() == Some("253") && !rule.unreachable && is_ts_fwmark(rule.mark),
        5250 => rule.lookup.is_none() && rule.unreachable && is_ts_fwmark(rule.mark),
        5270 => rule.lookup.as_deref() == Some("52") && !rule.unreachable && rule.mark.is_none(),
        _ => false,
    }
}

#[cfg(any(target_os = "linux", test))]
fn is_unparsed_ts_policy_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    let prio_match = ["5210:", "5230:", "5250:", "5270:"]
        .iter()
        .any(|p| trimmed.starts_with(p));
    if !prio_match {
        return false;
    }
    if crate::netfx::effect::shared::parse_rule_line(line).is_some() {
        return false;
    }
    trimmed.contains("0x80000") || trimmed.contains("lookup 52")
}

#[cfg(any(target_os = "linux", test))]
fn del_args_for_ts_rule(
    family: &str,
    rule: &crate::netfx::effect::shared::ParsedRule,
) -> Vec<String> {
    let mut args = vec![
        family.to_string(),
        "rule".into(),
        "del".into(),
        "pref".into(),
        rule.priority.to_string(),
    ];
    if let Some((val, mask)) = rule.mark {
        args.push("fwmark".into());
        if mask == u32::MAX {
            args.push(format!("{val:#x}"));
        } else {
            args.push(format!("{val:#x}/{mask:#x}"));
        }
    }
    if rule.unreachable {
        args.push("unreachable".into());
    } else if let Some(table) = &rule.lookup {
        args.push("lookup".into());
        match table.as_str() {
            "254" => args.push("main".into()),
            "253" => args.push("default".into()),
            other => args.push(other.to_string()),
        }
    }
    args
}

/// Inspect both IPv4 and IPv6 policy rule tables for leftover `tailscaled`
/// daemon-owned rules (`5210`/`5230`/`5250`/`5270`, which survive a forced
/// `SIGKILL` because `tailscaled --cleanup` only cleans firewall state), delete
/// exact owned remnants safely, and verify clean readback in both families.
#[cfg(any(target_os = "linux", test))]
pub(super) fn cleanup_and_verify_ts_policy_rules_with(
    mut run_cmd: impl FnMut(&str, &[&str]) -> Result<String, String>,
) -> Result<(), String> {
    use crate::netfx::effect::shared::{parse_rule_line, rule_del_check, RuleDelCheck};

    for family in ["-4", "-6"] {
        for _ in 0..16 {
            let listing = run_cmd("ip", &[family, "rule", "show"])
                .map_err(|e| format!("verify ip {family} rule cleanup readback: {e}"))?;
            if let Some(bad) = listing.lines().find(|l| is_unparsed_ts_policy_line(l)) {
                return Err(format!(
                    "unparseable tailscaled policy rule in ip {family} rule show: {}",
                    bad.trim()
                ));
            }
            let Some(owned) = listing
                .lines()
                .filter_map(parse_rule_line)
                .find(is_ts_daemon_rule)
            else {
                break;
            };
            let del_args = del_args_for_ts_rule(family, &owned);
            let safe = match rule_del_check(&listing, &del_args) {
                RuleDelCheck::SafeSingleMatch => true,
                RuleDelCheck::Missing => false,
                RuleDelCheck::Ambiguous => {
                    // Allow deleting one copy ONLY if every row at this priority
                    // parses as an exact identical daemon-owned copy (no foreign
                    // or unparseable sibling at the same priority).
                    let prefix = format!("{}:", owned.priority);
                    let same_prio: Vec<&str> = listing
                        .lines()
                        .filter(|l| l.trim_start().starts_with(&prefix))
                        .collect();
                    !same_prio.is_empty()
                        && same_prio
                            .iter()
                            .all(|l| parse_rule_line(l).as_ref() == Some(&owned))
                }
            };
            if !safe {
                return Err(format!(
                    "ambiguous tailscaled policy rule at priority {} in ip {family} rule show; refusing unsafe delete",
                    owned.priority
                ));
            }
            let refs: Vec<&str> = del_args.iter().map(String::as_str).collect();
            run_cmd("ip", &refs).map_err(|e| {
                format!(
                    "remove residual tailscaled policy rule (ip {}): {e}",
                    del_args.join(" ")
                )
            })?;
        }
        let verify = run_cmd("ip", &[family, "rule", "show"])
            .map_err(|e| format!("verify ip {family} rule post-cleanup readback: {e}"))?;
        if let Some(bad) = verify.lines().find(|l| is_unparsed_ts_policy_line(l)) {
            return Err(format!(
                "residual unparseable tailscaled policy rule in ip {family}: {}",
                bad.trim()
            ));
        }
        if let Some(remnant) = verify
            .lines()
            .filter_map(parse_rule_line)
            .find(is_ts_daemon_rule)
        {
            return Err(format!(
                "residual tailscaled policy rule at priority {} remains in ip {family}",
                remnant.priority
            ));
        }
    }
    Ok(())
}

pub(super) fn cleanup_and_verify_ts_policy_rules() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        cleanup_and_verify_ts_policy_rules_with(|program, args| {
            crate::net_tools::Cmd::new(program, args).run()
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

/// Run `tailscaled --cleanup`, require exit 0, verify IPv4/IPv6 firewall
/// readback confirms no residual `ts-*` chains or `tailscale` nftables remain,
/// and clean + verify IPv4/IPv6 daemon-owned policy rules (`5210`–`5270`).
pub(super) fn run_tailscaled_cleanup_checked() -> Result<(), String> {
    if Path::new(TAILSCALED_BIN).exists() {
        let mut cleanup = Command::new(TAILSCALED_BIN);
        cleanup.arg("--cleanup");
        let out = run_with_timeout(cleanup, 10)?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "tailscaled --cleanup exited {}: {}",
                out.status,
                stderr.trim()
            ));
        }
    }
    verify_no_residual_ts_firewall_with(|program, args| {
        crate::net_tools::Cmd::new(program, args).run()
    })?;
    cleanup_and_verify_ts_policy_rules()
}

#[cfg(any(target_os = "linux", test))]
fn is_process_gone(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

/// Inspect a Linux `/proc`-style directory for live `tailscaled` PIDs.
/// Fails closed (`Err`) if procfs is unreadable/empty/unmounted or any live
/// PID's identity cannot be read; skips only PIDs proven to have exited
/// (`ENOENT`/`ESRCH`) or zombies.
#[cfg(any(target_os = "linux", test))]
fn list_tailscaled_pids_in(proc_root: &Path) -> Result<Vec<i32>, String> {
    if proc_root == Path::new("/proc") {
        let self_stat = std::fs::read_to_string(proc_root.join("self/stat"))
            .map_err(|e| format!("inspect /proc/self/stat: {e}"))?;
        if self_stat.trim().is_empty() {
            return Err("inspect /proc/self/stat: empty procfs read".into());
        }
    }
    let entries = std::fs::read_dir(proc_root)
        .map_err(|e| format!("inspect {} for tailscaled: {e}", proc_root.display()))?;
    let self_pid = std::process::id() as i32;
    let mut saw_pid = false;
    let mut pids = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read {} entry: {e}", proc_root.display()))?;
        let name = entry.file_name();
        let Some(text) = name.to_str() else {
            continue;
        };
        let Ok(pid) = text.parse::<i32>() else {
            continue;
        };
        if pid <= 0 {
            continue;
        }
        let dir = entry.path();
        // Verify stat first to prove procfs is populated and skip zombies; fail
        // closed on unreadable/empty stat of a still-live process.
        match std::fs::read_to_string(dir.join("stat")) {
            Ok(stat) => {
                if stat.trim().is_empty() {
                    if dir.join("stat").exists() {
                        return Err(format!("inspect {}/stat: empty stat", dir.display()));
                    }
                    continue;
                }
                saw_pid = true;
                if pid == self_pid {
                    continue;
                }
                if let Some(after) = stat.rsplit_once(')').map(|(_, rest)| rest.trim_start()) {
                    if after.starts_with('Z') {
                        continue;
                    }
                }
            }
            Err(e) if is_process_gone(&e) => continue,
            Err(e) => {
                return Err(format!("inspect {}/stat: {e}", dir.display()));
            }
        }
        let comm = match std::fs::read_to_string(dir.join("comm")) {
            Ok(comm) => comm,
            Err(e) if is_process_gone(&e) => continue,
            Err(e) => return Err(format!("inspect {}/comm: {e}", dir.display())),
        };
        if comm.trim() == "tailscaled" {
            pids.push(pid);
            continue;
        }
        let raw_cmdline = match std::fs::read(dir.join("cmdline")) {
            Ok(raw) => raw,
            Err(e) if is_process_gone(&e) => continue,
            Err(e) => return Err(format!("inspect {}/cmdline: {e}", dir.display())),
        };
        let arg0 = raw_cmdline.split(|&b| b == 0).next().unwrap_or(&[]);
        let arg0 = std::str::from_utf8(arg0).unwrap_or("");
        if Path::new(arg0).file_name().and_then(|n| n.to_str()) == Some("tailscaled") {
            pids.push(pid);
        }
    }
    if !saw_pid {
        return Err(format!(
            "inspect {} for tailscaled: no readable numeric PID entries",
            proc_root.display()
        ));
    }
    pids.sort_unstable();
    Ok(pids)
}

fn list_running_tailscaled_pids() -> Result<Vec<i32>, String> {
    #[cfg(target_os = "linux")]
    {
        list_tailscaled_pids_in(Path::new("/proc"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let out = Command::new("pgrep")
            .args(["-x", "tailscaled"])
            .output()
            .map_err(|e| format!("inspect running tailscaled via pgrep: {e}"))?;
        match out.status.code() {
            Some(1) => Ok(Vec::new()),
            Some(0) => {
                let mut pids = Vec::new();
                for token in String::from_utf8_lossy(&out.stdout).split_whitespace() {
                    let pid = token
                        .parse::<i32>()
                        .map_err(|_| format!("malformed pgrep output: {token:?}"))?;
                    if pid > 0 && pid != std::process::id() as i32 {
                        pids.push(pid);
                    }
                }
                Ok(pids)
            }
            other => Err(format!("pgrep tailscaled failed with exit code {other:?}")),
        }
    }
}

/// SIGTERM then SIGKILL every running `tailscaled` instance and verify none
/// remain alive before releasing guards or spawning a replacement.
pub(super) fn stop_all_tailscaled_and_confirm() -> Result<(), String> {
    let found = list_running_tailscaled_pids()?;
    if found.is_empty() {
        return Ok(());
    }
    eprintln!("[tailscale] terminating tailscaled instance(s): {found:?}");
    for pid in &found {
        unsafe { libc::kill(*pid, libc::SIGTERM) };
    }
    for _ in 0..10 {
        thread::sleep(Duration::from_secs(1));
        if list_running_tailscaled_pids()?.is_empty() {
            return Ok(());
        }
    }
    for pid in list_running_tailscaled_pids()? {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    for _ in 0..5 {
        thread::sleep(Duration::from_secs(1));
        if list_running_tailscaled_pids()?.is_empty() {
            return Ok(());
        }
    }
    Err("tailscaled is still running; refusing to continue".into())
}

fn verify_no_legacy_policy_rules() -> Result<(), String> {
    for flag in ["-4", "-6"] {
        let out = crate::net_tools::Cmd::new("ip", &[flag, "rule", "show"]).run()?;
        for legacy in [ids::LEGACY_MIHOMO_PREF, ids::LEGACY_RELAY_PREF] {
            let prefix = format!("{legacy}:");
            if out.lines().any(|line| line.trim_start().starts_with(&prefix)) {
                return Err(format!(
                    "legacy policy rule priority {legacy} is still active ({flag}); deferring kernel TUN"
                ));
            }
        }
    }
    Ok(())
}

/// Stable fingerprint bound to the persisted active Tailscale profile in
/// `tailscaled.state`. Tailscale 1.104.7 stores the full profile key (e.g.
/// `profile-abcd`) in `_current-profile` AND registers it in `_profiles`; both
/// the registration and the profile prefs blob must exist and match.
fn state_profile_fingerprint(state_path: &Path) -> Option<String> {
    let raw = std::fs::read(state_path).ok()?;
    if raw.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    if let Ok(map) = serde_json::from_slice::<BTreeMap<String, String>>(&raw) {
        if let Some(cur_b64) = map.get("_current-profile") {
            let cur_bytes = base64::engine::general_purpose::STANDARD
                .decode(cur_b64.trim())
                .ok()?;
            let cur_key = std::str::from_utf8(&cur_bytes).ok()?.trim();
            if cur_key.is_empty() {
                return None;
            }
            // Verify `_profiles` JSON object (map[ProfileID]LoginProfile in
            // Tailscale 1.104.7 `ipn/ipnlocal/profiles.go`) registers `cur_key`.
            let profiles_b64 = map.get("_profiles")?;
            let profiles_bytes = base64::engine::general_purpose::STANDARD
                .decode(profiles_b64.trim())
                .ok()?;
            let profiles: Value = serde_json::from_slice(&profiles_bytes).ok()?;
            let registered = profiles
                .as_object()?
                .values()
                .any(|entry| entry.get("Key").and_then(Value::as_str) == Some(cur_key));
            if !registered {
                return None;
            }
            let profile_b64 = map.get(cur_key)?;
            hasher.update(b"profile:");
            hasher.update(cur_key.as_bytes());
            hasher.update(b":");
            hasher.update(profiles_b64.as_bytes());
            hasher.update(b":");
            hasher.update(profile_b64.as_bytes());
            return Some(format!("v2:{:x}", hasher.finalize()));
        }
    }
    hasher.update(b"raw:");
    hasher.update(&raw);
    Some(format!("v2:{:x}", hasher.finalize()))
}

fn marker_matches_state(marker_path: &Path, state_path: &Path) -> bool {
    let Some(expected) = state_profile_fingerprint(state_path) else {
        return false;
    };
    let Ok(stored) = std::fs::read_to_string(marker_path) else {
        return false;
    };
    stored.trim() == expected
}

fn write_bound_netfilter_off_marker(marker_path: &Path, state_path: &Path) -> Result<(), String> {
    let Some(proof) = state_profile_fingerprint(state_path) else {
        return Err("cannot fingerprint persisted tailscaled state".into());
    };
    let payload = format!("{proof}\n");
    crate::ota::storage::atomic_write_preserving_parent(marker_path, payload.as_bytes(), 0o600)
        .map_err(|error| format!("write {}: {error}", marker_path.display()))
}

fn probe_tun_device(path: &Path) -> Result<(), String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map(|_| ())
        .map_err(|error| format!("{} unavailable: {error}", path.display()))
}

fn is_enrolled_backend_state(state: &str) -> bool {
    !state.is_empty() && !matches!(state, "NoState" | "NeedsLogin")
}

/// Zero-window durable preflight for kernel TUN migration on a private socket:
/// 1. Confirm `/dev/net/tun` is accessible and `tailscaled.state` exists.
/// 2. If the state-bound marker matches the current persisted profile, skip preflight.
/// 3. Otherwise boot userspace `tailscaled` on a private socket (never the
///    production socket), verify an enrolled backend state, and check `NetfilterMode`:
///    - If already `Some(0)` from a cold load, stop cleanly.
///    - If non-zero, set `--netfilter-mode=off`, confirm `Some(0)`, stop, then
///      perform a second cold-load userspace pass WITHOUT calling `set` to prove
///      `NetfilterMode == 0` was actually persisted to disk (rejecting Tailscale
///      1.104.7's in-memory-only default for fresh profiles).
/// 4. Require `tailscaled --cleanup` to succeed, then write the state-bound marker.
#[allow(clippy::too_many_arguments)]
fn prepare_tun_mode_with<C>(
    probe_tun: impl FnOnce() -> Result<(), String>,
    state_exists: impl FnOnce() -> bool,
    marker_valid: impl FnOnce() -> bool,
    write_marker: impl FnOnce() -> Result<(), String>,
    mut spawn_userspace: impl FnMut() -> Result<C, String>,
    mut wait_ready: impl FnMut(&mut C) -> PreflightWait,
    mut read_backend_state: impl FnMut() -> Option<String>,
    mut read_netfilter_mode: impl FnMut() -> Option<i32>,
    set_netfilter_off: impl FnOnce() -> Result<(), String>,
    mut stop_child: impl FnMut(C) -> bool,
    run_cleanup: impl FnOnce() -> Result<(), String>,
) -> PreflightOutcome {
    if let Err(reason) = probe_tun() {
        return PreflightOutcome::Userspace {
            reason,
            sticky: true,
        };
    }
    if !state_exists() {
        return PreflightOutcome::Userspace {
            reason: "tailscaled state file not present yet; staying in userspace mode".into(),
            sticky: false,
        };
    }
    if marker_valid() {
        // Require successful cleanup on every path to kernel spawn.
        if let Err(error) = run_cleanup() {
            return PreflightOutcome::Userspace {
                reason: format!("tailscaled --cleanup failed before kernel TUN: {error}"),
                sticky: true,
            };
        }
        return PreflightOutcome::Kernel;
    }

    // Pass 1: cold-load inspection (and one-shot migration if NetfilterMode != 0).
    let mut child = match spawn_userspace() {
        Ok(child) => child,
        Err(error) => {
            return PreflightOutcome::Userspace {
                reason: format!("preflight spawn failed: {error}"),
                sticky: true,
            };
        }
    };
    match wait_ready(&mut child) {
        PreflightWait::Ready => {}
        PreflightWait::Aborted => {
            if !stop_child(child) {
                return PreflightOutcome::ChildUnconfirmed {
                    reason: "preflight daemon did not confirm exit on abort".into(),
                };
            }
            return PreflightOutcome::Aborted;
        }
        PreflightWait::Failed(reason) => {
            if !stop_child(child) {
                return PreflightOutcome::ChildUnconfirmed {
                    reason: format!("preflight daemon did not confirm exit after failure ({reason})"),
                };
            }
            return PreflightOutcome::Userspace {
                reason,
                sticky: true,
            };
        }
    }
    let state = read_backend_state();
    if !state.as_deref().is_some_and(is_enrolled_backend_state) {
        if !stop_child(child) {
            return PreflightOutcome::ChildUnconfirmed {
                reason: "preflight daemon did not confirm exit for non-enrolled node".into(),
            };
        }
        return PreflightOutcome::Userspace {
            reason: format!(
                "preflight observed non-enrolled backend state ({state:?}); staying in userspace mode"
            ),
            sticky: false,
        };
    }
    let initial_mode = read_netfilter_mode();
    let needs_reload_proof = match initial_mode {
        Some(0) => false,
        _ => {
            if let Err(error) = set_netfilter_off() {
                if !stop_child(child) {
                    return PreflightOutcome::ChildUnconfirmed {
                        reason: format!("preflight daemon did not confirm exit after set error ({error})"),
                    };
                }
                return PreflightOutcome::Userspace {
                    reason: format!("netfilter-mode=off preflight failed ({error})"),
                    sticky: true,
                };
            }
            let after_set = read_netfilter_mode();
            if after_set != Some(0) {
                if !stop_child(child) {
                    return PreflightOutcome::ChildUnconfirmed {
                        reason: "preflight daemon did not confirm exit after unconfirmed readback".into(),
                    };
                }
                return PreflightOutcome::Userspace {
                    reason: format!(
                        "netfilter-mode=off readback unconfirmed (observed {after_set:?}); staying in userspace mode"
                    ),
                    sticky: true,
                };
            }
            true
        }
    };
    if !stop_child(child) {
        return PreflightOutcome::ChildUnconfirmed {
            reason: "preflight daemon did not confirm exit".into(),
        };
    }

    // Pass 2: if Pass 1 mutated NetfilterMode, boot a fresh userspace process
    // without calling `set` and verify the persisted profile cold-loads as 0.
    if needs_reload_proof {
        let mut verify_child = match spawn_userspace() {
            Ok(child) => child,
            Err(error) => {
                return PreflightOutcome::Userspace {
                    reason: format!("preflight durability-check spawn failed: {error}"),
                    sticky: true,
                };
            }
        };
        match wait_ready(&mut verify_child) {
            PreflightWait::Ready => {}
            PreflightWait::Aborted => {
                if !stop_child(verify_child) {
                    return PreflightOutcome::ChildUnconfirmed {
                        reason: "preflight durability-check daemon did not confirm exit on abort".into(),
                    };
                }
                return PreflightOutcome::Aborted;
            }
            PreflightWait::Failed(reason) => {
                if !stop_child(verify_child) {
                    return PreflightOutcome::ChildUnconfirmed {
                        reason: format!("preflight durability-check daemon did not confirm exit ({reason})"),
                    };
                }
                return PreflightOutcome::Userspace {
                    reason,
                    sticky: true,
                };
            }
        }
        let persisted_state = read_backend_state();
        let persisted_mode = read_netfilter_mode();
        if !stop_child(verify_child) {
            return PreflightOutcome::ChildUnconfirmed {
                reason: "preflight durability-check daemon did not confirm exit".into(),
            };
        }
        if !persisted_state.as_deref().is_some_and(is_enrolled_backend_state)
            || persisted_mode != Some(0)
        {
            return PreflightOutcome::Userspace {
                reason: format!(
                    "netfilter-mode=off did not persist across restart (state={persisted_state:?}, mode={persisted_mode:?})"
                ),
                sticky: true,
            };
        }
    }

    if let Err(error) = run_cleanup() {
        return PreflightOutcome::Userspace {
            reason: format!("tailscaled --cleanup failed before kernel TUN: {error}"),
            sticky: true,
        };
    }
    match write_marker() {
        Ok(()) => PreflightOutcome::Kernel,
        Err(error) => PreflightOutcome::Userspace {
            reason: format!("could not persist netfilter-mode=off marker: {error}"),
            sticky: true,
        },
    }
}

/// Wait until the preflight daemon's LocalAPI responds AND finishes initial
/// `LocalBackend.Start()` state loading (`BackendState` leaves `"NoState"`).
/// On Tailscale 1.104.7, LocalAPI binds before `tailscaled.state` finishes
/// loading, briefly returning `"NoState"`.
fn wait_preflight_ready_with(
    max_polls: usize,
    mut is_aborted: impl FnMut() -> bool,
    mut child_exited: impl FnMut() -> bool,
    mut read_backend_state: impl FnMut() -> Option<String>,
    mut sleep_step: impl FnMut(),
    mut is_expired: impl FnMut() -> bool,
) -> PreflightWait {
    let mut saw_localapi = false;
    for _ in 0..max_polls {
        if is_aborted() {
            return PreflightWait::Aborted;
        }
        if child_exited() {
            return PreflightWait::Failed("tailscaled exited during preflight".into());
        }
        if let Some(state) = read_backend_state() {
            saw_localapi = true;
            if !state.is_empty() && state != "NoState" {
                return PreflightWait::Ready;
            }
        }
        if is_expired() {
            break;
        }
        sleep_step();
    }
    if saw_localapi {
        return PreflightWait::Ready;
    }
    PreflightWait::Failed("tailscaled LocalAPI did not become ready during preflight".into())
}

fn apply_isolated_net_namespace(cmd: &mut Command) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: closure invokes only async-signal-safe libc syscalls
        // (`unshare`, `socket`, `ioctl`, `close`) with stack data.
        unsafe {
            cmd.pre_exec(|| {
                if libc::unshare(libc::CLONE_NEWNET) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
                if fd >= 0 {
                    let mut ifr: libc::ifreq = std::mem::zeroed();
                    ifr.ifr_name[0] = b'l' as libc::c_char;
                    ifr.ifr_name[1] = b'o' as libc::c_char;
                    if libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut ifr) == 0 {
                        ifr.ifr_ifru.ifru_flags |=
                            (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
                        let _ = libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &mut ifr);
                    }
                    libc::close(fd);
                }
                Ok(())
            });
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cmd;
        Ok(())
    }
}

fn routes_include_exit_node(routes: &[String]) -> bool {
    let default_v4: ipnet::IpNet = super::config::DEFAULT_V4.parse().unwrap();
    let default_v6: ipnet::IpNet = super::config::DEFAULT_V6.parse().unwrap();
    routes.iter().any(|raw| match raw.parse::<ipnet::IpNet>() {
        Ok(net) => {
            let t = net.trunc();
            t == default_v4 || t == default_v6
        }
        // Fail closed on unparseable entries.
        Err(_) => true,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum ChildIsolationAction {
    Healthy,
    StopChild { clean: bool, reason: String },
}

fn check_child_dns_isolation_with(
    mode: TunMode,
    mut verify_mount: impl FnMut() -> Result<(), String>,
    mut clean_dns_running: impl FnMut() -> bool,
    mut restart_clean_dns: impl FnMut() -> Result<Option<u16>, String>,
    mut current_dnat_port: impl FnMut() -> Option<u16>,
    mut ensure_dnat: impl FnMut(Option<u16>) -> Result<(), String>,
) -> ChildIsolationAction {
    if let Err(err) = verify_mount() {
        return ChildIsolationAction::StopChild {
            clean: true,
            reason: format!("clean DNS mount isolation check failed: {err}"),
        };
    }
    let dnat_port = if clean_dns_running() {
        current_dnat_port()
    } else {
        match restart_clean_dns() {
            Ok(port) => port,
            Err(err) => {
                return ChildIsolationAction::StopChild {
                    clean: false,
                    reason: format!("clean DNS resolver stopped and restart failed: {err}"),
                };
            }
        }
    };
    match mode {
        TunMode::Kernel => {
            if let Err(err) = ensure_dnat(dnat_port) {
                return ChildIsolationAction::StopChild {
                    clean: false,
                    reason: format!("clean DNS DNAT delivery state unconfirmed ({dnat_port:?}): {err}"),
                };
            }
            ChildIsolationAction::Healthy
        }
        TunMode::Userspace => {
            if let Some(port) = dnat_port {
                return ChildIsolationAction::StopChild {
                    clean: false,
                    reason: format!(
                        "userspace clean DNS requires unavailable fallback DNAT port {port}"
                    ),
                };
            }
            if let Err(err) = ensure_dnat(None) {
                return ChildIsolationAction::StopChild {
                    clean: false,
                    reason: format!("userspace direct port-53 delivery blocked by stale DNAT: {err}"),
                };
            }
            ChildIsolationAction::Healthy
        }
        TunMode::PreflightIsolated => ChildIsolationAction::Healthy,
    }
}

fn ensure_userspace_exit_node_cleared_with<C>(
    mut spawn_isolated: impl FnMut() -> Result<C, String>,
    mut wait_ready: impl FnMut(&mut C) -> PreflightWait,
    mut read_advertise_routes: impl FnMut() -> Option<Vec<String>>,
    mut clear_exit_node: impl FnMut() -> Result<(), String>,
    mut stop_child: impl FnMut(C) -> bool,
) -> UserspaceScrubOutcome {
    let mut child = match spawn_isolated() {
        Ok(child) => child,
        Err(err) => {
            return UserspaceScrubOutcome::Failed(format!(
                "isolated exit-node scrub spawn failed: {err}"
            ))
        }
    };
    let pass1 = match wait_ready(&mut child) {
        PreflightWait::Aborted => Err(UserspaceScrubOutcome::Aborted),
        PreflightWait::Failed(reason) => Err(UserspaceScrubOutcome::Failed(format!(
            "isolated exit-node scrub not ready: {reason}"
        ))),
        PreflightWait::Ready => match read_advertise_routes() {
            None => Err(UserspaceScrubOutcome::Failed(
                "could not read persisted advertise_routes during isolated exit-node scrub".into(),
            )),
            Some(routes) if !routes_include_exit_node(&routes) => Ok(false),
            Some(_) => match clear_exit_node() {
                Err(err) => Err(UserspaceScrubOutcome::Failed(format!(
                    "failed to clear persisted exit-node advertisement before userspace start: {err}"
                ))),
                Ok(()) => Ok(true),
            },
        },
    };
    if !stop_child(child) {
        return UserspaceScrubOutcome::ChildUnconfirmed(
            "isolated exit-node scrub child did not confirm exit".into(),
        );
    }
    match pass1 {
        Err(outcome) => return outcome,
        Ok(false) => return UserspaceScrubOutcome::Clear,
        Ok(true) => {}
    }

    // Tailscale updates in-memory preferences before writing STATE_FILE and
    // can log a persistence failure while returning cleared prefs from the same
    // daemon. Cold-load STATE_FILE in a second isolated child before certifying
    // the profile or caching its fingerprint.
    let mut verify_child = match spawn_isolated() {
        Ok(child) => child,
        Err(err) => {
            return UserspaceScrubOutcome::Failed(format!(
                "isolated exit-node cold-load verify spawn failed: {err}"
            ))
        }
    };
    let pass2 = match wait_ready(&mut verify_child) {
        PreflightWait::Aborted => UserspaceScrubOutcome::Aborted,
        PreflightWait::Failed(reason) => UserspaceScrubOutcome::Failed(format!(
            "isolated exit-node cold-load verify not ready: {reason}"
        )),
        PreflightWait::Ready => match read_advertise_routes() {
            Some(after) if !routes_include_exit_node(&after) => UserspaceScrubOutcome::Clear,
            other => UserspaceScrubOutcome::Failed(format!(
                "persisted exit-node advertisement remained on disk after cold-load verify ({other:?})"
            )),
        },
    };
    if !stop_child(verify_child) {
        return UserspaceScrubOutcome::ChildUnconfirmed(
            "isolated exit-node cold-load verify child did not confirm exit".into(),
        );
    }
    pass2
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
    fn restore_checks_the_child_and_generation_and_can_retry_failed_replacement() {
        let root = std::env::temp_dir().join(format!("zte-ts-restore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let mut manager = test_manager(true, Some(500));
        let mgr = Arc::get_mut(&mut manager).unwrap();
        mgr.config.lock().unwrap().enrolled = true;
        mgr.test_io = Some(super::super::TestIo {
            root: root.clone(),
            cli: Box::new(|_| panic!("unexpected CLI")),
            status: Box::new(|| panic!("unexpected daemon probe")),
            up_command: None,
        });
        let active = mgr.active_child.lock().unwrap().unwrap();
        let generation = mgr.stopped_generation();
        let backup = mgr.device_path(STATE_BAK);
        let state = mgr.device_path(STATE_FILE);
        std::fs::write(backup, b"saved identity").unwrap();

        assert!(
            !mgr.restore_identity_if_current(active, generation + 1, || {
                panic!("stale generation cannot stop child");
            })
        );
        let replaced = ChildIdentity {
            instance: active.instance + 1,
            ..active
        };
        assert!(!mgr.restore_identity_if_current(replaced, generation, || {
            panic!("stale child cannot be stopped");
        }));
        // Unconfirmed child exit must refuse to overwrite persisted identity.
        std::fs::write(&state, b"old identity").unwrap();
        assert!(mgr.restore_identity_if_current(active, generation, || false));
        assert!(!mgr.state_restore_attempted.load(Ordering::Acquire));
        assert_eq!(std::fs::read(&state).unwrap(), b"old identity");
        std::fs::remove_file(&state).unwrap();

        std::fs::create_dir(&state).unwrap();
        assert!(mgr.restore_identity_if_current(active, generation, || true));
        assert!(!mgr.state_restore_attempted.load(Ordering::Acquire));
        assert!(state.is_dir());

        std::fs::remove_dir(&state).unwrap();
        std::fs::write(&state, b"old identity").unwrap();
        assert!(mgr.restore_identity_if_current(active, generation, || true));
        assert!(mgr.state_restore_attempted.load(Ordering::Acquire));
        assert_eq!(std::fs::read(state).unwrap(), b"saved identity");
        std::fs::remove_dir_all(root).unwrap();
    }

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

    #[test]
    fn preflight_proves_persisted_netfilter_off_across_cold_restart_and_binds_marker_to_state() {
        let trace = std::cell::RefCell::new(Vec::<&'static str>::new());
        let reads = std::cell::RefCell::new(vec![Some(2), Some(0), Some(0)].into_iter());
        let outcome = prepare_tun_mode_with(
            || {
                trace.borrow_mut().push("probe_tun");
                Ok(())
            },
            || {
                trace.borrow_mut().push("state_exists");
                true
            },
            || {
                trace.borrow_mut().push("marker_valid");
                false
            },
            || {
                trace.borrow_mut().push("write_marker");
                Ok(())
            },
            || {
                trace.borrow_mut().push("spawn_userspace");
                Ok("fake-child")
            },
            |_| {
                trace.borrow_mut().push("wait_ready");
                PreflightWait::Ready
            },
            || {
                trace.borrow_mut().push("read_state");
                Some("Running".into())
            },
            || {
                trace.borrow_mut().push("read_prefs");
                reads.borrow_mut().next().flatten()
            },
            || {
                trace.borrow_mut().push("set_off");
                Ok(())
            },
            |_| {
                trace.borrow_mut().push("stop_child");
                true
            },
            || {
                trace.borrow_mut().push("cleanup");
                Ok(())
            },
        );
        assert_eq!(outcome, PreflightOutcome::Kernel);
        assert_eq!(
            *trace.borrow(),
            [
                "probe_tun",
                "state_exists",
                "marker_valid",
                "spawn_userspace",
                "wait_ready",
                "read_state",
                "read_prefs",
                "set_off",
                "read_prefs",
                "stop_child",
                "spawn_userspace",
                "wait_ready",
                "read_state",
                "read_prefs",
                "stop_child",
                "cleanup",
                "write_marker",
            ]
        );

        // State-bound marker binds `_current-profile`, `_profiles` object map
        // (matching Tailscale 1.104.7 `map[ProfileID]LoginProfile`), and the
        // profile blob; removing `_profiles` registration invalidates it.
        let dir = std::env::temp_dir().join(format!("zte-ts-marker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let state = dir.join("tailscaled.state");
        let marker = dir.join("netfilter-off.verified");
        let profile_key_b64 = base64::engine::general_purpose::STANDARD.encode(b"profile-profA");
        let profiles_reg = base64::engine::general_purpose::STANDARD
            .encode(br#"{"profA":{"ID":"profA","Key":"profile-profA"}}"#);
        let profiles_empty = base64::engine::general_purpose::STANDARD.encode(br#"{}"#);
        let prefs_a = base64::engine::general_purpose::STANDARD.encode(br#"{"NetfilterMode":0}"#);
        let prefs_b = base64::engine::general_purpose::STANDARD.encode(br#"{"NetfilterMode":2}"#);
        std::fs::write(
            &state,
            format!(
                "{{\"_current-profile\":\"{profile_key_b64}\",\"_profiles\":\"{profiles_reg}\",\"profile-profA\":\"{prefs_a}\"}}"
            ),
        )
        .unwrap();
        write_bound_netfilter_off_marker(&marker, &state).unwrap();
        assert!(marker_matches_state(&marker, &state));
        // Removing profile registration in `_profiles` invalidates marker even when blob remains.
        std::fs::write(
            &state,
            format!(
                "{{\"_current-profile\":\"{profile_key_b64}\",\"_profiles\":\"{profiles_empty}\",\"profile-profA\":\"{prefs_a}\"}}"
            ),
        )
        .unwrap();
        assert!(!marker_matches_state(&marker, &state));
        // Replacing profile prefs invalidates marker.
        std::fs::write(
            &state,
            format!(
                "{{\"_current-profile\":\"{profile_key_b64}\",\"_profiles\":\"{profiles_reg}\",\"profile-profA\":\"{prefs_b}\"}}"
            ),
        )
        .unwrap();
        assert!(!marker_matches_state(&marker, &state));
        std::fs::remove_dir_all(&dir).unwrap();

        // Residual legacy ts-* chains AND native nftables ts-* chains/jumps fail cleanup readback.
        assert!(verify_no_residual_ts_firewall_with(|_, _| Ok(String::new())).is_ok());
        assert!(verify_no_residual_ts_firewall_with(|tool, _| {
            if tool == "ip6tables" {
                Ok("-N ts-input\n-A INPUT -j ts-input\n".into())
            } else {
                Ok(String::new())
            }
        })
        .is_err());
        for native_nft in [
            "table ip filter {\n\tchain ts-input {\n\t}\n}\n",
            "table ip6 filter {\n\tchain forward {\n\t\tjump ts-forward\n\t}\n}\n",
            "table ip nat {\n\tchain ts-postrouting {\n\t}\n}\n",
        ] {
            assert!(verify_no_residual_ts_firewall_with(|tool, _| {
                if tool == "nft" {
                    Ok(native_nft.into())
                } else {
                    Ok(String::new())
                }
            })
            .is_err());
        }

        // Unconfirmed preflight child exit returns ChildUnconfirmed (never Userspace!).
        let unconfirmed_stop = prepare_tun_mode_with(
            || Ok(()),
            || true,
            || false,
            || panic!("must not write marker"),
            || Ok("fake-child"),
            |_| PreflightWait::Ready,
            || Some("Running".into()),
            || Some(0),
            || panic!("already 0"),
            |_| false,
            || panic!("must not cleanup"),
        );
        assert!(matches!(
            unconfirmed_stop,
            PreflightOutcome::ChildUnconfirmed { .. }
        ));

        // Valid marker fast-path MUST still run cleanup and reject if cleanup fails.
        let fast_fail = prepare_tun_mode_with::<&str>(
            || Ok(()),
            || true,
            || true,
            || panic!("marker already valid"),
            || panic!("must not spawn preflight when marker is valid"),
            |_| panic!("must not wait"),
            || panic!("must not read state"),
            || panic!("must not read prefs"),
            || panic!("must not set"),
            |_| panic!("must not stop"),
            || Err("cleanup nonzero".into()),
        );
        assert!(matches!(
            fast_fail,
            PreflightOutcome::Userspace { reason, sticky: true } if reason.contains("cleanup failed")
        ));

        // Direct /proc enumeration detects live tailscaled, skips zombies, and
        // fails closed on both missing /proc AND per-PID unreadable comm/cmdline.
        let proc_dir = std::env::temp_dir().join(format!("zte-ts-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&proc_dir);
        std::fs::create_dir_all(proc_dir.join("1234")).unwrap();
        std::fs::write(proc_dir.join("1234/comm"), "tailscaled\n").unwrap();
        std::fs::write(proc_dir.join("1234/stat"), "1234 (tailscaled) S 1 1 1 0\n").unwrap();
        std::fs::write(proc_dir.join("1234/cmdline"), b"/data/tailscale/bin/tailscaled\0").unwrap();
        std::fs::create_dir_all(proc_dir.join("5678")).unwrap();
        std::fs::write(proc_dir.join("5678/comm"), "tailscaled\n").unwrap();
        std::fs::write(proc_dir.join("5678/stat"), "5678 (tailscaled) Z 1 1 1 0\n").unwrap();
        std::fs::create_dir_all(proc_dir.join("9999")).unwrap();
        std::fs::write(proc_dir.join("9999/comm"), "dnsmasq\n").unwrap();
        std::fs::write(proc_dir.join("9999/stat"), "9999 (dnsmasq) S 1 1 1 0\n").unwrap();
        std::fs::write(proc_dir.join("9999/cmdline"), b"/usr/sbin/dnsmasq\0").unwrap();
        assert_eq!(list_tailscaled_pids_in(&proc_dir).unwrap(), vec![1234]);
        // Per-PID unreadable comm (simulated with a directory -> EISDIR even as root) fails closed!
        std::fs::create_dir_all(proc_dir.join("2222/comm")).unwrap();
        std::fs::write(proc_dir.join("2222/stat"), "2222 (unknown) S 1 1 1 0\n").unwrap();
        assert!(
            list_tailscaled_pids_in(&proc_dir).is_err(),
            "per-PID unreadable comm must fail closed rather than returning empty"
        );
        std::fs::remove_dir_all(&proc_dir).unwrap();
        assert!(list_tailscaled_pids_in(&proc_dir).is_err(), "unreadable /proc must fail closed");
    }

    #[test]
    fn preflight_rejects_in_memory_only_netfilter_off_unenrolled_and_failed_cleanup() {
        // In-memory NetfilterMode=0 that reverts to 2 on cold restart must NOT promote.
        let mut reads = vec![Some(2), Some(0), Some(2)].into_iter();
        let non_durable = prepare_tun_mode_with(
            || Ok(()),
            || true,
            || false,
            || panic!("must not write marker when cold restart reverted to 2"),
            || Ok("fake-child"),
            |_| PreflightWait::Ready,
            || Some("Running".into()),
            || reads.next().flatten(),
            || Ok(()),
            |_| true,
            || panic!("must not run cleanup when durability check failed"),
        );
        assert!(matches!(
            non_durable,
            PreflightOutcome::Userspace { reason, sticky: true } if reason.contains("did not persist")
        ));

        // Unenrolled profile (NeedsLogin) stays in userspace (non-sticky so it can promote after login).
        let unenrolled = prepare_tun_mode_with(
            || Ok(()),
            || true,
            || false,
            || panic!("must not write marker for unenrolled profile"),
            || Ok("fake-child"),
            |_| PreflightWait::Ready,
            || Some("NeedsLogin".into()),
            || panic!("must not read prefs for unenrolled profile"),
            || panic!("must not set prefs for unenrolled profile"),
            |_| true,
            || panic!("must not cleanup"),
        );
        assert!(matches!(
            unenrolled,
            PreflightOutcome::Userspace { reason, sticky: false } if reason.contains("non-enrolled")
        ));

        // Failed cleanup refuses kernel promotion.
        let failed_cleanup = prepare_tun_mode_with(
            || Ok(()),
            || true,
            || false,
            || panic!("must not write marker when cleanup fails"),
            || Ok("fake-child"),
            |_| PreflightWait::Ready,
            || Some("Running".into()),
            || Some(0),
            || panic!("already 0 on cold load"),
            |_| true,
            || Err("cleanup failed".into()),
        );
        assert!(matches!(
            failed_cleanup,
            PreflightOutcome::Userspace { reason, sticky: true } if reason.contains("cleanup failed")
        ));

        // Unchecked startup orphan keeps userspace_loopback_active() fail-closed even when disabled.
        let mgr = test_manager(false, None);
        mgr.startup_orphan_cleared.store(false, Ordering::Release);
        assert!(mgr.userspace_loopback_active());
        mgr.startup_orphan_cleared.store(true, Ordering::Release);
        assert!(!mgr.userspace_loopback_active());

        // Disabling userspace keeps userspace_loopback_active() true until child exit is confirmed.
        let mgr = test_manager(true, Some(999));
        mgr.userspace_daemon_live.store(true, Ordering::Release);
        mgr.config.lock().unwrap().enabled = false;
        mgr.running.store(false, Ordering::SeqCst);
        assert!(
            mgr.userspace_loopback_active(),
            "loopback must stay classified as userspace while daemon has not confirmed exit"
        );
        mgr.userspace_daemon_live.store(false, Ordering::Release);
        *mgr.active_child.lock().unwrap() = None;
        assert!(!mgr.userspace_loopback_active());
    }

    #[test]
    fn wait_preflight_ready_waits_past_initial_nostate_before_returning_ready() {
        // Real tailscaled 1.104.7 briefly serves BackendState="NoState" right after
        // LocalAPI binds before LocalBackend finishes loading tailscaled.state.
        let mut states = vec![
            None,
            Some("NoState".to_string()),
            Some("NoState".to_string()),
            Some("Starting".to_string()),
            Some("Running".to_string()),
        ]
        .into_iter();
        let mut sleeps = 0usize;
        let res = wait_preflight_ready_with(
            10,
            || false,
            || false,
            || states.next().flatten(),
            || sleeps += 1,
            || false,
        );
        assert_eq!(res, PreflightWait::Ready);
        assert_eq!(sleeps, 3, "must stop polling as soon as BackendState leaves NoState");

        // NeedsLogin is a valid settled state (non-enrolled) and returns immediately.
        let mut states = vec![Some("NoState".to_string()), Some("NeedsLogin".to_string())].into_iter();
        let mut sleeps = 0usize;
        let res = wait_preflight_ready_with(
            10,
            || false,
            || false,
            || states.next().flatten(),
            || sleeps += 1,
            || false,
        );
        assert_eq!(res, PreflightWait::Ready);
        assert_eq!(sleeps, 1);

        // Persistent NoState until timeout yields Ready so Pass 1 can classify it non-sticky.
        let res = wait_preflight_ready_with(
            3,
            || false,
            || false,
            || Some("NoState".to_string()),
            || {},
            || false,
        );
        assert_eq!(res, PreflightWait::Ready);

        // Never-responding LocalAPI fails preflight.
        let res = wait_preflight_ready_with(
            3,
            || false,
            || false,
            || None,
            || {},
            || false,
        );
        assert!(matches!(res, PreflightWait::Failed(msg) if msg.contains("did not become ready")));

        // Abort and early exit short-circuit immediately.
        let res = wait_preflight_ready_with(3, || true, || false, || None, || {}, || false);
        assert_eq!(res, PreflightWait::Aborted);
        let res = wait_preflight_ready_with(3, || false, || true, || None, || {}, || false);
        assert!(matches!(res, PreflightWait::Failed(msg) if msg.contains("exited during preflight")));
    }

    #[test]
    fn slot_change_pause_is_independent_of_update_resume_and_mutually_exclusive() {
        let mgr = test_manager(true, None);
        // Active Tailscale binary update blocks OTA slot change before quiesce.
        mgr.updating.store(true, Ordering::Release);
        let err = mgr.before_slot_change(|| Ok(())).unwrap_err();
        assert!(err.contains("update in progress"), "unexpected err: {err}");
        assert!(!mgr.slot_change_paused.load(Ordering::Acquire));
        mgr.updating.store(false, Ordering::Release);

        // `resume_supervisor()` only clears the update pause, never `slot_change_paused`.
        mgr.paused.store(true, Ordering::SeqCst);
        mgr.slot_change_paused.store(true, Ordering::SeqCst);
        assert!(mgr.is_paused());
        mgr.resume_supervisor();
        assert!(!mgr.paused.load(Ordering::SeqCst));
        assert!(
            mgr.is_paused(),
            "resume_supervisor() must not unpause an active OTA slot change"
        );
        // Second concurrent slot change is rejected while slot_change_paused is held.
        let err = mgr.before_slot_change(|| Ok(())).unwrap_err();
        assert!(
            err.contains("slot change") && err.contains("already in progress"),
            "unexpected err: {err}"
        );
        mgr.slot_change_paused.store(false, Ordering::SeqCst);
        assert!(!mgr.is_paused());

        // Durable pending OTA trial (even in a fresh candidate where
        // slot_change_paused == false) MUST pause the supervisor (blocking both
        // kernel and userspace daemon starts) and reject candidate-side mutations.
        mgr.test_ota_trial_pending.store(true, Ordering::Release);
        assert!(mgr.slot_change_blocked());
        assert!(mgr.is_paused());
        let stopped = mgr.stopped_generation();
        let enroll_err = mgr.check_enrollment_admission(stopped).unwrap_err();
        assert_eq!(enroll_err.0, 409);
        assert!(mgr.do_enable().is_err());
        assert!(mgr.before_slot_change(|| Ok(())).is_err());
        mgr.test_ota_trial_pending.store(false, Ordering::Release);
        assert!(!mgr.is_paused());
    }

    #[test]
    fn slot_change_persists_and_completes_fallback_dns_flush_before_callback() {
        use crate::netfx::effect::fake::FakeNft;
        use crate::netfx::effect::testing::Kernel;
        use super::super::netplane::{self, ExitUplink, Layout, NetPlane};

        let mgr = test_manager(true, None);
        let dir = std::env::temp_dir().join(format!("u60-ts-slot-change-dnat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = dir.join("network.json");
        let marker = netplane::dnat_flush_marker_path(&journal);
        let mut plane = NetPlane::at(journal.clone(), dir.join("u60_tail.nft"));
        let mut kernel = Kernel::seeded();
        let mut nft = FakeNft::default();
        let fallback = Layout::closed_guard(ExitUplink::Cellular)
            .with_clean_dns_dnat(Some(crate::netfx::ids::CLEAN_DNS_FALLBACK_PORT));
        plane.sync_with(fallback, false, &mut kernel, &mut nft).unwrap();
        plane
            .ensure_clean_dns_dnat_with(
                Some(crate::netfx::ids::CLEAN_DNS_FALLBACK_PORT),
                &mut kernel,
                &mut nft,
            )
            .unwrap();
        assert!(plane.clean_dns_dnat_confirmed(Some(crate::netfx::ids::CLEAN_DNS_FALLBACK_PORT)));
        assert!(journal.exists());
        *mgr.netplane.lock().unwrap() = plane;

        // Pass 1: `release_with()` persists the same-boot flush marker BEFORE
        // deleting `network.json`, then `recover_with()` fails on the conntrack
        // flush -> `before_slot_change_with` MUST abort before the callback!
        let mut callback_calls = 0usize;
        let mut flush_calls = 0usize;
        let boot = crate::net_tools::boot_id();
        let err = mgr
            .before_slot_change_with(
                &journal,
                || Ok(()),
                |p| p.release_with(&mut kernel),
                || {
                    netplane::recover_with(
                        &journal,
                        &boot,
                        || Ok(()),
                        || Ok(()),
                        || Ok(()),
                        |_| false,
                        |_| unreachable!("normal release already removed journal"),
                        || {
                            flush_calls += 1;
                            Err("conntrack busy".into())
                        },
                    )
                },
                || {
                    callback_calls += 1;
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(err.contains("conntrack busy"), "unexpected err: {err}");
        assert_eq!(flush_calls, 1);
        assert_eq!(callback_calls, 0, "slot-change callback must not run before flush succeeds");
        assert!(!journal.exists(), "normal release removed journal");
        assert!(marker.exists(), "flush marker must persist on disk across failed flush");

        // Pass 2: retry succeeds once `recover_with()` completes the flush and
        // deletes the marker -> slot-change callback now executes!
        let res = mgr
            .before_slot_change_with(
                &journal,
                || Ok(()),
                |p| p.release_with(&mut kernel),
                || {
                    netplane::recover_with(
                        &journal,
                        &boot,
                        || Ok(()),
                        || Ok(()),
                        || Ok(()),
                        |_| false,
                        |_| unreachable!("journal already removed"),
                        || {
                            flush_calls += 1;
                            Ok(())
                        },
                    )
                },
                || {
                    callback_calls += 1;
                    Ok("switched")
                },
            )
            .expect("slot change should proceed once fallback DNS flush succeeds");
        assert_eq!(res, "switched");
        assert_eq!(flush_calls, 2);
        assert_eq!(callback_calls, 1);
        assert!(!journal.exists());
        assert!(!marker.exists());

        // Pass 3: failed kernel-TUN activation of fallback `:1054` installs
        // `dns_out` then fails on a later rule, tearing down `network.json`
        // and leaving `NetPlane` `Inactive` with the flush marker persisted on
        // disk. `before_slot_change_with` MUST still block the callback until
        // recovery flushes conntrack and removes the marker!
        let mut kernel_fail = Kernel::seeded();
        let mut nft_fail = FakeNft::default();
        let mut fail_plane = NetPlane::at(journal.clone(), dir.join("u60_tail.nft"));
        kernel_fail.apply_error = Some(netplane::cgnat_main_rule().command().unwrap());
        let fallback2 = Layout::closed_guard(ExitUplink::Cellular)
            .with_clean_dns_dnat(Some(crate::netfx::ids::CLEAN_DNS_FALLBACK_PORT));
        assert!(fail_plane
            .sync_with(fallback2, false, &mut kernel_fail, &mut nft_fail)
            .is_err());
        kernel_fail.apply_error = None;
        assert!(!journal.exists());
        assert!(marker.exists());
        let mgr2 = test_manager(true, None);
        *mgr2.netplane.lock().unwrap() = fail_plane;

        let err2 = mgr2
            .before_slot_change_with(
                &journal,
                || Ok(()),
                |p| p.release_with(&mut kernel_fail),
                || {
                    netplane::recover_with(
                        &journal,
                        &boot,
                        || Ok(()),
                        || Ok(()),
                        || Ok(()),
                        |_| false,
                        |_| unreachable!("journal already deleted during partial activation cleanup"),
                        || {
                            flush_calls += 1;
                            Err("conntrack busy after partial activation".into())
                        },
                    )
                },
                || {
                    callback_calls += 1;
                    Ok("should-not-run")
                },
            )
            .unwrap_err();
        assert!(err2.contains("conntrack busy"), "unexpected err: {err2}");
        assert_eq!(flush_calls, 3);
        assert_eq!(callback_calls, 1);
        assert!(marker.exists());

        let res2 = mgr2
            .before_slot_change_with(
                &journal,
                || Ok(()),
                |p| p.release_with(&mut kernel_fail),
                || {
                    netplane::recover_with(
                        &journal,
                        &boot,
                        || Ok(()),
                        || Ok(()),
                        || Ok(()),
                        |_| false,
                        |_| unreachable!(),
                        || {
                            flush_calls += 1;
                            Ok(())
                        },
                    )
                },
                || {
                    callback_calls += 1;
                    Ok("switched-after-partial")
                },
            )
            .expect("slot change should succeed once partial-activation flush marker is cleared");
        assert_eq!(res2, "switched-after-partial");
        assert_eq!(flush_calls, 4);
        assert_eq!(callback_calls, 2);
        assert!(!journal.exists());
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forced_exit_policy_rule_cleanup_removes_exact_daemon_rules_and_retains_journal_on_failure() {
        let mut v4_rules = vec![
            "0:\tfrom all lookup local".to_string(),
            "5120:\tfrom all lookup 100".to_string(),
            "5210:\tfrom all fwmark 0x80000/0xff0000 lookup main".to_string(),
            "5230:\tfrom all fwmark 0x80000/0xff0000 lookup default".to_string(),
            "5250:\tfrom all fwmark 0x80000/0xff0000 unreachable".to_string(),
            "5270:\tfrom all lookup 52".to_string(),
            "18640:\tfrom all lookup 100".to_string(),
            "32766:\tfrom all lookup main".to_string(),
        ];
        let mut v6_rules = vec![
            "0:\tfrom all lookup local".to_string(),
            "5210:\tfrom all fwmark 0x80000/0xff0000 lookup main".to_string(),
            "5270:\tfrom all lookup 52".to_string(),
            "32766:\tfrom all lookup main".to_string(),
        ];
        let mut deleted = Vec::new();
        cleanup_and_verify_ts_policy_rules_with(|program, args| {
            assert_eq!(program, "ip");
            let rules = if args[0] == "-4" { &mut v4_rules } else { &mut v6_rules };
            if args.get(2) == Some(&"show") {
                return Ok(rules.join("\n"));
            }
            assert_eq!(args.get(2), Some(&"del"));
            deleted.push(args.join(" "));
            let pref = format!("{}:", args[4]);
            rules.retain(|line| !line.starts_with(&pref));
            Ok(String::new())
        })
        .unwrap();
        assert_eq!(deleted.len(), 6);
        assert!(v4_rules.iter().any(|l| l.starts_with("5120:")));
        assert!(v4_rules.iter().any(|l| l.starts_with("18640:")));
        assert!(!v4_rules.iter().any(|l| l.starts_with("5210:") || l.starts_with("5270:")));
        assert!(!v6_rules.iter().any(|l| l.starts_with("5210:") || l.starts_with("5270:")));

        // Unparseable Tailscale 5210 rule fails closed.
        let unparseable = cleanup_and_verify_ts_policy_rules_with(|_, args| {
            if args[0] == "-4" && args.get(2) == Some(&"show") {
                Ok("5210:\tfrom all not fwmark 0x80000/0xff0000 lookup main\n".into())
            } else {
                Ok(String::new())
            }
        });
        assert!(unparseable.is_err());

        // Failed delete fails closed (journal stays intact in deactivate_kernel_tun_with).
        let surviving = cleanup_and_verify_ts_policy_rules_with(|_, args| {
            if args.get(2) == Some(&"show") {
                Ok("5210:\tfrom all fwmark 0x80000/0xff0000 lookup main\n".into())
            } else {
                Err("RTNETLINK answers: Operation not permitted".into())
            }
        });
        assert!(surviving.is_err());

        // Direct /proc enumeration rejects empty readable procfs directories.
        let empty_proc = std::env::temp_dir().join(format!("zte-ts-empty-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&empty_proc);
        std::fs::create_dir_all(&empty_proc).unwrap();
        assert!(
            list_tailscaled_pids_in(&empty_proc).is_err(),
            "empty readable proc_root must fail closed rather than returning Ok([])"
        );
        std::fs::remove_dir_all(&empty_proc).unwrap();

        // Foreign rule with a different mask (`0x80000/0x80000`) MUST survive
        // untouched in both IPv4 and IPv6 without issuing any `ip rule del`.
        let mut foreign_deleted = Vec::new();
        cleanup_and_verify_ts_policy_rules_with(|_, args| {
            if args.get(2) == Some(&"show") {
                Ok("0:\tfrom all lookup local\n5210:\tfrom all fwmark 0x80000/0x80000 lookup main\n32766:\tfrom all lookup main\n".into())
            } else {
                foreign_deleted.push(args.join(" "));
                Ok(String::new())
            }
        })
        .expect("foreign 0x80000/0x80000 rule must not error or be deleted");
        assert!(
            foreign_deleted.is_empty(),
            "foreign 0x80000/0x80000 rule must never be deleted: {foreign_deleted:?}"
        );

        // When policy-rule cleanup fails, deactivate_kernel_tun_with MUST NOT
        // release the NetPlane journal.
        let mgr = test_manager(true, None);
        let dir = std::env::temp_dir().join(format!("zte-ts-deact-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let journal = dir.join("network.json");
        std::fs::write(&journal, r#"{"boot":"b1","undo":[]}"#).unwrap();
        mgr.deactivate_kernel_tun_with(|| Err("5210 cleanup failed".into()));
        assert!(
            journal.exists(),
            "failed policy-rule cleanup must retain the netplane journal"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn userspace_cold_start_scrub_clears_saved_exit_node_or_fails_closed() {
        // 1. Persisted exit routes (`0.0.0.0/0`, `::/0`) trigger isolated clear
        //    on child #1, stop child #1, and require a SECOND isolated cold-load
        //    child #2 to read clean routes from disk before certifying `Clear`.
        let mut cleared = false;
        let spawns = std::sync::atomic::AtomicUsize::new(0);
        let mut stops = 0usize;
        let ok = ensure_userspace_exit_node_cleared_with(
            || {
                let n = spawns.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(n)
            },
            |_| PreflightWait::Ready,
            || {
                if spawns.load(Ordering::SeqCst) == 1 {
                    Some(vec!["192.168.0.0/24".into(), "0.0.0.0/0".into(), "::/0".into()])
                } else {
                    Some(vec!["192.168.0.0/24".into()])
                }
            },
            || {
                cleared = true;
                Ok(())
            },
            |_| {
                stops += 1;
                true
            },
        );
        assert_eq!(ok, UserspaceScrubOutcome::Clear);
        assert!(cleared);
        assert_eq!(
            spawns.load(Ordering::SeqCst),
            2,
            "must spawn a second isolated child for cold-load disk verification"
        );
        assert_eq!(stops, 2, "must confirm exit of both isolated children");

        // 2. Simulated silent disk-write failure (Tailscale updated memory on
        //    child #1, but child #2 cold-loading disk still sees `0.0.0.0/0`):
        //    MUST fail closed so userspace daemon will NOT spawn or cache fp.
        let mut fail_spawns = 0usize;
        let still_on_disk = ensure_userspace_exit_node_cleared_with(
            || {
                fail_spawns += 1;
                Ok(fail_spawns)
            },
            |_| PreflightWait::Ready,
            || Some(vec!["0.0.0.0/0".into()]),
            || Ok(()),
            |_| true,
        );
        assert_eq!(fail_spawns, 2);
        assert!(matches!(still_on_disk, UserspaceScrubOutcome::Failed(_)));

        // 3. Already-clean persisted profile requires only 1 cold-load check.
        let mut clean_spawns = 0usize;
        let already_clean = ensure_userspace_exit_node_cleared_with(
            || {
                clean_spawns += 1;
                Ok(clean_spawns)
            },
            |_| PreflightWait::Ready,
            || Some(vec!["192.168.0.0/24".into()]),
            || panic!("already clean profile must not run clear CLI"),
            |_| true,
        );
        assert_eq!(already_clean, UserspaceScrubOutcome::Clear);
        assert_eq!(clean_spawns, 1);

        // 4. Unconfirmed child exit blocks replacement daemon startup.
        let stuck = ensure_userspace_exit_node_cleared_with(
            || Ok(()),
            |_| PreflightWait::Ready,
            || Some(Vec::new()),
            || Ok(()),
            |_| false,
        );
        assert!(matches!(stuck, UserspaceScrubOutcome::ChildUnconfirmed(_)));
    }

    #[test]
    fn child_dns_isolation_enforcer_stops_kernel_and_userspace_children_when_delivery_lost() {
        // 1. Mount loss stops child immediately (both Kernel and Userspace).
        for mode in [TunMode::Kernel, TunMode::Userspace] {
            let act = check_child_dns_isolation_with(
                mode,
                || Err("detached mount".into()),
                || panic!("must not continue past mount loss"),
                || panic!("must not restart DNS after mount loss"),
                || None,
                |_| panic!("must not check DNAT after mount loss"),
            );
            assert!(matches!(act, ChildIsolationAction::StopChild { clean: true, .. }));
        }

        // 2. Kernel fallback DNAT repair failure stops the child (closing PeerAPI).
        let kernel_dnat_lost = check_child_dns_isolation_with(
            TunMode::Kernel,
            || Ok(()),
            || true,
            || panic!("clean DNS still running"),
            || Some(ids::CLEAN_DNS_FALLBACK_PORT),
            |port| Err(format!("dns_out port {port:?} repair failed")),
        );
        assert!(matches!(
            kernel_dnat_lost,
            ChildIsolationAction::StopChild { clean: false, .. }
        ));

        // 3. Kernel restart onto direct port 53 (`None`) MUST confirm withdrawal
        //    of any previous fallback redirect and stop the child if stale DNAT remains.
        let kernel_stale_dnat = check_child_dns_isolation_with(
            TunMode::Kernel,
            || Ok(()),
            || false,
            || Ok(None),
            || Some(ids::CLEAN_DNS_FALLBACK_PORT),
            |port| {
                assert_eq!(port, None);
                Err("stale dns_out redirect still present".into())
            },
        );
        assert!(matches!(
            kernel_stale_dnat,
            ChildIsolationAction::StopChild { clean: false, .. }
        ));

        // 4. Kernel fallback DNAT repair success keeps the child healthy.
        let kernel_dnat_ok = check_child_dns_isolation_with(
            TunMode::Kernel,
            || Ok(()),
            || true,
            || panic!("clean DNS still running"),
            || Some(ids::CLEAN_DNS_FALLBACK_PORT),
            |port| {
                assert_eq!(port, Some(ids::CLEAN_DNS_FALLBACK_PORT));
                Ok(())
            },
        );
        assert_eq!(kernel_dnat_ok, ChildIsolationAction::Healthy);

        // 5. Userspace child stops immediately if Clean DNS dies and restarts
        //    onto a fallback DNAT port OR if a stale `dns_out` redirect stays active.
        let userspace_fallback = check_child_dns_isolation_with(
            TunMode::Userspace,
            || Ok(()),
            || false,
            || Ok(Some(ids::CLEAN_DNS_FALLBACK_PORT)),
            || None,
            |_| panic!("userspace rejects fallback port before ensure_dnat"),
        );
        assert!(matches!(
            userspace_fallback,
            ChildIsolationAction::StopChild { clean: false, .. }
        ));
        let userspace_stale_dnat = check_child_dns_isolation_with(
            TunMode::Userspace,
            || Ok(()),
            || true,
            || panic!("already running"),
            || None,
            |port| {
                assert_eq!(port, None);
                Err("stale dns_out redirect still active".into())
            },
        );
        assert!(matches!(
            userspace_stale_dnat,
            ChildIsolationAction::StopChild { clean: false, .. }
        ));

        // 6. Userspace child with intact mount, direct port-53 Clean DNS, and
        //    no stale fallback redirect stays healthy.
        let userspace_ok = check_child_dns_isolation_with(
            TunMode::Userspace,
            || Ok(()),
            || true,
            || panic!("already running"),
            || None,
            |port| {
                assert_eq!(port, None);
                Ok(())
            },
        );
        assert_eq!(userspace_ok, ChildIsolationAction::Healthy);
    }
}
