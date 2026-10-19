//! eSIM profile management with lpac (GSMA SGP.22 LPA: ES10 to the card over QMI-over-QRTR,
//! ES9+ to the operator's SM-DP+ over HTTPS).
//!
//! lpac is not part of this binary. It is a separately built private bundle (recipe in
//! `lpac-qrtr-build/`) copied to `ZTE_AGENT_LPAC_DIR` (default `/data/lpac`). The agent runs at
//! most one lpac process at a time, with a hard time limit, and only these commands:
//! `chip info`, `profile list`, `profile enable <iccid> 1`, `profile delete <iccid>`,
//! `profile nickname <iccid> [name]`, `profile download -p -a <code> [-c <code>]`,
//! `notification list` and `notification process -r <seq>`. Every run holds the agent's flag
//! and a `flock` on /tmp/lpac.lock, shared with lpac runs by hand.
//!
//! A download runs in the background. With preview on (the default) lpac stops after the
//! operator's server has sent the profile metadata and waits for one answer character on
//! stdin; the app shows the operator/profile name and answers through `/download/confirm`.
//!
//! Verified on a U60 Pro with a 9eSIM B1 (2026-10-18): listing leaves the connection alone;
//! enabling another profile (refresh flag set) makes the modem re-read the SIM, the firmware
//! picks the APN from its ICCID list, and WAN is down for roughly 20–45 s while it reattaches.
//!
//! While the modem reloads the SIM (a few seconds after `enable`) the eUICC's management
//! application cannot be selected: lpac fails in `euicc_init` with QMI error 80
//! (`SimFileNotFound`), seen live 3 times in 14 switches. So the agent keeps the last good
//! profile list, answers reads from it while a switch reloads the SIM, and re-reads the card
//! itself once the SIM is ready. Each switch is then verified step by step: card, modem
//! identity (`get_sim_info`), data connection.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::cache;
use crate::conn_watchdog::unix_now;
use crate::handlers::AppState;

const DEFAULT_DIR: &str = "/data/lpac";
/// Every card-only lpac command observed on the router finished in under 4 s.
const CARD_LIMIT: Duration = Duration::from_secs(30);
/// Downloads talk to the operator's server, wait for the user's confirmation and write the
/// profile to the card.
const DOWNLOAD_LIMIT: Duration = Duration::from_secs(300);
/// An unanswered preview is declined so the server session is cancelled cleanly.
const PREVIEW_LIMIT: Duration = Duration::from_secs(120);
/// lpac only notices SIGINT between steps; a step blocked on the network is killed after this.
const CANCEL_GRACE: Duration = Duration::from_secs(15);
/// A finished download's result is reported for this long, then the status reads `idle` again.
const RESULT_KEEP_SECS: u64 = 600;
/// lpac prints one JSON line per message; profile icons make `profile list` the largest.
const MAX_OUTPUT: u64 = 512 * 1024;
/// After a switch the WAN is down while the modem reattaches; the connectivity policies hold off.
pub const SWITCH_GUARD_SECS: u64 = 300;
/// The firmware's SIM reload and radio restart take about 3–8 s after `enable`.
const RELOAD_SETTLE: Duration = Duration::from_secs(5);
/// How long the card may stay unreadable after a switch before it is reported unavailable.
const CARD_CONFIRM_LIMIT: Duration = Duration::from_secs(60);
/// How long the modem has to load the new identity and connect data after a switch.
const SWITCH_VERIFY_LIMIT: Duration = Duration::from_secs(150);
const SWITCH_POLL: Duration = Duration::from_secs(3);
/// One receipt (ES9+ HandleNotification) to one operator server.
const RECEIPT_LIMIT: Duration = Duration::from_secs(45);
/// Pause between "data connected" after a switch and sending its receipts (DNS and routes settle).
const RECEIPT_AFTER_SWITCH: Duration = Duration::from_secs(5);
/// Second try for receipts a switch left that failed on the first.
const RECEIPT_SECOND_TRY: Duration = Duration::from_secs(30);
/// Pending receipts are retried this often while the router has mobile data.
const RECEIPT_RETRY: Duration = Duration::from_secs(600);
/// After this many failed attempts a receipt is left on the card and reported, not retried.
const RECEIPT_MAX_ATTEMPTS: u32 = 10;
/// Retry rounds before the background retry stops (about 4 hours); "send now" restarts it.
const RECEIPT_MAX_ROUNDS: u32 = 24;
/// SGP.22 profileNickname is a UTF8String of at most 64 bytes.
const NICKNAME_MAX_BYTES: usize = 64;
/// Shared with manual lpac runs over SSH (`flock -n /tmp/lpac.lock …`).
const DEFAULT_LOCK_PATH: &str = "/tmp/lpac.lock";

pub struct Esim {
    inner: Arc<Inner>,
}

struct Inner {
    /// lpac holds a logical channel to the card while it runs: never two at once.
    busy: AtomicBool,
    /// Unix seconds of the last successful profile switch (0 = none).
    switched_at: AtomicU64,
    download: Mutex<Download>,
    /// The running download's lpac: pid for cancel, stdin for the preview answer.
    child: ChildIo,
    /// Last good profile list, and whether it may be out of date.
    inventory: Mutex<Inventory>,
    /// The last profile switch, verified card → modem → data.
    switch: Mutex<Switch>,
    /// Identifies this agent run (start time, ms): clients must drop cached state when it changes.
    instance: u64,
    /// Operator receipts (SGP.22 notifications) waiting on the card.
    receipts: Mutex<Receipts>,
    /// File lock shared with lpac runs outside the agent.
    lock_path: PathBuf,
}

/// Pending operator receipts: install/enable/disable/delete notifications the card keeps until
/// they reach the operator's server. lpac's `-a` stops at the first failure, so each receipt
/// is sent on its own and counts its own attempts.
#[derive(Debug, Default)]
struct Receipts {
    /// As last listed from the card (`None` = not listed yet).
    pending: Option<Vec<Receipt>>,
    listed_at: u64,
    last_attempt_at: u64,
    last_sent_at: u64,
    /// A background retry loop is running.
    retrying: bool,
}

#[derive(Clone, Debug, PartialEq)]
struct Receipt {
    seq: u64,
    operation: String,
    address: String,
    iccid: Option<String>,
    attempts: u32,
    last_error: Option<String>,
}

impl Receipts {
    /// Replaces the list with a fresh card read, keeping attempt counts for receipts still there.
    fn merge(&mut self, fresh: Vec<Receipt>, now: u64) {
        let old = self.pending.take().unwrap_or_default();
        let merged = fresh
            .into_iter()
            .map(|mut r| {
                if let Some(o) = old.iter().find(|o| o.seq == r.seq) {
                    r.attempts = o.attempts;
                    r.last_error = o.last_error.clone();
                }
                r
            })
            .collect();
        self.pending = Some(merged);
        self.listed_at = now;
    }

    fn retryable(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|p| p.iter().any(|r| r.attempts < RECEIPT_MAX_ATTEMPTS))
    }

    fn view(&self, stale: bool) -> Value {
        let items: Vec<Value> = self
            .pending
            .iter()
            .flatten()
            .map(|r| {
                json!({
                    "seq": r.seq,
                    "operation": r.operation,
                    "address": r.address,
                    "iccid": r.iccid,
                    "attempts": r.attempts,
                    "last_error": r.last_error,
                    "gave_up": r.attempts >= RECEIPT_MAX_ATTEMPTS,
                })
            })
            .collect();
        json!({
            "count": self.pending.as_ref().map(Vec::len),
            "pending": items,
            "listed_at": self.listed_at,
            "last_attempt_at": self.last_attempt_at,
            "last_sent_at": self.last_sent_at,
            "retrying": self.retrying,
            "stale": stale,
        })
    }
}

fn receipt_views(data: &Value) -> Vec<Receipt> {
    data.as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|n| {
                    Some(Receipt {
                        seq: n["seqNumber"].as_u64()?,
                        operation: n["profileManagementOperation"].as_str().unwrap_or("").to_string(),
                        address: n["notificationAddress"].as_str().unwrap_or("").to_string(),
                        iccid: n["iccid"].as_str().map(str::to_string),
                        attempts: 0,
                        last_error: None,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Last successful profile list.
#[derive(Debug, Default)]
struct Inventory {
    profiles: Option<Vec<Value>>,
    observed_at: u64,
    /// Bumped whenever the card's contents or selection change (switch, delete, download).
    generation: u64,
    /// A switch is reloading the SIM: reads are answered from this list without touching the card.
    reloading: bool,
    error: Option<ReadError>,
    /// EID of the card this list belongs to (learned from `chip info`).
    eid: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct ReadError {
    /// "sim_reloading", "management_unavailable", "read_failed" or "not_installed".
    kind: &'static str,
    message: String,
    at: u64,
}

impl Inventory {
    /// Records the card's EID. A different EID means the card was swapped: the list and its
    /// error belong to the old card and are dropped. Returns true in that case.
    fn note_card(&mut self, eid: &str) -> bool {
        if eid.is_empty() {
            return false;
        }
        match &self.eid {
            Some(known) if known != eid => {
                *self = Inventory {
                    eid: Some(eid.to_string()),
                    generation: self.generation + 1,
                    ..Inventory::default()
                };
                true
            }
            Some(_) => false,
            None => {
                self.eid = Some(eid.to_string());
                false
            }
        }
    }

    fn record(&mut self, profiles: Vec<Value>, now: u64) {
        self.profiles = Some(profiles);
        self.observed_at = now;
        self.error = None;
    }

    /// `updating`: a newer list is coming (switch reload or another eSIM operation running).
    /// `stale`: the list is older than the latest attempt to read the card.
    fn view(&self, instance: u64, busy: bool) -> Value {
        let profiles = self.profiles.clone().unwrap_or_default();
        json!({
            "profiles": profiles,
            "enabled_iccid": enabled_iccid(&profiles),
            "observed_at": self.observed_at,
            "generation": self.generation,
            "agent_instance": instance,
            "updating": self.reloading || busy,
            "stale": self.reloading || busy || self.error.is_some(),
            "error": self.error.as_ref().map(|e| json!({"kind": e.kind, "message": e.message, "at": e.at})),
        })
    }
}

/// The last profile switch. `state` moves reloading → card_confirmed → modem_confirmed and ends
/// as "connected", "no_data" (applied, no data connection), "modem_unconfirmed" (card switched,
/// modem kept the old identity), "card_unconfirmed" (card unreadable) or "not_applied".
#[derive(Clone, Debug, Default, PartialEq)]
struct Switch {
    state: &'static str,
    target: String,
    previous: Option<String>,
    generation: u64,
    started_at: u64,
    card_confirmed_at: u64,
    modem_confirmed_at: u64,
    connected_at: u64,
    finished_at: u64,
    note: Option<String>,
}

impl Switch {
    fn finish(&mut self, state: &'static str, now: u64) {
        self.state = state;
        self.finished_at = now;
    }

    fn view(&self) -> Value {
        json!({
            "state": if self.state.is_empty() { "idle" } else { self.state },
            "target_iccid": if self.target.is_empty() { Value::Null } else { json!(self.target) },
            "previous_iccid": self.previous,
            "generation": self.generation,
            "started_at": self.started_at,
            "card_confirmed_at": self.card_confirmed_at,
            "modem_confirmed_at": self.modem_confirmed_at,
            "connected_at": self.connected_at,
            "finished_at": self.finished_at,
            "note": self.note,
        })
    }
}

#[derive(Default)]
struct ChildIo {
    /// 0 when no lpac runs. Held while signalling and while reaping, so a cancel can never
    /// reach a pid that has been reaped and reused.
    pid: Mutex<libc::pid_t>,
    stdin: Mutex<Option<ChildStdin>>,
}

impl ChildIo {
    /// Answers lpac's preview prompt (`y` installs, anything else cancels).
    fn answer(&self, accept: bool) -> bool {
        let mut slot = self.stdin.lock().unwrap();
        let Some(stdin) = slot.as_mut() else { return false };
        let ok = stdin.write_all(if accept { b"y\n" } else { b"n\n" }).is_ok();
        *slot = None; // lpac reads one character; EOF afterwards
        ok
    }

    /// SIGINT makes lpac cancel the session with the card and the server, then exit.
    fn interrupt(&self) -> bool {
        self.signal(libc::SIGINT)
    }

    /// Signals lpac's whole process group (it is spawned as a group leader).
    fn signal(&self, sig: libc::c_int) -> bool {
        let pid = self.pid.lock().unwrap();
        // SAFETY: a non-zero pid is our lpac child, not yet reaped (see `pid`), so its group
        // id is ours to signal.
        *pid > 0 && unsafe { libc::kill(-*pid, sig) } == 0
    }
}

/// State of the last profile download, polled by the app.
#[derive(Clone, Debug, Default, PartialEq)]
struct Download {
    /// "idle", "running", "confirm" (waiting for the user), "cancelling", "done", "failed" or
    /// "cancelled".
    state: &'static str,
    /// Last lpac progress step, e.g. `es9p_get_bound_profile_package`.
    step: String,
    provider: Option<String>,
    name: Option<String>,
    iccid: Option<String>,
    error: Option<String>,
    started_at: u64,
    finished_at: u64,
}

impl Download {
    fn is_finished(&self) -> bool {
        matches!(self.state, "done" | "failed" | "cancelled")
    }

    /// Forgets a finished result once it is older than `RESULT_KEEP_SECS`.
    fn expire(&mut self, now: u64) {
        if self.is_finished() && now.saturating_sub(self.finished_at) >= RESULT_KEEP_SECS {
            *self = Download::default();
        }
    }

    fn is_cancelling(&self, started_at: u64) -> bool {
        self.state == "cancelling" && self.started_at == started_at
    }

    fn view(&self) -> Value {
        json!({
            "state": if self.state.is_empty() { "idle" } else { self.state },
            "step": self.step,
            "provider": self.provider,
            "name": self.name,
            "iccid": self.iccid,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        })
    }

    /// Records a progress line; `es8p_metadata_parse` carries the operator's profile metadata.
    fn progress(&mut self, line: &Value) {
        if line["type"] != "progress" {
            return;
        }
        // Cancelling the session is lpac's cleanup after a failure or cancel: keep the step that
        // failed, so "failed at" names it.
        if let Some(step) = line["payload"]["message"].as_str().filter(|s| !s.ends_with("_cancel_session")) {
            self.step = step.to_string();
            if step == "preview" && self.state == "running" {
                self.state = "confirm";
            }
        }
        let meta = &line["payload"]["data"];
        if meta.is_object() {
            if let Some(p) = meta["serviceProviderName"].as_str() {
                self.provider = Some(p.to_string());
            }
            if let Some(n) = meta["profileName"].as_str() {
                self.name = Some(n.to_string());
            }
        }
    }
}

/// Released on drop, including when a download thread ends. Holds the shared file lock too,
/// so an lpac started by hand over SSH (with `flock -n`) and the agent never overlap.
struct BusyGuard {
    inner: Arc<Inner>,
    _lock: Option<std::fs::File>,
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.inner.busy.store(false, Ordering::Release);
    }
}

impl Esim {
    pub fn new() -> Self {
        let lock = std::env::var("ZTE_AGENT_LPAC_LOCK").unwrap_or_else(|_| DEFAULT_LOCK_PATH.into());
        Self::with_lock_path(PathBuf::from(lock))
    }

    fn with_lock_path(lock_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(Inner {
                busy: AtomicBool::new(false),
                switched_at: AtomicU64::new(0),
                download: Mutex::new(Download::default()),
                child: ChildIo::default(),
                inventory: Mutex::new(Inventory::default()),
                switch: Mutex::new(Switch::default()),
                instance: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or_default(),
                receipts: Mutex::new(Receipts::default()),
                lock_path,
            }),
        }
    }

    fn acquire(&self) -> Option<BusyGuard> {
        acquire(&self.inner)
    }

    fn reloading(&self) -> bool {
        self.inner.inventory.lock().unwrap().reloading
    }

    /// Whether a profile switch happened within `SWITCH_GUARD_SECS` (busy guard for policies).
    pub fn recently_switched(&self, now: u64) -> bool {
        let at = self.inner.switched_at.load(Ordering::Relaxed);
        at != 0 && now.saturating_sub(at) < SWITCH_GUARD_SECS
    }
}

fn error(status: u16, message: &str) -> (u16, Value) {
    (status, json!({"ok": false, "error": message}))
}

fn acquire(inner: &Arc<Inner>) -> Option<BusyGuard> {
    inner
        .busy
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .ok()?;
    let lock = match file_lock(&inner.lock_path) {
        Ok(lock) => lock,
        Err(()) => {
            // Someone else (an lpac run by hand) holds the card.
            inner.busy.store(false, Ordering::Release);
            return None;
        }
    };
    Some(BusyGuard { inner: Arc::clone(inner), _lock: lock })
}

/// Non-blocking exclusive `flock`. `Ok(None)` when the lock file cannot be created at all (the
/// agent then relies on its own flag only); `Err` when another process holds the lock.
fn file_lock(path: &Path) -> Result<Option<std::fs::File>, ()> {
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
    else {
        return Ok(None);
    };
    // SAFETY: `file` is an open descriptor owned by this function.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(Some(file))
    } else {
        Err(())
    }
}

fn busy() -> (u16, Value) {
    error(409, "eSIM manager busy; retry shortly")
}

fn reloading_reply() -> (u16, Value) {
    error(409, "the SIM is still reloading after the last switch; try again in a moment")
}

/// A failed card read: `euicc_init` / channel-open failures mean the eUICC's management
/// application could not be selected, which is expected while a switch reloads the SIM.
fn classify(message: &str, recently_switched: bool) -> &'static str {
    let channel = message.contains("euicc_init")
        || message.contains("open logical channel")
        || message.contains("SimFileNotFound");
    match (channel, recently_switched) {
        (true, true) => "sim_reloading",
        (true, false) => "management_unavailable",
        _ => "read_failed",
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /api/esim/profiles — a fresh read of the card, or the last good list (marked `updating`
/// / `stale`, with the read error) while a switch reloads the SIM, another eSIM operation runs,
/// or the read fails.
pub fn profiles(state: &AppState) -> (u16, Value) {
    let inner = &state.esim.inner;
    if state.esim.reloading() {
        return (200, json!({"ok": true, "data": inner.inventory.lock().unwrap().view(inner.instance, false)}));
    }
    let Some(_guard) = state.esim.acquire() else {
        let inv = inner.inventory.lock().unwrap();
        return if inv.profiles.is_some() {
            (200, json!({"ok": true, "data": inv.view(inner.instance, true)}))
        } else {
            busy()
        };
    };
    let result = lpac(&["profile", "list"], CARD_LIMIT, &|_| {}, None);
    if result.is_ok() && inner.receipts.lock().unwrap().pending.is_none() {
        // First good read since the agent started: learn whether receipts are waiting.
        let _ = list_receipts(inner);
        ensure_receipt_retry(inner);
    }
    let now = unix_now();
    let mut inv = inner.inventory.lock().unwrap();
    match result {
        Ok(data) => inv.record(profile_views(&data), now),
        Err(e) => {
            let kind = match &e {
                LpacError::NotInstalled(_) => "not_installed",
                LpacError::Failed(m) => classify(m, state.esim.recently_switched(now)),
            };
            inv.error = Some(ReadError { kind, message: e.message(), at: now });
            if inv.profiles.is_none() {
                let (status, mut body) = e.reply();
                body["kind"] = json!(kind);
                return (status, body);
            }
        }
    }
    let mut view = inv.view(inner.instance, false);
    drop(inv);
    view["pending_receipts"] = json!(inner.receipts.lock().unwrap().pending.as_ref().map(Vec::len));
    (200, json!({"ok": true, "data": view}))
}

/// GET /api/esim/switch — progress and verified outcome of the last profile switch.
pub fn switch_status(state: &AppState) -> (u16, Value) {
    let view = state.esim.inner.switch.lock().unwrap().view();
    (200, json!({"ok": true, "data": view}))
}

/// GET /api/esim/chip — card identity and capacity, plus which lpac build is installed.
pub fn chip(state: &AppState) -> (u16, Value) {
    let inner = &state.esim.inner;
    let Some(_guard) = state.esim.acquire() else {
        return busy();
    };
    match lpac(&["chip", "info"], CARD_LIMIT, &|_| {}, None) {
        Ok(data) => {
            let changed = inner
                .inventory
                .lock()
                .unwrap()
                .note_card(data["eidValue"].as_str().unwrap_or(""));
            let mut view = chip_view(&data);
            view["card_changed"] = json!(changed);
            view["lpac"] = config().map(|c| build_info(&c.dir)).unwrap_or(Value::Null);
            (200, json!({"ok": true, "data": view}))
        }
        Err(e) => e.reply(),
    }
}

/// Reads the card's EID (guard held) and refuses to continue if it is not the card the saved
/// list belongs to.
fn check_card(inner: &Arc<Inner>) -> Result<Value, (u16, Value)> {
    let data = lpac(&["chip", "info"], CARD_LIMIT, &|_| {}, None).map_err(LpacError::reply)?;
    let eid = data["eidValue"].as_str().unwrap_or("");
    if inner.inventory.lock().unwrap().note_card(eid) {
        eprintln!("[esim] a different eSIM card is in the slot; saved list dropped");
        return Err(error(409, "a different eSIM card is in the slot; reload the profile list"));
    }
    Ok(data)
}

/// `BUILDINFO` (written by `bundle.py`) and the lpac binary's checksum from `SHA256SUMS`.
fn build_info(dir: &Path) -> Value {
    let info: serde_json::Map<String, Value> = std::fs::read_to_string(dir.join("BUILDINFO"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), json!(v.trim())))
        .collect();
    let lpac_sha256 = std::fs::read_to_string(dir.join("SHA256SUMS"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_suffix("  lpac").map(str::to_string));
    json!({
        "build": if info.is_empty() { Value::Null } else { Value::Object(info) },
        "lpac_sha256": lpac_sha256,
    })
}

/// Parses `{"iccid": "..."}` for the mutating profile actions.
fn iccid_body(body: &[u8]) -> Result<String, (u16, Value)> {
    let parsed: Value = serde_json::from_slice(body).map_err(|_| error(400, "invalid JSON"))?;
    parsed["iccid"]
        .as_str()
        .filter(|s| valid_iccid(s))
        .map(str::to_string)
        .ok_or_else(|| error(400, "iccid must be 18–20 digits"))
}

/// POST /api/esim/enable — body `{"iccid": "..."}`. Switches the enabled profile; the WAN drops
/// while the modem reattaches with the new one.
pub fn enable(state: &AppState, body: &[u8]) -> (u16, Value) {
    if !state.auth.has_password() {
        return error(403, "agent password required");
    }
    let iccid = match iccid_body(body) {
        Ok(i) => i,
        Err(reply) => return reply,
    };
    if state.esim.reloading() {
        return reloading_reply();
    }
    let mode = crate::ubus::uci_get("zte_nwinfo.sys_info.operate_mode").ok();
    let policy = state.oos_policy.status();
    if radio_blocks_switch(mode.as_deref(), policy["state"].as_str()) {
        return error(
            409,
            "the modem is in airplane / low-power mode; turn it back on before switching profiles",
        );
    }
    let Some(guard) = state.esim.acquire() else {
        return busy();
    };
    if let Err(reply) = check_card(&state.esim.inner) {
        return reply;
    }
    let list = match lpac(&["profile", "list"], CARD_LIMIT, &|_| {}, None) {
        Ok(data) => profile_views(&data),
        Err(e) => return e.reply(),
    };
    let previous = enabled_iccid(&list);
    if let Err((status, message)) = check_enable_target(&list, &iccid) {
        return error(status, message);
    }
    let result = lpac(&["profile", "enable", &iccid, "1"], CARD_LIMIT, &|_| {}, None);
    drop(guard);
    let inner = &state.esim.inner;
    let now = unix_now();
    // Even a failed or timed-out enable may have switched the card: the background check reads
    // the card once the SIM settles and reports what actually happened.
    let generation = {
        let mut inv = inner.inventory.lock().unwrap();
        inv.record(list, now);
        inv.generation += 1;
        inv.reloading = true;
        inv.generation
    };
    *inner.switch.lock().unwrap() = Switch {
        state: "reloading",
        target: iccid.clone(),
        previous: previous.clone(),
        generation,
        started_at: now,
        note: result.as_ref().err().map(|e| format!("lpac reported: {}", e.message())),
        ..Switch::default()
    };
    inner.switched_at.store(now, Ordering::Relaxed);
    state
        .cache
        .invalidate_with_settle(cache::SIM_INFO, cache::SETTLE_WINDOW);
    let worker = Arc::clone(inner);
    let target = iccid.clone();
    if crate::system::try_spawn_named("esim-switch", move || verify_switch(worker, target)).is_err() {
        let mut inv = inner.inventory.lock().unwrap();
        inv.reloading = false;
        inner.switch.lock().unwrap().finish("card_unconfirmed", now);
    }
    match result {
        Ok(_) => {
            eprintln!(
                "[esim] enabled profile {} (was {})",
                mask(&iccid),
                previous.as_deref().map(mask).unwrap_or_else(|| "none".into())
            );
            (
                200,
                json!({"ok": true, "data": {
                    "enabled_iccid": iccid,
                    "previous_iccid": previous,
                    "reconnecting": true,
                    "generation": generation,
                }}),
            )
        }
        Err(e) => {
            eprintln!("[esim] enable {} uncertain: {}", mask(&iccid), e.message());
            let (status, mut body) = e.reply();
            body["outcome"] = json!("unknown");
            body["hint"] = json!("the agent is checking whether the switch happened: GET /api/esim/switch");
            (status, body)
        }
    }
}

/// Background check after `enable`: waits for the SIM to reload, re-reads the card (retrying
/// while the management application is not selectable), then checks that the modem loaded the
/// new identity and that data connects.
fn verify_switch(inner: Arc<Inner>, target: String) {
    let started = Instant::now();
    std::thread::sleep(RELOAD_SETTLE);
    let mut list = None;
    let mut last_error = String::from("the SIM did not report ready");
    while started.elapsed() < CARD_CONFIRM_LIMIT {
        if sim_ready() != Some(false) {
            if let Some(_guard) = acquire(&inner) {
                match lpac(&["profile", "list"], CARD_LIMIT, &|_| {}, None) {
                    Ok(data) => {
                        list = Some(profile_views(&data));
                        break;
                    }
                    Err(e) => last_error = e.message(),
                }
            }
        }
        std::thread::sleep(SWITCH_POLL);
    }
    let now = unix_now();
    let mut inv = inner.inventory.lock().unwrap();
    inv.reloading = false;
    let Some(list) = list else {
        inv.error = Some(ReadError { kind: "management_unavailable", message: last_error, at: now });
        drop(inv);
        eprintln!("[esim] switch check: card unreadable for {} s", CARD_CONFIRM_LIMIT.as_secs());
        inner.switch.lock().unwrap().finish("card_unconfirmed", now);
        return;
    };
    let enabled = enabled_iccid(&list);
    inv.record(list, now);
    drop(inv);
    if enabled.as_deref() != Some(target.as_str()) {
        eprintln!("[esim] switch check: {} is not enabled on the card", mask(&target));
        inner.switch.lock().unwrap().finish("not_applied", now);
        return;
    }
    {
        let mut sw = inner.switch.lock().unwrap();
        sw.card_confirmed_at = now;
        sw.state = "card_confirmed";
    }
    let connected = loop {
        let now = unix_now();
        let mut sw = inner.switch.lock().unwrap();
        if sw.modem_confirmed_at == 0 && modem_iccid().is_some_and(|m| same_iccid(&m, &target)) {
            sw.modem_confirmed_at = now;
            sw.state = "modem_confirmed";
        }
        if sw.modem_confirmed_at != 0 && data_connected() {
            sw.connected_at = now;
            sw.finish("connected", now);
            eprintln!("[esim] switch to {} verified: card, modem, data", mask(&target));
            break true;
        }
        if started.elapsed() >= SWITCH_VERIFY_LIMIT {
            let outcome = if sw.modem_confirmed_at != 0 { "no_data" } else { "modem_unconfirmed" };
            sw.finish(outcome, now);
            eprintln!("[esim] switch to {} ended as {outcome}", mask(&target));
            break false;
        }
        drop(sw);
        std::thread::sleep(SWITCH_POLL);
    };
    receipts_after_switch(&inner, connected);
}

/// The switch left an enable and a disable receipt on the card. With data up, send them once
/// traffic flows; otherwise list them so the count is right and leave them to the retry loop.
fn receipts_after_switch(inner: &Arc<Inner>, connected: bool) {
    if !connected {
        if let Some(_guard) = acquire_soon(inner) {
            let _ = list_receipts(inner);
        }
        ensure_receipt_retry(inner);
        return;
    }
    std::thread::sleep(RECEIPT_AFTER_SWITCH);
    let sent_all = acquire_soon(inner).is_some_and(|_guard| send_receipts(inner));
    // Right after the attach a request can still stall: one more try before the 10-minute loop.
    if !sent_all {
        std::thread::sleep(RECEIPT_SECOND_TRY);
        if data_connected() {
            if let Some(_guard) = acquire_soon(inner) {
                send_receipts(inner);
            }
        }
    }
    ensure_receipt_retry(inner);
}

/// Background work takes the card when it's free within 10 s; the app usually re-reads the
/// list as a switch completes.
fn acquire_soon(inner: &Arc<Inner>) -> Option<BusyGuard> {
    (0..10).find_map(|i| {
        if i > 0 {
            std::thread::sleep(Duration::from_secs(1));
        }
        acquire(inner)
    })
}

/// `Some(true)` when the modem reports the SIM ready; `None` if the firmware did not answer.
fn sim_ready() -> Option<bool> {
    let info = crate::ubus::call("zwrt_zte_mdm.api", "get_sim_info", Some("{}")).ok()?;
    let s = info["sim_states"].as_str()?.to_ascii_lowercase();
    Some(s.contains("ready") && !s.contains("not"))
}

/// ICCID of the subscription the modem has loaded.
fn modem_iccid() -> Option<String> {
    let info = crate::ubus::call("zwrt_zte_mdm.api", "get_sim_info", Some("{}")).ok()?;
    info["sim_iccid"].as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

fn data_connected() -> bool {
    crate::ubus::call(
        "zwrt_data",
        "get_wwaniface",
        Some(r#"{"source_module":"zte_topsw_data","cid":1}"#),
    )
    .ok()
    .and_then(|v| v["connect_status"].as_str().map(str::to_string))
    .is_some_and(|s| s.contains("connected") && !s.contains("disconnected"))
}

/// A switch while the user parked the modem would change the card but never attach. When the
/// no-service policy parked it (`lpm` / `probing`), switching to another network is the way out,
/// and the firmware's SIM reload brings the radio back online. Unknown mode: allowed.
fn radio_blocks_switch(operate_mode: Option<&str>, policy_state: Option<&str>) -> bool {
    let online = operate_mode.is_none_or(|m| m.trim().eq_ignore_ascii_case("ONLINE"));
    !online && !matches!(policy_state, Some("lpm" | "probing"))
}

/// Firmware and lpac may differ in a trailing filler `F`.
fn same_iccid(a: &str, b: &str) -> bool {
    let trim = |s: &str| s.trim().trim_end_matches(['F', 'f']).to_string();
    !a.trim().is_empty() && trim(a) == trim(b)
}

/// POST /api/esim/delete — body `{"iccid": "..."}`. Permanently removes a disabled profile.
pub fn delete(state: &AppState, body: &[u8]) -> (u16, Value) {
    if !state.auth.has_password() {
        return error(403, "agent password required");
    }
    let iccid = match iccid_body(body) {
        Ok(i) => i,
        Err(reply) => return reply,
    };
    if state.esim.reloading() {
        return reloading_reply();
    }
    let Some(_guard) = state.esim.acquire() else {
        return busy();
    };
    if let Err(reply) = check_card(&state.esim.inner) {
        return reply;
    }
    let list = match lpac(&["profile", "list"], CARD_LIMIT, &|_| {}, None) {
        Ok(data) => profile_views(&data),
        Err(e) => return e.reply(),
    };
    if let Err((status, message)) = check_delete_target(&list, &iccid) {
        return error(status, message);
    }
    if let Err(e) = lpac(&["profile", "delete", &iccid], CARD_LIMIT, &|_| {}, None) {
        return e.reply();
    }
    eprintln!("[esim] deleted profile {}", mask(&iccid));
    {
        let mut inv = state.esim.inner.inventory.lock().unwrap();
        let remaining = list.into_iter().filter(|p| p["iccid"] != iccid.as_str()).collect();
        inv.record(remaining, unix_now());
        inv.generation += 1;
    }
    let notified = send_receipts(&state.esim.inner);
    ensure_receipt_retry(&state.esim.inner);
    (
        200,
        json!({"ok": true, "data": {"deleted_iccid": iccid, "operator_notified": notified}}),
    )
}

/// POST /api/esim/download — body `{"activation_code": "LPA:1$...", "confirmation_code": "..."}`.
/// Starts the download in the background (it can take a minute); poll GET /api/esim/download.
pub fn download_start(state: &AppState, body: &[u8]) -> (u16, Value) {
    if !state.auth.has_password() {
        return error(403, "agent password required");
    }
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return error(400, "invalid JSON"),
    };
    let code = parsed["activation_code"].as_str().unwrap_or("").trim();
    let preview = parsed["preview"].as_bool().unwrap_or(true);
    let confirmation = parsed["confirmation_code"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let needs_confirmation = match check_activation_code(code) {
        Ok(needs) => needs,
        Err(message) => return error(400, message),
    };
    if let Some(c) = confirmation {
        if c.len() > 64 || c.chars().any(|ch| ch.is_control()) {
            return error(400, "confirmation code is too long or contains control characters");
        }
    } else if needs_confirmation {
        return error(400, "this activation code needs a confirmation code from the operator");
    }
    if state.esim.reloading() {
        return reloading_reply();
    }
    if !data_connected() {
        return error(
            409,
            "the router has no mobile data connection; downloads use the router's own internet",
        );
    }
    let Some(guard) = state.esim.acquire() else {
        return busy();
    };
    let free_nvm = match check_card(&state.esim.inner) {
        Ok(chip) => chip["EUICCInfo2"]["extCardResource"]["freeNonVolatileMemory"].clone(),
        Err(reply) => return reply,
    };
    let inner = Arc::clone(&state.esim.inner);
    *inner.download.lock().unwrap() = Download {
        state: "running",
        step: "starting".into(),
        started_at: unix_now(),
        ..Download::default()
    };
    let mut args: Vec<String> = vec!["profile".into(), "download".into()];
    if preview {
        args.push("-p".into());
    }
    args.extend(["-a".into(), code.into()]);
    if let Some(c) = confirmation {
        args.extend(["-c".into(), c.into()]);
    }
    let spawned = crate::system::try_spawn_named("esim-download", move || {
        let _guard = guard;
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let result = lpac(
            &refs,
            DOWNLOAD_LIMIT,
            &|line| {
                let asks = {
                    let mut d = inner.download.lock().unwrap();
                    d.progress(line);
                    d.state == "confirm"
                };
                if asks {
                    arm_preview_timeout(&inner);
                }
            },
            Some(&inner.child),
        );
        let notified = result.is_ok() && send_receipts(&inner);
        if result.is_ok() {
            inner.inventory.lock().unwrap().generation += 1;
            ensure_receipt_retry(&inner);
        }
        let mut d = inner.download.lock().unwrap();
        d.finished_at = unix_now();
        match result {
            Ok(data) => {
                d.state = "done";
                d.iccid = data["iccid"].as_str().map(str::to_string);
                eprintln!(
                    "[esim] downloaded profile {} (operator notified: {notified})",
                    d.iccid.as_deref().map(mask).unwrap_or_else(|| "?".into())
                );
            }
            Err(e) if d.state == "cancelling" || e.message().starts_with("cancelled") => {
                d.state = "cancelled";
                d.error = d.error.take().or(Some("cancelled".into()));
                eprintln!("[esim] download cancelled at {}", d.step);
            }
            Err(e) => {
                d.state = "failed";
                d.error = Some(e.message());
                eprintln!("[esim] download failed at {}", d.step);
            }
        }
    });
    if spawned.is_err() {
        let mut d = state.esim.inner.download.lock().unwrap();
        d.state = "failed";
        d.error = Some("cannot start the download thread".into());
        return error(503, "cannot start the download thread");
    }
    let mut view = state.esim.inner.download.lock().unwrap().view();
    view["free_nvm_bytes"] = free_nvm;
    (202, json!({"ok": true, "data": view}))
}

/// POST /api/esim/download/confirm — body `{"accept": true|false}`, while the state is "confirm".
pub fn download_confirm(state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return error(400, "invalid JSON"),
    };
    let Some(accept) = parsed["accept"].as_bool() else {
        return error(400, "accept must be true or false");
    };
    let inner = &state.esim.inner;
    let mut d = inner.download.lock().unwrap();
    if d.state != "confirm" {
        return error(409, "no download is waiting for confirmation");
    }
    if !inner.child.answer(accept) {
        return error(409, "the download is no longer waiting");
    }
    if accept {
        d.state = "running";
    } else {
        d.state = "cancelling";
        d.error = Some("declined".into());
    }
    (200, json!({"ok": true, "data": d.view()}))
}

/// POST /api/esim/download/cancel — stops a running download.
pub fn download_cancel(state: &AppState) -> (u16, Value) {
    let inner = &state.esim.inner;
    let mut d = inner.download.lock().unwrap();
    let sent = match d.state {
        "confirm" => inner.child.answer(false),
        "running" => inner.child.interrupt(),
        _ => return error(409, "no download is running"),
    };
    if !sent {
        return error(409, "the download cannot be cancelled now");
    }
    d.state = "cancelling";
    d.error = Some("cancelled".into());
    let view = d.view();
    let started = d.started_at;
    drop(d);
    let inner = Arc::clone(inner);
    let _ = crate::system::try_spawn_named("esim-cancel", move || {
        std::thread::sleep(CANCEL_GRACE);
        if inner.download.lock().unwrap().is_cancelling(started) {
            eprintln!("[esim] download did not stop after SIGINT; killing lpac");
            inner.child.signal(libc::SIGKILL);
        }
    });
    (200, json!({"ok": true, "data": view}))
}

/// Declines the preview if the user has not answered within `PREVIEW_LIMIT`.
fn arm_preview_timeout(inner: &Arc<Inner>) {
    let inner = Arc::clone(inner);
    let started = inner.download.lock().unwrap().started_at;
    let _ = crate::system::try_spawn_named("esim-preview", move || {
        std::thread::sleep(PREVIEW_LIMIT);
        let mut d = inner.download.lock().unwrap();
        if d.state == "confirm" && d.started_at == started && inner.child.answer(false) {
            d.state = "cancelling";
            d.error = Some("not confirmed within 2 minutes".into());
        }
    });
}

/// GET /api/esim/download — state of the last download (a finished result for 10 minutes).
pub fn download_status(state: &AppState) -> (u16, Value) {
    let mut d = state.esim.inner.download.lock().unwrap();
    d.expire(unix_now());
    (200, json!({"ok": true, "data": d.view()}))
}

/// DELETE /api/esim/download — dismisses a finished result (the app's "close" on the result card).
pub fn download_dismiss(state: &AppState) -> (u16, Value) {
    let mut d = state.esim.inner.download.lock().unwrap();
    if !d.is_finished() && !d.state.is_empty() && d.state != "idle" {
        return error(409, "a download is still in progress");
    }
    *d = Download::default();
    (200, json!({"ok": true, "data": d.view()}))
}

/// Lists the receipts waiting on the card (guard held) and merges them into the saved state.
fn list_receipts(inner: &Arc<Inner>) -> Result<usize, String> {
    let data = lpac(&["notification", "list"], CARD_LIMIT, &|_| {}, None).map_err(|e| e.message())?;
    let fresh = receipt_views(&data);
    let n = fresh.len();
    inner.receipts.lock().unwrap().merge(fresh, unix_now());
    Ok(n)
}

/// Sends each pending receipt on its own (guard held) and removes the ones the operator's
/// server accepted. Returns true when nothing is left pending. Without internet they stay on
/// the card for the retry loop.
fn send_receipts(inner: &Arc<Inner>) -> bool {
    if list_receipts(inner).is_err() {
        return false;
    }
    let now = unix_now();
    let todo: Vec<(u64, String)> = {
        let mut r = inner.receipts.lock().unwrap();
        r.last_attempt_at = now;
        r.pending
            .iter()
            .flatten()
            .filter(|x| x.attempts < RECEIPT_MAX_ATTEMPTS)
            .map(|x| (x.seq, x.address.clone()))
            .collect()
    };
    // A server that failed (or hung until the limit) is skipped for the rest of this round, so
    // one unreachable operator can't hold the card for 45 s per receipt.
    let mut failed_servers = std::collections::HashSet::new();
    let mut sent = 0;
    for (seq, address) in todo {
        if failed_servers.contains(&address) {
            continue;
        }
        let arg = seq.to_string();
        let result = lpac(&["notification", "process", "-r", &arg], RECEIPT_LIMIT, &|_| {}, None);
        let mut r = inner.receipts.lock().unwrap();
        match result {
            Ok(_) => {
                if let Some(p) = r.pending.as_mut() {
                    p.retain(|x| x.seq != seq);
                }
                r.last_sent_at = unix_now();
                sent += 1;
            }
            Err(e) => {
                if let Some(x) = r.pending.iter_mut().flatten().find(|x| x.seq == seq) {
                    x.attempts += 1;
                    x.last_error = Some(e.message());
                }
                eprintln!("[esim] operator receipt {seq} to {address} not sent: {}", e.message());
                failed_servers.insert(address);
            }
        }
    }
    if sent > 0 {
        eprintln!("[esim] sent {sent} operator receipt(s)");
    }
    let _ = list_receipts(inner);
    inner.receipts.lock().unwrap().pending.as_ref().is_some_and(Vec::is_empty)
}

/// Starts the background retry if receipts are waiting and no retry loop runs. It tries every
/// `RECEIPT_RETRY` while the router has mobile data and stops when nothing retryable is left.
fn ensure_receipt_retry(inner: &Arc<Inner>) {
    {
        let mut r = inner.receipts.lock().unwrap();
        if r.retrying || !r.retryable() {
            return;
        }
        r.retrying = true;
    }
    let worker = Arc::clone(inner);
    let spawned = crate::system::try_spawn_named("esim-receipts", move || {
        for _ in 0..RECEIPT_MAX_ROUNDS {
            std::thread::sleep(RECEIPT_RETRY);
            if !worker.inventory.lock().unwrap().reloading && data_connected() {
                if let Some(_guard) = acquire(&worker) {
                    send_receipts(&worker);
                }
            }
            if !worker.receipts.lock().unwrap().retryable() {
                break;
            }
        }
        worker.receipts.lock().unwrap().retrying = false;
    });
    if spawned.is_err() {
        inner.receipts.lock().unwrap().retrying = false;
    }
}

/// GET /api/esim/notifications — receipts waiting on the card for the operators' servers.
pub fn notifications(state: &AppState) -> (u16, Value) {
    let inner = &state.esim.inner;
    if state.esim.reloading() {
        return (200, json!({"ok": true, "data": inner.receipts.lock().unwrap().view(true)}));
    }
    let Some(_guard) = state.esim.acquire() else {
        return (200, json!({"ok": true, "data": inner.receipts.lock().unwrap().view(true)}));
    };
    let stale = list_receipts(inner).is_err();
    (200, json!({"ok": true, "data": inner.receipts.lock().unwrap().view(stale)}))
}

/// POST /api/esim/notifications/process — sends pending receipts now (in the background) and
/// restarts the retry loop, including receipts that had given up.
pub fn notifications_process(state: &AppState) -> (u16, Value) {
    if !state.auth.has_password() {
        return error(403, "agent password required");
    }
    if state.esim.reloading() {
        return reloading_reply();
    }
    if !data_connected() {
        return error(409, "the router has no mobile data connection");
    }
    let Some(guard) = state.esim.acquire() else {
        return busy();
    };
    let inner = Arc::clone(&state.esim.inner);
    if let Some(p) = inner.receipts.lock().unwrap().pending.as_mut() {
        for x in p.iter_mut() {
            x.attempts = 0;
        }
    }
    let worker = Arc::clone(&inner);
    let spawned = crate::system::try_spawn_named("esim-receipts-now", move || {
        let _guard = guard;
        send_receipts(&worker);
        drop(_guard);
        ensure_receipt_retry(&worker);
    });
    if spawned.is_err() {
        return error(503, "cannot start the receipt thread");
    }
    (202, json!({"ok": true, "data": inner.receipts.lock().unwrap().view(true)}))
}

/// POST /api/esim/nickname — body `{"iccid": "...", "nickname": "..."}`; an empty nickname
/// clears it.
pub fn nickname(state: &AppState, body: &[u8]) -> (u16, Value) {
    if !state.auth.has_password() {
        return error(403, "agent password required");
    }
    let iccid = match iccid_body(body) {
        Ok(i) => i,
        Err(reply) => return reply,
    };
    let parsed: Value = serde_json::from_slice(body).unwrap_or_default();
    let name = parsed["nickname"].as_str().unwrap_or("").trim().to_string();
    if let Err(message) = check_nickname(&name) {
        return error(400, message);
    }
    if state.esim.reloading() {
        return reloading_reply();
    }
    let Some(_guard) = state.esim.acquire() else {
        return busy();
    };
    if let Err(reply) = check_card(&state.esim.inner) {
        return reply;
    }
    let list = match lpac(&["profile", "list"], CARD_LIMIT, &|_| {}, None) {
        Ok(data) => profile_views(&data),
        Err(e) => return e.reply(),
    };
    if !list.iter().any(|p| p["iccid"] == iccid.as_str()) {
        return error(404, "no profile with this ICCID on the eSIM");
    }
    let mut args = vec!["profile", "nickname", iccid.as_str()];
    if !name.is_empty() {
        args.push(name.as_str());
    }
    if let Err(e) = lpac(&args, CARD_LIMIT, &|_| {}, None) {
        return e.reply();
    }
    let updated: Vec<Value> = list
        .into_iter()
        .map(|mut p| {
            if p["iccid"] == iccid.as_str() {
                p["nickname"] = if name.is_empty() { Value::Null } else { json!(name) };
            }
            p
        })
        .collect();
    let generation = {
        let mut inv = state.esim.inner.inventory.lock().unwrap();
        inv.record(updated, unix_now());
        inv.generation += 1;
        inv.generation
    };
    eprintln!("[esim] renamed profile {}", mask(&iccid));
    (200, json!({"ok": true, "data": {"iccid": iccid, "nickname": name, "generation": generation}}))
}

fn check_nickname(name: &str) -> Result<(), &'static str> {
    if name.len() > NICKNAME_MAX_BYTES {
        return Err("nickname is longer than 64 bytes");
    }
    if name.chars().any(char::is_control) {
        return Err("nickname contains control characters");
    }
    Ok(())
}

fn enabled_iccid(list: &[Value]) -> Option<String> {
    list.iter()
        .find(|p| p["state"] == "enabled")
        .and_then(|p| p["iccid"].as_str())
        .map(str::to_string)
}

/// The profile must exist, be disabled and be an ordinary operator profile.
fn check_enable_target(list: &[Value], iccid: &str) -> Result<(), (u16, &'static str)> {
    let Some(target) = list.iter().find(|p| p["iccid"] == iccid) else {
        return Err((404, "no profile with this ICCID on the eSIM"));
    };
    if target["state"] != "disabled" {
        return Err((409, "this profile is already enabled"));
    }
    if target["class"] != "operational" {
        return Err((400, "only operational profiles can be enabled here"));
    }
    Ok(())
}

/// Deleting is permanent; never the profile the router is using.
fn check_delete_target(list: &[Value], iccid: &str) -> Result<(), (u16, &'static str)> {
    let Some(target) = list.iter().find(|p| p["iccid"] == iccid) else {
        return Err((404, "no profile with this ICCID on the eSIM"));
    };
    if target["state"] != "disabled" {
        return Err((409, "switch to another profile before deleting the active one"));
    }
    Ok(())
}

/// `LPA:1$<SM-DP+ address>$<matching ID>[$<OID>[$<confirmation code required flag>]]`
/// (SGP.22 §4.1). Returns whether the code says a confirmation code is required.
fn check_activation_code(code: &str) -> Result<bool, &'static str> {
    const BAD: &str = "activation code must look like LPA:1$<server>$<matching ID>";
    if code.len() > 512 || code.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(BAD);
    }
    let Some(rest) = code.get(..4).filter(|p| p.eq_ignore_ascii_case("LPA:")).map(|_| &code[4..]) else {
        return Err(BAD);
    };
    let parts: Vec<&str> = rest.split('$').collect();
    if parts.len() < 3 || parts.len() > 5 || parts[0] != "1" {
        return Err(BAD);
    }
    let server_ok = !parts[1].is_empty()
        && parts[1]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
    if !server_ok {
        return Err("the activation code's server address is invalid");
    }
    // lpac accepts only letters, digits and '-' in the matching ID.
    if !parts[2].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err("the activation code's matching ID is invalid");
    }
    Ok(parts.get(4) == Some(&"1"))
}

fn valid_iccid(s: &str) -> bool {
    let digits = s.strip_suffix(['F', 'f']).unwrap_or(s);
    (18..=20).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Last four digits only, for logs.
fn mask(iccid: &str) -> String {
    let tail: String = iccid.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
    format!("…{tail}")
}

// ---------------------------------------------------------------------------
// lpac output → API views
// ---------------------------------------------------------------------------

/// Keeps the fields the app needs; drops icons (base64 images, often several KB).
fn profile_views(data: &Value) -> Vec<Value> {
    data.as_array()
        .map(|items| {
            items
                .iter()
                .map(|p| {
                    json!({
                        "iccid": p["iccid"],
                        "isdp_aid": p["isdpAid"],
                        "state": p["profileState"],
                        "nickname": p["profileNickname"],
                        "provider": p["serviceProviderName"],
                        "name": p["profileName"],
                        "class": p["profileClass"],
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn chip_view(data: &Value) -> Value {
    let info = &data["EUICCInfo2"];
    json!({
        "eid": data["eidValue"],
        "firmware": info["euiccFirmwareVer"],
        "sgp22_version": info["svn"],
        "profile_version": info["profileVersion"],
        "free_nvm_bytes": info["extCardResource"]["freeNonVolatileMemory"],
        "free_ram_bytes": info["extCardResource"]["freeVolatileMemory"],
    })
}

/// The final `{"type":"lpa",...}` line carries the result; earlier lines are progress reports.
fn parse_output(stdout: &str) -> Result<Value, String> {
    let result = stdout
        .lines()
        .rev()
        .filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
        .find(|v| v["type"] == "lpa")
        .ok_or("lpac printed no result")?;
    let payload = &result["payload"];
    if payload["code"].as_i64() == Some(0) {
        return Ok(payload["data"].clone());
    }
    let message = payload["message"].as_str().unwrap_or("lpac error");
    Err(match payload["data"].as_str() {
        Some(reason) if !reason.is_empty() => format!("{message}: {reason}"),
        _ => message.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Running lpac
// ---------------------------------------------------------------------------

enum LpacError {
    NotInstalled(String),
    Failed(String),
}

impl LpacError {
    fn message(&self) -> String {
        match self {
            LpacError::NotInstalled(m) | LpacError::Failed(m) => m.clone(),
        }
    }

    fn reply(self) -> (u16, Value) {
        match self {
            LpacError::NotInstalled(m) => error(503, &m),
            LpacError::Failed(m) => error(502, &m),
        }
    }
}

struct Config {
    dir: PathBuf,
    node: String,
    slot: String,
}

fn config() -> Result<Config, LpacError> {
    let dir = PathBuf::from(std::env::var("ZTE_AGENT_LPAC_DIR").unwrap_or_else(|_| DEFAULT_DIR.into()));
    let number = |name: &str, default: &str| {
        let v = std::env::var(name).unwrap_or_else(|_| default.into());
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(LpacError::NotInstalled(format!("{name} must be a number")));
        }
        Ok(v)
    };
    Ok(Config {
        node: number("ZTE_AGENT_LPAC_QRTR_NODE", "3")?,
        slot: number("ZTE_AGENT_LPAC_UIM_SLOT", "1")?,
        dir,
    })
}

/// The bundle runs as root with access to the SIM: refuse files others could have replaced.
fn check_bundle(dir: &Path) -> Result<(), LpacError> {
    let missing = || {
        LpacError::NotInstalled(format!(
            "lpac is not installed (expected a bundle in {})",
            dir.display()
        ))
    };
    let euid = unsafe { libc::geteuid() };
    for rel in ["", "lpac", "ld-musl-aarch64.so.1", "lib", "driver"] {
        let path = dir.join(rel);
        let meta = std::fs::symlink_metadata(&path).map_err(|_| missing())?;
        if meta.file_type().is_symlink() || meta.uid() != euid || meta.mode() & 0o022 != 0 {
            return Err(LpacError::NotInstalled(format!(
                "{} must be owned by the agent user and not group/world-writable",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Runs lpac with `args`, calling `on_line` for every JSON line it prints (progress reports),
/// and returns the data of the final result line. At `limit` lpac gets SIGINT, which makes a
/// download cancel its session with the card and the server; SIGKILL follows 15 s later.
fn lpac(
    args: &[&str],
    limit: Duration,
    on_line: &(dyn Fn(&Value) + Sync),
    io: Option<&ChildIo>,
) -> Result<Value, LpacError> {
    lpac_in(&config()?, args, limit, on_line, io)
}

fn lpac_in(
    cfg: &Config,
    args: &[&str],
    limit: Duration,
    on_line: &(dyn Fn(&Value) + Sync),
    io: Option<&ChildIo>,
) -> Result<Value, LpacError> {
    check_bundle(&cfg.dir)?;
    let dir = &cfg.dir;
    let mut child = Command::new(dir.join("ld-musl-aarch64.so.1"))
        .arg("--library-path")
        .arg(dir.join("lib"))
        .arg(dir.join("lpac"))
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env("LPAC_APDU", "qmi_qrtr")
        .env("LPAC_APDU_QMI_QRTR_NODE", &cfg.node)
        .env("LPAC_APDU_QMI_UIM_SLOT", &cfg.slot)
        .env("LPAC_HTTP", "curl")
        // Operators' SM-DP+ servers chain to the GSMA eSIM root CI, which no web CA list holds.
        .env("LPAC_HTTP_CA_FILE", dir.join("gsma-ci.pem"))
        .env("GIO_MODULE_DIR", dir.join("no-modules"))
        .env("GIO_USE_VFS", "local")
        .env("GIO_USE_PROXY_RESOLVER", "dummy")
        .stdin(if io.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| LpacError::Failed(format!("cannot start lpac: {e}")))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let pid = child.id() as libc::pid_t;
    if let Some(io) = io {
        *io.stdin.lock().unwrap() = child.stdin.take();
        *io.pid.lock().unwrap() = pid;
    }
    // Drain both pipes while waiting so a large profile list can never block lpac.
    let (status, out, err) = std::thread::scope(|s| {
        // Past MAX_OUTPUT the rest is read and discarded, so lpac never blocks on a full pipe.
        let out = s.spawn(move || {
            let mut text = String::new();
            if let Some(pipe) = stdout {
                let mut reader = BufReader::new(pipe.take(MAX_OUTPUT));
                for line in reader.by_ref().lines().map_while(Result::ok) {
                    if let Ok(v) = serde_json::from_str::<Value>(line.trim()) {
                        on_line(&v);
                    }
                    text.push_str(&line);
                    text.push('\n');
                }
                let _ = std::io::copy(&mut reader.into_inner().into_inner(), &mut std::io::sink());
            }
            text
        });
        let err = s.spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = stderr {
                let _ = p.by_ref().take(MAX_OUTPUT).read_to_end(&mut buf);
                let _ = std::io::copy(&mut p, &mut std::io::sink());
            }
            buf
        });
        let started = Instant::now();
        let mut interrupted = false;
        let status = loop {
            let polled = match io {
                Some(io) => {
                    let mut slot = io.pid.lock().unwrap();
                    let polled = child.try_wait();
                    if !matches!(polled, Ok(None)) {
                        *slot = 0;
                    }
                    polled
                }
                None => child.try_wait(),
            };
            match polled {
                Ok(Some(status)) => break Some(status),
                Ok(None) if started.elapsed() < limit => {}
                Ok(None) if !interrupted => {
                    // SAFETY: `pid` is our own child, not yet reaped (try_wait returned None),
                    // and leads its own process group.
                    unsafe { libc::kill(-pid, libc::SIGINT) };
                    interrupted = true;
                }
                Ok(None) if started.elapsed() < limit + Duration::from_secs(15) => {}
                _ => {
                    let slot = io.map(|io| io.pid.lock().unwrap());
                    // SAFETY: as above; the group goes too, so no helper keeps the pipes open.
                    unsafe { libc::kill(-pid, libc::SIGKILL) };
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(mut slot) = slot {
                        *slot = 0;
                    }
                    break None;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        // Anything lpac left in its group (no helper is expected) would hold the pipes open
        // and stall the readers; the leader is reaped, so the group id is still ours.
        // SAFETY: ESRCH when the group is empty, which is the normal case.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        if let Some(io) = io {
            *io.stdin.lock().unwrap() = None;
        }
        let status = if interrupted { None } else { status };
        (
            status,
            out.join().unwrap_or_default(),
            err.join().unwrap_or_default(),
        )
    });
    let Some(status) = status else {
        return Err(LpacError::Failed(format!(
            "lpac did not finish within {} s",
            limit.as_secs()
        )));
    };
    match parse_output(&out) {
        Ok(data) => Ok(data),
        Err(message) => {
            let detail = String::from_utf8_lossy(&err);
            let detail = detail.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
            eprintln!("[esim] lpac {} failed ({status}): {message}", args[..2.min(args.len())].join(" "));
            Err(LpacError::Failed(if detail.is_empty() {
                message
            } else {
                format!("{message} ({})", detail.trim())
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = r#"{"type":"lpa","payload":{"code":0,"message":"success","data":[{"iccid":"8963000000000000001","isdpAid":"A0000005591010FFFFFFFF8900001000","profileState":"enabled","profileNickname":"Smart","serviceProviderName":"SMART","profileName":"Operational","iconType":"png","icon":"iVBORw0KGgo=","profileClass":"operational"},{"iccid":"8963000000000000002","isdpAid":"A0000005591010FFFFFFFF8900001100","profileState":"disabled","profileNickname":null,"serviceProviderName":"GOMO","profileName":"Globe Philippines ODC","iconType":"none","icon":null,"profileClass":"operational"},{"iccid":"8963000000000000003","isdpAid":"A0000005591010FFFFFFFF8900001200","profileState":"disabled","profileNickname":null,"serviceProviderName":"Test","profileName":"Test","iconType":"none","icon":null,"profileClass":"test"}]}}"#;

    fn list() -> Vec<Value> {
        profile_views(&parse_output(LIST).unwrap())
    }

    #[test]
    fn profile_list_maps_fields_and_drops_icons() {
        let p = list();
        assert_eq!(p.len(), 3);
        assert_eq!(p[0]["iccid"], "8963000000000000001");
        assert_eq!(p[0]["state"], "enabled");
        assert_eq!(p[0]["nickname"], "Smart");
        assert_eq!(p[1]["provider"], "GOMO");
        assert_eq!(p[1]["nickname"], Value::Null);
        assert!(p.iter().all(|v| v.get("icon").is_none()));
        assert_eq!(enabled_iccid(&p).as_deref(), Some("8963000000000000001"));
    }

    #[test]
    fn result_is_the_last_lpa_line_after_progress_reports() {
        let out = "{\"type\":\"progress\",\"payload\":{\"code\":0,\"message\":\"es10b\",\"data\":null}}\n\
                   {\"type\":\"lpa\",\"payload\":{\"code\":0,\"message\":\"success\",\"data\":null}}\n";
        assert_eq!(parse_output(out).unwrap(), Value::Null);
    }

    #[test]
    fn failures_carry_lpac_reason() {
        let out = r#"{"type":"lpa","payload":{"code":-1,"message":"es10c_enable_profile","data":"profile not in disabled state"}}"#;
        assert_eq!(
            parse_output(out).unwrap_err(),
            "es10c_enable_profile: profile not in disabled state"
        );
        assert!(parse_output("").is_err());
        assert!(parse_output("garbage\n").is_err());
    }

    #[test]
    fn enable_target_must_be_a_disabled_operational_profile() {
        let p = list();
        assert!(check_enable_target(&p, "8963000000000000002").is_ok());
        assert_eq!(check_enable_target(&p, "8963000000000000001").unwrap_err().0, 409);
        assert_eq!(check_enable_target(&p, "8963000000000000003").unwrap_err().0, 400);
        assert_eq!(check_enable_target(&p, "8963000000000000009").unwrap_err().0, 404);
    }

    #[test]
    fn delete_never_removes_the_active_profile() {
        let p = list();
        assert!(check_delete_target(&p, "8963000000000000002").is_ok());
        assert!(check_delete_target(&p, "8963000000000000003").is_ok());
        assert_eq!(check_delete_target(&p, "8963000000000000001").unwrap_err().0, 409);
        assert_eq!(check_delete_target(&p, "8963000000000000009").unwrap_err().0, 404);
    }

    #[test]
    fn activation_codes() {
        assert_eq!(check_activation_code("LPA:1$smdp.example.com$ABC-123"), Ok(false));
        assert_eq!(check_activation_code("lpa:1$smdp.example.com:443$ABC123"), Ok(false));
        assert_eq!(check_activation_code("LPA:1$smdp.example.com$ABC123$1.3.6.1$1"), Ok(true));
        assert_eq!(check_activation_code("LPA:1$smdp.example.com$$$"), Ok(false));
        assert!(check_activation_code("LPA:2$smdp.example.com$ABC").is_err());
        assert!(check_activation_code("smdp.example.com$ABC").is_err());
        assert!(check_activation_code("LPA:1$smdp.example.com").is_err());
        assert!(check_activation_code("LPA:1$smdp.example.com$AB C").is_err());
        assert!(check_activation_code("LPA:1$smdp.example.com$AB_C").is_err());
        assert!(check_activation_code("LPA:1$sm dp$ABC").is_err());
        assert!(check_activation_code("LPA:1$;reboot$ABC").is_err());
        assert!(check_activation_code("").is_err());
    }

    #[test]
    fn download_progress_tracks_step_and_metadata() {
        let mut d = Download { state: "running", ..Download::default() };
        d.progress(&json!({"type":"progress","payload":{"code":0,"message":"es9p_initiate_authentication","data":"smdp.example.com"}}));
        assert_eq!(d.step, "es9p_initiate_authentication");
        d.progress(&json!({"type":"progress","payload":{"code":0,"message":"es8p_metadata_parse","data":{"iccid":"8963000000000000004","serviceProviderName":"GOMO","profileName":"Globe"}}}));
        assert_eq!(d.provider.as_deref(), Some("GOMO"));
        assert_eq!(d.name.as_deref(), Some("Globe"));
        d.progress(&json!({"type":"lpa","payload":{"code":0,"message":"success","data":null}}));
        assert_eq!(d.step, "es8p_metadata_parse", "result lines are not progress");
        d.progress(&json!({"type":"progress","payload":{"code":0,"message":"es9p_authenticate_client","data":null}}));
        d.progress(&json!({"type":"progress","payload":{"code":0,"message":"es9p_cancel_session","data":null}}));
        assert_eq!(d.step, "es9p_authenticate_client", "cleanup does not hide the failing step");
        assert_eq!(Download::default().view()["state"], "idle");
    }

    #[test]
    fn preview_prompt_moves_a_running_download_to_confirm() {
        let mut d = Download { state: "running", ..Download::default() };
        d.progress(&json!({"type":"progress","payload":{"code":0,"message":"preview","data":"y/n"}}));
        assert_eq!(d.state, "confirm");
        assert_eq!(d.view()["state"], "confirm");
    }

    #[test]
    fn finished_results_expire_but_running_downloads_do_not() {
        let mut d = Download { state: "cancelled", finished_at: 1_000, ..Download::default() };
        d.expire(1_000 + RESULT_KEEP_SECS - 1);
        assert_eq!(d.state, "cancelled");
        d.expire(1_000 + RESULT_KEEP_SECS);
        assert_eq!(d.view()["state"], "idle");
        let mut running = Download { state: "running", started_at: 1, ..Download::default() };
        running.expire(1_000_000);
        assert_eq!(running.state, "running");
    }

    #[test]
    fn answering_or_cancelling_without_a_child_does_nothing() {
        let io = ChildIo::default();
        assert!(!io.answer(true));
        assert!(!io.interrupt());
    }

    #[test]
    fn iccid_validation() {
        assert!(valid_iccid("8963000000000000001"));
        assert!(valid_iccid("896300000000000000F"));
        assert!(valid_iccid("89630000000000000012"));
        assert!(!valid_iccid("89630000000000001"));
        assert!(!valid_iccid("8963000000000000001; reboot"));
        assert!(!valid_iccid(""));
    }

    #[test]
    fn chip_view_picks_identity_and_memory() {
        let data = json!({"eidValue":"89000000000000000000000000000001","EUICCInfo2":{"profileVersion":"2.3.1","svn":"2.2.2","euiccFirmwareVer":"4.2.0","extCardResource":{"installedApplication":0,"freeNonVolatileMemory":972020,"freeVolatileMemory":16619}}});
        let v = chip_view(&data);
        assert_eq!(v["firmware"], "4.2.0");
        assert_eq!(v["sgp22_version"], "2.2.2");
        assert_eq!(v["free_nvm_bytes"], 972020);
    }

    fn temp_lock(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("zte-agent-lock-{}-{tag}", std::process::id()))
    }

    #[test]
    fn the_file_lock_keeps_a_second_holder_out() {
        let path = temp_lock("shared");
        let a = Esim::with_lock_path(path.clone());
        let b = Esim::with_lock_path(path.clone());
        let g = a.acquire().expect("first holder");
        assert!(b.acquire().is_none(), "another holder of the file lock is refused");
        assert!(!b.inner.busy.load(Ordering::Relaxed), "a refused acquire leaves no flag set");
        drop(g);
        // A child being spawned by another thread holds a copy of the descriptor until its
        // exec, so the lock can take a moment to come free.
        let freed = (0..200).any(|_| b.acquire().is_some() || {
            std::thread::sleep(Duration::from_millis(5));
            false
        });
        assert!(freed);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn switching_is_refused_only_when_the_user_parked_the_radio() {
        assert!(!radio_blocks_switch(Some("ONLINE"), Some("idle")));
        assert!(!radio_blocks_switch(Some(" online "), None));
        assert!(!radio_blocks_switch(None, None), "unknown mode does not block");
        assert!(radio_blocks_switch(Some("LPM"), Some("idle")));
        assert!(radio_blocks_switch(Some("OFFLINE"), None));
        assert!(!radio_blocks_switch(Some("LPM"), Some("lpm")), "parked by the no-service policy");
        assert!(!radio_blocks_switch(Some("LPM"), Some("probing")));
    }

    #[test]
    fn a_different_card_drops_the_saved_list() {
        let mut inv = Inventory::default();
        assert!(!inv.note_card("89000000000000000000000000000001"));
        inv.record(list(), 10);
        inv.generation = 4;
        assert!(!inv.note_card("89000000000000000000000000000001"));
        assert!(!inv.note_card(""), "an empty EID proves nothing");
        assert!(inv.profiles.is_some());
        assert!(inv.note_card("89000000000000000000000000000002"));
        assert!(inv.profiles.is_none());
        assert_eq!(inv.generation, 5);
        assert_eq!(inv.eid.as_deref(), Some("89000000000000000000000000000002"));
    }

    #[test]
    fn receipts_keep_attempt_counts_across_reads() {
        let data = json!([
            {"seqNumber": 7, "profileManagementOperation": "install", "notificationAddress": "smdp.example.com", "iccid": "8963000000000000004"},
            {"seqNumber": 8, "profileManagementOperation": "delete", "notificationAddress": "smdp.example.net", "iccid": null},
            {"profileManagementOperation": "install"}
        ]);
        let fresh = receipt_views(&data);
        assert_eq!(fresh.len(), 2, "entries without a sequence number are skipped");
        let mut r = Receipts::default();
        assert!(!r.retryable());
        r.merge(fresh.clone(), 100);
        r.pending.as_mut().unwrap()[0].attempts = RECEIPT_MAX_ATTEMPTS;
        r.pending.as_mut().unwrap()[1].attempts = 2;
        r.merge(fresh, 200);
        let p = r.pending.as_ref().unwrap();
        assert_eq!((p[0].attempts, p[1].attempts), (RECEIPT_MAX_ATTEMPTS, 2));
        assert!(r.retryable());
        let v = r.view(false);
        assert_eq!(v["count"], 2);
        assert_eq!(v["pending"][0]["gave_up"], true);
        assert_eq!(v["pending"][1]["operation"], "delete");
        r.merge(vec![], 300);
        assert!(!r.retryable());
        assert_eq!(r.view(false)["count"], 0);
        assert_eq!(Receipts::default().view(true)["count"], Value::Null, "not listed yet");
    }

    #[test]
    fn nickname_limits() {
        assert!(check_nickname("").is_ok());
        assert!(check_nickname("Travel – Globe").is_ok());
        assert!(check_nickname(&"x".repeat(64)).is_ok());
        assert!(check_nickname(&"x".repeat(65)).is_err());
        assert!(check_nickname(&"é".repeat(33)).is_err(), "64 bytes, not 64 characters");
        assert!(check_nickname("line\nbreak").is_err());
    }

    #[test]
    fn build_info_reads_buildinfo_and_the_lpac_checksum() {
        let dir = std::env::temp_dir().join(format!("zte-agent-buildinfo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(build_info(&dir)["build"], Value::Null);
        std::fs::write(dir.join("BUILDINFO"), "lpac_commit=c7c8d4f\npatch_sha256=abc\n").unwrap();
        std::fs::write(dir.join("SHA256SUMS"), "111  bounded\n222  lpac\n333  lib/liblpac.so\n").unwrap();
        let v = build_info(&dir);
        assert_eq!(v["build"]["lpac_commit"], "c7c8d4f");
        assert_eq!(v["lpac_sha256"], "222");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn busy_guard_is_exclusive_and_released_on_drop() {
        let e = Esim::with_lock_path(temp_lock("busy"));
        let g = e.acquire().expect("first");
        assert!(e.acquire().is_none());
        drop(g);
        assert!(e.acquire().is_some());
    }

    #[test]
    fn switch_guard_expires() {
        let e = Esim::new();
        assert!(!e.recently_switched(1_000));
        e.inner.switched_at.store(1_000, Ordering::Relaxed);
        assert!(e.recently_switched(1_000 + SWITCH_GUARD_SECS - 1));
        assert!(!e.recently_switched(1_000 + SWITCH_GUARD_SECS));
    }

    #[test]
    fn channel_failures_are_reloading_right_after_a_switch_and_unavailable_otherwise() {
        let msg = "euicc_init (error: open logical channel failed: QMI protocol error (80): 'SimFileNotFound')";
        assert_eq!(classify(msg, true), "sim_reloading");
        assert_eq!(classify(msg, false), "management_unavailable");
        assert_eq!(classify("es10c_enable_profile: unknown", true), "read_failed");
    }

    #[test]
    fn inventory_view_marks_old_lists() {
        let mut inv = Inventory::default();
        assert_eq!(inv.view(7, false)["profiles"], json!([]));
        inv.record(list(), 100);
        let v = inv.view(7, false);
        assert_eq!((v["stale"].as_bool(), v["updating"].as_bool()), (Some(false), Some(false)));
        assert_eq!(v["enabled_iccid"], "8963000000000000001");
        assert_eq!(v["agent_instance"], 7);
        inv.reloading = true;
        assert_eq!(inv.view(7, false)["updating"], true);
        inv.reloading = false;
        inv.error = Some(ReadError { kind: "management_unavailable", message: "x".into(), at: 200 });
        let v = inv.view(7, false);
        assert_eq!(v["stale"], true);
        assert_eq!(v["error"]["kind"], "management_unavailable");
        assert_eq!(v["observed_at"], 100, "a failed read keeps the time of the last good one");
        inv.record(list(), 300);
        assert_eq!(inv.view(7, false)["error"], Value::Null, "a good read clears the error");
        assert_eq!(inv.view(7, true)["updating"], true);
    }

    #[test]
    fn iccid_comparison_ignores_filler() {
        assert!(same_iccid("8963000000000000001F", "8963000000000000001"));
        assert!(same_iccid(" 8963000000000000001 ", "8963000000000000001"));
        assert!(!same_iccid("8963000000000000002", "8963000000000000001"));
        assert!(!same_iccid("", ""));
    }

    #[test]
    fn switch_view_starts_idle() {
        assert_eq!(Switch::default().view()["state"], "idle");
        assert_eq!(Switch::default().view()["target_iccid"], Value::Null);
        let mut sw = Switch { state: "reloading", target: "8963000000000000001".into(), ..Switch::default() };
        sw.finish("connected", 9);
        assert_eq!((sw.view()["state"].as_str(), sw.finished_at), (Some("connected"), 9));
    }

    /// A bundle whose "loader" is a shell script standing in for lpac.
    fn fake_bundle(script: &str) -> Config {
        use std::os::unix::fs::PermissionsExt;
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zte-agent-lpac-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["lib", "driver"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
            std::fs::set_permissions(dir.join(sub), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(dir.join("lpac"), "").unwrap();
        std::fs::set_permissions(dir.join("lpac"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let ld = dir.join("ld-musl-aarch64.so.1");
        std::fs::write(&ld, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&ld, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        Config { dir, node: "3".into(), slot: "1".into() }
    }

    fn run_fake(script: &str, limit: Duration) -> Result<Value, LpacError> {
        let cfg = fake_bundle(script);
        let result = lpac_in(&cfg, &["profile", "list"], limit, &|_| {}, None);
        let _ = std::fs::remove_dir_all(&cfg.dir);
        result
    }

    const OK_LINE: &str = r#"echo '{"type":"lpa","payload":{"code":0,"message":"success","data":[]}}'"#;

    #[test]
    fn heavy_stderr_and_stdout_beyond_the_cap_do_not_block_lpac() {
        let script = format!(
            "head -c 2000000 /dev/zero | tr '\\0' x >&2\nhead -c 1000000 /dev/zero | tr '\\0' y\necho\n{OK_LINE}"
        );
        let started = Instant::now();
        let result = run_fake(&script, Duration::from_secs(20));
        assert!(started.elapsed() < Duration::from_secs(15), "drained, not timed out");
        // The result line came after the cap, so it was discarded: still never a false success.
        assert!(result.is_err());
        assert!(run_fake(&format!("head -c 2000000 /dev/zero | tr '\\0' x >&2\n{OK_LINE}"), Duration::from_secs(20)).is_ok());
    }

    #[test]
    fn lpac_trusts_the_bundled_gsma_roots_for_operator_servers() {
        let cfg = fake_bundle(r#"echo "{\"type\":\"lpa\",\"payload\":{\"code\":0,\"message\":\"success\",\"data\":\"$LPAC_HTTP_CA_FILE\"}}""#);
        let result = lpac_in(&cfg, &["notification", "list"], Duration::from_secs(10), &|_| {}, None);
        let data = result.map_err(|e| e.message().to_string()).unwrap();
        assert_eq!(data, json!(cfg.dir.join("gsma-ci.pem").to_str().unwrap()));
        let _ = std::fs::remove_dir_all(&cfg.dir);
    }

    #[test]
    fn exiting_without_a_result_is_a_failure() {
        let e = run_fake("exit 0", Duration::from_secs(10)).unwrap_err();
        assert!(e.message().contains("no result"), "{}", e.message());
        let progress_only = r#"echo '{"type":"progress","payload":{"code":0,"message":"es10b","data":null}}'"#;
        assert!(run_fake(progress_only, Duration::from_secs(10)).is_err());
    }

    #[test]
    fn output_after_the_result_is_still_drained() {
        let script = format!("{OK_LINE}\necho '{{\"type\":\"progress\",\"payload\":{{\"code\":0,\"message\":\"cleanup\"}}}}'\nexit 0");
        assert!(run_fake(&script, Duration::from_secs(10)).is_ok());
    }

    #[test]
    fn a_hung_lpac_and_its_helpers_are_stopped_at_the_limit() {
        // The helper keeps stdout open: only a process-group signal ends it.
        let started = Instant::now();
        let e = run_fake("sleep 60 &\nsleep 60", Duration::from_secs(1)).unwrap_err();
        assert!(e.message().contains("did not finish"), "{}", e.message());
        assert!(started.elapsed() < Duration::from_secs(20), "took {:?}", started.elapsed());
    }

    #[test]
    fn logs_show_only_the_last_four_digits() {
        assert_eq!(mask("8963000000000000001"), "…0001");
    }
}
