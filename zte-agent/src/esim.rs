//! eSIM profile management with lpac (GSMA SGP.22 LPA: ES10 to the card over QMI-over-QRTR,
//! ES9+ to the operator's SM-DP+ over HTTPS).
//!
//! lpac is not part of this binary. It is a separately built private bundle (recipe in
//! `lpac-qrtr-build/`) copied to `ZTE_AGENT_LPAC_DIR` (default `/data/lpac`). The agent runs at
//! most one lpac process at a time, with a hard time limit, and only these commands:
//! `chip info`, `profile list`, `profile enable <iccid> 1`, `profile delete <iccid>`,
//! `profile download -p -a <code> [-c <code>]` and `notification process -a -r`.
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
/// Sending install/delete receipts to operator servers (needs internet; best effort).
const NOTIFY_LIMIT: Duration = Duration::from_secs(60);
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
}

#[derive(Clone, Debug, PartialEq)]
struct ReadError {
    /// "sim_reloading", "management_unavailable", "read_failed" or "not_installed".
    kind: &'static str,
    message: String,
    at: u64,
}

impl Inventory {
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
        if let Some(step) = line["payload"]["message"].as_str() {
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

/// Released on drop, including when a download thread ends.
struct BusyGuard(Arc<Inner>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
    }
}

impl Esim {
    pub fn new() -> Self {
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
        .ok()
        .map(|_| BusyGuard(Arc::clone(inner)))
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
    (200, json!({"ok": true, "data": inv.view(inner.instance, false)}))
}

/// GET /api/esim/switch — progress and verified outcome of the last profile switch.
pub fn switch_status(state: &AppState) -> (u16, Value) {
    let view = state.esim.inner.switch.lock().unwrap().view();
    (200, json!({"ok": true, "data": view}))
}

/// GET /api/esim/chip
pub fn chip(state: &AppState) -> (u16, Value) {
    let Some(_guard) = state.esim.acquire() else {
        return busy();
    };
    match lpac(&["chip", "info"], CARD_LIMIT, &|_| {}, None) {
        Ok(data) => (200, json!({"ok": true, "data": chip_view(&data)})),
        Err(e) => e.reply(),
    }
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
    let Some(guard) = state.esim.acquire() else {
        return busy();
    };
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
    loop {
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
            return;
        }
        if started.elapsed() >= SWITCH_VERIFY_LIMIT {
            let outcome = if sw.modem_confirmed_at != 0 { "no_data" } else { "modem_unconfirmed" };
            sw.finish(outcome, now);
            eprintln!("[esim] switch to {} ended as {outcome}", mask(&target));
            return;
        }
        drop(sw);
        std::thread::sleep(SWITCH_POLL);
    }
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
    let notified = send_notifications();
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
    let Some(guard) = state.esim.acquire() else {
        return busy();
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
        let notified = result.is_ok() && send_notifications();
        if result.is_ok() {
            inner.inventory.lock().unwrap().generation += 1;
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
    let view = state.esim.inner.download.lock().unwrap().view();
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

/// Sends pending install/delete receipts to the operators' servers and removes the ones sent.
/// Best effort: without internet they stay on the card for a later attempt.
fn send_notifications() -> bool {
    match lpac(&["notification", "process", "-a", "-r"], NOTIFY_LIMIT, &|_| {}, None) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("[esim] operator notifications not sent: {}", e.message());
            false
        }
    }
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

    #[test]
    fn busy_guard_is_exclusive_and_released_on_drop() {
        let e = Esim::new();
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
