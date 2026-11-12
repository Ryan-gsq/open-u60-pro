//! The Mihomo controller (`relay-mihomo-architecture.md` sections 3 and 5):
//! one thread that serializes owner commands, routing writes from the
//! console and Zashboard, egress changes, core exits, retries, `net_guard`
//! checks and rule-set refreshes. Nothing here holds the relay's network
//! lock: a relay association or CAC never delays an exit, a retry or a
//! repair (I2). HTTP never waits for it on the runtime thread: pages read
//! the published `Snapshot`, commands wait on the blocking pool, the
//! dashboard bridge awaits a oneshot.
//!
//! Device work goes through `Port`, so tests replay exits, retries, switches
//! and failures with a fake device and short timings (I6).
//!
//! States (section 5.2): `Off`; `Starting` (guard, kernel settings and
//! policy routes before the core, the plan only from what the ready core
//! reports); `Running`; `Restarting` (a planned restart: interception stays,
//! nothing skips the core, `to_core` drops what no core takes); `Backoff`
//! (D3 after a confirmed core failure: interception withdrawn, fake-ip fails
//! fast, retries at 5, 15, 30, 60 s then every 5 min); `CleanupPending` (a
//! release failed: the journal and ownership stay; a D3 withdrawal that
//! failed is retried on the same timers, since until it works the old
//! tables keep LAN DNS on a core that is gone).
//!
//! What the kernel may hold is kept as `NftTables` keeps it: the table last
//! confirmed and the ones declared since that did not confirm, since a
//! `reconcile` loads the last of them later (and a failed load may have
//! committed). Narrowing before a change and the connections a change
//! resets follow everything the kernel may hold (I4), and the status
//! follows what a reconcile loaded (I7).

use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::egress::{self, Change, Uplink};
use super::intercept::Shape;
use super::routing::{self, Chain, Mode, Selected};
use crate::netfx::conntrack::{Report, Scope};

pub(super) type Reply = SyncSender<Result<(), String>>;
/// A routing write's answer: the core's status and body.
pub(super) type Answered = Result<(u16, Vec<u8>), String>;

/// A write to the core that can change routing: `PATCH /configs` (mode),
/// `PUT /proxies/<group>` (a choice), `PUT /providers/rules/<set>`.
#[derive(Clone, Debug)]
pub(super) struct Write {
    pub method: &'static str,
    pub segments: Vec<String>,
    pub body: Value,
}

pub(super) enum Answer {
    Sync(SyncSender<Answered>),
    Async(tokio::sync::oneshot::Sender<Answered>),
}

impl Answer {
    fn send(self, answer: Answered) {
        match self {
            Answer::Sync(tx) => drop(tx.send(answer)),
            Answer::Async(tx) => drop(tx.send(answer)),
        }
    }
}

pub(super) enum Message {
    /// The agent started: adopt this boot's tables if the owner wants
    /// Mihomo on, else roll back what a previous process left.
    Boot,
    /// Turn on (`owner`: the owner's switch; otherwise the boot restore).
    Enable { local: String, owner: bool, reply: Option<Reply> },
    Disable { reply: Option<Reply> },
    /// The DIRECT bypass setting changed (the flag file is written).
    Bypass { reply: Reply },
    /// The selected profile changed while running.
    Config { refresh: bool, reply: Reply },
    Write { write: Write, answer: Answer },
    /// The relay changed its routes.
    Egress,
    /// A ZTE script or event settled (`net_guard::on_settled`): check now
    /// rather than at the next tick.
    Guard,
    Exited { generation: u64, how: String },
    #[cfg(test)]
    Stop,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Phase {
    #[default]
    Off,
    Starting,
    Running,
    Restarting,
    /// A hot reload of the same configuration's DNS filter (v3).
    Reloading,
    Backoff,
    CleanupPending,
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Phase::Off => "off",
            Phase::Starting => "starting",
            Phase::Running => "running",
            Phase::Restarting => "restarting",
            Phase::Reloading => "reloading",
            Phase::Backoff => "backoff",
            Phase::CleanupPending => "cleanup_pending",
        }
    }
}

/// What the kernel does with LAN IPv4 that is neither fake-ip nor private.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Bypass {
    /// All of it goes to the core, and why.
    None(String),
    /// Rule mode: what this many DIRECT rules match skips the core; `cut`
    /// is why the chain ends early.
    Rules { returns: usize, cut: Option<String> },
    /// Direct mode: all of it skips the core.
    All,
}

impl Bypass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::None(_) => "none",
            Self::Rules { .. } => "rules",
            Self::All => "all_ipv4",
        }
    }
}

/// What pages and the bridge read; never waits for the controller.
#[derive(Clone, Debug, Default)]
pub(super) struct Snapshot {
    pub phase: Phase,
    pub error: Option<String>,
    /// The running core's controller secret (never leaves the router).
    pub secret: Option<String>,
    pub mode: Option<Mode>,
    pub bypass: Option<Bypass>,
    /// Consecutive failed starts and confirmed exits (D2).
    pub failures: u32,
    pub retry_at: Option<Instant>,
    pub reason: Option<String>,
    pub tables: Value,
    pub generation: u64,
    /// The running core's process id (diagnostics).
    pub core_pid: Option<u32>,
    /// What the last connection reset did.
    pub last_reset: Value,
    /// A problem the core does not report as an error: a node in use has
    /// only an IPv6 address while the egress has no IPv6.
    pub notice: Option<String>,
}

impl Snapshot {
    /// A core runs and may take traffic.
    pub fn running(&self) -> bool {
        matches!(self.phase, Phase::Starting | Phase::Running | Phase::Restarting | Phase::Reloading)
    }
}

/// The configuration a start uses, written and validated.
#[derive(Clone, Debug)]
pub(super) struct Prepared {
    pub secret: String,
    pub local: String,
    pub runtime: Value,
    pub routes: routing::Routes,
    pub dns: Vec<String>,
    pub bypass: bool,
    pub notice: Option<String>,
    pub source: String,
    /// The managed configuration's text, kept to fall back to.
    pub config: String,
}

/// Which configuration to prepare.
#[derive(Clone, Debug)]
pub(super) enum Source {
    /// The selected profile, with the runtime mode and log level (if any).
    Selected { local: String, runtime: Option<Value> },
    /// A configuration that ran before (falls back to it as is).
    Previous(Box<Prepared>),
    /// The running configuration again, with the DNS filter the settings
    /// give now: same secret, mode, log level, egress interface and ports.
    Reload(Box<Prepared>),
    Refresh(Box<Prepared>),
}

/// How effects are taken when a start begins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Engage {
    /// Nothing owned yet: claim the names, journal, apply.
    Fresh,
    /// After D3 (fake-ip reject loaded): kernel settings and routes again.
    FromBackoff,
    /// A previous agent's effects of this boot: re-take them as they are.
    Adopt,
}

pub(super) trait CoreHandle: Send {
    fn generation(&self) -> u64;
    fn pid(&self) -> u32;
    /// TERM, then KILL; true once reaped.
    fn stop(&self) -> bool;
}

/// The device, for the controller (`DevicePort` in `mihomo.rs`).
pub(super) trait Port: Send + 'static {
    /// Whether this boot's previous agent left effects the owner still wants.
    fn adoptable(&mut self) -> bool;
    /// Rolls back what a previous process left.
    fn recover(&mut self) -> Result<(), String>;
    /// Whether starting is refused for now (an install is in progress).
    fn busy(&mut self) -> Option<String>;
    /// Writes and validates the configuration. `serving`: a core keeps
    /// serving meanwhile, so a validation runs in the background (one Go
    /// execution slot, lower priority).
    fn prepare(&mut self, source: &Source, serving: bool) -> Result<Prepared, String>;
    /// Ports the core binds are free (checked before each spawn).
    fn ports_free(&mut self) -> Result<(), String>;
    /// Effects are held (a start re-applies them rather than claiming them).
    fn owns(&mut self) -> bool;
    fn engage(&mut self, how: Engage) -> Result<(), String>;
    /// Loads a table shape; `Err` when it is not confirmed.
    fn tables(&mut self, shape: Shape) -> Result<(), String>;
    fn tables_status(&mut self) -> Value;
    /// D3: fake-ip fails fast, kernel settings and policy routes are
    /// released, LAN traffic goes direct. Nothing to do when nothing is owned.
    fn direct(&mut self) -> Result<(), String>;
    /// Off: releases everything, the journal last.
    fn release_all(&mut self) -> Result<(), String>;
    fn spawn(&mut self, generation: u64, prepared: &Prepared, exits: Sender<Message>) -> Result<Box<dyn CoreHandle>, String>;
    fn ready(&mut self, prepared: &Prepared) -> bool;
    /// Local delivery of marked traffic works (policy routing).
    fn verify_routing(&mut self) -> Result<(), String>;
    /// The running core's mode, choices and runtime settings.
    fn read_back(&mut self, secret: &str) -> Option<(Mode, Selected, Value)>;
    /// The kernel plan for these choices, with `unsettled` rule sets unknown.
    fn plan(&mut self, routes: &routing::Routes, bypass: bool, mode: Mode, selected: &Selected, unsettled: &[String]) -> (Bypass, Chain);
    fn reset(&mut self, reason: &'static str, scope: Scope, changed: Instant) -> Result<Report, String>;
    fn write(&mut self, secret: &str, write: &Write) -> Answered;
    /// `PUT /configs?force=false` with the whole managed configuration: the
    /// core's status, or why the call did not finish (the result is unknown).
    fn reload(&mut self, secret: &str, config: &str) -> Result<u16, String>;
    /// After a reload, whatever its answer: the mode, egress interface and
    /// choices are as before (no group fell back to `COMPATIBLE`), the rule
    /// sets and listeners are there, and `probe` answers as the new filter
    /// says (fake or not).
    fn verify_reload(&mut self, prepared: &Prepared, probe: Option<&(String, bool)>, before: &Selected) -> Result<(), String>;
    /// The egress now; `upstream`: also which access point the relay is on.
    fn uplink(&mut self, upstream: bool) -> Uplink;
    /// Re-applies what another writer removed (`net_guard` decides when).
    fn reconcile(&mut self) -> Guarded;
    /// Whether the owner wants Mihomo on after a restart.
    fn wanted(&mut self) -> bool;
    fn set_wanted(&mut self, on: bool) -> Result<(), String>;
    /// A rule set's file changed since `plan` read it.
    fn sources_changed(&mut self) -> bool;
    fn guard_due(&mut self) -> bool;
    fn retry_reset(&mut self);
}

/// What a `net_guard` check found.
pub(super) struct Guarded {
    pub result: Result<(), String>,
    /// The tables' target is what the kernel holds now (a target that had
    /// not loaded may have been loaded by this check).
    pub confirmed: bool,
}

/// Delays and windows; tests shorten them.
#[derive(Clone, Debug)]
pub(super) struct Timings {
    /// D2: waits before each retry; the last repeats.
    pub retries: Vec<Duration>,
    /// Three confirmed exits within this window skip to the last wait.
    pub quick: Duration,
    /// Running this long clears the failure count.
    pub stable: Duration,
    pub ready: Duration,
    pub tick: Duration,
    pub audit: Duration,
    /// The fallback re-read of the core's mode and choices.
    pub follow: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            retries: [5, 15, 30, 60, 300].map(Duration::from_secs).to_vec(),
            quick: Duration::from_secs(60),
            stable: Duration::from_secs(300),
            ready: Duration::from_secs(6),
            tick: Duration::from_secs(2),
            audit: Duration::from_secs(15),
            follow: Duration::from_secs(60),
        }
    }
}

/// A table declared that the kernel was not read to hold.
struct Pending {
    bypass: Bypass,
    chain: Chain,
    /// Declared to narrow the bypass before a change that then did not
    /// happen: once loaded, the plan is followed again.
    narrowing: bool,
}

/// The running core and what the kernel was set up for.
struct Run {
    core: Box<dyn CoreHandle>,
    prepared: Prepared,
    mode: Mode,
    selected: Selected,
    /// What the kernel was last read to hold (`Chain::default()` while
    /// nothing is bypassed), and what that bypasses.
    kernel: (Bypass, Chain),
    /// Tables declared since that did not confirm, oldest first.
    pending: Vec<Pending>,
    /// Every chain connections may have skipped the core by since the last
    /// reset, confirmed or pending (a tightening narrows `kernel`, not this).
    bypassed: Vec<Chain>,
    /// The bypass was narrowed for a change, and what the core runs since
    /// has not been read back yet.
    unfollowed: bool,
    uplink: Uplink,
    /// The egress has IPv6 now (the last observation).
    ipv6: bool,
    stranding: Option<(Uplink, Instant)>,
    /// An IPv6-only egress change waiting to hold, and since when.
    v6: Option<(Uplink, Instant)>,
    started: Instant,
    audited: Instant,
    followed: Instant,
    /// Rule sets the controller refreshes: name, interval, next due.
    refresh: Vec<(String, Duration, Instant)>,
}

impl Run {
    /// The kernel may let traffic skip the core: the confirmed table does,
    /// or one a reconcile may still load.
    fn may_return(&self) -> bool {
        self.kernel.1.returns > 0 || self.pending.iter().any(|p| p.chain.returns > 0)
    }

    /// The table the kernel holds or a reconcile will load.
    fn target(&self) -> &Chain {
        self.pending.last().map_or(&self.kernel.1, |p| &p.chain)
    }

    fn declared(&mut self, bypass: Bypass, chain: Chain, narrowing: bool, confirmed: bool) {
        if chain.returns > 0 && !self.bypassed.contains(&chain) {
            self.bypassed.push(chain.clone());
        }
        if confirmed {
            self.kernel = (bypass, chain);
            self.pending.clear();
        } else {
            self.pending.push(Pending { bypass, chain, narrowing });
        }
    }

    /// After a reset: from now on connections can skip the core only by
    /// what the kernel may still hold.
    fn reset_done(&mut self) {
        let mut bypassed: Vec<Chain> = Vec::new();
        for chain in std::iter::once(&self.kernel.1).chain(self.pending.iter().map(|p| &p.chain)) {
            if chain.returns > 0 && !bypassed.contains(chain) {
                bypassed.push(chain.clone());
            }
        }
        self.bypassed = bypassed;
    }

    /// A reconcile confirmed the target: the last table declared is what
    /// the kernel holds. `Some(narrowing)` when one was pending.
    fn loaded(&mut self) -> Option<bool> {
        let last = self.pending.pop()?;
        self.pending.clear();
        self.kernel = (last.bypass, last.chain);
        Some(last.narrowing)
    }
}

/// Why a planned restart runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Restart {
    /// The selected profile changed: the old core serves until the new
    /// configuration is ready, and keeps serving if it is not.
    Profile,
    /// The egress moved: the old core's connections are stranded.
    Egress,
}

pub(super) struct Controller<P: Port> {
    port: P,
    rx: Receiver<Message>,
    tx: Sender<Message>,
    shared: Arc<Mutex<Snapshot>>,
    timings: Timings,
    phase: Phase,
    run: Option<Run>,
    /// The core generation counter: every spawn takes the next.
    generation: u64,
    error: Option<String>,
    failures: u32,
    exits: VecDeque<Instant>,
    retry_at: Option<Instant>,
    local: String,
    reason: Option<String>,
    backlog: VecDeque<Message>,
    v6_restarted: Option<Instant>,
    egress_restarted: Option<Instant>,
    last_reset: Value,
    /// Why the core went direct, while its interception is still being
    /// withdrawn (CleanupPending, retried on the D2 timers).
    cause: Option<String>,
    /// The egress when the core went direct (D3): a new IPv4 egress since
    /// is worth a retry at once.
    seen: Uplink,
}

/// Why a wait ended early.
enum Interrupted {
    Exited(String),
    Cancelled,
    TimedOut,
}

impl<P: Port> Controller<P> {
    pub fn new(port: P, rx: Receiver<Message>, tx: Sender<Message>, shared: Arc<Mutex<Snapshot>>, timings: Timings) -> Self {
        Self {
            port,
            rx,
            tx,
            shared,
            timings,
            phase: Phase::Off,
            run: None,
            generation: 0,
            error: None,
            failures: 0,
            exits: VecDeque::new(),
            retry_at: None,
            local: String::new(),
            reason: None,
            backlog: VecDeque::new(),
            v6_restarted: None,
            egress_restarted: None,
            last_reset: Value::Null,
            cause: None,
            seen: Uplink::default(),
        }
    }

    /// Runs the controller; a panic on its thread calls `end` (finding 8).
    /// The core dies with this thread (its parent-death signal follows the
    /// thread that forked it), while the tables, LAN DNS redirected to it
    /// and a `running` snapshot would stay, in an agent `zte-agent guard`
    /// still sees alive. `end` takes the agent down, so the guard starts it
    /// again and the new agent adopts this boot's tables.
    pub fn supervised(self, end: impl FnOnce(String)) {
        if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.run())) {
            let what = panic.downcast_ref::<&str>().map(|s| (*s).to_owned()).or_else(|| panic.downcast_ref::<String>().cloned());
            end(what.unwrap_or_else(|| "a panic".into()));
        }
    }

    pub fn run(mut self) {
        loop {
            let message = match self.backlog.pop_front() {
                Some(message) => Some(message),
                None => match self.rx.recv_timeout(self.timings.tick) {
                    Ok(message) => Some(message),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => return,
                },
            };
            match message {
                #[cfg(test)]
                Some(Message::Stop) => return,
                Some(message) => self.handle(message),
                None => self.tick(),
            }
        }
    }

    fn publish(&mut self) {
        let tables = self.port.tables_status();
        let mut snapshot = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        snapshot.phase = self.phase;
        snapshot.error.clone_from(&self.error);
        snapshot.secret = self.run.as_ref().map(|r| r.prepared.secret.clone());
        snapshot.mode = self.run.as_ref().map(|r| r.mode);
        snapshot.failures = self.failures;
        snapshot.retry_at = self.retry_at;
        snapshot.reason.clone_from(&self.reason);
        snapshot.tables = tables;
        snapshot.generation = self.generation;
        snapshot.core_pid = self.run.as_ref().map(|r| r.core.pid());
        snapshot.notice = self.run.as_ref().and_then(|r| r.prepared.notice.clone()).or_else(|| self.run.as_ref().filter(|r| !r.ipv6).and_then(|r| {
            let nodes = r.prepared.routes.v6_only_in_use(r.mode, &r.selected);
            (!nodes.is_empty()).then(|| format!("{} only has an IPv6 server address and the uplink has no IPv6, so connections through it fail. Turn on IPv6 for the relay or choose another node.", nodes.join(", ")))
        }));
        snapshot.last_reset.clone_from(&self.last_reset);
        if self.phase == Phase::Off {
            snapshot.bypass = None;
        }
    }

    fn set_bypass(&mut self, bypass: Bypass) {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner).bypass = Some(bypass);
    }

    fn handle(&mut self, message: Message) {
        match message {
            Message::Boot => self.boot(),
            Message::Enable { local, owner, reply } => {
                let result = self.enable(local, owner);
                self.publish();
                if let Some(reply) = reply {
                    let _ = reply.send(result);
                }
            }
            Message::Disable { reply } => {
                let result = self.disable();
                self.publish();
                if let Some(reply) = reply {
                    let _ = reply.send(result);
                }
            }
            Message::Bypass { reply } => {
                let result = if self.phase == Phase::Running { self.reload("the DIRECT bypass setting changed") } else { Ok(()) };
                self.publish();
                let _ = reply.send(result);
            }
            Message::Config { refresh, reply } => {
                let result = match self.phase {
                    Phase::Running if refresh => self.refresh(),
                    Phase::Running => self.restart("the profile changed", Restart::Profile),
                    Phase::Backoff => self.start(false),
                    _ if refresh => self.port.prepare(&Source::Selected { local: self.local.clone(), runtime: None }, false).map(|_| ()),
                    _ => Ok(()),
                };
                self.publish();
                let _ = reply.send(result);
            }
            Message::Write { write, answer } => {
                let result = if self.phase == Phase::Running { self.write(&write) } else { Err("Mihomo is restarting; retry".into()) };
                self.publish();
                answer.send(result);
            }
            Message::Egress => {
                self.egress();
                self.publish();
            }
            Message::Guard => {
                if self.phase == Phase::Running {
                    self.guard();
                    self.publish();
                }
            }
            Message::Exited { generation, how } => {
                self.exited(generation, how);
                self.publish();
            }
            #[cfg(test)]
            Message::Stop => {}
        }
    }

    fn boot(&mut self) {
        if self.port.wanted() && self.port.adoptable() {
            crate::netlog!("[mihomo] adopting this boot's interception after an agent restart");
            self.phase = Phase::Restarting;
            self.reason = Some("the agent restarted".into());
            self.publish();
            let adopted = self.port.engage(Engage::Adopt).and_then(|()| self.port.tables(Shape::Hold));
            match adopted.and_then(|()| self.launch(Source::Selected { local: self.local.clone(), runtime: None }, true)) {
                Ok(()) => {}
                Err(e) => {
                    crate::netlog!("[mihomo] adoption failed: {e}");
                    self.fail(format!("Mihomo did not come back after the agent restarted: {e}"));
                }
            }
        } else if let Err(e) = self.port.recover() {
            self.phase = Phase::CleanupPending;
            self.error = Some(e);
        }
        self.publish();
    }

    fn enable(&mut self, local: String, owner: bool) -> Result<(), String> {
        if !local.is_empty() {
            self.local = local;
        }
        match self.phase {
            Phase::Running | Phase::Starting | Phase::Restarting | Phase::Reloading => {
                if owner {
                    self.port.set_wanted(true)?;
                } else {
                    crate::netlog!("[mihomo] restore: already {}", self.phase.name());
                }
                return Ok(());
            }
            // The boot restore runs once the router and the relay are back
            // (section 5.2): what failed before is worth trying now, not at
            // the next D2 step (up to 5 min away).
            Phase::Backoff if !owner => return self.retry(Some("the boot restore")),
            Phase::CleanupPending if !owner && self.cause.is_some() => return self.retry(Some("the boot restore")),
            Phase::CleanupPending => return Err(self.error.clone().unwrap_or_else(|| "Mihomo's previous network changes are not cleaned up; turn it off to retry".into())),
            Phase::Off | Phase::Backoff => {}
        }
        if !owner && !self.port.wanted() {
            return Ok(());
        }
        if owner {
            self.failures = 0;
            self.exits.clear();
        }
        let result = self.start(owner);
        match (&result, owner) {
            (Ok(()), true) => {
                if let Err(e) = self.port.set_wanted(true) {
                    self.error = Some(format!("Mihomo is on, but it will stay off after a restart: {e}"));
                }
            }
            // The owner saw it fail: a restart must not retry it.
            (Err(e), true) => {
                if let Err(clear) = self.port.set_wanted(false) {
                    let error = format!("{e}; {clear}. The saved restart choice could not be removed");
                    self.error = Some(error.clone());
                    return Err(error);
                }
            }
            _ => {}
        }
        result
    }

    fn disable(&mut self) -> Result<(), String> {
        self.retry_at = None;
        let forgotten = self.port.set_wanted(false);
        let result = self.stop_all();
        result.and(forgotten)
    }

    /// Stops the core and releases everything (Off), or CleanupPending.
    fn stop_all(&mut self) -> Result<(), String> {
        let had = self.run.is_some() || self.phase != Phase::Off;
        if let Some(run) = self.run.take() {
            run.core.stop();
        }
        self.retry_at = None;
        // Releasing everything also ends a D3 withdrawal still pending.
        self.cause = None;
        match self.port.release_all() {
            Ok(()) => {
                self.phase = Phase::Off;
                self.error = None;
                self.reason = None;
                if had {
                    self.reset("Mihomo turned off", Scope::Lan { v4: true, v6: false }, Instant::now());
                }
                Ok(())
            }
            Err(e) => {
                self.phase = Phase::CleanupPending;
                self.error = Some(e.clone());
                Err(e)
            }
        }
    }

    /// A start from Off or Backoff. Effects still held (D3 keeps the
    /// journal) are re-applied; with none held (a start that failed before
    /// it claimed any, an adoption that failed) they are claimed afresh.
    /// A failed start the owner asked for releases what it took and stays
    /// off (the owner sees the error); a boot restore or a retry falls back
    /// to D3 and retries.
    fn start(&mut self, owner: bool) -> Result<(), String> {
        let from_backoff = self.phase == Phase::Backoff;
        if let Some(busy) = self.port.busy() {
            if !owner {
                self.fail(busy.clone());
            }
            return Err(busy);
        }
        let how = if self.port.owns() { Engage::FromBackoff } else { Engage::Fresh };
        self.retry_at = None;
        self.phase = Phase::Starting;
        self.reason = None;
        self.publish();
        let engaged = self.port.engage(how).and_then(|()| {
            // A start from D3 keeps fake-ip failing fast until the full
            // table takes over (section 5.2).
            if how == Engage::FromBackoff {
                Ok(())
            } else {
                self.port.tables(Shape::Guard)
            }
        });
        let result = engaged.and_then(|()| self.launch(Source::Selected { local: self.local.clone(), runtime: None }, false));
        match &result {
            Ok(()) => {
                self.error = None;
                // Connections that went direct before keep their path until reset.
                let scope = Scope::Lan { v4: true, v6: from_backoff };
                self.reset("Mihomo started", scope, Instant::now());
                if let Some(run) = self.run.as_mut() {
                    run.reset_done();
                }
            }
            Err(e) if owner => {
                let _ = self.stop_all();
                if self.phase == Phase::Off {
                    self.error = Some(e.clone());
                }
            }
            Err(e) => self.fail(e.clone()),
        }
        result
    }

    /// Prepares, spawns and verifies a core, then loads the plan its
    /// read-back mode and choices give. The tables already hold or guard.
    fn launch(&mut self, source: Source, restart: bool) -> Result<(), String> {
        let prepared = self.port.prepare(&source, false)?;
        self.launch_prepared(prepared, restart)
    }

    /// `launch` with a configuration already prepared and validated.
    fn launch_prepared(&mut self, prepared: Prepared, restart: bool) -> Result<(), String> {
        self.port.ports_free()?;
        self.generation += 1;
        let generation = self.generation;
        let core = self.port.spawn(generation, &prepared, self.tx.clone())?;
        let deadline = Instant::now() + self.timings.ready;
        let ready = self.wait(deadline, generation, |port| port.ready(&prepared));
        if let Err(why) = ready {
            core.stop();
            return Err(match why {
                Interrupted::Exited(how) => format!("Mihomo exited while starting ({how})"),
                Interrupted::Cancelled => "Turned off while starting".into(),
                Interrupted::TimedOut => "Mihomo controller, private download proxy, transparent proxy port or dual-stack TCP/UDP DNS did not become ready".into(),
            });
        }
        if !restart {
            // Guard only so far: interception goes in now that it listens.
            if let Err(e) = self.port.tables(Shape::Hold) {
                core.stop();
                return Err(e);
            }
        }
        if let Err(e) = self.port.verify_routing() {
            core.stop();
            return Err(e);
        }
        // The first table with DIRECT returns follows what this core
        // reports once ready, never what was stored before (section 3).
        let Some((mode, selected, runtime)) = self.port.read_back(&prepared.secret) else {
            core.stop();
            return Err("Mihomo did not report its mode and proxy groups".into());
        };
        let mut prepared = prepared;
        prepared.runtime = runtime;
        let (bypass, chain) = self.port.plan(&prepared.routes, prepared.bypass, mode, &selected, &[]);
        let now = Instant::now();
        let refresh = prepared.routes.refresh().into_iter().enumerate().map(|(i, (name, every))| {
            let every = Duration::from_secs(every);
            (name, every, now + every.min(Duration::from_secs(3600)) + Duration::from_secs(10 * i as u64))
        }).collect();
        let uplink = self.port.uplink(true);
        self.run = Some(Run {
            core,
            prepared: prepared.clone(),
            mode,
            selected,
            // The tables hold: nothing skips the core yet.
            kernel: (Bypass::None("The kernel plan is being loaded".into()), Chain::default()),
            pending: Vec::new(),
            bypassed: Vec::new(),
            unfollowed: false,
            ipv6: uplink.paths[1].is_some(),
            uplink,
            stranding: None,
            v6: None,
            started: now,
            audited: now,
            followed: now,
            refresh,
        });
        if let Err(e) = self.load(Shape::Full(&chain), bypass, false) {
            // Stays held (nothing skips the core) until a reconcile loads
            // it; `guard` then takes it as the kernel's.
            self.set_bypass(Bypass::None(format!("The kernel plan is not confirmed yet: {e}")));
            self.error = Some(e);
        }
        self.phase = Phase::Running;
        self.reason = None;
        self.publish();
        crate::netlog!("[mihomo] running generation={generation} mode={}", mode.name());
        Ok(())
    }

    /// Waits until `done`, or a reason to stop waiting: the exit of this
    /// generation's core, the owner turning it off. Other messages wait in
    /// the backlog, in order.
    fn wait(&mut self, deadline: Instant, generation: u64, mut done: impl FnMut(&mut P) -> bool) -> Result<(), Interrupted> {
        loop {
            if done(&mut self.port) {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Interrupted::TimedOut);
            }
            match self.rx.recv_timeout((deadline - now).min(Duration::from_millis(150))) {
                Ok(Message::Exited { generation: g, how }) if g == generation => return Err(Interrupted::Exited(how)),
                Ok(Message::Exited { generation: g, how }) => crate::netlog!("[mihomo] ignored the exit of an old core generation={g} ({how})"),
                Ok(message @ Message::Disable { .. }) => {
                    self.backlog.push_front(message);
                    return Err(Interrupted::Cancelled);
                }
                Ok(message) => self.backlog.push_back(message),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(Interrupted::Cancelled),
            }
        }
    }

    /// A planned restart (finding 4). The new configuration is prepared and
    /// validated while the old core still serves (`mihomo -t` took about
    /// 1.7 s, a clock check up to 16 s, all of it behind a hold table with
    /// no core); only then is the bypass tightened (hold), the old core
    /// stopped and the new one started (I4). A profile that does not
    /// validate leaves the old core serving; one that validates but does not
    /// start falls back to the configuration that ran before.
    fn restart(&mut self, reason: &str, why: Restart) -> Result<(), String> {
        crate::netlog!("[mihomo] restarting: {reason}");
        let Some(run) = self.run.as_ref() else { return Ok(()) };
        let source = Source::Selected { local: run.prepared.local.clone(), runtime: Some(run.prepared.runtime.clone()) };
        let prepared = match self.port.prepare(&source, why == Restart::Profile) {
            Ok(prepared) => prepared,
            Err(e) if why == Restart::Profile => {
                crate::netlog!("[mihomo] the new profile was not started ({e}); the running one keeps serving");
                let error = format!("{e}; the running profile keeps serving");
                self.error = Some(error.clone());
                return Err(error);
            }
            Err(e) => {
                let error = format!("The planned restart failed: {e}");
                self.fail(error.clone());
                return Err(error);
            }
        };
        self.restart_prepared(reason, why, prepared)
    }

    fn restart_prepared(&mut self, reason: &str, why: Restart, prepared: Prepared) -> Result<(), String> {
        // Interception stays and nothing may skip the core before the old
        // one stops (section 5.2).
        if self.phase != Phase::Reloading {
            self.load(Shape::Hold, Bypass::None(format!("Restarting: {reason}")), true).map_err(|e| format!("Mihomo was not restarted: {e}"))?;
        }
        let Some(old) = self.run.take() else { return Ok(()) };
        self.phase = Phase::Restarting;
        self.reason = Some(reason.into());
        self.publish();
        let held = Instant::now();
        old.core.stop();
        let mut result = self.launch_prepared(prepared, true);
        if let (Err(e), Restart::Profile) = (&result, why) {
            crate::netlog!("[mihomo] the new profile did not start ({e}); starting the previous one");
            let fallback = self.launch(Source::Previous(Box::new(old.prepared.clone())), true);
            result = match fallback {
                Ok(()) => Err(format!("{e}; the previous profile was started again")),
                Err(again) => Err(format!("{e}; the previous profile did not start either: {again}")),
            };
            if self.phase == Phase::Running {
                crate::netlog!("[mihomo] the restart held traffic for {} ms", held.elapsed().as_millis());
                self.error = result.as_ref().err().cloned();
                return result;
            }
        }
        match &result {
            Ok(()) => {
                crate::netlog!("[mihomo] the restart held traffic for {} ms", held.elapsed().as_millis());
                let lost = routing::lost_from(&old.bypassed, self.run.as_ref().map_or(&Chain::default(), Run::target));
                self.reset("Mihomo restarted", lost, Instant::now());
                if let Some(run) = self.run.as_mut() {
                    run.reset_done();
                }
            }
            Err(e) => self.fail(format!("The planned restart failed: {e}")),
        }
        result
    }

    /// v3 (section 5.5): the same configuration with another DNS filter,
    /// by `PUT /configs?force=false`. Tightened first; committed only when
    /// the read-back proves it (a 204 alone does not, a timeout is unknown);
    /// otherwise a planned restart behind the interception takes over.
    fn reload(&mut self, reason: &str) -> Result<(), String> {
        let Some(run) = self.run.as_ref() else { return Ok(()) };
        let previous = run.prepared.clone();
        let next = self.port.prepare(&Source::Reload(Box::new(previous.clone())), true)?;
        if next.config == previous.config {
            if self.run.as_ref().is_some_and(Run::may_return) {
                self.load(Shape::Hold, Bypass::None(format!("Following {reason}")), true)?;
            }
            if let Some(run) = self.run.as_mut() {
                run.prepared = next.clone();
            }
            self.widen(reason);
            return Ok(());
        }
        self.reload_prepared(reason, next)
    }

    fn refresh(&mut self) -> Result<(), String> {
        let Some(run) = self.run.as_ref() else { return Ok(()) };
        if !self.port.ready(&run.prepared) {
            return self.restart("the profile changed while the core was unhealthy", Restart::Profile);
        }
        let previous = run.prepared.clone();
        let next = self.port.prepare(&Source::Refresh(Box::new(previous.clone())), true)?;
        if super::reload::needs_restart(&previous.config, &next.config) {
            return self.restart_prepared("the profile changed startup settings", Restart::Profile, next);
        }
        self.reload_prepared("the selected subscription refreshed", next)
    }

    fn reload_prepared(&mut self, reason: &str, next: Prepared) -> Result<(), String> {
        let Some(run) = self.run.as_ref() else { return Ok(()) };
        let (previous, before) = (run.prepared.clone(), run.selected.clone());
        if self.run.as_ref().is_some_and(Run::may_return) {
            self.load(Shape::Hold, Bypass::None(format!("Reloading: {reason}")), true).map_err(|e| format!("Nothing was changed: the bypass could not be narrowed first ({e})"))?;
        }
        crate::netlog!("[mihomo] reloading: {reason}");
        self.set_bypass(Bypass::None(format!("Reloading: {reason}")));
        self.phase = Phase::Reloading;
        self.reason = Some(reason.into());
        self.publish();
        let started = Instant::now();
        let answered = self.port.reload(&next.secret, &next.config);
        let probe = routing::reload_probe(&previous.dns, &next.dns);
        let verified = match &answered {
            Ok(status) if !(200..300).contains(status) => Err("Mihomo rejected the reload".into()),
            Err(_) if next.source != previous.source => Err("the subscription reload result is unknown".into()),
            _ => self.port.verify_reload(&next, probe.as_ref(), &before),
        };
        crate::netlog!("[mihomo] reload answered={answered:?} verified={:?} elapsed_ms={}", verified.as_ref().err(), started.elapsed().as_millis());
        match verified {
            Ok(()) => {
                if let Some(run) = self.run.as_mut() {
                    run.prepared = next.clone();
                    let now = Instant::now();
                    run.refresh = next.routes.refresh().into_iter().map(|(name, every)| {
                        let every = Duration::from_secs(every);
                        (name, every, now + every)
                    }).collect();
                }
                self.phase = Phase::Running;
                self.reason = None;
                self.widen(reason);
                Ok(())
            }
            Err(e) => self.restart_prepared(&format!("the reload was not confirmed ({e})"), Restart::Profile, next),
        }
    }

    /// D3: a confirmed core failure. Interception is withdrawn and LAN
    /// traffic goes direct while fake-ip fails fast; retries follow D2.
    fn fail(&mut self, error: String) {
        crate::netlog!("[mihomo] direct until the core is back: {error}");
        self.seen = match self.run.take() {
            Some(run) => {
                run.core.stop();
                run.uplink
            }
            None => self.port.uplink(true),
        };
        let now = Instant::now();
        self.exits.push_back(now);
        while self.exits.front().is_some_and(|at| now.duration_since(*at) > self.timings.quick) {
            self.exits.pop_front();
        }
        self.failures += 1;
        self.retry_at = Some(now + self.step());
        self.cause = Some(error);
        self.withdraw();
    }

    /// The D2 wait before the next retry.
    fn step(&self) -> Duration {
        let last = self.timings.retries.len() - 1;
        self.timings.retries[if self.exits.len() >= 3 { last } else { (self.failures.max(1) as usize - 1).min(last) }]
    }

    /// D3's withdrawal: Backoff once it is done. Until then the old tables
    /// may still send LAN traffic and DNS to a core that is gone, so the
    /// state is CleanupPending (not "direct") and the withdrawal is tried
    /// again on the D2 timers (finding 3). With effects held, interception
    /// gives way to the fake-ip reject (`Port::direct`); with none held,
    /// whatever a previous agent left is rolled back (`Port::recover`): an
    /// adoption that failed before it took them leaves that agent's tables,
    /// LAN DNS redirected to a core that died with it (finding 2).
    fn withdraw(&mut self) {
        let Some(cause) = self.cause.clone() else { return };
        let withdrawn = if self.port.owns() { self.port.direct() } else { self.port.recover() };
        match withdrawn {
            Ok(()) => {
                self.cause = None;
                self.phase = Phase::Backoff;
                self.error = Some(cause);
                self.set_bypass(Bypass::None("Mihomo is not running; LAN traffic goes direct".into()));
            }
            Err(e) => {
                crate::netlog!("[mihomo] the interception could not be withdrawn yet: {e}");
                self.phase = Phase::CleanupPending;
                self.error = Some(format!("{cause}; its interception could not be withdrawn yet, so LAN traffic may still be sent to it ({e}); retrying"));
                self.set_bypass(Bypass::None("Mihomo is not running and its interception is still in place".into()));
            }
        }
    }

    /// D2's retry (`why`: what made it come early): the withdrawal if it is
    /// still pending, then a start; off if the owner no longer wants it.
    fn retry(&mut self, why: Option<&str>) -> Result<(), String> {
        if !self.port.wanted() {
            return self.stop_all();
        }
        match why {
            Some(why) => crate::netlog!("[mihomo] retrying now ({why}) after {} failure(s)", self.failures),
            None => crate::netlog!("[mihomo] retrying after {} failure(s)", self.failures),
        }
        if self.cause.is_some() {
            self.withdraw();
            if self.cause.is_some() {
                self.retry_at = Some(Instant::now() + self.step());
                return Err(self.error.clone().unwrap_or_default());
            }
        }
        self.start(false)
    }

    /// Loads `shape` and records it either way: a table that did not
    /// confirm stays `NftTables`' target, which a reconcile may load later.
    /// `narrowing`: before a change.
    fn load(&mut self, shape: Shape, bypass: Bypass, narrowing: bool) -> Result<(), String> {
        let chain = match &shape {
            Shape::Full(chain) => (*chain).clone(),
            _ => Chain::default(),
        };
        let loaded = self.port.tables(shape);
        if let Some(run) = self.run.as_mut() {
            run.declared(bypass, chain, narrowing, loaded.is_ok());
            run.unfollowed |= narrowing && loaded.is_ok();
            let shown = run.kernel.0.clone();
            self.set_bypass(shown);
        }
        loaded
    }

    fn exited(&mut self, generation: u64, how: String) {
        if self.run.as_ref().is_none_or(|r| r.core.generation() != generation) {
            crate::netlog!("[mihomo] ignored the exit of an old core generation={generation} ({how})");
            return;
        }
        self.fail(format!("Mihomo exited ({how})"));
    }

    /// A routing write (section 5.4): tighten, write, read back, load the
    /// new plan, reset what lost DIRECT. Refreshing a rule set the kernel
    /// never reads (`domain`) changes no plan and no DNS answer (a refreshed
    /// set's names are fake-ip): it goes to the core as it is, with no table
    /// loaded around it (finding 6: two 112 KB loads per refresh before).
    fn write(&mut self, write: &Write) -> Answered {
        let run = self.run.as_ref().ok_or("Mihomo is off")?;
        let secret = run.prepared.secret.clone();
        let unsettled: Vec<String> = match write.segments.as_slice() {
            [providers, rules, name] if providers == "providers" && rules == "rules" => vec![name.clone()],
            _ => Vec::new(),
        };
        if unsettled.first().is_some_and(|name| !run.prepared.routes.reaches_kernel(name)) {
            return self.port.write(&secret, write);
        }
        let mut answer = None;
        self.follow("a routing change", &unsettled, |port| {
            answer = Some(port.write(&secret, write));
        })?;
        answer.unwrap_or_else(|| Err("Mihomo did not answer".into()))
    }

    /// Tightens before `change`, then follows what the core reports. With
    /// `unsettled` rule sets, only they are treated as unknown meanwhile;
    /// otherwise nothing skips the core during the change. Whether to
    /// tighten is decided by everything the kernel may hold, a table still
    /// pending included (I4).
    fn follow(&mut self, why: &str, unsettled: &[String], change: impl FnOnce(&mut P)) -> Result<(), String> {
        let Some(run) = self.run.as_ref() else { return Err("Mihomo is off".into()) };
        if run.may_return() {
            let narrowed = if unsettled.is_empty() {
                self.load(Shape::Hold, Bypass::None(format!("Following {why}")), true)
            } else {
                let (routes, enabled, mode, selected) = (run.prepared.routes.clone(), run.prepared.bypass, run.mode, run.selected.clone());
                let (bypass, tight) = self.port.plan(&routes, enabled, mode, &selected, unsettled);
                self.load(Shape::Full(&tight), bypass, true)
            };
            narrowed.map_err(|e| format!("Nothing was changed: the bypass could not be narrowed first ({e})"))?;
        }
        change(&mut self.port);
        self.widen(why);
        Ok(())
    }

    /// Reads back what the core runs and loads the plan that gives,
    /// resetting what lost DIRECT since the last reset. Until the core
    /// answers, the bypass stays narrowed and the next tick asks again.
    fn widen(&mut self, why: &str) {
        let Some(secret) = self.run.as_ref().map(|r| r.prepared.secret.clone()) else { return };
        let Some((mode, selected, runtime)) = self.port.read_back(&secret) else {
            self.error = Some(format!("Mihomo did not report its state after {why}; the bypass stays narrowed until it does"));
            return;
        };
        let Some(run) = self.run.as_mut() else { return };
        let routes = run.prepared.routes.clone();
        let (bypass, chain) = self.port.plan(&routes, run.prepared.bypass, mode, &selected, &[]);
        let lost = self.run.as_ref().map(|run| routing::lost_from(&run.bypassed, &chain)).unwrap_or(Scope::Destinations(Vec::new()));
        self.reset("Mihomo routing changed", lost, Instant::now());
        if let Some(run) = self.run.as_mut() {
            run.reset_done();
            run.mode = mode;
            run.selected = selected;
            run.prepared.runtime = runtime;
            run.followed = Instant::now();
            run.unfollowed = false;
        }
        if let Err(e) = self.load(Shape::Full(&chain), bypass, false) {
            if self.run.as_ref().is_some_and(|r| r.kernel.1.returns == 0) {
                self.set_bypass(Bypass::None(format!("The new kernel plan is not confirmed yet: {e}")));
            }
            self.error = Some(e);
        }
    }

    fn reset(&mut self, reason: &'static str, scope: Scope, changed: Instant) {
        self.last_reset = match self.port.reset(reason, scope, changed) {
            Ok(report) => report.json(),
            Err(e) => crate::netfx::conntrack::failed_json(&e),
        };
    }

    /// The relay changed its routes.
    /// `net_guard`'s check when it is due: another writer may have removed
    /// interception, routes or kernel settings. A table that had not loaded
    /// may load here: what the controller believes and shows follows it,
    /// and a narrowing that was loaded for a change that never happened is
    /// widened again once the core is read back.
    fn guard(&mut self) {
        if !self.port.guard_due() {
            return;
        }
        let checked = self.port.reconcile();
        if let Err(e) = checked.result {
            self.error = Some(e);
        }
        let Some(run) = self.run.as_mut().filter(|_| checked.confirmed) else { return };
        let Some(narrowing) = run.loaded() else { return };
        crate::netlog!("[mihomo] a table that had not loaded is in the kernel now (bypass {})", run.kernel.0.label());
        let shown = run.kernel.0.clone();
        self.set_bypass(shown);
        if narrowing {
            self.widen("a narrowed table that loaded late");
        }
    }

    fn egress(&mut self) {
        let observed = self.port.uplink(true);
        let Some(run) = self.run.as_mut() else {
            self.egress_while_direct(observed);
            return;
        };
        run.ipv6 = observed.paths[1].is_some();
        match egress::change(&run.uplink, &observed) {
            Change::None => crate::netlog!("[mihomo] duplicate uplink notification; core kept running"),
            Change::Adopt => {
                run.uplink.adopt(&observed);
                run.v6 = None;
                crate::netlog!("[mihomo] the egress changed without moving the core's connections; core kept running");
            }
            Change::Gone => {
                run.v6 = None;
                crate::netlog!("[mihomo] no egress; the core keeps running until one appears");
            }
            Change::V6 => {
                if run.v6.as_ref().is_none_or(|(seen, _)| *seen != observed) {
                    run.v6 = Some((observed, Instant::now()));
                }
            }
            Change::V4 => {
                if let Err(e) = self.restart("the egress changed", Restart::Egress) {
                    crate::netlog!("[mihomo] did not follow the egress change: {e}");
                }
            }
        }
    }

    /// In D3 (or while its withdrawal is pending), an IPv4 egress that is
    /// new since the core went direct (the relay came up after the boot
    /// restore failed without it, or moved) retries at once instead of at
    /// the next D2 step.
    fn egress_while_direct(&mut self, observed: Uplink) {
        if self.phase != Phase::Backoff && self.cause.is_none() {
            return;
        }
        let change = egress::change(&self.seen, &observed);
        if matches!(change, Change::Adopt | Change::V6 | Change::V4) {
            self.seen.adopt(&observed);
        }
        if change == Change::V4 {
            let _ = self.retry(Some("a new IPv4 egress"));
        }
    }

    fn tick(&mut self) {
        self.port.retry_reset();
        match self.phase {
            Phase::Backoff | Phase::CleanupPending if (self.phase == Phase::Backoff || self.cause.is_some()) && self.retry_at.is_some_and(|at| Instant::now() >= at) => {
                let _ = self.retry(None);
                self.publish();
                return;
            }
            Phase::Running => {}
            _ => return,
        }
        let now = Instant::now();
        if self.run.as_ref().is_some_and(|r| now.duration_since(r.started) >= self.timings.stable) && self.failures > 0 {
            self.failures = 0;
            self.exits.clear();
        }
        self.guard();
        // A narrowing whose follow did not read the core back yet.
        if self.run.as_ref().is_some_and(|r| r.unfollowed) {
            self.widen("an earlier change");
        }
        // An IPv6-only egress change that held.
        let v6 = self.run.as_ref().and_then(|r| r.v6.clone());
        if let Some((seen, since)) = v6 {
            let observed = self.port.uplink(true);
            if observed != seen {
                if let Some(run) = self.run.as_mut() {
                    run.v6 = (egress::change(&run.uplink, &observed) == Change::V6).then(|| (observed, now));
                }
            } else if egress::v6_due(since, self.v6_restarted) <= now {
                self.v6_restarted = Some(now);
                let _ = self.restart("the IPv6 egress changed", Restart::Egress);
                self.publish();
                return;
            }
        }
        // Outside the relay: only an egress that strands connections. The
        // relay announces its own routes, so this needs no `iw`.
        if self.run.as_ref().is_some_and(|r| now.duration_since(r.audited) >= self.timings.audit || r.stranding.is_some()) {
            let observed = self.port.uplink(false);
            let last = self.egress_restarted;
            let restart = self.run.as_mut().is_some_and(|run| {
                run.audited = now;
                run.ipv6 = observed.paths[1].is_some();
                egress::settle_egress(&mut run.uplink, &mut run.stranding, observed, last, now)
            });
            if restart {
                self.egress_restarted = Some(now);
                let _ = self.restart("the egress left the core's interface or source address", Restart::Egress);
                self.publish();
                return;
            }
        }
        // Rule sets the controller refreshes (Q2), one per tick.
        let due = self.run.as_ref().and_then(|r| r.refresh.iter().position(|(_, _, at)| *at <= now));
        if let Some(index) = due {
            let (name, every) = {
                let run = self.run.as_mut().unwrap();
                let entry = &mut run.refresh[index];
                entry.2 = now + entry.1;
                (entry.0.clone(), entry.1)
            };
            let write = Write { method: "PUT", segments: vec!["providers".into(), "rules".into(), name.clone()], body: json!({}) };
            match self.write(&write) {
                Ok((status, _)) if (200..300).contains(&status) => crate::netlog!("[mihomo] refreshed rule set {name}"),
                outcome => {
                    // Again in 10 min (or at its own interval, if shorter).
                    if let Some(entry) = self.run.as_mut().map(|r| &mut r.refresh[index]) {
                        entry.2 = now + every.min(Duration::from_secs(600));
                    }
                    crate::netlog!("[mihomo] rule set {name} not refreshed: {:?}", outcome.map(|(status, _)| status));
                }
            }
        }
        // The fallback re-read: a mode or choice changed without passing
        // here, or a rule-set file changed, is followed at once.
        let sources = self.port.sources_changed();
        let follow = sources || self.run.as_ref().is_some_and(|r| now.duration_since(r.followed) >= self.timings.follow);
        if follow {
            let current = self.run.as_ref().map(|r| (r.mode, r.selected.clone(), r.prepared.secret.clone()));
            if let Some((mode, selected, secret)) = current {
                let differs = sources || self.port.read_back(&secret).is_none_or(|(m, s, _)| m != mode || s != selected);
                if differs {
                    crate::netlog!("[mihomo] the core's mode, a group or a rule set changed outside the controller; following it");
                    let _ = self.follow("a change in the core", &[], |_| {});
                } else if let Some(run) = self.run.as_mut() {
                    run.followed = now;
                }
            }
        }
        self.publish();
    }
}

/// The D2 wait before retry number `failures` (1-based), given recent exits.
#[cfg(test)]
pub(super) fn retry_wait(timings: &Timings, failures: u32, recent_exits: usize) -> Duration {
    let last = timings.retries.len() - 1;
    timings.retries[if recent_exits >= 3 { last } else { (failures as usize).saturating_sub(1).min(last) }]
}

#[cfg(test)]
mod tests;
