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
//! release failed: the journal and ownership stay).

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
    Config { reply: Reply },
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
    fn prepare(&mut self, source: &Source) -> Result<Prepared, String>;
    /// Ports the core binds are free (checked before each spawn).
    fn ports_free(&mut self) -> Result<(), String>;
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
    fn plan(&mut self, routes: &routing::Routes, mode: Mode, selected: &Selected, unsettled: &[String]) -> (Bypass, Chain);
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
    fn uplink(&mut self) -> Uplink;
    /// Re-applies what another writer removed (`net_guard` decides when).
    fn reconcile(&mut self) -> Result<(), String>;
    /// Whether the owner wants Mihomo on after a restart.
    fn wanted(&mut self) -> bool;
    fn set_wanted(&mut self, on: bool) -> Result<(), String>;
    /// A rule set's file changed since `plan` read it.
    fn sources_changed(&mut self) -> bool;
    fn guard_due(&mut self) -> bool;
    fn retry_reset(&mut self);
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

/// The running core and what the kernel was set up for.
struct Run {
    core: Box<dyn CoreHandle>,
    prepared: Prepared,
    mode: Mode,
    selected: Selected,
    /// What the kernel holds (`Chain::default()` while nothing is bypassed).
    chain: Chain,
    /// The widest chain connections may still use: what was bypassed since
    /// the last reset (a tightening narrows `chain`, not this).
    bypassed: Chain,
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
    /// The last configuration that ran, to fall back to.
    previous: Option<Prepared>,
    v6_restarted: Option<Instant>,
    egress_restarted: Option<Instant>,
    last_reset: Value,
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
            previous: None,
            v6_restarted: None,
            egress_restarted: None,
            last_reset: Value::Null,
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
        snapshot.notice = self.run.as_ref().filter(|r| !r.ipv6).and_then(|r| {
            let nodes = r.prepared.routes.v6_only_in_use(r.mode, &r.selected);
            (!nodes.is_empty()).then(|| format!("{} only has an IPv6 server address and the uplink has no IPv6, so connections through it fail. Turn on IPv6 for the relay or choose another node.", nodes.join(", ")))
        });
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
            Message::Config { reply } => {
                let result = match self.phase {
                    Phase::Running => self.restart("the profile changed", true),
                    Phase::Backoff => self.start(Engage::FromBackoff, false),
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
                }
                return Ok(());
            }
            Phase::CleanupPending => return Err(self.error.clone().unwrap_or_else(|| "Mihomo's previous network changes are not cleaned up; turn it off to retry".into())),
            Phase::Backoff if !owner => return Ok(()),
            Phase::Off | Phase::Backoff => {}
        }
        if !owner && !self.port.wanted() {
            return Ok(());
        }
        let from = if self.phase == Phase::Backoff { Engage::FromBackoff } else { Engage::Fresh };
        if owner {
            self.failures = 0;
            self.exits.clear();
        }
        let result = self.start(from, owner);
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

    /// A start from Off or Backoff (`how`). A failed start the owner asked
    /// for releases what it took and stays off (the owner sees the error);
    /// a boot restore or a retry falls back to D3 and retries.
    fn start(&mut self, how: Engage, owner: bool) -> Result<(), String> {
        if let Some(busy) = self.port.busy() {
            if !owner {
                self.fail(busy.clone());
            }
            return Err(busy);
        }
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
                let scope = Scope::Lan { v4: true, v6: how == Engage::FromBackoff };
                self.reset("Mihomo started", scope, Instant::now());
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
        let prepared = self.port.prepare(&source)?;
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
        let (bypass, chain) = self.port.plan(&prepared.routes, mode, &selected, &[]);
        let now = Instant::now();
        let refresh = prepared.routes.refresh().into_iter().enumerate().map(|(i, (name, every))| {
            let every = Duration::from_secs(every);
            (name, every, now + every.min(Duration::from_secs(3600)) + Duration::from_secs(10 * i as u64))
        }).collect();
        let uplink = self.port.uplink();
        let mut run = Run {
            core,
            prepared: prepared.clone(),
            mode,
            selected,
            chain: Chain::default(),
            bypassed: Chain::default(),
            ipv6: uplink.paths[1].is_some(),
            uplink,
            stranding: None,
            v6: None,
            started: now,
            audited: now,
            followed: now,
            refresh,
        };
        match self.port.tables(Shape::Full(&chain)) {
            Ok(()) => {
                run.bypassed = chain.clone();
                run.chain = chain;
                self.set_bypass(bypass);
            }
            Err(e) => {
                // Stays held (nothing skips the core) until a reconcile loads it.
                self.set_bypass(Bypass::None(format!("The kernel plan is not confirmed yet: {e}")));
                self.error = Some(e);
            }
        }
        self.run = Some(run);
        self.previous = Some(prepared);
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

    /// A planned restart: tighten (hold), stop the old core, start the new
    /// one, load its plan. `config`: the profile changed, so a failure falls
    /// back to the configuration that ran before.
    fn restart(&mut self, reason: &str, config: bool) -> Result<(), String> {
        crate::netlog!("[mihomo] restarting: {reason}");
        // Interception stays and nothing may skip the core before the old
        // one stops (section 5.2).
        self.port.tables(Shape::Hold).map_err(|e| format!("Mihomo was not restarted: {e}"))?;
        let Some(old) = self.run.take() else { return Ok(()) };
        self.set_bypass(Bypass::None(format!("Restarting: {reason}")));
        self.phase = Phase::Restarting;
        self.reason = Some(reason.into());
        self.publish();
        old.core.stop();
        let runtime = Some(old.prepared.runtime.clone());
        let mut result = self.launch(Source::Selected { local: old.prepared.local.clone(), runtime }, true);
        if let (Err(e), true) = (&result, config) {
            crate::netlog!("[mihomo] the new profile did not start ({e}); starting the previous one");
            let fallback = self.launch(Source::Previous(Box::new(old.prepared.clone())), true);
            result = match fallback {
                Ok(()) => Err(format!("{e}; the previous profile was started again")),
                Err(again) => Err(format!("{e}; the previous profile did not start either: {again}")),
            };
            if self.phase == Phase::Running {
                self.error = result.as_ref().err().cloned();
                return result;
            }
        }
        match &result {
            Ok(()) => {
                let lost = routing::lost(&old.bypassed, &self.run.as_ref().map(|r| r.chain.clone()).unwrap_or_default());
                self.reset("Mihomo restarted", lost, Instant::now());
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
        let (previous, before) = (run.prepared.clone(), run.selected.clone());
        let next = self.port.prepare(&Source::Reload(Box::new(previous.clone())))?;
        if next.dns == previous.dns {
            // DNS stays: only what skips the core changes.
            return self.follow(reason, &[], |_| {});
        }
        if run.chain.returns > 0 {
            self.port.tables(Shape::Hold).map_err(|e| format!("Nothing was changed: the bypass could not be narrowed first ({e})"))?;
            if let Some(run) = self.run.as_mut() {
                run.chain = Chain::default();
            }
        }
        crate::netlog!("[mihomo] reloading: {reason}");
        self.set_bypass(Bypass::None(format!("Reloading: {reason}")));
        self.phase = Phase::Reloading;
        self.reason = Some(reason.into());
        self.publish();
        let started = Instant::now();
        let answered = self.port.reload(&next.secret, &next.config);
        let probe = routing::reload_probe(&previous.dns, &next.dns);
        let verified = self.port.verify_reload(&next, probe.as_ref(), &before);
        crate::netlog!("[mihomo] reload answered={answered:?} verified={:?} elapsed_ms={}", verified.as_ref().err(), started.elapsed().as_millis());
        self.phase = Phase::Running;
        self.reason = None;
        match verified {
            Ok(()) => {
                if let Some(run) = self.run.as_mut() {
                    run.prepared = next.clone();
                }
                self.previous = Some(next);
                self.follow(reason, &[], |_| {})
            }
            Err(e) => self.restart(&format!("the reload was not confirmed ({e})"), false),
        }
    }

    /// D3: a confirmed core failure. Interception is withdrawn and LAN
    /// traffic goes direct while fake-ip fails fast; retries follow D2.
    fn fail(&mut self, error: String) {
        crate::netlog!("[mihomo] direct until the core is back: {error}");
        if let Some(run) = self.run.take() {
            run.core.stop();
        }
        if let Err(e) = self.port.direct() {
            self.phase = Phase::CleanupPending;
            self.error = Some(format!("{error}; and its network changes could not be released: {e}"));
            return;
        }
        let now = Instant::now();
        self.exits.push_back(now);
        while self.exits.front().is_some_and(|at| now.duration_since(*at) > self.timings.quick) {
            self.exits.pop_front();
        }
        self.failures += 1;
        let last = self.timings.retries.len() - 1;
        let step = if self.exits.len() >= 3 { last } else { (self.failures as usize - 1).min(last) };
        self.retry_at = Some(now + self.timings.retries[step]);
        self.phase = Phase::Backoff;
        self.error = Some(error);
        self.set_bypass(Bypass::None("Mihomo is not running; LAN traffic goes direct".into()));
    }

    fn exited(&mut self, generation: u64, how: String) {
        if self.run.as_ref().is_none_or(|r| r.core.generation() != generation) {
            crate::netlog!("[mihomo] ignored the exit of an old core generation={generation} ({how})");
            return;
        }
        self.fail(format!("Mihomo exited ({how})"));
    }

    /// A routing write (section 5.4): tighten, write, read back, load the
    /// new plan, reset what lost DIRECT.
    fn write(&mut self, write: &Write) -> Answered {
        let secret = self.run.as_ref().map(|r| r.prepared.secret.clone()).ok_or("Mihomo is off")?;
        let unsettled: Vec<String> = match write.segments.as_slice() {
            [providers, rules, name] if providers == "providers" && rules == "rules" => vec![name.clone()],
            _ => Vec::new(),
        };
        let mut answer = None;
        self.follow("a routing change", &unsettled, |port| {
            answer = Some(port.write(&secret, write));
        })?;
        answer.unwrap_or_else(|| Err("Mihomo did not answer".into()))
    }

    /// Tightens before `change`, then follows what the core reports. With
    /// `unsettled` rule sets, only they are treated as unknown meanwhile;
    /// otherwise nothing skips the core during the change.
    fn follow(&mut self, why: &str, unsettled: &[String], change: impl FnOnce(&mut P)) -> Result<(), String> {
        let Some(run) = self.run.as_ref() else { return Err("Mihomo is off".into()) };
        let (old, routes, mode, selected, secret) = (run.bypassed.clone(), run.prepared.routes.clone(), run.mode, run.selected.clone(), run.prepared.secret.clone());
        if run.chain.returns > 0 {
            let tightened = if unsettled.is_empty() {
                self.port.tables(Shape::Hold)
            } else {
                let (_, tight) = self.port.plan(&routes, mode, &selected, unsettled);
                self.port.tables(Shape::Full(&tight))
            };
            tightened.map_err(|e| format!("Nothing was changed: the bypass could not be narrowed first ({e})"))?;
            if let Some(run) = self.run.as_mut() {
                run.chain = Chain::default();
            }
            self.set_bypass(Bypass::None(format!("Following {why}")));
        }
        change(&mut self.port);
        let Some((mode, selected, runtime)) = self.port.read_back(&secret) else {
            self.error = Some(format!("Mihomo did not report its state after {why}; the bypass stays off until it does"));
            return Ok(());
        };
        let (bypass, chain) = self.port.plan(&routes, mode, &selected, &[]);
        let lost = routing::lost(&old, &chain);
        let changed = Instant::now();
        self.reset("Mihomo routing changed", lost, changed);
        let loaded = self.port.tables(Shape::Full(&chain));
        if let Some(run) = self.run.as_mut() {
            run.mode = mode;
            run.selected = selected;
            run.prepared.runtime = runtime;
            run.followed = Instant::now();
            if loaded.is_ok() {
                run.bypassed = chain.clone();
                run.chain = chain;
            }
        }
        match loaded {
            Ok(()) => self.set_bypass(bypass),
            Err(e) => {
                self.set_bypass(Bypass::None(format!("The new kernel plan is not confirmed yet: {e}")));
                self.error = Some(e);
            }
        }
        Ok(())
    }

    fn reset(&mut self, reason: &'static str, scope: Scope, changed: Instant) {
        self.last_reset = match self.port.reset(reason, scope, changed) {
            Ok(report) => report.json(),
            Err(e) => crate::netfx::conntrack::failed_json(&e),
        };
    }

    /// The relay changed its routes.
    /// `net_guard`'s check when it is due: another writer may have removed
    /// interception, routes or kernel settings.
    fn guard(&mut self) {
        if self.port.guard_due() {
            if let Err(e) = self.port.reconcile() {
                self.error = Some(e);
            }
        }
    }

    fn egress(&mut self) {
        let observed = self.port.uplink();
        let Some(run) = self.run.as_mut() else { return };
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
                if let Err(e) = self.restart("the egress changed", false) {
                    crate::netlog!("[mihomo] did not follow the egress change: {e}");
                }
            }
        }
    }

    fn tick(&mut self) {
        self.port.retry_reset();
        match self.phase {
            Phase::Backoff if self.retry_at.is_some_and(|at| Instant::now() >= at) => {
                if self.port.wanted() {
                    crate::netlog!("[mihomo] retrying after {} failure(s)", self.failures);
                    let _ = self.start(Engage::FromBackoff, false);
                } else {
                    let _ = self.stop_all();
                }
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
        // An IPv6-only egress change that held.
        let v6 = self.run.as_ref().and_then(|r| r.v6.clone());
        if let Some((seen, since)) = v6 {
            let observed = self.port.uplink();
            if observed != seen {
                if let Some(run) = self.run.as_mut() {
                    run.v6 = (egress::change(&run.uplink, &observed) == Change::V6).then(|| (observed, now));
                }
            } else if egress::v6_due(since, self.v6_restarted) <= now {
                self.v6_restarted = Some(now);
                let _ = self.restart("the IPv6 egress changed", false);
                self.publish();
                return;
            }
        }
        // Outside the relay: only an egress that strands connections.
        if self.run.as_ref().is_some_and(|r| now.duration_since(r.audited) >= self.timings.audit || r.stranding.is_some()) {
            let observed = self.port.uplink();
            let last = self.egress_restarted;
            let restart = self.run.as_mut().is_some_and(|run| {
                run.audited = now;
                run.ipv6 = observed.paths[1].is_some();
                egress::settle_egress(&mut run.uplink, &mut run.stranding, observed, last, now)
            });
            if restart {
                self.egress_restarted = Some(now);
                let _ = self.restart("the egress left the core's interface or source address", false);
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
