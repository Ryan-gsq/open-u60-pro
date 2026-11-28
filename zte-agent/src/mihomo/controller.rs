//! The Mihomo controller (`relay-mihomo-architecture.md` sections 3 and 5):
//! one thread that serializes owner commands, routing writes from the
//! console and Zashboard, egress changes, core exits, retries, `net_guard`
//! checks and rule-set refreshes. The relay admission gate is independent of
//! this controller (I2). Pages read the published `Snapshot`, owner commands
//! wait on the blocking pool, and dashboard writes await a oneshot.
//!
//! Device work goes through `Port`, so tests replay exits, retries, switches
//! and failures with a fake device and short timings (I6).
//!
//! States (section 5.2): `Off`; `Starting` (guard, kernel settings and
//! policy routes before the core, the plan only from what the ready core
//! reports); `Running`; `Restarting` (a planned restart: interception stays,
//! nothing skips the core, `to_core` drops what no core takes); `Reloading`
//! (same core, bypass narrowed as needed until readback confirms the new
//! configuration); `Backoff` (D3 after a confirmed core failure: interception
//! withdrawn, fake-ip fails
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

use super::egress::{self, Binding, Change, Uplink};
use super::intercept::{Shape, TailscaleExit};
use super::routing::{self, Chain, Mode, Selected};
use super::TailscaleExitConfig;
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

pub(super) type Validation = Box<dyn FnOnce() -> Result<(), String> + Send>;
const MAX_EGRESS_ATTEMPTS: usize = 4;

pub(super) enum Message {
    Validated { ticket: u64, result: Result<(), String> },
    /// The agent started: adopt this boot's tables if the owner wants
    /// Mihomo on, else roll back what a previous process left.
    Boot,
    /// Turn on (`owner`: the owner's switch; otherwise the boot restore).
    Enable { local: String, owner: bool, reply: Option<Reply> },
    Disable { reply: Option<Reply> },
    /// The DIRECT bypass setting changed (the flag file is written).
    Bypass { reply: Reply },
    /// Tailscale Exit Node via Mihomo state (`sniffer` / `tproxy_v4` / `tproxy_v6`) changed.
    TailscaleExit,
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
    Barrier(SyncSender<()>),
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
    pub compilation: Option<routing::Compilation>,
    pub dns_filter: Option<routing::DnsDiagnostics>,
    /// Consecutive failed starts and confirmed exits (D2).
    pub failures: u32,
    pub retry_at: Option<Instant>,
    pub reason: Option<String>,
    pub tables: Value,
    pub generation: u64,
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
    pub facts: super::reload::Facts,
    pub secret: String,
    pub local: String,
    pub runtime: Value,
    pub routes: routing::Routes,
    pub dns: routing::DnsFilter,
    pub bypass: bool,
    pub tailscale_sniffer: bool,
    pub notice: Option<String>,
    pub source: String,
    /// The managed configuration's text, kept to fall back to.
    pub config: String,
    pub egress: Binding,
}

/// Which configuration to prepare.
#[derive(Clone, Debug)]
pub(super) enum Source {
    /// The selected profile, with the runtime mode and log level (if any).
    Selected { local: String, runtime: Option<Value> },
    /// An already prepared configuration, rebound to the current egress.
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
    fn prepare(&mut self, source: &Source, serving: bool, egress: Binding) -> Result<Prepared, String>;
    fn validator(&self, _prepared: &Prepared, _serving: bool) -> Option<Validation> { None }
    /// Ports the core binds are free (checked before each spawn).
    fn ports_free(&mut self) -> Result<(), String>;
    /// Effects are held (a start re-applies them rather than claiming them).
    fn owns(&mut self) -> bool;
    fn engage(&mut self, how: Engage) -> Result<(), String>;
    /// Loads a table shape; `Err` when it is not confirmed.
    fn tables(&mut self, shape: Shape) -> Result<(), String>;
    /// Loads a table shape together with optional Tailscale Strategy B interception.
    fn tables_with_tailscale(&mut self, shape: Shape, _ts: TailscaleExit) -> Result<(), String> {
        self.tables(shape)
    }
    fn tables_status(&mut self) -> Value;
    /// Generation number the firewall owner last accepted as its nft target.
    fn tables_target_generation(&mut self) -> Option<u64> {
        None
    }
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
    /// The Tailscale Strategy B IPv4 rule chain for these choices.
    fn plan_tailscale(&mut self, _routes: &routing::Routes, _mode: Mode, _selected: &Selected, _unsettled: &[String]) -> Chain {
        Chain::default()
    }
    /// Current Tailscale Exit Node via Mihomo configuration.
    fn tailscale_exit(&mut self) -> TailscaleExitConfig {
        TailscaleExitConfig::default()
    }
    fn reset(&mut self, reason: &'static str, scope: Scope, changed: Instant) -> Result<Report, String>;
    /// Evict conntrack entries originating on `tailscale0` (`TAILSCALE_CT_MARK`).
    fn reset_tailscale(&mut self, _reason: &'static str, _v4: bool, _v6: bool) -> Result<(), String> {
        Ok(())
    }
    /// Families (`(v4, v6)`) with a pending marked-conntrack reset owned by `netfx`.
    fn tailscale_reset_pending(&mut self) -> (bool, bool) {
        (false, false)
    }
    /// Start instant of the latest completed marked IPv4 (`TAILSCALE_CT_MARK`)
    /// reset in `netfx`, regardless of which subsystem drove the retry.
    fn tailscale_v4_reset_started(&mut self) -> Option<Instant> {
        None
    }
    /// Notifies observers (such as Tailscale Clean DNS) after `publish()`.
    fn on_state_change(&mut self) {}
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
    fn egress_generation(&self) -> u64;
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
    /// Generation number the firewall owner confirmed in the kernel, if known.
    pub confirmed_generation: Option<u64>,
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
    ts_chain: Chain,
    ts_exit: TailscaleExitConfig,
    /// Declared to narrow the bypass before a change that then did not
    /// happen: once loaded, the plan is followed again.
    narrowing: bool,
    /// The `NftTables` target generation accepted by `EffectSet` for this entry.
    target_generation: Option<u64>,
}

/// A Strategy B Tailscale IPv4 bypass chain that flows may have used since the
/// last qualifying marked IPv4 reset. `retired_at` is `None` while the chain is
/// still live (confirmed or pending), and stamped when a later confirmed table
/// removes it; only an IPv4 reset that started at or after `retired_at` may
/// discard it.
#[derive(Clone)]
struct TsBypassed {
    chain: Chain,
    retired_at: Option<Instant>,
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
    /// Confirmed Tailscale Strategy B IPv4 chain and exit configuration.
    ts_chain: Chain,
    ts_bypassed: Vec<TsBypassed>,
    ts_exit: TailscaleExitConfig,
    /// Tailscale exit table or sniffer state still needs to be synced into the kernel.
    ts_exit_dirty: bool,
    /// Newest accepted table declared since that did not confirm (bounded to 1).
    pending: Option<Pending>,
    /// True when any unconfirmed table since the last confirmation was a narrowing.
    pending_narrowing: bool,
    /// Tailscale families that may have been enabled by an unconfirmed table
    /// since the last confirmation.
    ts_unconfirmed_enabled: (bool, bool),
    /// Tailscale families that may have been disabled/withdrawn by an
    /// unconfirmed table since the last confirmation (so a later re-enable
    /// confirmation must still reset direct flows).
    ts_unconfirmed_disabled: (bool, bool),
    /// Deduplicated LAN return chains present in unconfirmed tables since the
    /// last confirmation (for `may_return` and `reset_lan_done`).
    unconfirmed_lan_returns: Vec<Chain>,
    /// Deduplicated Tailscale IPv4 return chains present in unconfirmed tables
    /// since the last confirmation.
    unconfirmed_ts_returns: Vec<Chain>,
    /// Deduplicated Tailscale IPv4/IPv6 skip prefixes present in unconfirmed
    /// tables (for active families) since the last confirmation.
    unconfirmed_ts_skip_v4: Vec<String>,
    unconfirmed_ts_skip_v6: Vec<String>,
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
    /// or one a reconcile may still load / an unconfirmed write may have committed.
    fn may_return(&self) -> bool {
        self.kernel.1.returns > 0
            || self.ts_chain.returns > 0
            || self
                .pending
                .as_ref()
                .is_some_and(|p| p.chain.returns > 0 || p.ts_chain.returns > 0)
            || !self.unconfirmed_lan_returns.is_empty()
            || !self.unconfirmed_ts_returns.is_empty()
    }

    /// The table the kernel holds or a reconcile will load.
    fn target(&self) -> &Chain {
        self.pending.as_ref().map_or(&self.kernel.1, |p| &p.chain)
    }

    /// True when IPv4 `tailscale0` TPROXY is confirmed OR present in any
    /// unconfirmed table that may have committed or be replayed by reconcile.
    fn may_intercept_ts_v4(&self) -> bool {
        self.ts_exit.tproxy_v4 || self.ts_unconfirmed_enabled.0
    }

    /// True when IPv6 `tailscale0` TPROXY is confirmed OR present in any
    /// unconfirmed table that may have committed or be replayed by reconcile.
    fn may_intercept_ts_v6(&self) -> bool {
        self.ts_exit.tproxy_v6 || self.ts_unconfirmed_enabled.1
    }

    /// Families that need a marked-conntrack reset upon confirming `next`:
    /// covers new enables from an off confirmed state, reversals of an
    /// unconfirmed withdrawal that may have committed before readback failed,
    /// AND removals of confirmed or unconfirmed `skip_v4`/`skip_v6` bypass
    /// prefixes while that exit family remains enabled.
    fn needs_enable_reset(&self, next: &TailscaleExitConfig) -> (bool, bool) {
        let v4 = next.tproxy_v4
            && (!self.ts_exit.tproxy_v4
                || self.ts_unconfirmed_disabled.0
                || routing::lost_cidrs_v4(&self.ts_exit.skip_v4, &next.skip_v4)
                || routing::lost_cidrs_v4(&self.unconfirmed_ts_skip_v4, &next.skip_v4));
        let v6 = next.tproxy_v6
            && (!self.ts_exit.tproxy_v6
                || self.ts_unconfirmed_disabled.1
                || routing::lost_cidrs_v6(&self.ts_exit.skip_v6, &next.skip_v6)
                || routing::lost_cidrs_v6(&self.unconfirmed_ts_skip_v6, &next.skip_v6));
        (v4, v6)
    }

    /// The Tailscale exit config the kernel holds or a reconcile will load.
    fn ts_target(&self) -> &TailscaleExitConfig {
        self.pending.as_ref().map_or(&self.ts_exit, |p| &p.ts_exit)
    }

    /// The Tailscale Strategy B chain the kernel holds or a reconcile will load.
    fn ts_target_chain(&self) -> &Chain {
        self.pending.as_ref().map_or(&self.ts_chain, |p| &p.ts_chain)
    }

    fn clear_unconfirmed(&mut self) {
        self.pending = None;
        self.pending_narrowing = false;
        self.ts_unconfirmed_enabled = (false, false);
        self.ts_unconfirmed_disabled = (false, false);
        self.unconfirmed_lan_returns.clear();
        self.unconfirmed_ts_returns.clear();
        self.unconfirmed_ts_skip_v4.clear();
        self.unconfirmed_ts_skip_v6.clear();
    }

    fn declared(
        &mut self,
        bypass: Bypass,
        chain: Chain,
        ts_chain: Chain,
        ts_exit: TailscaleExitConfig,
        narrowing: bool,
        confirmed: bool,
        target_generation: Option<u64>,
    ) {
        if chain.returns > 0 && !self.bypassed.contains(&chain) {
            self.bypassed.push(chain.clone());
        }
        if ts_chain.returns > 0 {
            if let Some(existing) = self.ts_bypassed.iter_mut().find(|entry| entry.chain == ts_chain) {
                existing.retired_at = None;
            } else {
                self.ts_bypassed.push(TsBypassed { chain: ts_chain.clone(), retired_at: None });
            }
        }
        if confirmed {
            self.kernel = (bypass, chain);
            self.ts_chain = ts_chain;
            self.ts_exit = ts_exit;
            self.clear_unconfirmed();
            self.stamp_retired_ts_bypassed(Instant::now());
        } else {
            self.pending_narrowing |= narrowing;
            self.ts_unconfirmed_enabled.0 |= ts_exit.tproxy_v4;
            self.ts_unconfirmed_enabled.1 |= ts_exit.tproxy_v6;
            self.ts_unconfirmed_disabled.0 |= !ts_exit.tproxy_v4;
            self.ts_unconfirmed_disabled.1 |= !ts_exit.tproxy_v6;
            if ts_exit.tproxy_v4 {
                for cidr in &ts_exit.skip_v4 {
                    if !self.unconfirmed_ts_skip_v4.contains(cidr) {
                        self.unconfirmed_ts_skip_v4.push(cidr.clone());
                    }
                }
            }
            if ts_exit.tproxy_v6 {
                for cidr in &ts_exit.skip_v6 {
                    if !self.unconfirmed_ts_skip_v6.contains(cidr) {
                        self.unconfirmed_ts_skip_v6.push(cidr.clone());
                    }
                }
            }
            if chain.returns > 0 && !self.unconfirmed_lan_returns.contains(&chain) {
                self.unconfirmed_lan_returns.push(chain.clone());
            }
            if ts_chain.returns > 0 && !self.unconfirmed_ts_returns.contains(&ts_chain) {
                self.unconfirmed_ts_returns.push(ts_chain.clone());
            }
            self.pending = Some(Pending {
                bypass,
                chain,
                ts_chain,
                ts_exit,
                narrowing,
                target_generation,
            });
        }
    }

    fn ts_bypassed_chains(&self) -> Vec<Chain> {
        self.ts_bypassed.iter().map(|entry| entry.chain.clone()).collect()
    }

    fn stamp_retired_ts_bypassed(&mut self, now: Instant) {
        for entry in &mut self.ts_bypassed {
            let still_live = self.ts_chain == entry.chain
                || self.pending.as_ref().is_some_and(|p| p.ts_chain == entry.chain)
                || self.unconfirmed_ts_returns.contains(&entry.chain);
            if still_live {
                entry.retired_at = None;
            } else if entry.retired_at.is_none() {
                entry.retired_at = Some(now);
            }
        }
    }

    /// After a LAN reset: from now on LAN connections can skip the core only by
    /// what the kernel may still hold.
    fn reset_lan_done(&mut self) {
        let mut bypassed: Vec<Chain> = Vec::new();
        for chain in std::iter::once(&self.kernel.1)
            .chain(self.pending.iter().map(|p| &p.chain))
            .chain(self.unconfirmed_lan_returns.iter())
        {
            if chain.returns > 0 && !bypassed.contains(chain) {
                bypassed.push(chain.clone());
            }
        }
        self.bypassed = bypassed;
    }

    /// Retires only those historical Tailscale IPv4 bypass chains that were
    /// removed from the kernel BEFORE a confirmed IPv4 reset started.
    fn retire_ts_bypassed(&mut self, v4_reset_started: Instant) {
        self.ts_bypassed.retain(|entry| {
            let still_live = self.ts_chain == entry.chain
                || self.pending.as_ref().is_some_and(|p| p.ts_chain == entry.chain)
                || self.unconfirmed_ts_returns.contains(&entry.chain);
            still_live || entry.retired_at.is_none_or(|retired| v4_reset_started < retired)
        });
    }

    /// A reconcile confirmed `confirmed_generation`: promote ONLY the matching
    /// pending target so an older confirmed generation can never falsely promote
    /// a newer entry that `EffectSet` rejected before updating its target.
    /// Returns `(narrowing, newly_enabled_families)` when promoted.
    fn loaded(&mut self, confirmed_generation: Option<u64>) -> Option<(bool, (bool, bool))> {
        let matches_gen = self.pending.as_ref().is_some_and(|p| match confirmed_generation {
            Some(gen) => p.target_generation == Some(gen),
            None => true,
        });
        if !matches_gen {
            return None;
        }
        let matched = self.pending.take()?;
        let newly = self.needs_enable_reset(&matched.ts_exit);
        let was_narrowing = self.pending_narrowing || matched.narrowing;
        self.kernel = (matched.bypass, matched.chain);
        self.ts_chain = matched.ts_chain;
        self.ts_exit = matched.ts_exit;
        self.clear_unconfirmed();
        self.stamp_retired_ts_bypassed(Instant::now());
        Some((was_narrowing, newly))
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

/// Tailscale interception state carried across a stopping core handoff into
/// `CleanupPending`.
#[derive(Clone, Debug, Default)]
struct StoppingTs {
    /// Families cleanup is allowed to keep enabled: confirmed active on the
    /// stopping core AND never had a withdrawal attempted while `Running` or
    /// during `CleanupPending`.
    allow: (bool, bool),
    /// Families that may still be intercepted in the kernel or `EffectSet`
    /// target (confirmed OR unconfirmed enable), eligible for withdrawal.
    may: (bool, bool),
    /// Confirmed + unconfirmed IPv4/IPv6 skip prefixes that may have allowed
    /// marked Tailscale traffic to skip Mihomo while this core ran or stopped.
    skip_v4: Vec<String>,
    skip_v6: Vec<String>,
    /// True when the handed-off `Run` had an unconfirmed Tailscale exit or
    /// skip-list update that still needs confirmation during `CleanupPending`.
    pending_sync: bool,
}

impl StoppingTs {
    fn from_run(run: &Run) -> Self {
        let mut skip_v4 = if run.ts_exit.tproxy_v4 {
            run.ts_exit.skip_v4.clone()
        } else {
            Vec::new()
        };
        for cidr in &run.unconfirmed_ts_skip_v4 {
            if !skip_v4.contains(cidr) {
                skip_v4.push(cidr.clone());
            }
        }
        let mut skip_v6 = if run.ts_exit.tproxy_v6 {
            run.ts_exit.skip_v6.clone()
        } else {
            Vec::new()
        };
        for cidr in &run.unconfirmed_ts_skip_v6 {
            if !skip_v6.contains(cidr) {
                skip_v6.push(cidr.clone());
            }
        }
        let allow = (
            run.ts_exit.tproxy_v4 && !run.ts_unconfirmed_disabled.0,
            run.ts_exit.tproxy_v6 && !run.ts_unconfirmed_disabled.1,
        );
        let may = (run.may_intercept_ts_v4(), run.may_intercept_ts_v6());
        let pending_sync = run.ts_exit_dirty
            || (may.0 && !allow.0)
            || (may.1 && !allow.1)
            || (allow.0 && !run.unconfirmed_ts_skip_v4.is_empty())
            || (allow.1 && !run.unconfirmed_ts_skip_v6.is_empty())
            || run.pending.as_ref().is_some_and(|p| p.ts_exit != run.ts_exit);
        Self {
            allow,
            may,
            skip_v4,
            skip_v6,
            pending_sync,
        }
    }

    fn from_hold(confirmed: &TailscaleExitConfig, may: (bool, bool)) -> Self {
        let allow = (confirmed.tproxy_v4, confirmed.tproxy_v6);
        let may = (confirmed.tproxy_v4 || may.0, confirmed.tproxy_v6 || may.1);
        Self {
            allow,
            may,
            skip_v4: if confirmed.tproxy_v4 { confirmed.skip_v4.clone() } else { Vec::new() },
            skip_v6: if confirmed.tproxy_v6 { confirmed.skip_v6.clone() } else { Vec::new() },
            pending_sync: (may.0 && !allow.0) || (may.1 && !allow.1),
        }
    }
}

pub(super) struct Controller<P: Port> {
    port: P,
    rx: Receiver<Message>,
    tx: Sender<Message>,
    shared: Arc<Mutex<Snapshot>>,
    timings: Timings,
    phase: Phase,
    run: Option<Run>,
    /// A core whose `stop()` did not confirm exit yet; interception stays in
    /// place and no replacement starts until `stop()` succeeds or the reaper
    /// reports `Message::Exited` for its generation.
    stopping_core: Option<Box<dyn CoreHandle>>,
    /// Tailscale interception and skip history for `stopping_core`.
    stopping_ts: StoppingTs,
    validation_ticket: u64,
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
    /// Tailscale exit revocation arrived during CleanupPending while a stopping
    /// core still owned interception and failed to apply; retried on tick.
    cleanup_ts_dirty: bool,
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
            stopping_core: None,
            stopping_ts: StoppingTs::default(),
            generation: 0,
            validation_ticket: 0,
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
            cleanup_ts_dirty: false,
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
            end(crate::common::panic_message(panic.as_ref()));
        }
    }

    pub fn run(mut self) {
        let mut next_tick = Instant::now() + self.timings.tick;
        loop {
            let now = Instant::now();
            if now >= next_tick {
                self.tick();
                next_tick = now + self.timings.tick;
            }
            let message = match self.backlog.pop_front() {
                Some(message) => message,
                None => match self.rx.recv_timeout(next_tick.saturating_duration_since(Instant::now())) {
                    Ok(message) => message,
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => return,
                },
            };
            match message {
                #[cfg(test)]
                Message::Stop => return,
                message => self.handle(message),
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
        snapshot.compilation = self.run.as_ref().map(|r| r.kernel.1.compilation());
        snapshot.dns_filter = self.run.as_ref().map(|r| r.prepared.dns.diagnostics.clone());
        snapshot.failures = self.failures;
        snapshot.retry_at = self.retry_at;
        snapshot.reason.clone_from(&self.reason);
        snapshot.tables = tables;
        snapshot.generation = self.generation;
        snapshot.notice = self.run.as_ref().and_then(|r| r.prepared.notice.clone()).or_else(|| self.run.as_ref().filter(|r| !r.ipv6).and_then(|r| {
            let nodes = r.prepared.routes.v6_only_in_use(r.mode, &r.selected);
            (!nodes.is_empty()).then(|| format!("{} only has an IPv6 server address and the uplink has no IPv6, so connections through it fail. Turn on IPv6 for the relay or choose another node.", nodes.join(", ")))
        }));
        snapshot.last_reset.clone_from(&self.last_reset);
        if self.phase == Phase::Off {
            snapshot.bypass = None;
        }
        drop(snapshot);
        crate::events::touch(crate::events::Topic::Mihomo);
        crate::events::touch(crate::events::Topic::Relay);
        self.port.on_state_change();
    }

    fn effective_ts_exit(&mut self, sniffer_ready: bool) -> TailscaleExitConfig {
        let cfg = self.port.tailscale_exit();
        let allow_ts = !cfg.sniffer || sniffer_ready;
        TailscaleExitConfig {
            sniffer: cfg.sniffer && sniffer_ready,
            tproxy_v4: allow_ts && cfg.tproxy_v4,
            tproxy_v6: allow_ts && cfg.tproxy_v6,
            skip_v4: cfg.skip_v4,
            skip_v6: cfg.skip_v6,
        }
    }

    fn apply_tables_with(
        &mut self,
        shape: Shape,
        ts_chain: Option<&Chain>,
        effective: &TailscaleExitConfig,
    ) -> Result<(), String> {
        let ts = TailscaleExit {
            v4: effective.tproxy_v4,
            v6: effective.tproxy_v6,
            skip_v4: &effective.skip_v4,
            skip_v6: &effective.skip_v6,
            chain: (effective.tproxy_v4).then_some(ts_chain).flatten(),
        };
        self.port.tables_with_tailscale(shape, ts)
    }

    fn apply_tables_for(
        &mut self,
        shape: Shape,
        ts_chain: Option<&Chain>,
        sniffer_ready: bool,
    ) -> (TailscaleExitConfig, Result<(), String>) {
        let effective = self.effective_ts_exit(sniffer_ready);
        let result = self.apply_tables_with(shape, ts_chain, &effective);
        (effective, result)
    }

    fn stop_core(&mut self, core: Box<dyn CoreHandle>, ts: StoppingTs) -> bool {
        if core.stop() {
            self.stopping_ts = StoppingTs::default();
            true
        } else {
            let cfg = self.port.tailscale_exit();
            let want_v4 = ts.allow.0 && cfg.tproxy_v4;
            let want_v6 = ts.allow.1 && cfg.tproxy_v6;
            let skip_diff = (want_v4 && ts.skip_v4 != cfg.skip_v4)
                || (want_v6 && ts.skip_v6 != cfg.skip_v6);
            if ts.pending_sync
                || (ts.may.0 && !want_v4)
                || (ts.may.1 && !want_v6)
                || skip_diff
            {
                self.cleanup_ts_dirty = true;
            }
            self.stopping_core = Some(core);
            self.stopping_ts = ts;
            false
        }
    }

    fn sync_ts_v4_reset_ack(&mut self) {
        if let Some(started) = self.port.tailscale_v4_reset_started() {
            if let Some(run) = self.run.as_mut() {
                run.retire_ts_bypassed(started);
            }
        }
    }

    fn reset_tailscale_flows(&mut self, reason: &'static str, v4: bool, v6: bool, clear_bypass_record: bool) {
        if !v4 && !v6 {
            return;
        }
        let started_before = Instant::now();
        let res = self.port.reset_tailscale(reason, v4, v6);
        if let Err(e) = &res {
            crate::netlog!("[mihomo] tailscale conntrack reset failed ({reason}): {e}");
        }
        self.sync_ts_v4_reset_ack();
        // Fallback for minimal `Port` implementations that do not expose a
        // completion timestamp: ONLY retire IPv4 history when an IPv4 reset
        // itself succeeded and no IPv4 retry remains pending.
        if v4
            && clear_bypass_record
            && self.port.tailscale_v4_reset_started().is_none()
            && !self.port.tailscale_reset_pending().0
        {
            if let Some(run) = self.run.as_mut() {
                run.retire_ts_bypassed(started_before);
            }
        }
    }

    fn sync_cleanup_tailscale_exit(&mut self) -> bool {
        if self.stopping_core.is_none() || !self.port.owns() {
            self.cleanup_ts_dirty = false;
            return true;
        }
        let cfg = self.port.tailscale_exit();
        // CleanupPending may ONLY keep families already CONFIRMED intercepted
        // by the stopping core generation that have NEVER had a withdrawal
        // attempted (while Running or during CleanupPending).
        let next_v4 = self.stopping_ts.allow.0 && cfg.tproxy_v4;
        let next_v6 = self.stopping_ts.allow.1 && cfg.tproxy_v6;
        // Narrow `allow` BEFORE attempting the write so a failed readback after
        // a committed withdrawal can never re-enable that family if approval
        // returns before the retry, while `may` stays set until confirmed.
        self.stopping_ts.allow = (next_v4, next_v6);
        let ts = TailscaleExit {
            v4: next_v4,
            v6: next_v6,
            skip_v4: &cfg.skip_v4,
            skip_v6: &cfg.skip_v6,
            chain: None,
        };
        let gen_before = self.port.tables_target_generation();
        let applied = self.port.tables_with_tailscale(Shape::Hold, ts);
        let gen_after = self.port.tables_target_generation();
        let accepted = applied.is_ok()
            || (gen_before.is_none() && gen_after.is_none())
            || (gen_after.is_some() && gen_after != gen_before);
        match applied {
            Ok(()) => {
                let reset_v4 =
                    next_v4 && routing::lost_cidrs_v4(&self.stopping_ts.skip_v4, &cfg.skip_v4);
                let reset_v6 =
                    next_v6 && routing::lost_cidrs_v6(&self.stopping_ts.skip_v6, &cfg.skip_v6);
                self.stopping_ts.may = (next_v4, next_v6);
                self.stopping_ts.skip_v4 = if next_v4 { cfg.skip_v4 } else { Vec::new() };
                self.stopping_ts.skip_v6 = if next_v6 { cfg.skip_v6 } else { Vec::new() };
                self.stopping_ts.pending_sync = false;
                self.cleanup_ts_dirty = false;
                if reset_v4 || reset_v6 {
                    self.reset_tailscale_flows(
                        "Tailscale skip subnet removed during CleanupPending",
                        reset_v4,
                        reset_v6,
                        false,
                    );
                }
                true
            }
            Err(e) => {
                crate::netlog!("[mihomo] Tailscale exit update during CleanupPending failed: {e}");
                if accepted {
                    if next_v4 {
                        for cidr in cfg.skip_v4 {
                            if !self.stopping_ts.skip_v4.contains(&cidr) {
                                self.stopping_ts.skip_v4.push(cidr);
                            }
                        }
                    }
                    if next_v6 {
                        for cidr in cfg.skip_v6 {
                            if !self.stopping_ts.skip_v6.contains(&cidr) {
                                self.stopping_ts.skip_v6.push(cidr);
                            }
                        }
                    }
                }
                self.cleanup_ts_dirty = true;
                self.error = Some(e);
                false
            }
        }
    }

    /// Supersedes any revoked pending Tailscale target (or changed skip list)
    /// before guard reconciliation so `reconcile()` can never replay a revoked
    /// unconfirmed enable. Returns `Ok(changed)` when safe to proceed with
    /// `reconcile()`, or `Err(())` when superseding did not confirm (so the
    /// caller MUST skip `reconcile()` rather than risk replaying an older target
    /// after a journal write failure).
    fn supersede_revoked_tailscale_before_guard(&mut self) -> Result<bool, ()> {
        if let Some(sniffer_ready) = self.run.as_ref().map(|r| r.prepared.tailscale_sniffer) {
            let effective = self.effective_ts_exit(sniffer_ready);
            let needs_supersede = self.run.as_ref().is_some_and(|r| {
                (r.may_intercept_ts_v4() && !effective.tproxy_v4)
                    || (r.may_intercept_ts_v6() && !effective.tproxy_v6)
                    || r.ts_target().skip_v4 != effective.skip_v4
                    || r.ts_target().skip_v6 != effective.skip_v6
            });
            if needs_supersede {
                if self.apply_tailscale_kernel_only("Tailscale exit revoked before guard") {
                    return Ok(true);
                }
                return Err(());
            }
            return Ok(false);
        }
        if self.stopping_core.is_some() && self.port.owns() {
            let cfg = self.port.tailscale_exit();
            let want_v4 = self.stopping_ts.allow.0 && cfg.tproxy_v4;
            let want_v6 = self.stopping_ts.allow.1 && cfg.tproxy_v6;
            let skip_changed = (want_v4 && self.stopping_ts.skip_v4 != cfg.skip_v4)
                || (want_v6 && self.stopping_ts.skip_v6 != cfg.skip_v6);
            if (self.stopping_ts.may.0 && !want_v4)
                || (self.stopping_ts.may.1 && !want_v6)
                || skip_changed
            {
                if self.sync_cleanup_tailscale_exit() {
                    return Ok(true);
                }
                return Err(());
            }
        }
        Ok(false)
    }

    /// Applies Tailscale exit withdrawals or skip-list updates straight to the
    /// kernel nftables without waiting on core HTTP read-back. Returns `true`
    /// only when the firewall owner accepted and confirmed the new table.
    fn apply_tailscale_kernel_only(&mut self, why: &str) -> bool {
        let Some((lan_chain, bypass, ts_chain, effective, desired_sniffer)) = self.run.as_ref().map(|r| {
            let desired = self.port.tailscale_exit();
            let sniffer_ready = r.prepared.tailscale_sniffer;
            let allow_ts = !desired.sniffer || sniffer_ready;
            let effective = TailscaleExitConfig {
                sniffer: desired.sniffer && sniffer_ready,
                tproxy_v4: allow_ts && desired.tproxy_v4,
                tproxy_v6: allow_ts && desired.tproxy_v6,
                skip_v4: desired.skip_v4,
                skip_v6: desired.skip_v6,
            };
            let ts_chain = if effective.tproxy_v4 {
                r.ts_target_chain().clone()
            } else {
                Chain::default()
            };
            (
                r.target().clone(),
                r.pending.as_ref().map_or_else(|| r.kernel.0.clone(), |p| p.bypass.clone()),
                ts_chain,
                effective,
                desired.sniffer,
            )
        }) else {
            return false;
        };
        // Only choose `Shape::Hold` when NEITHER LAN nor Tailscale has DIRECT
        // rules: when LAN bypass is off but Tailscale DIRECT rules are active,
        // submit `Shape::Full` so single-hop Tailscale DIRECT stays intact and
        // recorded state matches the submitted table exactly.
        let use_hold = lan_chain.returns == 0 && matches!(bypass, Bypass::None(_)) && ts_chain.returns == 0;
        let shape = if use_hold { Shape::Hold } else { Shape::Full(&lan_chain) };
        let submitted_ts_chain = if use_hold { Chain::default() } else { ts_chain };
        let ts_arg = (!use_hold).then_some(&submitted_ts_chain);
        let gen_before = self.port.tables_target_generation();
        let applied = self.apply_tables_with(shape, ts_arg, &effective);
        let gen_after = self.port.tables_target_generation();
        let accepted = applied.is_ok()
            || (gen_before.is_none() && gen_after.is_none())
            || (gen_after.is_some() && gen_after != gen_before);
        match applied {
            Ok(()) => {
                let mut newly = (false, false);
                if let Some(run) = self.run.as_mut() {
                    newly = run.needs_enable_reset(&effective);
                    let had_narrowing = run.pending_narrowing;
                    run.declared(bypass, lan_chain, submitted_ts_chain, effective, false, true, gen_after);
                    run.unfollowed |= had_narrowing;
                    run.ts_exit_dirty = desired_sniffer != run.prepared.tailscale_sniffer;
                }
                if newly.0 || newly.1 {
                    self.reset_tailscale_flows("Tailscale exit via Mihomo enabled", newly.0, newly.1, true);
                }
                true
            }
            Err(e) => {
                crate::netlog!("[mihomo] kernel Tailscale exit update failed ({why}): {e}");
                if let Some(run) = self.run.as_mut() {
                    if accepted {
                        run.declared(bypass, lan_chain, submitted_ts_chain, effective, false, false, gen_after);
                    }
                    run.ts_exit_dirty = true;
                }
                self.error = Some(e);
                false
            }
        }
    }

    fn sync_tailscale_exit(&mut self) {
        let Some((prev_sniffer, prev_ts, may_v4, may_v6, target_ts)) = self.run.as_ref().map(|r| {
            (
                r.prepared.tailscale_sniffer,
                r.ts_exit.clone(),
                r.may_intercept_ts_v4(),
                r.may_intercept_ts_v6(),
                r.ts_target().clone(),
            )
        }) else {
            return;
        };
        let desired = self.port.tailscale_exit();
        // Supersede BOTH confirmed enables AND unconfirmed pending enables
        // that may have committed to nftables or could be replayed by guard.
        let revoked_v4 = may_v4 && !desired.tproxy_v4;
        let revoked_v6 = may_v6 && !desired.tproxy_v6;
        let skip_changed = desired.skip_v4 != prev_ts.skip_v4
            || desired.skip_v6 != prev_ts.skip_v6
            || desired.skip_v4 != target_ts.skip_v4
            || desired.skip_v6 != target_ts.skip_v6;

        if prev_sniffer != desired.sniffer {
            if revoked_v4 || revoked_v6 {
                // Withdraw revoked tailscale0 interception immediately before
                // waiting on config preparation or reload.
                self.apply_tailscale_kernel_only("Tailscale exit revoked");
            }
            if let Err(e) = self.reload("Tailscale exit-via-Mihomo changed") {
                crate::netlog!("[mihomo] reload after Tailscale exit change: {e}");
                if let Some(run) = self.run.as_mut() {
                    run.ts_exit_dirty = true;
                }
                if !desired.tproxy_v4 || !desired.tproxy_v6 || skip_changed {
                    self.apply_tailscale_kernel_only("Tailscale exit revoked");
                }
                return;
            }
        } else {
            if revoked_v4 || revoked_v6 || skip_changed {
                self.apply_tailscale_kernel_only("Tailscale exit state changed");
            }
            let needs_widen = desired.tproxy_v4
                || desired.tproxy_v6
                || self.run.as_ref().is_some_and(|r| r.unfollowed);
            if needs_widen {
                self.widen("Tailscale exit state changed");
            }
        }
    }

    fn set_bypass(&mut self, bypass: Bypass) {
        let mut snapshot = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        snapshot.bypass = Some(bypass);
        snapshot.compilation = self.run.as_ref().map(|run| run.kernel.1.compilation());
    }

    fn handle(&mut self, message: Message) {
        match message {
            Message::Validated { .. } => {}
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
            Message::TailscaleExit => {
                match self.phase {
                    Phase::Running => self.sync_tailscale_exit(),
                    Phase::CleanupPending if self.stopping_core.is_some() && self.port.owns() => {
                        let _ = self.sync_cleanup_tailscale_exit();
                    }
                    Phase::CleanupPending if self.cause.is_some() => {
                        self.withdraw(false);
                    }
                    _ => {}
                }
                self.publish();
            }
            Message::Config { refresh, reply } => {
                let result = match self.phase {
                    Phase::Running if refresh => self.refresh(),
                    Phase::Running => self.restart("the profile changed", Restart::Profile),
                    Phase::Backoff => self.start(false),
                    _ => self.prepare(&Source::Selected { local: self.local.clone(), runtime: None }, false).map(|_| ()),
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
            Message::Barrier(reply) => { let _ = reply.send(()); }
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
            let mut holding_ts = TailscaleExitConfig::default();
            let adopted = self.port.engage(Engage::Adopt).and_then(|()| {
                let (eff, res) = self.apply_tables_for(Shape::Hold, None, false);
                res.map(|()| {
                    if eff.tproxy_v4 || eff.tproxy_v6 {
                        self.reset_tailscale_flows(
                            "Mihomo adopt Hold started for Tailscale exit",
                            eff.tproxy_v4,
                            eff.tproxy_v6,
                            false,
                        );
                    }
                    holding_ts = eff;
                })
            });
            let mut bypassed = Vec::new();
            let mut ts_bypassed = Vec::new();
            match adopted.and_then(|()| {
                self.launch(
                    Source::Selected { local: self.local.clone(), runtime: None },
                    true,
                    &mut holding_ts,
                    &mut bypassed,
                    &mut ts_bypassed,
                )
            }) {
                Ok(()) if !bypassed.is_empty() || !ts_bypassed.is_empty() => self.reset_restart_bypass(&bypassed),
                Ok(()) => {}
                Err(_) if self.run.is_some() => {
                    if !bypassed.is_empty() || !ts_bypassed.is_empty() {
                        self.reset_restart_bypass(&bypassed);
                    }
                }
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
        if owner {
            if self.run.is_some() {
                if let Err(e) = self.port.set_wanted(true) {
                    self.error = Some(format!("Mihomo is on, but it will stay off after a restart: {e}"));
                }
            } else if let Err(e) = &result {
                // The owner saw it fail: a restart must not retry it.
                if let Err(clear) = self.port.set_wanted(false) {
                    let error = format!("{e}; {clear}. The saved restart choice could not be removed");
                    self.error = Some(error.clone());
                    return Err(error);
                }
            }
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
        let had = self.run.is_some() || self.stopping_core.is_some() || self.phase != Phase::Off;
        let (core_to_stop, stopping_ts) = match self.run.take() {
            Some(r) => {
                let stopping_ts = StoppingTs::from_run(&r);
                (Some(r.core), stopping_ts)
            }
            None => (self.stopping_core.take(), self.stopping_ts.clone()),
        };
        if let Some(core) = core_to_stop {
            if !self.stop_core(core, stopping_ts) {
                self.retry_at = None;
                self.cause = None;
                self.phase = Phase::CleanupPending;
                let error = "Mihomo did not confirm exit yet; interception stays in place until it exits".to_string();
                self.error = Some(error.clone());
                return Err(error);
            }
        }
        self.retry_at = None;
        // Releasing everything also ends a D3 withdrawal still pending.
        self.cause = None;
        match self.port.release_all() {
            Ok(()) => {
                self.cleanup_ts_dirty = false;
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
        if self.stopping_core.is_some() {
            let err = "Previous Mihomo core has not confirmed exit yet".to_string();
            self.phase = Phase::CleanupPending;
            self.error = Some(err.clone());
            return Err(err);
        }
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
        let result = engaged.and_then(|()| {
            let mut holding_ts = TailscaleExitConfig::default();
            let mut ts_bypassed = Vec::new();
            self.launch(
                Source::Selected { local: self.local.clone(), runtime: None },
                false,
                &mut holding_ts,
                &mut Vec::new(),
                &mut ts_bypassed,
            )
        });
        match &result {
            Ok(()) | Err(_) if self.run.is_some() => {
                if result.is_ok() {
                    self.error = None;
                }
                // Connections that went direct before keep their path until reset.
                let scope = Scope::Lan { v4: true, v6: from_backoff };
                self.reset("Mihomo started", scope, Instant::now());
                if let Some(run) = self.run.as_mut() {
                    run.reset_lan_done();
                }
                // Also evaluate any Tailscale DIRECT history accumulated across
                // egress-rollback candidates before the final candidate published.
                self.reset_lost_ts_bypassed("Mihomo started for Tailscale routing");
                self.publish();
            }
            Ok(()) => {}
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

    fn prepare(&mut self, source: &Source, serving: bool) -> Result<Prepared, String> {
        let existing = match source {
            Source::Reload(previous) | Source::Refresh(previous) => Some(&previous.egress),
            _ => None,
        };
        let mut retry = None;
        let mut attempts_left = MAX_EGRESS_ATTEMPTS;
        loop {
            let egress = existing.cloned().unwrap_or_else(|| self.observe_binding());
            let (candidate, error) = match self.port.prepare(retry.as_ref().unwrap_or(source), serving, egress.clone()) {
                Ok(prepared) => match self.validate(&prepared, serving)? {
                    Ok(()) => return Ok(prepared),
                    Err(error) => (Some(prepared), error),
                },
                Err(error) => (None, error),
            };
            attempts_left -= 1;
            if existing.is_some() || attempts_left == 0 || self.binding_is_current(&egress) {
                return Err(error);
            }
            if let Some(candidate) = candidate {
                retry = Some(Source::Previous(Box::new(candidate)));
            }
        }
    }

    /// Only one worker owns candidate.yaml at a time. Exit and guard messages
    /// remain actionable while it checks. A queued disable or the loss of
    /// the serving generation invalidates the result before any widening.
    fn validate(&mut self, prepared: &Prepared, serving: bool) -> Result<Result<(), String>, String> {
        let Some(validate) = self.port.validator(prepared, serving) else { return Ok(Ok(())) };
        self.validation_ticket += 1;
        let ticket = self.validation_ticket;
        let tx = self.tx.clone();
        std::thread::Builder::new().name("mihomo-validate".into()).spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(validate)).unwrap_or_else(|_| Err("Mihomo validation worker stopped".into()));
            let _ = tx.send(Message::Validated { ticket, result });
        }).map_err(|e| format!("Cannot start Mihomo validation: {e}"))?;
        let generation = self.run.as_ref().map(|r| r.core.generation());
        let mut cancelled = false;
        loop {
            match self.rx.recv().map_err(|_| "Mihomo controller stopped")? {
                Message::Validated { ticket: id, result } if id == ticket => {
                    if cancelled || generation != self.run.as_ref().map(|r| r.core.generation()) { return Err("Mihomo validation superseded".into()); }
                    return Ok(result);
                }
                Message::Validated { .. } => {}
                event @ (Message::Guard | Message::Exited { .. }) => self.handle(event),
                Message::TailscaleExit => {
                    if matches!(self.supersede_revoked_tailscale_before_guard(), Ok(true) | Err(())) {
                        self.publish();
                    }
                    self.backlog.push_back(Message::TailscaleExit);
                }
                message => {
                    cancelled |= matches!(message, Message::Disable { .. });
                    self.backlog.push_back(message);
                }
            }
        }
    }

    /// Prepares, spawns and verifies a core, then loads the plan its
    /// read-back mode and choices give. The tables already hold or guard.
    fn launch(
        &mut self,
        source: Source,
        holding: bool,
        holding_ts: &mut TailscaleExitConfig,
        bypassed: &mut Vec<Chain>,
        ts_bypassed: &mut Vec<TsBypassed>,
    ) -> Result<(), String> {
        let prepared = self.prepare(&source, false)?;
        self.launch_prepared(prepared, holding, holding_ts, bypassed, ts_bypassed)
    }

    fn observe_binding(&mut self) -> Binding {
        Binding { generation: self.port.egress_generation(), uplink: self.port.uplink(true) }
    }

    fn binding_is_current(&mut self, prepared: &Binding) -> bool {
        if self.port.egress_generation() != prepared.generation {
            return false;
        }
        let observed = self.observe_binding();
        &observed == prepared && self.port.egress_generation() == observed.generation
    }

    /// `launch` with a configuration already prepared and validated.
    fn launch_prepared(
        &mut self,
        mut prepared: Prepared,
        mut holding: bool,
        holding_ts: &mut TailscaleExitConfig,
        bypassed: &mut Vec<Chain>,
        ts_bypassed: &mut Vec<TsBypassed>,
    ) -> Result<(), String> {
        for attempt in 0..MAX_EGRESS_ATTEMPTS {
            if self.backlog.iter().any(|message| matches!(message, Message::Disable { .. })) {
                return Err("Turned off while starting".into());
            }
            if self.launch_current(&mut prepared, &mut holding, holding_ts, bypassed, ts_bypassed)? {
                return Ok(());
            }
            if attempt + 1 < MAX_EGRESS_ATTEMPTS {
                prepared = self.prepare(&Source::Previous(Box::new(prepared)), false)?;
            }
        }
        Err("The Mihomo egress kept changing during startup".into())
    }

    fn launch_current(
        &mut self,
        prepared: &mut Prepared,
        holding: &mut bool,
        holding_ts: &mut TailscaleExitConfig,
        bypassed: &mut Vec<Chain>,
        ts_bypassed: &mut Vec<TsBypassed>,
    ) -> Result<bool, String> {
        self.port.ports_free()?;
        if !self.binding_is_current(&prepared.egress) {
            return Ok(false);
        }
        self.generation += 1;
        let generation = self.generation;
        let core = self.port.spawn(generation, prepared, self.tx.clone())?;
        let deadline = Instant::now() + self.timings.ready;
        let mut hold_confirmed = if *holding {
            holding_ts.clone()
        } else {
            TailscaleExitConfig::default()
        };
        let mut hold_may = (hold_confirmed.tproxy_v4, hold_confirmed.tproxy_v6);
        let ready = self.wait(deadline, generation, |port| {
            port.egress_generation() != prepared.egress.generation || port.ready(prepared)
        });
        if let Err(why) = ready {
            if !self.stop_core(core, StoppingTs::from_hold(&hold_confirmed, hold_may)) {
                return Err("Mihomo did not confirm exit after startup failure".into());
            }
            if !matches!(why, Interrupted::Cancelled) && !self.binding_is_current(&prepared.egress) {
                return Ok(false);
            }
            return Err(match why {
                Interrupted::Exited(how) => format!("Mihomo exited while starting ({how})"),
                Interrupted::Cancelled => "Turned off while starting".into(),
                Interrupted::TimedOut => "Mihomo controller, private download proxy, transparent proxy port or dual-stack TCP/UDP DNS did not become ready".into(),
            });
        }
        if self.port.egress_generation() != prepared.egress.generation {
            if !self.stop_core(core, StoppingTs::from_hold(&hold_confirmed, hold_may)) {
                return Err("Mihomo did not confirm exit while rebinding egress".into());
            }
            return Ok(false);
        }
        if !*holding {
            // Guard only so far: interception goes in now that it listens.
            let (eff, res) = self.apply_tables_for(Shape::Hold, None, prepared.tailscale_sniffer);
            match res {
                Ok(()) => {
                    let newly_v4 = eff.tproxy_v4 && !hold_confirmed.tproxy_v4;
                    let newly_v6 = eff.tproxy_v6 && !hold_confirmed.tproxy_v6;
                    *holding_ts = eff.clone();
                    hold_confirmed = eff.clone();
                    hold_may = (eff.tproxy_v4, eff.tproxy_v6);
                    if newly_v4 || newly_v6 {
                        self.reset_tailscale_flows(
                            "Mihomo Hold started for Tailscale exit",
                            newly_v4,
                            newly_v6,
                            false,
                        );
                    }
                }
                Err(e) => {
                    hold_may = (hold_may.0 || eff.tproxy_v4, hold_may.1 || eff.tproxy_v6);
                    let _ = self.stop_core(core, StoppingTs::from_hold(&hold_confirmed, hold_may));
                    return Err(e);
                }
            }
            *holding = true;
        }
        if let Err(e) = self.port.verify_routing() {
            if !self.stop_core(core, StoppingTs::from_hold(&hold_confirmed, hold_may)) {
                return Err(format!("{e}; Mihomo did not confirm exit"));
            }
            if !self.binding_is_current(&prepared.egress) {
                return Ok(false);
            }
            return Err(e);
        }
        // The first table with DIRECT returns follows what this core
        // reports once ready, never what was stored before (section 3).
        let Some((mode, selected, runtime)) = self.port.read_back(&prepared.secret) else {
            if !self.stop_core(core, StoppingTs::from_hold(&hold_confirmed, hold_may)) {
                return Err("Mihomo did not report its mode and proxy groups and did not confirm exit".into());
            }
            if !self.binding_is_current(&prepared.egress) {
                return Ok(false);
            }
            return Err("Mihomo did not report its mode and proxy groups".into());
        };
        prepared.runtime = runtime;
        let (bypass, chain) = self.port.plan(&prepared.routes, prepared.bypass, mode, &selected, &[]);
        let effective_ts = self.effective_ts_exit(prepared.tailscale_sniffer);
        let ts_chain = if effective_ts.tproxy_v4 {
            self.port.plan_tailscale(&prepared.routes, mode, &selected, &[])
        } else {
            Chain::default()
        };
        if !self.binding_is_current(&prepared.egress) {
            if !self.stop_core(core, StoppingTs::from_hold(&hold_confirmed, hold_may)) {
                return Err("Mihomo did not confirm exit while rebinding egress".into());
            }
            return Ok(false);
        }
        let now = Instant::now();
        let refresh = prepared.routes.refresh().into_iter().enumerate().map(|(i, (name, every))| {
            let every = Duration::from_secs(every);
            (name, every, now + every.min(Duration::from_secs(3600)) + Duration::from_secs(10 * i as u64))
        }).collect();
        let uplink = prepared.egress.uplink.clone();
        let gen_before = self.port.tables_target_generation();
        let loaded = self.apply_tables_with(Shape::Full(&chain), Some(&ts_chain), &effective_ts);
        let gen_after = self.port.tables_target_generation();
        let accepted = loaded.is_ok()
            || (gen_before.is_none() && gen_after.is_none())
            || (gen_after.is_some() && gen_after != gen_before);
        *holding = false;
        let ts_exit_dirty = loaded.is_err() && (effective_ts.tproxy_v4 || effective_ts.tproxy_v6 || effective_ts != *holding_ts);
        let mut run = Run {
            core,
            prepared: prepared.clone(),
            mode,
            selected,
            // The tables hold: nothing skips the core yet, while any Tailscale
            // family confirmed during Hold is already live in the kernel.
            kernel: (Bypass::None("The kernel plan is being loaded".into()), Chain::default()),
            ts_chain: Chain::default(),
            ts_bypassed: ts_bypassed.clone(),
            ts_exit: holding_ts.clone(),
            ts_exit_dirty,
            pending: None,
            pending_narrowing: false,
            ts_unconfirmed_enabled: (false, false),
            ts_unconfirmed_disabled: (false, false),
            unconfirmed_lan_returns: Vec::new(),
            unconfirmed_ts_returns: Vec::new(),
            unconfirmed_ts_skip_v4: Vec::new(),
            unconfirmed_ts_skip_v6: Vec::new(),
            bypassed: Vec::new(),
            unfollowed: !accepted,
            ipv6: uplink.paths[1].is_some(),
            uplink,
            stranding: None,
            v6: None,
            started: now,
            audited: now,
            followed: now,
            refresh,
        };
        if loaded.is_ok() {
            // Run the first-interception / skip-removal marked reset IMMEDIATELY
            // at Full confirmation, BEFORE any egress rollback can overwrite
            // `holding_ts` and return early with a zero delta on the next try.
            let (newly_v4, newly_v6) = run.needs_enable_reset(&effective_ts);
            run.declared(bypass, chain, ts_chain, effective_ts, false, true, gen_after);
            if newly_v4 || newly_v6 {
                self.reset_tailscale_flows("Mihomo started for Tailscale exit", newly_v4, newly_v6, false);
            }
        } else if accepted {
            run.declared(bypass, chain, ts_chain, effective_ts, false, false, gen_after);
        }
        let rollback = if self.binding_is_current(&prepared.egress) {
            Ok(())
        } else {
            let rb_gen_before = self.port.tables_target_generation();
            let (rb_effective, held) = self.apply_tables_for(Shape::Hold, None, prepared.tailscale_sniffer);
            let rb_gen_after = self.port.tables_target_generation();
            let rb_accepted = held.is_ok()
                || (rb_gen_before.is_none() && rb_gen_after.is_none())
                || (rb_gen_after.is_some() && rb_gen_after != rb_gen_before);
            for chain in bypassed.iter() {
                if !run.bypassed.contains(chain) {
                    run.bypassed.push(chain.clone());
                }
            }
            match held {
                Ok(()) => {
                    // Compute the rollback delta via `run.needs_enable_reset`
                    // BEFORE clearing unconfirmed history so reversing an
                    // unconfirmed `Full` withdrawal or removing a skip prefix
                    // still resets marked Tailscale flows!
                    let (newly_v4, newly_v6) = run.needs_enable_reset(&rb_effective);
                    if newly_v4 || newly_v6 {
                        self.reset_tailscale_flows(
                            "Mihomo rollback Hold enabled Tailscale exit",
                            newly_v4,
                            newly_v6,
                            false,
                        );
                    }
                    run.ts_chain = Chain::default();
                    run.ts_exit = rb_effective.clone();
                    run.clear_unconfirmed();
                    run.stamp_retired_ts_bypassed(Instant::now());
                    *holding = true;
                    *holding_ts = rb_effective.clone();
                    *bypassed = run.bypassed;
                    *ts_bypassed = run.ts_bypassed;
                    let c = (rb_effective.tproxy_v4, rb_effective.tproxy_v6);
                    if !self.stop_core(run.core, StoppingTs::from_hold(&rb_effective, c)) {
                        return Err("Mihomo did not confirm exit after egress rollback".into());
                    }
                    return Ok(false);
                }
                Err(e) => {
                    let reason = "The egress changed while starting Mihomo";
                    if rb_accepted {
                        run.declared(
                            Bypass::None(reason.into()),
                            Chain::default(),
                            Chain::default(),
                            rb_effective,
                            true,
                            false,
                            rb_gen_after,
                        );
                    } else {
                        run.unfollowed = true;
                    }
                    Err(format!("{reason}; the Hold table could not be confirmed: {e}"))
                }
            }
        };
        let shown = match &loaded {
            Ok(_) => run.kernel.0.clone(),
            Err(e) => Bypass::None(format!("The kernel plan is not confirmed yet: {e}")),
        };
        self.run = Some(run);
        self.sync_ts_v4_reset_ack();
        self.set_bypass(shown);
        self.error = rollback.as_ref().err().cloned().or_else(|| loaded.err());
        self.phase = Phase::Running;
        self.reason = None;
        self.publish();
        crate::netlog!("[mihomo] running generation={generation} mode={}", mode.name());
        rollback.map(|()| true)
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
        let prepared = match self.prepare(&source, why == Restart::Profile) {
            Ok(prepared) => prepared,
            Err(e) if self.run.is_none() => return Err(e),
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
            self.load(Shape::Hold, Bypass::None(format!("Restarting: {reason}")), Chain::default(), true).map_err(|e| format!("Mihomo was not restarted: {e}"))?;
        }
        let Some(mut old) = self.run.take() else { return Ok(()) };
        self.phase = Phase::Restarting;
        self.reason = Some(reason.into());
        self.publish();
        let held = Instant::now();
        old.stamp_retired_ts_bypassed(held);
        let old_stopping_ts = StoppingTs::from_run(&old);
        let mut holding_ts = old.ts_exit.clone();
        if !self.stop_core(old.core, old_stopping_ts) {
            let error = "The previous Mihomo core did not confirm exit; keeping interception in place".to_string();
            self.fail(error.clone());
            return Err(error);
        }
        let mut bypassed = old.bypassed;
        let mut ts_bypassed = old.ts_bypassed;
        let mut result = self.launch_prepared(prepared, true, &mut holding_ts, &mut bypassed, &mut ts_bypassed);
        if let Err(e) = &result {
            if why == Restart::Profile && self.run.is_none() && self.stopping_core.is_none() {
                crate::netlog!("[mihomo] the new profile did not start ({e}); starting the previous one");
                result = match self.launch(
                    Source::Previous(Box::new(old.prepared)),
                    true,
                    &mut holding_ts,
                    &mut bypassed,
                    &mut ts_bypassed,
                ) {
                    Ok(()) => Err(format!("{e}; the previous profile was started again")),
                    Err(again) => Err(format!("{e}; starting the previous profile: {again}")),
                };
            }
        }
        if self.run.is_some() {
            // Evaluate lost DIRECT destinations whenever a replacement Run
            // becomes active, including when `launch_current()` returned `Err`
            // after confirming `Full` and failing rollback `Hold`.
            self.reset_restart_bypass(&bypassed);
            crate::netlog!("[mihomo] the restart took {} ms", held.elapsed().as_millis());
            if let Err(e) = &result {
                self.error = Some(e.clone());
            }
        } else if let Err(e) = &result {
            self.fail(format!("The planned restart failed: {e}"));
        }
        result
    }

    fn reset_lost_ts_bypassed(&mut self, reason: &'static str) {
        self.sync_ts_v4_reset_ack();
        let ts_lost = self.run.as_ref().is_some_and(|run| {
            let bypassed_chains = run.ts_bypassed_chains();
            run.may_intercept_ts_v4()
                && !matches!(
                    routing::lost_from(&bypassed_chains, run.ts_target_chain()),
                    Scope::Destinations(ref d) if d.is_empty()
                )
        });
        if ts_lost {
            self.reset_tailscale_flows(reason, true, false, true);
        }
    }

    fn reset_restart_bypass(&mut self, bypassed: &[Chain]) {
        let Some(run) = self.run.as_ref() else { return };
        let mut combined = bypassed.to_vec();
        for chain in &run.bypassed {
            if !combined.contains(chain) {
                combined.push(chain.clone());
            }
        }
        let lost = routing::lost_from(&combined, run.target());
        self.reset("Mihomo restarted", lost, Instant::now());
        if let Some(run) = self.run.as_mut() {
            run.reset_lan_done();
        }
        self.reset_lost_ts_bypassed("Mihomo restarted for Tailscale routing");
    }

    /// v3 (section 5.5): the same configuration with another DNS filter,
    /// by `PUT /configs?force=false`. Tightened first; committed only when
    /// the read-back proves it (a 204 alone does not, a timeout is unknown);
    /// otherwise a planned restart behind the interception takes over.
    fn reload(&mut self, reason: &str) -> Result<(), String> {
        let Some(run) = self.run.as_ref() else { return Ok(()) };
        let previous = run.prepared.clone();
        let next = self.prepare(&Source::Reload(Box::new(previous.clone())), true)?;
        if next.config == previous.config {
            if self.run.as_ref().is_some_and(Run::may_return) {
                self.load(Shape::Hold, Bypass::None(format!("Following {reason}")), Chain::default(), true)?;
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
        let next = self.prepare(&Source::Refresh(Box::new(previous.clone())), true)?;
        if previous.facts.needs_restart(&next.facts) {
            return self.restart_prepared("the profile changed startup settings", Restart::Profile, next);
        }
        self.reload_prepared("the selected subscription refreshed", next)
    }

    fn reload_prepared(&mut self, reason: &str, next: Prepared) -> Result<(), String> {
        let Some(run) = self.run.as_ref() else { return Ok(()) };
        let (previous, before) = (run.prepared.clone(), run.selected.clone());
        if self.run.as_ref().is_some_and(Run::may_return) {
            self.load(Shape::Hold, Bypass::None(format!("Reloading: {reason}")), Chain::default(), true).map_err(|e| format!("Nothing was changed: the bypass could not be narrowed first ({e})"))?;
        }
        crate::netlog!("[mihomo] reloading: {reason}");
        self.set_bypass(Bypass::None(format!("Reloading: {reason}")));
        self.phase = Phase::Reloading;
        self.reason = Some(reason.into());
        self.publish();
        let started = Instant::now();
        let answered = self.port.reload(&next.secret, &next.config);
        let probe = routing::reload_probe(&previous.dns.rules, &next.dns.rules);
        let verified = match &answered {
            Ok(status) if !(200..300).contains(status) => Err("Mihomo rejected the reload".into()),
            Err(_) if next.source != previous.source || next.tailscale_sniffer != previous.tailscale_sniffer => {
                Err("the reload result is unknown".into())
            }
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

    /// D3: a confirmed core failure. Interception is withdrawn ONLY after core
    /// exit is confirmed; until then the handle and tables remain in place.
    fn fail(&mut self, error: String) {
        self.fail_inner(error, false);
    }

    fn fail_inner(&mut self, error: String, already_exited: bool) {
        crate::netlog!("[mihomo] direct until the core is back: {error}");
        self.seen = match self.run.take() {
            Some(run) => {
                let stopping_ts = StoppingTs::from_run(&run);
                let uplink = run.uplink;
                if already_exited {
                    let _ = run.core.stop();
                } else {
                    let _ = self.stop_core(run.core, stopping_ts);
                }
                uplink
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
        self.withdraw(false);
    }

    /// The D2 wait before the next retry.
    fn step(&self) -> Duration {
        let last = self.timings.retries.len() - 1;
        self.timings.retries[if self.exits.len() >= 3 { last } else { (self.failures.max(1) as usize - 1).min(last) }]
    }

    /// D3's withdrawal: Backoff once the core has confirmed exit and tables are
    /// withdrawn. Until then the state stays CleanupPending with interception
    /// intact (and retried on D2 timers or when the reaper sends `Exited`).
    fn withdraw(&mut self, retry_stop: bool) {
        let Some(cause) = self.cause.clone() else { return };
        if retry_stop {
            if let Some(core) = self.stopping_core.take() {
                if !self.stop_core(core, self.stopping_ts.clone()) {
                    // `stop_core` preserved `stopping_core` and `stopping_ts`.
                }
            }
        }
        if self.stopping_core.is_some() {
            crate::netlog!("[mihomo] core exit is not confirmed yet; keeping interception in place");
            self.phase = Phase::CleanupPending;
            self.error = Some(format!("{cause}; Mihomo has not confirmed exit yet, so interception stays in place until it exits"));
            self.set_bypass(Bypass::None("Mihomo is stopping; its interception stays in place until exit is confirmed".into()));
            return;
        }
        let withdrawn = if self.port.owns() { self.port.direct() } else { self.port.recover() };
        match withdrawn {
            Ok(()) => {
                self.cleanup_ts_dirty = false;
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
            self.withdraw(true);
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
    fn load(&mut self, shape: Shape, bypass: Bypass, ts_chain: Chain, narrowing: bool) -> Result<(), String> {
        self.load_inner(shape, bypass, ts_chain, None, narrowing, false, "Tailscale exit via Mihomo enabled")
    }

    fn load_inner(
        &mut self,
        shape: Shape,
        bypass: Bypass,
        ts_chain: Chain,
        sampled_ts: Option<TailscaleExitConfig>,
        narrowing: bool,
        extra_ts_v4_reset: bool,
        ts_reset_reason: &'static str,
    ) -> Result<(), String> {
        let chain = match &shape {
            Shape::Full(chain) => (*chain).clone(),
            _ => Chain::default(),
        };
        let sniffer_ready = self.run.as_ref().is_some_and(|r| r.prepared.tailscale_sniffer);
        let submitted_ts = sampled_ts.unwrap_or_else(|| self.effective_ts_exit(sniffer_ready));
        let submitted_ts_chain = if matches!(shape, Shape::Full(_)) && submitted_ts.tproxy_v4 {
            ts_chain
        } else {
            Chain::default()
        };
        let ts_arg = matches!(shape, Shape::Full(_)).then_some(&submitted_ts_chain);
        let gen_before = self.port.tables_target_generation();
        let loaded = self.apply_tables_with(shape, ts_arg, &submitted_ts);
        let gen_after = self.port.tables_target_generation();
        let accepted = loaded.is_ok()
            || (gen_before.is_none() && gen_after.is_none())
            || (gen_after.is_some() && gen_after != gen_before);
        let mut newly_ts = (false, false);
        if let Some(run) = self.run.as_mut() {
            let confirmed = loaded.is_ok();
            if accepted {
                if confirmed {
                    newly_ts = run.needs_enable_reset(&submitted_ts);
                }
                run.declared(bypass, chain, submitted_ts_chain, submitted_ts, narrowing, confirmed, gen_after);
                run.unfollowed |= narrowing && confirmed;
                if confirmed {
                    run.ts_exit_dirty = false;
                }
            } else {
                // `EffectSet` rejected the batch before updating its nft target
                // (e.g. journal write failure): do NOT push an unaccepted entry
                // into `run.pending`, otherwise `guard()` confirming the older
                // generation could falsely promote it!
                if submitted_ts != run.ts_exit {
                    run.ts_exit_dirty = true;
                }
                if !narrowing {
                    run.unfollowed = true;
                }
            }
            let shown = run.kernel.0.clone();
            self.set_bypass(shown);
        }
        let reset_v4 = newly_ts.0 || extra_ts_v4_reset;
        let reset_v6 = newly_ts.1;
        if reset_v4 || reset_v6 {
            self.reset_tailscale_flows(ts_reset_reason, reset_v4, reset_v6, true);
        }
        loaded
    }

    fn exited(&mut self, generation: u64, how: String) {
        if self.stopping_core.as_ref().is_some_and(|c| c.generation() == generation) {
            crate::netlog!("[mihomo] confirmed exit of stopping core generation={generation} ({how})");
            self.stopping_core = None;
            self.stopping_ts = StoppingTs::default();
            if self.cause.is_some() {
                self.withdraw(false);
            } else if self.phase == Phase::CleanupPending && !self.port.wanted() {
                let _ = self.stop_all();
            }
            return;
        }
        if self.run.as_ref().is_none_or(|r| r.core.generation() != generation) {
            crate::netlog!("[mihomo] ignored the exit of an old core generation={generation} ({how})");
            return;
        }
        self.fail_inner(format!("Mihomo exited ({how})"), true);
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
        use super::follow::{plan, Before};
        match plan(run.may_return(), unsettled) {
            Before::Keep => Ok(()),
            Before::Hold => self.load(Shape::Hold, Bypass::None(format!("Following {why}")), Chain::default(), true),
            Before::ExcludeProviders => {
                let sniffer_ready = run.prepared.tailscale_sniffer;
                let routes = run.prepared.routes.clone();
                let bypass_on = run.prepared.bypass;
                let mode = run.mode;
                let selected = run.selected.clone();
                let (bypass, tight) = self.port.plan(&routes, bypass_on, mode, &selected, unsettled);
                let effective_ts = self.effective_ts_exit(sniffer_ready);
                let ts_tight = if effective_ts.tproxy_v4 {
                    self.port.plan_tailscale(&routes, mode, &selected, unsettled)
                } else {
                    Chain::default()
                };
                self.load_inner(
                    Shape::Full(&tight),
                    bypass,
                    ts_tight,
                    Some(effective_ts),
                    true,
                    false,
                    "Tailscale exit via Mihomo enabled",
                )
            }
        }.map_err(|e| format!("Nothing was changed: the bypass could not be narrowed first ({e})"))?;
        change(&mut self.port);
        self.widen(why);
        Ok(())
    }

    /// Reads back what the core runs and loads the plan that gives,
    /// resetting what lost DIRECT since the last reset. Until the core
    /// answers, the bypass stays narrowed and the next tick asks again.
    fn widen(&mut self, why: &str) {
        let Some((secret, sniffer_ready)) = self.run.as_ref().map(|r| (r.prepared.secret.clone(), r.prepared.tailscale_sniffer)) else { return };
        let Some((mode, selected, runtime)) = self.port.read_back(&secret) else {
            if let Some(run) = self.run.as_mut() {
                run.unfollowed = true;
            }
            self.error = Some(format!("Mihomo did not report its state after {why}; the bypass stays narrowed until it does"));
            let effective = self.effective_ts_exit(sniffer_ready);
            let needs_withdrawal = self.run.as_ref().is_some_and(|r| {
                !r.ts_exit_dirty
                    && ((r.may_intercept_ts_v4() && !effective.tproxy_v4)
                        || (r.may_intercept_ts_v6() && !effective.tproxy_v6)
                        || r.ts_target().skip_v4 != effective.skip_v4
                        || r.ts_target().skip_v6 != effective.skip_v6)
            });
            if needs_withdrawal {
                self.apply_tailscale_kernel_only(why);
            }
            return;
        };
        self.sync_ts_v4_reset_ack();
        let Some(run) = self.run.as_mut() else { return };
        let routes = run.prepared.routes.clone();
        let bypass_on = run.prepared.bypass;
        let (bypass, chain) = self.port.plan(&routes, bypass_on, mode, &selected, &[]);
        let effective_ts = self.effective_ts_exit(sniffer_ready);
        let ts_chain = if effective_ts.tproxy_v4 {
            self.port.plan_tailscale(&routes, mode, &selected, &[])
        } else {
            Chain::default()
        };
        let lost = self.run.as_ref().map(|run| routing::lost_from(&run.bypassed, &chain)).unwrap_or(Scope::Destinations(Vec::new()));
        let ts_lost = self.run.as_ref().is_some_and(|run| {
            let bypassed_chains = run.ts_bypassed_chains();
            !matches!(routing::lost_from(&bypassed_chains, &ts_chain), Scope::Destinations(ref d) if d.is_empty())
        });
        self.reset("Mihomo routing changed", lost, Instant::now());
        if let Some(run) = self.run.as_mut() {
            run.reset_lan_done();
            run.mode = mode;
            run.selected = selected;
            run.prepared.runtime = runtime;
            run.followed = Instant::now();
            run.unfollowed = false;
        }
        if let Err(e) = self.load_inner(
            Shape::Full(&chain),
            bypass,
            ts_chain,
            Some(effective_ts.clone()),
            false,
            ts_lost,
            "Mihomo Tailscale routing changed",
        ) {
            if let Some(run) = self.run.as_mut() {
                if run.ts_exit != effective_ts {
                    run.ts_exit_dirty = true;
                }
                if run.kernel.1.returns == 0 {
                    self.set_bypass(Bypass::None(format!("The new kernel plan is not confirmed yet: {e}")));
                }
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
    fn guard(&mut self) -> bool {
        if !self.port.guard_due() {
            return false;
        }
        // Supersede any revoked pending Tailscale target before reconciling so
        // guard can never replay an unconfirmed enable after revocation. If
        // superseding did not confirm (e.g. journal write failed before
        // EffectSet updated its target), skip `reconcile()` rather than risk
        // replaying the older enable target!
        if self.supersede_revoked_tailscale_before_guard().is_err() {
            return true;
        }
        let checked = self.port.reconcile();
        if let Err(e) = checked.result {
            self.error = Some(e);
        }
        let Some(run) = self.run.as_mut().filter(|_| checked.confirmed) else { return true };
        let Some((narrowing, (newly_v4, newly_v6))) = run.loaded(checked.confirmed_generation) else { return true };
        crate::netlog!("[mihomo] a table that had not loaded is in the kernel now (bypass {})", run.kernel.0.label());
        let shown = run.kernel.0.clone();
        self.set_bypass(shown);
        if newly_v4 || newly_v6 {
            self.reset_tailscale_flows("Mihomo Tailscale exit enabled (late reconcile)", newly_v4, newly_v6, true);
        }
        if narrowing {
            self.widen("a narrowed table that loaded late");
        }
        true
    }

    fn egress(&mut self) {
        let observed = self.port.uplink(true);
        let Some(run) = self.run.as_mut() else {
            self.egress_while_direct(observed);
            return;
        };
        run.ipv6 = observed.paths[1].is_some();
        match run.prepared.egress.change(&run.uplink, &observed) {
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
            Change::V4 | Change::Rebind => {
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
        self.sync_ts_v4_reset_ack();
        match self.phase {
            Phase::CleanupPending if self.stopping_core.is_some() && self.port.owns() => {
                let cfg = self.port.tailscale_exit();
                let want_v4 = self.stopping_ts.allow.0 && cfg.tproxy_v4;
                let want_v6 = self.stopping_ts.allow.1 && cfg.tproxy_v6;
                let needs_ts_sync = self.cleanup_ts_dirty
                    || self.stopping_ts.pending_sync
                    || (self.stopping_ts.may.0 && !want_v4)
                    || (self.stopping_ts.may.1 && !want_v6)
                    || (want_v4 && self.stopping_ts.skip_v4 != cfg.skip_v4)
                    || (want_v6 && self.stopping_ts.skip_v6 != cfg.skip_v6);
                let retry_due =
                    self.cause.is_some() && self.retry_at.is_some_and(|at| Instant::now() >= at);
                if needs_ts_sync {
                    let _ = self.sync_cleanup_tailscale_exit();
                }
                if retry_due {
                    let _ = self.retry(None);
                }
                if needs_ts_sync || retry_due {
                    self.publish();
                }
                return;
            }
            Phase::Backoff | Phase::CleanupPending if (self.phase == Phase::Backoff || self.cause.is_some()) && self.retry_at.is_some_and(|at| Instant::now() >= at) => {
                let _ = self.retry(None);
                self.publish();
                return;
            }
            Phase::Running => {}
            _ => return,
        }
        let mut changed = false;
        let now = Instant::now();
        if self.run.as_ref().is_some_and(|r| now.duration_since(r.started) >= self.timings.stable) && self.failures > 0 {
            changed = true;
            self.failures = 0;
            self.exits.clear();
        }
        changed |= self.guard();
        // A Tailscale exit withdrawal/update whose kernel load or reload did not confirm yet.
        let desired_ts = self.port.tailscale_exit();
        let ts_needs_sync = self.run.as_ref().is_some_and(|r| {
            let allow_ts = !desired_ts.sniffer || r.prepared.tailscale_sniffer;
            let want_v4 = allow_ts && desired_ts.tproxy_v4;
            let want_v6 = allow_ts && desired_ts.tproxy_v6;
            r.ts_exit_dirty
                || r.prepared.tailscale_sniffer != desired_ts.sniffer
                || r.ts_exit.tproxy_v4 != want_v4
                || r.ts_exit.tproxy_v6 != want_v6
                || r.may_intercept_ts_v4() != want_v4
                || r.may_intercept_ts_v6() != want_v6
                || r.ts_exit.skip_v4 != desired_ts.skip_v4
                || r.ts_exit.skip_v6 != desired_ts.skip_v6
                || r.ts_target().skip_v4 != desired_ts.skip_v4
                || r.ts_target().skip_v6 != desired_ts.skip_v6
        });
        if ts_needs_sync {
            changed = true;
            self.sync_tailscale_exit();
        }
        // A narrowing whose follow did not read the core back yet.
        if self.run.as_ref().is_some_and(|r| r.unfollowed) {
            changed = true;
            self.widen("an earlier change");
        }
        // An IPv6-only egress change that held.
        let v6 = self.run.as_ref().and_then(|r| r.v6.clone());
        if let Some((seen, since)) = v6 {
            let observed = self.port.uplink(true);
            if observed != seen {
                if let Some(run) = self.run.as_mut() {
                    run.v6 = (run.prepared.egress.change(&run.uplink, &observed) == Change::V6).then(|| (observed, now));
                }
            } else if egress::v6_due(since, self.v6_restarted) <= now {
                self.v6_restarted = Some(now);
                let _ = self.restart("the IPv6 egress changed", Restart::Egress);
                self.publish();
                return;
            }
        }
        // Check routes and the relay's access point, even without a notification.
        if self.run.as_ref().is_some_and(|r| now.duration_since(r.audited) >= self.timings.audit || r.stranding.is_some()) {
            let observed = self.port.uplink(true);
            let changed_family = self.run.as_mut().and_then(|run| {
                run.audited = now;
                changed |= run.ipv6 != observed.paths[1].is_some();
                run.ipv6 = observed.paths[1].is_some();
                let family = run.prepared.egress.change(&run.uplink, &observed);
                let last = if family == Change::V6 {
                    self.egress_restarted.max(self.v6_restarted)
                } else {
                    self.egress_restarted
                };
                egress::settle_egress(&run.prepared.egress, &mut run.uplink, &mut run.stranding, observed, last, now).then_some(family)
            });
            if let Some(family) = changed_family {
                self.egress_restarted = Some(now);
                if family == Change::V6 {
                    self.v6_restarted = Some(now);
                }
                let _ = self.restart("the egress changed during the route audit", Restart::Egress);
                self.publish();
                return;
            }
        }
        // Rule sets the controller refreshes (Q2), one per tick.
        let due = self.run.as_ref().and_then(|r| r.refresh.iter().position(|(_, _, at)| *at <= now));
        if let Some(index) = due {
            changed = true;
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
                let observed = if sources { None } else { self.port.read_back(&secret) };
                let differs = super::follow::decide(sources, (mode, &selected), observed.as_ref().map(|(m, s, _)| (*m, s)));
                if differs {
                    changed = true;
                    crate::netlog!("[mihomo] the core's mode, a group or a rule set changed outside the controller; following it");
                    let _ = self.follow("a change in the core", &[], |_| {});
                } else if let Some(run) = self.run.as_mut() {
                    run.followed = now;
                }
            }
        }
        if changed { self.publish(); }
    }
}

/// The D2 wait before retry number `failures` (1-based), given recent exits.
#[cfg(test)]
pub(super) fn retry_wait(timings: &Timings, failures: u32, recent_exits: usize) -> Duration {
    let last = timings.retries.len() - 1;
    timings.retries[if recent_exits >= 3 { last } else { (failures as usize).saturating_sub(1).min(last) }]
}

#[cfg(test)]
pub(super) mod tests;
