use super::*;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender};

pub(super) type Reply = SyncSender<Result<Option<Value>, String>>;

pub(super) enum Command {
    Boot,
    Restore,
    Scan,
    Connect { selection: Selection, ipv6: bool, remember: bool, generation: u64 },
    PowerSave(bool),
    Offload(bool),
    Forget(String),
    Clock,
}

pub(super) enum Message {
    Request(Request),
    Disconnect,
    Tick,
    Retry {
        generation: u64,
        attempt: usize,
    },
    Wake,
    #[cfg(test)]
    Stop,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Started {
    Pending,
    Running,
    Abandoned,
}

struct Start {
    state: Started,
    claim: Option<crate::netfx::admission::Claim>,
}

impl Start {
    fn pending(claim: Option<crate::netfx::admission::Claim>) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self { state: Started::Pending, claim }))
    }
}

pub(super) struct Request {
    command: Command,
    reply: Reply,
    started: Arc<Mutex<Start>>,
    deadline: Option<Instant>,
}

pub(super) fn boot(sender: &Sender<Message>, reply: Reply) {
    let _ = sender.send(Message::Request(Request { command: Command::Boot, reply, started: Start::pending(None), deadline: None }));
}

pub(super) fn request(relay: &WifiRelay, command: Command, deadline: Option<Instant>) -> Result<Option<Value>, String> {
    let claim = if let Some(deadline) = deadline {
        use crate::netfx::admission::{begin, RELAY_OPERATION, VENDOR_WIFI_RELOAD, VENDOR_WRITE};
        Some(
            begin(&relay.lock, RELAY_OPERATION, &[VENDOR_WRITE, VENDOR_WIFI_RELOAD], deadline.saturating_duration_since(Instant::now()))
                .map_err(|error| {
                    if error == "A network operation is in progress; retry after it finishes" {
                        relay.in_progress()
                    } else {
                        error
                    }
                })?,
        )
    } else {
        None
    };
    let (reply, answer) = mpsc::sync_channel(1);
    let started = Start::pending(claim);
    relay.send(Message::Request(Request { command, reply, started: Arc::clone(&started), deadline }))?;
    if let Some(deadline) = deadline {
        match answer.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(result) => return result,
            Err(RecvTimeoutError::Disconnected) => return Err("The relay controller stopped".into()),
            Err(RecvTimeoutError::Timeout) => {
                let mut state = started.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.state == Started::Pending {
                    state.state = Started::Abandoned;
                    state.claim.take();
                    return Err(relay.in_progress());
                }
            }
        }
    }
    answer.recv().map_err(|_| "The relay controller stopped".to_owned())?
}

pub(super) struct State {
    pub session: Option<Session>,
    pub scans: Vec<Network>,
    pub error: Option<String>,
    pub phase: Phase,
}

impl Default for State {
    fn default() -> Self {
        Self { session: None, scans: Vec::new(), error: None, phase: Phase::Idle }
    }
}

pub(super) struct Selection {
    pub network: Network,
    pub password: String,
    pub config: String,
}

impl Selection {
    pub fn from(scans: &[Network], id: &str, password: &str) -> Result<Self, String> {
        let (network, password, config) = selected_config(scans, id, password)?;
        Ok(Self { network, password, config })
    }
}

pub(super) struct Observation {
    #[cfg(test)]
    pub link: Option<String>,
    pub lease: Option<Lease>,
    pub helpers: bool,
    pub resolvers_valid: bool,
    pub hotspot_off: bool,
    pub by_owner: bool,
}

pub(super) trait Port: Send + 'static {
    fn now(&self) -> Instant;
    fn boot_now(&self) -> BootInstant;
    fn snapshot(&mut self, state: &State) -> Value;
    fn pending(&self) -> bool;
    fn target(&mut self) -> Option<resume::Resume>;
    fn clear(&mut self) -> Result<(), String>;
    fn hotspot(&mut self) -> (bool, bool);
    fn recover(&mut self) -> Result<(), String>;
    fn adopt(&mut self) -> Option<Session>;
    fn scan(&mut self, state: &mut State, cancel: &Cancellation) -> Result<Vec<Network>, String>;
    fn join(&mut self, state: &mut State, selection: Selection, ipv6: bool, cancel: &Cancellation) -> Result<Session, String>;
    fn persist(&mut self, selection: &Selection, ipv6: bool, remember: bool) -> Option<String>;
    fn cleanup(&mut self, session: &mut Session) -> Result<(), String>;
    fn observe_link(&mut self) -> (Option<String>, u128);
    fn observe(&mut self, session: &mut Session) -> Observation;
    fn renew(&mut self, session: &mut Session);
    fn maintain(&mut self, session: &mut Session) -> Result<bool, String>;
    fn uplink_changed(&self);
    fn power_save(&mut self, state: &mut State, enabled: bool) -> Result<(), String>;
    fn offload(&mut self, state: &mut State, enabled: bool) -> Result<Option<Value>, String>;
    fn forget(&mut self, id: &str) -> Result<(), String>;
    fn clock(&mut self) -> Result<(), String>;
}

pub(super) struct Timings {
    pub tick: Duration,
    pub retries: Vec<Duration>,
}

impl Default for Timings {
    fn default() -> Self {
        Self { tick: Duration::from_secs(3), retries: RESTORE_WAITS.map(Duration::from_secs).to_vec() }
    }
}

struct Restoring {
    target: resume::Resume,
    generation: u64,
    attempt: usize,
    due: Option<Instant>,
    reply: Reply,
}

pub(super) struct Controller<P: Port> {
    port: P,
    receiver: Receiver<Message>,
    sender: Sender<Message>,
    shared: Arc<Shared>,
    lock: NetworkLock,
    timings: Timings,
    state: State,
    restoring: Option<Restoring>,
    tick_at: Option<Instant>,
    booted: bool,
    unpublished: Option<(u64, bool)>,
    unpublished_scans: Option<(u64, Vec<Network>)>,
    restore_replies: Vec<Reply>,
    notify: bool,
}

impl<P: Port> Controller<P> {
    pub fn new(
        port: P,
        receiver: Receiver<Message>,
        sender: Sender<Message>,
        shared: Arc<Shared>,
        lock: NetworkLock,
        timings: Timings,
    ) -> Self {
        let state = State { scans: shared.snapshot.lock().unwrap_or_else(std::sync::PoisonError::into_inner).scans.clone(), ..State::default() };
        Self {
            port,
            receiver,
            sender,
            shared,
            lock,
            timings,
            state,
            restoring: None,
            tick_at: None,
            booted: false,
            unpublished: None,
            unpublished_scans: None,
            restore_replies: Vec::new(),
            notify: false,
        }
    }

    pub fn supervised(self, end: impl FnOnce(String)) {
        if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.run())) {
            let what = panic.downcast_ref::<&str>().map(|text| (*text).to_owned()).or_else(|| panic.downcast_ref::<String>().cloned());
            end(what.unwrap_or_else(|| "a panic".into()));
        }
    }

    pub fn run(mut self) {
        loop {
            self.cancelled_restore();
            let disconnect = self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner).disconnect;
            if (disconnect && self.booted) || !self.restore_replies.is_empty() {
                self.finish(None);
            }
            let now = self.port.now();
            if self.tick_at.is_some_and(|due| due <= now) {
                self.tick_at = None;
                let _ = self.shared.queue_tick(&self.sender);
            }
            if let Some(restore) = self.restoring.as_mut().filter(|restore| restore.due.is_some_and(|due| due <= now)) {
                restore.due = None;
                let _ = self.sender.send(Message::Retry { generation: restore.generation, attempt: restore.attempt });
            }
            let due = self.tick_at.into_iter().chain(self.restoring.as_ref().and_then(|restore| restore.due)).min();
            let wait = due.map_or(Duration::from_secs(3600), |due| due.saturating_duration_since(now));
            match self.receiver.recv_timeout(wait) {
                Ok(Message::Request(request)) => self.handle(request),
                Ok(Message::Disconnect) => self.finish(None),
                Ok(Message::Tick) => self.tick(),
                Ok(Message::Retry { generation, attempt }) => {
                    if self.restoring.as_ref().is_some_and(|restore| restore.generation == generation && restore.attempt == attempt) {
                        self.restore_attempt();
                    }
                }
                Ok(Message::Wake) => {}
                #[cfg(test)]
                Ok(Message::Stop) => return,
                Err(RecvTimeoutError::Disconnected) => return,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn claim(&self) -> crate::netfx::admission::Claim {
        crate::netfx::admission::claim(crate::netfx::admission::RELAY_OPERATION, Duration::from_secs(3600))
    }

    fn cancellation(&self, generation: u64, target: Option<resume::Resume>) -> Cancellation {
        Cancellation { shared: Arc::clone(&self.shared), generation, target }
    }

    fn phase(&mut self, phase: Phase) {
        self.state.phase = phase;
        self.shared.phase(phase);
    }

    fn handle(&mut self, request: Request) {
        let mut cancel = self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut start = request.started.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if start.state == Started::Abandoned {
            return;
        }
        if request.deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            start.state = Started::Abandoned;
            start.claim.take();
            let _ = request.reply.send(Err(self.shared.in_progress()));
            return;
        }
        if cancel.disconnect && !matches!(request.command, Command::Boot) {
            drop(cancel);
            drop(start);
            self.finish(None);
            return self.handle(request);
        }
        start.state = Started::Running;
        let claim = start.claim.take();
        cancel.working = true;
        let generation = cancel.restore_generation;
        drop(cancel);
        drop(start);
        let _claim = claim.unwrap_or_else(|| self.claim());
        let result = match request.command {
            Command::Boot => {
                if !self.booted && self.state.session.is_none() {
                    self.phase(Phase::Recovering);
                    self.state.session = self.port.adopt();
                    if self.state.session.is_some() {
                        self.unpublished = Some((generation, false));
                    }
                    if self.state.session.is_none() {
                        self.state.error = self.port.recover().err();
                    }
                }
                self.booted = true;
                Ok(None)
            }
            Command::Restore => {
                if self.begin_restore(request.reply.clone()) {
                    self.finish(None);
                    return;
                }
                Ok(None)
            }
            Command::Scan => self.scan(self.cancellation(generation, None)).map(|_| None),
            Command::Connect { selection, ipv6, remember, generation } => {
                self.join(selection, ipv6, Origin::Owner { remember, generation }).map(|_| None)
            }
            Command::PowerSave(enabled) => self.port.power_save(&mut self.state, enabled).map(|_| None),
            Command::Offload(enabled) => self.port.offload(&mut self.state, enabled),
            Command::Forget(id) => self.port.forget(&id).map(|_| None),
            Command::Clock => {
                if self.state.session.as_ref().is_some_and(|session| session.selected.is_some() && session.lease.is_some()) {
                    self.port.clock().map(|_| None)
                } else {
                    Err("Connect Wi-Fi relay before checking time".into())
                }
            }
        };
        self.finish(Some((request.reply, result)));
    }

    fn settle(&mut self) {
        self.state.phase = if let Some(session) = &self.state.session {
            if session.association.since.is_some() {
                Phase::Recovering
            } else {
                Phase::Active
            }
        } else if self.restoring.is_some() {
            Phase::Recovering
        } else if self.port.pending() {
            Phase::RecoveryPending
        } else {
            Phase::Idle
        };
    }

    fn finish(&mut self, mut reply: Option<(Reply, Result<Option<Value>, String>)>) {
        let _claim = self.claim();
        let mut disconnect_reply = None;
        let mut disconnected = Ok(None);
        loop {
            let pending = {
                let mut cancel = self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                cancel.working = true;
                if cancel.disconnect {
                    cancel.disconnect = false;
                    cancel.tearing_down = true;
                    disconnect_reply = cancel.reply.take().or(disconnect_reply);
                    true
                } else {
                    false
                }
            };
            if pending {
                disconnected = self.teardown().map(|_| None);
                self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner).tearing_down = false;
            }
            self.cancelled_restore();
            self.settle();
            let value = self.port.snapshot(&self.state);
            let pending = self.port.pending();
            let mut cancel = self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if cancel.disconnect {
                drop(cancel);
                continue;
            }
            if self.unpublished_scans.as_ref().is_some_and(|(generation, _)| *generation != cancel.restore_generation) {
                drop(cancel);
                self.state.scans = self.unpublished_scans.take().unwrap().1;
                if let Some((_, result)) = reply.as_mut() {
                    *result = Err(RESTORE_CANCELLED.into());
                }
                continue;
            }
            if self.unpublished.is_some_and(|(generation, _)| generation != cancel.restore_generation) {
                drop(cancel);
                let (_, owner) = self.unpublished.take().unwrap();
                let cleared = if owner { self.port.clear() } else { Ok(()) };
                self.phase(Phase::Disconnecting);
                let cleaned = self.state.session.take().map_or(Ok(()), |mut session| self.port.cleanup(&mut session));
                self.state.error = cleaned.and(cleared).err();
                if let Some((_, result)) = reply.as_mut() {
                    *result = Err(self.state.error.clone().unwrap_or_else(|| RESTORE_CANCELLED.into()));
                }
                continue;
            }
            self.shared.publish(&self.state, value, pending, &cancel);
            self.unpublished = None;
            self.unpublished_scans = None;
            cancel.working = false;
            let notify = std::mem::take(&mut self.notify) && self.state.session.is_some();
            drop(cancel);
            if notify {
                self.port.uplink_changed();
            }
            for reply in self.restore_replies.drain(..) {
                let _ = reply.send(Ok(None));
            }
            if let Some(reply) = disconnect_reply {
                let _ = reply.send(disconnected);
            }
            if let Some((reply, result)) = reply {
                let _ = reply.send(result);
            }
            let active = self.state.session.as_ref().is_some_and(|session| session.selected.is_some());
            self.tick_at = if active { self.tick_at.or_else(|| Some(self.port.now() + self.timings.tick)) } else { None };
            return;
        }
    }

    fn teardown(&mut self) -> Result<(), String> {
        self.phase(Phase::Disconnecting);
        let cleared = self.port.clear();
        let session = self.state.session.take();
        self.shared.active.store(false, Ordering::Release);
        self.publish();
        let result = if let Some(mut session) = session { self.port.cleanup(&mut session) } else { self.port.recover() };
        let result = result.and(cleared);
        self.state.error = result.as_ref().err().cloned();
        result
    }

    fn scan(&mut self, cancel: Cancellation) -> Result<(), String> {
        cancel.check()?;
        self.phase(Phase::Scanning);
        let scans = self.port.scan(&mut self.state, &cancel)?;
        cancel.check()?;
        let previous = std::mem::replace(&mut self.state.scans, scans);
        self.unpublished_scans = Some((cancel.generation, previous));
        self.state.error = None;
        Ok(())
    }

    fn join(&mut self, selection: Selection, ipv6: bool, origin: Origin<'_>) -> Result<(), String> {
        let target = match origin {
            Origin::Restore(target, _) => Some(target.clone()),
            _ => None,
        };
        let cancel = self.cancellation(origin.generation(), target);
        cancel.check()?;
        self.phase(Phase::Connecting);
        self.state.error = None;
        let saved = Selection { network: selection.network.clone(), password: selection.password.clone(), config: String::new() };
        let result = self.port.join(&mut self.state, selection, ipv6, &cancel);
        let mut session = match result {
            Ok(session) => session,
            Err(error) => {
                if self.state.error.is_none() {
                    self.state.error = (error != RESTORE_CANCELLED).then(|| error.clone());
                }
                return Err(error);
            }
        };
        if let Err(error) = cancel.check() {
            self.phase(Phase::Disconnecting);
            return self.port.cleanup(&mut session).and(Err(error));
        }
        let error = match origin {
            Origin::Owner { remember, .. } => self.port.persist(&saved, ipv6, remember),
            _ => None,
        };
        let guard = self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.restore_generation != origin.generation() || guard.disconnect {
            drop(guard);
            let cleared = if matches!(origin, Origin::Owner { .. }) { self.port.clear() } else { Ok(()) };
            self.phase(Phase::Disconnecting);
            let result = self.port.cleanup(&mut session).and(cleared);
            self.state.error = result.as_ref().err().cloned();
            return result.and(Err(RESTORE_CANCELLED.into()));
        }
        self.state.session = Some(session);
        self.state.error = error;
        self.state.phase = Phase::Active;
        self.unpublished = Some((origin.generation(), matches!(origin, Origin::Owner { .. })));
        drop(guard);
        self.notify = true;
        Ok(())
    }

    fn begin_restore(&mut self, reply: Reply) -> bool {
        let Some(target) = self.port.target() else { return false };
        let mut cancel = self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.state.session.is_some() || cancel.restore_generation != 0 || self.restoring.is_some() {
            return false;
        }
        cancel.restoring = Some(target.ssid.clone());
        self.restoring = Some(Restoring {
            target,
            generation: cancel.restore_generation,
            attempt: 0,
            due: Some(self.port.now() + self.timings.retries[0]),
            reply,
        });
        true
    }

    fn cancelled_restore(&mut self) {
        if self.restoring.as_ref().is_some_and(|restore| !self.shared.generation_matches(restore.generation)) {
            self.end_restore(None);
        }
    }

    fn end_restore(&mut self, error: Option<String>) {
        let Some(restore) = self.restoring.take() else { return };
        let mut cancel = self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if cancel.restore_generation == restore.generation {
            cancel.restoring = None;
            if error.is_some() {
                self.state.error = error;
            }
        }
        self.restore_replies.push(restore.reply);
    }

    fn restore_attempt(&mut self) {
        let Some(restore) = self.restoring.as_ref() else { return };
        let (target, generation, attempt) = (restore.target.clone(), restore.generation, restore.attempt);
        {
            let mut cancel = self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if cancel.disconnect || cancel.restore_generation != generation {
                return;
            }
            cancel.working = true;
        }
        let _claim = self.claim();
        let (off, owner) = self.port.hotspot();
        let result = if off && owner {
            let error = self.port.clear().err();
            self.end_restore(error);
            self.shared.cancel_restore();
            self.finish(None);
            return;
        } else if off {
            crate::netlog!("[relay] restore attempt {} skipped: Wi-Fi is off, but not by the owner's switch", attempt + 1);
            Err("Wi-Fi is off".into())
        } else {
            let admission = crate::netfx::admission::begin(
                &self.lock,
                crate::netfx::admission::RELAY_OPERATION,
                &[crate::netfx::admission::VENDOR_WRITE, crate::netfx::admission::VENDOR_WIFI_RELOAD],
                crate::netfx::admission::WAIT,
            );
            if self.port.target().as_ref() != Some(&target) {
                self.end_restore(None);
                self.finish(None);
                return;
            }
            admission.and_then(|_claim| {
                self.scan(self.cancellation(generation, Some(target.clone()))).and_then(|()| {
                    let selected =
                        resume::pick(&target, &self.state.scans).ok_or_else(|| "The network was not found in the scan".to_owned())?;
                    let selection = Selection::from(&self.state.scans, &selected.id, "")?;
                    self.join(selection, target.ipv6, Origin::Restore(&target, generation))
                })
            })
        };
        match result {
            Ok(()) => {
                crate::netlog!("[relay] restored after {} attempt(s)", attempt + 1);
                self.end_restore(None);
            }
            Err(error) if error == RESTORE_CANCELLED => self.end_restore(None),
            Err(error) => {
                if !off && error != RESTORE_NO_PASSWORD {
                    crate::netlog!("[relay] restore attempt {} failed: {error}", attempt + 1);
                }
                if error == RESTORE_NO_PASSWORD || attempt + 1 == self.timings.retries.len() {
                    self.end_restore(Some(format!("Could not reconnect after the agent restarted: {error}. Scan and reconnect.")));
                } else if let Some(restore) = self.restoring.as_mut() {
                    restore.attempt += 1;
                    restore.due = Some(self.port.now() + self.timings.retries[restore.attempt]);
                }
            }
        }
        self.finish(None);
    }

    fn tick(&mut self) {
        self.shared.tick_pending.store(false, Ordering::Release);
        self.tick_at = None;
        if !self.state.session.as_ref().is_some_and(|session| session.selected.is_some()) {
            return;
        }
        {
            let mut cancel = self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if cancel.disconnect {
                return;
            }
            cancel.working = true;
        }
        let _claim = self.claim();
        let (link, query_ms) = self.port.observe_link();
        let session = self.state.session.as_mut().unwrap();
        let previous = session.association.state;
        let recovering = session.association.since.is_some();
        let link = session.association.observe(link.as_deref(), self.port.boot_now());
        if previous != session.association.state {
            crate::netlog!(
                "[relay] association state={} recovery_ms={} query_ms={query_ms}",
                session.association.state,
                session.association.elapsed(self.port.boot_now()).as_millis()
            );
        }
        if recovering && link == AssociationResult::Ready {
            self.port.renew(session);
        }
        let observed = self.port.observe(session);
        let change = session.lease.as_ref().map_or(LeaseChange::Replaced, |lease| lease_change(lease, observed.lease.as_ref()));
        let change = if matches!(change, LeaseChange::Resolvers(_)) && !observed.resolvers_valid { LeaseChange::Replaced } else { change };
        match decide(link, observed.helpers, change, observed.hotspot_off) {
            Decision::Teardown(reason) => {
                crate::netlog!(
                    "[relay] teardown reason={reason} recovery_ms={} query_ms={query_ms}",
                    session.association.elapsed(self.port.boot_now()).as_millis()
                );
                if observed.hotspot_off {
                    self.shared.cancel_restore();
                }
                self.phase(Phase::Disconnecting);
                let intent = if observed.by_owner { self.port.clear() } else { Ok(()) };
                let mut session = self.state.session.take().unwrap();
                self.publish();
                let restored = self.port.cleanup(&mut session);
                self.state.error = Some(restored.err().or_else(|| intent.err()).unwrap_or_else(|| {
                    if observed.by_owner { "Hotspot was turned off; relay stopped and restart recovery cancelled".into() }
                    else if observed.hotspot_off { "Wi-Fi is off; relay stopped. It reconnects when the router next starts with Wi-Fi on.".into() }
                    else { "Wi-Fi relay disconnected or lease changed; previous routing restored. Cellular data is used only if already enabled. Scan and reconnect.".into() }
                }));
            }
            Decision::Hold => self.phase(Phase::Recovering),
            Decision::Keep(next) => {
                if let Some(next) = next {
                    session.lease = Some(next);
                }
                match self.port.maintain(session) {
                    Err(error) => {
                        self.phase(Phase::Disconnecting);
                        let mut session = self.state.session.take().unwrap();
                        self.publish();
                        self.state.error = Some(self.port.cleanup(&mut session).err().unwrap_or(error));
                    }
                    Ok(true) => self.notify = true,
                    Ok(false) => {}
                }
            }
        }
        self.finish(None);
    }

    fn publish(&mut self) {
        let value = self.port.snapshot(&self.state);
        let pending = self.port.pending();
        let cancel = self.shared.cancel.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.shared.publish(&self.state, value, pending, &cancel);
    }
}

#[cfg(test)]
mod tests;
