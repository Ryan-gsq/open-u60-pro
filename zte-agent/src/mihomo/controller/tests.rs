//! The controller against a fake device: exits, retries, switches and
//! failures replayed with short timings (I6; release blocker 3).

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

struct FakeCore {
    generation: u64,
    alive: Arc<AtomicBool>,
}

impl CoreHandle for FakeCore {
    fn generation(&self) -> u64 {
        self.generation
    }
    fn pid(&self) -> u32 {
        4000 + self.generation as u32
    }
    fn stop(&self) -> bool {
        self.alive.store(false, Ordering::SeqCst);
        true
    }
}

#[derive(Default)]
struct World {
    events: Vec<String>,
    wanted: bool,
    adoptable: bool,
    owned: bool,
    steps: bool,
    tables: Option<String>,
    spawned: Vec<u64>,
    /// Errors for the next `prepare` calls (`None`: succeed).
    prepare: VecDeque<Option<String>>,
    tables_fail: VecDeque<String>,
    release_fail: Option<String>,
    unready: bool,
    resets: Vec<Scope>,
    selected_direct: bool,
    writes: Vec<String>,
    uplink: Uplink,
    busy: Option<String>,
    /// Changes the DNS filter a `prepare` gives (the bypass setting).
    dns: u32,
    reload: Option<Result<u16, String>>,
    verify: Option<String>,
}

#[derive(Clone)]
struct FakePort(Arc<Mutex<World>>);

impl FakePort {
    fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.0.lock().unwrap()
    }
    fn log(&self, event: impl Into<String>) {
        self.world().events.push(event.into());
    }
}

fn chain(direct: bool) -> Chain {
    if direct {
        Chain { rules: vec!["ip daddr @ip_0 return".into()], sets: vec![("ip_0".into(), vec!["1.2.3.0/24".into()])], returns: 1, cut: None, plain: vec![Some((true, vec!["1.2.3.0/24".into()]))] }
    } else {
        Chain::default()
    }
}

impl Port for FakePort {
    fn adoptable(&mut self) -> bool {
        self.world().adoptable
    }
    fn recover(&mut self) -> Result<(), String> {
        self.log("recover");
        Ok(())
    }
    fn busy(&mut self) -> Option<String> {
        self.world().busy.clone()
    }
    fn prepare(&mut self, source: &Source) -> Result<Prepared, String> {
        let previous = matches!(source, Source::Previous(_));
        self.log(match source { Source::Previous(_) => "prepare previous", Source::Reload(_) => "prepare reload", _ => "prepare" });
        if let Some(Some(error)) = self.world().prepare.pop_front() {
            return Err(error);
        }
        let dns = vec![format!("filter {}", self.world().dns)];
        Ok(Prepared { secret: "s".into(), local: "u60.home.arpa".into(), runtime: json!({"mode": "rule"}), routes: routing::Routes::default(), dns, config: if previous { "previous".into() } else { "selected".into() } })
    }
    fn ports_free(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn engage(&mut self, how: Engage) -> Result<(), String> {
        self.log(format!("engage {how:?}"));
        let mut w = self.world();
        w.owned = true;
        w.steps = true;
        Ok(())
    }
    fn tables(&mut self, shape: Shape) -> Result<(), String> {
        let name = match shape {
            Shape::Guard => "guard".to_owned(),
            Shape::Hold => "hold".to_owned(),
            Shape::Full(c) => format!("full/{}", c.returns),
            Shape::FakeReject => "reject".to_owned(),
        };
        self.log(format!("tables {name}"));
        let mut w = self.world();
        if let Some(error) = w.tables_fail.pop_front() {
            return Err(error);
        }
        w.tables = Some(name);
        Ok(())
    }
    fn tables_status(&mut self) -> Value {
        json!(self.world().tables)
    }
    fn direct(&mut self) -> Result<(), String> {
        self.log("direct");
        let mut w = self.world();
        if w.owned {
            w.tables = Some("reject".into());
            w.steps = false;
        }
        Ok(())
    }
    fn release_all(&mut self) -> Result<(), String> {
        self.log("release");
        let mut w = self.world();
        if let Some(error) = w.release_fail.clone() {
            return Err(error);
        }
        w.owned = false;
        w.steps = false;
        w.tables = None;
        Ok(())
    }
    fn spawn(&mut self, generation: u64, _: &Prepared, _: Sender<Message>) -> Result<Box<dyn CoreHandle>, String> {
        self.log(format!("spawn {generation}"));
        self.world().spawned.push(generation);
        Ok(Box::new(FakeCore { generation, alive: Arc::new(AtomicBool::new(true)) }))
    }
    fn ready(&mut self, _: &Prepared) -> bool {
        !self.world().unready
    }
    fn verify_routing(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn read_back(&mut self, _: &str) -> Option<(Mode, Selected, Value)> {
        let direct = self.world().selected_direct;
        Some((Mode::Rule, [("G".to_owned(), if direct { "DIRECT" } else { "P" }.to_owned())].into(), json!({"mode": "rule", "log-level": "info"})))
    }
    fn plan(&mut self, _: &routing::Routes, _: Mode, selected: &Selected, unsettled: &[String]) -> (Bypass, Chain) {
        let direct = selected.get("G").is_some_and(|g| g == "DIRECT") && unsettled.is_empty();
        let chain = chain(direct);
        (if direct { Bypass::Rules { returns: 1, cut: None } } else { Bypass::None("none".into()) }, chain)
    }
    fn reset(&mut self, _: &'static str, scope: Scope, _: Instant) -> Result<Report, String> {
        self.world().resets.push(scope.clone());
        Ok(Report { scope, merged: false, deleted: 1 })
    }
    fn write(&mut self, _: &str, write: &Write) -> Answered {
        let tables = self.world().tables.clone();
        self.log(format!("write {} with tables {}", write.segments.join("/"), tables.unwrap_or_default()));
        let mut w = self.world();
        w.writes.push(write.segments.join("/"));
        if write.segments.first().is_some_and(|s| s == "proxies") {
            w.selected_direct = write.body["name"] == "DIRECT";
        }
        Ok((204, Vec::new()))
    }
    fn reload(&mut self, _: &str, _: &str) -> Result<u16, String> {
        let tables = self.world().tables.clone();
        self.log(format!("reload with tables {}", tables.unwrap_or_default()));
        self.world().reload.clone().unwrap_or(Ok(204))
    }
    fn verify_reload(&mut self, _: &Prepared, _: Option<&(String, bool)>, _: &Selected) -> Result<(), String> {
        self.world().verify.clone().map_or(Ok(()), Err)
    }
    fn uplink(&mut self) -> Uplink {
        self.world().uplink.clone()
    }
    fn reconcile(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn wanted(&mut self) -> bool {
        self.world().wanted
    }
    fn set_wanted(&mut self, on: bool) -> Result<(), String> {
        self.world().wanted = on;
        Ok(())
    }
    fn sources_changed(&mut self) -> bool {
        false
    }
    fn guard_due(&mut self) -> bool {
        false
    }
    fn retry_reset(&mut self) {}
}

fn timings() -> Timings {
    Timings {
        retries: [60, 120, 180, 240, 400].map(Duration::from_millis).to_vec(),
        quick: Duration::from_secs(5),
        stable: Duration::from_secs(60),
        ready: Duration::from_millis(300),
        tick: Duration::from_millis(10),
        audit: Duration::from_secs(60),
        follow: Duration::from_secs(60),
    }
}

struct Harness {
    port: FakePort,
    tx: Sender<Message>,
    shared: Arc<Mutex<Snapshot>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Harness {
    fn new(world: World) -> Self {
        let port = FakePort(Arc::new(Mutex::new(world)));
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let controller = Controller::new(port.clone(), rx, tx.clone(), Arc::clone(&shared), timings());
        let thread = std::thread::spawn(move || controller.run());
        Self { port, tx, shared, thread: Some(thread) }
    }

    fn call(&self, make: impl FnOnce(Reply) -> Message) -> Result<(), String> {
        let (reply, answer) = mpsc::sync_channel(1);
        self.tx.send(make(reply)).unwrap();
        answer.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    fn enable(&self, owner: bool) -> Result<(), String> {
        self.call(|reply| Message::Enable { local: "u60.home.arpa".into(), owner, reply: Some(reply) })
    }

    fn write(&self, group: &str, name: &str) -> Answered {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx.send(Message::Write { write: Write { method: "PUT", segments: vec!["proxies".into(), group.into()], body: json!({"name": name}) }, answer: Answer::Sync(tx) }).unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    fn snapshot(&self) -> Snapshot {
        self.shared.lock().unwrap().clone()
    }

    fn until(&self, what: &str, pred: impl Fn(&Snapshot) -> bool) -> Snapshot {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = self.snapshot();
            if pred(&snapshot) {
                return snapshot;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}: {snapshot:?}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn events(&self) -> Vec<String> {
        self.port.world().events.clone()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.tx.send(Message::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn after(events: &[String], first: &str, then: &str) -> bool {
    let a = events.iter().position(|e| e == first);
    let b = events.iter().rposition(|e| e == then);
    matches!((a, b), (Some(a), Some(b)) if a < b)
}

#[test]
fn a_start_guards_before_the_core_and_loads_the_plan_the_ready_core_reports() {
    let h = Harness::new(World { selected_direct: true, ..World::default() });
    h.enable(true).unwrap();
    let s = h.snapshot();
    assert_eq!((s.phase, s.generation), (Phase::Running, 1));
    assert_eq!(s.bypass, Some(Bypass::Rules { returns: 1, cut: None }));
    let events = h.events();
    assert_eq!(events, ["engage Fresh", "tables guard", "prepare", "spawn 1", "tables hold", "tables full/1"]);
    assert!(h.port.world().wanted);
    assert_eq!(h.port.world().resets, [Scope::Lan { v4: true, v6: false }], "the old direct path is reset once");
}

/// Release blocker 3: an old generation's exit, arriving after the new core
/// is ready, changes nothing.
#[test]
fn an_old_cores_late_exit_cannot_touch_the_new_one() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    // The relay brought up an uplink the core was started without: a
    // planned restart to generation 2.
    h.port.world().uplink = Uplink::sample("u60sta0", 9, "192.0.2.2", None);
    h.tx.send(Message::Egress).unwrap();
    let s = h.until("generation 2", |s| s.generation == 2 && s.phase == Phase::Running);
    let events = h.events();
    assert!(after(&events, "tables hold", "spawn 2"), "interception held before the old core stopped: {events:?}");
    h.tx.send(Message::Exited { generation: 1, how: "signal 15".into() }).unwrap();
    std::thread::sleep(Duration::from_millis(80));
    let later = h.snapshot();
    assert_eq!((later.phase, later.generation), (Phase::Running, s.generation));
    assert!(!h.events().contains(&"direct".to_owned()), "no D3 for a stale exit");
    assert_eq!(h.port.world().tables.as_deref(), Some("full/0"));
}

/// D3 and D2: a confirmed exit withdraws interception and retries 1st, 2nd…
/// A relay switch: the old uplink goes, a recreated interface comes up, and
/// IPv6 is added to it later. The core restarts once, for the new IPv4.
#[test]
fn a_relay_switch_restarts_the_core_once() {
    let h = Harness::new(World { uplink: Uplink::sample("u60sta0", 9, "192.168.2.124", Some("2409:8a00::5")), ..World::default() });
    h.enable(true).unwrap();
    let settle = || std::thread::sleep(Duration::from_millis(80));
    h.port.world().uplink = Uplink::default();
    h.tx.send(Message::Egress).unwrap();
    settle();
    assert_eq!(h.snapshot().generation, 1, "no egress: nothing to restart onto");
    h.port.world().uplink = Uplink::sample("u60sta0", 10, "192.168.2.124", None);
    h.tx.send(Message::Egress).unwrap();
    h.until("generation 2", |s| s.generation == 2 && s.phase == Phase::Running);
    h.port.world().uplink = Uplink::sample("u60sta0", 10, "192.168.2.124", Some("2409:8a00::5"));
    h.tx.send(Message::Egress).unwrap();
    settle();
    let s = h.snapshot();
    assert_eq!((s.phase, s.generation), (Phase::Running, 2), "IPv6 added to the same interface restarts nothing");
    assert_eq!(h.events().iter().filter(|e| e.starts_with("spawn")).count(), 2);
}

/// D3 and D2: a confirmed exit withdraws interception and retries 1st, 2nd…
#[test]
fn a_confirmed_exit_goes_direct_and_retries_with_backoff() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    h.tx.send(Message::Exited { generation: 1, how: "signal 9".into() }).unwrap();
    let s = h.until("backoff", |s| s.phase == Phase::Backoff);
    assert_eq!(s.failures, 1);
    assert!(s.error.unwrap().contains("signal 9"));
    assert_eq!(h.port.world().tables.as_deref(), Some("reject"), "fake-ip fails fast, everything else direct");
    assert!(!h.port.world().steps, "kernel settings and policy routes released");
    let s = h.until("retried", |s| s.phase == Phase::Running && s.generation == 2);
    assert_eq!(s.failures, 1, "cleared only after running stably");
    assert!(h.events().contains(&"engage FromBackoff".to_owned()));
    assert_eq!(h.port.world().resets.last(), Some(&Scope::Lan { v4: true, v6: true }), "after fail-open, both families are reset");
    // Three exits within the window: the longest wait at once.
    for generation in [2, 3] {
        h.tx.send(Message::Exited { generation, how: "exit code 2".into() }).unwrap();
        h.until("next generation", |s| s.generation == generation + 1 && s.phase == Phase::Running);
    }
    h.tx.send(Message::Exited { generation: 4, how: "exit code 2".into() }).unwrap();
    let s = h.until("fourth failure", |s| s.failures == 4 && s.phase == Phase::Backoff);
    let wait = s.retry_at.unwrap().saturating_duration_since(Instant::now());
    assert!(wait > Duration::from_millis(250), "jumped to the last step: {wait:?}");
    assert_eq!(retry_wait(&timings(), 1, 0), Duration::from_millis(60));
    assert_eq!(retry_wait(&timings(), 2, 2), Duration::from_millis(120));
    assert_eq!(retry_wait(&timings(), 2, 3), Duration::from_millis(400));
    assert_eq!(retry_wait(&timings(), 9, 0), Duration::from_millis(400));
}

/// Release blocker 3: a retry that was due before the owner turned it off
/// never starts the old core again.
#[test]
fn a_retry_queued_before_the_owner_turned_it_off_starts_nothing() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    h.tx.send(Message::Exited { generation: 1, how: "signal 9".into() }).unwrap();
    h.until("backoff", |s| s.phase == Phase::Backoff);
    h.call(|reply| Message::Disable { reply: Some(reply) }).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let s = h.snapshot();
    assert_eq!(s.phase, Phase::Off);
    assert_eq!(h.port.world().spawned, [1], "no retry after Off");
    assert!(!h.port.world().wanted && !h.port.world().owned);
    // A late exit of that core changes nothing either.
    h.tx.send(Message::Exited { generation: 1, how: "signal 9".into() }).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(h.snapshot().phase, Phase::Off);
}

#[test]
fn a_failed_release_stays_pending_and_owned_until_a_retry_succeeds() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    h.port.world().release_fail = Some("Network cleanup paused: rule busy".into());
    assert!(h.call(|reply| Message::Disable { reply: Some(reply) }).is_err());
    let s = h.snapshot();
    assert_eq!(s.phase, Phase::CleanupPending);
    assert!(h.port.world().owned, "the journal and ownership stay");
    assert!(h.enable(true).is_err(), "no start over effects not cleaned up");
    h.port.world().release_fail = None;
    h.call(|reply| Message::Disable { reply: Some(reply) }).unwrap();
    assert_eq!(h.snapshot().phase, Phase::Off);
    assert!(!h.port.world().owned);
}

#[test]
fn the_owners_failed_start_stays_off_and_a_boot_restore_keeps_retrying() {
    let h = Harness::new(World::default());
    h.port.world().prepare.push_back(Some("Mihomo could not validate the configuration".into()));
    assert!(h.enable(true).is_err());
    let s = h.snapshot();
    assert_eq!(s.phase, Phase::Off);
    assert!(!h.port.world().wanted && !h.port.world().owned, "the owner saw it fail: no autostart, nothing held");
    h.port.world().wanted = true;
    h.port.world().prepare.push_back(Some("Uplink unavailable".into()));
    assert!(h.enable(false).is_err());
    h.until("backoff", |s| s.phase == Phase::Backoff);
    assert!(h.port.world().wanted, "a boot restore keeps the owner's choice");
    h.until("retried", |s| s.phase == Phase::Running);
    let none = Harness::new(World::default());
    none.enable(false).unwrap();
    assert_eq!(none.snapshot().phase, Phase::Off, "nothing wanted: a restore does nothing");
}

/// Section 5.4: tighten before the core changes, follow what it reports,
/// reset only what lost DIRECT.
#[test]
fn a_group_switch_tightens_first_and_resets_what_lost_direct() {
    let h = Harness::new(World { selected_direct: true, ..World::default() });
    h.enable(true).unwrap();
    h.port.world().resets.clear();
    assert_eq!(h.write("G", "P").unwrap().0, 204);
    let events = h.events();
    let write = events.iter().find(|e| e.starts_with("write")).unwrap();
    assert_eq!(write, "write proxies/G with tables hold", "nothing skipped the core while the core changed");
    assert_eq!(h.port.world().tables.as_deref(), Some("full/0"));
    match h.port.world().resets.as_slice() {
        [Scope::Destinations(lost)] => assert_eq!(lost.iter().map(ToString::to_string).collect::<Vec<_>>(), ["1.2.3.0/24"]),
        other => panic!("{other:?}"),
    }
    assert_eq!(h.snapshot().bypass.unwrap().label(), "none");
    // Back to DIRECT: nothing lost, nothing reset; connections in the core go on.
    h.port.world().resets.clear();
    h.write("G", "DIRECT").unwrap();
    assert!(matches!(h.port.world().resets.as_slice(), [Scope::Destinations(d)] if d.is_empty()));
    // A tightening that cannot be confirmed changes nothing in the core.
    h.port.world().tables_fail.push_back("generation 9 is not confirmed".into());
    let before = h.port.world().writes.len();
    assert!(h.write("G", "P").unwrap_err().contains("narrowed"));
    assert_eq!(h.port.world().writes.len(), before);
}

/// Bridge writes during a restart are refused, not applied across generations.
#[test]
fn a_write_is_refused_unless_running() {
    let h = Harness::new(World::default());
    assert!(h.write("G", "P").unwrap_err().contains("restarting"));
}

#[test]
fn a_new_profile_that_fails_falls_back_to_the_previous_one_without_going_direct() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    h.port.world().prepare.push_back(Some("invalid profile".into()));
    let error = h.call(|reply| Message::Config { reply }).unwrap_err();
    assert!(error.contains("previous profile was started again"), "{error}");
    assert_eq!(h.snapshot().phase, Phase::Running);
    assert!(h.events().contains(&"prepare previous".to_owned()));
    assert!(!h.events().contains(&"direct".to_owned()));
    // Both fail: the planned restart failed finally, D3.
    h.port.world().prepare.extend([Some("invalid profile".into()), Some("previous broke too".into())]);
    assert!(h.call(|reply| Message::Config { reply }).is_err());
    h.until("backoff", |s| s.phase == Phase::Backoff);
}

/// Q1: after the agent restarted in the same boot, the owner's choice and
/// the previous tables are taken over without a direct window.
#[test]
fn an_agent_restart_adopts_the_interception_without_going_direct() {
    let h = Harness::new(World { wanted: true, adoptable: true, ..World::default() });
    h.tx.send(Message::Boot).unwrap();
    h.until("running", |s| s.phase == Phase::Running);
    let events = h.events();
    assert_eq!(&events[..3], ["engage Adopt", "tables hold", "prepare"]);
    assert!(!events.iter().any(|e| e == "recover" || e == "direct" || e == "tables guard"), "{events:?}");
    let other = Harness::new(World { wanted: false, adoptable: true, ..World::default() });
    other.tx.send(Message::Boot).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(other.events(), ["recover"], "not wanted: roll back");
}

#[test]
fn a_core_that_never_becomes_ready_is_stopped_and_a_turn_off_cancels_the_wait() {
    let h = Harness::new(World { unready: true, ..World::default() });
    assert!(h.enable(true).unwrap_err().contains("did not become ready"));
    assert_eq!(h.snapshot().phase, Phase::Off);
    let h = Harness::new(World { unready: true, wanted: true, ..World::default() });
    let (reply, answer) = mpsc::sync_channel(1);
    h.tx.send(Message::Enable { local: String::new(), owner: false, reply: Some(reply) }).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    h.call(|reply| Message::Disable { reply: Some(reply) }).unwrap();
    assert!(answer.recv_timeout(Duration::from_secs(2)).unwrap().unwrap_err().contains("Turned off"));
    assert_eq!(h.snapshot().phase, Phase::Off);
    assert!(!h.port.world().wanted);
}

#[test]
fn an_install_in_progress_defers_a_retry() {
    let h = Harness::new(World { wanted: true, busy: Some("A Mihomo operation is in progress".into()), ..World::default() });
    assert!(h.enable(false).is_err());
    let s = h.until("backoff", |s| s.phase == Phase::Backoff);
    assert!(s.error.unwrap().contains("in progress"));
    h.port.world().busy = None;
    h.until("started after", |s| s.phase == Phase::Running);
}

/// v3 (section 5.5): a DNS filter change reloads the same core, tightened
/// first; a reload that is not proven falls back to a planned restart.
#[test]
fn a_dns_filter_change_reloads_tightened_and_falls_back_to_a_restart() {
    let h = Harness::new(World { selected_direct: true, ..World::default() });
    h.enable(true).unwrap();
    h.port.world().dns = 1;
    h.call(|reply| Message::Bypass { reply }).unwrap();
    let events = h.events();
    assert!(events.contains(&"reload with tables hold".to_owned()), "nothing skipped the core during the reload: {events:?}");
    let s = h.snapshot();
    assert_eq!((s.phase, s.generation), (Phase::Running, 1), "the same core");
    assert_eq!(h.port.world().tables.as_deref(), Some("full/1"), "the bypass is back once proven");
    // A 204 the read-back does not prove: restart behind the interception.
    h.port.world().dns = 2;
    h.port.world().verify = Some("u60-reload-probe.invalid still answers as before the reload".into());
    h.call(|reply| Message::Bypass { reply }).unwrap();
    let s = h.snapshot();
    assert_eq!((s.phase, s.generation), (Phase::Running, 2), "a planned restart took over");
    // A timeout is unknown: the read-back decides, here that it applied.
    h.port.world().dns = 3;
    h.port.world().verify = None;
    h.port.world().reload = Some(Err("Mihomo did not answer the reload".into()));
    h.call(|reply| Message::Bypass { reply }).unwrap();
    assert_eq!(h.snapshot().generation, 2, "committed without a restart");
    // The same filter: only the kernel plan follows, no reload.
    let reloads = h.events().iter().filter(|e| e.starts_with("reload")).count();
    h.call(|reply| Message::Bypass { reply }).unwrap();
    assert_eq!(h.events().iter().filter(|e| e.starts_with("reload")).count(), reloads);
}
