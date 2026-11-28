//! The controller against a fake device: exits, retries, switches and
//! failures replayed with short timings (I6; release blocker 3).

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

struct FakeCore {
    generation: u64,
    alive: Arc<AtomicBool>,
    world: Arc<Mutex<World>>,
}

impl CoreHandle for FakeCore {
    fn generation(&self) -> u64 {
        self.generation
    }
    fn stop(&self) -> bool {
        let mut w = self.world.lock().unwrap();
        w.events.push(format!("stop {}", self.generation));
        let confirmed = w.stop_confirmed.pop_front().unwrap_or(true);
        if confirmed {
            self.alive.store(false, Ordering::SeqCst);
        }
        confirmed
    }
}

#[derive(Default)]
struct World {
    events: Vec<String>,
    validation: Option<Validation>,
    wanted: bool,
    mihomo: Option<Arc<super::super::Mihomo>>,
    adoptable: bool,
    /// Effects are held (`Port::owns`).
    owned: bool,
    steps: bool,
    /// What the kernel holds.
    tables: Option<String>,
    /// What `NftTables` would load on a reconcile (the last declared).
    target: Option<String>,
    /// Generation counters mirroring `NftTables`.
    table_gen: u64,
    table_target_gen: Option<u64>,
    table_confirmed_gen: Option<u64>,
    /// A previous agent's journal and tables are still in the kernel.
    leftover: bool,
    spawned: Vec<u64>,
    spawned_bindings: Vec<Binding>,
    /// Errors for the next `prepare` calls (`None`: succeed).
    prepare: VecDeque<Option<String>>,
    /// Results for the next table loads, whatever their shape.
    tables_fail: VecDeque<Option<String>>,
    /// Like `tables_fail`, but commits live kernel tables BEFORE returning `Err`
    /// (simulating a kernel commit whose readback timed out).
    tables_commit_then_fail: VecDeque<Option<String>>,
    /// Failures injected BEFORE updating `target`/`ts_target_*` (simulating a
    /// journal `write_ahead` failure inside `EffectSet::declare_with`).
    tables_reject_before_target: VecDeque<Option<String>>,
    /// Errors for the next loads of shapes starting with this name.
    shape_fail: Vec<(String, String)>,
    /// Errors for the next D3 withdrawals and rollbacks.
    direct_fail: VecDeque<String>,
    adopt_fail: Option<String>,
    release_fail: Option<String>,
    unready: bool,
    /// Cores that never become ready, by spawn order (then ready).
    unready_spawns: VecDeque<bool>,
    unready_now: bool,
    resets: Vec<Scope>,
    selected_direct: bool,
    port_direct: bool,
    writes: Vec<String>,
    write_results: VecDeque<Answered>,
    read_results: VecDeque<Option<bool>>,
    uplink: Uplink,
    egress_generation: u64,
    egress_on_full: Option<Uplink>,
    ts_exit_on_full: Option<TailscaleExitConfig>,
    uplink_sampled: Option<mpsc::SyncSender<Instant>>,
    busy: Option<String>,
    guard_due: bool,
    /// Panic in the next `engage` (a defect on the controller's thread).
    panic: bool,
    /// Changes the DNS filter a `prepare` gives (the bypass setting).
    dns: u32,
    bypass_off: bool,
    /// The configuration a `prepare` gives routes for (none: empty).
    config: Option<&'static str>,
    reload: Option<Result<u16, String>>,
    verify: Option<String>,
    running_configs: Vec<String>,
    /// The mode and log level the core reports (none: rule, info).
    runtime: Option<Value>,
    /// The mode and log level each `prepare` of the selected profile was given.
    given: Vec<Option<Value>>,
    /// Tailscale Strategy B Exit Node state for controller linkage tests.
    tailscale_exit: TailscaleExitConfig,
    ts_tables_active: bool,
    ts_tables_v4: bool,
    ts_tables_v6: bool,
    ts_target_v4: bool,
    ts_target_v6: bool,
    ts_resets: Vec<(bool, bool)>,
    ts_pending_reset: (bool, bool),
    ts_v4_reset_started: Option<Instant>,
    ts_reset_fail_v4: VecDeque<Option<String>>,
    ts_reset_fail_v6: VecDeque<Option<String>>,
    /// Per-call return values for `FakeCore::stop()` (`true` by default).
    stop_confirmed: VecDeque<bool>,
    state_notifications: usize,
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
        Chain { rules: vec!["ip daddr @ip_0 return".into()], sets: vec![("ip_0".into(), vec!["1.2.3.0/24".into()])], returns: 1, plain: vec![Some((true, vec!["1.2.3.0/24".into()]))], ..Chain::default() }
    } else {
        Chain::default()
    }
}

fn port_direct_chain() -> Chain {
    Chain {
        rules: vec!["th dport { 443 } return".into()],
        returns: 1,
        plain: vec![None],
        ..Chain::default()
    }
}

impl Port for FakePort {
    fn adoptable(&mut self) -> bool {
        self.world().adoptable
    }
    fn recover(&mut self) -> Result<(), String> {
        self.log("recover");
        let mut w = self.world();
        if let Some(error) = w.direct_fail.pop_front() {
            return Err(error);
        }
        w.leftover = false;
        w.tables = None;
        Ok(())
    }
    fn busy(&mut self) -> Option<String> {
        self.world().busy.clone()
    }
    fn prepare(&mut self, source: &Source, serving: bool, egress: Binding) -> Result<Prepared, String> {
        self.log(match (source, serving) {
            (Source::Previous(_), _) => "prepare previous",
            (Source::Reload(_), _) => "prepare reload",
            (Source::Refresh(_), _) => "prepare refresh",
            (_, true) => "prepare serving",
            _ => "prepare",
        });
        if let Some(Some(error)) = self.world().prepare.pop_front() {
            return Err(error);
        }
        if let Source::Selected { runtime, .. } = source {
            self.world().given.push(runtime.clone());
        }
        let dns = routing::DnsFilter { rules: vec![format!("filter {}", self.world().dns)], ..Default::default() };
        let routes = self.world().config.map_or_else(routing::Routes::default, |yaml| routing::Routes::from(&serde_yaml_ng::from_str::<serde_yaml_ng::Value>(yaml).unwrap()));
        if let Source::Previous(previous) = source {
            return Ok(Prepared { egress, ..(**previous).clone() });
        }
        let config = self.world().config.unwrap_or("profile: selected");
        let bypass = !self.world().bypass_off;
        let tailscale_sniffer = self.world().tailscale_exit.sniffer;
        let notice = super::super::geodata::bypass_notice(config, bypass);
        let text = if tailscale_sniffer {
            format!("{config}\nfilter: {}\nsniffer: {{enable: true}}\n", self.world().dns)
        } else {
            format!("{config}\nfilter: {}", self.world().dns)
        };
        Ok(Prepared { facts: super::super::reload::Facts::from(&serde_yaml_ng::from_str(&text).unwrap()), secret: "s".into(), local: "u60.home.arpa".into(), runtime: json!({"mode": "rule"}), routes, dns, bypass, tailscale_sniffer, notice, source: config.into(), config: text, egress })
    }
    fn validator(&self, _: &Prepared, _: bool) -> Option<Validation> { self.world().validation.take() }
    fn ports_free(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn owns(&mut self) -> bool {
        self.world().owned
    }
    /// As `DevicePort`: a fresh start claims names nothing holds, a start
    /// from D3 needs the effects it kept, an adoption takes the previous
    /// agent's.
    fn engage(&mut self, how: Engage) -> Result<(), String> {
        self.log(format!("engage {how:?}"));
        let mut w = self.world();
        if std::mem::take(&mut w.panic) {
            drop(w);
            panic!("a defect on the controller's thread");
        }
        match how {
            Engage::Fresh if w.owned || w.leftover => return Err("Mihomo's nftables tables are left from before; turn Mihomo off to clean them up".into()),
            Engage::FromBackoff if !w.owned => return Err("Mihomo owns nothing to start from".into()),
            Engage::Adopt => {
                if let Some(error) = w.adopt_fail.clone() {
                    return Err(error);
                }
                w.leftover = false;
            }
            _ => {}
        }
        w.owned = true;
        w.steps = true;
        Ok(())
    }
    /// As `NftTables`: a load that fails stays the target.
    fn tables(&mut self, shape: Shape) -> Result<(), String> {
        let name = match shape {
            Shape::Guard => "guard".to_owned(),
            Shape::Hold => "hold".to_owned(),
            Shape::Full(c) => format!("full/{}", c.returns),
            Shape::FakeReject => "reject".to_owned(),
        };
        self.log(format!("tables {name}"));
        let mut w = self.world();
        w.table_gen += 1;
        w.table_target_gen = Some(w.table_gen);
        w.target = Some(name.clone());
        if let Some(Some(error)) = w.tables_fail.pop_front() {
            return Err(error);
        }
        if let Some(at) = w.shape_fail.iter().position(|(prefix, _)| name.starts_with(prefix.as_str())) {
            return Err(w.shape_fail.remove(at).1);
        }
        w.tables = Some(name);
        w.table_confirmed_gen = w.table_target_gen;
        if matches!(shape, Shape::Full(_)) {
            if let Some(uplink) = w.egress_on_full.take() {
                w.uplink = uplink;
            }
            if let Some(ts_exit) = w.ts_exit_on_full.take() {
                w.tailscale_exit = ts_exit;
            }
        }
        Ok(())
    }
    fn tables_with_tailscale(&mut self, shape: Shape, ts: TailscaleExit) -> Result<(), String> {
        {
            let mut w = self.world();
            if let Some(Some(error)) = w.tables_reject_before_target.pop_front() {
                return Err(error);
            }
            let active = matches!(shape, Shape::Hold | Shape::Full(_));
            w.ts_target_v4 = active && ts.v4;
            w.ts_target_v6 = active && ts.v6;
        }
        let commit_fail = self.world().tables_commit_then_fail.pop_front().flatten();
        let res = self.tables(shape);
        if res.is_ok() || commit_fail.is_some() {
            let mut w = self.world();
            w.ts_tables_v4 = w.ts_target_v4;
            w.ts_tables_v6 = w.ts_target_v6;
            w.ts_tables_active = w.ts_tables_v4 || w.ts_tables_v6;
        }
        if let Some(err) = commit_fail {
            return Err(err);
        }
        res
    }
    fn tailscale_exit(&mut self) -> TailscaleExitConfig {
        self.world().tailscale_exit.clone()
    }
    fn plan_tailscale(&mut self, _: &routing::Routes, _: Mode, selected: &Selected, unsettled: &[String]) -> Chain {
        let direct = selected.get("G").is_some_and(|g| g == "DIRECT") && unsettled.is_empty();
        if direct && self.world().port_direct {
            port_direct_chain()
        } else {
            chain(direct)
        }
    }
    fn reset_tailscale(&mut self, _reason: &'static str, v4: bool, v6: bool) -> Result<(), String> {
        let mut w = self.world();
        let want_v4 = v4 || w.ts_pending_reset.0;
        let want_v6 = v6 || w.ts_pending_reset.1;
        if !want_v4 && !want_v6 {
            return Ok(());
        }
        w.ts_resets.push((want_v4, want_v6));
        let started = Instant::now();
        let fail_v4 = want_v4 && w.ts_reset_fail_v4.pop_front().flatten().is_some();
        let fail_v6 = want_v6 && w.ts_reset_fail_v6.pop_front().flatten().is_some();
        if want_v4 && !fail_v4 {
            w.ts_v4_reset_started = Some(started);
        }
        w.ts_pending_reset = (fail_v4, fail_v6);
        if fail_v4 || fail_v6 {
            Err("simulated marked conntrack failure".into())
        } else {
            Ok(())
        }
    }
    fn tailscale_reset_pending(&mut self) -> (bool, bool) {
        self.world().ts_pending_reset
    }
    fn tailscale_v4_reset_started(&mut self) -> Option<Instant> {
        self.world().ts_v4_reset_started
    }
    fn on_state_change(&mut self) {
        self.world().state_notifications += 1;
    }
    fn tables_status(&mut self) -> Value {
        json!(self.world().tables)
    }
    fn tables_target_generation(&mut self) -> Option<u64> {
        self.world().table_target_gen
    }
    fn direct(&mut self) -> Result<(), String> {
        self.log("direct");
        let mut w = self.world();
        if let Some(error) = w.direct_fail.pop_front() {
            if w.owned {
                w.table_gen += 1;
                w.table_target_gen = Some(w.table_gen);
                w.target = Some("reject".into());
            }
            return Err(error);
        }
        if w.owned {
            w.table_gen += 1;
            w.table_target_gen = Some(w.table_gen);
            w.table_confirmed_gen = w.table_target_gen;
            w.tables = Some("reject".into());
            w.target = w.tables.clone();
            w.ts_tables_active = false;
            w.ts_tables_v4 = false;
            w.ts_tables_v6 = false;
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
        w.target = None;
        w.table_target_gen = None;
        w.table_confirmed_gen = None;
        w.leftover = false;
        Ok(())
    }
    fn spawn(&mut self, generation: u64, prepared: &Prepared, _: Sender<Message>) -> Result<Box<dyn CoreHandle>, String> {
        self.log(format!("spawn {generation}"));
        let mut w = self.world();
        w.spawned.push(generation);
        w.spawned_bindings.push(prepared.egress.clone());
        w.running_configs.push(prepared.config.clone());
        w.unready_now = w.unready_spawns.pop_front().unwrap_or(false);
        Ok(Box::new(FakeCore { generation, alive: Arc::new(AtomicBool::new(true)), world: Arc::clone(&self.0) }))
    }
    fn ready(&mut self, _: &Prepared) -> bool {
        let w = self.world();
        !w.unready && !w.unready_now
    }
    fn verify_routing(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn read_back(&mut self, _: &str) -> Option<(Mode, Selected, Value)> {
        let mut world = self.world();
        let direct = world.read_results.pop_front().unwrap_or(Some(world.selected_direct))?;
        let runtime = world.runtime.clone().unwrap_or_else(|| json!({"mode": "rule", "log-level": "info"}));
        Some((Mode::Rule, [("G".to_owned(), if direct { "DIRECT" } else { "P" }.to_owned())].into(), runtime))
    }
    fn plan(&mut self, _: &routing::Routes, bypass: bool, _: Mode, selected: &Selected, unsettled: &[String]) -> (Bypass, Chain) {
        let direct = bypass && selected.get("G").is_some_and(|g| g == "DIRECT") && unsettled.is_empty();
        let chain = if direct && self.world().port_direct {
            port_direct_chain()
        } else {
            chain(direct)
        };
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
        if let Some(result) = w.write_results.pop_front() {
            return result;
        }
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
    fn uplink(&mut self, upstream: bool) -> Uplink {
        let world = self.world();
        if let Some(sampled) = &world.uplink_sampled {
            let _ = sampled.try_send(Instant::now());
        }
        let observed = world.uplink.clone();
        if upstream { observed } else { observed.with_upstream(None) }
    }
    fn egress_generation(&self) -> u64 {
        self.world().egress_generation
    }
    /// As `NftTables::reconcile`: the target is loaded.
    fn reconcile(&mut self) -> Guarded {
        self.log("reconcile");
        let mut w = self.world();
        if w.owned && (w.target != w.tables || w.ts_target_v4 != w.ts_tables_v4 || w.ts_target_v6 != w.ts_tables_v6) {
            w.tables = w.target.clone();
            w.ts_tables_v4 = w.ts_target_v4;
            w.ts_tables_v6 = w.ts_target_v6;
            w.ts_tables_active = w.ts_tables_v4 || w.ts_tables_v6;
            w.table_confirmed_gen = w.table_target_gen;
        }
        Guarded {
            result: Ok(()),
            confirmed: w.owned && w.target == w.tables,
            confirmed_generation: w.table_confirmed_gen,
        }
    }
    fn wanted(&mut self) -> bool {
        let world = self.world();
        world.mihomo.as_ref().map_or(world.wanted, |mihomo| mihomo.wants_restore())
    }
    fn set_wanted(&mut self, on: bool) -> Result<(), String> {
        let mut world = self.world();
        if let Some(mihomo) = &world.mihomo {
            return mihomo.set_wanted(on);
        }
        world.wanted = on;
        Ok(())
    }
    fn sources_changed(&mut self) -> bool {
        false
    }
    fn guard_due(&mut self) -> bool {
        self.world().guard_due
    }
    fn retry_reset(&mut self) {
        let pending = self.world().ts_pending_reset;
        if pending.0 || pending.1 {
            let _ = self.reset_tailscale("retry", false, false);
        }
    }
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

pub(in crate::mihomo) struct Harness {
    port: FakePort,
    tx: Sender<Message>,
    shared: Arc<Mutex<Snapshot>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Harness {
    fn new(world: World) -> Self {
        Self::with(world, timings())
    }

    pub(in crate::mihomo) fn for_mihomo(mihomo: &Arc<super::super::Mihomo>) -> Self {
        let world = World {
            mihomo: Some(Arc::clone(mihomo)),
            prepare: [Some("fixture rejected the start".into())].into(),
            ..World::default()
        };
        let harness = Self::with_snapshot(world, Timings::default(), Arc::clone(&mihomo.shared));
        harness.tx.send(Message::Boot).unwrap();
        *mihomo.commands.lock().unwrap() = Some(harness.tx.clone());
        harness
    }

    fn with(world: World, timings: Timings) -> Self {
        Self::with_snapshot(world, timings, Arc::new(Mutex::new(Snapshot::default())))
    }

    fn with_snapshot(world: World, timings: Timings, shared: Arc<Mutex<Snapshot>>) -> Self {
        let port = FakePort(Arc::new(Mutex::new(world)));
        let (tx, rx) = mpsc::channel();
        let controller = Controller::new(port.clone(), rx, tx.clone(), Arc::clone(&shared), timings);
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

    fn barrier(&self) {
        let (reply, answer) = mpsc::sync_channel(1);
        self.tx.send(Message::Barrier(reply)).unwrap();
        answer.recv_timeout(Duration::from_secs(5)).unwrap();
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

#[test]
fn an_egress_switch_during_validation_rebinds_before_spawn() {
    let relay = Uplink::sample("ath20", 9, "192.0.2.2", None);
    let cellular = Uplink::sample("rmnet_data0", 3, "10.1.0.2", None);
    for (next, rejected) in [(cellular.clone(), false), (relay.clone(), false), (cellular, true)] {
        let port = FakePort(Arc::new(Mutex::new(World { uplink: relay.clone(), ..World::default() })));
        let changing = port.clone();
        let entered = next.clone();
        port.world().validation = Some(Box::new(move || {
            let mut world = changing.world();
            world.uplink = entered;
            world.egress_generation += 1;
            if rejected { Err("the old egress failed validation".into()) } else { Ok(()) }
        }));
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let mut controller = Controller::new(port.clone(), rx, tx, Arc::clone(&shared), timings());

        controller.enable(String::new(), true).unwrap();

        let binding = Binding { uplink: next.clone(), generation: 1 };
        assert_eq!(port.world().spawned_bindings, [binding.clone()]);
        let run = controller.run.as_ref().unwrap();
        assert_eq!(run.prepared.egress, binding);
        assert_eq!(run.uplink, next);
        assert_eq!(shared.lock().unwrap().phase, Phase::Running);
    }
}

#[test]
fn an_unannounced_egress_switch_before_publication_discards_the_candidate() {
    let relay = Uplink::sample("ath20", 9, "192.0.2.2", None);
    let cellular = Uplink::sample("rmnet_data0", 3, "10.1.0.2", None);
    let port = FakePort(Arc::new(Mutex::new(World {
        uplink: relay.clone(),
        egress_on_full: Some(cellular.clone()),
        ..World::default()
    })));
    let (tx, rx) = mpsc::channel();
    let shared = Arc::new(Mutex::new(Snapshot::default()));
    let mut controller = Controller::new(port.clone(), rx, tx, Arc::clone(&shared), timings());

    controller.enable(String::new(), true).unwrap();

    let world = port.world();
    assert_eq!(world.spawned_bindings, [
        Binding { uplink: relay, generation: 0 },
        Binding { uplink: cellular.clone(), generation: 0 },
    ]);
    assert_eq!(world.events, [
        "engage Fresh", "tables guard", "prepare", "spawn 1", "tables hold", "tables full/0",
        "tables hold", "stop 1", "prepare previous", "spawn 2", "tables full/0",
    ]);
    let run = controller.run.as_ref().unwrap();
    assert_eq!(run.uplink, cellular);
    let snapshot = shared.lock().unwrap();
    assert_eq!((snapshot.phase, snapshot.generation), (Phase::Running, 2));
}

#[test]
fn a_restart_resets_lost_direct_from_stale_candidates_with_or_without_profile_fallback() {
    let relay = Uplink::sample("ath20", 9, "192.0.2.2", None);
    let cellular = Uplink::sample("rmnet_data0", 3, "10.1.0.2", None);
    for fallback in [false, true] {
        let h = Harness::new(World { uplink: relay.clone(), ..World::default() });
        h.enable(true).unwrap();
        {
            let mut world = h.port.world();
            world.config = Some("profile: replacement");
            world.egress_on_full = Some(cellular.clone());
            world.read_results = [Some(true), (!fallback).then_some(false), Some(false)].into();
        }
        let result = h.call(|reply| Message::Config { refresh: false, reply });
        if fallback {
            assert!(result.unwrap_err().contains("previous profile was started again"));
        } else {
            result.unwrap();
        }
        let snapshot = h.snapshot();
        assert_eq!(snapshot.phase, Phase::Running);
        assert_eq!(snapshot.generation, if fallback { 4 } else { 3 });
        let world = h.port.world();
        assert!(after(&world.events, "tables full/1", "stop 2"));
        assert!(world.running_configs.last().unwrap().starts_with(if fallback { "profile: selected" } else { "profile: replacement" }));
        assert_eq!(world.resets.last(), Some(&Scope::Destinations(vec!["1.2.3.0/24".parse().unwrap()])));
    }
}

#[test]
fn a_stale_candidate_keeps_serving_when_hold_cannot_be_confirmed() {
    let h = Harness::new(World { uplink: Uplink::sample("ath20", 9, "192.0.2.2", None), ..World::default() });
    h.enable(true).unwrap();
    {
        let mut world = h.port.world();
        world.egress_on_full = Some(Uplink::sample("rmnet_data0", 3, "10.1.0.2", None));
        world.read_results.push_back(Some(true));
        world.tables_fail = [None, None, Some("Hold did not read back".into())].into();
    }
    let error = h.call(|reply| Message::Config { refresh: false, reply }).unwrap_err();

    assert!(error.contains("Hold did not read back"));
    let snapshot = h.snapshot();
    assert_eq!((snapshot.phase, snapshot.generation), (Phase::Running, 2));
    assert_eq!(snapshot.error.as_deref(), Some(error.as_str()));
    assert_eq!(snapshot.bypass, Some(Bypass::Rules { returns: 1, cut: None }));
    let world = h.port.world();
    assert_eq!(world.tables.as_deref(), Some("full/1"));
    assert_eq!(world.target.as_deref(), Some("hold"));
    assert_eq!(world.spawned, [1, 2]);
    assert!(!world.events.iter().any(|e| matches!(e.as_str(), "stop 2" | "prepare previous" | "direct")));
}

#[test]
fn a_retained_core_still_resets_prestart_connections_on_fresh_start_and_d3_retry() {
    // Fresh start: Full installs, egress changes, Hold cannot be confirmed -> core stays running,
    // Hold error is preserved, and pre-start LAN IPv4 connections are still reset.
    let fresh = Harness::new(World {
        uplink: Uplink::sample("ath20", 9, "192.0.2.2", None),
        egress_on_full: Some(Uplink::sample("rmnet_data0", 3, "10.1.0.2", None)),
        tables_fail: [None, None, None, Some("Hold did not read back".into())].into(),
        ..World::default()
    });
    let error = fresh.enable(true).unwrap_err();
    assert!(error.contains("Hold did not read back"));
    let snapshot = fresh.snapshot();
    assert_eq!((snapshot.phase, snapshot.generation), (Phase::Running, 1));
    assert_eq!(snapshot.error.as_deref(), Some(error.as_str()));
    assert_eq!(fresh.port.world().resets, [Scope::Lan { v4: true, v6: false }]);

    // D3 backoff retry: same Hold rollback failure keeps the core, preserves the Hold error,
    // and resets both IPv4 and IPv6 LAN connections from the fail-open period.
    let retry = Harness::new(World { uplink: Uplink::sample("ath20", 9, "192.0.2.2", None), ..World::default() });
    retry.enable(true).unwrap();
    retry.tx.send(Message::Exited { generation: 1, how: "signal 9".into() }).unwrap();
    retry.until("backoff", |s| s.phase == Phase::Backoff);
    {
        let mut world = retry.port.world();
        world.resets.clear();
        world.egress_on_full = Some(Uplink::sample("rmnet_data0", 3, "10.1.0.2", None));
        world.tables_fail = [None, None, Some("Hold did not read back".into())].into();
    }
    let error = retry.call(|reply| Message::Config { refresh: false, reply }).unwrap_err();
    assert!(error.contains("Hold did not read back"));
    let snapshot = retry.snapshot();
    assert_eq!((snapshot.phase, snapshot.generation), (Phase::Running, 2));
    assert_eq!(snapshot.error.as_deref(), Some(error.as_str()));
    assert_eq!(retry.port.world().resets, [Scope::Lan { v4: true, v6: true }]);
}

#[test]
fn a_periodic_route_audit_follows_relay_changes_without_notifications() {
    let relay = |index, gateway| Uplink::sample_with_gateway("ath20", index, "192.0.2.2", None, Some(gateway));
    let initial = relay(9, "192.0.2.1").with_upstream(Some("c0:a4:76:b1:f0:e4"));
    let cellular = Uplink::sample("rmnet_data0", 3, "10.1.0.2", None);
    for (next, expected_generation) in [
        (initial.clone(), 1),
        (relay(9, "192.0.2.254"), 2),
        (relay(10, "192.0.2.1"), 2),
        (initial.clone().with_upstream(Some("c0:a4:76:b1:f0:e5")), 2),
        (cellular, 2),
    ] {
        let port = FakePort(Arc::new(Mutex::new(World { uplink: initial.clone(), ..World::default() })));
        let (tx, rx) = mpsc::channel();
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let mut controller = Controller::new(port.clone(), rx, tx, Arc::clone(&shared), timings());
        controller.enable(String::new(), true).unwrap();
        port.world().uplink = next.clone();
        controller.timings.audit = Duration::ZERO;

        controller.tick();
        let run = controller.run.as_mut().unwrap();
        assert_eq!(run.core.generation(), 1);
        assert_eq!(run.stranding.is_some(), expected_generation == 2);
        if let Some((_, since)) = &mut run.stranding {
            *since -= egress::EGRESS_SETTLE;
        }
        controller.tick();

        let snapshot = shared.lock().unwrap();
        assert_eq!((snapshot.phase, snapshot.generation), (Phase::Running, expected_generation));
        assert_eq!(controller.run.as_ref().unwrap().prepared.egress.uplink, next);
    }
}

#[test]
fn frequent_mailbox_messages_do_not_postpone_the_route_audit() {
    let timings = Timings { tick: Duration::from_millis(120), audit: Duration::from_millis(180), ..timings() };
    let h = Harness::with(World::default(), timings);
    h.enable(true).unwrap();
    let started = Instant::now();
    let (sampled, observation) = mpsc::sync_channel(1);
    h.port.world().uplink_sampled = Some(sampled);
    let (finish, finished) = mpsc::channel();
    let tx = h.tx.clone();
    let traffic = std::thread::spawn(move || {
        while let Err(RecvTimeoutError::Timeout) = finished.recv_timeout(Duration::from_millis(5)) {
            tx.send(Message::Guard).unwrap();
        }
    });

    let audited = observation.recv_timeout(Duration::from_millis(600));
    finish.send(()).unwrap();
    traffic.join().unwrap();
    assert!(audited.expect("audit during continuous mailbox activity").duration_since(started) < Duration::from_millis(600));
}

/// Release blocker 3: an old generation's exit, arriving after the new core
/// is ready, changes nothing.
#[test]
fn an_old_cores_late_exit_cannot_touch_the_new_one() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    // The relay brought up an uplink the core was started without: a
    // planned restart to generation 2.
    h.port.world().uplink = Uplink::sample("ath20", 9, "192.0.2.2", None);
    h.tx.send(Message::Egress).unwrap();
    let s = h.until("generation 2", |s| s.generation == 2 && s.phase == Phase::Running);
    let events = h.events();
    assert!(after(&events, "tables hold", "spawn 2"), "interception held before the old core stopped: {events:?}");
    h.tx.send(Message::Exited { generation: 1, how: "signal 15".into() }).unwrap();
    h.barrier();
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
    let h = Harness::new(World { uplink: Uplink::sample("ath20", 9, "192.168.2.124", Some("2409:8a00::5")), ..World::default() });
    h.enable(true).unwrap();
    h.port.world().uplink = Uplink::default();
    h.tx.send(Message::Egress).unwrap();
    h.barrier();
    assert_eq!(h.snapshot().generation, 1, "no egress: nothing to restart onto");
    h.port.world().uplink = Uplink::sample("ath20", 10, "192.168.2.124", None);
    h.tx.send(Message::Egress).unwrap();
    h.until("generation 2", |s| s.generation == 2 && s.phase == Phase::Running);
    h.port.world().uplink = Uplink::sample("ath20", 10, "192.168.2.124", Some("2409:8a00::5"));
    h.tx.send(Message::Egress).unwrap();
    h.barrier();
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
    h.barrier();
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
    h.port.world().tables_fail.push_back(Some("generation 9 is not confirmed".into()));
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
    // It does not validate: the running core never stopped.
    h.port.world().prepare.push_back(Some("invalid profile".into()));
    let before = h.events().len();
    let error = h.call(|reply| Message::Config { refresh: false, reply }).unwrap_err();
    assert!(error.contains("running profile keeps serving"), "{error}");
    let s = h.snapshot();
    assert_eq!((s.phase, s.generation), (Phase::Running, 1));
    assert_eq!(h.events()[before..], ["prepare serving"], "nothing held, nothing stopped");
    // It validates but does not start: the previous one starts again.
    h.port.world().unready_spawns.push_back(true);
    let error = h.call(|reply| Message::Config { refresh: false, reply }).unwrap_err();
    assert!(error.contains("previous profile was started again"), "{error}");
    assert_eq!(h.snapshot().phase, Phase::Running);
    assert!(h.events().contains(&"prepare previous".to_owned()));
    assert!(!h.events().contains(&"direct".to_owned()));
    // Both fail: the planned restart failed finally, D3.
    h.port.world().unready_spawns.push_back(true);
    h.port.world().prepare.extend([None, Some("previous broke too".into())]);
    assert!(h.call(|reply| Message::Config { refresh: false, reply }).is_err());
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
    other.barrier();
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

#[test]
fn a_follow_uses_the_running_bypass_setting_until_reload_commits() {
    let h = Harness::new(World { selected_direct: true, ..World::default() });
    h.enable(true).unwrap();
    h.port.world().bypass_off = true;
    h.write("G", "DIRECT").unwrap();
    assert_eq!(h.port.world().tables.as_deref(), Some("full/1"));
}

#[test]
fn missing_geodata_mode_is_reported_without_changing_the_core_database() {
    let h = Harness::new(World { config: Some("rules: ['GEOIP,CN,DIRECT', 'MATCH,REJECT']"), ..World::default() });
    h.enable(true).unwrap();
    assert!(h.snapshot().notice.unwrap().contains("geodata-mode"));
}

#[test]
fn a_subscription_refresh_reloads_once_without_stopping_the_core() {
    let h = Harness::new(World { selected_direct: true, ..World::default() });
    h.enable(true).unwrap();
    let before = h.events().len();
    h.port.world().config = Some("rules: ['MATCH,G']");
    h.call(|reply| Message::Config { refresh: true, reply }).unwrap();
    assert_eq!(h.snapshot().generation, 1);
    assert_eq!(&h.events()[before..], ["prepare refresh", "tables hold", "reload with tables hold", "tables full/1"]);
    h.port.world().config = Some("tproxy-port: 9999");
    h.call(|reply| Message::Config { refresh: true, reply }).unwrap();
    assert_eq!(h.snapshot().generation, 2);
    assert_eq!(h.events().iter().filter(|event| *event == "prepare refresh").count(), 2);
}

#[test]
fn a_rejected_refresh_keeps_serving_and_a_failed_reload_reuses_validation_for_restart() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    h.port.world().prepare.push_back(Some("validation failed".into()));
    assert!(h.call(|reply| Message::Config { refresh: true, reply }).is_err());
    assert_eq!(h.snapshot().generation, 1);
    assert!(!h.events().iter().any(|event| event.starts_with("stop")));
    h.port.world().reload = Some(Ok(400));
    h.call(|reply| Message::Config { refresh: true, reply }).unwrap();
    assert_eq!(h.snapshot().generation, 2);
    assert_eq!(h.events().iter().filter(|event| *event == "prepare refresh").count(), 2);
    assert_eq!(h.events().iter().filter(|event| *event == "prepare serving").count(), 0);
    h.port.world().unready_spawns.push_back(true);
    let error = h.call(|reply| Message::Config { refresh: true, reply }).unwrap_err();
    assert!(error.contains("previous profile was started again"));
    assert_eq!(h.snapshot().phase, Phase::Running);
    assert!(!h.events().iter().any(|event| event == "direct"));
}

#[test]
fn an_unknown_subscription_reload_restarts_instead_of_accepting_the_old_rules() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    h.port.world().config = Some("rules: ['MATCH,REJECT']");
    h.port.world().reload = Some(Err("timeout".into()));
    h.call(|reply| Message::Config { refresh: true, reply }).unwrap();
    assert_eq!(h.snapshot().generation, 2);
}

#[test]
fn a_failed_change_after_a_hot_reload_falls_back_to_the_hot_reloaded_config() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    h.port.world().config = Some("rules: ['MATCH,G']");
    h.call(|reply| Message::Config { refresh: true, reply }).unwrap();
    h.port.world().config = Some("rules: ['MATCH,REJECT']");
    h.port.world().reload = Some(Ok(400));
    h.port.world().unready_spawns.push_back(true);
    assert!(h.call(|reply| Message::Config { refresh: true, reply }).is_err());
    assert_eq!(h.port.world().running_configs.last().unwrap(), "rules: ['MATCH,G']\nfilter: 0");
}

/// D2 with a first wait long enough that only an early retry can start it.
fn slow_retries() -> Timings {
    Timings { retries: vec![Duration::from_secs(30)], ..timings() }
}

/// Finding 2, first case: a boot restore that failed before it held
/// anything (an install in progress) retries by claiming the effects
/// afresh, and keeps its own error meanwhile.
#[test]
fn a_retry_from_backoff_starts_fresh_when_nothing_is_held() {
    let h = Harness::new(World { wanted: true, busy: Some("A Mihomo operation is in progress".into()), ..World::default() });
    assert!(h.enable(false).is_err());
    h.until("backoff", |s| s.phase == Phase::Backoff);
    assert!(!h.port.world().owned);
    std::thread::sleep(Duration::from_millis(150));
    let error = h.snapshot().error.unwrap();
    assert!(error.contains("in progress"), "the original error, not a missing journal: {error}");
    h.port.world().busy = None;
    h.until("started", |s| s.phase == Phase::Running);
    let events = h.events();
    assert!(events.contains(&"engage Fresh".to_owned()) && !events.contains(&"engage FromBackoff".to_owned()), "{events:?}");
    assert_eq!(h.port.world().tables.as_deref(), Some("full/0"));
}

/// Finding 2, second case: an adoption that fails before it took the
/// previous agent's effects leaves that agent's tables (DNS redirected to a
/// core that is gone). They are rolled back before the status says direct;
/// a rollback that fails is CleanupPending and retried; the retry then
/// claims the effects afresh.
#[test]
fn a_failed_adoption_rolls_the_old_tables_back_before_going_direct() {
    let world = World { wanted: true, adoptable: true, leftover: true, tables: Some("full/1".into()), adopt_fail: Some("Network cleanup paused: rule busy".into()), ..World::default() };
    let h = Harness::with(world, slow_retries());
    h.tx.send(Message::Boot).unwrap();
    let s = h.until("backoff", |s| s.phase == Phase::Backoff);
    assert!(s.error.unwrap().contains("did not come back"));
    {
        let w = h.port.world();
        assert!(!w.leftover && w.tables.is_none(), "the old tables are gone: LAN DNS works");
    }
    h.port.world().adopt_fail = None;
    h.enable(false).unwrap();
    assert_eq!(h.snapshot().phase, Phase::Running);
    assert!(h.events().contains(&"engage Fresh".to_owned()));
    // The rollback itself fails: not "direct" while the old tables stay.
    let world = World { wanted: true, adoptable: true, leftover: true, tables: Some("full/1".into()), adopt_fail: Some("busy".into()), direct_fail: ["Network cleanup paused: rule busy".to_owned()].into(), ..World::default() };
    let h = Harness::new(world);
    h.tx.send(Message::Boot).unwrap();
    let s = h.until("cleanup pending", |s| s.phase == Phase::CleanupPending);
    assert!(s.error.unwrap().contains("could not be withdrawn"));
    assert!(h.port.world().leftover);
    h.port.world().adopt_fail = None;
    h.until("rolled back and started", |s| s.phase == Phase::Running);
    assert!(!h.port.world().leftover);
}

/// Finding 3: the fake-ip reject table that withdraws interception after a
/// core exit does not load. The state says the cleanup is pending (not
/// "direct") and the withdrawal is retried on the D2 timers until it works;
/// then the core starts again.
#[test]
fn a_failed_withdrawal_is_retried_until_it_works() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    h.port.world().direct_fail.extend(["nftables did not load generation 4: Device tool timed out".to_owned(), "generation 5 is not confirmed".to_owned()]);
    h.tx.send(Message::Exited { generation: 1, how: "signal 9".into() }).unwrap();
    let s = h.until("cleanup pending", |s| s.phase == Phase::CleanupPending);
    let error = s.error.unwrap();
    assert!(error.contains("signal 9") && error.contains("could not be withdrawn"), "{error}");
    assert!(s.retry_at.is_some(), "retried on the D2 timers");
    h.until("withdrawn and started again", |s| s.phase == Phase::Running && s.generation == 2);
    let events = h.events();
    assert_eq!(events.iter().filter(|e| *e == "direct").count(), 3, "{events:?}");
    assert!(after(&events, "direct", "engage FromBackoff"));
}

/// Finding 1, first case: a plan that did not load may still be loaded by a
/// reconcile, so the next switch tightens first and resets what it let
/// through.
#[test]
fn a_plan_that_did_not_load_is_tightened_before_the_next_switch() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    h.port.world().shape_fail.push(("full".into(), "generation 3 is not confirmed".into()));
    h.write("G", "DIRECT").unwrap();
    {
        let w = h.port.world();
        assert_eq!((w.tables.as_deref(), w.target.as_deref()), (Some("full/0"), Some("full/1")), "the plan is the target, not loaded");
    }
    h.port.world().resets.clear();
    h.write("G", "P").unwrap();
    let events = h.events();
    assert_eq!(events.iter().rfind(|e| e.starts_with("write")).unwrap(), "write proxies/G with tables hold", "{events:?}");
    let resets = h.port.world().resets.clone();
    match resets.as_slice() {
        [Scope::Destinations(lost)] => assert_eq!(lost.iter().map(ToString::to_string).collect::<Vec<_>>(), ["1.2.3.0/24"]),
        other => panic!("{other:?}"),
    }
}

/// Finding 1, the same once a reconcile loaded it: the status follows the
/// kernel, and the next switch tightens first.
#[test]
fn a_plan_a_reconcile_loads_later_is_shown_and_tightened_before_the_next_switch() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    h.port.world().shape_fail.push(("full".into(), "generation 3 is not confirmed".into()));
    h.write("G", "DIRECT").unwrap();
    assert_eq!(h.snapshot().bypass.unwrap().label(), "none");
    h.port.world().guard_due = true;
    h.tx.send(Message::Guard).unwrap();
    h.until("the late table shown", |s| s.bypass.as_ref().is_some_and(|b| b.label() == "rules"));
    h.port.world().guard_due = false;
    assert_eq!(h.port.world().tables.as_deref(), Some("full/1"));
    h.port.world().resets.clear();
    h.write("G", "P").unwrap();
    let events = h.events();
    assert_eq!(events.iter().rfind(|e| e.starts_with("write")).unwrap(), "write proxies/G with tables hold", "{events:?}");
    assert!(matches!(h.port.world().resets.as_slice(), [Scope::Destinations(lost)] if lost.len() == 1));
}

/// Finding 1, mirror case: a narrowing that did not load, which a reconcile
/// loads later, turns the bypass off in the kernel. The status says so, and
/// the plan the core still runs is loaded again once it is read back.
#[test]
fn a_narrowing_a_reconcile_loads_later_is_shown_and_widened_again() {
    let h = Harness::new(World { selected_direct: true, ..World::default() });
    h.enable(true).unwrap();
    h.port.world().tables_fail.push_back(Some("generation 3 is not confirmed".into()));
    assert!(h.write("G", "P").unwrap_err().contains("narrowed"));
    assert_eq!(h.snapshot().bypass.unwrap().label(), "rules", "the kernel still holds the plan");
    let writes = h.port.world().writes.len();
    // The check loads the narrowing; loading the plan again fails once.
    h.port.world().shape_fail.push(("full".into(), "generation 4 is not confirmed".into()));
    h.port.world().guard_due = true;
    h.tx.send(Message::Guard).unwrap();
    h.until("the narrowing shown", |s| s.bypass.as_ref().is_some_and(|b| b.label() == "none"));
    assert!(h.events().contains(&"tables hold".to_owned()));
    // A later check loads the plan of the core, which never changed.
    h.until("the plan back", |s| s.bypass.as_ref().is_some_and(|b| b.label() == "rules"));
    h.port.world().guard_due = false;
    assert_eq!(h.port.world().tables.as_deref(), Some("full/1"));
    assert_eq!(h.port.world().writes.len(), writes, "nothing was written to the core");
}

/// Finding 5: the boot restore, sent once the router and the relay are
/// back, retries a core in D3 at once instead of at its next step.
#[test]
fn a_boot_restore_in_backoff_retries_now() {
    let h = Harness::with(World { wanted: true, busy: Some("A Mihomo operation is in progress".into()), ..World::default() }, slow_retries());
    assert!(h.enable(false).is_err());
    assert_eq!(h.snapshot().phase, Phase::Backoff);
    h.port.world().busy = None;
    h.enable(false).unwrap();
    assert_eq!(h.snapshot().phase, Phase::Running, "not at the next step, 30 s later");
}

/// Finding 5: an IPv4 egress that appears in D3 retries at once; the same
/// egress again does not.
#[test]
fn a_new_ipv4_egress_in_backoff_retries_now() {
    let h = Harness::with(World { wanted: true, ..World::default() }, slow_retries());
    h.port.world().prepare.push_back(Some("Mihomo validation timed out".into()));
    assert!(h.enable(false).is_err());
    assert_eq!(h.snapshot().phase, Phase::Backoff);
    h.tx.send(Message::Egress).unwrap();
    h.barrier();
    assert_eq!(h.snapshot().phase, Phase::Backoff, "no new egress: the timer decides");
    h.port.world().uplink = Uplink::sample("ath20", 9, "192.0.2.2", None);
    h.tx.send(Message::Egress).unwrap();
    h.until("started on the new egress", |s| s.phase == Phase::Running);
}

/// Finding 8: a panic on the controller's thread ends the agent (`end`)
/// rather than leaving the tables, a dead core and a `running` snapshot.
#[test]
fn a_panic_on_the_controller_thread_ends_the_agent() {
    let port = FakePort(Arc::new(Mutex::new(World { panic: true, ..World::default() })));
    let (tx, rx) = mpsc::channel();
    let controller = Controller::new(port, rx, tx.clone(), Arc::new(Mutex::new(Snapshot::default())), timings());
    let (ended, why) = mpsc::channel();
    let thread = std::thread::spawn(move || controller.supervised(move |what| ended.send(what).unwrap()));
    tx.send(Message::Enable { local: String::new(), owner: true, reply: None }).unwrap();
    assert!(why.recv_timeout(Duration::from_secs(5)).unwrap().contains("defect"));
    thread.join().unwrap();
}

/// Finding 4: a planned restart prepares and validates while the old core
/// serves (in the background for a profile change); the hold table goes in
/// and the old core stops only then.
#[test]
fn a_planned_restart_prepares_before_it_holds_and_stops_the_old_core() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    h.call(|reply| Message::Config { refresh: false, reply }).unwrap();
    let events = h.events();
    let at = |e: &str| events.iter().rposition(|x| x == e).unwrap_or_else(|| panic!("{e}: {events:?}"));
    assert!(at("prepare serving") < at("tables hold") && at("tables hold") < at("stop 1") && at("stop 1") < at("spawn 2"), "{events:?}");
    h.port.world().uplink = Uplink::sample("ath20", 9, "192.0.2.2", None);
    h.tx.send(Message::Egress).unwrap();
    h.until("generation 3", |s| s.generation == 3 && s.phase == Phase::Running);
    let events = h.events();
    let at = |e: &str| events.iter().rposition(|x| x == e).unwrap();
    assert!(at("prepare") < at("tables hold") && at("tables hold") < at("stop 2"), "{events:?}");
}

/// A mode or log level set through the controller is what the next planned
/// restart starts the core with: a profile edit does not put them back.
#[test]
fn a_planned_restart_keeps_the_mode_and_log_level_the_core_reported() {
    let h = Harness::new(World::default());
    h.enable(true).unwrap();
    let set = json!({"mode": "global", "log-level": "debug"});
    h.port.world().runtime = Some(set.clone());
    h.write("G", "P").unwrap();
    h.call(|reply| Message::Config { refresh: false, reply }).unwrap();
    assert_eq!(h.port.world().given.last(), Some(&Some(set)));
}

/// Finding 6: refreshing a `domain` rule set changes no kernel plan, so no
/// table is loaded around it; a set the kernel reads is still treated as
/// unknown while it refreshes.
#[test]
fn a_domain_rule_set_refresh_loads_no_table() {
    let config = "rule-providers:\n  names: {type: http, behavior: domain, url: 'https://example.invalid/a', interval: 3600}\n  cidrs: {type: http, behavior: ipcidr, url: 'https://example.invalid/b', interval: 3600}\nrules: ['MATCH,G']";
    let h = Harness::new(World { selected_direct: true, config: Some(config), ..World::default() });
    h.enable(true).unwrap();
    let refresh = |name: &str| {
        let (tx, rx) = mpsc::sync_channel(1);
        h.tx.send(Message::Write { write: Write { method: "PUT", segments: vec!["providers".into(), "rules".into(), name.into()], body: json!({}) }, answer: Answer::Sync(tx) }).unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap()
    };
    let before = h.events().len();
    refresh("names");
    assert_eq!(h.events()[before..], ["write providers/rules/names with tables full/1"]);
    let before = h.events().len();
    refresh("cidrs");
    assert_eq!(h.events()[before..], ["tables full/0", "write providers/rules/cidrs with tables full/0", "tables full/1"]);
}

#[test]
fn exit_while_validating_withdraws_now_and_discards_the_candidate() {
    let h = Harness::with(World::default(), slow_retries());
    h.enable(true).unwrap();
    let generation = h.snapshot().generation;
    let (started, waiting) = mpsc::sync_channel(1);
    let (finish, done) = mpsc::sync_channel(1);
    h.port.world().validation = Some(Box::new(move || { started.send(()).unwrap(); done.recv_timeout(Duration::from_secs(5)).unwrap(); Ok(()) }));
    let (reply, result) = mpsc::sync_channel(1);
    h.tx.send(Message::Config { refresh: true, reply }).unwrap();
    waiting.recv_timeout(Duration::from_secs(2)).unwrap();
    h.tx.send(Message::Exited { generation, how: "fixture".into() }).unwrap();
    h.until("D3 during validation", |s| s.phase == Phase::Backoff);
    finish.send(()).unwrap();
    assert!(result.recv_timeout(Duration::from_secs(2)).unwrap().is_err());
    assert_eq!(h.port.world().spawned, [generation]);
}

#[test]
fn routing_write_waits_in_hold_for_readback_then_resets_only_lost_direct() {
    for result in [Ok((204, Vec::new())), Err("Mihomo did not answer".into())] {
        let port = FakePort(Arc::new(Mutex::new(World { selected_direct: true, ..World::default() })));
        let mut controller = direct_controller(&port);
        {
            let mut world = port.world();
            world.resets.clear();
            world.events.clear();
            world.write_results.push_back(result.clone());
            world.read_results.extend([None, Some(false)]);
        }
        assert_eq!(controller.write(&select_proxy()), result);
        {
            let world = port.world();
            assert_eq!(world.tables.as_deref(), Some("hold"));
            assert!(world.resets.is_empty());
        }
        controller.tick();
        controller.tick();
        let world = port.world();
        assert_eq!(world.events, ["tables hold", "write proxies/G with tables hold", "tables full/0"]);
        assert_eq!(world.writes, ["proxies/G"]);
        assert_eq!(world.resets, [Scope::Destinations(vec!["1.2.3.0/24".parse().unwrap()])]);
        assert_eq!(world.tables.as_deref(), Some("full/0"));
    }
}

#[test]
fn refused_routing_write_returns_the_core_reply_and_restores_the_old_plan() {
    let port = FakePort(Arc::new(Mutex::new(World { selected_direct: true, ..World::default() })));
    let mut controller = direct_controller(&port);
    let denied = Ok((400, br#"{"message":"Unknown proxy"}"#.to_vec()));
    {
        let mut world = port.world();
        world.resets.clear();
        world.events.clear();
        world.write_results.push_back(denied.clone());
        world.read_results.push_back(Some(true));
    }
    assert_eq!(controller.write(&select_proxy()), denied);
    let world = port.world();
    assert_eq!(world.events, ["tables hold", "write proxies/G with tables hold", "tables full/1"]);
    assert_eq!(world.tables.as_deref(), Some("full/1"));
    assert_eq!(world.resets, [Scope::Destinations(Vec::new())]);
}

fn direct_controller(port: &FakePort) -> Controller<FakePort> {
    let (tx, rx) = mpsc::channel();
    let mut controller = Controller::new(port.clone(), rx, tx, Arc::new(Mutex::new(Snapshot::default())), timings());
    controller.enable("u60.home.arpa".into(), true).unwrap();
    controller
}

fn select_proxy() -> Write {
    Write { method: "PUT", segments: vec!["proxies".into(), "G".into()], body: json!({"name": "P"}) }
}

fn select_direct() -> Write {
    Write { method: "PUT", segments: vec!["proxies".into(), "G".into()], body: json!({"name": "DIRECT"}) }
}

#[test]
fn tailscale_exit_d3_backoff_withdraws_tproxy_and_recovery_reengages_with_notifications() {
    let port = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        ..World::default()
    })));
    let mut controller = direct_controller(&port);
    assert!(!port.world().ts_tables_active);
    let initial_notes = port.world().state_notifications;

    // 1. Enabling `exit_via_mihomo` (`sniffer` + `tproxy_v4`) hot-reloads Mihomo,
    //    engages `tailscale0` TPROXY, resets stale direct tailscale conntrack flows,
    //    and notifies observers.
    port.world().tailscale_exit = TailscaleExitConfig {
        sniffer: true,
        tproxy_v4: true,
        tproxy_v6: false,
        skip_v4: vec!["192.168.0.0/24".into()],
        skip_v6: Vec::new(),
    };
    controller.handle(Message::TailscaleExit);
    {
        let w = port.world();
        assert!(w.ts_tables_active, "tailscale0 TPROXY must engage when exit_via_mihomo is active");
        assert_eq!(w.ts_resets, vec![(true, false)]);
        assert!(w.state_notifications > initial_notes);
    }

    // 2. Core exit triggers D3 backoff (`Shape::FakeReject`): `tailscale0` TPROXY
    //    is withdrawn so Exit traffic falls back to kernel FORWARD + direct DoH.
    let before_fail_notes = port.world().state_notifications;
    let gen = controller.generation;
    controller.handle(Message::Exited { generation: gen, how: "crashed".into() });
    assert_eq!(controller.phase, Phase::Backoff);
    {
        let w = port.world();
        assert!(!w.ts_tables_active, "D3 backoff must withdraw tailscale0 TPROXY");
        assert!(w.state_notifications > before_fail_notes, "D3 transition must notify Clean DNS");
    }

    // 3. Recovery retry brings Mihomo back to `Running`: `tailscale0` TPROXY
    //    automatically re-engages and evicts fallback direct flows.
    let before_recover_notes = port.world().state_notifications;
    controller.retry(Some("test recovery")).unwrap();
    assert_eq!(controller.phase, Phase::Running);
    {
        let w = port.world();
        assert!(w.ts_tables_active, "recovery from D3 must automatically re-engage tailscale0 TPROXY");
        assert_eq!(w.ts_resets, vec![(true, false), (true, false)]);
        assert!(w.state_notifications > before_recover_notes, "recovery must notify Clean DNS");
    }
}

#[test]
fn revoked_tailscale_exit_family_withdraws_without_core_readback_and_retries_table_error() {
    let port = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: true,
            skip_v4: vec!["192.168.0.0/24".into()],
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut controller = direct_controller(&port);
    assert!(port.world().ts_tables_v4);
    assert!(port.world().ts_tables_v6);

    // Revoke IPv4 exit while keeping sniffer=true and IPv6 exit active, AND
    // simulate BOTH a transient core read_back outage and a transient nftables error.
    {
        let mut w = port.world();
        w.tailscale_exit.tproxy_v4 = false;
        w.read_results.extend([None, None, None]);
        w.tables_fail.push_back(Some("transient nft busy".into()));
    }
    controller.handle(Message::TailscaleExit);
    assert!(port.world().ts_tables_v4, "first attempt failed nftables; must stay dirty");

    // Next tick retries kernel withdrawal WITHOUT needing core read_back!
    controller.tick();
    {
        let w = port.world();
        assert!(!w.ts_tables_v4, "revoked IPv4 family must be withdrawn even while read_back fails");
        assert!(w.ts_tables_v6, "still-approved IPv6 family remains active");
    }

    // Now revoke IPv6 too while read_back is still failing -> immediate withdrawal.
    {
        let mut w = port.world();
        w.tailscale_exit.tproxy_v6 = false;
        w.read_results.push_back(None);
    }
    controller.handle(Message::TailscaleExit);
    assert!(!port.world().ts_tables_active);
}

#[test]
fn d3_retains_stopping_core_and_interception_until_exit_is_confirmed() {
    let port = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut controller = direct_controller(&port);
    let gen = controller.generation;
    assert!(port.world().ts_tables_active);

    // Trigger an egress restart whose prepare() fails while the old core's stop()
    // returns false (exit not confirmed yet).
    {
        let mut w = port.world();
        w.uplink = Uplink::sample("ath20", 9, "192.0.2.2", None);
        w.prepare.push_back(Some("prepare failed during egress switch".into()));
        w.stop_confirmed.push_back(false);
        w.stop_confirmed.push_back(false);
    }
    controller.handle(Message::Egress);
    assert_eq!(controller.phase, Phase::CleanupPending);
    assert!(controller.stopping_core.is_some(), "unconfirmed core handle must be retained");
    assert!(port.world().ts_tables_active, "interception must stay in place until exit is confirmed");
    assert_ne!(port.world().tables.as_deref(), Some("reject"));

    // A D2 retry while stop() still returns false keeps CleanupPending and does not withdraw.
    assert!(controller.retry(Some("retry while still alive")).is_err());
    assert_eq!(controller.phase, Phase::CleanupPending);
    assert!(port.world().ts_tables_active);
    assert_eq!(port.world().spawned, vec![gen]);

    // Once the reaper reports Exited for that generation, D3 withdraws interception cleanly.
    controller.handle(Message::Exited { generation: gen, how: "signal 9".into() });
    assert_eq!(controller.phase, Phase::Backoff);
    assert!(controller.stopping_core.is_none());
    assert!(!port.world().ts_tables_active);
    assert_eq!(port.world().tables.as_deref(), Some("reject"));
}

#[test]
fn timed_out_sniffer_reload_restarts_core_and_failed_ts_reset_retries_on_tick() {
    let port = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        ..World::default()
    })));
    let mut controller = direct_controller(&port);
    let gen1 = controller.generation;

    // Enabling tailscale sniffer with a timed-out reload PUT must NOT trust
    // old core state; it must restart into a fresh core generation.
    {
        let mut w = port.world();
        w.tailscale_exit = TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        };
        w.reload = Some(Err("Mihomo did not answer the reload".into()));
    }
    controller.handle(Message::TailscaleExit);
    assert_eq!(controller.phase, Phase::Running);
    assert!(controller.generation > gen1, "timed-out sniffer-only reload must restart core");
    assert!(port.world().ts_tables_active);

    // Losing a Tailscale DIRECT route when reset_tailscale fails must keep the
    // reset pending in the single netfx owner and retry ONLY the failed family.
    {
        let mut w = port.world();
        w.ts_resets.clear();
        w.ts_reset_fail_v4.push_back(Some("conntrack busy".into()));
    }
    controller.write(&select_proxy()).unwrap();
    assert_eq!(port.world().ts_resets, vec![(true, false)]);
    assert_eq!(port.world().ts_pending_reset, (true, false));

    controller.tick();
    assert_eq!(port.world().ts_pending_reset, (false, false));
    assert_eq!(port.world().ts_resets, vec![(true, false), (true, false)]);

    // Partial dual-family failure (IPv4 succeeds, IPv6 fails): subsequent ticks
    // MUST retry ONLY IPv6 and NEVER repeatedly reset healthy IPv4 flows.
    {
        let mut w = port.world();
        w.ts_resets.clear();
        w.ts_reset_fail_v4.push_back(None);
        w.ts_reset_fail_v6.push_back(Some("v6 busy".into()));
        w.ts_reset_fail_v6.push_back(Some("v6 still busy".into()));
        w.ts_reset_fail_v6.push_back(None);
        w.tailscale_exit.tproxy_v6 = true;
    }
    controller.reset_tailscale_flows("dual test", true, true, false);
    assert_eq!(port.world().ts_pending_reset, (false, true));
    controller.tick();
    controller.tick();
    assert_eq!(port.world().ts_pending_reset, (false, false));
    assert_eq!(
        port.world().ts_resets,
        vec![(true, true), (false, true), (false, true)],
        "healthy IPv4 must never be reset again during IPv6 retry"
    );
}

#[test]
fn revocation_supersedes_unconfirmed_enable_and_handles_cleanup_pending_and_late_guard_reset() {
    let port = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: false,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut controller = direct_controller(&port);
    assert!(!port.world().ts_tables_active);

    // 1. Enable IPv4 exit, but table read-back fails (unconfirmed enable left in
    //    `run.pending` and `ts_target_v4 == true`).
    {
        let mut w = port.world();
        w.tailscale_exit.tproxy_v4 = true;
        w.tables_fail.push_back(Some("readback timed out".into()));
    }
    controller.handle(Message::TailscaleExit);
    assert!(!port.world().ts_tables_v4);
    assert!(port.world().ts_target_v4);

    // 2a. Revoke IPv4 BEFORE confirmation, inject journal-write failures
    //     BEFORE `EffectSet` updates its target (`tables_reject_before_target`),
    //     and run `tick()` with `guard_due = true` -> guard MUST skip
    //     `reconcile()` rather than replay the old enable target!
    {
        let mut w = port.world();
        w.ts_resets.clear();
        w.events.clear();
        w.tailscale_exit.tproxy_v4 = false;
        w.guard_due = true;
        // One failure for `guard()`'s pre-reconcile supersede, one for `tick()`'s
        // subsequent `sync_tailscale_exit()` retry.
        w.tables_reject_before_target
            .push_back(Some("journal write failed before nft target update".into()));
        w.tables_reject_before_target
            .push_back(Some("journal write still failing".into()));
    }
    controller.tick();
    assert!(
        !port.world().events.iter().any(|e| e == "reconcile"),
        "guard must skip reconcile() when withdrawal failed before EffectSet updated target: {:?}",
        port.world().events
    );
    assert!(
        !port.world().ts_tables_v4,
        "guard must never replay old enable target when withdrawal failed before EffectSet updated target"
    );
    assert!(port.world().ts_target_v4, "old target stayed unaccepted in EffectSet");
    assert!(port.world().ts_resets.is_empty());

    // 2b. Once journal write recovers, the next `tick()` supersedes and confirms
    //     the withdrawal without ever replaying the revoked enable.
    controller.tick();
    assert!(!port.world().ts_target_v4, "guard must supersede revoked pending enable");
    assert!(!port.world().ts_tables_v4, "guard must never replay revoked enable");
    assert!(port.world().ts_resets.is_empty(), "guard must not reset flows for revoked enable");

    // 3. Re-enable IPv4 with initial table confirmation failing, then guard
    //    reconciles late -> late confirmation MUST trigger conntrack reset!
    {
        let mut w = port.world();
        w.ts_resets.clear();
        w.tailscale_exit.tproxy_v4 = true;
        w.tables_fail.push_back(Some("transient nft".into()));
        w.guard_due = true;
    }
    controller.handle(Message::TailscaleExit);
    assert!(port.world().ts_resets.is_empty());
    controller.guard();
    assert!(port.world().ts_tables_v4);
    assert_eq!(port.world().ts_resets, vec![(true, false)], "late guard confirmation must reset direct flows");

    // 4. Ordinary `widen()` (routing update) running while IPv6 enable was
    //    published concurrently (before `Message::TailscaleExit` runs) MUST
    //    reset IPv6 flows at the common `load()` confirmation point AND MUST
    //    NOT wipe IPv4 bypass history!
    {
        let mut w = port.world();
        w.ts_resets.clear();
        w.tailscale_exit.tproxy_v6 = true;
        w.guard_due = false;
    }
    controller.widen("concurrent routing update");
    assert!(port.world().ts_tables_v6);
    assert_eq!(
        port.world().ts_resets,
        vec![(false, true)],
        "ordinary load() confirming a new family must reset flows"
    );

    // 5a. External IPv4 retry that completed BEFORE `Hold` removed the old
    //     DIRECT chain MUST NOT clear IPv4 bypass history: flows created while
    //     the old DIRECT chain was still live must still be reset when the
    //     route moves to PROXY!
    {
        let mut w = port.world();
        w.ts_resets.clear();
        w.ts_pending_reset = (false, false);
        w.ts_v4_reset_started = Some(Instant::now() - Duration::from_secs(1));
    }
    controller.write(&select_proxy()).unwrap();
    assert_eq!(
        port.world().ts_resets,
        vec![(true, false)],
        "an earlier external IPv4 reset before Hold retired the DIRECT chain must not skip the post-Hold reset"
    );

    // 5b. External retry (e.g. Wi-Fi relay maintenance) completing a pending
    //     marked IPv4 reset AFTER `Hold` retired the old DIRECT chain MUST
    //     retire the bypass history so a later update does NOT reset healthy IPv4 flows!
    controller.write(&select_direct()).unwrap();
    {
        let mut w = port.world();
        w.ts_resets.clear();
        w.ts_reset_fail_v4.push_back(Some("conntrack busy".into()));
    }
    controller.write(&select_proxy()).unwrap();
    assert_eq!(port.world().ts_pending_reset, (true, false));
    assert_eq!(port.world().ts_resets, vec![(true, false)]);
    // Simulate Wi-Fi relay completing the pending marked IPv4 reset AFTER Hold retired DIRECT.
    {
        let mut w = port.world();
        w.ts_pending_reset = (false, false);
        w.ts_v4_reset_started = Some(Instant::now());
        w.ts_resets.clear();
        w.tailscale_exit.tproxy_v6 = false;
    }
    controller.widen("post-external-retry update");
    assert!(
        port.world().ts_resets.is_empty(),
        "ordered completion after retirement must prevent duplicate IPv4 reset: {:?}",
        port.world().ts_resets
    );

    // 6. Enter CleanupPending with IPv4 confirmed AND a failed unconfirmed IPv6
    //    enable still pending in `run.pending`; revoking IPv4 while IPv6 stays
    //    desired MUST withdraw IPv4 and MUST NOT newly enable IPv6 on the stopping core!
    {
        let mut w = port.world();
        w.tailscale_exit.tproxy_v6 = true;
        w.tables_fail.push_back(Some("ipv6 enable never reached kernel".into()));
    }
    controller.handle(Message::TailscaleExit);
    assert!(port.world().ts_tables_v4);
    assert!(!port.world().ts_tables_v6);

    let gen = controller.generation;
    {
        let mut w = port.world();
        w.uplink = Uplink::sample("ath20", 9, "192.0.2.2", None);
        w.prepare.push_back(Some("prepare failed".into()));
        w.stop_confirmed.push_back(false);
    }
    controller.handle(Message::Egress);
    assert_eq!(controller.phase, Phase::CleanupPending);
    assert!(port.world().ts_tables_v4);
    assert!(!port.world().ts_tables_v6);

    {
        let mut w = port.world();
        w.tailscale_exit.tproxy_v4 = false;
        w.tailscale_exit.tproxy_v6 = true;
    }
    controller.handle(Message::TailscaleExit);
    assert_eq!(controller.phase, Phase::CleanupPending);
    assert!(!port.world().ts_tables_v4, "revocation during CleanupPending must withdraw IPv4 ts_pre immediately");
    assert!(
        !port.world().ts_tables_v6,
        "CleanupPending must never newly enable an unconfirmed pending IPv6 family on a stopping core"
    );
    controller.handle(Message::Exited { generation: gen, how: "signal 9".into() });
    assert_eq!(controller.phase, Phase::Backoff);

    // 7. First confirmed Hold table enabling IPv4 interception when the
    //    subsequent Full table fails MUST reset IPv4 flows immediately at Hold
    //    confirmation and carry `ts_exit.tproxy_v4 == true` into `Run`!
    let port2 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        shape_fail: vec![("full/".into(), "full table readback failed".into())],
        ..World::default()
    })));
    let (_tx, rx) = mpsc::channel();
    let shared = Arc::new(Mutex::new(Snapshot::default()));
    let mut ctrl2 = Controller::new(port2.clone(), rx, _tx, shared, timings());
    ctrl2.handle(Message::Enable { local: "192.168.0.1".into(), owner: true, reply: None });
    assert_eq!(ctrl2.phase, Phase::Running);
    assert_eq!(
        port2.world().ts_resets,
        vec![(true, false)],
        "Hold confirmation enabling IPv4 must reset direct flows even when subsequent Full fails"
    );
    assert!(
        ctrl2.run.as_ref().is_some_and(|r| r.ts_exit.tproxy_v4),
        "Hold-confirmed family must be carried into Run.ts_exit when Full fails"
    );

    // 8. Pre-target journal-write failure during IPv6 ENABLE followed by guard
    //    and CleanupPending: guard confirming the old IPv4-only generation MUST
    //    NOT promote the rejected IPv6 enable into `Run.ts_exit` or allow
    //    CleanupPending to newly enable IPv6 on a stopping core!
    let port3 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut ctrl3 = direct_controller(&port3);
    {
        let mut w = port3.world();
        w.ts_resets.clear();
        w.tailscale_exit.tproxy_v6 = true;
        w.tables_reject_before_target
            .push_back(Some("journal write failed before EffectSet accepted v6 enable".into()));
        w.guard_due = true;
    }
    ctrl3.widen("v6 enable hits pre-target journal error");
    assert!(!port3.world().ts_tables_v6);
    assert!(!port3.world().ts_target_v6);
    ctrl3.guard();
    assert!(
        !ctrl3.run.as_ref().unwrap().ts_exit.tproxy_v6,
        "guard confirming older IPv4-only generation must NEVER promote rejected IPv6 enable"
    );
    assert!(port3.world().ts_resets.is_empty());
    let gen3 = ctrl3.generation;
    {
        let mut w = port3.world();
        w.uplink = Uplink::sample("ath20", 9, "192.0.2.2", None);
        w.prepare.push_back(Some("prepare failed".into()));
        w.stop_confirmed.push_back(false);
    }
    ctrl3.handle(Message::Egress);
    assert_eq!(ctrl3.phase, Phase::CleanupPending);
    port3.world().tailscale_exit.tproxy_v4 = false;
    ctrl3.handle(Message::TailscaleExit);
    assert!(!port3.world().ts_tables_v4);
    assert!(
        !port3.world().ts_tables_v6,
        "CleanupPending must NOT enable IPv6 after pre-target journal failure + guard"
    );
    ctrl3.handle(Message::Exited { generation: gen3, how: "signal 9".into() });

    // 9. Profile restart changing Tailscale DIRECT -> PROXY while IPv4
    //    interception stays enabled (zero family-enable delta!) MUST carry
    //    `ts_bypassed` through restart and reset marked IPv4 flows!
    let port4 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut ctrl4 = direct_controller(&port4);
    {
        let mut w = port4.world();
        w.ts_resets.clear();
        w.selected_direct = false;
    }
    ctrl4.restart("profile switched DIRECT to PROXY", Restart::Profile).unwrap();
    assert_eq!(
        port4.world().ts_resets,
        vec![(true, false)],
        "profile restart dropping a Tailscale DIRECT chain must reset marked IPv4 flows"
    );

    // 10. Egress rollback after a family first becomes active in `Full`:
    //     `Full` confirms `tproxy_v4 = true`, then egress moves before
    //     publication -> the first-interception reset MUST run BEFORE rollback
    //     copies `tproxy_v4 = true` into `holding_ts` and retries launch!
    let port5 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: false,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        egress_on_full: Some(Uplink::sample("ath20", 9, "192.0.2.9", None)),
        ..World::default()
    })));
    // Wait until after Hold confirms, then flip tproxy_v4 = true before Full via
    // a custom launch sequence: start with Hold confirmed (v4=false), enable v4,
    // and run `launch_prepared` with `egress_on_full` triggering rollback.
    let mut ctrl5 = direct_controller(&port5);
    assert!(!port5.world().ts_tables_v4);
    {
        let mut w = port5.world();
        w.ts_resets.clear();
        w.egress_on_full = Some(Uplink::sample("ath20", 9, "192.0.2.10", None));
        // Restart holds with v4=false; enable v4 right after Hold so Full is the
        // FIRST table to confirm v4=true right before egress changes!
        w.tailscale_exit.tproxy_v4 = false;
    }
    // Prepare a restart behind Hold (v4=false), flip v4=true before `launch_prepared`.
    let prepared5 = ctrl5
        .prepare(&Source::Selected { local: "u60.home.arpa".into(), runtime: None }, false)
        .unwrap();
    let old5 = ctrl5.run.take().unwrap();
    let mut holding_ts5 = old5.ts_exit.clone();
    let mut bypassed5 = old5.bypassed;
    let mut ts_bypassed5 = old5.ts_bypassed;
    let _ = old5.core.stop();
    port5.world().tailscale_exit.tproxy_v4 = true;
    ctrl5
        .launch_prepared(prepared5, true, &mut holding_ts5, &mut bypassed5, &mut ts_bypassed5)
        .unwrap();
    assert!(port5.world().ts_tables_v4);
    assert_eq!(
        port5.world().ts_resets,
        vec![(true, false)],
        "egress rollback after Full first enabled IPv4 must still run the marked IPv4 reset"
    );

    // 11. `apply_tailscale_kernel_only()` advancing nft target to IPv6 where
    //     IPv4 withdrawal ACTUALLY COMMITTED in the kernel before readback
    //     failed, followed by desired flipping back to IPv4 while core HTTP
    //     readback is unavailable -> `guard()` MUST supersede the obsolete
    //     IPv6 target AND reset IPv4 marked flows (reversing an unconfirmed
    //     withdrawal that may have let direct flows start)!
    let port6 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut ctrl6 = direct_controller(&port6);
    {
        let mut w = port6.world();
        w.ts_resets.clear();
        w.tailscale_exit.tproxy_v4 = false;
        w.tailscale_exit.tproxy_v6 = true;
        w.tables_commit_then_fail
            .push_back(Some("nft committed v4 withdrawal + v6 enable then readback timed out".into()));
    }
    assert!(!ctrl6.apply_tailscale_kernel_only("v4 -> v6 committed then readback failed"));
    assert!(port6.world().ts_target_v6, "EffectSet accepted the v6 target");
    assert!(!port6.world().ts_tables_v4, "v4 withdrawal committed in kernel");
    assert!(port6.world().ts_tables_v6);
    // Repeated readback failures MUST keep `run.pending` bounded (1 slot, not unbounded Vec).
    {
        let mut w = port6.world();
        w.tables_fail.push_back(Some("repeat fail 1".into()));
        w.tables_fail.push_back(Some("repeat fail 2".into()));
    }
    assert!(!ctrl6.apply_tailscale_kernel_only("retry 1"));
    assert!(!ctrl6.apply_tailscale_kernel_only("retry 2"));
    assert!(ctrl6.run.as_ref().unwrap().pending.is_some());
    // Desired returns to IPv4-only while core HTTP read_back is unavailable.
    {
        let mut w = port6.world();
        w.ts_resets.clear();
        w.tailscale_exit.tproxy_v4 = true;
        w.tailscale_exit.tproxy_v6 = false;
        w.read_results.push_back(None);
        w.guard_due = true;
    }
    ctrl6.guard();
    assert!(!port6.world().ts_target_v6, "guard must supersede accepted obsolete IPv6 target");
    assert!(!port6.world().ts_tables_v6, "guard must NEVER reconcile obsolete IPv6 target");
    assert!(port6.world().ts_tables_v4);
    assert_eq!(
        port6.world().ts_resets,
        vec![(true, false)],
        "reversing an unconfirmed IPv4 withdrawal must still reset marked IPv4 flows"
    );

    // 12. Accepted rollback `Hold` whose readback fails must retain the exact
    //     submitted `TailscaleExitConfig` (not `default()`), so late guard
    //     confirmation records the enabled family and runs the marked reset!
    let port7 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: false,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut ctrl7 = direct_controller(&port7);
    let prepared7 = ctrl7
        .prepare(&Source::Selected { local: "u60.home.arpa".into(), runtime: None }, false)
        .unwrap();
    let old7 = ctrl7.run.take().unwrap();
    let mut holding_ts7 = old7.ts_exit.clone();
    let mut bypassed7 = old7.bypassed;
    let mut ts_bypassed7 = old7.ts_bypassed;
    let _ = old7.core.stop();
    {
        let mut w = port7.world();
        w.ts_resets.clear();
        w.tailscale_exit.tproxy_v4 = true;
        w.egress_on_full = Some(Uplink::sample("ath20", 9, "192.0.2.11", None));
        w.shape_fail.push(("hold".into(), "rollback Hold readback failed".into()));
    }
    assert!(ctrl7
        .launch_prepared(prepared7, true, &mut holding_ts7, &mut bypassed7, &mut ts_bypassed7)
        .is_err());
    assert!(ctrl7.run.is_some());
    assert!(
        ctrl7.run.as_ref().unwrap().ts_target().tproxy_v4,
        "accepted rollback Hold pending entry must retain submitted tproxy_v4=true, not default false"
    );
    port7.world().guard_due = true;
    ctrl7.guard();
    assert!(
        ctrl7.run.as_ref().unwrap().ts_exit.tproxy_v4,
        "late guard confirming rollback Hold must keep ts_exit.tproxy_v4=true"
    );

    // 13. Profile restart publishing confirmed PROXY replacement when rollback
    //     Hold fails (`launch_prepared` returns `Err` with `self.run.is_some()`)
    //     MUST still run `reset_restart_bypass` and reset marked IPv4 flows!
    let port8 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut ctrl8 = direct_controller(&port8);
    {
        let mut w = port8.world();
        w.resets.clear();
        w.ts_resets.clear();
        w.selected_direct = false;
        w.egress_on_full = Some(Uplink::sample("ath20", 9, "192.0.2.12", None));
        // Restart's initial Hold succeeds; Full confirms PROXY (and moves egress);
        // rollback Hold fails readback -> launch_current publishes Run and returns Err!
        w.tables_fail.push_back(None); // initial restart Hold succeeds
        w.tables_fail.push_back(None); // replacement Full succeeds
        w.tables_fail.push_back(Some("rollback Hold readback failed".into()));
    }
    assert!(ctrl8.restart("profile switched DIRECT->PROXY with failed rollback Hold", Restart::Profile).is_err());
    assert!(ctrl8.run.is_some(), "replacement Run stayed published");
    assert_eq!(
        port8.world().resets,
        vec![Scope::Destinations(vec!["1.2.3.0/24".parse().unwrap()])],
        "failed rollback Hold must preserve LAN bypassed history and reset lost LAN destinations"
    );
    assert_eq!(
        port8.world().ts_resets,
        vec![(true, false)],
        "published replacement Run after failed rollback Hold must still reset lost Tailscale DIRECT flows"
    );

    // 14. Fresh start where Candidate 1 confirms DIRECT `Full`, loses egress
    //     and rolls back to `Hold`, and Candidate 2 confirms PROXY `Full` with
    //     IPv4 interception still enabled -> `start()` MUST reset the stale
    //     candidate's lost Tailscale DIRECT flows in addition to LAN!
    let port9 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        read_results: VecDeque::from([Some(true), Some(false)]),
        egress_on_full: Some(Uplink::sample("ath20", 9, "192.0.2.13", None)),
        ..World::default()
    })));
    let (tx9, rx9) = mpsc::channel();
    let mut ctrl9 = Controller::new(port9.clone(), rx9, tx9, Arc::new(Mutex::new(Snapshot::default())), timings());
    ctrl9.handle(Message::Enable { local: "u60.home.arpa".into(), owner: true, reply: None });
    assert_eq!(ctrl9.phase, Phase::Running);
    assert_eq!(
        port9.world().ts_resets,
        vec![(true, false), (true, false)],
        "fresh start must reset both initial Hold enable and Candidate 1's lost Tailscale DIRECT flows after rollback"
    );

    // 15. With LAN bypass OFF and Tailscale DIRECT active, a kernel-only
    //     update MUST submit `Shape::Full` (not `Shape::Hold`) so the rendered
    //     Tailscale DIRECT chain matches the submitted table!
    let port10 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        bypass_off: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut ctrl10 = direct_controller(&port10);
    assert_eq!(ctrl10.run.as_ref().unwrap().ts_chain.returns, 1);
    assert_eq!(port10.world().tables.as_deref(), Some("full/0"));
    port10.world().tailscale_exit.skip_v4.push("10.0.0.0/8".into());
    assert!(ctrl10.apply_tailscale_kernel_only("skip_v4 update with LAN bypass off"));
    assert_eq!(
        port10.world().tables.as_deref(),
        Some("full/0"),
        "kernel-only update with LAN bypass off and Tailscale DIRECT active must submit Shape::Full, not Hold"
    );
    assert_eq!(ctrl10.run.as_ref().unwrap().ts_chain.returns, 1);

    // 16. Rollback Hold confirming IPv4 enabled after an unconfirmed `Full`
    //     IPv4 withdrawal MUST reset marked IPv4 flows (via
    //     `run.needs_enable_reset()`) even when both candidates are PROXY.
    let port11 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: false,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut ctrl11 = direct_controller(&port11);
    let mut prepared11 = ctrl11
        .prepare(&Source::Selected { local: "u60.home.arpa".into(), runtime: None }, false)
        .unwrap();
    let old11 = ctrl11.run.take().unwrap();
    let mut holding_ts11 = old11.ts_exit.clone();
    assert!(holding_ts11.tproxy_v4);
    let mut bypassed11 = old11.bypassed;
    let mut ts_bypassed11 = old11.ts_bypassed;
    let _ = old11.core.stop();
    {
        let mut w = port11.world();
        w.ts_resets.clear();
        // `Full` withdraws IPv4 (committed to kernel, readback fails), egress
        // moves, and IPv4 approval returns before rollback `Hold` confirms!
        w.tailscale_exit.tproxy_v4 = false;
        w.tables_commit_then_fail
            .push_back(Some("Full IPv4 withdrawal readback failed".into()));
        w.egress_on_full = Some(Uplink::sample("ath20", 9, "192.0.2.16", None));
        w.ts_exit_on_full = Some(TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        });
    }
    let rolled = ctrl11
        .launch_current(&mut prepared11, &mut true, &mut holding_ts11, &mut bypassed11, &mut ts_bypassed11)
        .expect("rollback Hold should succeed");
    assert!(!rolled, "egress moved -> rollback returns Ok(false)");
    assert!(holding_ts11.tproxy_v4);
    assert_eq!(
        port11.world().ts_resets,
        vec![(true, false)],
        "rollback Hold re-enabling IPv4 after unconfirmed Full withdrawal must reset marked IPv4 flows"
    );

    // 17. CleanupPending MUST never re-enable a family on a stopping core once
    //     withdrawal was attempted — even if the first withdrawal failed
    //     readback (or failed pre-target) and approval returned before retry!
    let port12 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: false,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut ctrl12 = direct_controller(&port12);
    port12.world().stop_confirmed.push_back(false);
    assert!(ctrl12.stop_all().is_err());
    assert_eq!(ctrl12.phase, Phase::CleanupPending);
    assert_eq!(ctrl12.stopping_ts.allow, (true, false));
    {
        let mut w = port12.world();
        w.tailscale_exit.tproxy_v4 = false;
        w.tables_commit_then_fail
            .push_back(Some("cleanup withdrawal readback failed".into()));
    }
    ctrl12.handle(Message::TailscaleExit);
    assert!(ctrl12.cleanup_ts_dirty);
    assert_eq!(ctrl12.stopping_ts.allow, (false, false), "attempted withdrawal removes v4 from re-enable set");
    assert_eq!(ctrl12.stopping_ts.may, (true, false), "unconfirmed withdrawal remains eligible for retries");
    // Approval returns BEFORE the cleanup retry!
    port12.world().tailscale_exit.tproxy_v4 = true;
    ctrl12.tick();
    assert!(!ctrl12.cleanup_ts_dirty);
    assert_eq!(ctrl12.stopping_ts.allow, (false, false));
    assert_eq!(ctrl12.stopping_ts.may, (false, false));
    assert!(
        !port12.world().ts_target_v4 && !port12.world().ts_tables_v4,
        "CleanupPending retry must keep IPv4 withdrawn, never re-enabling on stopping core"
    );
    // Also verify pre-target journal failure + returning approval + guard supersede:
    ctrl12.stopping_ts.allow = (true, false);
    ctrl12.stopping_ts.may = (true, false);
    {
        let mut w = port12.world();
        w.ts_target_v4 = true;
        w.tailscale_exit.tproxy_v4 = false;
        w.tables_reject_before_target
            .push_back(Some("journal write failed before cleanup withdrawal".into()));
    }
    ctrl12.handle(Message::TailscaleExit);
    assert!(port12.world().ts_target_v4, "pre-target failure left old v4 target");
    assert_eq!(ctrl12.stopping_ts.allow, (false, false));
    assert_eq!(ctrl12.stopping_ts.may, (true, false));
    port12.world().tailscale_exit.tproxy_v4 = true;
    assert_eq!(ctrl12.supersede_revoked_tailscale_before_guard(), Ok(true));
    assert!(
        !port12.world().ts_target_v4 && !port12.world().ts_tables_v4,
        "supersede before guard must still withdraw even when approval returned after pre-target failure"
    );

    // 18. Removing an approved public subnet from `skip_v4` / `skip_v6` while
    //     the exit family stays enabled on an unchanged PROXY profile MUST
    //     reset existing marked flows for that family (both confirmed and
    //     unconfirmed skip additions).
    let port13 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: false,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: true,
            skip_v4: vec!["198.51.100.0/24".into()],
            skip_v6: vec!["2001:db8::/32".into()],
        },
        ..World::default()
    })));
    let mut ctrl13 = direct_controller(&port13);
    port13.world().ts_resets.clear();
    port13.world().tailscale_exit.skip_v4.clear();
    ctrl13.sync_tailscale_exit();
    assert_eq!(
        port13.world().ts_resets,
        vec![(true, false)],
        "removing skip_v4 on unchanged PROXY profile must reset marked IPv4 flows"
    );
    port13.world().ts_resets.clear();
    port13.world().tailscale_exit.skip_v6.clear();
    ctrl13.sync_tailscale_exit();
    assert_eq!(
        port13.world().ts_resets,
        vec![(false, true)],
        "removing skip_v6 on unchanged PROXY profile must reset marked IPv6 flows"
    );
    // Unconfirmed skip_v4 addition followed by removal in `widen()` must also reset!
    {
        let mut w = port13.world();
        w.ts_resets.clear();
        w.tailscale_exit.skip_v4 = vec!["198.51.100.0/24".into()];
        w.tables_commit_then_fail
            .push_back(Some("unconfirmed skip_v4 addition".into()));
    }
    assert!(!ctrl13.apply_tailscale_kernel_only("unconfirmed skip_v4 add"));
    port13.world().tailscale_exit.skip_v4.clear();
    ctrl13.widen("removed unconfirmed skip_v4");
    assert_eq!(
        port13.world().ts_resets,
        vec![(true, false)],
        "removing an unconfirmed skip_v4 prefix via widen() must reset marked IPv4 flows"
    );

    // 19. Late guard confirmation MUST preserve accumulated `pending_narrowing`
    //     when a failed `Hold` (`narrowing == true`) is followed by a failed
    //     kernel-only update (`narrowing == false`) with both exit families off.
    let port14 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: false,
            tproxy_v4: false,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut ctrl14 = direct_controller(&port14);
    assert_eq!(ctrl14.run.as_ref().unwrap().kernel.1.returns, 1);
    port14.world().tables_fail.push_back(Some("Hold readback failed".into()));
    assert!(ctrl14.load(Shape::Hold, Bypass::None("narrowing".into()), Chain::default(), true).is_err());
    port14.world().tailscale_exit.skip_v4.push("10.0.0.0/8".into());
    port14.world().tables_fail.push_back(Some("kernel-only readback failed".into()));
    assert!(!ctrl14.apply_tailscale_kernel_only("copied Hold with narrowing=false"));
    assert!(ctrl14.run.as_ref().unwrap().pending_narrowing);
    assert!(!ctrl14.run.as_ref().unwrap().pending.as_ref().unwrap().narrowing);
    port14.world().guard_due = true;
    ctrl14.guard();
    assert_eq!(
        ctrl14.run.as_ref().unwrap().kernel.1.returns,
        1,
        "late guard confirmation must preserve pending_narrowing and widen LAN DIRECT back"
    );

    // 20. Restarting from all-PROXY into a profile with a port-based DIRECT
    //     rule MUST NOT trigger a whole-LAN reset, and fresh start into a
    //     port-based DIRECT profile MUST NOT trigger an extra self-comparison
    //     Tailscale reset!
    let port15 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: false,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: false,
            tproxy_v4: false,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut ctrl15 = direct_controller(&port15);
    {
        let mut w = port15.world();
        w.resets.clear();
        w.selected_direct = true;
        w.port_direct = true;
    }
    ctrl15.restart("switch PROXY -> port-DIRECT", Restart::Profile).unwrap();
    assert_eq!(
        port15.world().resets,
        vec![Scope::Destinations(Vec::new())],
        "replacement's own port-based DIRECT chain must not trigger a whole-LAN reset"
    );

    let port16 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: true,
        port_direct: true,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let (tx16, rx16) = mpsc::channel();
    let mut ctrl16 = Controller::new(port16.clone(), rx16, tx16, Arc::new(Mutex::new(Snapshot::default())), timings());
    ctrl16.handle(Message::Enable { local: "u60.home.arpa".into(), owner: true, reply: None });
    assert_eq!(ctrl16.phase, Phase::Running);
    assert_eq!(
        port16.world().ts_resets,
        vec![(true, false)],
        "fresh start into a port-based DIRECT profile must only run the initial enable reset, not a self-comparison reset"
    );

    // 21. An unconfirmed IPv4 withdrawal attempted while `Running` (readback
    //     failed) MUST be carried across `stop_all()` into `CleanupPending` so
    //     returning approval cannot re-enable IPv4 on the stopping core!
    let port17 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: false,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: false,
            skip_v4: Vec::new(),
            skip_v6: Vec::new(),
        },
        ..World::default()
    })));
    let mut ctrl17 = direct_controller(&port17);
    {
        let mut w = port17.world();
        w.tailscale_exit.tproxy_v4 = false;
        w.tables_commit_then_fail
            .push_back(Some("Running IPv4 withdrawal readback failed".into()));
    }
    assert!(!ctrl17.apply_tailscale_kernel_only("Running withdrawal"));
    assert!(ctrl17.run.as_ref().unwrap().ts_unconfirmed_disabled.0);
    // Stop fails while withdrawal is still unconfirmed -> enters CleanupPending!
    port17.world().stop_confirmed.push_back(false);
    assert!(ctrl17.stop_all().is_err());
    assert_eq!(ctrl17.phase, Phase::CleanupPending);
    assert_eq!(
        ctrl17.stopping_ts.allow,
        (false, false),
        "stop handoff must carry unconfirmed withdrawal and disallow re-enabling IPv4"
    );
    assert_eq!(
        ctrl17.stopping_ts.may,
        (true, false),
        "stop handoff must keep IPv4 eligible for withdrawal retries"
    );
    assert!(ctrl17.cleanup_ts_dirty);
    // Approval returns while stopping -> CleanupPending tick MUST keep IPv4 withdrawn!
    port17.world().tailscale_exit.tproxy_v4 = true;
    ctrl17.tick();
    assert!(!ctrl17.cleanup_ts_dirty);
    assert_eq!(ctrl17.stopping_ts.allow, (false, false));
    assert_eq!(ctrl17.stopping_ts.may, (false, false));
    assert!(
        !port17.world().ts_target_v4 && !port17.world().ts_tables_v4,
        "CleanupPending must not re-enable IPv4 after a Running withdrawal failed readback"
    );

    // 22. Removing an approved public subnet from `skip_v4`/`skip_v6` during
    //     `CleanupPending` while that exit family stays intercepted MUST reset
    //     existing marked flows for that family (including unconfirmed additions).
    let port18 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: false,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: true,
            skip_v4: vec!["198.51.100.0/24".into()],
            skip_v6: vec!["2001:db8::/32".into()],
        },
        ..World::default()
    })));
    let mut ctrl18 = direct_controller(&port18);
    port18.world().stop_confirmed.push_back(false);
    assert!(ctrl18.stop_all().is_err());
    assert_eq!(ctrl18.phase, Phase::CleanupPending);
    port18.world().ts_resets.clear();
    port18.world().tailscale_exit.skip_v4.clear();
    ctrl18.handle(Message::TailscaleExit);
    assert_eq!(
        port18.world().ts_resets,
        vec![(true, false)],
        "removing skip_v4 during CleanupPending must reset marked IPv4 flows"
    );
    port18.world().ts_resets.clear();
    port18.world().tailscale_exit.skip_v6.clear();
    ctrl18.handle(Message::TailscaleExit);
    assert_eq!(
        port18.world().ts_resets,
        vec![(false, true)],
        "removing skip_v6 during CleanupPending must reset marked IPv6 flows"
    );
    // Unconfirmed skip_v4 addition during CleanupPending followed by removal must also reset!
    {
        let mut w = port18.world();
        w.ts_resets.clear();
        w.tailscale_exit.skip_v4 = vec!["203.0.113.0/24".into()];
        w.tables_commit_then_fail
            .push_back(Some("unconfirmed cleanup skip_v4 add".into()));
    }
    ctrl18.handle(Message::TailscaleExit);
    assert!(ctrl18.cleanup_ts_dirty);
    port18.world().tailscale_exit.skip_v4.clear();
    ctrl18.tick();
    assert_eq!(
        port18.world().ts_resets,
        vec![(true, false)],
        "removing an unconfirmed cleanup skip_v4 prefix must reset marked IPv4 flows"
    );

    // 22b. Skip-prefix removal that committed while `Running` and failed
    //      readback BEFORE `stop_all()` MUST keep `cleanup_ts_dirty = true` so
    //      the very next `tick()` — with desired config unchanged and NO second
    //      Tailscale notification — confirms the removal and resets ONLY the
    //      affected family (verified for both IPv4 and IPv6)!
    let port19 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: false,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: true,
            skip_v4: vec!["198.51.100.0/24".into()],
            skip_v6: vec!["2001:db8::/32".into()],
        },
        ..World::default()
    })));
    let mut ctrl19 = direct_controller(&port19);
    {
        let mut w = port19.world();
        w.ts_resets.clear();
        w.tailscale_exit.skip_v4.clear();
        w.tables_commit_then_fail
            .push_back(Some("Running skip_v4 removal readback failed".into()));
    }
    assert!(!ctrl19.apply_tailscale_kernel_only("Running skip_v4 removal"));
    assert!(port19.world().ts_resets.is_empty(), "unconfirmed removal did not reset yet");
    port19.world().stop_confirmed.push_back(false);
    assert!(ctrl19.stop_all().is_err());
    assert_eq!(ctrl19.phase, Phase::CleanupPending);
    assert!(
        ctrl19.cleanup_ts_dirty,
        "stop handoff must carry pending Running skip_v4 removal into cleanup_ts_dirty"
    );
    // Desired config is unchanged and no TailscaleExit notification arrives:
    // the next `tick()` MUST confirm the removal and reset ONLY IPv4!
    ctrl19.tick();
    assert!(!ctrl19.cleanup_ts_dirty);
    assert_eq!(
        port19.world().ts_resets,
        vec![(true, false)],
        "CleanupPending tick must confirm Running skip_v4 removal and reset only IPv4"
    );

    let port20 = FakePort(Arc::new(Mutex::new(World {
        selected_direct: false,
        wanted: true,
        tailscale_exit: TailscaleExitConfig {
            sniffer: true,
            tproxy_v4: true,
            tproxy_v6: true,
            skip_v4: vec!["198.51.100.0/24".into()],
            skip_v6: vec!["2001:db8::/32".into()],
        },
        ..World::default()
    })));
    let mut ctrl20 = direct_controller(&port20);
    {
        let mut w = port20.world();
        w.ts_resets.clear();
        w.tailscale_exit.skip_v6.clear();
        w.tables_commit_then_fail
            .push_back(Some("Running skip_v6 removal readback failed".into()));
    }
    assert!(!ctrl20.apply_tailscale_kernel_only("Running skip_v6 removal"));
    assert!(port20.world().ts_resets.is_empty());
    port20.world().stop_confirmed.push_back(false);
    assert!(ctrl20.stop_all().is_err());
    assert_eq!(ctrl20.phase, Phase::CleanupPending);
    assert!(
        ctrl20.cleanup_ts_dirty,
        "stop handoff must carry pending Running skip_v6 removal into cleanup_ts_dirty"
    );
    ctrl20.tick();
    assert!(!ctrl20.cleanup_ts_dirty);
    assert_eq!(
        port20.world().ts_resets,
        vec![(false, true)],
        "CleanupPending tick must confirm Running skip_v6 removal and reset only IPv6"
    );
}
