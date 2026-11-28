use super::*;
use std::collections::VecDeque;
use std::sync::mpsc;

#[derive(Default)]
struct World {
    calls: Vec<String>,
    scans: Vec<Network>,
    target: Option<resume::Resume>,
    observations: VecDeque<Observation>,
    joins: VecDeque<Result<(), String>>,
    pending: bool,
    off: (bool, bool),
    off_during_join: Option<(bool, bool)>,
    cleanup_error: Option<String>,
    clear_error: Option<String>,
    pause: Option<(&'static str, mpsc::Sender<()>, mpsc::Receiver<()>)>,
    panic: bool,
    elapsed: Duration,
    adopted: bool,
    prepare_hotspot: bool,
    scan_rounds: bool,
    record_subscription_dns: bool,
    cellular: Option<CellularFixture>,
}

struct CellularFixture {
    dir: test_dir::TestDir,
    pause: cellular::Pause,
    modem: cellular::tests::Modem,
}

impl CellularFixture {
    fn new(strict: bool) -> Self {
        let dir = test_dir::TestDir::new("relayctl-cellular");
        cellular::save(dir.path(), strict).unwrap();
        let modem = cellular::tests::Modem::new(dir.path(), true);
        Self { dir, pause: cellular::Pause::default(), modem }
    }

    fn set(&mut self, enabled: bool) -> Result<(), String> {
        self.modem.set(&mut self.pause, enabled)
    }

    fn reconcile(&mut self) -> Result<(), String> {
        self.modem.reconcile(&mut self.pause)
    }
}

#[derive(Clone)]
struct FakePort {
    world: Arc<Mutex<World>>,
    epoch: Instant,
}

impl FakePort {
    fn record_subscription_dns(&self, state: &State) {
        let mut world = self.world.lock().unwrap();
        if world.record_subscription_dns {
            let servers = state.session.as_ref().and_then(|session| session.lease.as_ref()).map(|lease| {
                if lease.dns.is_empty() { vec![lease.gateway] } else { lease.dns.clone() }
            }).unwrap_or_default();
            world.calls.push(format!("subscription DNS {servers:?}"));
        }
    }

    fn call(&self, name: &'static str) {
        let pause = {
            let mut world = self.world.lock().unwrap();
            world.calls.push(format!("enter {name}"));
            if world.pause.as_ref().is_some_and(|pause| pause.0 == name) {
                world.pause.take()
            } else {
                None
            }
        };
        if let Some((_, entered, release)) = pause {
            entered.send(()).unwrap();
            release.recv_timeout(Duration::from_secs(60)).unwrap();
        }
        let mut world = self.world.lock().unwrap();
        if std::mem::take(&mut world.panic) {
            drop(world);
            panic!("scripted port panic");
        }
        world.calls.push(format!("exit {name}"));
    }
}

struct ScanPort<'a> {
    port: &'a FakePort,
    round: usize,
}

impl scan::Supplicant for ScanPort<'_> {
    fn request(&mut self, command: &str) -> Result<String, String> {
        if command.starts_with("SCAN ") {
            self.round += 1;
            self.port.call(if self.round == 1 { "scan-round-1" } else { "scan-round-2" });
        }
        Ok("OK".into())
    }

    fn scan_done(&mut self, _: Instant) -> Result<bool, String> { Ok(true) }
}

impl Port for FakePort {
    fn now(&self) -> Instant {
        self.epoch + self.world.lock().unwrap().elapsed
    }
    fn boot_now(&self) -> BootInstant {
        BootInstant::from_duration(self.world.lock().unwrap().elapsed)
    }
    fn sync_subscription_dns(&self, state: &State) {
        self.record_subscription_dns(state);
    }
    fn snapshot(&mut self, state: &State) -> Value {
        if self.world.lock().unwrap().pause.as_ref().is_some_and(|pause| pause.0 == "snapshot") {
            self.call("snapshot");
        }
        let mut value = snapshot(state, self.boot_now());
        let world = self.world.lock().unwrap();
        value["autostart"] = json!(world.target.is_some());
        if let Some(cellular) = &world.cellular {
            value["strict_zero_cellular"] = json!(cellular::enabled(cellular.dir.path()));
            value["cellular_pause"] = json!(cellular.pause);
        }
        if !value["offload"].is_object() {
            value["offload"] = json!({});
        }
        value
    }
    fn pending(&self) -> bool {
        self.world.lock().unwrap().pending
    }
    fn target(&mut self) -> Option<resume::Resume> {
        self.world.lock().unwrap().target.clone()
    }
    fn clear(&mut self) -> Result<(), String> {
        self.call("clear");
        if let Some(error) = self.world.lock().unwrap().clear_error.clone() {
            return Err(error);
        }
        self.world.lock().unwrap().target = None;
        Ok(())
    }
    fn hotspot(&mut self) -> (bool, bool) {
        self.world.lock().unwrap().off
    }
    fn recover(&mut self) -> Result<(), String> {
        self.call("recover");
        let mut world = self.world.lock().unwrap();
        if let Some(error) = world.cleanup_error.clone() {
            return Err(error);
        }
        if let Some(cellular) = world.cellular.as_mut() {
            cellular.set(false)?;
        }
        world.pending = false;
        Ok(())
    }
    fn adopt(&mut self, allow_cellular_pause: bool) -> Option<Session> {
        self.call("adopt");
        let mut world = self.world.lock().unwrap();
        if !world.adopted {
            return None;
        }
        if allow_cellular_pause {
            if let Some(cellular) = world.cellular.as_mut() {
                let _ = cellular.reconcile();
            }
        }
        let mut session = Session::new(Path::new("/tmp/u60-test/work/relayctl/fake"));
        session.selected = Some(network());
        session.lease = Some(lease());
        Some(session)
    }
    fn scan(&mut self, state: &mut State, cancel: &Cancellation) -> Result<Vec<Network>, String> {
        self.call("scan");
        let rounds = self.world.lock().unwrap().scan_rounds;
        if rounds {
            assert!(state.session.is_none());
            let mut temporary = Session::new(Path::new("/tmp/u60-test/work/relayctl/fake-scan"));
            self.world.lock().unwrap().pending = true;
            let result = scan::run(&mut ScanPort { port: self, round: 0 }, &[vec![2412], vec![5180]], || cancel.check());
            self.cleanup(&mut temporary)?;
            cancel.check()?;
            result?;
        }
        Ok(self.world.lock().unwrap().scans.clone())
    }
    fn join(&mut self, state: &mut State, selection: Selection, _: bool, cancel: &Cancellation, allow_cellular_pause: bool) -> Result<Session, String> {
        self.call("join");
        let hotspot_state = self.world.lock().unwrap().off_during_join.take();
        if let Some(hotspot_state) = hotspot_state {
            let (_off, by_owner) = hotspot_state;
            self.world.lock().unwrap().off = hotspot_state;
            let clear_error = finish_join_hotspot_failure(&cancel.shared, by_owner, || {
                self.world.lock().unwrap().target = None;
                Ok(())
            });
            if let Some(error) = clear_error {
                state.error = Some(error);
            }
            return Err("Hotspot was turned off while connecting relay".into());
        }
        if let Some(result) = self.world.lock().unwrap().joins.pop_front() {
            result?;
        }
        if let Some(mut session) = state.session.take() {
            self.cleanup(&mut session)?;
        }
        let mut session = Session::new(Path::new("/tmp/u60-test/work/relayctl/fake"));
        let prepare = self.world.lock().unwrap().prepare_hotspot;
        if prepare {
            cancel.check()?;
            self.world.lock().unwrap().pending = true;
            self.call("hotspot-prepare");
            self.call("join-boundary");
            if let Err(error) = cancel.check() {
                self.cleanup(&mut session)?;
                return Err(error);
            }
        }
        let paused = if allow_cellular_pause {
            self.world.lock().unwrap().cellular.as_mut()
                .filter(|cellular| cellular::enabled(cellular.dir.path()))
                .map_or(Ok(()), |cellular| cellular.set(true))
        } else {
            Ok(())
        };
        if let Err(error) = paused {
            return self.cleanup(&mut session).and(Err(error));
        }
        session.selected = Some(selection.network);
        session.lease = Some(lease());
        Ok(session)
    }
    fn persist(&mut self, selection: &Selection, ipv6: bool, _: bool) -> Option<String> {
        self.call("persist");
        self.world.lock().unwrap().target = Some(resume::Resume {
            ssid: selection.network.ssid.clone(),
            security: selection.network.security.into(),
            bssid: selection.network.bssid.clone(),
            ipv6,
        });
        None
    }
    fn cleanup(&mut self, _: &mut Session) -> Result<(), String> {
        self.call("cleanup");
        self.recover()
    }
    fn observe_link(&mut self) -> (Option<String>, u128) {
        self.call("observe");
        (
            self.world
                .lock()
                .unwrap()
                .observations
                .front()
                .and_then(|observation| observation.link.clone())
                .or_else(|| Some("COMPLETED".into())),
            0,
        )
    }
    fn observe(&mut self, _: &mut Session) -> Observation {
        self.world.lock().unwrap().observations.pop_front().unwrap_or_else(|| observation("COMPLETED"))
    }
    fn renew(&mut self, _: &mut Session) {
        self.call("renew");
    }
    fn maintain(&mut self, _: &mut Session, allow_cellular_pause: bool) -> Result<bool, String> {
        self.call("maintain");
        if allow_cellular_pause {
            if let Some(cellular) = self.world.lock().unwrap().cellular.as_mut() {
                let _ = cellular.reconcile();
            }
        }
        Ok(false)
    }
    fn prepare_slot_change(&mut self, state: &mut State) -> Result<(), String> {
        self.call("prepare-slot-change");
        if let Some(cellular) = self.world.lock().unwrap().cellular.as_mut() {
            if cellular.pause.error().is_some_and(|error| state.error.as_deref() == Some(error)) {
                state.error = None;
            }
            cellular.set(false)?;
            if cellular.dir.path().join(cellular::JOURNAL).exists() {
                return Err("cellular pause journal still present after cleanup".into());
            }
        }
        Ok(())
    }
    fn resume_slot_change(&mut self, state: &mut State) {
        self.call("resume-slot-change");
        if state.session.is_some() {
            if let Some(cellular) = self.world.lock().unwrap().cellular.as_mut() {
                if cellular::enabled(cellular.dir.path()) {
                    let _ = cellular.reconcile();
                }
            }
        }
    }
    fn uplink_changed(&self) {
        self.call("egress");
    }
    fn power_save(&mut self, _: &mut State, _: bool) -> Result<(), String> {
        self.call("power-save");
        Ok(())
    }
    fn strict_zero_cellular(&mut self, state: &mut State, enabled: bool) -> Result<(), String> {
        if let Some(cellular) = self.world.lock().unwrap().cellular.as_mut() {
            cellular::save(cellular.dir.path(), enabled)?;
            if state.session.is_some() || !enabled {
                cellular.set(enabled).map_err(|error| format!("Setting saved. {error}"))?;
            }
        }
        Ok(())
    }

    fn offload(&mut self, _: &mut State, _: bool) -> Result<Option<Value>, String> {
        self.call("offload");
        Ok(None)
    }
    fn forget(&mut self, _: &str) -> Result<(), String> {
        self.call("forget");
        Ok(())
    }
    fn clock(&mut self) -> Result<(), String> {
        self.call("clock");
        Ok(())
    }
}

fn network() -> Network {
    Network {
        id: "open".into(),
        ssid: "Test".into(),
        frequency: 5180,
        signal: -40,
        security: "open",
        supported: true,
        bssid: "02:00:00:00:00:01".into(),
    }
}

fn lease() -> Lease {
    Lease { ip: "10.0.0.2".parse().unwrap(), subnet: "255.255.255.0".parse().unwrap(), gateway: "10.0.0.1".parse().unwrap(), dns: vec![] }
}

fn observation(link: &str) -> Observation {
    Observation { link: Some(link.into()), lease: Some(lease()), helpers: true, resolvers_valid: true, hotspot_off: false, by_owner: false }
}

struct Harness {
    relay: Arc<WifiRelay>,
    port: FakePort,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Harness {
    fn new(mut world: World) -> Self {
        if world.scans.is_empty() {
            world.scans.push(network());
        }
        let relay = Arc::new(WifiRelay::new(Arc::new(crate::netfx::admission::Gate::new())));
        relay.shared.snapshot.lock().unwrap().scans = world.scans.clone();
        let port = FakePort { world: Arc::new(Mutex::new(world)), epoch: Instant::now() };
        let (sender, receiver) = mpsc::channel();
        assert!(relay.commands.set(sender.clone()).is_ok());
        let controller =
            Controller::new(port.clone(), receiver, sender, Arc::clone(&relay.shared), Arc::clone(&relay.lock), Timings::default());
        let thread = std::thread::spawn(move || controller.run());
        Self { relay, port, thread: Some(thread) }
    }

    fn pause(&self, name: &'static str) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered, ready) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        self.port.world.lock().unwrap().pause = Some((name, entered, blocked));
        (ready, release)
    }

    fn connect(&self) -> Result<(), String> {
        self.relay.connect_remembered("open", "", true, false, false)
    }
    fn calls(&self) -> Vec<String> {
        self.port.world.lock().unwrap().calls.clone()
    }
    fn barrier(&self) {
        self.relay.forget("barrier").unwrap();
    }

    fn until(&self, predicate: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !predicate() {
            assert!(Instant::now() < deadline, "controller did not finish the scripted step");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn tick(&self, observation: Observation, seconds: u64) {
        {
            let mut world = self.port.world.lock().unwrap();
            world.elapsed += Duration::from_secs(seconds);
            world.observations.push_back(observation);
        }
        self.relay.send(Message::Tick).unwrap();
        self.barrier();
    }

    fn restore(&self) -> (mpsc::Receiver<()>, std::thread::JoinHandle<()>) {
        let relay = Arc::clone(&self.relay);
        let (done, answer) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            relay.restore();
            done.send(()).unwrap();
        });
        (answer, thread)
    }

    fn advance(&self, seconds: u64) {
        self.port.world.lock().unwrap().elapsed += Duration::from_secs(seconds);
        self.relay.send(Message::Wake).unwrap();
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.relay.send(Message::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn strict_connect_returns_pause_failure_and_cleans_up_without_publishing_a_session() {
    let mut cellular = CellularFixture::new(true);
    cellular.modem.fail_write = true;
    let harness = Harness::new(World { cellular: Some(cellular), ..World::default() });

    assert_eq!(harness.connect(), Err("Cannot pause cellular data: write failed".into()));
    let status = harness.relay.status();
    assert_eq!(status["phase"], "idle");
    assert_eq!(status["connected"], false);
    assert_eq!(status["error"], "Cannot pause cellular data: write failed");
    let calls = harness.calls();
    assert!(calls.contains(&"enter cleanup".into()));
    assert!(!calls.contains(&"enter persist".into()));
    assert!(!calls.contains(&"enter egress".into()));
    let world = harness.port.world.lock().unwrap();
    let cellular = world.cellular.as_ref().unwrap();
    assert_eq!(cellular.modem.writes, [false]);
    assert!(!cellular.dir.path().join(cellular::JOURNAL).exists());
}

#[test]
fn enabling_strict_mode_on_a_live_relay_returns_and_publishes_the_pause_failure() {
    let mut cellular = CellularFixture::new(false);
    cellular.modem.fail_write = true;
    let harness = Harness::new(World { cellular: Some(cellular), ..World::default() });
    harness.connect().unwrap();

    assert_eq!(harness.relay.set_strict_zero_cellular(true), Err("Setting saved. Cannot pause cellular data: write failed".into()));
    let status = harness.relay.status();
    assert_eq!(status["connected"], true);
    assert_eq!(status["strict_zero_cellular"], true);
    assert_eq!(status["cellular_pause"], json!({"state":"error","original_enabled":true,"error":"Cannot pause cellular data: write failed"}));
}

#[test]
fn maintenance_publishes_a_restarted_modem_failure_and_clears_it_after_verified_repause() {
    let harness = Harness::new(World { cellular: Some(CellularFixture::new(true)), ..World::default() });
    harness.connect().unwrap();
    assert_eq!(harness.relay.status()["cellular_pause"]["state"], "paused");
    {
        let mut world = harness.port.world.lock().unwrap();
        let cellular = world.cellular.as_mut().unwrap();
        cellular.modem.on = true;
        cellular.modem.fail_write = true;
    }

    harness.tick(observation("COMPLETED"), 0);
    let status = harness.relay.status();
    assert_eq!(status["connected"], true);
    assert_eq!(status["cellular_pause"], json!({"state":"error","original_enabled":true,"error":"Cannot pause cellular data: write failed"}));
    harness.port.world.lock().unwrap().cellular.as_mut().unwrap().modem.fail_write = false;

    harness.tick(observation("COMPLETED"), 0);
    let status = harness.relay.status();
    assert_eq!(status["cellular_pause"], json!({"state":"paused","original_enabled":true,"error":null}));
    let world = harness.port.world.lock().unwrap();
    let cellular = world.cellular.as_ref().unwrap();
    assert_eq!(cellular.modem.writes, [false, false, false]);
    assert!(!cellular.modem.on);
    assert_eq!(fs::read(cellular.dir.path().join(cellular::JOURNAL)).unwrap(), b"1\n");
}

#[test]
fn slot_change_restores_strict_cellular_pause_and_blocks_repausing_during_handoff() {
    let harness = Harness::new(World { cellular: Some(CellularFixture::new(true)), ..World::default() });
    harness.connect().unwrap();
    assert_eq!(harness.relay.status()["cellular_pause"]["state"], "paused");
    {
        let world = harness.port.world.lock().unwrap();
        let cellular = world.cellular.as_ref().unwrap();
        assert!(!cellular.modem.on);
        assert!(cellular.dir.path().join(cellular::JOURNAL).exists());
    }

    // 1. If restoring cellular fails, slot change aborts BEFORE the callback,
    //    keeps `cellular-pause` on disk, and leaves the relay unlocked.
    harness.port.world.lock().unwrap().cellular.as_mut().unwrap().modem.fail_write = true;
    let mut callback_calls = 0usize;
    let err = harness
        .relay
        .before_slot_change(|| {
            callback_calls += 1;
            Ok(())
        })
        .unwrap_err();
    assert!(err.contains("relay slot-change cleanup failed"), "unexpected err: {err}");
    assert_eq!(callback_calls, 0);
    {
        let world = harness.port.world.lock().unwrap();
        let cellular = world.cellular.as_ref().unwrap();
        assert!(!cellular.modem.on);
        assert!(cellular.dir.path().join(cellular::JOURNAL).exists());
    }

    // 2. If the OTA callback itself fails after cellular was restored, the hold
    //    is released and strict zero-cellular re-pauses cellular cleanly.
    harness.port.world.lock().unwrap().cellular.as_mut().unwrap().modem.fail_write = false;
    let aborted = harness
        .relay
        .before_slot_change(|| -> Result<(), String> {
            let world = harness.port.world.lock().unwrap();
            let cellular = world.cellular.as_ref().unwrap();
            assert!(cellular.modem.on, "cellular must be restored before OTA callback runs");
            assert!(!cellular.dir.path().join(cellular::JOURNAL).exists());
            Err("simulated OTA launch error".into())
        })
        .unwrap_err();
    assert_eq!(aborted, "simulated OTA launch error");
    // Drain controller queue via a harmless status/tick cycle so ResumeSlotChange completes.
    harness.tick(observation("COMPLETED"), 0);
    assert_eq!(harness.relay.status()["cellular_pause"]["state"], "paused");
    {
        let world = harness.port.world.lock().unwrap();
        let cellular = world.cellular.as_ref().unwrap();
        assert!(!cellular.modem.on);
        assert!(cellular.dir.path().join(cellular::JOURNAL).exists());
    }

    // 3. On a successful slot change, cellular is restored and `cellular-pause`
    //    is removed BEFORE the callback, AND subsequent maintenance ticks or
    //    strict-mode writes CANNOT re-pause cellular while handoff proceeds!
    harness
        .relay
        .before_slot_change(|| {
            callback_calls += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(callback_calls, 1);
    assert_eq!(harness.relay.status()["cellular_pause"]["state"], "idle");
    // Periodic maintenance tick must NOT re-pause cellular.
    harness.tick(observation("COMPLETED"), 0);
    // Explicit strict-mode toggle must be refused during handoff.
    assert!(harness.relay.set_strict_zero_cellular(true).is_err());
    {
        let world = harness.port.world.lock().unwrap();
        let cellular = world.cellular.as_ref().unwrap();
        assert!(cellular.modem.on, "cellular must remain restored throughout slot handoff");
        assert!(
            !cellular.dir.path().join(cellular::JOURNAL).exists(),
            "cellular-pause journal must never be recreated during slot handoff"
        );
    }
}

#[test]
fn pending_ota_trial_defers_cellular_pause_until_commit_across_adopt_join_and_ticks() {
    // 1. Adoption during a pending trial must NOT pause cellular or create
    //    `cellular-pause`; once `pending` clears on commit, the next tick
    //    reconciles strict mode cleanly.
    let harness = Harness::new(World {
        adopted: true,
        cellular: Some(CellularFixture::new(true)),
        ..World::default()
    });
    // Start fresh with trial pending enabled before Boot adoption runs.
    let trial_world = Arc::new(Mutex::new(World {
        adopted: true,
        cellular: Some(CellularFixture::new(true)),
        ..World::default()
    }));
    let lock: NetworkLock = Arc::new(crate::netfx::admission::Gate::new());
    let shared = Arc::new(Shared::new());
    shared.test_ota_trial_pending.store(true, Ordering::SeqCst);
    let (sender, receiver) = mpsc::channel();
    let (boot_tx, boot_rx) = mpsc::sync_channel(1);
    boot(&sender, boot_tx);
    let relay = Arc::new(WifiRelay {
        lock: Arc::clone(&lock),
        shared: Arc::clone(&shared),
        commands: OnceLock::from(sender.clone()),
        mihomo: None,
        tailscale: None,
    });
    let port = FakePort { world: Arc::clone(&trial_world), epoch: Instant::now() };
    let controller = Controller::new(port, receiver, sender.clone(), Arc::clone(&shared), lock, Timings { tick: Duration::from_secs(3600), retries: vec![Duration::from_secs(1)] });
    let handle = std::thread::spawn(move || controller.run());
    boot_rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    {
        let world = trial_world.lock().unwrap();
        let cellular = world.cellular.as_ref().unwrap();
        assert!(cellular.modem.on, "adoption during pending OTA trial must not pause cellular");
        assert!(!cellular.dir.path().join(cellular::JOURNAL).exists());
    }
    // Strict-mode write is refused while trial is pending.
    assert!(relay.set_strict_zero_cellular(true).is_err());
    // Maintenance tick while trial is still pending must not pause cellular.
    let _ = relay.send(Message::Tick);
    let _ = relay.call(Command::Clock);
    {
        let world = trial_world.lock().unwrap();
        let cellular = world.cellular.as_ref().unwrap();
        assert!(cellular.modem.on);
        assert!(!cellular.dir.path().join(cellular::JOURNAL).exists());
    }
    // Once commit clears `pending`, the next tick reconciles strict mode!
    shared.test_ota_trial_pending.store(false, Ordering::SeqCst);
    let _ = relay.send(Message::Tick);
    let _ = relay.call(Command::Clock);
    {
        let world = trial_world.lock().unwrap();
        let cellular = world.cellular.as_ref().unwrap();
        assert!(!cellular.modem.on, "strict mode must reconcile after OTA commit");
        assert_eq!(fs::read(cellular.dir.path().join(cellular::JOURNAL)).unwrap(), b"1\n");
    }
    let _ = sender.send(Message::Stop);
    handle.join().unwrap();

    // 2. Join during a pending trial must also skip pausing cellular until commit.
    let join_harness = Harness::new(World {
        cellular: Some(CellularFixture::new(true)),
        ..World::default()
    });
    join_harness.relay.shared.test_ota_trial_pending.store(true, Ordering::SeqCst);
    join_harness.connect().unwrap();
    {
        let world = join_harness.port.world.lock().unwrap();
        let cellular = world.cellular.as_ref().unwrap();
        assert!(cellular.modem.on, "join during pending OTA trial must not pause cellular");
        assert!(!cellular.dir.path().join(cellular::JOURNAL).exists());
    }
    join_harness.relay.shared.test_ota_trial_pending.store(false, Ordering::SeqCst);
    join_harness.tick(observation("COMPLETED"), 0);
    {
        let world = join_harness.port.world.lock().unwrap();
        let cellular = world.cellular.as_ref().unwrap();
        assert!(!cellular.modem.on);
        assert!(cellular.dir.path().join(cellular::JOURNAL).exists());
    }
    drop(harness);
}

#[test]
fn aborted_slot_change_rearms_suppressed_relay_restore_attempt() {
    let harness = Harness::new(World {
        target: Some(resume::Resume {
            ssid: "Test".into(),
            security: "open".into(),
            bssid: "02:00:00:00:00:01".into(),
            ipv6: false,
        }),
        scans: vec![network()],
        // First attempt fails so attempt 1 is scheduled for the retry wait.
        joins: [Err("temporary AP miss".into())].into(),
        ..World::default()
    });
    let relay = Arc::clone(&harness.relay);
    let restore_thread = std::thread::spawn(move || relay.restore());
    // Wait until attempt 0 has failed and attempt 1 is scheduled (`restoring == Some("Test")`).
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let calls = harness.port.world.lock().unwrap().calls.clone();
        if calls.iter().any(|c| c == "exit join") && !harness.relay.status()["restoring"].is_null() {
            break;
        }
        assert!(Instant::now() < deadline, "restore did not schedule retry");
        std::thread::sleep(Duration::from_millis(5));
    }

    // Start a slot change that aborts AFTER the scheduled restore retry becomes
    // due (and also receives an explicit queued `Message::Retry`) while
    // `slot_change_paused` is active.
    let err = harness
        .relay
        .before_slot_change(|| -> Result<(), String> {
            harness.port.world.lock().unwrap().elapsed += Duration::from_secs(60);
            let _ = harness.relay.send(Message::Retry { generation: 0, attempt: 1 });
            // Synchronize with controller loop so both the timer check and the
            // queued `Message::Retry` are processed while `slot_change_paused == true`.
            assert!(harness.relay.set_strict_zero_cellular(true).is_err());
            assert_eq!(harness.relay.status()["connected"], false);
            Err("aborted OTA".into())
        })
        .unwrap_err();
    assert_eq!(err, "aborted OTA");

    // `ResumeSlotChange` MUST rearm the suppressed restore attempt so the
    // waiting restore thread finishes and connects instead of stranding!
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        restore_thread.join().unwrap();
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("suppressed restore must be rearmed and complete after aborted OTA");
    assert_eq!(harness.relay.status()["connected"], true);
}

#[test]
fn a_timed_out_request_never_runs_when_the_controller_frees_up_after_the_deadline() {
    let harness = Harness::new(World::default());
    let (entered, release) = harness.pause("scan");
    let relay = Arc::clone(&harness.relay);
    let scan = std::thread::spawn(move || relay.scan());
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let error = harness.relay.set_power_save(true).unwrap_err();
    let (code, value) = change_error(&harness.relay, error);
    assert_eq!(code, 409);
    assert_eq!(value["phase"], "scanning");
    release.send(()).unwrap();
    scan.join().unwrap().unwrap();
    harness.barrier();
    assert!(!harness.calls().iter().any(|call| call.contains("power-save")));
}

#[test]
fn disconnect_during_join_discards_late_success_and_cleans_before_the_next_connect() {
    let harness = Harness::new(World::default());
    let (entered, release) = harness.pause("join");
    let relay = Arc::clone(&harness.relay);
    let join = std::thread::spawn(move || relay.connect_remembered("open", "", true, false, false));
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let started = Instant::now();
    for _ in 0..5 {
        harness.relay.disconnect().unwrap();
    }
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(harness.relay.status()["phase"], "disconnecting");
    assert_eq!(harness.relay.status()["recovery_required"], false);
    let relay = Arc::clone(&harness.relay);
    let next = std::thread::spawn(move || relay.connect_remembered("open", "", true, false, false));
    release.send(()).unwrap();
    assert_eq!(join.join().unwrap().unwrap_err(), RESTORE_CANCELLED);
    next.join().unwrap().unwrap();
    let calls = harness.calls();
    assert_eq!(calls.iter().filter(|call| call.as_str() == "enter persist").count(), 1);
    assert!(calls.iter().position(|call| call == "enter cleanup").unwrap() < calls.iter().rposition(|call| call == "enter join").unwrap());
    assert_eq!(harness.relay.status()["phase"], "active");
}

#[test]
fn disconnect_during_hotspot_preparation_waits_for_the_join_boundary_before_cleanup() {
    let harness = Harness::new(World { prepare_hotspot: true, ..World::default() });
    let (entered, release) = harness.pause("hotspot-prepare");
    let relay = Arc::clone(&harness.relay);
    let (done, answer) = mpsc::channel();
    let join = std::thread::spawn(move || done.send(relay.connect_remembered("open", "", true, false, false)).unwrap());
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(harness.relay.status()["phase"], "connecting");
    harness.relay.disconnect().unwrap();
    assert_eq!(harness.relay.status()["phase"], "disconnecting");
    assert_eq!(harness.relay.status()["recovery_required"], false);
    assert!(answer.recv_timeout(Duration::from_millis(100)).is_err(), "disconnect cannot interrupt the blocked port step");
    assert_eq!(harness.calls(), ["enter join", "exit join", "enter hotspot-prepare"]);
    release.send(()).unwrap();
    assert_eq!(answer.recv_timeout(Duration::from_secs(2)).unwrap().unwrap_err(), RESTORE_CANCELLED);
    join.join().unwrap();
    let calls = harness.calls();
    let position = |event: &str| calls.iter().position(|call| call == event).unwrap();
    assert!(position("exit hotspot-prepare") < position("enter join-boundary"));
    assert!(position("exit join-boundary") < position("enter cleanup"));
    assert_eq!(calls.iter().filter(|call| call.as_str() == "enter cleanup").count(), 1);
    assert!(!calls.contains(&"enter persist".into()));
    assert_eq!(harness.relay.status()["phase"], "idle");
    assert_eq!(harness.relay.status()["recovery_required"], false);
    assert!(!harness.port.world.lock().unwrap().pending);
}

#[test]
fn cancellation_between_scan_rounds_cleans_the_temporary_session() {
    let harness = Harness::new(World { scan_rounds: true, ..World::default() });
    let (entered, release) = harness.pause("scan-round-1");
    let relay = Arc::clone(&harness.relay);
    let scan = std::thread::spawn(move || relay.scan());
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    harness.relay.disconnect().unwrap();
    release.send(()).unwrap();
    assert_eq!(scan.join().unwrap().unwrap_err(), RESTORE_CANCELLED);
    let calls = harness.calls();
    assert!(calls.contains(&"exit scan-round-1".into()));
    assert!(!calls.contains(&"enter scan-round-2".into()));
    assert_eq!(calls.iter().filter(|call| call.as_str() == "enter cleanup").count(), 1);
    assert_eq!(harness.relay.status()["phase"], "idle");
    assert_eq!(harness.relay.status()["recovery_required"], false);
    assert!(!harness.port.world.lock().unwrap().pending);
}

#[test]
fn an_idle_disconnect_waits_for_teardown_and_returns_its_error() {
    let harness = Harness::new(World { cleanup_error: Some("retained journal".into()), pending: true, ..World::default() });
    let (entered, release) = harness.pause("recover");
    let relay = Arc::clone(&harness.relay);
    let (result, answer) = mpsc::channel();
    let thread = std::thread::spawn(move || result.send(relay.disconnect()).unwrap());
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(answer.try_recv().is_err());
    harness.relay.disconnect().unwrap();
    release.send(()).unwrap();
    assert_eq!(answer.recv_timeout(Duration::from_secs(2)).unwrap().unwrap_err(), "retained journal");
    thread.join().unwrap();
    assert!(harness.relay.owns_network());
    assert_eq!(harness.relay.status()["phase"], "recovery_pending");
}

#[test]
fn status_and_admission_are_answered_during_a_sixty_second_port_wait() {
    let harness = Harness::new(World::default());
    let (entered, release) = harness.pause("scan");
    let relay = Arc::clone(&harness.relay);
    let thread = std::thread::spawn(move || relay.scan());
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let started = Instant::now();
    assert_eq!(harness.relay.status()["phase"], "scanning");
    assert!(harness.relay.owns_network());
    assert!(crate::netfx::admission::enter(&harness.relay.lock, Duration::ZERO).is_some());
    assert!(started.elapsed() < Duration::from_millis(100));
    release.send(()).unwrap();
    thread.join().unwrap().unwrap();
}

fn target() -> resume::Resume {
    let network = network();
    resume::Resume { ssid: network.ssid, security: network.security.into(), bssid: network.bssid, ipv6: false }
}

#[test]
fn operations_and_ticks_run_in_arrival_order_without_overlap() {
    let harness = Harness::new(World::default());
    let (entered, release) = harness.pause("scan");
    let relay = Arc::clone(&harness.relay);
    let worker = std::thread::spawn(move || relay.scan());
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let (reply, answer) = mpsc::sync_channel(1);
    let generation = harness.relay.shared.cancel.lock().unwrap().restore_generation;
    harness
        .relay
        .send(Message::Request(Request {
            command: Command::Connect {
                selection: Selection::from(&[network()], "open", "").unwrap(),
                ipv6: false,
                remember: false,
                generation,
            },
            reply,
            started: Start::pending(None),
            deadline: None,
        }))
        .unwrap();
    harness.relay.send(Message::Tick).unwrap();
    release.send(()).unwrap();
    worker.join().unwrap().unwrap();
    answer.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    harness.barrier();
    let calls = harness.calls();
    assert!(calls.iter().position(|call| call == "exit scan").unwrap() < calls.iter().position(|call| call == "enter join").unwrap());
    assert!(calls.iter().position(|call| call == "exit join").unwrap() < calls.iter().position(|call| call == "enter observe").unwrap());
    for pair in calls.chunks_exact(2) {
        assert_eq!(pair[0].strip_prefix("enter "), pair[1].strip_prefix("exit "));
    }
}

#[test]
fn boot_runs_first_without_a_barrier_and_the_second_boot_is_idempotent() {
    for adopted in [false, true] {
        let relay = Arc::new(WifiRelay::new(Arc::new(crate::netfx::admission::Gate::new())));
        let port = FakePort { world: Arc::new(Mutex::new(World { adopted, ..World::default() })), epoch: Instant::now() };
        let (sender, receiver) = mpsc::channel();
        let (reply, answer) = mpsc::sync_channel(1);
        boot(&sender, reply);
        assert!(relay.commands.set(sender.clone()).is_ok());
        let controller =
            Controller::new(port.clone(), receiver, sender, Arc::clone(&relay.shared), Arc::clone(&relay.lock), Timings::default());
        let thread = std::thread::spawn(move || controller.run());
        answer.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        let before = port.world.lock().unwrap().calls.clone();
        assert_eq!(before[0], "enter adopt");
        assert_eq!(before.iter().filter(|call| call.as_str() == "enter recover").count(), usize::from(!adopted));
        relay.recover_idle();
        assert_eq!(port.world.lock().unwrap().calls, before);
        relay.send(Message::Stop).unwrap();
        thread.join().unwrap();
    }
}

#[test]
fn restore_cancel_is_immediate_and_stale_results_cannot_overwrite_owner_state() {
    let harness = Harness::new(World { target: Some(target()), ..World::default() });
    let (entered, release) = harness.pause("join");
    let (answer, thread) = harness.restore();
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    harness.relay.disconnect().unwrap();
    assert!(harness.relay.status()["restoring"].is_null());
    release.send(()).unwrap();
    answer.recv_timeout(Duration::from_secs(2)).unwrap();
    thread.join().unwrap();
    harness.barrier();
    assert_eq!(harness.relay.status()["connected"], false);
    assert!(!harness.calls().contains(&"enter persist".into()));
    assert!(harness.port.world.lock().unwrap().target.is_none());
}

#[test]
fn restore_wait_is_woken_by_cancel_instead_of_waiting_five_minutes() {
    let harness = Harness::new(World { target: Some(target()), off: (true, false), ..World::default() });
    let (answer, thread) = harness.restore();
    harness.until(|| harness.relay.status()["restoring"].is_string());
    harness.relay.disconnect().unwrap();
    answer.recv_timeout(Duration::from_secs(2)).unwrap();
    thread.join().unwrap();
    assert!(harness.relay.status()["restoring"].is_null());
}

#[test]
fn restore_rechecks_changed_target_and_same_target_owner_replacement() {
    let temp = crate::wifi_relay::test_dir::TestDir::new("restore-target");
    let root = temp.path();
    resume::save(root, &network(), false).unwrap();
    let shared = Arc::new(Shared::new());
    let port = DevicePort { control: None, settings: None, cellular_pause: cellular::Pause::default(), cellular_deferred_by_trial: false, shared: Arc::clone(&shared), mihomo: None, tailscale: None };
    let cancel = Cancellation { shared: Arc::clone(&shared), generation: 0, target: Some(target()) };
    assert!(cancel.check().is_ok());
    let mut changed = network();
    changed.ssid = "Changed".into();
    resume::save(root, &changed, false).unwrap();
    assert_ne!(resume::load(root), cancel.target);
    shared.cancel_restore();
    resume::save(root, &network(), false).unwrap();
    assert_eq!(resume::load(root), cancel.target);
    assert_eq!(port.check(&cancel).unwrap_err(), RESTORE_CANCELLED);
}

#[test]
fn restore_retries_follow_every_offset_and_serve_requests_between_attempts() {
    let harness = Harness::new(World {
        target: Some(target()),
        joins: (0..10).map(|_| Err("upstream unavailable".into())).collect(),
        ..World::default()
    });
    let (answer, thread) = harness.restore();
    for (attempt, wait) in RESTORE_WAITS.into_iter().enumerate() {
        if wait != 0 {
            harness.advance(wait - 1);
            harness.barrier();
            assert_eq!(harness.calls().iter().filter(|call| call.as_str() == "exit join").count(), attempt);
            harness.advance(1);
        }
        harness.until(|| harness.calls().iter().filter(|call| call.as_str() == "exit join").count() == attempt + 1);
        harness.barrier();
        if attempt != 9 {
            assert!(answer.try_recv().is_err());
        }
    }
    answer.recv_timeout(Duration::from_secs(2)).unwrap();
    thread.join().unwrap();
    assert!(harness.port.world.lock().unwrap().target.is_some());
    assert!(harness.relay.status()["error"].as_str().unwrap().contains("Could not reconnect"));
}

#[test]
fn restore_distinguishes_owner_off_firmware_off_and_missing_password() {
    for owner in [true, false] {
        let harness = Harness::new(World { target: Some(target()), off: (true, owner), ..World::default() });
        let (answer, thread) = harness.restore();
        if owner {
            answer.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(harness.port.world.lock().unwrap().target.is_none());
        } else {
            harness.until(|| harness.relay.status()["restoring"].is_string());
            harness.barrier();
            assert!(harness.port.world.lock().unwrap().target.is_some());
            assert!(!harness.calls().contains(&"enter scan".into()));
            harness.relay.disconnect().unwrap();
            answer.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        thread.join().unwrap();
    }
    let harness = Harness::new(World { target: Some(target()), joins: [Err(RESTORE_NO_PASSWORD.into())].into(), ..World::default() });
    let (answer, thread) = harness.restore();
    answer.recv_timeout(Duration::from_secs(2)).unwrap();
    thread.join().unwrap();
    harness.barrier();
    assert_eq!(harness.calls().iter().filter(|call| call.as_str() == "enter join").count(), 1);
    assert!(harness.relay.status()["error"].as_str().unwrap().contains(RESTORE_NO_PASSWORD));
}

#[test]
fn firmware_shutdown_preserves_target_and_retries_until_wifi_returns_after_boot() {
    let before_reboot = Harness::new(World::default());
    before_reboot.connect().unwrap();
    let mut shutdown = observation("COMPLETED");
    shutdown.hotspot_off = true;
    shutdown.by_owner = false;
    before_reboot.tick(shutdown, 0);
    assert_eq!(before_reboot.relay.status()["phase"], "idle");
    let saved = before_reboot.port.world.lock().unwrap().target.clone();
    assert!(saved.is_some(), "firmware power-off must keep resume target");

    let after_reboot = Harness::new(World { target: saved, off: (true, false), ..World::default() });
    let (answer, thread) = after_reboot.restore();
    after_reboot.until(|| after_reboot.relay.status()["restoring"].is_string());
    after_reboot.barrier();
    assert!(after_reboot.port.world.lock().unwrap().target.is_some());
    after_reboot.port.world.lock().unwrap().off = (false, false);
    after_reboot.advance(RESTORE_WAITS[1]);
    answer.recv_timeout(Duration::from_secs(2)).unwrap();
    thread.join().unwrap();
    assert_eq!(after_reboot.relay.status()["phase"], "active");
    assert!(after_reboot.relay.status()["restoring"].is_null());
}

#[test]
fn temporary_hotspot_off_during_join_retries_and_recovers_in_same_boot() {
    let harness = Harness::new(World {
        target: Some(target()),
        off: (false, false),
        off_during_join: Some((true, false)),
        ..World::default()
    });
    let (answer, thread) = harness.restore();
    harness.until(|| harness.calls().contains(&"exit join".into()));
    harness.barrier();
    assert!(answer.try_recv().is_err());
    assert!(harness.relay.status()["restoring"].is_string());
    assert!(harness.port.world.lock().unwrap().target.is_some());
    assert!(harness.relay.shared.generation_matches(0));

    harness.port.world.lock().unwrap().off = (false, false);
    harness.advance(RESTORE_WAITS[1]);
    answer.recv_timeout(Duration::from_secs(2)).unwrap();
    thread.join().unwrap();
    assert_eq!(harness.relay.status()["phase"], "active");
    assert!(harness.relay.status()["restoring"].is_null());
    assert_eq!(harness.calls().iter().filter(|call| call.as_str() == "enter join").count(), 2);

    let owner_off = Harness::new(World {
        target: Some(target()),
        off: (false, false),
        off_during_join: Some((true, true)),
        ..World::default()
    });
    let (owner_answer, owner_thread) = owner_off.restore();
    owner_answer.recv_timeout(Duration::from_secs(2)).unwrap();
    owner_thread.join().unwrap();
    assert!(owner_off.port.world.lock().unwrap().target.is_none());
    assert!(owner_off.relay.status()["restoring"].is_null());
    assert_eq!(owner_off.calls().iter().filter(|call| call.as_str() == "enter join").count(), 1);
}

#[test]
fn an_owner_connect_cancels_the_restore_schedule_within_one_turn() {
    let harness = Harness::new(World { target: Some(target()), joins: [Err("not ready".into())].into(), ..World::default() });
    let (answer, thread) = harness.restore();
    harness.until(|| harness.calls().contains(&"exit join".into()));
    harness.barrier();
    harness.connect().unwrap();
    answer.recv_timeout(Duration::from_secs(2)).unwrap();
    thread.join().unwrap();
    assert_eq!(harness.relay.status()["phase"], "active");
    assert!(harness.relay.status()["restoring"].is_null());
}

#[test]
fn scripted_observations_cover_grace_renewal_dns_helpers_and_hotspot_shutdown() {
    let harness = Harness::new(World::default());
    harness.connect().unwrap();
    harness.tick(observation("SCANNING"), 0);
    assert_eq!(harness.relay.status()["phase"], "recovering");
    harness.tick(observation("COMPLETED"), 11);
    assert_eq!(harness.relay.status()["phase"], "active");
    assert!(harness.calls().contains(&"enter renew".into()));
    let mut dns = observation("COMPLETED");
    dns.lease.as_mut().unwrap().dns = vec![lease().gateway, "10.0.0.53".parse().unwrap()];
    harness.tick(dns, 0);
    assert_eq!(harness.relay.status()["phase"], "active");
    harness.tick(observation("SCANNING"), 0);
    harness.tick(observation("SCANNING"), 12);
    assert_eq!(harness.relay.status()["phase"], "idle");
    assert!(harness.port.world.lock().unwrap().target.is_some());
    for failure in ["helpers", "address", "owner", "firmware"] {
        harness.connect().unwrap();
        let mut next = observation("COMPLETED");
        match failure {
            "helpers" => next.helpers = false,
            "address" => next.lease.as_mut().unwrap().ip = "10.0.0.3".parse().unwrap(),
            "owner" => {
                next.hotspot_off = true;
                next.by_owner = true;
            }
            _ => next.hotspot_off = true,
        }
        harness.tick(next, 0);
        assert_eq!(harness.relay.status()["phase"], "idle", "{failure}");
        assert_eq!(harness.port.world.lock().unwrap().target.is_some(), failure != "owner");
    }
}

#[test]
fn a_port_panic_reaches_the_abort_hook_and_stops_processing() {
    let shared = Arc::new(Shared::new());
    let port = FakePort { world: Arc::new(Mutex::new(World { panic: true, ..World::default() })), epoch: Instant::now() };
    let (sender, receiver) = mpsc::channel();
    let (reply, _) = mpsc::sync_channel(1);
    boot(&sender, reply);
    let (reply, _) = mpsc::sync_channel(1);
    boot(&sender, reply);
    let controller = Controller::new(port.clone(), receiver, sender, shared, Arc::new(crate::netfx::admission::Gate::new()), Timings::default());
    let (ended, answer) = mpsc::channel();
    let thread = std::thread::spawn(move || controller.supervised(|why| ended.send(why).unwrap()));
    assert_eq!(answer.recv_timeout(Duration::from_secs(2)).unwrap(), "scripted port panic");
    thread.join().unwrap();
    assert_eq!(port.world.lock().unwrap().calls, ["enter adopt"]);
}

#[test]
fn invalid_owner_connect_preserves_the_current_recovery_generation() {
    let harness = Harness::new(World::default());
    harness.relay.shared.cancel.lock().unwrap().restoring = Some("Test".into());
    assert!(harness.relay.connect_remembered("missing", "", true, false, false).is_err());
    assert!(harness.relay.connect_remembered("open", "unexpected", true, false, false).is_err());
    assert_eq!(harness.relay.shared.cancel.lock().unwrap().restore_generation, 0);
    assert!(harness.calls().is_empty());
}

#[test]
fn every_owner_request_stops_waiting_for_an_operation_and_reports_its_phase() {
    let harness = Harness::new(World::default());
    let (entered, release) = harness.pause("scan");
    let relay = Arc::clone(&harness.relay);
    let thread = std::thread::spawn(move || relay.scan());
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    for action in ["scan", "connect", "power-save", "offload", "forget", "clock"] {
        let started = Instant::now();
        let result = match action {
            "scan" => harness.relay.scan(),
            "connect" => harness.connect(),
            "power-save" => harness.relay.set_power_save(true),
            "offload" => harness.relay.set_offload_enabled(true).map(|_| ()),
            "forget" => harness.relay.forget("missing"),
            _ => harness.relay.recheck_clock(),
        };
        let (code, value) = change_error(&harness.relay, result.unwrap_err());
        assert_eq!((code, value["phase"].as_str()), (409, Some("scanning")), "{action}");
        assert!(started.elapsed() >= crate::netfx::admission::WAIT && started.elapsed() < Duration::from_secs(1));
    }
    release.send(()).unwrap();
    assert_eq!(thread.join().unwrap().unwrap_err(), RESTORE_CANCELLED);
    harness.barrier();
    assert_eq!(harness.calls(), ["enter scan", "exit scan", "enter forget", "exit forget"]);
}

#[test]
fn published_phases_do_not_report_journals_as_failed_recovery_during_work() {
    let shared = Shared::new();
    let mut state = State::default();
    for phase in
        [Phase::Scanning, Phase::Connecting, Phase::Active, Phase::Recovering, Phase::Disconnecting, Phase::Idle, Phase::RecoveryPending]
    {
        state.phase = phase;
        let cancel = shared.cancel.lock().unwrap();
        shared.publish(&state, snapshot(&state, BootClock.now()), true, &cancel);
        assert_eq!(shared.snapshot.lock().unwrap().value["recovery_required"], matches!(phase, Phase::Idle | Phase::RecoveryPending));
    }
}

#[test]
fn clock_recheck_requires_a_stable_connected_relay_without_restarting_it() {
    let harness = Harness::new(World::default());
    assert_eq!(harness.relay.recheck_clock().unwrap_err(), "Connect Wi-Fi relay before checking time");
    harness.connect().unwrap();
    let before = harness.calls().len();
    harness.relay.recheck_clock().unwrap();
    assert_eq!(harness.calls()[before..], ["enter clock", "exit clock"]);
    assert_eq!(harness.relay.status()["phase"], "active");
}

#[test]
fn status_reads_only_memory_while_tick_and_conntrack_reset_are_locked() {
    let harness = Harness::new(World::default());
    harness.connect().unwrap();
    let (entered, release) = harness.pause("observe");
    harness.relay.send(Message::Tick).unwrap();
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    crate::netfx::conntrack::while_reset_locked(|| {
        let started = Instant::now();
        assert_eq!(harness.relay.status()["connected"], true);
        assert!(harness.relay.active() && harness.relay.owns_network());
        harness.relay.disconnect().unwrap();
        assert!(started.elapsed() < Duration::from_millis(200));
    });
    release.send(()).unwrap();
    harness.barrier();
}

#[test]
fn status_reads_do_not_wait_for_ipv6_network_effects() {
    let harness = Harness::new(World::default());
    harness.connect().unwrap();
    let (entered, release) = harness.pause("maintain");
    harness.relay.send(Message::Tick).unwrap();
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let started = Instant::now();
    assert_eq!(harness.relay.status()["connected"], true);
    assert!(started.elapsed() < Duration::from_millis(100));
    release.send(()).unwrap();
    harness.barrier();
}

#[test]
fn admission_and_cancellation_do_not_wait_for_the_tick_state_lock() {
    let harness = Harness::new(World::default());
    harness.connect().unwrap();
    let (entered, release) = harness.pause("maintain");
    harness.relay.send(Message::Tick).unwrap();
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let started = Instant::now();
    assert!(harness.relay.active() && harness.relay.owns_network());
    harness.relay.shared.cancel_restore();
    assert!(started.elapsed() < Duration::from_millis(100));
    release.send(()).unwrap();
    harness.barrier();
}

#[test]
fn a_connect_validates_during_tick_and_uses_the_same_wait_without_late_device_work() {
    let harness = Harness::new(World::default());
    harness.connect().unwrap();
    let generation = harness.relay.shared.cancel.lock().unwrap().restore_generation;
    let (entered, release) = harness.pause("maintain");
    harness.relay.send(Message::Tick).unwrap();
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(harness.relay.connect_remembered("invalid", "", true, false, false).is_err());
    assert_eq!(harness.relay.shared.cancel.lock().unwrap().restore_generation, generation);
    let started = Instant::now();
    let error = harness.connect().unwrap_err();
    assert!(started.elapsed() >= crate::netfx::admission::WAIT && started.elapsed() < Duration::from_secs(1));
    assert_eq!(change_error(&harness.relay, error).0, 409);
    assert_eq!(harness.relay.shared.cancel.lock().unwrap().restore_generation, generation + 1);
    release.send(()).unwrap();
    harness.barrier();
    assert_eq!(harness.calls().iter().filter(|call| call.as_str() == "enter join").count(), 1);
}

#[test]
fn disconnect_returns_immediately_during_teardown_and_invalidates_late_success() {
    let harness = Harness::new(World::default());
    harness.connect().unwrap();
    let generation = harness.relay.shared.cancel.lock().unwrap().restore_generation;
    let (entered, release) = harness.pause("cleanup");
    let relay = Arc::clone(&harness.relay);
    let thread = std::thread::spawn(move || relay.disconnect());
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    for _ in 0..5 {
        let started = Instant::now();
        harness.relay.disconnect().unwrap();
        assert!(started.elapsed() < Duration::from_millis(100));
    }
    assert!(!harness.relay.shared.generation_matches(generation));
    assert_eq!(harness.relay.status()["phase"], "disconnecting");
    assert_eq!(harness.relay.status()["connected"], false);
    release.send(()).unwrap();
    thread.join().unwrap().unwrap();
    harness.barrier();
    assert_eq!(harness.calls().iter().filter(|call| call.as_str() == "enter cleanup").count(), 1);
}

#[test]
fn an_operation_publishes_its_phase_until_the_holder_finishes() {
    let harness = Harness::new(World::default());
    for operation in ["scan", "join", "cleanup"] {
        let (entered, release) = harness.pause(operation);
        let relay = Arc::clone(&harness.relay);
        let thread = std::thread::spawn(move || match operation {
            "scan" => relay.scan(),
            "join" => relay.connect_remembered("open", "", true, false, false),
            _ => relay.disconnect(),
        });
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        let expected = match operation {
            "scan" => "scanning",
            "join" => "connecting",
            _ => "disconnecting",
        };
        assert_eq!(harness.relay.status()["phase"], expected);
        assert_eq!(harness.relay.status()["recovery_required"], false);
        release.send(()).unwrap();
        thread.join().unwrap().unwrap();
    }
    assert_eq!(harness.relay.status()["phase"], "idle");
}

#[test]
fn the_holder_completes_a_busy_disconnect_before_releasing_the_operation() {
    let harness = Harness::new(World::default());
    harness.connect().unwrap();
    let (entered, release) = harness.pause("scan");
    let relay = Arc::clone(&harness.relay);
    let thread = std::thread::spawn(move || relay.scan());
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    harness.relay.disconnect().unwrap();
    assert!(harness.relay.shared.cancel.lock().unwrap().disconnect);
    release.send(()).unwrap();
    assert_eq!(thread.join().unwrap().unwrap_err(), RESTORE_CANCELLED);
    assert_eq!(harness.relay.status()["phase"], "idle");
    assert!(!harness.relay.active());
    assert!(harness.calls().contains(&"exit cleanup".into()));
}

#[tokio::test]
async fn four_disconnects_cannot_fill_the_general_lane_behind_teardown() {
    use crate::httpd::gate::{Gate, Lane};
    use crate::server::{lane, route, Method};
    let harness = Harness::new(World::default());
    harness.connect().unwrap();
    let mut state = crate::handlers::AppState::new();
    state.wifi_relay = Arc::clone(&harness.relay);
    let state = Arc::new(state);
    let (entered, release) = harness.pause("cleanup");
    let relay = Arc::clone(&harness.relay);
    let teardown = std::thread::spawn(move || relay.disconnect());
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let gate = Arc::new(Gate::new(4, 2, Duration::from_millis(200)));
    let mut requests = Vec::new();
    for _ in 0..5 {
        let gate = Arc::clone(&gate);
        let state = Arc::clone(&state);
        requests.push(tokio::spawn(async move {
            gate.run(lane(Method::Post, "/api/wifi-relay/disconnect"), move || {
                route(&Method::Post, "/api/wifi-relay/disconnect", &state, b"{}")
            })
            .await
        }));
    }
    for request in requests {
        assert_eq!(request.await.unwrap().unwrap().0, 200);
    }
    let status_state = Arc::clone(&state);
    assert_eq!(gate.run(Lane::General, move || route(&Method::Get, "/api/wifi-relay/status", &status_state, b"")).await.unwrap().0, 200);
    assert_eq!(gate.available(Lane::General), 4);
    release.send(()).unwrap();
    teardown.join().unwrap().unwrap();
}

#[test]
fn a_request_started_at_the_deadline_wins_once_and_waits_for_its_result() {
    let harness = Harness::new(World::default());
    let (entered, release) = harness.pause("scan");
    let relay = Arc::clone(&harness.relay);
    let (done, answer) = mpsc::channel();
    let thread = std::thread::spawn(move || done.send(relay.scan()).unwrap());
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::sleep(crate::netfx::admission::WAIT + Duration::from_millis(10));
    assert!(answer.try_recv().is_err());
    release.send(()).unwrap();
    answer.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    thread.join().unwrap();
}

#[test]
fn subscription_dns_follows_adoption_renewal_errors_and_teardown_at_publication() {
    let harness = Harness::new(World { adopted: true, record_subscription_dns: true, ..World::default() });
    harness.relay.recover_idle();
    assert_eq!(harness.calls(), ["enter adopt", "exit adopt", "subscription DNS [10.0.0.1]"]);

    let mut renewed = observation("COMPLETED");
    renewed.lease.as_mut().unwrap().dns = vec!["10.0.0.1".parse().unwrap(), "10.0.0.53".parse().unwrap()];
    harness.tick(renewed, 1);
    let calls = harness.calls();
    assert!(calls.windows(2).any(|trace| trace == ["exit maintain", "subscription DNS [10.0.0.1, 10.0.0.53]"]));

    harness.relay.disconnect().unwrap();
    let calls = harness.calls();
    assert!(calls.windows(2).any(|trace| trace == ["subscription DNS []", "enter cleanup"]));
    assert_eq!(calls.last().map(String::as_str), Some("subscription DNS []"));

    harness.port.world.lock().unwrap().joins.push_back(Err("association failed".into()));
    assert_eq!(harness.connect().unwrap_err(), "association failed");
    let calls = harness.calls();
    assert!(calls.ends_with(&["exit join".into(), "subscription DNS []".into()]));

    harness.connect().unwrap();
    let calls = harness.calls();
    assert!(calls.ends_with(&["subscription DNS [10.0.0.1]".into(), "enter egress".into(), "exit egress".into()]));
}

#[test]
fn a_new_owner_during_snapshot_build_cannot_publish_the_previous_join() {
    let harness = Harness::new(World { record_subscription_dns: true, ..World::default() });
    let (entered, release) = harness.pause("snapshot");
    let relay = Arc::clone(&harness.relay);
    let thread = std::thread::spawn(move || relay.connect_remembered("open", "", true, false, false));
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    harness.relay.shared.cancel_restore();
    release.send(()).unwrap();
    assert_eq!(thread.join().unwrap().unwrap_err(), RESTORE_CANCELLED);
    assert_eq!(harness.relay.status()["connected"], false);
    assert!(harness.port.world.lock().unwrap().target.is_none());
    let calls = harness.calls();
    assert!(calls.windows(2).any(|trace| trace == ["subscription DNS [10.0.0.1]", "enter snapshot"]));
    assert_eq!(calls.last().map(String::as_str), Some("subscription DNS []"));
    assert!(!harness.calls().contains(&"enter egress".into()));
}

#[test]
fn an_expired_request_is_abandoned_even_when_its_waiter_has_not_run_yet() {
    let harness = Harness::new(World::default());
    let (reply, answer) = mpsc::sync_channel(1);
    let start = Start::pending(None);
    harness
        .relay
        .send(Message::Request(Request {
            command: Command::PowerSave(true),
            reply,
            started: Arc::clone(&start),
            deadline: Some(Instant::now() - Duration::from_nanos(1)),
        }))
        .unwrap();
    let error = answer.recv_timeout(Duration::from_secs(2)).unwrap().unwrap_err();
    assert_eq!(change_error(&harness.relay, error).0, 409);
    assert!(start.lock().unwrap().state == Started::Abandoned);
    assert!(harness.calls().is_empty());
}

#[test]
fn abandoned_requests_release_admission_before_the_controller_dequeues_them() {
    let relay = Arc::new(WifiRelay::new(Arc::new(crate::netfx::admission::Gate::new())));
    let (sender, receiver) = mpsc::channel();
    assert!(relay.commands.set(sender).is_ok());
    let worker = Arc::clone(&relay);
    let thread = std::thread::spawn(move || worker.set_power_save(true));
    let Message::Request(request) = receiver.recv_timeout(Duration::from_secs(2)).unwrap() else { panic!("expected owner request") };
    assert!(request.started.lock().unwrap().claim.is_some());
    assert_eq!(change_error(&relay, thread.join().unwrap().unwrap_err()).0, 409);
    let start = request.started.lock().unwrap();
    assert!(start.state == Started::Abandoned && start.claim.is_none());
}

#[test]
fn restore_checks_changed_target_before_the_next_scan() {
    let harness = Harness::new(World { target: Some(target()), joins: [Err("not ready".into())].into(), ..World::default() });
    let (answer, thread) = harness.restore();
    harness.until(|| harness.calls().contains(&"exit join".into()));
    harness.barrier();
    harness.port.world.lock().unwrap().target.as_mut().unwrap().ssid = "Changed".into();
    harness.advance(10);
    answer.recv_timeout(Duration::from_secs(2)).unwrap();
    thread.join().unwrap();
    assert_eq!(harness.calls().iter().filter(|call| call.as_str() == "enter scan").count(), 1);
}

#[test]
fn cancellation_during_persistence_reports_a_failed_intent_clear() {
    let harness = Harness::new(World { clear_error: Some("Cannot clear the relay to restore".into()), ..World::default() });
    let (entered, release) = harness.pause("persist");
    let relay = Arc::clone(&harness.relay);
    let thread = std::thread::spawn(move || relay.connect_remembered("open", "", true, false, false));
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    harness.relay.shared.cancel_restore();
    release.send(()).unwrap();
    assert_eq!(thread.join().unwrap().unwrap_err(), "Cannot clear the relay to restore");
    assert_eq!(harness.relay.status()["connected"], false);
    assert_eq!(harness.relay.status()["error"], "Cannot clear the relay to restore");
}

#[test]
fn ticks_run_only_with_a_selected_session_at_three_second_deadlines() {
    let harness = Harness::new(World::default());
    harness.advance(30);
    harness.barrier();
    assert!(!harness.calls().contains(&"enter observe".into()));
    harness.connect().unwrap();
    harness.advance(2);
    harness.barrier();
    assert!(!harness.calls().contains(&"enter observe".into()));
    harness.advance(1);
    harness.until(|| harness.calls().contains(&"exit observe".into()));
    harness.barrier();
    harness.relay.disconnect().unwrap();
    harness.advance(30);
    harness.barrier();
    assert_eq!(harness.calls().iter().filter(|call| call.as_str() == "enter observe").count(), 1);
}

#[test]
fn settled_triggers_and_the_timer_coalesce_during_a_blocked_operation() {
    let harness = Harness::new(World::default());
    harness.connect().unwrap();
    let (entered, release) = harness.pause("scan");
    let relay = Arc::clone(&harness.relay);
    let scan = std::thread::spawn(move || relay.scan());
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    for _ in 0..50 {
        harness.relay.send(Message::Tick).unwrap();
    }
    harness.advance(65);
    release.send(()).unwrap();
    scan.join().unwrap().unwrap();
    harness.barrier();
    for action in ["observe", "maintain"] {
        assert_eq!(harness.calls().iter().filter(|call| **call == format!("enter {action}")).count(), 1, "{action}");
    }
    harness.relay.send(Message::Tick).unwrap();
    harness.barrier();
    assert_eq!(harness.calls().iter().filter(|call| call.as_str() == "enter observe").count(), 2);
}

#[test]
fn a_poisoned_cancel_cell_still_allows_ticks_commands_and_disconnect() {
    let harness = Harness::new(World::default());
    harness.connect().unwrap();
    let shared = Arc::clone(&harness.relay.shared);
    assert!(std::thread::spawn(move || {
        let _cancel = shared.cancel.lock().unwrap();
        panic!("poison the cancellation cell");
    }).join().is_err());
    harness.relay.send(Message::Tick).unwrap();
    harness.barrier();
    harness.relay.disconnect().unwrap();
    assert_eq!(harness.relay.status()["phase"], "idle");
    harness.connect().unwrap();
    assert_eq!(harness.relay.status()["phase"], "active");
}
