//! One trigger for keeping the agent's network changes in place against
//! ZTE's own (owner decision 63, `zte-agent/docs/relay-hw-offload.md`).
//! ZTE rewrites legacy iptables, sysctls and routes from many paths: firewall
//! reloads (`fw3`), Wi-Fi/QoS/speed-limit/IPA scripts and WAN events. Each
//! owner (relay, Mihomo) keeps its changes in a `Transaction`, which can
//! re-check and re-apply them (`Transaction::reconcile`); this module only
//! decides when: shortly after a ZTE script runs (inotify `IN_OPEN`, every
//! launcher opens the file) or a firmware event (`ubus listen`), and once a
//! minute as a fallback. Nothing runs while no owner holds changes.
//!
//! Timing (`relay-mihomo-architecture.md` section 4.4): a full check once the
//! trigger has been quiet `SETTLE` (owners are woken for it), again
//! `RECHECK` after a check that had to restore something; and for `SAMPLE`
//! after each trigger, every `SAMPLE_EVERY`, only the kernel settings owners
//! hold (`hold`) are read and written back if changed, under the holder's
//! registration, so a released setting is never written again. Opens of a
//! script the agent runs itself (`own_run`) count once per run; other
//! scripts and events in that window still count.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Firmware events after which ZTE may rewrite rules, routes or sysctls.
pub const EVENTS: &[&str] = &["zwrt_wlan", "zwrt_router.msg", "zwrt_smart_mng.msg", "network.interface"];
/// Scripts and tools that rewrite them.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const WATCHED: &[&str] = &[
    "/sbin/fw3",
    "/etc/init.d/firewall",
    "/sbin/firewall_init.sh",
    "/sbin/firewall_sys_fw.sh",
    "/sbin/module_firewall_init.sh",
    "/sbin/module_firewall_sys.sh",
    "/sbin/firewall_redirect.sh",
    "/sbin/firewall_portmapping.sh",
    "/sbin/firewall_porttrigger.sh",
    "/sbin/firewall_multi_wan_redirect.sh",
    "/sbin/firewall_multi_wan_second_redirect.sh",
    "/sbin/wifi_isolate_and_second_ssid_access_control.sh",
    "/sbin/isolate_exclude.sh",
    "/sbin/mwan_speedlimit.sh",
    "/sbin/speedlimit.sh",
    "/sbin/qos_set.sh",
    "/sbin/smart_set_qos_policy.sh",
    "/sbin/ipacm_switch.sh",
    "/sbin/router_common.sh",
    "/etc/hotplug.d/iface/15-mwan3",
];
/// A script runs for a while: check once it has been quiet this long.
const SETTLE: Duration = Duration::from_secs(2);
/// After a check restored something: once more this much later.
const RECHECK: Duration = Duration::from_secs(5);
/// Held kernel settings are sampled this long after a trigger, this often.
const SAMPLE: Duration = Duration::from_secs(3);
const SAMPLE_EVERY: Duration = Duration::from_millis(500);
const FALLBACK: Duration = Duration::from_secs(60);

static GENERATION: AtomicU64 = AtomicU64::new(0);
static LAST: Mutex<Option<Instant>> = Mutex::new(None);
/// Wakes the sampler after a trigger.
static TRIGGERED: Condvar = Condvar::new();

/// Something ZTE runs may have changed our state.
pub fn poke() {
    *LAST.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
    GENERATION.fetch_add(1, Ordering::Relaxed);
    TRIGGERED.notify_all();
}

/// One owner's position: what it has checked against.
#[derive(Default)]
pub struct Cursor {
    seen: u64,
    checked: Option<Instant>,
    recheck: Option<Instant>,
}

impl Cursor {
    /// Due after a settled trigger the owner has not checked yet, `RECHECK`
    /// after a check that restored something, or after `FALLBACK` without
    /// one. The first call is due.
    pub fn due(&mut self) -> bool {
        let generation = GENERATION.load(Ordering::Relaxed);
        let settled = LAST
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none_or(|at| at.elapsed() >= SETTLE);
        let recheck = self.recheck.is_some_and(|at| Instant::now() >= at);
        let due = (generation != self.seen && settled) || recheck || self.checked.is_none_or(|at| at.elapsed() >= FALLBACK);
        if due {
            self.seen = generation;
            self.checked = Some(Instant::now());
            self.recheck = None;
        }
        due
    }

    /// After a check: one that had to restore something is repeated
    /// `RECHECK` later (a script may still be rewriting).
    pub fn after(&mut self, result: &crate::net_tools::Reconciled) {
        if !result.restored.is_empty() {
            self.recheck = Some(Instant::now() + RECHECK);
        }
    }
}

/// A kernel setting an owner holds (`@u60-sysctl`, kept by `Transaction`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Held {
    owner: String,
    key: String,
    value: String,
    generation: u64,
}

static HELD: Mutex<Vec<Held>> = Mutex::new(Vec::new());
static HELD_GENERATION: AtomicU64 = AtomicU64::new(0);

/// `owner` (its journal) keeps `key` at `value` until `release`.
pub fn hold(owner: &str, key: &str, value: &str) {
    let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
    held.retain(|h| !(h.owner == owner && h.key == key));
    let generation = HELD_GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    held.push(Held { owner: owner.into(), key: key.into(), value: value.into(), generation });
}

/// Before `owner` restores `key` (or every key, `None`): the sampler stops
/// writing it, including a write that is waiting for this lock.
pub fn release(owner: &str, key: Option<&str>) {
    HELD.lock().unwrap_or_else(PoisonError::into_inner).retain(|h| !(h.owner == owner && key.is_none_or(|k| h.key == k)));
}

/// One sample of the held settings: each one read differently is written
/// back if its holder still holds it at the same generation. `read` and
/// `write` stand for `/proc/sys` (tests).
fn sample(read: impl Fn(&str) -> Option<String>, write: impl Fn(&str, &str) -> Result<(), String>) -> Vec<String> {
    let held = HELD.lock().unwrap_or_else(PoisonError::into_inner).clone();
    let mut restored = Vec::new();
    for h in held {
        let Some(now) = read(&h.key) else { continue };
        if now == h.value {
            continue;
        }
        let current = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        if !current.contains(&h) {
            continue;
        }
        match write(&h.key, &h.value) {
            Ok(()) => restored.push(format!("{} {now} -> {}", h.key, h.value)),
            Err(e) => crate::netlog!("[guard] could not set {} back to {}: {e}", h.key, h.value),
        }
        drop(current);
    }
    restored
}

type Waker = Box<dyn Fn() + Send + Sync>;
static WAKERS: Mutex<Vec<Waker>> = Mutex::new(Vec::new());

/// Called once a trigger has settled, so an owner checks without waiting
/// for its next tick.
pub fn on_settled(waker: impl Fn() + Send + Sync + 'static) {
    WAKERS.lock().unwrap_or_else(PoisonError::into_inner).push(Box::new(waker));
}

/// After each trigger: samples the held settings for `SAMPLE`, and wakes
/// the owners once the trigger is `SETTLE` quiet.
fn sampler() {
    let mut seen = GENERATION.load(Ordering::Relaxed);
    loop {
        let mut last = LAST.lock().unwrap_or_else(PoisonError::into_inner);
        while GENERATION.load(Ordering::Relaxed) == seen {
            last = TRIGGERED.wait(last).unwrap_or_else(PoisonError::into_inner);
        }
        drop(last);
        let mut woke: Option<u64> = None;
        loop {
            let generation = GENERATION.load(Ordering::Relaxed);
            let quiet = LAST.lock().unwrap_or_else(PoisonError::into_inner).map_or(SAMPLE, |at| at.elapsed());
            let restored = sample(|key| crate::net_tools::sysctl_read(key).ok(), |key, value| crate::net_tools::sysctl_write(key, value));
            if !restored.is_empty() {
                crate::netlog!("[guard] kernel settings set back {} ms after a trigger: {}", quiet.as_millis(), restored.join("; "));
            }
            if quiet >= SETTLE && woke != Some(generation) {
                woke = Some(generation);
                WAKERS.lock().unwrap_or_else(PoisonError::into_inner).iter().for_each(|wake| wake());
            }
            if quiet >= SAMPLE && woke == Some(generation) {
                seen = generation;
                break;
            }
            std::thread::sleep(SAMPLE_EVERY);
        }
    }
}

/// A script the agent itself runs: its opens during `own_run` count as one
/// trigger, since another opener cannot be told apart.
struct Own {
    path: &'static str,
    until: Option<Instant>,
    counted: bool,
}

static OWN: Mutex<Vec<Own>> = Mutex::new(Vec::new());
/// Opens that arrive just after the run returns are still its own.
const OWN_GRACE: Duration = Duration::from_secs(1);

/// Runs `f`, which runs the watched script `path`.
pub fn own_run<T>(path: &'static str, f: impl FnOnce() -> T) -> T {
    OWN.lock().unwrap_or_else(PoisonError::into_inner).push(Own { path, until: None, counted: false });
    let result = f();
    let mut own = OWN.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(run) = own.iter_mut().rev().find(|o| o.path == path && o.until.is_none()) {
        run.until = Some(Instant::now() + OWN_GRACE);
    }
    result
}

/// Whether an open of `path` is a trigger.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn counts(path: &str) -> bool {
    let mut own = OWN.lock().unwrap_or_else(PoisonError::into_inner);
    own.retain(|o| o.until.is_none_or(|at| Instant::now() < at));
    match own.iter_mut().find(|o| o.path == path) {
        Some(run) if run.counted => false,
        Some(run) => {
            run.counted = true;
            true
        }
        None => true,
    }
}

/// Logs what an owner's reconcile re-applied, so ZTE's rewrites stay visible,
/// and what it could not (once until that changes; the owner shows it).
pub fn report(owner: &str, result: crate::net_tools::Reconciled) -> Result<(), String> {
    static FAILED: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
    if !result.restored.is_empty() {
        crate::netlog!("[guard] {owner}: restored after another writer removed them: {}", result.restored.join("; "));
    }
    let failed = result.failed.join("; ");
    let mut logged = FAILED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let last = logged.iter().position(|(o, _)| o == owner);
    if !failed.is_empty() && last.is_none_or(|i| logged[i].1 != failed) {
        crate::netlog!("[guard] {owner}: could not re-apply: {failed}");
    }
    match last {
        Some(i) => logged[i].1.clone_from(&failed),
        None => logged.push((owner.to_owned(), failed.clone())),
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("{owner} could not restore some network changes: {failed}"))
    }
}

/// Subscribes the firmware events and starts the script watch. Call before
/// `EventBus::start`.
pub fn start(bus: &crate::event_bus::EventBus) {
    bus.subscribe_fn(EVENTS, Arc::new(|_, _| poke()));
    crate::system::spawn_named("net-guard", watch);
    crate::system::spawn_named("net-guard-sample", sampler);
}

#[cfg(target_os = "linux")]
fn watch() {
    use std::ffi::CString;
    // SAFETY: plain inotify syscalls on a descriptor this thread owns.
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return crate::netlog!("[guard] inotify unavailable; relying on events and the fallback check");
    }
    let mut watched = 0;
    let mut paths: Vec<(i32, &'static str)> = Vec::new();
    for path in WATCHED {
        let Ok(c) = CString::new(*path) else { continue };
        let wd = unsafe { libc::inotify_add_watch(fd, c.as_ptr(), libc::IN_OPEN) };
        if wd >= 0 {
            watched += 1;
            paths.push((wd, path));
        }
    }
    crate::netlog!("[guard] watching {watched} ZTE scripts");
    let mut buffer = [0u64; 512];
    let header = std::mem::size_of::<libc::inotify_event>();
    loop {
        let n = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), std::mem::size_of_val(&buffer)) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return crate::netlog!("[guard] inotify read failed; relying on events and the fallback check");
        }
        // Watches on files carry no name: each event is its header alone.
        let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), n as usize) };
        let mut at = 0;
        let (mut trigger, mut parsed) = (false, false);
        while at + header <= bytes.len() {
            // SAFETY: a whole event header lies at `at` in what the kernel wrote.
            let event = unsafe { std::ptr::read_unaligned(bytes[at..].as_ptr().cast::<libc::inotify_event>()) };
            let path = paths.iter().find(|(wd, _)| *wd == event.wd).map(|(_, p)| *p);
            trigger |= path.is_none_or(counts);
            parsed = true;
            at += header + event.len as usize;
        }
        // Unreadable events keep one check.
        if trigger || !parsed {
            poke();
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn watch() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_checks_first_then_only_after_a_settled_trigger_or_the_fallback() {
        let mut cursor = Cursor::default();
        assert!(cursor.due(), "first check");
        assert!(!cursor.due(), "nothing new");
        poke();
        assert!(!cursor.due(), "the script is still running");
        *LAST.lock().unwrap() = Some(Instant::now() - SETTLE);
        assert!(cursor.due(), "settled trigger");
        assert!(!cursor.due());
        cursor.checked = Some(Instant::now() - FALLBACK);
        assert!(cursor.due(), "fallback");
        let restored = crate::net_tools::Reconciled { restored: vec!["x".into()], failed: vec![] };
        cursor.after(&restored);
        assert!(!cursor.due(), "not at once");
        cursor.recheck = Some(Instant::now() - Duration::from_millis(1));
        assert!(cursor.due(), "{RECHECK:?} after a repair");
        assert!(!cursor.due(), "once");
        cursor.after(&crate::net_tools::Reconciled::default());
        assert!(cursor.recheck.is_none(), "nothing restored, no recheck");
    }

    /// A sampled setting is written back only while its holder holds it at
    /// the same generation: never after `release`.
    #[test]
    fn held_settings_are_written_back_only_while_held() {
        use std::collections::BTreeMap;
        let kernel = Mutex::new(BTreeMap::from([("brnf-test".to_owned(), "1".to_owned())]));
        let read = |key: &str| kernel.lock().unwrap().get(key).cloned();
        let write = |key: &str, value: &str| {
            kernel.lock().unwrap().insert(key.into(), value.into());
            Ok(())
        };
        let owner = "/journal/test-held.json";
        hold(owner, "brnf-test", "0");
        assert_eq!(sample(read, write), ["brnf-test 1 -> 0"]);
        assert!(sample(read, write).is_empty(), "already right");
        kernel.lock().unwrap().insert("brnf-test".into(), "1".into());
        release(owner, Some("brnf-test"));
        assert!(sample(read, write).is_empty(), "released: the owner's undo decides");
        assert_eq!(kernel.lock().unwrap()["brnf-test"], "1");
        hold(owner, "brnf-test", "0");
        release(owner, None);
        assert!(sample(read, write).is_empty());
    }

    #[test]
    fn the_agents_own_script_run_counts_once_and_others_still_count() {
        const PATH: &str = "/sbin/test-own-switch.sh";
        own_run(PATH, || {
            assert!(counts(PATH), "its first open: the source cannot be told");
            assert!(!counts(PATH), "later opens of the same run");
            assert!(counts("/sbin/fw3"), "another script in the window");
        });
        assert!(!counts(PATH), "within the grace after the run");
        OWN.lock().unwrap().iter_mut().filter(|o| o.path == PATH).for_each(|o| o.until = Some(Instant::now()));
        assert!(counts(PATH), "after the window");
    }
}
