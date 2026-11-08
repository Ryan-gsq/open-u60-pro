//! One trigger for keeping the agent's network changes in place against
//! ZTE's own (owner decision 63, `zte-agent/docs/relay-hw-offload.md`).
//! ZTE rewrites legacy iptables, sysctls and routes from many paths: firewall
//! reloads (`fw3`), Wi-Fi/QoS/speed-limit/IPA scripts and WAN events. Each
//! owner (relay, Mihomo) keeps its changes in a `Transaction`, which can
//! re-check and re-apply them (`Transaction::reconcile`); this module only
//! decides when: shortly after a ZTE script runs (inotify `IN_OPEN`, every
//! launcher opens the file) or a firmware event (`ubus listen`), and once a
//! minute as a fallback. Nothing runs while no owner holds changes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
const FALLBACK: Duration = Duration::from_secs(60);

static GENERATION: AtomicU64 = AtomicU64::new(0);
static LAST: Mutex<Option<Instant>> = Mutex::new(None);

/// Something ZTE runs may have changed our state.
pub fn poke() {
    *LAST.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Instant::now());
    GENERATION.fetch_add(1, Ordering::Relaxed);
}

/// One owner's position: what it has checked against.
#[derive(Default)]
pub struct Cursor {
    seen: u64,
    checked: Option<Instant>,
}

impl Cursor {
    /// Due after a settled trigger the owner has not checked yet, or after
    /// `FALLBACK` without one. The first call is due.
    pub fn due(&mut self) -> bool {
        let generation = GENERATION.load(Ordering::Relaxed);
        let settled = LAST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none_or(|at| at.elapsed() >= SETTLE);
        let due = (generation != self.seen && settled) || self.checked.is_none_or(|at| at.elapsed() >= FALLBACK);
        if due {
            self.seen = generation;
            self.checked = Some(Instant::now());
        }
        due
    }
}

/// Logs what an owner's reconcile re-applied, so ZTE's rewrites stay visible,
/// and what it could not (once until that changes; the owner shows it).
pub fn report(owner: &str, result: crate::net_tools::Reconciled) -> Result<(), String> {
    static FAILED: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());
    if !result.restored.is_empty() {
        eprintln!("[guard] {owner}: restored after another writer removed them: {}", result.restored.join("; "));
    }
    let failed = result.failed.join("; ");
    let mut logged = FAILED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let last = logged.iter().position(|(o, _)| o == owner);
    if !failed.is_empty() && last.is_none_or(|i| logged[i].1 != failed) {
        eprintln!("[guard] {owner}: could not re-apply: {failed}");
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
}

#[cfg(target_os = "linux")]
fn watch() {
    use std::ffi::CString;
    // SAFETY: plain inotify syscalls on a descriptor this thread owns.
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return eprintln!("[guard] inotify unavailable; relying on events and the fallback check");
    }
    let mut watched = 0;
    for path in WATCHED {
        let Ok(c) = CString::new(*path) else { continue };
        if unsafe { libc::inotify_add_watch(fd, c.as_ptr(), libc::IN_OPEN) } >= 0 {
            watched += 1;
        }
    }
    eprintln!("[guard] watching {watched} ZTE scripts");
    let mut buffer = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return eprintln!("[guard] inotify read failed; relying on events and the fallback check");
        }
        poke();
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
    }
}
