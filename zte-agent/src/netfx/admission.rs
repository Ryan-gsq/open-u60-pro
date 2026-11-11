//! Admission of owner settings that would conflict with the relay or Mihomo
//! (`relay-mihomo-architecture.md` section 4.6, D9): they wait a bounded time
//! for a network operation in progress instead of failing at once, then
//! check who owns the network and write.

use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

/// How long an owner request waits before it answers "in progress".
#[cfg(not(test))]
pub const WAIT: Duration = Duration::from_secs(3);
#[cfg(test)]
pub const WAIT: Duration = Duration::from_millis(50);

/// A vendor Wi-Fi reload (`zwrt_wlan reload`) the agent started: it goes on
/// after the request that started it answered.
pub const VENDOR_WIFI_RELOAD: &str = "vendor Wi-Fi reload";
/// An owner change of router settings that conflicts with the relay or
/// Mihomo (hotspot, guest Wi-Fi, LAN, USB, firewall, fixed DHCP).
pub const VENDOR_WRITE: &str = "router setting change";
/// A relay operation (scan, connect, disconnect, settings) in progress.
pub const RELAY_OPERATION: &str = "Wi-Fi relay operation";
const IN_PROGRESS: &str = "A network operation is in progress; retry after it finishes";

struct Held {
    what: &'static str,
    id: u64,
    until: Instant,
}

/// Operations that hold a resource, each until released or its bound
/// passes (section 4.6). The network lock only guards checking and
/// registering them; nobody holds it across device work.
static HELD: Mutex<Vec<Held>> = Mutex::new(Vec::new());
static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// `what` is held for at most `bound`; the id releases it.
pub fn occupy(what: &'static str, bound: Duration) -> u64 {
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    HELD.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(Held { what, id, until: Instant::now() + bound });
    id
}

/// Releases every occupation of `what`.
pub fn release(what: &'static str) {
    HELD.lock().unwrap_or_else(std::sync::PoisonError::into_inner).retain(|h| h.what != what);
}

fn release_id(id: u64) {
    HELD.lock().unwrap_or_else(std::sync::PoisonError::into_inner).retain(|h| h.id != id);
}

/// Whether `what` is still held.
pub fn held(what: &'static str) -> bool {
    let mut held = HELD.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    held.retain(|h| h.until > now);
    held.iter().any(|h| h.what == what)
}

/// An occupation, released when dropped.
#[derive(Debug)]
pub struct Claim(u64);

impl Drop for Claim {
    fn drop(&mut self) {
        release_id(self.0);
    }
}

/// An owner write that may conflict with the relay or Mihomo (D9, section
/// 4.6). Within short critical sections of `lock`: waits at most `WAIT`
/// while a relay operation is in progress (then "in progress"), refuses a
/// conflict (`conflict` says why: the relay or Mihomo owns the network),
/// otherwise registers `what` until the claim is dropped, so a relay
/// operation cannot start in the middle of the write.
pub fn admit(lock: &Mutex<()>, what: &'static str, conflict: impl Fn() -> Option<String>) -> Result<Claim, String> {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(_guard) = enter(lock, Duration::ZERO) {
            if !held(RELAY_OPERATION) {
                if let Some(why) = conflict() {
                    return Err(why);
                }
                return Ok(Claim(occupy(what, Duration::from_secs(600))));
            }
        }
        if Instant::now() >= deadline {
            return Err(IN_PROGRESS.into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A relay operation the owner asked for (or a boot restore): refused while
/// one of `blockers` is held, registered as `what` until the claim drops.
pub fn begin(lock: &Mutex<()>, what: &'static str, blockers: &[&'static str]) -> Result<Claim, String> {
    let _guard = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(blocker) = blockers.iter().find(|b| held(b)) {
        return Err(if *blocker == VENDOR_WIFI_RELOAD {
            "Wi-Fi is still applying its new settings; retry in a moment".into()
        } else {
            format!("A {blocker} is in progress; retry after it finishes")
        });
    }
    Ok(Claim(occupy(what, Duration::from_secs(3600))))
}

/// The lock within `wait`, or `None` when an operation still holds it.
pub fn enter(lock: &Mutex<()>, wait: Duration) -> Option<MutexGuard<'_, ()>> {
    let deadline = Instant::now() + wait;
    loop {
        match lock.try_lock() {
            Ok(guard) => return Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => return Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(TryLockError::WouldBlock) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn an_occupation_lasts_until_released_or_its_bound() {
        occupy("test reload", Duration::from_secs(60));
        assert!(held("test reload") && !held("another"));
        release("test reload");
        assert!(!held("test reload"));
        occupy("test bound", Duration::from_millis(20));
        assert!(held("test bound"));
        std::thread::sleep(Duration::from_millis(30));
        assert!(!held("test bound"), "never held forever");
        let first = Claim(occupy("test claim", Duration::from_secs(60)));
        let second = Claim(occupy("test claim", Duration::from_secs(60)));
        drop(first);
        assert!(held("test claim"), "each claim releases only itself");
        drop(second);
        assert!(!held("test claim"));
    }

    /// Section 4.6: a write waits at most `WAIT` for a relay operation,
    /// refuses a conflict at once, and holds its own claim meanwhile.
    #[test]
    fn writes_and_relay_operations_admit_each_other_in_short_sections() {
        let _serial = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let lock = Mutex::new(());
        let relay = begin(&lock, RELAY_OPERATION, &[VENDOR_WRITE]).unwrap();
        let started = Instant::now();
        assert_eq!(admit(&lock, VENDOR_WRITE, || None).err().as_deref(), Some(IN_PROGRESS));
        assert!(started.elapsed() >= WAIT);
        drop(relay);
        assert_eq!(admit(&lock, VENDOR_WRITE, || Some("Disconnect Wi-Fi relay first".into())).err().as_deref(), Some("Disconnect Wi-Fi relay first"));
        let write = admit(&lock, VENDOR_WRITE, || None).unwrap();
        assert!(lock.try_lock().is_ok(), "the lock is not held across the write");
        assert!(begin(&lock, RELAY_OPERATION, &[VENDOR_WRITE]).unwrap_err().contains("router setting change"));
        drop(write);
        occupy(VENDOR_WIFI_RELOAD, Duration::from_secs(60));
        assert!(begin(&lock, RELAY_OPERATION, &[VENDOR_WIFI_RELOAD]).unwrap_err().contains("applying"));
        release(VENDOR_WIFI_RELOAD);
        assert!(begin(&lock, RELAY_OPERATION, &[VENDOR_WIFI_RELOAD]).is_ok());
    }

    /// Tests that use the shared registry's real names.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[test]
    fn a_short_operation_is_waited_for_and_a_long_one_is_refused() {
        let lock = Arc::new(Mutex::new(()));
        let held = Arc::clone(&lock);
        let (started, ready) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _guard = held.lock().unwrap();
            started.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });
        ready.recv().unwrap();
        assert!(enter(&lock, Duration::from_secs(3)).is_some(), "released after 100 ms");
        worker.join().unwrap();
        let _busy = lock.lock().unwrap();
        let before = Instant::now();
        assert!(enter(&lock, Duration::from_millis(200)).is_none());
        assert!(before.elapsed() >= Duration::from_millis(200));
    }
}
