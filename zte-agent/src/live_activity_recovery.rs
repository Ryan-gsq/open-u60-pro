//! SIM/WAN recovery and a TLS-authenticated UTC anchor, independent of carrier wall-clock jumps.
use super::{now, LiveActivity};
use crate::conn_watchdog::ConnWatchdog;
use serde_json::Value;
use std::sync::{mpsc::Receiver, Arc};
use std::time::{Duration, Instant, UNIX_EPOCH};

/// Probe cadence after a verified result while an activity is registered.
const PROBE_INTERVAL_ACTIVE: Duration = Duration::from_secs(300);
/// Probe cadence after a verified result with no activity; nothing consumes the result sooner.
const PROBE_INTERVAL_IDLE: Duration = Duration::from_secs(3600);
/// Delay before probing after a SIM/WAN event, so the interface can settle.
const EVENT_PROBE_DELAY: Duration = Duration::from_secs(3);
/// Upper bound on one condvar wait while an activity is registered: the clock-drift repair
/// runs at least this often.
const DRIFT_CHECK_INTERVAL: Duration = Duration::from_secs(15);
/// Upper bound on one condvar wait with no activity registered. Nothing consumes the clock
/// state until one exists, drift is repaired on the next probe or registration anyway, and
/// registration notifies the condvar, so idle wakes can be rare.
const IDLE_WAKE_INTERVAL: Duration = Duration::from_secs(300);

fn probe_interval(registered: bool) -> Duration {
    if registered {
        PROBE_INTERVAL_ACTIVE
    } else {
        PROBE_INTERVAL_IDLE
    }
}
/// How long the recovery thread may sleep before `next_probe`, capped so the clock-drift
/// repair keeps running while an activity needs it.
fn probe_wait(next_probe: Instant, now: Instant, registered: bool) -> Duration {
    let cap = if registered {
        DRIFT_CHECK_INTERVAL
    } else {
        IDLE_WAKE_INTERVAL
    };
    next_probe.saturating_duration_since(now).min(cap)
}
fn probe_retry_delay(failures: u32) -> Duration {
    // 30s, 60s, 120s, 240s, then every 5 minutes while offline.
    Duration::from_secs((30u64 << failures.min(4)).min(300))
}

#[derive(Default)]
pub(super) struct Recovery {
    anchor: Option<(u64, Instant)>,
    pub paused: bool,
    pub error: Option<&'static str>,
    pub last_sync: Option<u64>,
    pub last_event: Option<&'static str>,
    revision: u64,
}
impl Recovery {
    pub fn utc(&self) -> Option<u64> {
        self.anchor.and_then(|(epoch, instant)| {
            (instant.elapsed() < Duration::from_secs(6 * 3600))
                .then(|| epoch.saturating_add(instant.elapsed().as_secs()))
        })
    }
    pub fn label(&self) -> &'static str {
        if self.utc().is_none() {
            "waiting_for_time"
        } else if self.paused {
            "waiting_for_network"
        } else {
            "ready"
        }
    }
    /// Discard any in-flight probe result and schedule a fresh one shortly.
    pub fn reprobe(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }
    #[cfg(test)]
    pub fn verified(epoch: u64) -> Self {
        Self {
            anchor: Some((epoch, Instant::now())),
            ..Self::default()
        }
    }
}

fn event_label(name: &str, value: &Value) -> Option<&'static str> {
    match name {
        "zwrt_card_state_event" if value["sim_hotswap"] == "sim hot remove" => Some("sim_removed"),
        "zwrt_card_state_event" if value["sim_states"] == "sim ready" => Some("sim_ready"),
        "router_event_wan_connect_status" => match value["wan_status"].as_str()? {
            "disconnected" => Some("wan_down"),
            "ipv4_connected" | "ipv6_connected" | "connected" | "ipv4_ipv6_connected" => {
                Some("wan_up")
            }
            _ => None,
        },
        "network.interface"
            if matches!(value["interface"].as_str(), Some("zte_wan" | "zte_wan6")) =>
        {
            match value["action"].as_str()? {
                "ifup" => Some("wan_up"),
                "ifdown" => Some("wan_down"),
                _ => None,
            }
        }
        _ => None,
    }
}

impl LiveActivity {
    pub(super) fn trusted_now(&self) -> Option<u64> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .recovery
            .utc()
    }
    fn recovery_event(&self, name: &str, value: &Value) {
        let Some(label) = event_label(name, value) else {
            return;
        };
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.recovery.last_event == Some(label) {
            return;
        }
        state.recovery.last_event = Some(label);
        state.recovery.paused = true;
        state.recovery.reprobe();
        // Invalidate in-flight results but retain the token and its trusted UTC expiry.
        state.generation = state.generation.wrapping_add(1);
        self.changed.notify_all();
        eprintln!("[live_activity] recovery event: {label}");
    }
    pub(super) fn start_recovery(
        self: &Arc<Self>,
        events: Vec<(&'static str, Receiver<Value>)>,
        watchdog: Arc<ConnWatchdog>,
    ) {
        for (name, receiver) in events {
            let service = Arc::clone(self);
            std::thread::spawn(move || {
                for value in receiver {
                    service.recovery_event(name, &value);
                }
            });
        }
        let service = Arc::clone(self);
        std::thread::spawn(move || service.recovery_loop(watchdog));
    }
    /// `watchdog` receives every probe outcome: it is the connectivity
    /// watchdog's only "is the internet reachable" signal.
    fn recovery_loop(&self, watchdog: Arc<ConnWatchdog>) {
        if self.provider.is_none() {
            return;
        }
        let Ok(client) = reqwest::blocking::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            // Each probe is a cold connection: no idle socket, keepalives, or pool reaper between.
            .pool_max_idle_per_host(0)
            .build()
        else {
            return;
        };
        let mut next_probe = Instant::now();
        let mut last_ok: Option<Instant> = None;
        let mut failures: u32 = 0;
        let mut observed = 0;
        loop {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.recovery.revision != observed {
                observed = state.recovery.revision;
                last_ok = None;
                failures = 0;
                next_probe = Instant::now() + EVENT_PROBE_DELAY;
            }
            // Re-derive the cadence from the last success: registration notifies `changed`, so a
            // new activity pulls the next probe in to at most PROBE_INTERVAL_ACTIVE after it.
            if let Some(ok) = last_ok {
                next_probe = ok + probe_interval(state.registered());
            }
            // Carrier time can change without a SIM event. Repair from the verified monotonic
            // anchor between network checks, without repeatedly signing or calling ubus.
            if let Some(utc) = state.recovery.utc() {
                if now().abs_diff(utc) > 5 {
                    state.recovery.error = set_clock(utc).err();
                }
            }
            if Instant::now() < next_probe {
                let wait = probe_wait(next_probe, Instant::now(), state.registered());
                drop(
                    self.changed
                        .wait_timeout(state, wait)
                        .unwrap_or_else(|p| p.into_inner()),
                );
                continue;
            }
            let revision = state.recovery.revision;
            drop(state);
            // Apple's connectivity endpoint supplies current Date over verified TLS.
            // No key, JWT, activity token, SIM identity, or credentials are sent by this probe.
            let result = verified_server_time(&client);
            watchdog.probe_result(result.is_ok());
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.recovery.revision != revision {
                continue;
            }
            match result {
                Ok(epoch) => {
                    let recovering = state.recovery.paused || state.recovery.utc().is_none();
                    state.recovery.anchor = Some((epoch, Instant::now()));
                    state.recovery.last_sync = Some(epoch);
                    state.recovery.error = if now().abs_diff(epoch) > 5 {
                        set_clock(epoch).err()
                    } else {
                        None
                    };
                    state.recovery.paused = false;
                    if recovering {
                        state.generation = state.generation.wrapping_add(1);
                        self.changed.notify_all();
                        eprintln!("[live_activity] network and UTC verified; resuming delivery");
                    }
                    failures = 0;
                    last_ok = Some(Instant::now());
                }
                Err(message) => {
                    state.recovery.error = Some(message);
                    if !state.recovery.paused {
                        state.generation = state.generation.wrapping_add(1);
                    }
                    state.recovery.paused = true;
                    self.changed.notify_all();
                    last_ok = None;
                    next_probe = Instant::now() + probe_retry_delay(failures);
                    failures = failures.saturating_add(1);
                }
            }
        }
    }
}
fn verified_server_time(client: &reqwest::blocking::Client) -> Result<u64, &'static str> {
    let started = Instant::now();
    let response = client
        .get(format!(
            "https://www.apple.com/library/test/success.html?u60-time-check={}",
            now()
        ))
        .header("Cache-Control", "no-cache, no-store")
        .send()
        .map_err(|_| "time verification failed: DNS, TLS or internet unavailable")?;
    if !response.status().is_success() {
        return Err("time endpoint unavailable");
    }
    if started.elapsed() > Duration::from_secs(10) {
        return Err("time response too slow");
    }
    if response.headers().get("age").is_some_and(|v| {
        v.to_str()
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .is_none_or(|age| age > 0)
    }) {
        return Err("cached time response rejected");
    }
    let date = response
        .headers()
        .get("date")
        .and_then(|v| v.to_str().ok())
        .ok_or("time response missing Date")?;
    parse_server_time(date)
}
fn parse_server_time(date: &str) -> Result<u64, &'static str> {
    let epoch = httpdate::parse_http_date(date)
        .map_err(|_| "invalid time response")?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "invalid time epoch")?
        .as_secs();
    if !(1_700_000_000..4_102_444_800).contains(&epoch) {
        return Err("time response outside supported range");
    }
    Ok(epoch)
}
fn set_clock(epoch: u64) -> Result<(), &'static str> {
    let time = libc::timespec {
        tv_sec: epoch as _,
        tv_nsec: 0,
    };
    // SAFETY: `time` points to an initialized timespec for the duration of this synchronous call.
    if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &time) } != 0 {
        return Err("verified UTC available; cannot set modem clock");
    }
    eprintln!("[live_activity] corrected modem UTC from verified time anchor");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn observed_sim_events_are_recognized_without_retaining_identity() {
        assert_eq!(
            event_label(
                "zwrt_card_state_event",
                &json!({"sim_hotswap":"sim hot remove"})
            ),
            Some("sim_removed")
        );
        assert_eq!(
            event_label(
                "zwrt_card_state_event",
                &json!({"sim_states":"sim ready","sim_iccid":"private"})
            ),
            Some("sim_ready")
        );
        assert_eq!(
            event_label("zwrt_card_state_event", &json!({"other":"noise"})),
            None
        );
    }
    #[test]
    fn only_wan_interface_events_trigger_recovery() {
        assert_eq!(
            event_label(
                "network.interface",
                &json!({"interface":"lan","action":"ifdown"})
            ),
            None
        );
        assert_eq!(
            event_label(
                "network.interface",
                &json!({"interface":"zte_wan","action":"ifup"})
            ),
            Some("wan_up")
        );
        assert_eq!(
            event_label(
                "router_event_wan_connect_status",
                &json!({"wan_status":"ipv4_connected"})
            ),
            Some("wan_up")
        );
    }
    #[test]
    fn utc_anchor_is_not_derived_from_system_wall_clock() {
        let recovery = Recovery::verified(1_789_000_000);
        assert!((1_789_000_000..=1_789_000_002).contains(&recovery.utc().unwrap()));
        assert_ne!(recovery.utc(), Some(1_789_028_800));
    }
    #[test]
    fn sim_removal_preserves_registration_and_duplicate_events_are_debounced() {
        let service = super::super::tests::test_service();
        let body =
            serde_json::to_vec(&json!({"push_token":"ab".repeat(40),"expires_at":now()+3600}))
                .unwrap();
        assert_eq!(service.register(&body).0, 200);
        service.recovery_event(
            "zwrt_card_state_event",
            &json!({"sim_hotswap":"sim hot remove"}),
        );
        let generation = service.state.lock().unwrap().generation;
        service.recovery_event(
            "zwrt_card_state_event",
            &json!({"sim_hotswap":"sim hot remove"}),
        );
        let state = service.state.lock().unwrap();
        assert!(state.activity.is_some());
        assert!(state.recovery.paused);
        assert_eq!(state.generation, generation);
    }
    #[test]
    fn wan_up_requests_verification_before_resuming() {
        let service = super::super::tests::test_service();
        service.recovery_event(
            "network.interface",
            &json!({"interface":"zte_wan","action":"ifdown"}),
        );
        service.recovery_event(
            "router_event_wan_connect_status",
            &json!({"wan_status":"ipv4_connected"}),
        );
        let state = service.state.lock().unwrap();
        assert_eq!(state.recovery.last_event, Some("wan_up"));
        assert_eq!(state.recovery.revision, 2);
        assert!(state.recovery.paused);
    }
    #[test]
    fn offline_probe_backoff_is_bounded_and_starts_at_thirty_seconds() {
        let delays: Vec<_> = (0..7).map(|n| probe_retry_delay(n).as_secs()).collect();
        assert_eq!(delays, [30, 60, 120, 240, 300, 300, 300]);
        assert_eq!(probe_retry_delay(u32::MAX).as_secs(), 300);
    }
    #[test]
    fn probe_cadence_follows_registration_as_reported_by_status() {
        assert_eq!(probe_interval(true), Duration::from_secs(300));
        assert_eq!(probe_interval(false), Duration::from_secs(3600));
        let service = super::super::tests::test_service();
        let registered = |service: &LiveActivity| {
            let reported = service.status().1["data"]["registered"].as_bool().unwrap();
            assert_eq!(reported, service.state.lock().unwrap().registered());
            reported
        };
        assert_eq!(probe_interval(registered(&service)), PROBE_INTERVAL_IDLE);
        let body =
            serde_json::to_vec(&json!({"push_token":"ab".repeat(40),"expires_at":now()+3600}))
                .unwrap();
        assert_eq!(service.register(&body).0, 200);
        assert_eq!(probe_interval(registered(&service)), PROBE_INTERVAL_ACTIVE);
        // An expired activity that the delivery thread has not yet dropped counts as idle.
        service
            .state
            .lock()
            .unwrap()
            .activity
            .as_mut()
            .unwrap()
            .expires_at = 1_700_000_000;
        assert_eq!(probe_interval(registered(&service)), PROBE_INTERVAL_IDLE);
    }
    #[test]
    fn idle_recovery_wait_is_long_while_registered_drift_repair_stays_frequent() {
        let now = Instant::now();
        let far = now + PROBE_INTERVAL_IDLE;
        assert_eq!(probe_wait(far, now, true), DRIFT_CHECK_INTERVAL);
        assert_eq!(probe_wait(far, now, false), IDLE_WAKE_INTERVAL);
        assert_eq!(IDLE_WAKE_INTERVAL, Duration::from_secs(300));
        // A probe due before the cap is never delayed past it, and one already due does not wait.
        let soon = now + Duration::from_secs(3);
        assert_eq!(probe_wait(soon, now, true), Duration::from_secs(3));
        assert_eq!(probe_wait(soon, now, false), Duration::from_secs(3));
        assert_eq!(
            probe_wait(now, now + Duration::from_secs(1), false),
            Duration::ZERO
        );
    }
    #[test]
    fn registration_wakes_an_idle_recovery_wait_immediately() {
        let service = Arc::new(super::super::tests::test_service());
        let (entered, waiting) = std::sync::mpsc::channel();
        let waiter = {
            let service = Arc::clone(&service);
            std::thread::spawn(move || {
                let state = service.state.lock().unwrap();
                let wait = probe_wait(Instant::now() + PROBE_INTERVAL_IDLE, Instant::now(), false);
                assert_eq!(wait, IDLE_WAKE_INTERVAL);
                // Sent while holding the lock: `register` cannot run until the wait releases it.
                entered.send(()).unwrap();
                let started = Instant::now();
                drop(service.changed.wait_timeout(state, wait).unwrap());
                started.elapsed()
            })
        };
        waiting.recv().unwrap();
        let body =
            serde_json::to_vec(&json!({"push_token":"ab".repeat(40),"expires_at":now()+3600}))
                .unwrap();
        assert_eq!(service.register(&body).0, 200);
        assert!(waiter.join().unwrap() < Duration::from_secs(5));
    }
    #[test]
    fn new_registration_while_paused_requests_an_immediate_probe() {
        let service = super::super::tests::test_service();
        let body = |token: &str| {
            serde_json::to_vec(&json!({"push_token":token.repeat(40),"expires_at":now()+3600}))
                .unwrap()
        };
        let revision = |service: &LiveActivity| service.state.lock().unwrap().recovery.revision;
        assert_eq!(service.register(&body("ab")).0, 200);
        assert_eq!(
            revision(&service),
            0,
            "online registration does not reprobe"
        );
        service.recovery_event(
            "router_event_wan_connect_status",
            &json!({"wan_status":"disconnected"}),
        );
        assert_eq!(revision(&service), 1);
        assert_eq!(service.register(&body("ab")).0, 200);
        assert_eq!(
            revision(&service),
            1,
            "repeated PUT of the same token is a no-op"
        );
        assert_eq!(service.register(&body("cd")).0, 200);
        assert_eq!(
            revision(&service),
            2,
            "a new token while paused asks for a 3 s probe"
        );
        assert!(service.state.lock().unwrap().recovery.paused);
    }
    #[test]
    fn invalid_time_is_not_accepted() {
        assert!(parse_server_time("garbage").is_err());
        assert!(parse_server_time("Thu, 01 Jan 1970 00:00:00 GMT").is_err());
        assert_eq!(
            parse_server_time("Tue, 15 Sep 2026 09:35:53 GMT").unwrap(),
            1789464953
        );
    }
}
