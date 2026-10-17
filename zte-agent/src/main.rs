mod at_cmd;
mod at_terminal;
mod auth;
mod bearer;
mod cache;
mod cell;
mod charge_policy;
mod conn_watchdog;
mod device_ext;
pub mod doh;
mod event_bus;
mod handlers;
mod lan_test;
mod live_activity;
mod modem_ext;
mod network_ext;
mod oos_policy;
mod router;
mod scheduler;
mod server;
mod sim;
mod sms;
mod sms_forward;
mod speedtest;
mod stk;
mod system;
mod tailscale;
mod telephony;
mod ubus;
mod usb;
mod wifi;

use std::sync::Arc;

use event_bus::EventBus;
use handlers::AppState;

const DEFAULT_BIND: &str = "0.0.0.0:9090";
// 4 workers: tailscale setup/logout are legitimately slow (up to ~1-2 min
// against the control plane) and must not starve the rest of the API.
const DEFAULT_THREADS: usize = 4;

fn main() {
    let bind = std::env::var("ZTE_AGENT_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let threads: usize = std::env::var("ZTE_AGENT_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_THREADS);

    let state = Arc::new(AppState::new());

    // Set password from environment if provided
    if let Ok(pw) = std::env::var("ZTE_AGENT_PASSWORD") {
        state.auth.set_password(&pw);
    }

    // Event bus: single `ubus listen` process dispatches to subscribers
    let event_bus = EventBus::new();
    let sms_rx = event_bus.subscribe("zwrt_wms_status_event");
    let charger_rx = event_bus.subscribe("BSP_CHARGER_EVENT");
    let service_rx = event_bus.subscribe("zwrt_servicestatus");
    let wan_status_rx = event_bus.subscribe("router_event_wan_connect_status");
    let ts_wan_rx = event_bus.subscribe("router_event_wan_connect_status");
    let apns_events = [
        "zwrt_card_state_event",
        "router_event_wan_connect_status",
        "network.interface",
    ]
    .into_iter()
    .map(|name| (name, event_bus.subscribe(name)))
    .collect();
    let cache_events = cache::EVENTS
        .iter()
        .map(|&name| (name, event_bus.subscribe(name)))
        .collect();
    let oos_service_rx = event_bus.subscribe("zwrt_servicestatus");
    let connwd_wan_rx = event_bus.subscribe("router_event_wan_connect_status");
    // The firmware restarts Wi-Fi on every wake from sleep, which re-runs the
    // zte_post_wifi.sh script that can spin forever; check 150 s after each.
    let power_rx = event_bus.subscribe("zwrt_device_power_state_event");
    event_bus.start();
    system::spawn_named("wifi-power-watch", move || {
        for event in power_rx.iter() {
            if event["action"].as_str() == Some("mode_power_on") {
                system::arm_post_wifi_watchdog(std::time::Duration::from_secs(150));
            }
        }
    });

    Arc::clone(&state.cache).start_event_invalidation(cache_events);

    state.live_activity.start(Arc::clone(&state), apns_events);
    state.doh.auto_start();
    state.scheduler.start(Arc::clone(&state));
    state
        .charge_limit
        .start(charger_rx, Arc::clone(&state.cache));
    state.sms_forward.start(sms_rx, service_rx, wan_status_rx);
    state.tailscale.auto_start();
    state.tailscale.start_wan_watch(ts_wan_rx);
    state.oos_policy.start(
        Box::new(oos_policy::DeviceEffects::new(Arc::clone(&state))),
        busy_check(&state),
        oos_service_rx,
    );
    state.conn_watchdog.start(
        Box::new(conn_watchdog::DeviceEffects::new(Arc::clone(&state))),
        busy_check(&state),
        connwd_wan_rx,
    );

    // Firmware bug guard: zte_post_wifi.sh can spin forever after any Wi-Fi
    // reconfiguration (see system::kill_stuck_post_wifi); sweep every 5 min.
    system::start_post_wifi_watchdog();

    server::start(&bind, threads, state);
}

/// Guard shared by the no-service policy and the connectivity watchdog: the
/// reason an action must wait, or `None`. Only called when a policy is about
/// to act (a few times per incident), so it can afford an `AT+CLCC` to
/// confirm a call flag the app may never have cleared.
fn busy_check(state: &Arc<AppState>) -> Box<dyn Fn() -> Option<&'static str> + Send> {
    let state = Arc::clone(state);
    Box::new(move || {
        use std::sync::atomic::Ordering;
        if state.speedtest.is_running() {
            return Some("speed test");
        }
        // USSD prompts expire network-side within a few minutes; treat the
        // flag as stale after 3 min.
        let ussd_at = state.ussd_prompt_at.load(Ordering::Relaxed);
        if ussd_at != 0 && conn_watchdog::unix_now().saturating_sub(ussd_at) < 180 {
            return Some("USSD session");
        }
        if state.call_active.load(Ordering::Relaxed) {
            // Re-check with the modem: the far end may have hung up after
            // the app stopped polling call_status. Fail closed: only a
            // complete "no calls" reply clears the flag; an empty, partial
            // or ERROR reply keeps deferring (the policies retry in 60 s).
            match at_cmd::send(&state.at_port, "AT+CLCC", 2) {
                Ok(resp) if clcc_confirms_idle(&resp) => {
                    state.call_active.store(false, Ordering::Relaxed)
                }
                Ok(resp) => {
                    eprintln!(
                        "[busy_check] AT+CLCC inconclusive ({} bytes), keeping call_active",
                        resp.len()
                    );
                    return Some("voice call");
                }
                Err(e) => {
                    eprintln!("[busy_check] AT+CLCC failed: {e}; keeping call_active");
                    return Some("voice call");
                }
            }
        }
        None
    })
}

/// Whether an `AT+CLCC` reply positively confirms no call is in progress: it
/// must carry the final `OK` and list no `+CLCC:` entries. Anything else
/// (empty, truncated, `ERROR`) is inconclusive and must not clear the flag.
fn clcc_confirms_idle(resp: &str) -> bool {
    resp.contains("OK") && telephony::parse_clcc(resp).is_empty()
}

#[cfg(test)]
mod tests {
    use super::clcc_confirms_idle;

    #[test]
    fn clcc_idle_only_on_final_ok_without_calls() {
        assert!(clcc_confirms_idle("\r\nOK\r\n"));
        assert!(clcc_confirms_idle("AT+CLCC\r\r\nOK\r\n"));
    }

    #[test]
    fn clcc_inconclusive_replies_keep_call_active() {
        assert!(!clcc_confirms_idle(""));
        assert!(!clcc_confirms_idle("\r\nERROR\r\n"));
        assert!(!clcc_confirms_idle("+CME ERROR: 3\r\n"));
        // Command echo only: the reader timed out before any reply packet.
        assert!(!clcc_confirms_idle("AT+CLCC\r\n"));
    }

    #[test]
    fn clcc_with_call_listed_is_not_idle() {
        assert!(!clcc_confirms_idle(
            "+CLCC: 1,0,0,0,0,\"+15551234567\",145\r\nOK\r\n"
        ));
        // Truncated: call line captured but the final OK went to another reader.
        assert!(!clcc_confirms_idle("+CLCC: 1,1,4,0,0,\"123\",129\r\n"));
    }
}
