use serde_json::{json, Value};

use crate::cache;
use crate::handlers::AppState;
use crate::ubus;

pub fn sim_info(state: &AppState) -> (u16, Value) {
    let fetch = || ubus::call("zwrt_zte_mdm.api", "get_sim_info", Some("{}"));
    match state
        .cache
        .get_or_fetch(cache::SIM_INFO, cache::SIM_INFO_TTL, fetch)
    {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

/// PIN/PUK/lock operations change `get_sim_info` (state, remaining tries)
/// and the modem re-registers afterwards; drop the entry and keep reads
/// near-fresh for the settle window. Applied on failure too: a wrong PIN
/// still decrements the counter.
fn settle_sim_info(state: &AppState) {
    state
        .cache
        .invalidate_with_settle(cache::SIM_INFO, cache::SETTLE_WINDOW);
}

pub fn sim_imei(_state: &AppState) -> (u16, Value) {
    match ubus::call("zwrt_zte_mdm.api", "get_imei", Some("{}")) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn sim_pin_verify(state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let result = ubus::call(
        "zwrt_zte_mdm.api",
        "sim_verify_pin_puk",
        Some(&parsed.to_string()),
    );
    settle_sim_info(state);
    match result {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn sim_pin_change(state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let result = ubus::call(
        "zwrt_zte_mdm.api",
        "sim_change_pin",
        Some(&parsed.to_string()),
    );
    settle_sim_info(state);
    match result {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn sim_pin_mode(state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let result = ubus::call(
        "zwrt_zte_mdm.api",
        "sim_change_pin_mode",
        Some(&parsed.to_string()),
    );
    settle_sim_info(state);
    match result {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn sim_unlock(state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let result = ubus::call(
        "zwrt_zte_mdm.api",
        "set_simlock_nck",
        Some(&parsed.to_string()),
    );
    settle_sim_info(state);
    match result {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn sim_lock_trials(_state: &AppState) -> (u16, Value) {
    match ubus::call("zwrt_zte_mdm.api", "get_simlock_available_trials", Some("{}")) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}
