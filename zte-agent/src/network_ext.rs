use serde_json::{json, Value};

use crate::cache;
use crate::handlers::AppState;
use crate::ubus;

pub fn network_wan(state: &AppState) -> (u16, Value) {
    let fetch = || ubus::call("network.interface.zte_wan", "status", Some("{}"));
    match state.cache.get_or_fetch(cache::WAN, cache::WAN_TTL, fetch) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn network_wan6(state: &AppState) -> (u16, Value) {
    let fetch = || ubus::call("network.interface.zte_wan6", "status", Some("{}"));
    match state.cache.get_or_fetch(cache::WAN6, cache::WAN_TTL, fetch) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn network_lan_status(_state: &AppState) -> (u16, Value) {
    match ubus::call("network.interface.lan", "status", Some("{}")) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

/// Both `luci-rpc` reads run under the one cache slot so overlapping pollers
/// (Android asks twice per tick) share a single pair of forks. A response
/// whose `hosts` could not be read is returned but not cached.
pub fn network_clients(state: &AppState) -> (u16, Value) {
    let fetch = || {
        let hints = ubus::call("luci-rpc", "getHostHints", Some("{}")).unwrap_or(Value::Null);
        let dhcp = ubus::call("luci-rpc", "getDHCPLeases", Some(r#"{"family":4}"#))
            .ok()
            .and_then(|mut v| v.get_mut("dhcp_leases").map(Value::take));
        let mut result = serde_json::Map::new();
        let cacheable = !hints.is_null();
        result.insert("hosts".into(), hints);
        if let Some(leases) = dhcp {
            result.insert("dhcp_leases".into(), leases);
        }
        let result = Value::Object(result);
        if cacheable {
            Ok(result)
        } else {
            Err(result)
        }
    };
    let data = state
        .cache
        .get_or_fetch(cache::CLIENTS, cache::CLIENTS_TTL, fetch)
        .unwrap_or_else(|uncached| uncached);
    (200, json!({"ok": true, "data": data}))
}

pub fn network_speeds(state: &AppState) -> (u16, Value) {
    let fetch = || ubus::call("zwrt_data", "get_wwandst", Some(r#"{"cid":1,"type":1}"#));
    match state
        .cache
        .get_or_fetch(cache::SPEEDS, cache::SPEEDS_TTL, fetch)
    {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn network_rmnet(_state: &AppState) -> (u16, Value) {
    match ubus::call("network.device", "status", Some(r#"{"name":"rmnet_data0"}"#)) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn network_battery_ubus(state: &AppState) -> (u16, Value) {
    let fetch = || ubus::call("zwrt_bsp.battery", "list", Some("{}"));
    match state
        .cache
        .get_or_fetch(cache::BATTERY_INFO, cache::BATTERY_INFO_TTL, fetch)
    {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}
