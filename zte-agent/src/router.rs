use std::net::Ipv4Addr;

use serde_json::{json, Value};
use std::sync::Mutex;

use crate::handlers::AppState;
use crate::ubus;

use ports::{
    build_port_forward_switch_payload, build_port_mapping_write, normalize_port_rules,
    reviewed_port_rules_match,
};
use qos::{
    build_legacy_qos_switch_payload, build_legacy_router_qos_payload, build_qos_mode_payload,
    normalize_legacy_qos_para, qos_data_from_smart_mode,
};

pub fn router_dns_get(_state: &AppState) -> (u16, Value) {
    match ubus::call("zwrt_router.api", "router_get_dns_para", Some("{}")) {
        Ok(data) => {
            // Firmware returns keys with "wan_" prefix (e.g. wan_dns_mode);
            // strip it so iOS client can use clean names (dns_mode, prefer_dns_manual, etc.)
            let mut cleaned = serde_json::Map::new();
            if let Some(obj) = data.as_object() {
                for (k, v) in obj {
                    let key = k.strip_prefix("wan_").unwrap_or(k).to_string();
                    cleaned.insert(key, v.clone());
                }
            }
            // Firmware bug: sometimes returns empty manual DNS values; fill from UCI
            if cleaned.get("dns_mode").and_then(|v| v.as_str()) == Some("manual") {
                if cleaned
                    .get("prefer_dns_manual")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .is_empty()
                {
                    if let Ok(v) = ubus::uci_get("network.wan.dns") {
                        let mut parts = v.split_whitespace();
                        if let Some(primary) = parts.next() {
                            cleaned.insert("prefer_dns_manual".into(), Value::String(primary.to_string()));
                        }
                        if let Some(secondary) = parts.next() {
                            cleaned.insert("standby_dns_manual".into(), Value::String(secondary.to_string()));
                        }
                    }
                }
            }
            (200, json!({"ok": true, "data": Value::Object(cleaned)}))
        }
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn router_dns_set(state: &AppState, body: &[u8]) -> (u16, Value) {
    crate::dns_control::legacy_router_apply(state, body)
}

pub fn router_lan_get(_state: &AppState) -> (u16, Value) {
    let read = || -> Result<_, String> {
        let network = ubus::uci_show_map(&ubus::uci_show("network.lan")?);
        let dhcp = ubus::uci_show_map(&ubus::uci_show("dhcp.lan")?);
        let required = |map: &std::collections::HashMap<String, String>, key: &str| {
            map.get(key)
                .filter(|value| !value.is_empty())
                .cloned()
                .ok_or_else(|| format!("LAN setting {key} is unavailable"))
        };
        let ip = required(&network, "network.lan.ipaddr")?;
        let mask = required(&network, "network.lan.netmask")?;
        let start = required(&dhcp, "dhcp.lan.start")?;
        let limit = required(&dhcp, "dhcp.lan.limit")?;
        let lease = required(&dhcp, "dhcp.lan.leasetime")?;
        let end = strict_compute_dhcp_end(&ip, &mask, &start, &limit)
            .ok_or_else(|| "The reported DHCP pool is invalid".to_string())?;
        Ok((
            ip,
            mask,
            start,
            lease,
            end,
            dhcp.get("dhcp.lan.ignore").is_some_and(|v| v == "1"),
        ))
    };
    let (ip, mask, start, lease, end, ignored) = match read() {
        Ok(values) => values,
        Err(error) => return (503, json!({"ok":false,"error":error})),
    };
    (
        200,
        json!({"ok": true, "data": {
            "lan_ipaddr": ip, "lan_netmask": mask,
            "dhcp_enable": if ignored { "0" } else { "1" },
            "dhcp_start": start, "dhcp_end": end,
            "dhcp_lease_time": lease
        }}),
    )
}

/// The DHCP range's last address from UCI's `start` offset and `limit`:
/// the router's network (its address and netmask) plus `start + limit - 1`,
/// at most the subnet's last host (as OpenWrt's `ipcalc.sh` keeps the range
/// inside the subnet). On a /24 this is the old answer (the last octet
/// replaced) for every range that fits the subnet. Without a usable address
/// or netmask (/8 to /30), the old answer.
#[cfg(test)]
fn compute_dhcp_end(base_ip: &str, netmask: &str, start: &str, limit: &str) -> String {
    let start_num: u32 = start.parse().unwrap_or(100);
    let limit_num: u32 = limit.parse().unwrap_or(50);
    let end_host = start_num.saturating_add(limit_num).saturating_sub(1);
    let mask = netmask
        .parse::<Ipv4Addr>()
        .map(u32::from)
        .ok()
        .filter(|m| m.count_ones() == m.leading_ones() && (8..=30).contains(&m.leading_ones()));
    match (base_ip.parse::<Ipv4Addr>(), mask) {
        (Ok(ip), Some(m)) => {
            let net = u32::from(ip) & m;
            let last_host = (net | !m) - 1;
            Ipv4Addr::from(net.saturating_add(end_host).min(last_host)).to_string()
        }
        // Replace last octet of base IP with end_host
        _ => match base_ip.rfind('.') {
            Some(prefix) => format!("{}.{end_host}", &base_ip[..prefix]),
            None => format!("192.168.0.{end_host}"),
        },
    }
}

pub fn router_lan_set(state: &AppState, body: &[u8]) -> (u16, Value) {
    let _claim = match crate::netfx::admission::admit(&state.network_lock, crate::netfx::admission::VENDOR_WRITE, || (state.wifi_relay.owns_network() || state.mihomo.owns_network()).then(|| "Stop or recover Wi-Fi relay and Mihomo before changing LAN settings".to_owned())) {
        Ok(claim) => claim,
        Err(e) => return (409, json!({"ok":false,"error":e})),
    };
    lan_set_with(state, body, |params| ubus::call("zwrt_router.api", "router_set_lan_para", Some(params)))
}

/// `router_lan_set` with the firmware call as `apply` (tests swap it).
fn lan_set_with(state: &AppState, body: &[u8], apply: impl FnOnce(&str) -> Result<Value, String>) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    match apply(&parsed.to_string()) {
        Ok(data) => {
            // LAN HTTPS: a certificate (and local name) for the new address.
            let ip = parsed["lan_ipaddr"].as_str().or(parsed["ipaddr"].as_str()).and_then(|s| s.parse().ok());
            if let Some(ip) = ip {
                state.tls.lan_changed(ip);
            }
            (200, json!({"ok": true, "data": data}))
        }
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn router_firewall_get(_state: &AppState) -> (u16, Value) {
    match ubus::call("zwrt_router.api", "router_get_firewall_para", Some("{}")) {
        Ok(data) => (200, json!({"ok": true, "data": normalize_firewall_para(data)})),
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_firewall_switch_set(_state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let payload = match build_firewall_switch_payload(&parsed) {
        Ok(value) => value,
        Err(error) => return (400, json!({"ok": false, "error": error})),
    };
    match ubus::call("zwrt_router.api", "router_set_firewall_switch", Some(&payload.to_string())) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_firewall_level_set(_state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let payload = match build_firewall_level_payload(&parsed) {
        Ok(value) => value,
        Err(error) => return (400, json!({"ok": false, "error": error})),
    };
    match ubus::call("zwrt_router.api", "router_set_firewall_level", Some(&payload.to_string())) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_firewall_nat_set(_state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let payload = match build_nat_switch_payload(&parsed) {
        Ok(value) => value,
        Err(error) => return (400, json!({"ok": false, "error": error})),
    };
    match ubus::call("zwrt_router.api", "router_set_nat_switch", Some(&payload.to_string())) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_firewall_dmz_set(_state: &AppState, body: &[u8]) -> (u16, Value) {
    router_firewall_dmz_set_with(
        body,
        read_lan_subnet,
        |payload| ubus::call("zwrt_router.api", "router_set_dmz", Some(payload)),
        || ubus::uci_show("zwrt_router.firewall"),
        |value| ubus::uci_set("zwrt_router.firewall.dmz_ip", value),
    )
}

fn router_firewall_dmz_set_with<FLan, FCall, FShow, FSet>(
    body: &[u8],
    read_lan: FLan,
    call_dmz: FCall,
    show_firewall: FShow,
    set_dmz_ip: FSet,
) -> (u16, Value)
where
    FLan: FnOnce() -> Result<(Ipv4Addr, Ipv4Addr), String>,
    FCall: FnOnce(&str) -> Result<Value, String>,
    FShow: FnOnce() -> Result<String, String>,
    FSet: FnOnce(&str) -> Result<(), String>,
{
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let plan = match build_dmz_payload(&parsed) {
        Ok(result) => result,
        Err(error) => return (400, json!({"ok": false, "error": error})),
    };
    if let Some(target_ip) = plan.enable_ip {
        let (lan_ip, lan_mask) = match read_lan() {
            Ok(subnet) => subnet,
            Err(error) => return (503, json!({"ok": false, "error": error})),
        };
        if let Err(error) = validate_lan_host(target_ip, lan_ip, lan_mask) {
            return (400, json!({"ok": false, "error": error}));
        }
    }
    static DMZ_WRITES: Mutex<()> = Mutex::new(());
    let _guard = DMZ_WRITES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match call_dmz(&plan.payload.to_string()) {
        Ok(data) => {
            if let Some(desired_ip) = plan.sync_dmz_ip {
                let show = match show_firewall() {
                    Ok(text) => text,
                    Err(error) => {
                        return (
                            503,
                            json!({"ok": false, "error": format!("DMZ state updated, but failed to verify dmz_ip: {error}")}),
                        );
                    }
                };
                let values = ubus::uci_show_map(&show);
                let current_ip = values
                    .get("zwrt_router.firewall.dmz_ip")
                    .map(|value| value.trim())
                    .unwrap_or("");
                if current_ip != desired_ip {
                    if let Err(error) = set_dmz_ip(&desired_ip) {
                        return (
                            503,
                            json!({"ok": false, "error": format!("DMZ state updated, but failed to persist dmz_ip: {error}")}),
                        );
                    }
                }
            }
            (200, json!({"ok": true, "data": data}))
        }
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_firewall_upnp_get(_state: &AppState) -> (u16, Value) {
    match ubus::call("zwrt_router.api", "router_get_upnp", Some("{}")) {
        Ok(data) => (200, json!({"ok": true, "data": normalize_upnp_para(data)})),
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_firewall_upnp_set(_state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let payload = match build_upnp_switch_payload(&parsed) {
        Ok(value) => value,
        Err(error) => return (400, json!({"ok": false, "error": error})),
    };
    match ubus::call("zwrt_router.api", "router_set_upnp_switch", Some(&payload.to_string())) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_firewall_port_forward_get(_state: &AppState) -> (u16, Value) {
    match ubus::call("zwrt_router.api", "router_get_portmapping_rule", Some("{}")) {
        Ok(data) => match normalize_port_rules(data) {
            Ok(normalized) => (200, json!({"ok": true, "data": normalized})),
            Err(error) => (503, json!({"ok": false, "error": error})),
        },
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_firewall_port_forward_set(_state: &AppState, body: &[u8]) -> (u16, Value) {
    router_firewall_port_forward_set_with(
        body,
        read_lan_subnet,
        || ubus::call("zwrt_router.api", "router_get_portmapping_rule", Some("{}")),
        |payload| ubus::call("zwrt_router.api", "router_set_portmapping", Some(payload)),
    )
}

fn router_firewall_port_forward_set_with<FLan, FGet, FSet>(
    body: &[u8],
    read_lan: FLan,
    get_rules: FGet,
    set_rule: FSet,
) -> (u16, Value)
where
    FLan: FnOnce() -> Result<(Ipv4Addr, Ipv4Addr), String>,
    FGet: FnOnce() -> Result<Value, String>,
    FSet: FnOnce(&str) -> Result<Value, String>,
{
    let mut parsed: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let expected = parsed
        .as_object_mut()
        .and_then(|object| object.remove("expected_rules"));
    if let Some(expected_value) = &expected {
        if parsed.get("action").and_then(Value::as_str).map(str::trim) != Some("delete")
            || !expected_value.is_array()
        {
            return (
                400,
                json!({"ok":false,"error":"expected_rules requires a delete and a rule array"}),
            );
        }
    }
    let write = match build_port_mapping_write(&parsed, expected.is_some()) {
        Ok(value) => value,
        Err(error) => return (400, json!({"ok": false, "error": error})),
    };
    if let Some(target_ip) = write.lan_host {
        let (lan_ip, lan_mask) = match read_lan() {
            Ok(subnet) => subnet,
            Err(error) => return (503, json!({"ok": false, "error": error})),
        };
        if let Err(error) = validate_lan_host(target_ip, lan_ip, lan_mask) {
            return (400, json!({"ok": false, "error": error}));
        }
    }
    // Rule ids can be array positions. Serialize agent writes and check the browser's
    // reviewed list immediately before deleting; native callers may omit this guard.
    static WRITES: Mutex<()> = Mutex::new(());
    let _guard = WRITES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(expected) = expected {
        let current = match get_rules() {
            Ok(data) => match normalize_port_rules(data) {
                Ok(normalized) => normalized,
                Err(error) => return (503, json!({"ok": false, "error": error})),
            },
            Err(error) => return (503, json!({"ok":false,"error":error})),
        };
        let Some(delete_id) = write.delete_target.as_deref() else {
            return (
                400,
                json!({"ok": false, "error": "expected_rules requires a single rule id"}),
            );
        };
        if !reviewed_port_rules_match(&expected, &current, delete_id) {
            return (
                409,
                json!({"ok":false,"error":"Port-forward rules changed. Review the current list before deleting."}),
            );
        }
    }
    match set_rule(&write.payload.to_string()) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_firewall_port_forward_switch(_state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let payload = match build_port_forward_switch_payload(&parsed) {
        Ok(value) => value,
        Err(error) => return (400, json!({"ok": false, "error": error})),
    };
    match ubus::call("zwrt_router.api", "router_set_portmapping_switch", Some(&payload.to_string())) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_firewall_filter_rules(_state: &AppState) -> (u16, Value) {
    match ubus::call("zwrt_router.api", "router_get_macipport_filter_rule", Some("{}")) {
        Ok(data) => match normalize_filter_rules(data) {
            Ok(normalized) => (200, json!({"ok": true, "data": normalized})),
            Err(error) => (503, json!({"ok": false, "error": error})),
        },
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_vpn_get(_state: &AppState) -> (u16, Value) {
    match ubus::call("zwrt_router.api", "router_get_alg_para", Some("{}")) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_vpn_set(_state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    match ubus::call("zwrt_router.api", "router_set_alg_switch", Some(&parsed.to_string())) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_qos_get(_state: &AppState) -> (u16, Value) {
    router_qos_get_with(read_smart_qos_mode, |object, method, params| {
        ubus::call(object, method, Some(params))
    })
}

pub fn router_qos_set(_state: &AppState, body: &[u8]) -> (u16, Value) {
    router_qos_set_with(body, read_smart_qos_mode, |object, method, params| {
        ubus::call(object, method, Some(params))
    })
}

fn read_smart_qos_mode() -> Option<String> {
    read_smart_qos_mode_with(ubus::committed_option, ubus::uci_get)
}

fn read_smart_qos_mode_with(
    committed: impl FnOnce(&str, &str, &str) -> Option<String>,
    uci_get: impl FnOnce(&str) -> Result<String, String>,
) -> Option<String> {
    committed("zwrt_smart_mng", "smart_qos", "mode")
        .or_else(|| uci_get("zwrt_smart_mng.smart_qos.mode").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

enum QosBackend {
    SmartMng(String),
    RouterQos(Value),
    RouterQosSwitch(Value),
}

fn detect_qos_backend<FSmart, FUbus>(
    read_smart_mode: FSmart,
    ubus_call: &mut FUbus,
) -> Result<QosBackend, String>
where
    FSmart: FnOnce() -> Option<String>,
    FUbus: FnMut(&str, &str, &str) -> Result<Value, String>,
{
    if let Some(mode) = read_smart_mode()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Ok(QosBackend::SmartMng(mode));
    }
    let first_err = match ubus_call("zwrt_router.api", "router_get_qos", "{}") {
        Ok(data) => {
            if let Some(normalized) = normalize_legacy_qos_para(data) {
                return Ok(QosBackend::RouterQos(normalized));
            }
            None
        }
        Err(error) => Some(error),
    };
    match ubus_call("zwrt_router.api", "router_get_qos_switch", "{}") {
        Ok(data) => {
            if let Some(normalized) = normalize_legacy_qos_para(data) {
                return Ok(QosBackend::RouterQosSwitch(normalized));
            }
            Err(first_err.unwrap_or_else(|| "QoS settings are unavailable on this router".to_string()))
        }
        Err(second_err) => Err(first_err.unwrap_or(second_err)),
    }
}

fn router_qos_get_with<FSmart, FUbus>(
    read_smart_mode: FSmart,
    mut ubus_call: FUbus,
) -> (u16, Value)
where
    FSmart: FnOnce() -> Option<String>,
    FUbus: FnMut(&str, &str, &str) -> Result<Value, String>,
{
    match detect_qos_backend(read_smart_mode, &mut ubus_call) {
        Ok(QosBackend::SmartMng(mode)) => (200, json!({"ok": true, "data": qos_data_from_smart_mode(&mode)})),
        Ok(QosBackend::RouterQos(data)) | Ok(QosBackend::RouterQosSwitch(data)) => {
            (200, json!({"ok": true, "data": data}))
        }
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

fn router_qos_set_with<FSmart, FUbus>(
    body: &[u8],
    read_smart_mode: FSmart,
    mut ubus_call: FUbus,
) -> (u16, Value)
where
    FSmart: FnOnce() -> Option<String>,
    FUbus: FnMut(&str, &str, &str) -> Result<Value, String>,
{
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    if !parsed.is_object() {
        return (400, json!({"ok": false, "error": "expected JSON object"}));
    }
    let backend = match detect_qos_backend(read_smart_mode, &mut ubus_call) {
        Ok(found) => found,
        Err(error) => return (503, json!({"ok": false, "error": error})),
    };
    let (object, method, payload) = match backend {
        QosBackend::SmartMng(_) => match build_qos_mode_payload(&parsed) {
            Ok(value) => ("zwrt_smart_mng.api", "zte_smart_mng_set_qos_mode", value),
            Err(error) => return (400, json!({"ok": false, "error": error})),
        },
        QosBackend::RouterQos(current) => match build_legacy_router_qos_payload(&parsed, &current) {
            Ok(value) => ("zwrt_router.api", "router_set_qos", value),
            Err(error) => return (400, json!({"ok": false, "error": error})),
        },
        QosBackend::RouterQosSwitch(_) => match build_legacy_qos_switch_payload(&parsed) {
            Ok(value) => ("zwrt_router.api", "router_set_qos_switch", value),
            Err(error) => return (400, json!({"ok": false, "error": error})),
        },
    };
    match ubus_call(object, method, &payload.to_string()) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(error) => (503, json!({"ok": false, "error": error})),
    }
}

pub fn router_domain_filter_get(_state: &AppState) -> (u16, Value) {
    match ubus::call("zwrt_router.api", "router_get_domainfilter_rule", Some("{}")) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn router_domain_filter_set(_state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    match ubus::call("zwrt_router.api", "router_set_domain_filter", Some(&parsed.to_string())) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn router_apn_mode_get(_state: &AppState) -> (u16, Value) {
    match ubus::call("zwrt_apn_object", "get_apn_mode", Some("{}")) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn router_apn_mode_set(_state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    match ubus::call("zwrt_apn_object", "set_apn_mode", Some(&parsed.to_string())) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn router_apn_profiles_get(_state: &AppState) -> (u16, Value) {
    match ubus::call("zwrt_apn_object", "get_manu_apn_list", Some("{}")) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn router_apn_profiles_add(_state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    match ubus::call("zwrt_apn_object", "add_manu_apn", Some(&parsed.to_string())) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn router_apn_profiles_modify(_state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    match ubus::call("zwrt_apn_object", "modify_manu_apn", Some(&parsed.to_string())) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn router_apn_auto_profiles(_state: &AppState) -> (u16, Value) {
    match ubus::call("zwrt_apn_object", "get_auto_apn_list", Some("{}")) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn router_apn_profiles_delete(_state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    match ubus::call("zwrt_apn_object", "delete_manu_apn", Some(&parsed.to_string())) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

pub fn router_apn_profiles_activate(_state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    match ubus::call("zwrt_apn_object", "enable_manu_apn_id", Some(&parsed.to_string())) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

#[cfg(test)]
mod tests {
    /// A LAN apply that the firmware took moves LAN HTTPS to the posted
    /// address (the hosts line follows); a refused one changes nothing.
    #[test]
    fn a_lan_apply_moves_https() {
        let w = crate::tls::tests::World::new("lan-apply");
        let mut state = crate::handlers::AppState::new();
        state.tls = std::sync::Arc::new(w.tls());
        state.tls.turn_on().unwrap();
        let body = br#"{"lan_ipaddr":"192.168.8.1","lan_netmask":"255.255.255.0"}"#;
        let (status, _) = super::lan_set_with(&state, body, |_| Err("refused (fake)".into()));
        assert_eq!((status, w.hosts_file().as_deref()), (503, Some("192.168.0.1 u60.home.arpa\n")));
        let sent = std::cell::RefCell::new(String::new());
        let (status, _) = super::lan_set_with(&state, body, |p| {
            *sent.borrow_mut() = p.to_owned();
            Ok(serde_json::json!({"result": "success"}))
        });
        assert_eq!(status, 200);
        assert!(sent.borrow().contains("\"lan_ipaddr\":\"192.168.8.1\""));
        assert_eq!(w.hosts_file().as_deref(), Some("192.168.8.1 u60.home.arpa\n"));
        assert!(state.tls.status().error.unwrap().contains("now 192.168.8.1"));
    }

    use super::compute_dhcp_end;

    /// The old answer: the last octet replaced.
    fn last_octet(ip: &str, n: u32) -> String {
        format!("{}.{n}", &ip[..ip.rfind('.').unwrap()])
    }

    #[test]
    fn dhcp_end_on_a_24_changes_only_past_the_subnet() {
        assert_eq!(compute_dhcp_end("192.168.0.1", "255.255.255.0", "100", "50"), "192.168.0.149");
        for start in 1..=254u32 {
            for limit in 1..=(255 - start) {
                assert_eq!(
                    compute_dhcp_end("192.168.0.1", "255.255.255.0", &start.to_string(), &limit.to_string()),
                    last_octet("192.168.0.1", start + limit - 1),
                    "{start} {limit}"
                );
            }
        }
        // A range past the subnet stops at its last host (before: ".299").
        assert_eq!(compute_dhcp_end("192.168.0.1", "255.255.255.0", "200", "100"), "192.168.0.254");
        assert_eq!(compute_dhcp_end("192.168.0.1", "255.255.255.0", "100", "156"), "192.168.0.254");
    }

    #[test]
    fn dhcp_end_from_the_network_and_netmask() {
        // The verifier's case: a /16 with start 200, limit 100.
        assert_eq!(compute_dhcp_end("10.0.0.1", "255.255.0.0", "200", "100"), "10.0.1.43");
        assert_eq!(compute_dhcp_end("10.0.0.1", "255.255.0.0", "100", "150"), "10.0.0.249");
        assert_eq!(compute_dhcp_end("10.0.5.1", "255.255.0.0", "100", "50"), "10.0.0.149");
        assert_eq!(compute_dhcp_end("172.16.3.1", "255.255.254.0", "300", "10"), "172.16.3.53");
        assert_eq!(compute_dhcp_end("10.0.0.1", "255.255.0.0", "65000", "1000"), "10.0.255.254");
        assert_eq!(compute_dhcp_end("192.168.8.1", "255.255.255.0", "", ""), "192.168.8.149");
        // No usable address or netmask: the old answer.
        assert_eq!(compute_dhcp_end("192.168.0.1", "", "100", "50"), "192.168.0.149");
        assert_eq!(compute_dhcp_end("192.168.0.1", "255.0.255.0", "200", "100"), "192.168.0.299");
        assert_eq!(compute_dhcp_end("", "", "", ""), "192.168.0.149");
        assert_eq!(compute_dhcp_end("192.168.0.1", "255.255.255.0", "0", "0"), "192.168.0.0");
    }
}

fn strict_compute_dhcp_end(base_ip: &str, netmask: &str, start: &str, limit: &str) -> Option<String> {
    let ip = u32::from(base_ip.parse::<Ipv4Addr>().ok()?);
    let mask = u32::from(netmask.parse::<Ipv4Addr>().ok()?);
    let inverse = !mask;
    if !(3..0x8000_0000).contains(&inverse) || inverse & (inverse + 1) != 0 {
        return None;
    }
    let network = ip & mask;
    let offset: u32 = start.parse().ok()?;
    let count: u32 = limit.parse().ok()?;
    let end = offset.checked_add(count.checked_sub(1)?)?;
    if offset == 0 || end >= inverse {
        return None;
    }
    Some(Ipv4Addr::from(network.checked_add(end)?).to_string())
}

fn parse_switch_flag(value: &Value) -> Option<i64> {
    match value {
        Value::Bool(flag) => Some(i64::from(*flag)),
        Value::Number(number) => match number.as_i64() {
            Some(0) => Some(0),
            Some(1) => Some(1),
            _ => None,
        },
        Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "on" => Some(1),
            "0" | "false" | "off" => Some(0),
            _ => None,
        },
        _ => None,
    }
}

fn switch_str(flag: i64) -> &'static str {
    if flag == 0 { "0" } else { "1" }
}

fn value_as_id_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Value::Number(number) if number.is_i64() || number.is_u64() => Some(number.to_string()),
        _ => None,
    }
}

fn is_usable_unicast_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] != 0 && octets[0] != 127 && octets[0] < 224
}

fn parse_usable_unicast_ipv4(raw: &str) -> Result<Ipv4Addr, &'static str> {
    let ip = raw
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| "invalid IPv4 address")?;
    if !is_usable_unicast_ipv4(ip) {
        return Err("IPv4 address must be a usable unicast address");
    }
    Ok(ip)
}

fn read_lan_subnet() -> Result<(Ipv4Addr, Ipv4Addr), String> {
    let (ip_str, mask_str) = match (
        ubus::committed_option("network", "lan", "ipaddr"),
        ubus::committed_option("network", "lan", "netmask"),
    ) {
        (Some(ip), Some(mask)) if !ip.trim().is_empty() && !mask.trim().is_empty() => (ip, mask),
        _ => {
            let network = ubus::uci_show_map(&ubus::uci_show("network.lan")?);
            let ip = network
                .get("network.lan.ipaddr")
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .ok_or_else(|| "LAN setting network.lan.ipaddr is unavailable".to_string())?;
            let mask = network
                .get("network.lan.netmask")
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .ok_or_else(|| "LAN setting network.lan.netmask is unavailable".to_string())?;
            (ip, mask)
        }
    };
    let ip = ip_str
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| "LAN IPv4 address is invalid".to_string())?;
    let mask = mask_str
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| "LAN subnet mask is invalid".to_string())?;
    Ok((ip, mask))
}

fn validate_lan_host(
    target: Ipv4Addr,
    lan_ip: Ipv4Addr,
    lan_mask: Ipv4Addr,
) -> Result<(), &'static str> {
    if !is_usable_unicast_ipv4(target) {
        return Err("destination IP must be a usable unicast IPv4 address");
    }
    let router = u32::from(lan_ip);
    let mask = u32::from(lan_mask);
    let inverse = !mask;
    if !(3..0x8000_0000).contains(&inverse) || inverse & (inverse + 1) != 0 {
        return Err("LAN subnet mask is invalid");
    }
    let network = router & mask;
    let broadcast = network + inverse;
    let host = u32::from(target);
    if host <= network || host >= broadcast || host == router {
        return Err("destination IP must be inside the LAN subnet and different from the router");
    }
    Ok(())
}

fn validate_safe_label(text: &str, max_bytes: usize, err: &'static str) -> Result<(), &'static str> {
    if text.len() > max_bytes {
        return Err(err);
    }
    if text.chars().any(|ch| {
        ch.is_control()
            || matches!(
                ch,
                '\'' | '"' | ';' | '$' | '`' | '\\' | '|' | '<' | '>' | '&'
            )
    }) {
        return Err(err);
    }
    Ok(())
}

fn parse_switch_from_keys(
    map: &serde_json::Map<String, Value>,
    keys: &[&str],
    invalid_err: &'static str,
    conflict_err: &'static str,
) -> Result<i64, &'static str> {
    let mut resolved: Option<i64> = None;
    for key in keys {
        if let Some(value) = map.get(*key).filter(|value| !value.is_null()) {
            let flag = parse_switch_flag(value).ok_or(invalid_err)?;
            if let Some(prev) = resolved {
                if prev != flag {
                    return Err(conflict_err);
                }
            } else {
                resolved = Some(flag);
            }
        }
    }
    resolved.ok_or(invalid_err)
}

fn first_non_null<'a>(
    map: &'a serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter()
        .find_map(|key| map.get(*key).filter(|value| !value.is_null()))
}

fn insert_normalized_switch(
    map: &mut serde_json::Map<String, Value>,
    target: &str,
    sources: &[&str],
) {
    if map.contains_key(target) {
        return;
    }
    let Some(raw) = first_non_null(map, sources) else {
        return;
    };
    if let Some(flag) = parse_switch_flag(raw) {
        map.insert(target.to_string(), Value::String(switch_str(flag).to_string()));
    } else if let Some(text) = raw.as_str().filter(|text| !text.is_empty()) {
        map.insert(target.to_string(), Value::String(text.to_string()));
    }
}

fn normalize_firewall_para(mut data: Value) -> Value {
    if let Some(map) = data.as_object_mut() {
        insert_normalized_switch(map, "firewall_switch", &["firewall_enable"]);
        insert_normalized_switch(map, "nat_switch", &["nat_enable"]);
        insert_normalized_switch(map, "dmz_enabled", &["dmz_enable"]);
        if !map.contains_key("wan_ping_filter") {
            if let Some(flag) = map.get("wan_ping_enable").and_then(parse_switch_flag) {
                let blocked = if flag == 0 { 1 } else { 0 };
                map.insert(
                    "wan_ping_filter".to_string(),
                    Value::String(switch_str(blocked).to_string()),
                );
            }
        }
        insert_normalized_switch(
            map,
            "port_forward_switch",
            &["portmapping_enable", "portforward_enable"],
        );
        if !map.contains_key("firewall_level") {
            if let Some(level) = map.get("level").and_then(Value::as_str) {
                map.insert(
                    "firewall_level".to_string(),
                    Value::String(level.trim().to_ascii_lowercase()),
                );
            }
        }
    }
    data
}

fn build_firewall_switch_payload(parsed: &Value) -> Result<Value, &'static str> {
    let map = parsed.as_object().ok_or("expected JSON object")?;
    let flag = parse_switch_from_keys(
        map,
        &["enable", "firewall_switch"],
        "invalid firewall_switch",
        "conflicting firewall_switch fields",
    )?;
    Ok(json!({"enable": flag}))
}

fn build_firewall_level_payload(parsed: &Value) -> Result<Value, &'static str> {
    let map = parsed.as_object().ok_or("expected JSON object")?;
    let raw = first_non_null(map, &["level", "firewall_level"])
        .and_then(Value::as_str)
        .ok_or("missing firewall_level")?;
    let firmware_level = match raw.trim().to_ascii_lowercase().as_str() {
        "low" => "Low",
        "medium" => "Medium",
        "high" => "High",
        "off" => "Off",
        _ => return Err("invalid firewall_level"),
    };
    Ok(json!({"level": firmware_level}))
}

fn build_nat_switch_payload(parsed: &Value) -> Result<Value, &'static str> {
    let map = parsed.as_object().ok_or("expected JSON object")?;
    let flag = parse_switch_from_keys(
        map,
        &["enable", "nat_switch"],
        "invalid nat_switch",
        "conflicting nat_switch fields",
    )?;
    let mut payload = serde_json::Map::new();
    payload.insert("enable".to_string(), json!(flag));
    if let Some(nat_type) = map
        .get("nat_type")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        payload.insert("nat_type".to_string(), Value::String(nat_type.to_string()));
    }
    Ok(Value::Object(payload))
}

#[derive(Debug, PartialEq, Eq)]
struct DmzWritePlan {
    payload: Value,
    enable_ip: Option<Ipv4Addr>,
    sync_dmz_ip: Option<String>,
}

fn build_dmz_payload(parsed: &Value) -> Result<DmzWritePlan, &'static str> {
    let map = parsed.as_object().ok_or("expected JSON object")?;
    let flag = parse_switch_from_keys(
        map,
        &["dmz_enable", "dmz_enabled"],
        "invalid dmz_enabled",
        "conflicting dmz_enabled fields",
    )?;
    let mut payload = serde_json::Map::new();
    payload.insert("dmz_enable".to_string(), json!(flag));
    let explicit_ip = match map.get("dmz_ip") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                Some(String::new())
            } else {
                let parsed_ip = parse_usable_unicast_ipv4(trimmed).map_err(|_| "invalid dmz_ip")?;
                Some(parsed_ip.to_string())
            }
        }
        Some(_) => return Err("invalid dmz_ip"),
    };
    let (enable_ip, sync_dmz_ip) = if flag == 1 {
        let dmz_ip = explicit_ip
            .filter(|value| !value.is_empty())
            .ok_or("dmz_ip is required when enabling DMZ")?;
        let parsed_ip = dmz_ip.parse::<Ipv4Addr>().map_err(|_| "invalid dmz_ip")?;
        payload.insert("dmz_ip".to_string(), Value::String(dmz_ip));
        (Some(parsed_ip), None)
    } else {
        (None, explicit_ip)
    };
    if let Some(raw_hostname) = map.get("dmz_hostname").filter(|value| !value.is_null()) {
        let hostname = raw_hostname.as_str().ok_or("invalid dmz_hostname")?.trim();
        validate_safe_label(hostname, 64, "invalid dmz_hostname")?;
        if !hostname.is_empty() {
            payload.insert("dmz_hostname".to_string(), Value::String(hostname.to_string()));
        }
    }
    Ok(DmzWritePlan {
        payload: Value::Object(payload),
        enable_ip,
        sync_dmz_ip,
    })
}

fn normalize_upnp_para(mut data: Value) -> Value {
    if let Some(map) = data.as_object_mut() {
        insert_normalized_switch(map, "upnp_switch", &["enable_upnp", "enabled"]);
    }
    data
}

fn build_upnp_switch_payload(parsed: &Value) -> Result<Value, &'static str> {
    let map = parsed.as_object().ok_or("expected JSON object")?;
    let flag = parse_switch_from_keys(
        map,
        &["enable_upnp", "upnp_switch", "enabled"],
        "invalid upnp_switch",
        "conflicting upnp_switch fields",
    )?;
    let mut payload = serde_json::Map::new();
    payload.insert("enable_upnp".to_string(), json!(flag));
    for key in ["notify_interval", "ttl"] {
        if let Some(raw) = map.get(key).filter(|value| !value.is_null()) {
            if raw.as_str().is_some_and(|text| text.trim().is_empty()) {
                continue;
            }
            let parsed_int = raw
                .as_i64()
                .or_else(|| raw.as_str().and_then(|text| text.trim().parse::<i64>().ok()))
                .filter(|number| *number >= 0)
                .ok_or("invalid UPnP numeric parameter")?;
            payload.insert(key.to_string(), json!(parsed_int));
        }
    }
    if let Some(raw) = map.get("natpmp").filter(|value| !value.is_null()) {
        if !raw.as_str().is_some_and(|text| text.trim().is_empty()) {
            let natpmp = parse_switch_flag(raw).ok_or("invalid natpmp")?;
            payload.insert("natpmp".to_string(), json!(natpmp));
        }
    }
    Ok(Value::Object(payload))
}

fn normalize_protocol_from_firmware(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tcp udp" | "udp tcp" | "tcp+udp" | "tcp_udp" | "tcp/udp" | "tcpudp" | "both" | "all" => {
            "tcp+udp".to_string()
        }
        other => other.to_string(),
    }
}

fn normalize_filter_rule_entry(
    section_id: Option<&str>,
    entry: &serde_json::Map<String, Value>,
) -> Value {
    let mut rule = entry.clone();
    if let Some(section) = section_id {
        rule.entry("id".to_string())
            .or_insert_with(|| Value::String(section.to_string()));
    }
    if !rule.contains_key("protocol") {
        if let Some(proto) = entry.get("proto").and_then(Value::as_str) {
            rule.insert(
                "protocol".to_string(),
                Value::String(normalize_protocol_from_firmware(proto)),
            );
        }
    }
    if let Some(flag) = first_non_null(entry, &["enabled", "enable"]).and_then(parse_switch_flag) {
        rule.insert(
            "enabled".to_string(),
            Value::String(switch_str(flag).to_string()),
        );
    }
    Value::Object(rule)
}

fn normalize_filter_rules(data: Value) -> Result<Value, &'static str> {
    let Some(map) = data.as_object() else {
        return Err("router returned a malformed filter rule list");
    };
    if let Some(raw_list) = map.get("rule_list") {
        let Some(list) = raw_list.as_array() else {
            return Err("router returned a malformed filter rule list");
        };
        let mut rules = Vec::with_capacity(list.len());
        for entry in list {
            let Some(obj) = entry.as_object() else {
                return Err("router returned a malformed filter rule list");
            };
            rules.push(normalize_filter_rule_entry(None, obj));
        }
        return Ok(json!({"rule_list": rules}));
    }
    let mut rules = Vec::with_capacity(map.len());
    for (section_id, entry) in map {
        let Some(obj) = entry.as_object() else {
            return Err("router returned a malformed filter rule list");
        };
        rules.push(normalize_filter_rule_entry(Some(section_id), obj));
    }
    Ok(json!({"rule_list": rules}))
}

mod ports {
    use std::net::Ipv4Addr;

    use serde_json::{json, Value};

    use super::{
        normalize_protocol_from_firmware, parse_switch_flag, parse_switch_from_keys,
        parse_usable_unicast_ipv4, switch_str, validate_safe_label, value_as_id_string,
    };

    pub(super) fn reviewed_port_rules_match(expected: &Value, current: &Value, id: &str) -> bool {
        let Some(rules) = current.get("rule_list").and_then(Value::as_array) else {
            return false;
        };
        if !rules.iter().all(Value::is_object) {
            return false;
        }
        if current.get("rule_list") != Some(expected) {
            return false;
        }
        if id.is_empty() {
            return false;
        }
        rules
            .iter()
            .enumerate()
            .filter(|(index, rule)| {
                let reported = rule.get("id");
                match reported {
                    Some(Value::String(value)) => value == id,
                    Some(Value::Number(value)) => value.to_string() == id,
                    None | Some(Value::Null) => index.to_string() == id,
                    _ => false,
                }
            })
            .count()
            == 1
    }

    fn value_as_text(value: &Value) -> Option<String> {
        match value {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        }
    }

    fn parse_single_port(raw: &str) -> Option<u16> {
        if raw.is_empty() || raw.len() > 5 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let port = raw.parse::<u16>().ok()?;
        (port >= 1).then_some(port)
    }

    fn parse_port_spec(value: &Value) -> Result<String, &'static str> {
        match value {
            Value::Number(number) => {
                let port = number.as_u64().ok_or("invalid port")?;
                if !(1..=65535).contains(&port) {
                    return Err("port must be between 1 and 65535");
                }
                Ok(port.to_string())
            }
            Value::String(text) => {
                let trimmed = text.trim();
                if let Some((start_raw, end_raw)) = trimmed.split_once('-') {
                    if end_raw.contains('-') {
                        return Err("invalid port range");
                    }
                    let start = parse_single_port(start_raw).ok_or("invalid port range")?;
                    let end = parse_single_port(end_raw).ok_or("invalid port range")?;
                    if start > end {
                        return Err("invalid port range");
                    }
                    Ok(format!("{start}-{end}"))
                } else {
                    let port =
                        parse_single_port(trimmed).ok_or("port must be between 1 and 65535")?;
                    Ok(port.to_string())
                }
            }
            _ => Err("invalid port"),
        }
    }

    fn parse_src_ip_spec(raw: &str) -> Result<String, &'static str> {
        let trimmed = raw.trim();
        if let Some((ip_part, prefix_part)) = trimmed.split_once('/') {
            let ip = parse_usable_unicast_ipv4(ip_part).map_err(|_| "invalid src_ip")?;
            if prefix_part.is_empty()
                || prefix_part.len() > 2
                || !prefix_part.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err("invalid src_ip");
            }
            let prefix: u8 = prefix_part.parse().map_err(|_| "invalid src_ip")?;
            if !(1..=32).contains(&prefix) {
                return Err("invalid src_ip");
            }
            Ok(format!("{ip}/{prefix}"))
        } else {
            let ip = parse_usable_unicast_ipv4(trimmed).map_err(|_| "invalid src_ip")?;
            Ok(ip.to_string())
        }
    }

    fn protocol_to_firmware(raw: &str) -> Result<&'static str, &'static str> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok("tcp"),
            "udp" => Ok("udp"),
            "tcp+udp" | "tcp udp" | "udp tcp" | "tcp_udp" | "tcp/udp" | "tcpudp" | "both"
            | "all" => Ok("tcp udp"),
            _ => Err("invalid protocol"),
        }
    }

    fn normalize_port_rule_entry(
        section_id: Option<&str>,
        entry: &serde_json::Map<String, Value>,
    ) -> Value {
        let mut rule = serde_json::Map::new();
        if let Some(id) = entry
            .get("id")
            .or_else(|| entry.get("section_id"))
            .and_then(value_as_id_string)
            .or_else(|| section_id.map(str::to_string))
        {
            rule.insert("id".to_string(), Value::String(id));
        }
        let name = entry
            .get("comment")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .or_else(|| entry.get("name").and_then(Value::as_str))
            .unwrap_or("");
        let protocol = entry
            .get("protocol")
            .or_else(|| entry.get("proto"))
            .and_then(Value::as_str)
            .map(normalize_protocol_from_firmware)
            .unwrap_or_default();
        let wan_port = entry
            .get("wan_port")
            .or_else(|| entry.get("src_dport"))
            .and_then(value_as_text)
            .unwrap_or_default();
        let lan_ip = entry
            .get("lan_ip")
            .or_else(|| entry.get("dest_ip"))
            .and_then(value_as_text)
            .unwrap_or_default();
        let lan_port = entry
            .get("lan_port")
            .or_else(|| entry.get("dest_port"))
            .or_else(|| entry.get("src_dport"))
            .and_then(value_as_text)
            .unwrap_or_default();
        let enabled = entry
            .get("enabled")
            .and_then(parse_switch_flag)
            .map(switch_str)
            .unwrap_or("1");
        rule.insert("name".to_string(), Value::String(name.to_string()));
        rule.insert("protocol".to_string(), Value::String(protocol));
        rule.insert("wan_port".to_string(), Value::String(wan_port));
        rule.insert("lan_ip".to_string(), Value::String(lan_ip));
        rule.insert("lan_port".to_string(), Value::String(lan_port));
        rule.insert("enabled".to_string(), Value::String(enabled.to_string()));
        for (key, value) in entry {
            if !matches!(
                key.as_str(),
                "id" | "section_id"
                    | "name"
                    | "comment"
                    | "protocol"
                    | "proto"
                    | "wan_port"
                    | "src_dport"
                    | "lan_ip"
                    | "dest_ip"
                    | "lan_port"
                    | "dest_port"
                    | "enabled"
            ) {
                rule.insert(key.clone(), value.clone());
            }
        }
        Value::Object(rule)
    }

    pub(super) fn normalize_port_rules(data: Value) -> Result<Value, &'static str> {
        let Some(map) = data.as_object() else {
            return Err("router returned a malformed port-forward rule list");
        };
        if let Some(raw_list) = map.get("rule_list") {
            let Some(list) = raw_list.as_array() else {
                return Err("router returned a malformed port-forward rule list");
            };
            let mut rules = Vec::with_capacity(list.len());
            for entry in list {
                let Some(obj) = entry.as_object() else {
                    return Err("router returned a malformed port-forward rule list");
                };
                rules.push(normalize_port_rule_entry(None, obj));
            }
            return Ok(json!({"rule_list": rules}));
        }
        let mut rules = Vec::with_capacity(map.len());
        for (section_id, entry) in map {
            let Some(obj) = entry.as_object() else {
                return Err("router returned a malformed port-forward rule list");
            };
            rules.push(normalize_port_rule_entry(Some(section_id), obj));
        }
        Ok(json!({"rule_list": rules}))
    }

    fn resolve_section_ids(
        map: &serde_json::Map<String, Value>,
    ) -> Result<Vec<String>, &'static str> {
        let from_id = match map.get("id") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value_as_id_string(value).ok_or("invalid rule id")?),
        };
        let from_section = match map.get("section_id") {
            None | Some(Value::Null) => None,
            Some(Value::Array(array)) => {
                if array.is_empty() {
                    return Err("missing rule id");
                }
                let mut ids = Vec::with_capacity(array.len());
                for item in array {
                    ids.push(value_as_id_string(item).ok_or("invalid rule id")?);
                }
                Some(ids)
            }
            Some(value) => Some(vec![value_as_id_string(value).ok_or("invalid rule id")?]),
        };
        match (from_id, from_section) {
            (Some(single), Some(section_ids)) => {
                if section_ids.len() == 1 && section_ids[0] == single {
                    Ok(section_ids)
                } else {
                    Err("conflicting rule id and section_id")
                }
            }
            (Some(single), None) => Ok(vec![single]),
            (None, Some(section_ids)) => Ok(section_ids),
            (None, None) => Err("missing rule id"),
        }
    }

    fn resolve_aliased_field<T, F>(
        map: &serde_json::Map<String, Value>,
        primary: &str,
        alias: &str,
        parse: F,
        conflict_err: &'static str,
    ) -> Result<Option<T>, &'static str>
    where
        T: PartialEq,
        F: Fn(&Value) -> Result<T, &'static str>,
    {
        let first = match map.get(primary) {
            None | Some(Value::Null) => None,
            Some(value) => Some(parse(value)?),
        };
        let second = match map.get(alias) {
            None | Some(Value::Null) => None,
            Some(value) => Some(parse(value)?),
        };
        match (first, second) {
            (Some(lhs), Some(rhs)) => {
                if lhs == rhs {
                    Ok(Some(lhs))
                } else {
                    Err(conflict_err)
                }
            }
            (Some(val), None) | (None, Some(val)) => Ok(Some(val)),
            (None, None) => Ok(None),
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct PortMappingWrite {
        pub(super) payload: Value,
        pub(super) delete_target: Option<String>,
        pub(super) lan_host: Option<Ipv4Addr>,
    }

    pub(super) fn build_port_mapping_write(
        parsed: &Value,
        has_expected_rules: bool,
    ) -> Result<PortMappingWrite, &'static str> {
        let map = parsed.as_object().ok_or("expected JSON object")?;
        let action = map
            .get("action")
            .and_then(Value::as_str)
            .map(str::trim)
            .ok_or("missing action")?;
        match action {
            "delete" => {
                let ids = resolve_section_ids(map)?;
                if has_expected_rules && ids.len() != 1 {
                    return Err("expected_rules requires a single rule id");
                }
                let delete_target = if ids.len() == 1 {
                    Some(ids[0].clone())
                } else {
                    None
                };
                Ok(PortMappingWrite {
                    payload: json!({"action": "delete", "section_id": ids}),
                    delete_target,
                    lan_host: None,
                })
            }
            "add" | "modify" => {
                let mut payload = serde_json::Map::new();
                payload.insert("action".to_string(), Value::String(action.to_string()));
                if action == "modify" {
                    let ids = resolve_section_ids(map)?;
                    if ids.len() != 1 {
                        return Err("modify requires a single rule id");
                    }
                    payload.insert("section_id".to_string(), json!(ids));
                }
                let src_dport = resolve_aliased_field(
                    map,
                    "src_dport",
                    "wan_port",
                    parse_port_spec,
                    "conflicting external port fields",
                )?
                .ok_or("missing external port")?;
                let dest_ip = resolve_aliased_field(
                    map,
                    "dest_ip",
                    "lan_ip",
                    |value| {
                        let text = value.as_str().ok_or("invalid destination IP")?;
                        parse_usable_unicast_ipv4(text).map_err(|_| "invalid destination IP")
                    },
                    "conflicting destination IP fields",
                )?
                .ok_or("missing destination IP")?;
                let dest_port = resolve_aliased_field(
                    map,
                    "dest_port",
                    "lan_port",
                    parse_port_spec,
                    "conflicting internal port fields",
                )?
                .unwrap_or_else(|| src_dport.clone());
                let proto = resolve_aliased_field(
                    map,
                    "proto",
                    "protocol",
                    |value| {
                        let text = value.as_str().ok_or("invalid protocol")?;
                        protocol_to_firmware(text)
                    },
                    "conflicting protocol fields",
                )?
                .ok_or("missing protocol")?;
                let enabled = match map.get("enabled") {
                    Some(value) if !value.is_null() => {
                        parse_switch_flag(value).ok_or("invalid enabled flag")?
                    }
                    _ => 1,
                };
                let raw_comment = match map.get("comment") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(text)) => Some(text.trim().to_string()),
                    Some(_) => return Err("invalid rule name"),
                };
                let raw_name = match map.get("name") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(text)) => Some(text.trim().to_string()),
                    Some(_) => return Err("invalid rule name"),
                };
                let comment = match (raw_comment, raw_name) {
                    (Some(lhs), Some(rhs)) if !lhs.is_empty() && !rhs.is_empty() && lhs != rhs => {
                        return Err("conflicting name and comment");
                    }
                    (Some(lhs), _) if !lhs.is_empty() => lhs,
                    (_, Some(rhs)) => rhs,
                    (Some(lhs), None) => lhs,
                    (None, None) => String::new(),
                };
                validate_safe_label(&comment, 64, "invalid rule name")?;
                payload.insert("src_dport".to_string(), Value::String(src_dport));
                payload.insert("dest_ip".to_string(), Value::String(dest_ip.to_string()));
                payload.insert("dest_port".to_string(), Value::String(dest_port));
                payload.insert("proto".to_string(), Value::String(proto.to_string()));
                payload.insert("enabled".to_string(), json!(enabled));
                payload.insert("comment".to_string(), Value::String(comment));
                if let Some(raw_src_ip) = map.get("src_ip").filter(|value| !value.is_null()) {
                    let text = raw_src_ip.as_str().ok_or("invalid src_ip")?.trim();
                    if !text.is_empty() {
                        let src_ip = parse_src_ip_spec(text)?;
                        payload.insert("src_ip".to_string(), Value::String(src_ip));
                    }
                }
                Ok(PortMappingWrite {
                    payload: Value::Object(payload),
                    delete_target: None,
                    lan_host: Some(dest_ip),
                })
            }
            _ => Err("invalid action"),
        }
    }

    pub(super) fn build_port_forward_switch_payload(parsed: &Value) -> Result<Value, &'static str> {
        let map = parsed.as_object().ok_or("expected JSON object")?;
        let flag = parse_switch_from_keys(
            map,
            &[
                "portmapping_enable",
                "portforward_enable",
                "port_forward_switch",
                "enable",
            ],
            "invalid port_forward_switch",
            "conflicting port_forward_switch fields",
        )?;
        Ok(json!({"portmapping_enable": flag}))
    }
}

mod qos {
    use serde_json::{json, Value};

    use super::{first_non_null, parse_switch_flag, parse_switch_from_keys, switch_str};

    pub(super) fn qos_data_from_smart_mode(mode: &str) -> Value {
        let trimmed = mode.trim();
        let enabled = !matches!(
            trimmed.to_ascii_lowercase().as_str(),
            "nomal_mode" | "normal_mode" | "stop" | "off" | "0" | ""
        );
        json!({
            "qos_switch": switch_str(i64::from(enabled)),
            "qos_mode": trimmed
        })
    }

    pub(super) fn normalize_legacy_qos_para(mut data: Value) -> Option<Value> {
        let map = data.as_object_mut()?;
        let flag =
            first_non_null(map, &["qos_switch", "qos_smart_switch"]).and_then(parse_switch_flag)?;
        map.insert(
            "qos_switch".to_string(),
            Value::String(switch_str(flag).to_string()),
        );
        Some(data)
    }

    pub(super) fn build_qos_mode_payload(parsed: &Value) -> Result<Value, &'static str> {
        let map = parsed.as_object().ok_or("expected JSON object")?;
        if let Some(raw) = map.get("qos_mode").filter(|value| !value.is_null()) {
            let mode_raw = raw.as_str().ok_or("invalid qos_mode")?;
            let mode = match mode_raw.trim() {
                "Nomal_mode" => "Nomal_mode",
                "Ai_mode" => "Ai_mode",
                "Game_mode" => "Game_mode",
                "Video_mode" => "Video_mode",
                "Live_mode" => "Live_mode",
                "Chat_mode" => "Chat_mode",
                _ => return Err("invalid qos_mode"),
            };
            return Ok(json!({"qos_mode": mode}));
        }
        let flag = parse_switch_from_keys(
            map,
            &["qos_switch", "qos_smart_switch", "enable"],
            "invalid qos_switch",
            "conflicting qos_switch fields",
        )?;
        let mode = if flag == 0 { "Nomal_mode" } else { "Ai_mode" };
        Ok(json!({"qos_mode": mode}))
    }

    pub(super) fn build_legacy_router_qos_payload(
        parsed: &Value,
        current: &Value,
    ) -> Result<Value, &'static str> {
        let map = parsed.as_object().ok_or("expected JSON object")?;
        if map.get("qos_mode").is_some_and(|value| !value.is_null()) {
            return Err("qos_mode is not supported on this router");
        }
        let flag = parse_switch_from_keys(
            map,
            &["qos_switch", "qos_smart_switch", "enable"],
            "invalid qos_switch",
            "conflicting qos_switch fields",
        )?;
        let mut payload = serde_json::Map::new();
        payload.insert("qos_smart_switch".to_string(), json!(flag));
        for key in [
            "qos_smart_pri_type",
            "upload_total_limit_rate",
            "upload_total_limit_unit",
            "download_total_limit_rate",
            "download_total_limit_unit",
        ] {
            let candidate = map.get(key).filter(|value| !value.is_null()).or_else(|| {
                (key == "qos_smart_pri_type")
                    .then(|| current.get(key))
                    .flatten()
                    .filter(|value| !value.is_null())
            });
            if let Some(raw) = candidate {
                if raw.as_str().is_some_and(|text| text.trim().is_empty()) {
                    continue;
                }
                let number = raw
                    .as_i64()
                    .or_else(|| {
                        raw.as_str()
                            .and_then(|text| text.trim().parse::<i64>().ok())
                    })
                    .filter(|value| *value >= 0)
                    .ok_or("invalid QoS numeric parameter")?;
                payload.insert(key.to_string(), json!(number));
            }
        }
        Ok(Value::Object(payload))
    }

    pub(super) fn build_legacy_qos_switch_payload(parsed: &Value) -> Result<Value, &'static str> {
        let map = parsed.as_object().ok_or("expected JSON object")?;
        if map.get("qos_mode").is_some_and(|value| !value.is_null()) {
            return Err("qos_mode is not supported on this router");
        }
        let flag = parse_switch_from_keys(
            map,
            &["qos_switch", "qos_smart_switch", "enable"],
            "invalid qos_switch",
            "conflicting qos_switch fields",
        )?;
        Ok(json!({"qos_switch": switch_str(flag)}))
    }
}

#[cfg(test)]
mod console_routing_tests {
    use super::ports::PortMappingWrite;
    use super::*;

    #[test]
    fn dhcp_end_crosses_octets_using_the_actual_subnet() {
        assert_eq!(
            strict_compute_dhcp_end("192.168.1.1", "255.255.254.0", "250", "30"),
            Some("192.168.1.23".into())
        );
    }

    #[test]
    fn dhcp_end_preserves_a_standard_pool() {
        assert_eq!(
            strict_compute_dhcp_end("192.168.0.1", "255.255.255.0", "100", "50"),
            Some("192.168.0.149".into())
        );
    }

    #[test]
    fn dhcp_end_rejects_invalid_configuration_without_inventing_defaults() {
        for (mask, start, count) in [
            ("255.255.255.0", "250", "10"),
            ("255.255.255.0", "100", "0"),
            ("255.0.255.0", "100", "50"),
            ("255.255.255.0", "4294967295", "2"),
            ("255.255.255.0", "bad", "50"),
        ] {
            assert_eq!(strict_compute_dhcp_end("192.168.0.1", mask, start, count), None);
        }
    }

    #[test]
    fn reviewed_rule_deletion_rejects_a_shifted_or_missing_list() {
        let reviewed = json!([{"name":"First"},{"name":"Second"}]);
        assert!(!reviewed_port_rules_match(
            &reviewed,
            &json!({"rule_list":[{"name":"Second"}]}),
            "0"
        ));
        assert!(!reviewed_port_rules_match(
            &reviewed,
            &json!({}),
            "0"
        ));
    }

    #[test]
    fn reviewed_rule_deletion_accepts_numeric_ids_and_position_fallbacks() {
        for (rules, id) in [
            (json!([{"name":"Position"}]), "0"),
            (json!([{"id":42,"name":"Explicit"}]), "42"),
        ] {
            assert!(reviewed_port_rules_match(
                &rules,
                &json!({"rule_list":rules}),
                id
            ));
        }
    }

    #[test]
    fn reviewed_rule_deletion_rejects_duplicate_ids() {
        let rules = json!([{"id":"0","name":"First"},{"id":"0","name":"Second"}]);
        assert!(!reviewed_port_rules_match(
            &rules,
            &json!({"rule_list":rules}),
            "0"
        ));
    }

    #[test]
    fn firewall_para_normalizes_firmware_keys_and_preserves_originals() {
        let raw = json!({
            "firewall_enable": "1",
            "dmz_enable": "0",
            "dmz_ip": "",
            "portforward_enable": "0",
            "portmapping_enable": "1",
            "wan_ping_enable": "0",
            "nat_enable": "1",
            "level": "High"
        });
        let normalized = normalize_firewall_para(raw);
        assert_eq!(normalized["firewall_switch"], "1");
        assert_eq!(normalized["nat_switch"], "1");
        assert_eq!(normalized["dmz_enabled"], "0");
        assert_eq!(normalized["dmz_ip"], "");
        assert_eq!(normalized["port_forward_switch"], "1");
        assert_eq!(normalized["wan_ping_filter"], "1");
        assert_eq!(normalized["wan_ping_enable"], "0");
        assert_eq!(normalized["firewall_level"], "high");
        assert_eq!(normalized["firewall_enable"], "1");

        let ping_allowed = normalize_firewall_para(json!({"wan_ping_enable": "1"}));
        assert_eq!(ping_allowed["wan_ping_filter"], "0");
        assert_eq!(ping_allowed["wan_ping_enable"], "1");

        let explicit_filter = normalize_firewall_para(json!({
            "wan_ping_enable": "1",
            "wan_ping_filter": "1"
        }));
        assert_eq!(explicit_filter["wan_ping_filter"], "1");
    }

    #[test]
    fn firewall_para_keeps_empty_level_key_present() {
        let normalized = normalize_firewall_para(json!({"firewall_enable": "1", "level": ""}));
        assert_eq!(normalized.get("firewall_level"), Some(&json!("")));
    }

    #[test]
    fn firewall_write_payloads_translate_to_firmware_schema() {
        assert_eq!(
            build_firewall_switch_payload(&json!({"firewall_switch": "0"})).unwrap(),
            json!({"enable": 0})
        );
        assert_eq!(
            build_firewall_level_payload(&json!({"firewall_level": "medium"})).unwrap(),
            json!({"level": "Medium"})
        );
        assert_eq!(
            build_firewall_level_payload(&json!({"firewall_level": "HIGH"})).unwrap(),
            json!({"level": "High"})
        );
        assert!(build_firewall_level_payload(&json!({"firewall_level": "extreme"})).is_err());
        assert_eq!(
            build_nat_switch_payload(&json!({"nat_switch": "1"})).unwrap(),
            json!({"enable": 1})
        );
        assert_eq!(
            build_dmz_payload(&json!({"dmz_enabled": "1", "dmz_ip": "192.168.0.10"})).unwrap(),
            DmzWritePlan {
                payload: json!({"dmz_enable": 1, "dmz_ip": "192.168.0.10"}),
                enable_ip: Some(Ipv4Addr::new(192, 168, 0, 10)),
                sync_dmz_ip: None,
            }
        );
        assert_eq!(
            build_dmz_payload(&json!({"dmz_enabled": "0", "dmz_ip": ""})).unwrap(),
            DmzWritePlan {
                payload: json!({"dmz_enable": 0}),
                enable_ip: None,
                sync_dmz_ip: Some(String::new()),
            }
        );
        assert_eq!(
            build_dmz_payload(&json!({"dmz_enabled": "0", "dmz_ip": "192.168.0.10"})).unwrap(),
            DmzWritePlan {
                payload: json!({"dmz_enable": 0}),
                enable_ip: None,
                sync_dmz_ip: Some("192.168.0.10".to_string()),
            }
        );
        assert_eq!(
            build_dmz_payload(&json!({"dmz_enabled": "0"})).unwrap(),
            DmzWritePlan {
                payload: json!({"dmz_enable": 0}),
                enable_ip: None,
                sync_dmz_ip: None,
            }
        );
        assert!(build_dmz_payload(&json!({"dmz_enabled": "1", "dmz_ip": ""})).is_err());
        assert!(build_dmz_payload(&json!({"dmz_enabled": "0", "dmz_ip": "not-an-ip"})).is_err());
        assert!(build_dmz_payload(&json!({"dmz_enabled": "0", "dmz_ip": "127.0.0.1"})).is_err());
        assert_eq!(
            build_port_forward_switch_payload(&json!({"port_forward_switch": "1"})).unwrap(),
            json!({"portmapping_enable": 1})
        );
    }

    #[test]
    fn upnp_normalizes_read_and_translates_write() {
        let normalized = normalize_upnp_para(json!({
            "enabled": "0",
            "enable_upnp": "1",
            "notify_interval": "60",
            "ttl": "",
            "enable_natpmp": "0"
        }));
        assert_eq!(normalized["upnp_switch"], "1");
        assert_eq!(normalized["notify_interval"], "60");
        assert_eq!(
            build_upnp_switch_payload(&json!({"upnp_switch": "1"})).unwrap(),
            json!({"enable_upnp": 1})
        );
        assert_eq!(
            build_upnp_switch_payload(&json!({"upnp_switch": "0", "notify_interval": "60"}))
                .unwrap(),
            json!({"enable_upnp": 0, "notify_interval": 60})
        );
    }

    #[test]
    fn port_rules_normalize_empty_and_section_keyed_firmware_maps() {
        assert_eq!(normalize_port_rules(json!({})).unwrap(), json!({"rule_list": []}));
        let firmware = json!({
            "cfg0a1b2c": {
                "name": "Home server",
                "proto": "tcp udp",
                "src_ip": "203.0.113.5",
                "src_dport": "8443",
                "dest_ip": "192.168.0.10",
                "dest_port": "443",
                "enabled": "1"
            }
        });
        let normalized = normalize_port_rules(firmware).unwrap();
        assert_eq!(
            normalized,
            json!({
                "rule_list": [{
                    "id": "cfg0a1b2c",
                    "name": "Home server",
                    "protocol": "tcp+udp",
                    "wan_port": "8443",
                    "lan_ip": "192.168.0.10",
                    "lan_port": "443",
                    "enabled": "1",
                    "src_ip": "203.0.113.5"
                }]
            })
        );
        assert!(reviewed_port_rules_match(
            &normalized["rule_list"],
            &normalized,
            "cfg0a1b2c"
        ));
        let mut changed_src = normalized.clone();
        changed_src["rule_list"][0]["src_ip"] = json!("198.51.100.9");
        assert!(!reviewed_port_rules_match(
            &normalized["rule_list"],
            &changed_src,
            "cfg0a1b2c"
        ));
        assert!(normalize_port_rules(json!({"rule_list": ["bad", {"name": "Second"}]})).is_err());
        assert!(normalize_port_rules(json!({"rule_list": "corrupt"})).is_err());
        assert!(normalize_port_rules(json!({"cfg0": "bad"})).is_err());
        assert!(normalize_port_rules(Value::Null).is_err());
    }

    #[test]
    fn port_mapping_payload_translates_add_and_delete() {
        assert_eq!(
            build_port_mapping_write(
                &json!({
                    "action": "add",
                    "name": "Home server",
                    "protocol": "tcp+udp",
                    "wan_port": "8443",
                    "lan_ip": "192.168.0.10",
                    "lan_port": "443",
                    "enabled": "1",
                    "src_ip": "203.0.113.0/24"
                }),
                false
            )
            .unwrap(),
            PortMappingWrite {
                payload: json!({
                    "action": "add",
                    "src_dport": "8443",
                    "dest_ip": "192.168.0.10",
                    "dest_port": "443",
                    "proto": "tcp udp",
                    "enabled": 1,
                    "comment": "Home server",
                    "src_ip": "203.0.113.0/24"
                }),
                delete_target: None,
                lan_host: Some(Ipv4Addr::new(192, 168, 0, 10)),
            }
        );
        assert_eq!(
            build_port_mapping_write(&json!({"action": "delete", "id": "cfg0a1b2c"}), true)
                .unwrap(),
            PortMappingWrite {
                payload: json!({"action": "delete", "section_id": ["cfg0a1b2c"]}),
                delete_target: Some("cfg0a1b2c".to_string()),
                lan_host: None,
            }
        );
        assert!(build_port_mapping_write(&json!({"action": "delete"}), false).is_err());
        assert!(
            build_port_mapping_write(
                &json!({"action": "delete", "id": "ruleA", "section_id": ["ruleB"]}),
                true
            )
            .is_err()
        );
        assert!(
            build_port_mapping_write(
                &json!({"action": "delete", "section_id": ["ruleA", "ruleB"]}),
                true
            )
            .is_err()
        );
        assert!(
            build_port_mapping_write(
                &json!({"action": "delete", "section_id": ["ruleA", "ruleB"]}),
                false
            )
            .is_ok()
        );
        for bad in [
            json!({"action": "add", "protocol": "icmp", "wan_port": "80", "lan_ip": "192.168.0.10", "lan_port": "80"}),
            json!({"action": "add", "protocol": "tcp", "wan_port": true, "lan_ip": "192.168.0.10", "lan_port": "80"}),
            json!({"action": "add", "protocol": "tcp", "wan_port": "0", "lan_ip": "192.168.0.10", "lan_port": "80"}),
            json!({"action": "add", "protocol": "tcp", "wan_port": "65536", "lan_ip": "192.168.0.10", "lan_port": "80"}),
            json!({"action": "add", "protocol": "tcp", "wan_port": "90-80", "lan_ip": "192.168.0.10", "lan_port": "80"}),
            json!({"action": "add", "protocol": "tcp", "wan_port": "80;id", "lan_ip": "192.168.0.10", "lan_port": "80"}),
            json!({"action": "add", "protocol": "tcp", "wan_port": "80", "lan_ip": "127.0.0.1", "lan_port": "80"}),
            json!({"action": "add", "protocol": "tcp", "wan_port": "80", "lan_ip": "not-an-ip", "lan_port": "80"}),
            json!({"action": "add", "protocol": "tcp", "wan_port": "80", "lan_ip": "192.168.0.10", "lan_port": ""}),
            json!({"action": "add", "protocol": "tcp", "wan_port": "80", "lan_ip": "192.168.0.10", "lan_port": "80", "name": "bad;cmd"}),
            json!({"action": "add", "protocol": "tcp", "wan_port": "80", "lan_ip": "192.168.0.10", "lan_port": "80", "src_ip": "not-a-cidr"}),
        ] {
            assert!(build_port_mapping_write(&bad, false).is_err(), "expected error for {bad}");
        }
    }

    #[test]
    fn port_forward_reads_only_the_required_state_before_writing() {
        use std::cell::RefCell;

        let steps = RefCell::new(Vec::new());
        let wan_rule = json!({"cfgA": {"comment": "A", "proto": "udp", "src_dport": "53", "dest_ip": "192.168.0.10", "dest_port": "5300"}});
        let reviewed = json!([{"id": "cfgA", "name": "A", "protocol": "udp", "wan_port": "53", "lan_ip": "192.168.0.10", "lan_port": "5300", "enabled": "1"}]);
        let add = json!({"action": "add", "name": "A", "protocol": "udp", "wan_port": "53", "lan_ip": "192.168.0.10", "lan_port": "5300", "enabled": "1"});
        let delete = json!({"action": "delete", "id": "cfgA", "expected_rules": reviewed});
        for (input, expected_steps, expected_write) in [
            (add, ["lan", "set"], json!({"action": "add", "comment": "A", "proto": "udp", "src_dport": "53", "dest_ip": "192.168.0.10", "dest_port": "5300", "enabled": 1})),
            (delete, ["get", "set"], json!({"action": "delete", "section_id": ["cfgA"]})),
        ] {
            let response = router_firewall_port_forward_set_with(
                input.to_string().as_bytes(),
                || {
                    steps.borrow_mut().push("lan");
                    Ok((Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 255, 0)))
                },
                || {
                    steps.borrow_mut().push("get");
                    Ok(wan_rule.clone())
                },
                |payload| {
                    steps.borrow_mut().push("set");
                    assert_eq!(serde_json::from_str::<Value>(payload).unwrap(), expected_write);
                    Ok(json!({"status": "applied"}))
                },
            );
            assert_eq!(response, (200, json!({"ok": true, "data": {"status": "applied"}})));
            assert_eq!(*steps.borrow(), expected_steps);
            steps.borrow_mut().clear();
        }
    }

    #[test]
    fn guarded_port_forward_delete_enforces_single_target_and_rejects_malformed_lists() {
        let lan = || Ok((Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 255, 0)));
        let mut called = false;
        let (status, _) = router_firewall_port_forward_set_with(
            br#"{"action":"delete","id":"cfgA","section_id":["cfgB"],"expected_rules":[{"id":"cfgA","name":"A","protocol":"tcp","wan_port":"80","lan_ip":"192.168.0.10","lan_port":"80","enabled":"1"}]}"#,
            lan,
            || Ok(json!({"cfgA":{"name":"A","proto":"tcp","src_dport":"80","dest_ip":"192.168.0.10","dest_port":"80","enabled":"1"}})),
            |_| {
                called = true;
                Ok(json!({}))
            },
        );
        assert_eq!(status, 400);
        assert!(!called);

        let (status, _) = router_firewall_port_forward_set_with(
            br#"{"action":"delete","id":"0","expected_rules":[{"name":"Second","protocol":"tcp","wan_port":"80","lan_ip":"192.168.0.10","lan_port":"80","enabled":"1"}]}"#,
            lan,
            || Ok(json!({"rule_list":["corrupt",{"name":"Second","proto":"tcp","src_dport":"80","dest_ip":"192.168.0.10","dest_port":"80","enabled":"1"}]})),
            |_| {
                called = true;
                Ok(json!({}))
            },
        );
        assert_eq!(status, 503);
        assert!(!called);

        let (status, _) = router_firewall_port_forward_set_with(
            br#"{"action":"add","name":"Outside","protocol":"tcp","wan_port":"80","lan_ip":"10.0.0.2","lan_port":"80","enabled":"1"}"#,
            lan,
            || Ok(json!({})),
            |_| {
                called = true;
                Ok(json!({}))
            },
        );
        assert_eq!(status, 400);
        assert!(!called);
    }

    #[test]
    fn dmz_write_persists_disabled_ip_and_reports_uci_failures() {
        let lan = || Ok((Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 255, 0)));
        let mut written = None;
        let (status, _) = router_firewall_dmz_set_with(
            br#"{"dmz_enabled":"0","dmz_ip":"192.168.0.10"}"#,
            lan,
            |_| Ok(json!({})),
            || Ok("zwrt_router.firewall=zudata_firewall\n".to_string()),
            |value| {
                written = Some(value.to_string());
                Ok(())
            },
        );
        assert_eq!(status, 200);
        assert_eq!(written.as_deref(), Some("192.168.0.10"));

        let (status, _) = router_firewall_dmz_set_with(
            br#"{"dmz_enabled":"0","dmz_ip":""}"#,
            lan,
            |_| Ok(json!({})),
            || Err("uci timeout".to_string()),
            |_| Ok(()),
        );
        assert_eq!(status, 503);

        let (status, _) = router_firewall_dmz_set_with(
            br#"{"dmz_enabled":"0","dmz_ip":""}"#,
            lan,
            |_| Ok(json!({})),
            || Ok("zwrt_router.firewall.dmz_ip='192.168.0.10'\n".to_string()),
            |_| Err("uci commit failed".to_string()),
        );
        assert_eq!(status, 503);

        let (status, _) = router_firewall_dmz_set_with(
            br#"{"dmz_enabled":"1","dmz_ip":"192.168.0.1"}"#,
            lan,
            |_| Ok(json!({})),
            || Ok(String::new()),
            |_| Ok(()),
        );
        assert_eq!(status, 400);
    }

    #[test]
    fn filter_rules_normalize_empty_and_section_keyed_maps() {
        assert_eq!(normalize_filter_rules(json!({})).unwrap(), json!({"rule_list": []}));
        let firmware = json!({
            "cfg112233": {
                "src_mac": "AA:BB:CC:DD:EE:FF",
                "src_ip": "192.168.0.25",
                "src_port": "1024-65535",
                "dest_ip": "203.0.113.10",
                "dest_port": "443",
                "proto": "tcp udp",
                "enabled": 1,
                "target": "DROP"
            }
        });
        let normalized = normalize_filter_rules(firmware).unwrap();
        assert_eq!(
            normalized,
            json!({
                "rule_list": [{
                    "id": "cfg112233",
                    "src_mac": "AA:BB:CC:DD:EE:FF",
                    "src_ip": "192.168.0.25",
                    "src_port": "1024-65535",
                    "dest_ip": "203.0.113.10",
                    "dest_port": "443",
                    "proto": "tcp udp",
                    "protocol": "tcp+udp",
                    "enabled": "1",
                    "target": "DROP"
                }]
            })
        );
        assert!(normalize_filter_rules(json!({"rule_list": ["bad"]})).is_err());
        assert!(normalize_filter_rules(json!({"cfg0": "bad"})).is_err());
    }

    #[test]
    fn qos_reads_committed_mode_then_uci_then_legacy_ubus_in_order() {
        use std::cell::RefCell;

        for (committed, uci, expected_steps, expected_data) in [
            (
                Some(" Game_mode "),
                Err("unused"),
                &[][..],
                json!({"qos_mode": "Game_mode", "qos_switch": "1"}),
            ),
            (
                None,
                Ok(" Nomal_mode "),
                &["uci"][..],
                json!({"qos_mode": "Nomal_mode", "qos_switch": "0"}),
            ),
            (
                None,
                Err("mode unavailable"),
                &["uci", "router_get_qos", "router_get_qos_switch"][..],
                json!({"qos_switch": "1", "vendor_key": 42}),
            ),
            (
                Some(" "),
                Ok("unused"),
                &["router_get_qos", "router_get_qos_switch"][..],
                json!({"qos_switch": "1", "vendor_key": 42}),
            ),
        ] {
            let steps = RefCell::new(Vec::new());
            let response = router_qos_get_with(
                || {
                    read_smart_qos_mode_with(
                        |package, section, key| {
                            assert_eq!((package, section, key), ("zwrt_smart_mng", "smart_qos", "mode"));
                            steps.borrow_mut().push("committed");
                            committed.map(str::to_owned)
                        },
                        |key| {
                            assert_eq!(key, "zwrt_smart_mng.smart_qos.mode");
                            steps.borrow_mut().push("uci");
                            uci.map(str::to_owned).map_err(str::to_owned)
                        },
                    )
                },
                |object, method, params| {
                    assert_eq!((object, params), ("zwrt_router.api", "{}"));
                    match method {
                        "router_get_qos" => {
                            steps.borrow_mut().push("router_get_qos");
                            Ok(json!({}))
                        }
                        "router_get_qos_switch" => {
                            steps.borrow_mut().push("router_get_qos_switch");
                            Ok(json!({"qos_switch": true, "vendor_key": 42}))
                        }
                        _ => panic!("unexpected method: {method}"),
                    }
                },
            );
            assert_eq!(response, (200, json!({"ok": true, "data": expected_data})));
            let mut expected = vec!["committed"];
            expected.extend_from_slice(expected_steps);
            assert_eq!(steps.into_inner(), expected);
        }
    }

    #[test]
    fn qos_translates_smart_mng_and_legacy_backends() {
        assert_eq!(
            qos_data_from_smart_mode("Nomal_mode"),
            json!({"qos_switch": "0", "qos_mode": "Nomal_mode"})
        );
        assert_eq!(
            qos_data_from_smart_mode("Ai_mode"),
            json!({"qos_switch": "1", "qos_mode": "Ai_mode"})
        );
        assert_eq!(
            build_qos_mode_payload(&json!({"qos_switch": "1"})).unwrap(),
            json!({"qos_mode": "Ai_mode"})
        );
        assert_eq!(
            build_qos_mode_payload(&json!({"qos_switch": "0"})).unwrap(),
            json!({"qos_mode": "Nomal_mode"})
        );
        assert_eq!(
            build_qos_mode_payload(&json!({"qos_mode": "Game_mode"})).unwrap(),
            json!({"qos_mode": "Game_mode"})
        );
        assert!(build_qos_mode_payload(&json!({"qos_mode": "Bogus_mode"})).is_err());
        assert!(normalize_legacy_qos_para(json!({})).is_none());
        assert_eq!(
            normalize_legacy_qos_para(json!({"qos_smart_switch": "1"})),
            Some(json!({"qos_smart_switch": "1", "qos_switch": "1"}))
        );

        let mut calls = Vec::new();
        let (status, body) = router_qos_get_with(
            || None,
            |object, method, _params| {
                calls.push((object.to_string(), method.to_string()));
                if method == "router_get_qos" {
                    Ok(json!({"qos_smart_switch": "0", "qos_smart_pri_type": "2"}))
                } else {
                    Err("unexpected".to_string())
                }
            },
        );
        assert_eq!(status, 200);
        assert_eq!(body["data"]["qos_switch"], "0");
        assert_eq!(calls, vec![("zwrt_router.api".into(), "router_get_qos".into())]);

        let mut write_calls = Vec::new();
        let (status, _) = router_qos_set_with(
            br#"{"qos_switch":"1"}"#,
            || None,
            |object, method, params| {
                write_calls.push((object.to_string(), method.to_string(), params.to_string()));
                match method {
                    "router_get_qos" => Ok(json!({"qos_smart_switch": "0", "qos_smart_pri_type": "2"})),
                    "router_set_qos" => Ok(json!({})),
                    _ => Err("unexpected".to_string()),
                }
            },
        );
        assert_eq!(status, 200);
        assert_eq!(write_calls.len(), 2);
        assert_eq!(write_calls[1].0, "zwrt_router.api");
        assert_eq!(write_calls[1].1, "router_set_qos");
        assert_eq!(
            serde_json::from_str::<Value>(&write_calls[1].2).unwrap(),
            json!({"qos_smart_switch": 1, "qos_smart_pri_type": 2})
        );

        let mut switch_calls = Vec::new();
        let (status, _) = router_qos_set_with(
            br#"{"qos_switch":"1"}"#,
            || None,
            |object, method, params| {
                switch_calls.push((object.to_string(), method.to_string(), params.to_string()));
                match method {
                    "router_get_qos" => Err("Method not found".to_string()),
                    "router_get_qos_switch" => Ok(json!({"qos_switch": "0"})),
                    "router_set_qos_switch" => Ok(json!({})),
                    _ => Err("unexpected".to_string()),
                }
            },
        );
        assert_eq!(status, 200);
        assert_eq!(switch_calls[2].0, "zwrt_router.api");
        assert_eq!(switch_calls[2].1, "router_set_qos_switch");
        assert_eq!(
            serde_json::from_str::<Value>(&switch_calls[2].2).unwrap(),
            json!({"qos_switch": "1"})
        );

        let (status, _) = router_qos_set_with(
            br#"{"qos_mode":"Game_mode"}"#,
            || None,
            |_object, method, _params| {
                if method == "router_get_qos" {
                    Ok(json!({"qos_smart_switch": "0"}))
                } else {
                    Err("unexpected".to_string())
                }
            },
        );
        assert_eq!(status, 400);

        let mut smart_calls = Vec::new();
        let (status, _) = router_qos_set_with(
            br#"{"qos_switch":"1"}"#,
            || Some("Nomal_mode".to_string()),
            |object, method, params| {
                smart_calls.push((object.to_string(), method.to_string(), params.to_string()));
                Ok(json!({}))
            },
        );
        assert_eq!(status, 200);
        assert_eq!(smart_calls.len(), 1);
        assert_eq!(smart_calls[0].0, "zwrt_smart_mng.api");
        assert_eq!(smart_calls[0].1, "zte_smart_mng_set_qos_mode");
        assert_eq!(
            serde_json::from_str::<Value>(&smart_calls[0].2).unwrap(),
            json!({"qos_mode": "Ai_mode"})
        );
    }
}
