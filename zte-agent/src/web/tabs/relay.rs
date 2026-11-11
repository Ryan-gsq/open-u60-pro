//! Web-only Wi-Fi relay tab; the companion apps deliberately stay unchanged.

use serde_json::json;

use crate::server::Method;
use crate::web::action::{Action, After, Confirm, Field, Kind, Need};
use crate::web::kit::Tab;
use crate::web::pages::network;
use crate::web::screen::{Block, Read, Screen};

pub static RELAY: Screen = Screen {
    path: network::RELAY,
    id: "relay",
    title: "Wi-Fi Relay",
    tab: Tab::Relay,
    reads: &[Read::Api("/api/wifi-relay/status")],
    blocks: &[Block::Custom(network::relay_page)],
    ..Screen::BLANK
};

pub static SCAN: Action = Action {
    path: network::SCAN,
    screen: &RELAY,
    fields: &[],
    confirm: &[],
    confirm_at: None,
    unchanged: None,
    reads: &[],
    call: (Method::Post, "/api/wifi-relay/scan"),
    body: |_, _| Some(json!({})),
    after: After::Flash(|_, _| (Some(true), "Wi-Fi scan complete.".into())),
    again: None,
    once: true,
};

pub static DISCONNECT: Action = Action {
    path: network::DISCONNECT,
    screen: &RELAY,
    fields: &[],
    confirm: &[],
    confirm_at: None,
    unchanged: None,
    reads: &[],
    call: (Method::Post, "/api/wifi-relay/disconnect"),
    body: |_, _| Some(json!({})),
    after: After::Flash(|_, _| (Some(true), "Relay disconnected. Previous hotspot settings restored; cellular data is used only if already enabled.".into())),
    again: None,
    once: true,
};

/// Installs or removes the IPACM entry for hardware forwarding.
pub static OFFLOAD: Action = Action {
    path: network::OFFLOAD,
    screen: &RELAY,
    fields: &[Field { name: "install", kind: Kind::Choice(&["0", "1"]) }],
    confirm: &[],
    confirm_at: None,
    unchanged: None,
    reads: &[],
    call: (Method::Post, "/api/wifi-relay/offload"),
    body: |v, _| Some(json!({"install": v.get("install") == "1"})),
    after: After::Flash(|v, data| (Some(true), if v.get("install") != "1" {
        "Hardware forwarding removed. The relay forwards on the CPU now; restart the router to unload it fully."
    } else if data["offload"]["config"] == "loaded" {
        "Hardware forwarding installed. The router had already loaded it, so it applies at once."
    } else {
        "Hardware forwarding installed. Restart the router to load it; the relay then reconnects by itself if a restart choice is saved."
    }.into())),
    again: None,
    once: true,
};

/// Turns hardware forwarding on or off without a restart (a connected relay
/// follows at once).
pub static OFFLOAD_SWITCH: Action = Action {
    path: network::OFFLOAD_SWITCH,
    screen: &RELAY,
    fields: &[Field { name: "enabled", kind: Kind::Choice(&["0", "1"]) }],
    confirm: &[],
    confirm_at: None,
    unchanged: None,
    reads: &[],
    call: (Method::Post, "/api/wifi-relay/offload"),
    body: |v, _| Some(json!({"enabled": v.get("enabled") == "1"})),
    after: After::Flash(|v, data| {
        let (ok, note) = reset_note(&data["reset"]);
        (ok, format!("{}{note}", if v.get("enabled") == "1" {
            "Hardware forwarding on. A connected relay uses it at once."
        } else {
            "Hardware forwarding off. The relay forwards on the CPU."
        }))
    }),
    again: None,
    once: true,
};

/// What resetting existing LAN connections did (`conntrack::Report::json`,
/// null when the path did not change): said as it happened, never assumed.
pub fn reset_note(reset: &serde_json::Value) -> (Option<bool>, String) {
    let scope = reset["scope"].as_str().unwrap_or("LAN IPv4");
    match reset["result"].as_str() {
        Some("reset") => (Some(true), format!(" Existing {scope} connections were reset ({}).", reset["deleted"].as_u64().unwrap_or(0))),
        Some("none") => (Some(true), format!(" No existing {scope} connection needed a reset.")),
        Some("merged") => (Some(true), format!(" Existing {scope} connections were already reset for this change.")),
        Some("failed") => (None, format!(" Existing {scope} connections were not all reset; the router retries.")),
        _ => (Some(true), String::new()),
    }
}

/// Whether relay connections turn the upstream Wi-Fi power save off.
pub static POWER_SAVE: Action = Action {
    path: network::POWER_SAVE,
    screen: &RELAY,
    fields: &[Field { name: "auto_off", kind: Kind::Choice(&["0", "1"]) }],
    confirm: &[],
    confirm_at: None,
    unchanged: None,
    reads: &[],
    call: (Method::Post, "/api/wifi-relay/power-save"),
    body: |v, _| Some(json!({"auto_off": v.get("auto_off") == "1"})),
    after: After::Flash(|v, _| (Some(true), if v.get("auto_off") == "1" {
        "Wi-Fi power save turns off at every relay connection, the current one included."
    } else {
        "Wi-Fi power save stays at the driver's default (on), the current connection included."
    }.into())),
    again: None,
    once: true,
};

// Installation uses the generic action confirmation table on the setup page.
pub static INSTALL_CONFIRM: &[Confirm] = &[Confirm {
    when: ("install", "1"),
    need: Need::Always,
    title: "Install Mihomo and Zashboard?",
    lines: &[
        "Downloads about 22 MB from official GitHub releases. Cellular data may be used. The proxy remains off until you save a configuration and start it.",
    ],
    remote: None,
    label: "Download & install",
}];
