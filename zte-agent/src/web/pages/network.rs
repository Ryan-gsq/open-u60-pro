//! Web-only optional networking controls. All device effects use the same
//! Rust handlers as the authenticated JSON routes; no mobile UI changes.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::Method as HttpMethod;
use axum::response::Response;
use maud::{html, Markup};
use serde_json::json;

use crate::handlers::AppState;
use crate::httpd::{api, gate::Lane, Ctx};
use crate::server::Method;
use crate::web::job::{self, OnceJob, Sent};
use crate::web::kit;
use crate::web::render::{self, once_field};
use crate::web::screen::PageData;
use crate::web::session::{self, Form};
use crate::web::store::{Token, SETTLE_SLOW};
use crate::web::CspNonce;

pub const MIHOMO: &str = "/ui/router/mihomo";
pub const SWITCH: &str = "/ui/router/mihomo/switch";
pub const INSTALL: &str = "/ui/router/mihomo/install";
pub const CONFIG: &str = "/ui/router/mihomo/config";
pub const OPEN: &str = "/ui/router/mihomo/open";
pub const DIRECT_BYPASS: &str = "/ui/router/mihomo/direct-bypass";
pub const RELAY: &str = "/ui/relay";
pub const SCAN: &str = "/ui/relay/scan";
pub const CONNECT: &str = "/ui/relay/connect";
pub const DISCONNECT: &str = "/ui/relay/disconnect";
pub const CLOCK: &str = "/ui/relay/clock";
pub const FORGET: &str = "/ui/relay/forget";
pub const OFFLOAD_SWITCH: &str = "/ui/relay/offload-switch";
pub const POWER_SAVE: &str = "/ui/relay/power-save";

pub fn mihomo_card(pd: &PageData) -> Markup {
    let Some(status) = pd.read(0) else {
        return html! { p.msg.err { "Mihomo status unavailable" } };
    };
    let on = status["running"].as_bool() == Some(true);
    let hidden = html! { (pd.csrf()) (once_field(&pd.once())) };
    let state = if on { "Running" } else { "Off" };
    kit::section(
        Some("Mihomo / Clash"),
        Some(html! {
            p.foot { "Experimental LAN TCP/UDP, IPv4/IPv6 interception. Node UDP support and IPv6 exit reachability still apply. Off restores direct routing; it is not a kill switch." }
            @if let Some(e) = status["error"].as_str() { p.foot.err role="alert" { (e) } }
        }),
        html! {
            li {
                form method="post" action=(SWITCH) data-net-switch {
                    (hidden)
                    input type="hidden" name="enable" value=(if on { "0" } else { "1" });
                    div.it {
                        span { "Clash proxy" small data-net-state data-idle-label=(state) role="status" { (state) } }
                        span data-net-spinner-host hidden {}
                        button.sw type="submit" role="switch" aria-checked=(if on { "true" } else { "false" }) aria-label="Clash proxy"
                            data-busy-label=(if on { "Stopping Clash..." } else { "Starting Clash..." }) {}
                    }
                    div data-net-feedback {}
                }
            }
            @if on { li { a.it href=(OPEN) target="_blank" rel="noopener noreferrer" { span { "Open Zashboard" } (kit::icon(kit::Icon::Arrows)) } } }
            (kit::link_row(MIHOMO, Some(kit::Icon::Gear), "Mihomo setup & status"))
        },
    )
}

/// The controller's state (`mihomo::controller::Phase`), as the page says it.
fn state_label(s: &serde_json::Value) -> String {
    match s["state"].as_str() {
        Some("running") => "Running".into(),
        Some("starting") => "Starting".into(),
        Some("restarting") => format!("Restarting{}", s["reason"].as_str().map(|r| format!(" ({r})")).unwrap_or_default()),
        Some("reloading") => "Reloading its DNS settings".into(),
        // D3: interception is withdrawn while the core is down.
        Some("backoff") => "Not running: LAN traffic goes direct until a retry works".into(),
        Some("cleanup_pending") => "Network changes not cleaned up".into(),
        None if s["running"] == true => "Running".into(),
        _ => "Off".into(),
    }
}

pub fn mihomo_page(pd: &PageData) -> Markup {
    let Some(s) = pd.read(0) else {
        return html! { p.msg.err { "Mihomo status unavailable" } };
    };
    let on = s["running"].as_bool() == Some(true);
    let installed = s["installed"].as_bool() == Some(true);
    let recovery = s["recovery_required"].as_bool() == Some(true);
    let autostart = s["autostart"].as_bool() == Some(true);
    html! {
        (kit::section(Some("Mihomo"), Some(html! {
            p.foot { "Mihomo " (s["version"].as_str().unwrap_or("")) " and Zashboard " (s["dashboard_version"].as_str().unwrap_or("")) ". Attempts to start after an agent restart or reboot only when its enabled choice is saved. Switching off clears that choice. No subscription or paid node is included." }
            @if let Some(e) = s["error"].as_str() { p.foot.err role="alert" { (e) } }
            @if let Some(n) = s["notice"].as_str() { p.foot.err role="alert" { (n) } }
        }), html! {
            (kit::kv_row(None, "Core", if installed { "Installed" } else { "Not installed" }))
            (kit::kv_row(None, "Configuration", if s["configured"].as_bool() == Some(true) { "Saved privately" } else { "Not configured" }))
            (kit::kv_row(None, "Clash proxy", &state_label(s)))
            @if s["direct_fallback"] == true {
                (kit::kv_row(None, "Failed starts or exits", &s["failures"].as_u64().unwrap_or(0).to_string()))
                @if let Some(retry) = s["retry_in_s"].as_u64() {
                    (kit::kv_row(None, "Next retry", &format!("in {retry} s")))
                }
            }
            (kit::kv_row(None, "After a restart", match s["autostart"].as_bool() {
                Some(true) => "Automatic start enabled",
                Some(false) => "Stays off",
                None => "Unknown",
            }))
            @if on { li { a.it href=(OPEN) target="_blank" rel="noopener noreferrer" { span { "Open Zashboard" } } } }
        }))
        @if recovery || (!on && autostart) {
            form method="post" action=(SWITCH) {
                (pd.csrf()) (once_field(&pd.once()))
                input type="hidden" name="enable" value="0";
                (kit::section(Some(if recovery { "Recovery required" } else { "Automatic start enabled" }), Some(html! {
                    p.foot { (if recovery { "Some proxy network changes remain. Retry cleanup before starting or reinstalling. This also clears automatic start." } else { "The core is off, but its restart choice is still saved. Cancel pending restoration and keep it off after future restarts." }) }
                }), html! {
                    li { button.it.cv.snd type="submit" { (if recovery { "Retry proxy cleanup" } else { "Stop automatic start & keep off" }) } }
                }))
            }
        }
        @if !on && !recovery {
            form method="post" action=(INSTALL) {
                (pd.csrf()) (once_field(&pd.once()))
                input type="hidden" name="install" value="1";
                (kit::section(Some("Install / repair"), Some(html! { p.foot { "Downloads about 22 MB from pinned official releases, verifies SHA-256, and saves to /data/zte-agent-mihomo. This may use cellular data. Does not start the proxy." } }), html! {
                    li { button.it.cv.snd type="submit" { (if installed { "Reinstall pinned core & dashboard" } else { "Install core & Zashboard" }) } }
                }))
            }
        }
        @if installed && !recovery { (super::mihomo_profiles::panel(pd)) }
        @if installed && !recovery {
            @let bypass = s["cn_direct"].as_bool() == Some(true);
            form method="post" action=(DIRECT_BYPASS) {
                (pd.csrf()) (once_field(&pd.once()))
                input type="hidden" name="enable" value=(if bypass { "0" } else { "1" });
                (kit::section(Some("Bypass Mihomo for DIRECT rules"), Some(html! {
                    p.foot { "In rule mode the kernel checks the rules top-down, in Mihomo's order: IPv4 that a rule sends DIRECT by address, port or network (IP-CIDR, any GEOIP code, DST-PORT, NETWORK, rule sets with addresses) skips Mihomo, so on the Wi-Fi relay it can use hardware forwarding; what such a rule sends to a proxy still goes to Mihomo. DNS is always fake-ip: only domains a rule sends to DIRECT itself get real addresses; a domain behind a proxy group or a refreshed rule set always gets a fake one and goes through Mihomo, so switching a group can never leave a client on a direct address. A proxy rule the kernel cannot check (IP-ASN, NOT, binary rule sets, a file rule set) ends the chain there; a DIRECT one is skipped. Direct mode: all IPv4 skips Mihomo; global mode: nothing. IPv6 always goes through Mihomo. Changing this reloads the core's DNS settings behind its interception (a restart if the reload cannot be confirmed; nothing goes direct meanwhile) and resets only connections that lose the bypass." }
                }), html! {
                    (kit::kv_row(None, "Setting", if bypass { "On" } else { "Off" }))
                    @if on {
                        @let kernel = &s["kernel"];
                        @let returns = kernel["returns"].as_u64().unwrap_or(0);
                        (kit::kv_row(None, "Running core", &match kernel["bypass"].as_str() {
                            Some("rules") => format!("IPv4 matched by {returns} DIRECT rule{} bypasses the proxy", if returns == 1 { "" } else { "s" }),
                            Some("all_ipv4") => "All IPv4 bypasses the proxy (direct mode)".to_owned(),
                            _ => "All traffic through the proxy".to_owned(),
                        }))
                        @if bypass {
                            @if let Some(reason) = kernel["reason"].as_str() {
                                (kit::kv_row(None, if kernel["bypass"] == "rules" { "Chain ends at" } else { "Why" }, reason))
                            }
                        }
                    }
                    li { button.it.cv.snd type="submit" { (if bypass { "Turn off DIRECT bypass" } else { "Turn on DIRECT bypass" }) } }
                }))
            }
        }
        p.actions { a.btn href="/ui/router" { "Back to Router & proxy switch" } }
    }
}

pub fn relay_page(pd: &PageData) -> Markup {
    let Some(s) = pd.read(0) else {
        return html! { p.msg.err { "Wi-Fi relay status unavailable" } };
    };
    let connected = s["connected"].as_bool() == Some(true);
    let recovery = s["recovery_required"].as_bool() == Some(true);
    let autostart = s["autostart"].as_bool() == Some(true);
    let operation = match s["phase"].as_str() {
        Some("scanning") => Some(("Scanning…", "Scanning nearby Wi-Fi networks…")),
        Some("connecting") => Some(("Connecting…", "Connecting to upstream Wi-Fi… Hotspots may briefly reconnect.")),
        Some("recovering") => Some(("Recovering…", "Recovering the Wi-Fi relay connection or its previous settings…")),
        Some("disconnecting") => Some(("Disconnecting…", "Disconnecting… (the hotspot is returning to its channel, up to about 80 s)")),
        _ => None,
    };
    // Resuming the saved owner-selected network after startup.
    let restoring = s["restoring"].as_str().filter(|_| !connected);
    let networks = s["networks"].as_array().filter(|n| !n.is_empty());
    html! {
        div.relay-page {
            section.relay-hero aria-labelledby="relay-heading" {
                div.relay-head {
                    span.relay-glyph { (kit::icon(kit::Icon::Wifi)) }
                    span class=(if connected { "relay-state on" } else { "relay-state" }) {
                        (if let Some((label, _)) = operation { label } else if connected { "Wi-Fi linked" } else if restoring.is_some() { "Reconnecting" } else if recovery { "Recovery required" } else { "Relay off" })
                    }
                }
                h2 #relay-heading { (if connected { s["ssid"].as_str().unwrap_or("Wi-Fi relay") } else { restoring.unwrap_or("Share a Wi-Fi connection") }) }
                p role="status" { (if let Some((_, description)) = operation { description } else if connected { "Connected (internet not verified). Network authentication may still be required." } else if restoring.is_some() { "Trying the last selected remembered or open network. After a reboot this can take a few minutes. Stop reconnecting cancels this attempt and clears the restart choice." } else if recovery { "Some relay settings still need cleanup. Retry without scanning or connecting to Wi-Fi." } else { "Use nearby Wi-Fi as your U60's internet connection." }) }
                div.relay-path aria-label="Upstream Wi-Fi to U60 Pro to your devices" {
                    span.relay-hop { (kit::icon(kit::Icon::Wifi)) "Wi-Fi" }
                    (kit::icon(kit::Icon::Arrows))
                    span.relay-hop { (kit::icon(kit::Icon::Router)) "U60 Pro" }
                    (kit::icon(kit::Icon::Arrows))
                    span.relay-hop { (kit::icon(kit::Icon::Laptop)) "Devices" }
                }
                @if connected {
                    div.relay-address { span { "UPSTREAM IPv4" } code { (s["address"].as_str().unwrap_or("")) } }
                    @if let Some(frequency) = s["frequency"].as_u64() {
                        div.relay-address {
                            span { "UPSTREAM LINK" }
                            span { (if frequency < 3000 { "2.4 GHz" } else { "5 GHz" }) " \u{b7} negotiated bandwidth" }
                        }
                    }
                    div.relay-address {
                        span { "AFTER A RESTART" }
                        span { (match s["autostart"].as_bool() {
                            Some(true) => "Automatic reconnect enabled",
                            Some(false) => "Stays off; no restart choice saved",
                            None => "Unknown",
                        }) }
                    }
                    div.relay-address {
                        span { "UPSTREAM IPv6 / NAT66" }
                        span {
                            (match s["ipv6"]["state"].as_str().unwrap_or("off") {
                                "configured" => "Configured, forwarded by the CPU (internet not verified)",
                                "detecting" => "Discovering upstream IPv6",
                                "no_upstream" => "No usable upstream IPv6; IPv4 only",
                                "unsupported" => "Unavailable; IPv4 only",
                                "expired" => "Upstream IPv6 expired; IPv4 only",
                                "error" => "IPv6 setup failed; IPv4 only",
                                _ => "Off",
                            })
                        }
                    }
                    @if s["ipv6"]["upstream"].as_bool() == Some(true) {
                        div.relay-address { span { "UPSTREAM IPv6" } code { (s["ipv6"]["address"].as_str().unwrap_or("")) } }
                        div.relay-address { span { "LAN IPv6 PREFIX" } code { (s["ipv6"]["lan_prefix"].as_str().unwrap_or("")) } }
                    }
                    @if let Some(e) = s["ipv6"]["error"].as_str() { p.msg.err { (e) } }
                    p.relay-copy { "The router's parental control and URL filter do not apply to devices using the relay: relayed traffic is accepted ahead of them, and hardware-forwarded connections skip the router's filtering altogether. Only relayed IPv4 can be hardware forwarded; IPv6 (NAT66) and traffic through Clash use the CPU." }
                    @if let Some(e) = s["clock_error"].as_str() {
                        div.msg.info role="status" {
                            strong { "Wi-Fi connected; time not verified." }
                            p { (e) }
                            form method="post" action=(CLOCK) {
                                (pd.csrf()) (once_field(&pd.once()))
                                button.relay-btn.relay-secondary type="submit" data-busy-label="Verifying time over Wi-Fi..." {
                                    (kit::icon(kit::Icon::ClockArrow)) "Recheck time"
                                }
                            }
                            p.foot { "Retry after upstream internet or portal access is restored. This check does not reconnect Wi-Fi." }
                        }
                    }
                }
                @if autostart && !connected && restoring.is_none() {
                    p.relay-copy { "A restart connection choice is still saved. Disconnect clears it and cancels any pending restoration." }
                }
                @if connected || recovery || restoring.is_some() || autostart || operation.is_some() {
                    form method="post" action=(DISCONNECT) {
                        (pd.csrf()) (once_field(&pd.once()))
                        button.relay-btn.relay-stop type="submit" data-busy-label="Disconnecting relay and restoring network settings..." { (kit::icon(kit::Icon::Power)) (if connected { "Disconnect relay" } else if recovery { "Retry relay cleanup" } else if restoring.is_some() { "Stop reconnecting" } else { "Disconnect & clear restart choice" }) }
                    }
                }
            }
            p.relay-caution { (kit::icon(kit::Icon::Info)) span { "Hotspots may briefly reconnect. If Wi-Fi drops, SIM data may be used only if cellular data is already on. Relay never turns it on." } }
            @if let Some(e) = s["error"].as_str() { p.msg.err role="alert" { (e) } }
            section.relay-panel aria-labelledby="networks-heading" {
                form method="post" action=(SCAN) {
                    (pd.csrf()) (once_field(&pd.once()))
                    div.relay-head {
                        div { h2 #networks-heading { "Upstream networks" } p.relay-copy { (if networks.is_some() { "Select a Wi-Fi network." } else { "Find nearby Wi-Fi." }) } }
                        button.relay-btn.relay-secondary type="submit" aria-label="Scan upstream Wi-Fi" {
                            (kit::icon(kit::Icon::Antenna)) (if networks.is_some() { "Rescan" } else { "Scan" })
                        }
                    }
                }
                @if let Some(networks) = networks {
                    form.relay-connect method="post" action=(CONNECT) {
                        (pd.csrf()) (once_field(&pd.once()))
                        fieldset.relay-networks {
                            legend.sr { "Select upstream Wi-Fi" }
                            @for n in networks {
                                label.relay-network {
                                    input type="radio" name="network" value=(n["id"].as_str().unwrap_or("")) required disabled[n["supported"].as_bool() != Some(true)];
                                    (kit::icon(kit::Icon::Wifi))
                                    span.relay-network-name {
                                        strong { (n["ssid"].as_str().unwrap_or("")) }
                                        small {
                                            (if n["frequency"].as_u64().unwrap_or(0) < 3000 { "2.4 GHz" } else { "5 GHz" })
                                            " / " (n["signal"].as_i64().unwrap_or(0)) " dBm / "
                                            (if n["supported"].as_bool() != Some(true) { "Unsupported" } else if n["security"].as_str() == Some("open") { "Open" } else { "WPA2" })
                                        }
                                    }
                                    @if n["remembered"].as_bool() == Some(true) { span.badge.gr { "Saved" } }
                                }
                            }
                        }
                        label.relay-password for="relay-password" { span { "Wi-Fi password" } small { "Leave empty for saved or open networks" } }
                        input.relay-input #relay-password type="password" name="password" maxlength="64" autocomplete="new-password" placeholder="Network password";
                        label.relay-consent { input type="checkbox" name="remember" value="1" checked; span { "Remember this network’s password after a successful connection." } }
                        label.relay-consent {
                            input type="checkbox" name="ipv6" value="1" checked;
                            span { "Use upstream IPv6 for Clash and enable LAN NAT66 when available (experimental)." }
                        }
                        label.relay-consent {
                            input type="checkbox" name="confirmed" value="1" checked required;
                            span { "I accept hotspot reconnection and possible cellular data charges." }
                        }
                        button.relay-btn.relay-primary type="submit" { "Connect to Wi-Fi" (kit::icon(kit::Icon::Arrows)) }
                        p.relay-private { (kit::icon(kit::Icon::Lock)) "Password stays private on U60. After a successful connection, the last selected remembered or open network can reconnect after restart. Disconnect clears that choice; a dropped link does not reconnect automatically while the agent runs." }
                    }
                } @else {
                    div.relay-empty { (kit::icon(kit::Icon::Wifi)) p { "Your next connection starts here." } small { "Tap Scan to discover available networks." } }
                }
            }
            @if let Some(error) = s["saved_error"].as_str() { p.msg.err { (error) } }
            @if let Some(saved) = s["saved_networks"].as_array().filter(|s| !s.is_empty()) {
                section.relay-panel {
                    h2 { "Saved Wi-Fi networks" }
                    p.relay-copy { "Scan and select a network to connect. Forget removes any remembered password without disconnecting an active relay." }
                    @for network in saved {
                        @let id = network["id"].as_str().unwrap_or("");
                        @let active = connected && s["saved_network_id"].as_str() == Some(id);
                        div.relay-connect {
                            div.relay-head {
                                span.relay-network-name {
                                    strong { (network["ssid"].as_str().unwrap_or("")) }
                                    small { (if network["security"].as_str() == Some("open") { "Open network; no password needed" } else if network["remembered"].as_bool() == Some(true) { "Password remembered; leave it empty when connecting" } else { "Password not saved; enter it when connecting" }) }
                                }
                                @if active { span.badge.gr { "Connected" } }
                            }
                            form method="post" action=(FORGET) {
                                (pd.csrf()) (once_field(&pd.once()))
                                input type="hidden" name="id" value=(id);
                                p.actions { button.btn type="submit" { "Forget" } }
                            }
                        }
                    }
                }
            }
            details.relay-notes {
                summary { "Compatibility & safety" }
                p { "Experimental B31 AP + STA, IPv4 NAT. Keep both main hotspots enabled and Guest WiFi off. Do not change WiFi, LAN or USB settings while connected." }
                p { "Open and WPA2-Personal networks on radio-enabled 2.4 GHz and 5 GHz channels, including DFS. DFS may delay hotspot availability during radar checks. WPA3-only, enterprise and hidden SSIDs are not supported." }
                p { "Optional upstream IPv6 with LAN SLAAC/NAT66. Without a usable upstream IPv6 address and default route, relay stays IPv4-only. Cellular IPv6 bypass stays blocked. Internet access and hotel authorization are not verified automatically." }
                p { "IPv6 needs the existing LAN odhcpd service and kernel NAT support. Its temporary settings are restored on disconnect; do not change the vendor LAN/DHCP settings while relaying. Restart resumes only the saved connection choice, not every remembered network." }
                p { "Refresh this page to read the current state. No background scanning or polling runs while relay is off and no startup restoration is pending." }
            }
            (offload_panel(pd, s, connected))
            (power_save_panel(pd, s, connected))
        }
    }
}

fn power_save_panel(pd: &PageData, s: &serde_json::Value, connected: bool) -> Markup {
    let power = &s["power_save"];
    let auto_off = power["auto_off"].as_bool() != Some(false);
    html! {
        section.relay-panel aria-labelledby="power-save-heading" {
            form.relay-head method="post" action=(POWER_SAVE) {
                (pd.csrf()) (once_field(&pd.once()))
                input type="hidden" name="auto_off" value=(if auto_off { "0" } else { "1" });
                div {
                    h2 #power-save-heading { "Turn off Wi-Fi power save" }
                    p.relay-copy { "On the upstream link, at every relay connection." }
                }
                button.sw type="submit" role="switch" aria-checked=(if auto_off { "true" } else { "false" }) aria-labelledby="power-save-heading" {}
            }
            p.relay-copy { "Power save lets the U60 doze between beacons while the upstream router holds its traffic. With it off, short speed tests through the relay ran faster (about 170–220 to 245–250 Mbit/s) and the radio uses a little more power. A change applies to the current connection at once. This is not the router's power saver mode." }
            @if connected {
                div.relay-address {
                    span { "THIS CONNECTION" }
                    span { (if power["off"].as_bool() == Some(true) { "Power save off" } else { "Power save on" }) }
                }
                @if let Some(error) = power["error"].as_str() { p.msg.err { (error) } }
            }
        }
    }
}

fn offload_panel(pd: &PageData, s: &serde_json::Value, connected: bool) -> Markup {
    let offload = &s["offload"];
    let enabled = offload["enabled"].as_bool() != Some(false);
    html! {
        section.relay-panel aria-labelledby="offload-heading" {
            form.relay-head method="post" action=(OFFLOAD_SWITCH) {
                (pd.csrf()) (once_field(&pd.once()))
                input type="hidden" name="enabled" value=(if enabled { "0" } else { "1" });
                div {
                    h2 #offload-heading { "Hardware forwarding" }
                    p.relay-copy { "Turning it on or off applies to the current relay connection at once." }
                }
                button.sw type="submit" role="switch" aria-checked=(if enabled { "true" } else { "false" }) aria-labelledby="offload-heading" {}
            }
            p.relay-copy { "Qualcomm IPA carries relayed IPv4 NAT traffic without the CPU. Offloaded connections skip the router's firewall rules, speed limits, Smart QoS and parental control. IPv6/NAT66 and traffic through Mihomo stay on the CPU. Whether IPA is active is decided by the router's own settings, which this page never changes: the Balanced (极速模式) working mode turns acceleration on; any other working mode, a router speed limit or power saver mode keeps relayed traffic on the CPU. A change of path resets existing LAN IPv4 connections once." }
            div.relay-address {
                span { "IPA CONFIGURATION" }
                span { (match offload["config"].as_str() {
                    Some("listed") => "Lists the relay interface",
                    Some("not_listed") => "Does not list the relay interface; the relay forwards on the CPU",
                    _ => "Unavailable on this firmware",
                }) }
            }
            @if connected {
                div.relay-address {
                    span { "RELAY PATH" }
                    span { (relay_path(offload)) }
                }
                @if let Some(mihomo) = offload["ipv4_through_mihomo"].as_str().filter(|m| *m != "none") {
                    div.relay-address {
                        span { "PUBLIC IPv4" }
                        span { (if mihomo == "all" { "Handled by Mihomo (on the CPU)" } else { "Handled by Mihomo, except what its DIRECT rules bypass" }) }
                    }
                }
                @if let Some(reason) = offload["reason"].as_str() { p.relay-copy { (reason) } }
            }
        }
    }
}

/// The relay's IPv4 path: with the `main` route in place, the router's
/// working mode decides whether IPA carries it.
fn relay_path(offload: &serde_json::Value) -> &'static str {
    match (offload["route"].as_bool(), offload["state"].as_str()) {
        (Some(true), _) => "Hardware (IPA) in the Balanced (极速模式) working mode; CPU in any other",
        (_, Some("releasing")) => "Leaving hardware forwarding",
        _ => "CPU",
    }
}

pub fn custom_post(path: &str) -> bool {
    [CONFIG, CONNECT, FORGET, CLOCK, super::reservations::APPLY].contains(&path)
}

pub async fn post(ctx: Ctx, req: Request) -> Response {
    let nonce = CspNonce::of(&req);
    let path = req.uri().path().to_owned();
    let home = if path == super::reservations::APPLY { super::reservations::PATH } else if [CONNECT, FORGET, CLOCK].contains(&path.as_str()) { RELAY } else { MIHOMO };
    let (parts, body) = req.into_parts();
    let Some(p) = session::find_session(&ctx.app.auth, &parts.headers) else {
        return session::reply_unread(&parts.headers, body, session::login_redirect(&HttpMethod::POST, home, None)).await;
    };
    if !api::header(&parts.headers, "content-type").is_some_and(|s| s.split(';').next() == Some("application/x-www-form-urlencoded")) {
        return session::reply_unread(&parts.headers, body, render::bad_request(&nonce)).await;
    }
    let max = if path == CONFIG { crate::mihomo::MAX_CONFIG * 3 + 4096 } else { session::FORM_MAX };
    let form = match api::read_capped(&parts.headers, body, max, ctx.body_wait).await {
        Ok(b) => Form::parse(&b),
        Err(_) => return render::error(413, "Form too large", "The request was too large or incomplete.", &nonce),
    };
    if !session::verify_post(&ctx.app.auth, &parts.headers, &p, form.get("csrf")) {
        return render::form_refused(&nonce, home);
    }
    if path == CONNECT && form.get("confirmed") != Some("1") {
        return render::error(400, "Confirmation required", "Confirm the hotspot interruption and possible cellular data charges.", &nonce);
    }
    let api_path = if path == super::reservations::APPLY { "/api/router/reservations" } else if path == CONNECT { "/api/wifi-relay/connect" } else if path == FORGET { "/api/wifi-relay/forget" } else if path == CLOCK { "/api/wifi-relay/clock" } else { "/api/mihomo/config" };
    let (method, data, success) = if path == super::reservations::APPLY {
        (Method::Post, json!({"action":form.get("action").unwrap_or(""),"id":form.get("id").unwrap_or(""),"name":form.get("name").unwrap_or(""),"mac":form.get("mac").unwrap_or(""),"ip":form.get("ip").unwrap_or("")}), "Reservation updated. Reconnect the client to renew its IPv4 lease.")
    } else if path == FORGET {
        (Method::Post, json!({"id":form.get("id").unwrap_or("")}), "Saved Wi-Fi choice and any remembered password removed. Active relay is unchanged.")
    } else if path == CLOCK {
        (Method::Post, json!({}), "Time verified over Wi-Fi. Relay connection was not restarted.")
    } else if path == CONNECT {
        (
            Method::Post,
            json!({"network":form.get("network").unwrap_or(""),"password":form.get("password").unwrap_or(""),"confirmed":true,"ipv6":form.get("ipv6")==Some("1"),"remember":form.get("remember")==Some("1")}),
            "Wi-Fi relay connected. Internet access still needs verification; a hotel may require web login.",
        )
    } else {
        (Method::Put, json!({"yaml":form.get("yaml").unwrap_or("")}), "Mihomo configuration validated and saved. Use the switch in Router to start Clash.")
    };
    let token = form.get("once").unwrap_or("").to_owned();
    let digest = job::digest(&[&path, &data.to_string()]);
    let owner = p.id;
    let flash = Arc::clone(&ctx.flash);
    let work: OnceJob = Box::new(move |app: &AppState, claim| {
        claim.disarm();
        let result = super::call(app, method, api_path, &data);
        claim.set(match &result {
            Ok(_) => Token::Sent(claim.digest()),
            Err((s, e)) => Token::Failed(claim.digest(), *s, e.clone()),
        });
        flash_line(&flash, app, owner, home, result.map(|_| success.to_owned()).map_err(|(_, e)| e))
    });
    let line = |r| flash_line(&ctx.flash, &ctx.app, owner, home, r);
    match job::once(&ctx, owner, &nonce, &token, digest, Lane::Slow, SETTLE_SLOW, work).await {
        Sent::Ran(r) => r,
        Sent::Done(Ok(())) => line(Ok(success.into())),
        Sent::Done(Err((_, e))) => line(Err(e)),
        Sent::Expired => line(Err("This form expired. Refresh and try again.".into())),
        Sent::Unknown => line(Err("The operation may still be running. Check before repeating it.".into())),
        Sent::Busy => line(Err("The router is busy. Nothing was changed.".into())),
    }
}

pub(super) fn flash_line(flash: &crate::web::store::Flash, app: &AppState, owner: crate::auth::SessionId, home: &str, result: Result<String, String>) -> Response {
    let Ok(id) = app.auth.random_hex(8) else { return session::see_other(home) };
    let (ok, text) = match result {
        Ok(s) => (true, s),
        Err(e) => (false, e),
    };
    flash.insert(id.clone(), owner, (Some(ok), text), app.auth.now());
    let separator = if home.contains('?') { '&' } else { '?' };
    session::see_other(&format!("{home}{separator}r={id}"))
}

pub fn open(ctx: &Ctx) -> Response {
    if !ctx.app.mihomo.running() {
        return session::see_other("/ui/router");
    }
    session::see_other(&crate::web::mihomo::dashboard_link())
}
