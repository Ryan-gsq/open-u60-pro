use std::num::NonZeroU32;

use sha2::{Digest, Sha256};

use super::{scan, Network};

pub(super) fn channel(f: u32) -> Option<u32> {
    if (2412..=2472).contains(&f) && (f - 2407).is_multiple_of(5) {
        return Some((f - 2407) / 5);
    }
    if f == 2484 {
        return Some(14);
    }
    let ch = f.checked_sub(5000)? / 5;
    ((5005..=5895).contains(&f) && (f - 5000).is_multiple_of(5)).then_some(ch)
}

pub(super) fn decode_ssid(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |byte: u8| (byte as char).to_digit(16).map(|n| n as u8);
    let mut bytes = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if i + 3 < b.len() && &b[i..i + 2] == b"\\x" {
            // Scan output is untrusted UTF-8: byte offsets need not be
            // character boundaries when a malformed escape follows \\x.
            if let (Some(hi), Some(lo)) = (hex(b[i + 2]), hex(b[i + 3])) {
                bytes.push(hi * 16 + lo);
                i += 4;
                continue;
            }
        }
        if b[i] == b'\\' && matches!(b.get(i + 1), Some(b'\\' | b'"')) {
            i += 1;
        }
        bytes.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Fresh entries of the supplicant's `BSS` pages (`====`/`####` after each
/// entry) as (bssid, MHz, dBm, flags, ssid). Entries older than `max_age`
/// seconds came from the kernel's cache, not this scan, and are left out.
fn fresh_bss(text: &str, max_age: u64, mut each: impl FnMut(&str, u32, i32, &str, &str)) {
    let mut fields = std::collections::HashMap::new();
    for line in text.lines().chain(["===="]) {
        if line != "====" && line != "####" {
            if let Some((key, value)) = line.split_once('=') {
                fields.insert(key, value);
            }
            continue;
        }
        let field = |key| fields.get(key).copied().unwrap_or("");
        let fresh = field("age").parse::<u64>().is_ok_and(|age| age <= max_age);
        if let (true, Ok(frequency), Ok(signal)) = (fresh, field("freq").parse(), field("level").parse()) {
            each(field("bssid"), frequency, signal, field("flags"), field("ssid"));
        }
        fields.clear();
    }
}

/// Networks offered for relay, strongest first.
pub fn parse_bss(text: &str, max_age: u64) -> Vec<Network> {
    let mut out: Vec<Network> = Vec::new();
    fresh_bss(text, max_age, |bssid, frequency, signal, flags, ssid| out.extend(network(bssid, frequency, signal, flags, ssid)));
    out.sort_by_key(|n| std::cmp::Reverse(n.signal));
    out.truncate(80);
    out
}

/// A cached BSS can be returned even when its channel was not scanned.
/// Only the PHY's currently enabled channels may be offered for connection.
pub(super) fn parse_bss_on_channels(text: &str, max_age: u64, channels: &scan::Channels) -> Vec<Network> {
    let mut networks = parse_bss(text, max_age);
    for network in &mut networks {
        network.supported &= channels.contains(network.frequency);
    }
    networks
}

fn network(bssid: &str, frequency: u32, signal: i32, flags: &str, ssid: &str) -> Option<Network> {
    if bssid.len() != 17 || !bssid.split(':').all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }
    let ssid = decode_ssid(ssid);
    if ssid.is_empty() || ssid.len() > 32 || ssid.chars().any(char::is_control) {
        return None;
    }
    let security = if flags.contains("WPA2-PSK") {
        "wpa2"
    } else if flags == "[ESS]" || flags == "[WPS][ESS]" {
        "open"
    } else {
        "unsupported"
    };
    let id = network_id(bssid, frequency, &ssid);
    Some(Network { id, ssid, frequency, signal, security, supported: security != "unsupported" && channel(frequency).is_some(), bssid: bssid.into() })
}

/// A scanned network's id: stable for one BSS, channel and name.
pub(super) fn network_id(bssid: &str, frequency: u32, ssid: &str) -> String {
    format!("{:x}", Sha256::digest(format!("{bssid}:{frequency}:{ssid}").as_bytes()))[..16].to_owned()
}

pub(super) fn wpa_network(n: &Network, password: &str) -> Result<String, String> {
    // scan_freq keeps the supplicant's own scans to one channel: the driver
    // drops 5 GHz from multi-channel scans while the hotspot runs 160 MHz.
    let mut config = format!("network={{\nssid={}\nbssid={}\nfreq_list={f}\nscan_freq={f}\n", crate::common::hex_lower(n.ssid.as_bytes()), n.bssid, f = n.frequency);
    match n.security {
        "open" if password.is_empty() => config.push_str("key_mgmt=NONE\n"),
        "wpa2" => {
            let psk = if password.len() == 64 && password.bytes().all(|b| b.is_ascii_hexdigit()) {
                password.to_ascii_lowercase()
            } else {
                if !(8..=63).contains(&password.len()) || !password.bytes().all(|b| (32..=126).contains(&b)) {
                    return Err("WPA2 password must be 8-63 printable ASCII characters or a 64-digit hex PSK".into());
                }
                let mut key = [0u8; 32];
                ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA1, NonZeroU32::new(4096).unwrap(), n.ssid.as_bytes(), password.as_bytes(), &mut key);
                crate::common::hex_lower(&key)
            };
            config.push_str(&format!("key_mgmt=WPA-PSK\nproto=RSN\npsk={psk}\n"));
        }
        _ => return Err("Unsupported Wi-Fi security or password supplied for an open network".into()),
    }
    config.push_str("}\n");
    Ok(config)
}
