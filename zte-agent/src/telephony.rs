use serde_json::{json, Value};

use std::sync::atomic::Ordering;

use crate::at_cmd;
use crate::handlers::AppState;

// ---------------------------------------------------------------------------
// GSM 7-bit default alphabet → UTF-8
// ---------------------------------------------------------------------------

const GSM7_TABLE: &[&str] = &[
    "@", "\u{00A3}", "$", "\u{00A5}", "\u{00E8}", "\u{00E9}", "\u{00F9}",
    "\u{00EC}", "\u{00F2}", "\u{00C7}", "\n", "\u{00D8}", "\u{00F8}", "\r",
    "\u{00C5}", "\u{00E5}", "_", "_", " ", "!", "\"",
    "#", "\u{00A4}", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?",
    "\u{00A1}", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
    "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
    "\u{00C4}", "\u{00D6}", "\u{00D1}", "\u{00DC}", "\u{00A7}",
    "\u{00BF}", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
    "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
    "\u{00E4}", "\u{00F6}", "\u{00F1}", "\u{00FC}", "\u{00E0}",
];

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i + 1 < hex.len() {
        if let Ok(b) = u8::from_str_radix(&hex[i..i + 2], 16) {
            bytes.push(b);
        }
        i += 2;
    }
    bytes
}

fn decode_gsm7(hex_str: &str) -> String {
    if hex_str.is_empty() {
        return String::new();
    }
    let bytes = hex_to_bytes(hex_str);
    // Unpack 7-bit septets from 8-bit octets
    let mut septets = Vec::new();
    let mut shift: u32 = 0;
    for (bi, &byte) in bytes.iter().enumerate() {
        let val = if bi > 0 {
            ((byte as u32) << shift) + ((bytes[bi - 1] as u32) >> (8 - shift))
        } else {
            byte as u32
        };
        septets.push((val % 128) as usize);
        shift += 1;
        if shift == 7 {
            septets.push((byte as u32 >> 1) as usize);
            shift = 0;
        }
    }
    let mut out = String::new();
    for s in septets {
        if let Some(&ch) = GSM7_TABLE.get(s) {
            out.push_str(ch);
        }
    }
    out
}

fn decode_ucs2(hex_str: &str) -> String {
    if hex_str.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let mut i = 0;
    while i + 3 < hex_str.len() {
        if let Ok(cp) = u32::from_str_radix(&hex_str[i..i + 4], 16) {
            if let Some(ch) = char::from_u32(cp) {
                out.push(ch);
            }
        }
        i += 4;
    }
    out
}

fn decode_ussd_response(hex_str: &str, dcs: u32) -> String {
    if hex_str.is_empty() {
        return String::new();
    }
    let coding = dcs % 16;
    if coding == 8 {
        return decode_ucs2(hex_str);
    }
    if coding == 0 || coding == 15 {
        let decoded = decode_gsm7(hex_str);
        if !decoded.is_empty() {
            return decoded;
        }
    }
    // Fallback: plain ASCII hex
    let mut out = String::new();
    let bytes = hex_to_bytes(hex_str);
    for b in &bytes {
        if *b >= 32 && *b < 127 {
            out.push(*b as char);
        }
    }
    if !out.is_empty() {
        return out;
    }
    hex_str.to_string()
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

pub(crate) fn parse_clcc(raw: &str) -> Vec<Value> {
    let dir_names = ["mo", "mt"];
    let stat_names = ["active", "held", "dialing", "alerting", "incoming", "waiting", "releasing"];

    let mut calls = Vec::new();
    for line in raw.lines() {
        // +CLCC: idx,dir,stat,mode,mpty[,"number",type]
        let Some(rest) = line.strip_prefix("+CLCC:") else {
            continue;
        };
        let rest = rest.trim();
        let parts: Vec<&str> = rest.splitn(6, ',').collect();
        if parts.len() < 5 {
            continue;
        }
        let id: i64 = parts[0].trim().parse().unwrap_or(-1);
        let dir_i: usize = parts[1].trim().parse().unwrap_or(0);
        let stat_i: usize = parts[2].trim().parse().unwrap_or(0);
        let mode: i64 = parts[3].trim().parse().unwrap_or(0);
        let number = if parts.len() > 5 {
            parts[5].trim().trim_matches('"').to_string()
        } else {
            String::new()
        };
        let dir = dir_names.get(dir_i).unwrap_or(&"unknown");
        let stat = stat_names.get(stat_i).unwrap_or(&"unknown");
        calls.push(json!({
            "id": id,
            "dir": dir,
            "stat": stat,
            "mode": mode,
            "number": number,
        }));
    }
    calls
}

fn parse_cusd(raw: &str) -> Option<(i64, String, u32)> {
    // Look for +CUSD: status[,"body"[,dcs]]
    for line in raw.lines() {
        let Some(rest) = line.strip_prefix("+CUSD:") else {
            continue;
        };
        let rest = rest.trim();
        // Parse status
        let status_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        let status: i64 = rest[..status_end].parse().unwrap_or(-1);
        let after_status = &rest[status_end..];

        // Try to extract body between quotes
        let mut body = String::new();
        let mut dcs: u32 = 15;
        if let Some(q1) = after_status.find('"') {
            let after_q1 = &after_status[q1 + 1..];
            if let Some(q2) = after_q1.find('"') {
                body = after_q1[..q2].to_string();
                // Look for dcs after closing quote
                let after_body = &after_q1[q2 + 1..];
                if let Some(comma) = after_body.find(',') {
                    let dcs_str = after_body[comma + 1..].trim();
                    let dcs_end = dcs_str
                        .find(|c: char| !c.is_ascii_digit())
                        .unwrap_or(dcs_str.len());
                    dcs = dcs_str[..dcs_end].parse().unwrap_or(15);
                }
            }
        }
        return Some((status, body, dcs));
    }
    None
}

fn format_ussd_response(parsed: (i64, String, u32)) -> Value {
    let (status, body, dcs) = parsed;
    let decoded = decode_ussd_response(&body, dcs);
    let response = if decoded.is_empty() { &body } else { &decoded };
    let session_active = status == 1;
    json!({
        "response": response,
        "raw_response": body,
        "status": status,
        "dcs": dcs,
        "session_active": session_active,
    })
}

/// Record whether the network left a USSD prompt open (`+CUSD: 1`): the
/// modem policies hold off while one is pending.
fn note_ussd_prompt(state: &AppState, parsed: Option<&(i64, String, u32)>) {
    let pending = parsed.is_some_and(|(status, _, _)| *status == 1);
    let at = if pending {
        crate::conn_watchdog::unix_now()
    } else {
        0
    };
    state.ussd_prompt_at.store(at, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /api/call/dial — body: {"number": "..."}
pub fn call_dial(state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let number = match parsed["number"].as_str() {
        Some(n) if !n.is_empty() => n,
        _ => return (400, json!({"ok": false, "error": "missing number"})),
    };
    // Sanitize: keep digits, +, *, #
    let clean: String = number.chars().filter(|c| c.is_ascii_digit() || "+*#".contains(*c)).collect();
    match at_cmd::send(&state.at_port, &format!("ATD{clean};"), 5) {
        Ok(resp) if resp.contains("ERROR") => (500, json!({"ok": false, "error": "dial failed"})),
        Ok(_) => {
            state.call_active.store(true, Ordering::Relaxed);
            (200, json!({"ok": true, "data": {"status": "ok"}}))
        }
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

/// POST /api/call/hangup
pub fn call_hangup(state: &AppState) -> (u16, Value) {
    match at_cmd::send(&state.at_port, "AT+CHUP", 3) {
        Ok(_) => {
            state.call_active.store(false, Ordering::Relaxed);
            (200, json!({"ok": true, "data": {"status": "ok"}}))
        }
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

/// POST /api/call/answer
pub fn call_answer(state: &AppState) -> (u16, Value) {
    match at_cmd::send(&state.at_port, "ATA", 3) {
        Ok(_) => {
            // An answered call is active even if the app never polls call_status;
            // the modem policies must not touch the radio while it lasts.
            state.call_active.store(true, Ordering::Relaxed);
            (200, json!({"ok": true, "data": {"status": "ok"}}))
        }
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

/// GET /api/call/status
pub fn call_status(state: &AppState) -> (u16, Value) {
    match at_cmd::send(&state.at_port, "AT+CLCC", 2) {
        Ok(resp) => {
            let calls = parse_clcc(&resp);
            // Fail closed: the AT node can hand a reply to another reader, so
            // only a terminal OK with no +CLCC line proves there is no call.
            if !calls.is_empty() {
                state.call_active.store(true, Ordering::Relaxed);
            } else if resp.contains("OK") {
                state.call_active.store(false, Ordering::Relaxed);
            }
            (200, json!({"ok": true, "data": {"calls": calls}}))
        }
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

/// POST /api/call/dtmf — body: {"digits": "123"}
pub fn call_dtmf(state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let digits = match parsed["digits"].as_str() {
        Some(d) if !d.is_empty() => d,
        _ => return (400, json!({"ok": false, "error": "missing digits"})),
    };
    let cmds: Vec<String> = digits
        .chars()
        .filter(|c| c.is_ascii_digit() || "*#ABCD".contains(*c))
        .map(|d| format!("+VTS={d}"))
        .collect();
    if cmds.is_empty() {
        return (400, json!({"ok": false, "error": "no valid digits"}));
    }
    let at_cmd_str = format!("AT{}", cmds.join(";"));
    match at_cmd::send(&state.at_port, &at_cmd_str, 2) {
        Ok(_) => (200, json!({"ok": true, "data": {"status": "ok"}})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

/// POST /api/call/mute — body: {"enabled": true/false}
pub fn call_mute(state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let enabled = parsed["enabled"].as_bool().unwrap_or(false);
    let val = if enabled { "1" } else { "0" };
    match at_cmd::send(&state.at_port, &format!("AT+CMUT={val}"), 2) {
        Ok(_) => (200, json!({"ok": true, "data": {"muted": enabled}})),
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

/// POST /api/ussd/send — body: {"code": "*123#"}
pub fn ussd_send(state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let code = match parsed["code"].as_str() {
        Some(c) if !c.is_empty() => c,
        _ => return (400, json!({"ok": false, "error": "missing code"})),
    };
    let clean: String = code.chars().filter(|c| c.is_ascii_digit() || "*#+".contains(*c)).collect();
    let at = format!("AT+CUSD=1,\"{clean}\",15");
    match at_cmd::send(&state.at_port, &at, 8) {
        Ok(resp) => {
            if resp.contains("ERROR") {
                return (500, json!({"ok": false, "error": "USSD failed"}));
            }
            let parsed = parse_cusd(&resp);
            note_ussd_prompt(state, parsed.as_ref());
            match parsed {
                Some(parsed) => (200, json!({"ok": true, "data": format_ussd_response(parsed)})),
                None => {
                    let clean_resp: String = resp.chars().filter(|c| !c.is_control()).collect();
                    (200, json!({"ok": true, "data": {
                        "response": clean_resp,
                        "raw_response": clean_resp,
                        "status": -1,
                        "dcs": 15,
                        "session_active": false,
                    }}))
                }
            }
        }
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

/// POST /api/ussd/respond — body: {"reply": "1"}
pub fn ussd_respond(state: &AppState, body: &[u8]) -> (u16, Value) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok": false, "error": "invalid JSON"})),
    };
    let reply = match parsed["reply"].as_str() {
        Some(r) if !r.is_empty() => r,
        _ => return (400, json!({"ok": false, "error": "missing reply"})),
    };
    let clean: String = reply.chars().filter(|c| c.is_ascii_digit() || "*#+".contains(*c)).collect();
    let at = format!("AT+CUSD=1,\"{clean}\",15");
    match at_cmd::send(&state.at_port, &at, 8) {
        Ok(resp) => {
            let parsed = parse_cusd(&resp);
            note_ussd_prompt(state, parsed.as_ref());
            match parsed {
                Some(parsed) => (
                    200,
                    json!({"ok": true, "data": format_ussd_response(parsed)}),
                ),
                None => {
                    let clean_resp: String = resp.chars().filter(|c| !c.is_control()).collect();
                    (
                        200,
                        json!({"ok": true, "data": {
                            "response": clean_resp,
                            "raw_response": clean_resp,
                            "status": -1,
                            "dcs": 15,
                            "session_active": false,
                        }}),
                    )
                }
            }
        }
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

/// POST /api/ussd/cancel
pub fn ussd_cancel(state: &AppState) -> (u16, Value) {
    match at_cmd::send(&state.at_port, "AT+CUSD=2", 3) {
        Ok(_) => {
            state.ussd_prompt_at.store(0, Ordering::Relaxed);
            (200, json!({"ok": true, "data": {"status": "ok"}}))
        }
        Err(e) => (503, json!({"ok": false, "error": e})),
    }
}

/// GET /api/stk/menu — Qualcomm RIL session snapshot.
pub fn stk_menu(state: &AppState) -> (u16, Value) {
    state.stk.request("menu", &[])
}

/// POST /api/stk/select — requires item_id and command_id from the current snapshot.
pub fn stk_select(state: &AppState, body: &[u8]) -> (u16, Value) {
    state.stk.request("select", body)
}
