//! QoS the network granted on the current data session: the QCI/5QI of the
//! default bearer and the AMBR (the operator's rate cap).
//!
//! The QMI messages carrying these are not public, but the stock
//! `zte_topsw_data` daemon decodes them and leaves two traces: the
//! `zwrt_data_tmp.wwaniface1.qci` UCI state and one `[DATA]` line per session
//! setup in /logfs/key.log (same format strings in B27 and B31). The log runs
//! to 8 MiB before rotating, so it is scanned backwards once and afterwards
//! only appended bytes are read.
//!
//! Ported from dklasens/MU5250-OpenUI#17. Differences: nothing is reported
//! while the data session is down (the log keeps the last session's line),
//! IMS is matched on the APN's first label (LTE logs `ims.mncXXX.mccYYY.gprs`),
//! a line still being written is left for the next read, and a line longer
//! than the scan window cannot stall the scan.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::ubus;

const SECTION: &str = "zwrt_data_tmp.wwaniface1";
const KEY_LOG: &str = "/logfs/key.log";
const KEY_LOG_ROTATED: &str = "/logfs/key.log.0";
const CHUNK: u64 = 256 * 1024;
/// The bearer only changes on session setup, and each refresh forks `uci`.
const TTL: Duration = Duration::from_secs(10);
/// The `connect_status` values the stock scripts treat as a cellular data session.
const CONNECTED: [&str; 3] = ["ipv4_connected", "ipv6_connected", "ipv4_ipv6_connected"];
/// Sessions that never carry user data.
const NON_DATA_APNS: [&str; 2] = ["ims", "sos"];

struct State {
    cached: Option<(Instant, Value)>,
    log: LogCursor,
}

static STATE: Mutex<State> = Mutex::new(State {
    cached: None,
    log: LogCursor::new(),
});

#[derive(Debug, Clone, PartialEq)]
struct Ambr {
    apn: String,
    dl_mbps: f64,
    ul_mbps: f64,
}

/// The `bearer` object of GET /api/network/signal: `{qci, ambr_dl_mbps,
/// ambr_ul_mbps}`, or null when there is no data session or nothing is known.
pub fn read() -> Value {
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, value)) = &state.cached {
        if at.elapsed() < TTL {
            return value.clone();
        }
    }
    let value = refresh(&mut state.log);
    state.cached = Some((Instant::now(), value.clone()));
    value
}

fn refresh(log: &mut LogCursor) -> Value {
    let section = ubus::uci_show(SECTION).unwrap_or_default();
    // An unreadable status fails open: the log still describes the last session.
    if uci_option(&section, "connect_status").is_some_and(|s| !is_connected(s)) {
        return Value::Null;
    }
    let qci = uci_option(&section, "qci")
        .and_then(|v| v.parse::<u8>().ok())
        .filter(|&q| q > 0);
    let ambr = log.refresh(Path::new(KEY_LOG), Path::new(KEY_LOG_ROTATED));
    if qci.is_none() && ambr.is_none() {
        return Value::Null;
    }
    json!({
        "qci": qci,
        "ambr_dl_mbps": ambr.as_ref().map(|a| a.dl_mbps),
        "ambr_ul_mbps": ambr.as_ref().map(|a| a.ul_mbps),
    })
}

fn is_connected(status: &str) -> bool {
    CONNECTED.contains(&status)
}

/// One option's value from `uci show <SECTION>` output (`<SECTION>.<name>='<value>'`).
fn uci_option<'a>(show: &'a str, name: &str) -> Option<&'a str> {
    show.lines().find_map(|line| {
        let value = line
            .strip_prefix(SECTION)?
            .strip_prefix('.')?
            .strip_prefix(name)?
            .strip_prefix('=')?;
        Some(value.trim().trim_matches('\''))
    })
}

/// How far the log has been read, and the newest data-session AMBR seen in it.
struct LogCursor {
    scanned: bool,
    ino: u64,
    read_len: u64,
    ambr: Option<Ambr>,
}

impl LogCursor {
    const fn new() -> Self {
        LogCursor {
            scanned: false,
            ino: 0,
            read_len: 0,
            ambr: None,
        }
    }

    fn refresh(&mut self, log: &Path, rotated: &Path) -> Option<Ambr> {
        let (ino, len) = std::fs::metadata(log).map_or((0, 0), |m| (m.ino(), m.len()));
        if !self.scanned || ino != self.ino || len < self.read_len {
            // First look, or the log rotated (renamed or truncated). The old
            // file's unread tail is in `rotated`, so a match there is still newer
            // than the one we hold.
            let fresh = scan(log, 0, len);
            self.read_len = fresh.consumed;
            let older = || {
                let end = std::fs::metadata(rotated).map_or(0, |m| m.len());
                scan(rotated, 0, end).newest
            };
            if let Some(a) = fresh.newest.or_else(older) {
                self.ambr = Some(a);
            }
            self.scanned = true;
            self.ino = ino;
        } else if len > self.read_len {
            let tail = scan(log, self.read_len, len);
            self.read_len = tail.consumed;
            if tail.newest.is_some() {
                self.ambr = tail.newest;
            }
        }
        self.ambr.clone()
    }
}

struct Scan {
    newest: Option<Ambr>,
    /// Offset just past the last complete line in the scanned range.
    consumed: u64,
}

fn scan(path: &Path, floor: u64, end: u64) -> Scan {
    scan_chunked(path, floor, end, CHUNK)
}

/// Finds the newest data-session AMBR line in `floor..end`, reading backwards
/// `chunk` bytes at a time. `floor` must be a line start.
fn scan_chunked(path: &Path, floor: u64, end: u64, chunk: u64) -> Scan {
    let mut out = Scan {
        newest: None,
        consumed: floor,
    };
    let Ok(mut file) = File::open(path) else {
        return out;
    };
    let mut hi = end;
    let mut newest_window = true;
    while hi > floor {
        let lo = hi.saturating_sub(chunk).max(floor);
        let Some(buf) = read_range(&mut file, lo, hi) else {
            break;
        };
        // Bytes after the last newline are a line still being written.
        let stop = if newest_window {
            newest_window = false;
            let stop = buf.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
            if stop > 0 {
                out.consumed = lo + stop as u64;
            }
            stop
        } else {
            buf.len()
        };
        // Bytes before the first newline may finish a line that began before `lo`.
        let start = if lo == floor {
            0
        } else {
            buf.iter()
                .position(|&b| b == b'\n')
                .map_or(buf.len(), |i| i + 1)
        };
        if start < stop {
            if let Some(a) = newest(&String::from_utf8_lossy(&buf[start..stop])) {
                out.newest = Some(a);
                return out;
            }
        }
        // Re-read the cut line whole in the next window, unless it fills this
        // one: such a line is not an AMBR line, and re-reading would not progress.
        hi = if start == 0 || start >= buf.len() {
            lo
        } else {
            lo + start as u64
        };
    }
    out
}

fn read_range(file: &mut File, start: u64, end: u64) -> Option<Vec<u8>> {
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    file.take(end.saturating_sub(start))
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

/// The newest AMBR line in `text` for a session that carries user data.
fn newest(text: &str) -> Option<Ambr> {
    text.lines()
        .rev()
        .filter_map(parse_line)
        .find(|a| is_data_apn(&a.apn))
}

fn is_data_apn(apn: &str) -> bool {
    let label = apn.split('.').next().unwrap_or(apn);
    !NON_DATA_APNS.iter().any(|n| label.eq_ignore_ascii_case(n))
}

/// Parses the two line shapes `zte_topsw_data` writes. A line without usable
/// rates (e.g. a modification that leaves the AMBR unchanged) is skipped, so
/// the AMBR from the session's setup still applies.
///
/// 5G PDU session, value × unit:
/// `dnn=3gnet session_ambr_dl=2000 session_ambr_dl_unit=6(1Mbps) …`
///
/// LTE default bearer, the three APN-AMBR octets of TS 24.301 §9.9.4.2:
/// `access_point=… apn_ambr_dl=8640kbps apn_ambr_dl_ext=176.000Mbps apn_ambr_dl_ext2=1208.640Mbps …`
fn parse_line(line: &str) -> Option<Ambr> {
    let (apn, dl_mbps, ul_mbps) = if line.contains(" session_ambr_dl=") {
        (
            field(line, "dnn")?,
            nr_rate(line, "dl")?,
            nr_rate(line, "ul")?,
        )
    } else if line.contains(" apn_ambr_dl=") {
        (
            field(line, "access_point")?,
            lte_rate(line, "dl")?,
            lte_rate(line, "ul")?,
        )
    } else {
        return None;
    };
    Some(Ambr {
        apn: apn.into(),
        dl_mbps,
        ul_mbps,
    })
}

/// The value after ` key=`, up to the next space.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let at = line.find(&format!(" {key}="))? + key.len() + 2;
    line[at..].split(' ').next()
}

/// Value × the TS 24.501 unit, printed as e.g. `6(1Mbps)` or `11(1Gbps)`.
fn nr_rate(line: &str, dir: &str) -> Option<f64> {
    let value: f64 = field(line, &format!("session_ambr_{dir}"))?.parse().ok()?;
    let unit = field(line, &format!("session_ambr_{dir}_unit"))?
        .split_once('(')?
        .1
        .strip_suffix(')')?;
    let split = unit.find(|c: char| !c.is_ascii_digit() && c != '.')?;
    let (multiplier, name) = unit.split_at(split);
    let scale = match name.to_ascii_lowercase().as_str() {
        "kbps" => 1e-3,
        "mbps" => 1.0,
        "gbps" => 1e3,
        "tbps" => 1e6,
        "pbps" => 1e9,
        _ => return None,
    };
    mbps(value * multiplier.parse::<f64>().ok()? * scale)
}

/// The daemon prints the base octet in kbps, the extended octet in Mbps, and
/// the extended-2 octet as a running total that also counts the other two
/// (0.000 when an octet is unused). A non-zero extended octet replaces the
/// base octet, so the base is taken back out of that total.
fn lte_rate(line: &str, dir: &str) -> Option<f64> {
    let num =
        |key: String, suffix: &str| field(line, &key)?.strip_suffix(suffix)?.parse::<f64>().ok();
    let base = num(format!("apn_ambr_{dir}"), "kbps")? / 1000.0;
    let ext = num(format!("apn_ambr_{dir}_ext"), "Mbps")?;
    let ext2 = num(format!("apn_ambr_{dir}_ext2"), "Mbps")?;
    let total = match (ext2 > 0.0, ext > 0.0) {
        (true, true) => ext2 - base,
        (true, false) => ext2,
        (false, true) => ext,
        (false, false) => base,
    };
    mbps(total)
}

/// Rounds to the kbps and rejects 0, which the network never grants.
fn mbps(value: f64) -> Option<f64> {
    let rounded = (value * 1000.0).round() / 1000.0;
    (rounded > 0.0).then_some(rounded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    const LTE: &str = "12:14:56 : [DATA] eps_bearer_id=5 msg_type=193 access_point=internet.mnc001.mcc260.gprs apn_ambr_dl=8640kbps apn_ambr_ul=8640kbps apn_ambr_dl_ext=176.000Mbps apn_ambr_ul_ext=200.000Mbps apn_ambr_dl_ext2=1208.640Mbps apn_ambr_ul_ext2=0.000Mbps";
    const LTE_IMS: &str = "12:14:57 : [DATA] eps_bearer_id=6 msg_type=193 access_point=ims.mnc001.mcc260.gprs apn_ambr_dl=64kbps apn_ambr_ul=64kbps apn_ambr_dl_ext=0.000Mbps apn_ambr_ul_ext=0.000Mbps apn_ambr_dl_ext2=0.000Mbps apn_ambr_ul_ext2=0.000Mbps";
    const NR: &str = "12:14:56 : [DATA] pdu_session_id=2 msg_type=194 dnn=3gnet session_ambr_dl=2000 session_ambr_dl_unit=6(1Mbps) session_ambr_ul=200 session_ambr_ul_unit=6(1Mbps)";
    const NR_IMS: &str = "12:14:56 : [DATA] pdu_session_id=1 msg_type=194 dnn=IMS session_ambr_dl=30000 session_ambr_dl_unit=1(1Kbps) session_ambr_ul=30000 session_ambr_ul_unit=1(1Kbps)";

    fn ambr(apn: &str, dl_mbps: f64, ul_mbps: f64) -> Option<Ambr> {
        Some(Ambr {
            apn: apn.into(),
            dl_mbps,
            ul_mbps,
        })
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("zte-agent-bearer-{}-{name}", std::process::id()))
    }

    #[test]
    fn parses_session_and_apn_ambr() {
        assert_eq!(
            parse_line(LTE),
            ambr("internet.mnc001.mcc260.gprs", 1200.0, 200.0)
        );
        assert_eq!(parse_line(NR), ambr("3gnet", 2000.0, 200.0));
        assert_eq!(
            newest(&format!("{LTE}\n{NR}\n{NR_IMS}\n")),
            ambr("3gnet", 2000.0, 200.0)
        );
    }

    #[test]
    fn skips_ims_with_an_operator_suffix() {
        assert_eq!(newest(&format!("{LTE}\n{LTE_IMS}\n")), parse_line(LTE));
        assert!(is_data_apn("internet"));
        assert!(!is_data_apn("SOS"));
    }

    #[test]
    fn lte_without_extended_octets_uses_the_base_octet() {
        let line = LTE
            .replace("apn_ambr_dl=8640kbps", "apn_ambr_dl=5000kbps")
            .replace("apn_ambr_dl_ext=176.000Mbps", "apn_ambr_dl_ext=0.000Mbps")
            .replace(
                "apn_ambr_dl_ext2=1208.640Mbps",
                "apn_ambr_dl_ext2=0.000Mbps",
            )
            .replace("apn_ambr_ul_ext=200.000Mbps", "apn_ambr_ul_ext=0.000Mbps");
        assert_eq!(lte_rate(&line, "dl"), Some(5.0));
        assert_eq!(lte_rate(&line, "ul"), Some(8.64));
    }

    #[test]
    fn nr_scales_by_the_printed_unit() {
        let line = NR
            .replace(
                "session_ambr_dl=2000 session_ambr_dl_unit=6(1Mbps)",
                "session_ambr_dl=2 session_ambr_dl_unit=11(1Gbps)",
            )
            .replace(
                "session_ambr_ul=200 session_ambr_ul_unit=6(1Mbps)",
                "session_ambr_ul=50 session_ambr_ul_unit=7(4Mbps)",
            );
        assert_eq!(parse_line(&line), ambr("3gnet", 2000.0, 200.0));
        assert_eq!(nr_rate(NR_IMS, "dl"), Some(30.0));
    }

    #[test]
    fn a_line_without_rates_keeps_the_previous_ambr() {
        let modify = NR
            .replace("msg_type=194", "msg_type=203")
            .replace("session_ambr_dl=2000", "session_ambr_dl=0")
            .replace("session_ambr_ul=200", "session_ambr_ul=0");
        assert_eq!(parse_line(&modify), None);
        assert_eq!(newest(&format!("{NR}\n{modify}\n")), parse_line(NR));
    }

    #[test]
    fn reads_options_from_uci_show() {
        let show = "zwrt_data_tmp.wwaniface1=wwaniface\n\
            zwrt_data_tmp.wwaniface1.connect_status='ipv4_ipv6_connected'\n\
            zwrt_data_tmp.wwaniface1.qci_extra='9'\n\
            zwrt_data_tmp.wwaniface1.qci='6'\n";
        assert_eq!(uci_option(show, "qci"), Some("6"));
        assert_eq!(
            uci_option(show, "connect_status").map(is_connected),
            Some(true)
        );
        assert_eq!(uci_option(show, "ipv4_address"), None);
        assert!(!is_connected("disconnected"));
        assert!(!is_connected("eth_connected"));
    }

    #[test]
    fn scans_backwards_across_windows_and_skips_a_partial_line() {
        let path = temp_path("windows");
        let filler: String = (0..40)
            .map(|i| format!("12:00:{i:02} : [ROUTE] filler line {i}\n"))
            .collect();
        // Parses fine, but has no newline yet.
        let partial = NR.replace("session_ambr_dl=2000", "session_ambr_dl=9999");
        let text = format!("{filler}{NR}\n{filler}{NR_IMS}\n{filler}{partial}");
        std::fs::write(&path, &text).unwrap();
        let complete = (text.len() - partial.len()) as u64;
        for chunk in [250, 300, 512, 4096, CHUNK] {
            let scan = scan_chunked(&path, 0, text.len() as u64, chunk);
            assert_eq!(scan.newest, parse_line(NR), "chunk {chunk}");
            assert_eq!(scan.consumed, complete, "chunk {chunk}");
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_line_longer_than_the_window_does_not_stall() {
        let path = temp_path("long");
        let text = format!("{NR}\n{}\n", "x".repeat(1000));
        std::fs::write(&path, &text).unwrap();
        let scan = scan_chunked(&path, 0, text.len() as u64, 64);
        assert_eq!(scan.newest, None);
        assert_eq!(scan.consumed, text.len() as u64);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn follows_appends_and_rotation() {
        let (log, rotated) = (temp_path("key.log"), temp_path("key.log.0"));
        let _ = std::fs::remove_file(&rotated);
        std::fs::write(&log, format!("{NR}\n")).unwrap();
        let mut cursor = LogCursor::new();
        assert_eq!(cursor.refresh(&log, &rotated), parse_line(NR));

        // A line still being written is not read until its newline lands.
        let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        file.write_all(LTE.as_bytes()).unwrap();
        assert_eq!(cursor.refresh(&log, &rotated), parse_line(NR));
        file.write_all(b"\n").unwrap();
        assert_eq!(cursor.refresh(&log, &rotated), parse_line(LTE));

        // After a rename rotation the fresh log has no data session yet, so the
        // newest line is the one in the rotated file.
        std::fs::rename(&log, &rotated).unwrap();
        std::fs::write(&log, format!("{NR_IMS}\n")).unwrap();
        assert_eq!(cursor.refresh(&log, &rotated), parse_line(LTE));
        let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        writeln!(file, "{NR}").unwrap();
        assert_eq!(cursor.refresh(&log, &rotated), parse_line(NR));

        std::fs::remove_file(&log).unwrap();
        std::fs::remove_file(&rotated).unwrap();
    }

    /// Verbatim from a U60 Pro (B27) on DITO, 2026-10-16. The daemon ends each
    /// line with a space. The LTE extended-2 octet is 2 × 256 Mbps, printed as
    /// 512 + 12.2 + 8.64.
    #[test]
    fn parses_lines_from_a_dito_session() {
        let lte = "2026-10-16 01:31:15 : [DATA] eps_bearer_id=5 msg_type=193 access_point=internet.dito.ph.MNC066.MCC515.GPRS apn_ambr_dl=8640kbps apn_ambr_ul=8640kbps apn_ambr_dl_ext=12.200Mbps apn_ambr_ul_ext=12.200Mbps apn_ambr_dl_ext2=532.840Mbps apn_ambr_ul_ext2=532.840Mbps ";
        let ims = "2026-10-16 01:33:23 : [DATA] pdu_session_id=1 msg_type=194 dnn=ims session_ambr_dl=100 session_ambr_dl_unit=6(1Mbps) session_ambr_ul=100 session_ambr_ul_unit=6(1Mbps) ";
        let nr = "2026-10-16 01:33:23 : [DATA] pdu_session_id=2 msg_type=194 dnn=internet.dito.ph session_ambr_dl=10000 session_ambr_dl_unit=6(1Mbps) session_ambr_ul=10000 session_ambr_ul_unit=6(1Mbps) ";
        assert_eq!(
            parse_line(lte),
            ambr("internet.dito.ph.MNC066.MCC515.GPRS", 524.2, 524.2)
        );
        assert_eq!(newest(&format!("{lte}\n{ims}\n")), parse_line(lte));
        assert_eq!(
            newest(&format!("{lte}\n{nr}\n{ims}\n")),
            ambr("internet.dito.ph", 10000.0, 10000.0)
        );
    }

    /// Verbatim from the same device on GOMO (Globe), 2026-10-17: down 4 × 256
    /// + 24, up 1 × 256 + 256 (printed with the 8.64 base added). The agent
    /// returned exactly these values on the device.
    #[test]
    fn parses_a_line_from_a_globe_session() {
        let line = "2026-10-16 02:45:05 : [DATA] eps_bearer_id=5 msg_type=193 access_point=athome.globe.com.ph.MNC002.MCC515.GPRS apn_ambr_dl=8640kbps apn_ambr_ul=8640kbps apn_ambr_dl_ext=24.000Mbps apn_ambr_ul_ext=256.000Mbps apn_ambr_dl_ext2=1056.640Mbps apn_ambr_ul_ext2=520.640Mbps ";
        assert_eq!(
            parse_line(line),
            ambr("athome.globe.com.ph.MNC002.MCC515.GPRS", 1048.0, 512.0)
        );
    }

    /// Checks a key.log pulled off a device:
    /// `BEARER_LOG=/tmp/key.log cargo test -p zte-agent real_log -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_log() {
        let path = std::env::var("BEARER_LOG").expect("BEARER_LOG");
        let mut cursor = LogCursor::new();
        let ambr = cursor.refresh(Path::new(&path), Path::new("/nonexistent"));
        println!("newest data-session AMBR: {ambr:?}");
        println!("consumed {} bytes", cursor.read_len);
    }
}
