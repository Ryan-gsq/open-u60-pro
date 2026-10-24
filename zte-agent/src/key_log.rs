//! Backward reads of the firmware's `/logfs/key.log`, without forking.
//!
//! Several firmware daemons append one line per event; the log runs to
//! 8 MiB and is then renamed to `key.log.0`. Its timestamps mix UTC and
//! local time and jump when the clock is corrected, so callers rely on line
//! order only: the newest matching line is the one nearest the end.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const KEY_LOG: &str = "/logfs/key.log";
pub const KEY_LOG_ROTATED: &str = "/logfs/key.log.0";

pub struct Scan<T> {
    pub newest: Option<T>,
    /// Offset just past the last complete line in the scanned range.
    pub consumed: u64,
}

/// Finds the newest match in `floor..end`, reading backwards `chunk` bytes at
/// a time. `find` gets a block of complete lines and returns the newest match
/// in it. `floor` must be a line start. A line still being written (no
/// newline yet) is never passed to `find`.
pub fn scan_back<T>(
    path: &Path,
    floor: u64,
    end: u64,
    chunk: u64,
    find: impl Fn(&str) -> Option<T>,
) -> Scan<T> {
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
        // Bytes after the last newline are a line still being written; it
        // may span several windows.
        let stop = if newest_window {
            match buf.iter().rposition(|&b| b == b'\n') {
                Some(i) => {
                    newest_window = false;
                    out.consumed = lo + i as u64 + 1;
                    i + 1
                }
                None => 0,
            }
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
            if let Some(found) = find(&String::from_utf8_lossy(&buf[start..stop])) {
                out.newest = Some(found);
                return out;
            }
        }
        // Re-read the cut line whole in the next window, unless it fills this
        // one: such a line is longer than any line we look for, and re-reading
        // would not progress.
        hi = if start == 0 || start >= buf.len() {
            lo
        } else {
            lo + start as u64
        };
    }
    out
}

/// Result of [`newest`].
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct Newest<T> {
    pub found: Option<T>,
    /// The start (at most one read window) of a line still being written at
    /// the end of the log, lossily decoded; empty when the log ends with a
    /// complete line. It is newer than `found`.
    pub pending: String,
}

/// The newest match in the whole of `log`, or, when the log has none (it was
/// just rotated), in `rotated`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn newest<T>(
    log: &Path,
    rotated: &Path,
    chunk: u64,
    find: impl Fn(&str) -> Option<T>,
) -> Newest<T> {
    let len = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
    let end = len(log);
    let scan = scan_back(log, 0, end, chunk, &find);
    let pending = if scan.consumed < end {
        File::open(log)
            .ok()
            .and_then(|mut f| read_range(&mut f, scan.consumed, end.min(scan.consumed + chunk)))
            .map(|buf| String::from_utf8_lossy(&buf).into_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let found = scan
        .newest
        .or_else(|| scan_back(rotated, 0, len(rotated), chunk, &find).newest);
    Newest { found, pending }
}

pub fn read_range(file: &mut File, start: u64, end: u64) -> Option<Vec<u8>> {
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    file.take(end.saturating_sub(start))
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("zte-agent-keylog-{}-{name}", std::process::id()))
    }

    /// The newest line starting with "match".
    fn last_match(text: &str) -> Option<String> {
        text.lines()
            .rev()
            .find(|l| l.starts_with("match"))
            .map(str::to_string)
    }

    #[test]
    fn falls_back_to_the_rotated_log() {
        let (log, rotated) = (temp_path("log"), temp_path("log.0"));
        std::fs::write(&rotated, "match old\nfiller\n").unwrap();
        std::fs::write(&log, "filler\n").unwrap();
        let found = |log: &PathBuf| newest(log, &rotated, 4096, last_match).found;
        assert_eq!(found(&log).as_deref(), Some("match old"));
        std::fs::write(&log, "match new\nfiller\n").unwrap();
        assert_eq!(found(&log).as_deref(), Some("match new"));
        std::fs::remove_file(&log).unwrap();
        assert_eq!(
            found(&log).as_deref(),
            Some("match old"),
            "a missing log reads as empty"
        );
        std::fs::remove_file(&rotated).unwrap();
        assert_eq!(found(&log), None);
    }

    #[test]
    fn a_partial_last_line_is_not_matched() {
        let (log, rotated) = (temp_path("partial"), temp_path("partial.0"));
        // Shorter and longer than the read window: the head of a partial
        // line that spans several windows is not a line either.
        for partial in [
            "match still being writ".to_string(),
            format!("match {}", "y".repeat(100)),
        ] {
            std::fs::write(&log, format!("match done\n{partial}")).unwrap();
            for chunk in [12, 16, 40, 4096] {
                let n = newest(&log, &rotated, chunk, last_match);
                let what = format!("chunk {chunk}, partial {} bytes", partial.len());
                assert_eq!(n.found.as_deref(), Some("match done"), "{what}");
                // The partial line is reported, from its start, one window at most.
                let shown = partial.len().min(chunk as usize);
                assert_eq!(n.pending, partial[..shown], "{what}");
            }
            let scan = scan_back(&log, 0, 11 + partial.len() as u64, 16, last_match);
            assert_eq!(scan.consumed, 11, "only the complete line is consumed");
        }
        std::fs::write(&log, "match done\n").unwrap();
        assert_eq!(newest(&log, &rotated, 16, last_match).pending, "");
        std::fs::remove_file(&log).unwrap();
    }
}
