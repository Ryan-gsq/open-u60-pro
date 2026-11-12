//! B31 firmware turns the driver's DFS channel switch off for the first
//! 10 minutes of every 160 MHz 5 GHz start: `/sbin/zte_wifi_dfs_hdlr.sh`
//! runs `iwpriv wlan2 disableDfsCS 1`, sleeps 599 s, then sets it back to 0
//! (the ini also loads it as 1). While it is off, a STA connect with the AP
//! spanning DFS (44/160 covers 52–64) asks the AP to CSA to non-DFS 44/80,
//! but the driver ends that CSA without the channel change: the connect
//! waits 10 s and fails, and `Channel switch in progress` rejects every
//! later connect until the hotspot restarts (the reboot failure).
//!
//! Owner decision 62: the switch is on before each join. The vendor's own
//! `wireless.zte_mbb.dfs_channel_switch_disable=1`, which the script reads
//! with `uci get` when it starts, makes it leave `disableDfsCS` alone, and
//! the Wi-Fi scripts then load the driver with `gDisableDFSChSwitch=0`. The
//! agent sets that key persistently (owner approval, 2026-11-12). A driver
//! loaded before the key was committed still starts with the flag on, so
//! each join also turns it back on. A script that started before the key
//! was set has read it already: inside its first second it may still turn
//! the flag off after a join turned it on.

use super::Cmd;

const KEY: &str = "wireless.zte_mbb.dfs_channel_switch_disable";

/// What a join found or did to the vendor key.
#[derive(Debug, PartialEq, Eq)]
enum Key {
    /// Already `1`, committed.
    Kept,
    /// Set and committed now.
    Committed,
    /// Set, but not committed: `uci commit wireless` would also make these
    /// other pending `wireless` changes permanent. `uci get` already reads
    /// the key; the next join commits once nothing else is pending.
    Uncommitted(usize),
}

/// Best effort: a firmware without the key or the command keeps its old
/// behaviour, and the join goes on either way.
pub(super) fn allow() {
    let _ = allow_with(&mut |cmd| cmd.run());
}

fn allow_with(run: &mut impl FnMut(&Cmd) -> Result<String, String>) -> Result<Key, String> {
    let key = vendor_key(run);
    match &key {
        Ok(Key::Kept) => {}
        Ok(Key::Committed) => crate::netlog!("[relay] set and committed {KEY}=1: the vendor DFS script now leaves the DFS channel switch on"),
        Ok(Key::Uncommitted(others)) => crate::netlog!("[relay] set {KEY}=1 without committing it: {others} other uncommitted wireless change(s); the next join commits it"),
        Err(e) => crate::netlog!("[relay] cannot set {KEY}=1: {e}"),
    }
    if let Err(e) = run(&Cmd::new("iwpriv", &["wlan2", "disableDfsCS", "0"])) {
        crate::netlog!("[relay] cannot turn the DFS channel switch on for wlan2: {e}");
    }
    key
}

fn vendor_key(run: &mut impl FnMut(&Cmd) -> Result<String, String>) -> Result<Key, String> {
    // `uci -q get` fails on a missing option as well.
    let value = run(&Cmd::new("uci", &["-q", "get", KEY])).map(|v| v.trim().to_owned()).unwrap_or_default();
    let changes = run(&Cmd::new("uci", &["-q", "changes", "wireless"]))?;
    if value == "1" && !changes.lines().any(about_key) {
        return Ok(Key::Kept);
    }
    if value != "1" {
        run(&Cmd::new("uci", &["set", &format!("{KEY}=1")]))?;
    }
    // Read again right before the commit: a change made meanwhile is not ours to make permanent.
    let others = others(&run(&Cmd::new("uci", &["-q", "changes", "wireless"]))?);
    if others > 0 {
        return Ok(Key::Uncommitted(others));
    }
    run(&Cmd::new("uci", &["commit", "wireless"]))?;
    Ok(Key::Committed)
}

/// A `uci changes` line that sets or deletes the key.
fn about_key(line: &str) -> bool {
    let line = line.strip_prefix('-').unwrap_or(line);
    line == KEY || line.strip_prefix(KEY).is_some_and(|rest| rest.starts_with('='))
}

fn others(changes: &str) -> usize {
    changes.lines().filter(|l| !l.trim().is_empty() && !about_key(l)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `wireless` as uci sees it: the committed key, its pending delta and
    /// other pending changes.
    #[derive(Default)]
    struct Uci {
        committed: Option<String>,
        delta: Option<String>,
        unrelated: Vec<String>,
        /// Another writer's change that appears after the first `changes` read.
        racing: Option<String>,
        broken: bool,
        calls: Vec<String>,
    }

    impl Uci {
        fn run(&mut self, cmd: &Cmd) -> Result<String, String> {
            let args: Vec<_> = cmd.args.iter().map(String::as_str).collect();
            self.calls.push(format!("{} {}", cmd.program, args.join(" ")));
            if cmd.program == "uci" && self.broken {
                return Err("uci: I/O error".into());
            }
            match (cmd.program.as_str(), args.as_slice()) {
                ("uci", ["-q", "get", KEY]) => self.delta.clone().or_else(|| self.committed.clone()).ok_or_else(|| "exit status 1".into()),
                ("uci", ["-q", "changes", "wireless"]) => {
                    let mut lines = self.unrelated.clone();
                    lines.extend(self.delta.as_ref().map(|d| format!("{KEY}='{d}'")));
                    if let Some(change) = self.racing.take() {
                        self.unrelated.push(change);
                    }
                    Ok(lines.join("\n"))
                }
                ("uci", ["set", set]) if *set == format!("{KEY}=1") => {
                    self.delta = Some("1".into());
                    Ok(String::new())
                }
                ("uci", ["commit", "wireless"]) => {
                    self.committed = self.delta.take().or(self.committed.take());
                    self.unrelated.clear();
                    Ok(String::new())
                }
                ("iwpriv", ["wlan2", "disableDfsCS", "0"]) => Ok(String::new()),
                _ => Err(format!("unexpected {cmd:?}")),
            }
        }

        fn allow(&mut self) -> Result<Key, String> {
            allow_with(&mut |cmd| self.run(cmd))
        }

        fn wrote(&self) -> Vec<&str> {
            self.calls.iter().map(String::as_str).filter(|c| c.starts_with("uci set") || c.starts_with("uci commit")).collect()
        }
    }

    const SWITCH_ON: &str = "iwpriv wlan2 disableDfsCS 0";

    #[test]
    fn a_committed_key_is_left_alone_and_the_switch_still_turned_on() {
        let mut uci = Uci { committed: Some("1".into()), ..Uci::default() };
        assert_eq!(uci.allow(), Ok(Key::Kept));
        assert!(uci.wrote().is_empty());
        assert_eq!(uci.calls.last().map(String::as_str), Some(SWITCH_ON));
    }

    #[test]
    fn a_missing_key_is_set_and_committed_once_when_nothing_else_is_pending() {
        let mut uci = Uci::default();
        assert_eq!(uci.allow(), Ok(Key::Committed));
        assert_eq!(uci.wrote(), [format!("uci set {KEY}=1").as_str(), "uci commit wireless"]);
        assert_eq!((uci.committed.as_deref(), uci.delta.as_deref()), (Some("1"), None));
        assert_eq!(uci.calls.last().map(String::as_str), Some(SWITCH_ON));
        uci.calls.clear();
        assert_eq!(uci.allow(), Ok(Key::Kept), "the next join writes nothing");
        assert!(uci.wrote().is_empty());
        // Another value, committed by someone else, is set to 1 as well.
        let mut uci = Uci { committed: Some("0".into()), ..Uci::default() };
        assert_eq!(uci.allow(), Ok(Key::Committed));
        assert_eq!(uci.committed.as_deref(), Some("1"));
    }

    #[test]
    fn other_pending_changes_are_never_committed_with_the_key() {
        let mut uci = Uci { unrelated: vec!["wireless.main_5g.ssid='Pending'".into()], ..Uci::default() };
        assert_eq!(uci.allow(), Ok(Key::Uncommitted(1)));
        assert_eq!(uci.wrote(), [format!("uci set {KEY}=1").as_str()]);
        assert_eq!((uci.committed.as_deref(), uci.delta.as_deref()), (None, Some("1")), "set for `uci get`, not committed");
        assert_eq!(uci.calls.last().map(String::as_str), Some(SWITCH_ON));
        // Still pending at the next join: the delta is not set twice.
        uci.calls.clear();
        assert_eq!(uci.allow(), Ok(Key::Uncommitted(1)));
        assert!(uci.wrote().is_empty());
        // The other writer reverts its change: the next join commits only the key.
        uci.unrelated.clear();
        assert_eq!(uci.allow(), Ok(Key::Committed));
        assert_eq!(uci.committed.as_deref(), Some("1"));
        // A change that appears between the first read and the commit.
        let mut uci = Uci { racing: Some("wireless.wifi1.channel='149'".into()), ..Uci::default() };
        assert_eq!(uci.allow(), Ok(Key::Uncommitted(1)));
        assert!(!uci.wrote().contains(&"uci commit wireless"));
    }

    #[test]
    fn a_failing_uci_does_not_stop_the_join() {
        let mut uci = Uci { broken: true, ..Uci::default() };
        assert!(uci.allow().is_err());
        assert_eq!(uci.calls.last().map(String::as_str), Some(SWITCH_ON));
        // `set` refused, e.g. a firmware without the `zte_mbb` section.
        let mut calls = Vec::new();
        let mut refused = |cmd: &Cmd| {
            calls.push(cmd.program.clone());
            if cmd.args.first().is_some_and(|a| a == "set") { Err("uci: Invalid argument".to_owned()) } else { Ok(String::new()) }
        };
        assert_eq!(allow_with(&mut refused), Err("uci: Invalid argument".into()));
        assert_eq!(calls.last().map(String::as_str), Some("iwpriv"));
    }

    #[test]
    fn only_the_keys_own_deltas_count_as_ours() {
        assert!(about_key(&format!("{KEY}='1'")) && about_key(&format!("-{KEY}")));
        assert!(!about_key(&format!("{KEY}_extra='1'")) && !about_key("wireless.zte_mbb.wifi_onoff='0'"));
        assert_eq!(others(&format!("\n{KEY}='1'\nwireless.wifi1.channel='36'\n")), 1);
    }
}
