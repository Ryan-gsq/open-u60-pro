//! Wi-Fi power save of the relay's upstream link (owner decision 65). The
//! driver turns it on for every new station interface: the U60 dozes between
//! beacons and the upstream AP holds its frames meanwhile. With it off, short
//! single-connection tests through the relay went from 166-218 to 244-250
//! Mbit/s (2026-11-08, `zte-agent/docs/relay-hw-offload.md`). Each relay
//! connection turns it off unless the owner keeps the driver's default. A
//! step of the session's network plan, so `net_guard` turns it off again if
//! the driver or a script turns it back on. Unrelated to ZTE's power saver
//! mode (`zwrt_zte_mc.power.power_saver_mode`).

use std::path::Path;

use serde_json::{json, Value};

use super::{net, Cmd, Resource, Internal, EffectSet, IFACE};

/// In the relay's state directory: the owner keeps the driver's power save.
const KEEP: &str = "keep-power-save";
const PROGRAM: &str = "@u60-relay-power-save";

/// Whether relay connections turn power save off (the default).
pub(super) fn auto_off(root: &Path) -> bool {
    !root.join(KEEP).exists()
}

pub(super) fn save(root: &Path, auto_off: bool) -> Result<(), String> {
    let path = root.join(KEEP);
    let result = if auto_off {
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
            _ => Ok(()),
        }
    } else {
        net::write_private(&path, b"1\n")
    };
    result.map_err(|_| "Cannot save the Wi-Fi power save setting".into())
}

/// The undo is a plain `iw` command, not `@u60-relay-power-save on`: a
/// journal must stay undoable by the agent it may roll back to, which does
/// not know this step (`relay-mihomo-architecture.md` section 4.2).
fn step() -> Resource {
    Resource::Internal(Internal::new(PROGRAM, vec!["off".into()], vec![]).with_undo(restore()))
}

fn restore() -> Cmd {
    Cmd::new("iw", &["dev", IFACE, "set", "power_save", "on"])
}

/// Whether `cmd` is this step's undo, which never pauses a cleanup: the
/// interface is deleted right after, or is already gone.
pub(crate) fn is_restore(cmd: &Cmd) -> bool {
    *cmd == restore()
}

/// This connection: whether the step is applied, or why it failed.
#[derive(Default)]
pub(super) struct State {
    off: bool,
    error: Option<String>,
}

impl State {
    /// Turns power save off (`auto_off`) or back on for this connection.
    pub(super) fn set(&mut self, network: &mut EffectSet, auto_off: bool) -> Result<(), String> {
        let result = if auto_off {
            network.declare(vec![step()]).map_err(|e| format!("Power save could not be turned off on this connection ({e})"))
        } else {
            match network.withdraw(&[step().key()]).and_then(|()| read()) {
                Ok(true) => Ok(()),
                _ => Err("Power save could not be turned back on; it stays off until the relay reconnects".into()),
            }
        };
        self.off = if auto_off { result.is_ok() } else { result.is_err() };
        match &result {
            Ok(()) => crate::netlog!("[relay] upstream Wi-Fi power save {}", if auto_off { "turned off" } else { "back on" }),
            Err(e) => crate::netlog!("[relay] upstream Wi-Fi power save not changed: {e}"),
        }
        self.error = result.as_ref().err().cloned();
        result
    }

    pub(super) fn status(&self) -> Value {
        json!({"off": self.off, "error": self.error})
    }
}

fn read() -> Result<bool, String> {
    parse(&Cmd::new("iw", &["dev", IFACE, "get", "power_save"]).run()?).ok_or_else(|| "Cannot read Wi-Fi power save".into())
}

fn parse(text: &str) -> Option<bool> {
    match text.trim().strip_prefix("Power save:")?.trim() {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

/// `@u60-relay-power-save off`. The undo is `restore`'s plain `iw` command.
pub(crate) fn command(args: &[String]) -> Result<(), String> {
    match args {
        [mode] if mode == "off" => Cmd::new("iw", &["dev", IFACE, "set", "power_save", "off"]).run().map(|_| ()),
        _ => Err("Invalid relay power save command".into()),
    }
}

/// Whether an applied `@u60-relay-power-save` step still holds.
pub(crate) fn present(args: &[String]) -> Result<bool, String> {
    Ok(read()? == (args.first().map(String::as_str) == Some("on")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_iw_readback_is_parsed_strictly() {
        assert_eq!(parse("Power save: on\n"), Some(true));
        assert_eq!(parse("Power save: off"), Some(false));
        assert_eq!(parse("command failed: No such device (-19)"), None);
        assert_eq!(parse("Power save: unknown"), None);
    }

    #[test]
    fn turning_off_is_the_default_and_keeping_it_is_saved_privately() {
        let root = std::env::temp_dir().join(format!("u60-power-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        assert!(auto_off(&root), "no file: turn it off");
        save(&root, true).unwrap();
        save(&root, false).unwrap();
        assert!(!auto_off(&root));
        save(&root, false).unwrap();
        assert!(!auto_off(&root));
        save(&root, true).unwrap();
        assert!(auto_off(&root));
        save(&root, true).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_step_turns_it_off_and_its_undo_back_on() {
        let step = step().step_with(|_| Ok("1".into())).unwrap();
        assert_eq!((step.apply.program.as_str(), step.apply.args.as_slice()), (PROGRAM, &["off".to_owned()][..]));
        assert_eq!((step.undo.program.as_str(), step.undo.args.join(" ")), ("iw", format!("dev {IFACE} set power_save on")), "an undo the previous agent runs");
        assert!(is_restore(&step.undo));
        assert!(command(&["auto".into()]).is_err());
        assert!(command(&[]).is_err());
    }

    #[test]
    fn releasing_a_step_that_never_applied_changes_nothing() {
        let dir = std::env::temp_dir().join(format!("u60-power-save-tx-{}", std::process::id()));
        let mut network = EffectSet::new("relay", dir.join("network.json"));
        network.withdraw(&[step().key()]).unwrap();
        assert!(!dir.join("network.json").exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
