use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

use super::net;

const SETTING: &str = "strict-zero-cellular";
pub(super) const JOURNAL: &str = "cellular-pause";
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const UNKNOWN_STATUS: &str = "The modem did not report a recognized cellular connection status";

pub(super) fn enabled(root: &Path) -> bool {
    root.join(SETTING).exists()
}

pub(super) fn save(root: &Path, enabled: bool) -> Result<(), String> {
    let path = root.join(SETTING);
    let result = if enabled {
        net::write_private(&path, b"1\n").and_then(|()| sync_dir(root))
    } else {
        remove(&path)
    };
    result.map_err(|error| format!("Cannot save the strict zero-cellular setting: {error}"))
}

fn remove(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => sync_dir(path.parent().ok_or("Invalid cellular pause path")?),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn sync_dir(root: &Path) -> Result<(), String> {
    File::open(root).and_then(|dir| dir.sync_all()).map_err(|error| error.to_string())
}

fn original_enabled(root: &Path) -> Result<Option<bool>, String> {
    let path = root.join(JOURNAL);
    if !crate::ota::storage::entry_exists(&path)
        .map_err(|error| format!("Cannot inspect the cellular pause journal: {error}"))?
    {
        return Ok(None);
    }
    match crate::ota::storage::read_regular_bounded(&path, 64) {
        Ok(bytes) if bytes == b"1\n" => Ok(Some(true)),
        Ok(bytes) if bytes == b"0\n" => Ok(Some(false)),
        Ok(_) => Err("The cellular pause journal is invalid".into()),
        Err(error) => Err(format!("Cannot read the cellular pause journal: {error}")),
    }
}

fn data_enabled(value: &Value) -> Result<bool, String> {
    match (value["enable"].as_u64(), value["enable"].as_str()) {
        (Some(0), _) | (_, Some("0")) => Ok(false),
        (Some(1), _) | (_, Some("1")) => Ok(true),
        _ => Err("The modem did not report whether cellular data is enabled".into()),
    }
}

trait DataCall {
    fn state(&mut self) -> Result<DataState, String>;
    fn set_enabled(&mut self, enabled: bool) -> Result<(), String>;
}

enum Connection {
    Disconnected,
    Disconnecting,
    Active,
    Unknown,
}

struct DataState {
    enabled: bool,
    connection: Connection,
}

impl DataState {
    fn read(value: &Value) -> Result<Self, String> {
        let connection = match value["connect_status"].as_str() {
            Some("disconnected" | "ipv4_ipv6_disconnected") => Connection::Disconnected,
            Some("disconnecting") => Connection::Disconnecting,
            Some(
                "connected"
                | "connecting"
                | "ipv4_connected"
                | "ipv6_connected"
                | "ipv4_ipv6_connected"
                | "ipv4_disconnected"
                | "ipv6_disconnected",
            ) => Connection::Active,
            _ => Connection::Unknown,
        };
        Ok(Self { enabled: data_enabled(value)?, connection })
    }

    fn needs_pause(&self) -> bool {
        self.enabled || matches!(self.connection, Connection::Active)
    }

    fn paused(self) -> Result<bool, String> {
        match self.connection {
            Connection::Disconnected => Ok(!self.enabled),
            Connection::Disconnecting | Connection::Active => Ok(false),
            Connection::Unknown => Err(UNKNOWN_STATUS.into()),
        }
    }
}

struct Device;

impl DataCall for Device {
    fn state(&mut self) -> Result<DataState, String> {
        let value = crate::ubus::call_bounded("zwrt_data", "get_wwaniface", Some(r#"{"cid":1}"#), 2)?;
        DataState::read(&value)
    }

    fn set_enabled(&mut self, enabled: bool) -> Result<(), String> {
        let body = if enabled { r#"{"cid":1,"enable":1}"# } else { r#"{"cid":1,"enable":0}"# };
        crate::ubus::call_bounded("zwrt_data", "set_wwaniface", Some(body), 3)?;
        Ok(())
    }
}

fn confirm(
    modem: &mut impl DataCall, mut state: DataState, matches: impl Fn(DataState) -> Result<bool, String>, error: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + CONFIRM_TIMEOUT;
    loop {
        if matches(state)? {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(error.into());
        }
        std::thread::sleep(POLL_INTERVAL.min(remaining));
        state = modem.state()?;
    }
}

#[derive(Default, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    #[default]
    Idle,
    Paused,
    AlreadyOff,
    Error,
}

#[derive(Default, Serialize)]
pub(super) struct Pause {
    state: Phase,
    original_enabled: Option<bool>,
    error: Option<String>,
}

impl Pause {
    pub(super) fn reconcile(&mut self, root: &Path) -> Result<(), String> {
        self.reconcile_with(root, &mut Device)
    }

    pub(super) fn set(&mut self, root: &Path, pause: bool) -> Result<(), String> {
        self.set_with(root, pause, &mut Device)
    }

    fn reconcile_with(&mut self, root: &Path, modem: &mut impl DataCall) -> Result<(), String> {
        self.set_with(root, enabled(root), modem)
    }

    fn set_with(&mut self, root: &Path, pause: bool, modem: &mut impl DataCall) -> Result<(), String> {
        let result = if pause { self.pause(root, modem) } else { self.restore(root, modem) };
        self.error = None;
        result.map_err(|error| self.failed(format!("Cannot {} cellular data: {error}", if pause { "pause" } else { "restore" })))
    }

    fn pause(&mut self, root: &Path, modem: &mut impl DataCall) -> Result<(), String> {
        self.original_enabled = original_enabled(root)?;
        let mut state = modem.state()?;
        if matches!(state.connection, Connection::Unknown) {
            return Err(UNKNOWN_STATUS.into());
        }
        let original = self.original_enabled.unwrap_or(state.enabled);
        let new_journal = self.original_enabled.is_none();
        if new_journal {
            net::write_private(&root.join(JOURNAL), if original { b"1\n" } else { b"0\n" })?;
            self.original_enabled = Some(original);
        }
        let needs_pause = state.needs_pause();
        if new_journal || needs_pause {
            sync_dir(root)?;
        }
        if needs_pause {
            modem.set_enabled(false)?;
            state = modem.state()?;
        }
        confirm(modem, state, DataState::paused, "The modem did not confirm that cellular data was disabled and disconnected")?;
        self.state = if original { Phase::Paused } else { Phase::AlreadyOff };
        Ok(())
    }

    fn restore(&mut self, root: &Path, modem: &mut impl DataCall) -> Result<(), String> {
        self.original_enabled = original_enabled(root)?;
        if let Some(target_enabled) = self.original_enabled {
            let mut state = modem.state()?;
            if state.enabled != target_enabled {
                match modem.set_enabled(target_enabled) {
                    Ok(()) => state = modem.state()?,
                    Err(write_error) => {
                        // On B31 firmware (e.g. out-of-service / LIMITED_SERVICE),
                        // `zwrt_data set_wwaniface enable=1` commits `enable=1`
                        // synchronously and can still exit with ubus Unknown error (rc=9).
                        // Accept the write if immediate readback confirms the target state.
                        match modem.state() {
                            Ok(fresh) if fresh.enabled == target_enabled => state = fresh,
                            _ => return Err(write_error),
                        }
                    }
                }
            }
            let error = if target_enabled {
                "The modem did not confirm that cellular data was enabled"
            } else {
                "The modem did not confirm that cellular data was disabled"
            };
            confirm(modem, state, |state| Ok(state.enabled == target_enabled), error)?;
        }
        remove(&root.join(JOURNAL))?;
        self.original_enabled = None;
        self.state = Phase::Idle;
        Ok(())
    }

    pub(super) fn failed(&mut self, error: String) -> String {
        self.state = Phase::Error;
        self.error = Some(error.clone());
        error
    }

    pub(super) fn error(&self) -> Option<&str> { self.error.as_deref() }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::path::PathBuf;

    pub(in crate::wifi_relay) struct Modem {
        root: PathBuf,
        pub(in crate::wifi_relay) on: bool,
        fail_read: bool,
        pub(in crate::wifi_relay) fail_write: bool,
        commit_before_fail_write: bool,
        statuses: VecDeque<Option<&'static str>>,
        reads: usize,
        pub(in crate::wifi_relay) writes: Vec<bool>,
    }

    impl Modem {
        pub(in crate::wifi_relay) fn new(root: &Path, on: bool) -> Self {
            Self { root: root.into(), on, fail_read: false, fail_write: false, commit_before_fail_write: false, statuses: VecDeque::new(), reads: 0, writes: Vec::new() }
        }

        pub(in crate::wifi_relay) fn set(&mut self, pause: &mut Pause, enabled: bool) -> Result<(), String> {
            let root = self.root.clone();
            pause.set_with(&root, enabled, self)
        }

        pub(in crate::wifi_relay) fn reconcile(&mut self, pause: &mut Pause) -> Result<(), String> {
            let root = self.root.clone();
            pause.reconcile_with(&root, self)
        }
    }

    impl DataCall for Modem {
        fn state(&mut self) -> Result<DataState, String> {
            self.reads += 1;
            if self.fail_read {
                return Err("read failed".into());
            }
            let status = if self.statuses.len() > 1 {
                self.statuses.pop_front().unwrap()
            } else {
                self.statuses.front().copied().unwrap_or(Some(if self.on { "ipv4_connected" } else { "disconnected" }))
            };
            let mut reported = json!({"enable": u8::from(self.on)});
            if let Some(status) = status {
                reported["connect_status"] = json!(status);
            }
            DataState::read(&reported)
        }

        fn set_enabled(&mut self, enabled: bool) -> Result<(), String> {
            let original = original_enabled(&self.root).unwrap();
            assert!(original.is_some(), "persisted before either modem write");
            if enabled {
                assert_eq!(original, Some(true));
            }
            self.writes.push(enabled);
            if self.fail_write {
                if self.commit_before_fail_write {
                    self.on = enabled;
                }
                return Err("write failed".into());
            }
            self.on = enabled;
            Ok(())
        }
    }

    #[test]
    fn cellular_state_requires_an_explicit_integer_or_string_bit() {
        for (value, enabled) in [(json!(0), false), (json!(1), true), (json!("0"), false), (json!("1"), true)] {
            assert_eq!(data_enabled(&json!({"enable": value})), Ok(enabled));
        }
        for value in [json!(null), json!(true), json!(2), json!(""), json!({})] {
            assert!(data_enabled(&json!({"enable": value})).is_err());
        }
    }

    #[test]
    fn strict_setting_defaults_off_and_is_persisted_separately_from_the_journal() {
        let dir = super::super::test_dir::TestDir::new("strict-setting");
        let root = dir.path();
        assert!(!enabled(root));
        save(root, true).unwrap();
        assert!(enabled(root));
        assert_eq!(original_enabled(root), Ok(None));
        save(root, false).unwrap();
        save(root, false).unwrap();
        assert!(!enabled(root));
    }

    #[test]
    fn pauses_and_restores_cellular_that_was_on_including_after_a_restart() {
        for restart in [false, true] {
            let dir = super::super::test_dir::TestDir::new("cellular-pause");
            let root = dir.path();
            let mut modem = Modem::new(root, true);
            let mut pause = Pause::default();
            pause.set_with(root, true, &mut modem).unwrap();
            pause.set_with(root, true, &mut modem).unwrap();
            assert!(!modem.on);
            assert_eq!(modem.writes, [false]);
            assert_eq!(serde_json::to_value(&pause).unwrap(), json!({"state":"paused","original_enabled":true,"error":null}));
            if restart {
                pause = Pause::default();
            }
            pause.set_with(root, false, &mut modem).unwrap();
            assert_eq!(modem.writes, [false, true]);
            assert!(modem.on);
            assert_eq!(original_enabled(root), Ok(None));
            assert_eq!(serde_json::to_value(&pause).unwrap(), json!({"state":"idle","original_enabled":null,"error":null}));
        }
    }

    #[test]
    fn adoption_reconciles_a_strict_session_before_restoring_cellular_on_disconnect() {
        for modem_restarted in [false, true] {
            let dir = super::super::test_dir::TestDir::new("cellular-adoption");
            let root = dir.path();
            save(root, true).unwrap();
            fs::write(root.join(JOURNAL), b"1\n").unwrap();
            let mut modem = Modem::new(root, modem_restarted);
            let mut pause = Pause::default();

            pause.reconcile_with(root, &mut modem).unwrap();
            assert_eq!(original_enabled(root), Ok(Some(true)));
            assert!(!modem.on);
            assert_eq!(modem.writes, if modem_restarted { vec![false] } else { vec![] });
            assert_eq!(serde_json::to_value(&pause).unwrap()["state"], "paused");

            pause.set_with(root, false, &mut modem).unwrap();
            assert_eq!(modem.writes.last(), Some(&true));
            assert_eq!(original_enabled(root), Ok(None));
        }
    }

    #[test]
    fn cellular_that_was_off_stays_off_through_pause_and_recovery() {
        let dir = super::super::test_dir::TestDir::new("cellular-already-off");
        let root = dir.path();
        let mut modem = Modem::new(root, false);
        let mut pause = Pause::default();
        pause.set_with(root, true, &mut modem).unwrap();
        assert_eq!(serde_json::to_value(&pause).unwrap(), json!({"state":"already_off","original_enabled":false,"error":null}));
        assert_eq!(original_enabled(root), Ok(Some(false)));
        Pause::default().set_with(root, false, &mut modem).unwrap();
        assert_eq!(original_enabled(root), Ok(None));
        assert!(modem.writes.is_empty());
        assert!(!modem.on);
    }

    #[test]
    fn disabled_but_connected_cellular_times_out_and_stays_disabled_on_cleanup() {
        let dir = super::super::test_dir::TestDir::new("cellular-disabled-connected");
        let root = dir.path();
        let mut modem = Modem::new(root, false);
        modem.statuses.push_back(Some("ipv4_connected"));
        let mut pause = Pause::default();

        let error = pause.set_with(root, true, &mut modem).unwrap_err();
        assert!(error.contains("did not confirm"));
        assert!(modem.reads > 1);
        assert_eq!(modem.writes, [false]);
        assert_eq!(original_enabled(root), Ok(Some(false)));
        assert_eq!(serde_json::to_value(&pause).unwrap()["state"], "error");
        pause.set_with(root, false, &mut modem).unwrap();
        assert_eq!(modem.writes, [false]);
    }

    #[test]
    fn active_call_with_enable_zero_reissues_pause_and_preserves_original_journal() {
        for originally_enabled in [true, false] {
            let dir = super::super::test_dir::TestDir::new("cellular-active-enable-zero");
            let root = dir.path();
            save(root, true).unwrap();
            let mut modem = Modem::new(root, originally_enabled);
            let mut pause = Pause::default();
            pause.reconcile_with(root, &mut modem).unwrap();
            modem.writes.clear();

            // Modem reports enable=0 while a data call is actively connected.
            modem.on = false;
            modem.fail_write = true;
            modem.statuses = [Some("ipv4_connected")].into();
            let error = pause.reconcile_with(root, &mut modem).unwrap_err();
            assert!(error.contains("write failed"));
            assert_eq!(modem.writes, [false]);
            assert_eq!(original_enabled(root), Ok(Some(originally_enabled)));
            assert_eq!(serde_json::to_value(&pause).unwrap()["state"], "error");

            // Once the write succeeds, the reissued pause disconnects the call and clears the error.
            modem.fail_write = false;
            modem.statuses = [Some("ipv4_connected"), Some("disconnecting"), Some("disconnected")].into();
            pause.reconcile_with(root, &mut modem).unwrap();
            assert_eq!(modem.writes, [false, false]);
            assert_eq!(original_enabled(root), Ok(Some(originally_enabled)));
            let expected_phase = if originally_enabled { "paused" } else { "already_off" };
            assert_eq!(
                serde_json::to_value(&pause).unwrap(),
                json!({"state": expected_phase, "original_enabled": originally_enabled, "error": null})
            );

            // Cleanup restores cellular ONLY if it was originally enabled.
            modem.statuses.clear();
            pause.set_with(root, false, &mut modem).unwrap();
            let expected_writes = if originally_enabled { vec![false, false, true] } else { vec![false, false] };
            assert_eq!(modem.writes, expected_writes);
            assert_eq!(modem.on, originally_enabled);
            assert_eq!(original_enabled(root), Ok(None));
        }
    }

    #[test]
    fn disabled_with_missing_or_unknown_connection_status_is_unconfirmed() {
        for initial_enabled in [false, true] {
            for status in [None, Some("unexpected")] {
                let dir = super::super::test_dir::TestDir::new("cellular-unknown-status");
                let root = dir.path();
                let mut modem = Modem::new(root, initial_enabled);
                modem.statuses = [status, Some("disconnected")].into();
                let mut pause = Pause::default();

                let error = pause.set_with(root, true, &mut modem).unwrap_err();
                assert!(error.contains(UNKNOWN_STATUS));
                assert_eq!(modem.reads, 1);
                assert!(modem.writes.is_empty());
                assert_eq!(original_enabled(root), Ok(None));
                pause.set_with(root, false, &mut modem).unwrap();
                assert!(modem.writes.is_empty());
            }
        }
    }

    #[test]
    fn retry_queries_connection_status_when_the_journal_says_cellular_was_off() {
        let dir = super::super::test_dir::TestDir::new("cellular-retry");
        let root = dir.path();
        save(root, true).unwrap();
        fs::write(root.join(JOURNAL), b"0\n").unwrap();
        let mut modem = Modem::new(root, false);
        modem.statuses.push_back(None);
        let mut pause = Pause::default();

        assert!(pause.reconcile_with(root, &mut modem).is_err());
        assert_eq!(modem.reads, 1);
        modem.statuses = [Some("ipv4_ipv6_disconnected")].into();
        pause.reconcile_with(root, &mut modem).unwrap();
        assert_eq!(modem.reads, 2);
        assert_eq!(original_enabled(root), Ok(Some(false)));
        assert_eq!(serde_json::to_value(&pause).unwrap()["state"], "already_off");
        assert!(modem.writes.is_empty());
    }

    #[test]
    fn already_disabled_cellular_can_finish_disconnecting_during_confirmation() {
        let dir = super::super::test_dir::TestDir::new("cellular-disconnecting");
        let root = dir.path();
        let mut modem = Modem::new(root, false);
        modem.statuses = [Some("disconnecting"), Some("disconnected")].into();
        let mut pause = Pause::default();

        pause.set_with(root, true, &mut modem).unwrap();
        assert_eq!(modem.reads, 2);
        assert_eq!(original_enabled(root), Ok(Some(false)));
        assert_eq!(serde_json::to_value(&pause).unwrap()["state"], "already_off");
        pause.set_with(root, false, &mut modem).unwrap();
        assert!(modem.writes.is_empty());
    }

    #[test]
    fn active_strict_reconciliation_updates_status_and_repauses_cellular_after_a_restart() {
        let dir = super::super::test_dir::TestDir::new("cellular-maintenance");
        let root = dir.path();
        save(root, true).unwrap();
        let mut modem = Modem::new(root, false);
        let mut pause = Pause::default();
        pause.reconcile_with(root, &mut modem).unwrap();

        modem.on = true;
        modem.fail_write = true;
        let error = pause.reconcile_with(root, &mut modem).unwrap_err();
        assert_eq!(serde_json::to_value(&pause).unwrap(), json!({"state":"error","original_enabled":false,"error":error}));
        assert_eq!(modem.writes, [false]);
        assert_eq!(original_enabled(root), Ok(Some(false)));

        modem.fail_write = false;
        pause.reconcile_with(root, &mut modem).unwrap();
        assert_eq!(serde_json::to_value(&pause).unwrap(), json!({"state":"already_off","original_enabled":false,"error":null}));
        assert!(!modem.on);
        assert_eq!(modem.writes, [false, false]);
        assert_eq!(original_enabled(root), Ok(Some(false)));
        pause.set_with(root, false, &mut modem).unwrap();
        assert_eq!(modem.writes, [false, false]);
    }

    #[test]
    fn pause_and_restore_errors_are_reported_and_the_journal_survives_failed_writes() {
        let dir = super::super::test_dir::TestDir::new("cellular-failed-write");
        let root = dir.path();
        let mut modem = Modem::new(root, true);
        let mut pause = Pause::default();
        modem.fail_read = true;
        assert_eq!(pause.set_with(root, true, &mut modem), Err("Cannot pause cellular data: read failed".into()));
        assert_eq!(original_enabled(root), Ok(None));
        assert!(modem.writes.is_empty());

        modem.fail_read = false;
        modem.fail_write = true;
        let error = pause.set_with(root, true, &mut modem).unwrap_err();
        assert_eq!(serde_json::to_value(&pause).unwrap(), json!({"state":"error","original_enabled":true,"error":"Cannot pause cellular data: write failed"}));
        assert_eq!(pause.error, Some(error));
        assert_eq!(original_enabled(root), Ok(Some(true)));

        modem.on = false;
        let error = pause.set_with(root, false, &mut modem).unwrap_err();
        assert_eq!(serde_json::to_value(&pause).unwrap(), json!({"state":"error","original_enabled":true,"error":"Cannot restore cellular data: write failed"}));
        assert_eq!(pause.error, Some(error));
        assert_eq!(original_enabled(root), Ok(Some(true)));
        modem.fail_write = false;
        pause.set_with(root, false, &mut modem).unwrap();
        assert!(pause.error.is_none());
        assert_eq!(original_enabled(root), Ok(None));
    }

    #[test]
    fn failed_pause_that_left_cellular_enabled_does_not_write_enable_on_cleanup() {
        let dir = super::super::test_dir::TestDir::new("cellular-no-change");
        let root = dir.path();
        let mut modem = Modem::new(root, true);
        modem.fail_write = true;
        let mut pause = Pause::default();

        assert!(pause.set_with(root, true, &mut modem).is_err());
        pause.set_with(root, false, &mut modem).unwrap();
        assert_eq!(modem.writes, [false]);
        assert_eq!(original_enabled(root), Ok(None));
        assert!(modem.on);
    }

    #[test]
    fn failed_pause_confirmation_restores_cellular_after_enable_changed() {
        let dir = super::super::test_dir::TestDir::new("cellular-unconfirmed-change");
        let root = dir.path();
        let mut modem = Modem::new(root, true);
        modem.statuses = [Some("ipv4_connected"), None].into();
        let mut pause = Pause::default();

        assert!(pause.set_with(root, true, &mut modem).is_err());
        assert!(!modem.on);
        assert_eq!(original_enabled(root), Ok(Some(true)));
        pause.set_with(root, false, &mut modem).unwrap();
        assert_eq!(modem.writes, [false, true]);
        assert_eq!(original_enabled(root), Ok(None));
        assert!(modem.on);
    }

    #[test]
    fn corrupt_journal_does_not_authorize_a_modem_write() {
        let dir = super::super::test_dir::TestDir::new("cellular-unknown-original-state");
        let root = dir.path();
        fs::write(root.join(JOURNAL), b"unknown").unwrap();
        let mut modem = Modem::new(root, false);
        let mut pause = Pause::default();
        assert!(pause.set_with(root, true, &mut modem).is_err());
        assert!(pause.set_with(root, false, &mut modem).is_err());
        assert!(modem.writes.is_empty());
        assert!(root.join(JOURNAL).exists());
    }

    #[test]
    fn bare_connected_status_is_recognized_as_active_and_pauses_to_disconnected() {
        for initial_enabled in [true, false] {
            let dir = super::super::test_dir::TestDir::new("cellular-bare-connected");
            let root = dir.path();
            let mut modem = Modem::new(root, initial_enabled);
            modem.statuses = [Some("connected"), Some("disconnecting"), Some("disconnected")].into();
            let mut pause = Pause::default();

            pause.set_with(root, true, &mut modem).unwrap();
            assert!(!modem.on);
            assert_eq!(modem.writes, [false]);
            assert_eq!(original_enabled(root), Ok(Some(initial_enabled)));
            let expected_phase = if initial_enabled { "paused" } else { "already_off" };
            assert_eq!(
                serde_json::to_value(&pause).unwrap(),
                json!({"state": expected_phase, "original_enabled": initial_enabled, "error": null})
            );

            modem.statuses.clear();
            pause.set_with(root, false, &mut modem).unwrap();
            let expected_writes = if initial_enabled { vec![false, true] } else { vec![false] };
            assert_eq!(modem.writes, expected_writes);
            assert_eq!(modem.on, initial_enabled);
            assert_eq!(original_enabled(root), Ok(None));
        }
    }

    #[test]
    fn restore_verifies_recorded_off_state_and_retains_journal_on_failure() {
        let dir = super::super::test_dir::TestDir::new("cellular-restore-off");
        let root = dir.path();
        fs::write(root.join(JOURNAL), b"0\n").unwrap();

        // 1. Read failure while restoring recorded `0` must fail and retain journal.
        let mut modem = Modem::new(root, false);
        modem.fail_read = true;
        let mut pause = Pause::default();
        assert!(pause.set_with(root, false, &mut modem).is_err());
        assert_eq!(original_enabled(root), Ok(Some(false)));
        assert!(root.join(JOURNAL).exists());

        // 2. If the modem came back enabled before recovery and disabling fails,
        //    restore must fail and retain the journal.
        modem.fail_read = false;
        modem.on = true;
        modem.fail_write = true;
        assert!(pause.set_with(root, false, &mut modem).is_err());
        assert_eq!(modem.writes, [false]);
        assert!(modem.on);
        assert_eq!(original_enabled(root), Ok(Some(false)));
        assert!(root.join(JOURNAL).exists());

        // 3. Once disabling succeeds and readback confirms `enable=0`, the
        //    journal is removed and cellular stays disabled.
        modem.fail_write = false;
        pause.set_with(root, false, &mut modem).unwrap();
        assert_eq!(modem.writes, [false, false]);
        assert!(!modem.on);
        assert_eq!(original_enabled(root), Ok(None));
        assert!(!root.join(JOURNAL).exists());

        // 4. FIFO and dangling symlink at `cellular-pause` must return Err
        //    immediately without blocking or treating the entry as absent.
        let journal = root.join(JOURNAL);
        let c_fifo = std::ffi::CString::new(journal.to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated path with private mode 0600.
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
        assert!(
            original_enabled(root).is_err(),
            "FIFO at cellular-pause must fail immediately without blocking"
        );
        fs::remove_file(&journal).unwrap();

        std::os::unix::fs::symlink(root.join("missing-cellular-target"), &journal).unwrap();
        assert!(
            original_enabled(root).is_err(),
            "dangling symlink at cellular-pause must not be accepted as absent"
        );
        fs::remove_file(&journal).unwrap();
    }

    #[test]
    fn restore_accepts_committed_enable_when_modem_write_returns_error() {
        let dir = super::super::test_dir::TestDir::new("cellular-restore-commit-on-err");
        let root = dir.path();
        let mut modem = Modem::new(root, true);
        let mut pause = Pause::default();
        pause.set_with(root, true, &mut modem).unwrap();
        assert!(!modem.on);
        assert_eq!(original_enabled(root), Ok(Some(true)));

        // Simulate B31 zwrt_data returning ubus Unknown error (rc=9) while
        // synchronously committing enable=1 (e.g. LIMITED_SERVICE_WCDMA).
        modem.fail_write = true;
        modem.commit_before_fail_write = true;
        modem.statuses = [Some("disconnected")].into();
        pause.set_with(root, false, &mut modem).unwrap();
        assert!(modem.on);
        assert_eq!(original_enabled(root), Ok(None));
        assert!(!root.join(JOURNAL).exists());
        assert_eq!(
            serde_json::to_value(&pause).unwrap(),
            json!({"state":"idle","original_enabled":null,"error":null})
        );
    }
}
