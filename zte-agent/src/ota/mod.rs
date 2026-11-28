//! Signed, crash-safe updates for the on-device agent.
//!
//! Release manifests are signed offline. Downloads always land in the
//! inactive slot, are bounded and hashed, and are never selected by the boot
//! supervisor until a short local health trial succeeds.

pub mod manifest;
mod readiness;
pub mod storage;

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use manifest::{Channel, ManifestVerifier, ReleaseManifest, MAX_BINARY_BYTES, MAX_ENVELOPE_BYTES};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use storage::{Paths, Slot};

const STABLE_CHANNEL_URL: &str =
    "https://raw.githubusercontent.com/jesther-ai/open-u60-pro/ota-channels/stable.json";
const BETA_CHANNEL_URL: &str =
    "https://raw.githubusercontent.com/jesther-ai/open-u60-pro/ota-channels/beta.json";
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const HTTP_TIMEOUT: Duration = Duration::from_secs(45);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DOWNLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const REQUIRED_HEADROOM: u64 = 8 * 1024 * 1024;
const TRIAL_SECONDS: u64 = 60;
const PROMOTED_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const SUPERVISOR_SCRIPT: &[u8] = include_bytes!("../../../scripts/router/zte-agent-supervisor.sh");

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub channel: Channel,
    pub automatic_checks: bool,
    pub automatic_downloads: bool,
    /// Reserved for a future hardware-validated release. It cannot be enabled
    /// by the current API, even if an old settings file contains `true`.
    pub automatic_install: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            channel: Channel::Stable,
            automatic_checks: true,
            automatic_downloads: false,
            automatic_install: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    #[default]
    Idle,
    Checking,
    Downloading,
    Staged,
    Installing,
    RollingBack,
    Failed,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct PersistentState {
    phase: Phase,
    available: Option<ReleaseManifest>,
    staged: Option<ReleaseManifest>,
    staged_slot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback_target: Option<String>,
    last_check: Option<u64>,
    last_error: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct RuntimeState {
    persistent: PersistentState,
    bytes_received: u64,
    bytes_total: u64,
}

pub struct OtaManager {
    paths: Paths,
    verifier: ManifestVerifier,
    settings: Mutex<Settings>,
    state: Mutex<RuntimeState>,
    operation: AtomicBool,
    #[cfg(test)]
    supervisor_confirmed: AtomicBool,
    dashboard: Weak<crate::dashboard::Dashboard>,
    #[cfg(test)]
    test_slot_change_blocked: AtomicBool,
}

impl OtaManager {
    pub fn system(dashboard: Weak<crate::dashboard::Dashboard>) -> Arc<Self> {
        let paths = if cfg!(test) {
            let root =
                std::env::temp_dir().join(format!("u60-ota-appstate-{}", std::process::id()));
            Paths::new(root.clone(), root.join("supervisor"), root.join("legacy"))
        } else {
            Paths::system()
        };
        if let Err(error) = paths.prepare() {
            eprintln!("[ota] cannot prepare update storage: {error}");
        }
        let defer_supervisor = std::env::var("ZTE_OTA_TRIAL").as_deref() == Ok("1")
            || paths.pending.try_exists().unwrap_or(true)
            || same_boot_rollback_blocked_in(&paths);
        let _supervisor_ok = if !defer_supervisor {
            match ensure_supervisor(&paths) {
                Ok(()) => {
                    #[cfg(not(test))]
                    supervisor_repair_confirmed().store(true, Ordering::Release);
                    true
                }
                Err(error) => {
                    eprintln!("[ota] cannot repair update supervisor: {error}");
                    false
                }
            }
        } else {
            false
        };
        let mut settings = storage::read_json::<Settings>(&paths.settings).unwrap_or_default();
        settings.automatic_install = false;
        let mut persistent = storage::read_json(&paths.state).unwrap_or_default();
        if let Some(message) = reconcile_startup_state(&paths, &mut persistent) {
            if let Err(error) = storage::write_json(&paths.state, &persistent) {
                eprintln!("[ota] cannot save recovered update state: {error}");
            }
            paths.append_log(message);
        }
        let key = include_str!(concat!(env!("OUT_DIR"), "/ota-public-key.pem"));
        Arc::new(Self {
            paths,
            verifier: ManifestVerifier::from_pem((!key.trim().is_empty()).then_some(key)),
            settings: Mutex::new(settings),
            state: Mutex::new(RuntimeState {
                persistent,
                ..RuntimeState::default()
            }),
            operation: AtomicBool::new(false),
            #[cfg(test)]
            supervisor_confirmed: AtomicBool::new(_supervisor_ok),
            dashboard,
            #[cfg(test)]
            test_slot_change_blocked: AtomicBool::new(false),
        })
    }

    #[cfg(test)]
    fn test(paths: Paths, verifier: ManifestVerifier) -> Self {
        paths.prepare().unwrap();
        Self {
            paths,
            verifier,
            settings: Mutex::new(Settings::default()),
            state: Mutex::new(RuntimeState::default()),
            operation: AtomicBool::new(false),
            supervisor_confirmed: AtomicBool::new(true),
            dashboard: Weak::new(),
            test_slot_change_blocked: AtomicBool::new(false),
        }
    }

    fn supervisor_flag(&self) -> &AtomicBool {
        #[cfg(not(test))]
        {
            supervisor_repair_confirmed()
        }
        #[cfg(test)]
        {
            &self.supervisor_confirmed
        }
    }

    fn slot_change_blocked(&self) -> bool {
        #[cfg(test)]
        if self.test_slot_change_blocked.load(Ordering::Acquire) {
            return true;
        }
        let origin = trial_origin();
        let current_ppid = if origin.helper_ppid.is_some() {
            // SAFETY: `getppid` has no preconditions and always succeeds.
            unsafe { libc::getppid() as u32 }
        } else {
            0
        };
        slot_change_pending_with_rescue(
            &self.paths,
            origin.is_trial,
            origin.helper_ppid,
            current_ppid,
            trial_commit_confirmed(),
            self.supervisor_flag(),
            || std::env::current_exe().ok().and_then(|exe| running_slot_for(&self.paths, &exe)),
            || {
                std::env::current_exe()
                    .ok()
                    .is_some_and(|exe| running_is_stable_rescue(&self.paths, &exe))
            },
            sync_ota_dir,
            ensure_supervisor,
        )
    }

    fn slot_change_blocked_read_only(&self) -> bool {
        #[cfg(test)]
        if self.test_slot_change_blocked.load(Ordering::Acquire) {
            return true;
        }
        let origin = trial_origin();
        if origin.is_trial && !trial_commit_confirmed().load(Ordering::Acquire) {
            return true;
        }
        if !self.supervisor_flag().load(Ordering::Acquire) {
            return true;
        }
        if self.paths.pending.try_exists().unwrap_or(true) {
            return true;
        }
        same_boot_rollback_blocked_in(&self.paths)
    }

    pub fn start(self: &Arc<Self>) {
        if std::env::var("ZTE_OTA_TRIAL").as_deref() == Ok("1") {
            let manager = Arc::clone(self);
            crate::system::spawn_named("ota-trial-state", move || {
                std::thread::sleep(Duration::from_secs(TRIAL_SECONDS));
                let mut last_error: Option<String> = None;
                loop {
                    if finalize_trial_once(
                        &manager,
                        || manager.slot_change_blocked(),
                        ensure_supervisor,
                        &mut last_error,
                    ) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(5));
                }
            });
        } else {
            if !self.supervisor_flag().load(Ordering::Acquire) {
                let manager = Arc::clone(self);
                crate::system::spawn_named("ota-supervisor-repair", move || {
                    let mut last_error: Option<String> = None;
                    loop {
                        if manager.supervisor_flag().load(Ordering::Acquire) {
                            return;
                        }
                        if manager.paths.pending.try_exists().unwrap_or(true)
                            || same_boot_rollback_blocked_in(&manager.paths)
                        {
                            std::thread::sleep(Duration::from_secs(1));
                            continue;
                        }
                        match ensure_supervisor(&manager.paths) {
                            Ok(()) => {
                                manager.supervisor_flag().store(true, Ordering::Release);
                                return;
                            }
                            Err(error) => {
                                let msg = error.to_string();
                                if last_error.as_deref() != Some(msg.as_str()) {
                                    manager.paths.append_log(&format!(
                                        "could not repair update supervisor at startup: {msg}"
                                    ));
                                    last_error = Some(msg);
                                }
                            }
                        }
                        std::thread::sleep(Duration::from_secs(5));
                    }
                });
            }
            // If an older helper spawned this non-trial agent before clearing
            // `pending`, startup reconciliation returned early; retry until
            // `pending` is gone so `Installing`/`RollingBack` cannot stick.
            let needs_reconcile = matches!(
                self.state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .persistent
                    .phase,
                Phase::Installing | Phase::RollingBack
            );
            if needs_reconcile {
                let manager = Arc::clone(self);
                crate::system::spawn_named("ota-recovery-reconcile", move || loop {
                    if reconcile_pending_non_trial_once(&manager, || {
                        manager.paths.pending.try_exists().unwrap_or(true)
                    }) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(2));
                });
            }
        }
        let manager = Arc::clone(self);
        crate::system::spawn_named("ota-check", move || {
            // Give WAN and DNS time to settle after boot.
            std::thread::sleep(Duration::from_secs(90));
            loop {
                if manager.settings().automatic_checks && !manager.slot_change_blocked() {
                    if let Err(error) = manager.check() {
                        eprintln!("[ota] automatic check failed: {error}");
                    }
                }
                std::thread::sleep(CHECK_INTERVAL);
            }
        });
    }

    pub fn status(&self) -> Value {
        let settings = self.settings();
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let active = self.paths.active_slot();
        let trial_in_progress = self.slot_change_blocked_read_only();
        let staged_slot = state
            .persistent
            .staged_slot
            .as_deref()
            .and_then(Slot::parse);
        let rollback_available = self.paths.rollback_available()
            && active.is_some_and(|slot| {
                let other = slot.other();
                staged_slot != Some(other) && !slot_quarantined(&self.paths, other)
            });
        json!({"ok":true,"data":{
            "current":crate::build_info::current(),
            "channel":settings.channel,
            "settings":settings,
            "phase":state.persistent.phase,
            "available":state.persistent.available,
            "staged":state.persistent.staged,
            "staged_slot":state.persistent.staged_slot,
            "last_check":state.persistent.last_check,
            "last_error":state.persistent.last_error,
            "progress":{
                "received":state.bytes_received,
                "total":state.bytes_total,
                "percent":progress_percent(state.bytes_received, state.bytes_total),
            },
            "signing_configured":self.verifier.configured(),
            "bootstrap_ready":self.paths.bootstrap_ready(),
            "rollback_available":rollback_available,
            "active_slot":active.map(Slot::as_str),
            "trial_in_progress":trial_in_progress,
            "automatic_install_supported":false,
            "restart_scope":"agent_only"
        }})
    }

    pub fn settings(&self) -> Settings {
        self.settings
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn update_settings(&self, body: &[u8]) -> Result<(), String> {
        if self.operation.swap(true, Ordering::AcqRel) {
            return Err("another update operation is already running".into());
        }
        let _guard = Operation(&self.operation);
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            channel: Channel,
            automatic_checks: bool,
            automatic_downloads: bool,
        }
        let input: Input =
            serde_json::from_slice(body).map_err(|_| "invalid settings".to_string())?;
        let next = Settings {
            channel: input.channel,
            automatic_checks: input.automatic_checks,
            automatic_downloads: input.automatic_downloads,
            automatic_install: false,
        };
        let channel_changed = {
            let settings = self.settings.lock().unwrap_or_else(|p| p.into_inner());
            settings.channel != next.channel
        };
        if channel_changed {
            let live_trial = self.slot_change_blocked()
                || matches!(
                    self.state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .persistent
                        .phase,
                    Phase::Installing | Phase::RollingBack
                );
            if live_trial {
                return Err(
                    "cannot change update channel while a health trial or slot change is in progress"
                        .into(),
                );
            }
        }
        storage::write_json(&self.paths.settings, &next).map_err(|e| e.to_string())?;
        {
            let mut settings = self.settings.lock().unwrap_or_else(|p| p.into_inner());
            *settings = next;
        }
        if channel_changed {
            self.change(|state| {
                state.persistent.phase = Phase::Idle;
                state.persistent.available = None;
                state.persistent.staged = None;
                state.persistent.staged_slot = None;
                state.persistent.rollback_target = None;
                state.persistent.last_check = None;
                state.persistent.last_error = None;
                state.bytes_received = 0;
                state.bytes_total = 0;
            });
        }
        self.notify();
        Ok(())
    }

    pub fn check(&self) -> Result<(), String> {
        self.check_with(|| self.check_inner())
    }

    fn check_with(
        &self,
        check_fn: impl FnOnce() -> Result<Option<ReleaseManifest>, String>,
    ) -> Result<(), String> {
        // Acquire the exclusive operation guard FIRST before inspecting
        // `slot_change_blocked()` and the live trial phase so a handoff that
        // completes admission concurrently cannot be clobbered by `Checking`/`Failed`.
        if self.operation.swap(true, Ordering::AcqRel) {
            return Err("another update operation is already running".into());
        }
        let _guard = Operation(&self.operation);
        let blocked_at_start = self.slot_change_blocked();
        let previous_trial_phase = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if blocked_at_start
                || matches!(state.persistent.phase, Phase::Installing | Phase::RollingBack)
            {
                Some(state.persistent.phase)
            } else {
                None
            }
        };
        if previous_trial_phase.is_none() {
            self.change(|state| {
                state.persistent.phase = Phase::Checking;
                state.persistent.last_error = None;
            });
        }
        let result = check_fn();
        match result {
            Ok(available) => {
                let auto_download = self.settings().automatic_downloads && available.is_some();
                let blocked = self.slot_change_blocked();
                self.change(|state| {
                    state.persistent.available = available;
                    state.persistent.last_check = Some(unix_now());
                    state.persistent.last_error = None;
                    state.persistent.phase = if let Some(trial_phase) = previous_trial_phase {
                        trial_phase
                    } else if blocked {
                        Phase::Installing
                    } else if state.persistent.staged.is_some() {
                        Phase::Staged
                    } else {
                        Phase::Idle
                    };
                });
                drop(_guard);
                if auto_download && !blocked && !self.slot_change_blocked() {
                    self.download()?;
                }
                Ok(())
            }
            Err(error) => {
                let blocked = self.slot_change_blocked();
                if previous_trial_phase.is_some() || blocked {
                    let preserved = previous_trial_phase.unwrap_or(Phase::Installing);
                    self.change(|state| {
                        state.persistent.phase = preserved;
                        state.persistent.last_error = Some(error.clone());
                    });
                } else {
                    self.fail(&error);
                }
                Err(error)
            }
        }
    }

    fn check_inner(&self) -> Result<Option<ReleaseManifest>, String> {
        if !self.verifier.configured() {
            return Err("this build has no OTA release signing key".into());
        }
        let channel = self.settings().channel;
        let stable = self.fetch_manifest(stable_url())?;
        let beta = if channel == Channel::Beta {
            self.fetch_manifest(beta_url())?
        } else {
            None
        };
        let current = Version::parse(crate::build_info::VERSION)
            .map_err(|_| "current build has an invalid version".to_string())?;
        let blocked = read_blocked_versions(&self.paths)?;
        select_candidate(channel, &current, stable, beta, &blocked)
    }

    fn fetch_manifest(&self, url: &str) -> Result<Option<ReleaseManifest>, String> {
        validate_channel_url(url)?;
        let response = client(HTTP_TIMEOUT)?
            .get(url)
            .send()
            .map_err(|e| format!("release channel request failed: {e}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response = response
            .error_for_status()
            .map_err(|e| format!("release channel request failed: {e}"))?;
        if response
            .content_length()
            .is_some_and(|size| size > MAX_ENVELOPE_BYTES as u64)
        {
            return Err("signed release envelope is too large".into());
        }
        let mut bytes = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or(4096)
                .min(MAX_ENVELOPE_BYTES as u64) as usize,
        );
        response
            .take(MAX_ENVELOPE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("release channel read failed: {e}"))?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err("signed release envelope is too large".into());
        }
        self.verifier
            .verify(&bytes)
            .map(Some)
            .map_err(|e| e.to_string())
    }

    pub fn download(&self) -> Result<(), String> {
        let _guard = self.begin(Phase::Downloading)?;
        let result = self.download_inner();
        if let Err(error) = &result {
            if !self.slot_change_blocked() {
                self.fail(error);
            }
        }
        result
    }

    fn download_inner(&self) -> Result<(), String> {
        if self.slot_change_blocked() {
            return Err("an agent health trial or slot change is in progress".into());
        }
        let manifest = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .persistent
            .available
            .clone()
            .ok_or_else(|| "check for an update first".to_string())?;
        manifest.validate().map_err(|e| e.to_string())?;
        let blocked = read_blocked_versions(&self.paths)?;
        if blocked.iter().any(|item| item == &manifest.version) {
            return Err(format!(
                "release {} is quarantined in blocked.json",
                manifest.version
            ));
        }
        let slot = self.paths.active_slot().unwrap_or(Slot::A).other();
        let available = storage::available_bytes(&self.paths.root).map_err(|e| e.to_string())?;
        if available < manifest.size.saturating_add(REQUIRED_HEADROOM) {
            return Err("not enough free storage for a safe update".into());
        }
        let destination = self.paths.slot_download(slot);
        let metadata_destination = self.paths.slot_meta_download(slot);
        let _cleanup = RemoveFilesOnDrop([destination.clone(), metadata_destination.clone()]);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o700)
            .open(&destination)
            .map_err(|e| e.to_string())?;
        let mut response = client(DOWNLOAD_IDLE_TIMEOUT)?
            .get(&manifest.binary_url)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|e| format!("binary download failed: {e}"))?;
        if response
            .content_length()
            .is_some_and(|size| size != manifest.size)
        {
            return Err("download size does not match the signed manifest".into());
        }
        self.change(|state| {
            state.bytes_received = 0;
            state.bytes_total = manifest.size;
        });
        stream_verified_binary(
            &mut response,
            &mut file,
            manifest.size,
            &manifest.sha256,
            DOWNLOAD_TIMEOUT,
            |received| self.set_progress(received),
        )?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        probe(&destination, &manifest.version)?;
        storage::write_json(&metadata_destination, &manifest).map_err(|e| e.to_string())?;
        if self.slot_change_blocked() {
            return Err("an agent health trial or slot change is in progress".into());
        }
        fs::rename(&destination, self.paths.slot_binary(slot)).map_err(|e| e.to_string())?;
        storage::sync_parent(&self.paths.slot_binary(slot)).map_err(|e| e.to_string())?;
        fs::rename(&metadata_destination, self.paths.slot_meta(slot)).map_err(|e| e.to_string())?;
        storage::sync_parent(&self.paths.slot_meta(slot)).map_err(|e| e.to_string())?;
        self.paths
            .clear_slot_bootstrap_digest(slot)
            .map_err(|e| format!("cannot retire bootstrap digest: {e}"))?;
        self.change(|state| {
            state.persistent.staged = Some(manifest);
            state.persistent.staged_slot = Some(slot.as_str().into());
            state.persistent.phase = Phase::Staged;
            state.persistent.last_error = None;
        });
        Ok(())
    }

    pub fn install(&self) -> Result<(), String> {
        let _guard = self.begin(Phase::Installing)?;
        let result = self.install_inner();
        if let Err(error) = &result {
            if !self.slot_change_blocked() {
                self.fail(error);
            }
        }
        result
    }

    fn install_inner(&self) -> Result<(), String> {
        if self.slot_change_blocked() {
            return Err("an agent health trial is already in progress".into());
        }
        ensure_supervisor(&self.paths)
            .map_err(|error| format!("update supervisor is not repairable: {error}"))?;
        if !self.paths.bootstrap_ready() {
            return Err("OTA bootstrap supervisor is not installed yet".into());
        }
        let (manifest, slot) = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let manifest = state
                .persistent
                .staged
                .clone()
                .ok_or_else(|| "download an update first".to_string())?;
            let slot = state
                .persistent
                .staged_slot
                .as_deref()
                .and_then(Slot::parse)
                .ok_or_else(|| "staged update slot is invalid".to_string())?;
            (manifest, slot)
        };
        let previous = self
            .paths
            .active_slot()
            .ok_or_else(|| "active OTA slot is missing".to_string())?;
        if slot == previous {
            return Err("staged update must be in the inactive slot".into());
        }
        verify_staged_slot(&self.paths, slot, &manifest)?;
        verify_active_slot(&self.paths, previous)?;
        let current = std::env::current_exe().map_err(|e| e.to_string())?;
        launch_helper(
            &self.paths,
            &current,
            slot,
            previous,
            &manifest.version,
            std::process::id(),
        )?;
        self.paths.append_log(&format!(
            "installing {} in slot {}",
            manifest.version,
            slot.as_str()
        ));
        crate::system::spawn_named("ota-exit", || {
            std::thread::sleep(Duration::from_millis(1200));
            std::process::exit(0);
        });
        Ok(())
    }

    pub fn rollback(&self) -> Result<(), String> {
        let _guard = self.begin(Phase::RollingBack)?;
        let result = self.rollback_inner();
        if let Err(error) = &result {
            if !self.slot_change_blocked() {
                self.fail(error);
            }
        }
        result
    }

    fn rollback_inner(&self) -> Result<(), String> {
        if self.slot_change_blocked() {
            return Err("an agent health trial is already in progress".into());
        }
        ensure_supervisor(&self.paths)
            .map_err(|error| format!("update supervisor is not repairable: {error}"))?;
        let active = self
            .paths
            .active_slot()
            .ok_or_else(|| "active OTA slot is missing".to_string())?;
        verify_active_slot(&self.paths, active)?;
        let previous = active.other();
        if self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .persistent
            .staged_slot
            .as_deref()
            .and_then(Slot::parse)
            == Some(previous)
        {
            return Err("the inactive slot contains a staged update, not a rollback build".into());
        }
        let version = verify_rollback_slot(&self.paths, previous)?;
        self.change(|state| {
            state.persistent.rollback_target = Some(previous.as_str().into());
        });
        let current = std::env::current_exe().map_err(|e| e.to_string())?;
        launch_helper(
            &self.paths,
            &current,
            previous,
            active,
            &version,
            std::process::id(),
        )?;
        crate::system::spawn_named("ota-exit", || {
            std::thread::sleep(Duration::from_millis(1200));
            std::process::exit(0);
        });
        Ok(())
    }

    fn begin(&self, phase: Phase) -> Result<Operation<'_>, String> {
        if self.operation.swap(true, Ordering::AcqRel) {
            return Err("another update operation is already running".into());
        }
        let guard = Operation(&self.operation);
        // Check slot-change eligibility UNDER `self.operation` BEFORE writing
        // the new phase so a racing download or duplicate install/rollback
        // during the 1.2s exit delay can never clobber `Installing`/`RollingBack`.
        let live_trial = self.slot_change_blocked()
            || matches!(
                self.state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .persistent
                    .phase,
                Phase::Installing | Phase::RollingBack
            );
        if live_trial {
            return Err("an agent health trial or slot change is in progress".into());
        }
        self.change(|state| {
            state.persistent.phase = phase;
            state.persistent.rollback_target = None;
            state.persistent.last_error = None;
        });
        Ok(guard)
    }

    fn fail(&self, error: &str) {
        self.change(|state| {
            state.persistent.phase = Phase::Failed;
            state.persistent.rollback_target = None;
            state.persistent.last_error = Some(error.into());
        });
    }

    fn change(&self, change: impl FnOnce(&mut RuntimeState)) {
        self.change_if(|state| {
            change(state);
            true
        });
    }

    fn change_if(&self, change: impl FnOnce(&mut RuntimeState) -> bool) {
        let persistent = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if !change(&mut state) {
                return;
            }
            state.persistent.clone()
        };
        if let Err(error) = storage::write_json(&self.paths.state, &persistent) {
            eprintln!("[ota] cannot save state: {error}");
        }
        self.notify();
    }

    /// Download byte counts are live-only state. Publishing them must not rewrite
    /// the persistent OTA journal for every network chunk.
    fn set_progress(&self, received: u64) {
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.bytes_received = received.min(state.bytes_total);
        }
        self.notify();
    }

    fn notify(&self) {
        if let Some(dashboard) = self.dashboard.upgrade() {
            dashboard.request_refresh();
        }
    }
}

fn progress_percent(received: u64, total: u64) -> u8 {
    if total == 0 {
        return 0;
    }
    ((u128::from(received.min(total)) * 100) / u128::from(total)) as u8
}

struct RemoveFilesOnDrop([PathBuf; 2]);

impl Drop for RemoveFilesOnDrop {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

fn ensure_supervisor(paths: &Paths) -> std::io::Result<()> {
    ensure_supervisor_with(paths, storage::sync_parent)
}

fn ensure_supervisor_with(
    paths: &Paths,
    sync_parent: impl FnOnce(&Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let current = fs::read(&paths.supervisor).ok();
    let executable = fs::metadata(&paths.supervisor)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false);
    if current.as_deref() == Some(SUPERVISOR_SCRIPT) && executable {
        // Always sync the supervisor file and its parent directory even when
        // VFS bytes and mode already match, so a previous rename whose parent
        // sync failed cannot be misreported as durable on retry or restart.
        fs::File::open(&paths.supervisor)?.sync_all()?;
        return sync_parent(&paths.supervisor);
    }
    storage::atomic_write_preserving_parent_with(
        &paths.supervisor,
        SUPERVISOR_SCRIPT,
        0o755,
        sync_parent,
    )
}

fn finalize_trial_once(
    manager: &OtaManager,
    mut is_pending: impl FnMut() -> bool,
    mut repair_supervisor: impl FnMut(&Paths) -> std::io::Result<()>,
    last_error: &mut Option<String>,
) -> bool {
    if is_pending() {
        return false;
    }
    if let Err(error) = repair_supervisor(&manager.paths) {
        let msg = error.to_string();
        if last_error.as_deref() != Some(msg.as_str()) {
            manager
                .paths
                .append_log(&format!("could not repair update supervisor: {msg}"));
            *last_error = Some(msg);
        }
        return false;
    }
    // Serialize with active OTA operations (`check`, `download`, `install`,
    // `rollback`, `update_settings`) so delayed finalization never races a
    // newer operation; retry on the next tick while an operation holds the lock.
    if manager.operation.swap(true, Ordering::AcqRel) {
        return false;
    }
    let _op = Operation(&manager.operation);
    // Re-check pending/blocked state UNDER the operation guard so a subsequent
    // install/rollback that wrote `pending` and released `operation` during its
    // 1.2s exit delay cannot have its `Installing`/`RollingBack` phase rewritten.
    if is_pending() {
        return false;
    }
    let active = manager.paths.active_slot();
    manager.change_if(|state| {
        let trial_phase = matches!(
            state.persistent.phase,
            Phase::Installing | Phase::RollingBack
        );
        let staged_is_active_trial = active.is_some()
            && state
                .persistent
                .staged_slot
                .as_deref()
                .and_then(Slot::parse)
                == active;
        if !trial_phase && !staged_is_active_trial {
            // A subsequent check/download after commit confirmation already
            // replaced the completed trial's state; leave it untouched.
            return false;
        }
        let mut changed = false;
        if trial_phase {
            state.persistent.phase = if staged_is_active_trial {
                Phase::Idle
            } else if state.persistent.staged.is_some() {
                Phase::Staged
            } else {
                Phase::Idle
            };
            state.persistent.rollback_target = None;
            state.persistent.last_error = None;
            state.bytes_received = 0;
            state.bytes_total = 0;
            changed = true;
        }
        if staged_is_active_trial {
            if let Some(staged) = &state.persistent.staged {
                if state
                    .persistent
                    .available
                    .as_ref()
                    .is_some_and(|avail| avail.version == staged.version)
                {
                    state.persistent.available = None;
                }
            }
            state.persistent.staged = None;
            state.persistent.staged_slot = None;
            if state.persistent.phase == Phase::Staged {
                state.persistent.phase = Phase::Idle;
            }
            changed = true;
        } else if trial_phase
            && state
                .persistent
                .available
                .as_ref()
                .is_some_and(|avail| avail.version == crate::build_info::VERSION)
        {
            state.persistent.available = None;
        }
        changed
    });
    true
}

fn reconcile_pending_non_trial_once(
    manager: &OtaManager,
    mut is_pending: impl FnMut() -> bool,
) -> bool {
    if is_pending() {
        return false;
    }
    if manager.operation.swap(true, Ordering::AcqRel) {
        return false;
    }
    let _op = Operation(&manager.operation);
    if is_pending() {
        return false;
    }
    let mut reconciled_msg: Option<&'static str> = None;
    manager.change_if(|state| {
        if !matches!(
            state.persistent.phase,
            Phase::Installing | Phase::RollingBack
        ) {
            return false;
        }
        reconciled_msg = reconcile_startup_state(&manager.paths, &mut state.persistent);
        reconciled_msg.is_some()
    });
    if let Some(msg) = reconciled_msg {
        manager.paths.append_log(msg);
    }
    true
}

fn stream_verified_binary(
    reader: &mut impl Read,
    writer: &mut impl Write,
    expected_size: u64,
    expected_sha256: &str,
    total_timeout: Duration,
    mut progress: impl FnMut(u64),
) -> Result<(), String> {
    let started = Instant::now();
    let mut digest = Sha256::new();
    let mut received = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        if started.elapsed() >= total_timeout {
            return Err("binary download exceeded the total time limit".into());
        }
        let count = reader.read(&mut buffer).map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut {
                "binary download stalled".to_string()
            } else {
                format!("binary download read failed: {error}")
            }
        })?;
        if started.elapsed() >= total_timeout {
            return Err("binary download exceeded the total time limit".into());
        }
        if count == 0 {
            break;
        }
        received = received.saturating_add(count as u64);
        if received > expected_size || received > MAX_BINARY_BYTES {
            return Err("download exceeded the signed size".into());
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|error| format!("cannot write update download: {error}"))?;
        digest.update(&buffer[..count]);
        progress(received);
    }
    if received != expected_size || expected_sha256 != manifest::hex(&digest.finalize()) {
        return Err("download failed signed size or SHA-256 verification".into());
    }
    Ok(())
}

fn verify_file_integrity(
    path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("update binary is missing: {error}"))?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return Err("update binary size no longer matches the signed manifest".into());
    }
    let mut file =
        fs::File::open(path).map_err(|error| format!("cannot read update binary: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read update binary: {error}"))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if expected_sha256 != manifest::hex(&digest.finalize()) {
        return Err("update binary SHA-256 no longer matches the signed manifest".into());
    }
    Ok(())
}

fn verify_release_binary(path: &Path, manifest: &ReleaseManifest) -> Result<(), String> {
    manifest.validate().map_err(|error| error.to_string())?;
    if !storage::executable(path) {
        return Err("update binary is not executable".into());
    }
    verify_file_integrity(path, manifest.size, &manifest.sha256)?;
    probe(path, &manifest.version)
}

fn verify_staged_slot(paths: &Paths, slot: Slot, manifest: &ReleaseManifest) -> Result<(), String> {
    let blocked = read_blocked_versions(paths)?;
    if blocked.iter().any(|item| item == &manifest.version) {
        return Err(format!(
            "staged update version {} is quarantined in blocked.json",
            manifest.version
        ));
    }
    let stored = storage::read_json::<ReleaseManifest>(&paths.slot_meta(slot))
        .ok_or_else(|| "staged update metadata is missing or corrupted".to_string())?;
    if stored != *manifest {
        return Err("staged update metadata changed after download".into());
    }
    verify_release_binary(&paths.slot_binary(slot), manifest)
        .map_err(|error| format!("staged update failed preflight verification: {error}"))
}

fn read_blocked_versions(paths: &Paths) -> Result<Vec<String>, String> {
    if !storage::entry_exists(&paths.blocked).map_err(|error| {
        format!(
            "cannot inspect quarantine list {}: {error}",
            paths.blocked.display()
        )
    })? {
        return Ok(Vec::new());
    }
    let bytes = storage::read_regular_bounded(&paths.blocked, storage::MAX_JSON_BYTES)
        .map_err(|error| {
            format!(
                "cannot read quarantine list {}: {error}",
                paths.blocked.display()
            )
        })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "quarantine list {} is malformed: {error}",
            paths.blocked.display()
        )
    })
}

fn verify_stable_rescue(paths: &Paths) -> Result<ReleaseManifest, String> {
    let stable = paths.stable_binary();
    let manifest = storage::read_json::<ReleaseManifest>(&paths.stable_meta())
        .ok_or_else(|| "Stable rescue metadata is missing or corrupted".to_string())?;
    if manifest.channel != Channel::Stable {
        return Err(format!(
            "Stable rescue metadata channel {:?} is not stable",
            manifest.channel
        ));
    }
    let blocked = read_blocked_versions(paths)?;
    if blocked.iter().any(|item| item == &manifest.version) {
        return Err(format!(
            "Stable rescue version {} is quarantined in blocked.json",
            manifest.version
        ));
    }
    verify_release_binary(&stable, &manifest)
        .map_err(|error| format!("Stable rescue agent is not safe: {error}"))?;
    Ok(manifest)
}

fn verify_active_slot(paths: &Paths, slot: Slot) -> Result<(), String> {
    // Require positive digest metadata (`release.json` or `bootstrap.sha256`)
    // on the active slot so preflight always matches both `verify_recovery_slot`
    // in Rust `recover()` and `verified_slot_integrity` in the shell launcher.
    verify_recovery_slot(paths, slot).map_err(|error| {
        format!("active rollback slot failed preflight verification: {error}")
    })
}

/// Positive digest verification required for pending rollback recovery: unlike
/// legacy executable-only slots, refuses probe-only executables lacking both
/// signed `release.json` and `bootstrap.sha256` so an unverified slot can never
/// displace a verified Stable rescue.
fn verify_recovery_slot(paths: &Paths, slot: Slot) -> Result<(), String> {
    let binary = paths.slot_binary(slot);
    let meta_path = paths.slot_meta(slot);
    if storage::entry_exists(&meta_path).unwrap_or(true) {
        let manifest = storage::read_json::<ReleaseManifest>(&meta_path)
            .ok_or_else(|| "rollback slot metadata is unreadable or corrupted".to_string())?;
        if manifest.version != crate::build_info::VERSION {
            return Err("rollback slot metadata does not match the running agent".into());
        }
        let blocked = read_blocked_versions(paths)?;
        if blocked.iter().any(|item| item == &manifest.version) {
            return Err(format!(
                "rollback slot version {} is quarantined in blocked.json",
                manifest.version
            ));
        }
        return verify_release_binary(&binary, &manifest)
            .map_err(|error| format!("rollback slot failed digest verification: {error}"));
    }
    if storage::entry_exists(&paths.slot_bootstrap_digest(slot)).unwrap_or(true) {
        let version = verify_bootstrap_slot(paths, slot, Some(crate::build_info::VERSION))
            .map_err(|error| format!("rollback bootstrap slot failed digest verification: {error}"))?;
        let blocked = read_blocked_versions(paths)?;
        if blocked.iter().any(|item| item == &version) {
            return Err(format!(
                "rollback bootstrap slot version {version} is quarantined in blocked.json"
            ));
        }
        return Ok(());
    }
    Err("rollback slot has neither release metadata nor bootstrap digest".into())
}

fn parse_bootstrap_identity(path: &Path) -> Result<(String, String), String> {
    let bytes = storage::read_regular_bounded(path, 4096)
        .map_err(|error| format!("bootstrap digest is unreadable: {error}"))?;
    if bytes.contains(&0) {
        return Err("bootstrap identity contains NUL bytes".into());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "bootstrap identity is not valid UTF-8".to_string())?;
    let trimmed = text.strip_suffix('\n').unwrap_or(text);
    let mut lines = trimmed.split('\n');
    let sha256 = lines.next().unwrap_or_default();
    let version = lines.next().unwrap_or_default();
    if lines.next().is_some()
        || sha256.len() != 64
        || !sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || version.is_empty()
        || version.bytes().any(|b| {
            !matches!(
                b,
                b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' | b'.' | b'+' | b'-'
            )
        })
        || Version::parse(version).is_err()
    {
        return Err("bootstrap identity is malformed".into());
    }
    Ok((sha256.to_owned(), version.to_owned()))
}

fn read_bootstrap_version(paths: &Paths, slot: Slot) -> Result<Option<String>, String> {
    let path = paths.slot_bootstrap_digest(slot);
    match storage::entry_exists(&path) {
        Ok(false) => return Ok(None),
        Err(error) => return Err(format!("inspect bootstrap digest {}: {error}", path.display())),
        Ok(true) => {}
    }
    parse_bootstrap_identity(&path).map(|(_, version)| Some(version))
}

fn slot_quarantined(paths: &Paths, slot: Slot) -> bool {
    let meta_path = paths.slot_meta(slot);
    match storage::entry_exists(&meta_path) {
        Ok(true) => {
            let Some(manifest) = storage::read_json::<ReleaseManifest>(&meta_path) else {
                return true;
            };
            if manifest.validate().is_err() {
                return true;
            }
            return match read_blocked_versions(paths) {
                Ok(blocked) => blocked.iter().any(|item| item == &manifest.version),
                Err(_) => true,
            };
        }
        Err(_) => return true,
        Ok(false) => {}
    }
    match read_bootstrap_version(paths, slot) {
        Ok(Some(version)) => match read_blocked_versions(paths) {
            Ok(blocked) => blocked.iter().any(|item| item == &version),
            Err(_) => true,
        },
        Ok(None) => false,
        Err(_) => true,
    }
}

fn verify_rollback_slot(paths: &Paths, slot: Slot) -> Result<String, String> {
    let binary = paths.slot_binary(slot);
    let meta_path = paths.slot_meta(slot);
    if storage::entry_exists(&meta_path).unwrap_or(true) {
        let manifest = storage::read_json::<ReleaseManifest>(&meta_path)
            .ok_or_else(|| "rollback slot metadata is unreadable or corrupted".to_string())?;
        let blocked = read_blocked_versions(paths)?;
        if blocked.iter().any(|item| item == &manifest.version) {
            return Err(format!(
                "rollback slot version {} is quarantined in blocked.json",
                manifest.version
            ));
        }
        verify_release_binary(&binary, &manifest)
            .map_err(|error| format!("rollback slot failed preflight verification: {error}"))?;
        return Ok(manifest.version);
    }
    if storage::entry_exists(&paths.slot_bootstrap_digest(slot)).unwrap_or(true) {
        let version = verify_bootstrap_slot(paths, slot, None)
            .map_err(|error| format!("rollback bootstrap slot failed preflight: {error}"))?;
        let blocked = read_blocked_versions(paths)?;
        if blocked.iter().any(|item| item == &version) {
            return Err(format!(
                "rollback bootstrap slot version {version} is quarantined in blocked.json"
            ));
        }
        return Ok(version);
    }
    if storage::executable(&binary) {
        Ok("bootstrap-slot".into())
    } else {
        Err("no previous agent slot is available".into())
    }
}

fn verify_bootstrap_slot(
    paths: &Paths,
    slot: Slot,
    expected_version: Option<&str>,
) -> Result<String, String> {
    let (sha256, version) = parse_bootstrap_identity(&paths.slot_bootstrap_digest(slot))?;
    if expected_version.is_some_and(|expected| expected != version) {
        return Err("bootstrap identity does not match the running agent".into());
    }
    let binary = paths.slot_binary(slot);
    if !storage::executable(&binary) {
        return Err("bootstrap binary is not executable".into());
    }
    let size = fs::metadata(&binary)
        .map_err(|error| format!("bootstrap binary is missing: {error}"))?
        .len();
    verify_file_integrity(&binary, size, &sha256)?;
    probe(&binary, &version)?;
    Ok(version)
}

fn launch_helper(
    paths: &Paths,
    helper: &Path,
    candidate: Slot,
    previous: Slot,
    version: &str,
    parent: u32,
) -> Result<(), String> {
    paths
        .clear_helper_ready()
        .map_err(|error| format!("cannot clear stale helper handshake: {error}"))?;
    paths
        .write_pending(candidate, previous, version)
        .map_err(|error| error.to_string())?;
    let parent = parent.to_string();
    let result = Command::new(helper)
        .args([
            "ota-helper",
            candidate.as_str(),
            previous.as_str(),
            version,
            &parent,
        ])
        .env_remove("ZTE_OTA_TRIAL")
        .env_remove("ZTE_OTA_PROMOTED")
        .env("ZTE_OTA_SUPERVISOR", &paths.supervisor)
        .env_remove("ZTE_OTA_REAL_SUPERVISOR")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match result {
        Ok(child) => child,
        Err(error) => {
            return clear_failed_launch(paths, format!("cannot start update helper: {error}"))
        }
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if paths.helper_ready.exists() {
            if let Err(error) = paths.clear_helper_ready() {
                let _ = child.kill();
                let _ = child.wait();
                return clear_failed_launch(
                    paths,
                    format!("cannot clear helper handshake: {error}"),
                );
            }
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            return clear_failed_launch(
                paths,
                format!("update helper exited before handoff with {status}"),
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    clear_failed_launch(paths, "update helper did not confirm startup".into())
}

fn clear_failed_launch(paths: &Paths, error: String) -> Result<(), String> {
    let ready_error = paths.clear_helper_ready().err();
    match paths.clear_pending() {
        Ok(()) if ready_error.is_none() => Err(error),
        Ok(()) => Err(format!(
            "{error}; cannot clear helper handshake: {}",
            ready_error.expect("checked")
        )),
        Err(cleanup) => Err(format!("{error}; cannot clear pending marker: {cleanup}")),
    }
}

fn reconcile_startup_state(
    paths: &Paths,
    persistent: &mut PersistentState,
) -> Option<&'static str> {
    // A live helper owns state reconciliation while its pending marker exists.
    // Without that marker, a transient phase survived a process or router
    // restart and must not leave the console permanently stuck in progress.
    if paths.pending.exists() {
        return None;
    }

    let mut message = match persistent.phase {
        Phase::Installing => {
            let candidate = persistent.staged_slot.as_deref().and_then(Slot::parse);
            let completed = candidate.is_some() && candidate == paths.active_slot();
            persistent.phase = Phase::Idle;
            persistent.staged = None;
            persistent.staged_slot = None;
            persistent.rollback_target = None;
            if completed {
                persistent.available = None;
                persistent.last_error = None;
                Some("reconciled a completed update after restart")
            } else {
                persistent.last_error = Some(
                    "the previous update trial was interrupted; the previous agent was restored"
                        .into(),
                );
                Some("recovered an interrupted update trial at startup")
            }
        }
        Phase::RollingBack => {
            let target = persistent
                .rollback_target
                .as_deref()
                .and_then(Slot::parse);
            let completed = target.is_some() && target == paths.active_slot();
            persistent.phase = Phase::Idle;
            persistent.staged = None;
            persistent.staged_slot = None;
            persistent.rollback_target = None;
            if completed {
                persistent.last_error = None;
                Some("reconciled a completed rollback after restart")
            } else {
                persistent.last_error = Some(
                    "the previous rollback trial was interrupted; an active agent was restored"
                        .into(),
                );
                Some("recovered an interrupted rollback trial at startup")
            }
        }
        Phase::Checking | Phase::Downloading => {
            persistent.phase = if persistent.staged.is_some() {
                Phase::Staged
            } else {
                Phase::Idle
            };
            persistent.rollback_target = None;
            persistent.last_error =
                Some("the previous update operation was interrupted; retry the operation".into());
            Some("recovered an interrupted update operation at startup")
        }
        Phase::Idle | Phase::Staged | Phase::Failed => None,
    };
    let blocked = read_blocked_versions(paths);
    if let Some(avail) = &persistent.available {
        let quarantined = match &blocked {
            Ok(list) => list.iter().any(|item| item == &avail.version),
            Err(_) => true,
        };
        if quarantined {
            persistent.available = None;
            if message.is_none() {
                message = Some("cleared quarantined cached update at startup");
            }
        }
    }
    if let Some(staged) = &persistent.staged {
        let quarantined = match &blocked {
            Ok(list) => list.iter().any(|item| item == &staged.version),
            Err(_) => true,
        };
        if quarantined {
            persistent.staged = None;
            persistent.staged_slot = None;
            if persistent.phase == Phase::Staged {
                persistent.phase = Phase::Idle;
            }
            if message.is_none() {
                message = Some("cleared quarantined staged update at startup");
            }
        }
    }
    message
}

fn read_state_for_reconcile(paths: &Paths) -> Result<Option<PersistentState>, String> {
    if !storage::entry_exists(&paths.state)
        .map_err(|error| format!("inspect {}: {error}", paths.state.display()))?
    {
        return Ok(None);
    }
    let bytes = storage::read_regular_bounded(&paths.state, storage::MAX_JSON_BYTES)
        .map_err(|error| format!("read {}: {error}", paths.state.display()))?;
    match serde_json::from_slice::<PersistentState>(&bytes) {
        Ok(state) => Ok(Some(state)),
        Err(_) => Ok(Some(PersistentState::default())),
    }
}

fn reconcile_state_for_promotion(paths: &Paths, candidate: Slot) -> Result<(), String> {
    let Some(mut persistent) = read_state_for_reconcile(paths)? else {
        return Ok(());
    };
    let changed = match persistent.phase {
        Phase::Installing => {
            persistent.phase = Phase::Idle;
            persistent.staged = None;
            persistent.staged_slot = None;
            persistent.rollback_target = None;
            persistent.available = None;
            persistent.last_error = None;
            true
        }
        Phase::RollingBack => {
            persistent.phase = Phase::Idle;
            persistent.staged = None;
            persistent.staged_slot = None;
            persistent.rollback_target = None;
            persistent.last_error = None;
            true
        }
        _ => {
            if persistent.staged_slot.as_deref().and_then(Slot::parse) == Some(candidate) {
                persistent.staged = None;
                persistent.staged_slot = None;
                persistent.rollback_target = None;
                if persistent.phase == Phase::Staged {
                    persistent.phase = Phase::Idle;
                }
                true
            } else {
                false
            }
        }
    };
    if changed {
        storage::write_json(&paths.state, &persistent)
            .map_err(|error| format!("persist reconciled promotion state: {error}"))?;
    }
    Ok(())
}

fn reconcile_state_for_recovery(
    paths: &Paths,
    fallback_error: Option<&str>,
) -> Result<(), String> {
    let Some(mut persistent) = read_state_for_reconcile(paths)? else {
        return Ok(());
    };
    let mut changed = match persistent.phase {
        Phase::Installing => {
            persistent.phase = Phase::Idle;
            persistent.staged = None;
            persistent.staged_slot = None;
            persistent.rollback_target = None;
            persistent.last_error = Some(
                fallback_error
                    .unwrap_or(
                        "the previous update trial was interrupted; the previous agent was restored",
                    )
                    .into(),
            );
            true
        }
        Phase::RollingBack => {
            persistent.phase = Phase::Idle;
            persistent.staged = None;
            persistent.staged_slot = None;
            persistent.rollback_target = None;
            persistent.last_error = Some(
                fallback_error
                    .unwrap_or(
                        "the previous rollback trial was interrupted; an active agent was restored",
                    )
                    .into(),
            );
            true
        }
        _ => {
            if let Some(error) = fallback_error {
                persistent.phase = Phase::Idle;
                persistent.staged = None;
                persistent.staged_slot = None;
                persistent.rollback_target = None;
                persistent.last_error = Some(error.into());
                true
            } else {
                false
            }
        }
    };
    let blocked = read_blocked_versions(paths);
    if let Some(avail) = &persistent.available {
        let quarantined = match &blocked {
            Ok(list) => list.iter().any(|item| item == &avail.version),
            Err(_) => true,
        };
        if quarantined {
            persistent.available = None;
            changed = true;
        }
    }
    if let Some(staged) = &persistent.staged {
        let quarantined = match &blocked {
            Ok(list) => list.iter().any(|item| item == &staged.version),
            Err(_) => true,
        };
        if quarantined {
            persistent.staged = None;
            persistent.staged_slot = None;
            if persistent.phase == Phase::Staged {
                persistent.phase = Phase::Idle;
            }
            changed = true;
        }
    }
    if changed {
        storage::write_json(&paths.state, &persistent)
            .map_err(|error| format!("persist reconciled recovery state: {error}"))?;
    }
    Ok(())
}

fn select_candidate(
    channel: Channel,
    current: &Version,
    stable: Option<ReleaseManifest>,
    beta: Option<ReleaseManifest>,
    blocked: &[String],
) -> Result<Option<ReleaseManifest>, String> {
    let candidate = if channel == Channel::Stable {
        let Some(stable) = stable else {
            return Ok(None);
        };
        // Leaving Beta explicitly returns to the newest Stable release, even
        // when it sorts below a later prerelease already installed.
        let version = stable.semver().map_err(|e| e.to_string())?;
        (stable.version != crate::build_info::VERSION
            && !blocked.contains(&stable.version)
            && (version.cmp(current).is_gt() || !current.pre.is_empty()))
        .then_some(stable)
    } else {
        let mut releases: Vec<_> = stable.into_iter().chain(beta).collect();
        releases.sort_by_key(|release| release.semver().ok());
        releases
            .into_iter()
            .filter(|release| !blocked.contains(&release.version))
            .filter(|release| {
                release
                    .semver()
                    .is_ok_and(|version| version.cmp(current).is_gt())
            })
            .next_back()
    };
    if let Some(release) = &candidate {
        if release
            .minimum_updater_semver()
            .map_err(|e| e.to_string())?
            .cmp(current)
            .is_gt()
        {
            return Err(format!(
                "{} requires updater {} or newer",
                release.version, release.minimum_updater_version
            ));
        }
    }
    Ok(candidate)
}

#[derive(Debug)]
struct Operation<'a>(&'a AtomicBool);

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn client(timeout: Duration) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent(concat!("open-u60-ota/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())
}

fn stable_url() -> &'static str {
    option_env!("ZTE_OTA_STABLE_URL").unwrap_or(STABLE_CHANNEL_URL)
}

fn beta_url() -> &'static str {
    option_env!("ZTE_OTA_BETA_URL").unwrap_or(BETA_CHANNEL_URL)
}

fn validate_channel_url(value: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(value).map_err(|_| "invalid release channel URL".to_string())?;
    let production = url.scheme() == "https"
        && url.host_str() == Some("raw.githubusercontent.com")
        && url
            .path()
            .starts_with("/jesther-ai/open-u60-pro/ota-channels/");
    let test = cfg!(test) && matches!(url.host_str(), Some("127.0.0.1" | "localhost"));
    if production || test {
        Ok(())
    } else {
        Err("release channel URL is not trusted".into())
    }
}

fn probe(binary: &Path, expected: &str) -> Result<(), String> {
    let status = Command::new(binary)
        .args(["ota-probe", expected])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("downloaded agent cannot run: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("downloaded agent failed its compatibility probe".into())
    }
}

pub fn probe_cli(expected: Option<&str>) -> i32 {
    if expected == Some(crate::build_info::VERSION)
        && crate::build_info::TARGET == manifest::RELEASE_TARGET
    {
        0
    } else {
        2
    }
}

/// Run by the old binary after the API response is sent. The pending marker
/// makes a power loss fail safe: the shell supervisor boots the previous slot.
pub fn helper_cli(args: &[String]) -> i32 {
    if args.len() != 4 {
        return 2;
    }
    let Some(candidate) = Slot::parse(&args[0]) else {
        return 2;
    };
    let Some(previous) = Slot::parse(&args[1]) else {
        return 2;
    };
    let expected = &args[2];
    let Ok(parent) = args[3].parse::<u32>() else {
        return 2;
    };
    let paths = Paths::system();
    if let Err(error) = paths.write_helper_ready() {
        paths.append_log(&format!("update helper could not confirm startup: {error}"));
        return 7;
    }
    if !wait_for_exit(parent, Duration::from_secs(15)) {
        paths.append_log("update helper timed out waiting for the previous agent");
        if let Err(error) = paths.clear_pending() {
            paths.append_log(&format!("could not clear pending update marker: {error}"));
        }
        let _ = paths.clear_helper_ready();
        return 3;
    }
    let binary = paths.slot_binary(candidate);
    // Pin the exact candidate binary fd, release metadata bytes, and bootstrap
    // digest identity BEFORE launching the trial so an in-flight download from
    // an older rollback candidate cannot swap the promoted slot or last-stable.
    let pinned = match pin_candidate(&paths, candidate, expected) {
        Ok(pinned) => pinned,
        Err(error) => {
            paths.append_log(&format!(
                "candidate {expected} could not be pinned before trial: {error}"
            ));
            return recover(&paths, previous, Some((candidate, expected)), None);
        }
    };
    // Durably record that same-boot rollback must confirm Tailscale cleanup
    // BEFORE the trial candidate can spawn `tailscaled` (even in userspace
    // mode, which leaves no kernel journal).
    if let Err(error) = write_rollback_blocked_marker(&paths) {
        paths.append_log(&format!(
            "cannot persist rollback cleanup guard before trial: {error}"
        ));
        return recover(&paths, previous, None, None);
    }
    let mut child = match Command::new(&binary)
        .env("ZTE_OTA_TRIAL", "1")
        .env_remove("ZTE_OTA_PROMOTED")
        .env("ZTE_AGENT_GUARD", "0")
        .env("ZTE_OTA_SUPERVISOR", &paths.supervisor)
        .env_remove("ZTE_OTA_REAL_SUPERVISOR")
        .stdin(Stdio::null())
        .stdout(log_file(&paths.update_log))
        .stderr(log_file(&paths.update_log))
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            paths.append_log(&format!("candidate {expected} could not start: {error}"));
            return recover(&paths, previous, Some((candidate, expected)), None);
        }
    };
    let address = bind_address();
    if health_trial(&mut child, address) {
        // Stop and reap the trial process BEFORE verifying identity and
        // committing `active = candidate`. Keep `pending` and `rollback-blocked`
        // durably on disk while spawning the fresh promoted process and
        // verifying that THIS specific child owns and answers on its listener,
        // so both the boot supervisor and `guard` continue honoring the handoff
        // on power loss or startup hang. Only AFTER readiness succeeds do we
        // clear `rollback-blocked` then `pending` and refresh `last-stable`.
        let promotion = promote_pinned_trial_with(
            || {
                let _ = child.kill();
                let _ = child.wait();
            },
            || verify_candidate_unmodified(&paths, candidate, &pinned),
            || {
                let _ = fs::remove_file(paths.slot_download(candidate));
                let _ = fs::remove_file(paths.slot_meta_download(candidate));
            },
            || paths.write_active(candidate),
            || paths.point_legacy_link(candidate),
            || reconcile_state_for_promotion(&paths, candidate),
            || {
                let mut cmd = Command::new(&binary);
                configure_handoff_child_env(&mut cmd, &paths);
                cmd.stdin(Stdio::null())
                    .stdout(log_file(&paths.update_log))
                    .stderr(log_file(&paths.update_log))
                    .spawn()
            },
            |promoted| wait_for_child_listener(promoted, address, PROMOTED_STARTUP_TIMEOUT),
            |promoted| {
                let _ = promoted.kill();
                let _ = promoted.wait();
            },
            || paths.clear_pending(),
            || clear_rollback_blocked_marker(&paths),
            || paths.pending.try_exists().unwrap_or(false),
            || paths.write_pending(candidate, previous, expected),
            || {
                if let Err(error) = clear_rollback_attempt_marker(&paths) {
                    paths.append_log(&format!("could not clear rollback-attempt marker: {error}"));
                }
                if let Err(error) = copy_pinned_stable(&paths, &pinned) {
                    paths.append_log(&format!("could not refresh Stable rescue copy: {error}"));
                }
            },
        );
        match promotion {
            Ok(()) => {
                paths.append_log(&format!(
                    "candidate {expected} passed the {TRIAL_SECONDS}s trial"
                ));
                0
            }
            Err(PromotionFailure::SlotModified(error)) => {
                paths.append_log(&format!("candidate {expected} commit aborted: {error}"));
                let _ = paths.write_pending(candidate, previous, expected);
                let _ = fs::remove_file(paths.slot_download(candidate));
                let _ = fs::remove_file(paths.slot_meta_download(candidate));
                if let Err(disarm_err) = disarm_slot_binary(&paths, candidate) {
                    paths.append_log(&format!(
                        "could not disarm modified candidate slot ({disarm_err}); retaining rollback markers"
                    ));
                    return 9;
                }
                recover(&paths, previous, None, None)
            }
            Err(PromotionFailure::PendingRestoreFailed(error)) => {
                // `clear_pending` unlinked `pending` then failed `sync_parent`,
                // AND restoring `pending` failed while the verified promoted
                // child was already live and listening. Do NOT kill the live
                // child or publish an orphaned `rollback-blocked` marker.
                paths.append_log(&format!(
                    "candidate {expected} pending sync and restore failed ({error}); leaving verified promoted agent running"
                ));
                9
            }
            Err(PromotionFailure::CommitIo(error)) => {
                paths.append_log(&format!("candidate {expected} commit failed: {error}"));
                if let Err(restore_err) = restore_handoff_markers_before_recovery(
                    &paths,
                    candidate,
                    previous,
                    expected,
                ) {
                    paths.append_log(&format!(
                        "could not restore handoff markers before recovery ({restore_err}); aborting recovery"
                    ));
                    return 9;
                }
                recover(&paths, previous, None, None)
            }
            Err(PromotionFailure::SpawnFailed(error)) => {
                paths.append_log(&format!(
                    "promoted candidate {expected} could not start or reach listener: {error}"
                ));
                if let Err(restore_err) = restore_handoff_markers_before_recovery(
                    &paths,
                    candidate,
                    previous,
                    expected,
                ) {
                    paths.append_log(&format!(
                        "could not restore handoff markers before recovery ({restore_err}); aborting recovery"
                    ));
                    return 9;
                }
                let summary = format!(
                    "promoted candidate {expected} failed startup verification ({error}); the previous agent was restored"
                );
                recover_with_error(
                    &paths,
                    previous,
                    Some((candidate, expected)),
                    None,
                    Some(&summary),
                )
            }
        }
    } else {
        paths.append_log(&format!("candidate {expected} failed its health trial"));
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(paths.slot_download(candidate));
        let _ = fs::remove_file(paths.slot_meta_download(candidate));
        if slot_changed_from_pinned(&paths, candidate, &pinned) {
            paths.append_log(&format!(
                "failed candidate {expected} slot was modified during trial; disarming without quarantining replacement"
            ));
            if let Err(disarm_err) = disarm_slot_binary(&paths, candidate) {
                paths.append_log(&format!(
                    "could not disarm modified candidate slot ({disarm_err}); retaining rollback markers"
                ));
                return 9;
            }
            return recover(&paths, previous, None, None);
        }
        recover(&paths, previous, Some((candidate, expected)), None)
    }
}

#[derive(Debug)]
enum PromotionFailure {
    SlotModified(String),
    CommitIo(String),
    PendingRestoreFailed(String),
    SpawnFailed(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    size: u64,
    sha256: String,
}

struct PinnedCandidate {
    binary_id: FileIdentity,
    binary_file: fs::File,
    meta: Option<(FileIdentity, Vec<u8>)>,
    bootstrap: Option<FileIdentity>,
    stable_manifest: Option<ReleaseManifest>,
}

const MAX_BOOTSTRAP_DIGEST_BYTES: u64 = 4096;

fn file_identity_from_file(
    mut file: &fs::File,
    max_bytes: Option<u64>,
    capture_bytes: bool,
) -> Result<(FileIdentity, Option<Vec<u8>>), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("stat pinned file: {error}"))?;
    if let Some(limit) = max_bytes {
        if metadata.len() > limit {
            return Err(format!("pinned file exceeds {limit}-byte limit"));
        }
    }
    let mut digest = Sha256::new();
    let mut bytes = capture_bytes.then(Vec::new);
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let count = file
            .read(&mut buf)
            .map_err(|error| format!("read pinned file: {error}"))?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count as u64);
        if let Some(limit) = max_bytes {
            if total > limit {
                return Err(format!("pinned file exceeds {limit}-byte limit"));
            }
        }
        digest.update(&buf[..count]);
        if let Some(out) = bytes.as_mut() {
            out.extend_from_slice(&buf[..count]);
        }
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("rewind pinned file: {error}"))?;
    Ok((
        FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: total,
            sha256: manifest::hex(&digest.finalize()),
        },
        bytes,
    ))
}

fn optional_file_identity(path: &Path, max_bytes: u64) -> Result<Option<FileIdentity>, String> {
    if !storage::entry_exists(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?
    {
        return Ok(None);
    }
    let file = storage::open_regular_nonblocking(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    file_identity_from_file(&file, Some(max_bytes), false).map(|(id, _)| Some(id))
}

fn pin_candidate(
    paths: &Paths,
    candidate: Slot,
    expected: &str,
) -> Result<PinnedCandidate, String> {
    let bin_path = paths.slot_binary(candidate);
    let binary_file = storage::open_regular_nonblocking(&bin_path)
        .map_err(|error| format!("open candidate binary {}: {error}", bin_path.display()))?;
    let (binary_id, _) =
        file_identity_from_file(&binary_file, Some(manifest::MAX_BINARY_BYTES), false)?;
    let meta_path = paths.slot_meta(candidate);
    let meta = if storage::entry_exists(&meta_path)
        .map_err(|error| format!("inspect candidate metadata {}: {error}", meta_path.display()))?
    {
        let file = storage::open_regular_nonblocking(&meta_path)
            .map_err(|error| format!("open candidate metadata {}: {error}", meta_path.display()))?;
        let (id, bytes) =
            file_identity_from_file(&file, Some(storage::MAX_JSON_BYTES as u64), true)?;
        let bytes = bytes.unwrap_or_default();
        Some((id, bytes))
    } else {
        None
    };
    let stable_manifest = if let Some((_, bytes)) = &meta {
        let manifest: ReleaseManifest = serde_json::from_slice(bytes)
            .map_err(|error| format!("candidate metadata is malformed: {error}"))?;
        manifest
            .validate()
            .map_err(|error| format!("candidate metadata failed validation: {error}"))?;
        if !expected.is_empty() && manifest.version != expected {
            return Err(format!(
                "candidate metadata version {} does not match expected {expected}",
                manifest.version
            ));
        }
        if manifest.size != binary_id.size || manifest.sha256 != binary_id.sha256 {
            return Err("candidate binary does not match its pinned release metadata".into());
        }
        (manifest.channel == Channel::Stable).then_some(manifest)
    } else {
        None
    };
    let bootstrap_path = paths.slot_bootstrap_digest(candidate);
    let bootstrap = optional_file_identity(&bootstrap_path, MAX_BOOTSTRAP_DIGEST_BYTES)?;
    if meta.is_none() {
        if bootstrap.is_some() {
            let (boot_sha, boot_ver) = parse_bootstrap_identity(&bootstrap_path)?;
            if boot_sha != binary_id.sha256 {
                return Err("candidate binary does not match pinned bootstrap digest".into());
            }
            if !expected.is_empty() && expected != "bootstrap-slot" && boot_ver != expected {
                return Err(format!(
                    "candidate bootstrap version {boot_ver} does not match expected {expected}"
                ));
            }
        } else if expected != "bootstrap-slot" {
            return Err(
                "candidate slot is missing both release metadata and bootstrap digest".into(),
            );
        }
    }
    Ok(PinnedCandidate {
        binary_id,
        binary_file,
        meta,
        bootstrap,
        stable_manifest,
    })
}

fn slot_changed_from_pinned(paths: &Paths, candidate: Slot, pinned: &PinnedCandidate) -> bool {
    optional_file_identity(&paths.slot_binary(candidate), manifest::MAX_BINARY_BYTES)
        .map(|cur| cur.as_ref() != Some(&pinned.binary_id))
        .unwrap_or(true)
        || optional_file_identity(&paths.slot_meta(candidate), storage::MAX_JSON_BYTES as u64)
            .map(|cur| cur.as_ref() != pinned.meta.as_ref().map(|(id, _)| id))
            .unwrap_or(true)
        || optional_file_identity(&paths.slot_bootstrap_digest(candidate), MAX_BOOTSTRAP_DIGEST_BYTES)
            .map(|cur| cur != pinned.bootstrap)
            .unwrap_or(true)
}

fn verify_candidate_unmodified(
    paths: &Paths,
    candidate: Slot,
    pinned: &PinnedCandidate,
) -> Result<(), String> {
    let bin_path = paths.slot_binary(candidate);
    let file = storage::open_regular_nonblocking(&bin_path)
        .map_err(|error| format!("open candidate binary {}: {error}", bin_path.display()))?;
    let (current_bin, _) =
        file_identity_from_file(&file, Some(manifest::MAX_BINARY_BYTES), false)?;
    if current_bin != pinned.binary_id {
        return Err("candidate binary changed during the health trial".into());
    }
    let current_meta =
        optional_file_identity(&paths.slot_meta(candidate), storage::MAX_JSON_BYTES as u64)?;
    if current_meta.as_ref() != pinned.meta.as_ref().map(|(id, _)| id) {
        return Err("candidate metadata changed during the health trial".into());
    }
    let current_bootstrap =
        optional_file_identity(&paths.slot_bootstrap_digest(candidate), MAX_BOOTSTRAP_DIGEST_BYTES)?;
    if current_bootstrap != pinned.bootstrap {
        return Err("candidate bootstrap digest changed during the health trial".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn promote_pinned_trial_with<C>(
    stop_trial_child: impl FnOnce(),
    verify_unmodified: impl FnOnce() -> Result<(), String>,
    cleanup_downloads: impl FnOnce(),
    write_active: impl FnOnce() -> std::io::Result<()>,
    point_legacy: impl FnOnce() -> std::io::Result<()>,
    reconcile_state: impl FnOnce() -> Result<(), String>,
    spawn_promoted: impl FnOnce() -> std::io::Result<C>,
    verify_promoted_ready: impl FnOnce(&mut C) -> Result<(), String>,
    stop_promoted: impl FnOnce(&mut C),
    clear_pending: impl FnOnce() -> std::io::Result<()>,
    clear_rollback_blocked: impl FnOnce() -> std::io::Result<()>,
    pending_exists: impl FnOnce() -> bool,
    restore_pending: impl FnOnce() -> std::io::Result<()>,
    refresh_stable: impl FnOnce(),
) -> Result<(), PromotionFailure> {
    stop_trial_child();
    verify_unmodified().map_err(PromotionFailure::SlotModified)?;
    cleanup_downloads();
    write_active().map_err(|error| PromotionFailure::CommitIo(error.to_string()))?;
    point_legacy().map_err(|error| PromotionFailure::CommitIo(error.to_string()))?;
    reconcile_state().map_err(PromotionFailure::CommitIo)?;
    // Keep `pending` and `rollback-blocked` on disk until `promoted` is
    // positively verified to own and answer on its listener, so a power loss
    // or guard wakeup during startup never leaves an unready candidate live.
    let mut promoted =
        spawn_promoted().map_err(|error| PromotionFailure::SpawnFailed(error.to_string()))?;
    if let Err(error) = verify_promoted_ready(&mut promoted) {
        stop_promoted(&mut promoted);
        return Err(PromotionFailure::SpawnFailed(error));
    }
    if let Err(error) = clear_handoff_markers_with(clear_rollback_blocked, clear_pending) {
        // If `clear_pending` unlinked `pending` before failing `sync_parent`,
        // restore `pending` BEFORE killing `promoted` so its guard never wakes
        // up to an absent `pending` marker and launches a racing supervisor.
        // If restoring `pending` also fails, leave the already-verified live
        // child running rather than killing it without reclaimable ownership.
        if !pending_exists() {
            if let Err(restore_err) = restore_pending() {
                return Err(PromotionFailure::PendingRestoreFailed(format!(
                    "{error}; restore pending failed: {restore_err}"
                )));
            }
        }
        stop_promoted(&mut promoted);
        return Err(PromotionFailure::CommitIo(error.to_string()));
    }
    refresh_stable();
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn proc_net_tcp_matches(
    table_path: &Path,
    is_v6: bool,
    target_ip: std::net::IpAddr,
    target_port: u16,
    socket_inodes: &std::collections::HashSet<String>,
) -> bool {
    let Ok(text) = fs::read_to_string(table_path) else {
        return false;
    };
    let mut child_exact = false;
    let mut child_wildcard = false;
    let mut other_exact = false;
    let mut other_wildcard = false;
    for line in text.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let Some(_sl) = fields.next() else { continue };
        let Some(local) = fields.next() else { continue };
        let Some(_rem) = fields.next() else { continue };
        let Some(state) = fields.next() else { continue };
        if state != "0A" {
            continue;
        }
        let Some(inode) = fields.nth(5) else { continue };
        let Some((hex_ip, hex_port)) = local.split_once(':') else {
            continue;
        };
        if u16::from_str_radix(hex_port, 16) != Ok(target_port) {
            continue;
        }
        let (is_exact, is_wildcard) = if !is_v6 {
            let std::net::IpAddr::V4(target_v4) = target_ip else {
                continue;
            };
            if hex_ip.len() != 8 {
                continue;
            }
            let Ok(word) = u32::from_str_radix(hex_ip, 16) else {
                continue;
            };
            let bound = std::net::Ipv4Addr::from(word.to_ne_bytes());
            (bound == target_v4, bound.is_unspecified())
        } else {
            let std::net::IpAddr::V6(target_v6) = target_ip else {
                continue;
            };
            if hex_ip.len() != 32 {
                continue;
            }
            let mut bytes = [0u8; 16];
            let mut ok = true;
            for (i, chunk) in hex_ip.as_bytes().chunks_exact(8).enumerate() {
                let Ok(s) = std::str::from_utf8(chunk) else {
                    ok = false;
                    break;
                };
                let Ok(word) = u32::from_str_radix(s, 16) else {
                    ok = false;
                    break;
                };
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_ne_bytes());
            }
            if !ok {
                continue;
            }
            let bound = std::net::Ipv6Addr::from(bytes);
            (bound == target_v6, bound.is_unspecified())
        };
        if !is_exact && !is_wildcard {
            continue;
        }
        let owned = socket_inodes.contains(inode);
        if owned {
            child_exact |= is_exact;
            child_wildcard |= is_wildcard;
        } else {
            other_exact |= is_exact;
            other_wildcard |= is_wildcard;
        }
    }
    (child_exact && !other_exact) || (child_wildcard && !other_exact && !other_wildcard)
}

#[cfg(any(target_os = "linux", test))]
fn proc_pid_listens_on(proc_root: &Path, pid: u32, address: SocketAddr) -> bool {
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let Ok(entries) = fs::read_dir(&fd_dir) else {
        return false;
    };
    let mut inodes = std::collections::HashSet::new();
    for entry in entries.flatten() {
        if let Ok(target) = fs::read_link(entry.path()) {
            if let Some(rest) = target
                .to_str()
                .and_then(|s| s.strip_prefix("socket:["))
                .and_then(|s| s.strip_suffix(']'))
            {
                if !rest.is_empty() {
                    inodes.insert(rest.to_owned());
                }
            }
        }
    }
    if inodes.is_empty() {
        return false;
    }
    let net_dir = proc_root.join(pid.to_string()).join("net");
    if address.is_ipv4() {
        proc_net_tcp_matches(&net_dir.join("tcp"), false, address.ip(), address.port(), &inodes)
    } else {
        proc_net_tcp_matches(&net_dir.join("tcp6"), true, address.ip(), address.port(), &inodes)
    }
}

#[cfg(target_os = "macos")]
fn lsof_output_matches_pid(output: &str, pid: u32, address: SocketAddr) -> bool {
    let expected_type = if address.is_ipv4() { "IPv4" } else { "IPv6" };
    let mut cur_pid: Option<u32> = None;
    let mut cur_type: Option<&str> = None;
    let mut child_exact = false;
    let mut child_wildcard = false;
    let mut other_exact = false;
    let mut other_wildcard = false;
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix('p') {
            cur_pid = rest.parse().ok();
            cur_type = None;
        } else if line.starts_with('f') {
            cur_type = None;
        } else if let Some(rest) = line.strip_prefix('t') {
            cur_type = Some(rest);
        } else if let Some(name) = line.strip_prefix('n') {
            if cur_type != Some(expected_type) {
                continue;
            }
            let Some((raw_host, raw_port)) = name.rsplit_once(':') else {
                continue;
            };
            if raw_port.parse::<u16>() != Ok(address.port()) {
                continue;
            }
            let host = raw_host
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(raw_host);
            let is_wildcard = host == "*"
                || (address.is_ipv4() && host == "0.0.0.0")
                || (address.is_ipv6() && host == "::");
            let is_exact = host.parse::<std::net::IpAddr>().ok() == Some(address.ip());
            if !is_exact && !is_wildcard {
                continue;
            }
            if cur_pid == Some(pid) {
                child_exact |= is_exact;
                child_wildcard |= is_wildcard;
            } else {
                other_exact |= is_exact;
                other_wildcard |= is_wildcard;
            }
        }
    }
    (child_exact && !other_exact) || (child_wildcard && !other_exact && !other_wildcard)
}

fn pid_owns_listener(pid: u32, address: SocketAddr) -> bool {
    #[cfg(target_os = "linux")]
    {
        return proc_pid_listens_on(Path::new("/proc"), pid, address);
    }
    #[cfg(target_os = "macos")]
    {
        let proto = if address.is_ipv4() {
            format!("-i4TCP:{}", address.port())
        } else {
            format!("-i6TCP:{}", address.port())
        };
        let Ok(output) = Command::new("/usr/sbin/lsof")
            .args(["-nP", "-a", &proto, "-sTCP:LISTEN", "-F", "ptn"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        else {
            return false;
        };
        if !output.status.success() {
            return false;
        }
        return lsof_output_matches_pid(&String::from_utf8_lossy(&output.stdout), pid, address);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (pid, address);
        false
    }
}

fn wait_for_child_listener(
    child: &mut Child,
    address: SocketAddr,
    timeout: Duration,
) -> Result<(), String> {
    wait_for_child_listener_with(child, address, timeout, pid_owns_listener)
}

fn wait_for_child_listener_with(
    child: &mut Child,
    address: SocketAddr,
    timeout: Duration,
    mut owns_listener: impl FnMut(u32, SocketAddr) -> bool,
) -> Result<(), String> {
    let pid = child.id();
    let started = Instant::now();
    while started.elapsed() < timeout {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!(
                    "spawned agent exited before reaching listener ({status})"
                ));
            }
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not observe spawned agent: {error}"));
            }
        }
        if owns_listener(pid, address)
            && TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_ok()
        {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!(
                    "spawned agent exited immediately after bind ({status})"
                ));
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("spawned agent did not bind and answer on its listener in time".into())
}

struct RemoveDirOnDrop(Option<PathBuf>);

impl Drop for RemoveDirOnDrop {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

fn copy_pinned_stable(paths: &Paths, pinned: &PinnedCandidate) -> std::io::Result<()> {
    copy_pinned_stable_with(
        paths,
        pinned,
        |path, bytes| storage::atomic_write(path, bytes, 0o600),
        storage::exchange_directories,
    )
}

fn copy_pinned_stable_with(
    paths: &Paths,
    pinned: &PinnedCandidate,
    write_meta: impl FnOnce(&Path, &[u8]) -> std::io::Result<()>,
    exchange_dirs: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let Some(manifest) = &pinned.stable_manifest else {
        return Ok(());
    };
    let Some((_, meta_bytes)) = &pinned.meta else {
        return Ok(());
    };
    manifest
        .validate()
        .map_err(|error| std::io::Error::other(format!("invalid pinned stable manifest: {error}")))?;
    let mut reader = &pinned.binary_file;
    reader.seek(SeekFrom::Start(0))?;
    let (actual_id, _) =
        file_identity_from_file(&pinned.binary_file, Some(manifest::MAX_BINARY_BYTES), false)
            .map_err(std::io::Error::other)?;
    if actual_id != pinned.binary_id
        || manifest.size != actual_id.size
        || manifest.sha256 != actual_id.sha256
    {
        return Err(std::io::Error::other(
            "pinned candidate binary does not match validated stable manifest before copying to last-stable",
        ));
    }

    // Build the entire new Stable rescue pair (binary + release.json) inside a
    // private staging directory first, then publish atomically:
    // - When `last-stable` is missing or empty (e.g. first Stable promotion
    //   after `Paths::prepare()`), a single POSIX `rename(2)` replaces the
    //   empty directory atomically even without `RENAME_EXCHANGE`.
    // - When `last-stable` already holds a rescue pair, require atomic
    //   directory exchange (`exchange_directories`) so unsupported filesystems
    //   keep the existing valid pair untouched rather than risking a mixed pair.
    let staging_dir = paths
        .root
        .join(format!(".last-stable.next.{}", std::process::id()));
    let _ = fs::remove_dir_all(&staging_dir);
    fs::create_dir_all(&staging_dir)?;
    fs::set_permissions(&staging_dir, fs::Permissions::from_mode(0o700))?;
    let mut staging_guard = RemoveDirOnDrop(Some(staging_dir.clone()));

    let staged_bin = staging_dir.join("zte-agent");
    let staged_meta = staging_dir.join("release.json");
    storage::atomic_copy_reader(&mut reader, &staged_bin, 0o755)?;
    write_meta(&staged_meta, meta_bytes)?;
    fs::File::open(&staging_dir)?.sync_all()?;

    let stable_dir = paths.stable_dir();
    let stable_empty = match fs::read_dir(&stable_dir) {
        Ok(mut entries) => entries.next().is_none(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(error),
    };
    if stable_empty {
        fs::rename(&staging_dir, &stable_dir)?;
        staging_guard.0 = None;
        return fs::File::open(&paths.root)?.sync_all();
    }

    exchange_dirs(&staging_dir, &stable_dir)?;
    fs::File::open(&paths.root)?.sync_all()?;
    // `staging_dir` now holds the previous generation; drop guard removes it.
    Ok(())
}

fn health_trial(child: &mut Child, address: SocketAddr) -> bool {
    let pid = child.id();
    let started = Instant::now();
    let mut consecutive = 0u8;
    while started.elapsed() < Duration::from_secs(TRIAL_SECONDS) {
        if child.try_wait().ok().flatten().is_some() {
            return false;
        }
        if pid_owns_listener(pid, address)
            && TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_ok()
        {
            consecutive = consecutive.saturating_add(1);
        } else {
            consecutive = 0;
        }
        // Require the listener to remain reachable, then keep observing the
        // process for the full trial to catch delayed startup crashes.
        std::thread::sleep(Duration::from_secs(if consecutive >= 3 { 5 } else { 1 }));
    }
    consecutive >= 3 && child.try_wait().ok().flatten().is_none()
}

#[cfg(test)]
fn commit_trial_with(
    write_active: impl FnOnce() -> std::io::Result<()>,
    point_legacy: impl FnOnce() -> std::io::Result<()>,
    clear_pending: impl FnOnce() -> std::io::Result<()>,
    clear_rollback_blocked: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    write_active()?;
    point_legacy()?;
    clear_pending()?;
    // Only remove `rollback-blocked` after `clear_pending()` (including its
    // directory sync) has fully succeeded.
    clear_rollback_blocked()
}

fn verify_rollback_cleanup_with(
    recover_tailscale: impl FnOnce() -> Result<(), String>,
    journal_exists: impl FnOnce() -> Result<bool, String>,
) -> Result<(), String> {
    recover_tailscale()?;
    if journal_exists()? {
        return Err("rollback tailscale journal still present after cleanup".into());
    }
    Ok(())
}

fn write_rollback_blocked_marker_with(paths: &Paths, boot_id: &str) -> Result<(), String> {
    let token = crate::net_tools::valid_boot_token(boot_id.as_bytes())
        .ok_or_else(|| "cannot determine a valid kernel boot ID for rollback guard".to_string())?;
    let body = format!("{token}\n");
    storage::atomic_write(&paths.root.join("rollback-blocked"), body.as_bytes(), 0o600)
        .map_err(|error| error.to_string())
}

fn write_rollback_blocked_marker(paths: &Paths) -> Result<(), String> {
    write_rollback_blocked_marker_with(paths, &crate::net_tools::boot_id())
}

fn clear_rollback_blocked_marker(paths: &Paths) -> std::io::Result<()> {
    let marker = paths.root.join("rollback-blocked");
    match fs::remove_file(&marker) {
        Ok(()) => storage::sync_parent(&marker),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn clear_rollback_attempt_marker(paths: &Paths) -> std::io::Result<()> {
    let marker = paths.rollback_attempt();
    match fs::remove_file(&marker) {
        Ok(()) => storage::sync_parent(&marker),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Called once the main HTTP listener is bound and its Tokio runtime is ready.
/// Clears any `rollback-attempt` marker left by the boot supervisor during a
/// pending-rollback launch so future restarts know this slot started cleanly.
pub(crate) fn confirm_boot_ready() {
    if std::env::var_os("ZTE_OTA_TRIAL").as_deref() == Some(std::ffi::OsStr::new("1")) {
        return;
    }
    let paths = Paths::system();
    if paths.pending.try_exists().unwrap_or(true) {
        return;
    }
    if let Err(error) = clear_rollback_attempt_marker(&paths) {
        paths.append_log(&format!("could not clear rollback-attempt marker: {error}"));
    }
}

fn configure_handoff_child_env(command: &mut Command, paths: &Paths) {
    // Do NOT pass `ZTE_OTA_TRIAL=1` to a promoted or recovered replacement:
    // legacy `965ebfe` binaries treat `ZTE_OTA_TRIAL=1` as an active trial and
    // run their 60s `ota-trial-state` finalizer (unconditionally wiping
    // `state.json`) while also leaking `ZTE_OTA_TRIAL=1` into their guard and
    // subsequent helper spawns. Instead, direct legacy startup
    // `ensure_supervisor()` writes to a private shadow path inside `paths.root`
    // while carrying the real supervisor path in `ZTE_OTA_REAL_SUPERVISOR` for
    // new binaries, guards, and the boot supervisor.
    command
        .env_remove("ZTE_OTA_TRIAL")
        .env_remove("ZTE_OTA_PROMOTED")
        .env_remove("ZTE_AGENT_GUARD")
        .env("ZTE_OTA_SUPERVISOR", paths.legacy_supervisor_shadow())
        .env("ZTE_OTA_REAL_SUPERVISOR", &paths.supervisor);
}

fn restore_handoff_markers_before_recovery_with(
    write_pending: impl FnOnce() -> std::io::Result<()>,
    pending_exists: impl FnOnce() -> bool,
    write_rollback_blocked: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    // Always restore and verify `pending` BEFORE publishing `rollback-blocked`
    // so a crash or I/O error on `write_pending` (e.g. after `clear_pending`
    // unlinked `pending` then failed `sync_parent`) can NEVER leave an orphaned
    // `rollback-blocked` marker (which makes the supervisor exit 8).
    write_pending().map_err(|error| format!("restore pending marker: {error}"))?;
    if !pending_exists() {
        return Err("pending marker missing after restore".into());
    }
    write_rollback_blocked()
        .map_err(|error| format!("restore rollback-blocked marker: {error}"))?;
    Ok(())
}

fn restore_handoff_markers_before_recovery(
    paths: &Paths,
    candidate: Slot,
    previous: Slot,
    expected: &str,
) -> Result<(), String> {
    restore_handoff_markers_before_recovery_with(
        || paths.write_pending(candidate, previous, expected),
        || paths.pending.try_exists().unwrap_or(false),
        || write_rollback_blocked_marker(paths),
    )
}

fn clear_handoff_markers_with(
    clear_rollback_blocked: impl FnOnce() -> std::io::Result<()>,
    clear_pending: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    // Remove and sync `rollback-blocked` BEFORE `pending` so a failure on the
    // second removal leaves `pending` intact as a durable retry marker instead
    // of leaving an orphaned `rollback-blocked` (which causes the supervisor
    // to exit 8 on the next same-boot attempt).
    clear_rollback_blocked()?;
    clear_pending()
}

fn write_recover_pending_marker_with(
    paths: &Paths,
    boot_id: &str,
    owner: &str,
) -> Result<(), String> {
    let token = crate::net_tools::valid_boot_token(boot_id.as_bytes())
        .ok_or_else(|| "cannot determine a valid kernel boot ID for recovery marker".to_string())?;
    let body = format!("{token}\n{owner}\n");
    storage::atomic_write(
        &paths.root.join("network-recover-pending"),
        body.as_bytes(),
        0o600,
    )
    .map_err(|error| error.to_string())
}

fn write_recover_pending_marker(paths: &Paths, owner: &str) -> Result<(), String> {
    write_recover_pending_marker_with(paths, &crate::net_tools::boot_id(), owner)
}

fn clear_recover_pending_marker(paths: &Paths) -> std::io::Result<()> {
    let marker = paths.root.join("network-recover-pending");
    match fs::remove_file(&marker) {
        Ok(()) => storage::sync_parent(&marker),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn run_verified_owned_rollback_cleanup_with(
    paths: &Paths,
    owner: &str,
    cleanup: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    // Persist the cleanup obligation BEFORE invoking cleanup so a partial
    // failure (e.g. `tailscaled` killed before policy-rule verification fails)
    // is never forgotten across restarts even if no trigger file remains.
    write_recover_pending_marker(paths, owner)
        .map_err(|error| format!("persist recovery-pending marker ({owner}): {error}"))?;
    cleanup()?;
    clear_recover_pending_marker(paths)
        .map_err(|error| format!("clear recovery-pending marker ({owner}): {error}"))?;
    Ok(())
}

fn run_verified_rollback_cleanup(perf: &crate::netfx::perf::Perf) -> Result<(), String> {
    struct ReleasePerfOwner<'a>(&'a crate::netfx::perf::Perf);
    impl Drop for ReleasePerfOwner<'_> {
        fn drop(&mut self) {
            self.0.release_owner();
        }
    }

    // Acquire and release the exclusive performance owner flock strictly inside
    // this cleanup scope so any replacement agent spawned afterwards can claim
    // `owner.lock` immediately without racing the helper.
    let _release_perf = ReleasePerfOwner(perf);
    verify_rollback_cleanup_with(
        || {
            crate::tailscale::recover_network()?;
            crate::wifi_relay::restore_cellular_pause()?;
            perf.recover()
        },
        || {
            let journal = Path::new(crate::tailscale::netplane::JOURNAL_PATH);
            let marker = crate::tailscale::netplane::dnat_flush_marker_path(journal);
            let cellular_pause = crate::wifi_relay::cellular_pause_journal_path();
            let perf_journal = perf.journal_path();
            let journal_present = storage::entry_exists(journal)
                .map_err(|e| format!("inspect tailscale journal: {e}"))?;
            let marker_present = storage::entry_exists(&marker)
                .map_err(|e| format!("inspect tailscale clean DNS flush marker: {e}"))?;
            let cellular_present = storage::entry_exists(&cellular_pause)
                .map_err(|e| format!("inspect cellular pause journal: {e}"))?;
            let perf_present = storage::entry_exists(&perf_journal)
                .map_err(|e| format!("inspect performance journal: {e}"))?;
            Ok(journal_present || marker_present || cellular_present || perf_present)
        },
    )
}

fn recover(
    paths: &Paths,
    previous: Slot,
    failed_candidate: Option<(Slot, &str)>,
    child: Option<&mut Child>,
) -> i32 {
    recover_with_error(paths, previous, failed_candidate, child, None)
}

fn recover_with_error(
    paths: &Paths,
    previous: Slot,
    failed_candidate: Option<(Slot, &str)>,
    child: Option<&mut Child>,
    fallback_error: Option<&str>,
) -> i32 {
    let perf = crate::netfx::perf::Perf::router();
    let address = bind_address();
    recover_with_perf_and_hooks(
        paths,
        previous,
        failed_candidate,
        child,
        &perf,
        fallback_error,
        |spawned| wait_for_child_listener(spawned, address, PROMOTED_STARTUP_TIMEOUT),
        clear_rollback_blocked_marker,
        |p| p.clear_pending(),
    )
}

#[cfg(test)]
fn recover_with_perf(
    paths: &Paths,
    previous: Slot,
    failed_candidate: Option<(Slot, &str)>,
    child: Option<&mut Child>,
    perf: &crate::netfx::perf::Perf,
) -> i32 {
    recover_with_perf_and_hooks(
        paths,
        previous,
        failed_candidate,
        child,
        perf,
        None,
        |_| Ok(()),
        clear_rollback_blocked_marker,
        |p| p.clear_pending(),
    )
}

fn restore_pending_before_stop(
    paths: &Paths,
    saved_pending: Option<&[u8]>,
    restore_pending: &mut impl FnMut(&Paths, &[u8]) -> std::io::Result<()>,
) -> Result<(), String> {
    if !storage::entry_exists(&paths.pending).unwrap_or(false) {
        let bytes = saved_pending.ok_or_else(|| {
            "pending marker was unlinked and no backup payload is available".to_string()
        })?;
        restore_pending(paths, bytes).map_err(|error| format!("restore pending marker: {error}"))?;
        if !storage::entry_exists(&paths.pending).unwrap_or(false) {
            return Err("pending marker still missing after restore".into());
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn recover_with_perf_and_hooks(
    paths: &Paths,
    previous: Slot,
    failed_candidate: Option<(Slot, &str)>,
    child: Option<&mut Child>,
    perf: &crate::netfx::perf::Perf,
    fallback_error: Option<&str>,
    verify_child_ready: impl FnMut(&mut Child) -> Result<(), String>,
    clear_rollback_blocked: impl FnMut(&Paths) -> std::io::Result<()>,
    clear_pending: impl FnMut(&Paths) -> std::io::Result<()>,
) -> i32 {
    recover_with_perf_and_restore_hooks(
        paths,
        previous,
        failed_candidate,
        child,
        perf,
        fallback_error,
        verify_child_ready,
        clear_rollback_blocked,
        clear_pending,
        |p, bytes| storage::atomic_write(&p.pending, bytes, 0o600),
    )
}

#[allow(clippy::too_many_arguments)]
fn recover_with_perf_and_restore_hooks(
    paths: &Paths,
    previous: Slot,
    failed_candidate: Option<(Slot, &str)>,
    child: Option<&mut Child>,
    perf: &crate::netfx::perf::Perf,
    fallback_error: Option<&str>,
    mut verify_child_ready: impl FnMut(&mut Child) -> Result<(), String>,
    mut clear_rollback_blocked: impl FnMut(&Paths) -> std::io::Result<()>,
    mut clear_pending: impl FnMut(&Paths) -> std::io::Result<()>,
    mut restore_pending: impl FnMut(&Paths, &[u8]) -> std::io::Result<()>,
) -> i32 {
    if let Some(child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
    let saved_pending = storage::read_regular_bounded(&paths.pending, 4096)
        .ok()
        .or_else(|| {
            failed_candidate.map(|(cand, exp)| {
                format!("{}\n{}\n{exp}\n", cand.as_str(), previous.as_str()).into_bytes()
            })
        });
    if let Err(error) = run_verified_rollback_cleanup(perf) {
        if let Err(marker_error) = write_rollback_blocked_marker(paths) {
            paths.append_log(&format!(
                "rollback cleanup guard write failed: {marker_error}"
            ));
        }
        paths.append_log(&format!(
            "rollback aborted: tailscale data-plane cleanup failed ({error}); retaining pending marker"
        ));
        return 8;
    }
    if let Some((cand_slot, expected)) = failed_candidate {
        if let Err(error) = quarantine_failed_candidate(paths, cand_slot, expected, previous) {
            paths.append_log(&format!(
                "could not quarantine failed candidate ({error}); retaining rollback markers"
            ));
            return 9;
        }
    }
    let previous_error = match verify_recovery_slot(paths, previous) {
        Ok(()) => {
            if let Err(error) = paths.write_active(previous) {
                paths.append_log(&format!(
                    "could not restore active slot marker ({error}); retaining rollback markers"
                ));
                return 9;
            }
            if let Err(error) = paths.point_legacy_link(previous) {
                paths.append_log(&format!("could not restore legacy agent link: {error}"));
            }
            if let Err(error) = reconcile_state_for_recovery(paths, fallback_error) {
                paths.append_log(&format!(
                    "could not persist reconciled recovery state ({error}); retaining rollback markers"
                ));
                return 9;
            }
            let mut prev_cmd = Command::new(paths.slot_binary(previous));
            configure_handoff_child_env(&mut prev_cmd, paths);
            match prev_cmd
                .stdin(Stdio::null())
                .stdout(log_file(&paths.update_log))
                .stderr(log_file(&paths.update_log))
                .spawn()
            {
                Ok(mut prev_child) => match verify_child_ready(&mut prev_child) {
                    Ok(()) => {
                        if let Err(error) = clear_handoff_markers_with(
                            || clear_rollback_blocked(paths),
                            || clear_pending(paths),
                        ) {
                            // Apply promotion's restore-before-stop rule: if
                            // `clear_pending` unlinked `pending` before failing
                            // `sync_parent`, restore `pending` BEFORE killing
                            // `prev_child` so its guard cannot launch a racing
                            // supervisor; if restore fails, leave the verified
                            // child running.
                            if let Err(restore_err) = restore_pending_before_stop(
                                paths,
                                saved_pending.as_deref(),
                                &mut restore_pending,
                            ) {
                                paths.append_log(&format!(
                                    "could not clear or restore pending marker after restoring previous slot ({error}; {restore_err}); leaving verified previous agent running"
                                ));
                                return 9;
                            }
                            let _ = prev_child.kill();
                            let _ = prev_child.wait();
                            if let Err(cleanup_err) = run_verified_rollback_cleanup(perf) {
                                let _ = write_rollback_blocked_marker(paths);
                                paths.append_log(&format!(
                                    "post-previous cleanup failed after clear_pending error ({cleanup_err}); retaining rollback markers"
                                ));
                                return 8;
                            }
                            paths.append_log(&format!(
                                "could not clear rollback handoff markers after restoring previous slot ({error}); retaining markers"
                            ));
                            return 9;
                        }
                        let _ = clear_rollback_attempt_marker(paths);
                        return 4;
                    }
                    Err(error) => {
                        let _ = prev_child.kill();
                        let _ = prev_child.wait();
                        // Re-verify network cleanup after killing the failed
                        // previous-slot child so we can safely clear
                        // `rollback-blocked` before disarming the slot.
                        if let Err(cleanup_err) = run_verified_rollback_cleanup(perf) {
                            let _ = write_rollback_blocked_marker(paths);
                            paths.append_log(&format!(
                                "rollback aborted after failed previous-slot startup: cleanup failed ({cleanup_err}); retaining rollback markers"
                            ));
                            return 8;
                        }
                        format!("rollback agent failed startup verification: {error}")
                    }
                },
                Err(error) => format!("rollback agent could not start: {error}"),
            }
        }
        Err(error) => format!("rollback agent is no longer safe: {error}"),
    };
    paths.append_log(&previous_error);

    let stable = paths.stable_binary();
    if let Err(error) = verify_stable_rescue(paths) {
        paths.append_log(&error);
        return 5;
    }
    // Same-boot network cleanup is verified clean right above. Durably clear
    // `rollback-blocked` BEFORE disarming `previous` (while keeping `pending`
    // on disk!) so a subsequent crash, Stable startup failure, or `clear_pending`
    // failure never strands verified Stable rescue with a disarmed `previous`
    // slot and a live `rollback-blocked` marker (which would make the shell
    // supervisor require `previous network-recover` and exit 8).
    if let Err(error) = clear_rollback_blocked(paths) {
        paths.append_log(&format!(
            "could not clear rollback-blocked before disarming previous slot for rescue ({error}); retaining rollback markers"
        ));
        return 9;
    }
    // Disarm the rejected unverified/unbootable previous slot — and, if we did
    // not already quarantine a failed candidate (e.g. pre-trial guard-write
    // failure), also disarm the other (untried candidate) slot — before
    // entering Stable rescue so even an older `HEAD` supervisor reinstalled by
    // Stable cannot select either A/B slot on the following restart.
    if let Err(error) = disarm_slot_binary(paths, previous) {
        paths.append_log(&format!(
            "could not disarm rejected previous slot before rescue ({error}); retaining rollback markers"
        ));
        return 9;
    }
    if failed_candidate.is_none() {
        if let Err(error) = disarm_slot_binary(paths, previous.other()) {
            paths.append_log(&format!(
                "could not disarm untried candidate slot before rescue ({error}); retaining rollback markers"
            ));
            return 9;
        }
    }
    if let Err(error) = paths.write_rescue() {
        paths.append_log(&format!(
            "could not mark Stable rescue mode ({error}); retaining rollback markers"
        ));
        return 9;
    }
    if let Err(error) = paths.point_legacy_path(&stable) {
        paths.append_log(&format!("could not link the Stable rescue agent: {error}"));
    }
    if let Err(error) = reconcile_state_for_recovery(paths, fallback_error) {
        paths.append_log(&format!(
            "could not persist reconciled rescue state ({error}); retaining rollback markers"
        ));
        return 9;
    }
    let mut stable_cmd = Command::new(&stable);
    configure_handoff_child_env(&mut stable_cmd, paths);
    match stable_cmd
        .stdin(Stdio::null())
        .stdout(log_file(&paths.update_log))
        .stderr(log_file(&paths.update_log))
        .spawn()
    {
        Ok(mut stable_child) => match verify_child_ready(&mut stable_child) {
            Ok(()) => {
                if let Err(error) = clear_pending(paths) {
                    // Apply promotion's restore-before-stop rule: restore
                    // `pending` BEFORE stopping `stable_child` or running
                    // cleanup so `stable_child`'s guard never launches a racing
                    // supervisor concurrently with cleanup. If restore fails,
                    // leave the verified Stable child running and skip cleanup.
                    if let Err(restore_err) = restore_pending_before_stop(
                        paths,
                        saved_pending.as_deref(),
                        &mut restore_pending,
                    ) {
                        paths.append_log(&format!(
                            "could not clear or restore pending marker after starting Stable rescue ({error}; {restore_err}); leaving verified Stable agent running"
                        ));
                        return 9;
                    }
                    let _ = stable_child.kill();
                    let _ = stable_child.wait();
                    if let Err(cleanup_err) = run_verified_owned_rollback_cleanup_with(
                        paths,
                        "stable",
                        || run_verified_rollback_cleanup(perf),
                    ) {
                        paths.append_log(&format!(
                            "post-Stable cleanup failed after clear_pending error ({cleanup_err}); retaining pending"
                        ));
                        return 8;
                    }
                    paths.append_log(&format!(
                        "could not clear pending marker after starting Stable rescue ({error}); retaining pending"
                    ));
                    return 9;
                }
                let _ = clear_rollback_attempt_marker(paths);
                paths.append_log("started the last Stable rescue agent");
                6
            }
            Err(error) => {
                let _ = stable_child.kill();
                let _ = stable_child.wait();
                if let Err(cleanup_err) = run_verified_owned_rollback_cleanup_with(
                    paths,
                    "stable",
                    || run_verified_rollback_cleanup(perf),
                ) {
                    paths.append_log(&format!(
                        "post-Stable cleanup failed after startup verification error ({cleanup_err}); retaining pending"
                    ));
                    return 8;
                }
                paths.append_log(&format!(
                    "Stable rescue agent failed startup verification: {error}"
                ));
                5
            }
        },
        Err(error) => {
            paths.append_log(&format!("Stable rescue agent could not start: {error}"));
            5
        }
    }
}

fn block_version(paths: &Paths, version: &str) -> Result<(), String> {
    let mut blocked = read_blocked_versions(paths)?;
    let canonical = format!("\"{version}\"");
    let raw_has_canonical = storage::read_regular_bounded(&paths.blocked, storage::MAX_JSON_BYTES)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .is_some_and(|text| text.contains(&canonical));
    let mut changed = false;
    if !blocked.iter().any(|item| item == version) {
        blocked.push(version.to_owned());
        changed = true;
    }
    if changed || !raw_has_canonical {
        // Rewrite canonical JSON even when an escaped form (e.g. `2\u002e4.0`)
        // already decoded to `version`, so an older `HEAD` supervisor's literal
        // lookup in `blocked.json` also rejects the quarantined candidate.
        // Keep the serialized list within `storage::MAX_JSON_BYTES` (256 KiB)
        // so the shell boot supervisor can always parse it.
        let serialized = serde_json::to_vec_pretty(&blocked)
            .map_err(|error| format!("encode blocked.json: {error}"))?;
        if serialized.len() > storage::MAX_JSON_BYTES {
            return Err("quarantine list exceeds 256 KiB limit".into());
        }
        storage::atomic_write(&paths.blocked, &serialized, 0o600)
            .map_err(|error| format!("write blocked.json: {error}"))?;
    }
    let readback = read_blocked_versions(paths)?;
    let raw_readback = storage::read_regular_bounded(&paths.blocked, storage::MAX_JSON_BYTES)
        .map_err(|error| format!("read back blocked.json: {error}"))
        .and_then(|bytes| {
            String::from_utf8(bytes)
                .map_err(|error| format!("decode blocked.json readback: {error}"))
        })?;
    if !readback.iter().any(|item| item == version) || !raw_readback.contains(&canonical) {
        return Err("quarantined version missing canonical entry in blocked.json readback".into());
    }
    Ok(())
}

fn disarm_slot_binary(paths: &Paths, slot: Slot) -> Result<(), String> {
    let binary = paths.slot_binary(slot);
    match storage::entry_exists(&binary) {
        Ok(false) => return Ok(()),
        Err(error) => return Err(format!("inspect slot {} binary: {error}", slot.as_str())),
        Ok(true) => {}
    }
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("disarm slot {} binary: {error}", slot.as_str()))?;
    let file = storage::open_regular_nonblocking(&binary).map_err(|error| {
        format!(
            "open disarmed slot {} binary for sync: {error}",
            slot.as_str()
        )
    })?;
    file.sync_all()
        .map_err(|error| format!("sync disarmed slot {} binary: {error}", slot.as_str()))?;
    storage::sync_parent(&binary)
        .map_err(|error| format!("sync slot {} dir after disarm: {error}", slot.as_str()))?;
    if storage::executable(&binary) {
        return Err(format!(
            "slot {} binary remains executable after disarm",
            slot.as_str()
        ));
    }
    Ok(())
}

/// Exclude a failed candidate durably before clearing rollback markers:
/// - Signed release with a valid `ReleaseManifest` (matching shell
///   `parse_release_meta`) and version distinct from `last-stable` and
///   `previous` (reading `previous` from either `release.json` or
///   `bootstrap.sha256`): quarantine its version in `blocked.json` (read back
///   to confirm).
/// - Candidate lacking valid `release.json`, sharing a version with
///   `last-stable`/`previous`, or when `previous`/`last-stable` metadata is
///   damaged/unknown: disarm its executable bit durably without poisoning
///   `blocked.json`.
fn quarantine_failed_candidate(
    paths: &Paths,
    candidate: Slot,
    expected: &str,
    previous: Slot,
) -> Result<(), String> {
    let mut stable_unknown = false;
    let stable_meta_path = paths.stable_meta();
    let stable_ver = if storage::entry_exists(&stable_meta_path).unwrap_or(true) {
        match storage::read_json::<ReleaseManifest>(&stable_meta_path) {
            Some(m) if m.validate().is_ok() => Some(m.version),
            _ => {
                stable_unknown = true;
                None
            }
        }
    } else {
        None
    };
    let mut prev_unknown = false;
    let prev_meta_path = paths.slot_meta(previous);
    let prev_ver = if storage::entry_exists(&prev_meta_path).unwrap_or(true) {
        match storage::read_json::<ReleaseManifest>(&prev_meta_path) {
            Some(m) if m.validate().is_ok() => Some(m.version),
            _ => {
                prev_unknown = true;
                None
            }
        }
    } else if storage::entry_exists(&paths.slot_bootstrap_digest(previous)).unwrap_or(true) {
        match parse_bootstrap_identity(&paths.slot_bootstrap_digest(previous)) {
            Ok((_, v)) => Some(v),
            Err(_) => {
                prev_unknown = true;
                None
            }
        }
    } else {
        None
    };
    if !prev_unknown && !stable_unknown {
        if let Some(cand_manifest) =
            storage::read_json::<ReleaseManifest>(&paths.slot_meta(candidate))
        {
            let ver = cand_manifest.version.as_str();
            // Only attribute the failure to `ver` in `blocked.json` when the
            // candidate metadata passes full `ReleaseManifest::validate()` and
            // matches `expected` (or `expected` is empty). Otherwise disarm the
            // slot instead of poisoning `blocked.json`.
            if cand_manifest.validate().is_ok()
                && (expected.is_empty() || ver == expected)
                && stable_ver.as_deref() != Some(ver)
                && prev_ver.as_deref() != Some(ver)
            {
                return block_version(paths, ver);
            }
        }
    }
    disarm_slot_binary(paths, candidate)
}

fn log_file(path: &Path) -> Stdio {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::null())
}

fn wait_for_exit(pid: u32, timeout: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn bind_address_from(raw: Option<&str>) -> SocketAddr {
    let mut address: SocketAddr = raw
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:9090".parse().expect("static socket address"));
    match address.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => {
            address.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        }
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => {
            address.set_ip(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        }
        _ => {}
    }
    address
}

fn bind_address() -> SocketAddr {
    bind_address_from(std::env::var("ZTE_AGENT_BIND").ok().as_deref())
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn status_api(state: &crate::handlers::AppState) -> (u16, Value) {
    (200, status_with_readiness(state, readiness::STATUS_MAX_AGE))
}

pub(crate) fn dashboard_status(state: &crate::handlers::AppState) -> Value {
    status_with_readiness(state, readiness::STATUS_MAX_AGE)
}

pub fn settings_api(state: &crate::handlers::AppState, body: &[u8]) -> (u16, Value) {
    mutate(state, || state.ota.update_settings(body))
}

pub fn check_api(state: &crate::handlers::AppState) -> (u16, Value) {
    mutate(state, || state.ota.check())
}

pub fn download_api(state: &crate::handlers::AppState) -> (u16, Value) {
    mutate(state, || state.ota.download())
}

struct TrialOrigin {
    is_trial: bool,
    helper_ppid: Option<u32>,
}

fn trial_origin() -> &'static TrialOrigin {
    static ORIGIN: std::sync::OnceLock<TrialOrigin> = std::sync::OnceLock::new();
    ORIGIN.get_or_init(|| {
        let is_trial =
            std::env::var_os("ZTE_OTA_TRIAL").as_deref() == Some(std::ffi::OsStr::new("1"));
        let helper_ppid = if is_trial {
            // SAFETY: `getppid` has no preconditions and always succeeds.
            let ppid = unsafe { libc::getppid() };
            (ppid > 1).then_some(ppid as u32)
        } else {
            None
        };
        TrialOrigin {
            is_trial,
            helper_ppid,
        }
    })
}

pub(crate) fn record_trial_parent() {
    let _ = trial_origin();
}

fn trial_commit_confirmed() -> &'static AtomicBool {
    static CONFIRMED: AtomicBool = AtomicBool::new(false);
    &CONFIRMED
}

fn supervisor_repair_confirmed() -> &'static AtomicBool {
    static CONFIRMED: AtomicBool = AtomicBool::new(false);
    &CONFIRMED
}

fn running_slot_for(paths: &Paths, exe: &Path) -> Option<Slot> {
    let canon_exe = fs::canonicalize(exe).ok();
    for slot in [Slot::A, Slot::B] {
        let slot_bin = paths.slot_binary(slot);
        if exe == slot_bin {
            return Some(slot);
        }
        if let (Some(c_exe), Ok(c_slot)) = (&canon_exe, fs::canonicalize(&slot_bin)) {
            if c_exe == &c_slot {
                return Some(slot);
            }
        }
    }
    None
}

fn running_is_stable_rescue(paths: &Paths, exe: &Path) -> bool {
    let stable_bin = paths.stable_binary();
    if exe == stable_bin {
        return true;
    }
    match (fs::canonicalize(exe).ok(), fs::canonicalize(&stable_bin).ok()) {
        (Some(c_exe), Some(c_stable)) => c_exe == c_stable,
        _ => false,
    }
}

fn active_is_rescue(paths: &Paths) -> bool {
    storage::read_regular_bounded(&paths.active, 64)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .is_some_and(|value| value.trim() == "rescue")
}

fn sync_ota_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

fn same_boot_rollback_blocked_in(paths: &Paths) -> bool {
    let marker = paths.root.join("rollback-blocked");
    match storage::entry_exists(&marker) {
        Ok(false) => return false,
        Err(_) => return true,
        Ok(true) => {}
    }
    let Ok(raw) = storage::read_regular_bounded(&marker, 256) else {
        return true;
    };
    let Some(saved) = crate::net_tools::valid_boot_token(&raw) else {
        return true;
    };
    let current = crate::net_tools::boot_id();
    let Some(cur) = crate::net_tools::valid_boot_token(current.as_bytes()) else {
        return true;
    };
    saved == cur
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn slot_change_pending_with(
    paths: &Paths,
    is_trial: bool,
    helper_ppid: Option<u32>,
    current_ppid: u32,
    trial_confirmed: &AtomicBool,
    supervisor_confirmed: &AtomicBool,
    running_slot: impl FnOnce() -> Option<Slot>,
    sync_dir_fn: impl FnOnce(&Path) -> std::io::Result<()>,
    repair_supervisor: impl FnOnce(&Paths) -> std::io::Result<()>,
) -> bool {
    slot_change_pending_with_rescue(
        paths,
        is_trial,
        helper_ppid,
        current_ppid,
        trial_confirmed,
        supervisor_confirmed,
        running_slot,
        || false,
        sync_dir_fn,
        repair_supervisor,
    )
}

#[allow(clippy::too_many_arguments)]
fn slot_change_pending_with_rescue(
    paths: &Paths,
    is_trial: bool,
    helper_ppid: Option<u32>,
    current_ppid: u32,
    trial_confirmed: &AtomicBool,
    supervisor_confirmed: &AtomicBool,
    running_slot: impl FnOnce() -> Option<Slot>,
    running_is_rescue: impl FnOnce() -> bool,
    sync_dir_fn: impl FnOnce(&Path) -> std::io::Result<()>,
    repair_supervisor: impl FnOnce(&Paths) -> std::io::Result<()>,
) -> bool {
    if paths.pending.try_exists().unwrap_or(true) || same_boot_rollback_blocked_in(paths) {
        return true;
    }
    if is_trial && !trial_confirmed.load(Ordering::Acquire) {
        static CONFIRM_LOCK: Mutex<()> = Mutex::new(());
        let _guard = CONFIRM_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        if !trial_confirmed.load(Ordering::Acquire) {
            // 1. Wait for spawning ota-helper parent to exit.
            if helper_ppid.is_some_and(|ppid| ppid == current_ppid) {
                return true;
            }
            // 2. Both `pending` and same-boot `rollback-blocked` must be absent.
            if paths.pending.try_exists().unwrap_or(true)
                || same_boot_rollback_blocked_in(paths)
            {
                return true;
            }
            // 3. Confirm `active` names THIS running candidate's slot (or `rescue`
            //    when spawned as the Stable rescue binary).
            let slot_opt = running_slot();
            let is_rescue = slot_opt.is_none() && running_is_rescue();
            let active_matches = |p: &Paths| match slot_opt {
                Some(slot) => p.active_slot() == Some(slot),
                None if is_rescue => active_is_rescue(p),
                None => false,
            };
            if !active_matches(paths) {
                return true;
            }
            // 4. Durably sync the OTA directory before opening the gate so an
            //    abnormal legacy helper exit after `unlink(pending)` and before
            //    `sync_parent()` can never leave `pending` resurrectable across
            //    a sudden power loss.
            if sync_dir_fn(&paths.root).is_err() {
                return true;
            }
            if paths.pending.try_exists().unwrap_or(true)
                || same_boot_rollback_blocked_in(paths)
                || !active_matches(paths)
            {
                return true;
            }
            // 5. Ensure the updated boot supervisor is installed and its parent
            //    directory is durably synced before releasing network effects.
            if repair_supervisor(paths).is_err() {
                return true;
            }
            supervisor_confirmed.store(true, Ordering::Release);
            trial_confirmed.store(true, Ordering::Release);
            return false;
        }
    }
    // Ordinary non-trial startup (including a restart after commit before
    // supervisor repair succeeded): keep the gate closed and retry supervisor
    // repair + parent sync before releasing network effects.
    if !supervisor_confirmed.load(Ordering::Acquire) {
        if repair_supervisor(paths).is_err() {
            return true;
        }
        supervisor_confirmed.store(true, Ordering::Release);
    }
    false
}

fn slot_change_pending_in(paths: &Paths) -> bool {
    let origin = trial_origin();
    let current_ppid = if origin.helper_ppid.is_some() {
        // SAFETY: `getppid` has no preconditions and always succeeds.
        unsafe { libc::getppid() as u32 }
    } else {
        0
    };
    let repair = |p: &Paths| {
        #[cfg(test)]
        if p.supervisor == Path::new("/data/local/tmp/zte-agent-supervisor.sh") {
            return Ok(());
        }
        ensure_supervisor(p)
    };
    slot_change_pending_with_rescue(
        paths,
        origin.is_trial,
        origin.helper_ppid,
        current_ppid,
        trial_commit_confirmed(),
        supervisor_repair_confirmed(),
        || std::env::current_exe().ok().and_then(|exe| running_slot_for(paths, &exe)),
        || {
            std::env::current_exe()
                .ok()
                .is_some_and(|exe| running_is_stable_rescue(paths, &exe))
        },
        sync_ota_dir,
        repair,
    )
}

pub(crate) fn slot_change_pending() -> bool {
    slot_change_pending_in(&Paths::system())
}

pub fn install_api(state: &crate::handlers::AppState, body: &[u8]) -> (u16, Value) {
    if !confirmed(body) {
        return (
            400,
            json!({"ok":false,"error":"explicit confirmation required"}),
        );
    }
    if let Some(reason) = restart_busy_reason(state) {
        return (
            409,
            json!({"ok":false,"error":format!("update deferred during {reason}")}),
        );
    }
    let readiness = readiness::read(state, Duration::ZERO);
    if let Some(reason) = readiness.blocking_reason().map(str::to_owned) {
        return (
            409,
            json!({"ok":false,"error":format!("update deferred: {reason}"),"data":{"install_readiness":readiness}}),
        );
    }
    mutate(state, || {
        state.mihomo.before_slot_change(|| {
            state.wifi_relay.before_slot_change(|| {
                state.tailscale.before_slot_change(|| {
                    state.perf.before_slot_change(|| state.ota.install())
                })
            })
        })
    })
}

pub fn rollback_api(state: &crate::handlers::AppState, body: &[u8]) -> (u16, Value) {
    if !confirmed(body) {
        return (
            400,
            json!({"ok":false,"error":"explicit confirmation required"}),
        );
    }
    if let Some(reason) = restart_busy_reason(state) {
        return (
            409,
            json!({"ok":false,"error":format!("rollback deferred during {reason}")}),
        );
    }
    mutate(state, || {
        state.mihomo.before_slot_change(|| {
            state.wifi_relay.before_slot_change(|| {
                state.tailscale.before_slot_change(|| {
                    state.perf.before_slot_change(|| state.ota.rollback())
                })
            })
        })
    })
}

fn mutate(
    state: &crate::handlers::AppState,
    action: impl FnOnce() -> Result<(), String>,
) -> (u16, Value) {
    if !state.auth.has_password() {
        return (403, json!({"ok":false,"error":"agent password required"}));
    }
    match action() {
        Ok(()) => (200, status_with_readiness(state, readiness::STATUS_MAX_AGE)),
        Err(error) => (
            503,
            json!({"ok":false,"error":error,"data":status_with_readiness(state, readiness::STATUS_MAX_AGE)["data"].clone()}),
        ),
    }
}

fn status_with_readiness(state: &crate::handlers::AppState, max_age: Duration) -> Value {
    let mut status = state.ota.status();
    if let Some(data) = status["data"].as_object_mut() {
        data.insert(
            "install_readiness".into(),
            json!(readiness::read(state, max_age)),
        );
    }
    status
}

fn confirmed(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .is_some_and(|value| value["confirm"] == true)
}

fn restart_busy_reason(state: &crate::handlers::AppState) -> Option<&'static str> {
    use std::sync::atomic::Ordering;
    if state.speedtest.is_running() {
        return Some("a speed test");
    }
    if state.tailscale.is_updating() {
        return Some("a Tailscale binary update");
    }
    if state.esim.recently_switched() {
        return Some("an eSIM profile switch");
    }
    if state.call_active.load(Ordering::Relaxed) {
        return Some("a voice call");
    }
    if crate::system::read_battery().is_some_and(|battery| {
        battery.capacity <= 15
            && !matches!(
                battery.status.to_ascii_lowercase().as_str(),
                "charging" | "full"
            )
    }) {
        return Some("a critically low battery");
    }
    let ussd_at = state.ussd_prompt_at.load(Ordering::Relaxed);
    if ussd_at != 0 && unix_now().saturating_sub(ussd_at) < 180 {
        return Some("a USSD session");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;

    #[test]
    fn progress_percentage_is_exact_bounded_and_never_rounds_up() {
        assert_eq!(progress_percent(0, 0), 0);
        assert_eq!(progress_percent(0, 1000), 0);
        assert_eq!(progress_percent(999, 1000), 99);
        assert_eq!(progress_percent(1000, 1000), 100);
        assert_eq!(progress_percent(1001, 1000), 100);
        assert_eq!(progress_percent(u64::MAX - 1, u64::MAX), 99);
    }

    struct TimedOutReader;

    impl Read for TimedOutReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "fixture stalled",
            ))
        }
    }

    struct SlowReader {
        inner: std::io::Cursor<Vec<u8>>,
        delay: Duration,
    }

    impl Read for SlowReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.delay);
            self.inner.read(buffer)
        }
    }

    struct FailedWriter;

    impl Write for FailedWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "fixture storage failure",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn manager(name: &str) -> OtaManager {
        let root =
            std::env::temp_dir().join(format!("u60-ota-manager-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let key = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        OtaManager::test(
            Paths::new(root.clone(), root.join("supervisor"), root.join("legacy")),
            ManifestVerifier::from_key(*key.verifying_key()),
        )
    }

    fn release(channel: Channel, version: &str) -> ReleaseManifest {
        let tag = format!("v{version}");
        ReleaseManifest {
            schema: 1,
            channel,
            version: version.into(),
            tag: tag.clone(),
            commit: "1234567890ab".into(),
            target: manifest::RELEASE_TARGET.into(),
            size: 7_000_000,
            sha256: "a".repeat(64),
            binary_url: format!(
                "https://github.com/jesther-ai/open-u60-pro/releases/download/{tag}/zte-agent"
            ),
            notes_url: format!("https://github.com/jesther-ai/open-u60-pro/releases/tag/{tag}"),
            published_at: "2026-11-02T00:00:00Z".into(),
            minimum_updater_version: "2.4.0-beta.1".into(),
        }
    }

    fn sha256(bytes: &[u8]) -> String {
        manifest::hex(&Sha256::digest(bytes))
    }

    fn release_for_binary(channel: Channel, version: &str, bytes: &[u8]) -> ReleaseManifest {
        let mut manifest = release(channel, version);
        manifest.size = bytes.len() as u64;
        manifest.sha256 = sha256(bytes);
        manifest
    }

    fn pad_script(bytes: impl Into<Vec<u8>>) -> Vec<u8> {
        let mut script = bytes.into();
        if script.len() < 1024 {
            if !script.ends_with(b"\n") {
                script.push(b'\n');
            }
            script.push(b'#');
            script.resize(1024, b'x');
        }
        script
    }

    fn test_agent(version: &str, probe_ok: bool, marker: &str) -> Vec<u8> {
        let mut script = format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then\n  [ {probe_ok} = true ] && {{ [ -z \"${{2:-}}\" ] || [ \"$2\" = \"{version}\" ]; }} && exit 0\n  exit 2\nfi\n[ -z \"${{ZTE_TEST_MARKER:-}}\" ] || printf '%s' '{marker}' > \"$ZTE_TEST_MARKER\"\n#"
        )
        .into_bytes();
        script.resize(1024, b'x');
        script
    }

    fn write_release_agent(paths: &Paths, slot: Slot, manifest: &ReleaseManifest, bytes: &[u8]) {
        fs::write(paths.slot_binary(slot), bytes).unwrap();
        fs::set_permissions(paths.slot_binary(slot), fs::Permissions::from_mode(0o755)).unwrap();
        storage::write_json(&paths.slot_meta(slot), manifest).unwrap();
    }

    fn channel_response(status: &str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let status = status.to_owned();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )
                .unwrap();
        });
        format!("http://{address}/channel.json")
    }

    #[test]
    fn beta_channel_selects_beta_before_the_first_stable_pointer() {
        let current = Version::parse("2.4.0-beta.1").unwrap();
        let candidate = select_candidate(
            Channel::Beta,
            &current,
            None,
            Some(release(Channel::Beta, "2.4.0-beta.2")),
            &[],
        )
        .unwrap()
        .unwrap();

        assert_eq!(candidate.version, "2.4.0-beta.2");
    }

    #[test]
    fn stable_channel_has_no_candidate_before_its_first_pointer() {
        let current = Version::parse("2.4.0-beta.1").unwrap();
        let candidate = select_candidate(Channel::Stable, &current, None, None, &[]).unwrap();

        assert!(candidate.is_none());
    }

    #[test]
    fn missing_channel_pointer_is_not_an_update_failure() {
        let manager = manager("missing-channel");
        let result = manager
            .fetch_manifest(&channel_response("404 Not Found"))
            .unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn channel_server_failure_is_not_treated_as_unpublished() {
        let manager = manager("failed-channel");
        let error = manager
            .fetch_manifest(&channel_response("503 Service Unavailable"))
            .unwrap_err();

        assert!(error.contains("503 Service Unavailable"), "{error}");
    }

    #[test]
    fn interrupted_trial_clears_staging_after_the_supervisor_restores_previous() {
        let manager = manager("interrupted-trial");
        manager.paths.write_active(Slot::B).unwrap();
        let candidate = release(Channel::Beta, "2.4.0-beta.5");
        let mut persistent = PersistentState {
            phase: Phase::Installing,
            available: Some(candidate.clone()),
            staged: Some(candidate),
            staged_slot: Some("a".into()),
            ..PersistentState::default()
        };

        let message = reconcile_startup_state(&manager.paths, &mut persistent);

        assert_eq!(
            message,
            Some("recovered an interrupted update trial at startup")
        );
        assert_eq!(persistent.phase, Phase::Idle);
        assert!(persistent.available.is_some());
        assert!(persistent.staged.is_none());
        assert!(persistent.staged_slot.is_none());
        assert!(persistent
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("previous agent was restored")));
    }

    #[test]
    fn completed_trial_clears_the_installed_candidate_without_an_error() {
        let manager = manager("completed-trial");
        manager.paths.write_active(Slot::A).unwrap();
        let candidate = release(Channel::Beta, "2.4.0-beta.5");
        let mut persistent = PersistentState {
            phase: Phase::Installing,
            available: Some(candidate.clone()),
            staged: Some(candidate),
            staged_slot: Some("a".into()),
            last_error: Some("old error".into()),
            ..PersistentState::default()
        };

        let message = reconcile_startup_state(&manager.paths, &mut persistent);

        assert_eq!(message, Some("reconciled a completed update after restart"));
        assert_eq!(persistent.phase, Phase::Idle);
        assert!(persistent.available.is_none());
        assert!(persistent.staged.is_none());
        assert!(persistent.staged_slot.is_none());
        assert!(persistent.last_error.is_none());
    }

    #[test]
    fn live_trial_is_left_for_the_update_helper_to_reconcile() {
        let manager = manager("live-trial");
        manager.paths.write_active(Slot::B).unwrap();
        manager
            .paths
            .write_pending(Slot::A, Slot::B, "2.4.0-beta.5")
            .unwrap();
        let candidate = release(Channel::Beta, "2.4.0-beta.5");
        let mut persistent = PersistentState {
            phase: Phase::Installing,
            available: Some(candidate.clone()),
            staged: Some(candidate),
            staged_slot: Some("a".into()),
            ..PersistentState::default()
        };

        assert!(reconcile_startup_state(&manager.paths, &mut persistent).is_none());
        assert_eq!(persistent.phase, Phase::Installing);
        assert!(persistent.staged.is_some());
        assert_eq!(persistent.staged_slot.as_deref(), Some("a"));
    }

    #[test]
    fn interrupted_download_returns_to_an_actionable_idle_state() {
        let manager = manager("interrupted-download");
        let mut persistent = PersistentState {
            phase: Phase::Downloading,
            available: Some(release(Channel::Beta, "2.4.0-beta.5")),
            ..PersistentState::default()
        };

        let message = reconcile_startup_state(&manager.paths, &mut persistent);

        assert_eq!(
            message,
            Some("recovered an interrupted update operation at startup")
        );
        assert_eq!(persistent.phase, Phase::Idle);
        assert!(persistent.available.is_some());
        assert!(persistent
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("retry")));
    }

    #[test]
    fn automatic_install_cannot_be_enabled() {
        let manager = manager("settings");
        manager
            .update_settings(
                br#"{"channel":"beta","automatic_checks":false,"automatic_downloads":true}"#,
            )
            .unwrap();
        let settings = manager.settings();
        assert_eq!(settings.channel, Channel::Beta);
        assert!(settings.automatic_downloads);
        assert!(!settings.automatic_install);
    }

    #[test]
    fn switching_channels_discards_the_old_candidate() {
        let manager = manager("channel-switch");
        manager.change(|state| {
            state.persistent.phase = Phase::Staged;
            state.persistent.available = Some(release(Channel::Stable, "2.4.1"));
            state.persistent.staged = Some(release(Channel::Stable, "2.4.1"));
            state.persistent.staged_slot = Some("b".into());
            state.persistent.last_check = Some(1);
            state.bytes_received = 7_000_000;
            state.bytes_total = 7_000_000;
        });

        manager
            .update_settings(
                br#"{"channel":"beta","automatic_checks":true,"automatic_downloads":false}"#,
            )
            .unwrap();

        let state = manager.state.lock().unwrap();
        assert_eq!(state.persistent.phase, Phase::Idle);
        assert!(state.persistent.available.is_none());
        assert!(state.persistent.staged.is_none());
        assert!(state.persistent.staged_slot.is_none());
        assert!(state.persistent.last_check.is_none());
        assert_eq!(state.bytes_received, 0);
        assert_eq!(state.bytes_total, 0);
    }

    #[test]
    fn preference_changes_wait_for_an_update_operation() {
        let manager = manager("settings-operation");
        let _operation = manager.begin(Phase::Checking).unwrap();
        assert_eq!(
            manager
                .update_settings(
                    br#"{"channel":"beta","automatic_checks":true,"automatic_downloads":false}"#,
                )
                .unwrap_err(),
            "another update operation is already running"
        );
    }

    #[test]
    fn a_staged_candidate_is_not_presented_as_a_rollback() {
        let manager = manager("rollback-status");
        manager.paths.write_active(Slot::A).unwrap();
        fs::write(manager.paths.slot_binary(Slot::A), b"active").unwrap();
        fs::write(manager.paths.slot_binary(Slot::B), b"inactive").unwrap();
        for slot in [Slot::A, Slot::B] {
            fs::set_permissions(
                manager.paths.slot_binary(slot),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        manager.change(|state| {
            state.persistent.staged = Some(release(Channel::Stable, "2.4.1"));
            state.persistent.staged_slot = Some("b".into());
        });
        assert_eq!(manager.status()["data"]["rollback_available"], false);

        manager.change(|state| {
            state.persistent.staged = None;
            state.persistent.staged_slot = None;
        });
        assert_eq!(manager.status()["data"]["rollback_available"], true);
    }

    #[test]
    fn overlapping_operations_are_rejected() {
        let manager = manager("operation");
        let _first = manager.begin(Phase::Checking).unwrap();
        assert_eq!(
            manager.begin(Phase::Downloading).unwrap_err(),
            "another update operation is already running"
        );
    }

    #[test]
    fn update_mutations_require_an_agent_password() {
        let state = crate::handlers::AppState::new();
        assert_eq!(
            settings_api(
                &state,
                br#"{"channel":"stable","automatic_checks":true,"automatic_downloads":false}"#
            )
            .0,
            403
        );
        state.auth.set_password("fixture-only");
        assert_eq!(
            settings_api(
                &state,
                br#"{"channel":"stable","automatic_checks":true,"automatic_downloads":false}"#
            )
            .0,
            200
        );
        assert_eq!(install_api(&state, br#"{"confirm":false}"#).0, 400);
    }

    #[test]
    fn verified_stream_accepts_only_the_exact_signed_payload() {
        let bytes = vec![0x5a; 1024];
        let digest = sha256(&bytes);
        let mut output = Vec::new();
        let mut progress = Vec::new();

        stream_verified_binary(
            &mut bytes.as_slice(),
            &mut output,
            bytes.len() as u64,
            &digest,
            Duration::from_secs(1),
            |received| progress.push(received),
        )
        .unwrap();

        assert_eq!(output, bytes);
        assert_eq!(progress.last(), Some(&(bytes.len() as u64)));
    }

    #[test]
    fn verified_stream_rejects_truncated_oversized_and_corrupted_payloads() {
        let signed = vec![0x41; 1024];
        let digest = sha256(&signed);
        for (name, payload) in [
            ("truncated", signed[..1023].to_vec()),
            ("oversized", [signed.clone(), vec![0x41]].concat()),
            ("corrupted", vec![0x42; 1024]),
        ] {
            let error = stream_verified_binary(
                &mut payload.as_slice(),
                &mut Vec::new(),
                signed.len() as u64,
                &digest,
                Duration::from_secs(1),
                |_| {},
            )
            .unwrap_err();
            assert!(
                error.contains("signed size") || error.contains("SHA-256"),
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn verified_stream_stops_on_idle_total_and_storage_failures() {
        let bytes = vec![0x51; 1024];
        let digest = sha256(&bytes);
        let idle_error = stream_verified_binary(
            &mut TimedOutReader,
            &mut Vec::new(),
            bytes.len() as u64,
            &digest,
            Duration::from_secs(1),
            |_| {},
        )
        .unwrap_err();
        assert!(idle_error.contains("stalled"), "{idle_error}");

        let total_error = stream_verified_binary(
            &mut SlowReader {
                inner: std::io::Cursor::new(bytes.clone()),
                delay: Duration::from_millis(10),
            },
            &mut Vec::new(),
            bytes.len() as u64,
            &digest,
            Duration::from_millis(1),
            |_| {},
        )
        .unwrap_err();
        assert!(total_error.contains("total time limit"), "{total_error}");

        let write_error = stream_verified_binary(
            &mut bytes.as_slice(),
            &mut FailedWriter,
            bytes.len() as u64,
            &digest,
            Duration::from_secs(1),
            |_| {},
        )
        .unwrap_err();
        assert!(write_error.contains("cannot write"), "{write_error}");
    }

    #[test]
    fn install_preflight_rejects_a_staged_binary_changed_after_download() {
        let manager = manager("staged-corruption");
        let bytes = test_agent("2.4.0-beta.8", true, "candidate");
        let manifest = release_for_binary(Channel::Beta, "2.4.0-beta.8", &bytes);
        write_release_agent(&manager.paths, Slot::B, &manifest, &bytes);
        verify_staged_slot(&manager.paths, Slot::B, &manifest).unwrap();

        let mut corrupted = bytes;
        *corrupted.last_mut().unwrap() = b'y';
        fs::write(manager.paths.slot_binary(Slot::B), corrupted).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::B),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        let error = verify_staged_slot(&manager.paths, Slot::B, &manifest).unwrap_err();
        assert!(error.contains("SHA-256"), "{error}");
        assert!(!manager.paths.pending.exists());
    }

    #[test]
    fn install_preflight_rejects_changed_staged_metadata() {
        let manager = manager("staged-metadata");
        let bytes = test_agent("2.4.0-beta.8", true, "candidate");
        let expected = release_for_binary(Channel::Beta, "2.4.0-beta.8", &bytes);
        let changed = release_for_binary(Channel::Beta, "2.4.0-beta.9", &bytes);
        write_release_agent(&manager.paths, Slot::B, &changed, &bytes);

        let error = verify_staged_slot(&manager.paths, Slot::B, &expected).unwrap_err();
        assert!(error.contains("metadata changed"), "{error}");
    }

    #[test]
    fn install_preflight_rejects_a_corrupted_bootstrap_fallback() {
        let manager = manager("bootstrap-preflight");
        let original = test_agent(crate::build_info::VERSION, true, "active");
        let mut corrupted = original.clone();
        *corrupted.last_mut().unwrap() = b'y';
        fs::write(manager.paths.slot_binary(Slot::A), corrupted).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::A),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(
            manager.paths.slot_bootstrap_digest(Slot::A),
            format!("{}\n{}\n", sha256(&original), crate::build_info::VERSION),
        )
        .unwrap();

        let error = verify_active_slot(&manager.paths, Slot::A).unwrap_err();
        assert!(error.contains("SHA-256"), "{error}");
    }

    #[test]
    fn helper_launch_failure_clears_the_pending_marker() {
        let manager = manager("helper-launch");
        let error = launch_helper(
            &manager.paths,
            &manager.paths.root.join("missing-helper"),
            Slot::B,
            Slot::A,
            "2.4.0-beta.8",
            std::process::id(),
        )
        .unwrap_err();

        assert!(error.contains("cannot start update helper"), "{error}");
        assert!(!manager.paths.pending.exists());
    }

    #[test]
    fn helper_immediate_exit_clears_the_pending_marker() {
        let manager = manager("helper-exit");
        let error = launch_helper(
            &manager.paths,
            Path::new("/usr/bin/false"),
            Slot::B,
            Slot::A,
            "2.4.0-beta.8",
            std::process::id(),
        )
        .unwrap_err();

        assert!(error.contains("exited before handoff"), "{error}");
        assert!(!manager.paths.pending.exists());
    }

    #[test]
    fn helper_must_confirm_startup_before_the_agent_can_exit() {
        let manager = manager("helper-handshake");
        let helper = manager.paths.root.join("fixture-helper.sh");
        fs::write(
            &helper,
            format!(
                "#!/bin/sh\nprintf 'ready\\n' > '{}'\nsleep 1\n",
                manager.paths.helper_ready.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();

        launch_helper(
            &manager.paths,
            &helper,
            Slot::B,
            Slot::A,
            "2.4.0-beta.8",
            std::process::id(),
        )
        .unwrap();

        assert!(manager.paths.pending.exists());
        assert!(!manager.paths.helper_ready.exists());
        manager.paths.clear_pending().unwrap();
    }

    #[test]
    fn rollback_cleanup_gate_refuses_handoff_on_error_or_surviving_journal() {
        assert!(verify_rollback_cleanup_with(|| Ok(()), || Ok(false)).is_ok());
        assert!(verify_rollback_cleanup_with(|| Err("busy".into()), || Ok(false)).is_err());
        assert!(verify_rollback_cleanup_with(|| Ok(()), || Ok(true)).is_err());
        assert!(verify_rollback_cleanup_with(|| Ok(()), || Err("io error".into())).is_err());
    }

    #[test]
    fn supervisor_refuses_same_boot_rollback_while_current_boot_tailscale_journal_survives() {
        let manager = manager("supervisor-ts-rollback-gate");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let slot_a = test_agent("2.4.0-beta.7", true, "a");
        let slot_b = test_agent("2.4.0-beta.8", true, "b");
        let rel_a = release_for_binary(Channel::Beta, "2.4.0-beta.7", &slot_a);
        let rel_b = release_for_binary(Channel::Beta, "2.4.0-beta.8", &slot_b);
        write_release_agent(&manager.paths, Slot::A, &rel_a, &slot_a);
        write_release_agent(&manager.paths, Slot::B, &rel_b, &slot_b);
        manager.paths.write_active(Slot::A).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.8")
            .unwrap();

        let ts_journal = manager.paths.root.join("tailscale-network.json");
        let boot_id_file = manager.paths.root.join("boot_id");
        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();
        fs::write(&boot_id_file, "boot-uuid-123\n").unwrap();
        // Also exercise JSON whitespace around `"boot"`.
        fs::write(&ts_journal, "{ \"boot\" : \"boot-uuid-123\" , \"undo\" : [] }\n").unwrap();

        // Same-boot journal still present: supervisor must refuse handoff and keep pending.
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(8));
        assert!(manager.paths.pending.exists(), "pending marker must be retained");
        assert_ne!(
            fs::read_to_string(&marker).ok().as_deref(),
            Some("a"),
            "previous slot must not have been launched"
        );
        let _ = fs::remove_file(&marker);

        // Unreadable/missing boot_id must fail closed and refuse rollback handoff.
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", manager.paths.root.join("missing-boot-id"))
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(8));
        assert!(manager.paths.pending.exists());
        let _ = fs::remove_file(&marker);

        // Empty readable PROC_ROOT (like an unmounted /proc) MUST fail closed
        // even with no journal and no rollback-blocked marker.
        fs::remove_file(&ts_journal).unwrap();
        let empty_proc = manager.paths.root.join("empty-proc");
        fs::create_dir_all(&empty_proc).unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &empty_proc)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(8));
        assert!(manager.paths.pending.exists());
        let _ = fs::remove_file(&marker);

        // Even with NO kernel journal and NO rollback-blocked marker, a live
        // tailscaled process in PROC_ROOT must STILL block rollback handoff!
        fs::create_dir_all(fake_proc.join("4242")).unwrap();
        fs::write(fake_proc.join("4242/stat"), "4242 (tailscaled) S 1 1 1 0\n").unwrap();
        fs::write(fake_proc.join("4242/comm"), "tailscaled\n").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(8));
        assert!(manager.paths.pending.exists());
        let _ = fs::remove_file(&marker);

        // With a same-boot rollback-blocked marker and an older candidate that
        // exits 0 without stopping tailscaled, a live tailscaled still blocks.
        let blocked = manager.paths.root.join("rollback-blocked");
        fs::write(&blocked, "boot-uuid-123\n").unwrap();
        let prev_new = pad_script(b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then exit 0; fi\nif [ \"${1:-}\" = network-recover ]; then exit 1; fi\n[ -z \"${ZTE_TEST_MARKER:-}\" ] || printf 'a-daemon' > \"$ZTE_TEST_MARKER\"\n");
        let rel_a_new = release_for_binary(Channel::Beta, "2.4.0-beta.7", &prev_new);
        write_release_agent(&manager.paths, Slot::A, &rel_a_new, &prev_new);
        let legacy_cand = pad_script(b"#!/bin/sh\nexit 0\n");
        let rel_b_legacy = release_for_binary(Channel::Beta, "2.4.0-beta.8", &legacy_cand);
        write_release_agent(&manager.paths, Slot::B, &rel_b_legacy, &legacy_cand);
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(8));
        assert!(manager.paths.pending.exists());
        assert!(blocked.exists());
        assert_ne!(fs::read_to_string(&marker).ok().as_deref(), Some("a-daemon"));
        let _ = fs::remove_file(&marker);

        // Unreadable/missing /proc root also fails closed on rollback-blocked.
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", manager.paths.root.join("missing-proc"))
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(8));
        assert!(manager.paths.pending.exists());
        assert!(blocked.exists());

        // Same-boot rollback-blocked with NO journal and NO live tailscaled
        // (e.g. tailscaled exited via SIGKILL leaving 5210 policy rules, so
        // `network-recover` fails) MUST still invoke previous `network-recover`
        // and refuse handoff (exit 8) if it fails!
        fs::remove_dir_all(fake_proc.join("4242")).unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(8),
            "failed rollback-blocked recovery must refuse handoff even when journal and daemon are absent"
        );
        assert!(manager.paths.pending.exists());
        assert!(blocked.exists());
        assert_ne!(fs::read_to_string(&marker).ok().as_deref(), Some("a-daemon"));
        let _ = fs::remove_file(&marker);

        // Restore live tailscaled fixture for the bootstrap slot recovery check.
        fs::create_dir_all(fake_proc.join("4242")).unwrap();
        fs::write(fake_proc.join("4242/stat"), "4242 (tailscaled) S 1 1 1 0\n").unwrap();
        fs::write(fake_proc.join("4242/comm"), "tailscaled\n").unwrap();

        // A standard `setup.sh` bootstrap slot (no release.json, verified via
        // bootstrap.sha256) MUST be allowed to run `network-recover` and clean
        // up a live tailscaled process so rollback handoff succeeds.
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::A));
        let boot_prev = format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then [ \"${{2:-}}\" = \"2.3.5\" ] && exit 0; exit 2; fi\nif [ \"${{1:-}}\" = network-recover ]; then rm -rf \"{}/4242\"; exit 0; fi\n[ -z \"${{ZTE_TEST_MARKER:-}}\" ] || printf 'a-bootstrap' > \"$ZTE_TEST_MARKER\"\n",
            fake_proc.display()
        )
        .into_bytes();
        fs::write(manager.paths.slot_binary(Slot::A), &boot_prev).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::A),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(
            manager.paths.slot_bootstrap_digest(Slot::A),
            format!("{}\n2.3.5\n", sha256(&boot_prev)),
        )
        .unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success(), "bootstrap slot recovery must succeed");
        assert!(!manager.paths.pending.exists());
        assert!(!blocked.exists());
        assert_eq!(fs::read_to_string(&marker).unwrap(), "a-bootstrap");
        let _ = fs::remove_file(&marker);

        // Second launcher invocation with ONLY a surviving same-boot Clean DNS
        // flush marker (`network.json` already deleted and no live tailscaled):
        // even if an older previous slot predates the marker and exits 0 on
        // `network-recover` without deleting it, the shell rollback guard MUST
        // trigger candidate recovery and refuse handoff (exit 8) while the
        // same-boot flush marker survives!
        let ts_flush_marker = crate::tailscale::netplane::dnat_flush_marker_path(&ts_journal);
        let _ = fs::remove_file(&ts_journal);
        fs::write(&ts_flush_marker, "boot-uuid-123\n").unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.8")
            .unwrap();
        let cand_fail_flush = pad_script(b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then exit 0; fi\nif [ \"${1:-}\" = network-recover ]; then exit 1; fi\nexit 0\n");
        let rel_b_flush_fail = release_for_binary(Channel::Beta, "2.4.0-beta.8", &cand_fail_flush);
        write_release_agent(&manager.paths, Slot::B, &rel_b_flush_fail, &cand_fail_flush);
        let old_prev_ignores_marker = pad_script(b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then exit 0; fi\nif [ \"${1:-}\" = network-recover ]; then exit 0; fi\n[ -z \"${ZTE_TEST_MARKER:-}\" ] || printf 'a-stale-flush' > \"$ZTE_TEST_MARKER\"\n");
        let rel_a_old = release_for_binary(Channel::Beta, "2.4.0-beta.7", &old_prev_ignores_marker);
        write_release_agent(&manager.paths, Slot::A, &rel_a_old, &old_prev_ignores_marker);
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(8),
            "surviving same-boot flush marker without journal must trigger recovery and refuse handoff on failure"
        );
        assert!(manager.paths.pending.exists());
        assert!(ts_flush_marker.exists());
        assert!(!marker.exists());
        // Even with rollback-blocked also set so previous slot returns 0, the
        // surviving flush marker MUST still block handoff (exit 8)!
        fs::write(&blocked, "boot-uuid-123\n").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(8),
            "older previous binary exiting 0 without clearing same-boot flush marker must still be rejected"
        );
        assert!(ts_flush_marker.exists());
        assert!(!marker.exists());

        // Critical pending-trial failure case: BOTH `pending` and same-boot
        // `rollback-blocked` exist, candidate B removes `ts_flush_marker` and
        // exits 1 (e.g. relay recovery failed), while older previous A exits 0.
        // The supervisor MUST NOT let previous A's exit 0 override candidate B's
        // failure or clear `network-recover-pending`; BOTH this invocation AND a
        // second consecutive invocation (without recreating `ts_flush_marker`)
        // MUST exit 8 and keep `network-recover-pending` until B exits 0!
        let pend_recover_pending = manager.paths.root.join("network-recover-pending");
        let pend_recover_calls = manager.paths.root.join("pend-recover-calls");
        let cand_deletes_then_fails = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then exit 0; fi\nif [ \"${{1:-}}\" = network-recover ]; then printf 'f' >> \"{}\"; rm -f \"{}\"; exit 1; fi\nexit 0\n",
            pend_recover_calls.display(),
            ts_flush_marker.display()
        ));
        let rel_b_del_fail =
            release_for_binary(Channel::Beta, "2.4.0-beta.8", &cand_deletes_then_fails);
        write_release_agent(
            &manager.paths,
            Slot::B,
            &rel_b_del_fail,
            &cand_deletes_then_fails,
        );
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(8),
            "invoked candidate failure must not be overridden by older previous slot exiting 0"
        );
        assert!(!ts_flush_marker.exists(), "candidate removed flush marker before exiting 1");
        assert!(pend_recover_pending.exists(), "network-recover-pending must survive failed candidate");
        assert!(manager.paths.pending.exists());
        assert!(blocked.exists());
        assert!(!marker.exists());
        assert_eq!(fs::read_to_string(&pend_recover_calls).unwrap(), "f");

        // Second consecutive invocation without recreating `ts_flush_marker`:
        // `network-recover-pending` MUST still re-invoke candidate B and exit 8!
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(8));
        assert!(pend_recover_pending.exists());
        assert!(manager.paths.pending.exists());
        assert!(blocked.exists());
        assert!(!marker.exists());
        assert_eq!(fs::read_to_string(&pend_recover_calls).unwrap(), "ff");

        // Even if candidate B now FAILS integrity verification while
        // `network-recover-pending` and `rollback-blocked` exist, the
        // supervisor MUST NOT accept older previous A's exit 0 or clear
        // `network-recover-pending`!
        let mut corrupt_b_pend = cand_deletes_then_fails.clone();
        *corrupt_b_pend.last_mut().unwrap() = b'Z';
        write_release_agent(
            &manager.paths,
            Slot::B,
            &rel_b_del_fail,
            &corrupt_b_pend,
        );
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(8),
            "unverified candidate with outstanding network-recover-pending must not be cleared by older previous slot"
        );
        assert!(pend_recover_pending.exists());
        assert!(manager.paths.pending.exists());
        assert!(blocked.exists());
        assert!(!marker.exists());

        // Once candidate `network-recover` finally succeeds (still without
        // recreating `ts_flush_marker`), `network-recover-pending` clears and
        // handoff to slot A succeeds cleanly.
        let cand_clear_flush = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then exit 0; fi\nif [ \"${{1:-}}\" = network-recover ]; then printf 'ok' >> \"{}\"; rm -f \"{}\"; exit 0; fi\nexit 0\n",
            pend_recover_calls.display(),
            ts_flush_marker.display()
        ));
        let rel_b_flush_ok = release_for_binary(Channel::Beta, "2.4.0-beta.8", &cand_clear_flush);
        write_release_agent(&manager.paths, Slot::B, &rel_b_flush_ok, &cand_clear_flush);
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success(), "rollback handoff must succeed once candidate recovery succeeds");
        assert!(!ts_flush_marker.exists());
        assert!(!pend_recover_pending.exists());
        assert!(!manager.paths.pending.exists());
        assert!(!blocked.exists());
        assert_eq!(fs::read_to_string(&pend_recover_calls).unwrap(), "ffok");
        assert_eq!(fs::read_to_string(&marker).unwrap(), "a-stale-flush");
        let _ = fs::remove_file(&marker);

        // JSON-escaped `"boot"` values (e.g. `boot-uuid\u002d123` or `boot\tuuid`)
        // in the Tailscale journal MUST fail closed (exit 8) instead of being
        // misclassified as a different boot!
        for escaped_json in [
            "{\"boot\":\"boot-uuid\\u002d123\",\"undo\":[]}\n",
            "{\"boot\":\"boot-uuid\\t123\",\"undo\":[]}\n",
        ] {
            fs::write(&ts_journal, escaped_json).unwrap();
            manager
                .paths
                .write_pending(Slot::B, Slot::A, "2.4.0-beta.8")
                .unwrap();
            let cand_keep_j = pad_script(b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then exit 0; fi\nif [ \"${1:-}\" = network-recover ]; then exit 1; fi\nexit 0\n");
            let rel_b_keep = release_for_binary(Channel::Beta, "2.4.0-beta.8", &cand_keep_j);
            write_release_agent(&manager.paths, Slot::B, &rel_b_keep, &cand_keep_j);
            let status = Command::new("sh")
                .arg(&manager.paths.supervisor)
                .env("ZTE_OTA_ROOT", &manager.paths.root)
                .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
                .env("ZTE_TEST_MARKER", &marker)
                .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
                .env("ZTE_BOOT_ID_PATH", &boot_id_file)
                .env("ZTE_PROC_ROOT", &fake_proc)
                .status()
                .unwrap();
            assert_eq!(
                status.code(),
                Some(8),
                "escaped JSON boot field {escaped_json:?} must fail closed as same-boot"
            );
            assert!(!marker.exists());
            let _ = fs::remove_file(&pend_recover_pending);
        }
        let _ = fs::remove_file(&ts_journal);
        let _ = fs::remove_file(&manager.paths.pending);

        // Surviving same-boot performance journal MUST also block rollback
        // until candidate recovery removes it.
        let perf_journal = manager.paths.root.join("perf-network.json");
        fs::write(&perf_journal, "{\"boot\":\"boot-uuid-123\",\"originals\":[]}\n").unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.8")
            .unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_PERF_JOURNAL", &perf_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(8),
            "surviving same-boot perf journal must block rollback handoff"
        );
        assert!(perf_journal.exists());
        assert!(!marker.exists());
        let _ = fs::remove_file(&perf_journal);
        let _ = fs::remove_file(&pend_recover_pending);
        let _ = fs::remove_file(&manager.paths.pending);

        // Surviving strict-zero-cellular `cellular-pause` journal (even with NO
        // Tailscale journal, flush marker, or tailscaled) MUST trigger candidate
        // recovery and refuse rollback handoff (exit 8) while it remains on disk.
        let cellular_pause = manager.paths.root.join("cellular-pause");
        fs::write(&cellular_pause, "1\n").unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.8")
            .unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_RELAY_CELLULAR_PAUSE", &cellular_pause)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(8),
            "surviving cellular-pause journal must refuse rollback handoff to an older slot"
        );
        assert!(cellular_pause.exists());
        assert!(!marker.exists());
        let cand_clear_cell = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then exit 0; fi\nif [ \"${{1:-}}\" = network-recover ]; then rm -f \"{}\"; exit 0; fi\nexit 0\n",
            cellular_pause.display()
        ));
        let rel_b_cell = release_for_binary(Channel::Beta, "2.4.0-beta.8", &cand_clear_cell);
        write_release_agent(&manager.paths, Slot::B, &rel_b_cell, &cand_clear_cell);
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_RELAY_CELLULAR_PAUSE", &cellular_pause)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success(), "rollback proceeds once cellular-pause is cleared");
        assert!(!cellular_pause.exists());
        assert_eq!(fs::read_to_string(&marker).unwrap(), "a-stale-flush");
        let _ = fs::remove_file(&marker);
        // Restore bootstrap slot A for the reboot check below.
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::A));
        fs::write(manager.paths.slot_binary(Slot::A), &boot_prev).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::A),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(
            manager.paths.slot_bootstrap_digest(Slot::A),
            format!("{}\n2.3.5\n", sha256(&boot_prev)),
        )
        .unwrap();

        // After a reboot (different boot_id, simulated live tailscaled gone and
        // only init running in proc), old-boot blocked marker & journal are
        // positively identified as another boot and recovery proceeds to slot A.
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.8")
            .unwrap();
        fs::write(&blocked, "boot-uuid-123\n").unwrap();
        fs::write(&boot_id_file, "boot-uuid-456\n").unwrap();
        fs::write(&ts_journal, "{ \"boot\" : \"boot-uuid-123\" , \"undo\" : [] }\n").unwrap();
        fs::write(&ts_flush_marker, "boot-uuid-123\n").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(!manager.paths.pending.exists());
        assert!(!blocked.exists());
        assert_eq!(fs::read_to_string(&marker).unwrap(), "a-bootstrap");
        let _ = fs::remove_file(&marker);

        // Interrupted commit (`active=b`, `pending` has candidate=b, previous=a)
        // with unavailable previous slot A MUST NOT clear pending or boot the
        // excluded candidate B; with no rescue it exits 127 keeping pending,
        // and with a valid stable rescue it boots rescue and clears pending.
        let _ = fs::remove_file(&ts_journal);
        let broken_a = test_agent("2.4.0-beta.7", false, "broken-a");
        let rel_broken_a = release_for_binary(Channel::Beta, "2.4.0-beta.7", &broken_a);
        let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::A));
        write_release_agent(&manager.paths, Slot::A, &rel_broken_a, &broken_a);
        let cand_b = test_agent("2.4.0-beta.8", true, "excluded-b");
        let rel_cand_b = release_for_binary(Channel::Beta, "2.4.0-beta.8", &cand_b);
        write_release_agent(&manager.paths, Slot::B, &rel_cand_b, &cand_b);
        manager.paths.write_active(Slot::B).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.8")
            .unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(127));
        assert!(
            manager.paths.pending.exists(),
            "pending must be retained when no verified non-excluded slot exists"
        );
        assert_ne!(
            fs::read_to_string(&marker).ok().as_deref(),
            Some("excluded-b"),
            "interrupted commit must never boot excluded candidate"
        );
        // Providing a valid last-stable rescue selects rescue instead of B.
        let stable_bytes = test_agent("2.3.0", true, "stable-rescue");
        let stable = release_for_binary(Channel::Stable, "2.3.0", &stable_bytes);
        fs::write(manager.paths.stable_binary(), &stable_bytes).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable).unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(!manager.paths.pending.exists());
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-rescue");
        let _ = fs::remove_file(&marker);

        // Persisted `active=rescue` MUST stay on `last-stable` across a second
        // restart (never falling through to boot the excluded candidate B),
        // AND candidate B's version must have been quarantined in `blocked.json`
        // so even an older `HEAD` supervisor reinstalled by `last-stable` skips B!
        let blocked_json: Vec<String> =
            storage::read_json(&manager.paths.blocked).expect("blocked.json must be valid JSON");
        assert!(
            blocked_json.iter().any(|v| v == "2.4.0-beta.8"),
            "failed candidate version must be quarantined in blocked.json: {blocked_json:?}"
        );
        // Ordinary restart with already-persisted `active=rescue` MUST succeed
        // even if `active.tmp` cannot be written (no rewrite required).
        let active_tmp = manager.paths.root.join("active.tmp");
        fs::create_dir_all(&active_tmp).unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        fs::remove_dir_all(&active_tmp).unwrap();
        assert!(
            status.success(),
            "ordinary restart with unchanged active=rescue must not require rewriting active.tmp"
        );
        assert_eq!(
            fs::read_to_string(&marker).unwrap(),
            "stable-rescue",
            "second restart after rescue must stay on last-stable instead of booting B"
        );
        let _ = fs::remove_file(&marker);

        // If `last-stable/release.json` disappears while `active=rescue` is
        // persisted, the supervisor MUST stop (exit 127) and keep `active=rescue`
        // rather than scanning A/B and booting excluded candidate B!
        let saved_stable_meta = fs::read(&manager.paths.stable_meta()).unwrap();
        fs::remove_file(&manager.paths.stable_meta()).unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(127),
            "unverifiable persisted rescue must stop instead of falling back to A/B"
        );
        assert_eq!(fs::read_to_string(&manager.paths.active).unwrap().trim(), "rescue");
        assert!(!marker.exists());
        fs::write(&manager.paths.stable_meta(), &saved_stable_meta).unwrap();

        // Rust helper `recover()` MUST reject a probe-only previous slot
        // (executable returning 0 on `ota-probe`, missing both release.json and
        // bootstrap.sha256), disarm BOTH rejected slot A and bootstrap/same-
        // version candidate B, fall back to verified `last-stable` rescue, and
        // keep A and B unbootable even under the older `HEAD` supervisor!
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::A));
        let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::A));
        let probe_only_a = test_agent(crate::build_info::VERSION, true, "probe-only-a");
        fs::write(manager.paths.slot_binary(Slot::A), &probe_only_a).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::A),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        // Preflight MUST reject probe-only active slots (matching recovery and
        // same-boot shell integrity verification), even if Stable rescue exists.
        assert!(
            verify_active_slot(&manager.paths, Slot::A).is_err(),
            "preflight must reject probe-only active slot lacking digest metadata"
        );

        // Quarantined Stable rescue (its version in blocked.json) MUST be
        // rejected by verify_stable_rescue() and recover() (returns 5, retains
        // pending, never launches quarantined Stable).
        let saved_blocked = fs::read(&manager.paths.blocked).unwrap();
        storage::write_json(&manager.paths.blocked, &vec!["2.3.0".to_string()]).unwrap();
        assert!(verify_stable_rescue(&manager.paths).is_err());
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.8")
            .unwrap();
        assert_eq!(recover(&manager.paths, Slot::A, None, None), 5);
        assert!(manager.paths.pending.exists());
        fs::write(&manager.paths.blocked, &saved_blocked).unwrap();

        // Guard-write failure path (`failed_candidate = None`) entering rescue
        // MUST disarm BOTH probe-only A AND untried staged B so an older HEAD
        // supervisor cannot launch B on the following restart.
        let untried_b = test_agent("2.4.0-beta.77", true, "untried-b");
        let rel_untried_b = release_for_binary(Channel::Beta, "2.4.0-beta.77", &untried_b);
        write_release_agent(&manager.paths, Slot::B, &rel_untried_b, &untried_b);
        let rescue_perf = crate::netfx::perf::Perf::for_test(&manager.paths.root.join("perf-rescue"));
        assert_eq!(recover_with_perf(&manager.paths, Slot::A, None, None, &rescue_perf), 6);
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::A)));
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        assert_eq!(fs::read_to_string(&manager.paths.active).unwrap().trim(), "rescue");
        let _ = fs::remove_file(&marker);

        // Previous verified bootstrap slot A sharing version with signed
        // candidate B: collision check MUST read bootstrap.sha256 line 2 and
        // disarm B instead of adding the shared version to blocked.json!
        let boot_a_same = test_agent("2.4.0-beta.55", true, "boot-a-same");
        fs::write(manager.paths.slot_binary(Slot::A), &boot_a_same).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::A),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(
            manager.paths.slot_bootstrap_digest(Slot::A),
            format!("{}\n2.4.0-beta.55\n", sha256(&boot_a_same)),
        )
        .unwrap();
        let cand_b_same = test_agent("2.4.0-beta.55", true, "cand-b-same");
        let rel_b_same = release_for_binary(Channel::Beta, "2.4.0-beta.55", &cand_b_same);
        write_release_agent(&manager.paths, Slot::B, &rel_b_same, &cand_b_same);
        quarantine_failed_candidate(&manager.paths, Slot::B, "2.4.0-beta.55", Slot::A).unwrap();
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        let blocked_after_boot_same: Vec<String> =
            storage::read_json(&manager.paths.blocked).unwrap_or_default();
        assert!(
            !blocked_after_boot_same.iter().any(|v| v == "2.4.0-beta.55"),
            "previous bootstrap version collision must disarm B without poisoning blocked.json"
        );
        // Shell launcher collision check with bootstrap A + same-version signed B:
        write_release_agent(&manager.paths, Slot::B, &rel_b_same, &cand_b_same);
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.55")
            .unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(fs::read_to_string(&marker).unwrap(), "boot-a-same");
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        let blocked_after_shell_boot_same: Vec<String> =
            storage::read_json(&manager.paths.blocked).unwrap_or_default();
        assert!(!blocked_after_shell_boot_same.iter().any(|v| v == "2.4.0-beta.55"));
        let _ = fs::remove_file(&marker);

        // Commit-failure sequence: `active=b` succeeds, `clear_pending()`
        // unlinks `pending` then fails on directory sync, and persistent
        // storage fault prevents `write_pending` restoration AND `recover()`
        // quarantine (`blocked.json` is malformed). Because `rollback-blocked`
        // is kept on disk until AFTER `clear_pending()` succeeds, it survives
        // and the next shell supervisor invocation fails closed (exit 8) instead
        // of taking the ordinary boot path and restarting candidate B!
        let rb_marker = manager.paths.root.join("rollback-blocked");
        fs::write(&rb_marker, "boot-uuid-456\n").unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.88")
            .unwrap();
        let cand_b_commit = test_agent("2.4.0-beta.88", true, "cand-b-commit");
        let rel_b_commit = release_for_binary(Channel::Beta, "2.4.0-beta.88", &cand_b_commit);
        write_release_agent(&manager.paths, Slot::B, &rel_b_commit, &cand_b_commit);
        let commit_err = commit_trial_with(
            || manager.paths.write_active(Slot::B),
            || Ok(()),
            || {
                // Simulate unlink succeeding, then parent directory sync failing.
                fs::remove_file(&manager.paths.pending)?;
                Err(std::io::Error::new(std::io::ErrorKind::Other, "simulated sync EIO"))
            },
            || panic!("must not remove rollback-blocked before clear_pending succeeds"),
        );
        assert!(commit_err.is_err());
        assert!(!manager.paths.pending.exists());
        assert!(rb_marker.exists(), "rollback-blocked must survive failed clear_pending");
        assert_eq!(fs::read_to_string(&manager.paths.active).unwrap().trim(), "b");
        // Simulate malformed quarantine list + failed restoration during recovery:
        let saved_blocked2 = fs::read(&manager.paths.blocked).unwrap();
        let damaged_blocked = b"[\"2.3.0\""; // missing closing ']'
        fs::write(&manager.paths.blocked, damaged_blocked).unwrap();
        assert!(
            verify_stable_rescue(&manager.paths).is_err(),
            "malformed blocked.json must reject Stable rescue"
        );
        assert!(
            block_version(&manager.paths, "2.4.0-beta.88").is_err(),
            "malformed blocked.json must fail closed without overwriting"
        );
        assert_eq!(
            fs::read(&manager.paths.blocked).unwrap(),
            damaged_blocked,
            "malformed blocked.json bytes must be retained untouched"
        );
        assert_eq!(
            recover(&manager.paths, Slot::A, Some((Slot::B, "2.4.0-beta.88")), None),
            9,
            "recover must abort with 9 when quarantine file is malformed"
        );
        assert!(rb_marker.exists());
        assert_eq!(fs::read(&manager.paths.blocked).unwrap(), damaged_blocked);
        // Shell launcher sees surviving `rollback-blocked` without `pending` and
        // refuses to launch stopped candidate B (exit 8)!
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(8),
            "surviving same-boot rollback-blocked after commit error must block ordinary boot of B"
        );
        assert!(rb_marker.exists());
        assert!(!marker.exists());
        // Shell pending-rollback quarantine MUST reject ALL malformed JSON
        // forms — including `[broken]`, truncated `["2.4.0-beta.88"`, raw
        // control bytes (e.g. 0x0C form feed), and invalid UTF-8 (0xFF) —
        // exiting 9 while retaining `pending` and exact file bytes untouched.
        let _ = fs::remove_file(&rb_marker);
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.88")
            .unwrap();
        for bad_json in [
            damaged_blocked.as_slice(),
            b"[broken]".as_slice(),
            b"[\"2.4.0-beta.88\"".as_slice(),
            b"[\"2.0.0\x0c\"]".as_slice(),
            b"[\"2.0.0\xff\"]".as_slice(),
        ] {
            fs::write(&manager.paths.blocked, bad_json).unwrap();
            let status = Command::new("sh")
                .arg(&manager.paths.supervisor)
                .env("ZTE_OTA_ROOT", &manager.paths.root)
                .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
                .env("ZTE_TEST_MARKER", &marker)
                .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
                .env("ZTE_BOOT_ID_PATH", &boot_id_file)
                .env("ZTE_PROC_ROOT", &fake_proc)
                .status()
                .unwrap();
            assert_eq!(
                status.code(),
                Some(9),
                "malformed blocked.json {:?} must exit 9",
                String::from_utf8_lossy(bad_json)
            );
            assert!(manager.paths.pending.exists());
            assert_eq!(fs::read(&manager.paths.blocked).unwrap(), bad_json);
            assert!(!marker.exists());
        }

        // Valid empty array with arbitrary whitespace (`[  ]`) MUST update cleanly
        // into valid JSON `["2.4.0-beta.88"]`!
        fs::write(&manager.paths.blocked, b"[  ]\n").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success(), "empty whitespace array `[  ]` must append valid JSON");
        assert!(!manager.paths.pending.exists());
        let parsed_after_ws: Vec<String> = storage::read_json(&manager.paths.blocked)
            .expect("quarantine update after `[  ]` must produce valid JSON");
        assert_eq!(parsed_after_ws, vec!["2.4.0-beta.88".to_string()]);
        let _ = fs::remove_file(&marker);

        // Escaped version already present in `blocked.json` (`["2\u002e4.0-beta.88"]`)
        // MUST be recognized as equal by decoded value (no duplicate appended!).
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.88")
            .unwrap();
        fs::write(&manager.paths.blocked, b"[\"2\\u002e4.0-beta.88\"]\n").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success());
        let parsed_after_esc: Vec<String> = storage::read_json(&manager.paths.blocked).unwrap();
        assert_eq!(
            parsed_after_esc,
            vec!["2.4.0-beta.88".to_string()],
            "escaped version must match by decoded value without appending a duplicate"
        );
        let _ = fs::remove_file(&marker);

        // Persisted `active=rescue` MUST reject truncated `["2.3.`, JSON-escaped
        // `["2\u002e3.0"]`, raw control-byte, and invalid UTF-8 `blocked.json`
        // (stopping with exit 127 and preserving `active=rescue` without launching).
        manager.paths.write_rescue().unwrap();
        for rescue_blocker in [
            b"[\"2.3.".as_slice(),
            b"[\"2\\u002e3.0\"]".as_slice(),
            b"[\"1.0.0\x0c\"]".as_slice(),
            b"[\"1.0.0\xff\"]".as_slice(),
        ] {
            fs::write(&manager.paths.blocked, rescue_blocker).unwrap();
            let status = Command::new("sh")
                .arg(&manager.paths.supervisor)
                .env("ZTE_OTA_ROOT", &manager.paths.root)
                .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
                .env("ZTE_TEST_MARKER", &marker)
                .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
                .env("ZTE_BOOT_ID_PATH", &boot_id_file)
                .env("ZTE_PROC_ROOT", &fake_proc)
                .status()
                .unwrap();
            assert_eq!(
                status.code(),
                Some(127),
                "blocked.json {:?} must reject Stable rescue eligibility",
                String::from_utf8_lossy(rescue_blocker)
            );
            assert_eq!(fs::read_to_string(&manager.paths.active).unwrap().trim(), "rescue");
            assert!(!marker.exists());
        }
        // Damaged candidate `release.json` (raw tab, raw NUL, or truncated) MUST
        // disarm candidate slot B by slot without mutating `blocked.json` or
        // leaving `blocked.json.tmp`, matching Rust's `quarantine_failed_candidate`
        // and booting verified fallback cleanly.
        let valid_blocked = b"[\"1.0.0\"]\n";
        fs::write(&manager.paths.blocked, valid_blocked).unwrap();
        let saved_cand_meta = fs::read(manager.paths.slot_meta(Slot::B)).unwrap();
        for damaged_meta in [
            b"{\n  \"version\": \"2.4.0\tbeta\",\n  \"size\": 1024,\n  \"sha256\": \"0000\"\n}\n".as_slice(),
            b"{\n  \"version\": \"2.4.0\0-beta.88\",\n  \"size\": 1024,\n  \"sha256\": \"0000\"\n}\n".as_slice(),
            b"{\n  \"schema\": 1,\n  \"channel\": \"beta\",\n  \"version\": \"2.4.0-beta.99\",\n".as_slice(),
        ] {
            fs::set_permissions(
                manager.paths.slot_binary(Slot::B),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            fs::write(manager.paths.slot_meta(Slot::B), damaged_meta).unwrap();
            manager
                .paths
                .write_pending(Slot::B, Slot::A, "2.4.0-beta.99")
                .unwrap();
            let _ = fs::remove_file(&marker);
            let status = Command::new("sh")
                .arg(&manager.paths.supervisor)
                .env("ZTE_OTA_ROOT", &manager.paths.root)
                .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
                .env("ZTE_TEST_MARKER", &marker)
                .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
                .env("ZTE_BOOT_ID_PATH", &boot_id_file)
                .env("ZTE_PROC_ROOT", &fake_proc)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "damaged candidate metadata must disarm candidate by slot and boot verified fallback (got {:?})",
                status.code()
            );
            assert!(!manager.paths.pending.exists());
            assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
            assert_eq!(
                fs::read(&manager.paths.blocked).unwrap(),
                valid_blocked,
                "damaged candidate metadata must never corrupt or mutate valid blocked.json"
            );
            assert!(!manager.paths.root.join("blocked.json.tmp").exists());
        }
        fs::set_permissions(
            manager.paths.slot_binary(Slot::B),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(manager.paths.slot_meta(Slot::B), &saved_cand_meta).unwrap();
        let _ = fs::remove_file(&manager.paths.pending);

        // NUL-damaged `pending` marker whose candidate-slot field is corrupted
        // to empty (`\0\na\n2.4.0-beta.88\n`) MUST be rejected BEFORE any `sed`
        // or handoff even when the previous slot A is verified and runnable:
        // exits 9, retains `pending` and `blocked.json` byte-for-byte, and
        // launches nothing.
        let runnable_prev = test_agent("2.4.0-beta.87", true, "runnable-prev-a");
        let runnable_prev_rel = release_for_binary(Channel::Beta, "2.4.0-beta.87", &runnable_prev);
        write_release_agent(&manager.paths, Slot::A, &runnable_prev_rel, &runnable_prev);
        let damaged_pending = b"\0\na\n2.4.0-beta.88\n";
        fs::write(&manager.paths.pending, damaged_pending).unwrap();
        fs::write(&manager.paths.blocked, valid_blocked).unwrap();
        let _ = fs::remove_file(&marker);
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(9),
            "NUL-damaged pending marker with empty candidate field must exit 9 before handoff"
        );
        assert_eq!(
            fs::read(&manager.paths.pending).unwrap(),
            damaged_pending,
            "damaged pending marker must be retained byte-for-byte"
        );
        assert_eq!(
            fs::read(&manager.paths.blocked).unwrap(),
            valid_blocked,
            "blocked.json must remain byte-identical when pending is NUL-damaged"
        );
        assert!(!marker.exists(), "must stop before launching previous slot");
        let _ = fs::remove_file(&manager.paths.pending);

        // A `pending` marker naming the same slot as both candidate and previous
        // (`b\nb\n2.4.0-beta.88\n`) MUST be rejected BEFORE recovery/quarantine
        // with exit 9, preserving `pending`, `active`, `blocked.json`, and slot B's
        // executable permissions even when both slots A and B are verified/runnable.
        manager.paths.write_active(Slot::A).unwrap();
        let runnable_b = test_agent("2.4.0-beta.88", true, "runnable-b");
        let runnable_b_rel = release_for_binary(Channel::Beta, "2.4.0-beta.88", &runnable_b);
        write_release_agent(&manager.paths, Slot::B, &runnable_b_rel, &runnable_b);
        let dup_slot_pending = b"b\nb\n2.4.0-beta.88\n";
        fs::write(&manager.paths.pending, dup_slot_pending).unwrap();
        fs::write(&manager.paths.blocked, valid_blocked).unwrap();
        let _ = fs::remove_file(&marker);
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(9),
            "pending marker naming the same slot twice must exit 9 before recovery"
        );
        assert_eq!(fs::read(&manager.paths.pending).unwrap(), dup_slot_pending);
        assert_eq!(fs::read_to_string(&manager.paths.active).unwrap().trim(), "a");
        assert_eq!(fs::read(&manager.paths.blocked).unwrap(), valid_blocked);
        assert!(
            storage::executable(&manager.paths.slot_binary(Slot::B)),
            "slot B permissions must remain untouched when duplicate-slot pending is rejected"
        );
        assert!(!marker.exists(), "must stop before launching any slot");
        let _ = fs::remove_file(&manager.paths.pending);

        // Rust `recover()` with an already-escaped entry `["2\u002e4.0-beta.88"]`
        // in `blocked.json` MUST rewrite the canonical literal `"2.4.0-beta.88"`
        // before clearing `pending`, so an older `HEAD` supervisor on the next
        // boot skips candidate B and launches Stable rescue instead!
        fs::write(&manager.paths.blocked, b"[\"2\\u002e4.0-beta.88\"]\n").unwrap();
        let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::A));
        fs::write(manager.paths.slot_binary(Slot::A), &probe_only_a).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::A),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.88")
            .unwrap();
        assert_eq!(
            recover_with_perf(
                &manager.paths,
                Slot::A,
                Some((Slot::B, "2.4.0-beta.88")),
                None,
                &rescue_perf,
            ),
            6
        );
        assert!(!manager.paths.pending.exists());
        assert!(
            fs::read_to_string(&manager.paths.blocked)
                .unwrap()
                .contains("\"2.4.0-beta.88\""),
            "Rust block_version must persist canonical literal for HEAD supervisor compatibility"
        );
        let _ = fs::remove_file(&marker);
        let head_sup_check = manager.paths.root.join("head-supervisor-canon.sh");
        let head_script_canon = r#"#!/bin/sh
set -u
OTA_ROOT="${ZTE_OTA_ROOT}"
ACTIVE="$OTA_ROOT/active"
LAST_STABLE="$OTA_ROOT/last-stable/zte-agent"
LAST_STABLE_META="$OTA_ROOT/last-stable/release.json"
BLOCKED="$OTA_ROOT/blocked.json"
slot_binary() { printf '%s/slot-%s/zte-agent' "$OTA_ROOT" "$1"; }
slot_meta() { printf '%s/slot-%s/release.json' "$OTA_ROOT" "$1"; }
valid_slot() { [ "$1" = a ] || [ "$1" = b ]; }
runnable_binary() {
    b=$1; m=$2; [ -x "$b" ] || return 1
    if [ -f "$m" ]; then
        v=$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$m" | sed -n '1p')
        [ -n "$v" ] || return 1
        if [ -f "$BLOCKED" ] && grep -Fq "\"$v\"" "$BLOCKED"; then return 1; fi
        "$b" ota-probe "$v" >/dev/null 2>&1; return $?
    fi
    return 0
}
runnable_slot() { runnable_binary "$(slot_binary "$1")" "$(slot_meta "$1")"; }
runnable_stable() { [ -f "$LAST_STABLE_META" ] && runnable_binary "$LAST_STABLE" "$LAST_STABLE_META"; }
active=$(sed -n '1p' "$ACTIVE" 2>/dev/null || true)
if ! valid_slot "$active" || ! runnable_slot "$active"; then
    if runnable_slot a; then active=a
    elif runnable_slot b; then active=b
    elif runnable_stable; then active=stable
    else exit 127
    fi
fi
if valid_slot "$active"; then
    printf '%s\n' "$active" > "$ACTIVE"
    exec "$(slot_binary "$active")"
else
    printf 'rescue\n' > "$ACTIVE"
    exec "$LAST_STABLE"
fi
"#;
        fs::write(&head_sup_check, head_script_canon).unwrap();
        let status = Command::new("sh")
            .arg(&head_sup_check)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_TEST_MARKER", &marker)
            .status()
            .unwrap();
        assert!(status.success(), "HEAD supervisor must boot Stable rescue, not escaped-blocked B");
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-rescue");
        assert_eq!(fs::read_to_string(&manager.paths.active).unwrap().trim(), "rescue");
        let _ = fs::remove_file(&marker);
        fs::write(&manager.paths.blocked, &saved_blocked2).unwrap();

        // Restore probe-only A for the subsequent same-version / bootstrap tests.
        let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::A));
        fs::write(manager.paths.slot_binary(Slot::A), &probe_only_a).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::A),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        // Candidate B sharing Stable's version ("2.3.0"): recover() must disarm
        // slot B (NOT poison blocked.json with "2.3.0"!), disarm rejected A,
        // and launch Stable rescue (exit 6).
        let same_ver_b = test_agent("2.3.0", true, "same-ver-b");
        let rel_same_b = release_for_binary(Channel::Stable, "2.3.0", &same_ver_b);
        write_release_agent(&manager.paths, Slot::B, &rel_same_b, &same_ver_b);
        manager.paths.write_active(Slot::B).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.3.0")
            .unwrap();
        assert_eq!(
            recover_with_perf(
                &manager.paths,
                Slot::A,
                Some((Slot::B, "2.3.0")),
                None,
                &rescue_perf,
            ),
            6,
            "probe-only previous slot without digest metadata must fall back to Stable rescue"
        );
        assert_eq!(fs::read_to_string(&manager.paths.active).unwrap().trim(), "rescue");
        assert!(!manager.paths.pending.exists());
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::A)));
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        let blocked_after_same: Vec<String> =
            storage::read_json(&manager.paths.blocked).unwrap_or_default();
        assert!(
            !blocked_after_same.iter().any(|v| v == "2.3.0"),
            "same-version candidate must not poison Stable version in blocked.json"
        );
        let _ = fs::remove_file(&marker);

        // Candidate B lacking release.json (bootstrap slot) is also disarmed.
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::B));
        let boot_b = test_agent("2.3.5-boot.1", true, "boot-b");
        fs::write(manager.paths.slot_binary(Slot::B), &boot_b).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::B),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(
            manager.paths.slot_bootstrap_digest(Slot::B),
            format!("{}\n2.3.5-boot.1\n", sha256(&boot_b)),
        )
        .unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.3.5-boot.1")
            .unwrap();
        assert_eq!(
            recover_with_perf(
                &manager.paths,
                Slot::A,
                Some((Slot::B, "2.3.5-boot.1")),
                None,
                &rescue_perf,
            ),
            6
        );
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        let _ = fs::remove_file(&marker);

        // Failed quarantine write (blocked.json replaced by a directory) MUST
        // abort recover() with 9 and retain pending + rollback-blocked.
        let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::B));
        let cand_b_new = test_agent("2.4.0-beta.99", true, "cand-b-99");
        let rel_b_new = release_for_binary(Channel::Beta, "2.4.0-beta.99", &cand_b_new);
        write_release_agent(&manager.paths, Slot::B, &rel_b_new, &cand_b_new);
        let _ = fs::remove_file(&manager.paths.blocked);
        fs::create_dir_all(manager.paths.blocked.join("dir-blocker")).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.99")
            .unwrap();
        let blocked = manager.paths.root.join("rollback-blocked");
        fs::write(&blocked, "boot-uuid-456\n").unwrap();
        assert_eq!(
            recover(&manager.paths, Slot::A, Some((Slot::B, "2.4.0-beta.99")), None),
            9,
            "quarantine write failure must retain rollback markers"
        );
        assert!(manager.paths.pending.exists());
        assert!(blocked.exists());
        fs::remove_dir_all(&manager.paths.blocked).unwrap();
        let _ = fs::remove_file(&blocked);

        // Executable-only previous slot A (missing both release.json and
        // bootstrap.sha256, exiting 42) MUST NOT displace verified last-stable
        // rescue during pending rollback, AND MUST be disarmed so even a
        // subsequent boot under the older `HEAD` supervisor (without
        // `active=rescue` awareness) boots Stable (or exits 127 if Stable is
        // removed) and NEVER boots A or B!
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::A));
        let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::A));
        fs::write(manager.paths.slot_binary(Slot::A), b"#!/bin/sh\nexit 42\n").unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::A),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        manager.paths.write_active(Slot::B).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.99")
            .unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success(), "unverified previous slot must fall through to rescue");
        assert!(!manager.paths.pending.exists());
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::A)));
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-rescue");
        let _ = fs::remove_file(&marker);

        // Model an older `last-stable` reinstalling the pre-Ticket-#8 `HEAD`
        // supervisor (which treats `active=rescue` as invalid and scans A/B):
        // Launch 2 MUST still select Stable (not A or B), and if Stable's
        // manifest is removed it MUST exit 127 without launching A or B!
        let head_sup = manager.paths.root.join("head-supervisor.sh");
        let head_script = r#"#!/bin/sh
set -u
OTA_ROOT="${ZTE_OTA_ROOT}"
ACTIVE="$OTA_ROOT/active"
LAST_STABLE="$OTA_ROOT/last-stable/zte-agent"
LAST_STABLE_META="$OTA_ROOT/last-stable/release.json"
BLOCKED="$OTA_ROOT/blocked.json"
slot_binary() { printf '%s/slot-%s/zte-agent' "$OTA_ROOT" "$1"; }
slot_meta() { printf '%s/slot-%s/release.json' "$OTA_ROOT" "$1"; }
valid_slot() { [ "$1" = a ] || [ "$1" = b ]; }
runnable_binary() {
    b=$1; m=$2; [ -x "$b" ] || return 1
    if [ -f "$m" ]; then
        v=$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$m" | sed -n '1p')
        [ -n "$v" ] || return 1
        if [ -f "$BLOCKED" ] && grep -Fq "\"$v\"" "$BLOCKED"; then return 1; fi
        "$b" ota-probe "$v" >/dev/null 2>&1; return $?
    fi
    return 0
}
runnable_slot() { runnable_binary "$(slot_binary "$1")" "$(slot_meta "$1")"; }
runnable_stable() { [ -f "$LAST_STABLE_META" ] && runnable_binary "$LAST_STABLE" "$LAST_STABLE_META"; }
active=$(sed -n '1p' "$ACTIVE" 2>/dev/null || true)
if ! valid_slot "$active" || ! runnable_slot "$active"; then
    if runnable_slot a; then active=a
    elif runnable_slot b; then active=b
    elif runnable_stable; then active=stable
    else exit 127
    fi
fi
if valid_slot "$active"; then
    printf '%s\n' "$active" > "$ACTIVE"
    exec "$(slot_binary "$active")"
else
    printf 'rescue\n' > "$ACTIVE"
    exec "$LAST_STABLE"
fi
"#;
        fs::write(&head_sup, head_script).unwrap();
        let status = Command::new("sh")
            .arg(&head_sup)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_TEST_MARKER", &marker)
            .status()
            .unwrap();
        assert!(status.success(), "older HEAD supervisor must keep booting Stable rescue");
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-rescue");
        assert_eq!(fs::read_to_string(&manager.paths.active).unwrap().trim(), "rescue");
        let _ = fs::remove_file(&marker);
        // Even with Stable manifest missing, older HEAD supervisor exits 127 (neither A nor B).
        let saved_stable_meta3 = fs::read(&manager.paths.stable_meta()).unwrap();
        fs::remove_file(&manager.paths.stable_meta()).unwrap();
        let status = Command::new("sh")
            .arg(&head_sup)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_TEST_MARKER", &marker)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(127));
        assert!(!marker.exists());
        assert_eq!(fs::read_to_string(&manager.paths.active).unwrap().trim(), "rescue");
        fs::write(&manager.paths.stable_meta(), &saved_stable_meta3).unwrap();

        // Failed active-slot persistence (active path replaced by a non-empty
        // directory so rename fails) MUST refuse handoff (exit 9) and retain
        // BOTH pending and rollback-blocked markers in shell AND Rust helper!
        let mut good_prev = format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then [ \"${{2:-}}\" = \"{}\" ] && exit 0; exit 2; fi\nif [ \"${{1:-}}\" = network-recover ]; then exit 0; fi\n[ -z \"${{ZTE_TEST_MARKER:-}}\" ] || printf 'good-a' > \"$ZTE_TEST_MARKER\"\n#",
            crate::build_info::VERSION
        )
        .into_bytes();
        good_prev.resize(1024, b'x');
        let rel_good_prev = release_for_binary(Channel::Stable, crate::build_info::VERSION, &good_prev);
        write_release_agent(&manager.paths, Slot::A, &rel_good_prev, &good_prev);
        fs::remove_file(&manager.paths.active).unwrap();
        fs::create_dir_all(manager.paths.active.join("blocker")).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.99")
            .unwrap();
        let blocked = manager.paths.root.join("rollback-blocked");
        fs::write(&blocked, "boot-uuid-456\n").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(9),
            "failed active-slot write must exit 9 instead of clearing rollback markers"
        );
        assert!(manager.paths.pending.exists());
        assert!(blocked.exists());
        assert!(!marker.exists());

        // Rust helper `recover()` also retains both markers on write_active failure.
        assert_eq!(recover(&manager.paths, Slot::A, None, None), 9);
        assert!(manager.paths.pending.exists());
        assert!(blocked.exists());
    }

    #[test]
    fn missing_or_damaged_supervisor_is_repaired_atomically() {
        let manager = manager("supervisor-repair");
        fs::write(&manager.paths.supervisor, b"damaged").unwrap();
        fs::set_permissions(&manager.paths.supervisor, fs::Permissions::from_mode(0o600)).unwrap();

        ensure_supervisor(&manager.paths).unwrap();

        assert_eq!(
            fs::read(&manager.paths.supervisor).unwrap(),
            SUPERVISOR_SCRIPT
        );
        assert!(storage::executable(&manager.paths.supervisor));
    }

    #[test]
    fn supervisor_skips_a_corrupted_active_slot_and_runs_the_verified_fallback() {
        let manager = manager("supervisor-fallback");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let active_bytes = test_agent("2.4.0-beta.7", true, "a");
        let active = release_for_binary(Channel::Beta, "2.4.0-beta.7", &active_bytes);
        let mut corrupted_active = active_bytes;
        *corrupted_active.last_mut().unwrap() = b'y';
        write_release_agent(&manager.paths, Slot::A, &active, &corrupted_active);
        let fallback_bytes = test_agent("2.4.0-beta.8", true, "b");
        let fallback = release_for_binary(Channel::Beta, "2.4.0-beta.8", &fallback_bytes);
        write_release_agent(&manager.paths, Slot::B, &fallback, &fallback_bytes);
        manager.paths.write_active(Slot::A).unwrap();

        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(fs::read_to_string(marker).unwrap(), "b");
        assert_eq!(manager.paths.active_slot(), Some(Slot::B));
    }

    #[test]
    fn supervisor_hash_checks_fresh_bootstrap_copies() {
        let manager = manager("supervisor-bootstrap");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let original = test_agent("2.3.5", true, "a");
        let mut corrupted = original.clone();
        *corrupted.last_mut().unwrap() = b'y';
        fs::write(manager.paths.slot_binary(Slot::A), &corrupted).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::A),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(
            manager.paths.slot_bootstrap_digest(Slot::A),
            format!("{}\n2.3.5\n", sha256(&original)),
        )
        .unwrap();
        let fallback = test_agent("2.3.5", true, "b");
        fs::write(manager.paths.slot_binary(Slot::B), &fallback).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::B),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(
            manager.paths.slot_bootstrap_digest(Slot::B),
            format!("{}\n2.3.5\n", sha256(&fallback)),
        )
        .unwrap();
        manager.paths.write_active(Slot::A).unwrap();

        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(fs::read_to_string(marker).unwrap(), "b");
        assert_eq!(manager.paths.active_slot(), Some(Slot::B));
    }

    #[test]
    fn pending_candidate_is_never_selected_during_boot_recovery() {
        let manager = manager("supervisor-pending");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let candidate_bytes = test_agent("2.4.0-beta.9", true, "candidate");
        let candidate = release_for_binary(Channel::Beta, "2.4.0-beta.9", &candidate_bytes);
        write_release_agent(&manager.paths, Slot::A, &candidate, &candidate_bytes);
        let previous_bytes = test_agent("2.4.0-beta.8", false, "previous");
        let previous = release_for_binary(Channel::Beta, "2.4.0-beta.8", &previous_bytes);
        write_release_agent(&manager.paths, Slot::B, &previous, &previous_bytes);
        let stable_bytes = test_agent("2.3.0", true, "stable");
        let stable = release_for_binary(Channel::Stable, "2.3.0", &stable_bytes);
        fs::write(manager.paths.stable_binary(), &stable_bytes).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable).unwrap();
        manager.paths.write_active(Slot::B).unwrap();
        manager
            .paths
            .write_pending(Slot::A, Slot::B, "2.4.0-beta.9")
            .unwrap();

        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(fs::read_to_string(marker).unwrap(), "stable");
        assert!(!manager.paths.pending.exists());
        assert_eq!(manager.paths.active_slot(), None);
    }

    #[test]
    fn supervisor_never_boots_a_quarantined_candidate() {
        let manager = manager("supervisor-quarantine");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let broken_bytes = test_agent("2.4.0-beta.7", false, "broken");
        let broken = release_for_binary(Channel::Beta, "2.4.0-beta.7", &broken_bytes);
        write_release_agent(&manager.paths, Slot::A, &broken, &broken_bytes);
        let blocked_bytes = test_agent("2.4.0-beta.8", true, "blocked");
        let blocked = release_for_binary(Channel::Beta, "2.4.0-beta.8", &blocked_bytes);
        write_release_agent(&manager.paths, Slot::B, &blocked, &blocked_bytes);
        storage::write_json(&manager.paths.blocked, &vec![blocked.version.clone()]).unwrap();
        let stable_bytes = test_agent("2.3.0", true, "stable");
        let stable = release_for_binary(Channel::Stable, "2.3.0", &stable_bytes);
        fs::write(manager.paths.stable_binary(), &stable_bytes).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable).unwrap();
        manager.paths.write_active(Slot::A).unwrap();

        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();

        assert!(status.success());
        assert_eq!(fs::read_to_string(marker).unwrap(), "stable");
        assert_eq!(manager.paths.active_slot(), None);
    }

    #[test]
    fn supervisor_non_pending_fallback_enforces_same_boot_tailscale_cleanup_gate() {
        let manager = manager("supervisor-fallback-ts-gate");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let ts_journal = manager.paths.root.join("tailscale-network.json");
        let ts_flush_marker = crate::tailscale::netplane::dnat_flush_marker_path(&ts_journal);
        let boot_id_file = manager.paths.root.join("boot_id");
        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();
        fs::write(&boot_id_file, "boot-uuid-123\n").unwrap();

        let slot_a = test_agent("2.4.0-beta.7", true, "a-fallback");
        let rel_a = release_for_binary(Channel::Beta, "2.4.0-beta.7", &slot_a);
        write_release_agent(&manager.paths, Slot::A, &rel_a, &slot_a);

        // 1. Active slot B corrupted (not runnable) with pending absent and a
        //    same-boot Clean DNS flush marker present: fallback to A MUST fail
        //    closed (exit 8) without modifying `active` or launching A.
        let slot_b_orig = test_agent("2.4.0-beta.8", true, "b-active");
        let rel_b = release_for_binary(Channel::Beta, "2.4.0-beta.8", &slot_b_orig);
        let mut slot_b_corrupt = slot_b_orig.clone();
        *slot_b_corrupt.last_mut().unwrap() = b'y';
        write_release_agent(&manager.paths, Slot::B, &rel_b, &slot_b_corrupt);
        manager.paths.write_active(Slot::B).unwrap();
        fs::write(&ts_flush_marker, "boot-uuid-123\n").unwrap();

        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(8),
            "non-pending fallback with same-boot flush marker must refuse slot switch"
        );
        assert_eq!(manager.paths.active_slot(), Some(Slot::B));
        assert!(!marker.exists());
        assert!(ts_flush_marker.exists());

        // 2. Same when only a same-boot journal or live tailscaled exists.
        fs::remove_file(&ts_flush_marker).unwrap();
        fs::write(&ts_journal, "{ \"boot\" : \"boot-uuid-123\" , \"undo\" : [] }\n").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(8));
        assert_eq!(manager.paths.active_slot(), Some(Slot::B));
        assert!(!marker.exists());

        fs::remove_file(&ts_journal).unwrap();
        fs::create_dir_all(fake_proc.join("4242")).unwrap();
        fs::write(fake_proc.join("4242/stat"), "4242 (tailscaled) S 1 1 1 0\n").unwrap();
        fs::write(fake_proc.join("4242/comm"), "tailscaled\n").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(8));
        assert_eq!(manager.paths.active_slot(), Some(Slot::B));
        assert!(!marker.exists());
        fs::remove_dir_all(fake_proc.join("4242")).unwrap();

        // 3. Normal same-slot restart (B runnable, no slot switch) MUST NOT be
        //    blocked by its own same-boot flush marker.
        write_release_agent(&manager.paths, Slot::B, &rel_b, &slot_b_orig);
        fs::write(&ts_flush_marker, "boot-uuid-123\n").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success(), "same-slot restart must not be blocked");
        assert_eq!(fs::read_to_string(&marker).unwrap(), "b-active");
        assert_eq!(manager.paths.active_slot(), Some(Slot::B));
        fs::remove_file(&marker).unwrap();

        // 4. Integrity-verified active slot B quarantined in blocked.json:
        //    - If B's `network-recover` fails or leaves the marker behind, exit 8.
        //    - Once B's `network-recover` clears the marker and exits 0, switch to A.
        storage::write_json(&manager.paths.blocked, &vec!["2.4.0-beta.8".to_string()]).unwrap();
        let b_ignores_marker = pad_script(b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then exit 0; fi\nif [ \"${1:-}\" = network-recover ]; then exit 0; fi\nexit 0\n");
        let rel_b_ign = release_for_binary(Channel::Beta, "2.4.0-beta.8", &b_ignores_marker);
        write_release_agent(&manager.paths, Slot::B, &rel_b_ign, &b_ignores_marker);
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(8));
        assert_eq!(manager.paths.active_slot(), Some(Slot::B));
        assert!(!marker.exists());

        // Even if B's `network-recover` removes the marker before failing with
        // a non-zero exit code (e.g. relay recovery failed after Tailscale
        // cleanup), the supervisor MUST persist `network-recover-pending`
        // BEFORE running B so BOTH this invocation AND a second consecutive
        // invocation (with no fixture reset and all Tailscale markers absent!)
        // still refuse fallback (exit 8) until B's `network-recover` succeeds!
        let recover_pending = manager.paths.root.join("network-recover-pending");
        let recover_calls = manager.paths.root.join("recover-calls");
        let b_partial_fail = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then exit 0; fi\nif [ \"${{1:-}}\" = network-recover ]; then printf 'x' >> \"{}\"; rm -f \"{}\"; exit 1; fi\nexit 0\n",
            recover_calls.display(),
            ts_flush_marker.display()
        ));
        let rel_b_partial = release_for_binary(Channel::Beta, "2.4.0-beta.8", &b_partial_fail);
        write_release_agent(&manager.paths, Slot::B, &rel_b_partial, &b_partial_fail);
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(8));
        assert_eq!(manager.paths.active_slot(), Some(Slot::B));
        assert!(!marker.exists());
        assert!(!ts_flush_marker.exists(), "B already deleted flush marker before exiting 1");
        assert!(recover_pending.exists(), "same-boot recovery obligation must persist across failure");
        assert_eq!(fs::read_to_string(&recover_calls).unwrap(), "x");

        // Second consecutive invocation WITHOUT resetting the fixture: all
        // Tailscale markers and daemon are gone, yet `network-recover-pending`
        // MUST keep blocking fallback and re-invoking B's `network-recover`!
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(8),
            "retry after failed recovery must not forget pending recovery obligation"
        );
        assert_eq!(manager.paths.active_slot(), Some(Slot::B));
        assert!(!marker.exists());
        assert!(recover_pending.exists());
        assert_eq!(fs::read_to_string(&recover_calls).unwrap(), "xx");

        // Once B's `network-recover` finally succeeds (still without recreating
        // `ts_flush_marker`), the supervisor invokes it, clears
        // `network-recover-pending`, and switches cleanly to A.
        let b_clears_marker = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then exit 0; fi\nif [ \"${{1:-}}\" = network-recover ]; then printf 'ok' >> \"{}\"; rm -f \"{}\"; exit 0; fi\nexit 0\n",
            recover_calls.display(),
            ts_flush_marker.display()
        ));
        let rel_b_ok = release_for_binary(Channel::Beta, "2.4.0-beta.8", &b_clears_marker);
        write_release_agent(&manager.paths, Slot::B, &rel_b_ok, &b_clears_marker);
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success(), "fallback to A should proceed once B completes recovery");
        assert!(!ts_flush_marker.exists());
        assert!(!recover_pending.exists(), "recovery-pending marker must be cleared on success");
        assert_eq!(fs::read_to_string(&recover_calls).unwrap(), "xxok");
        assert_eq!(manager.paths.active_slot(), Some(Slot::A));
        assert_eq!(fs::read_to_string(&marker).unwrap(), "a-fallback");
        fs::remove_file(&marker).unwrap();

        // 5. Malformed flush markers (internally spaced, multi-line, control
        //    char, non-UTF-8, NUL) MUST ALL fail closed (exit 8) in the shell
        //    predicate instead of being stripped/classified as a stale boot!
        write_release_agent(&manager.paths, Slot::B, &rel_b, &slot_b_corrupt);
        manager.paths.write_active(Slot::B).unwrap();
        for bad_marker in [
            b"boot-uuid 456\n".as_slice(),
            b"boot-uuid\n456\n".as_slice(),
            b"boot-uuid\x0c\n".as_slice(),
            b"boot-uuid\xff\n".as_slice(),
            b"boot-uuid\0\n".as_slice(),
        ] {
            fs::write(&ts_flush_marker, bad_marker).unwrap();
            let status = Command::new("sh")
                .arg(&manager.paths.supervisor)
                .env("ZTE_OTA_ROOT", &manager.paths.root)
                .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
                .env("ZTE_TEST_MARKER", &marker)
                .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
                .env("ZTE_BOOT_ID_PATH", &boot_id_file)
                .env("ZTE_PROC_ROOT", &fake_proc)
                .status()
                .unwrap();
            assert_eq!(
                status.code(),
                Some(8),
                "malformed flush marker {:?} must fail closed in shell supervisor",
                String::from_utf8_lossy(bad_marker)
            );
            assert_eq!(manager.paths.active_slot(), Some(Slot::B));
            assert!(!marker.exists());
        }

        // 6. After reboot (new boot_id), stale prior-boot flush & recovery
        //    markers no longer block fallback from corrupted B to A.
        fs::write(&ts_flush_marker, "boot-uuid-123\n").unwrap();
        fs::write(&recover_pending, "boot-uuid-123\n").unwrap();
        fs::write(&boot_id_file, "boot-uuid-456\n").unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success(), "stale prior-boot markers must not block post-reboot fallback");
        assert!(!recover_pending.exists(), "stale prior-boot recovery-pending marker should be removed");
        assert_eq!(manager.paths.active_slot(), Some(Slot::A));
        assert_eq!(fs::read_to_string(&marker).unwrap(), "a-fallback");
    }

    #[test]
    fn failed_candidate_recovery_uses_only_a_verified_stable_rescue() {
        let manager = manager("helper-stable-rescue");
        let previous_bytes = test_agent(crate::build_info::VERSION, false, "previous");
        let previous =
            release_for_binary(Channel::Stable, crate::build_info::VERSION, &previous_bytes);
        write_release_agent(&manager.paths, Slot::B, &previous, &previous_bytes);
        let stable_bytes = test_agent("2.3.0", true, "stable");
        let stable = release_for_binary(Channel::Stable, "2.3.0", &stable_bytes);
        fs::write(manager.paths.stable_binary(), &stable_bytes).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable).unwrap();

        let rescue_perf = crate::netfx::perf::Perf::for_test(&manager.paths.root.join("perf-rescue"));
        assert_eq!(recover_with_perf(&manager.paths, Slot::B, None, None, &rescue_perf), 6);
        assert_eq!(manager.paths.active_slot(), None);
        assert_eq!(
            fs::read_link(&manager.paths.legacy_link).unwrap(),
            manager.paths.stable_binary()
        );
    }

    #[test]
    fn trial_gate_stays_closed_until_helper_exits_active_matches_dir_syncs_and_supervisor_repairs() {
        let manager = manager("trial-parent-gate");
        let confirmed = AtomicBool::new(false);
        let sup_confirmed = AtomicBool::new(false);
        assert!(!manager.paths.pending.exists());

        // 1. Helper still alive as direct parent even after `pending` unlinked.
        assert!(
            slot_change_pending_with(
                &manager.paths,
                true,
                Some(4242),
                4242,
                &confirmed,
                &sup_confirmed,
                || Some(Slot::B),
                |_| Ok(()),
                |_| Ok(()),
            ),
            "trial gate must stay closed while spawning ota-helper is still parent"
        );
        assert!(!confirmed.load(Ordering::Acquire));

        // 2. Helper died abnormally (reparented to PID 1) after unlinking
        //    `pending`, BEFORE `active` was updated to candidate slot B.
        manager.paths.write_active(Slot::A).unwrap();
        assert!(
            slot_change_pending_with(
                &manager.paths,
                true,
                Some(4242),
                1,
                &confirmed,
                &sup_confirmed,
                || Some(Slot::B),
                |_| Ok(()),
                |_| Ok(()),
            ),
            "trial gate must stay closed when reparented before active names this slot"
        );
        assert!(!confirmed.load(Ordering::Acquire));

        // 3. `active` now names slot B, but OTA directory sync fails (simulating
        //    abnormal legacy helper exit before `sync_parent()` on faulted flash).
        manager.paths.write_active(Slot::B).unwrap();
        let sync_attempts = std::cell::Cell::new(0usize);
        assert!(
            slot_change_pending_with(
                &manager.paths,
                true,
                Some(4242),
                1,
                &confirmed,
                &sup_confirmed,
                || Some(Slot::B),
                |_| {
                    sync_attempts.set(sync_attempts.get() + 1);
                    Err(std::io::Error::other("simulated dir fsync failure"))
                },
                |_| Ok(()),
            ),
            "trial gate must stay closed if candidate cannot durably sync OTA directory"
        );
        assert_eq!(sync_attempts.get(), 1);
        assert!(!confirmed.load(Ordering::Acquire));

        // 4. Directory sync succeeds, but supervisor repair fails transiently.
        assert!(
            slot_change_pending_with(
                &manager.paths,
                true,
                Some(4242),
                1,
                &confirmed,
                &sup_confirmed,
                || Some(Slot::B),
                sync_ota_dir,
                |_| Err(std::io::Error::other("transient supervisor write failure")),
            ),
            "trial gate must stay closed until boot supervisor repair succeeds"
        );
        assert!(!confirmed.load(Ordering::Acquire));

        // 5. Reparented + `active` matches slot B + real directory fsync succeeds
        //    + real `ensure_supervisor` succeeds -> gate opens and caches commit.
        assert!(
            !slot_change_pending_with(
                &manager.paths,
                true,
                Some(4242),
                1,
                &confirmed,
                &sup_confirmed,
                || Some(Slot::B),
                sync_ota_dir,
                ensure_supervisor,
            ),
            "trial gate must open once active, dir fsync, and supervisor repair all succeed"
        );
        assert!(confirmed.load(Ordering::Acquire));
        assert!(sup_confirmed.load(Ordering::Acquire));
        assert_eq!(fs::read(&manager.paths.supervisor).unwrap(), SUPERVISOR_SCRIPT);

        // 6. Same-boot `rollback-blocked` still closes gate even after initial
        //    trial commit confirmation; malformed fails closed; prior-boot opens.
        let blocked = manager.paths.root.join("rollback-blocked");
        fs::write(&blocked, format!("{}\n", crate::net_tools::boot_id())).unwrap();
        assert!(slot_change_pending_with(
            &manager.paths,
            true,
            Some(4242),
            1,
            &confirmed,
            &sup_confirmed,
            || Some(Slot::B),
            sync_ota_dir,
            ensure_supervisor,
        ));
        fs::write(&blocked, b"bad boot\x0c\n").unwrap();
        assert!(slot_change_pending_with(
            &manager.paths,
            false,
            None,
            1,
            &confirmed,
            &sup_confirmed,
            || None,
            sync_ota_dir,
            ensure_supervisor,
        ));
        fs::write(&blocked, "prior-boot-id\n").unwrap();
        assert!(!slot_change_pending_with(
            &manager.paths,
            false,
            None,
            1,
            &confirmed,
            &sup_confirmed,
            || None,
            sync_ota_dir,
            ensure_supervisor,
        ));
    }

    #[test]
    fn ensure_supervisor_retry_still_requires_parent_directory_sync_and_non_trial_gate_waits() {
        let manager = manager("supervisor-parent-sync-retry");

        // 1. First write renames the new supervisor into place, then parent
        //    directory sync fails -> returns Err even though VFS bytes match.
        let err = ensure_supervisor_with(&manager.paths, |_| {
            Err(std::io::Error::other("simulated parent dir fsync failure"))
        })
        .unwrap_err();
        assert!(err.to_string().contains("fsync failure"));
        assert_eq!(fs::read(&manager.paths.supervisor).unwrap(), SUPERVISOR_SCRIPT);
        assert!(storage::executable(&manager.paths.supervisor));

        // 2. Retry on the matching VFS file MUST NOT short-circuit before the
        //    parent directory sync succeeds.
        assert!(
            ensure_supervisor_with(&manager.paths, |_| {
                Err(std::io::Error::other("parent dir fsync still failing"))
            })
            .is_err(),
            "ensure_supervisor retry must still require parent-directory sync"
        );

        // 3. Ordinary non-trial restart (`is_trial = false`, no `pending`, no
        //    `rollback-blocked`) keeps the network gate closed until supervisor
        //    repair + parent sync succeeds.
        let trial_confirmed = AtomicBool::new(false);
        let sup_confirmed = AtomicBool::new(false);
        assert!(
            slot_change_pending_with(
                &manager.paths,
                false,
                None,
                1,
                &trial_confirmed,
                &sup_confirmed,
                || None,
                sync_ota_dir,
                |p| {
                    ensure_supervisor_with(p, |_| {
                        Err(std::io::Error::other("still unsynced"))
                    })
                },
            ),
            "non-trial startup must keep network gate closed while supervisor repair fails"
        );
        assert!(!sup_confirmed.load(Ordering::Acquire));

        // 4. Once parent-directory sync succeeds, gate opens and caches success.
        assert!(
            !slot_change_pending_with(
                &manager.paths,
                false,
                None,
                1,
                &trial_confirmed,
                &sup_confirmed,
                || None,
                sync_ota_dir,
                ensure_supervisor,
            ),
            "non-trial network gate must open once supervisor repair and parent sync succeed"
        );
        assert!(sup_confirmed.load(Ordering::Acquire));
    }

    #[test]
    fn delayed_trial_finalization_retries_past_12_checks_and_transient_supervisor_failures() {
        let manager = manager("trial-finalize-retry");
        manager.paths.write_active(Slot::B).unwrap();
        let promoted_manifest = release(Channel::Beta, "2.5.0-beta.1");
        manager.change(|state| {
            state.persistent.phase = Phase::Installing;
            state.persistent.staged = Some(promoted_manifest.clone());
            state.persistent.staged_slot = Some("b".into());
            state.persistent.available = Some(promoted_manifest.clone());
        });
        let mut last_error = None;

        // 15 consecutive pending ticks (past the old 12-iteration cap) must keep
        // returning false without clearing trial state.
        for _ in 0..15 {
            assert!(!finalize_trial_once(
                &manager,
                || true,
                ensure_supervisor,
                &mut last_error,
            ));
            assert_eq!(
                manager.state.lock().unwrap().persistent.phase,
                Phase::Installing
            );
        }

        // Transient `ensure_supervisor` failure must NOT clear trial state.
        assert!(!finalize_trial_once(
            &manager,
            || false,
            |_| Err(std::io::Error::other("read-only /data/local/tmp")),
            &mut last_error,
        ));
        assert_eq!(
            manager.state.lock().unwrap().persistent.phase,
            Phase::Installing
        );
        assert!(last_error.is_some());

        // While an OTA operation holds `manager.operation`, finalization defers
        // instead of racing it.
        manager.operation.store(true, Ordering::Release);
        assert!(!finalize_trial_once(
            &manager,
            || false,
            ensure_supervisor,
            &mut last_error,
        ));
        manager.operation.store(false, Ordering::Release);

        // Subsequent retry where `ensure_supervisor` succeeds repairs the
        // supervisor and clears ONLY the completed trial state to Idle.
        assert!(finalize_trial_once(
            &manager,
            || false,
            ensure_supervisor,
            &mut last_error,
        ));
        assert_eq!(manager.state.lock().unwrap().persistent.phase, Phase::Idle);
        assert_eq!(manager.state.lock().unwrap().persistent.staged, None);
        assert_eq!(manager.state.lock().unwrap().persistent.staged_slot, None);
        assert_eq!(manager.state.lock().unwrap().persistent.available, None);
        assert_eq!(fs::read(&manager.paths.supervisor).unwrap(), SUPERVISOR_SCRIPT);

        // If a subsequent check/download already staged a newer update in the
        // inactive slot (slot A, while active is B) before the finalizer wakes,
        // finalization MUST NOT erase `available`, `staged`, or `staged_slot`.
        let next_manifest = release(Channel::Beta, "2.5.0-beta.2");
        manager.change(|state| {
            state.persistent.phase = Phase::Staged;
            state.persistent.available = Some(next_manifest.clone());
            state.persistent.staged = Some(next_manifest.clone());
            state.persistent.staged_slot = Some("a".into());
        });
        assert!(finalize_trial_once(
            &manager,
            || false,
            ensure_supervisor,
            &mut last_error,
        ));
        let persistent = manager.state.lock().unwrap().persistent.clone();
        assert_eq!(persistent.phase, Phase::Staged);
        assert_eq!(persistent.available, Some(next_manifest.clone()));
        assert_eq!(persistent.staged, Some(next_manifest.clone()));
        assert_eq!(persistent.staged_slot.as_deref(), Some("a"));

        // If a new install creates `pending` and releases `manager.operation`
        // (e.g., during its 1.2s exit delay) AFTER the finalizer's pre-lock
        // `is_pending()` returned `false`, re-checking `is_pending()` UNDER the
        // operation guard MUST prevent rewriting the new `Installing` phase!
        manager.change(|state| {
            state.persistent.phase = Phase::Installing;
            state.persistent.staged = Some(next_manifest.clone());
            state.persistent.staged_slot = Some("a".into());
        });
        let calls = std::cell::Cell::new(0usize);
        assert!(!finalize_trial_once(
            &manager,
            || {
                let n = calls.get();
                calls.set(n + 1);
                n > 0 // false pre-lock, true once re-checked under `manager.operation`
            },
            ensure_supervisor,
            &mut last_error,
        ));
        assert_eq!(calls.get(), 2);
        assert_eq!(
            manager.state.lock().unwrap().persistent.phase,
            Phase::Installing,
            "old finalizer must not rewrite a newly admitted install's Installing phase"
        );
    }

    #[test]
    fn downloads_and_auto_downloads_are_blocked_during_slot_change_or_trial() {
        let manager = manager("download-blocked-during-trial");
        manager.paths.write_active(Slot::A).unwrap();
        let trial_b_bytes = test_agent("2.5.0-beta.1", true, "trial-b");
        let trial_b_rel = release_for_binary(Channel::Beta, "2.5.0-beta.1", &trial_b_bytes);
        write_release_agent(&manager.paths, Slot::B, &trial_b_rel, &trial_b_bytes);

        let newer_bytes = test_agent("2.5.0-beta.2", true, "newer-b");
        let newer_rel = release_for_binary(Channel::Beta, "2.5.0-beta.2", &newer_bytes);
        manager
            .update_settings(
                br#"{"channel":"beta","automatic_checks":true,"automatic_downloads":true}"#,
            )
            .unwrap();
        manager.change(|state| {
            state.persistent.phase = Phase::Installing;
            state.persistent.available = Some(newer_rel.clone());
            state.persistent.staged = Some(trial_b_rel.clone());
            state.persistent.staged_slot = Some("b".into());
        });

        // 1. Manual download blocked while `pending` exists.
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.5.0-beta.1")
            .unwrap();
        assert!(manager.download().is_err());
        assert_eq!(fs::read(manager.paths.slot_binary(Slot::B)).unwrap(), trial_b_bytes);
        assert_eq!(manager.state.lock().unwrap().persistent.phase, Phase::Installing);

        // 1b. Switching release channel during a live trial MUST be rejected so
        //     `phase`, `staged`, and `staged_slot` are not cleared to Idle.
        let ch_err = manager
            .update_settings(
                br#"{"channel":"stable","automatic_checks":true,"automatic_downloads":true}"#,
            )
            .unwrap_err();
        assert!(ch_err.contains("cannot change update channel"));
        assert_eq!(manager.settings().channel, Channel::Beta);
        {
            let p = &manager.state.lock().unwrap().persistent;
            assert_eq!(p.phase, Phase::Installing);
            assert_eq!(p.staged_slot.as_deref(), Some("b"));
        }

        // 2. Automatic download via `check_with` also blocked while `pending` exists,
        //    and a FAILED manual check preserves the live trial phase (`Installing`
        //    or `RollingBack`) on disk instead of persisting `Checking`/`Failed`.
        let newer_for_check = newer_rel.clone();
        manager.check_with(|| Ok(Some(newer_for_check))).unwrap();
        assert_eq!(fs::read(manager.paths.slot_binary(Slot::B)).unwrap(), trial_b_bytes);
        assert_eq!(
            storage::read_json::<ReleaseManifest>(&manager.paths.slot_meta(Slot::B))
                .unwrap()
                .version,
            "2.5.0-beta.1"
        );
        assert_eq!(manager.state.lock().unwrap().persistent.phase, Phase::Installing);

        for live_phase in [Phase::Installing, Phase::RollingBack] {
            manager.change(|state| state.persistent.phase = live_phase);
            let err = manager
                .check_with(|| Err("simulated network timeout".into()))
                .unwrap_err();
            assert!(err.contains("network timeout"));
            assert_eq!(
                manager.state.lock().unwrap().persistent.phase,
                live_phase,
                "failed check during trial must preserve {live_phase:?} in memory"
            );
            assert_eq!(
                storage::read_json::<PersistentState>(&manager.paths.state)
                    .unwrap()
                    .phase,
                live_phase,
                "failed check during trial must preserve {live_phase:?} on disk"
            );
        }

        // 3. Even after `pending` is unlinked, if the full slot-change condition
        //    is still blocked (same-boot `rollback-blocked` or active helper),
        //    BOTH manual and automatic downloads must still be refused.
        manager.paths.clear_pending().unwrap();
        manager.test_slot_change_blocked.store(true, Ordering::Release);
        assert!(manager.download().is_err());
        let newer_for_check2 = newer_rel.clone();
        manager.check_with(|| Ok(Some(newer_for_check2))).unwrap();
        assert_eq!(fs::read(manager.paths.slot_binary(Slot::B)).unwrap(), trial_b_bytes);
        assert_eq!(
            storage::read_json::<ReleaseManifest>(&manager.paths.slot_meta(Slot::B))
                .unwrap()
                .version,
            "2.5.0-beta.1"
        );
    }

    #[test]
    fn pinned_trial_promotion_stops_paused_legacy_downloader_before_commit_and_respawns_active() {
        let manager = manager("pinned-trial-promotion");
        manager.paths.write_active(Slot::A).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0")
            .unwrap();
        // Old readable `state.json` (simulating legacy downloader whose
        // `Phase::Downloading` journal write failed silently!).
        storage::write_json(&manager.paths.state, &PersistentState::default()).unwrap();

        let promoted_marker = manager.paths.root.join("promoted-started");
        let paused_ready = manager.paths.root.join("legacy-downloader-paused");
        let orig_b_script = format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then exit 0; fi\nprintf '%s:%s' \"$(cat \"{}\")\" \"${{ZTE_OTA_TRIAL:-}}\" > \"{}\"\n",
            manager.paths.active.display(),
            promoted_marker.display()
        );
        let mut orig_b_bytes = orig_b_script.into_bytes();
        orig_b_bytes.push(b'#');
        orig_b_bytes.resize(1024, b'x');
        let orig_b_rel = release_for_binary(Channel::Stable, "2.4.0", &orig_b_bytes);
        write_release_agent(&manager.paths, Slot::B, &orig_b_rel, &orig_b_bytes);
        let _pinned = pin_candidate(&manager.paths, Slot::B, "2.4.0").unwrap();

        // Spawn a real child simulating a legacy downloader that:
        //  1) Reads `active` (sees `a`, so selects `slot=b` in memory),
        //  2) Leaves `state.json` untouched (failed `Phase::Downloading` write),
        //  3) Signals it is paused right between slot selection and creating
        //     `slot-b/zte-agent.download`,
        //  4) After 300ms, if still alive, creates `.download` and renames a
        //     tampered binary over `slot-b/zte-agent`!
        let legacy_downloader = format!(
            "#!/bin/sh\nactive=$(cat \"{}\")\nif [ \"$active\" = a ]; then target=\"{}\"; dl=\"{}\"; else exit 0; fi\nprintf 'paused' > \"{}\"\nsleep 0.3\nprintf 'tampered' > \"$dl\"\nmv -f \"$dl\" \"$target\"\n",
            manager.paths.active.display(),
            manager.paths.slot_binary(Slot::B).display(),
            manager.paths.slot_download(Slot::B).display(),
            paused_ready.display(),
        );
        let mut trial_child = Command::new("sh")
            .arg("-c")
            .arg(&legacy_downloader)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && !paused_ready.exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(paused_ready.exists(), "simulated legacy downloader must reach paused window");

        // Promote while the legacy downloader is paused right between slot
        // selection and creating `zte-agent.download`: `stop_trial_child` MUST
        // kill & reap it before commit, verify pinned identity, write `active=b`
        // + reconciled state while KEEPING `pending` and `rollback-blocked` on
        // disk AND spawning the promoted child with `configure_handoff_child_env`
        // (NO `ZTE_OTA_TRIAL=1`, legacy `ensure_supervisor` redirected to shadow,
        // real supervisor carried in `ZTE_OTA_REAL_SUPERVISOR`).
        //
        // Model a faithful `965ebfe` promoted child through:
        //  1) Startup `ensure_supervisor` writing to `$ZTE_OTA_SUPERVISOR`
        //  2) Delayed `ota-trial-state` finalizer tick (if `ZTE_OTA_TRIAL=1`,
        //     wipes `state.json` after `pending` disappears!)
        //  3) Subsequent child spawn (`guard` / next `ota-helper`) inheriting env
        //  4) Real TCP listener bind for `wait_for_child_listener`
        ensure_supervisor(&manager.paths).unwrap();
        let hardened_supervisor = fs::read(&manager.paths.supervisor).unwrap();
        let next_spawn_env = manager.paths.root.join("legacy-next-spawn.env");
        let finalizer_done = manager.paths.root.join("legacy-finalizer-done");
        let staged_after_promote_flag = manager.paths.root.join("staged-after-promote");
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = reserve.local_addr().unwrap();
        drop(reserve);

        let legacy_promoted_script = format!(
            concat!(
                "#!/bin/sh\n",
                "if [ \"${{1:-}}\" = ota-probe ]; then exit 0; fi\n",
                "sup=\"${{ZTE_OTA_SUPERVISOR:-/data/local/tmp/zte-agent-supervisor.sh}}\"\n",
                "if [ \"${{ZTE_OTA_TRIAL:-}}\" != \"1\" ]; then\n",
                "  printf 'legacy-supervisor\\n' > \"$sup\"\n",
                "  chmod 755 \"$sup\"\n",
                "fi\n",
                "printf '%s:%s:%s' \"$(cat \"{}\")\" \"${{ZTE_OTA_TRIAL:-}}\" \"${{ZTE_OTA_PROMOTED:-}}\" > \"{}\"\n",
                "# Simulate legacy guard / next ota-helper inheriting environment\n",
                "sh -c 'printf \"%s|%s|%s|%s\" \"${{ZTE_OTA_TRIAL:-}}\" \"${{ZTE_OTA_PROMOTED:-}}\" \"${{ZTE_OTA_SUPERVISOR:-}}\" \"${{ZTE_OTA_REAL_SUPERVISOR:-}}\" > \"{}\"' &\n",
                "# Simulate 965ebfe ota-trial-state finalizer tick once pending clears & a download was staged\n",
                "(\n",
                "  i=0\n",
                "  while [ ! -f \"{}\" ] && [ \"$i\" -lt 100 ]; do sleep 0.05; i=$((i+1)); done\n",
                "  if [ \"${{ZTE_OTA_TRIAL:-}}\" = \"1\" ] && [ ! -e \"{}\" ]; then\n",
                "    printf '{{\"phase\":\"idle\",\"staged\":null}}' > \"{}\"\n",
                "  fi\n",
                "  printf 'done' > \"{}\"\n",
                ") &\n",
                "exec python3 -c \"import socket, sys, time; s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', int(sys.argv[1]))); s.listen(4); time.sleep(5)\" \"{}\"\n"
            ),
            manager.paths.active.display(),
            promoted_marker.display(),
            next_spawn_env.display(),
            staged_after_promote_flag.display(),
            manager.paths.pending.display(),
            manager.paths.state.display(),
            finalizer_done.display(),
            listen_addr.port(),
        );
        let mut legacy_promoted_bytes = legacy_promoted_script.into_bytes();
        if legacy_promoted_bytes.len() < 1024 {
            legacy_promoted_bytes.push(b'#');
            legacy_promoted_bytes.resize(1024, b'x');
        }
        let legacy_promoted_rel =
            release_for_binary(Channel::Stable, "2.4.0", &legacy_promoted_bytes);
        write_release_agent(
            &manager.paths,
            Slot::B,
            &legacy_promoted_rel,
            &legacy_promoted_bytes,
        );
        let pinned = pin_candidate(&manager.paths, Slot::B, "2.4.0").unwrap();

        let bin_path = manager.paths.slot_binary(Slot::B);
        let events = std::cell::RefCell::new(Vec::new());
        let promoted_pid = std::cell::Cell::new(0u32);
        promote_pinned_trial_with(
            || {
                let _ = trial_child.kill();
                let _ = trial_child.wait();
            },
            || verify_candidate_unmodified(&manager.paths, Slot::B, &pinned),
            || {
                let _ = fs::remove_file(manager.paths.slot_download(Slot::B));
                let _ = fs::remove_file(manager.paths.slot_meta_download(Slot::B));
            },
            || manager.paths.write_active(Slot::B),
            || manager.paths.point_legacy_link(Slot::B),
            || reconcile_state_for_promotion(&manager.paths, Slot::B),
            || {
                assert!(
                    manager.paths.pending.exists(),
                    "pending marker must still exist when spawning promoted candidate"
                );
                let mut cmd = Command::new(&bin_path);
                configure_handoff_child_env(&mut cmd, &manager.paths);
                let child = cmd.spawn()?;
                promoted_pid.set(child.id());
                Ok(child)
            },
            |promoted| {
                assert!(
                    manager.paths.pending.exists(),
                    "pending marker must remain on disk while waiting for promoted readiness"
                );
                let res =
                    wait_for_child_listener(promoted, listen_addr, Duration::from_secs(5));
                assert_eq!(
                    fs::read(&manager.paths.supervisor).unwrap(),
                    hardened_supervisor,
                    "hardened boot supervisor must remain untouched by legacy startup ensure_supervisor"
                );
                assert_eq!(
                    fs::read_to_string(manager.paths.legacy_supervisor_shadow()).unwrap(),
                    "legacy-supervisor\n",
                    "legacy ensure_supervisor write must land in private shadow file"
                );
                events.borrow_mut().push("listener-ready");
                res
            },
            |promoted| {
                let _ = promoted.kill();
                let _ = promoted.wait();
            },
            || {
                events.borrow_mut().push("clear-pending");
                manager.paths.clear_pending()
            },
            || {
                events.borrow_mut().push("clear-rollback-blocked");
                clear_rollback_blocked_marker(&manager.paths)
            },
            || manager.paths.pending.try_exists().unwrap_or(false),
            || manager.paths.write_pending(Slot::B, Slot::A, "2.4.0"),
            || {
                events.borrow_mut().push("refresh-stable");
                copy_pinned_stable(&manager.paths, &pinned).unwrap();
            },
        )
        .unwrap();
        assert_eq!(
            *events.borrow(),
            vec![
                "listener-ready",
                "clear-rollback-blocked",
                "clear-pending",
                "refresh-stable"
            ]
        );

        // Immediately after promotion commits, simulate a user staging a new
        // download into `state.json`, then wait for the legacy child's
        // simulated 60s finalizer tick to finish: because `ZTE_OTA_TRIAL` was
        // NOT passed, the staged download MUST survive untouched!
        let next_staged = PersistentState {
            phase: Phase::Staged,
            staged: Some(release(Channel::Stable, "2.5.0")),
            staged_slot: Some("a".into()),
            available: Some(release(Channel::Stable, "2.5.0")),
            last_error: None,
            ..PersistentState::default()
        };
        storage::write_json(&manager.paths.state, &next_staged).unwrap();
        fs::write(&staged_after_promote_flag, "1").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && (!finalizer_done.exists() || !next_spawn_env.exists()) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(finalizer_done.exists(), "simulated legacy finalizer tick must complete");
        if promoted_pid.get() > 1 {
            // SAFETY: terminate our test's spawned python3 listener cleanly.
            unsafe {
                libc::kill(promoted_pid.get() as libc::pid_t, libc::SIGKILL);
            }
        }
        let persisted_after_tick: PersistentState =
            storage::read_json(&manager.paths.state).unwrap();
        assert_eq!(
            persisted_after_tick.phase,
            Phase::Staged,
            "promoted legacy 965ebfe child must not run ota-trial-state and wipe staged downloads"
        );
        assert_eq!(
            persisted_after_tick.staged.as_ref().map(|r| r.version.as_str()),
            Some("2.5.0")
        );
        assert_eq!(
            fs::read_to_string(&next_spawn_env).unwrap(),
            format!(
                "||{}|{}",
                manager.paths.legacy_supervisor_shadow().display(),
                manager.paths.supervisor.display()
            ),
            "legacy child's guard/helper spawns must not inherit ZTE_OTA_TRIAL or ZTE_OTA_PROMOTED while preserving ZTE_OTA_REAL_SUPERVISOR"
        );

        // Wait past the killed child's 300ms tamper window and verify slot B
        // remained untouched and the fresh promoted agent saw `active=b` with no trial flags.
        std::thread::sleep(Duration::from_millis(450));
        assert_eq!(
            fs::read(manager.paths.slot_binary(Slot::B)).unwrap(),
            legacy_promoted_bytes
        );
        assert!(!manager.paths.slot_download(Slot::B).exists());
        assert_eq!(manager.paths.active_slot(), Some(Slot::B));
        assert!(!manager.paths.pending.exists());
        assert_eq!(
            fs::read_to_string(&promoted_marker).unwrap(),
            "b::",
            "promoted agent must start with active=b and no ZTE_OTA_TRIAL/ZTE_OTA_PROMOTED"
        );
        assert_eq!(
            fs::read(&manager.paths.supervisor).unwrap(),
            hardened_supervisor
        );

        // Confirm an early exit before listener bind (e.g. failed auth/perf
        // startup before `guard::spawn()`) fails promotion as `SpawnFailed`,
        // NEVER clears `pending`, and does NOT overwrite `last-stable`.
        let mut refreshed_on_early_exit = false;
        let mut cleared_on_early_exit = false;
        let unused_reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let unused_addr = unused_reserve.local_addr().unwrap();
        drop(unused_reserve);
        assert!(matches!(
            promote_pinned_trial_with(
                || {},
                || Ok(()),
                || {},
                || Ok(()),
                || Ok(()),
                || Ok(()),
                || Command::new("sh").arg("-c").arg("exit 1").spawn(),
                |promoted| wait_for_child_listener(
                    promoted,
                    unused_addr,
                    Duration::from_secs(3)
                ),
                |promoted| {
                    let _ = promoted.kill();
                    let _ = promoted.wait();
                },
                || {
                    cleared_on_early_exit = true;
                    Ok(())
                },
                || Ok(()),
                || true,
                || Ok(()),
                || {
                    refreshed_on_early_exit = true;
                },
            ),
            Err(PromotionFailure::SpawnFailed(_))
        ));
        assert!(!cleared_on_early_exit, "pending must stay on disk when promoted child exits early");
        assert!(
            !refreshed_on_early_exit,
            "last-stable must not be refreshed when promoted child exits before binding listener"
        );

        // Confirm an UNRELATED listener already occupying the configured port
        // does NOT satisfy `wait_for_child_listener` for a stalled child!
        let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied_addr = squatter.local_addr().unwrap();
        let mut refreshed_on_occupied = false;
        let mut cleared_on_occupied = false;
        let mut stalled_reaped = false;
        assert!(matches!(
            promote_pinned_trial_with(
                || {},
                || Ok(()),
                || {},
                || Ok(()),
                || Ok(()),
                || Ok(()),
                || Command::new("sh").arg("-c").arg("sleep 30").spawn(),
                |promoted| {
                    let res = wait_for_child_listener(
                        promoted,
                        occupied_addr,
                        Duration::from_millis(450),
                    );
                    stalled_reaped = promoted.try_wait().ok().flatten().is_some();
                    res
                },
                |promoted| {
                    let _ = promoted.kill();
                    let _ = promoted.wait();
                },
                || {
                    cleared_on_occupied = true;
                    Ok(())
                },
                || Ok(()),
                || true,
                || Ok(()),
                || {
                    refreshed_on_occupied = true;
                },
            ),
            Err(PromotionFailure::SpawnFailed(_))
        ));
        drop(squatter);
        assert!(stalled_reaped, "stalled promoted child must be killed and reaped");
        assert!(
            !cleared_on_occupied && !refreshed_on_occupied,
            "unrelated listener occupying the port must never satisfy child readiness"
        );

        // Confirm that when `clear_pending` unlinks `pending` then fails
        // `sync_parent`, `restore_pending` runs BEFORE `stop_promoted` so the
        // child's guard observes `pending` on disk and does NOT wake up to
        // launch a racing supervisor!
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0")
            .unwrap();
        let clear_events = std::cell::RefCell::new(Vec::new());
        let mut refreshed_on_clear_err = false;
        assert!(matches!(
            promote_pinned_trial_with(
                || {},
                || Ok(()),
                || {},
                || Ok(()),
                || Ok(()),
                || Ok(()),
                || Ok(()),
                |_| Ok(()),
                |_| {
                    assert!(
                        manager.paths.pending.exists(),
                        "pending MUST be restored on disk BEFORE killing the guarded promoted child"
                    );
                    clear_events.borrow_mut().push("stop-promoted");
                },
                || {
                    clear_events.borrow_mut().push("clear-pending-unlink-then-fail");
                    let _ = fs::remove_file(&manager.paths.pending);
                    Err(std::io::Error::other("simulated sync_parent failure after unlink"))
                },
                || Ok(()),
                || manager.paths.pending.try_exists().unwrap_or(false),
                || {
                    clear_events.borrow_mut().push("restore-pending");
                    manager.paths.write_pending(Slot::B, Slot::A, "2.4.0")
                },
                || {
                    refreshed_on_clear_err = true;
                },
            ),
            Err(PromotionFailure::CommitIo(_))
        ));
        assert!(!refreshed_on_clear_err);
        assert_eq!(
            *clear_events.borrow(),
            vec![
                "clear-pending-unlink-then-fail",
                "restore-pending",
                "stop-promoted"
            ]
        );

        // If `clear_pending` unlinked `pending` then failed `sync_parent` AND
        // `restore_pending` ALSO fails, `promote_pinned_trial_with` MUST NOT
        // kill the already-verified live child (returning `PendingRestoreFailed`).
        let mut stopped_on_restore_fail = false;
        assert!(matches!(
            promote_pinned_trial_with(
                || {},
                || Ok(()),
                || {},
                || Ok(()),
                || Ok(()),
                || Ok(()),
                || Ok(()),
                |_| Ok(()),
                |_| {
                    stopped_on_restore_fail = true;
                },
                || {
                    let _ = fs::remove_file(&manager.paths.pending);
                    Err(std::io::Error::other("simulated sync_parent failure after unlink"))
                },
                || Ok(()),
                || manager.paths.pending.try_exists().unwrap_or(false),
                || Err(std::io::Error::other("simulated restore_pending failure")),
                || {},
            ),
            Err(PromotionFailure::PendingRestoreFailed(_))
        ));
        assert!(
            !stopped_on_restore_fail,
            "must not kill already-verified live child when pending cannot be restored"
        );

        // Also confirm modifying slot B before `stop_trial_child` is caught as SlotModified.
        let replaced_b = test_agent("2.5.0", true, "replaced-b");
        let replaced_rel = release_for_binary(Channel::Stable, "2.5.0", &replaced_b);
        write_release_agent(&manager.paths, Slot::B, &replaced_rel, &replaced_b);
        assert!(matches!(
            promote_pinned_trial_with(
                || {},
                || verify_candidate_unmodified(&manager.paths, Slot::B, &pinned),
                || {},
                || manager.paths.write_active(Slot::B),
                || manager.paths.point_legacy_link(Slot::B),
                || Ok(()),
                || Ok(()),
                |_| Ok(()),
                |_| {},
                || manager.paths.clear_pending(),
                || Ok(()),
                || true,
                || Ok(()),
                || {},
            ),
            Err(PromotionFailure::SlotModified(_))
        ));
    }

    #[test]
    fn failed_stable_refresh_preserves_previous_valid_rescue_pair_and_success_swaps_atomically() {
        let manager = manager("atomic-stable-refresh");
        // 0. Fresh installation (`Paths::prepare()` creates an empty `last-stable`
        //    directory): the first Stable rescue MUST install atomically via a
        //    single directory rename even when `exchange_directories` returns ENOSYS.
        let old_bytes = test_agent("2.3.0", true, "stable-2.3.0");
        let old_rel = release_for_binary(Channel::Stable, "2.3.0", &old_bytes);
        write_release_agent(&manager.paths, Slot::A, &old_rel, &old_bytes);
        let pinned_first = pin_candidate(&manager.paths, Slot::A, "2.3.0").unwrap();
        assert!(manager.paths.stable_dir().is_dir());
        copy_pinned_stable_with(
            &manager.paths,
            &pinned_first,
            |path, bytes| storage::atomic_write(path, bytes, 0o600),
            |_, _| Err(std::io::Error::from_raw_os_error(libc::ENOSYS)),
        )
        .expect("first Stable rescue into empty last-stable must succeed even without RENAME_EXCHANGE");
        assert_eq!(verify_stable_rescue(&manager.paths).unwrap().version, "2.3.0");

        // Prepare new Stable candidate (v2.4.0) in slot B.
        let new_bytes = test_agent("2.4.0", true, "stable-2.4.0");
        let new_rel = release_for_binary(Channel::Stable, "2.4.0", &new_bytes);
        write_release_agent(&manager.paths, Slot::B, &new_rel, &new_bytes);
        let pinned = pin_candidate(&manager.paths, Slot::B, "2.4.0").unwrap();

        // P1 #5: If slot B's binary or manifest was swapped/mismatched before
        // `pin_candidate` (e.g. between parent preflight and helper startup),
        // `pin_candidate` MUST reject it so an invalid pair can NEVER replace
        // the existing valid `last-stable` rescue!
        let swapped_bytes = test_agent("2.4.0", true, "tampered-2.4.0");
        fs::write(manager.paths.slot_binary(Slot::B), &swapped_bytes).unwrap();
        assert!(
            pin_candidate(&manager.paths, Slot::B, "2.4.0").is_err(),
            "pin_candidate must reject binary/manifest digest mismatch"
        );
        fs::write(manager.paths.slot_binary(Slot::B), &new_bytes).unwrap();
        assert!(
            pin_candidate(&manager.paths, Slot::B, "2.9.9").is_err(),
            "pin_candidate must reject manifest/expected version mismatch"
        );

        // 1. Metadata write error during refresh MUST leave previous v2.3.0 pair
        //    completely intact and verifiable!
        assert!(
            copy_pinned_stable_with(
                &manager.paths,
                &pinned,
                |_, _| Err(std::io::Error::other("simulated metadata write failure")),
                storage::exchange_directories,
            )
            .is_err()
        );
        assert_eq!(fs::read(manager.paths.stable_binary()).unwrap(), old_bytes);
        assert_eq!(
            verify_stable_rescue(&manager.paths).unwrap().version,
            "2.3.0",
            "failed Stable refresh must preserve the previous valid rescue pair"
        );

        // 1b. Once a rescue pair exists, unsupported directory exchange (`ENOSYS`)
        //     MUST keep the existing valid v2.3.0 pair untouched instead of doing
        //     two separate non-atomic file renames.
        assert!(
            copy_pinned_stable_with(
                &manager.paths,
                &pinned,
                |path, bytes| storage::atomic_write(path, bytes, 0o600),
                |_, _| Err(std::io::Error::from_raw_os_error(libc::ENOSYS)),
            )
            .is_err()
        );
        assert_eq!(fs::read(manager.paths.stable_binary()).unwrap(), old_bytes);
        assert_eq!(verify_stable_rescue(&manager.paths).unwrap().version, "2.3.0");
        assert!(
            !manager
                .paths
                .root
                .join(format!(".last-stable.next.{}", std::process::id()))
                .exists()
        );

        // 2. Successful refresh atomically swaps `last-stable` to v2.4.0 (even
        //    after slot B on disk is atomically replaced with v2.5.0!).
        let other_bytes = test_agent("2.5.0", true, "other-2.5.0");
        let other_rel = release_for_binary(Channel::Stable, "2.5.0", &other_bytes);
        let tmp_bin = manager.paths.slot_download(Slot::B);
        let tmp_meta = manager.paths.slot_meta_download(Slot::B);
        fs::write(&tmp_bin, &other_bytes).unwrap();
        fs::set_permissions(&tmp_bin, fs::Permissions::from_mode(0o755)).unwrap();
        storage::write_json(&tmp_meta, &other_rel).unwrap();
        fs::rename(&tmp_bin, manager.paths.slot_binary(Slot::B)).unwrap();
        fs::rename(&tmp_meta, manager.paths.slot_meta(Slot::B)).unwrap();

        copy_pinned_stable(&manager.paths, &pinned).unwrap();
        assert_eq!(fs::read(manager.paths.stable_binary()).unwrap(), new_bytes);
        assert_eq!(verify_stable_rescue(&manager.paths).unwrap().version, "2.4.0");
        assert!(
            !manager
                .paths
                .root
                .join(format!(".last-stable.next.{}", std::process::id()))
                .exists()
        );
    }

    #[test]
    fn mismatched_replacement_during_failed_or_interrupted_trial_is_disarmed_not_quarantined() {
        let manager = manager("mismatched-slot-quarantine");
        ensure_supervisor(&manager.paths).unwrap();
        let prev_bytes = test_agent("2.4.0-beta.7", true, "prev-a");
        let prev_rel = release_for_binary(Channel::Beta, "2.4.0-beta.7", &prev_bytes);
        write_release_agent(&manager.paths, Slot::A, &prev_rel, &prev_bytes);
        manager.paths.write_active(Slot::A).unwrap();

        // Slot B was supposed to trial "2.4.0-beta.8", but a legacy download
        // replaced slot B on disk with untested version "2.5.0" before failure.
        let replaced_bytes = test_agent("2.5.0", true, "untested-2.5.0");
        let replaced_rel = release_for_binary(Channel::Stable, "2.5.0", &replaced_bytes);
        write_release_agent(&manager.paths, Slot::B, &replaced_rel, &replaced_bytes);

        // 1. Rust `quarantine_failed_candidate`: must disarm slot B and NOT add
        //    untested "2.5.0" to `blocked.json`.
        quarantine_failed_candidate(&manager.paths, Slot::B, "2.4.0-beta.8", Slot::A).unwrap();
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        assert!(
            !read_blocked_versions(&manager.paths)
                .unwrap()
                .iter()
                .any(|v| v == "2.5.0"),
            "Rust quarantine must not attribute trial failure to replaced version 2.5.0"
        );

        // 2. Shell supervisor on interrupted trial (`pending` says 2.4.0-beta.8,
        //    slot B `release.json` says 2.5.0): must disarm slot B, NOT block 2.5.0,
        //    and restore previous slot A.
        write_release_agent(&manager.paths, Slot::B, &replaced_rel, &replaced_bytes);
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.8")
            .unwrap();
        let marker = manager.paths.root.join("started");
        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();

        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(fs::read_to_string(&marker).unwrap(), "prev-a");
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        assert!(
            !read_blocked_versions(&manager.paths)
                .unwrap()
                .iter()
                .any(|v| v == "2.5.0"),
            "shell supervisor must not quarantine mismatched replacement version 2.5.0"
        );
    }

    #[test]
    fn manual_rollback_and_status_reject_quarantined_release_in_blocked_json() {
        let manager = manager("rollback-rejects-quarantined");
        ensure_supervisor(&manager.paths).unwrap();
        let active_bytes = test_agent(crate::build_info::VERSION, true, "active-a");
        let active_rel =
            release_for_binary(Channel::Stable, crate::build_info::VERSION, &active_bytes);
        write_release_agent(&manager.paths, Slot::A, &active_rel, &active_bytes);
        manager.paths.write_active(Slot::A).unwrap();

        // 1. Signed `release.json` slot quarantined in `blocked.json`.
        let bad_bytes = test_agent("2.4.0-beta.9", true, "bad-b");
        let bad_rel = release_for_binary(Channel::Beta, "2.4.0-beta.9", &bad_bytes);
        write_release_agent(&manager.paths, Slot::B, &bad_rel, &bad_bytes);
        block_version(&manager.paths, "2.4.0-beta.9").unwrap();

        assert_eq!(
            manager.status()["data"]["rollback_available"],
            json!(false),
            "status must not offer a quarantined slot for rollback"
        );
        let err = verify_rollback_slot(&manager.paths, Slot::B).unwrap_err();
        assert!(err.contains("quarantined"));
        assert!(manager.rollback().unwrap_err().contains("quarantined"));

        // Corrupt `blocked.json` must also fail closed for rollback availability & preflight.
        fs::write(&manager.paths.blocked, b"{not-json").unwrap();
        assert_eq!(manager.status()["data"]["rollback_available"], json!(false));
        assert!(verify_rollback_slot(&manager.paths, Slot::B).is_err());

        // Clearing `blocked.json` makes slot B eligible again.
        fs::remove_file(&manager.paths.blocked).unwrap();
        assert_eq!(manager.status()["data"]["rollback_available"], json!(true));
        assert_eq!(
            verify_rollback_slot(&manager.paths, Slot::B).unwrap(),
            "2.4.0-beta.9"
        );

        // 2. Versioned `bootstrap.sha256` slot (without `release.json`) must ALSO
        //    enforce `blocked.json` in both `status` and `verify_rollback_slot`.
        fs::remove_file(manager.paths.slot_meta(Slot::B)).unwrap();
        let boot_bytes = test_agent("2.4.0-beta.8", true, "boot-b");
        fs::write(manager.paths.slot_binary(Slot::B), &boot_bytes).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::B),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(
            manager.paths.slot_bootstrap_digest(Slot::B),
            format!("{}\n2.4.0-beta.8\n", sha256(&boot_bytes)),
        )
        .unwrap();
        block_version(&manager.paths, "2.4.0-beta.8").unwrap();

        assert_eq!(
            manager.status()["data"]["rollback_available"],
            json!(false),
            "status must not offer a quarantined versioned bootstrap slot"
        );
        assert!(
            verify_rollback_slot(&manager.paths, Slot::B)
                .unwrap_err()
                .contains("quarantined")
        );
        assert!(manager.rollback().unwrap_err().contains("quarantined"));

        fs::write(&manager.paths.blocked, b"{corrupt").unwrap();
        assert_eq!(manager.status()["data"]["rollback_available"], json!(false));
        assert!(verify_rollback_slot(&manager.paths, Slot::B).is_err());

        fs::remove_file(&manager.paths.blocked).unwrap();
        assert_eq!(manager.status()["data"]["rollback_available"], json!(true));
        assert_eq!(
            verify_rollback_slot(&manager.paths, Slot::B).unwrap(),
            "2.4.0-beta.8"
        );

        // 2b. Malformed `bootstrap.sha256` files — including bad digest, non-SemVer
        //     versions (`01.2.3`, `dev_build`, `1.2.3-01`), trailing NUL byte on a
        //     3rd line, extra 3rd line, blank 3rd line, and CRLF — MUST be rejected
        //     identically by Rust (`status`, `verify_rollback_slot`) AND the shell
        //     supervisor!
        let mut corrupt_a = active_bytes;
        *corrupt_a.last_mut().unwrap() = b'Z';
        let stable_bytes = test_agent("2.3.0", true, "stable-over-quarantined-boot");
        let stable_rel = release_for_binary(Channel::Stable, "2.3.0", &stable_bytes);
        fs::write(manager.paths.stable_binary(), &stable_bytes).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_rel).unwrap();
        let marker = manager.paths.root.join("boot-selected");
        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();

        let valid_sha = sha256(&boot_bytes);
        for bad_boot in [
            b"not-a-64-char-sha256\n2.4.0-beta.8\n".to_vec(),
            format!("{valid_sha}\n01.2.3\n").into_bytes(),
            format!("{valid_sha}\ndev_build\n").into_bytes(),
            format!("{valid_sha}\n1.2.3-01\n").into_bytes(),
            format!("{valid_sha}\n2.4.0-beta.8\n\0extra\n").into_bytes(),
            format!("{valid_sha}\n2.4.0-beta.8\nextra\n").into_bytes(),
            format!("{valid_sha}\n2.4.0-beta.8\n\n").into_bytes(),
            format!("{valid_sha}\r\n2.4.0-beta.8\r\n").into_bytes(),
        ] {
            // Re-enable slot B executable bit (previous supervisor rescue disarms it).
            fs::set_permissions(
                manager.paths.slot_binary(Slot::B),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            manager.paths.write_active(Slot::A).unwrap();
            fs::write(manager.paths.slot_bootstrap_digest(Slot::B), &bad_boot).unwrap();
            assert_eq!(
                manager.status()["data"]["rollback_available"],
                json!(false),
                "status must reject malformed bootstrap.sha256 {:?}",
                String::from_utf8_lossy(&bad_boot)
            );
            assert!(
                verify_rollback_slot(&manager.paths, Slot::B).is_err(),
                "verify_rollback_slot must reject malformed bootstrap.sha256 {:?}",
                String::from_utf8_lossy(&bad_boot)
            );

            // Corrupt slot A and run the ACTUAL shell supervisor: it must reject
            // the same malformed `bootstrap.sha256` on slot B and select Stable.
            write_release_agent(&manager.paths, Slot::A, &active_rel, &corrupt_a);
            let _ = fs::remove_file(&marker);
            let status = Command::new("sh")
                .arg(&manager.paths.supervisor)
                .env("ZTE_OTA_ROOT", &manager.paths.root)
                .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
                .env("ZTE_TEST_MARKER", &marker)
                .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
                .env("ZTE_PROC_ROOT", &fake_proc)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "shell supervisor must fall back to Stable for malformed bootstrap {:?}",
                String::from_utf8_lossy(&bad_boot)
            );
            assert_eq!(
                fs::read_to_string(&marker).unwrap(),
                "stable-over-quarantined-boot",
                "shell supervisor must reject malformed bootstrap.sha256 {:?}",
                String::from_utf8_lossy(&bad_boot)
            );
        }

        // 2c. Shell supervisor must ALSO enforce `blocked.json` on versioned
        //     `bootstrap.sha256` slots instead of booting a quarantined bootstrap slot.
        fs::set_permissions(
            manager.paths.slot_binary(Slot::B),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        manager.paths.write_active(Slot::A).unwrap();
        write_release_agent(&manager.paths, Slot::A, &active_rel, &corrupt_a);
        fs::write(
            manager.paths.slot_bootstrap_digest(Slot::B),
            format!("{}\n2.4.0-beta.8\n", sha256(&boot_bytes)),
        )
        .unwrap();
        block_version(&manager.paths, "2.4.0-beta.8").unwrap();
        let _ = fs::remove_file(&marker);
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            fs::read_to_string(&marker).unwrap(),
            "stable-over-quarantined-boot",
            "shell supervisor must skip quarantined bootstrap.sha256 slot and boot Stable rescue"
        );
    }

    #[test]
    fn quarantined_cached_update_cannot_be_redownloaded_or_reinstalled() {
        let manager = manager("quarantined-cached-update");
        manager.paths.write_active(Slot::A).unwrap();
        let bad_bytes = test_agent("2.5.0-beta.3", true, "bad-2.5.0-beta.3");
        let bad_rel = release_for_binary(Channel::Beta, "2.5.0-beta.3", &bad_bytes);
        write_release_agent(&manager.paths, Slot::B, &bad_rel, &bad_bytes);
        block_version(&manager.paths, "2.5.0-beta.3").unwrap();

        // 1. Startup reconciliation after a failed install clears quarantined `available`.
        let mut persistent = PersistentState {
            phase: Phase::Installing,
            available: Some(bad_rel.clone()),
            staged: Some(bad_rel.clone()),
            staged_slot: Some("b".into()),
            ..PersistentState::default()
        };
        assert!(reconcile_startup_state(&manager.paths, &mut persistent).is_some());
        assert_eq!(persistent.phase, Phase::Idle);
        assert_eq!(persistent.staged, None);
        assert_eq!(persistent.available, None);

        // 1b. Startup reconciliation also clears quarantined `Phase::Staged`.
        let mut staged_persistent = PersistentState {
            phase: Phase::Staged,
            available: Some(bad_rel.clone()),
            staged: Some(bad_rel.clone()),
            staged_slot: Some("b".into()),
            ..PersistentState::default()
        };
        assert!(reconcile_startup_state(&manager.paths, &mut staged_persistent).is_some());
        assert_eq!(staged_persistent.phase, Phase::Idle);
        assert_eq!(staged_persistent.staged, None);
        assert_eq!(staged_persistent.staged_slot, None);
        assert_eq!(staged_persistent.available, None);

        // 2. Manual `download()` rejects a cached quarantined `available` manifest.
        manager.change(|state| {
            state.persistent.available = Some(bad_rel.clone());
        });
        assert!(manager.download().unwrap_err().contains("quarantined"));

        // 3. `verify_staged_slot()` rejects a quarantined staged copy.
        assert!(
            verify_staged_slot(&manager.paths, Slot::B, &bad_rel)
                .unwrap_err()
                .contains("quarantined")
        );
    }

    #[test]
    fn rollback_blocked_marker_rejects_empty_or_malformed_boot_id() {
        let manager = manager("rollback-blocked-boot-validation");
        let marker = manager.paths.root.join("rollback-blocked");
        for bad in ["", "   \n", "boot id", "boot\x0cid", "boot\0id"] {
            assert!(
                write_rollback_blocked_marker_with(&manager.paths, bad).is_err(),
                "invalid boot_id {bad:?} must be rejected before starting trial"
            );
            assert!(!marker.exists());
        }
        write_rollback_blocked_marker_with(&manager.paths, "boot-uuid-valid").unwrap();
        assert_eq!(fs::read_to_string(&marker).unwrap(), "boot-uuid-valid\n");
    }

    #[test]
    fn rollback_helper_releases_perf_owner_lock_before_spawning_replacement_agent() {
        let manager = manager("helper-releases-perf-lock");
        let perf_dir = manager.paths.root.join("perf-state");
        let perf = crate::netfx::perf::Perf::for_test(&perf_dir);
        let owner_lock = perf_dir.join("run/owner.lock");
        let lock_result = manager.paths.root.join("child-lock-result");

        // Pre-seed a same-boot empty perf journal so recover_with_perf acquires
        // `owner.lock` and removes the journal before spawning.
        fs::create_dir_all(perf.journal_path().parent().unwrap()).unwrap();
        fs::write(
            perf.journal_path(),
            "{\"boot\":\"perf-test-boot\",\"originals\":[]}\n",
        )
        .unwrap();

        let make_lock_claiming_agent = |tag: &str| {
            let script = format!(
                "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then exit 0; fi\npython3 -c 'import fcntl, os, sys\nlock_path, out_path, tag = sys.argv[1:4]\nwith open(lock_path, \"r+\") as f:\n    try:\n        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)\n        status = tag + \":locked:trial=\" + os.environ.get(\"ZTE_OTA_TRIAL\", \"\") + \":sup=\" + os.environ.get(\"ZTE_OTA_SUPERVISOR\", \"\") + \":real=\" + os.environ.get(\"ZTE_OTA_REAL_SUPERVISOR\", \"\")\n    except BlockingIOError:\n        status = tag + \":blocked\"\ntmp = out_path + \".tmp\"\nwith open(tmp, \"w\") as out:\n    out.write(status)\nos.replace(tmp, out_path)\n' \"{}\" \"{}\" \"{}\"\n",
                owner_lock.display(),
                lock_result.display(),
                tag
            );
            let mut bytes = script.into_bytes();
            if bytes.len() < 1024 {
                bytes.push(b'\n');
                bytes.push(b'#');
                bytes.resize(1024, b'x');
            }
            bytes
        };

        // 1. Previous-slot rollback: `perf` remains alive in this process
        //    (matching the process-wide OnceLock singleton) while the spawned
        //    child tries a nonblocking exclusive flock on `owner.lock`.
        let prev_bytes = make_lock_claiming_agent("prev");
        let prev_rel =
            release_for_binary(Channel::Stable, crate::build_info::VERSION, &prev_bytes);
        write_release_agent(&manager.paths, Slot::A, &prev_rel, &prev_bytes);
        assert_eq!(
            recover_with_perf(&manager.paths, Slot::A, None, None, &perf),
            4
        );
        assert!(!perf.journal_path().exists());

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !lock_result.exists() {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            fs::read_to_string(&lock_result).unwrap(),
            format!(
                "prev:locked:trial=:sup={}:real={}",
                manager.paths.legacy_supervisor_shadow().display(),
                manager.paths.supervisor.display()
            ),
            "previous-slot child must acquire perf owner.lock without ZTE_OTA_TRIAL while isolating legacy supervisor writes"
        );
        fs::remove_file(&lock_result).unwrap();

        // 2. Stable-rescue fallback: corrupt previous slot so recover_with_perf
        //    spawns Stable rescue, still keeping `perf` alive in the parent.
        fs::write(
            perf.journal_path(),
            "{\"boot\":\"perf-test-boot\",\"originals\":[]}\n",
        )
        .unwrap();
        let bad_prev = test_agent(crate::build_info::VERSION, false, "bad-prev");
        let bad_prev_rel =
            release_for_binary(Channel::Stable, crate::build_info::VERSION, &bad_prev);
        write_release_agent(&manager.paths, Slot::A, &bad_prev_rel, &bad_prev);
        let stable_bytes = make_lock_claiming_agent("stable");
        let stable_rel = release_for_binary(Channel::Stable, "2.3.0", &stable_bytes);
        fs::write(manager.paths.stable_binary(), &stable_bytes).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_rel).unwrap();

        assert_eq!(
            recover_with_perf(&manager.paths, Slot::A, None, None, &perf),
            6
        );
        assert!(!perf.journal_path().exists());

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !lock_result.exists() {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            fs::read_to_string(&lock_result).unwrap(),
            format!(
                "stable:locked:trial=:sup={}:real={}",
                manager.paths.legacy_supervisor_shadow().display(),
                manager.paths.supervisor.display()
            ),
            "Stable rescue child must acquire perf owner.lock without ZTE_OTA_TRIAL while isolating legacy supervisor writes"
        );
        drop(perf);
    }

    #[test]
    fn supervisor_journal_parser_rejects_nested_boot_and_truncated_json() {
        let manager = manager("supervisor-strict-json-journal");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let ts_journal = manager.paths.root.join("tailscale-network.json");
        let boot_id_file = manager.paths.root.join("boot_id");
        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();
        fs::write(&boot_id_file, "boot-uuid-123\n").unwrap();

        let slot_a = test_agent("2.4.0-beta.7", true, "a-fallback");
        let rel_a = release_for_binary(Channel::Beta, "2.4.0-beta.7", &slot_a);
        write_release_agent(&manager.paths, Slot::A, &rel_a, &slot_a);

        // Corrupted active slot B cannot run `network-recover`, so any journal
        // NOT positively proven to be a complete valid prior-boot JSON object
        // MUST cause exit 8.
        let slot_b = test_agent("2.4.0-beta.8", true, "b-active");
        let rel_b = release_for_binary(Channel::Beta, "2.4.0-beta.8", &slot_b);
        let mut slot_b_corrupt = slot_b;
        *slot_b_corrupt.last_mut().unwrap() = b'Z';
        write_release_agent(&manager.paths, Slot::B, &rel_b, &slot_b_corrupt);
        manager.paths.write_active(Slot::B).unwrap();

        for tricky_json in [
            // Escaped top-level `boot` naming current boot + nested literal `boot` naming prior boot
            "{\"\\u0062oot\":\"boot-uuid-123\",\"nested\":{\"boot\":\"prior-boot\"}}\n",
            // Nested literal `boot` only (no top-level `boot`)
            "{\"undo\":[{\"boot\":\"prior-boot\"}]}\n",
            // Truncated JSON ending immediately after prior-boot value
            "{\"boot\":\"prior-boot\"",
            // Truncated JSON inside array
            "{\"boot\":\"prior-boot\",\"undo\":[",
            // Duplicate top-level `boot` key
            "{\"boot\":\"prior-boot\",\"boot\":\"boot-uuid-123\"}\n",
            // Trailing garbage after object
            "{\"boot\":\"prior-boot\",\"undo\":[]} trailing\n",
            // Escaped prior-boot value
            "{\"boot\":\"prior\\u002dboot\",\"undo\":[]}\n",
        ] {
            fs::write(&ts_journal, tricky_json).unwrap();
            let status = Command::new("sh")
                .arg(&manager.paths.supervisor)
                .env("ZTE_OTA_ROOT", &manager.paths.root)
                .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
                .env("ZTE_TEST_MARKER", &marker)
                .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
                .env("ZTE_BOOT_ID_PATH", &boot_id_file)
                .env("ZTE_PROC_ROOT", &fake_proc)
                .status()
                .unwrap();
            assert_eq!(
                status.code(),
                Some(8),
                "ambiguous or truncated JSON journal {tricky_json:?} must fail closed"
            );
            assert!(!marker.exists());
            assert_eq!(manager.paths.active_slot(), Some(Slot::B));
        }

        // Valid complete prior-boot JSON (even with a nested `"boot"` matching
        // the current boot!) is unambiguously a prior-boot journal and allows
        // fallback to verified slot A.
        fs::write(
            &ts_journal,
            "{\"undo\":[{\"boot\":\"boot-uuid-123\",\"n\":1,\"ok\":true,\"x\":null}],\"boot\":\"prior-boot\"}\n",
        )
        .unwrap();
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "complete valid prior-boot JSON journal must allow fallback"
        );
        assert_eq!(fs::read_to_string(&marker).unwrap(), "a-fallback");
        assert_eq!(manager.paths.active_slot(), Some(Slot::A));
    }

    #[test]
    fn supervisor_non_pending_fallback_skips_unverified_executable_slot_for_verified_stable() {
        let manager = manager("supervisor-verified-fallback-only");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();

        // Active slot A is corrupted.
        let active_bytes = test_agent("2.4.0-beta.7", true, "a");
        let active_rel = release_for_binary(Channel::Beta, "2.4.0-beta.7", &active_bytes);
        let mut corrupted_a = active_bytes;
        *corrupted_a.last_mut().unwrap() = b'Z';
        write_release_agent(&manager.paths, Slot::A, &active_rel, &corrupted_a);
        manager.paths.write_active(Slot::A).unwrap();

        // Slot B is executable-only (neither `release.json` nor `bootstrap.sha256`).
        let unverified_b = test_agent("2.4.0-beta.8", true, "unverified-b");
        fs::write(manager.paths.slot_binary(Slot::B), &unverified_b).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::B),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::B));
        let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::B));

        // Verified Stable rescue copy is available.
        let stable_bytes = test_agent("2.3.0", true, "stable-rescue");
        let stable_rel = release_for_binary(Channel::Stable, "2.3.0", &stable_bytes);
        fs::write(manager.paths.stable_binary(), &stable_bytes).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_rel).unwrap();

        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "supervisor must fall back to verified Stable rescue when alternative slot is unverified"
        );
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-rescue");
        assert_eq!(manager.paths.active_slot(), None);
        assert_eq!(
            fs::read_to_string(&manager.paths.active).unwrap().trim(),
            "rescue"
        );
        // Both rejected A/B slot binaries must be disarmed before entering rescue
        // so an older Stable supervisor reinstalled on startup cannot boot slot B.
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::A)));
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));

        // Simulate Stable reinstalling the older HEAD supervisor (which accepts
        // executable-only slots on fallback) and restarting a second time.
        let legacy_supervisor = r#"#!/bin/sh
set -u
OTA_ROOT="${ZTE_OTA_ROOT:-/data/open-u60/update}"
ACTIVE="$OTA_ROOT/active"
LEGACY="${ZTE_OTA_LEGACY_LINK:-/data/zte-agent}"
LAST_STABLE="$OTA_ROOT/last-stable/zte-agent"
LAST_STABLE_META="$OTA_ROOT/last-stable/release.json"
slot_binary() { printf '%s/slot-%s/zte-agent' "$OTA_ROOT" "$1"; }
slot_meta() { printf '%s/slot-%s/release.json' "$OTA_ROOT" "$1"; }
valid_slot() { [ "$1" = a ] || [ "$1" = b ]; }
runnable_binary() {
    [ -x "$1" ] || return 1
    if [ -f "$2" ]; then
        ver=$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$2" | sed -n '1p')
        sz=$(sed -n 's/^[[:space:]]*"size"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$2" | sed -n '1p')
        sha=$(sed -n 's/^[[:space:]]*"sha256"[[:space:]]*:[[:space:]]*"\([0-9a-f][0-9a-f]*\)".*/\1/p' "$2" | sed -n '1p')
        [ -n "$ver" ] && [ -n "$sz" ] && [ -n "$sha" ] || return 1
        [ "$(wc -c < "$1" | tr -d '[:space:]')" = "$sz" ] || return 1
        [ "$(sha256sum "$1" 2>/dev/null | sed -n 's/[[:space:]].*//p')" = "$sha" ] || return 1
        "$1" ota-probe "$ver" >/dev/null 2>&1
        return $?
    fi
    return 0
}
runnable_slot() { runnable_binary "$(slot_binary "$1")" "$(slot_meta "$1")"; }
runnable_stable() { [ -f "$LAST_STABLE_META" ] && runnable_binary "$LAST_STABLE" "$LAST_STABLE_META"; }
active=$(sed -n '1p' "$ACTIVE" 2>/dev/null || true)
if ! valid_slot "$active" || ! runnable_slot "$active"; then
    if runnable_slot a; then active=a
    elif runnable_slot b; then active=b
    elif runnable_stable; then active=stable
    else exit 127; fi
fi
if valid_slot "$active"; then
    printf '%s\n' "$active" > "$ACTIVE"
    binary=$(slot_binary "$active")
else
    printf 'rescue\n' > "$ACTIVE"
    binary=$LAST_STABLE
fi
ln -sfn "$binary" "$LEGACY.next"
mv -f "$LEGACY.next" "$LEGACY"
exec "$binary"
"#;
        fs::write(&manager.paths.supervisor, legacy_supervisor).unwrap();
        fs::set_permissions(&manager.paths.supervisor, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_file(&marker).unwrap();

        let status2 = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .status()
            .unwrap();
        assert!(
            status2.success(),
            "second start under reinstalled legacy supervisor must still boot verified Stable rescue"
        );
        assert_eq!(
            fs::read_to_string(&marker).unwrap(),
            "stable-rescue",
            "legacy supervisor must not boot disarmed unverified slot B"
        );
        assert_eq!(
            fs::read_to_string(&manager.paths.active).unwrap().trim(),
            "rescue"
        );
    }

    #[test]
    fn completed_manual_rollback_reconciles_without_interruption_error() {
        let manager = manager("completed-manual-rollback");
        manager.paths.write_active(Slot::B).unwrap();

        // 1. When `active_slot()` matches `rollback_target`, startup
        //    reconciliation reports a completed rollback with `last_error: None`.
        let mut completed = PersistentState {
            phase: Phase::RollingBack,
            rollback_target: Some("b".into()),
            ..PersistentState::default()
        };
        assert_eq!(
            reconcile_startup_state(&manager.paths, &mut completed),
            Some("reconciled a completed rollback after restart")
        );
        assert_eq!(completed.phase, Phase::Idle);
        assert_eq!(completed.rollback_target, None);
        assert_eq!(completed.last_error, None);

        // 2. When `active_slot()` does NOT match `rollback_target`, startup
        //    reconciliation reports an interrupted rollback.
        let mut interrupted = PersistentState {
            phase: Phase::RollingBack,
            rollback_target: Some("a".into()),
            ..PersistentState::default()
        };
        assert_eq!(
            reconcile_startup_state(&manager.paths, &mut interrupted),
            Some("recovered an interrupted rollback trial at startup")
        );
        assert_eq!(interrupted.phase, Phase::Idle);
        assert_eq!(interrupted.rollback_target, None);
        assert!(interrupted.last_error.is_some());

        // 3. `reconcile_state_for_promotion` persists clean `Idle` before
        //    spawning even an older legacy rollback binary.
        storage::write_json(
            &manager.paths.state,
            &PersistentState {
                phase: Phase::RollingBack,
                rollback_target: Some("b".into()),
                ..PersistentState::default()
            },
        )
        .unwrap();
        reconcile_state_for_promotion(&manager.paths, Slot::B).unwrap();
        let saved: PersistentState = storage::read_json(&manager.paths.state).unwrap();
        assert_eq!(saved.phase, Phase::Idle);
        assert_eq!(saved.rollback_target, None);
        assert_eq!(saved.last_error, None);
    }

    #[test]
    fn recovery_reconciles_state_before_spawn_and_non_trial_startup_retries_after_pending_clears() {
        let manager = manager("recovery-reconciles-state");
        let perf_dir = manager.paths.root.join("perf-state");
        let perf = crate::netfx::perf::Perf::for_test(&perf_dir);
        let observed_state = manager.paths.root.join("child-observed-state.json");

        // Prepare a previous slot binary that captures `state.json` immediately
        // on spawn (even before the helper clears `pending`).
        let script = format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then exit 0; fi\ncp \"{}\" \"{}.tmp\" && mv -f \"{}.tmp\" \"{}\"\n",
            manager.paths.state.display(),
            observed_state.display(),
            observed_state.display(),
            observed_state.display()
        );
        let mut prev_bytes = script.into_bytes();
        prev_bytes.push(b'#');
        prev_bytes.resize(1024, b'x');
        let prev_rel =
            release_for_binary(Channel::Stable, crate::build_info::VERSION, &prev_bytes);
        write_release_agent(&manager.paths, Slot::A, &prev_rel, &prev_bytes);

        let bad_bytes = test_agent("2.5.0-beta.9", true, "bad-cand");
        let bad_rel = release_for_binary(Channel::Beta, "2.5.0-beta.9", &bad_bytes);
        write_release_agent(&manager.paths, Slot::B, &bad_rel, &bad_bytes);
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.5.0-beta.9")
            .unwrap();
        storage::write_json(
            &manager.paths.state,
            &PersistentState {
                phase: Phase::Installing,
                available: Some(bad_rel.clone()),
                staged: Some(bad_rel.clone()),
                staged_slot: Some("b".into()),
                ..PersistentState::default()
            },
        )
        .unwrap();

        // 1. `recover_with_perf` persists reconciled `Idle` state (and clears
        //    quarantined `available`) BEFORE spawning slot A.
        assert_eq!(
            recover_with_perf(&manager.paths, Slot::A, Some((Slot::B, "2.5.0-beta.9")), None, &perf),
            4
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && !observed_state.exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
        let child_saw: PersistentState = storage::read_json(&observed_state).unwrap();
        assert_eq!(child_saw.phase, Phase::Idle);
        assert_eq!(child_saw.staged, None);
        assert_eq!(child_saw.available, None);
        assert!(child_saw.last_error.is_some());

        // 1b. If persisting reconciled `state.json` fails (e.g. `state.json`
        //     replaced by an unwritable directory), `recover_with_perf` MUST
        //     propagate the error, exit 9 without spawning a legacy child with
        //     stale `Installing` while `pending` exists, and retain `pending`.
        let _ = fs::remove_file(&observed_state);
        let _ = fs::remove_file(&manager.paths.state);
        fs::create_dir(&manager.paths.state).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.5.0-beta.9")
            .unwrap();
        assert_eq!(
            recover_with_perf(&manager.paths, Slot::A, None, None, &perf),
            9
        );
        assert!(manager.paths.pending.exists());
        assert!(!observed_state.exists());
        fs::remove_dir(&manager.paths.state).unwrap();

        // 2. Non-trial startup retry (`reconcile_pending_non_trial_once`): waits
        //    while `pending` exists (e.g. older helper), never clobbers a newly
        //    admitted install while `pending` is present, and reconciles once
        //    `pending` disappears.
        manager.paths.write_active(Slot::A).unwrap();
        manager.change(|state| {
            state.persistent.phase = Phase::Installing;
            state.persistent.staged = Some(bad_rel.clone());
            state.persistent.staged_slot = Some("b".into());
        });
        assert!(!reconcile_pending_non_trial_once(&manager, || true));
        assert_eq!(
            manager.state.lock().unwrap().persistent.phase,
            Phase::Installing
        );
        // Once `pending` is gone, non-trial retry reconciles to Idle with error.
        let _ = manager.paths.clear_pending();
        assert!(reconcile_pending_non_trial_once(&manager, || false));
        let p = &manager.state.lock().unwrap().persistent;
        assert_eq!(p.phase, Phase::Idle);
        assert_eq!(p.staged, None);
        assert!(p.last_error.is_some());
    }

    #[test]
    fn racing_download_and_duplicate_install_do_not_clobber_live_install_phase() {
        let manager = manager("racing-download-vs-install");
        manager.paths.write_active(Slot::A).unwrap();
        let staged_bytes = test_agent("2.5.0-beta.1", true, "staged-b");
        let staged_rel = release_for_binary(Channel::Beta, "2.5.0-beta.1", &staged_bytes);
        write_release_agent(&manager.paths, Slot::B, &staged_rel, &staged_bytes);

        // Simulate `install()` having written `Phase::Installing` and `pending`
        // and released `self.operation` during its 1.2s exit delay.
        manager.change(|state| {
            state.persistent.phase = Phase::Installing;
            state.persistent.available = Some(staged_rel.clone());
            state.persistent.staged = Some(staged_rel.clone());
            state.persistent.staged_slot = Some("b".into());
            state.persistent.last_error = None;
        });
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.5.0-beta.1")
            .unwrap();

        // A racing `download()`, duplicate `install()`, and `rollback()` must
        // ALL fail inside `begin()` under `self.operation` BEFORE touching phase
        // or calling `fail()`, preserving `Installing` and `last_error: None`.
        for res in [manager.download(), manager.install(), manager.rollback()] {
            assert!(res.is_err());
            let p = &manager.state.lock().unwrap().persistent;
            assert_eq!(p.phase, Phase::Installing);
            assert_eq!(p.last_error, None);
            let persisted: PersistentState = storage::read_json(&manager.paths.state).unwrap();
            assert_eq!(persisted.phase, Phase::Installing);
            assert_eq!(persisted.last_error, None);
        }
    }

    #[test]
    fn proc_pid_listener_matcher_attributes_sockets_by_pid_and_rejects_other_processes() {
        let manager = manager("proc-pid-listener-match");
        let proc_root = manager.paths.root.join("proc");
        let fd_dir = proc_root.join("4242/fd");
        let net_dir = proc_root.join("4242/net");
        fs::create_dir_all(&fd_dir).unwrap();
        fs::create_dir_all(&net_dir).unwrap();

        // Child PID 4242 owns socket inode 77777; another process owns 88888.
        std::os::unix::fs::symlink("socket:[77777]", fd_dir.join("3")).unwrap();
        let loopback_hex = format!("{:08X}", u32::from_ne_bytes([127, 0, 0, 1]));
        let port_hex = format!("{:04X}", 9090u16);
        let tcp_table = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {loopback_hex}:{port_hex} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 88888 1\n"
        );
        fs::write(net_dir.join("tcp"), &tcp_table).unwrap();

        let target: SocketAddr = "127.0.0.1:9090".parse().unwrap();
        assert!(
            !proc_pid_listens_on(&proc_root, 4242, target),
            "socket owned by another PID (inode 88888) must not satisfy PID 4242"
        );

        // ESTABLISHED (01) owned by PID 4242 is not a listener.
        let est_table = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {loopback_hex}:{port_hex} 0100007F:9999 01 00000000:00000000 00:00000000 00000000 0 0 77777 1\n"
        );
        fs::write(net_dir.join("tcp"), &est_table).unwrap();
        assert!(!proc_pid_listens_on(&proc_root, 4242, target));

        // LISTEN (0A) owned by PID 4242 on matching IPv4 port matches.
        let listen_table = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {loopback_hex}:{port_hex} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 77777 1\n"
        );
        fs::write(net_dir.join("tcp"), &listen_table).unwrap();
        assert!(proc_pid_listens_on(&proc_root, 4242, target));

        // Wildcard IPv4 `0.0.0.0` owned by PID 4242 MUST NOT match when another
        // process holds exact `127.0.0.1` on the same port.
        let conflict_table = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:{port_hex} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 77777 1\n   1: {loopback_hex}:{port_hex} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 88888 1\n"
        );
        fs::write(net_dir.join("tcp"), &conflict_table).unwrap();
        assert!(
            !proc_pid_listens_on(&proc_root, 4242, target),
            "wildcard listener must not match when another PID holds exact loopback address"
        );

        // IPv6 `::` LISTEN (0A) owned by PID 4242 MUST NOT satisfy an IPv4 probe
        // (`127.0.0.1:9090`), and MUST satisfy an IPv6 probe (`[::1]:9090`).
        fs::remove_file(net_dir.join("tcp")).unwrap();
        let tcp6_table = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000000000000000000000000000:{port_hex} 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 77777 1\n"
        );
        fs::write(net_dir.join("tcp6"), &tcp6_table).unwrap();
        assert!(
            !proc_pid_listens_on(&proc_root, 4242, target),
            "IPv6 wildcard listener must never satisfy an IPv4 readiness probe"
        );
        let v6_target: SocketAddr = "[::1]:9090".parse().unwrap();
        assert!(proc_pid_listens_on(&proc_root, 4242, v6_target));

        // `bind_address_from` preserves the configured IP family for unspecified binds.
        assert_eq!(
            bind_address_from(Some("0.0.0.0:9090")),
            "127.0.0.1:9090".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            bind_address_from(Some("[::]:9090")),
            "[::1]:9090".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn cross_family_ipv6_child_cannot_satisfy_ipv4_readiness_with_unrelated_ipv4_listener() {
        // Reproduce cross-family spoofing: parent holds IPv4 `127.0.0.1:<port>`
        // while child binds IPv6-only `[::]:<port>` (`IPV6_V6ONLY = 1`) on the
        // exact same port. An IPv4 readiness check MUST reject this child.
        let v4_squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let v4_addr = v4_squatter.local_addr().unwrap();
        let port = v4_addr.port();

        let mut v6_child = Command::new("python3")
            .arg("-c")
            .arg("import socket, sys, time; s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('::', int(sys.argv[1]))); s.listen(4); time.sleep(10)")
            .arg(port.to_string())
            .spawn()
            .unwrap();

        // Give the Python child a moment to bind `[::]:<port>` so we test with
        // both listeners simultaneously active.
        std::thread::sleep(Duration::from_millis(250));
        let err = wait_for_child_listener(&mut v6_child, v4_addr, Duration::from_millis(500));
        assert!(
            err.is_err(),
            "IPv6-only child + unrelated IPv4 listener on same port must NOT pass IPv4 readiness"
        );
        drop(v4_squatter);

        // Now verify that an IPv6 probe (`bind_address_from(Some("[::]:<port>"))`)
        // DOES pass when the child binds IPv6 `[::]:<port>`.
        let v6_addr = bind_address_from(Some(&format!("[::]:{port}")));
        assert!(v6_addr.is_ipv6());
        let mut v6_legit = Command::new("python3")
            .arg("-c")
            .arg("import socket, sys, time; s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('::', int(sys.argv[1]))); s.listen(4); time.sleep(10)")
            .arg(port.to_string())
            .spawn()
            .unwrap();
        let res = wait_for_child_listener(&mut v6_legit, v6_addr, Duration::from_secs(5));
        let _ = v6_legit.kill();
        let _ = v6_legit.wait();
        assert!(
            res.is_ok(),
            "IPv6-only child must pass matching IPv6 readiness probe: {res:?}"
        );
    }

    #[test]
    fn recovery_verifies_previous_child_readiness_and_falls_back_to_stable_on_early_exit() {
        let manager = manager("recovery-verifies-prev-child");
        let perf_dir = manager.paths.root.join("perf-state");
        let perf = crate::netfx::perf::Perf::for_test(&perf_dir);

        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen_addr = reserve.local_addr().unwrap();
        drop(reserve);

        // Slot A passes `ota-probe` but exits 1 on normal startup (simulating
        // failed auth verifier or `perf.start()` before `guard::spawn()`).
        let mut failing_prev = b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then exit 0; fi\nexit 1\n".to_vec();
        failing_prev.push(b'#');
        failing_prev.resize(1024, b'x');
        let prev_rel =
            release_for_binary(Channel::Stable, crate::build_info::VERSION, &failing_prev);
        write_release_agent(&manager.paths, Slot::A, &prev_rel, &failing_prev);

        // Stable rescue copy starts a real listening TCP socket on `listen_addr`.
        let stable_script = format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then exit 0; fi\nexec python3 -c \"import socket, sys, time; s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', {})); s.listen(4); time.sleep(5)\"\n",
            listen_addr.port()
        );
        let mut stable_bytes = stable_script.into_bytes();
        stable_bytes.push(b'#');
        stable_bytes.resize(1024, b'x');
        let stable_rel = release_for_binary(Channel::Stable, "2.3.0", &stable_bytes);
        fs::write(manager.paths.stable_binary(), &stable_bytes).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_rel).unwrap();

        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.5.0-beta.1")
            .unwrap();
        let mut last_pid: Option<u32> = None;
        let rc = recover_with_perf_and_hooks(
            &manager.paths,
            Slot::A,
            None,
            None,
            &perf,
            None,
            |spawned| {
                last_pid = Some(spawned.id());
                wait_for_child_listener(spawned, listen_addr, Duration::from_secs(5))
            },
            clear_rollback_blocked_marker,
            |p| p.clear_pending(),
        );
        if let Some(pid) = last_pid {
            // SAFETY: killing our own short-lived test child after verification.
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }
        assert_eq!(
            rc, 6,
            "early-exiting previous slot must fall through to verified Stable rescue"
        );
        assert!(!manager.paths.pending.exists());
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::A)));
        assert_eq!(
            fs::read_to_string(&manager.paths.active).unwrap().trim(),
            "rescue"
        );

        // Verify Stable rescue binary spawned with `ZTE_OTA_TRIAL=1` can open
        // its own gate once helper exits and `pending` + `rollback-blocked` clear.
        let rescue_confirmed = AtomicBool::new(false);
        let rescue_sup = AtomicBool::new(false);
        assert!(!slot_change_pending_with_rescue(
            &manager.paths,
            true,
            Some(9999),
            1,
            &rescue_confirmed,
            &rescue_sup,
            || None,
            || true,
            |_| Ok(()),
            |_| Ok(()),
        ));
        assert!(rescue_confirmed.load(Ordering::Acquire));

        // If clearing handoff markers fails on EITHER boundary — (a) first
        // removal (`rollback-blocked`), OR (b) second removal (`pending`) AFTER
        // `rollback-blocked` was actually unlinked — on EITHER previous-slot OR
        // Stable recovery:
        //  - helper must kill the child and return 9;
        //  - `pending` MUST still survive as the durable retry record;
        //  - on Stable recovery, `rollback-blocked` is cleared BEFORE disarming
        //    previous slot A, so if 1st removal fails slot A stays armed, and if
        //    2nd removal fails (or Stable crashes) slot A stays DISARMED while
        //    same-boot shell supervisor retry boots verified Stable rescue (exit 0)
        //    WITHOUT re-enabling slot A!
        ensure_supervisor(&manager.paths).unwrap();
        let sup_marker = manager.paths.root.join("sup-retry-started");
        let boot_id_file = manager.paths.root.join("boot_id");
        fs::write(&boot_id_file, "boot-uuid-1\n").unwrap();
        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();

        let ok_prev = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then [ \"${{2:-}}\" = \"{}\" ] && exit 0; exit 2; fi\nrm -f \"${{ZTE_OTA_ROOT}}/rollback-attempt\"\n[ -z \"${{ZTE_TEST_MARKER:-}}\" ] || printf 'ok-prev' > \"$ZTE_TEST_MARKER\"\n",
            crate::build_info::VERSION
        ));
        let ok_prev_rel =
            release_for_binary(Channel::Stable, crate::build_info::VERSION, &ok_prev);
        write_release_agent(&manager.paths, Slot::A, &ok_prev_rel, &ok_prev);
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.5.0-beta.1")
            .unwrap();
        write_rollback_blocked_marker_with(&manager.paths, "boot-uuid-1").unwrap();
        // (a) Previous-slot: 1st removal (`rollback-blocked`) fails -> both survive.
        let rc_prev_first_err = recover_with_perf_and_hooks(
            &manager.paths,
            Slot::A,
            None,
            None,
            &perf,
            None,
            |_| Ok(()),
            |_| Err(std::io::Error::other("simulated rollback-blocked remove failure")),
            |p| p.clear_pending(),
        );
        assert_eq!(rc_prev_first_err, 9);
        assert!(manager.paths.pending.exists());
        assert!(manager.paths.root.join("rollback-blocked").exists());

        // (b) Previous-slot: 1st removal succeeds, 2nd removal (`pending`) fails ->
        //     `pending` still survives, `rollback-blocked` is NOT orphaned, and
        //     same-boot shell supervisor retry succeeds (exit 0)!
        let rc_prev_second_err = recover_with_perf_and_hooks(
            &manager.paths,
            Slot::A,
            None,
            None,
            &perf,
            None,
            |_| Ok(()),
            clear_rollback_blocked_marker,
            |_| Err(std::io::Error::other("simulated pending remove failure")),
        );
        assert_eq!(rc_prev_second_err, 9);
        assert!(
            manager.paths.pending.exists(),
            "pending must survive when second removal fails on previous-slot recovery"
        );
        assert!(!manager.paths.root.join("rollback-blocked").exists());
        let _ = fs::remove_file(&sup_marker);
        let retry_prev = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &sup_marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(
            retry_prev.success(),
            "same-boot supervisor retry after 2nd-removal failure must succeed (got {:?})",
            retry_prev.code()
        );
        assert_eq!(fs::read_to_string(&sup_marker).unwrap(), "ok-prev");

        // Corrupt slot A so recovery takes the Stable branch, then test BOTH
        // 1st-removal and 2nd-removal failures on Stable recovery WITHOUT
        // artificially re-enabling slot A.
        write_release_agent(&manager.paths, Slot::A, &prev_rel, &failing_prev);
        let mut stable_retry_agent = b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then [ \"${2:-}\" = \"2.3.0\" ] && exit 0; exit 2; fi\nif [ -n \"${ZTE_TEST_MARKER:-}\" ]; then printf 'stable-retry-ok' > \"$ZTE_TEST_MARKER\"; exit 0; fi\nsleep 2\n#".to_vec();
        stable_retry_agent.resize(1024, b'x');
        let stable_retry_rel = release_for_binary(Channel::Stable, "2.3.0", &stable_retry_agent);
        fs::write(manager.paths.stable_binary(), &stable_retry_agent).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_retry_rel).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.5.0-beta.1")
            .unwrap();
        write_rollback_blocked_marker_with(&manager.paths, "boot-uuid-1").unwrap();

        // (c) Stable: `clear_rollback_blocked` fails BEFORE disarming slot A ->
        //     slot A remains armed, both markers survive, returns 9.
        let rc_stable_first_err = recover_with_perf_and_hooks(
            &manager.paths,
            Slot::A,
            None,
            None,
            &perf,
            None,
            |child| {
                std::thread::sleep(Duration::from_millis(80));
                if child.try_wait().ok().flatten().is_some() {
                    Err("exited".into())
                } else {
                    Ok(())
                }
            },
            |_| Err(std::io::Error::other("simulated rollback-blocked remove failure")),
            |p| p.clear_pending(),
        );
        assert_eq!(rc_stable_first_err, 9);
        assert!(manager.paths.pending.exists());
        assert!(manager.paths.root.join("rollback-blocked").exists());
        assert!(
            storage::executable(&manager.paths.slot_binary(Slot::A)),
            "previous slot A must stay armed if clearing rollback-blocked fails before disarm"
        );

        // (d) Stable: `clear_rollback_blocked` succeeds BEFORE disarming slot A,
        //     then slot A is durably disarmed and `clear_pending` fails ->
        //     slot A stays DISARMED, `pending` survives, `rollback-blocked` is
        //     already gone, and same-boot shell supervisor boots verified Stable
        //     rescue (exit 0) WITHOUT re-enabling slot A!
        let rc_stable_second_err = recover_with_perf_and_hooks(
            &manager.paths,
            Slot::A,
            None,
            None,
            &perf,
            None,
            |child| {
                std::thread::sleep(Duration::from_millis(80));
                if child.try_wait().ok().flatten().is_some() {
                    Err("exited".into())
                } else {
                    Ok(())
                }
            },
            clear_rollback_blocked_marker,
            |_| Err(std::io::Error::other("simulated pending remove failure")),
        );
        assert_eq!(rc_stable_second_err, 9);
        assert!(
            !storage::executable(&manager.paths.slot_binary(Slot::A)),
            "previous slot A must remain disarmed after Stable fallback failure"
        );
        assert!(
            manager.paths.pending.exists(),
            "pending must survive when second removal fails on Stable recovery"
        );
        assert!(!manager.paths.root.join("rollback-blocked").exists());
        let _ = fs::remove_file(&sup_marker);
        let retry_stable = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &sup_marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(
            retry_stable.success(),
            "same-boot supervisor retry with disarmed slot A must boot verified Stable (got {:?})",
            retry_stable.code()
        );
        assert_eq!(fs::read_to_string(&sup_marker).unwrap(), "stable-retry-ok");

        // When Stable rescue ALSO exits early before reaching its listener,
        // `recover` must return 5, RETAIN `pending` on disk, and NOT leave
        // `rollback-blocked` stranding a subsequent same-boot retry.
        let mut failing_stable =
            b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then exit 0; fi\nexit 1\n".to_vec();
        failing_stable.push(b'#');
        failing_stable.resize(1024, b'x');
        let failing_stable_rel = release_for_binary(Channel::Stable, "2.3.0", &failing_stable);
        fs::write(manager.paths.stable_binary(), &failing_stable).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &failing_stable_rel).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.5.0-beta.1")
            .unwrap();
        write_rollback_blocked_marker_with(&manager.paths, "boot-uuid-1").unwrap();
        let rc2 = recover_with_perf_and_hooks(
            &manager.paths,
            Slot::A,
            None,
            None,
            &perf,
            None,
            |spawned| wait_for_child_listener(spawned, listen_addr, Duration::from_secs(3)),
            clear_rollback_blocked_marker,
            |p| p.clear_pending(),
        );
        assert_eq!(rc2, 5);
        assert!(
            manager.paths.pending.exists(),
            "pending marker must remain on disk when Stable rescue also exits early"
        );
        assert!(
            !manager.paths.root.join("rollback-blocked").exists(),
            "rollback-blocked must already be cleared before disarming previous slot for Stable"
        );
    }

    #[test]
    fn damaged_previous_bootstrap_does_not_block_verified_stable_rescue() {
        let manager = manager("damaged-prev-boot-stable-rescue");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();

        // Previous slot A has a malformed `bootstrap.sha256` (no `release.json`).
        let prev_a = test_agent("2.4.0-beta.7", true, "prev-a");
        fs::write(manager.paths.slot_binary(Slot::A), &prev_a).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::A),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::A));
        fs::write(
            manager.paths.slot_bootstrap_digest(Slot::A),
            "not-a-sha256\n01.2.3\n",
        )
        .unwrap();

        // Candidate slot B is a valid signed release recorded in `pending`.
        let cand_b = test_agent("2.4.0-beta.8", true, "cand-b");
        let rel_b = release_for_binary(Channel::Beta, "2.4.0-beta.8", &cand_b);
        write_release_agent(&manager.paths, Slot::B, &rel_b, &cand_b);

        // Verified Stable rescue is available.
        let stable = test_agent("2.3.0", true, "stable-rescue");
        let rel_stable = release_for_binary(Channel::Stable, "2.3.0", &stable);
        fs::write(manager.paths.stable_binary(), &stable).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &rel_stable).unwrap();

        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.8")
            .unwrap();

        // 1. Shell supervisor must NOT exit 9; it must disarm both slots and
        //    boot the verified Stable rescue cleanly.
        let status = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "damaged previous bootstrap.sha256 must not block verified Stable rescue (got {:?})",
            status.code()
        );
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-rescue");
        assert!(!manager.paths.pending.exists());
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::A)));
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        assert_eq!(
            fs::read_to_string(&manager.paths.active).unwrap().trim(),
            "rescue"
        );
        assert!(
            read_blocked_versions(&manager.paths).unwrap().is_empty(),
            "unknown previous version must disarm candidate by slot rather than poisoning blocked.json"
        );

        // 2. Rust `quarantine_failed_candidate` must also disarm B by slot and
        //    succeed when previous slot A's bootstrap.sha256 is damaged.
        fs::set_permissions(
            manager.paths.slot_binary(Slot::B),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        quarantine_failed_candidate(&manager.paths, Slot::B, "2.4.0-beta.8", Slot::A).unwrap();
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        assert!(read_blocked_versions(&manager.paths).unwrap().is_empty());
    }

    #[test]
    fn rust_recovery_rejects_quarantined_previous_release_and_bootstrap_slots() {
        let manager = manager("recovery-rejects-quarantined-prev");
        let perf_dir = manager.paths.root.join("perf-state");
        let perf = crate::netfx::perf::Perf::for_test(&perf_dir);

        // Seed verified Stable rescue (version distinct from current build).
        let stable_bytes = test_agent("2.3.0", true, "stable-rescue");
        let stable_rel = release_for_binary(Channel::Stable, "2.3.0", &stable_bytes);
        fs::write(manager.paths.stable_binary(), &stable_bytes).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_rel).unwrap();

        // 1. Quarantined versioned `bootstrap.sha256` previous slot A must be
        //    rejected by `verify_recovery_slot` and skipped in favor of Stable rescue.
        let boot_bytes = test_agent(crate::build_info::VERSION, true, "boot-a");
        fs::write(manager.paths.slot_binary(Slot::A), &boot_bytes).unwrap();
        fs::set_permissions(
            manager.paths.slot_binary(Slot::A),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::A));
        fs::write(
            manager.paths.slot_bootstrap_digest(Slot::A),
            format!("{}\n{}\n", sha256(&boot_bytes), crate::build_info::VERSION),
        )
        .unwrap();
        block_version(&manager.paths, crate::build_info::VERSION).unwrap();

        assert!(
            verify_recovery_slot(&manager.paths, Slot::A)
                .unwrap_err()
                .contains("quarantined")
        );
        assert_eq!(
            recover_with_perf(&manager.paths, Slot::A, None, None, &perf),
            6,
            "Rust recovery must skip quarantined bootstrap previous slot and boot Stable rescue"
        );
        assert_eq!(
            fs::read_to_string(&manager.paths.active).unwrap().trim(),
            "rescue"
        );

        // 2. Quarantined `release.json` previous slot A must also be rejected.
        let rel_a = release_for_binary(Channel::Stable, crate::build_info::VERSION, &boot_bytes);
        let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::A));
        write_release_agent(&manager.paths, Slot::A, &rel_a, &boot_bytes);
        assert!(
            verify_recovery_slot(&manager.paths, Slot::A)
                .unwrap_err()
                .contains("quarantined")
        );
    }

    #[test]
    fn supervisor_marker_removal_and_truncated_release_meta_agreement() {
        let manager = manager("supervisor-marker-and-truncated-meta");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let boot_id_file = manager.paths.root.join("boot_id");
        fs::write(&boot_id_file, "boot-uuid-trunc\n").unwrap();
        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();

        // A. Shell supervisor MUST NOT exec replacement when removing
        //    `rollback-blocked`, removing `pending`, or syncing fails; and a
        //    `rollback-blocked` removal failure MUST preserve `pending`.
        let prev_script = b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then [ \"${2:-}\" = \"2.3.5\" ] && exit 0; exit 2; fi\nif [ \"${1:-}\" = network-recover ]; then exit 0; fi\n[ -z \"${ZTE_TEST_MARKER:-}\" ] || printf 'prev-a:%s:%s:%s' \"${ZTE_OTA_SUPERVISOR:-}\" \"${ZTE_OTA_REAL_SUPERVISOR:-}\" \"${ZTE_OTA_TRIAL:-}\" > \"$ZTE_TEST_MARKER\"\n#".to_vec();
        let mut prev_bytes = prev_script;
        prev_bytes.resize(1024, b'x');
        let prev_rel = release_for_binary(Channel::Stable, "2.3.5", &prev_bytes);
        write_release_agent(&manager.paths, Slot::A, &prev_rel, &prev_bytes);

        let cand_bytes = test_agent("2.4.0-beta.9", true, "cand-b");
        let cand_rel = release_for_binary(Channel::Beta, "2.4.0-beta.9", &cand_bytes);
        write_release_agent(&manager.paths, Slot::B, &cand_rel, &cand_bytes);

        let stable_bytes = test_agent("2.3.0", true, "stable-rescue");
        let stable_rel = release_for_binary(Channel::Stable, "2.3.0", &stable_bytes);
        fs::write(manager.paths.stable_binary(), &stable_bytes).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_rel).unwrap();

        // A1. Unremovable `rollback-blocked` directory -> exit 9, `pending` kept, no exec.
        let rb_dir = manager.paths.root.join("rollback-blocked");
        fs::create_dir_all(&rb_dir).unwrap();
        fs::write(rb_dir.join("keep"), "x").unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let _ = fs::remove_file(&marker);
        let st_rb_fail = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(st_rb_fail.code(), Some(9));
        assert!(manager.paths.pending.exists(), "pending must survive rollback-blocked removal failure");
        assert!(!marker.exists(), "replacement must not exec when rollback-blocked removal fails");
        fs::remove_dir_all(&rb_dir).unwrap();

        // A2. Failing `rm` on `pending` (via shadowed PATH shim) -> exit 9, `pending` kept, no exec.
        let shim_bin = manager.paths.root.join("shim-rm");
        fs::create_dir_all(&shim_bin).unwrap();
        let rm_shim = format!(
            "#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = \"{}\" ]; then exit 1; fi\ndone\nexec /bin/rm \"$@\"\n",
            manager.paths.pending.display()
        );
        fs::write(shim_bin.join("rm"), rm_shim).unwrap();
        fs::set_permissions(shim_bin.join("rm"), fs::Permissions::from_mode(0o755)).unwrap();
        write_rollback_blocked_marker_with(&manager.paths, "boot-uuid-trunc").unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let orig_path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
        let _ = fs::remove_file(&marker);
        let st_pending_fail = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("PATH", format!("{}:{orig_path}", shim_bin.display()))
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(st_pending_fail.code(), Some(9));
        assert!(manager.paths.pending.exists(), "pending must still exist after failed rm");
        assert!(!rb_dir.exists(), "rollback-blocked must have been removed before pending");
        assert!(!marker.exists(), "replacement must not exec when pending removal fails");

        // A3. Path-specific `sync` failure IMMEDIATELY AFTER `rollback-blocked`
        //     is removed — while bare `sync` STILL succeeds — MUST stop handoff
        //     (exit 9), leave `pending` intact, and NEVER exec slot A!
        let shim_sync = manager.paths.root.join("shim-sync");
        fs::create_dir_all(&shim_sync).unwrap();
        let sync_shim = format!(
            concat!(
                "#!/bin/sh\n",
                "if [ \"$#\" -eq 0 ]; then exit 0; fi\n",
                "if [ \"$1\" = \"{}\" ] && [ ! -e \"{}\" ]; then\n",
                "  echo \"sync: error syncing '$1': Input/output error\" >&2\n",
                "  exit 1\n",
                "fi\n",
                "exit 0\n"
            ),
            manager.paths.root.display(),
            rb_dir.display(),
        );
        fs::write(shim_sync.join("sync"), sync_shim).unwrap();
        fs::set_permissions(shim_sync.join("sync"), fs::Permissions::from_mode(0o755)).unwrap();
        write_rollback_blocked_marker_with(&manager.paths, "boot-uuid-trunc").unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let _ = fs::remove_file(&marker);
        let st_sync_fail = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("PATH", format!("{}:{orig_path}", shim_sync.display()))
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            st_sync_fail.code(),
            Some(9),
            "path-specific sync I/O error after removing rollback-blocked must abort even if bare sync succeeds"
        );
        assert!(manager.paths.pending.exists(), "pending must remain when marker sync fails");
        assert!(!marker.exists(), "replacement must not exec when marker sync fails");

        // A4. Path-specific `sync` failure when syncing a disarmed slot binary
        //     (while bare `sync` succeeds) MUST abort (exit 9) and retain `pending`.
        let shim_disarm_sync = manager.paths.root.join("shim-disarm-sync");
        fs::create_dir_all(&shim_disarm_sync).unwrap();
        let disarm_sync_shim = format!(
            "#!/bin/sh\nif [ \"$#\" -eq 0 ]; then exit 0; fi\nif [ \"$1\" = \"{}\" ]; then echo 'sync: I/O error' >&2; exit 1; fi\nexit 0\n",
            manager.paths.slot_binary(Slot::B).display(),
        );
        fs::write(shim_disarm_sync.join("sync"), disarm_sync_shim).unwrap();
        fs::set_permissions(
            shim_disarm_sync.join("sync"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let truncated_cand_for_disarm = b"{\"schema\":1,\"version\":\"2.4.0-beta.9\",\n";
        let saved_cand_meta_b = fs::read(manager.paths.slot_meta(Slot::B)).unwrap();
        fs::write(manager.paths.slot_meta(Slot::B), truncated_cand_for_disarm).unwrap();
        fs::set_permissions(manager.paths.slot_binary(Slot::B), fs::Permissions::from_mode(0o755))
            .unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let _ = fs::remove_file(&marker);
        let st_disarm_sync_fail = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("PATH", format!("{}:{orig_path}", shim_disarm_sync.display()))
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(st_disarm_sync_fail.code(), Some(9));
        assert!(manager.paths.pending.exists());
        assert!(!marker.exists());
        fs::write(manager.paths.slot_meta(Slot::B), &saved_cand_meta_b).unwrap();
        fs::set_permissions(manager.paths.slot_binary(Slot::B), fs::Permissions::from_mode(0o755))
            .unwrap();

        // A5. Shell-launched legacy `965ebfe` agent on cold start (receiving the
        //     real supervisor path in `ZTE_OTA_SUPERVISOR`, just like
        //     `start_zte_agent.sh`) MUST receive the shadow path in
        //     `ZTE_OTA_SUPERVISOR` and the real path in `ZTE_OTA_REAL_SUPERVISOR`
        //     so its startup repair cannot overwrite the hardened supervisor!
        let hardened_supervisor = fs::read(&manager.paths.supervisor).unwrap();
        let mut legacy_cold_prev = b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then [ \"${2:-}\" = \"2.3.5\" ] && exit 0; exit 2; fi\nif [ \"${1:-}\" = network-recover ]; then exit 0; fi\nsup=\"${ZTE_OTA_SUPERVISOR:-/data/local/tmp/zte-agent-supervisor.sh}\"\nprintf 'legacy-overwrite\\n' > \"$sup\"\nchmod 755 \"$sup\"\n[ -z \"${ZTE_TEST_MARKER:-}\" ] || printf 'prev-a:%s:%s:%s' \"${ZTE_OTA_SUPERVISOR:-}\" \"${ZTE_OTA_REAL_SUPERVISOR:-}\" \"${ZTE_OTA_TRIAL:-}\" > \"$ZTE_TEST_MARKER\"\n#".to_vec();
        legacy_cold_prev.resize(1024, b'x');
        let legacy_cold_rel = release_for_binary(Channel::Stable, "2.3.5", &legacy_cold_prev);
        write_release_agent(&manager.paths, Slot::A, &legacy_cold_rel, &legacy_cold_prev);
        let _ = fs::remove_file(&manager.paths.blocked);
        let _ = fs::remove_file(&marker);
        let st_ok = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_OTA_SUPERVISOR", &manager.paths.supervisor)
            .env_remove("ZTE_OTA_REAL_SUPERVISOR")
            .env("ZTE_OTA_TRIAL", "1")
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(st_ok.success());
        assert_eq!(
            fs::read(&manager.paths.supervisor).unwrap(),
            hardened_supervisor,
            "shell-launched legacy agent must not overwrite the real hardened supervisor"
        );
        assert_eq!(
            fs::read_to_string(manager.paths.legacy_supervisor_shadow()).unwrap(),
            "legacy-overwrite\n"
        );
        assert_eq!(
            fs::read_to_string(&marker).unwrap(),
            format!(
                "prev-a:{}:{}:",
                manager.paths.legacy_supervisor_shadow().display(),
                manager.paths.supervisor.display()
            )
        );
        // Restore clean prev_bytes for subsequent checks.
        write_release_agent(&manager.paths, Slot::A, &prev_rel, &prev_bytes);

        // B. Cross-implementation Rust vs Shell agreement on damaged `release.json`
        // B1. Truncated previous-slot `release.json` immediately after `"version"`.
        let truncated_prev = b"{\n  \"schema\": 1,\n  \"channel\": \"stable\",\n  \"version\": \"2.3.5\",\n";
        fs::write(manager.paths.slot_meta(Slot::A), truncated_prev).unwrap();
        let _ = fs::remove_file(&manager.paths.blocked);
        fs::set_permissions(manager.paths.slot_binary(Slot::B), fs::Permissions::from_mode(0o755))
            .unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let _ = fs::remove_file(&marker);
        let st_trunc_prev = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(st_trunc_prev.success(), "truncated previous release.json must boot verified Stable");
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-rescue");
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        assert!(
            read_blocked_versions(&manager.paths).unwrap().is_empty(),
            "shell must NOT globally quarantine candidate when previous release.json is truncated"
        );
        fs::set_permissions(manager.paths.slot_binary(Slot::B), fs::Permissions::from_mode(0o755))
            .unwrap();
        quarantine_failed_candidate(&manager.paths, Slot::B, "2.4.0-beta.9", Slot::A).unwrap();
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        assert!(read_blocked_versions(&manager.paths).unwrap().is_empty());

        // B2. Truncated `last-stable/release.json` immediately after `"version"`.
        write_release_agent(&manager.paths, Slot::A, &prev_rel, &prev_bytes);
        let truncated_stable = b"{\n  \"schema\": 1,\n  \"channel\": \"stable\",\n  \"version\": \"2.3.0\",\n";
        fs::write(manager.paths.stable_meta(), truncated_stable).unwrap();
        let _ = fs::remove_file(&manager.paths.blocked);
        fs::set_permissions(manager.paths.slot_binary(Slot::B), fs::Permissions::from_mode(0o755))
            .unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let _ = fs::remove_file(&marker);
        let st_trunc_stable = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(st_trunc_stable.success(), "truncated last-stable release.json must boot valid previous slot A");
        assert!(fs::read_to_string(&marker).unwrap().starts_with("prev-a:"));
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        assert!(
            read_blocked_versions(&manager.paths).unwrap().is_empty(),
            "shell must NOT globally quarantine candidate when last-stable release.json is truncated"
        );
        fs::set_permissions(manager.paths.slot_binary(Slot::B), fs::Permissions::from_mode(0o755))
            .unwrap();
        quarantine_failed_candidate(&manager.paths, Slot::B, "2.4.0-beta.9", Slot::A).unwrap();
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
        assert!(read_blocked_versions(&manager.paths).unwrap().is_empty());
        // Restore valid Stable metadata for remaining checks.
        storage::write_json(&manager.paths.stable_meta(), &stable_rel).unwrap();

        // B3. Candidate `release.json` > 256 KiB via trailing whitespace AND
        //     candidate `release.json` with escaped `\n` in `sha256`: BOTH Shell
        //     and Rust MUST disarm slot B without globally quarantining it.
        let mut oversized_cand = serde_json::to_vec_pretty(&cand_rel).unwrap();
        oversized_cand.resize(262_145, b' ');
        let mut newline_sha_rel = cand_rel.clone();
        newline_sha_rel.sha256 = format!("{}\n", "a".repeat(63));
        let newline_sha_bytes = serde_json::to_vec_pretty(&newline_sha_rel).unwrap();
        for (label, bad_cand_meta) in [
            ("oversized >256KiB", oversized_cand),
            ("escaped newline in sha256", newline_sha_bytes),
        ] {
            let _ = fs::remove_file(&manager.paths.blocked);
            fs::set_permissions(
                manager.paths.slot_binary(Slot::B),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            fs::write(manager.paths.slot_meta(Slot::B), &bad_cand_meta).unwrap();
            manager
                .paths
                .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
                .unwrap();
            let _ = fs::remove_file(&marker);
            let st = Command::new("sh")
                .arg(&manager.paths.supervisor)
                .env("ZTE_OTA_ROOT", &manager.paths.root)
                .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
                .env("ZTE_TEST_MARKER", &marker)
                .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
                .env("ZTE_BOOT_ID_PATH", &boot_id_file)
                .env("ZTE_PROC_ROOT", &fake_proc)
                .status()
                .unwrap();
            assert!(st.success(), "{label}: shell supervisor must boot valid previous slot");
            assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
            assert!(
                read_blocked_versions(&manager.paths).unwrap().is_empty(),
                "{label}: shell must disarm candidate slot rather than globally quarantining"
            );

            fs::set_permissions(
                manager.paths.slot_binary(Slot::B),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            quarantine_failed_candidate(&manager.paths, Slot::B, "2.4.0-beta.9", Slot::A).unwrap();
            assert!(!storage::executable(&manager.paths.slot_binary(Slot::B)));
            assert!(
                read_blocked_versions(&manager.paths).unwrap().is_empty(),
                "{label}: Rust must match shell and disarm candidate slot"
            );
        }

        // B4. Boot selection with `schema: 2` on previous slot A: BOTH Rust
        //     `verify_recovery_slot` AND Shell supervisor MUST reject slot A
        //     and select verified Stable rescue!
        let mut schema2_rel = prev_rel.clone();
        schema2_rel.schema = 2;
        write_release_agent(&manager.paths, Slot::A, &schema2_rel, &prev_bytes);
        assert!(
            verify_recovery_slot(&manager.paths, Slot::A).is_err(),
            "Rust recovery must reject schema: 2"
        );
        let _ = fs::remove_file(&manager.paths.blocked);
        let _ = fs::remove_file(&manager.paths.pending);
        manager.paths.write_active(Slot::A).unwrap();
        let _ = fs::remove_file(&marker);
        let st_schema2 = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(st_schema2.success());
        assert_eq!(
            fs::read_to_string(&marker).unwrap(),
            "stable-rescue",
            "shell boot selection must reject schema: 2 and fall back to verified Stable"
        );

        // C. Non-regular metadata entries (directory at `slot-a/release.json`
        //    or `slot-a/bootstrap.sha256`) MUST NOT fall through to
        //    executable-only boot!
        for meta_name in ["release.json", "bootstrap.sha256"] {
            let _ = fs::remove_file(manager.paths.slot_meta(Slot::A));
            let _ = fs::remove_dir_all(manager.paths.slot_meta(Slot::A));
            let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::A));
            let _ = fs::remove_dir_all(manager.paths.slot_bootstrap_digest(Slot::A));
            fs::write(manager.paths.slot_binary(Slot::A), &prev_bytes).unwrap();
            fs::set_permissions(
                manager.paths.slot_binary(Slot::A),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            fs::create_dir_all(manager.paths.slot_dir(Slot::A).join(meta_name)).unwrap();
            manager.paths.write_active(Slot::A).unwrap();
            let _ = fs::remove_file(&marker);
            let st_dir_meta = Command::new("sh")
                .arg(&manager.paths.supervisor)
                .env("ZTE_OTA_ROOT", &manager.paths.root)
                .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
                .env("ZTE_TEST_MARKER", &marker)
                .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
                .env("ZTE_BOOT_ID_PATH", &boot_id_file)
                .env("ZTE_PROC_ROOT", &fake_proc)
                .status()
                .unwrap();
            assert!(st_dir_meta.success());
            assert_eq!(
                fs::read_to_string(&marker).unwrap(),
                "stable-rescue",
                "directory at slot-a/{meta_name} must NOT enable executable-only boot"
            );
            let _ = fs::remove_dir_all(manager.paths.slot_dir(Slot::A).join(meta_name));
        }

        // D. Promotion error handler MUST restore & verify `pending` BEFORE
        //    publishing `rollback-blocked` — even after `clear_pending` already
        //    unlinked `pending` and failed `sync_parent` — and MUST NEVER create
        //    an orphaned `rollback-blocked` if `write_pending` fails!
        let _ = fs::remove_file(&manager.paths.pending);
        let _ = fs::remove_file(&rb_dir);
        let order = std::cell::RefCell::new(Vec::new());
        restore_handoff_markers_before_recovery_with(
            || {
                order.borrow_mut().push("write-pending");
                manager.paths.write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            },
            || {
                order.borrow_mut().push("verify-pending");
                manager.paths.pending.try_exists().unwrap_or(false)
            },
            || {
                assert!(
                    manager.paths.pending.exists(),
                    "pending must exist on disk before writing rollback-blocked"
                );
                order.borrow_mut().push("write-rollback-blocked");
                write_rollback_blocked_marker_with(&manager.paths, "boot-uuid-trunc")
            },
        )
        .unwrap();
        assert_eq!(
            *order.borrow(),
            vec!["write-pending", "verify-pending", "write-rollback-blocked"]
        );

        // Now simulate `clear_pending` unlinking `pending` then failing sync,
        // followed by a failed `write_pending` restore: `rollback-blocked` MUST
        // NOT be created!
        let _ = fs::remove_file(&rb_dir);
        let _ = fs::remove_file(&manager.paths.pending);
        let mut rb_called = false;
        let err = restore_handoff_markers_before_recovery_with(
            || Err(std::io::Error::other("simulated write_pending failure after unlink")),
            || manager.paths.pending.try_exists().unwrap_or(false),
            || {
                rb_called = true;
                write_rollback_blocked_marker_with(&manager.paths, "boot-uuid-trunc")
            },
        );
        assert!(err.is_err());
        assert!(!rb_called, "rollback-blocked must NEVER be written if pending restore failed");
        assert!(!rb_dir.exists(), "must never leave an orphaned rollback-blocked marker");
    }

    #[test]
    fn round15_shell_rollback_attempt_rescue_sync_and_cross_impl_edges() {
        let manager = manager("round15-hardening-edges");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let boot_id_file = manager.paths.root.join("boot_id");
        fs::write(&boot_id_file, "boot-uuid-r15\n").unwrap();
        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();
        let orig_path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());

        // 1. P1 #1 / Round 16 P1 #5: Shell rollback with a previous slot that
        //    passes `ota-probe` but exits 1 during normal startup (before
        //    starting its guard): ONE invocation automatically advances to
        //    verified Stable rescue via the rollback attempt owner (NO manual
        //    second invocation needed!).
        let failing_prev = pad_script(
            b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then [ \"${2:-}\" = \"2.3.5\" ] && exit 0; exit 2; fi\nexit 1\n",
        );
        let failing_prev_rel = release_for_binary(Channel::Stable, "2.3.5", &failing_prev);
        write_release_agent(&manager.paths, Slot::A, &failing_prev_rel, &failing_prev);
        let cand_b = test_agent("2.4.0-beta.9", true, "cand-b");
        let cand_b_rel = release_for_binary(Channel::Beta, "2.4.0-beta.9", &cand_b);
        write_release_agent(&manager.paths, Slot::B, &cand_b_rel, &cand_b);
        let stable_bytes = test_agent("2.3.0", true, "stable-after-failed-prev");
        let stable_rel = release_for_binary(Channel::Stable, "2.3.0", &stable_bytes);
        fs::write(manager.paths.stable_binary(), &stable_bytes).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_rel).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();

        let no_launcher = manager.paths.root.join("no-launcher.sh");
        let st1 = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_SUPERVISOR", &manager.paths.supervisor)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_AGENT_LAUNCHER", &no_launcher)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(st1.code(), Some(1), "first invocation execs failing previous slot A");
        let auto_deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < auto_deadline
            && (fs::read_to_string(&marker).ok().as_deref() != Some("stable-after-failed-prev")
                || manager.paths.rollback_attempt().exists())
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            fs::read_to_string(&marker).unwrap_or_default(),
            "stable-after-failed-prev",
            "rollback attempt owner must advance to verified Stable automatically without a manual second invocation"
        );
        assert_eq!(fs::read_to_string(&manager.paths.active).unwrap().trim(), "rescue");
        assert!(!manager.paths.rollback_attempt().exists());
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::A)));

        // 1b. Round 16 P1 #5 (enforced timeout + ZTE_AGENT_LAUNCHER handoff):
        //     A slow/hung legacy previous slot that never binds its listener
        //     within the configured poll timeout MUST be terminated by the
        //     rollback owner and handed off via ZTE_AGENT_LAUNCHER to verified
        //     Stable rescue (never surviving past timeout with a stale marker!).
        let hung_pid_file = manager.paths.root.join("hung-prev.pid");
        let hung_prev = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then [ \"${{2:-}}\" = \"2.3.5\" ] && exit 0; exit 2; fi\nprintf '%s\\n' \"$$\" > \"{}\"\nexec sleep 60\n",
            hung_pid_file.display()
        ));
        let hung_prev_rel = release_for_binary(Channel::Stable, "2.3.5", &hung_prev);
        write_release_agent(&manager.paths, Slot::A, &hung_prev_rel, &hung_prev);
        write_release_agent(&manager.paths, Slot::B, &cand_b_rel, &cand_b);
        let _ = fs::remove_file(&manager.paths.blocked);
        let _ = fs::remove_file(&marker);
        let _ = fs::remove_file(&hung_pid_file);
        manager.paths.write_active(Slot::A).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let launcher_called = manager.paths.root.join("launcher-called");
        let fake_launcher = manager.paths.root.join("start_zte_agent.sh");
        fs::write(
            &fake_launcher,
            format!(
                "#!/bin/sh\nprintf 'called' > \"{}\"\nexec sh \"{}\"\n",
                launcher_called.display(),
                manager.paths.supervisor.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_launcher, fs::Permissions::from_mode(0o755)).unwrap();
        let mut hung_child = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_SUPERVISOR", &manager.paths.supervisor)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_AGENT_LAUNCHER", &fake_launcher)
            .env("ZTE_OTA_ROLLBACK_WAIT_POLLS", "3")
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .spawn()
            .unwrap();
        let timeout_deadline = Instant::now() + Duration::from_secs(8);
        while Instant::now() < timeout_deadline
            && (fs::read_to_string(&marker).ok().as_deref() != Some("stable-after-failed-prev")
                || manager.paths.rollback_attempt().exists())
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        let hung_exit = hung_child.wait().unwrap();
        assert!(
            !hung_exit.success(),
            "rollback owner must enforce timeout by terminating hung previous slot (got {:?})",
            hung_exit
        );
        assert_eq!(fs::read_to_string(&launcher_called).unwrap_or_default(), "called");
        assert_eq!(
            fs::read_to_string(&marker).unwrap_or_default(),
            "stable-after-failed-prev"
        );
        assert_eq!(fs::read_to_string(&manager.paths.active).unwrap().trim(), "rescue");
        assert!(!manager.paths.rollback_attempt().exists());
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::A)));

        // 1c. Round 16 P2 #4: Native listener executable using real Linux `/proc`
        //     on Linux (and macOS `lsof` on macOS) so CI exercises the exact
        //     production `/proc/$pid/exe` + `/proc/$pid/fd` + `/proc/$pid/net/tcp`
        //     ownership check without relying on a Python wrapper or fake `/proc`.
        let reserve = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bind_port = reserve.local_addr().unwrap().port();
        drop(reserve);
        let listener_c = manager.paths.root.join("native-listener.c");
        let listener_bin = manager.paths.root.join("native-listener");
        fs::write(
            &listener_c,
            r#"#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "ota-probe") == 0) {
        return (argc >= 3 && strcmp(argv[2], "2.3.5") == 0) ? 0 : 2;
    }
    const char *port_s = getenv("ZTE_TEST_LISTEN_PORT");
    int port = port_s ? atoi(port_s) : 0;
    if (port <= 0 || port > 65535) return 3;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 4;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 5;
    if (listen(fd, 4) < 0) return 6;
    sleep(10);
    return 0;
}
"#,
        )
        .unwrap();
        let cc_status = Command::new("cc")
            .arg("-O2")
            .arg(&listener_c)
            .arg("-o")
            .arg(&listener_bin)
            .status()
            .expect("compile native listener fixture with cc");
        assert!(cc_status.success(), "native listener fixture must compile");
        let listening_prev = fs::read(&listener_bin).unwrap();
        let listening_prev_rel = release_for_binary(Channel::Stable, "2.3.5", &listening_prev);
        write_release_agent(&manager.paths, Slot::A, &listening_prev_rel, &listening_prev);
        write_release_agent(&manager.paths, Slot::B, &cand_b_rel, &cand_b);
        let _ = fs::remove_file(&manager.paths.blocked);
        manager.paths.write_active(Slot::A).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let proc_root_for_listener = if cfg!(target_os = "linux") {
            PathBuf::from("/proc")
        } else {
            fake_proc.clone()
        };
        let mut healthy_child = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_SUPERVISOR", &manager.paths.supervisor)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_AGENT_LAUNCHER", &no_launcher)
            .env("ZTE_AGENT_BIND", format!("127.0.0.1:{bind_port}"))
            .env("ZTE_TEST_LISTEN_PORT", bind_port.to_string())
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &proc_root_for_listener)
            .spawn()
            .unwrap();
        let listen_addr = SocketAddr::from(([127, 0, 0, 1], bind_port));
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut listener_reachable = false;
        while Instant::now() < deadline {
            if !manager.paths.pending.exists() && !manager.paths.rollback_attempt().exists() {
                if TcpStream::connect_timeout(&listen_addr, Duration::from_millis(200)).is_ok() {
                    listener_reachable = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let pending_cleared = !manager.paths.pending.exists();
        let attempt_cleared = !manager.paths.rollback_attempt().exists();
        let still_running = healthy_child.try_wait().unwrap().is_none();
        let _ = healthy_child.kill();
        let _ = healthy_child.wait();
        assert!(
            pending_cleared && attempt_cleared && listener_reachable && still_running,
            "rollback owner must finish pending handoff, observe native listener, and clear rollback-attempt while child stays running (pending_cleared={pending_cleared}, attempt_cleared={attempt_cleared}, listener_reachable={listener_reachable}, running={still_running})"
        );

        // 2. P1 #2: Shell rescue with ONE sync failure on slot A after chmod 600:
        //    because shell clears `rollback-blocked` BEFORE disarming slot A,
        //    first run exits 9 with `pending` kept & `rollback-blocked` cleared,
        //    and retry (fault removed) exits 0 booting verified Stable (NOT exit 8)!
        let probe_fail_a = pad_script(
            b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then exit 2; fi\nif [ \"${1:-}\" = network-recover ]; then exit 0; fi\nexit 0\n",
        );
        let probe_fail_a_rel = release_for_binary(Channel::Stable, "2.3.5", &probe_fail_a);
        write_release_agent(&manager.paths, Slot::A, &probe_fail_a_rel, &probe_fail_a);
        let _ = fs::remove_file(&manager.paths.blocked);
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        write_rollback_blocked_marker_with(&manager.paths, "boot-uuid-r15").unwrap();
        let shim_a_sync = manager.paths.root.join("shim-a-sync");
        fs::create_dir_all(&shim_a_sync).unwrap();
        fs::write(
            shim_a_sync.join("sync"),
            format!(
                "#!/bin/sh\nif [ \"$#\" -eq 0 ]; then exit 0; fi\nif [ \"$1\" = \"{}\" ]; then echo 'sync: I/O error' >&2; exit 1; fi\nexit 0\n",
                manager.paths.slot_binary(Slot::A).display()
            ),
        )
        .unwrap();
        fs::set_permissions(shim_a_sync.join("sync"), fs::Permissions::from_mode(0o755)).unwrap();
        let _ = fs::remove_file(&marker);
        let st_fail_a_sync = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("PATH", format!("{}:{orig_path}", shim_a_sync.display()))
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(st_fail_a_sync.code(), Some(9));
        assert!(manager.paths.pending.exists());
        assert!(!manager.paths.root.join("rollback-blocked").exists());
        assert!(!storage::executable(&manager.paths.slot_binary(Slot::A)));
        let st_retry_rescue = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(
            st_retry_rescue.success(),
            "retry after slot-A disarm sync failure must boot verified Stable instead of exiting 8 (got {:?})",
            st_retry_rescue.code()
        );
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-after-failed-prev");

        // 3. P1 #3: Both A & B disarmed + live `tailscaled` AND same-boot journal:
        //    verified Stable rescue runs `network-recover`, cleans both, and boots!
        let ts_journal = manager.paths.root.join("ts-net-r15.json");
        fs::write(&ts_journal, "{\"boot\":\"boot-uuid-r15\",\"undo\":[]}\n").unwrap();
        fs::create_dir_all(fake_proc.join("7777")).unwrap();
        fs::write(fake_proc.join("7777/stat"), "7777 (tailscaled) S 1 1 1 0\n").unwrap();
        fs::write(fake_proc.join("7777/comm"), "tailscaled\n").unwrap();
        let stable_cleaner = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then [ \"${{2:-}}\" = \"2.3.0\" ] && exit 0; exit 2; fi\nif [ \"${{1:-}}\" = network-recover ]; then rm -rf \"{}/7777\" \"{}\"; exit 0; fi\n[ -z \"${{ZTE_TEST_MARKER:-}}\" ] || printf 'stable-cleaned' > \"$ZTE_TEST_MARKER\"\n",
            fake_proc.display(),
            ts_journal.display()
        ));
        let stable_cleaner_rel = release_for_binary(Channel::Stable, "2.3.0", &stable_cleaner);
        fs::write(manager.paths.stable_binary(), &stable_cleaner).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_cleaner_rel).unwrap();
        fs::set_permissions(manager.paths.slot_binary(Slot::A), fs::Permissions::from_mode(0o600))
            .unwrap();
        fs::set_permissions(manager.paths.slot_binary(Slot::B), fs::Permissions::from_mode(0o600))
            .unwrap();
        let _ = fs::remove_file(&manager.paths.blocked);
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let _ = fs::remove_file(&marker);
        let st_stable_clean = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(
            st_stable_clean.success(),
            "verified Stable rescue must clean up interrupted daemon/journal when A and B are disarmed (got {:?})",
            st_stable_clean.code()
        );
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-cleaned");
        assert!(!ts_journal.exists());
        assert!(!fake_proc.join("7777").exists());

        // 4. P2 #1: Failing path-specific sync on `active.tmp` OR `blocked.json.tmp`
        //    must abort with exit 9, remove the temp file, keep `pending`, and not exec.
        let good_a = test_agent("2.3.5", true, "good-a");
        let good_a_rel = release_for_binary(Channel::Stable, "2.3.5", &good_a);
        write_release_agent(&manager.paths, Slot::A, &good_a_rel, &good_a);
        write_release_agent(&manager.paths, Slot::B, &cand_b_rel, &cand_b);
        for tmp_name in ["active.tmp", "blocked.json.tmp"] {
            let shim_tmp = manager.paths.root.join(format!("shim-{tmp_name}"));
            fs::create_dir_all(&shim_tmp).unwrap();
            let target_tmp = manager.paths.root.join(tmp_name);
            fs::write(
                shim_tmp.join("sync"),
                format!(
                    "#!/bin/sh\nif [ \"$#\" -eq 0 ]; then exit 0; fi\nif [ \"$1\" = \"{}\" ]; then echo 'sync: I/O error' >&2; exit 1; fi\nexit 0\n",
                    target_tmp.display()
                ),
            )
            .unwrap();
            fs::set_permissions(shim_tmp.join("sync"), fs::Permissions::from_mode(0o755)).unwrap();
            let _ = fs::remove_file(&manager.paths.blocked);
            manager
                .paths
                .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
                .unwrap();
            let _ = fs::remove_file(&marker);
            let st_tmp = Command::new("sh")
                .arg(&manager.paths.supervisor)
                .env("PATH", format!("{}:{orig_path}", shim_tmp.display()))
                .env("ZTE_OTA_ROOT", &manager.paths.root)
                .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
                .env("ZTE_TEST_MARKER", &marker)
                .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
                .env("ZTE_BOOT_ID_PATH", &boot_id_file)
                .env("ZTE_PROC_ROOT", &fake_proc)
                .status()
                .unwrap();
            assert_eq!(st_tmp.code(), Some(9), "sync failure on {tmp_name} must exit 9");
            assert!(!target_tmp.exists(), "{tmp_name} must be cleaned up on sync error");
            assert!(manager.paths.pending.exists());
            assert!(!marker.exists());
        }

        // 5. P2 #2: Rust `manifest.validate()` rejects explicit `:443` URL and
        //    escaped NUL in `published_at` (matching Shell `parse_release_meta`!).
        let mut port443 = good_a_rel.clone();
        port443.binary_url = format!(
            "https://github.com:443/jesther-ai/open-u60-pro/releases/download/{}/zte-agent",
            port443.tag
        );
        assert!(port443.validate().is_err(), "explicit :443 URL must be rejected");
        let mut nul_pub = good_a_rel.clone();
        nul_pub.published_at = "2026-11-02\0Z".into();
        assert!(nul_pub.validate().is_err(), "NUL in published_at must be rejected");

        // 6. P2 #3: Unified 256 KiB cap on `blocked.json` across Rust & Shell.
        let mut huge_blocked = vec![b'['];
        huge_blocked.resize(storage::MAX_JSON_BYTES, b' ');
        huge_blocked.push(b']');
        assert_eq!(huge_blocked.len(), storage::MAX_JSON_BYTES + 1);
        fs::write(&manager.paths.blocked, &huge_blocked).unwrap();
        assert!(
            read_blocked_versions(&manager.paths).is_err(),
            "Rust read_blocked_versions must enforce the same 256 KiB cap as shell"
        );
        let _ = fs::remove_file(&manager.paths.blocked);

        // 7. P2 #4: Dangling symlink and FIFO at `slot-b/release.json` must be
        //    rejected by Rust without falling through to executable-only or blocking!
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::B));
        let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::B));
        std::os::unix::fs::symlink(
            manager.paths.root.join("does-not-exist"),
            manager.paths.slot_meta(Slot::B),
        )
        .unwrap();
        assert!(
            verify_rollback_slot(&manager.paths, Slot::B).is_err(),
            "dangling symlink at release.json must not fall through to executable-only"
        );
        assert!(slot_quarantined(&manager.paths, Slot::B));
        fs::remove_file(manager.paths.slot_meta(Slot::B)).unwrap();

        let fifo_path = manager.paths.slot_meta(Slot::B);
        let c_fifo = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated path with private mode 0600.
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
        assert!(
            storage::read_json::<ReleaseManifest>(&fifo_path).is_none(),
            "FIFO at release.json must be rejected immediately without blocking"
        );
        assert!(
            verify_rollback_slot(&manager.paths, Slot::B).is_err(),
            "FIFO at release.json must not fall through or block"
        );
        fs::remove_file(&fifo_path).unwrap();
    }

    #[test]
    fn round16_recovery_restore_rescue_owner_and_channel_checks() {
        let manager = manager("round16-recovery-rescue-checks");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let boot_id_file = manager.paths.root.join("boot_id");
        fs::write(&boot_id_file, "boot-uuid-r16\n").unwrap();
        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();
        let perf = crate::netfx::perf::Perf::for_test(&manager.paths.root.join("perf-r16"));

        // 1. P1 #1: Restore-before-stop on BOTH previous-slot AND Stable recovery
        //    branches when `clear_pending` ACTUALLY unlinks `pending` then fails!
        let sleeper_prev = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then [ \"${{2:-}}\" = \"{}\" ] && exit 0; exit 2; fi\nexec sleep 30\n",
            crate::build_info::VERSION
        ));
        let sleeper_prev_rel =
            release_for_binary(Channel::Stable, crate::build_info::VERSION, &sleeper_prev);
        write_release_agent(&manager.paths, Slot::A, &sleeper_prev_rel, &sleeper_prev);
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.5.0-beta.1")
            .unwrap();
        let prev_pid_ok = std::cell::Cell::new(None);
        let mut restored_while_alive = false;
        let rc_prev_restore_ok = recover_with_perf_and_restore_hooks(
            &manager.paths,
            Slot::A,
            None,
            None,
            &perf,
            None,
            |child| {
                prev_pid_ok.set(Some(child.id()));
                Ok(())
            },
            clear_rollback_blocked_marker,
            |p| {
                // Simulate `clear_pending` unlinking `pending` then failing sync.
                fs::remove_file(&p.pending)?;
                Err(std::io::Error::other("simulated sync_parent failure after unlink"))
            },
            |p, bytes| {
                assert!(!p.pending.exists(), "pending must have been unlinked before restore");
                // Child MUST still be alive while `pending` is being restored!
                let pid = prev_pid_ok.get().unwrap() as i32;
                // SAFETY: signal 0 probes liveness of our own test child.
                assert_eq!(unsafe { libc::kill(pid, 0) }, 0, "prev child must stay alive until pending is restored");
                restored_while_alive = true;
                storage::atomic_write(&p.pending, bytes, 0o600)
            },
        );
        assert_eq!(rc_prev_restore_ok, 9);
        assert!(restored_while_alive);
        assert!(manager.paths.pending.exists());
        // After restore succeeds, helper kills & reaps `prev_child`.
        // SAFETY: signal 0 probes that our reaped child no longer exists.
        assert_ne!(unsafe { libc::kill(prev_pid_ok.get().unwrap() as i32, 0) }, 0);

        // 1b. Previous-slot: `clear_pending` unlinks `pending` then fails AND
        //     `restore_pending` ALSO fails -> verified live child MUST NOT be killed!
        let mut prev_pid_keep: Option<u32> = None;
        let rc_prev_restore_err = recover_with_perf_and_restore_hooks(
            &manager.paths,
            Slot::A,
            None,
            None,
            &perf,
            None,
            |child| {
                prev_pid_keep = Some(child.id());
                Ok(())
            },
            clear_rollback_blocked_marker,
            |p| {
                fs::remove_file(&p.pending)?;
                Err(std::io::Error::other("simulated sync_parent failure after unlink"))
            },
            |_, _| Err(std::io::Error::other("simulated restore failure")),
        );
        let live_prev_pid = prev_pid_keep.unwrap() as i32;
        // SAFETY: signal 0 checks our own test child; SIGKILL cleans it up.
        let prev_stayed_alive = unsafe { libc::kill(live_prev_pid, 0) } == 0;
        unsafe {
            libc::kill(live_prev_pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(live_prev_pid, &mut status, 0);
        }
        assert_eq!(rc_prev_restore_err, 9);
        assert!(
            prev_stayed_alive,
            "previous child must NOT be killed when pending was unlinked and restore failed"
        );

        // 1c. Stable branch: `clear_pending` unlinks `pending` then fails,
        //     `restore_pending` succeeds BEFORE kill & cleanup.
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::A));
        fs::set_permissions(manager.paths.slot_binary(Slot::A), fs::Permissions::from_mode(0o600))
            .unwrap();
        let sleeper_stable = pad_script(
            b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then [ \"${2:-}\" = \"2.3.0\" ] && exit 0; exit 2; fi\nexec sleep 30\n",
        );
        let sleeper_stable_rel = release_for_binary(Channel::Stable, "2.3.0", &sleeper_stable);
        fs::write(manager.paths.stable_binary(), &sleeper_stable).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &sleeper_stable_rel).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.5.0-beta.1")
            .unwrap();
        let stable_pid_ok = std::cell::Cell::new(None);
        let mut stable_restored_while_alive = false;
        let rc_stable_restore_ok = recover_with_perf_and_restore_hooks(
            &manager.paths,
            Slot::A,
            None,
            None,
            &perf,
            None,
            |child| {
                stable_pid_ok.set(Some(child.id()));
                Ok(())
            },
            clear_rollback_blocked_marker,
            |p| {
                fs::remove_file(&p.pending)?;
                Err(std::io::Error::other("simulated sync_parent failure after unlink"))
            },
            |p, bytes| {
                assert!(!p.pending.exists());
                let pid = stable_pid_ok.get().unwrap() as i32;
                // SAFETY: signal 0 probes liveness of our own test child.
                assert_eq!(unsafe { libc::kill(pid, 0) }, 0, "Stable child must stay alive until pending is restored");
                stable_restored_while_alive = true;
                storage::atomic_write(&p.pending, bytes, 0o600)
            },
        );
        assert_eq!(rc_stable_restore_ok, 9);
        assert!(stable_restored_while_alive);
        assert!(manager.paths.pending.exists());
        // SAFETY: signal 0 probes that our reaped child no longer exists.
        assert_ne!(unsafe { libc::kill(stable_pid_ok.get().unwrap() as i32, 0) }, 0);

        // 1d. Stable branch: `clear_pending` unlinks `pending` then fails AND
        //     `restore_pending` ALSO fails -> verified Stable child MUST NOT be
        //     killed and concurrent cleanup MUST NOT run!
        let mut stable_pid_keep: Option<u32> = None;
        let rc_stable_restore_err = recover_with_perf_and_restore_hooks(
            &manager.paths,
            Slot::A,
            None,
            None,
            &perf,
            None,
            |child| {
                stable_pid_keep = Some(child.id());
                Ok(())
            },
            clear_rollback_blocked_marker,
            |p| {
                fs::remove_file(&p.pending)?;
                Err(std::io::Error::other("simulated sync_parent failure after unlink"))
            },
            |_, _| Err(std::io::Error::other("simulated restore failure")),
        );
        let live_stable_pid = stable_pid_keep.unwrap() as i32;
        // SAFETY: signal 0 checks our own test child; SIGKILL cleans it up.
        let stable_stayed_alive = unsafe { libc::kill(live_stable_pid, 0) } == 0;
        unsafe {
            libc::kill(live_stable_pid, libc::SIGKILL);
            let mut status = 0;
            libc::waitpid(live_stable_pid, &mut status, 0);
        }
        assert_eq!(rc_stable_restore_err, 9);
        assert!(
            stable_stayed_alive,
            "Stable child must NOT be killed when pending was unlinked and restore failed"
        );

        // 2. P1 #2: Stable `network-recover` deletes the triggering Tailscale
        //    journal then returns exit 1 -> invocation 1 exits 8 and persists
        //    `network-recover-pending` (`boot-uuid-r16\nstable`); invocation 2
        //    MUST invoke Stable `network-recover` a SECOND time before clearing
        //    the marker and booting Stable!
        let ts_journal = manager.paths.root.join("ts-r16.json");
        let stable_calls = manager.paths.root.join("stable-recover-calls");
        fs::write(&ts_journal, "{\"boot\":\"boot-uuid-r16\",\"undo\":[]}\n").unwrap();
        let stable_two_step = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then [ \"${{2:-}}\" = \"2.3.0\" ] && exit 0; exit 2; fi\nif [ \"${{1:-}}\" = network-recover ]; then\n  printf '1\\n' >> \"{}\"\n  if [ -e \"{}\" ]; then rm -f \"{}\"; exit 1; fi\n  exit 0\nfi\n[ -z \"${{ZTE_TEST_MARKER:-}}\" ] || printf 'stable-r16-ok' > \"$ZTE_TEST_MARKER\"\n",
            stable_calls.display(),
            ts_journal.display(),
            ts_journal.display(),
        ));
        let stable_two_step_rel = release_for_binary(Channel::Stable, "2.3.0", &stable_two_step);
        fs::write(manager.paths.stable_binary(), &stable_two_step).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_two_step_rel).unwrap();
        fs::set_permissions(manager.paths.slot_binary(Slot::A), fs::Permissions::from_mode(0o600))
            .unwrap();
        let _ = fs::remove_file(manager.paths.slot_binary(Slot::B));
        let _ = fs::remove_file(&manager.paths.blocked);
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let _ = fs::remove_file(&marker);
        let st_stable_fail1 = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(st_stable_fail1.code(), Some(8));
        assert!(!ts_journal.exists(), "first Stable cleanup unlinked triggering journal");
        assert_eq!(
            fs::read_to_string(manager.paths.root.join("network-recover-pending")).unwrap(),
            "boot-uuid-r16\nstable\n"
        );
        let st_stable_retry2 = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(
            st_stable_retry2.success(),
            "second invocation must retry Stable network-recover and boot Stable (got {:?})",
            st_stable_retry2.code()
        );
        assert_eq!(
            fs::read_to_string(&stable_calls).unwrap().lines().count(),
            2,
            "failed Stable cleanup must NOT be forgotten on the next invocation"
        );
        assert!(!manager.paths.root.join("network-recover-pending").exists());
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-r16-ok");

        // 3. P1 #3: Interrupted Stable rescue (`active=rescue`, `pending` kept,
        //    A disarmed, B quarantined in `blocked.json` yet still `0755` with
        //    valid digest, live Tailscale journal + daemon): shell MUST route
        //    cleanup directly to verified Stable with ZERO calls to candidate B!
        let cand_b_called = manager.paths.root.join("cand-b-called");
        let cand_b_fail = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then [ \"${{2:-}}\" = \"2.4.0-beta.9\" ] && exit 0; exit 2; fi\nprintf 'called' > \"{}\"\nexit 1\n",
            cand_b_called.display()
        ));
        let cand_b_fail_rel = release_for_binary(Channel::Beta, "2.4.0-beta.9", &cand_b_fail);
        write_release_agent(&manager.paths, Slot::B, &cand_b_fail_rel, &cand_b_fail);
        fs::write(&manager.paths.blocked, "[\"2.4.0-beta.9\"]\n").unwrap();
        fs::set_permissions(manager.paths.slot_binary(Slot::A), fs::Permissions::from_mode(0o600))
            .unwrap();
        manager.paths.write_rescue().unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        fs::write(&ts_journal, "{\"boot\":\"boot-uuid-r16\",\"undo\":[]}\n").unwrap();
        fs::create_dir_all(fake_proc.join("8888")).unwrap();
        fs::write(fake_proc.join("8888/stat"), "8888 (tailscaled) S 1 1 1 0\n").unwrap();
        fs::write(fake_proc.join("8888/comm"), "tailscaled\n").unwrap();
        let stable_rescue_cleaner = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then [ \"${{2:-}}\" = \"2.3.0\" ] && exit 0; exit 2; fi\nif [ \"${{1:-}}\" = network-recover ]; then rm -rf \"{}/8888\" \"{}\"; exit 0; fi\n[ -z \"${{ZTE_TEST_MARKER:-}}\" ] || printf 'stable-owned-rescue' > \"$ZTE_TEST_MARKER\"\n",
            fake_proc.display(),
            ts_journal.display()
        ));
        let stable_rescue_cleaner_rel =
            release_for_binary(Channel::Stable, "2.3.0", &stable_rescue_cleaner);
        fs::write(manager.paths.stable_binary(), &stable_rescue_cleaner).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_rescue_cleaner_rel).unwrap();
        let _ = fs::remove_file(&marker);
        let st_rescue_owned = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", &ts_journal)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(
            st_rescue_owned.success(),
            "interrupted Stable rescue must route cleanup to Stable instead of failed candidate B (got {:?})",
            st_rescue_owned.code()
        );
        assert!(
            !cand_b_called.exists(),
            "quarantined candidate B must receive ZERO calls once active=rescue owns recovery"
        );
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-owned-rescue");
        assert!(!ts_journal.exists());
        assert!(!fake_proc.join("8888").exists());

        // 4. P1 #4: `pin_candidate` MUST reject a slot missing both `release.json`
        //    and `bootstrap.sha256` for any ordinary version (allowing only the
        //    explicit `bootstrap-slot` compatibility marker).
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::B));
        let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::B));
        assert!(
            pin_candidate(&manager.paths, Slot::B, "2.4.0").is_err(),
            "versioned candidate missing all identity metadata must be rejected"
        );
        assert!(
            pin_candidate(&manager.paths, Slot::B, "").is_err(),
            "empty expected version missing all identity metadata must be rejected"
        );
        assert!(
            pin_candidate(&manager.paths, Slot::B, "bootstrap-slot").is_ok(),
            "explicit bootstrap-slot compatibility path must remain supported"
        );

        // 5. P2 #1: Dangling symlink at `blocked.json` MUST be rejected by BOTH
        //    Rust and Shell (never treated as absent!).
        let _ = fs::remove_file(&manager.paths.blocked);
        std::os::unix::fs::symlink(
            manager.paths.root.join("missing-blocked-target"),
            &manager.paths.blocked,
        )
        .unwrap();
        assert!(
            read_blocked_versions(&manager.paths).is_err(),
            "Rust must reject dangling blocked.json symlink"
        );
        let good_a = test_agent("2.3.5", true, "good-a-r16");
        let good_a_rel = release_for_binary(Channel::Stable, "2.3.5", &good_a);
        write_release_agent(&manager.paths, Slot::A, &good_a_rel, &good_a);
        manager.paths.write_active(Slot::A).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let st_dangling_blocked = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            st_dangling_blocked.code(),
            Some(9),
            "Shell must fail closed (exit 9) on dangling blocked.json symlink during rollback"
        );
        let _ = fs::remove_file(&manager.paths.pending);
        let _ = fs::remove_file(&marker);
        let st_dangling_boot = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            st_dangling_boot.code(),
            Some(127),
            "Shell must reject slots when blocked.json is a dangling symlink"
        );
        fs::remove_file(&manager.paths.blocked).unwrap();

        // 6. P2 #2: Valid signed `Channel::Beta` release in `last-stable` MUST be
        //    rejected by BOTH Rust (`verify_stable_rescue`) and Shell (`active=rescue`)!
        let beta_rescue = test_agent("2.4.0-beta.7", true, "beta-rescue");
        let beta_rescue_rel = release_for_binary(Channel::Beta, "2.4.0-beta.7", &beta_rescue);
        fs::write(manager.paths.stable_binary(), &beta_rescue).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &beta_rescue_rel).unwrap();
        assert!(
            verify_stable_rescue(&manager.paths).is_err(),
            "Rust verify_stable_rescue must reject Channel::Beta in last-stable"
        );
        manager.paths.write_rescue().unwrap();
        let _ = fs::remove_file(&marker);
        let st_beta_rescue = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            st_beta_rescue.code(),
            Some(127),
            "Shell must refuse to execute a Channel::Beta rescue copy"
        );
        assert!(!marker.exists());

        // 7. P2 #3: Bounded nonblocking reads on `state.json`, `rollback-blocked`,
        //    and `pin_candidate` metadata (FIFOs never block; >256 KiB rejected).
        let _ = fs::remove_file(&manager.paths.state);
        let c_state_fifo =
            std::ffi::CString::new(manager.paths.state.to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated path with private mode 0600.
        assert_eq!(unsafe { libc::mkfifo(c_state_fifo.as_ptr(), 0o600) }, 0);
        assert!(
            read_state_for_reconcile(&manager.paths).is_err(),
            "FIFO at state.json must return Err immediately without blocking"
        );
        fs::remove_file(&manager.paths.state).unwrap();

        let rb_marker = manager.paths.root.join("rollback-blocked");
        let _ = fs::remove_file(&rb_marker);
        let c_rb_fifo = std::ffi::CString::new(rb_marker.to_str().unwrap()).unwrap();
        // SAFETY: valid NUL-terminated path with private mode 0600.
        assert_eq!(unsafe { libc::mkfifo(c_rb_fifo.as_ptr(), 0o600) }, 0);
        assert!(
            same_boot_rollback_blocked_in(&manager.paths),
            "FIFO at rollback-blocked must fail closed immediately without blocking"
        );
        fs::remove_file(&rb_marker).unwrap();

        let mut huge_meta = serde_json::to_vec_pretty(&cand_b_fail_rel).unwrap();
        huge_meta.resize(storage::MAX_JSON_BYTES + 1, b' ');
        fs::write(manager.paths.slot_meta(Slot::B), &huge_meta).unwrap();
        assert!(
            pin_candidate(&manager.paths, Slot::B, "2.4.0-beta.9").is_err(),
            "pin_candidate must reject >256 KiB metadata during bounded capture"
        );
    }

    #[test]
    fn round17_cleanup_owner_isolation_and_hardening_edges() {
        let manager = manager("round17-hardening-edges");
        ensure_supervisor(&manager.paths).unwrap();
        let marker = manager.paths.root.join("started");
        let boot_id_file = manager.paths.root.join("boot_id");
        let current_boot = crate::net_tools::boot_id();
        fs::write(&boot_id_file, format!("{current_boot}\n")).unwrap();
        let fake_proc = manager.paths.root.join("proc");
        fs::create_dir_all(fake_proc.join("1")).unwrap();
        fs::write(fake_proc.join("1/stat"), "1 (init) S 0 1 1 0\n").unwrap();
        fs::write(fake_proc.join("1/comm"), "init\n").unwrap();
        fs::write(fake_proc.join("1/cmdline"), b"/sbin/init\0").unwrap();
        let no_launcher = manager.paths.root.join("no-launcher.sh");

        // 1. P1 #1: Candidate B unavailable, previous A verified, `cellular-pause`
        //    present -> Stable acts solely as fallback cleaner. When Stable's
        //    cleanup fails once and succeeds on retry, slot A MUST still boot
        //    and MUST NOT be disarmed or switched to `active=rescue`!
        let healthy_a = pad_script(
            b"#!/bin/sh\nif [ \"${1:-}\" = ota-probe ]; then [ \"${2:-}\" = \"2.3.5\" ] && exit 0; exit 2; fi\nrm -f \"${ZTE_OTA_ROOT}/rollback-attempt\"\n[ -z \"${ZTE_TEST_MARKER:-}\" ] || printf 'healthy-prev-a' > \"$ZTE_TEST_MARKER\"\n",
        );
        let healthy_a_rel = release_for_binary(Channel::Stable, "2.3.5", &healthy_a);
        write_release_agent(&manager.paths, Slot::A, &healthy_a_rel, &healthy_a);
        let _ = fs::remove_file(manager.paths.slot_binary(Slot::B));
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::B));
        let cell_pause = manager.paths.root.join("cellular-pause-r17");
        fs::write(&cell_pause, b"1\n").unwrap();
        let stable_fail_once_flag = manager.paths.root.join("stable-failed-once");
        let stable_cleaner = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then [ \"${{2:-}}\" = \"2.3.0\" ] && exit 0; exit 2; fi\nif [ \"${{1:-}}\" = network-recover ]; then\n  if [ ! -e \"{}\" ]; then printf '1' > \"{}\"; exit 1; fi\n  rm -f \"{}\"\n  exit 0\nfi\n[ -z \"${{ZTE_TEST_MARKER:-}}\" ] || printf 'wrong-stable-boot' > \"$ZTE_TEST_MARKER\"\n",
            stable_fail_once_flag.display(),
            stable_fail_once_flag.display(),
            cell_pause.display(),
        ));
        let stable_cleaner_rel = release_for_binary(Channel::Stable, "2.3.0", &stable_cleaner);
        fs::write(manager.paths.stable_binary(), &stable_cleaner).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_cleaner_rel).unwrap();
        manager.paths.write_active(Slot::A).unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let _ = fs::remove_file(&marker);
        let st_fail1 = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_SUPERVISOR", &manager.paths.supervisor)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_AGENT_LAUNCHER", &no_launcher)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_RELAY_CELLULAR_PAUSE", &cell_pause)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(st_fail1.code(), Some(8));
        assert_eq!(
            fs::read_to_string(manager.paths.root.join("network-recover-pending")).unwrap(),
            format!("{current_boot}\nstable\n")
        );
        let st_retry_ok = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_SUPERVISOR", &manager.paths.supervisor)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_AGENT_LAUNCHER", &no_launcher)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_RELAY_CELLULAR_PAUSE", &cell_pause)
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(
            st_retry_ok.success(),
            "retrying Stable cleanup must succeed and boot healthy slot A (got {:?})",
            st_retry_ok.code()
        );
        assert_eq!(fs::read_to_string(&marker).unwrap(), "healthy-prev-a");
        assert_eq!(fs::read_to_string(&manager.paths.active).unwrap().trim(), "a");
        assert!(
            storage::executable(&manager.paths.slot_binary(Slot::A)),
            "healthy slot A must remain executable after Stable cleanup retry"
        );
        assert!(!manager.paths.root.join("network-recover-pending").exists());

        // 2. P1 #2: Rust post-Stable cleanup MUST persist `network-recover-pending`
        //    (`stable`) BEFORE cleanup and retain it on failure even if no other
        //    trigger file remains, so the next Shell supervisor invocation runs
        //    Stable `network-recover` before booting Stable!
        let stable_recover_ran = manager.paths.root.join("stable-post-rust-recover");
        let stable_after_rust = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then [ \"${{2:-}}\" = \"2.3.0\" ] && exit 0; exit 2; fi\nif [ \"${{1:-}}\" = network-recover ]; then printf 'ran' > \"{}\"; exit 0; fi\n[ -z \"${{ZTE_TEST_MARKER:-}}\" ] || printf 'stable-after-rust-cleanup' > \"$ZTE_TEST_MARKER\"\n",
            stable_recover_ran.display()
        ));
        let stable_after_rust_rel =
            release_for_binary(Channel::Stable, "2.3.0", &stable_after_rust);
        fs::write(manager.paths.stable_binary(), &stable_after_rust).unwrap();
        fs::set_permissions(
            manager.paths.stable_binary(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        storage::write_json(&manager.paths.stable_meta(), &stable_after_rust_rel).unwrap();
        fs::set_permissions(manager.paths.slot_binary(Slot::A), fs::Permissions::from_mode(0o600))
            .unwrap();
        manager.paths.write_rescue().unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        let cleanup_err = run_verified_owned_rollback_cleanup_with(
            &manager.paths,
            "stable",
            || Err("simulated policy-rule verification failure after tailscaled stopped".into()),
        );
        assert!(cleanup_err.is_err());
        assert_eq!(
            fs::read_to_string(manager.paths.root.join("network-recover-pending")).unwrap(),
            format!("{current_boot}\nstable\n")
        );
        // No journals/daemons exist anymore, yet Shell MUST still invoke Stable
        // `network-recover` because Rust recorded the Stable obligation!
        let _ = fs::remove_file(&marker);
        let st_after_rust = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert!(st_after_rust.success());
        assert_eq!(
            fs::read_to_string(&stable_recover_ran).unwrap_or_default(),
            "ran",
            "Shell must run Stable network-recover after Rust post-Stable cleanup failed"
        );
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-after-rust-cleanup");
        assert!(!manager.paths.root.join("network-recover-pending").exists());
        // Verify successful owned cleanup clears the marker cleanly.
        run_verified_owned_rollback_cleanup_with(&manager.paths, "stable", || Ok(())).unwrap();
        assert!(!manager.paths.root.join("network-recover-pending").exists());

        // 3. P2 #1: Blank second owner line (`boot-id\n\n`) in `network-recover-pending`
        //    MUST fail closed (exit 8) instead of being treated as legacy and
        //    invoking quarantined candidate B!
        let cand_b_called = manager.paths.root.join("cand-b-blank-owner");
        let cand_b_script = pad_script(format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = ota-probe ]; then [ \"${{2:-}}\" = \"2.4.0-beta.9\" ] && exit 0; exit 2; fi\nprintf 'called' > \"{}\"\nexit 0\n",
            cand_b_called.display()
        ));
        let cand_b_rel = release_for_binary(Channel::Beta, "2.4.0-beta.9", &cand_b_script);
        write_release_agent(&manager.paths, Slot::B, &cand_b_rel, &cand_b_script);
        fs::write(&manager.paths.blocked, "[\"2.4.0-beta.9\"]\n").unwrap();
        manager.paths.write_rescue().unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        fs::write(
            manager.paths.root.join("network-recover-pending"),
            format!("{current_boot}\n\n"),
        )
        .unwrap();
        let st_blank_owner = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            st_blank_owner.code(),
            Some(8),
            "blank second owner line in network-recover-pending must fail closed with exit 8"
        );
        assert!(
            !cand_b_called.exists(),
            "quarantined candidate B must NOT be invoked for malformed blank owner line"
        );
        let _ = fs::remove_file(manager.paths.root.join("network-recover-pending"));
        let _ = fs::remove_file(&manager.paths.pending);

        // 4. P2 #2: Metadata-free legacy active slot MUST NOT boot when
        //    `blocked.json` is a dangling symlink!
        let _ = fs::remove_file(manager.paths.slot_meta(Slot::A));
        let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::A));
        fs::write(manager.paths.slot_binary(Slot::A), &healthy_a).unwrap();
        fs::set_permissions(manager.paths.slot_binary(Slot::A), fs::Permissions::from_mode(0o755))
            .unwrap();
        let _ = fs::remove_file(manager.paths.slot_binary(Slot::B));
        let _ = fs::remove_file(&manager.paths.blocked);
        std::os::unix::fs::symlink(
            manager.paths.root.join("missing-blocked-r17"),
            &manager.paths.blocked,
        )
        .unwrap();
        manager.paths.write_active(Slot::A).unwrap();
        let _ = fs::remove_file(&marker);
        let st_legacy_dangling = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .status()
            .unwrap();
        assert_eq!(
            st_legacy_dangling.code(),
            Some(127),
            "metadata-free active slot must NOT boot with a dangling blocked.json symlink"
        );
        assert!(!marker.exists());
        fs::remove_file(&manager.paths.blocked).unwrap();

        // 5. P2 #4: `optional_file_identity` & `verify_candidate_unmodified`
        //    enforce tight byte bounds on `bootstrap.sha256` (4 KiB) and
        //    replacement `release.json` (256 KiB) instead of hashing to EOF!
        let huge_boot = vec![b'a'; (MAX_BOOTSTRAP_DIGEST_BYTES as usize) + 1];
        fs::write(manager.paths.slot_bootstrap_digest(Slot::A), &huge_boot).unwrap();
        assert!(
            optional_file_identity(
                &manager.paths.slot_bootstrap_digest(Slot::A),
                MAX_BOOTSTRAP_DIGEST_BYTES
            )
            .is_err(),
            "oversized bootstrap.sha256 must be rejected without unbounded hashing"
        );
        assert!(pin_candidate(&manager.paths, Slot::A, "2.3.5").is_err());
        let _ = fs::remove_file(manager.paths.slot_bootstrap_digest(Slot::A));
        write_release_agent(&manager.paths, Slot::B, &cand_b_rel, &cand_b_script);
        let pinned_b = pin_candidate(&manager.paths, Slot::B, "2.4.0-beta.9").unwrap();
        let mut huge_replacement = serde_json::to_vec_pretty(&cand_b_rel).unwrap();
        huge_replacement.resize(storage::MAX_JSON_BYTES + 1, b' ');
        fs::write(manager.paths.slot_meta(Slot::B), &huge_replacement).unwrap();
        assert!(
            verify_candidate_unmodified(&manager.paths, Slot::B, &pinned_b).is_err(),
            "oversized replacement release.json must fail bounded recheck immediately"
        );
        assert!(slot_changed_from_pinned(&manager.paths, Slot::B, &pinned_b));

        // 6. Round 18 P1 #3: Legacy `965ebfe` Stable returning 0 for
        //    `network-recover` MUST NOT clear `network-recover-pending` while
        //    Tailscale RPDB policy rules (`5210:`/`5110:`) remain active!
        let fake_ip_dirty = manager.paths.root.join("fake-ip-dirty");
        fs::write(
            &fake_ip_dirty,
            "#!/bin/sh\nif [ \"$1\" = -4 ]; then printf '0:\\tfrom all lookup local\\n5210:\\tfrom all fwmark 0x80000/0xff0000 lookup main\\n'; else printf '0:\\tfrom all lookup local\\n'; fi\n",
        )
        .unwrap();
        fs::set_permissions(&fake_ip_dirty, fs::Permissions::from_mode(0o755)).unwrap();
        let fake_ip_clean = manager.paths.root.join("fake-ip-clean");
        fs::write(&fake_ip_clean, "#!/bin/sh\nprintf '0:\\tfrom all lookup local\\n'\n").unwrap();
        fs::set_permissions(&fake_ip_clean, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(manager.paths.slot_binary(Slot::A), fs::Permissions::from_mode(0o600))
            .unwrap();
        manager.paths.write_rescue().unwrap();
        manager
            .paths
            .write_pending(Slot::B, Slot::A, "2.4.0-beta.9")
            .unwrap();
        write_recover_pending_marker(&manager.paths, "stable").unwrap();
        let _ = fs::remove_file(&marker);
        let st_dirty_rules = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .env("ZTE_IP_BIN", &fake_ip_dirty)
            .status()
            .unwrap();
        assert_eq!(
            st_dirty_rules.code(),
            Some(8),
            "legacy Stable returning 0 must NOT clear obligation while Tailscale RPDB policy rules remain"
        );
        assert!(manager.paths.root.join("network-recover-pending").exists());
        assert!(!marker.exists());

        let st_clean_rules = Command::new("sh")
            .arg(&manager.paths.supervisor)
            .env("ZTE_OTA_ROOT", &manager.paths.root)
            .env("ZTE_OTA_LEGACY_LINK", &manager.paths.legacy_link)
            .env("ZTE_TEST_MARKER", &marker)
            .env("ZTE_TAILSCALE_JOURNAL", manager.paths.root.join("no-journal"))
            .env("ZTE_BOOT_ID_PATH", &boot_id_file)
            .env("ZTE_PROC_ROOT", &fake_proc)
            .env("ZTE_IP_BIN", &fake_ip_clean)
            .status()
            .unwrap();
        assert!(st_clean_rules.success());
        assert!(!manager.paths.root.join("network-recover-pending").exists());
        assert_eq!(fs::read_to_string(&marker).unwrap(), "stable-after-rust-cleanup");
    }
}
