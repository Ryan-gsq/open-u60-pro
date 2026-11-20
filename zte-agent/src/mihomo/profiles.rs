//! Private, immutable profile bodies and one atomic selection/metadata index.

use std::fs;
use std::io::Read;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{geodata, net, transform, Mihomo, MAX_CONFIG};
use transform::Extensions;

const MAX_PROFILES: usize = 16;
const MAX_LIBRARY: u64 = 24 * 1024 * 1024;
const INTERVALS: &[u64] = &[0, 1, 6, 12, 24, 72, 168];

/// Saves in this process, plus the library file's mtime and length: a status
/// answered from `Mihomo::status_cache` is valid while all three are unchanged.
pub(super) type LibraryStamp = (u64, Option<SystemTime>, u64);

#[derive(Clone, Deserialize, Serialize)]
struct Profile<T = String> {
    id: String,
    name: String,
    url: Option<String>,
    interval_hours: u64,
    updated: u64,
    attempted: u64,
    error: Option<String>,
    source: T,
    compiled: T,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct Library<T = String> {
    selected: Option<String>,
    extensions: Extensions,
    profiles: Vec<Profile<T>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum BodyRef { Inline(String), Blob { sha256: String } }
impl Default for BodyRef { fn default() -> Self { Self::Inline(String::new()) } }

fn blob_key(key: &str) -> bool { key.len() == 64 && key.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn hash(text: &str) -> String { use sha2::Digest; format!("{:x}", sha2::Sha256::digest(text.as_bytes())) }
fn sync_dir(dir: &std::path::Path) -> Result<(), String> { fs::File::open(dir).and_then(|dir| dir.sync_all()).map_err(|e| e.to_string()) }

impl<T> Library<T> {
    fn map_bodies<U>(self, mut map: impl FnMut(T) -> Result<U, String>) -> Result<Library<U>, String> {
        let mut profiles = Vec::with_capacity(self.profiles.len());
        for p in self.profiles {
            profiles.push(Profile { id: p.id, name: p.name, url: p.url, interval_hours: p.interval_hours, updated: p.updated, attempted: p.attempted,
                error: p.error, source: map(p.source)?, compiled: map(p.compiled)? });
        }
        Ok(Library { selected: self.selected, extensions: self.extensions, profiles })
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub action: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub yaml: String,
    #[serde(default)]
    pub interval_hours: u64,
    #[serde(default)]
    pub extensions: Extensions,
    #[serde(default)]
    pub source_type: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Mihomo {
    pub(crate) fn set_subscription_dns(&self, servers: Vec<std::net::Ipv4Addr>) {
        *self
            .subscription_dns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = servers;
    }

    fn fetch_subscription(&self, url: &str) -> Result<String, String> {
        fetch(url, &self.downloader())
    }

    fn library_path(&self) -> std::path::PathBuf { self.root.join("profiles.json") }

    fn read_index(&self) -> Result<Library<BodyRef>, String> {
        let file = match fs::File::open(self.library_path()) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Library::default()),
            Err(_) => return Err("Cannot read profile library".into()),
        };
        let mut bytes = Vec::new();
        file.take(MAX_LIBRARY + 1).read_to_end(&mut bytes).map_err(|_| "Cannot read profile library")?;
        if bytes.len() as u64 > MAX_LIBRARY { return Err("Profile library exceeds its size limit".into()); }
        let library: Library<BodyRef> = serde_json::from_slice(&bytes).map_err(|_| "Profile library is damaged; restore its backup before changing profiles")?;
        if library.profiles.len() > MAX_PROFILES || library.selected.as_ref().is_some_and(|id| !library.profiles.iter().any(|p| &p.id == id)) {
            return Err("Invalid profile selection".into());
        }
        Ok(library)
    }

    fn blob_text(&self, body: BodyRef) -> Result<String, String> {
        match body {
            BodyRef::Inline(text) if text.len() <= MAX_CONFIG => Ok(text),
            BodyRef::Blob { sha256 } if blob_key(&sha256) => {
                let mut text = String::new();
                fs::File::open(self.root.join("profile-bodies").join(&sha256)).and_then(|f| f.take(MAX_CONFIG as u64 + 1).read_to_string(&mut text))
                    .map_err(|_| "Cannot read profile contents")?;
                if text.len() > MAX_CONFIG || hash(&text) != sha256 { return Err("Profile contents failed verification".into()); }
                Ok(text)
            }
            _ => Err("Invalid profile contents".into()),
        }
    }

    fn load_library(&self) -> Result<Library, String> {
        let _storage = self.profile_storage.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.read_index()?.map_bodies(|body| self.blob_text(body))
    }

    fn save_library(&self, library: &Library) -> Result<(), String> {
        let _storage = self.profile_storage.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if crate::ota::slot_change_pending() { return self.save_inline(library); }
        let dir = self.root.join("profile-bodies");
        net::private_dir(&dir)?;
        let mut live = std::collections::HashSet::new();
        let mut wrote = false;
        let mut size = 0u64;
        let index = library.clone().map_bodies(|text| {
            size += text.len() as u64;
            if text.len() > MAX_CONFIG || size > MAX_LIBRARY { return Err("Profile library is full".into()); }
            let sha256 = hash(&text);
            let path = dir.join(&sha256);
            if live.insert(sha256.clone()) && !path.try_exists().map_err(|e| e.to_string())? {
                net::write_private(&path, text.as_bytes())?;
                wrote = true;
            }
            Ok(BodyRef::Blob { sha256 })
        })?;
        if wrote { sync_dir(&dir)?; }
        self.write_index(&index, size, true)
    }

    /// Caller serializes readers opening blobs with the index commit and GC.
    fn write_index(&self, index: &Library<BodyRef>, payload: u64, collect: bool) -> Result<(), String> {
        let bytes = serde_json::to_vec(index).map_err(|_| "Cannot encode profile library")?;
        if payload + bytes.len() as u64 > MAX_LIBRARY { return Err("Profile library is full".into()); }
        net::write_private(&self.library_path(), &bytes).map_err(|_| "Cannot save private profile library")?;
        self.library_revision.fetch_add(1, Ordering::AcqRel);
        if collect && sync_dir(&self.root).is_ok() {
            let live: std::collections::HashSet<&str> = index.profiles.iter().flat_map(|p| [&p.source, &p.compiled]).filter_map(|body| match body {
                BodyRef::Blob { sha256 } => Some(sha256.as_str()), BodyRef::Inline(_) => None,
            }).collect();
            for entry in fs::read_dir(self.root.join("profile-bodies")).into_iter().flatten().flatten() {
                if entry.file_name().to_str().is_some_and(|name| blob_key(name) && !live.contains(name)) { let _ = fs::remove_file(entry.path()); }
            }
        }
        Ok(())
    }

    fn change_metadata(&self, request: &Request) -> Result<(), String> {
        let _operation = self.operation.try_lock().map_err(|_| "A Mihomo operation is in progress")?;
        let storage = self.profile_storage.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut index = self.read_index()?;
        let delete = request.action == "delete";
        if delete {
            if index.selected.as_ref() == Some(&request.id) {
                if self.running() { return Err("Turn off Mihomo or select another profile before deleting the active one".into()); }
                index.selected = None;
            }
            let position = index.profiles.iter().position(|p| p.id == request.id).ok_or("Unknown profile")?;
            index.profiles.remove(position);
        } else {
            interval(request.interval_hours)?;
            let profile = index.profiles.iter_mut().find(|p| p.id == request.id && p.url.is_some()).ok_or("Select a subscription profile")?;
            profile.interval_hours = request.interval_hours;
            profile.attempted = now();
        }
        if index.profiles.iter().any(|p| matches!(p.source, BodyRef::Inline(_)) || matches!(p.compiled, BodyRef::Inline(_))) || crate::ota::slot_change_pending() {
            let library = index.map_bodies(|b| self.blob_text(b))?;
            drop(storage);
            self.save_library(&library)?;
        } else {
            self.write_index(&index, 0, delete)?;
        }
        self.wake_profiles();
        Ok(())
    }

    // An old A/B slot understands only the inline format. At a slot change
    // publish it atomically, under the same lock as a profile edit. A trial
    // keeps it readable until the supervisor removes the pending marker.
    pub(crate) fn before_slot_change<T>(&self, change: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let _profiles = self.profile_operation.try_lock().map_err(|_| "A profile operation is in progress")?;
        if self.library_path().try_exists().map_err(|e| e.to_string())? {
            let library = self.load_library()?;
            self.save_inline(&library)?;
        }
        change()
    }

    fn save_inline(&self, library: &Library) -> Result<(), String> {
        let data = serde_json::to_vec(library).map_err(|e| e.to_string())?;
        if data.len() as u64 > MAX_LIBRARY { return Err("Profile library is full".into()); }
        net::write_private(&self.library_path(), &data)?;
        self.library_revision.fetch_add(1, Ordering::AcqRel);
        sync_dir(&self.root)
    }

    fn library_stamp(&self) -> LibraryStamp {
        let (modified, length) = fs::metadata(self.library_path())
            .map(|m| (m.modified().ok(), m.len()))
            .unwrap_or((None, 0));
        (self.library_revision.load(Ordering::Acquire), modified, length)
    }

    pub(super) fn selected_source(&self) -> Result<String, String> {
        let _storage = self.profile_storage.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let library = self.read_index()?;
        let profile = library.profiles.into_iter().find(|p| Some(&p.id) == library.selected.as_ref()).ok_or("Select a validated Mihomo profile first")?;
        self.blob_text(profile.compiled)
    }

    pub fn profile_status(&self) -> Result<Value, String> {
        // The library can hold up to 24 MB of subscription text (each profile
        // stored twice); status is polled, so parse it only after a change.
        let stamp = self.library_stamp();
        if let Some((cached, value)) = self
            .status_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            if *cached == stamp {
                return Ok(value.clone());
            }
        }
        let library = self.read_index()?;
        let value =
            json!({"selected": library.selected, "profiles":library.profiles.iter().map(|p| json!({
            "id":p.id,"name":p.name,"remote":p.url.is_some(),"interval_hours":p.interval_hours,
            "updated":p.updated,"attempted":p.attempted,"error":p.error
        })).collect::<Vec<_>>(), "merge_enabled": library.extensions.merge_enabled,
            "script_enabled":library.extensions.script_enabled,
            "merge_saved":!library.extensions.merge.is_empty(),"script_saved":!library.extensions.script.is_empty()});
        *self
            .status_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((stamp, value.clone()));
        Ok(value)
    }

    /// Explicit authenticated editor only; not a status/list response.
    pub fn profile_editor(&self, id: &str) -> Result<Value, String> {
        let library = self.read_index()?;
        let p = library
            .profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or("Unknown profile")?;
        Ok(json!({"id":p.id,"name":p.name,"url":p.url,
            "source_type":if p.url.is_some() { "remote" } else { "local" },"interval_hours":p.interval_hours}))
    }

    /// Private authenticated editor only; scripts never enter status responses.
    pub fn extensions_editor(&self) -> Result<Value, String> {
        serde_json::to_value(self.read_index()?.extensions)
            .map_err(|_| "Cannot read global extensions".into())
    }

    pub(super) fn validate_profile(&self, source: &str) -> Result<(), String> {
        if !self.root.join("mihomo").is_file() { return Err("Install Mihomo first".into()); }
        let (mapping, _) = super::managed_mapping(source, "validation-only", None, true)?;
        let config = serde_yaml_ng::to_string(&mapping).map_err(|_| "Cannot encode Mihomo configuration")?;
        self.validate_candidate("check.yaml", &config, "validation-only", &geodata::required(&mapping), self.running())
    }

    fn refresh_source(&self, profile: &mut Profile, extensions: &Extensions, source: String, selected: bool) -> Result<(), String> {
        if source != profile.source {
            let compiled = transform::compile(&source, &profile.name, extensions)?;
            if !selected {
                self.validate_profile(&compiled)?;
            }
            profile.source = source;
            profile.compiled = compiled;
        }
        profile.updated = now();
        profile.error = None;
        Ok(())
    }

    pub fn profiles_change(&self, request: Request) -> Result<(), String> {
        let _profiles = self
            .profile_operation
            .try_lock()
            .map_err(|_| "A profile operation is in progress")?;
        if matches!(request.action.as_str(), "schedule" | "delete") { return self.change_metadata(&request); }
        let old = self.load_library()?;
        let mut next = old.clone();
        match request.action.as_str() {
            "replace-current" => {
                if self.running() {
                    return Err("Turn off Mihomo before replacing its configuration".into());
                }
                let name = selected(&next)
                    .map(|p| p.name.as_str())
                    .unwrap_or("Pasted configuration");
                let compiled = transform::compile(&request.yaml, name, &next.extensions)?;
                if let Some(id) = &next.selected {
                    let profile = next.profiles.iter_mut().find(|p| &p.id == id).unwrap();
                    profile.source = request.yaml;
                    profile.compiled = compiled;
                    profile.url = None;
                    profile.interval_hours = 0;
                    profile.updated = now();
                    profile.attempted = now();
                    profile.error = None;
                } else {
                    next.selected = Some("legacy".into());
                    next.profiles.push(Profile {
                        id: "legacy".into(),
                        name: "Pasted configuration".into(),
                        url: None,
                        interval_hours: 0,
                        updated: now(),
                        attempted: now(),
                        error: None,
                        source: request.yaml,
                        compiled,
                    });
                }
            }
            "add" | "edit" => {
                let editing = request.action == "edit";
                if !editing && next.profiles.len() >= MAX_PROFILES {
                    return Err("At most 16 profiles can be saved".into());
                }
                let name = request.name.trim();
                if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                    return Err("Enter a profile name (1-128 bytes)".into());
                }
                interval(request.interval_hours)?;
                let remote = match request.source_type.as_str() {
                    "remote" => true,
                    "local" => false,
                    "" => !request.url.trim().is_empty(),
                    _ => return Err("Choose remote or local configuration".into()),
                };
                if request.source_type.is_empty() && remote == !request.yaml.trim().is_empty() {
                    return Err("Use a subscription URL or YAML, not both".into());
                }
                let old_profile = if editing {
                    Some(
                        next.profiles
                            .iter()
                            .find(|p| p.id == request.id)
                            .ok_or("Unknown profile")?,
                    )
                } else {
                    None
                };
                let source = if remote {
                    subscription_url(request.url.trim())?;
                    if let Some(p) =
                        old_profile.filter(|p| p.url.as_deref() == Some(request.url.trim()))
                    {
                        p.source.clone()
                    } else {
                        self.fetch_subscription(request.url.trim())?
                    }
                } else if request.yaml.trim().is_empty() && editing {
                    old_profile
                        .filter(|p| p.url.is_none())
                        .ok_or("Paste or select a local YAML file")?
                        .source
                        .clone()
                } else {
                    request.yaml
                };
                let compiled = transform::compile(&source, name, &next.extensions)?;
                if next.selected.is_some() && !(editing && next.selected.as_ref() == Some(&request.id)) { self.validate_profile(&compiled)?; }
                let mut random = [0u8; 8];
                getrandom::getrandom(&mut random).map_err(|_| "Cannot create profile ID")?;
                let id = random
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                let id = if editing { request.id.clone() } else { id };
                if !editing && next.selected.is_none() {
                    next.selected = Some(id.clone());
                }
                let updated = Profile {
                    id,
                    name: name.into(),
                    url: remote.then(|| request.url.trim().to_owned()),
                    interval_hours: if remote { request.interval_hours } else { 0 },
                    updated: now(),
                    attempted: now(),
                    error: None,
                    source,
                    compiled,
                };
                if editing {
                    *next
                        .profiles
                        .iter_mut()
                        .find(|p| p.id == request.id)
                        .unwrap() = updated;
                } else {
                    next.profiles.push(updated);
                }
            }
            "select" => {
                let profile = next
                    .profiles
                    .iter()
                    .find(|p| p.id == request.id)
                    .ok_or("Unknown profile")?;
                next.selected = Some(profile.id.clone());
            }
            "refresh" => {
                let profile = next
                    .profiles
                    .iter_mut()
                    .find(|p| p.id == request.id)
                    .ok_or("Unknown profile")?;
                let result = (|| {
                    let source = self.fetch_subscription(
                        profile
                            .url
                            .as_deref()
                            .ok_or("Local files have no subscription to update")?,
                    )?;
                    let active = next.selected.as_deref() == Some(&profile.id);
                    self.refresh_source(profile, &next.extensions, source, active)
                })();
                profile.attempted = now();
                if let Err(e) = result {
                    profile.error = Some(e.clone());
                    self.save_library(&next)?;
                    self.wake_profiles();
                    return Err(e);
                }
            }
            "extensions" => {
                request.extensions.validate()?;
                let mut extensions = request.extensions;
                // Empty editor means retain private saved content; enable switches
                // are independent. Explicit {} / identity main replace old content.
                if extensions.merge.trim().is_empty() {
                    extensions.merge = next.extensions.merge.clone();
                }
                if extensions.script.trim().is_empty() {
                    extensions.script = next.extensions.script.clone();
                }
                for profile in &mut next.profiles {
                    profile.compiled =
                        transform::compile(&profile.source, &profile.name, &extensions)?;
                    if next.selected.as_ref() != Some(&profile.id) { self.validate_profile(&profile.compiled)?; }
                }
                if next.profiles.is_empty() {
                    return Err("Add a profile before validating global extensions".into());
                }
                next.extensions = extensions;
            }
            _ => return Err("Unknown profile action".into()),
        }
        if let Err(error) = self.commit_library(&old, &next, request.action == "replace-current", request.action == "refresh") {
            if request.action == "refresh" {
                let mut failed = old;
                if let Some(profile) = failed.profiles.iter_mut().find(|p| p.id == request.id) {
                    profile.attempted = now();
                    profile.error = Some(error.clone());
                    self.save_library(&failed)?;
                }
            }
            self.wake_profiles();
            return Err(error);
        }
        self.wake_profiles();
        Ok(())
    }

    fn commit_library(
        &self,
        old: &Library,
        next: &Library,
        require_off: bool,
        refresh: bool,
    ) -> Result<(), String> {
        {
            let _operation = self
                .operation
                .try_lock()
                .map_err(|_| "A Mihomo operation is in progress")?;
            if (require_off || (old.selected.is_some() && next.selected.is_none())) && self.running() {
                return Err(
                    "Turn off Mihomo or select another profile before changing the active one".into(),
                );
            }
            self.save_library(next)?;
        }
        let changed = old.selected != next.selected
            || selected(old).map(|p| &p.compiled) != selected(next).map(|p| &p.compiled);
        if let Some(current) = selected(next).filter(|_| changed) {
            if let Err(error) = self.config_changed(refresh, &current.compiled) {
                // Keep the previous selection and processed config together.
                self.save_library(old)?;
                return Err(if self.running() {
                    format!("Profile could not start; previous profile restored ({error})")
                } else {
                    format!("Profile could not start; previous selection restored but proxy is off. Check recovery status ({error})")
                });
            }
        }
        Ok(())
    }

    fn wake_profiles(&self) {
        let mut revision = self
            .profile_revision
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *revision = revision.wrapping_add(1);
        self.profile_wake.notify_all();
        crate::events::touch(crate::events::Topic::Mihomo);
    }

    pub fn start_profiles(self: &Arc<Self>) {
        let this = Arc::clone(self);
        crate::system::spawn_named("mh-subscriptions", move || loop {
            let revision = *this
                .profile_revision
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let due = this.read_index().map(|l| {
                l.profiles
                    .into_iter()
                    .filter_map(|p| {
                        (p.url.is_some() && p.interval_hours > 0).then(|| {
                            let wait = due_in(&p, now());
                            (p.id, wait)
                        })
                    })
                    .min_by_key(|(_, wait)| *wait)
            });
            let delay = match due {
                Ok(Some((id, 0))) => {
                    let request = Request {
                        action: "refresh".into(),
                        id,
                        name: String::new(),
                        url: String::new(),
                        yaml: String::new(),
                        interval_hours: 0,
                        extensions: Extensions::default(),
                        source_type: String::new(),
                    };
                    let _ = this.profiles_change(request);
                    Some(Duration::from_secs(60))
                }
                Ok(Some((_, wait))) => Some(Duration::from_secs(wait.min(3600))),
                Ok(None) => None,
                Err(_) => Some(Duration::from_secs(300)),
            };
            let guard = this
                .profile_revision
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *guard != revision {
                continue;
            }
            if let Some(delay) = delay {
                drop(
                    this.profile_wake
                        .wait_timeout(guard, delay)
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
            } else {
                drop(
                    this.profile_wake
                        .wait(guard)
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
            }
        });
    }
}

fn due_in<T>(profile: &Profile<T>, now: u64) -> u64 {
    let interval = if profile.error.is_some() {
        3600
    } else {
        profile.interval_hours.saturating_mul(3600)
    };
    // A clock correction must neither spin nor postpone updates indefinitely.
    if profile.attempted > now {
        0
    } else {
        profile
            .attempted
            .saturating_add(interval)
            .saturating_sub(now)
    }
}

fn selected(library: &Library) -> Option<&Profile> {
    library
        .selected
        .as_ref()
        .and_then(|id| library.profiles.iter().find(|p| &p.id == id))
}

fn interval(hours: u64) -> Result<(), String> {
    if INTERVALS.contains(&hours) {
        Ok(())
    } else {
        Err("Choose manual, 1, 6, 12, 24, 72 or 168 hours".into())
    }
}

fn subscription_url(url: &str) -> Result<reqwest::Url, String> {
    super::download::https_url(url)
}

fn fetch(url: &str, download: &super::download::Download) -> Result<String, String> {
    let url = subscription_url(url)?;
    let bytes = download.bytes(url.as_str(), MAX_CONFIG as u64, Duration::from_secs(60))?;
    let text = String::from_utf8(bytes).map_err(|_| "Subscription must be UTF-8 Mihomo YAML")?;
    transform::mapping(&text)?;
    Ok(text)
}

pub fn status(state: &crate::handlers::AppState) -> (u16, Value) {
    match state.mihomo.profile_status() {
        Ok(data) => (200, json!({"ok":true,"data":data})),
        Err(e) => (503, json!({"ok":false,"error":e})),
    }
}

/// Explicit editor read for one profile (name, schedule, subscription URL).
/// Never part of status or list answers; the route requires the agent password.
pub fn editor(state: &crate::handlers::AppState, id: &str) -> (u16, Value) {
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|c| c.is_ascii_alphanumeric()) {
        return (400, json!({"ok":false,"error":"Invalid profile ID"}));
    }
    match state.mihomo.profile_editor(id) {
        Ok(data) => (200, json!({"ok":true,"data":data})),
        Err(e) => (if e == "Unknown profile" { 404 } else { 503 }, json!({"ok":false,"error":e})),
    }
}

/// Explicit editor read for the global Merge and Script (private content).
pub fn extensions(state: &crate::handlers::AppState) -> (u16, Value) {
    match state.mihomo.extensions_editor() {
        Ok(data) => (200, json!({"ok":true,"data":data})),
        Err(e) => (503, json!({"ok":false,"error":e})),
    }
}

pub fn change(state: &crate::handlers::AppState, body: &[u8]) -> (u16, Value) {
    let request = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (400, json!({"ok":false,"error":"Invalid profile request"})),
    };
    match state.mihomo.profiles_change(request) {
        Ok(()) => status(state),
        Err(e) => (503, json!({"ok":false,"error":e})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A library holding one local profile, saved through the normal path.
    fn seed(mihomo: &Mihomo, source: &str) -> Library {
        let library = Library {
            selected: Some("seed".into()),
            profiles: vec![Profile {
                id: "seed".into(),
                name: "Seeded".into(),
                url: None,
                interval_hours: 0,
                updated: 0,
                attempted: 0,
                error: None,
                source: source.into(),
                compiled: source.into(),
            }],
            ..Library::default()
        };
        mihomo.save_library(&library).unwrap();
        library
    }

    #[test]
    fn urls_never_accept_insecure_redirects_or_local_files() {
        for url in [
            "http://example.com/",
            "file:///etc/passwd",
            "https://u:p@example.com",
            "https://example.com/#secret",
        ] {
            assert!(subscription_url(url).is_err());
        }
        assert!(subscription_url("https://example.com/config?token=private").is_ok());
    }

    #[test]
    fn inline_library_migrates_atomically_and_round_trips_for_an_old_slot() {
        let root = std::env::temp_dir().join(format!("u60-profile-migration-{}", std::process::id()));
        let m = Mihomo::at(root.clone());
        let text = "rules: ['MATCH,DIRECT']";
        let original = seed(&m, text);
        m.save_inline(&original).unwrap();
        assert_eq!(m.selected_source().unwrap(), text);
        let mut next = m.load_library().unwrap();
        next.profiles[0].attempted += 1;
        m.save_library(&next).unwrap();
        let index = fs::read_to_string(m.library_path()).unwrap();
        assert!(!index.contains(text));
        assert_eq!(fs::read_dir(root.join("profile-bodies")).unwrap().count(), 1);
        m.before_slot_change(|| {
            let legacy: Library = serde_json::from_slice(&fs::read(m.library_path()).unwrap()).unwrap();
            assert_eq!(legacy.profiles[0].compiled, text);
            Ok(())
        }).unwrap();
        m.save_library(&next).unwrap();
        fs::remove_file(root.join("profile-bodies").join(hash(text))).unwrap();
        assert!(m.selected_source().is_err());
        assert_eq!(fs::read_to_string(m.library_path()).unwrap(), index);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn metadata_has_no_subscription_or_node_credentials() {
        let dir = std::env::temp_dir().join(format!("u60-profiles-{}", std::process::id()));
        let mihomo = Mihomo::at(dir.clone());
        let mut library = seed(&mihomo, "secret: private-node\nrules: ['MATCH,DIRECT']");
        library.profiles[0].url = Some("https://example.com/?token=private-url".into());
        library.extensions.merge = "secret: private-extension-secret".into();
        library.extensions.script = "function main(c) { c.secret = 'private-script-secret'; return c; }".into();
        mihomo.save_library(&library).unwrap();
        let status = mihomo.profile_status().unwrap().to_string();
        assert!(!status.contains("private-node") && !status.contains("private-url"));
        assert!(!status.contains("private-extension-secret") && !status.contains("private-script-secret"));
        let editor = mihomo.extensions_editor().unwrap();
        assert_eq!(editor["merge"], library.extensions.merge);
        assert_eq!(editor["script"], library.extensions.script);
        assert_eq!(editor["script_enabled"], false);
        assert_eq!(
            mihomo.selected_source().unwrap(),
            library.profiles[0].source
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn status_is_parsed_once_per_change_of_the_library() {
        let dir = std::env::temp_dir().join(format!("u60-status-cache-{}", std::process::id()));
        let mihomo = Mihomo::at(dir.clone());
        seed(&mihomo, "rules: ['MATCH,DIRECT']");
        let first = mihomo.profile_status().unwrap();
        assert_eq!(first["selected"], "seed");
        mihomo.save_library(&mihomo.load_library().unwrap()).unwrap();
        let saved = mihomo.profile_status().unwrap();
        assert_eq!(saved, first);
        // Same length and mtime, damaged content: only a cached answer survives.
        let path = mihomo.library_path();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let length = fs::metadata(&path).unwrap().len() as usize;
        fs::write(&path, vec![b'x'; length]).unwrap();
        fs::File::options().write(true).open(&path).unwrap().set_modified(modified).unwrap();
        assert_eq!(mihomo.profile_status().unwrap(), first, "served from the cache");
        // A different length (an out-of-band edit) must be noticed.
        fs::write(&path, b"damaged").unwrap();
        assert!(mihomo.profile_status().is_err());
        // A save from this process always invalidates, even within one mtime tick.
        mihomo.save_library(&Library::default()).unwrap();
        assert!(mihomo.profile_status().unwrap()["selected"].is_null());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn identical_refresh_only_updates_metadata_without_compilation_or_validation() {
        let dir = std::env::temp_dir().join(format!("u60-refresh-identical-{}", std::process::id()));
        let mihomo = Mihomo::at(dir.clone());
        let mut library = seed(&mihomo, "rules: ['MATCH,DIRECT']");
        let profile = &mut library.profiles[0];
        profile.compiled = "previous compiled text".into();
        profile.error = Some("previous failure".into());
        let extensions = Extensions { script_enabled: true, script: "function main(){throw Error()}".into(), ..Extensions::default() };
        mihomo.refresh_source(profile, &extensions, profile.source.clone(), true).unwrap();
        assert_eq!(profile.source, "rules: ['MATCH,DIRECT']");
        assert_eq!(profile.compiled, "previous compiled text");
        assert!(profile.updated > 0 && profile.error.is_none());
        assert!(!dir.join("check.yaml").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn changed_selected_refresh_is_validated_by_the_controller_and_failed_commit_restores_library() {
        use super::super::controller::{Message, Phase};
        let dir = std::env::temp_dir().join(format!("u60-refresh-commit-{}", std::process::id()));
        let mihomo = Mihomo::for_bridge(dir.clone(), "s".into());
        let old = seed(&mihomo, "rules: ['MATCH,DIRECT']");
        let mut next = old.clone();
        mihomo.refresh_source(&mut next.profiles[0], &next.extensions, "rules: ['MATCH,REJECT']".into(), true).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        *mihomo.commands.lock().unwrap() = Some(sender);
        let worker = std::thread::spawn(move || {
            let Message::Config { refresh, reply } = receiver.recv().unwrap() else { panic!("wrong command") };
            assert!(refresh);
            reply.send(Err("validation failed; running profile keeps serving".into())).unwrap();
        });
        assert!(mihomo.commit_library(&old, &next, false, true).is_err());
        worker.join().unwrap();
        assert_eq!(mihomo.selected_source().unwrap(), old.profiles[0].compiled);
        assert_eq!(mihomo.snapshot().phase, Phase::Running);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refresh_failure_retries_hourly_not_in_a_busy_loop() {
        let p: Profile = Profile {
            id: "x".into(),
            name: "x".into(),
            url: None,
            interval_hours: 24,
            updated: 10,
            attempted: 100,
            error: Some("failed".into()),
            source: "{}".into(),
            compiled: "{}".into(),
        };
        assert_eq!(due_in(&p, 101), 3599);
        assert_eq!(due_in(&p, 5000), 0);
        assert_eq!(due_in(&p, 50), 0);
    }

    #[test]
    fn delete_rechecks_lifecycle_before_committing_a_racing_start() {
        let dir =
            std::env::temp_dir().join(format!("u60-profile-start-race-{}", std::process::id()));
        let mihomo = Mihomo::for_bridge(
            dir.clone(),
            "test-secret".into(),
        );
        let old = seed(&mihomo, "rules: ['MATCH,DIRECT']");
        let before = fs::read(mihomo.library_path()).unwrap();
        let next = Library {
            selected: None,
            profiles: Vec::new(),
            ..old.clone()
        };
        assert!(mihomo.commit_library(&old, &next, false, false).is_err());
        assert!(mihomo.commit_library(&old, &old, true, false).is_err());
        assert_eq!(fs::read(mihomo.library_path()).unwrap(), before);
        assert!(mihomo.running());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn library_updates_are_validated_and_failures_leave_selection_and_bytes_unchanged() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("u60-library-transaction-{}", std::process::id()));
        let mihomo = Mihomo::at(dir.clone());
        net::write_private(&dir.join("mihomo"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(dir.join("mihomo"), fs::Permissions::from_mode(0o700)).unwrap();
        let request = |v: Value| serde_json::from_value::<Request>(v).unwrap();
        mihomo
            .profiles_change(request(
                json!({"action":"add","name":"One","yaml":"rules: ['MATCH,DIRECT']"}),
            ))
            .unwrap();
        let first = mihomo.load_library().unwrap().selected.unwrap();
        mihomo
            .profiles_change(request(
                json!({"action":"add","name":"Two","yaml":"rules: ['MATCH,REJECT']"}),
            ))
            .unwrap();
        let second = mihomo.load_library().unwrap().profiles[1].id.clone();
        assert_eq!(
            mihomo.load_library().unwrap().selected.as_deref(),
            Some(first.as_str())
        );
        let before = fs::read(mihomo.library_path()).unwrap();
        assert!(mihomo.profiles_change(request(json!({"action":"extensions","extensions":{"script_enabled":true,"script":"function main(){throw Error()}"}}))).is_err());
        assert_eq!(fs::read(mihomo.library_path()).unwrap(), before);
        // Core validation can reject valid YAML: no manifest write in that case.
        net::write_private(&dir.join("mihomo"), b"#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(dir.join("mihomo"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(mihomo
            .profiles_change(request(json!({"action":"select","id":second})))
            .is_err());
        assert_eq!(fs::read(mihomo.library_path()).unwrap(), before);
        net::write_private(&dir.join("mihomo"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(dir.join("mihomo"), fs::Permissions::from_mode(0o700)).unwrap();
        mihomo
            .profiles_change(request(json!({"action":"select","id":second})))
            .unwrap();
        assert!(mihomo.selected_source().unwrap().contains("REJECT"));
        assert!(
            !mihomo.running(),
            "selecting while off must not start proxy"
        );
        assert!(!dir.join("check.yaml").exists());
        let script = "function main(c) { c.ipv6 = true; return c; }";
        mihomo.profiles_change(request(json!({"action":"extensions","extensions":{"script_enabled":true,"script":script}}))).unwrap();
        assert_eq!(mihomo.extensions_editor().unwrap()["script"], script);
        let saved = fs::read(mihomo.library_path()).unwrap();
        assert!(mihomo.profiles_change(request(json!({"action":"extensions","extensions":{"script_enabled":true,"script":"function main(){throw Error()}"}}))).is_err());
        assert_eq!(fs::read(mihomo.library_path()).unwrap(), saved);
        assert_eq!(mihomo.extensions_editor().unwrap()["script"], script);
        mihomo
            .profiles_change(request(
                json!({"action":"edit","id":second,"source_type":"local","name":"Renamed"}),
            ))
            .unwrap();
        let library = mihomo.load_library().unwrap();
        assert_eq!(library.profiles[1].id, second);
        assert_eq!(library.profiles[1].name, "Renamed");
        assert!(mihomo.selected_source().unwrap().contains("REJECT"));
        let before = fs::read(mihomo.library_path()).unwrap();
        assert!(mihomo.profiles_change(request(json!({"action":"edit","id":second,"source_type":"local","name":"Invalid","yaml":"not a mapping"}))).is_err());
        assert_eq!(fs::read(mihomo.library_path()).unwrap(), before);
        mihomo
            .profiles_change(request(json!({"action":"delete","id":second})))
            .unwrap();
        assert!(mihomo.selected_source().is_err());
        assert_eq!(mihomo.status()["configured"], false);
        mihomo
            .profiles_change(request(
                json!({"action":"edit","id":first,"source_type":"local","name":"Still unselected"}),
            ))
            .unwrap();
        assert!(mihomo.load_library().unwrap().selected.is_none());
        // Metadata-only remote edits must work offline, without refetching.
        let mut library = mihomo.load_library().unwrap();
        library.profiles[0].url = Some("https://invalid.example/?token=private-url".into());
        mihomo.save_library(&library).unwrap();
        mihomo.profiles_change(request(json!({"action":"edit","id":first,"source_type":"remote","name":"Offline edit","url":"https://invalid.example/?token=private-url","interval_hours":6}))).unwrap();
        assert_eq!(mihomo.profile_editor(&first).unwrap()["interval_hours"], 6);
        assert!(mihomo.profile_editor(&first).unwrap().get("yaml").is_none());
        mihomo
            .profiles_change(request(json!({"action":"delete","id":first})))
            .unwrap();
        assert!(mihomo.load_library().unwrap().profiles.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
