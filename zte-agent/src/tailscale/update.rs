use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{
    daemon_status, handler_error, run_with_timeout, unix_now, AppState, TailscaleManager, TsConfig,
    BIN_DIR,
};

const BINARIES: [&str; 2] = ["tailscaled", "tailscale"];
const VERSIONS_CACHE_TTL: Duration = Duration::from_secs(600);
const VERSIONS_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const VERSIONS_FETCH_TIMEOUT: Duration = Duration::from_secs(12);
const SHA256_FETCH_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_LISTED_VERSIONS: usize = 15;
const PKGS_INDEX_MAX_BYTES: usize = 64 * 1024;
const GITHUB_RELEASES_MAX_BYTES: usize = 512 * 1024;
const SHA256_FILE_MAX_BYTES: usize = 1024;
const TAILSCALE_PKGS_INDEX_URL: &str = "https://pkgs.tailscale.com/stable/?mode=json";
const TAILSCALE_GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/tailscale/tailscale/releases?per_page=30";
const TAILSCALE_USER_AGENT: &str = concat!("open-u60-tailscale/", env!("CARGO_PKG_VERSION"));

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReleaseEntry {
    version: String,
    published_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VersionCatalog {
    latest: String,
    versions: Vec<ReleaseEntry>,
    source: String,
    warning: Option<String>,
    fetched_at: i64,
}

impl VersionCatalog {
    fn to_json(&self) -> Value {
        let versions: Vec<Value> = self
            .versions
            .iter()
            .map(|entry| {
                json!({
                    "version": entry.version,
                    "published_at": entry.published_at,
                })
            })
            .collect();
        json!({
            "latest": self.latest,
            "versions": versions,
            "source": self.source,
            "warning": self.warning,
            "fetched_at": self.fetched_at,
        })
    }
}

fn binary_path(bin_dir: &Path, name: &str, suffix: &str) -> PathBuf {
    bin_dir.join(format!("{name}{suffix}"))
}

/// A reboot mid-swap can leave `tailscaled` missing with `.prev`/`.new`
/// siblings present. Promote the known-good `.prev` first, else `.new`.
pub(super) fn recover_binaries_in(bin_dir: &Path) {
    for name in BINARIES {
        let current = binary_path(bin_dir, name, "");
        if current.exists() {
            continue;
        }
        for suffix in [".prev", ".new"] {
            let candidate = binary_path(bin_dir, name, suffix);
            if candidate.exists() {
                eprintln!("[tailscale] recovering {name} from {suffix} after interrupted update");
                if std::fs::rename(&candidate, &current).is_ok() {
                    break;
                }
            }
        }
    }
}

fn is_valid_version(version: &str) -> bool {
    !version.is_empty()
        && version
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

fn parse_stable_semver(raw: &str) -> Option<(String, semver::Version)> {
    let trimmed = raw.trim();
    let clean = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    if !is_valid_version(clean) {
        return None;
    }
    let parsed = semver::Version::parse(clean).ok()?;
    if !parsed.pre.is_empty() || !parsed.build.is_empty() {
        return None;
    }
    Some((clean.to_string(), parsed))
}

fn parse_pkgs_latest(body: &Value) -> Result<String, String> {
    if let Some(tarballs) = body.get("Tarballs").and_then(Value::as_object) {
        let arm64 = tarballs
            .get("arm64")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if arm64.is_empty() {
            return Err("pkgs.tailscale.com index is missing an arm64 tarball".into());
        }
    }
    let candidate = body["TarballsVersion"]
        .as_str()
        .or_else(|| body["Version"].as_str())
        .map(str::trim)
        .unwrap_or("");
    if is_valid_version(candidate) {
        Ok(candidate.to_string())
    } else {
        Err("pkgs.tailscale.com returned an invalid latest version".into())
    }
}

fn parse_github_releases(body: &Value) -> Result<Vec<ReleaseEntry>, String> {
    let list = body
        .as_array()
        .ok_or_else(|| "GitHub releases payload is not an array".to_string())?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for item in list {
        if item["draft"].as_bool().unwrap_or(false) || item["prerelease"].as_bool().unwrap_or(false)
        {
            continue;
        }
        let Some(tag) = item["tag_name"].as_str() else {
            continue;
        };
        let Some((version, _)) = parse_stable_semver(tag) else {
            continue;
        };
        if !seen.insert(version.clone()) {
            continue;
        }
        let published_at = item["published_at"]
            .as_str()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_string);
        out.push(ReleaseEntry {
            version,
            published_at,
        });
    }
    Ok(out)
}

fn compare_release_desc(left: &ReleaseEntry, right: &ReleaseEntry) -> std::cmp::Ordering {
    match (
        semver::Version::parse(&left.version),
        semver::Version::parse(&right.version),
    ) {
        (Ok(left_sv), Ok(right_sv)) => right_sv
            .cmp(&left_sv)
            .then_with(|| right.version.cmp(&left.version)),
        _ => right.version.cmp(&left.version),
    }
}

fn merge_version_catalog(
    pkgs: Result<String, String>,
    github: Result<Vec<ReleaseEntry>, String>,
    fetched_at: i64,
) -> Result<VersionCatalog, String> {
    match (pkgs, github) {
        (Ok(latest), Ok(gh_entries)) => {
            let latest_sv = semver::Version::parse(&latest).ok();
            let mut versions: Vec<ReleaseEntry> = gh_entries
                .into_iter()
                .filter(|entry| match (&latest_sv, semver::Version::parse(&entry.version).ok()) {
                    (Some(max_sv), Some(entry_sv)) => entry_sv <= *max_sv,
                    _ => true,
                })
                .collect();
            let warning = if versions.is_empty() {
                Some(
                    "GitHub returned no matching stable releases; showing latest stable from pkgs.tailscale.com."
                        .to_string(),
                )
            } else {
                None
            };
            if !versions.iter().any(|entry| entry.version == latest) {
                versions.push(ReleaseEntry {
                    version: latest.clone(),
                    published_at: None,
                });
            }
            versions.sort_by(compare_release_desc);
            versions.dedup_by(|left, right| left.version == right.version);
            versions.truncate(MAX_LISTED_VERSIONS);
            Ok(VersionCatalog {
                latest,
                versions,
                source: "github+pkgs".to_string(),
                warning,
                fetched_at,
            })
        }
        (Ok(latest), Err(gh_err)) => Ok(VersionCatalog {
            versions: vec![ReleaseEntry {
                version: latest.clone(),
                published_at: None,
            }],
            latest,
            source: "pkgs".to_string(),
            warning: Some(format!(
                "Could not load release history from GitHub ({gh_err}); showing latest stable from pkgs.tailscale.com."
            )),
            fetched_at,
        }),
        (Err(pkgs_err), Ok(mut gh_entries)) if !gh_entries.is_empty() => {
            gh_entries.sort_by(compare_release_desc);
            gh_entries.dedup_by(|left, right| left.version == right.version);
            gh_entries.truncate(MAX_LISTED_VERSIONS);
            let latest = gh_entries[0].version.clone();
            Ok(VersionCatalog {
                latest,
                versions: gh_entries,
                source: "github".to_string(),
                warning: Some(format!(
                    "Could not verify latest package index at pkgs.tailscale.com ({pkgs_err}); showing GitHub releases."
                )),
                fetched_at,
            })
        }
        (Err(pkgs_err), Err(gh_err)) => Err(format!(
            "failed to load Tailscale releases: pkgs.tailscale.com ({pkgs_err}); GitHub ({gh_err})"
        )),
        (Err(pkgs_err), Ok(_)) => Err(format!(
            "failed to load Tailscale releases: pkgs.tailscale.com ({pkgs_err}); GitHub returned no stable releases"
        )),
    }
}

fn parse_sha256_text(text: &str) -> Result<String, String> {
    let token = text.split_whitespace().next().unwrap_or("");
    if token.len() == 64 && token.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Ok(token.to_ascii_lowercase())
    } else {
        Err("official checksum response is not a valid 64-character SHA-256 digest".into())
    }
}

fn read_bounded_string(
    resp: ureq::http::Response<ureq::Body>,
    max_bytes: usize,
) -> Result<String, String> {
    let mut raw = Vec::new();
    resp.into_body()
        .into_reader()
        .take((max_bytes as u64) + 1)
        .read_to_end(&mut raw)
        .map_err(|err| format!("read response: {err}"))?;
    if raw.len() > max_bytes {
        return Err(format!("response exceeded {max_bytes}-byte limit"));
    }
    String::from_utf8(raw).map_err(|err| format!("invalid UTF-8 response: {err}"))
}

fn fetch_json_url(
    agent: &ureq::Agent,
    url: &str,
    accept: Option<&str>,
    max_bytes: usize,
) -> Result<Value, String> {
    let mut req = agent.get(url).header("User-Agent", TAILSCALE_USER_AGENT);
    if let Some(header_val) = accept {
        req = req.header("Accept", header_val);
    }
    let resp = req.call().map_err(|err| err.to_string())?;
    let text = read_bounded_string(resp, max_bytes)?;
    serde_json::from_str(&text).map_err(|err| format!("parse JSON: {err}"))
}

fn fetch_versions_from_urls(pkgs_url: &str, github_url: &str) -> Result<VersionCatalog, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(VERSIONS_CONNECT_TIMEOUT))
        .timeout_global(Some(VERSIONS_FETCH_TIMEOUT))
        .build()
        .into();
    let (pkgs_res, gh_res) = thread::scope(|scope| {
        let pkgs_handle = scope.spawn(|| {
            let body = fetch_json_url(&agent, pkgs_url, None, PKGS_INDEX_MAX_BYTES)?;
            parse_pkgs_latest(&body)
        });
        let gh_handle = scope.spawn(|| {
            let body = fetch_json_url(
                &agent,
                github_url,
                Some("application/vnd.github+json"),
                GITHUB_RELEASES_MAX_BYTES,
            )?;
            parse_github_releases(&body)
        });
        let pkgs_out = pkgs_handle
            .join()
            .unwrap_or_else(|_| Err("pkgs.tailscale.com lookup panicked".into()));
        let gh_out = gh_handle
            .join()
            .unwrap_or_else(|_| Err("GitHub releases lookup panicked".into()));
        (pkgs_out, gh_out)
    });
    merge_version_catalog(pkgs_res, gh_res, unix_now())
}

fn fetch_versions_live() -> Result<VersionCatalog, String> {
    if cfg!(test) {
        return Err("version lookup disabled in tests".into());
    }
    fetch_versions_from_urls(TAILSCALE_PKGS_INDEX_URL, TAILSCALE_GITHUB_RELEASES_URL)
}

impl TailscaleManager {
    fn versions_catalog_with<F>(
        &self,
        force_refresh: bool,
        fetch: F,
    ) -> Result<VersionCatalog, String>
    where
        F: FnOnce() -> Result<VersionCatalog, String>,
    {
        if !force_refresh {
            let guard = self
                .versions_cache
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            if let Some((catalog, fetched_instant)) = guard.as_ref() {
                if fetched_instant.elapsed() < VERSIONS_CACHE_TTL {
                    return Ok(catalog.clone());
                }
            }
        }
        let fresh = fetch()?;
        let mut guard = self
            .versions_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        *guard = Some((fresh.clone(), Instant::now()));
        Ok(fresh)
    }
}

/// GET /api/tailscale/versions — recent official stable ARM64 versions
/// (cached in memory for 10 minutes).
pub fn versions(state: &AppState) -> (u16, Value) {
    match state
        .tailscale
        .versions_catalog_with(false, fetch_versions_live)
    {
        Ok(catalog) => (200, json!({"ok": true, "data": catalog.to_json()})),
        Err(err) => (502, json!({"ok": false, "error": err})),
    }
}

/// POST /api/tailscale/versions/refresh — bypass cache and fetch recent
/// official stable ARM64 versions immediately.
pub fn versions_refresh(state: &AppState) -> (u16, Value) {
    match state
        .tailscale
        .versions_catalog_with(true, fetch_versions_live)
    {
        Ok(catalog) => (200, json!({"ok": true, "data": catalog.to_json()})),
        Err(err) => (502, json!({"ok": false, "error": err})),
    }
}

fn parse_update_request(body: &[u8]) -> Result<(String, Option<String>), String> {
    let parsed: Value = serde_json::from_slice(body).map_err(|_| "invalid JSON".to_string())?;
    let version = match parsed["version"].as_str().map(str::trim) {
        Some(ver) if is_valid_version(ver) => ver.to_string(),
        _ => return Err("missing or invalid 'version'".into()),
    };
    let sha256 = match parsed.get("sha256") {
        None | Some(Value::Null) => None,
        Some(Value::String(raw)) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.len() == 64 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
                Some(trimmed.to_ascii_lowercase())
            } else {
                return Err("missing or invalid 'sha256' (64 hex chars)".into());
            }
        }
        _ => return Err("missing or invalid 'sha256' (64 hex chars)".into()),
    };
    Ok((version, sha256))
}

fn fetch_official_sha256_at(url: &str) -> Result<String, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(VERSIONS_CONNECT_TIMEOUT))
        .timeout_global(Some(SHA256_FETCH_TIMEOUT))
        .build()
        .into();
    let resp = agent
        .get(url)
        .header("User-Agent", TAILSCALE_USER_AGENT)
        .call()
        .map_err(|err| format!("fetch official sha256 {url}: {err}"))?;
    let body = read_bounded_string(resp, SHA256_FILE_MAX_BYTES)?;
    parse_sha256_text(&body)
}

/// POST /api/tailscale/update — body: {"version": "1.104.7", "sha256": "<optional hex>"}
/// Installs when absent; upgrades with rollback when present. Runs in the
/// background (multi-minute download on cellular) — poll /status for
/// "updating" and "last_update".
pub fn update(state: &AppState, body: &[u8]) -> (u16, Value) {
    update_with_runner(state, body, run_update)
}

pub(super) fn update_with_runner(
    state: &AppState,
    body: &[u8],
    run: impl FnOnce(&Arc<TailscaleManager>, &str, Option<&str>) -> Result<(), String> + Send + 'static,
) -> (u16, Value) {
    let mgr = &state.tailscale;
    let (version, sha256) = match parse_update_request(body) {
        Ok(req) => req,
        Err(err) => return (400, json!({"ok": false, "error": err})),
    };

    {
        let Ok(_prefs) = mgr.prefs_lock.try_lock() else {
            return handler_error((409, "tailscale preferences are being changed".into()));
        };
        if mgr.updating.load(Ordering::Acquire) {
            return handler_error((409, "update already in progress".into()));
        }
        if mgr.slot_change_blocked() {
            return handler_error((409, "OTA slot change or health trial in progress".into()));
        }
        if mgr.enrollment_active() {
            return handler_error((409, "enrollment in progress".into()));
        }
        mgr.updating.store(true, Ordering::Release);
    }
    // Refresh so clients polling /status see "updating" immediately (the
    // cache is otherwise served for up to 10s)
    mgr.refresh_status();

    let mgr2 = Arc::clone(&state.tailscale);
    thread::spawn(move || {
        let result = run(&mgr2, &version, sha256.as_deref());
        if let Err(ref e) = result {
            eprintln!("[tailscale] update to {version} failed: {e}");
        }
        *mgr2.last_update.lock().unwrap() = Some(json!({
            "version": version,
            "ok": result.is_ok(),
            "error": result.err(),
            "finished_at": unix_now(),
        }));
        {
            let _prefs = mgr2.prefs_lock.lock().unwrap();
            mgr2.updating.store(false, Ordering::Release);
        }
        mgr2.refresh_status();
    });
    (202, json!({"ok": true, "data": {"status": "updating"}}))
}

fn run_update(
    mgr: &Arc<TailscaleManager>,
    version: &str,
    expected_sha256: Option<&str>,
) -> Result<(), String> {
    run_update_with(
        mgr,
        version,
        expected_sha256,
        Path::new(BIN_DIR),
        "/tmp/tailscale-update.tgz",
        "/tmp/tailscale-update",
        &UpdateOperations {
            fetch_digest: &fetch_official_sha256_at,
            download: &download_archive,
            quiesce: &|| mgr.quiesce_supervisor(),
            resume: &|| mgr.resume_supervisor(),
            wait: &thread::sleep,
            status: &daemon_status,
            persist: &|cfg| mgr.save_config(cfg),
        },
    )
}

struct UpdateOperations<'a> {
    fetch_digest: &'a dyn Fn(&str) -> Result<String, String>,
    download: &'a dyn Fn(&str, &str) -> Result<(), String>,
    quiesce: &'a dyn Fn() -> bool,
    resume: &'a dyn Fn(),
    wait: &'a dyn Fn(Duration),
    status: &'a dyn Fn(u64) -> Result<Value, String>,
    persist: &'a dyn Fn(&TsConfig) -> Result<(), String>,
}

fn run_update_with(
    mgr: &TailscaleManager,
    version: &str,
    expected_sha256: Option<&str>,
    bin_dir: &Path,
    tgz_path: &str,
    extract_dir: &str,
    ops: &UpdateOperations<'_>,
) -> Result<(), String> {
    let result = prepare_package(
        version,
        expected_sha256,
        bin_dir,
        tgz_path,
        extract_dir,
        ops,
    )
    .and_then(|()| switch_daemon(mgr, version, bin_dir, ops));
    // Never leak tmpfs space, whatever the exit path
    let _ = std::fs::remove_file(tgz_path);
    let _ = std::fs::remove_dir_all(extract_dir);
    for name in BINARIES {
        let _ = std::fs::remove_file(binary_path(bin_dir, name, ".new"));
    }
    result
}

fn download_archive(url: &str, tgz_path: &str) -> Result<(), String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_global(Some(Duration::from_secs(600)))
        .build()
        .into();
    let resp = agent
        .get(url)
        .header("User-Agent", TAILSCALE_USER_AGENT)
        .call()
        .map_err(|err| format!("download {url}: {err}"))?;
    let mut reader = resp.into_body().into_reader().take(120 * 1024 * 1024);
    let mut out = std::fs::File::create(tgz_path).map_err(|e| format!("create {tgz_path}: {e}"))?;
    std::io::copy(&mut reader, &mut out).map_err(|e| format!("download stream: {e}"))?;
    drop(out);
    Ok(())
}

fn prepare_package(
    version: &str,
    expected_sha256: Option<&str>,
    bin_dir: &Path,
    tgz_path: &str,
    extract_dir: &str,
    ops: &UpdateOperations<'_>,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let url = format!("https://pkgs.tailscale.com/stable/tailscale_{version}_arm64.tgz");
    let sha256 = match expected_sha256 {
        Some(digest) => digest.to_string(),
        None => {
            let sha_url = format!("{url}.sha256");
            (ops.fetch_digest)(&sha_url)?
        }
    };

    // 1. Download (streamed to tmpfs, 120 MB cap)
    (ops.download)(&url, tgz_path)?;

    // 2. Verify sha256
    let actual = sha256_file(tgz_path)?;
    if actual != sha256 {
        return Err(format!("sha256 mismatch: expected {sha256}, got {actual}"));
    }

    // 3. Extract via busybox tar
    let _ = std::fs::remove_dir_all(extract_dir);
    std::fs::create_dir_all(extract_dir).map_err(|e| format!("mkdir {extract_dir}: {e}"))?;
    let mut tar = Command::new("tar");
    tar.args(["-xzf", tgz_path, "-C", extract_dir]);
    let out = run_with_timeout(tar, 120)?;
    if !out.status.success() {
        return Err(format!(
            "tar extract failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let src_dir = format!("{extract_dir}/tailscale_{version}_arm64");

    // 4. Stage new binaries next to the current ones (same filesystem for
    //    atomic rename) and smoke-test before touching the live install.
    std::fs::create_dir_all(bin_dir).map_err(|e| format!("mkdir {}: {e}", bin_dir.display()))?;
    for name in BINARIES {
        let src = format!("{src_dir}/{name}");
        let staged = binary_path(bin_dir, name, ".new");
        std::fs::copy(&src, &staged).map_err(|e| format!("stage {name}: {e}"))?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {name}: {e}"))?;
    }
    let _ = std::fs::remove_file(tgz_path);
    let _ = std::fs::remove_dir_all(extract_dir);

    let mut smoke = Command::new(binary_path(bin_dir, "tailscaled", ".new"));
    smoke.arg("--version");
    let smoke_out = run_with_timeout(smoke, 15)?;
    if !smoke_out.status.success() {
        return Err("staged tailscaled failed --version smoke test".into());
    }

    Ok(())
}

fn switch_daemon(
    mgr: &TailscaleManager,
    version: &str,
    bin_dir: &Path,
    ops: &UpdateOperations<'_>,
) -> Result<(), String> {
    // 5. Quiesce the supervisor — a real handshake, not a best-effort wait:
    //    swapping binaries under a live or mid-spawn supervisor can leave the
    //    OLD daemon running while we validate and pin the new version.
    let was_running = mgr.running.load(Ordering::SeqCst);
    let enrolled = mgr.config.lock().unwrap().enrolled;
    if !(ops.quiesce)() {
        (ops.resume)();
        return Err("supervisor did not quiesce — update aborted".into());
    }

    let mut switched = Vec::new();
    let swapped = (|| -> Result<(), String> {
        for name in BINARIES {
            let current = binary_path(bin_dir, name, "");
            let prev = binary_path(bin_dir, name, ".prev");
            let staged = binary_path(bin_dir, name, ".new");
            let had_current = current.exists();
            if had_current {
                std::fs::rename(&current, &prev).map_err(|e| format!("backup {name}: {e}"))?;
            }
            switched.push((name, current.clone(), prev, had_current));
            std::fs::rename(staged, current).map_err(|e| format!("install {name}: {e}"))?;
        }
        Ok(())
    })();
    let rollback = |failure: String| {
        let mut errors = Vec::new();
        for (name, current, prev, had_current) in switched.iter().rev() {
            let result = if *had_current {
                std::fs::rename(prev, current)
            } else if current.exists() {
                std::fs::remove_file(current)
            } else {
                Ok(())
            };
            if let Err(error) = result {
                errors.push(format!("restore {name}: {error}"));
            }
        }
        (ops.resume)();
        if errors.is_empty() {
            failure
        } else {
            format!("{failure}. Rollback failed ({})", errors.join(", "))
        }
    };

    if let Err(error) = swapped {
        return Err(rollback(error));
    }

    // 6. Resume; if it was enrolled+enabled, require Running within 120s or
    //    roll back. Gate on `enrolled`, not the state file — tailscaled
    //    creates a state file before first login, and an unenrolled node
    //    sits in NeedsLogin forever (which is not a failed update).
    (ops.resume)();
    if was_running && enrolled {
        let mut healthy = false;
        for _ in 0..120 {
            (ops.wait)(Duration::from_secs(1));
            if let Ok(v) = (ops.status)(10) {
                if v["BackendState"].as_str() == Some("Running") {
                    healthy = true;
                    break;
                }
            }
        }
        if !healthy {
            eprintln!("[tailscale] update: not Running within 120s — rolling back");
            if !(ops.quiesce)() {
                (ops.resume)();
                return Err(
                    "updated tailscaled unhealthy and supervisor did not quiesce for rollback — manual intervention needed"
                        .into(),
                );
            }
            return Err(rollback(
                "updated tailscaled did not reach Running in 120s — rolled back".into(),
            ));
        }
    }

    let persisted = {
        let _prefs = mgr.prefs_lock.lock().unwrap();
        let mut current = mgr.config.lock().unwrap();
        let mut candidate = current.clone();
        candidate.pinned_version = version.to_string();
        (ops.persist)(&candidate).map(|()| {
            *current = candidate;
            mgr.prefs_gen.fetch_add(1, Ordering::Relaxed);
        })
    };
    if let Err(error) = persisted {
        if !(ops.quiesce)() {
            (ops.resume)();
            return Err(format!(
                "{error}. Supervisor did not quiesce for rollback — manual intervention needed"
            ));
        }
        return Err(rollback(error));
    }
    Ok(())
}

fn sha256_file(path: &str) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read {path}: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests;
