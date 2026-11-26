use super::*;
use std::cell::{Cell, RefCell};
use std::fs;
use std::os::unix::fs::symlink;
use std::sync::atomic::AtomicU64;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir();
        loop {
            let path = root.join(format!(
                "tailscale-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create {}: {e}", path.display()),
            }
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn sha256_file_hashes_empty_and_multiblock_files_and_reports_missing_file() {
    let dir = Scratch::new();
    let file = dir.0.join("archive");
    let path = file.to_str().unwrap();
    assert!(sha256_file(path)
        .unwrap_err()
        .starts_with(&format!("open {path}: ")));
    for (bytes, digest) in [
        (
            vec![],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            vec![b'x'; 65_537],
            "1abe08ebecf1c18cab71f6fe28aaddf20268f85bad78bb9a72f88ca47c874662",
        ),
    ] {
        fs::write(&file, bytes).unwrap();
        assert_eq!(sha256_file(path).unwrap(), digest);
    }
}

#[test]
fn recovery_keeps_current_and_prefers_previous_to_staged() {
    for (current, previous, staged, expected) in [
        (Some("live"), Some("backup"), Some("staged"), "live"),
        (None, Some("backup"), Some("staged"), "backup"),
        (None, None, Some("staged"), "staged"),
    ] {
        let dir = Scratch::new();
        for name in ["tailscaled", "tailscale"] {
            for (suffix, bytes) in [("", current), (".prev", previous), (".new", staged)] {
                if let Some(bytes) = bytes {
                    fs::write(dir.0.join(format!("{name}{suffix}")), bytes).unwrap();
                }
            }
        }
        recover_binaries_in(&dir.0);
        for name in ["tailscaled", "tailscale"] {
            assert_eq!(fs::read_to_string(dir.0.join(name)).unwrap(), expected);
            let backup = dir.0.join(format!("{name}.prev"));
            assert_eq!(
                fs::read_to_string(backup).ok().as_deref(),
                previous.filter(|_| current.is_some())
            );
            let staged_file = dir.0.join(format!("{name}.new"));
            assert_eq!(
                fs::read_to_string(staged_file).ok().as_deref(),
                staged.filter(|_| current.is_some() || previous.is_some())
            );
        }
    }
}

#[test]
fn recovery_tries_staged_file_if_previous_rename_fails() {
    let dir = Scratch::new();
    symlink("missing", dir.0.join("tailscaled")).unwrap();
    fs::create_dir(dir.0.join("tailscaled.prev")).unwrap();
    fs::write(dir.0.join("tailscaled.new"), b"staged").unwrap();
    recover_binaries_in(&dir.0);
    assert_eq!(fs::read(dir.0.join("tailscaled")).unwrap(), b"staged");
    assert!(dir.0.join("tailscaled.prev").is_dir());
    assert!(!dir.0.join("tailscaled.new").exists());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    ExplicitDigest,
    SidecarFailure,
    DigestMismatch,
    SmokeFailure,
    QuiesceFailure,
    SecondRenameFailure,
    HealthFailure,
    RollbackQuiesceFailure,
    Unenrolled,
    PersistFailure,
}

const VERSION: &str = "1.104.7";
const URL: &str = "https://pkgs.tailscale.com/stable/tailscale_1.104.7_arm64.tgz";
const NEW_CLI: &[u8] = b"new tailscale";
const OLD_DAEMON: &[u8] = b"old tailscaled";
const OLD_CLI: &[u8] = b"old tailscale";

fn characterize_update(scenario: Scenario, expected: Result<(), &str>, finish: &[&str]) {
    let dir = Scratch::new();
    let bin = dir.0.join("bin");
    fs::create_dir(&bin).unwrap();
    fs::write(bin.join("tailscaled"), OLD_DAEMON).unwrap();
    fs::write(bin.join("tailscale"), OLD_CLI).unwrap();

    let package_dir = dir.0.join("tailscale_1.104.7_arm64");
    fs::create_dir(&package_dir).unwrap();
    let new_daemon: &[u8] = if scenario == Scenario::SmokeFailure {
        b"#!/bin/sh\nexit 1\n"
    } else {
        b"#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = --version ]\n"
    };
    fs::write(package_dir.join("tailscaled"), new_daemon).unwrap();
    fs::write(package_dir.join("tailscale"), NEW_CLI).unwrap();
    let package = dir.0.join("fixture.tgz");
    if scenario == Scenario::DigestMismatch {
        fs::write(&package, b"not an archive").unwrap();
    } else {
        assert!(Command::new("tar")
            .args([
                "-czf",
                package.to_str().unwrap(),
                "-C",
                dir.0.to_str().unwrap(),
                "tailscale_1.104.7_arm64"
            ])
            .status()
            .unwrap()
            .success());
    }
    let actual = sha256_file(package.to_str().unwrap()).unwrap();
    let digest = if scenario == Scenario::DigestMismatch {
        "0000000000000000000000000000000000000000000000000000000000000000"
    } else {
        &actual
    };
    let archive = dir.0.join("download.tgz");
    let extract = dir.0.join("extract");
    fs::create_dir(&extract).unwrap();
    fs::write(extract.join("stale"), b"previous staging").unwrap();
    // A leftover from an earlier attempt is cleaned even if this one never stages a binary.
    fs::write(bin.join("tailscale.new"), b"previous staging").unwrap();

    let manager = TailscaleManager::with_config(TsConfig {
        enrolled: scenario != Scenario::Unenrolled,
        pinned_version: "1.100.0".into(),
        ..TsConfig::default()
    });
    manager.running.store(true, Ordering::SeqCst);
    let trace = RefCell::new(Vec::new());
    let quiesces = Cell::new(0);
    let probes = Cell::new(0);
    let live = || {
        (
            fs::read(bin.join("tailscaled")).unwrap(),
            fs::read(bin.join("tailscale")).unwrap(),
        )
    };
    let old = (OLD_DAEMON.to_vec(), OLD_CLI.to_vec());
    let new = (new_daemon.to_vec(), NEW_CLI.to_vec());
    let ops = UpdateOperations {
        fetch_digest: &|url| {
            trace.borrow_mut().push("sidecar");
            assert_eq!(url, format!("{URL}.sha256"));
            assert_eq!(live(), old);
            if scenario == Scenario::SidecarFailure {
                Err("sidecar unavailable".into())
            } else {
                Ok(digest.into())
            }
        },
        download: &|url, path| {
            trace.borrow_mut().push("download");
            assert_eq!(url, URL);
            assert_eq!(Path::new(path), archive);
            assert_eq!(live(), old);
            fs::copy(&package, path).unwrap();
            Ok(())
        },
        quiesce: &|| {
            trace.borrow_mut().push("quiesce");
            let call = quiesces.get() + 1;
            quiesces.set(call);
            assert_eq!(manager.config.lock().unwrap().pinned_version, "1.100.0");
            if call == 1 {
                assert_eq!(live(), old);
                assert!(!archive.exists());
                assert!(!extract.exists());
                assert_eq!(fs::read(bin.join("tailscaled.new")).unwrap(), new_daemon);
                assert_eq!(fs::read(bin.join("tailscale.new")).unwrap(), NEW_CLI);
                if scenario == Scenario::SecondRenameFailure {
                    fs::remove_file(bin.join("tailscale.new")).unwrap();
                }
                scenario != Scenario::QuiesceFailure
            } else {
                assert_eq!(call, 2);
                assert_eq!(live(), new);
                scenario != Scenario::RollbackQuiesceFailure
            }
        },
        resume: &|| {
            trace.borrow_mut().push("resume");
            let expected_live = match (scenario, quiesces.get()) {
                (Scenario::QuiesceFailure | Scenario::SecondRenameFailure, _)
                | (Scenario::HealthFailure, 2) => &old,
                _ => &new,
            };
            assert_eq!(&live(), expected_live);
        },
        wait: &|duration| {
            trace.borrow_mut().push("wait");
            assert_eq!(duration, Duration::from_secs(1));
        },
        status: &|timeout| {
            trace.borrow_mut().push("status");
            probes.set(probes.get() + 1);
            assert_eq!(timeout, 10);
            assert_eq!(live(), new);
            assert_eq!(manager.config.lock().unwrap().pinned_version, "1.100.0");
            if matches!(
                scenario,
                Scenario::HealthFailure | Scenario::RollbackQuiesceFailure
            ) {
                Ok(json!({"BackendState": "NeedsLogin"}))
            } else if probes.get() == 1 {
                Err("status temporarily unavailable".into())
            } else {
                Ok(json!({"BackendState": "Running"}))
            }
        },
        persist: &|cfg| {
            trace.borrow_mut().push("persist");
            assert_eq!(cfg.pinned_version, VERSION);
            assert_eq!(live(), new);
            if scenario == Scenario::PersistFailure {
                Err("save failed".into())
            } else {
                Ok(())
            }
        },
    };
    let result = run_update_with(
        &manager,
        VERSION,
        (scenario == Scenario::ExplicitDigest).then_some(digest),
        &bin,
        archive.to_str().unwrap(),
        extract.to_str().unwrap(),
        &ops,
    );
    match scenario {
        Scenario::SecondRenameFailure => {
            assert!(result.unwrap_err().starts_with("install tailscale: "))
        }
        Scenario::DigestMismatch => assert_eq!(
            result.unwrap_err(),
            format!("sha256 mismatch: expected {digest}, got {actual}")
        ),
        _ => assert_eq!(
            result.as_ref().map(|_| ()).map_err(String::as_str),
            expected,
            "{scenario:?}"
        ),
    }

    let mut expected_trace = Vec::new();
    if scenario != Scenario::ExplicitDigest {
        expected_trace.push("sidecar");
    }
    if scenario != Scenario::SidecarFailure {
        expected_trace.push("download");
    }
    expected_trace.extend_from_slice(finish);
    assert_eq!(*trace.borrow(), expected_trace, "{scenario:?}");
    let keep_new = expected.is_ok() || scenario == Scenario::RollbackQuiesceFailure;
    assert_eq!(live(), if keep_new { new } else { old });
    for (name, bytes) in [("tailscaled", OLD_DAEMON), ("tailscale", OLD_CLI)] {
        assert!(!bin.join(format!("{name}.new")).exists());
        assert_eq!(
            fs::read(bin.join(format!("{name}.prev"))).ok().as_deref(),
            keep_new.then_some(bytes)
        );
    }
    assert_eq!(
        manager.config.lock().unwrap().pinned_version,
        if expected.is_ok() { VERSION } else { "1.100.0" }
    );
    assert!(!archive.exists());
    assert!(!extract.exists());
}

#[test]
fn update_checks_digest_and_smoke_test_before_quiescing_or_touching_live_files() {
    characterize_update(Scenario::SidecarFailure, Err("sidecar unavailable"), &[]);
    characterize_update(Scenario::DigestMismatch, Err("sha256 mismatch"), &[]);
    characterize_update(
        Scenario::SmokeFailure,
        Err("staged tailscaled failed --version smoke test"),
        &[],
    );
    characterize_update(
        Scenario::ExplicitDigest,
        Ok(()),
        &[
            "quiesce", "resume", "wait", "status", "wait", "status", "persist",
        ],
    );
}

#[test]
fn update_aborts_on_first_quiesce_failure_and_restores_old_bytes_on_partial_swap() {
    characterize_update(
        Scenario::QuiesceFailure,
        Err("supervisor did not quiesce — update aborted"),
        &["quiesce", "resume"],
    );
    characterize_update(
        Scenario::SecondRenameFailure,
        Err("install tailscale"),
        &["quiesce", "resume"],
    );
}

#[test]
fn update_polls_120_times_and_rolls_back_only_after_second_quiesce() {
    let mut trace = vec!["quiesce", "resume"];
    trace.extend(["wait", "status"].repeat(120));
    trace.extend(["quiesce", "resume"]);
    characterize_update(
        Scenario::HealthFailure,
        Err("updated tailscaled did not reach Running in 120s — rolled back"),
        &trace,
    );
    characterize_update(
        Scenario::RollbackQuiesceFailure,
        Err("updated tailscaled unhealthy and supervisor did not quiesce for rollback — manual intervention needed"),
        &trace,
    );
}

#[test]
fn update_skips_health_wait_when_unenrolled_and_ignores_persist_failure() {
    characterize_update(
        Scenario::Unenrolled,
        Ok(()),
        &["quiesce", "resume", "persist"],
    );
    characterize_update(
        Scenario::PersistFailure,
        Ok(()),
        &[
            "quiesce", "resume", "wait", "status", "wait", "status", "persist",
        ],
    );
}

fn serve_http_once(
    response: impl AsRef<[u8]> + Send + 'static,
) -> (String, thread::JoinHandle<String>) {
    use std::io::Write;
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = [0u8; 4096];
        let read = stream.read(&mut buf).unwrap_or(0);
        let _ = stream.write_all(response.as_ref());
        String::from_utf8_lossy(&buf[..read]).into_owned()
    });
    (format!("http://{addr}"), handle)
}

#[test]
fn parse_update_request_accepts_optional_sha256_and_rejects_malformed_inputs() {
    let digest = "A1b2c3d4".repeat(8);
    assert_eq!(
        parse_update_request(br#"{"version":"1.104.7"}"#).unwrap(),
        ("1.104.7".to_string(), None)
    );
    assert_eq!(
        parse_update_request(br#"{"version":" 1.104.7 ","sha256":null}"#).unwrap(),
        ("1.104.7".to_string(), None)
    );
    assert_eq!(
        parse_update_request(br#"{"version":"1.104.7","sha256":"   "}"#).unwrap(),
        ("1.104.7".to_string(), None)
    );
    let body = format!(r#"{{"version":"1.104.7","sha256":" {digest} "}}"#);
    assert_eq!(
        parse_update_request(body.as_bytes()).unwrap(),
        ("1.104.7".to_string(), Some(digest.to_ascii_lowercase()))
    );
    for bad in [
        r#"{"version":"v1.104.7"}"#,
        r#"{"version":"1..2"}"#,
        r#"{"version":""}"#,
        r#"{"version":"1.104.7","sha256":"short"}"#,
        r#"{"version":"1.104.7","sha256":123}"#,
        "not-json",
    ] {
        assert!(parse_update_request(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn parse_sha256_text_accepts_bare_and_sha256sum_formats() {
    let digest = "D6BED2720310B328B861F943D7B4016C5358A9BAD60575EB51E8143B79068484";
    assert_eq!(
        parse_sha256_text(&format!("{digest}\n")).unwrap(),
        digest.to_ascii_lowercase()
    );
    assert_eq!(
        parse_sha256_text(&format!("  {digest}  tailscale_1.104.7_arm64.tgz\n")).unwrap(),
        digest.to_ascii_lowercase()
    );
    assert!(parse_sha256_text("not-a-hash").is_err());
    assert!(parse_sha256_text("").is_err());
}

#[test]
fn parse_github_releases_filters_prereleases_drafts_and_non_semver_tags() {
    let payload = json!([
        {"tag_name": "v1.104.7", "draft": false, "prerelease": false, "published_at": "2026-11-12T22:56:51Z"},
        {"tag_name": "v1.105.0-pre", "draft": false, "prerelease": false, "published_at": "2026-11-13T00:00:00Z"},
        {"tag_name": "v1.104.8", "draft": true, "prerelease": false, "published_at": "2026-11-13T00:00:00Z"},
        {"tag_name": "v1.104.6", "draft": false, "prerelease": true, "published_at": "2026-11-11T00:00:00Z"},
        {"tag_name": "cmd/cigocacher/deadbeef", "draft": false, "prerelease": false},
        {"tag_name": "v1.104.5", "draft": false, "prerelease": false, "published_at": "2026-11-03T00:29:40Z"},
        {"tag_name": "v1.104.5", "draft": false, "prerelease": false, "published_at": "2026-11-03T00:29:40Z"}
    ]);
    let releases = parse_github_releases(&payload).unwrap();
    assert_eq!(
        releases,
        vec![
            ReleaseEntry {
                version: "1.104.7".to_string(),
                published_at: Some("2026-11-12T22:56:51Z".to_string()),
            },
            ReleaseEntry {
                version: "1.104.5".to_string(),
                published_at: Some("2026-11-03T00:29:40Z".to_string()),
            },
        ]
    );
}

#[test]
fn merge_version_catalog_caps_to_pkgs_latest_and_handles_partial_fallbacks() {
    let combined = merge_version_catalog(
        Ok("1.104.7".to_string()),
        Ok(vec![
            ReleaseEntry {
                version: "1.104.8".to_string(),
                published_at: Some("2026-11-20T00:00:00Z".to_string()),
            },
            ReleaseEntry {
                version: "1.98.10".to_string(),
                published_at: Some("2026-07-28T23:02:06Z".to_string()),
            },
            ReleaseEntry {
                version: "1.104.7".to_string(),
                published_at: Some("2026-11-12T22:56:51Z".to_string()),
            },
            ReleaseEntry {
                version: "1.104.6".to_string(),
                published_at: Some("2026-11-11T00:29:49Z".to_string()),
            },
        ]),
        1_800_000_000,
    )
    .unwrap();
    assert_eq!(combined.latest, "1.104.7");
    assert_eq!(combined.source, "github+pkgs");
    assert_eq!(combined.warning, None);
    let ordered: Vec<&str> = combined
        .versions
        .iter()
        .map(|entry| entry.version.as_str())
        .collect();
    assert_eq!(ordered, vec!["1.104.7", "1.104.6", "1.98.10"]);

    let pkgs_only = merge_version_catalog(
        Ok("1.104.7".to_string()),
        Err("rate limited".to_string()),
        1_800_000_000,
    )
    .unwrap();
    assert_eq!(pkgs_only.latest, "1.104.7");
    assert_eq!(pkgs_only.source, "pkgs");
    assert_eq!(pkgs_only.versions.len(), 1);
    assert!(pkgs_only
        .warning
        .as_deref()
        .unwrap()
        .contains("rate limited"));

    let github_only = merge_version_catalog(
        Err("timeout".to_string()),
        Ok(vec![ReleaseEntry {
            version: "1.104.6".to_string(),
            published_at: Some("2026-11-11T00:29:49Z".to_string()),
        }]),
        1_800_000_000,
    )
    .unwrap();
    assert_eq!(github_only.latest, "1.104.6");
    assert_eq!(github_only.source, "github");
    assert!(github_only.warning.as_deref().unwrap().contains("timeout"));

    assert!(merge_version_catalog(
        Err("pkgs down".to_string()),
        Err("gh down".to_string()),
        1_800_000_000,
    )
    .is_err());
}

#[test]
fn versions_catalog_caches_until_forced_refresh() {
    use std::sync::atomic::AtomicUsize;

    let manager = TailscaleManager::new();
    let calls = AtomicUsize::new(0);
    let make = |version: &str| {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(VersionCatalog {
            latest: version.to_string(),
            versions: vec![ReleaseEntry {
                version: version.to_string(),
                published_at: None,
            }],
            source: "pkgs".to_string(),
            warning: None,
            fetched_at: 100,
        })
    };
    let first = manager
        .versions_catalog_with(false, || make("1.104.6"))
        .unwrap();
    let second = manager
        .versions_catalog_with(false, || make("1.104.7"))
        .unwrap();
    assert_eq!(first.latest, "1.104.6");
    assert_eq!(second.latest, "1.104.6");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let refreshed = manager
        .versions_catalog_with(true, || make("1.104.7"))
        .unwrap();
    assert_eq!(refreshed.latest, "1.104.7");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn versions_sources_respect_the_arm64_index_and_report_empty_github() {
    let missing_arm64 = "pkgs.tailscale.com index is missing an arm64 tarball";
    for (index, expected) in [
        (
            json!({"TarballsVersion": " 1.104.7 ", "Version": "1.0.0", "Tarballs": {"arm64": "tailscale.tgz"}}),
            Ok("1.104.7"),
        ),
        (json!({"Version": "1.104.6"}), Ok("1.104.6")),
        (
            json!({"TarballsVersion": "1.104.7", "Tarballs": {"amd64": "tailscale.tgz"}}),
            Err(missing_arm64),
        ),
        (
            json!({"TarballsVersion": "1.104.7", "Tarballs": {"arm64": " "}}),
            Err(missing_arm64),
        ),
    ] {
        let result = parse_pkgs_latest(&index);
        assert_eq!(
            result.as_deref().map_err(String::as_str),
            expected,
            "{index}"
        );
    }

    let releases = parse_github_releases(&json!([])).unwrap();
    let catalog = merge_version_catalog(Ok("1.104.7".into()), Ok(releases), 100).unwrap();
    assert_eq!(
        catalog.to_json(),
        json!({
            "latest": "1.104.7",
            "versions": [{"version": "1.104.7", "published_at": null}],
            "source": "github+pkgs",
            "warning": "GitHub returned no matching stable releases; showing latest stable from pkgs.tailscale.com.",
            "fetched_at": 100,
        })
    );
}

#[test]
fn versions_cache_keeps_unexpired_result_after_failed_forced_refresh_and_refetches_after_expiry() {
    let manager = TailscaleManager::new();
    let catalog = |version: &str| merge_version_catalog(Ok(version.into()), Ok(vec![]), 100);
    let first = manager
        .versions_catalog_with(false, || catalog("1.104.6"))
        .unwrap();
    let original_stamp = manager.versions_cache.lock().unwrap().as_ref().unwrap().1;
    assert_eq!(
        manager.versions_catalog_with(true, || Err("offline".into())),
        Err("offline".into())
    );
    assert_eq!(
        manager.versions_catalog_with(false, || panic!("unexpired cache must be used")),
        Ok(first)
    );
    {
        let mut cache = manager.versions_cache.lock().unwrap();
        let (_, fetched) = cache.as_mut().unwrap();
        assert_eq!(*fetched, original_stamp);
        *fetched = Instant::now() - VERSIONS_CACHE_TTL;
    }
    assert_eq!(
        manager.versions_catalog_with(false, || catalog("1.104.7")),
        catalog("1.104.7")
    );
    assert_eq!(
        manager.versions_catalog_with(false, || panic!("refetched catalog must be cached")),
        catalog("1.104.7")
    );
}

#[test]
fn bounded_response_rejects_one_extra_byte_and_non_utf8() {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(2)))
        .build();
    let agent: ureq::Agent = agent.into();
    for (response, expected) in [
        (&b"abc"[..], Ok("abc")),
        (&b"abcd"[..], Err("response exceeded 3-byte limit")),
        (&b"ab\xff"[..], Err("invalid UTF-8 response:")),
    ] {
        let mut wire = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        wire.extend_from_slice(response);
        let (url, server) = serve_http_once(wire);
        let body = agent.get(url).call().unwrap();
        let result = read_bounded_string(body, 3);
        server.join().unwrap();
        match expected {
            Ok(text) => assert_eq!(result.unwrap(), text),
            Err(prefix) => assert!(result.unwrap_err().starts_with(prefix)),
        }
    }
}

#[test]
fn fetch_versions_and_official_sha256_work_over_local_http() {
    let (pkgs_url, pkgs_srv) = serve_http_once(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"TarballsVersion\":\"1.104.7\",\"Tarballs\":{\"arm64\":\"tailscale_1.104.7_arm64.tgz\"}}",
    );
    let (gh_url, gh_srv) = serve_http_once(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n[{\"tag_name\":\"v1.104.7\",\"draft\":false,\"prerelease\":false,\"published_at\":\"2026-11-12T22:56:51Z\"},{\"tag_name\":\"v1.104.6\",\"draft\":false,\"prerelease\":false,\"published_at\":\"2026-11-11T00:29:49Z\"}]",
    );
    let catalog = fetch_versions_from_urls(&pkgs_url, &gh_url).unwrap();
    let pkgs_req = pkgs_srv.join().unwrap();
    let gh_req = gh_srv.join().unwrap();
    assert!(pkgs_req.contains("open-u60-tailscale/"), "{pkgs_req}");
    assert!(gh_req.contains("open-u60-tailscale/"), "{gh_req}");
    assert_eq!(catalog.latest, "1.104.7");
    assert_eq!(catalog.versions.len(), 2);
    assert_eq!(catalog.versions[1].version, "1.104.6");

    let digest = "d6bed2720310b328b861f943d7b4016c5358a9bad60575eb51e8143b79068484";
    let (sha_url, sha_srv) = serve_http_once(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nd6bed2720310b328b861f943d7b4016c5358a9bad60575eb51e8143b79068484\n",
    );
    assert_eq!(fetch_official_sha256_at(&sha_url).unwrap(), digest);
    assert!(sha_srv.join().unwrap().contains("open-u60-tailscale/"));
}
