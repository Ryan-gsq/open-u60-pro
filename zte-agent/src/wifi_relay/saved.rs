//! Opt-in remembered upstream credentials, separate from disposable sessions.
//! Matching includes security: an open SSID cannot inherit a WPA2 credential.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

use super::{net, Network, JOURNAL};

/// A remembered network. Older stores also hold `width_mode` (the retired
/// width tuning): it is ignored, so a saved `auto` reads as keeping the
/// negotiated width, and dropped at the next write; the previous agent reads
/// a store without it as `off`.
#[derive(Serialize, Deserialize)]
struct Saved {
    ssid: String,
    security: String,
    password: String,
}

pub(super) fn key(ssid: &str, security: &str) -> String {
    let hash = Sha256::digest(format!("{security}\0{ssid}"));
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn load(root: &Path) -> Result<Vec<Saved>, String> {
    let file = match std::fs::File::open(root.join("saved-wifi.json")) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("Cannot read remembered Wi-Fi networks".into()),
    };
    let mut data = Vec::new();
    file.take(16 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "Cannot read remembered Wi-Fi networks")?;
    if data.len() > 16 * 1024 {
        return Err("Remembered Wi-Fi store is too large".into());
    }
    serde_json::from_slice(&data).map_err(|_| "Remembered Wi-Fi store is invalid".into())
}

pub(super) fn password(network: &Network) -> Result<Option<String>, String> {
    Ok(load(Path::new(JOURNAL))?
        .into_iter()
        .find(|n| n.ssid == network.ssid && n.security == network.security)
        .map(|n| n.password))
}

/// Saves the password of a successful connection the owner asked to
/// remember. An unchecked Remember never erases a previously saved credential.
pub(super) fn remember(network: &Network, password: Option<&str>) -> Result<(), String> {
    remember_at(Path::new(JOURNAL), network, password)
}

fn remember_at(root: &Path, network: &Network, password: Option<&str>) -> Result<(), String> {
    let Some(password) = password else { return Ok(()) };
    let mut saved = load(root)?;
    saved.retain(|n| n.ssid != network.ssid || n.security != network.security);
    if saved.len() >= 32 {
        return Err("At most 32 Wi-Fi networks can be saved".into());
    }
    saved.push(Saved { ssid: network.ssid.clone(), security: network.security.into(), password: password.to_owned() });
    write(root, &saved)
}

fn write(root: &Path, saved: &[Saved]) -> Result<(), String> {
    let data = serde_json::to_vec(saved).map_err(|_| "Cannot encode remembered Wi-Fi")?;
    net::write_private(&root.join("saved-wifi.json"), &data)
        .map_err(|_| "Cannot save remembered Wi-Fi".into())
}

pub(super) fn forget(id: &str) -> Result<(), String> {
    let root = Path::new(JOURNAL);
    let mut saved = load(root)?;
    let len = saved.len();
    saved.retain(|n| key(&n.ssid, &n.security) != id);
    if len == saved.len() {
        return Err("Remembered Wi-Fi not found".into());
    }
    write(root, &saved)
}

pub(super) fn annotate(status: &mut Value) {
    match load(Path::new(JOURNAL)) {
        Ok(saved) => annotate_with(status, &saved),
        Err(e) => {
            status["saved_error"] = json!(e);
        }
    }
}

fn annotate_with(status: &mut Value, saved: &[Saved]) {
    status["saved_networks"] = json!(saved
        .iter()
        .map(|n| json!({"id":key(&n.ssid,&n.security),"ssid":n.ssid,"security":n.security,"remembered":!n.password.is_empty() || n.security == "open"}))
        .collect::<Vec<_>>());
    if let Some(networks) = status["networks"].as_array_mut() {
        for network in networks {
            let entry = saved.iter().find(|n| {
                network["ssid"].as_str() == Some(&n.ssid)
                    && network["security"].as_str() == Some(&n.security)
            });
            network["remembered"] =
                json!(entry.is_some_and(|n| !n.password.is_empty() || n.security == "open"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// v6: a store with the retired `width_mode` (`auto` included) loads
    /// with its passwords, reads as keeping the negotiated width, and loses
    /// the field at the next write; an unchecked Remember stores nothing.
    #[test]
    fn a_saved_width_choice_is_ignored_and_dropped_and_passwords_stay() {
        let root = std::env::temp_dir().join(format!("u60-saved-v6-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("saved-wifi.json"), r#"[{"ssid":"Home","security":"wpa2","password":"private-password","width_mode":"auto"},{"ssid":"Cafe","security":"wpa2","password":"","width_mode":"off"}]"#).unwrap();
        let stored = load(&root).unwrap();
        assert_eq!((stored[0].password.as_str(), stored.len()), ("private-password", 2));
        let network = Network { id: "scan".into(), ssid: "Other".into(), security: "wpa2", bssid: "02:00:00:00:00:01".into(), frequency: 5260, supported: true, signal: -40 };
        remember_at(&root, &network, None).unwrap();
        assert_eq!(load(&root).unwrap().len(), 2, "an unchecked Remember stores nothing");
        remember_at(&root, &network, Some("other-password")).unwrap();
        let text = std::fs::read_to_string(root.join("saved-wifi.json")).unwrap();
        assert!(!text.contains("width_mode"), "dropped at the next write");
        assert!(text.contains("private-password") && text.contains("other-password"));
        let mut status = json!({"networks":[{"ssid":"Home","security":"wpa2"},{"ssid":"Cafe","security":"wpa2"}]});
        annotate_with(&mut status, &load(&root).unwrap());
        assert_eq!((status["networks"][0]["remembered"].as_bool(), status["networks"][1]["remembered"].as_bool()), (Some(true), Some(false)));
        assert!(!status.to_string().contains("width_mode") && !status.to_string().contains("private-password"));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn remembered_metadata_never_contains_password_or_matches_open_twin() {
        let saved = vec![Saved {
            ssid: "Hotel".into(),
            security: "wpa2".into(),
            password: "private-password".into(),
        }];
        let mut status = json!({"networks":[{"ssid":"Hotel","security":"wpa2"},{"ssid":"Hotel","security":"open"}]});
        annotate_with(&mut status, &saved);
        assert_eq!(status["networks"][0]["remembered"], true);
        assert_eq!(status["networks"][1]["remembered"], false);
        assert!(!status.to_string().contains("private-password"));
    }

    #[test]
    fn saved_credentials_survive_reload_with_private_permissions_and_can_be_forgotten() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("u60-remembered-{}", std::process::id()));
        let saved = vec![Saved {
            ssid: "Test".into(),
            security: "wpa2".into(),
            password: "qa-password".into(),
        }];
        write(&root, &saved).unwrap();
        assert_eq!(load(&root).unwrap()[0].password, "qa-password");
        assert_eq!(
            std::fs::metadata(root.join("saved-wifi.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        write(&root, &[]).unwrap();
        assert!(load(&root).unwrap().is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
