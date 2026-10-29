//! Opt-in remembered upstream credentials, separate from disposable sessions.
//! Matching includes security: an open SSID cannot inherit a WPA2 credential.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

use super::{net, Network, JOURNAL};

#[derive(Serialize, Deserialize)]
struct Saved {
    ssid: String,
    security: String,
    password: String,
}

fn key(ssid: &str, security: &str) -> String {
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

pub(super) fn remember(network: &Network, password: &str) -> Result<(), String> {
    let root = Path::new(JOURNAL);
    let mut saved = load(root)?;
    saved.retain(|n| n.ssid != network.ssid || n.security != network.security);
    if saved.len() >= 32 {
        return Err("At most 32 Wi-Fi networks can be remembered".into());
    }
    saved.push(Saved {
        ssid: network.ssid.clone(),
        security: network.security.into(),
        password: password.into(),
    });
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
        .map(|n| json!({"id":key(&n.ssid,&n.security),"ssid":n.ssid,"security":n.security}))
        .collect::<Vec<_>>());
    if let Some(networks) = status["networks"].as_array_mut() {
        for network in networks {
            network["remembered"] = json!(saved
                .iter()
                .any(|n| network["ssid"].as_str() == Some(&n.ssid)
                    && network["security"].as_str() == Some(&n.security)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
