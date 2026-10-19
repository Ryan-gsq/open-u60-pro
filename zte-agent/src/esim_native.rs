//! eSIM card commands: the lpac commands the agent uses, answered with the `euicc` crate (an
//! LGPL-2.1 Rust translation of lpac's libeuicc) over the QRTR UIM transport, in-process.
//!
//! Commands, results and errors keep lpac's names and shape, which `esim.rs`'s views were
//! verified against. `supports` lists the commands `run` answers (on `esim.rs`'s card worker
//! thread); profile download runs on the download thread (`esim_download`).

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use euicc::Euicc;
use serde_json::{json, Value};

use crate::qrtr_uim::UimClient;

/// One QMI request to the modem.
const QMI_TIMEOUT: Duration = Duration::from_secs(10);
/// ES9+ HandleNotification to an operator server.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// GSMA RSP2 Root CI1, the only root SM-DP+ TLS certificates chain to on the tested card.
const GSMA_CI_PEM: &str = include_str!("../certs/gsma-rsp2-root-ci1.pem");

/// The commands `run` answers.
pub fn supports(args: &[&str]) -> bool {
    matches!(
        args,
        ["chip", "info"]
            | ["profile", "list"]
            | ["profile", "enable", _] | ["profile", "enable", _, _]
            | ["profile", "disable", _] | ["profile", "disable", _, _]
            | ["profile", "delete", _]
            | ["profile", "nickname", _] | ["profile", "nickname", _, _]
            | ["notification", "list"]
            | ["notification", "process", "-r", _]
    )
}

pub(crate) fn session(node: u32, slot: u8, deadline: Instant) -> Result<Euicc<UimClient>, String> {
    let client = UimClient::connect(node, slot, QMI_TIMEOUT, deadline).map_err(|e| format!("euicc_init: {e}"))?;
    Euicc::open(client).map_err(|e| format!("euicc_init: {e}"))
}

fn result(op: &str, code: u64) -> Result<Value, String> {
    if code == 0 {
        Ok(Value::Null)
    } else {
        Err(format!("es10c_{op}: {}", euicc::es10c::result_reason(op, code)))
    }
}

/// lpac's boolean words: 1/y/yes/on/true (any case) are true; anything else, or no flag, is false.
fn flag_true(flag: Option<&&str>) -> bool {
    flag.is_some_and(|f| matches!(f.to_ascii_lowercase().as_str(), "1" | "y" | "yes" | "on" | "true"))
}

/// Runs one command, giving up on the modem by `limit`.
pub fn run(args: &[&str], node: u32, slot: u8, limit: Duration) -> Result<Value, String> {
    let deadline = Instant::now() + limit;
    let session = || session(node, slot, deadline);
    match args {
        ["chip", "info"] => {
            let mut e = session()?;
            let eid = e.eid().map_err(|err| format!("es10c_get_eid: {err}"))?;
            // Like lpac, card details are optional: the EID alone identifies the card.
            let info = match e.euicc_info2() {
                Ok(info) => info2_json(&info),
                Err(err) => {
                    eprintln!("[esim] EUICCInfo2 unavailable: {err}");
                    Value::Null
                }
            };
            Ok(json!({"eidValue": eid, "EUICCInfo2": info}))
        }
        ["profile", "list"] => {
            let list = session()?.profiles().map_err(|e| format!("es10c_get_profiles_info: {e}"))?;
            Ok(Value::Array(list.iter().map(profile_json).collect()))
        }
        ["profile", "enable", id, rest @ ..] => {
            let code = session()?
                .enable_profile(id, flag_true(rest.first()))
                .map_err(|e| format!("es10c_enable_profile: {e}"))?;
            result("enable_profile", code)
        }
        ["profile", "disable", id, rest @ ..] => {
            let code = session()?
                .disable_profile(id, flag_true(rest.first()))
                .map_err(|e| format!("es10c_disable_profile: {e}"))?;
            result("disable_profile", code)
        }
        ["profile", "delete", id] => {
            let code = session()?.delete_profile(id).map_err(|e| format!("es10c_delete_profile: {e}"))?;
            result("delete_profile", code)
        }
        ["profile", "nickname", iccid, rest @ ..] => {
            // No name clears the nickname, as with lpac.
            let code = session()?
                .set_nickname(iccid, rest.first().copied().unwrap_or(""))
                .map_err(|e| format!("es10c_set_nickname: {e}"))?;
            result("set_nickname", code)
        }
        ["notification", "list"] => {
            let list = session()?
                .list_notifications()
                .map_err(|e| format!("es10b_list_notification: {e}"))?;
            Ok(Value::Array(list.iter().map(notification_json).collect()))
        }
        ["notification", "process", "-r", seq] => {
            let seq: u64 = seq.parse().map_err(|_| "notification sequence number must be a number".to_string())?;
            let mut e = session()?;
            let pending = e
                .retrieve_notification(seq)
                .map_err(|err| format!("es10b_retrieve_notifications_list: {err}"))?;
            let left = deadline.saturating_duration_since(Instant::now());
            handle_notification(pending.notification_address.trim(), &pending.der, left.min(HTTP_TIMEOUT))?;
            match e.remove_notification(seq) {
                Ok(0) => Ok(Value::Null),
                Ok(code) => Err(format!("es10b_remove_notification_from_list: result {code}")),
                Err(err) => Err(format!("es10b_remove_notification_from_list: {err}")),
            }
        }
        _ => Err(format!("unsupported eSIM command: {}", args.join(" "))),
    }
}

/// `zte-agent esim-native <command>` (e.g. `chip info`, `profile list`): runs one command and
/// prints its result as one JSON line in lpac's format, for diagnostics on the router. Takes the
/// agent's card lock without waiting, so it never talks to the card while the agent does. Exit
/// code 0 on success.
pub fn cli(args: &[String]) -> i32 {
    use std::os::fd::AsRawFd;
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let print = |code: i32, message: &str, data: Value| {
        println!("{}", json!({"type": "lpa", "payload": {"code": code, "message": message, "data": data}}));
    };
    if !supports(&refs) {
        print(-1, "unsupported", json!(refs.join(" ")));
        return 2;
    }
    let (node, slot) = match crate::esim::card_target() {
        Ok(target) => target,
        Err(e) => {
            print(-1, &e, Value::Null);
            return 2;
        }
    };
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(crate::esim::lock_path());
    // SAFETY: flock on a descriptor we own for the life of this function.
    let locked = lock.as_ref().is_ok_and(|f| unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0);
    if !locked {
        print(-1, "eSIM manager busy (lock held)", Value::Null);
        return 1;
    }
    match run(&refs, node, slot, Duration::from_secs(60)) {
        Ok(data) => {
            print(0, "success", data);
            0
        }
        Err(e) => {
            print(-1, &e, Value::Null);
            1
        }
    }
}

pub(crate) fn notification_json(n: &euicc::es10b::NotificationMetadata) -> Value {
    json!({
        "seqNumber": n.seq_number,
        "profileManagementOperation": n.profile_management_operation,
        // lpac's front end trims the card's address; so does this one.
        "notificationAddress": n.notification_address.as_deref().map(str::trim),
        "iccid": n.iccid,
    })
}

pub(crate) fn profile_json(p: &euicc::es10c::ProfileInfo) -> Value {
    json!({
        "iccid": p.iccid,
        "isdpAid": p.isdp_aid,
        "profileState": p.profile_state,
        "profileNickname": p.profile_nickname,
        "serviceProviderName": p.service_provider_name,
        "profileName": p.profile_name,
        "iconType": p.icon_type,
        "icon": p.icon,
        "profileClass": p.profile_class,
    })
}

pub(crate) fn info2_json(i: &euicc::info2::EuiccInfo2) -> Value {
    // Always objects, as lpac prints them (zeros / nulls when the card leaves them out).
    let r = i.ext_card_resource.clone().unwrap_or_default();
    let ext = json!({
        "installedApplication": r.installed_application,
        "freeNonVolatileMemory": r.free_non_volatile_memory,
        "freeVolatileMemory": r.free_volatile_memory,
    });
    let c = i.certification_data_object.clone().unwrap_or_default();
    let cert = json!({"platformLabel": c.platform_label, "discoveryBaseURL": c.discovery_base_url});
    json!({
        "profileVersion": i.profile_version,
        "svn": i.svn,
        "euiccFirmwareVer": i.euicc_firmware_ver,
        "extCardResource": ext,
        "uiccCapability": i.uicc_capability,
        "ts102241Version": i.ts102241_version,
        "globalplatformVersion": i.globalplatform_version,
        "rspCapability": i.rsp_capability,
        "euiccCiPKIdListForVerification": i.euicc_ci_pkid_list_for_verification,
        "euiccCiPKIdListForSigning": i.euicc_ci_pkid_list_for_signing,
        "euiccCategory": i.euicc_category,
        "forbiddenProfilePolicyRules": i.forbidden_profile_policy_rules,
        "ppVersion": i.pp_version,
        "sasAcreditationNumber": i.sas_acreditation_number,
        "certificationDataObject": cert,
    })
}

// ---------------------------------------------------------------------------
// ES9+ HandleNotification
// ---------------------------------------------------------------------------

/// The GSMA root as a rustls trust anchor. Its critical certificatePolicies extension makes
/// rustls refuse it as a certificate, so the anchor is built from its subject and key.
fn gsma_anchor() -> Result<rustls::pki_types::TrustAnchor<'static>, String> {
    let b64: String = GSMA_CI_PEM.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64.trim()).map_err(|e| format!("GSMA root: {e}"))?;
    let cert = euicc::der::parse(&der).filter(|t| t.tag == 0x30).ok_or("GSMA root: not a certificate")?;
    let tbs = euicc::der::parse(cert.value).filter(|t| t.tag == 0x30).ok_or("GSMA root: no tbsCertificate")?;
    let mut fields = euicc::der::iter(tbs.value).skip_while(|t| t.tag == 0xA0);
    // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    let subject = fields.nth(4).filter(|t| t.tag == 0x30).ok_or("GSMA root: no subject")?;
    let spki = fields.next().filter(|t| t.tag == 0x30).ok_or("GSMA root: no public key")?;
    Ok(rustls::pki_types::TrustAnchor {
        subject: subject.value.to_vec().into(),
        subject_public_key_info: spki.value.to_vec().into(),
        name_constraints: None,
    })
}

fn build_client() -> Result<reqwest::blocking::Client, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.roots.push(gsma_anchor()?);
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // HTTPS only, no redirects, no proxy: any 3xx is a failure, as with lpac's curl. No pooled
    // connections: a kept-alive socket can outlive the data session after a profile switch, and
    // idle keepalives wake the radio. Each call is a cold connection, like lpac's per-call curl.
    reqwest::blocking::Client::builder()
        .use_preconfigured_tls(tls)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .pool_max_idle_per_host(0)
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .build()
        .map_err(|e| e.to_string())
}

/// The ES9+ client, built on first use. Only a successful build is kept; a failure is retried
/// on the next call.
fn http_client() -> Result<&'static reqwest::blocking::Client, String> {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    if let Some(c) = CLIENT.get() {
        return Ok(c);
    }
    let built = build_client().map_err(|e| format!("HTTP client: {e}"))?;
    Ok(CLIENT.get_or_init(|| built))
}

/// The whole cause of a transport failure (DNS, TCP, TLS, timeout), not just "error sending
/// request".
pub(crate) fn transport_error(e: &reqwest::Error) -> String {
    let mut parts = Vec::new();
    if e.is_timeout() {
        parts.push("timed out".to_string());
    }
    let mut source = std::error::Error::source(e);
    while let Some(s) = source {
        let m = s.to_string();
        if m != "operation timed out" && !parts.contains(&m) {
            parts.push(m);
        }
        source = s.source();
    }
    if parts.is_empty() {
        e.to_string()
    } else {
        parts.join(": ")
    }
}

/// Largest ES9+ answer accepted (a bound profile package is tens of kilobytes).
const HTTP_MAX_BODY: u64 = 8 << 20;

/// `euicc::es9p::Http` over reqwest with the GSMA-only trust store; each call gets `timeout`.
pub(crate) struct Es9pHttp {
    pub timeout: Duration,
}

impl euicc::es9p::Http for Es9pHttp {
    fn post(&mut self, url: &str, headers: &[&str], body: &[u8]) -> Result<(u32, Vec<u8>), String> {
        let mut req = http_client()?.post(url).timeout(self.timeout).body(body.to_vec());
        for h in headers {
            if let Some((name, value)) = h.split_once(':') {
                req = req.header(name.trim(), value.trim());
            }
        }
        let resp = req.send().map_err(|e| transport_error(&e))?;
        let status = u32::from(resp.status().as_u16());
        let mut out = Vec::new();
        use std::io::Read;
        resp.take(HTTP_MAX_BODY + 1).read_to_end(&mut out).map_err(|e| {
            let cause = e.get_ref().and_then(|i| i.downcast_ref::<reqwest::Error>()).map_or_else(|| e.to_string(), transport_error);
            format!("reading the answer: {cause}")
        })?;
        if out.len() as u64 > HTTP_MAX_BODY {
            return Err("answer too large".into());
        }
        Ok((status, out))
    }
}

/// lpac-style error text for an ES9+ failure: `op: message`, plus the transport's cause.
pub(crate) fn es9p_error(op: &str, e: &euicc::es9p::Es9pStatus) -> String {
    if e.message.is_empty() {
        return format!("{op}: subject code {}, reason code {}", e.subject_code, e.reason_code);
    }
    match &e.transport_error {
        Some(cause) => format!("{op}: {} ({cause})", e.message),
        None if e.message == "HTTP status code error" => format!("{op}: {} ({})", e.message, e.subject_identifier),
        None => format!("{op}: {}", e.message),
    }
}

/// A server address from the card: a host name, optionally with a port.
fn valid_address(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= 255
        && address.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

/// ES9+ HandleNotification: delivers one receipt to the operator's server (SGP.22 §5.6.4).
fn handle_notification(address: &str, pending: &[u8], timeout: Duration) -> Result<(), String> {
    if !valid_address(address) {
        return Err("es9p_handle_notification: invalid server address".into());
    }
    let mut http = Es9pHttp { timeout };
    euicc::es9p::handle_notification(&mut http, address, &euicc::b64::encode(pending))
        .map_err(|e| es9p_error("es9p_handle_notification", &e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_commands_cover_everything_but_download() {
        for args in [
            &["chip", "info"][..],
            &["profile", "list"],
            &["profile", "enable", "8963000000000000001", "1"],
            &["profile", "delete", "8963000000000000001"],
            &["profile", "nickname", "8963000000000000001", "Travel"],
            &["profile", "nickname", "8963000000000000001"],
            &["notification", "list"],
            &["notification", "process", "-r", "12"],
        ] {
            assert!(supports(args), "{args:?}");
        }
        assert!(!supports(&["profile", "download", "-p", "-a", "LPA:1$x$y"]));
        assert!(!supports(&["notification", "process", "-a", "-r"]));
    }

    #[test]
    fn the_embedded_root_is_the_ci_key_the_card_trusts() {
        // SHA-1 of the public key bits = the card's euiccCiPKIdListForVerification entry.
        let anchor = gsma_anchor().unwrap();
        let spki = anchor.subject_public_key_info.as_ref();
        let bits = euicc::der::iter(spki).find(|t| t.tag == 0x03).unwrap().value;
        let key_id = sha1(&bits[1..]);
        assert_eq!(euicc::hex::encode(&key_id), "81370f5125d0b1d408d4c3b232e6d25e795bebfb");
    }

    /// Minimal SHA-1 for the key-ID check (the agent has no SHA-1 dependency).
    fn sha1(data: &[u8]) -> [u8; 20] {
        let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
        let mut msg = data.to_vec();
        let bit_len = (data.len() as u64) * 8;
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend(bit_len.to_be_bytes());
        for chunk in msg.chunks(64) {
            let mut w = [0u32; 80];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
            for (i, wi) in w.iter().enumerate() {
                let (f, k) = match i {
                    0..=19 => ((b & c) | (!b & d), 0x5A827999),
                    20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                    _ => (b ^ c ^ d, 0xCA62C1D6),
                };
                let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = t;
            }
            for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
                *x = x.wrapping_add(y);
            }
        }
        let mut out = [0u8; 20];
        for (i, v) in h.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }

    #[test]
    fn the_gsma_root_becomes_a_trust_anchor() {
        let anchor = gsma_anchor().unwrap();
        // The subject holds "GSM Association - RSP2 Root CI1"; the key is P-256.
        let subject = anchor.subject.as_ref();
        assert!(subject.windows(30).any(|w| w == b"GSM Association - RSP2 Root CI"));
        assert!(anchor.subject_public_key_info.as_ref().len() > 60);
        assert!(http_client().is_ok());
    }

    /// Network check (run with --ignored): each operator server the tested card talks to must pass
    /// TLS with only the GSMA root trusted. Any HTTP status means the chain was accepted.
    #[test]
    #[ignore]
    fn operator_servers_pass_tls_with_only_the_gsma_root() {
        let client = http_client().unwrap();
        let mut failed = Vec::new();
        for host in [
            "glo.prod.ondemandconnectivity.com",
            "sci.prod.ondemandconnectivity.com",
            "rsp-0001.linksfield.net",
            "rsp-eu.simlessly.com",
        ] {
            match client.get(format!("https://{host}/")).send() {
                Ok(r) => println!("{host}: TLS ok, HTTP {}", r.status().as_u16()),
                Err(e) => {
                    println!("{host}: FAILED {e:?}");
                    failed.push(host);
                }
            }
        }
        assert!(failed.is_empty(), "{failed:?}");
    }

    #[test]
    fn refresh_follows_lpac_boolean_words() {
        assert!(flag_true(Some(&"1")) && flag_true(Some(&"YES")) && flag_true(Some(&"on")));
        assert!(!flag_true(None), "no flag means no refresh, as in lpac");
        assert!(!flag_true(Some(&"0")) && !flag_true(Some(&"false")) && !flag_true(Some(&"maybe")));
    }

    #[test]
    fn server_addresses_are_host_names_only() {
        assert!(valid_address("rsp-0001.linksfield.net"));
        assert!(valid_address("smdp.example.com:8443"));
        assert!(!valid_address("evil.example/path?x"));
        assert!(!valid_address(""));
    }

    #[test]
    fn results_name_the_card_code() {
        assert_eq!(result("enable_profile", 0), Ok(Value::Null));
        assert_eq!(result("enable_profile", 5), Err("es10c_enable_profile: catBusy".into()));
        assert_eq!(result("delete_profile", 2), Err("es10c_delete_profile: profileNotInDisabledState".into()));
    }
}
