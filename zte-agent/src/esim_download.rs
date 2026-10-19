//! Profile download: the SGP.22 procedure (activation code → mutual authentication → preview →
//! prepare → bound profile package → install) over the `euicc` crate's card commands (ES10b) and
//! server calls (ES9+).
//!
//! Progress is reported with lpac's step names; on the same card and server the requests were
//! byte-for-byte lpac's. The user's decisions arrive on a control channel; each maps to its
//! SGP.22 cancel reason (lpac sent endUserRejection for all of them):
//! decline → endUserRejection, preview not answered → timeout, Cancel → postponed (the operator
//! keeps the QR code usable). Once the package is being installed, nothing cancels it.

use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError};
use std::time::{Duration, Instant};

use euicc::es9p::{self, Http};
use euicc::rsp::CancelSessionReason;
use euicc::{Apdu, Euicc};
use serde_json::{json, Value};

/// What the user (or the agent's preview timer) decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DownloadCtl {
    Accept,
    Decline,
    Cancel,
    PreviewTimeout,
}

/// An HTTP transport whose per-call timeout the procedure sets before each ES9+ call.
pub(crate) trait Es9pTransport: Http {
    fn set_timeout(&mut self, timeout: Duration);
}

impl Es9pTransport for crate::esim_native::Es9pHttp {
    fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
}

/// ES9+ call limits (each also capped by the download's deadline).
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const BPP_TIMEOUT: Duration = Duration::from_secs(120);
const CANCEL_TIMEOUT: Duration = Duration::from_secs(10);
/// Installing needs this much time left, or the session is cancelled before anything is written
/// (the tested install took 16 s for about 36 KB).
const INSTALL_MIN: Duration = Duration::from_secs(45);

/// A parsed SGP.22 activation code: `LPA:1$<SM-DP+ address>$<matching ID>[$<OID>[$<1 if a
/// confirmation code is required>[$<CI public key indicator>]]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivationCode {
    pub smdp: String,
    pub matching_id: String,
    pub confirmation_required: bool,
}

pub(crate) fn parse_activation_code(code: &str) -> Result<ActivationCode, &'static str> {
    let fields: Vec<&str> = code.trim().split('$').collect();
    if fields.first().map(|f| f.eq_ignore_ascii_case("LPA:1")) != Some(true) {
        return Err("activation code must start with LPA:1$");
    }
    if fields.len() < 3 {
        return Err("activation code has the wrong number of fields");
    }
    let smdp = fields[1].trim();
    if smdp.is_empty() || smdp.len() > 255 || !smdp.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':')) {
        return Err("activation code has an invalid server address");
    }
    Ok(ActivationCode {
        smdp: smdp.to_string(),
        matching_id: fields[2].to_string(),
        confirmation_required: fields.get(4) == Some(&"1"),
    })
}

/// Why a download stopped: the message, the reason to cancel the card session with (none when
/// there is nothing to cancel), and whether the server must be told too.
struct Stop {
    message: String,
    reason: Option<CancelSessionReason>,
    notify_server: bool,
}

impl Stop {
    fn new(message: String, reason: Option<CancelSessionReason>) -> Self {
        Stop { message, reason, notify_server: true }
    }

    /// Malformed data: the session can't continue (undefinedReason).
    fn fail(step: &str, detail: impl std::fmt::Display) -> Self {
        Stop::new(format!("{step}: {detail}"), Some(CancelSessionReason::Undefined))
    }

    /// A card error: a transport failure (the modem did not answer) is worth retrying later.
    fn card(step: &str, e: euicc::Error) -> Self {
        let reason = match e {
            euicc::Error::Transport(_) => CancelSessionReason::Timeout,
            _ => CancelSessionReason::Undefined,
        };
        Stop::new(format!("{step}: {e}"), Some(reason))
    }

    /// An ES9+ failure. Network and HTTP failures are retryable (timeout); when the server
    /// itself reported a failure it has ended the procedure, so only the card is cancelled.
    fn server(step: &str, e: &es9p::Es9pStatus) -> Self {
        let message = crate::esim_native::es9p_error(step, e);
        if e.transport_error.is_some() || e.message == "HTTP status code error" {
            Stop::new(message, Some(CancelSessionReason::Timeout))
        } else if e.subject_code != "0.0.0" {
            Stop { message, reason: Some(CancelSessionReason::Undefined), notify_server: false }
        } else {
            Stop::new(message, Some(CancelSessionReason::Undefined))
        }
    }

    fn user(ctl: DownloadCtl) -> Self {
        let (message, reason) = match ctl {
            DownloadCtl::Decline => ("cancelled: declined", CancelSessionReason::EndUserRejection),
            DownloadCtl::PreviewTimeout => ("cancelled: not confirmed in time", CancelSessionReason::Timeout),
            _ => ("cancelled", CancelSessionReason::Postponed),
        };
        Stop::new(message.into(), Some(reason))
    }
}

/// smdpSigned2's ccRequiredFlag: the operator wants a confirmation code even when the activation
/// code did not say so.
fn confirmation_required_by_server(b64_smdp_signed2: &str) -> bool {
    let der = euicc::b64::decode(b64_smdp_signed2);
    euicc::der::find(&der, 0x30)
        .and_then(|s| euicc::der::find(s.value, 0x01))
        .is_some_and(|flag| flag.value.iter().any(|b| *b != 0))
}

/// A pending Cancel, if the user sent one (other messages outside the preview are ignored).
fn cancelled(ctl: &Receiver<DownloadCtl>) -> bool {
    loop {
        match ctl.try_recv() {
            Ok(DownloadCtl::Cancel) => return true,
            Ok(_) => continue,
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return false,
        }
    }
}

fn left(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn metadata_json(m: &euicc::es8p::ProfileMetadata) -> Value {
    json!({
        "iccid": m.iccid,
        "serviceProviderName": m.service_provider_name,
        "profileName": m.profile_name,
        "iconType": m.icon_type,
        "icon": m.icon,
        "profileClass": m.profile_class,
    })
}

#[allow(clippy::too_many_arguments)]
/// Runs one download on an open card session. `progress(step, data)` gets lpac's steps; the
/// result data carries the new profile's `iccid` and the install receipt's `seqNumber`.
pub(crate) fn download<T: Apdu, H: Es9pTransport>(
    card: &mut Euicc<T>,
    http: &mut H,
    code: &ActivationCode,
    confirmation_code: Option<&str>,
    preview: bool,
    ctl: &Receiver<DownloadCtl>,
    progress: &mut dyn FnMut(&str, Value),
    deadline: Instant,
) -> Result<Value, String> {
    // Card and server transaction ids, once the card has opened its session.
    let mut session: Option<(Vec<u8>, String)> = None;
    let outcome = steps(card, http, code, confirmation_code, preview, ctl, progress, deadline, &mut session);
    match outcome {
        Ok(data) => Ok(data),
        Err(mut stop) => {
            // A Cancel the user pressed while the failing step ran still means "postpone".
            if stop.reason.is_some() && cancelled(ctl) {
                stop = Stop::user(DownloadCtl::Cancel);
            }
            if let (Some((card_tid, server_tid)), Some(reason)) = (session, stop.reason) {
                progress("es10b_cancel_session", json!(code.smdp));
                match card.cancel_session(&card_tid, reason) {
                    Ok(b64) if stop.notify_server => {
                        progress("es9p_cancel_session", json!(code.smdp));
                        http.set_timeout(CANCEL_TIMEOUT);
                        if let Err(e) = es9p::cancel_session(http, &code.smdp, &server_tid, &b64) {
                            eprintln!("[esim] {}", crate::esim_native::es9p_error("es9p_cancel_session", &e));
                        }
                    }
                    Ok(_) => {}
                    Err(e) => eprintln!("[esim] es10b_cancel_session: {e}"),
                }
            }
            Err(stop.message)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn steps<T: Apdu, H: Es9pTransport>(
    card: &mut Euicc<T>,
    http: &mut H,
    code: &ActivationCode,
    confirmation_code: Option<&str>,
    preview: bool,
    ctl: &Receiver<DownloadCtl>,
    progress: &mut dyn FnMut(&str, Value),
    deadline: Instant,
    session: &mut Option<(Vec<u8>, String)>,
) -> Result<Value, Stop> {
    let es9p_fail = Stop::server;
    if code.confirmation_required && confirmation_code.is_none_or(str::is_empty) {
        return Err(Stop::new("this activation code needs a confirmation code".into(), None));
    }

    progress("es10b_get_euicc_challenge_and_info", Value::Null);
    let challenge = card.get_euicc_challenge().map_err(|e| Stop::card("es10b_get_euicc_challenge_and_info", e))?;
    let info1 = card.get_euicc_info1().map_err(|e| Stop::card("es10b_get_euicc_challenge_and_info", e))?;
    if cancelled(ctl) {
        return Err(Stop::user(DownloadCtl::Cancel));
    }

    progress("es9p_initiate_authentication", json!(code.smdp));
    http.set_timeout(AUTH_TIMEOUT.min(left(deadline)));
    let (server_tid, auth) = es9p::initiate_authentication(http, &code.smdp, &challenge, &info1)
        .map_err(|e| es9p_fail("es9p_initiate_authentication", &e))?;
    if cancelled(ctl) {
        return Err(Stop::user(DownloadCtl::Cancel));
    }

    progress("es10b_authenticate_server", Value::Null);
    let (card_tid, auth_response) = card
        .authenticate_server(&auth, Some(&code.matching_id), None)
        .map_err(|e| Stop::card("es10b_authenticate_server", e))?;
    *session = Some((card_tid.clone(), server_tid.clone()));
    if cancelled(ctl) {
        return Err(Stop::user(DownloadCtl::Cancel));
    }

    progress("es9p_authenticate_client", Value::Null);
    http.set_timeout(AUTH_TIMEOUT.min(left(deadline)));
    let prepare = es9p::authenticate_client(http, &code.smdp, &server_tid, &auth_response)
        .map_err(|e| es9p_fail("es9p_authenticate_client", &e))?;
    let metadata = euicc::es8p::parse_metadata(&prepare.b64_profile_metadata)
        .map_err(|e| Stop::fail("es8p_metadata_parse", e))?;
    progress("es8p_metadata_parse", metadata_json(&metadata));
    if confirmation_code.is_none_or(str::is_empty) && confirmation_required_by_server(&prepare.b64_smdp_signed2) {
        // Stop before the preview; postponed keeps the order open for a retry with the code.
        return Err(Stop::new(
            "the operator requires a confirmation code for this profile".into(),
            Some(CancelSessionReason::Postponed),
        ));
    }

    if preview {
        progress("preview", json!("y/n"));
        match ctl.recv_timeout(left(deadline)) {
            Ok(DownloadCtl::Accept) => {}
            Ok(decision) => return Err(Stop::user(decision)),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                return Err(Stop::user(DownloadCtl::PreviewTimeout));
            }
        }
    } else if cancelled(ctl) {
        return Err(Stop::user(DownloadCtl::Cancel));
    }

    progress("es10b_prepare_download", Value::Null);
    let prepared = card
        .prepare_download(&prepare, &card_tid, confirmation_code)
        .map_err(|e| Stop::card("es10b_prepare_download", e))?;
    if cancelled(ctl) {
        return Err(Stop::user(DownloadCtl::Cancel));
    }

    progress("es9p_get_bound_profile_package", Value::Null);
    http.set_timeout(BPP_TIMEOUT.min(left(deadline)));
    let package = es9p::get_bound_profile_package(http, &code.smdp, &server_tid, &prepared)
        .map_err(|e| es9p_fail("es9p_get_bound_profile_package", &e))?;
    if cancelled(ctl) {
        return Err(Stop::user(DownloadCtl::Cancel));
    }
    if left(deadline) < INSTALL_MIN {
        return Err(Stop::new("not enough time left to install".into(), Some(CancelSessionReason::Timeout)));
    }

    // From here the install runs to the end. The agent refuses Cancel once this step is shown;
    // one accepted just before is already in the channel and is honoured here.
    progress("es10b_load_bound_profile_package", Value::Null);
    if cancelled(ctl) {
        return Err(Stop::user(DownloadCtl::Cancel));
    }
    let result = card.load_bound_profile_package(&package).map_err(|e| {
        Stop::new(format!("es10b_load_bound_profile_package: {e}"), Some(CancelSessionReason::LoadBppExecutionError))
    })?;
    if !result.is_success() {
        // The card ended the session itself; its installation result goes out as a receipt.
        *session = None;
        let command = euicc::download::bpp_command_id_str(result.bpp_command_id.unwrap_or(0xFF));
        let reason = euicc::download::error_reason_str(result.error_reason.unwrap_or(0xFF));
        return Err(Stop::new(format!("es10b_load_bound_profile_package: {command}, {reason}"), None));
    }
    Ok(json!({"iccid": result.iccid, "seqNumber": result.seq_number}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use euicc::der::Node;
    use std::sync::mpsc;

    fn p(tag: u16, v: &[u8]) -> Node {
        Node::Prim(tag, v.to_vec())
    }
    fn c(tag: u16, v: Vec<Node>) -> Node {
        Node::Cons(tag, v)
    }
    const TID: [u8; 16] = [0x11; 16];

    /// A card that answers each ES10b request; `log` records request tags and cancel reasons.
    #[derive(Default)]
    struct Card {
        pending: Vec<u8>,
        log: Vec<String>,
        install_error: bool,
        install_transport_error: bool,
    }

    impl Apdu for &mut Card {
        fn open_channel(&mut self, _aid: &[u8]) -> euicc::Result<u8> {
            Ok(1)
        }
        fn close_channel(&mut self, _channel: u8) {}
        fn transmit(&mut self, apdu: &[u8]) -> euicc::Result<Vec<u8>> {
            self.pending.extend_from_slice(&apdu[5..]);
            if apdu[2] == 0x11 {
                return Ok(vec![0x90, 0]);
            }
            let req = std::mem::take(&mut self.pending);
            let tag = if req[0] & 0x1F == 0x1F { u16::from_be_bytes([req[0], req[1]]) } else { u16::from(req[0]) };
            let mut out = match tag {
                0xBF2E => c(0xBF2E, vec![p(0x80, &[0xAB; 16])]).encode(),
                0xBF20 => c(0xBF20, vec![p(0x82, &[2, 2, 0])]).encode(),
                0xBF38 => c(0xBF38, vec![c(0xA0, vec![p(0x80, b"signed")])]).encode(),
                0xBF21 => c(0xBF21, vec![c(0xA0, vec![p(0x80, b"signed")])]).encode(),
                0xBF41 => {
                    self.log.push(format!("cancel {}", req[req.len() - 1]));
                    c(0xBF41, vec![c(0xA0, vec![p(0x80, &TID)])]).encode()
                }
                0x86 if self.install_transport_error => {
                    return Err(euicc::Error::Transport("modem did not answer in time".into()))
                }
                0x86 => {
                    let fin = if self.install_error {
                        c(0xA1, vec![p(0x80, &[5]), p(0x81, &[10])])
                    } else {
                        c(0xA0, vec![])
                    };
                    let meta = c(
                        0xBF2F,
                        vec![p(0x80, &[7]), p(0x81, &[0x07, 0x80]), p(0x5A, &[0x98, 0x36, 0, 0, 0, 0, 0, 0, 0, 0xF4])],
                    );
                    c(0xBF37, vec![c(0xBF27, vec![p(0x80, &TID), meta, c(0xA2, vec![fin])])]).encode()
                }
                _ => vec![],
            };
            if tag != 0x86 && tag != 0xBF41 {
                self.log.push(format!("{tag:04X}"));
            } else if tag == 0x86 {
                self.log.push("install".into());
            }
            out.extend([0x90, 0]);
            Ok(out)
        }
    }

    /// An SM-DP+ that answers the four ES9+ calls; `calls` records them.
    #[derive(Default)]
    struct Smdp {
        calls: Vec<String>,
        refuse_matching_id: bool,
        unreachable: bool,
        bpp_unreachable: bool,
        cc_in_signed2: bool,
    }

    impl Http for Smdp {
        fn post(&mut self, url: &str, headers: &[&str], body: &[u8]) -> Result<(u32, Vec<u8>), String> {
            assert_eq!(headers, es9p::HEADERS);
            let path = url.rsplit('/').next().unwrap_or("").to_string();
            self.calls.push(path.clone());
            if self.unreachable || (self.bpp_unreachable && path == "getBoundProfilePackage") {
                return Err("client error (Connect): dns error".into());
            }
            let _: Value = serde_json::from_slice(body).expect("JSON request");
            let ok = json!({"functionExecutionStatus": {"status": "Executed-Success"}});
            let b = |n: Node| euicc::b64::encode(&n.encode());
            let resp = match path.as_str() {
                "initiateAuthentication" => json!({"header": ok, "transactionId": "1111",
                    "serverSigned1": b(c(0x30, vec![p(0x80, &TID), p(0x81, &[0xAB; 16]), p(0x83, b"smdp.example"), p(0x84, &[1; 16])])),
                    "serverSignature1": b(p(0x5F37, &[2; 64])), "euiccCiPKIdToBeUsed": b(p(0x04, &[3; 20])),
                    "serverCertificate": b(c(0x30, vec![p(0x02, &[1])]))}),
                "authenticateClient" if self.refuse_matching_id => json!({"header": {"functionExecutionStatus": {
                    "status": "Failed", "statusCodeData": {"subjectCode": "8.2.6", "reasonCode": "3.8",
                    "message": "The matchingID is not found"}}}}),
                "authenticateClient" => json!({"header": ok, "transactionId": "1111",
                    "profileMetadata": b(c(0xBF25, vec![p(0x5A, &[0x98, 0x36, 0, 0, 0, 0, 0, 0, 0, 0xF4]),
                        p(0x91, b"Travel - PHL"), p(0x92, b"Klook_app")])),
                    "smdpSigned2": b(c(0x30, vec![p(0x80, &TID), p(0x01, &[if self.cc_in_signed2 { 0xFF } else { 0 }])])),
                    "smdpSignature2": b(p(0x5F37, &[4; 64])),
                    "smdpCertificate": b(c(0x30, vec![p(0x02, &[1])]))}),
                "getBoundProfilePackage" => json!({"header": ok, "transactionId": "1111",
                    "boundProfilePackage": b(c(0xBF36, vec![c(0xBF23, vec![p(0x80, &[0])]),
                        c(0xA0, vec![p(0x87, &[0; 300])]), c(0xA1, vec![p(0x88, &[0; 10])]), c(0xA3, vec![p(0x86, &[0; 500])])]))}),
                "cancelSession" => json!({"header": ok}),
                _ => return Ok((404, vec![])),
            };
            Ok((200, resp.to_string().into_bytes()))
        }
    }

    impl Es9pTransport for Smdp {
        fn set_timeout(&mut self, _timeout: Duration) {}
    }

    struct Run {
        steps: Vec<String>,
        result: Result<Value, String>,
        card: Vec<String>,
        server: Vec<String>,
    }

    /// `at_preview` is what the user answers when the preview is shown; `queued` arrives before
    /// the download starts.
    fn run(card: Card, smdp: Smdp, preview: bool, at_preview: Option<DownloadCtl>, queued: &[DownloadCtl], code: &str) -> Run {
        let (tx, rx) = mpsc::channel();
        for d in queued {
            tx.send(*d).unwrap();
        }
        let mut card = card;
        let mut smdp = smdp;
        let mut steps = Vec::new();
        let code = parse_activation_code(code).unwrap();
        let result = {
            let mut e = Euicc::open(&mut card).unwrap();
            let mut progress = |s: &str, _: Value| {
                if s == "preview" {
                    if let Some(d) = at_preview {
                        tx.send(d).unwrap();
                    }
                }
                steps.push(s.to_string());
            };
            download(&mut e, &mut smdp, &code, None, preview, &rx, &mut progress, Instant::now() + Duration::from_secs(300))
        };
        Run { steps, result, card: card.log, server: smdp.calls }
    }

    const CODE: &str = "LPA:1$smdp.example$ABC-123";

    #[test]
    fn a_confirmed_download_installs_and_reports_the_new_profile() {
        let r = run(Card::default(), Smdp::default(), true, Some(DownloadCtl::Accept), &[], CODE);
        let data = r.result.unwrap();
        assert_eq!(data["iccid"], "8963000000000000004");
        assert_eq!(data["seqNumber"], 7);
        assert_eq!(
            r.steps,
            [
                "es10b_get_euicc_challenge_and_info",
                "es9p_initiate_authentication",
                "es10b_authenticate_server",
                "es9p_authenticate_client",
                "es8p_metadata_parse",
                "preview",
                "es10b_prepare_download",
                "es9p_get_bound_profile_package",
                "es10b_load_bound_profile_package",
            ]
        );
        assert_eq!(r.server, ["initiateAuthentication", "authenticateClient", "getBoundProfilePackage"]);
        assert!(r.card.contains(&"install".to_string()));
    }

    #[test]
    fn each_decision_cancels_with_its_own_reason() {
        for (decision, reason, text) in [
            (DownloadCtl::Decline, 0, "cancelled: declined"),
            (DownloadCtl::PreviewTimeout, 2, "cancelled: not confirmed in time"),
            (DownloadCtl::Cancel, 1, "cancelled"),
        ] {
            let r = run(Card::default(), Smdp::default(), true, Some(decision), &[], CODE);
            assert_eq!(r.result.unwrap_err(), text);
            assert!(r.card.contains(&format!("cancel {reason}")), "{decision:?}: {:?}", r.card);
            assert_eq!(r.server.last().map(String::as_str), Some("cancelSession"));
            assert!(!r.card.contains(&"install".to_string()));
        }
    }

    #[test]
    fn a_cancel_before_the_card_session_opens_needs_no_card_cancel() {
        // Cancel arrives before the first check (right after the card challenge): no server
        // call is made and there is no card session to cancel.
        let r = run(Card::default(), Smdp::default(), true, None, &[DownloadCtl::Cancel], CODE);
        assert_eq!(r.result.unwrap_err(), "cancelled");
        assert!(r.server.is_empty());
        assert!(!r.card.iter().any(|l| l.starts_with("cancel")));
    }

    #[test]
    fn a_refused_code_cancels_only_the_card() {
        let smdp = Smdp { refuse_matching_id: true, ..Smdp::default() };
        let r = run(Card::default(), smdp, true, None, &[], CODE);
        assert_eq!(r.result.unwrap_err(), "es9p_authenticate_client: The matchingID is not found");
        assert!(r.card.contains(&"cancel 127".to_string()), "the card's context is discarded");
        assert_eq!(r.server, ["initiateAuthentication", "authenticateClient"], "the server already ended the procedure");
    }

    #[test]
    fn a_confirmation_code_required_by_the_server_stops_before_the_preview() {
        let smdp = Smdp { cc_in_signed2: true, ..Smdp::default() };
        let r = run(Card::default(), smdp, true, Some(DownloadCtl::Accept), &[], CODE);
        assert_eq!(r.result.unwrap_err(), "the operator requires a confirmation code for this profile");
        assert!(!r.steps.contains(&"preview".to_string()));
        assert!(r.card.contains(&"cancel 1".to_string()), "postponed keeps the order open");
    }

    #[test]
    fn a_network_failure_after_the_card_session_cancels_with_timeout() {
        let smdp = Smdp { bpp_unreachable: true, ..Smdp::default() };
        let r = run(Card::default(), smdp, true, Some(DownloadCtl::Accept), &[], CODE);
        assert!(r.result.unwrap_err().starts_with("es9p_get_bound_profile_package: HTTP transport failed"));
        assert!(r.card.contains(&"cancel 2".to_string()), "retryable: timeout");
    }

    #[test]
    fn an_unreachable_server_fails_without_a_card_session() {
        let smdp = Smdp { unreachable: true, ..Smdp::default() };
        let r = run(Card::default(), smdp, true, None, &[], CODE);
        assert_eq!(
            r.result.unwrap_err(),
            "es9p_initiate_authentication: HTTP transport failed (client error (Connect): dns error)"
        );
        assert!(!r.card.iter().any(|l| l.starts_with("cancel")));
    }

    #[test]
    fn install_errors_are_reported_and_not_cancelled() {
        let r = run(Card { install_error: true, ..Card::default() }, Smdp::default(), true, Some(DownloadCtl::Accept), &[], CODE);
        let e = r.result.unwrap_err();
        assert!(e.starts_with("es10b_load_bound_profile_package: "), "{e}");
        assert!(!r.card.iter().any(|l| l.starts_with("cancel")), "the card ended the session itself");

        let r = run(
            Card { install_transport_error: true, ..Card::default() },
            Smdp::default(),
            true,
            Some(DownloadCtl::Accept),
            &[],
            CODE,
        );
        assert!(r.result.unwrap_err().contains("modem did not answer"));
        assert!(r.card.contains(&"cancel 5".to_string()), "loadBppExecutionError");
    }

    #[test]
    fn without_preview_it_runs_straight_through() {
        let r = run(Card::default(), Smdp::default(), false, None, &[], CODE);
        assert!(r.result.is_ok());
        assert!(!r.steps.contains(&"preview".to_string()));
    }

    #[test]
    fn activation_codes() {
        let a = parse_activation_code("LPA:1$rsp.example.com$MATCH-1").unwrap();
        assert_eq!((a.smdp.as_str(), a.matching_id.as_str(), a.confirmation_required), ("rsp.example.com", "MATCH-1", false));
        let a = parse_activation_code("LPA:1$rsp.example.com$M$1.3.6.1.4.1.31746$1").unwrap();
        assert!(a.confirmation_required);
        let a = parse_activation_code("LPA:1$rsp.example.com$M$$1$CIKEY").unwrap();
        assert!(a.confirmation_required, "a sixth field (CI public key indicator) is ignored");
        assert!(parse_activation_code("LPA:1$rsp.example.com$").is_ok(), "an empty matching ID is allowed");
        assert!(parse_activation_code("LPA:2$x$y").is_err());
        assert!(parse_activation_code("LPA:1$evil.example/path$y").is_err());
        assert!(parse_activation_code("LPA:1$a$b$c$d$e$f").is_ok(), "extra parameters are ignored (SGP.22 4.1)");
        let r = run(Card::default(), Smdp::default(), true, None, &[], "LPA:1$smdp.example$M$$1");
        assert_eq!(r.result.unwrap_err(), "this activation code needs a confirmation code");
        assert!(r.steps.is_empty(), "nothing is sent without the confirmation code");
    }
}
