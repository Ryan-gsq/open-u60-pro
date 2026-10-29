//! Authenticated, same-origin Zashboard and its restricted Mihomo bridge.
//! The core secret never goes into HTML, URLs, JS storage or browser headers.

use std::path::Component;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header::*, Method, StatusCode};
use axum::response::Response;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{job, session, CspNonce};
use crate::auth::SessionCheck;
use crate::httpd::{api, gate::Lane, Ctx};
use crate::mihomo::{API, CONTROLLER, DASHBOARD};

mod dashboard;

pub fn is_path(path: &str) -> bool {
    path == DASHBOARD.trim_end_matches('/') || path.starts_with(DASHBOARD) || path == API || path.starts_with(&format!("{API}/"))
}

fn plain(status: u16, message: &'static str) -> Response {
    let mut r = Response::new(Body::from(message));
    *r.status_mut() = StatusCode::from_u16(status).unwrap();
    r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    r.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

pub fn dashboard_link() -> String {
    // The pinned dashboard adapter selects this browser's same-origin bridge
    // before its router mounts. No setup query or credentials are needed.
    format!("{DASHBOARD}#/proxies")
}

pub async fn dispatch(ctx: Ctx, mut req: Request) -> Response {
    let nonce = CspNonce::of(&req);
    let path = req.uri().path().to_owned();
    let Some(p) = session::find_session(&ctx.app.auth, req.headers()) else {
        let (parts, body) = req.into_parts();
        let response = if path.starts_with(DASHBOARD) && matches!(parts.method, Method::GET | Method::HEAD) {
            session::login_redirect(&Method::GET, "/ui/router/mihomo", None)
        } else {
            plain(401, "Sign in to the router first")
        };
        return session::reply_unread(&parts.headers, body, response).await;
    };
    if !ctx.app.mihomo.running() {
        return plain(409, "Mihomo is off");
    }
    if path == DASHBOARD.trim_end_matches('/') {
        return session::see_other(DASHBOARD);
    }
    if let Some(file) = path.strip_prefix(DASHBOARD) {
        if !matches!(*req.method(), Method::GET | Method::HEAD) {
            return plain(405, "GET only");
        }
        let file = if file.is_empty() { "index.html" } else { file };
        // Service-worker caches would survive logout/off and are unnecessary
        // for a device-local panel whose resources are already offline.
        if file == "sw.js" {
            return plain(404, "Service worker disabled");
        }
        if file == "registerSW.js" {
            let mut r = Response::new(Body::from("/* Device-local dashboard: service worker intentionally disabled. */"));
            r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/javascript; charset=utf-8"));
            return r;
        }
        let relative = std::path::Path::new(file);
        if file.contains(['%', '\\']) || relative.components().any(|c| !matches!(c, Component::Normal(_))) {
            return plain(404, "Not found");
        }
        let root = ctx.app.mihomo.dashboard_root();
        let file = file.to_owned();
        let head = req.method() == Method::HEAD;
        return job::run(
            &ctx,
            Lane::General,
            &nonce,
            "/ui/router/mihomo",
            Box::new(move |_| {
                let full = root.join(&file);
                let Ok(canonical) = full.canonicalize() else {
                    return plain(404, "Dashboard file not found");
                };
                let Ok(root) = root.canonicalize() else {
                    return plain(404, "Dashboard not installed");
                };
                if !canonical.starts_with(root) {
                    return plain(404, "Not found");
                }
                let Ok(data) = std::fs::read(canonical) else {
                    return plain(404, "Not found");
                };
                if data.len() > 8 * 1024 * 1024 {
                    return plain(413, "Dashboard file too large");
                }
                let data = match dashboard::asset(&file, data) {
                    Ok(data) => data,
                    Err(e) => return plain(503, e),
                };
                let mime = match std::path::Path::new(&file).extension().and_then(|e| e.to_str()).unwrap_or("") {
                    "html" => "text/html; charset=utf-8",
                    "js" => "text/javascript; charset=utf-8",
                    "css" => "text/css; charset=utf-8",
                    "svg" => "image/svg+xml",
                    "png" => "image/png",
                    "ico" => "image/x-icon",
                    "json" | "webmanifest" => "application/json",
                    "woff2" => "font/woff2",
                    "woff" => "font/woff",
                    _ => "application/octet-stream",
                };
                let mut r = Response::new(if head { Body::empty() } else { Body::from(data) });
                r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static(mime));
                r.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
                r
            }),
        )
        .await;
    }
    let endpoint = path.strip_prefix(API).unwrap_or("");
    if !allowed(req.method(), endpoint) {
        return plain(403, "This core operation is managed by the router");
    }
    let h = api::req_headers(req.headers());
    // Same-site is not enough: the vendor UI on port 80 is a different origin.
    // Require an exact Origin or Referer for API reads as well as writes.
    if !same_origin(&h) {
        return plain(403, "Same-origin dashboard requests only");
    }
    let Some(secret) = ctx.app.mihomo.secret() else {
        return plain(409, "Mihomo is off");
    };
    let query = bridge_query(req.uri().query());
    if req.headers().get(UPGRADE).is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket")) {
        if req.method() != Method::GET || !["/traffic", "/memory", "/connections", "/logs"].contains(&endpoint) {
            return plain(403, "WebSocket endpoint not allowed");
        }
        return websocket(&ctx, &mut req, &format!("{endpoint}{query}"), &secret, p.id).await;
    }
    let method = req.method().clone();
    let (parts, body) = req.into_parts();
    let bytes = match api::read_capped(&parts.headers, body, 64 * 1024, ctx.body_wait).await {
        Ok(v) => v,
        Err(_) => return plain(413, "Dashboard request too large"),
    };
    if method == Method::PATCH && endpoint == "/configs" && !safe_patch(&bytes) {
        return plain(403, "Only mode and log-level can be changed here");
    }
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap()
    });
    let mut request = client.request(method, format!("http://{CONTROLLER}{endpoint}{query}")).bearer_auth(secret).body(bytes);
    if let Some(ct) = parts.headers.get(CONTENT_TYPE) {
        request = request.header(CONTENT_TYPE, ct);
    }
    let Ok(response) = request.send().await else {
        return plain(502, "Mihomo did not answer");
    };
    let status = response.status();
    let ct = response.headers().get(CONTENT_TYPE).cloned();
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            return plain(502, "Mihomo response was interrupted");
        };
        if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
            return plain(502, "Mihomo response too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    // /configs includes the core secret. A dashboard needs neither that key
    // nor listening addresses; never reflect them back to the browser.
    if endpoint == "/configs" && status.is_success() {
        let Some(redacted) = dashboard_config(&bytes) else { return plain(502, "Invalid Mihomo configuration response"); };
        bytes = redacted;
    }
    let mut r = Response::new(Body::from(bytes));
    *r.status_mut() = status;
    if let Some(ct) = ct {
        r.headers_mut().insert(CONTENT_TYPE, ct);
    }
    r.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn dashboard_config(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let object = value.as_object_mut()?;
    for key in ["secret", "external-controller", "external-controller-tls", "external-ui", "authentication", "listeners"] {
        object.remove(key);
    }
    serde_json::to_vec(&value).ok()
}

fn same_origin(h: &crate::httpd::guard::ReqHeaders<'_>) -> bool {
    use crate::httpd::guard::{self, OriginVerdict};
    !guard::fetch_site_foreign(h)
        && match guard::origin_verdict(h) {
            OriginVerdict::Same => true,
            OriginVerdict::Absent => guard::referer_verdict(h) == OriginVerdict::Same,
            OriginVerdict::Cross => false,
        }
}

fn bridge_query(query: Option<&str>) -> String {
    // Mihomo prefers a nonempty WebSocket token query to Authorization. The
    // browser has no core credential; even a stale saved token must not win.
    let parts: Vec<_> = query
        .into_iter()
        .flat_map(|s| s.split('&'))
        .filter(|part| !part.is_empty() && crate::httpd::api::percent_decode(part.split('=').next().unwrap_or("")) != "token")
        .collect();
    if parts.is_empty() { String::new() } else { format!("?{}", parts.join("&")) }
}

fn allowed(method: &Method, path: &str) -> bool {
    let decoded = crate::httpd::api::percent_decode(path);
    if decoded.contains(['%', '\\']) || decoded.chars().any(char::is_control) || decoded.split('/').any(|s| s == "." || s == "..") {
        return false;
    }
    match *method {
        Method::GET => {
            path.is_empty()
                || path == "/"
                || [
                    "/version",
                    "/configs",
                    "/rules",
                    "/proxies",
                    "/group",
                    "/providers/proxies",
                    "/providers/rules",
                    "/storage/zashboard",
                    "/connections",
                    "/traffic",
                    "/memory",
                    "/logs",
                ]
                .contains(&path)
                || path.starts_with("/proxies/")
                || path.starts_with("/group/")
                || path.starts_with("/providers/proxies/")
                || path.starts_with("/providers/rules/")
        }
        Method::PATCH => path == "/configs",
        Method::PUT => path.starts_with("/proxies/") || path.starts_with("/providers/proxies/") || path.starts_with("/providers/rules/"),
        Method::DELETE => path == "/connections" || path.starts_with("/connections/"),
        Method::POST => path == "/cache/dns/flush" || path == "/cache/fakeip/flush",
        _ => false,
    }
}

fn safe_patch(bytes: &[u8]) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else { return false };
    let Some(m) = v.as_object() else { return false };
    !m.is_empty()
        && m.iter().all(|(k, v)| match k.as_str() {
            "mode" => v.as_str().is_some_and(|s| ["rule", "global", "direct"].contains(&s)),
            "log-level" => v.as_str().is_some_and(|s| ["silent", "error", "warning", "info", "debug"].contains(&s)),
            _ => false,
        })
}

async fn websocket(ctx: &Ctx, req: &mut Request, path: &str, secret: &str, owner: crate::auth::SessionId) -> Response {
    let Some(lifetime) = req.extensions().get::<crate::httpd::ConnectionLifetime>().cloned() else {
        return plain(503, "Dashboard stream requires a live listener connection");
    };
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let Ok(permit) = SLOTS.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(8))).clone().try_acquire_owned() else {
        return plain(503, "Too many dashboard streams");
    };
    let key = match req.headers().get("sec-websocket-key").and_then(|v| v.to_str().ok()) {
        Some(k) => k,
        None => return plain(400, "Missing WebSocket key"),
    };
    let Ok(Ok(mut upstream)) = tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(CONTROLLER)).await else {
        return plain(502, "Mihomo did not answer");
    };
    let handshake = format!("GET {path} HTTP/1.1\r\nHost: {CONTROLLER}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nAuthorization: Bearer {secret}\r\n\r\n");
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        upstream.write_all(handshake.as_bytes()).await?;
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
            head.push(upstream.read_u8().await?);
        }
        Ok::<_, std::io::Error>(head)
    })
    .await;
    let Ok(Ok(head)) = result else {
        return plain(502, "Mihomo WebSocket handshake failed");
    };
    let head = String::from_utf8_lossy(&head);
    if !head.starts_with("HTTP/1.1 101 ") {
        return plain(502, "Mihomo refused the WebSocket");
    }
    let accept = head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case("sec-websocket-accept").then_some(v.trim())
    });
    let Some(accept) = accept.and_then(|v| HeaderValue::from_str(v).ok()) else {
        return plain(502, "Invalid WebSocket handshake");
    };
    let upgrade = hyper::upgrade::on(req);
    let app = Arc::clone(&ctx.app);
    tokio::spawn(lifetime.until_stopped(async move {
        let _permit = permit;
        let Ok(client) = upgrade.await else { return };
        let mut client = hyper_util::rt::TokioIo::new(client);
        let relay = tokio::io::copy_bidirectional(&mut client, &mut upstream);
        tokio::pin!(relay);
        loop {
            tokio::select! {
                _ = &mut relay => break,
                _ = tokio::time::sleep(Duration::from_secs(15)) => {
                    if !app.mihomo.running() || !matches!(app.auth.touch_session(owner), SessionCheck::Live { .. }) { break; }
                }
            }
        }
    }));
    let mut r = Response::new(Body::empty());
    *r.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    r.headers_mut().insert(CONNECTION, HeaderValue::from_static("upgrade"));
    r.headers_mut().insert(UPGRADE, HeaderValue::from_static("websocket"));
    r.headers_mut().insert("sec-websocket-accept", accept);
    r
}

/// Zashboard is a trusted, separately version-pinned SPA. Give only its
/// entry page its own CSP; do not relax the agent's nonced page policy.
pub fn secure_dashboard(resp: &mut Response) {
    resp.headers_mut().insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(
        "default-src 'self'; script-src 'self' 'sha256-ZS0vkhcl113ly98eGGUNDhkTSpJH5poUYTIXHqXmIts='; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_download_credentials_never_reach_dashboard() {
        let bytes = dashboard_config(br#"{"mode":"rule","secret":"core-key","authentication":["proxy-key"],"listeners":[{"users":[{"password":"private-download-key"}]}]}"#).unwrap();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),serde_json::json!({"mode":"rule"}));
        assert!(dashboard_config(b"[]").is_none());
    }

    #[test]
    fn dashboard_cannot_reload_core_config_or_open_listeners() {
        assert!(!allowed(&Method::PUT, "/configs"));
        assert!(!allowed(&Method::POST, "/upgrade"));
        assert!(!allowed(&Method::PUT, "/restart"));
        assert!(allowed(&Method::GET, "/storage/zashboard"));
        assert!(!allowed(&Method::PUT, "/storage/zashboard"));
        assert!(!safe_patch(br#"{"mode":"rule","external-controller":"0.0.0.0:9090"}"#));
        assert!(safe_patch(br#"{"mode":"rule"}"#));
        assert!(!allowed(&Method::GET, "/providers/proxies/../../configs"));
    }

    #[test]
    fn link_contains_no_credentials_and_points_to_same_origin_bridge() {
        assert_eq!(dashboard_link(), "/ui/mihomo/dashboard/#/proxies");
        assert!(!dashboard_link().contains('?'));
    }

    #[test]
    fn browser_token_queries_never_override_the_server_only_core_secret() {
        assert_eq!(bridge_query(Some("token=outdated&level=info&%74oken=another&limit=7")), "?level=info&limit=7");
        assert_eq!(bridge_query(Some("token=")), "");
        assert_eq!(bridge_query(None), "");
    }
}
