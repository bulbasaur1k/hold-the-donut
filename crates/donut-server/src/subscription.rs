//! Subscription HTTP endpoint.
//!
//! Serves ready-to-import client configs for the `xhttp` inbound:
//!
//! ```text
//! GET /sub/<uuid>?format=json|xray|clash|links|happ&profile=ru|all
//! ```
//!
//! * `format=json` — XTLS-standard JSON **array** subscription (routing baked
//!   in → RU-split enforced; inbounds 10808/10809). Provider-style; the right
//!   choice for HAPP (it applies the routing inside the config it runs).
//! * `format=xray`  (default) — single full xray `client.json` (XMUX +
//!   pure-XUDP mux + geoip routing). For standalone `xray -c`, NOT a HAPP
//!   subscription (single object + :1080 inbound).
//! * `format=clash` — Clash-Meta (mihomo) YAML profile.
//! * `format=links` — base64 of the `vless://` link list (the classic
//!   subscription format v2rayN/NG understand). Connection only, no rules.
//! * `format=happ` — base64 of the `vless://` link + a `happ://routing/onadd`
//!   deeplink, so HAPP imports the connection AND applies the RU-split
//!   routing profile (rules-from-subscription, no :1080 clash).
//! * `profile=ru` (default) — RU split-tunnel; `profile=all` — proxy-all.
//!
//! `<uuid>` must be in the inbound's allowed-user set, otherwise 404 — the
//! same response a bad path gets, so the endpoint doesn't confirm UUIDs to
//! a prober. A minimal raw-HTTP/1.1 responder (like the metrics endpoint);
//! sits behind a TLS reverse proxy in production.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use donut_config::subgen::{self, RoutingProfile, XhttpParams};
use donut_core::UserAuth;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Resolved connection parameters the endpoint bakes into every served
/// config. Built once at startup from `[subscription]` + the inbound.
#[derive(Debug, Clone)]
pub struct SubServeConfig {
    /// `host:port` clients dial (public domain).
    pub public_address: String,
    /// TLS SNI / `serverName`.
    pub server_name: String,
    /// xHTTP `Host`.
    pub host: String,
    /// Secret path prefix.
    pub path: String,
    /// Framing mode.
    pub mode: String,
    /// uTLS fingerprint.
    pub fp: String,
    /// Local SOCKS the generated client opens.
    pub socks: String,
}

/// Serve the subscription endpoint on `listener` until it errors.
pub async fn serve(
    listener: TcpListener,
    cfg: Arc<SubServeConfig>,
    users: Arc<UserAuth>,
    accept_backoff: Duration,
) {
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(?e, "subscription listener accept error");
                tokio::time::sleep(accept_backoff).await;
                continue;
            }
        };
        let cfg = cfg.clone();
        let users = users.clone();
        tokio::spawn(async move {
            // Read the request head (cap so a slow client can't pin us).
            let mut buf = vec![0u8; 4096];
            let n = match sock.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return,
            };
            let head = String::from_utf8_lossy(&buf[..n]);
            let target = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1));
            let response = match target {
                Some(t) => handle(t, &cfg, &users),
                None => http_response(400, "text/plain", "bad request"),
            };
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        });
    }
}

/// Build the response for a request target like `/sub/<uuid>?format=clash`.
fn handle(target: &str, cfg: &SubServeConfig, users: &UserAuth) -> String {
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    let Some(uuid) = path.strip_prefix("/sub/").map(|s| s.trim_end_matches('/')) else {
        return http_response(404, "text/plain", "not found");
    };
    // Authorise: unknown UUID gets the same 404 as a bad path.
    let authorized = uuid
        .parse()
        .map(|id| users.is_authorized(&id))
        .unwrap_or(false);
    if uuid.is_empty() || !authorized {
        return http_response(404, "text/plain", "not found");
    }

    let format = query_value(query, "format").unwrap_or("xray");
    let profile = RoutingProfile::parse(query_value(query, "profile").unwrap_or("ru"));
    let label = format!("donut-{}", host_of(&cfg.public_address));
    let p = XhttpParams {
        uuid: uuid.to_string(),
        server_addr: cfg.public_address.clone(),
        sni: cfg.server_name.clone(),
        host: cfg.host.clone(),
        path: cfg.path.clone(),
        mode: cfg.mode.clone(),
        fp: cfg.fp.clone(),
        socks: cfg.socks.clone(),
        label,
    };

    match format {
        "clash" | "yaml" => http_response(
            200,
            "text/yaml; charset=utf-8",
            &subgen::clash_yaml(&p, profile),
        ),
        "links" | "link" | "sub" => {
            // Classic subscription: base64 of the newline-joined link list.
            let body = base64::engine::general_purpose::STANDARD
                .encode(format!("{}\n", subgen::vless_xhttp_link(&p)));
            http_response(200, "text/plain; charset=utf-8", &body)
        }
        "json" | "xray-json" | "sub-json" => {
            // XTLS-standard JSON array subscription: routing baked in (RU-split
            // enforced), inbounds on 10808/10809. Provider-style; HAPP applies
            // the routing because it's inside the config it runs.
            let arr = serde_json::to_string_pretty(&subgen::xray_json_subscription(&p, profile))
                .unwrap_or_else(|_| "[]".to_string());
            http_response(200, "application/json; charset=utf-8", &arr)
        }
        "happ" => {
            // HAPP subscription: base64 of the vless link + a
            // `happ://routing/onadd/...` deeplink, so HAPP imports the
            // connection AND applies the RU-split routing profile. No xray
            // inbound, so no :1080 clash with HAPP's own core.
            let body = base64::engine::general_purpose::STANDARD
                .encode(subgen::happ_subscription_body(&p, profile));
            http_response(200, "text/plain; charset=utf-8", &body)
        }
        _ => {
            // xray client.json (default).
            let json = serde_json::to_string_pretty(&subgen::xray_client_json(&p, profile))
                .unwrap_or_else(|_| "{}".to_string());
            http_response(200, "application/json; charset=utf-8", &json)
        }
    }
}

fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then_some(v)
    })
}

fn host_of(addr: &str) -> &str {
    addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr)
}

fn http_response(code: u16, content_type: &str, body: &str) -> String {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "OK",
    };
    format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}
