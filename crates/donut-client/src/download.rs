//! Tiny HTTPS downloader (no extra deps) for fetching geo `.dat` files.
//!
//! Uses the same `tokio-rustls` + `webpki-roots` stack the client already
//! links. It sends `Connection: close` and reads to EOF, so there's no need to
//! parse `Content-Length`/chunked framing, and it follows redirects (GitHub
//! release "latest/download" URLs 302 to the asset CDN).

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const MAX_REDIRECTS: usize = 6;

struct Url {
    host: String,
    port: u16,
    path: String,
}

fn parse_https(url: &str) -> anyhow::Result<Url> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("only https:// URLs are supported: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().context("bad port in URL")?),
        None => (authority.to_string(), 443u16),
    };
    Ok(Url {
        host,
        port,
        path: path.to_string(),
    })
}

fn tls_connector() -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

/// GET `url` over HTTPS (following redirects) and write the body to `dest`.
/// Returns the number of bytes written.
pub async fn https_get_to_file(url: &str, dest: &Path) -> anyhow::Result<u64> {
    let connector = tls_connector();
    let mut current = url.to_string();

    for _ in 0..MAX_REDIRECTS {
        let u = parse_https(&current)?;
        let raw = TcpStream::connect((u.host.as_str(), u.port))
            .await
            .with_context(|| format!("connect {}:{}", u.host, u.port))?;
        raw.set_nodelay(true).ok();
        let server_name = ServerName::try_from(u.host.clone())
            .with_context(|| format!("invalid host {}", u.host))?;
        let mut tls = connector
            .connect(server_name, raw)
            .await
            .with_context(|| format!("TLS handshake to {}", u.host))?;

        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: donut-client\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            u.path, u.host
        );
        tls.write_all(req.as_bytes()).await?;
        tls.flush().await?;

        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await?;

        let split = find_header_end(&buf)
            .ok_or_else(|| anyhow!("malformed HTTP response from {}", u.host))?;
        let head = &buf[..split];
        let head_str = String::from_utf8_lossy(head);
        let status = parse_status(&head_str)
            .ok_or_else(|| anyhow!("no HTTP status line from {}", u.host))?;

        match status {
            200 => {
                let body = &buf[split..];
                if body.is_empty() {
                    bail!("empty body from {}", u.host);
                }
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(dest, body)
                    .with_context(|| format!("writing {}", dest.display()))?;
                return Ok(body.len() as u64);
            }
            301 | 302 | 303 | 307 | 308 => {
                let loc = header_value(&head_str, "location")
                    .ok_or_else(|| anyhow!("redirect {status} without Location"))?;
                current = resolve_redirect(&u, &loc);
            }
            other => bail!("HTTP {other} from {}{}", u.host, u.path),
        }
    }
    bail!("too many redirects fetching {url}")
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_status(head: &str) -> Option<u16> {
    head.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
}

/// Resolve a (possibly relative) redirect target against the current URL.
fn resolve_redirect(cur: &Url, loc: &str) -> String {
    if loc.starts_with("https://") {
        loc.to_string()
    } else if let Some(rest) = loc.strip_prefix("http://") {
        format!("https://{rest}") // upgrade; we only speak TLS
    } else if loc.starts_with('/') {
        format!("https://{}:{}{}", cur.host, cur.port, loc)
    } else {
        format!("https://{}:{}/{}", cur.host, cur.port, loc)
    }
}
