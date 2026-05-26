//! Minimal `vless://` share-link parser — enough to import a link emitted by
//! `donut-tools` (or any standard VLESS client) into a donut-client config.

use anyhow::{anyhow, Context};

/// Parsed `vless://UUID@host:port?params#label`.
#[derive(Debug, Clone)]
pub struct VlessLink {
    pub uuid: String,
    pub host: String,
    pub port: u16,
    /// `security` param: `tls` / `reality` / `none`.
    pub security: String,
    /// `sni` (TLS server name); empty ⇒ falls back to `host`.
    pub sni: String,
    /// `fp` (uTLS fingerprint), e.g. `chrome`.
    pub fp: String,
    /// `flow`, e.g. `xtls-rprx-vision` (empty when absent).
    pub flow: String,
    /// `type` (network): `tcp` / `raw` / …
    pub network: String,
    /// Fragment label (display name).
    pub label: String,
}

impl VlessLink {
    /// SNI to present (explicit `sni`, else the host).
    pub fn server_name(&self) -> String {
        if self.sni.is_empty() {
            self.host.clone()
        } else {
            self.sni.clone()
        }
    }
}

/// Parse a `vless://` URI. Tolerant of missing optional params.
pub fn parse(s: &str) -> anyhow::Result<VlessLink> {
    let s = s.trim();
    let rest = s
        .strip_prefix("vless://")
        .ok_or_else(|| anyhow!("not a vless:// link"))?;

    // Split off the #fragment (label).
    let (rest, label) = match rest.split_once('#') {
        Some((r, frag)) => (r, pct_decode(frag)),
        None => (rest, String::new()),
    };
    // Split authority from ?query.
    let (authority, query) = match rest.split_once('?') {
        Some((a, q)) => (a, q),
        None => (rest, ""),
    };
    // authority = UUID@host:port
    let (uuid, hostport) = authority
        .split_once('@')
        .ok_or_else(|| anyhow!("missing UUID@host in link"))?;
    if uuid.is_empty() {
        return Err(anyhow!("empty UUID in link"));
    }
    let (host, port) = split_host_port(hostport)?;

    let mut link = VlessLink {
        uuid: uuid.to_string(),
        host,
        port,
        security: String::new(),
        sni: String::new(),
        fp: String::new(),
        flow: String::new(),
        network: "tcp".to_string(),
        label,
    };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = pct_decode(v);
        match k {
            "security" => link.security = v,
            "sni" => link.sni = v,
            "fp" => link.fp = v,
            "flow" => link.flow = v,
            "type" => link.network = v,
            _ => {}
        }
    }
    Ok(link)
}

/// Split `host:port`, handling bracketed IPv6 `[::1]:443`.
fn split_host_port(s: &str) -> anyhow::Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow!("malformed IPv6 host:port {s:?}"))?;
        let port = p.parse().with_context(|| format!("bad port in {s:?}"))?;
        return Ok((h.to_string(), port));
    }
    let (h, p) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("missing :port in {s:?}"))?;
    let port = p.parse().with_context(|| format!("bad port in {s:?}"))?;
    Ok((h.to_string(), port))
}

/// Percent-decode a URI component (`%XX` → byte; `+` is left as-is, per RFC
/// 3986 query semantics rather than form-encoding).
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_link() {
        let l = parse("vless://0d04868a-7ecf-4c84-9ee2-102ad5f3be26@cozbystorage.duckdns.org:443?type=tcp&security=tls&sni=cozbystorage.duckdns.org&fp=chrome&alpn=http%2F1.1&flow=xtls-rprx-vision#donut-cozby").unwrap();
        assert_eq!(l.uuid, "0d04868a-7ecf-4c84-9ee2-102ad5f3be26");
        assert_eq!(l.host, "cozbystorage.duckdns.org");
        assert_eq!(l.port, 443);
        assert_eq!(l.security, "tls");
        assert_eq!(l.sni, "cozbystorage.duckdns.org");
        assert_eq!(l.fp, "chrome");
        assert_eq!(l.flow, "xtls-rprx-vision");
        assert_eq!(l.network, "tcp");
        assert_eq!(l.label, "donut-cozby");
        assert_eq!(l.server_name(), "cozbystorage.duckdns.org");
    }

    #[test]
    fn server_name_falls_back_to_host() {
        let l = parse("vless://u@1.2.3.4:443?security=tls").unwrap();
        assert_eq!(l.server_name(), "1.2.3.4");
        assert_eq!(l.flow, "");
    }

    #[test]
    fn rejects_non_vless() {
        assert!(parse("https://example.com").is_err());
        assert!(parse("vless://nohost").is_err());
    }
}
