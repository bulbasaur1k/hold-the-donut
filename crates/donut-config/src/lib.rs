//! donut-config — JSON/TOML config loader for the donut server/client.
//!
//! A clean, documented subset shaped after Xray's `inbounds`/`outbounds`/
//! `log` layout (not byte-for-byte). The loader fully *materialises*
//! everything the daemons need — parsed x25519 keys, [`donut_core::ShortId`]s,
//! PEM cert chains / private keys — so the `main.rs` glue stays thin.
//!
//! The format is picked by file extension: `*.toml` is parsed as TOML,
//! everything else as JSON (the same `serde` structs back both). TOML is the
//! more readable hand-editing format; JSON stays fully supported. The schema
//! below is shown as JSON; the TOML form is the obvious 1:1 translation
//! (`[inbound]`, `[inbound.reality]`, `users = [...]`, …).
//!
//! Schemas (JSON):
//!
//! ```jsonc
//! // server
//! {
//!   "log": { "level": "info" },
//!   "inbound": {
//!     "listen": "0.0.0.0:443",
//!     "users": ["b831381d-6324-4d53-ad4f-8cda48b30811"], // allowed UUIDs
//!     "reality": {
//!       "private_key": "<base64-url or hex x25519 private key>",
//!       "short_ids": ["deadbeef", "0123"],
//!       "dest": "127.0.0.1:8443",       // selfsteal backdrop
//!       "cert": "/etc/donut/fullchain.pem",
//!       "key":  "/etc/donut/privkey.pem"
//!     }
//!   }
//!   // outbound is implicitly `freedom` for now
//! }
//!
//! // client
//! {
//!   "log": { "level": "info" },
//!   "inbound":  { "socks": "127.0.0.1:1080" },
//!   "outbound": {
//!     "server": "vpn.example.com:443",
//!     "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", // matches a server user
//!     "reality": {
//!       "public_key": "<base64-url or hex x25519 public key>",
//!       "short_id": "deadbeef",
//!       "server_name": "www.microsoft.com",
//!       "trusted_cert": "/etc/donut/server-cert.pem", // M3 simplification
//!       "version": [26, 4, 15],                         // optional
//!       "fingerprint": "randomized"                     // optional, uTLS-style
//!     }
//!   }
//! }
//! ```

#![forbid(unsafe_op_in_unsafe_fn)]

use std::net::IpAddr;
use std::sync::Arc;

use base64::prelude::*;
use donut_core::{ShortId, UserAuth, UserId};
use donut_dns::Resolver;
use donut_geo::{GeoIpDb, GeoSiteDb};
use donut_routing::Router;
pub use donut_routing::RoutingConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml: {0}")]
    Toml(String),
    #[error("bad x25519 key (expected 32 bytes as base64-url or hex): {0}")]
    Key(String),
    #[error("bad short id: {0}")]
    ShortId(String),
    #[error("bad user uuid: {0}")]
    User(String),
    #[error("inbound.users must list at least one allowed UUID")]
    NoUsers,
    #[error("outbound.uuid is required (the VLESS credential to present)")]
    NoUuid,
    #[error("pem: {0}")]
    Pem(String),
    #[error("routing: {0}")]
    Routing(String),
    #[error("geo: {0}")]
    Geo(String),
    #[error("dns: {0}")]
    Dns(String),
}

fn default_version() -> [u8; 3] {
    [26, 4, 15]
}

fn default_level() -> String {
    "info".to_string()
}

/// `{ "level": "info" }` — maps onto an env-filter directive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_level")]
    pub level: String,
    /// Log output format: `"text"` (default, human-readable) or `"json"`
    /// (structured, one JSON object per line — for log-analysis tooling).
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_level(),
            format: default_log_format(),
        }
    }
}

fn default_log_format() -> String {
    "text".to_string()
}

// ---- server ----------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub log: LogConfig,
    pub inbound: ServerInbound,
    /// Optional routing table. Default: everything to `freedom`.
    #[serde(default)]
    pub routing: RoutingConfig,
    /// Optional geo `.dat` paths for `geoip:`/`geosite:` rules.
    #[serde(default)]
    pub geo: GeoConfig,
    /// Resolver config for the freedom outbound. Default: system resolver.
    #[serde(default)]
    pub dns: DnsConfig,
    /// Optional Prometheus metrics endpoint.
    #[serde(default)]
    pub metrics: MetricsConfig,
}

/// Optional Prometheus `/metrics` listener. Absent ⇒ no metrics endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsConfig {
    #[serde(default)]
    pub listen: Option<String>,
}

/// Paths to v2fly `.dat` geo databases (optional).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoConfig {
    #[serde(default)]
    pub geoip: Option<String>,
    #[serde(default)]
    pub geosite: Option<String>,
}

/// Resolver config. If `doh` is empty the system resolver is used;
/// otherwise DNS-over-HTTPS against the listed upstream IPs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsConfig {
    #[serde(default)]
    pub doh: Vec<String>,
    #[serde(default)]
    pub doh_tls_name: Option<String>,
}

type GeoDatabases = (Option<Arc<GeoIpDb>>, Option<Arc<GeoSiteDb>>);

impl GeoConfig {
    /// Load the configured `.dat` databases (each optional).
    pub fn databases(&self) -> Result<GeoDatabases, ConfigError> {
        let geoip = match &self.geoip {
            Some(path) => Some(Arc::new(load_geoip(path)?)),
            None => None,
        };
        let geosite = match &self.geosite {
            Some(path) => Some(Arc::new(load_geosite(path)?)),
            None => None,
        };
        Ok((geoip, geosite))
    }
}

impl DnsConfig {
    /// Build the resolver: system resolver, or DoH if `doh` is non-empty.
    pub fn resolver(&self) -> Result<Resolver, ConfigError> {
        if self.doh.is_empty() {
            return Resolver::system().map_err(|e| ConfigError::Dns(e.to_string()));
        }
        let ips = self
            .doh
            .iter()
            .map(|s| s.parse::<IpAddr>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ConfigError::Dns(format!("bad DoH ip: {e}")))?;
        let tls_name = self
            .doh_tls_name
            .clone()
            .unwrap_or_else(|| "cloudflare-dns.com".to_string());
        Ok(Resolver::doh(&ips, &tls_name))
    }
}

impl ServerConfig {
    /// Compile the routing table into a runtime [`Router`], loading the
    /// geo databases referenced by `geoip:`/`geosite:` rules.
    pub fn router(&self) -> Result<Router, ConfigError> {
        let (geoip_db, geosite_db) = self.geo.databases()?;
        self.routing
            .build_with_geo(geoip_db, geosite_db)
            .map_err(|e| ConfigError::Routing(e.to_string()))
    }

    /// Build the freedom-outbound resolver from the `dns` section.
    pub fn resolver(&self) -> Result<Resolver, ConfigError> {
        self.dns.resolver()
    }
}

fn load_geoip(path: &str) -> Result<GeoIpDb, ConfigError> {
    let data = read(path)?;
    GeoIpDb::parse(&data).map_err(|e| ConfigError::Geo(format!("{path}: {e}")))
}

fn load_geosite(path: &str) -> Result<GeoSiteDb, ConfigError> {
    let data = read(path)?;
    GeoSiteDb::parse(&data).map_err(|e| ConfigError::Geo(format!("{path}: {e}")))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInbound {
    pub listen: String,
    /// Inbound transport: `"veil"` (REALITY veiled-TLS, default) or
    /// `"carrier"` (plain HTTP/1.1 carrier backend behind a TLS/HTTP-3
    /// reverse proxy such as Caddy — cert-based, no REALITY).
    #[serde(default = "default_server_transport")]
    pub transport: String,
    /// REALITY parameters. Required for `transport = "veil"`; ignored
    /// (and optional) for `"carrier"`.
    #[serde(default)]
    pub reality: Option<RealityServer>,
    /// Secret path prefix the front proxy forwards to this backend
    /// (`transport = "carrier"`). Must match the client's path.
    #[serde(default = "default_carrier_path")]
    pub path: String,
    /// PEM certificate chain. Required for `transport = "quic"` (direct
    /// H3 termination); ignored for `"carrier"` (front holds the cert)
    /// and `"veil"` (uses `reality.cert`).
    #[serde(default)]
    pub cert: Option<String>,
    /// PEM private key matching `cert`. Required for `transport = "quic"`.
    #[serde(default)]
    pub key: Option<String>,
    /// Decoy HTTP backend for self-steal (`transport = "quic"`):
    /// non-secret-path H3 requests are reverse-proxied here (e.g. the
    /// local filebrowser `127.0.0.1:8080`). Absent ⇒ non-secret requests
    /// get a 404.
    #[serde(default)]
    pub dest: Option<String>,
    /// Carrier framing mode for `transport = "tls"`: `"stream-one"`
    /// (default), `"stream-up"`, or `"packet-up"`. Must match the
    /// client's `outbound.mode`. Ignored by other transports.
    #[serde(default = "default_carrier_mode")]
    pub mode: String,
    /// Vision data-plane dialect for `transport = "raw"` + `flow =
    /// "xtls-rprx-vision"`: `"donut"` (default, our simpler padding —
    /// for the donut client) or `"xray"` (byte-faithful Xray Vision —
    /// interoperates with a real Xray VLESS client). Ignored otherwise.
    #[serde(default = "default_vision_dialect")]
    pub vision: String,
    /// Allowed VLESS user UUIDs. A tunnel session whose inner-frame UUID
    /// is not in this list is rejected before any upstream is dialled —
    /// this is the proxy's actual credential check, applied to every
    /// transport. Must list at least one UUID (an empty list authorises
    /// no one and the daemon refuses to start).
    #[serde(default)]
    pub users: Vec<String>,
}

impl ServerInbound {
    /// Materialise the allowed-user set from `users`. Errors on any
    /// unparseable UUID or an empty list (fail-closed: a server with no
    /// configured users would accept nobody, which is almost certainly a
    /// misconfiguration, so surface it loudly at startup).
    pub fn user_auth(&self) -> Result<UserAuth, ConfigError> {
        if self.users.is_empty() {
            return Err(ConfigError::NoUsers);
        }
        let users = self
            .users
            .iter()
            .map(|s| s.parse::<UserId>().map_err(|_| ConfigError::User(s.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(UserAuth::new(users))
    }

    /// Load the PEM certificate chain (`transport = "quic"`).
    pub fn cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, ConfigError> {
        let path = self.cert.as_deref().ok_or_else(|| {
            ConfigError::Pem("inbound.cert is required for transport=quic".into())
        })?;
        load_cert_chain(path)
    }
    /// Load the PEM private key (`transport = "quic"`).
    pub fn private_key_pem(&self) -> Result<PrivateKeyDer<'static>, ConfigError> {
        let path = self
            .key
            .as_deref()
            .ok_or_else(|| ConfigError::Pem("inbound.key is required for transport=quic".into()))?;
        load_private_key(path)
    }
}

fn default_server_transport() -> String {
    "veil".to_string()
}

fn default_carrier_path() -> String {
    "/".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityServer {
    pub private_key: String,
    pub short_ids: Vec<String>,
    pub dest: String,
    pub cert: String,
    pub key: String,
}

impl RealityServer {
    pub fn private_key_bytes(&self) -> Result<[u8; 32], ConfigError> {
        parse_x25519(&self.private_key)
    }
    pub fn short_id_set(&self) -> Result<Vec<ShortId>, ConfigError> {
        self.short_ids.iter().map(|s| parse_short_id(s)).collect()
    }
    pub fn cert_chain(&self) -> Result<Vec<CertificateDer<'static>>, ConfigError> {
        load_cert_chain(&self.cert)
    }
    pub fn private_key_pem(&self) -> Result<PrivateKeyDer<'static>, ConfigError> {
        load_private_key(&self.key)
    }
}

// ---- client ----------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(default)]
    pub log: LogConfig,
    pub inbound: ClientInbound,
    pub outbound: ClientOutbound,
    /// Split-tunnel routing. Outbound tags the client acts on:
    /// `direct`/`freedom` → dial straight from the client (bypass the
    /// server — keeps e.g. domestic `geoip:` traffic on the local IP);
    /// `block`/`blackhole` → drop; anything else (default `proxy`) →
    /// through the veiled tunnel. Absent ⇒ everything proxied.
    #[serde(default = "default_client_routing")]
    pub routing: RoutingConfig,
    /// Geo `.dat` paths for `geoip:`/`geosite:` split-tunnel rules.
    #[serde(default)]
    pub geo: GeoConfig,
    /// Resolver used for client-side **direct** dials (the tunnel path
    /// resolves server-side). Default: system resolver.
    #[serde(default)]
    pub dns: DnsConfig,
}

/// Client default: proxy everything (no split-tunnel rules).
fn default_client_routing() -> RoutingConfig {
    RoutingConfig {
        default: "proxy".to_string(),
        rules: Vec::new(),
    }
}

impl ClientConfig {
    /// Build the split-tunnel router (with any configured geo databases).
    pub fn router(&self) -> Result<Router, ConfigError> {
        let (geoip_db, geosite_db) = self.geo.databases()?;
        self.routing
            .build_with_geo(geoip_db, geosite_db)
            .map_err(|e| ConfigError::Routing(e.to_string()))
    }

    /// Build the resolver for client-side direct dials.
    pub fn resolver(&self) -> Result<Resolver, ConfigError> {
        self.dns.resolver()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInbound {
    pub socks: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientOutbound {
    pub server: String,
    /// VLESS user UUID presented on the inner frame. Must match one of
    /// the server's `inbound.users`, otherwise the server drops the
    /// session. Required.
    #[serde(default)]
    pub uuid: String,
    /// Client transport: `"veil"` (REALITY veiled-TLS, default),
    /// `"xhttp"` (carrier over plain TLS to a cert-based front), or
    /// `"h3"` (carrier over HTTP/3). The latter two use a real
    /// certificate + self-steal instead of REALITY.
    #[serde(default = "default_client_transport")]
    pub transport: String,
    /// REALITY parameters. Required for `transport = "veil"`; ignored
    /// (and optional) for `"xhttp"`/`"h3"`.
    #[serde(default)]
    pub reality: Option<RealityClient>,
    /// TLS SNI / certificate name of the front proxy (`xhttp`/`h3`).
    /// Empty ⇒ derived from the host part of `server`.
    #[serde(default)]
    pub server_name: String,
    /// Secret path prefix the front routes to the carrier backend
    /// (`xhttp`/`h3`). Must match the server's `inbound.path`.
    #[serde(default = "default_carrier_path")]
    pub path: String,
    /// Carrier framing mode for `xhttp`: `"stream-one"` (default,
    /// single full-duplex exchange), `"stream-up"` (separate POST-up /
    /// GET-down connections), or `"packet-up"` (many sequenced POSTs +
    /// one GET). Must match the server's `inbound.mode`. Ignored by
    /// `veil`/`h3`.
    #[serde(default = "default_carrier_mode")]
    pub mode: String,
    /// XTLS flow for `transport = "raw"`: `""`/`"none"` (default, plain
    /// VLESS) or `"xtls-rprx-vision"` (first-packet padding against
    /// TLS-in-TLS detection). Ignored by carrier transports.
    #[serde(default)]
    pub flow: String,
}

impl ClientOutbound {
    /// Parse the configured VLESS credential. Errors if `uuid` is empty
    /// (required) or not a valid UUID.
    pub fn user_id(&self) -> Result<UserId, ConfigError> {
        if self.uuid.trim().is_empty() {
            return Err(ConfigError::NoUuid);
        }
        self.uuid
            .parse::<UserId>()
            .map_err(|_| ConfigError::User(self.uuid.clone()))
    }
}

fn default_client_transport() -> String {
    "veil".to_string()
}

fn default_carrier_mode() -> String {
    "stream-one".to_string()
}

fn default_vision_dialect() -> String {
    "donut".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityClient {
    pub public_key: String,
    pub short_id: String,
    pub server_name: String,
    #[serde(default = "default_version")]
    pub version: [u8; 3],
    /// TLS ClientHello fingerprint to mimic (uTLS-style). Accepts
    /// `"native"` (default), `"randomized"`, `"randomizedalpn"`,
    /// `"randomizednoalpn"`. Parsed by `donut_veil::Fingerprint` at
    /// startup; an empty value means native.
    #[serde(default)]
    pub fingerprint: String,
    // No `trusted_cert`: the server is authenticated by the in-tunnel
    // AuthKey proof (REALITY-hardening), not WebPKI. Legacy configs that
    // still carry the field parse fine — it's ignored.
}

impl RealityClient {
    pub fn public_key_bytes(&self) -> Result<[u8; 32], ConfigError> {
        parse_x25519(&self.public_key)
    }
    pub fn short_id_value(&self) -> Result<ShortId, ConfigError> {
        parse_short_id(&self.short_id)
    }
}

// ---- loaders ---------------------------------------------------------

pub fn load_server(path: &str) -> Result<ServerConfig, ConfigError> {
    from_path(path)
}

pub fn load_client(path: &str) -> Result<ClientConfig, ConfigError> {
    from_path(path)
}

/// Load and deserialise a config from `path`, choosing the format by file
/// extension: `.toml` → TOML, anything else (`.json`, `.jsonc`, …) → JSON.
/// For an unknown/missing extension we try JSON first, then TOML, so a config
/// named without an extension still works.
pub fn from_path<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, ConfigError> {
    let data = read(path)?;
    match config_format(path) {
        Format::Toml => from_toml(&data),
        Format::Json => Ok(serde_json::from_slice(&data)?),
        Format::Unknown => match serde_json::from_slice(&data) {
            Ok(v) => Ok(v),
            Err(json_err) => from_toml(&data).map_err(|toml_err| {
                ConfigError::Toml(format!(
                    "{path}: not valid JSON ({json_err}) nor TOML ({toml_err})"
                ))
            }),
        },
    }
}

enum Format {
    Json,
    Toml,
    Unknown,
}

fn config_format(path: &str) -> Format {
    match std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("toml") => Format::Toml,
        Some("json") | Some("jsonc") | Some("js") => Format::Json,
        _ => Format::Unknown,
    }
}

fn from_toml<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, ConfigError> {
    let s = std::str::from_utf8(data).map_err(|e| ConfigError::Toml(e.to_string()))?;
    toml::from_str(s).map_err(|e| ConfigError::Toml(e.to_string()))
}

fn read(path: &str) -> Result<Vec<u8>, ConfigError> {
    std::fs::read(path).map_err(|source| ConfigError::Io {
        path: path.to_string(),
        source,
    })
}

// ---- materialisation helpers ----------------------------------------

/// Parse a 32-byte X25519 key from base64 (url-safe or standard, padded
/// or not) or hex. Xray emits base64-url for REALITY keys; hex is
/// accepted for convenience.
pub fn parse_x25519(s: &str) -> Result<[u8; 32], ConfigError> {
    let s = s.trim();
    let mut out = [0u8; 32];

    if let Ok(bytes) = hex::decode(s) {
        if bytes.len() == 32 {
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }
    for engine in [
        &BASE64_URL_SAFE_NO_PAD,
        &BASE64_URL_SAFE,
        &BASE64_STANDARD_NO_PAD,
        &BASE64_STANDARD,
    ] {
        if let Ok(bytes) = engine.decode(s) {
            if bytes.len() == 32 {
                out.copy_from_slice(&bytes);
                return Ok(out);
            }
        }
    }
    Err(ConfigError::Key(s.to_string()))
}

pub fn parse_short_id(s: &str) -> Result<ShortId, ConfigError> {
    s.parse::<ShortId>()
        .map_err(|_| ConfigError::ShortId(s.to_string()))
}

pub fn load_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, ConfigError> {
    let data = read(path)?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ConfigError::Pem(format!("{path}: {e}")))?;
    if certs.is_empty() {
        return Err(ConfigError::Pem(format!("no certificates in {path}")));
    }
    Ok(certs)
}

pub fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, ConfigError> {
    let data = read(path)?;
    let mut reader = std::io::BufReader::new(&data[..]);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| ConfigError::Pem(format!("{path}: {e}")))?
        .ok_or_else(|| ConfigError::Pem(format!("no private key in {path}")))
}

pub fn load_roots(path: &str) -> Result<RootCertStore, ConfigError> {
    let mut roots = RootCertStore::empty();
    for cert in load_cert_chain(path)? {
        roots
            .add(cert)
            .map_err(|e| ConfigError::Pem(format!("{path}: {e}")))?;
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_config_and_materialises() {
        let json = r#"{
            "inbound": {
                "listen": "0.0.0.0:443",
                "users": ["b831381d-6324-4d53-ad4f-8cda48b30811"],
                "reality": {
                    "private_key": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "short_ids": ["deadbeef", "0123"],
                    "dest": "127.0.0.1:8443",
                    "cert": "/x/fullchain.pem",
                    "key": "/x/privkey.pem"
                }
            }
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.inbound.listen, "0.0.0.0:443");
        assert_eq!(cfg.log.level, "info"); // default
        let reality = cfg.inbound.reality.as_ref().unwrap();
        assert_eq!(
            reality.private_key_bytes().unwrap()[..4],
            [0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(reality.short_id_set().unwrap().len(), 2);
        assert_eq!(cfg.inbound.transport, "veil"); // default

        // The allowed-user set materialises and authorises the configured UUID.
        let auth = cfg.inbound.user_auth().unwrap();
        let uuid: donut_core::UserId = "b831381d-6324-4d53-ad4f-8cda48b30811".parse().unwrap();
        assert!(auth.is_authorized(&uuid));
        assert!(!auth.is_authorized(&donut_core::UserId::new_v4()));
    }

    #[test]
    fn server_with_no_users_is_rejected() {
        let json = r#"{
            "inbound": {
                "listen": "0.0.0.0:443",
                "transport": "raw",
                "cert": "/x/fullchain.pem",
                "key": "/x/privkey.pem"
            }
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.inbound.users.is_empty());
        assert!(matches!(
            cfg.inbound.user_auth(),
            Err(ConfigError::NoUsers)
        ));
    }

    #[test]
    fn parses_client_config_with_default_version() {
        let json = r#"{
            "inbound": { "socks": "127.0.0.1:1080" },
            "outbound": {
                "server": "vpn.example.com:443",
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                "reality": {
                    "public_key": "0000000000000000000000000000000000000000000000000000000000000000",
                    "short_id": "deadbeef",
                    "server_name": "www.microsoft.com",
                    "trusted_cert": "/x/cert.pem"
                }
            }
        }"#;
        let cfg: ClientConfig = serde_json::from_str(json).unwrap();
        let reality = cfg.outbound.reality.as_ref().unwrap();
        assert_eq!(reality.version, [26, 4, 15]);
        assert_eq!(
            reality.short_id_value().unwrap(),
            "deadbeef".parse::<donut_core::ShortId>().unwrap()
        );
        assert_eq!(cfg.outbound.transport, "veil"); // default
        assert_eq!(
            cfg.outbound.user_id().unwrap(),
            "b831381d-6324-4d53-ad4f-8cda48b30811".parse().unwrap()
        );
    }

    #[test]
    fn client_without_uuid_is_rejected() {
        let json = r#"{
            "inbound": { "socks": "127.0.0.1:1080" },
            "outbound": { "server": "vpn.example.com:443", "transport": "raw" }
        }"#;
        let cfg: ClientConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(cfg.outbound.user_id(), Err(ConfigError::NoUuid)));
    }

    #[test]
    fn x25519_accepts_base64_and_hex() {
        let raw = [7u8; 32];
        let hexed = hex::encode(raw);
        assert_eq!(parse_x25519(&hexed).unwrap(), raw);
        let b64 = BASE64_URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(parse_x25519(&b64).unwrap(), raw);
        assert!(parse_x25519("too-short").is_err());
    }

    #[test]
    fn parses_server_and_client_config_from_toml() {
        let server = r#"
            [log]
            level = "info"

            [inbound]
            listen = "0.0.0.0:443"
            transport = "raw"
            vision = "xray"
            users = ["b831381d-6324-4d53-ad4f-8cda48b30811"]
            cert = "/x/fullchain.pem"
            key = "/x/privkey.pem"
        "#;
        let cfg: ServerConfig = toml::from_str(server).unwrap();
        assert_eq!(cfg.inbound.listen, "0.0.0.0:443");
        assert_eq!(cfg.inbound.transport, "raw");
        assert_eq!(cfg.inbound.vision, "xray");
        assert!(cfg.inbound.user_auth().is_ok());

        let client = r#"
            [inbound]
            socks = "127.0.0.1:1080"

            [outbound]
            server = "vpn.example.com:443"
            uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
            transport = "raw"
            flow = "xtls-rprx-vision"
        "#;
        let cfg: ClientConfig = toml::from_str(client).unwrap();
        assert_eq!(cfg.outbound.server, "vpn.example.com:443");
        assert_eq!(cfg.outbound.flow, "xtls-rprx-vision");
        assert!(cfg.outbound.user_id().is_ok());
    }

    #[test]
    fn from_path_picks_format_by_extension() {
        let base = std::env::temp_dir().join(format!("donut-cfg-{}", std::process::id()));
        let toml_path = format!("{}.toml", base.display());
        std::fs::write(
            &toml_path,
            "[inbound]\nlisten = \"0.0.0.0:443\"\nusers = [\"b831381d-6324-4d53-ad4f-8cda48b30811\"]\n",
        )
        .unwrap();
        let cfg: ServerConfig = from_path(&toml_path).unwrap();
        assert_eq!(cfg.inbound.listen, "0.0.0.0:443");
        std::fs::remove_file(&toml_path).ok();

        // Unknown extension falls back to JSON-then-TOML detection.
        let noext = format!("{}-noext", base.display());
        std::fs::write(
            &noext,
            "[inbound]\nlisten = \"0.0.0.0:8443\"\nusers = [\"b831381d-6324-4d53-ad4f-8cda48b30811\"]\n",
        )
        .unwrap();
        let cfg: ServerConfig = from_path(&noext).unwrap();
        assert_eq!(cfg.inbound.listen, "0.0.0.0:8443");
        std::fs::remove_file(&noext).ok();
    }
}
