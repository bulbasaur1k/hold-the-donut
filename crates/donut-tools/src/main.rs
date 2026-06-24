//! donut-tools — ops CLI: key generation, config helpers, peer probe.
//!
//! `keygen` and `config-gen` are implemented (M6/M9); `probe` lands later.

use base64::prelude::*;
use clap::{Args, Parser, Subcommand, ValueEnum};
use donut_config::{
    ClientConfig, ClientInbound, ClientOutbound, RealityClient, RealityServer, RoutingConfig,
    ServerConfig, ServerInbound,
};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug, Parser)]
#[command(name = "donut-tools", version, about = "hold-the-donut ops cli")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate an X25519 keypair + short identifier for a server.
    Keygen,
    /// Connectivity check against a peer (handshake + fallback path).
    Probe { target: String },
    /// Generate a consistent server + client config pair (fresh keypair).
    ConfigGen(ConfigGenArgs),
    /// Build a `vless://` share-link from explicit parameters (for pasting
    /// into off-the-shelf App Store clients like HAPP / Streisand / v2box).
    Link(LinkArgs),
    /// Generate admin credentials (username + Argon2 password hash) for the
    /// protected `/metrics` + `/healthz` endpoint. Prints the cleartext
    /// password once and a ready-to-paste `[metrics]` config snippet.
    AdminPasswd(AdminPasswdArgs),
    /// Mint a fresh per-device VLESS credential (one UUID per device, like
    /// xray-core). Prints the UUID, a registry line for the device list, and
    /// — when the entry's REALITY params are given — a ready donut-client
    /// `client.json` for that device.
    DeviceAdd(DeviceAddArgs),
    /// Probe a candidate REALITY masquerade target (like `xray tls ping`):
    /// checks TLS 1.3 + X25519, ALPN h2, and prints the certificate SANs to
    /// use as `serverNames`/`sni`. `target` is `host` or `host:port` (443).
    TlsPing { target: String },
    /// Scan an IPv4 subnet for REALITY-suitable masquerade hosts (like
    /// RealiTLScanner): TLS 1.3 + X25519 + ALPN h2, printing each host's
    /// certificate domains. Pick a neighbour in your VPS's own subnet/ASN so
    /// the cover's SNI/IP geolocation matches your server.
    RealityScan(RealityScanArgs),
    /// Build a `vless://…security=reality…flow=xtls-rprx-vision` share-link for
    /// `transport="reality"` — import straight into HAPP / Shadowrocket / v2box.
    /// Validated against real xray-core.
    RealityLink(RealityLinkArgs),
}

/// Parameters for `reality-link`.
#[derive(Debug, Clone, Args)]
struct RealityLinkArgs {
    /// VLESS user UUID (must match a server `inbound.users` entry).
    #[arg(long)]
    uuid: String,
    /// Public address the client dials (`host:port`).
    #[arg(long)]
    server: String,
    /// Server REALITY public key (X25519, base64-url) — from `keygen`.
    #[arg(long)]
    pbk: String,
    /// Server REALITY short id (hex).
    #[arg(long)]
    sid: String,
    /// SNI / serverName to mimic (your chosen masquerade target).
    #[arg(long, default_value = "www.microsoft.com")]
    sni: String,
    /// uTLS fingerprint.
    #[arg(long, default_value = "chrome")]
    fp: String,
    /// Display label (URL fragment). Empty ⇒ derived from the host.
    #[arg(long, default_value = "")]
    label: String,
}

/// Parameters for `reality-scan`.
#[derive(Debug, Clone, Args)]
struct RealityScanArgs {
    /// IPv4 CIDR to scan (e.g. `203.0.113.0/24`) or a single IP.
    cidr: String,
    /// Port to probe.
    #[arg(long, default_value_t = 443)]
    port: u16,
    /// Per-host handshake timeout (ms).
    #[arg(long, default_value_t = 2500)]
    timeout_ms: u64,
    /// Concurrent probes.
    #[arg(long, default_value_t = 64)]
    concurrency: usize,
}

/// Parameters for `device-add`.
#[derive(Debug, Clone, Args)]
struct DeviceAddArgs {
    /// Device label (e.g. "pixel-8", "macbook"). One UUID per device.
    #[arg(long)]
    name: String,
    /// Entry node the device dials (`host:port`).
    #[arg(long)]
    server: Option<String>,
    /// Entry REALITY public key (base64-url or hex). Enables client.json.
    #[arg(long)]
    reality_pub: Option<String>,
    /// Entry REALITY short id (hex). Required with `--reality-pub`.
    #[arg(long)]
    short_id: Option<String>,
    /// TLS SNI the client presents (the entry's selfsteal domain).
    #[arg(long, default_value = "www.microsoft.com")]
    sni: String,
    /// uTLS ClientHello fingerprint to mimic.
    #[arg(long, default_value = "randomized")]
    fp: String,
    /// Local SOCKS5 listen address the device's donut-client opens.
    #[arg(long, default_value = "127.0.0.1:1080")]
    socks: String,
}

/// Parameters for `admin-passwd`.
#[derive(Debug, Clone, Args)]
struct AdminPasswdArgs {
    /// Admin username.
    #[arg(long, default_value = "admin")]
    user: String,
    /// Password to hash. Omit to mint a fresh random 24-char password
    /// (printed once — copy it now, it is not recoverable from the hash).
    #[arg(long)]
    password: Option<String>,
}

/// Parameters for the `link` subcommand — a standalone `vless://` builder.
#[derive(Debug, Clone, Args)]
struct LinkArgs {
    /// VLESS user UUID (must match a server `inbound.users` entry).
    #[arg(long)]
    uuid: String,
    /// Public address the client dials (`host:port`).
    #[arg(long)]
    server_addr: String,
    /// TLS SNI / certificate name presented by the client.
    #[arg(long)]
    sni: String,
    /// uTLS ClientHello fingerprint to mimic.
    #[arg(long, default_value = "chrome")]
    fp: String,
    /// XTLS flow. Default matches a `raw` + `vision:"xray"` server.
    #[arg(long, default_value = "xtls-rprx-vision")]
    flow: String,
    /// Display label (URL fragment). Empty ⇒ derived from the host.
    #[arg(long, default_value = "")]
    label: String,
}

/// Which transport pair `config-gen` should emit. Server and client name
/// the same wire differently, hence the mapping below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TransportKind {
    /// REALITY veiled-TLS (server `veil` ↔ client `veil`). Emits a fresh
    /// X25519 keypair + ShortID; the cert/key authenticate the selfsteal
    /// backdrop the server forwards unauthenticated callers to.
    Veil,
    /// Cert-based TLS carrier on TCP (server `tls` ↔ client `xhttp`).
    /// donut-server terminates TLS itself; the secret path reaches the
    /// tunnel, everything else self-steals to the decoy. No REALITY.
    Tls,
    /// Cert-based QUIC / HTTP-3 (server `quic` ↔ client `h3`).
    /// donut-server terminates H3 itself; secret path → tunnel, else →
    /// decoy self-steal. No REALITY.
    Quic,
    /// Cert-based RAW + faithful Xray Vision (server `raw`, `vision:"xray"`,
    /// `flow=xtls-rprx-vision`). The interop path for **off-the-shelf App
    /// Store clients** (HAPP, Streisand, …): emits the server config plus a
    /// ready-to-paste `vless://` link — no donut-client needed.
    Raw,
    /// Cert-based **Xray-compatible xHTTP** (server `xhttp`, TLS+H2,
    /// stream-up). The DPI-evasion interop path for off-the-shelf clients
    /// (HAPP, Xray, …): traffic looks like ordinary web requests. Emits the
    /// server config plus a ready-to-paste `vless://…type=xhttp…` link — no
    /// donut-client needed.
    Xhttp,
}

/// Carrier framing mode for the cert-based TLS carrier (`tls`/`xhttp`).
/// Ignored by `veil` and `quic`/`h3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CarrierMode {
    /// Single full-duplex HTTP exchange (default).
    StreamOne,
    /// Separate long POST-up / GET-down connections.
    StreamUp,
    /// Many sequenced POSTs (up) + one long GET (down).
    PacketUp,
}

impl CarrierMode {
    fn as_str(self) -> &'static str {
        match self {
            CarrierMode::StreamOne => "stream-one",
            CarrierMode::StreamUp => "stream-up",
            CarrierMode::PacketUp => "packet-up",
        }
    }
}

/// Parameters for `config-gen`. Sensible defaults; override per deploy.
#[derive(Debug, Clone, Args)]
struct ConfigGenArgs {
    /// Transport pair to generate: `veil` (REALITY), `tls` (cert-based
    /// TLS carrier) or `quic` (cert-based QUIC/H3).
    #[arg(long, value_enum, default_value = "veil")]
    transport: TransportKind,
    /// SNI / decoy domain the client presents (your selfsteal domain).
    #[arg(long, default_value = "www.microsoft.com")]
    server_name: String,
    /// Public address the client dials (`host:port`).
    #[arg(long, default_value = "203.0.113.1:443")]
    server_addr: String,
    /// Server listen address.
    #[arg(long, default_value = "0.0.0.0:443")]
    listen: String,
    /// Selfsteal / decoy backdrop unauthenticated callers are forwarded to.
    #[arg(long, default_value = "127.0.0.1:8443")]
    dest: String,
    /// Local SOCKS5 listen address on the client.
    #[arg(long, default_value = "127.0.0.1:1080")]
    socks: String,
    /// Server TLS cert chain path (PEM). Used by `tls`/`quic`; for `veil`
    /// it authenticates the selfsteal backdrop.
    #[arg(long, default_value = "/etc/donut/fullchain.pem")]
    cert: String,
    /// Server TLS private key path (PEM).
    #[arg(long, default_value = "/etc/donut/privkey.pem")]
    key: String,
    /// Secret path prefix routed to the tunnel (`tls`/`quic`). Omit to
    /// mint a fresh random path; ignored by `veil`.
    #[arg(long)]
    path: Option<String>,
    /// Carrier framing mode for `tls` (`stream-one` default, `stream-up`,
    /// `packet-up`). Ignored by `veil`/`quic`. For `xhttp` the canonical
    /// mode is `stream-up`; `stream-one` is treated as unset → `stream-up`.
    #[arg(long, value_enum, default_value = "stream-one")]
    carrier_mode: CarrierMode,
    /// Pinned `Host`/`:authority` for `xhttp` (and the `host=` field in the
    /// share link). Defaults to `server_name` (the TLS SNI). Ignored by
    /// other transports.
    #[arg(long)]
    host: Option<String>,
    /// uTLS ClientHello fingerprint for the `xhttp` share link + client JSON.
    /// Default `firefox`. Ignored by other transports.
    #[arg(long, default_value = "firefox")]
    fp: String,
}

#[cfg(test)]
impl Default for ConfigGenArgs {
    fn default() -> Self {
        Self {
            transport: TransportKind::Veil,
            server_name: "www.microsoft.com".into(),
            server_addr: "203.0.113.1:443".into(),
            listen: "0.0.0.0:443".into(),
            dest: "127.0.0.1:8443".into(),
            socks: "127.0.0.1:1080".into(),
            cert: "/etc/donut/fullchain.pem".into(),
            key: "/etc/donut/privkey.pem".into(),
            path: None,
            carrier_mode: CarrierMode::StreamOne,
            host: None,
            fp: "firefox".into(),
        }
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen => keygen(),
        Cmd::Probe { target } => eprintln!("probe {target}: not yet implemented (M9)"),
        Cmd::ConfigGen(args) => config_gen(&args)?,
        Cmd::Link(args) => {
            let label = if args.label.is_empty() {
                host_of(&args.server_addr)
            } else {
                args.label.clone()
            };
            println!(
                "{}",
                vless_link(
                    &args.uuid,
                    &args.server_addr,
                    &args.sni,
                    &args.fp,
                    &args.flow,
                    &label
                )
            );
        }
        Cmd::AdminPasswd(args) => admin_passwd(&args)?,
        Cmd::DeviceAdd(args) => device_add(&args)?,
        Cmd::TlsPing { target } => tls_ping(&target)?,
        Cmd::RealityScan(args) => reality_scan(&args)?,
        Cmd::RealityLink(args) => {
            let label = if args.label.is_empty() {
                host_of(&args.server)
            } else {
                args.label.clone()
            };
            println!(
                "{}",
                vless_reality_link(
                    &args.uuid, &args.server, &args.pbk, &args.sid, &args.sni, &args.fp, &label
                )
            );
        }
    }
    Ok(())
}

/// Build a faithful-REALITY `vless://` share URI (validated against xray-core):
/// `vless://UUID@host:port?type=tcp&security=reality&encryption=none&pbk=..&sid=..&sni=..&fp=..&flow=xtls-rprx-vision#label`
fn vless_reality_link(
    uuid: &str,
    addr: &str,
    pbk: &str,
    sid: &str,
    sni: &str,
    fp: &str,
    label: &str,
) -> String {
    let params: [(&str, &str); 8] = [
        ("type", "tcp"),
        ("security", "reality"),
        ("encryption", "none"),
        ("pbk", pbk),
        ("sid", sid),
        ("sni", sni),
        ("fp", fp),
        ("flow", "xtls-rprx-vision"),
    ];
    let query = params
        .iter()
        .map(|(k, v)| format!("{k}={}", pct(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("vless://{uuid}@{addr}?{query}#{}", pct(label))
}

/// Extract the DNS SubjectAltNames from a leaf certificate DER.
fn cert_san_dns(der: &[u8]) -> Vec<String> {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for gn in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(d) = gn {
                    names.push(d.to_string());
                }
            }
        }
    }
    names
}

/// A REALITY-suitable host discovered by the scan.
struct ScanHit {
    ip: std::net::Ipv4Addr,
    alpn: String,
    sans: Vec<String>,
}

/// Probe one IP for REALITY suitability: a TLS 1.3 handshake offering only
/// X25519, no cert validation (we just read the cert). Returns a hit on
/// success. Connects by IP (no SNI) so the server returns its default cert.
fn probe_reality_target(
    ip: std::net::Ipv4Addr,
    port: u16,
    timeout: std::time::Duration,
) -> Option<ScanHit> {
    use std::io::Write as _;
    use std::net::{SocketAddr, TcpStream};
    use std::sync::Arc;

    use rustls::pki_types::ServerName;

    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .kx_groups
        .retain(|g| g.name() == rustls::NamedGroup::X25519);
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(donut_veil::NoCertVerification::arc())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let addr = SocketAddr::from((ip, port));
    let mut sock = TcpStream::connect_timeout(&addr, timeout).ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    sock.set_write_timeout(Some(timeout)).ok()?;

    let server_name = ServerName::IpAddress(std::net::IpAddr::V4(ip).into());
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).ok()?;
    // Drive the handshake; flush triggers it.
    conn.complete_io(&mut sock).ok()?;
    let _ = sock.flush();

    if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return None;
    }
    let alpn = match conn.alpn_protocol() {
        Some(p) => String::from_utf8_lossy(p).into_owned(),
        None => "-".to_string(),
    };
    let sans = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|leaf| cert_san_dns(leaf.as_ref()))
        .unwrap_or_default();
    Some(ScanHit { ip, alpn, sans })
}

/// Scan an IPv4 CIDR for REALITY-suitable hosts.
fn reality_scan(args: &RealityScanArgs) -> anyhow::Result<()> {
    let ips = parse_cidr_v4(&args.cidr)?;
    let timeout = std::time::Duration::from_millis(args.timeout_ms);
    eprintln!(
        "# scanning {} host(s) in {} on :{} (X25519 TLS 1.3, h2)…",
        ips.len(),
        args.cidr,
        args.port
    );

    let mut hits = 0usize;
    for chunk in ips.chunks(args.concurrency.max(1)) {
        let results: Vec<Option<ScanHit>> = std::thread::scope(|s| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|&ip| s.spawn(move || probe_reality_target(ip, args.port, timeout)))
                .collect();
            handles.into_iter().filter_map(|h| h.join().ok()).collect()
        });
        for hit in results.into_iter().flatten() {
            hits += 1;
            let h2 = if hit.alpn == "h2" { "h2 ✓" } else { &hit.alpn };
            let sans = if hit.sans.is_empty() {
                "<no SAN>".to_string()
            } else {
                hit.sans.join(", ")
            };
            println!("{}:{}  TLS1.3 X25519 {}  SAN: {}", hit.ip, args.port, h2, sans);
        }
    }
    eprintln!("# done — {hits} REALITY-suitable host(s). Validate a pick with `tls-ping`.");
    Ok(())
}

/// Expand an IPv4 `a.b.c.d/prefix` (or bare IP = /32) into host addresses.
/// Capped at 65536 hosts (prefix >= 16) to keep scans bounded.
fn parse_cidr_v4(s: &str) -> anyhow::Result<Vec<std::net::Ipv4Addr>> {
    let (ip_str, prefix) = match s.split_once('/') {
        Some((i, p)) => (i, p.parse::<u32>()?),
        None => (s, 32),
    };
    let ip: std::net::Ipv4Addr = ip_str.parse()?;
    anyhow::ensure!((16..=32).contains(&prefix), "prefix must be /16../32 (bounded scan)");
    let bits = 32 - prefix;
    let mask = if bits == 32 { 0 } else { u32::MAX << bits };
    let base = u32::from(ip) & mask;
    let count = 1u32 << bits;
    Ok((0..count)
        .map(|i| std::net::Ipv4Addr::from(base + i))
        .collect())
}

/// Probe a REALITY masquerade candidate (the donut analogue of `xray tls
/// ping`). A successful TLS 1.3 handshake offering ONLY X25519 proves the
/// target meets the REALITY minimum; the cert SANs become `serverNames`.
fn tls_ping(target: &str) -> anyhow::Result<()> {
    use std::net::TcpStream;
    use std::sync::Arc;

    use rustls::pki_types::ServerName;

    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse::<u16>()?)
        }
        _ => (target.to_string(), 443u16),
    };

    // Offer ONLY X25519: a completed TLS 1.3 handshake then proves the target
    // supports the REALITY minimum (TLS 1.3 + X25519) in one shot.
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .kx_groups
        .retain(|g| g.name() == rustls::NamedGroup::X25519);

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let server_name = ServerName::try_from(host.clone())?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    let mut sock = TcpStream::connect((host.as_str(), port))?;
    conn.complete_io(&mut sock)?;

    println!("# tls-ping {host}:{port}");
    println!("tls_version: {:?}", conn.protocol_version());
    println!("x25519: yes (TLS 1.3 handshake completed with X25519-only)");
    if let Some(cs) = conn.negotiated_cipher_suite() {
        println!("cipher: {:?}", cs.suite());
    }
    match conn.alpn_protocol() {
        Some(b"h2") => println!("alpn: h2 (HTTP/2 — good for REALITY)"),
        Some(p) => println!("alpn: {} (h2 preferred)", String::from_utf8_lossy(p)),
        None => println!("alpn: none (h2 preferred — target may not offer HTTP/2)"),
    }

    if let Some(leaf) = conn.peer_certificates().and_then(|c| c.first()) {
        println!("leaf_cert_size: {} bytes", leaf.as_ref().len());
        let sans = cert_san_dns(leaf.as_ref());
        println!(
            "serverNames (cert SANs): {}",
            if sans.is_empty() {
                "<none>".to_string()
            } else {
                sans.join(", ")
            }
        );
    }

    println!();
    println!("# REALITY suitability:");
    println!("#  [auto] TLS 1.3 + X25519 .......... PASS");
    println!("#  [manual] same ASN as your VPS (steal a datacenter-neighbour's cert)");
    println!("#  [manual] NOT behind a CDN you don't control (e.g. Cloudflare)");
    println!("#  [manual] foreign, stable, popular; use a SAN above as serverName/sni");
    Ok(())
}

/// Mint a per-device VLESS credential: a fresh UUID, a registry line for the
/// declarative device list, and (when REALITY params are supplied) a ready
/// donut-client config so the device can connect to the cascade entry.
fn device_add(args: &DeviceAddArgs) -> anyhow::Result<()> {
    let uuid = donut_core::UserId::new_v4().to_string();

    println!("# device: {}", args.name);
    println!("uuid: {uuid}");
    println!();
    println!("# add this line to your declarative device registry (devices.json):");
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({ "name": args.name, "uuid": uuid }))?
    );

    // Emit a client.json only when the entry's REALITY identity is known.
    let (Some(server), Some(pub_key), Some(short_id)) =
        (&args.server, &args.reality_pub, &args.short_id)
    else {
        println!();
        println!(
            "# (pass --server --reality-pub --short-id to also emit a donut-client client.json)"
        );
        return Ok(());
    };

    let outbound = ClientOutbound {
        server: server.clone(),
        uuid: uuid.clone(),
        transport: "veil".into(),
        reality: Some(RealityClient {
            public_key: pub_key.clone(),
            short_id: short_id.clone(),
            server_name: args.sni.clone(),
            version: [26, 4, 15],
            fingerprint: args.fp.clone(),
        }),
        server_name: String::new(),
        path: "/".into(),
        mode: "stream-one".into(),
        flow: "none".into(),
    };
    let client = ClientConfig {
        log: Default::default(),
        inbound: ClientInbound {
            socks: args.socks.clone(),
        },
        outbound,
        routing: RoutingConfig {
            default: "proxy".to_string(),
            rules: Vec::new(),
        },
        geo: Default::default(),
        dns: Default::default(),
    };
    println!();
    println!("// ===== client.json (device: {}) =====", args.name);
    println!("{}", serde_json::to_string_pretty(&client)?);
    Ok(())
}

/// Generate admin Basic-Auth credentials: an Argon2 PHC password hash plus a
/// `[metrics]` config snippet. The cleartext password is shown once.
fn admin_passwd(args: &AdminPasswdArgs) -> anyhow::Result<()> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::Argon2;

    let (password, generated) = match &args.password {
        Some(p) => (p.clone(), false),
        None => (random_password(24), true),
    };

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?
        .to_string();

    if generated {
        println!("# generated password (shown ONCE — copy it now):");
        println!("password: {password}");
        println!();
    }
    println!("# paste into the server config [metrics] section:");
    println!("[metrics]");
    println!("listen = \"127.0.0.1:9090\"   # bind to loopback / WireGuard, never 0.0.0.0");
    println!("username = \"{}\"", args.user);
    println!("password_hash = \"{hash}\"");
    println!();
    println!("# Prometheus scrape (basic_auth):");
    println!("#   basic_auth: {{ username: {}, password: <the password above> }}", args.user);
    Ok(())
}

/// A random alphanumeric password of `len` characters (CSPRNG).
fn random_password(len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

/// Generate a fresh X25519 keypair + an 8-byte ShortID, printing them
/// in the base64-url (xray-compatible) form the configs expect.
fn keygen() {
    let (private, public) = gen_keypair();
    let short_id = rand::random::<[u8; 8]>();

    println!("# donut REALITY keypair (X25519, base64-url)");
    println!();
    println!(
        "private_key (server config): {}",
        BASE64_URL_SAFE_NO_PAD.encode(private)
    );
    println!(
        "public_key  (client config): {}",
        BASE64_URL_SAFE_NO_PAD.encode(public)
    );
    println!("short_id    (both configs):  {}", hex::encode(short_id));
}

/// Build and print the deploy artifacts for the requested transport.
///
/// - `raw` (Xray-interop): the server config + a `vless://` link to paste into
///   off-the-shelf App Store clients (no donut-client config — those clients
///   speak the protocol directly).
/// - `veil`/`tls`/`quic`: a matching server + donut-client config pair (those
///   transports use our own framing, so they need the donut-client).
fn config_gen(args: &ConfigGenArgs) -> anyhow::Result<()> {
    if args.transport == TransportKind::Raw {
        let (server, uuid) = raw_server(args);
        let label = format!("donut-{}", host_of(&args.server_addr));
        let link = vless_link(
            &uuid,
            &args.server_addr,
            &args.server_name,
            "chrome",
            "xtls-rprx-vision",
            &label,
        );
        println!("// ===== server.json =====");
        println!("{}", serde_json::to_string_pretty(&server)?);
        println!();
        println!("// ===== share link (paste into HAPP / Streisand / v2box / etc.) =====");
        println!("{link}");
        return Ok(());
    }

    if args.transport == TransportKind::Xhttp {
        use donut_config::subgen::{self, RoutingProfile};
        let (server, uuid, path, host, mode) = xhttp_server(args);
        let p = subgen::XhttpParams {
            uuid,
            server_addr: args.server_addr.clone(),
            sni: args.server_name.clone(),
            host,
            path,
            mode: mode.to_string(),
            fp: args.fp.clone(),
            socks: args.socks.clone(),
            label: format!("donut-xhttp-{}", host_of(&args.server_addr)),
        };
        println!("// ===== server.json =====");
        println!("{}", serde_json::to_string_pretty(&server)?);
        println!();
        println!("// ===== share link (paste into HAPP / Streisand / v2box / etc.) =====");
        println!("{}", subgen::vless_xhttp_link(&p));
        println!();
        println!(
            "// ===== xray client.json (fp={}, XMUX + pure-XUDP mux, RU split-tunnel) =====",
            args.fp
        );
        println!(
            "{}",
            serde_json::to_string_pretty(&subgen::xray_client_json(&p, RoutingProfile::RuSplit))?
        );
        println!();
        println!("// ===== clash.yaml (mihomo, experimental xHTTP) =====");
        println!("{}", subgen::clash_yaml(&p, RoutingProfile::RuSplit));
        return Ok(());
    }

    let (server, client) = generate_pair(args);
    println!("// ===== server.json =====");
    println!("{}", serde_json::to_string_pretty(&server)?);
    println!();
    println!("// ===== client.json =====");
    println!("{}", serde_json::to_string_pretty(&client)?);
    Ok(())
}

/// Cert-based RAW server speaking **faithful Xray Vision** (`vision:"xray"`).
/// Returns the server config and the fresh user UUID (for the share link).
/// There is no paired donut-client: this transport targets off-the-shelf
/// clients, which connect with just the `vless://` link.
fn raw_server(args: &ConfigGenArgs) -> (ServerConfig, String) {
    let uuid = donut_core::UserId::new_v4().to_string();
    let inbound = ServerInbound {
        listen: args.listen.clone(),
        transport: "raw".into(),
        users: vec![uuid.clone()],
        reality: None,
        path: "/".into(),
        cert: Some(args.cert.clone()),
        key: Some(args.key.clone()),
        dest: Some(args.dest.clone()),
        mode: "stream-one".into(),
        vision: "xray".into(),
        host: None,
    };
    (server_config(inbound), uuid)
}

/// Cert-based **Xray-compatible xHTTP** server (`transport="xhttp"`, TLS+H2).
/// Returns the server config, the fresh user UUID, the secret path, the
/// pinned host, and the effective framing mode — everything the share link
/// needs. Like [`raw_server`] there is no paired donut-client: this targets
/// off-the-shelf clients (HAPP, Xray), which connect from the `vless://` link.
fn xhttp_server(args: &ConfigGenArgs) -> (ServerConfig, String, String, String, &'static str) {
    let path = args
        .path
        .clone()
        .unwrap_or_else(|| format!("/donut-{}", hex::encode(rand::random::<[u8; 8]>())));
    let uuid = donut_core::UserId::new_v4().to_string();
    let host = args
        .host
        .clone()
        .unwrap_or_else(|| args.server_name.clone());
    // xHTTP's canonical mode is stream-up; treat the global stream-one default
    // as unset so the server config and the share link agree (the server's
    // xhttp arm makes the same substitution).
    let mode = match args.carrier_mode {
        CarrierMode::StreamOne => "stream-up",
        other => other.as_str(),
    };

    let inbound = ServerInbound {
        listen: args.listen.clone(),
        transport: "xhttp".into(),
        users: vec![uuid.clone()],
        reality: None,
        path: path.clone(),
        cert: Some(args.cert.clone()),
        key: Some(args.key.clone()),
        dest: Some(args.dest.clone()),
        mode: mode.into(),
        vision: "donut".into(),
        host: Some(host.clone()),
    };
    (server_config(inbound), uuid, path, host, mode)
}

/// Build a standard `vless://` share URI:
/// `vless://UUID@host:port?type=tcp&security=tls&sni=..&fp=..&alpn=http/1.1&flow=..#label`
fn vless_link(uuid: &str, addr: &str, sni: &str, fp: &str, flow: &str, label: &str) -> String {
    let mut params: Vec<(&str, &str)> = vec![
        ("type", "tcp"),
        ("security", "tls"),
        ("sni", sni),
        ("fp", fp),
        ("alpn", "http/1.1"),
    ];
    if !flow.is_empty() && flow != "none" {
        params.push(("flow", flow));
    }
    let query = params
        .iter()
        .map(|(k, v)| format!("{k}={}", pct(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("vless://{uuid}@{addr}?{query}#{}", pct(label))
}

/// Host portion of a `host:port` address (for a default link label).
fn host_of(addr: &str) -> String {
    addr.rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(addr)
        .to_string()
}

/// Percent-encode an RFC 3986 query/fragment value (encode everything that
/// isn't an unreserved character).
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Produce a matching `(ServerConfig, ClientConfig)` for the requested
/// transport. REALITY pairs share a fresh keypair + ShortID; cert-based
/// pairs share a secret path.
fn generate_pair(args: &ConfigGenArgs) -> (ServerConfig, ClientConfig) {
    match args.transport {
        TransportKind::Veil => veil_pair(args),
        TransportKind::Tls => cert_pair(args, "tls", "xhttp", args.carrier_mode.as_str()),
        // QUIC/H3 ignore the carrier mode; pin it to the default.
        TransportKind::Quic => cert_pair(args, "quic", "h3", "stream-one"),
        // RAW and XHTTP emit a server + share-link (no donut-client),
        // handled directly in config_gen before this is reached.
        TransportKind::Raw => unreachable!("raw transport is handled by raw_server"),
        TransportKind::Xhttp => unreachable!("xhttp transport is handled by xhttp_server"),
    }
}

/// REALITY pair: server holds the private key, client the public; one
/// shared ShortID. The cert/key authenticate the selfsteal backdrop.
fn veil_pair(args: &ConfigGenArgs) -> (ServerConfig, ClientConfig) {
    let (private, public) = gen_keypair();
    let short_id = hex::encode(rand::random::<[u8; 8]>());
    let uuid = donut_core::UserId::new_v4().to_string();

    let inbound = ServerInbound {
        listen: args.listen.clone(),
        transport: "veil".into(),
        users: vec![uuid.clone()],
        reality: Some(RealityServer {
            private_key: BASE64_URL_SAFE_NO_PAD.encode(private),
            short_ids: vec![short_id.clone()],
            dest: args.dest.clone(),
            cert: args.cert.clone(),
            key: args.key.clone(),
            anti_replay_skew_secs: None,
        }),
        path: "/".into(),
        cert: None,
        key: None,
        dest: None,
        mode: "stream-one".into(),
        vision: "donut".into(),
        host: None,
    };

    let outbound = ClientOutbound {
        server: args.server_addr.clone(),
        uuid,
        transport: "veil".into(),
        reality: Some(RealityClient {
            public_key: BASE64_URL_SAFE_NO_PAD.encode(public),
            short_id,
            server_name: args.server_name.clone(),
            version: [26, 4, 15],
            fingerprint: "randomized".into(),
        }),
        server_name: String::new(),
        path: "/".into(),
        mode: "stream-one".into(),
        flow: "none".into(),
    };

    (server_config(inbound), client_config(args, outbound))
}

/// Cert-based carrier pair (no REALITY): donut terminates TLS/H3 itself.
/// A fresh secret path is routed to the tunnel; everything else
/// self-steals to the decoy `dest`.
fn cert_pair(
    args: &ConfigGenArgs,
    server_transport: &str,
    client_transport: &str,
    mode: &str,
) -> (ServerConfig, ClientConfig) {
    let path = args
        .path
        .clone()
        .unwrap_or_else(|| format!("/donut-{}", hex::encode(rand::random::<[u8; 4]>())));
    let uuid = donut_core::UserId::new_v4().to_string();

    let inbound = ServerInbound {
        listen: args.listen.clone(),
        transport: server_transport.into(),
        users: vec![uuid.clone()],
        reality: None,
        path: path.clone(),
        cert: Some(args.cert.clone()),
        key: Some(args.key.clone()),
        dest: Some(args.dest.clone()),
        mode: mode.into(),
        vision: "donut".into(),
        host: None,
    };

    let outbound = ClientOutbound {
        server: args.server_addr.clone(),
        uuid,
        transport: client_transport.into(),
        reality: None,
        server_name: args.server_name.clone(),
        path,
        mode: mode.into(),
        flow: "none".into(),
    };

    (server_config(inbound), client_config(args, outbound))
}

/// Wrap an inbound in a full server config (default routing/geo/dns).
fn server_config(inbound: ServerInbound) -> ServerConfig {
    ServerConfig {
        log: Default::default(),
        inbound,
        routing: Default::default(),
        geo: Default::default(),
        dns: Default::default(),
        metrics: Default::default(),
        subscription: Default::default(),
        tuning: Default::default(),
        outbounds: Vec::new(),
        fragment: None,
    }
}

/// Wrap an outbound in a full client config. Defaults to proxying
/// everything; users add `direct` geoip/geosite rules for split-tunnel
/// (see docs/examples/client.json).
fn client_config(args: &ConfigGenArgs, outbound: ClientOutbound) -> ClientConfig {
    ClientConfig {
        log: Default::default(),
        inbound: ClientInbound {
            socks: args.socks.clone(),
        },
        outbound,
        routing: RoutingConfig {
            default: "proxy".to_string(),
            rules: Vec::new(),
        },
        geo: Default::default(),
        dns: Default::default(),
    }
}

/// Pure keypair generation: returns `(private_bytes, public_bytes)`.
fn gen_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), *public.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_for(transport: TransportKind) -> ConfigGenArgs {
        ConfigGenArgs {
            transport,
            ..Default::default()
        }
    }

    #[test]
    fn public_key_derives_from_private() {
        let (private, public) = gen_keypair();
        let rederived = PublicKey::from(&StaticSecret::from(private));
        assert_eq!(rederived.as_bytes(), &public);
    }

    #[test]
    fn veil_pair_is_consistent_and_parses() {
        let (server, client) = generate_pair(&args_for(TransportKind::Veil));

        assert_eq!(server.inbound.transport, "veil");
        assert_eq!(client.outbound.transport, "veil");

        let server_reality = server.inbound.reality.as_ref().unwrap();
        let client_reality = client.outbound.reality.as_ref().unwrap();

        // Server's private key derives the client's public key.
        let priv_bytes = donut_config::parse_x25519(&server_reality.private_key).unwrap();
        let pub_bytes = donut_config::parse_x25519(&client_reality.public_key).unwrap();
        let derived = PublicKey::from(&StaticSecret::from(priv_bytes));
        assert_eq!(derived.as_bytes(), &pub_bytes);

        // Shared ShortID.
        assert_eq!(server_reality.short_ids[0], client_reality.short_id);

        assert_shared_uuid(&server, &client);
        assert_round_trips(&server, &client);
    }

    #[test]
    fn tls_pair_is_cert_based_and_parses() {
        let mut args = args_for(TransportKind::Tls);
        args.carrier_mode = CarrierMode::PacketUp;
        let (server, client) = generate_pair(&args);

        assert_eq!(server.inbound.transport, "tls");
        assert_eq!(client.outbound.transport, "xhttp");

        // No REALITY on either side.
        assert!(server.inbound.reality.is_none());
        assert!(client.outbound.reality.is_none());

        // Cert/key/decoy materialised server-side.
        assert_eq!(server.inbound.cert.as_deref(), Some(args.cert.as_str()));
        assert_eq!(server.inbound.key.as_deref(), Some(args.key.as_str()));
        assert_eq!(server.inbound.dest.as_deref(), Some(args.dest.as_str()));

        // Shared secret path + mode.
        assert_eq!(server.inbound.path, client.outbound.path);
        assert_eq!(server.inbound.mode, "packet-up");
        assert_eq!(client.outbound.mode, "packet-up");
        assert_eq!(client.outbound.server_name, args.server_name);

        assert_shared_uuid(&server, &client);
        assert_round_trips(&server, &client);
    }

    #[test]
    fn quic_pair_is_cert_based_and_parses() {
        let (server, client) = generate_pair(&args_for(TransportKind::Quic));

        assert_eq!(server.inbound.transport, "quic");
        assert_eq!(client.outbound.transport, "h3");

        assert!(server.inbound.reality.is_none());
        assert!(client.outbound.reality.is_none());

        assert_eq!(
            server.inbound.cert.as_deref(),
            Some("/etc/donut/fullchain.pem")
        );
        assert_eq!(server.inbound.dest.as_deref(), Some("127.0.0.1:8443"));
        assert_eq!(server.inbound.path, client.outbound.path);

        assert_round_trips(&server, &client);
    }

    #[test]
    fn raw_server_is_vision_xray_and_link_is_wellformed() {
        let args = args_for(TransportKind::Raw);
        let (server, uuid) = raw_server(&args);
        assert_eq!(server.inbound.transport, "raw");
        assert_eq!(server.inbound.vision, "xray");
        assert!(server.inbound.reality.is_none());
        assert_eq!(server.inbound.users, vec![uuid.clone()]);
        // The generated UUID authenticates against the server's user set.
        let auth = server.inbound.user_auth().unwrap();
        assert!(auth.is_authorized(&uuid.parse().unwrap()));

        let link = vless_link(
            &uuid,
            &args.server_addr,
            &args.server_name,
            "chrome",
            "xtls-rprx-vision",
            "donut",
        );
        assert!(link.starts_with(&format!("vless://{uuid}@203.0.113.1:443?")));
        assert!(link.contains("security=tls"));
        assert!(link.contains("flow=xtls-rprx-vision"));
        assert!(link.contains("type=tcp"));
        assert!(link.contains("alpn=http%2F1.1")); // '/' percent-encoded
        assert!(link.ends_with("#donut"));
    }

    #[test]
    fn link_omits_flow_when_none() {
        let link = vless_link("u", "h:443", "sni.example", "chrome", "none", "lbl");
        assert!(!link.contains("flow="));
    }

    #[test]
    fn xhttp_server_is_host_pinned_and_link_is_wellformed() {
        let mut args = args_for(TransportKind::Xhttp);
        args.server_name = "edge.example".into();
        // Default carrier_mode is stream-one → must surface as stream-up.
        let (server, uuid, path, host, mode) = xhttp_server(&args);

        assert_eq!(server.inbound.transport, "xhttp");
        assert_eq!(server.inbound.mode, "stream-up");
        assert_eq!(mode, "stream-up");
        assert!(server.inbound.reality.is_none());
        // Host pin defaults to the SNI and is carried into the config.
        assert_eq!(host, "edge.example");
        assert_eq!(server.inbound.host.as_deref(), Some("edge.example"));
        // Cert/key/decoy + a fresh secret path materialised server-side.
        assert_eq!(server.inbound.cert.as_deref(), Some(args.cert.as_str()));
        assert_eq!(server.inbound.dest.as_deref(), Some(args.dest.as_str()));
        assert!(path.starts_with("/donut-"));
        // The generated UUID authenticates against the server's user set.
        let auth = server.inbound.user_auth().unwrap();
        assert!(auth.is_authorized(&uuid.parse().unwrap()));

        let link = donut_config::subgen::vless_xhttp_link(&donut_config::subgen::XhttpParams {
            uuid: uuid.clone(),
            server_addr: args.server_addr.clone(),
            sni: args.server_name.clone(),
            host: host.clone(),
            path: path.clone(),
            mode: mode.to_string(),
            fp: "chrome".into(),
            socks: args.socks.clone(),
            label: "donut-xhttp".into(),
        });
        assert!(link.starts_with(&format!("vless://{uuid}@203.0.113.1:443?")));
        assert!(link.contains("type=xhttp"));
        assert!(link.contains("security=tls"));
        assert!(link.contains("encryption=none"));
        assert!(link.contains("mode=stream-up"));
        assert!(link.contains("host=edge.example"));
        assert!(link.contains("alpn=h2"));
        // The secret path is percent-encoded ('/' → %2F).
        assert!(link.contains(&format!("path={}", pct(&path))));
        assert!(link.contains("path=%2Fdonut-"));
        assert!(link.ends_with("#donut-xhttp"));
    }

    // The xray client.json shape (firefox fp, XMUX, pure-XUDP mux, RU
    // split-tunnel) is covered by `donut_config::subgen` unit tests.

    #[test]
    fn xhttp_explicit_host_and_mode_are_honoured() {
        let mut args = args_for(TransportKind::Xhttp);
        args.host = Some("front.cdn.example".into());
        args.carrier_mode = CarrierMode::PacketUp;
        let (server, _uuid, _path, host, mode) = xhttp_server(&args);
        assert_eq!(host, "front.cdn.example");
        assert_eq!(server.inbound.host.as_deref(), Some("front.cdn.example"));
        assert_eq!(mode, "packet-up");
        assert_eq!(server.inbound.mode, "packet-up");
    }

    #[test]
    fn explicit_path_is_shared_by_both_sides() {
        let mut args = args_for(TransportKind::Tls);
        args.path = Some("/secret-tunnel".into());
        let (server, client) = generate_pair(&args);
        assert_eq!(server.inbound.path, "/secret-tunnel");
        assert_eq!(client.outbound.path, "/secret-tunnel");
    }

    /// The client's credential is materialisable and accepted by the
    /// server's allowed-user set — config-gen must produce a pair that
    /// actually authenticates.
    fn assert_shared_uuid(server: &ServerConfig, client: &ClientConfig) {
        let auth = server
            .inbound
            .user_auth()
            .expect("server users materialise");
        let user = client.outbound.user_id().expect("client uuid materialises");
        assert!(
            auth.is_authorized(&user),
            "generated client UUID must be in the server's allowed set",
        );
    }

    /// Both halves serialise and round-trip back through the loader types.
    fn assert_round_trips(server: &ServerConfig, client: &ClientConfig) {
        let s_json = serde_json::to_string(server).unwrap();
        let _: ServerConfig = serde_json::from_str(&s_json).unwrap();
        let c_json = serde_json::to_string(client).unwrap();
        let _: ClientConfig = serde_json::from_str(&c_json).unwrap();
    }
}
