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
    /// `packet-up`). Ignored by `veil`/`quic`.
    #[arg(long, value_enum, default_value = "stream-one")]
    carrier_mode: CarrierMode,
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
    }
    Ok(())
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

/// Build and print a consistent server + client config pair.
fn config_gen(args: &ConfigGenArgs) -> anyhow::Result<()> {
    let (server, client) = generate_pair(args);
    println!("// ===== server.json =====");
    println!("{}", serde_json::to_string_pretty(&server)?);
    println!();
    println!("// ===== client.json =====");
    println!("{}", serde_json::to_string_pretty(&client)?);
    Ok(())
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
        }),
        path: "/".into(),
        cert: None,
        key: None,
        dest: None,
        mode: "stream-one".into(),
        vision: "donut".into(),
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

        assert_eq!(server.inbound.cert.as_deref(), Some("/etc/donut/fullchain.pem"));
        assert_eq!(server.inbound.dest.as_deref(), Some("127.0.0.1:8443"));
        assert_eq!(server.inbound.path, client.outbound.path);

        assert_round_trips(&server, &client);
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
        let auth = server.inbound.user_auth().expect("server users materialise");
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
