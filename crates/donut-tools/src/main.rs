//! donut-tools — ops CLI: key generation, config helpers, peer probe.
//!
//! `keygen` and `config-gen` are implemented (M6/M9); `probe` lands later.

use base64::prelude::*;
use clap::{Args, Parser, Subcommand};
use donut_config::{
    ClientConfig, ClientInbound, ClientOutbound, RealityClient, RealityServer, ServerConfig,
    ServerInbound,
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

/// Parameters for `config-gen`. Sensible defaults; override per deploy.
#[derive(Debug, Clone, Args)]
struct ConfigGenArgs {
    /// SNI / decoy domain the client presents (your selfsteal domain).
    #[arg(long, default_value = "www.microsoft.com")]
    server_name: String,
    /// Public address the client dials (`host:port`).
    #[arg(long, default_value = "203.0.113.1:443")]
    server_addr: String,
    /// Server listen address.
    #[arg(long, default_value = "0.0.0.0:443")]
    listen: String,
    /// Selfsteal backdrop the server forwards unauthenticated callers to.
    #[arg(long, default_value = "127.0.0.1:8443")]
    dest: String,
    /// Local SOCKS5 listen address on the client.
    #[arg(long, default_value = "127.0.0.1:1080")]
    socks: String,
    /// Server TLS cert chain path (PEM).
    #[arg(long, default_value = "/etc/donut/fullchain.pem")]
    cert: String,
    /// Server TLS private key path (PEM).
    #[arg(long, default_value = "/etc/donut/privkey.pem")]
    key: String,
}

#[cfg(test)]
impl Default for ConfigGenArgs {
    fn default() -> Self {
        Self {
            server_name: "www.microsoft.com".into(),
            server_addr: "203.0.113.1:443".into(),
            listen: "0.0.0.0:443".into(),
            dest: "127.0.0.1:8443".into(),
            socks: "127.0.0.1:1080".into(),
            cert: "/etc/donut/fullchain.pem".into(),
            key: "/etc/donut/privkey.pem".into(),
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

/// Produce a matching `(ServerConfig, ClientConfig)`: one fresh keypair
/// (server holds the private key, client the public), one shared ShortID.
fn generate_pair(args: &ConfigGenArgs) -> (ServerConfig, ClientConfig) {
    let (private, public) = gen_keypair();
    let short_id = hex::encode(rand::random::<[u8; 8]>());

    let server = ServerConfig {
        log: Default::default(),
        inbound: ServerInbound {
            listen: args.listen.clone(),
            reality: RealityServer {
                private_key: BASE64_URL_SAFE_NO_PAD.encode(private),
                short_ids: vec![short_id.clone()],
                dest: args.dest.clone(),
                cert: args.cert.clone(),
                key: args.key.clone(),
            },
        },
        routing: Default::default(),
        geo: Default::default(),
        dns: Default::default(),
        metrics: Default::default(),
    };

    let client = ClientConfig {
        log: Default::default(),
        inbound: ClientInbound {
            socks: args.socks.clone(),
        },
        outbound: ClientOutbound {
            server: args.server_addr.clone(),
            reality: RealityClient {
                public_key: BASE64_URL_SAFE_NO_PAD.encode(public),
                short_id,
                server_name: args.server_name.clone(),
                version: [26, 4, 15],
            },
        },
        // Proxy everything by default; users add `direct` geoip/geosite
        // rules for split-tunnel (see docs/examples/client.json).
        routing: donut_config::RoutingConfig {
            default: "proxy".to_string(),
            rules: Vec::new(),
        },
        geo: Default::default(),
        dns: Default::default(),
    };

    (server, client)
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

    #[test]
    fn public_key_derives_from_private() {
        let (private, public) = gen_keypair();
        let rederived = PublicKey::from(&StaticSecret::from(private));
        assert_eq!(rederived.as_bytes(), &public);
    }

    #[test]
    fn config_gen_pair_is_consistent_and_parses() {
        let (server, client) = generate_pair(&ConfigGenArgs::default());

        // Server's private key derives the client's public key.
        let priv_bytes = donut_config::parse_x25519(&server.inbound.reality.private_key).unwrap();
        let pub_bytes = donut_config::parse_x25519(&client.outbound.reality.public_key).unwrap();
        let derived = PublicKey::from(&StaticSecret::from(priv_bytes));
        assert_eq!(derived.as_bytes(), &pub_bytes);

        // Shared ShortID.
        assert_eq!(
            server.inbound.reality.short_ids[0],
            client.outbound.reality.short_id
        );

        // Both serialise and round-trip back through the loader's types.
        let s_json = serde_json::to_string(&server).unwrap();
        let _: ServerConfig = serde_json::from_str(&s_json).unwrap();
        let c_json = serde_json::to_string(&client).unwrap();
        let _: ClientConfig = serde_json::from_str(&c_json).unwrap();
    }
}
