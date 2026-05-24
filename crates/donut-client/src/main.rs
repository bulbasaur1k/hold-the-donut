//! donut-client — local agent entry point.
//!
//! Loads a JSON config (see `donut-config`), materialises the REALITY
//! client parameters + trusted cert, and runs a SOCKS5 listener that
//! tunnels through the veiled REALITY connection to the server.

use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;
use rustls::pki_types::ServerName;

#[derive(Debug, Parser)]
#[command(name = "donut-client", version, about = "hold-the-donut local agent")]
struct Args {
    /// Path to JSON config.
    #[arg(short, long, default_value = "/etc/donut/client.json")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = donut_config::load_client(&args.config)
        .with_context(|| format!("loading client config {}", args.config))?;

    init_tracing(&cfg.log.level);

    let socks: SocketAddr = cfg
        .inbound
        .socks
        .parse()
        .with_context(|| format!("parsing inbound.socks {}", cfg.inbound.socks))?;

    // Resolve the server endpoint (supports host:port and ip:port).
    let server = tokio::net::lookup_host(&cfg.outbound.server)
        .await
        .with_context(|| format!("resolving outbound.server {}", cfg.outbound.server))?
        .next()
        .with_context(|| format!("no addresses for {}", cfg.outbound.server))?;

    let public_key = cfg.outbound.reality.public_key_bytes()?;
    let short_id = cfg.outbound.reality.short_id_value()?;
    let veil_cfg =
        donut_veil::VeilClientConfig::new(public_key, short_id, cfg.outbound.reality.version);
    let server_name = ServerName::try_from(cfg.outbound.reality.server_name.clone())
        .with_context(|| format!("invalid server_name {}", cfg.outbound.reality.server_name))?;

    let router = std::sync::Arc::new(cfg.router()?);
    let resolver = std::sync::Arc::new(cfg.resolver()?);

    let veil_client = donut_client::VeilClient::new(veil_cfg, server_name);
    let bound = donut_client::run_veil_socks_proxy(socks, veil_client, server, router, resolver)
        .await
        .context("starting veil socks proxy")?;
    tracing::info!(%bound, %server, "donut-client SOCKS5 listening (VLESS+REALITY+XHTTP)");

    shutdown_signal().await;
    tracing::info!("donut-client shutting down");
    Ok(())
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
