//! donut-server — edge daemon entry point.
//!
//! Loads a JSON config (see `donut-config`), materialises the REALITY
//! parameters + selfsteal cert, and runs the veiled proxy until a
//! shutdown signal arrives.

use std::net::SocketAddr;

use anyhow::Context;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "donut-server", version, about = "hold-the-donut edge daemon")]
struct Args {
    /// Path to JSON config.
    #[arg(short, long, default_value = "/etc/donut/server.json")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = donut_config::load_server(&args.config)
        .with_context(|| format!("loading server config {}", args.config))?;

    init_tracing(&cfg.log.level);

    let listen: SocketAddr = cfg
        .inbound
        .listen
        .parse()
        .with_context(|| format!("parsing inbound.listen {}", cfg.inbound.listen))?;
    let dest: SocketAddr = cfg
        .inbound
        .reality
        .dest
        .parse()
        .with_context(|| format!("parsing reality.dest {}", cfg.inbound.reality.dest))?;

    let private_key = cfg.inbound.reality.private_key_bytes()?;
    let short_ids = cfg.inbound.reality.short_id_set()?;
    let veil = donut_veil::VeilServerConfig::new(private_key, short_ids)
        .context("building REALITY server config")?;
    let cert_chain = cfg.inbound.reality.cert_chain()?;
    let key = cfg.inbound.reality.private_key_pem()?;
    let router = std::sync::Arc::new(cfg.router()?);
    let resolver = std::sync::Arc::new(cfg.resolver()?);
    let metrics = donut_server::Metrics::new();

    // Optional Prometheus /metrics endpoint on its own listener.
    if let Some(addr) = &cfg.metrics.listen {
        let maddr: SocketAddr = addr
            .parse()
            .with_context(|| format!("parsing metrics.listen {addr}"))?;
        let listener = tokio::net::TcpListener::bind(maddr)
            .await
            .with_context(|| format!("binding metrics listener {maddr}"))?;
        tracing::info!(%maddr, "metrics endpoint listening on /metrics");
        tokio::spawn(donut_server::metrics::serve(listener, metrics.clone()));
    }

    let bound = donut_server::run_veil_proxy(
        listen, cert_chain, key, veil, dest, router, resolver, metrics,
    )
    .await
    .context("starting veil proxy")?;
    tracing::info!(%bound, %dest, "donut-server listening (VLESS+REALITY+XHTTP)");

    shutdown_signal().await;
    tracing::info!("donut-server shutting down");
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
