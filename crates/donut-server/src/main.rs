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

    init_tracing(&cfg.log.level, &cfg.log.format);

    let listen: SocketAddr = cfg
        .inbound
        .listen
        .parse()
        .with_context(|| format!("parsing inbound.listen {}", cfg.inbound.listen))?;

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

    match cfg.inbound.transport.as_str() {
        // Cert-based carrier backend behind a TLS/HTTP-3 reverse proxy
        // (e.g. Caddy). No REALITY: the front holds the certificate and
        // does self-steal; only the secret path reaches us.
        "carrier" => {
            let path = cfg.inbound.path.clone();
            let bound =
                donut_server::run_carrier_backend(listen, path.clone(), router, resolver, metrics)
                    .await
                    .context("starting carrier backend")?;
            tracing::info!(%bound, %path, "donut-server listening (carrier backend, cert-based, no REALITY)");
        }
        // Direct QUIC / HTTP-3 termination with a real certificate (no
        // reverse proxy in front). For direct-H3 cases / exercising the
        // server-side QUIC stack with Caddy disabled.
        "quic" => {
            let cert_chain = cfg.inbound.cert_chain()?;
            let key = cfg.inbound.private_key_pem()?;
            let path = cfg.inbound.path.clone();
            let decoy: Option<SocketAddr> = match cfg.inbound.dest.as_deref() {
                Some(d) => Some(
                    d.parse()
                        .with_context(|| format!("parsing inbound.dest {d}"))?,
                ),
                None => None,
            };
            let bound = donut_server::run_quic_proxy(
                listen,
                cert_chain,
                key,
                path.clone(),
                decoy,
                router,
                resolver,
                metrics,
            )
            .await
            .context("starting quic proxy")?;
            tracing::info!(%bound, %path, ?decoy, "donut-server listening (QUIC/HTTP-3, cert-based, self-steal)");
        }
        // Cert-based TLS carrier on TCP: donut-server terminates TLS
        // itself (no reverse proxy in the tunnel path), secret path →
        // full-duplex carrier tunnel, everything else → decoy self-steal.
        "tls" => {
            let cert_chain = cfg.inbound.cert_chain()?;
            let key = cfg.inbound.private_key_pem()?;
            let path = cfg.inbound.path.clone();
            let mode = donut_carrier::Mode::parse(&cfg.inbound.mode)
                .with_context(|| format!("unknown inbound.mode {:?}", cfg.inbound.mode))?;
            let decoy: Option<SocketAddr> = match cfg.inbound.dest.as_deref() {
                Some(d) => Some(
                    d.parse()
                        .with_context(|| format!("parsing inbound.dest {d}"))?,
                ),
                None => None,
            };
            let bound = donut_server::run_tls_carrier_proxy(
                listen,
                cert_chain,
                key,
                path.clone(),
                mode,
                decoy,
                router,
                resolver,
                metrics,
            )
            .await
            .context("starting tls carrier proxy")?;
            tracing::info!(%bound, %path, ?mode, ?decoy, "donut-server listening (TLS carrier, cert-based, self-steal)");
        }
        // Cert-based RAW: VLESS directly over TLS on TCP (no carrier
        // wrapping); first decrypted byte triages VLESS-vs-probe, probes
        // self-steal to `dest` (filebrowser). This is Xray's RAW/TCP
        // analogue and the transport `xtls-rprx-vision` rides on.
        "raw" => {
            let cert_chain = cfg.inbound.cert_chain()?;
            let key = cfg.inbound.private_key_pem()?;
            let decoy: Option<SocketAddr> = match cfg.inbound.dest.as_deref() {
                Some(d) => Some(
                    d.parse()
                        .with_context(|| format!("parsing inbound.dest {d}"))?,
                ),
                None => None,
            };
            let bound =
                donut_server::run_raw_proxy(listen, cert_chain, key, decoy, router, resolver, metrics)
                    .await
                    .context("starting raw proxy")?;
            tracing::info!(%bound, ?decoy, "donut-server listening (RAW VLESS over TLS, cert-based, self-steal)");
        }
        // REALITY veiled-TLS front door + selfsteal forward to `dest`.
        "veil" => {
            let reality = cfg
                .inbound
                .reality
                .as_ref()
                .context("inbound.reality is required for transport=\"veil\"")?;
            let dest: SocketAddr = reality
                .dest
                .parse()
                .with_context(|| format!("parsing reality.dest {}", reality.dest))?;
            let private_key = reality.private_key_bytes()?;
            let short_ids = reality.short_id_set()?;
            let veil = donut_veil::VeilServerConfig::new(private_key, short_ids)
                .context("building REALITY server config")?;
            let cert_chain = reality.cert_chain()?;
            let key = reality.private_key_pem()?;
            let bound = donut_server::run_veil_proxy(
                listen, cert_chain, key, veil, dest, router, resolver, metrics,
            )
            .await
            .context("starting veil proxy")?;
            tracing::info!(%bound, %dest, "donut-server listening (VLESS+REALITY+XHTTP)");
        }
        other => anyhow::bail!(
            "unknown inbound.transport {other:?} (expected \"veil\", \"carrier\", \"quic\", \"tls\" or \"raw\")"
        ),
    }

    shutdown_signal().await;
    tracing::info!("donut-server shutting down");
    Ok(())
}

fn init_tracing(level: &str, format: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    if format.eq_ignore_ascii_case("json") {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
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
