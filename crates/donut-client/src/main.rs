//! donut-client — local agent entry point.
//!
//! Loads a JSON config (see `donut-config`), materialises the REALITY
//! client parameters + trusted cert, and runs a SOCKS5 listener that
//! tunnels through the veiled REALITY connection to the server.

use std::net::SocketAddr;

use anyhow::Context;
use clap::{Parser, Subcommand};
use rustls::pki_types::ServerName;

mod download;
mod imports;
mod link;

#[derive(Debug, Parser)]
#[command(name = "donut-client", version, about = "hold-the-donut local agent")]
struct Cli {
    /// Path to config (JSON or TOML). Used in run mode (no subcommand).
    #[arg(short, long, default_value = "/etc/donut/client.json")]
    config: String,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the SOCKS5 proxy (the default when no subcommand is given).
    Run,
    /// Import a `vless://` link into a ready-to-use client config (TOML),
    /// with Russia→direct split-tunnel rules on by default.
    Import(imports::ImportArgs),
    /// Download geoip.dat + geosite.dat for split-tunnel routing.
    GeoUpdate(imports::GeoArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Import(args)) => return imports::cmd_import(args),
        Some(Cmd::GeoUpdate(args)) => return imports::cmd_geo_update(args).await,
        None | Some(Cmd::Run) => {}
    }
    run(&cli.config).await
}

async fn run(config: &str) -> anyhow::Result<()> {
    let cfg = donut_config::load_client(config)
        .with_context(|| format!("loading client config {config}"))?;

    init_tracing(&cfg.log.level, &cfg.log.format);

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

    let router = std::sync::Arc::new(cfg.router()?);
    let resolver = std::sync::Arc::new(cfg.resolver()?);

    // The VLESS credential presented on every inner frame. Required —
    // the server drops sessions whose UUID is not in its `inbound.users`.
    let user = cfg
        .outbound
        .user_id()
        .context("materialising outbound.uuid")?;

    match cfg.outbound.transport.as_str() {
        // REALITY veiled-TLS over TCP.
        "veil" => {
            let reality = cfg
                .outbound
                .reality
                .as_ref()
                .context("outbound.reality is required for transport=\"veil\"")?;
            let public_key = reality.public_key_bytes()?;
            let short_id = reality.short_id_value()?;
            let fingerprint = reality
                .fingerprint
                .parse::<donut_veil::Fingerprint>()
                .with_context(|| format!("parsing fingerprint {:?}", reality.fingerprint))?;
            let veil_cfg = donut_veil::VeilClientConfig::new(public_key, short_id, reality.version)
                .with_fingerprint(fingerprint);
            let server_name = ServerName::try_from(reality.server_name.clone())
                .with_context(|| format!("invalid server_name {}", reality.server_name))?;
            let veil_client = donut_client::VeilClient::new(veil_cfg, server_name);
            let bound = donut_client::run_veil_socks_proxy(
                socks,
                veil_client,
                server,
                user,
                router,
                resolver,
            )
            .await
            .context("starting veil socks proxy")?;
            tracing::info!(%bound, %server, "donut-client SOCKS5 listening (VLESS+REALITY+XHTTP/TCP)");
        }
        // Cert-based XHTTP over plain TLS to a reverse-proxy front.
        "xhttp" => {
            let name = cert_server_name(&cfg.outbound)?;
            let server_name = ServerName::try_from(name.clone())
                .with_context(|| format!("invalid server_name {name}"))?;
            let mode = donut_carrier::Mode::parse(&cfg.outbound.mode)
                .with_context(|| format!("unknown outbound.mode {:?}", cfg.outbound.mode))?;
            let xhttp =
                donut_client::XhttpClient::new(server_name, cfg.outbound.path.clone(), mode);
            let bound =
                donut_client::run_xhttp_socks_proxy(socks, xhttp, server, user, router, resolver)
                    .await
                    .context("starting xhttp socks proxy")?;
            tracing::info!(%bound, %server, path = %cfg.outbound.path, ?mode, "donut-client SOCKS5 listening (XHTTP/TLS, cert-based)");
        }
        // Cert-based XHTTP over HTTP/3 (full-duplex QUIC carrier).
        "h3" => {
            let name = cert_server_name(&cfg.outbound)?;
            let h3 = donut_client::H3Client::new(name, cfg.outbound.path.clone());
            let bound = donut_client::run_h3_socks_proxy(socks, h3, server, user, router, resolver)
                .await
                .context("starting h3 socks proxy")?;
            tracing::info!(%bound, %server, path = %cfg.outbound.path, "donut-client SOCKS5 listening (XHTTP over HTTP/3, cert-based)");
        }
        // Cert-based RAW: VLESS straight over TLS (no carrier), Xray
        // RAW/TCP analogue; the transport `xtls-rprx-vision` rides on.
        "raw" => {
            let name = cert_server_name(&cfg.outbound)?;
            let server_name = ServerName::try_from(name.clone())
                .with_context(|| format!("invalid server_name {name}"))?;
            let flow = donut_core::FlowKind::from_wire(&cfg.outbound.flow)
                .with_context(|| format!("unknown outbound.flow {:?}", cfg.outbound.flow))?;
            let raw = donut_client::RawClient::new(server_name);
            let bound =
                donut_client::run_raw_socks_proxy(socks, raw, server, user, router, resolver, flow)
                    .await
                    .context("starting raw socks proxy")?;
            tracing::info!(%bound, %server, ?flow, "donut-client SOCKS5 listening (RAW VLESS over TLS, cert-based)");
        }
        other => anyhow::bail!(
            "unknown outbound.transport {other:?} (expected \"veil\", \"xhttp\", \"h3\" or \"raw\")"
        ),
    }

    shutdown_signal().await;
    tracing::info!("donut-client shutting down");
    Ok(())
}

/// Derive the TLS SNI / certificate name for cert-based transports:
/// explicit `outbound.server_name`, else the host part of
/// `outbound.server` (port stripped).
fn cert_server_name(outbound: &donut_config::ClientOutbound) -> anyhow::Result<String> {
    if !outbound.server_name.is_empty() {
        return Ok(outbound.server_name.clone());
    }
    let host = outbound
        .server
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(outbound.server.as_str());
    if host.is_empty() {
        anyhow::bail!(
            "cannot derive server_name from outbound.server {:?}; set outbound.server_name",
            outbound.server
        );
    }
    Ok(host.to_string())
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
