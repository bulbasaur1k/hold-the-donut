//! donut-server — VLESS+REALITY+XHTTP proxy server.
//!
//! Status: **M0 stub.** Full implementation in M6.

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "donut-server", version, about = "hold-the-donut proxy server")]
struct Args {
    /// Path to JSON config (xray-compatible subset).
    #[arg(short, long, default_value = "/etc/donut/server.json")]
    config: String,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    tracing::info!(config = %args.config, "donut-server stub — M0");
    eprintln!("donut-server: not yet implemented (M0 stub; see docs/PLAN.md)");
    Ok(())
}
