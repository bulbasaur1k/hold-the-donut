//! donut-server — edge daemon.
//!
//! Status: **M0 stub.** Full implementation in M6.

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "donut-server", version, about = "hold-the-donut edge daemon")]
struct Args {
    /// Path to JSON config.
    #[arg(short, long, default_value = "/etc/donut/server.json")]
    config: String,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    tracing::info!(config = %args.config, "donut-server starting (M0 stub)");
    eprintln!("donut-server: not yet implemented (M0 stub)");
    Ok(())
}
