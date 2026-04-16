//! donut-client — local agent with SOCKS5/HTTP listener.
//!
//! Status: **M0 stub.** Full implementation in M7.

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "donut-client", version, about = "hold-the-donut local agent")]
struct Args {
    #[arg(short, long, default_value = "/etc/donut/client.json")]
    config: String,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    tracing::info!(config = %args.config, "donut-client starting (M0 stub)");
    eprintln!("donut-client: not yet implemented (M0 stub)");
    Ok(())
}
