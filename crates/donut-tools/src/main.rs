//! donut-tools — ops CLI: key generation, config helpers, peer probe.
//!
//! Status: **M0 stub.** Subcommands materialise in M9.

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "donut-tools", version, about = "hold-the-donut ops cli")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate an X25519 keypair + short identifier for a server.
    Keygen,
    /// Connectivity check against a peer (handshake + fallback path).
    Probe { target: String },
    /// Interactive config generator.
    ConfigGen {
        #[arg(long, value_parser = ["server", "client"])]
        kind: String,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    match args.cmd {
        Cmd::Keygen => eprintln!("keygen: not yet implemented (M9)"),
        Cmd::Probe { target } => eprintln!("probe {target}: not yet implemented (M9)"),
        Cmd::ConfigGen { kind } => eprintln!("config-gen {kind}: not yet implemented (M9)"),
    }
    Ok(())
}
