//! donut-tools — ops CLI: keygen, config-gen, check-reality.
//!
//! Status: **M0 stub.** Subcommands materialise in M9.

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "donut-tools", version, about = "hold-the-donut ops tool")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate an X25519 keypair + ShortID for a REALITY server.
    Keygen,
    /// Sanity-check a REALITY server (TLS handshake + selfsteal).
    CheckReality { target: String },
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
        Cmd::CheckReality { target } => {
            eprintln!("check-reality {target}: not yet implemented (M9)")
        }
        Cmd::ConfigGen { kind } => eprintln!("config-gen {kind}: not yet implemented (M9)"),
    }
    Ok(())
}
