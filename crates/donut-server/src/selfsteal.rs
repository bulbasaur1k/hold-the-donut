//! Selfsteal front door — REALITY-style active-probing defence.
//!
//! Every TCP connection to the public `:443` listener is first triaged
//! here. We read the leading ClientHello, run the veil decision
//! ([`donut_veil::server_verdict`]) and then either:
//!
//! * [`Triage::Tunnel`] — the caller is an authenticated veil peer;
//!   the caller terminates TLS and proxies the tunnel. The bytes we
//!   already read are handed back in `prefix` so the TLS layer can
//!   replay them.
//! * [`Triage::Forwarded`] — the caller is an unknown prober, browser
//!   or garbage. We open a connection to the selfsteal `dest` (a real
//!   web server — typically `127.0.0.1:<decoy>` serving our own domain
//!   with a valid cert) and relay the connection **byte-for-byte**,
//!   ClientHello included. The prober sees the decoy's real TLS
//!   handshake and content and cannot tell us apart from a plain
//!   reverse proxy. See `docs/PLAN.md` § "Self-Steal и подложка".
//!
//! The Forward path never enters the TLS state machine and needs no
//! TLS library: because we only ever *read* the bytes (and replay them
//! verbatim to `dest`), the relay is transparent by construction.

use std::net::SocketAddr;

use donut_veil::{server_verdict, VeilServerConfig, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// TLS handshake content type (`0x16`).
const TLS_HANDSHAKE: u8 = 0x16;
/// Upper bound on the ClientHello record we will buffer before giving
/// up and forwarding. A real ClientHello is well under one TLS record
/// (16 KiB); anything larger is treated as a non-veil caller.
const MAX_CLIENT_HELLO: usize = 16 * 1024;

/// Outcome of [`triage`].
pub enum Triage {
    /// Authenticated veil peer. `client` is positioned right after the
    /// bytes captured in `prefix`; replay `prefix` into the TLS layer
    /// before reading further from `client`. `auth_key` is the
    /// per-connection REALITY key, used to emit the server-auth proof.
    Tunnel {
        client: TcpStream,
        prefix: Vec<u8>,
        auth_key: [u8; 32],
    },
    /// Unknown caller; the connection was relayed verbatim to the
    /// selfsteal `dest` and run to completion.
    Forwarded,
}

/// Read the leading ClientHello off `client`, decide, and on a
/// non-authenticated caller transparently relay the whole connection
/// (ClientHello included) to the selfsteal `dest`.
pub async fn triage(
    mut client: TcpStream,
    veil: &VeilServerConfig,
    dest: SocketAddr,
) -> std::io::Result<Triage> {
    let mut prefix = Vec::with_capacity(2048);
    let hello = read_client_hello(&mut client, &mut prefix).await?;

    match server_verdict(veil, &hello) {
        Verdict::Tunnel { auth_key } => Ok(Triage::Tunnel {
            client,
            prefix,
            auth_key,
        }),
        Verdict::Forward => {
            relay_to_dest(client, prefix, dest).await?;
            Ok(Triage::Forwarded)
        }
    }
}

/// Open `dest`, replay everything we already read, then splice the two
/// sockets until either side closes.
async fn relay_to_dest(
    mut client: TcpStream,
    prefix: Vec<u8>,
    dest: SocketAddr,
) -> std::io::Result<()> {
    let mut upstream = TcpStream::connect(dest).await?;
    upstream.write_all(&prefix).await?;
    upstream.flush().await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    let _ = upstream.shutdown().await;
    let _ = client.shutdown().await;
    Ok(())
}

/// Read from `client` until we hold a complete first TLS record,
/// accumulating every byte into `prefix` so it can be replayed/relayed
/// verbatim. Returns the record *payload* — the handshake message that
/// [`server_verdict`] expects (offset 0 = `HandshakeType`).
///
/// On anything that is plainly not a TLS handshake (wrong content type,
/// bogus or oversized length, premature EOF) it returns whatever bytes
/// it has; [`server_verdict`] then parses them, fails, and forwards.
async fn read_client_hello(
    client: &mut TcpStream,
    prefix: &mut Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    let mut tmp = [0u8; 2048];
    loop {
        if !prefix.is_empty() && prefix[0] != TLS_HANDSHAKE {
            return Ok(Vec::new());
        }
        if prefix.len() >= 5 {
            let record_len = u16::from_be_bytes([prefix[3], prefix[4]]) as usize;
            if record_len == 0 || record_len > MAX_CLIENT_HELLO {
                return Ok(Vec::new());
            }
            if prefix.len() >= 5 + record_len {
                return Ok(prefix[5..5 + record_len].to_vec());
            }
        }

        let n = client.read(&mut tmp).await?;
        if n == 0 {
            // EOF before a full record — hand back the payload we have.
            return Ok(prefix.get(5..).map(<[u8]>::to_vec).unwrap_or_default());
        }
        prefix.extend_from_slice(&tmp[..n]);
        if prefix.len() > MAX_CLIENT_HELLO + 5 {
            return Ok(Vec::new());
        }
    }
}
