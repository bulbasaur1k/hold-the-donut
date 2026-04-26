//! donut-socks — local SOCKS5 inbound for the client daemon.
//!
//! Implements the minimum useful SOCKS5 surface (RFC 1928):
//! greeting with method NO-AUTH (`0x00`), CONNECT (`0x01`) to an
//! IPv4/IPv6/Domain destination, success reply with the bound
//! address. UDP ASSOCIATE and BIND are not implemented — they
//! aren't needed for the proxy plumbing in M7 step 1.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::net::{Ipv4Addr, Ipv6Addr};

use donut_core::{Address, Endpoint};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const VER: u8 = 0x05;
const RSV: u8 = 0x00;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Error)]
pub enum SocksError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("unsupported SOCKS version {0}")]
    BadVersion(u8),

    #[error("client offered no acceptable authentication methods")]
    NoAcceptableAuth,

    #[error("only CONNECT is supported, got {0}")]
    UnsupportedCommand(u8),

    #[error("invalid SOCKS5 address type {0}")]
    BadAddressType(u8),

    #[error("invalid utf-8 domain name in SOCKS5 request")]
    BadDomain,
}

/// Pending CONNECT request. The caller should resolve / dial the
/// target and then call [`PendingConnect::accept`] to send the
/// success reply, or [`PendingConnect::reject`] for the failure
/// reply.
pub struct PendingConnect {
    pub target: Endpoint,
    pub stream: TcpStream,
}

impl PendingConnect {
    /// Send the success reply and hand the underlying socket back.
    pub async fn accept(mut self, bound: std::net::SocketAddr) -> Result<TcpStream, SocksError> {
        write_reply(&mut self.stream, REP_SUCCEEDED, bound).await?;
        Ok(self.stream)
    }

    /// Send a generic failure reply and drop the socket.
    pub async fn reject(mut self) -> Result<(), SocksError> {
        let zero = "0.0.0.0:0".parse().expect("static literal");
        write_reply(&mut self.stream, REP_GENERAL_FAILURE, zero).await?;
        Ok(())
    }
}

/// Greet the client (NO-AUTH only) and read a CONNECT request.
/// Returns a [`PendingConnect`] holding the target and the open
/// socket. Refuses anything that isn't `VER=5 + CMD=CONNECT`.
pub async fn handshake_connect(mut stream: TcpStream) -> Result<PendingConnect, SocksError> {
    // 1. Greeting: VER NMETHODS METHODS...
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != VER {
        return Err(SocksError::BadVersion(header[0]));
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[VER, METHOD_NONE_ACCEPTABLE]).await?;
        return Err(SocksError::NoAcceptableAuth);
    }
    stream.write_all(&[VER, METHOD_NO_AUTH]).await?;

    // 2. CONNECT request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut request_head = [0u8; 4];
    stream.read_exact(&mut request_head).await?;
    if request_head[0] != VER {
        return Err(SocksError::BadVersion(request_head[0]));
    }
    if request_head[1] != CMD_CONNECT {
        write_reply(
            &mut stream,
            REP_COMMAND_NOT_SUPPORTED,
            "0.0.0.0:0".parse().unwrap(),
        )
        .await
        .ok();
        return Err(SocksError::UnsupportedCommand(request_head[1]));
    }
    let _rsv = request_head[2];
    let atyp = request_head[3];

    let address = match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            Address::ipv4(Ipv4Addr::from(buf))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            Address::ipv6(Ipv6Addr::from(buf))
        }
        ATYP_DOMAIN => {
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let len = len_byte[0] as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            let s = String::from_utf8(buf).map_err(|_| SocksError::BadDomain)?;
            Address::domain(s).map_err(|_| SocksError::BadDomain)?
        }
        other => return Err(SocksError::BadAddressType(other)),
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(PendingConnect {
        target: Endpoint::new(address, port),
        stream,
    })
}

async fn write_reply(
    stream: &mut TcpStream,
    rep: u8,
    bound: std::net::SocketAddr,
) -> Result<(), SocksError> {
    let mut out = vec![VER, rep, RSV];
    match bound {
        std::net::SocketAddr::V4(v4) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(v6) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    stream.write_all(&out).await?;
    stream.flush().await?;
    Ok(())
}
