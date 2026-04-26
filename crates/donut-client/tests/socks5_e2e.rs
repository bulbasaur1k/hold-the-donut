//! End-to-end SOCKS5 → donut-client → donut-server → echo target.
//!
//! Spins up:
//! 1. A throwaway TCP echo server on `127.0.0.1:0`.
//! 2. donut-server's carrier proxy on another `127.0.0.1:0`.
//! 3. donut-client's SOCKS5 inbound on a third `127.0.0.1:0`,
//!    pointing at donut-server.
//! 4. A hand-crafted SOCKS5 client that connects to donut-client,
//!    asks for CONNECT to the echo server, sends "hello-socks", and
//!    verifies the echoed payload.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[tokio::test]
async fn socks5_to_donut_client_to_donut_server_to_echo() {
    // 1. Echo server.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match echo_listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = s.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
                let _ = wr.shutdown().await;
            });
        }
    });

    // 2. donut-server carrier proxy.
    let proxy_addr = donut_server::run_carrier_proxy("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind donut-server");

    // 3. donut-client SOCKS5 inbound pointing at donut-server.
    let socks_addr =
        donut_client::run_local_socks_proxy("127.0.0.1:0".parse().unwrap(), proxy_addr)
            .await
            .expect("bind donut-client");

    // 4. Hand-crafted SOCKS5 client.
    let mut client = TcpStream::connect(socks_addr).await.unwrap();

    // greeting: VER NMETHODS METHODS — offer NO-AUTH only.
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    // CONNECT request: VER CMD RSV ATYP=IPv4 IP PORT
    let v4 = match echo_addr.ip() {
        std::net::IpAddr::V4(v) => v.octets(),
        _ => unreachable!("ephemeral 127.0.0.1 is v4"),
    };
    let port = echo_addr.port().to_be_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&v4);
    req.extend_from_slice(&port);
    client.write_all(&req).await.unwrap();

    // SOCKS5 reply.
    let mut reply_head = [0u8; 4];
    client.read_exact(&mut reply_head).await.unwrap();
    assert_eq!(reply_head[0], 0x05);
    assert_eq!(reply_head[1], 0x00, "REP=succeeded");
    let bound_len = match reply_head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        atyp => panic!("unexpected ATYP {atyp}"),
    };
    let mut bound = vec![0u8; bound_len];
    client.read_exact(&mut bound).await.unwrap();

    // Now the SOCKS5 socket is a transparent pipe to the echo server.
    client.write_all(b"hello-socks").await.unwrap();
    client.flush().await.unwrap();
    client.shutdown().await.unwrap();

    let mut echoed = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut echoed))
        .await
        .expect("read echoed timeout")
        .unwrap();
    assert_eq!(echoed, b"hello-socks");
}
