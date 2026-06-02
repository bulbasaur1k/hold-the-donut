//! End-to-end tests for the carrier transport.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::client::dial;
use crate::config::{ClientConfig, ServerConfig};
use crate::mode::Mode;
use crate::server::Server;

#[tokio::test]
async fn stream_one_round_trip_path_session() {
    // Spin up a carrier server on an ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_cfg = ServerConfig {
        mode: Mode::StreamOne,
        ..ServerConfig::default()
    };
    let mut server = Server::serve(listener, server_cfg);

    // Server task: accept one session and echo upstream → downstream.
    let server_task = tokio::spawn(async move {
        let mut session = server.accept().await.expect("server accepts session");
        let mut buf = [0u8; 64];
        let n = session.stream.read(&mut buf).await.unwrap();
        let payload = &buf[..n];
        session.stream.write_all(b"echo:").await.unwrap();
        session.stream.write_all(payload).await.unwrap();
        session.stream.flush().await.unwrap();
        session.stream.shutdown().await.unwrap();
    });

    // Client side: dial and exchange a small message.
    let client_cfg = ClientConfig {
        mode: Mode::StreamOne,
        ..ClientConfig::default()
    };
    let mut stream = timeout(Duration::from_secs(5), dial(addr, &client_cfg))
        .await
        .expect("dial timeout")
        .expect("dial succeeds");

    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();

    let mut downlink = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut downlink))
        .await
        .expect("read timeout")
        .unwrap();

    assert_eq!(downlink, b"echo:hello");
    server_task.await.unwrap();
}

#[tokio::test]
async fn stream_one_relays_chunked_data() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut server = Server::serve(
        listener,
        ServerConfig {
            mode: Mode::StreamOne,
            ..ServerConfig::default()
        },
    );

    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i & 0xff) as u8).collect();
    let payload_for_server = payload.clone();

    let server_task = tokio::spawn(async move {
        let mut session = server.accept().await.unwrap();
        let mut got = Vec::with_capacity(payload_for_server.len());
        let mut buf = [0u8; 4096];
        loop {
            let n = session.stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.len() >= payload_for_server.len() {
                break;
            }
        }
        assert_eq!(got, payload_for_server);
        session.stream.write_all(&got).await.unwrap();
        session.stream.shutdown().await.unwrap();
    });

    let client_cfg = ClientConfig {
        mode: Mode::StreamOne,
        ..ClientConfig::default()
    };
    let mut stream = dial(addr, &client_cfg).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();

    let mut got = Vec::with_capacity(payload.len());
    timeout(Duration::from_secs(5), stream.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.len(), payload.len());
    assert_eq!(got, payload);
    server_task.await.unwrap();
}

#[tokio::test]
async fn stream_up_round_trip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_cfg = ServerConfig {
        mode: Mode::StreamUp,
        ..ServerConfig::default()
    };
    let mut server = Server::serve(listener, server_cfg);

    let server_task = tokio::spawn(async move {
        let mut session = server.accept().await.expect("server accepts session");
        let mut buf = [0u8; 64];
        let n = session.stream.read(&mut buf).await.unwrap();
        let payload = &buf[..n];
        session.stream.write_all(b"echo:").await.unwrap();
        session.stream.write_all(payload).await.unwrap();
        session.stream.flush().await.unwrap();
        session.stream.shutdown().await.unwrap();
    });

    let client_cfg = ClientConfig {
        mode: Mode::StreamUp,
        ..ClientConfig::default()
    };
    let mut stream = timeout(Duration::from_secs(5), dial(addr, &client_cfg))
        .await
        .expect("dial timeout")
        .expect("dial succeeds");

    stream.write_all(b"world").await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();

    let mut downlink = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut downlink))
        .await
        .expect("read timeout")
        .unwrap();

    assert_eq!(downlink, b"echo:world");
    server_task.await.unwrap();
}

/// Wire-compat with an off-the-shelf Xray xHTTP client: the session id
/// is a **dashed UUID** in the path (not donut's 32-hex), the `Host` is
/// pinned, and the downlink response must carry the Xray-faithful header
/// set (X-Padding + SSE/no-buffer). Drives raw hyper requests rather than
/// the donut client so it exercises exactly the bytes Xray emits.
#[tokio::test]
async fn stream_up_accepts_xray_uuid_session() {
    use bytes::Bytes;
    use http::Request;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;

    const HOST: &str = "tunnel.example";
    const PREFIX: &str = "/secret";

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut server = Server::serve(
        listener,
        ServerConfig {
            mode: Mode::StreamUp,
            path_prefix: PREFIX.into(),
            host: Some(HOST.into()),
            ..ServerConfig::default()
        },
    );

    let server_task = tokio::spawn(async move {
        let mut session = server.accept().await.expect("server accepts session");
        let mut buf = [0u8; 64];
        let n = session.stream.read(&mut buf).await.unwrap();
        session.stream.write_all(b"echo:").await.unwrap();
        session.stream.write_all(&buf[..n]).await.unwrap();
        session.stream.flush().await.unwrap();
        session.stream.shutdown().await.unwrap();
    });

    // Dashed-UUID session id, exactly as Xray's xHTTP client places it.
    let sid = crate::session::SessionId::random().to_uuid();
    assert_eq!(sid.len(), 36);
    let path = format!("{PREFIX}/{sid}");

    // Downlink GET on its own connection — opens first, parks.
    let dl_tcp = TcpStream::connect(addr).await.unwrap();
    let (mut dl_send, dl_conn) = http1::handshake::<_, Empty<Bytes>>(TokioIo::new(dl_tcp))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = dl_conn.await;
    });
    let dl_req = Request::builder()
        .method("GET")
        .uri(&path)
        .header(http::header::HOST, HOST)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let dl_resp = dl_send.send_request(dl_req).await.unwrap();
    assert!(dl_resp.status().is_success(), "downlink GET accepted");

    // Xray-faithful response headers.
    let h = dl_resp.headers();
    assert!(h.contains_key("x-padding"), "X-Padding present");
    assert_eq!(
        h.get(http::header::CONTENT_TYPE).unwrap(),
        "text/event-stream"
    );
    assert_eq!(h.get("x-accel-buffering").unwrap(), "no");

    // Uplink POST on a second connection — pairs with the parked GET.
    let ul_tcp = TcpStream::connect(addr).await.unwrap();
    let (mut ul_send, ul_conn) = http1::handshake::<_, Full<Bytes>>(TokioIo::new(ul_tcp))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = ul_conn.await;
    });
    let ul_req = Request::builder()
        .method("POST")
        .uri(&path)
        .header(http::header::HOST, HOST)
        // Xray clients carry x_padding in Referer; its presence switches the
        // uplink POST response into the keepalive channel.
        .header(
            http::header::REFERER,
            format!("https://{HOST}/?x_padding=AAAA"),
        )
        .body(Full::new(Bytes::from_static(b"world")))
        .unwrap();
    let ul_resp = ul_send.send_request(ul_req).await.unwrap();
    assert!(ul_resp.status().is_success(), "uplink POST accepted");
    // Keepalive response headers (Xray sets these on the uplink POST 200).
    assert_eq!(
        ul_resp.headers().get("x-accel-buffering").unwrap(),
        "no",
        "uplink POST is the keepalive channel"
    );
    assert!(ul_resp.headers().contains_key("x-padding"));

    // Downlink body is the echo of the uplink.
    let body = timeout(Duration::from_secs(5), dl_resp.into_body().collect())
        .await
        .expect("downlink read timeout")
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"echo:world");

    server_task.await.unwrap();
}

/// A request to the right path but the **wrong Host** is not our tunnel:
/// with no decoy configured it must 404, never opening a session.
#[tokio::test]
async fn wrong_host_is_rejected() {
    use bytes::Bytes;
    use http::Request;
    use http_body_util::Empty;
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = Server::serve(
        listener,
        ServerConfig {
            mode: Mode::StreamUp,
            path_prefix: "/secret".into(),
            host: Some("tunnel.example".into()),
            ..ServerConfig::default()
        },
    );

    let sid = crate::session::SessionId::random().to_uuid();
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (mut send, conn) = http1::handshake::<_, Empty<Bytes>>(TokioIo::new(tcp))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("GET")
        .uri(format!("/secret/{sid}"))
        .header(http::header::HOST, "evil.example")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = send.send_request(req).await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn packet_up_round_trip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_cfg = ServerConfig {
        mode: Mode::PacketUp,
        ..ServerConfig::default()
    };
    let mut server = Server::serve(listener, server_cfg);

    let server_task = tokio::spawn(async move {
        let mut session = server.accept().await.expect("server accepts session");
        // Read the whole uplink (client closes after writing).
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = session.stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.ends_with(b"END") {
                break;
            }
        }
        session.stream.write_all(b"echo:").await.unwrap();
        session.stream.write_all(&got).await.unwrap();
        session.stream.shutdown().await.unwrap();
    });

    let client_cfg = ClientConfig {
        mode: Mode::PacketUp,
        ..ClientConfig::default()
    };
    let mut stream = timeout(Duration::from_secs(5), dial(addr, &client_cfg))
        .await
        .expect("dial timeout")
        .expect("dial succeeds");

    // Write three sequential pieces — they will become three sequenced POSTs.
    stream.write_all(b"hello-").await.unwrap();
    stream.flush().await.unwrap();
    stream.write_all(b"packet-").await.unwrap();
    stream.flush().await.unwrap();
    stream.write_all(b"up-END").await.unwrap();
    stream.shutdown().await.unwrap();

    let mut downlink = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut downlink))
        .await
        .expect("read timeout")
        .unwrap();

    assert_eq!(downlink, b"echo:hello-packet-up-END");
    server_task.await.unwrap();
}
