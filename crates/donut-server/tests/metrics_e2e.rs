//! The `/metrics` endpoint serves Prometheus text-exposition output.

use std::time::Duration;

use donut_server::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_endpoint_serves_prometheus_text() {
    let metrics = Metrics::new();
    metrics.connection_accepted();
    let _guard = metrics.tunnel_started();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(donut_server::metrics::serve(listener, metrics));

    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
        .await
        .unwrap();
    sock.flush().await.unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut resp))
        .await
        .expect("metrics read timed out")
        .unwrap();
    let text = String::from_utf8_lossy(&resp);

    assert!(text.contains("200 OK"), "HTTP 200 status");
    assert!(
        text.contains("text/plain; version=0.0.4"),
        "Prometheus content-type"
    );
    assert!(text.contains("donut_connections_total 1"));
    assert!(text.contains("donut_active_connections 1"));
    assert!(text.contains("# TYPE donut_handshakes_total counter"));
}
