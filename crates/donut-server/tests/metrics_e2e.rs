//! The admin endpoint serves Prometheus `/metrics` + `/healthz`, optionally
//! behind HTTP Basic Auth.

use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use donut_server::metrics::AdminAuth;
use donut_server::Metrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Drive one request against a freshly-spawned admin endpoint and return the
/// raw HTTP response text.
async fn request(auth: Option<Arc<AdminAuth>>, raw_request: &[u8]) -> String {
    let metrics = Metrics::new();
    metrics.connection_accepted();
    let _guard = metrics.tunnel_started();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(donut_server::metrics::serve(
        listener,
        metrics,
        auth,
        Duration::from_millis(100),
    ));

    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(raw_request).await.unwrap();
    sock.flush().await.unwrap();

    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut resp))
        .await
        .expect("admin read timed out")
        .unwrap();
    String::from_utf8_lossy(&resp).into_owned()
}

/// Argon2 PHC hash of `password` (fixed test salt — the production CLI uses
/// a CSPRNG salt; verification is salt-agnostic).
fn hash(password: &str) -> String {
    let salt = SaltString::encode_b64(b"donut-test-salt0").unwrap();
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_endpoint_serves_prometheus_text() {
    let text = request(None, b"GET /metrics HTTP/1.0\r\n\r\n").await;
    assert!(text.contains("200 OK"), "HTTP 200 status");
    assert!(
        text.contains("text/plain; version=0.0.4"),
        "Prometheus content-type"
    );
    assert!(text.contains("donut_connections_total 1"));
    assert!(text.contains("donut_active_connections 1"));
    assert!(text.contains("# TYPE donut_handshakes_total counter"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_serves_liveness_json() {
    let text = request(None, b"GET /healthz HTTP/1.0\r\n\r\n").await;
    assert!(text.contains("200 OK"));
    assert!(text.contains("application/json"));
    assert!(text.contains("\"status\":\"ok\""));
    assert!(text.contains("\"version\":"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic_auth_rejects_missing_and_wrong_credentials() {
    let guard = Arc::new(AdminAuth::new("admin".into(), hash("s3cret")).unwrap());

    // No Authorization header → 401 with a Basic challenge.
    let text = request(Some(guard.clone()), b"GET /metrics HTTP/1.0\r\n\r\n").await;
    assert!(text.contains("401 Unauthorized"), "missing creds → 401");
    assert!(text.contains("WWW-Authenticate: Basic"));

    // Wrong password → 401.
    let bad = base64_basic("admin", "nope");
    let req = format!("GET /metrics HTTP/1.0\r\nAuthorization: Basic {bad}\r\n\r\n");
    let text = request(Some(guard.clone()), req.as_bytes()).await;
    assert!(text.contains("401 Unauthorized"), "wrong pass → 401");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic_auth_accepts_valid_credentials() {
    let guard = Arc::new(AdminAuth::new("admin".into(), hash("s3cret")).unwrap());
    let ok = base64_basic("admin", "s3cret");
    let req = format!("GET /metrics HTTP/1.0\r\nAuthorization: Basic {ok}\r\n\r\n");
    let text = request(Some(guard), req.as_bytes()).await;
    assert!(text.contains("200 OK"), "valid creds → 200");
    assert!(text.contains("donut_connections_total 1"));
}

fn base64_basic(user: &str, pass: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
}
