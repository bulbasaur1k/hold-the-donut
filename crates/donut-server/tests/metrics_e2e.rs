//! The admin endpoint serves Prometheus `/metrics` + `/healthz`, optionally
//! behind HTTP Basic Auth.

use std::sync::atomic::{AtomicU64, Ordering};
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
    let store = new_store();
    tokio::spawn(donut_server::metrics::serve(
        listener,
        metrics,
        auth,
        store,
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

static STORE_SEQ: AtomicU64 = AtomicU64::new(0);

/// A fresh, empty durable user store backed by a unique temp file.
fn new_store() -> Arc<donut_server::UserStore> {
    let n = STORE_SEQ.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("donut-metrics-{}-{}.json", std::process::id(), n));
    let _ = std::fs::remove_file(&path);
    donut_server::UserStore::load_or_seed(path, &[]).unwrap()
}

/// One request/response against an already-running admin endpoint at `addr`.
async fn roundtrip(addr: std::net::SocketAddr, req: &[u8]) -> String {
    let mut sock = TcpStream::connect(addr).await.unwrap();
    sock.write_all(req).await.unwrap();
    sock.flush().await.unwrap();
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut resp))
        .await
        .expect("admin read timed out")
        .unwrap();
    String::from_utf8_lossy(&resp).into_owned()
}

#[tokio::test]
async fn admin_api_adds_lists_and_removes_users_live() {
    let guard = Arc::new(AdminAuth::new("admin".into(), hash("s3cret")).unwrap());
    let store = new_store();
    let handle = store.handle();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(donut_server::metrics::serve(
        listener,
        Metrics::new(),
        Some(guard),
        store.clone(),
        Duration::from_millis(100),
    ));

    let cred = base64_basic("admin", "s3cret");

    // POST a device — the server mints the UUID.
    let body = "{\"name\":\"pixel-8\"}";
    let post = format!(
        "POST /admin/users HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {cred}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = roundtrip(addr, post.as_bytes()).await;
    assert!(resp.contains("201 Created"), "resp: {resp}");
    let uuid_str = resp
        .rsplit_once("\"uuid\":\"")
        .and_then(|(_, r)| r.split('"').next())
        .expect("uuid in response")
        .to_string();
    let uuid: donut_core::UserId = uuid_str.parse().unwrap();

    // Live: the handle taken BEFORE the add now authorises it — no restart.
    assert!(handle.is_authorized(&uuid), "new user must authorise live");

    // GET lists it.
    let get = format!(
        "GET /admin/users HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {cred}\r\nConnection: close\r\n\r\n"
    );
    let list = roundtrip(addr, get.as_bytes()).await;
    assert!(list.contains("\"count\":1"), "list: {list}");
    assert!(list.contains(&uuid_str));

    // DELETE removes it, live.
    let del = format!(
        "DELETE /admin/users/{uuid_str} HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {cred}\r\nConnection: close\r\n\r\n"
    );
    let d = roundtrip(addr, del.as_bytes()).await;
    assert!(d.contains("200 OK"), "del: {d}");
    assert!(
        !handle.is_authorized(&uuid),
        "removed user must deauthorise live"
    );
}

#[tokio::test]
async fn admin_api_refuses_user_mgmt_without_credentials() {
    // Unauthenticated endpoint: metrics still serve, but user management must
    // be refused (creating a user requires admin credentials).
    let store = new_store();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(donut_server::metrics::serve(
        listener,
        Metrics::new(),
        None,
        store,
        Duration::from_millis(100),
    ));
    let post =
        "POST /admin/users HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
    let resp = roundtrip(addr, post.as_bytes()).await;
    assert!(resp.contains("403 Forbidden"), "resp: {resp}");
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
