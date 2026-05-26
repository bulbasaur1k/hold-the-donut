//! Server metrics in Prometheus text-exposition format.
//!
//! Plain atomic counters (no global singleton — a `Metrics` is owned by
//! the daemon and shared as `Arc<Metrics>` through the proxy paths). The
//! [`serve`] endpoint renders them on a dedicated listener so it never
//! mixes with the data plane. All metric names/labels are English.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Tunnel-session transport, for the per-kind active-session gauge. Lets a
/// leak (sessions/tasks that never terminate) be localised to a subsystem —
/// e.g. a runaway `mux` relay shows as a climbing `kind="mux"` series.
#[derive(Debug, Clone, Copy)]
pub enum SessionKind {
    Tcp,
    Udp,
    Mux,
}

/// Why a tunnel session ended badly — kept low-cardinality for Prometheus.
#[derive(Debug, Clone, Copy)]
pub enum SessErr {
    Reset,
    Timeout,
    Eof,
    Unsupported,
    Dial,
    Tls,
    Other,
}

impl SessErr {
    /// Classify a std::io error into a low-cardinality bucket.
    pub fn from_io(e: &std::io::Error) -> Self {
        use std::io::ErrorKind::*;
        match e.kind() {
            ConnectionReset | ConnectionAborted | BrokenPipe => SessErr::Reset,
            TimedOut => SessErr::Timeout,
            UnexpectedEof => SessErr::Eof,
            _ => SessErr::Other,
        }
    }
}

/// Fixed-bucket latency histogram backed by atomics (Prometheus histogram).
#[derive(Debug)]
struct Histogram {
    buckets: [AtomicU64; Self::BOUNDS.len() + 1],
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    /// Upper bounds (`le`) in seconds — tuned for proxy dial latency.
    const BOUNDS: [f64; 9] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5];

    fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        self.sum_micros
            .fetch_add(d.as_micros() as u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        let idx = Self::BOUNDS
            .iter()
            .position(|&b| secs <= b)
            .unwrap_or(Self::BOUNDS.len());
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, name: &str, help: &str) -> String {
        let mut out = format!("# HELP {name} {help}\n# TYPE {name} histogram\n");
        let mut cum = 0u64;
        for (i, b) in Self::BOUNDS.iter().enumerate() {
            cum += self.buckets[i].load(Ordering::Relaxed);
            out.push_str(&format!("{name}_bucket{{le=\"{b}\"}} {cum}\n"));
        }
        cum += self.buckets[Self::BOUNDS.len()].load(Ordering::Relaxed);
        out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {cum}\n"));
        let sum = self.sum_micros.load(Ordering::Relaxed) as f64 / 1.0e6;
        let count = self.count.load(Ordering::Relaxed);
        out.push_str(&format!("{name}_sum {sum}\n{name}_count {count}\n"));
        out
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

/// Atomic server counters.
#[derive(Debug, Default)]
pub struct Metrics {
    connections_total: AtomicU64,
    active_connections: AtomicI64,
    // active sessions split by transport (leak localisation)
    active_tcp: AtomicI64,
    active_udp: AtomicI64,
    active_mux: AtomicI64,
    handshakes_tunnel: AtomicU64,
    handshakes_forward: AtomicU64,
    rejected_unauthorized: AtomicU64,
    blackhole_total: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    // session outcomes + error breakdown (connection quality)
    sessions_ok: AtomicU64,
    sessions_error: AtomicU64,
    err_reset: AtomicU64,
    err_timeout: AtomicU64,
    err_eof: AtomicU64,
    err_unsupported: AtomicU64,
    err_dial: AtomicU64,
    err_tls: AtomicU64,
    err_other: AtomicU64,
    // upstream dial latency (connection quality)
    dial: Histogram,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A connection was accepted on the public listener.
    pub fn connection_accepted(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
    }

    /// An authenticated peer was tunnelled (TCP transport). Returns an RAII
    /// guard that holds the active-session gauges up for the session's life.
    pub fn tunnel_started(self: &Arc<Self>) -> ActiveGuard {
        self.tunnel_started_kind(SessionKind::Tcp)
    }

    /// As [`tunnel_started`], tagging the session's transport so the
    /// `donut_active_sessions{kind}` gauge can localise a leak.
    pub fn tunnel_started_kind(self: &Arc<Self>, kind: SessionKind) -> ActiveGuard {
        self.handshakes_tunnel.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.kind_gauge(kind).fetch_add(1, Ordering::Relaxed);
        ActiveGuard {
            metrics: self.clone(),
            kind,
        }
    }

    fn kind_gauge(&self, kind: SessionKind) -> &AtomicI64 {
        match kind {
            SessionKind::Tcp => &self.active_tcp,
            SessionKind::Udp => &self.active_udp,
            SessionKind::Mux => &self.active_mux,
        }
    }

    /// An unknown caller was relayed to the selfsteal dest.
    pub fn forwarded(&self) {
        self.handshakes_forward.fetch_add(1, Ordering::Relaxed);
    }

    /// A session presented a VLESS UUID not in the allowed-user set and
    /// was dropped before proxying (a failed credential / probe).
    pub fn rejected_unauthorized(&self) {
        self.rejected_unauthorized.fetch_add(1, Ordering::Relaxed);
    }

    /// A target was dropped by a routing block rule.
    pub fn blackholed(&self) {
        self.blackhole_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Account proxied bytes (`up` = client→target, `down` = target→client).
    pub fn add_bytes(&self, up: u64, down: u64) {
        self.bytes_up.fetch_add(up, Ordering::Relaxed);
        self.bytes_down.fetch_add(down, Ordering::Relaxed);
    }

    /// A tunnel session completed cleanly.
    pub fn session_ok(&self) {
        self.sessions_ok.fetch_add(1, Ordering::Relaxed);
    }

    /// A tunnel session ended with an error (also bumps the per-kind counter).
    pub fn session_error(&self, kind: SessErr) {
        self.sessions_error.fetch_add(1, Ordering::Relaxed);
        let c = match kind {
            SessErr::Reset => &self.err_reset,
            SessErr::Timeout => &self.err_timeout,
            SessErr::Eof => &self.err_eof,
            SessErr::Unsupported => &self.err_unsupported,
            SessErr::Dial => &self.err_dial,
            SessErr::Tls => &self.err_tls,
            SessErr::Other => &self.err_other,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// Record how long it took to dial the upstream target (connection quality).
    pub fn observe_dial(&self, d: Duration) {
        self.dial.observe(d);
    }

    /// Render the current values in Prometheus text-exposition format.
    pub fn render(&self) -> String {
        let connections = self.connections_total.load(Ordering::Relaxed);
        let active = self.active_connections.load(Ordering::Relaxed);
        let a_tcp = self.active_tcp.load(Ordering::Relaxed);
        let a_udp = self.active_udp.load(Ordering::Relaxed);
        let a_mux = self.active_mux.load(Ordering::Relaxed);
        let tunnel = self.handshakes_tunnel.load(Ordering::Relaxed);
        let forward = self.handshakes_forward.load(Ordering::Relaxed);
        let unauthorized = self.rejected_unauthorized.load(Ordering::Relaxed);
        let blackhole = self.blackhole_total.load(Ordering::Relaxed);
        let up = self.bytes_up.load(Ordering::Relaxed);
        let down = self.bytes_down.load(Ordering::Relaxed);
        let s_ok = self.sessions_ok.load(Ordering::Relaxed);
        let s_err = self.sessions_error.load(Ordering::Relaxed);
        let e_reset = self.err_reset.load(Ordering::Relaxed);
        let e_timeout = self.err_timeout.load(Ordering::Relaxed);
        let e_eof = self.err_eof.load(Ordering::Relaxed);
        let e_unsup = self.err_unsupported.load(Ordering::Relaxed);
        let e_dial = self.err_dial.load(Ordering::Relaxed);
        let e_tls = self.err_tls.load(Ordering::Relaxed);
        let e_other = self.err_other.load(Ordering::Relaxed);
        let mut out = format!(
            "# HELP donut_connections_total Total connections accepted on the public listener.\n\
             # TYPE donut_connections_total counter\n\
             donut_connections_total {connections}\n\
             # HELP donut_active_connections Currently active tunnelled connections.\n\
             # TYPE donut_active_connections gauge\n\
             donut_active_connections {active}\n\
             # HELP donut_active_sessions Currently active tunnel sessions by transport (leak localisation).\n\
             # TYPE donut_active_sessions gauge\n\
             donut_active_sessions{{kind=\"tcp\"}} {a_tcp}\n\
             donut_active_sessions{{kind=\"udp\"}} {a_udp}\n\
             donut_active_sessions{{kind=\"mux\"}} {a_mux}\n\
             # HELP donut_handshakes_total Connection triage outcomes (tunnel vs decoy self-steal).\n\
             # TYPE donut_handshakes_total counter\n\
             donut_handshakes_total{{result=\"tunnel\"}} {tunnel}\n\
             donut_handshakes_total{{result=\"forward\"}} {forward}\n\
             # HELP donut_rejected_unauthorized_total Tunnel sessions dropped for an unknown VLESS UUID.\n\
             # TYPE donut_rejected_unauthorized_total counter\n\
             donut_rejected_unauthorized_total {unauthorized}\n\
             # HELP donut_blackhole_total Connections dropped by a routing block rule.\n\
             # TYPE donut_blackhole_total counter\n\
             donut_blackhole_total {blackhole}\n\
             # HELP donut_bytes_total Proxied bytes by direction.\n\
             # TYPE donut_bytes_total counter\n\
             donut_bytes_total{{direction=\"up\"}} {up}\n\
             donut_bytes_total{{direction=\"down\"}} {down}\n\
             # HELP donut_sessions_total Tunnel session outcomes.\n\
             # TYPE donut_sessions_total counter\n\
             donut_sessions_total{{outcome=\"ok\"}} {s_ok}\n\
             donut_sessions_total{{outcome=\"error\"}} {s_err}\n\
             # HELP donut_session_errors_total Tunnel session errors by kind.\n\
             # TYPE donut_session_errors_total counter\n\
             donut_session_errors_total{{kind=\"reset\"}} {e_reset}\n\
             donut_session_errors_total{{kind=\"timeout\"}} {e_timeout}\n\
             donut_session_errors_total{{kind=\"eof\"}} {e_eof}\n\
             donut_session_errors_total{{kind=\"unsupported_command\"}} {e_unsup}\n\
             donut_session_errors_total{{kind=\"dial_failed\"}} {e_dial}\n\
             donut_session_errors_total{{kind=\"tls_handshake\"}} {e_tls}\n\
             donut_session_errors_total{{kind=\"other\"}} {e_other}\n"
        );
        out.push_str(&self.dial.render(
            "donut_upstream_dial_seconds",
            "Time to establish the upstream (target) TCP connection.",
        ));
        out.push_str(&proc_metrics());
        out
    }
}

/// Process self-metrics for leak detection: open file descriptors (socket
/// leaks), the FD ceiling, and resident memory (memory leaks). Read lazily
/// from `/proc` at render time, so they cost nothing on the data plane.
/// Linux-only; an empty string elsewhere (e.g. a macOS dev box).
#[cfg(target_os = "linux")]
fn proc_metrics() -> String {
    let mut out = String::new();
    if let Ok(rd) = std::fs::read_dir("/proc/self/fd") {
        // `read_dir` itself holds one fd while iterating, so this overcounts
        // by ~1 — fine for a leak trend.
        let n = rd.count();
        out.push_str(&format!(
            "# HELP donut_open_fds Open file descriptors held by the process.\n\
             # TYPE donut_open_fds gauge\n\
             donut_open_fds {n}\n"
        ));
    }
    if let Ok(limits) = std::fs::read_to_string("/proc/self/limits") {
        if let Some(max) = limits.lines().find_map(|l| {
            l.strip_prefix("Max open files")?
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok())
        }) {
            out.push_str(&format!(
                "# HELP donut_max_fds Soft RLIMIT_NOFILE (file-descriptor ceiling).\n\
                 # TYPE donut_max_fds gauge\n\
                 donut_max_fds {max}\n"
            ));
        }
    }
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        if let Some(kb) = status.lines().find_map(|l| {
            l.strip_prefix("VmRSS:")?
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok())
        }) {
            let bytes = kb * 1024;
            out.push_str(&format!(
                "# HELP donut_resident_memory_bytes Resident set size (RSS) of the process.\n\
                 # TYPE donut_resident_memory_bytes gauge\n\
                 donut_resident_memory_bytes {bytes}\n"
            ));
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
fn proc_metrics() -> String {
    String::new()
}

/// Holds the active-session gauges up for a tunnel session; both the total
/// and the per-kind gauge are decremented when the guard drops (any return
/// path), so a session that never ends shows as a stuck gauge.
pub struct ActiveGuard {
    metrics: Arc<Metrics>,
    kind: SessionKind,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.metrics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        self.metrics
            .kind_gauge(self.kind)
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Serve `GET /metrics` on `listener` in Prometheus text format. Runs
/// until the listener errors; spawn it on a dedicated address.
pub async fn serve(listener: TcpListener, metrics: Arc<Metrics>) {
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(?e, "metrics listener accept error");
                continue;
            }
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            // Drain the request line/headers (we serve the same body for
            // any request); cap the read so a slow client can't pin us.
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let body = metrics.render();
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_all_series_in_english() {
        let m = Metrics::new();
        m.connection_accepted();
        m.connection_accepted();
        let guard = m.tunnel_started();
        let mux_guard = m.tunnel_started_kind(SessionKind::Mux);
        m.forwarded();
        m.rejected_unauthorized();
        m.blackholed();
        m.add_bytes(100, 250);
        m.session_ok();
        m.session_error(SessErr::Unsupported);
        m.observe_dial(Duration::from_millis(30));

        let out = m.render();
        assert!(out.contains("donut_connections_total 2"));
        assert!(out.contains("donut_active_connections 2"));
        assert!(out.contains("donut_active_sessions{kind=\"tcp\"} 1"));
        assert!(out.contains("donut_active_sessions{kind=\"mux\"} 1"));
        assert!(out.contains("donut_handshakes_total{result=\"tunnel\"} 2"));
        assert!(out.contains("donut_handshakes_total{result=\"forward\"} 1"));
        assert!(out.contains("donut_rejected_unauthorized_total 1"));
        assert!(out.contains("donut_blackhole_total 1"));
        assert!(out.contains("donut_bytes_total{direction=\"up\"} 100"));
        assert!(out.contains("donut_bytes_total{direction=\"down\"} 250"));
        assert!(out.contains("donut_sessions_total{outcome=\"ok\"} 1"));
        assert!(out.contains("donut_session_errors_total{kind=\"unsupported_command\"} 1"));
        assert!(out.contains("donut_upstream_dial_seconds_count 1"));
        assert!(out.contains("donut_upstream_dial_seconds_bucket{le=\"+Inf\"} 1"));
        assert!(out.contains("# TYPE donut_upstream_dial_seconds histogram"));

        drop(guard);
        drop(mux_guard);
        let out = m.render();
        assert!(out.contains("donut_active_connections 0"));
        assert!(out.contains("donut_active_sessions{kind=\"tcp\"} 0"));
        assert!(out.contains("donut_active_sessions{kind=\"mux\"} 0"));
    }
}
