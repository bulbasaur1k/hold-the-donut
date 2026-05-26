//! Server metrics in Prometheus text-exposition format.
//!
//! Plain atomic counters (no global singleton — a `Metrics` is owned by
//! the daemon and shared as `Arc<Metrics>` through the proxy paths). The
//! [`serve`] endpoint renders them on a dedicated listener so it never
//! mixes with the data plane. All metric names/labels are English.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Atomic server counters.
#[derive(Debug, Default)]
pub struct Metrics {
    connections_total: AtomicU64,
    active_connections: AtomicI64,
    handshakes_tunnel: AtomicU64,
    handshakes_forward: AtomicU64,
    blackhole_total: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A connection was accepted on the public listener.
    pub fn connection_accepted(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
    }

    /// An authenticated peer was tunnelled. Returns an RAII guard that
    /// holds the `active_connections` gauge up for the session's life.
    pub fn tunnel_started(self: &Arc<Self>) -> ActiveGuard {
        self.handshakes_tunnel.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        ActiveGuard {
            metrics: self.clone(),
        }
    }

    /// An unknown caller was relayed to the selfsteal dest.
    pub fn forwarded(&self) {
        self.handshakes_forward.fetch_add(1, Ordering::Relaxed);
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

    /// Render the current values in Prometheus text-exposition format.
    pub fn render(&self) -> String {
        let connections = self.connections_total.load(Ordering::Relaxed);
        let active = self.active_connections.load(Ordering::Relaxed);
        let tunnel = self.handshakes_tunnel.load(Ordering::Relaxed);
        let forward = self.handshakes_forward.load(Ordering::Relaxed);
        let blackhole = self.blackhole_total.load(Ordering::Relaxed);
        let up = self.bytes_up.load(Ordering::Relaxed);
        let down = self.bytes_down.load(Ordering::Relaxed);
        format!(
            "# HELP donut_connections_total Total connections accepted on the public listener.\n\
             # TYPE donut_connections_total counter\n\
             donut_connections_total {connections}\n\
             # HELP donut_active_connections Currently active tunnelled connections.\n\
             # TYPE donut_active_connections gauge\n\
             donut_active_connections {active}\n\
             # HELP donut_handshakes_total Connection triage outcomes (tunnel vs decoy self-steal).\n\
             # TYPE donut_handshakes_total counter\n\
             donut_handshakes_total{{result=\"tunnel\"}} {tunnel}\n\
             donut_handshakes_total{{result=\"forward\"}} {forward}\n\
             # HELP donut_blackhole_total Connections dropped by a routing block rule.\n\
             # TYPE donut_blackhole_total counter\n\
             donut_blackhole_total {blackhole}\n\
             # HELP donut_bytes_total Proxied bytes by direction.\n\
             # TYPE donut_bytes_total counter\n\
             donut_bytes_total{{direction=\"up\"}} {up}\n\
             donut_bytes_total{{direction=\"down\"}} {down}\n"
        )
    }
}

/// Holds the `active_connections` gauge up for a tunnel session; the
/// gauge is decremented when the guard drops (any return path).
pub struct ActiveGuard {
    metrics: Arc<Metrics>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.metrics
            .active_connections
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
        m.forwarded();
        m.blackholed();
        m.add_bytes(100, 250);

        let out = m.render();
        assert!(out.contains("donut_connections_total 2"));
        assert!(out.contains("donut_active_connections 1"));
        assert!(out.contains("donut_handshakes_total{result=\"tunnel\"} 1"));
        assert!(out.contains("donut_handshakes_total{result=\"forward\"} 1"));
        assert!(out.contains("donut_blackhole_total 1"));
        assert!(out.contains("donut_bytes_total{direction=\"up\"} 100"));
        assert!(out.contains("donut_bytes_total{direction=\"down\"} 250"));
        assert!(out.contains("# TYPE donut_connections_total counter"));

        drop(guard);
        assert!(m.render().contains("donut_active_connections 0"));
    }
}
