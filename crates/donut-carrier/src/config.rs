use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::mode::Mode;
use crate::placement::Placement;

/// Server-side carrier configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Framing mode this server expects.
    pub mode: Mode,

    /// Where the session id is read from on incoming requests.
    pub session_placement: Placement,

    /// Where the sequence number is read from (`packet-up` only).
    pub seq_placement: Placement,

    /// Header name when `session_placement == Header`.
    pub session_header: String,

    /// Cookie / query key when the placement points at one of those.
    pub session_key: String,

    /// Header name when `seq_placement == Header`.
    pub seq_header: String,

    /// Path prefix that requests must start with.
    pub path_prefix: String,

    /// Maximum body length per uplink POST (`packet-up`).
    pub max_post_bytes: usize,

    /// Minimum interval between uplink POSTs to avoid hot loops.
    pub min_post_interval: Duration,

    /// Maximum number of out-of-order uplink POSTs buffered per
    /// session (`packet-up`).
    pub max_buffered_posts: usize,

    /// Inclusive range for the random `stream-up` server-side
    /// keepalive timeout.
    pub stream_up_secs: (u32, u32),
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            session_placement: Placement::Path,
            seq_placement: Placement::Header,
            session_header: "X-Session".into(),
            session_key: "x_session".into(),
            seq_header: "X-Seq".into(),
            path_prefix: "/".into(),
            max_post_bytes: 1_000_000,
            min_post_interval: Duration::from_millis(30),
            max_buffered_posts: 30,
            stream_up_secs: (20, 80),
        }
    }
}

/// Client-side carrier configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Framing mode the client uses to talk to the peer.
    pub mode: Mode,

    /// How the client encodes the session id on outgoing requests.
    pub session_placement: Placement,

    /// How the client encodes the sequence number (`packet-up`).
    pub seq_placement: Placement,

    pub session_header: String,
    pub session_key: String,
    pub seq_header: String,

    /// Server path prefix (default `"/"`).
    pub path_prefix: String,

    /// Host header value to send.
    pub host: String,

    /// Maximum bytes per POST in `packet-up` mode.
    pub max_post_bytes: usize,

    /// Minimum interval between POSTs in `packet-up` mode.
    pub min_post_interval: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            session_placement: Placement::Path,
            seq_placement: Placement::Header,
            session_header: "X-Session".into(),
            session_key: "x_session".into(),
            seq_header: "X-Seq".into(),
            path_prefix: "/".into(),
            host: "localhost".into(),
            max_post_bytes: 1_000_000,
            min_post_interval: Duration::from_millis(30),
        }
    }
}
