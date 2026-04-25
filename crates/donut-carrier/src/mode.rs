use serde::{Deserialize, Serialize};

/// Carrier framing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Single bidirectional HTTP exchange. Default under veiled-TLS.
    /// Uplink and downlink share the same request/response pair —
    /// hyper's H1.1 chunked / H2 stream framing carries both halves.
    #[default]
    StreamOne,

    /// One long chunked POST (uplink) and one long GET (downlink),
    /// bound by a session id. Fastest split mode.
    StreamUp,

    /// Many short sequenced POSTs (uplink) and one long GET
    /// (downlink). Used over channels where long-lived POSTs are
    /// blocked by middleboxes.
    PacketUp,
}
