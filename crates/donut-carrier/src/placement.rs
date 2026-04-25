use serde::{Deserialize, Serialize};

/// Where to place the session id (and seq number, in `packet-up`)
/// on an HTTP request. Mirrors upstream's set, restricted to the
/// values we actually implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Placement {
    /// Last segment of the request path. Default for session-id.
    #[default]
    Path,
    /// Query string under a configurable key (e.g. `?x_session=...`).
    Query,
    /// Header value under a configurable name (e.g. `X-Session`).
    Header,
    /// Cookie under a configurable name.
    Cookie,
}
