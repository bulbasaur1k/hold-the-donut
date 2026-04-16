//! donut-carrier — HTTP-based transport (3 modes, over H1/H2/H3).
//!
//! Three framing modes under an HTTP cover:
//! * `packet-up` — many short POSTs with sequence numbers (uplink),
//!   single long GET (downlink). Default placements: session via Path,
//!   seq via `X-Seq` header.
//! * `stream-up` — one long chunked POST, one long GET. Fastest split.
//! * `stream-one` — single request carries both directions. Default
//!   when the underlying TLS layer is veiled (`auto` resolves here).
//!
//! Session-id placements: `Path` (default), `Query`, `Header(X-Session)`,
//! `Cookie(x_session)`, `Body`.
//!
//! Server tunables (upstream defaults):
//! * `sc_max_each_post_bytes` = 1_000_000
//! * `sc_min_posts_interval_ms` = 30
//! * `sc_max_buffered_posts` = 30
//! * `sc_stream_up_server_secs` = 20..80
//!
//! Status: **M0 stub.** Implementation in M4 (H1/H2), extended in M5 (H3).

#![forbid(unsafe_op_in_unsafe_fn)]
