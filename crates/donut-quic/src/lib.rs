//! donut-quic — QUIC / HTTP-3 transport for the HTTP-based carrier.
//!
//! Uses [`quinn`] with a custom rustls provider that honours the
//! veil hooks from [`donut-rustls`]. `h3` + `h3-quinn` for the
//! HTTP-3 layer. Framing is delegated to [`donut-carrier`].
//!
//! Status: **M0 stub.** Implementation in M5.

#![forbid(unsafe_op_in_unsafe_fn)]
