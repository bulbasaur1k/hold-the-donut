//! donut-quic — QUIC / HTTP-3 transport for XHTTP.
//!
//! Uses [`quinn`] with a custom rustls provider that honours the
//! REALITY hooks from [`donut-rustls`]. `h3` + `h3-quinn` for the HTTP-3
//! layer. XHTTP framing is delegated to [`donut-xhttp`].
//!
//! Status: **M0 stub.** Implementation in M5.

#![forbid(unsafe_op_in_unsafe_fn)]
