//! donut-wire — inner-frame codec (byte-exact).
//!
//! Encode/decode of the minimal request header carried inside the
//! outer tunnel. See `docs/PROTOCOLS.md` § 1 for the frozen byte spec.
//!
//! Status: **M0 stub.** Implementation lands in M1.

#![forbid(unsafe_op_in_unsafe_fn)]
