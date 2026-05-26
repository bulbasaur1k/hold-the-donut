//! donut-io — shared low-level I/O helpers.
//!
//! Scope: bounded buffer pool on top of [`bytes::BytesMut`], tuned
//! bidirectional copy (splice / io_uring probing in later milestones),
//! socket tuning knobs (SO_REUSEPORT, TCP_FASTOPEN, SO_MARK).
//!
//! Status: **M0 stub.**

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod vision;
pub mod vision_xray;
